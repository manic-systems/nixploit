//! CPE configuration trees and CPE 2.3 names.

use std::{
   fmt::{Display, Formatter, Result as FormatResult},
   mem,
   str::FromStr,
};

use misstep::{Report, Result, ensure, report};
use serde::{
   Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::SerializeStruct as _,
};

use crate::{advisory::Bound, identifier::NormalizedName, source::Collection};

#[derive(Clone, Debug, Deserialize, Serialize)]
/// Logical grouping of CPE nodes with a shared operator.
pub struct Configuration {
   #[serde(default)]
   /// Operator combining child nodes.
   pub operator: Option<Operator>,
   #[serde(default)]
   /// Negation flag for the configuration group.
   pub negate: bool,
   #[serde(default)]
   /// Child nodes in this configuration group.
   pub nodes: Vec<Node>,
}

impl Configuration {
   /// Conditions every node of this configuration inherits.
   pub fn conditions(&self) -> Conditions {
      Conditions {
         additional: self
            .operator
            .as_ref()
            .is_some_and(|operator| operator.restricts(self.nodes.len())),
         negated: self.negate,
      }
   }
}

/// Logical operator joining CPE configuration members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operator {
   /// Every member must match.
   And,
   /// Any member may match.
   Or,
   /// An operator this scanner does not evaluate.
   Other(String),
}

impl Operator {
   /// Reports whether matching one member leaves requirements unverified.
   const fn restricts(&self, members: usize) -> bool {
      match *self {
         Self::And => members > 1,
         Self::Or => false,
         Self::Other(_) => true,
      }
   }
}

impl From<String> for Operator {
   fn from(text: String) -> Self {
      match text.as_str() {
         "AND" => Self::And,
         "OR" => Self::Or,
         _ => Self::Other(text),
      }
   }
}

impl Display for Operator {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(match *self {
         Self::And => "AND",
         Self::Or => "OR",
         Self::Other(ref text) => text,
      })
   }
}

impl Serialize for Operator {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      serializer.collect_str(self)
   }
}

impl<'de> Deserialize<'de> for Operator {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer).map(Self::from)
   }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// Single CPE configuration node with matches and children.
pub struct Node {
   #[serde(default)]
   /// Operator combining this node with its siblings.
   pub operator: Option<Operator>,
   #[serde(default)]
   /// Negation flag for this configuration node.
   pub negate: bool,
   #[serde(default)]
   /// CPE match entries evaluated at this node.
   pub cpe_match: Vec<CpeMatch>,
   #[serde(default)]
   /// Nested configuration nodes below this node.
   pub children: Vec<Self>,
}

#[derive(Clone, Copy, Default, Serialize)]
/// Accumulated operator and negation state during traversal.
pub struct Conditions {
   /// Whether an ancestor required additional version constraints.
   pub additional: bool,
   /// Whether an ancestor negated this branch.
   pub negated: bool,
}

impl Node {
   /// Walk matches and children while tracking inherited conditions.
   pub fn visit<Visitor>(&self, visitor: &mut Visitor, inherited: Conditions)
   where
      Visitor: FnMut(&CpeMatch, Conditions),
   {
      let members = self.cpe_match.len() + self.children.len();
      let conditions = Conditions {
         additional: inherited.additional
            || self
               .operator
               .as_ref()
               .is_some_and(|operator| operator.restricts(members)),
         negated: inherited.negated || self.negate,
      };

      for entry in &self.cpe_match {
         visitor(entry, conditions);
      }

      for child in &self.children {
         child.visit(visitor, conditions);
      }
   }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(from = "CpeMatchFields")]
/// CPE match entry with optional version range bounds.
pub struct CpeMatch {
   /// Whether this CPE entry marks the product as vulnerable.
   pub vulnerable: bool,
   /// CPE name identifying the matched product.
   pub criteria: Cpe,
   /// Lower bound for the affected version range.
   pub start: Bound,
   /// Upper bound for the affected version range.
   pub end: Bound,
}

impl Serialize for CpeMatch {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      let mut fields = serializer.serialize_struct("CpeMatch", 6)?;
      fields.serialize_field("vulnerable", &self.vulnerable)?;
      fields.serialize_field("criteria", &self.criteria)?;
      fields.serialize_field("versionStartIncluding", &self.start.including())?;
      fields.serialize_field("versionStartExcluding", &self.start.excluding())?;
      fields.serialize_field("versionEndIncluding", &self.end.including())?;
      fields.serialize_field("versionEndExcluding", &self.end.excluding())?;
      fields.end()
   }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// CPE match entry fields as NVD spells them.
struct CpeMatchFields {
   /// Whether this CPE entry marks the product as vulnerable.
   vulnerable: bool,
   /// CPE name identifying the matched product.
   criteria: Cpe,
   #[serde(default)]
   /// Inclusive lower bound for the affected version range.
   version_start_including: Option<String>,
   #[serde(default)]
   /// Exclusive lower bound for the affected version range.
   version_start_excluding: Option<String>,
   #[serde(default)]
   /// Inclusive upper bound for the affected version range.
   version_end_including: Option<String>,
   #[serde(default)]
   /// Exclusive upper bound for the affected version range.
   version_end_excluding: Option<String>,
}

impl From<CpeMatchFields> for CpeMatch {
   fn from(fields: CpeMatchFields) -> Self {
      Self {
         vulnerable: fields.vulnerable,
         criteria: fields.criteria,
         start: Bound::new(
            fields.version_start_including,
            fields.version_start_excluding,
         ),
         end: Bound::new(fields.version_end_including, fields.version_end_excluding),
      }
   }
}

impl From<Cpe> for CpeMatch {
   /// Treats a bare vulnerable CPE as a match entry without version bounds.
   fn from(criteria: Cpe) -> Self {
      Self {
         vulnerable: true,
         criteria,
         start: Bound::Unbounded,
         end: Bound::Unbounded,
      }
   }
}

#[derive(Clone, Debug)]
/// Preserves logical values and wildcard escapes in CPE components.
pub enum CpeValue {
   /// Accepts any value for this component.
   Any,
   /// Marks this component as inapplicable.
   NotApplicable,
   /// Contains decoded text without wildcard operators.
   Literal(String),
   /// Retains formatted wildcard syntax for separate evaluation.
   Pattern(String),
}

impl FromStr for CpeValue {
   type Err = Report;

   fn from_str(formatted: &str) -> Result<Self, Report> {
      match formatted {
         "*" => return Ok(Self::Any),
         "-" => return Ok(Self::NotApplicable),
         _ => {},
      }

      let mut literal = String::new();
      let mut escaped = false;
      let mut pattern = false;

      for character in formatted.chars() {
         if escaped {
            literal.push(character);
            escaped = false;
         } else if character == '\\' {
            escaped = true;
         } else {
            pattern |= matches!(character, '*' | '?');
            literal.push(character);
         }
      }

      ensure!(!escaped, "Trailing escape in CPE component");

      Ok(if pattern {
         Self::Pattern(formatted.to_owned())
      } else {
         Self::Literal(literal)
      })
   }
}

/// CPE part naming the kind of product.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Part {
   /// Applications.
   Application,
   /// Operating systems.
   OperatingSystem,
   /// Hardware devices, which configurations pair with the software running
   /// on them.
   Hardware,
}

/// Platform or package collection a CPE's target software names.
#[derive(Clone, Copy, Debug)]
pub enum Target {
   /// Microsoft Windows.
   Windows,
   /// Linux.
   Linux,
   /// macOS.
   Darwin,
   /// A language package collection.
   Collection(Collection),
   /// Any target this scanner cannot compare with a package.
   Other,
}

impl From<&str> for Target {
   fn from(target: &str) -> Self {
      match target {
         "windows" => Self::Windows,
         "linux" => Self::Linux,
         "macos" | "mac_os" | "darwin" => Self::Darwin,
         _ => target.parse().map_or(Self::Other, Self::Collection),
      }
   }
}

#[derive(Clone, Debug)]
/// Parsed CPE identity with vendor product and version fields.
pub struct Cpe {
   /// Formatted name as the source published it.
   text: String,
   /// CPE part component.
   part: Part,
   /// CPE vendor component.
   vendor: NormalizedName,
   /// CPE product component.
   product: NormalizedName,
   /// CPE version component.
   version: CpeValue,
   /// CPE update component.
   update: CpeValue,
   /// Target software identifies platform and package collection constraints.
   target: Target,
   /// Whether platform fields narrow this CPE beyond wildcards.
   restricted: bool,
}

impl Cpe {
   /// Report whether the CPE names software rather than a hardware device.
   pub const fn software(&self) -> bool {
      match self.part {
         Part::Application | Part::OperatingSystem => true,
         Part::Hardware => false,
      }
   }

   /// Borrow the CPE vendor component.
   pub const fn vendor(&self) -> &NormalizedName {
      &self.vendor
   }

   /// Borrow the CPE product component.
   pub const fn product(&self) -> &NormalizedName {
      &self.product
   }

   /// Borrow the CPE version component.
   pub const fn version(&self) -> &CpeValue {
      &self.version
   }

   /// Borrow the CPE update component.
   pub const fn update(&self) -> &CpeValue {
      &self.update
   }

   /// Return the platform or collection the target software names.
   pub const fn target(&self) -> Target {
      self.target
   }

   /// Report whether platform fields narrow this CPE beyond wildcards.
   pub const fn restricted(&self) -> bool {
      self.restricted
   }
}

impl FromStr for Cpe {
   type Err = Report;

   /// Parse CPE 2.3 formatted string criteria.
   fn from_str(criteria: &str) -> Result<Self, Report> {
      let malformed = |reason: &str| report!("Malformed CPE {criteria} ({reason})");
      let mut fields = Vec::with_capacity(13);
      let mut field = String::new();
      let mut escaped = false;

      for character in criteria.chars() {
         if escaped {
            field.push(character);
            escaped = false;
         } else if character == '\\' {
            field.push(character);
            escaped = true;
         } else if character == ':' {
            fields.push(mem::take(&mut field));
         } else {
            field.push(character);
         }
      }

      if escaped {
         return Err(malformed("trailing escape"));
      }

      fields.push(field);

      let components: [String; 13] = fields
         .try_into()
         .map_err(|_fields| malformed("expected 13 colon-separated fields"))?;
      let restricted = components[7..]
         .iter()
         .any(|component| !matches!(component.as_str(), "*" | "-"));
      let [
         scheme,
         format,
         part,
         vendor,
         product,
         version,
         update,
         _,
         _,
         _,
         target_sw,
         _,
         _,
      ] = components;

      if scheme != "cpe" {
         return Err(malformed("missing cpe scheme prefix"));
      }

      if format != "2.3" {
         return Err(malformed("unsupported CPE version"));
      }

      let kind = match part.as_str() {
         "a" => Part::Application,
         "o" => Part::OperatingSystem,
         "h" => Part::Hardware,
         _ => return Err(malformed("unknown part")),
      };

      let unescape = |component: &str| {
         let mut characters = component.chars();
         let mut literal = String::new();

         while let Some(character) = characters.next() {
            if character == '\\' {
               literal.extend(characters.next());
            } else {
               literal.push(character);
            }
         }

         literal
      };

      Ok(Self {
         text: criteria.to_owned(),
         part: kind,
         vendor: NormalizedName::from(unescape(&vendor).as_str()),
         product: NormalizedName::from(unescape(&product).as_str()),
         version: version.parse()?,
         update: update.parse()?,
         target: Target::from(unescape(&target_sw).as_str()),
         restricted,
      })
   }
}

impl Display for Cpe {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(&self.text)
   }
}

impl Serialize for Cpe {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      serializer.serialize_str(&self.text)
   }
}

impl<'de> Deserialize<'de> for Cpe {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer)?
         .parse()
         .map_err(Decoder::Error::custom)
   }
}

/// CPE text a CNA supplied beside its product claim.
#[derive(Clone, Debug)]
pub enum SuppliedCpe {
   /// A CPE 2.3 formatted string.
   Name(Cpe),
   /// Text this scanner cannot parse, such as a CPE 2.2 URI.
   Unsupported(String),
}

impl SuppliedCpe {
   /// Borrow the parsed name when it identifies software.
   pub const fn software(&self) -> Option<&Cpe> {
      match *self {
         Self::Name(ref cpe) if cpe.software() => Some(cpe),
         Self::Name(_) | Self::Unsupported(_) => None,
      }
   }
}

impl From<String> for SuppliedCpe {
   fn from(text: String) -> Self {
      text.parse().map_or(Self::Unsupported(text), Self::Name)
   }
}

impl Serialize for SuppliedCpe {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      match *self {
         Self::Name(ref cpe) => cpe.serialize(serializer),
         Self::Unsupported(ref text) => serializer.serialize_str(text),
      }
   }
}

impl<'de> Deserialize<'de> for SuppliedCpe {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer).map(Self::from)
   }
}
