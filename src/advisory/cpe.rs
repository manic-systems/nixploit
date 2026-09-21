//! CPE configuration trees and CPE 2.3 names.

use std::{
   fmt::{Display, Formatter, Result as FormatResult},
   mem,
   str::FromStr,
};

use misstep::{Report, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::identifier::NormalizedName;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// CPE match entry with optional version range bounds.
pub struct CpeMatch {
   /// Whether this CPE entry marks the product as vulnerable.
   pub vulnerable: bool,
   /// CPE formatted string identifying the matched product.
   pub criteria: String,
   #[serde(default)]
   /// Inclusive lower bound for the affected version range.
   pub version_start_including: Option<String>,
   #[serde(default)]
   /// Exclusive lower bound for the affected version range.
   pub version_start_excluding: Option<String>,
   #[serde(default)]
   /// Inclusive upper bound for the affected version range.
   pub version_end_including: Option<String>,
   #[serde(default)]
   /// Exclusive upper bound for the affected version range.
   pub version_end_excluding: Option<String>,
}

impl From<&str> for CpeMatch {
   /// Treats a bare vulnerable CPE as a match entry without version bounds.
   fn from(criteria: &str) -> Self {
      Self {
         vulnerable: true,
         criteria: criteria.to_owned(),
         version_start_including: None,
         version_start_excluding: None,
         version_end_including: None,
         version_end_excluding: None,
      }
   }
}

#[derive(Debug)]
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
         _ => {}
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

#[derive(Debug)]
/// Parsed CPE identity with vendor product and version fields.
pub struct Cpe {
   /// CPE vendor component.
   vendor: NormalizedName,
   /// CPE product component.
   product: NormalizedName,
   /// CPE version component.
   version: CpeValue,
   /// CPE update component.
   update: CpeValue,
   /// Target software identifies platform and package collection constraints.
   target_sw: String,
   /// Whether platform fields narrow this CPE beyond wildcards.
   restricted: bool,
}

impl Cpe {
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

   /// Borrow the CPE target software component.
   pub fn target_sw(&self) -> &str {
      &self.target_sw
   }

   /// Report whether platform fields narrow this CPE beyond wildcards.
   pub const fn restricted(&self) -> bool {
      self.restricted
   }
}

impl FromStr for Cpe {
   type Err = Report;

   /// Parse CPE 2.3 application or operating system criteria.
   fn from_str(criteria: &str) -> Result<Self, Report> {
      let malformed = |reason: &str| Report::msg(format!("Malformed CPE {criteria} ({reason})"));
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

      if !matches!(part.as_str(), "a" | "o") {
         return Err(malformed(
            "only application and operating system parts are supported",
         ));
      }

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
         vendor: NormalizedName::from(unescape(&vendor).as_str()),
         product: NormalizedName::from(unescape(&product).as_str()),
         version: version.parse()?,
         update: update.parse()?,
         target_sw: unescape(&target_sw),
         restricted,
      })
   }
}
