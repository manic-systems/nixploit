//! Validated identifiers shared by advisories, findings, and configuration.

use std::{
   fmt::{Display, Formatter, Result as FormatResult},
   str::FromStr,
};

use misstep::Report;
use rusqlite::{
   Result as SqlResult, ToSql,
   types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// A CVE or OSV-style `PREFIX-rest` vulnerability identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VulnerabilityId(String);

impl VulnerabilityId {
   /// Reports whether a CNA assigned this identifier as a CVE.
   pub fn is_cve(&self) -> bool {
      self.0.starts_with("CVE-")
   }

   /// Finds CVE identifiers embedded in free text such as patch file names.
   pub fn find_cves(text: &str) -> Vec<Self> {
      let uppercase = text.to_ascii_uppercase();

      uppercase
         .match_indices("CVE-")
         .filter_map(|(index, _prefix)| {
            let digits = uppercase
               .get(index + 9..)?
               .bytes()
               .take_while(u8::is_ascii_digit)
               .count();

            uppercase
               .get(index..index + 9 + digits)?
               .parse::<Self>()
               .ok()
               .filter(Self::is_cve)
         })
         .collect()
   }
}

impl FromStr for VulnerabilityId {
   type Err = Report;

   fn from_str(value: &str) -> Result<Self, Report> {
      let valid = match value.split_once('-') {
         Some(("CVE", rest)) => rest.split_once('-').is_some_and(|(year, number)| {
            year.len() == 4
               && number.len() >= 4
               && year
                  .bytes()
                  .chain(number.bytes())
                  .all(|byte| byte.is_ascii_digit())
         }),
         Some((prefix, rest)) => {
            prefix.len() >= 2
               && prefix.bytes().all(|byte| byte.is_ascii_uppercase())
               && !rest.is_empty()
               && rest.bytes().all(|byte| {
                  byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
               })
         }
         None => false,
      };

      if valid {
         Ok(Self(value.to_owned()))
      } else {
         Err(Report::msg(format!(
            "Invalid vulnerability identifier {value}"
         )))
      }
   }
}

impl Display for VulnerabilityId {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(&self.0)
   }
}

impl AsRef<str> for VulnerabilityId {
   fn as_ref(&self) -> &str {
      &self.0
   }
}

impl Serialize for VulnerabilityId {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      serializer.serialize_str(&self.0)
   }
}

impl<'de> Deserialize<'de> for VulnerabilityId {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer)?
         .parse()
         .map_err(Decoder::Error::custom)
   }
}

impl ToSql for VulnerabilityId {
   fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
      self.0.to_sql()
   }
}

impl FromSql for VulnerabilityId {
   fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
      String::column_result(value)?
         .parse()
         .map_err(|error: Report| FromSqlError::Other(error.to_string().into()))
   }
}

/// A product or vendor name folded into the form advisories are compared in.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedName(String);

impl NormalizedName {
   /// Reports whether the name stands in for an unnamed product or vendor.
   pub fn is_placeholder(&self) -> bool {
      matches!(
         self.0.as_str(),
         "" | "n/a" | "na" | "*" | "-" | "unknown" | "unspecified" | "not-applicable"
      )
   }
}

impl From<&str> for NormalizedName {
   fn from(name: &str) -> Self {
      Self(name.trim().to_lowercase().replace(['_', ' '], "-"))
   }
}

impl Display for NormalizedName {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(&self.0)
   }
}

impl AsRef<str> for NormalizedName {
   fn as_ref(&self) -> &str {
      &self.0
   }
}

impl<'de> Deserialize<'de> for NormalizedName {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      Ok(Self::from(String::deserialize(deserializer)?.as_str()))
   }
}

impl ToSql for NormalizedName {
   fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
      self.0.to_sql()
   }
}
