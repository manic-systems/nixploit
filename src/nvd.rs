//! NVD 2.0 and `VulnCheck` NVD++ feed shapes.

use std::{
   collections::BTreeSet,
   fmt::{self, Formatter},
   slice::Iter,
};

use misstep::Result;
use serde::{
   Deserialize, Deserializer,
   de::{
      DeserializeSeed, Error, IgnoredAny, MapAccess, SeqAccess, Visitor,
      value::{BorrowedStrDeserializer, MapAccessDeserializer},
   },
};
use serde_json::value::RawValue;

use crate::{
   advisory::{
      Advisory, AdvisoryTimestamp, AffectedSource, Claims, CpeSource, Description, Metrics,
      cpe::Configuration,
   },
   feed::FeedPage,
   identifier::VulnerabilityId,
};

/// One CVE as NVD and `VulnCheck` publish it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cve {
   /// CVE identifier.
   id: VulnerabilityId,
   #[serde(default)]
   /// Assigning CNA identifier.
   source_identifier: Option<String>,
   /// Timestamp of the most recent revision.
   last_modified: AdvisoryTimestamp,
   #[serde(default)]
   /// NVD analysis status including rejected records.
   vuln_status: String,
   #[serde(default)]
   /// Human readable descriptions keyed by language.
   descriptions: Vec<Description>,
   #[serde(default)]
   /// NVD CPE configuration trees.
   configurations: Vec<Configuration>,
   #[serde(default, rename = "vcConfigurations")]
   /// `VulnCheck` CPE configuration trees.
   vc_configurations: Vec<Configuration>,
   #[serde(default, rename = "vcVulnerableCPEs")]
   /// `VulnCheck` flat vulnerable CPE criteria.
   vc_vulnerable_cpes: Vec<String>,
   #[serde(default)]
   /// CNA and contributor product claims.
   affected: Vec<AffectedSource>,
   #[serde(default)]
   /// CVSS metrics grouped by metric version.
   metrics: Metrics,
   #[serde(default)]
   /// Date the CVE joined the CISA exploited catalog.
   cisa_exploit_add: Option<String>,
   #[serde(default, rename = "cveTags")]
   /// CVE program tags grouped by the source applying them.
   tags: Vec<CveTags>,
}

/// Tags one source applied to a CVE.
#[derive(Deserialize)]
struct CveTags {
   #[serde(default)]
   /// Tags from the CVE program's fixed vocabulary.
   tags: Vec<Tag>,
}

/// CVE program record tags.
#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Tag {
   /// A recognized party disputes that the issue is a vulnerability.
   Disputed,
   /// The vulnerability exists only in a service the vendor hosts.
   ExclusivelyHostedService,
   /// Tags that do not change applicability.
   #[serde(other)]
   Other,
}

impl From<Cve> for Advisory {
   fn from(cve: Cve) -> Self {
      let mut cpes = Vec::new();

      if !cve.configurations.is_empty() {
         cpes.push(CpeSource {
            source: "nvd".to_owned(),
            configurations: cve.configurations,
            vulnerable_cpes: Vec::new(),
         });
      }

      if !cve.vc_configurations.is_empty() || !cve.vc_vulnerable_cpes.is_empty() {
         cpes.push(CpeSource {
            source: "vulncheck".to_owned(),
            configurations: cve.vc_configurations,
            vulnerable_cpes: cve.vc_vulnerable_cpes,
         });
      }

      let tagged = |wanted| cve.tags.iter().any(|group| group.tags.contains(&wanted));
      let hosted = tagged(Tag::ExclusivelyHostedService);
      let disputed = tagged(Tag::Disputed);

      Self {
         vulnerabilities: BTreeSet::from([cve.id.clone()]),
         id: cve.id,
         modified: cve.last_modified,
         rejected: hosted || cve.vuln_status.eq_ignore_ascii_case("rejected"),
         source_identifier: cve.source_identifier,
         descriptions: cve.descriptions,
         metrics: cve.metrics,
         known_exploited: cve.cisa_exploit_add.is_some(),
         disputed,
         claims: Claims {
            cpes,
            affected: cve.affected,
         },
      }
   }
}

/// Deserializes the supported top-level feed shapes.
pub struct FeedSeed<'callback, Callback> {
   /// Receives each advisory as it is decoded.
   pub consume: &'callback mut Callback,
}

impl<'de, Callback> DeserializeSeed<'de> for FeedSeed<'_, Callback>
where
   Callback: FnMut(Advisory) -> Result<()>,
{
   type Value = FeedPage;

   fn deserialize<Decoder>(self, deserializer: Decoder) -> Result<Self::Value, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      deserializer.deserialize_any(self)
   }
}

impl<'de, Callback> Visitor<'de> for FeedSeed<'_, Callback>
where
   Callback: FnMut(Advisory) -> Result<()>,
{
   type Value = FeedPage;

   fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
      formatter.write_str("an NVD feed, VulnCheck data envelope, or array of CVEs")
   }

   fn visit_map<Mapping>(self, mut map: Mapping) -> Result<Self::Value, Mapping::Error>
   where
      Mapping: MapAccess<'de>,
   {
      let mut count = None;
      let mut expected = None;
      let mut page_size = None;
      let mut start = 0;

      while let Some(key) = map.next_key::<String>()? {
         match key.as_str() {
            "vulnerabilities" | "data" => {
               if count.is_some() {
                  return Err(Error::custom("Duplicate CVE collection"));
               }

               count = Some(map.next_value_seed(RecordsSeed {
                  consume: self.consume,
               })?);
            }
            "totalResults" => expected = Some(map.next_value::<usize>()?),
            "resultsPerPage" => page_size = Some(map.next_value::<usize>()?),
            "startIndex" => start = map.next_value::<usize>()?,
            _ => {
               map.next_value::<IgnoredAny>()?;
            }
         }
      }

      let actual = count.ok_or_else(|| Error::custom("Missing CVE collection"))?;

      if let Some(size) = page_size
         && size != actual
      {
         return Err(Error::custom(format!(
            "Incomplete feed page, expected {size} records and got {actual}"
         )));
      }

      let total = expected.unwrap_or(actual);

      if start > total || actual > total - start {
         return Err(Error::custom("Feed page exceeds totalResults"));
      }

      Ok(FeedPage {
         records: actual,
         start,
         total,
      })
   }

   fn visit_seq<Sequence>(self, seq: Sequence) -> Result<Self::Value, Sequence::Error>
   where
      Sequence: SeqAccess<'de>,
   {
      RecordsSeed {
         consume: self.consume,
      }
      .visit_seq(seq)
      .map(FeedPage::from)
   }
}

/// Deserializes a sequence of advisory records.
struct RecordsSeed<'callback, Callback> {
   /// Receives each advisory as it is decoded.
   consume: &'callback mut Callback,
}

impl<'de, Callback> DeserializeSeed<'de> for RecordsSeed<'_, Callback>
where
   Callback: FnMut(Advisory) -> Result<()>,
{
   type Value = usize;

   fn deserialize<Decoder>(self, deserializer: Decoder) -> Result<usize, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      deserializer.deserialize_seq(self)
   }
}

impl<'de, Callback> Visitor<'de> for RecordsSeed<'_, Callback>
where
   Callback: FnMut(Advisory) -> Result<()>,
{
   type Value = usize;

   fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
      formatter.write_str("an array of CVE records")
   }

   fn visit_seq<Sequence>(self, mut seq: Sequence) -> Result<usize, Sequence::Error>
   where
      Sequence: SeqAccess<'de>,
   {
      let mut count = 0;

      while let Some(raw) = seq.next_element::<Box<RawValue>>().map_err(|error| {
         Error::custom(format!("CVE record {} failed to parse\n{error}", count + 1))
      })? {
         let cve = serde_json::from_str::<Record>(raw.get())
            .map_err(|error| {
               Error::custom(format!("CVE record {} failed to parse\n{error}", count + 1))
            })?
            .0;

         (self.consume)(Advisory::from(cve)).map_err(Error::custom)?;
         count += 1;
      }

      Ok(count)
   }
}

/// A CVE stored directly or under an NVD `cve` envelope.
struct Record(Cve);

impl<'de> Deserialize<'de> for Record {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      deserializer.deserialize_map(RecordVisitor)
   }
}

/// Selects the nested or direct CVE representation.
struct RecordVisitor;

impl<'de> Visitor<'de> for RecordVisitor {
   type Value = Record;

   fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
      formatter.write_str("a CVE advisory or NVD CVE envelope")
   }

   fn visit_map<Mapping>(self, mut map: Mapping) -> Result<Self::Value, Mapping::Error>
   where
      Mapping: MapAccess<'de>,
   {
      let mut fields = Vec::new();

      while let Some(key) = map.next_key::<String>()? {
         if key == "cve" {
            let cve = map.next_value()?;

            while let Some(trailing_key) = map.next_key::<String>()? {
               if trailing_key == "cve" {
                  return Err(Error::duplicate_field("cve"));
               }

               map.next_value::<IgnoredAny>()?;
            }

            return Ok(Record(cve));
         }

         fields.push((key, map.next_value::<Box<RawValue>>()?));
      }

      let cve = Cve::deserialize(MapAccessDeserializer::new(BufferedFields {
         fields: fields.iter(),
         value: None,
      }))
      .map_err(Mapping::Error::custom)?;

      Ok(Record(cve))
   }
}

/// Replays direct CVE fields through serde's map deserializer.
struct BufferedFields<'field> {
   /// Fields retained while checking for an NVD envelope.
   fields: Iter<'field, (String, Box<RawValue>)>,
   /// Value paired with the most recently yielded key.
   value: Option<&'field RawValue>,
}

impl<'de> MapAccess<'de> for BufferedFields<'de> {
   type Error = serde_json::Error;

   fn next_key_seed<Key>(&mut self, seed: Key) -> Result<Option<Key::Value>, Self::Error>
   where
      Key: DeserializeSeed<'de>,
   {
      let Some(field) = self.fields.next() else {
         return Ok(None);
      };

      let key = &field.0;
      self.value = Some(&field.1);
      seed
         .deserialize(BorrowedStrDeserializer::new(key))
         .map(Some)
   }

   fn next_value_seed<Value>(&mut self, seed: Value) -> Result<Value::Value, Self::Error>
   where
      Value: DeserializeSeed<'de>,
   {
      let value = self
         .value
         .take()
         .ok_or_else(|| Error::custom("value requested before key"))?;

      seed.deserialize(value)
   }
}
