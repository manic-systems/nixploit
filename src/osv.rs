//! OSV schema records from the per-ecosystem vulnerability dumps.

use std::collections::BTreeSet;

use serde::{Deserialize, de::IgnoredAny};

use crate::{
   advisory::{
      Advisory, AdvisoryTimestamp, AffectedProduct, AffectedSource, AffectedVersion, Claims,
      Description, Ecosystem, Metrics, Status,
   },
   identifier::VulnerabilityId,
};

/// One OSV vulnerability record.
#[derive(Deserialize)]
pub struct Record {
   /// OSV identifier such as a GHSA or PYSEC id.
   id: VulnerabilityId,
   /// Timestamp of the most recent revision.
   modified: AdvisoryTimestamp,
   #[serde(default)]
   /// Time the record was withdrawn, when it was.
   withdrawn: Option<String>,
   #[serde(default)]
   /// Identifiers of the same vulnerability in other databases.
   aliases: Vec<String>,
   #[serde(default)]
   /// Identifiers this record was derived from.
   upstream: Vec<String>,
   #[serde(default)]
   /// One-line summary.
   summary: String,
   #[serde(default)]
   /// Longer description.
   details: String,
   #[serde(default)]
   /// Affected packages across ecosystems.
   affected: Vec<Affected>,
}

/// One affected package and its version ranges.
#[derive(Deserialize)]
struct Affected {
   #[serde(default)]
   /// Package identity, absent for records that only name repositories.
   package: Option<Package>,
   #[serde(default)]
   /// Version ranges described by ordered events.
   ranges: Vec<Range>,
   #[serde(default)]
   /// Explicitly enumerated affected versions.
   versions: Vec<String>,
}

impl Affected {
   /// Converts a package in a supported ecosystem into a product claim whose
   /// ranges use the ecosystem's ordering.
   fn into_claim(self) -> Option<(Ecosystem, AffectedProduct)> {
      let package = self.package?;
      let ecosystem = package.ecosystem.parse::<Ecosystem>().ok()?;
      let entry = |version: String, less_than, less_than_or_equal| AffectedVersion {
         version,
         status: Status::Affected,
         version_type: Some(ecosystem.version_type()),
         less_than,
         less_than_or_equal,
         changes: Vec::new(),
      };
      let mut versions = Vec::new();

      for range in self
         .ranges
         .into_iter()
         .filter(|range| range.kind != RangeKind::Git)
      {
         let mut introduced = None;

         for event in range.events {
            match event {
               Event::Introduced(version) => introduced = Some(version),
               Event::Fixed(version) => {
                  if let Some(start) = introduced.take() {
                     versions.push(entry(start, Some(version), None));
                  }
               }
               Event::LastAffected(version) => {
                  if let Some(start) = introduced.take() {
                     versions.push(entry(start, None, Some(version)));
                  }
               }
               Event::Limit(_) => {}
            }
         }

         if let Some(start) = introduced {
            versions.push(entry(start, None, Some("*".to_owned())));
         }
      }

      if versions.is_empty() {
         versions = self
            .versions
            .into_iter()
            .map(|version| entry(version, None, None))
            .collect();
      }

      Some((
         ecosystem,
         AffectedProduct {
            vendor: ecosystem.to_string(),
            product: package.name,
            package_name: None,
            collection_url: None,
            default_status: Status::Unaffected,
            versions,
            platforms: Vec::new(),
            cpes: Vec::new(),
            program_files: Vec::new(),
         },
      ))
   }
}

/// Package identity within an ecosystem.
#[derive(Deserialize)]
struct Package {
   /// Ecosystem name, possibly qualified such as `Debian:12`.
   ecosystem: String,
   /// Package name within the ecosystem.
   name: String,
}

/// Ordered introduction and fix events.
#[derive(Deserialize)]
struct Range {
   /// Ordering the events use.
   #[serde(rename = "type")]
   kind: RangeKind,
   /// Events in ascending version order.
   events: Vec<Event>,
}

/// Version ordering named by a range.
#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
enum RangeKind {
   /// Semantic versioning.
   Semver,
   /// The ecosystem's own version ordering.
   Ecosystem,
   /// Commit hashes in a repository.
   Git,
}

/// One boundary within a range.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Event {
   /// First affected version.
   Introduced(String),
   /// First unaffected version after an introduction.
   Fixed(String),
   /// Last affected version of an introduction.
   LastAffected(String),
   /// Upper bound on the search for commits, which only GIT ranges use.
   Limit(IgnoredAny),
}

impl From<Record> for Advisory {
   fn from(record: Record) -> Self {
      let mut identifiers = record
         .aliases
         .iter()
         .chain(&record.upstream)
         .filter_map(|identifier| identifier.parse::<VulnerabilityId>().ok())
         .collect::<BTreeSet<_>>();

      identifiers.insert(record.id.clone());

      let cves = identifiers
         .iter()
         .filter(|identifier| identifier.is_cve())
         .cloned()
         .collect::<BTreeSet<_>>();
      // OSV expects alias lists to be symmetric, so every record in a group
      // without a CVE picks the same smallest identifier.
      let vulnerabilities = if cves.is_empty() {
         identifiers.into_iter().take(1).collect()
      } else {
         cves
      };

      let description = if record.summary.is_empty() {
         record.details
      } else {
         record.summary
      };

      let mut affected = Vec::<AffectedSource>::new();

      for (ecosystem, product) in record.affected.into_iter().filter_map(Affected::into_claim) {
         match affected
            .iter_mut()
            .find(|source| source.ecosystem == Some(ecosystem))
         {
            Some(source) => source.affected_data.push(product),
            None => affected.push(AffectedSource {
               source: record.id.to_string(),
               ecosystem: Some(ecosystem),
               affected_data: vec![product],
            }),
         }
      }

      Self {
         id: record.id,
         vulnerabilities,
         modified: record.modified,
         rejected: record.withdrawn.is_some(),
         source_identifier: None,
         descriptions: vec![Description {
            lang: "en".to_owned(),
            value: description,
         }],
         metrics: Metrics::default(),
         known_exploited: false,
         disputed: false,
         claims: Claims {
            cpes: Vec::new(),
            affected,
         },
      }
   }
}
