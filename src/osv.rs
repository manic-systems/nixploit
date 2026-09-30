//! OSV schema records from the per-ecosystem vulnerability dumps.

use std::{
   collections::BTreeSet,
   fmt::{Display, Formatter, Result as FormatResult},
   str::FromStr,
};

use misstep::{Report, Result};
use serde::{Deserialize, de::IgnoredAny};

use crate::{
   advisory::{
      Advisory, AdvisoryTimestamp, AffectedProduct, AffectedSource, AffectedVersion, Claims,
      CommitRange, CommitSource, Description, Ecosystem, Metrics, Status,
   },
   identifier::VulnerabilityId,
};

/// One per-ecosystem dump in the OSV bucket.
#[derive(Clone, Copy)]
pub enum Dump {
   /// A package ecosystem's records.
   Ecosystem(Ecosystem),
   /// Records naming only repositories and their fixing commits.
   Git,
}

impl Dump {
   /// Every dump refreshed when an update names none.
   pub const ALL: [Self; 5] = [
      Self::Ecosystem(Ecosystem::PyPi),
      Self::Ecosystem(Ecosystem::Npm),
      Self::Ecosystem(Ecosystem::CratesIo),
      Self::Ecosystem(Ecosystem::Go),
      Self::Git,
   ];
}

impl FromStr for Dump {
   type Err = Report;

   fn from_str(value: &str) -> Result<Self> {
      if value == "GIT" {
         Ok(Self::Git)
      } else {
         value.parse().map(Self::Ecosystem)
      }
   }
}

pound::from_str!(Dump);

impl Display for Dump {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      match *self {
         Self::Ecosystem(ecosystem) => ecosystem.fmt(formatter),
         Self::Git => formatter.write_str("GIT"),
      }
   }
}

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
   #[serde(default)]
   /// Repository whose commits a GIT range names.
   repo: Option<String>,
   /// Events in ascending version order.
   events: Vec<Event>,
}

impl Range {
   /// Collects the commits of a GIT range. An introduction at `0` means the
   /// whole history is affected.
   fn commits(&self) -> Option<CommitRange> {
      if self.kind != RangeKind::Git {
         return None;
      }

      let mut commits = CommitRange {
         repository: self.repo.clone()?,
         introduced: Vec::new(),
         fixed: Vec::new(),
         last_affected: Vec::new(),
      };
      let mut origin = false;

      for event in &self.events {
         match *event {
            Event::Introduced(ref commit) if commit == "0" => origin = true,
            Event::Introduced(ref commit) => commits.introduced.push(commit.clone()),
            Event::Fixed(ref commit) => commits.fixed.push(commit.clone()),
            Event::LastAffected(ref commit) => commits.last_affected.push(commit.clone()),
            Event::Limit(_) => {}
         }
      }

      if origin {
         commits.introduced.clear();
      }

      Some(commits)
   }
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

      let ranges = record
         .affected
         .iter()
         .flat_map(|entry| &entry.ranges)
         .filter_map(Range::commits)
         .collect::<Vec<_>>();
      let commits = if ranges.is_empty() {
         Vec::new()
      } else {
         vec![CommitSource {
            source: record.id.to_string(),
            ranges,
         }]
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
            commits,
         },
      }
   }
}
