//! Provider-neutral advisory records and the claims they carry.

#![expect(
   clippy::mod_module_files,
   reason = "self_named_module_files also warns, and oversized modules split into folders"
)]

pub mod cpe;

use std::{
   collections::BTreeSet,
   fmt::{Display, Formatter, Result as FormatResult},
   str::FromStr,
};

use jiff::{Timestamp, civil::DateTime, tz::Offset};
use misstep::{Report, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{
   advisory::cpe::{Conditions, Configuration, Cpe},
   identifier::{NormalizedName, VulnerabilityId},
   source::{Collection, SourceUrl},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// A validated advisory revision time normalized to UTC.
pub struct AdvisoryTimestamp(Timestamp);

impl FromStr for AdvisoryTimestamp {
   type Err = Report;

   fn from_str(value: &str) -> Result<Self> {
      let timestamp = match value.parse::<Timestamp>() {
         Ok(timestamp) => timestamp,
         Err(offset_error) => {
            let datetime =
               DateTime::strptime("%Y-%m-%dT%H:%M:%S%.f", value).map_err(|datetime_error| {
                  Report::msg(format!(
                     "Invalid advisory timestamp {value:?}, {offset_error}, \
                      offsetless parse also failed, {datetime_error}"
                  ))
               })?;

            Offset::UTC.to_timestamp(datetime)?
         }
      };
      let canonical = format!("{timestamp:.9}");
      let four_digit_year = canonical.len() == 30
         && canonical.as_bytes()[..4].iter().all(u8::is_ascii_digit)
         && canonical.as_bytes()[4] == b'-';

      ensure!(
         four_digit_year,
         "Advisory timestamp normalizes outside four-digit UTC years"
      );

      Ok(Self(timestamp))
   }
}

impl Display for AdvisoryTimestamp {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f \
                parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      write!(formatter, "{:.9}", self.0)
   }
}

impl Serialize for AdvisoryTimestamp {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      serializer.collect_str(self)
   }
}

impl<'de> Deserialize<'de> for AdvisoryTimestamp {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer)?
         .parse()
         .map_err(Decoder::Error::custom)
   }
}

/// Package ecosystems whose OSV records use upstream release versions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Ecosystem {
   /// The Python Package Index.
   PyPi,
   /// The npm registry.
   Npm,
   /// The Rust crate registry.
   CratesIo,
   /// Go modules.
   Go,
}

impl Ecosystem {
   /// Every ecosystem refreshed when an update names none.
   pub const ALL: [Self; 4] = [Self::PyPi, Self::Npm, Self::CratesIo, Self::Go];

   /// Names the package collection shared with registry URLs and Nix builders.
   pub const fn collection(self) -> Collection {
      match self {
         Self::PyPi => Collection::Python,
         Self::Npm => Collection::NodeJs,
         Self::CratesIo => Collection::Rust,
         Self::Go => Collection::Go,
      }
   }

   /// Selects the version ordering used by this ecosystem's ranges.
   pub const fn version_type(self) -> VersionType {
      match self {
         Self::PyPi => VersionType::Python,
         Self::Npm | Self::CratesIo | Self::Go => VersionType::Semver,
      }
   }
}

impl FromStr for Ecosystem {
   type Err = Report;

   fn from_str(value: &str) -> Result<Self> {
      Self::ALL
         .into_iter()
         .find(|ecosystem| ecosystem.to_string() == value)
         .ok_or_else(|| Report::msg(format!("Unsupported ecosystem {value}")))
   }
}

pound::from_str!(Ecosystem);

impl Display for Ecosystem {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(match *self {
         Self::PyPi => "PyPI",
         Self::Npm => "npm",
         Self::CratesIo => "crates.io",
         Self::Go => "Go",
      })
   }
}

impl Serialize for Ecosystem {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      serializer.collect_str(self)
   }
}

impl<'de> Deserialize<'de> for Ecosystem {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer)?
         .parse()
         .map_err(Decoder::Error::custom)
   }
}

#[derive(Debug, Deserialize, Serialize)]
/// One provider record normalized into source-tagged claims.
pub struct Advisory {
   /// Identifier of the record within its provider.
   pub id: VulnerabilityId,
   /// Vulnerability identifiers this record describes.
   pub vulnerabilities: BTreeSet<VulnerabilityId>,
   /// Provider timestamp for the most recent record revision.
   pub modified: AdvisoryTimestamp,
   /// Whether the publisher rejected or withdrew this record.
   pub rejected: bool,
   /// Advisory source identifier when the provider supplies one.
   pub source_identifier: Option<String>,
   /// Human readable descriptions keyed by language.
   pub descriptions: Vec<Description>,
   /// CVSS metrics grouped by metric version.
   pub metrics: Metrics,
   /// Whether CISA lists the vulnerability as known exploited.
   pub known_exploited: bool,
   /// Whether a party the CVE program recognizes disputes the vulnerability.
   pub disputed: bool,
   /// CPE and product claims grouped by source.
   pub claims: Claims,
}

impl Advisory {
   /// Return the English description or an empty string.
   fn description(&self) -> &str {
      self
         .descriptions
         .iter()
         .find(|entry| entry.lang == "en")
         .map_or("", |entry| entry.value.as_str())
   }
}

#[derive(Debug, Default, Deserialize, Serialize)]
/// CPE and product claims, each group labeled by the source that made it.
pub struct Claims {
   /// CPE claims grouped by the source that analyzed them.
   pub cpes: Vec<CpeSource>,
   /// Product claims grouped by the source that published them.
   pub affected: Vec<AffectedSource>,
}

impl Claims {
   /// Collect product names from CPE and product claims.
   pub fn products(&self) -> BTreeSet<NormalizedName> {
      let mut products = BTreeSet::new();

      self.visit(&mut |product, _vendor, _namespace| {
         if !product.is_placeholder() {
            products.insert(product.clone());
         }
      });

      products
   }

   /// Collect vendor identities from CPE and CNA claims, where ecosystem
   /// package names carry no vendor and distribution package names carry the
   /// distributor's.
   pub fn product_vendors(&self) -> BTreeSet<(NormalizedName, NormalizedName)> {
      let mut vendors = BTreeSet::new();

      self.visit(&mut |product, vendor, namespace| {
         if namespace == Namespace::Upstream
            && !product.is_placeholder()
            && !vendor.is_placeholder()
         {
            vendors.insert((product.clone(), vendor.clone()));
         }
      });

      vendors
   }

   /// Whether a claim outside distribution packaging names one of the
   /// products, since distribution rebuilds only speak for a package when
   /// nothing describes the upstream release it was built from.
   pub fn names_upstream(&self, names: &BTreeSet<NormalizedName>) -> bool {
      let mut upstream = false;

      self.visit(&mut |product, _vendor, namespace| {
         upstream |= namespace != Namespace::Distribution && names.contains(product);
      });

      upstream
   }

   /// Adds groups from an older record whose source labels are not held yet.
   fn absorb(&mut self, older: Self) {
      // VulnCheck NVD++ records repeat NVD's CPE and CNA claims under the
      // same source labels, so the newest record carrying a label supplies it.
      for source in older.cpes {
         if !self.cpes.iter().any(|kept| kept.source == source.source) {
            self.cpes.push(source);
         }
      }

      for source in older.affected {
         if !self
            .affected
            .iter()
            .any(|kept| kept.source == source.source && kept.ecosystem == source.ecosystem)
         {
            self.affected.push(source);
         }
      }
   }

   /// Visits every claimed product with its vendor and the namespace
   /// qualifying the name.
   fn visit(&self, visit: &mut impl FnMut(&NormalizedName, &NormalizedName, Namespace)) {
      for source in &self.cpes {
         for configuration in &source.configurations {
            for node in &configuration.nodes {
               node.visit(
                  &mut |entry, _conditions| {
                     if entry.vulnerable
                        && let Ok(cpe) = entry.criteria.parse::<Cpe>()
                     {
                        visit(cpe.product(), cpe.vendor(), Namespace::Upstream);
                     }
                  },
                  Conditions::default(),
               );
            }
         }

         for criteria in &source.vulnerable_cpes {
            if let Ok(cpe) = criteria.parse::<Cpe>() {
               visit(cpe.product(), cpe.vendor(), Namespace::Upstream);
            }
         }
      }

      for source in &self.affected {
         for product in &source.affected_data {
            let vendor = NormalizedName::from(product.vendor.as_str());
            let namespace = Namespace::of(source, product);

            visit(
               &NormalizedName::from(product.product.as_str()),
               &vendor,
               namespace,
            );

            if let Some(name) = product.package_name.as_deref() {
               visit(&NormalizedName::from(name), &vendor, namespace);
            }

            for criteria in &product.cpes {
               if let Ok(cpe) = criteria.parse::<Cpe>() {
                  visit(cpe.product(), cpe.vendor(), namespace);
               }
            }
         }
      }
   }
}

#[derive(Debug, Deserialize, Serialize)]
/// CPE configurations published by one analyzing source.
pub struct CpeSource {
   /// Name of the source that assigned these CPEs.
   pub source: String,
   /// Logical CPE configuration trees.
   pub configurations: Vec<Configuration>,
   /// Flat vulnerable CPE criteria without configuration context.
   pub vulnerable_cpes: Vec<String>,
}

/// Claims from every cached record describing one vulnerability.
pub struct Vulnerability {
   /// Identifier used for findings and ignore rules.
   pub id: VulnerabilityId,
   /// Other identifiers naming the same vulnerability.
   pub aliases: BTreeSet<VulnerabilityId>,
   /// Assigning source used to recognize primary CNA claims.
   pub source_identifier: Option<String>,
   /// English description from the most authoritative record.
   pub description: String,
   /// Preferred severity score from the most authoritative record.
   pub cvss: Option<Cvss>,
   /// Whether any record marks the vulnerability as known exploited.
   pub known_exploited: bool,
   /// Whether any record marks the vulnerability as disputed.
   pub disputed: bool,
   /// Claims keeping one copy per source label.
   pub claims: Claims,
}

impl Vulnerability {
   /// Merges records ordered newest first, returning nothing when the
   /// vulnerability's own record is rejected.
   pub fn merge(id: VulnerabilityId, mut records: Vec<Advisory>) -> Option<Self> {
      records.sort_by_key(|record| record.id != id);

      if records
         .first()
         .is_none_or(|record| record.id == id && record.rejected)
      {
         return None;
      }

      let mut vulnerability = Self {
         id,
         aliases: BTreeSet::new(),
         source_identifier: None,
         description: String::new(),
         cvss: None,
         known_exploited: false,
         disputed: false,
         claims: Claims::default(),
      };

      for record in records.into_iter().filter(|record| !record.rejected) {
         if vulnerability.description.is_empty() {
            record
               .description()
               .clone_into(&mut vulnerability.description);
         }

         if vulnerability.cvss.is_none() {
            vulnerability.cvss = record.metrics.preferred().cloned();
         }

         vulnerability.known_exploited |= record.known_exploited;
         vulnerability.disputed |= record.disputed;
         vulnerability.source_identifier =
            vulnerability.source_identifier.or(record.source_identifier);
         vulnerability.claims.absorb(record.claims);
         vulnerability.aliases.extend(record.vulnerabilities);
         vulnerability.aliases.insert(record.id);
      }

      vulnerability.aliases.remove(&vulnerability.id);
      Some(vulnerability)
   }
}

#[derive(Debug, Deserialize, Serialize)]
/// Localized advisory text with its language tag.
pub struct Description {
   /// Language tag for the description text.
   pub lang: String,
   /// Advisory description in the tagged language.
   pub value: String,
}

/// Distribution product names that CNAs pair with the rebuilt package's
/// name.
const DISTRIBUTIONS: [&str; 6] = [
   "ubuntu",
   "debian",
   "red-hat-enterprise-linux",
   "fedora",
   "suse-linux-enterprise",
   "opensuse",
];

/// Package namespace in which a claim names its product.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Namespace {
   /// The product as its upstream project releases it.
   Upstream,
   /// A language ecosystem package.
   Ecosystem,
   /// A distribution's rebuild of the package.
   Distribution,
}

impl Namespace {
   /// Classifies one product of a source's claims.
   pub fn of(source: &AffectedSource, product: &AffectedProduct) -> Self {
      let distribution = NormalizedName::from(product.product.as_str());

      if source.ecosystem.is_some() {
         Self::Ecosystem
      } else if DISTRIBUTIONS
         .iter()
         .any(|name| distribution.as_ref().starts_with(name))
         || product
            .collection_url
            .as_deref()
            .and_then(|url| url.parse::<SourceUrl>().ok())
            .is_some_and(|url| url.distribution())
      {
         Self::Distribution
      } else {
         Self::Upstream
      }
   }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// Affected products grouped by publishing source.
pub struct AffectedSource {
   /// Name of the CNA, contributor, or OSV record publishing these products.
   pub source: String,
   #[serde(default)]
   /// Ecosystem qualifying package names from OSV records.
   pub ecosystem: Option<Ecosystem>,
   /// Affected products supplied by this source.
   pub affected_data: Vec<AffectedProduct>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// Single product affected record from a CNA source.
pub struct AffectedProduct {
   #[serde(default)]
   /// Vendor name reported for the affected product.
   pub vendor: String,
   #[serde(default)]
   /// Product name reported for the affected product.
   pub product: String,
   #[serde(default)]
   /// Package name when it differs from the product name.
   pub package_name: Option<String>,
   #[serde(default, rename = "collectionURL")]
   /// Package collection URL identifying the product source.
   pub collection_url: Option<String>,
   #[serde(default)]
   /// Default status applied when no version entry matches.
   pub default_status: Status,
   #[serde(default)]
   /// Explicit version ranges for this product.
   pub versions: Vec<AffectedVersion>,
   #[serde(default)]
   /// Platform constraints supplied for this product.
   pub platforms: Vec<String>,
   #[serde(default)]
   /// CPE criteria supplied alongside the product record.
   pub cpes: Vec<String>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
   /// Source files the fix touches, as kernel.org records them.
   pub program_files: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
/// Version status reported for an affected product range.
pub enum Status {
   /// Product is affected in this version range.
   Affected,
   /// Product is unaffected in this version range.
   Unaffected,
   #[default]
   /// Status is unknown when the source gives no verdict.
   Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// Version range entry with lifecycle and upper bound fields.
pub struct AffectedVersion {
   /// Base version introducing this status entry.
   pub version: String,
   /// Status applying from the base version onward.
   pub status: Status,
   #[serde(default)]
   /// Versioning scheme used for range comparison.
   pub version_type: Option<VersionType>,
   #[serde(default)]
   /// Exclusive upper bound for this status entry.
   pub less_than: Option<String>,
   #[serde(default)]
   /// Inclusive upper bound for this status entry.
   pub less_than_or_equal: Option<String>,
   #[serde(default)]
   /// Status changes within this version range.
   pub changes: Vec<StatusChange>,
}

/// Version ordering named by a CVE record's `versionType`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionType {
   /// Dotted numeric releases with common prerelease markers.
   Custom,
   /// Releases recorded by the Linux kernel CNA next to fixing commits.
   OriginalCommitForFix,
   /// Semantic versioning.
   Semver,
   /// Nix `builtins.compareVersions` ordering.
   Nix,
   /// Python package versions from PEP 440.
   Python,
   /// Git commit hashes.
   Git,
   /// A scheme without a supported ordering, such as `rpm` or `maven`.
   Other(String),
}

impl From<String> for VersionType {
   fn from(text: String) -> Self {
      match text.as_str() {
         "custom" => Self::Custom,
         "original_commit_for_fix" => Self::OriginalCommitForFix,
         "semver" => Self::Semver,
         "nix" => Self::Nix,
         "python" => Self::Python,
         "git" => Self::Git,
         _ => Self::Other(text),
      }
   }
}

impl Display for VersionType {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(match *self {
         Self::Custom => "custom",
         Self::OriginalCommitForFix => "original_commit_for_fix",
         Self::Semver => "semver",
         Self::Nix => "nix",
         Self::Python => "python",
         Self::Git => "git",
         Self::Other(ref text) => text,
      })
   }
}

impl Serialize for VersionType {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      serializer.collect_str(self)
   }
}

impl<'de> Deserialize<'de> for VersionType {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer).map(Self::from)
   }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// Status change recorded at a specific version.
pub struct StatusChange {
   /// Version where the status change takes effect.
   pub at: String,
   /// New status applying from that version onward.
   pub status: Status,
}

#[derive(Debug, Default, Deserialize, Serialize)]
/// CVSS metric collections grouped by metric version.
pub struct Metrics {
   #[serde(default, rename = "cvssMetricV40")]
   /// CVSS 4.0 metric entries.
   pub v40: Vec<Metric>,
   #[serde(default, rename = "cvssMetricV31")]
   /// CVSS 3.1 metric entries.
   pub v31: Vec<Metric>,
   #[serde(default, rename = "cvssMetricV30")]
   /// CVSS 3.0 metric entries.
   pub v30: Vec<Metric>,
   #[serde(default, rename = "cvssMetricV2")]
   /// CVSS 2.0 metric entries.
   pub v20: Vec<Metric>,
}

impl Metrics {
   /// Select the newest available primary CVSS score.
   pub fn preferred(&self) -> Option<&Cvss> {
      [&self.v40, &self.v31, &self.v30, &self.v20]
         .into_iter()
         .find_map(|metrics| {
            metrics
               .iter()
               .find(|metric| {
                  metric.kind == MetricKind::Primary && metric.cvss_data.score().is_some()
               })
               .or_else(|| {
                  metrics
                     .iter()
                     .find(|metric| metric.cvss_data.score().is_some())
               })
               .map(|metric| &metric.cvss_data)
         })
   }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// CVSS metric wrapper with source type and score data.
pub struct Metric {
   #[serde(default, rename = "type")]
   /// Whether the NVD or another source supplied the score.
   pub kind: MetricKind,
   /// CVSS score data for this metric entry.
   pub cvss_data: Cvss,
}

/// Role of the source that scored a CVSS metric.
#[derive(Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum MetricKind {
   /// The record's primary scoring source.
   Primary,
   /// An additional scoring source.
   Secondary,
   /// A missing or unrecognized source role.
   #[default]
   #[serde(other)]
   Other,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// CVSS score with version base score and vector.
pub struct Cvss {
   /// CVSS specification version for this score.
   pub version: String,
   /// Numeric CVSS base score.
   pub base_score: f64,
   #[serde(default)]
   /// CVSS vector describing the scored attributes.
   pub vector_string: String,
}

impl Cvss {
   /// Excludes invalid upstream scores without discarding the advisory.
   pub fn score(&self) -> Option<f64> {
      (self.base_score.is_finite() && (0.0_f64..=10.0_f64).contains(&self.base_score))
         .then_some(self.base_score)
   }
}
