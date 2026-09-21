use std::{
   collections::BTreeMap,
   fmt::{Display, Formatter, Result as FormatResult},
   fs,
   io::Write as _,
   os::unix::fs::PermissionsExt as _,
   path::Path,
};

use jiff::Timestamp;
use misstep::Result;
use prometheus::{
   Encoder as _, Gauge, GaugeVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
   core::Collector,
};

use crate::{advisory::Cvss, matching::Finding, output::Report};

/// Deduplicated state for one package vulnerability.
#[derive(Default)]
struct Aggregate {
   /// Highest valid CVSS score reported for the finding.
   score: Option<f64>,
   /// Whether any derivation marks the finding as known exploited.
   known_exploited: bool,
}

/// Severity labels used by aggregate finding metrics, most severe first.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum Severity {
   /// CVSS score at least 9.0.
   Critical,
   /// CVSS score at least 7.0.
   High,
   /// CVSS score at least 4.0.
   Medium,
   /// Positive CVSS score below 4.0.
   Low,
   /// CVSS score equal to zero.
   None,
   /// Finding without a CVSS score.
   Unscored,
}

/// Classifies an optional CVSS score.
impl From<Option<f64>> for Severity {
   fn from(score: Option<f64>) -> Self {
      match score {
         Some(value) if value >= 9.0 => Self::Critical,
         Some(value) if value >= 7.0 => Self::High,
         Some(value) if value >= 4.0 => Self::Medium,
         Some(value) if value > 0.0 => Self::Low,
         Some(_) => Self::None,
         None => Self::Unscored,
      }
   }
}

impl Severity {
   /// Every label, so severities without findings still publish a zero.
   const ALL: [Self; 6] = [
      Self::Critical,
      Self::High,
      Self::Medium,
      Self::Low,
      Self::None,
      Self::Unscored,
   ];
}

impl Display for Severity {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(match *self {
         Self::Critical => "critical",
         Self::High => "high",
         Self::Medium => "medium",
         Self::Low => "low",
         Self::None => "none",
         Self::Unscored => "unscored",
      })
   }
}

/// Prometheus collectors for one completed report.
struct Metrics {
   /// Finding counts by report bucket and severity.
   findings: IntGaugeVec,
   /// Known exploited finding counts by report bucket.
   known_exploited: IntGaugeVec,
   /// Scanned package count.
   scanned_packages: IntGauge,
   /// Skipped path count.
   skipped_paths: IntGauge,
   /// Missing derivation count.
   missing_derivations: IntGauge,
   /// Inventory collection duration.
   inventory_duration: Gauge,
   /// Deduplicated finding identities.
   finding_info: IntGaugeVec,
   /// Available CVSS scores.
   vulnerability_score: GaugeVec,
   /// Completed scan timestamp.
   last_success: IntGauge,
   /// Feed check timestamps.
   feed_checked: IntGaugeVec,
   /// Makes missing freshness state observable without a feed label.
   active_feeds: IntGauge,
}

impl Metrics {
   /// Creates the fixed collector set.
   fn new() -> Result<Self> {
      Ok(Self {
         findings: IntGaugeVec::new(
            Opts::new(
               "nixploit_findings",
               "Distinct package vulnerabilities by report bucket and \
                severity.",
            ),
            &["bucket", "severity"],
         )?,
         known_exploited: IntGaugeVec::new(
            Opts::new(
               "nixploit_known_exploited_findings",
               "Distinct known exploited package vulnerabilities by report \
                bucket.",
            ),
            &["bucket"],
         )?,
         scanned_packages: IntGauge::new(
            "nixploit_scanned_packages",
            "Number of packages in the scanned inventory.",
         )?,
         skipped_paths: IntGauge::new(
            "nixploit_skipped_paths",
            "Number of paths without usable package metadata.",
         )?,
         missing_derivations: IntGauge::new(
            "nixploit_missing_derivations",
            "Number of outputs without derivation metadata.",
         )?,
         inventory_duration: Gauge::new(
            "nixploit_inventory_duration_seconds",
            "Time spent collecting the package inventory.",
         )?,
         finding_info: IntGaugeVec::new(
            Opts::new(
               "nixploit_finding_info",
               "Identity and classification of a distinct package \
                vulnerability.",
            ),
            &[
               "bucket",
               "package",
               "version",
               "vulnerability",
               "severity",
               "known_exploited",
            ],
         )?,
         vulnerability_score: GaugeVec::new(
            Opts::new(
               "nixploit_vulnerability_score",
               "Highest available CVSS base score for a distinct package \
                vulnerability.",
            ),
            &["bucket", "package", "version", "vulnerability"],
         )?,
         last_success: IntGauge::new(
            "nixploit_last_success_timestamp_seconds",
            "Unix timestamp of the completed scan.",
         )?,
         feed_checked: IntGaugeVec::new(
            Opts::new(
               "nixploit_feed_checked_timestamp_seconds",
               "Unix timestamp of the last successful check for a feed.",
            ),
            &["feed"],
         )?,
         active_feeds: IntGauge::new(
            "nixploit_active_feeds",
            "Number of feeds whose retained records have completed checks.",
         )?,
      })
   }

   /// Populates collectors from a completed report.
   fn populate(&self, report: &Report) -> Result<()> {
      self
         .scanned_packages
         .set(i64::try_from(report.scanned_packages)?);
      self
         .skipped_paths
         .set(i64::try_from(report.skipped_paths.len())?);
      self
         .missing_derivations
         .set(i64::try_from(report.missing_derivations.len())?);
      self
         .inventory_duration
         .set(report.inventory_duration_seconds);
      self.last_success.set(Timestamp::now().as_second());
      self.active_feeds.set(i64::try_from(
         report
            .database
            .feeds
            .iter()
            .filter(|feed| feed.checked_at > 0)
            .count(),
      )?);

      for feed in &report.database.feeds {
         self
            .feed_checked
            .with_label_values(&[&feed.name])
            .set(feed.checked_at);
      }

      self.populate_bucket("affected", &report.affected)?;
      self.populate_bucket("unknown", &report.unknown)?;
      self.populate_bucket("suppressed", &report.suppressed)?;
      Ok(())
   }

   /// Populates metrics for one report bucket.
   fn populate_bucket(&self, bucket: &str, findings: &[Finding]) -> Result<()> {
      let mut aggregates = BTreeMap::new();

      for finding in findings {
         let aggregate = aggregates
            .entry((
               finding.package.as_str(),
               finding.version.as_str(),
               finding.id.as_ref(),
            ))
            .or_insert_with(Aggregate::default);

         if let Some(score) = finding.cvss.as_ref().and_then(Cvss::score) {
            aggregate.score = Some(aggregate.score.map_or(score, |current| current.max(score)));
         }

         aggregate.known_exploited |= finding.known_exploited;
      }

      let mut severity_counts = BTreeMap::<Severity, usize>::new();
      let mut known_exploited_count = 0_usize;

      for ((package, version, vulnerability), aggregate) in aggregates {
         let severity = Severity::from(aggregate.score);
         *severity_counts.entry(severity).or_default() += 1;
         known_exploited_count += usize::from(aggregate.known_exploited);

         self
            .finding_info
            .with_label_values(&[
               bucket,
               package,
               version,
               vulnerability,
               &severity.to_string(),
               if aggregate.known_exploited {
                  "true"
               } else {
                  "false"
               },
            ])
            .set(1);

         if let Some(score) = aggregate.score {
            self
               .vulnerability_score
               .with_label_values(&[bucket, package, version, vulnerability])
               .set(score);
         }
      }

      for severity in Severity::ALL {
         let count = severity_counts.get(&severity).copied().unwrap_or_default();

         self
            .findings
            .with_label_values(&[bucket, &severity.to_string()])
            .set(i64::try_from(count)?);
      }

      self
         .known_exploited
         .with_label_values(&[bucket])
         .set(i64::try_from(known_exploited_count)?);
      Ok(())
   }

   /// Registers and encodes all populated collectors.
   fn encode(self) -> Result<Vec<u8>> {
      let registry = Registry::new();
      let collectors: [Box<dyn Collector>; 11] = [
         Box::new(self.findings),
         Box::new(self.known_exploited),
         Box::new(self.scanned_packages),
         Box::new(self.skipped_paths),
         Box::new(self.missing_derivations),
         Box::new(self.inventory_duration),
         Box::new(self.finding_info),
         Box::new(self.vulnerability_score),
         Box::new(self.last_success),
         Box::new(self.feed_checked),
         Box::new(self.active_feeds),
      ];

      for collector in collectors {
         registry.register(collector)?;
      }

      let mut encoded = Vec::new();
      TextEncoder::new().encode(&registry.gather(), &mut encoded)?;
      Ok(encoded)
   }
}

/// Atomically writes a completed report in Prometheus text format.
pub fn write(report: &Report, path: &Path) -> Result<()> {
   let metrics = Metrics::new()?;
   metrics.populate(report)?;
   let encoded = metrics.encode()?;
   let mut temporary = tempfile::Builder::new()
      .prefix(".nixploit-")
      .suffix(".tmp")
      .tempfile_in(
         path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
      )?;

   temporary
      .as_file()
      .set_permissions(fs::Permissions::from_mode(0o644))?;
   temporary.write_all(&encoded)?;
   temporary.as_file_mut().sync_all()?;
   temporary.persist(path)?;
   Ok(())
}
