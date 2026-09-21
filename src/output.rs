use std::{
   collections::BTreeSet,
   io::{self, Error, Write},
};

use jiff::Timestamp;
use serde::Serialize;

use crate::{
   database::Stats,
   inventory::VersionOrigin,
   matching::{Evidence, Finding},
};

#[derive(Serialize)]
/// Scan report grouped into affected unknown and suppressed findings.
pub struct Report {
   /// Number of scanned packages covered by this report.
   pub scanned_packages: usize,
   /// Paths skipped because no package version was found.
   pub skipped_paths: BTreeSet<String>,
   /// Outputs missing derivation metadata during inventory.
   pub missing_derivations: BTreeSet<String>,
   /// Time spent collecting the package inventory.
   pub inventory_duration_seconds: f64,
   /// Database statistics for the imported CVE feeds.
   pub database: Stats,
   /// Findings with evidence of an affected version.
   pub affected: Vec<Finding>,
   /// Findings needing review because evidence was inconclusive.
   pub unknown: Vec<Finding>,
   /// Findings suppressed by configuration ignore rules.
   pub suppressed: Vec<Finding>,
}

impl Report {
   /// Sort each finding bucket by severity and identity.
   pub fn sort(&mut self) {
      for bucket in [&mut self.affected, &mut self.unknown, &mut self.suppressed] {
         bucket.sort_by(|left, right| {
            right
               .known_exploited
               .cmp(&left.known_exploited)
               .then_with(|| {
                  right
                     .cvss
                     .as_ref()
                     .map_or(0.0_f64, |score| score.base_score)
                     .total_cmp(&left.cvss.as_ref().map_or(0.0_f64, |score| score.base_score))
               })
               .then_with(|| {
                  (&left.package, &left.version, &left.id, &left.derivation).cmp(&(
                     &right.package,
                     &right.version,
                     &right.id,
                     &right.derivation,
                  ))
               })
         });
      }
   }

   /// Write the human readable report to the supplied writer.
   pub fn write<Writer>(
      &self,
      writer: &mut Writer,
      descriptions: bool,
      show_suppressed: bool,
   ) -> io::Result<()>
   where
      Writer: Write,
   {
      writeln!(
         writer,
         "{} packages scanned against {} cached vulnerabilities",
         self.scanned_packages, self.database.vulnerabilities
      )?;
      writeln!(
         writer,
         "{} affected, {} unknown, {} suppressed",
         self.affected.len(),
         self.unknown.len(),
         self.suppressed.len()
      )?;

      if !self.skipped_paths.is_empty() || !self.missing_derivations.is_empty() {
         writeln!(
            writer,
            "{} paths without package versions, {} outputs without derivation \
             metadata",
            self.skipped_paths.len(),
            self.missing_derivations.len()
         )?;
      }

      if let Some(oldest) = self
         .database
         .feeds
         .iter()
         .map(|feed| feed.checked_at)
         .min()
         .filter(|checked| *checked > 0)
      {
         let age = Timestamp::now().as_second().saturating_sub(oldest) / 86400;
         writeln!(
            writer,
            "Oldest feed check was {age} days ago. Use stats to inspect \
             imported coverage"
         )?;
      } else {
         writeln!(
            writer,
            "Some cached advisories lack a completed feed check. Refresh \
             their feeds to establish freshness"
         )?;
      }

      writeln!(writer, "\nAffected\n")?;

      if self.affected.is_empty() {
         writeln!(
            writer,
            "No affected versions matched the imported advisories"
         )?;
      }

      for finding in &self.affected {
         write_finding(writer, finding, descriptions, false)?;
      }

      if !self.unknown.is_empty() {
         writeln!(writer, "\nUnknown\n")?;
         writeln!(
            writer,
            "These product matches need review and do not set the exit \
             status\n"
         )?;

         for finding in &self.unknown {
            write_finding(writer, finding, descriptions, true)?;
         }
      }

      if show_suppressed && !self.suppressed.is_empty() {
         writeln!(writer, "\nSuppressed\n")?;

         for finding in &self.suppressed {
            write_finding(writer, finding, descriptions, false)?;
         }
      }

      Ok(())
   }
}

/// Write one finding in the human-readable report format.
fn write_finding<Writer>(
   writer: &mut Writer,
   finding: &Finding,
   descriptions: bool,
   ranges: bool,
) -> io::Result<()>
where
   Writer: Write,
{
   write!(
      writer,
      "{} {}  {}",
      finding.package, finding.version, finding.id
   )?;

   if let Some(score) = finding.cvss.as_ref() {
      write!(writer, "  CVSS {} {:.1}", score.version, score.base_score)?;
   }

   if finding.known_exploited {
      write!(writer, "  KEV")?;
   }

   if finding.disputed {
      write!(writer, "  Disputed")?;
   }

   writeln!(writer)?;
   if finding.id.is_cve() {
      writeln!(writer, "  https://nvd.nist.gov/vuln/detail/{}", finding.id)?;
   } else {
      writeln!(writer, "  https://osv.dev/vulnerability/{}", finding.id)?;
   }

   if !finding.aliases.is_empty() {
      let aliases = finding
         .aliases
         .iter()
         .map(AsRef::as_ref)
         .collect::<Vec<&str>>();

      writeln!(writer, "  Also {}", aliases.join(", "))?;
   }

   if let Some(derivation) = finding.derivation.as_ref() {
      writeln!(writer, "  {derivation}")?;
   }

   if finding.metadata != VersionOrigin::Declared {
      writeln!(writer, "  Package metadata inferred from a store name")?;

      for path in &finding.store_paths {
         writeln!(writer, "  {path}")?;
      }
   }

   if ranges {
      for evidence in &finding.evidence {
         let (label, source, affected, reason) = match *evidence {
            Evidence::Cna {
               ref source,
               primary,
               ref affected,
               ref reason,
               ..
            } => (
               if primary { "CNA" } else { "Contributor" },
               source,
               affected,
               reason,
            ),
            Evidence::Osv {
               ref source,
               ref affected,
               ref reason,
               ..
            } => ("OSV", source, affected, reason),
            Evidence::Cpe {
               ref source,
               ref criteria,
               ref reason,
               ..
            } => {
               writeln!(writer, "  CPE {source}  {reason}")?;
               writeln!(
                  writer,
                  "    {}",
                  serde_json::to_string(criteria).map_err(Error::other)?
               )?;
               continue;
            }
         };

         writeln!(
            writer,
            "  {label} {source}  {}  {}",
            affected.vendor, affected.product
         )?;
         writeln!(writer, "  {reason}")?;

         if affected.versions.is_empty() {
            writeln!(writer, "    No version data supplied")?;
         }

         for entry in &affected.versions {
            writeln!(
               writer,
               "    {}",
               serde_json::to_string(entry).map_err(Error::other)?
            )?;
         }
      }

      writeln!(writer, "  fingerprint = \"{}\"", finding.fingerprint)?;
   }

   if descriptions {
      writeln!(writer, "  {}", finding.description)?;
   }

   if let Some(reason) = finding.suppression.as_ref() {
      writeln!(writer, "  {reason}")?;
   }

   writeln!(writer)
}
