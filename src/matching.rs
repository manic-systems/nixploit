use std::{collections::BTreeSet, iter};

use hmac_sha256::Hash;
use misstep::Result;
use serde::{Deserialize, Serialize};

use crate::{
   advisory::{
      AffectedProduct, AffectedSource, AffectedVersion, Cvss, Ecosystem, Namespace, Vulnerability,
      cpe::{Conditions, Configuration, Cpe, CpeMatch},
   },
   config::Config,
   database::Database,
   digest::Sha256,
   identifier::{NormalizedName, VulnerabilityId},
   identity::{Attribution, Identity},
   inventory::{Package, VersionOrigin},
   kbuild::BuildScope,
   source::SourceUrl,
   version::{CommitPolicy, Match, ProductKind},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
/// Classifies the certainty of a vulnerability finding.
pub enum Bucket {
   /// Marks evidence that establishes an affected package.
   Affected,
   /// Marks evidence whose applicability cannot be established.
   Unknown,
}

#[derive(Serialize)]
/// Describes one vulnerability finding for an installed package.
pub struct Finding {
   /// Names the installed package.
   pub package: String,
   /// Records the installed package version.
   pub version: String,
   /// Names the installed derivation when available.
   pub derivation: Option<String>,
   /// Retains the store outputs needed to inspect inferred package metadata.
   pub store_paths: BTreeSet<String>,
   /// Distinguishes inferred names from derivation attributes during review.
   pub metadata: VersionOrigin,
   /// Retains source provenance used to resolve advisory identity conflicts.
   pub source_urls: BTreeSet<SourceUrl>,
   /// Identifies the vulnerability, preferring its CVE.
   pub id: VulnerabilityId,
   /// Other identifiers naming the same vulnerability.
   pub aliases: BTreeSet<VulnerabilityId>,
   /// Classifies the finding certainty.
   pub bucket: Bucket,
   /// Records the preferred severity score when available.
   pub cvss: Option<Cvss>,
   /// Reports whether the vulnerability is known to be exploited.
   pub known_exploited: bool,
   /// Reports whether a recognized party disputes the vulnerability.
   pub disputed: bool,
   /// Describes the vulnerability.
   pub description: String,
   /// Records the advisory claims supporting the finding.
   pub evidence: Vec<Evidence>,
   /// Lists the version ranges copied from the evidence.
   pub raw_ranges: Vec<String>,
   /// Identifies the stable set of advisory claims.
   pub fingerprint: Sha256,
   /// Explains why the finding is suppressed when applicable.
   pub suppression: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Records an advisory claim that applies to an installed package.
pub enum Evidence {
   /// Records evidence derived from a CPE match.
   Cpe {
      /// Names the advisory data source.
      source: String,
      /// Records the CPE match criteria.
      criteria: CpeMatch,
      /// Records additional CPE applicability conditions.
      conditions: Conditions,
      /// Retains the configuration whose restrictions must be reviewed together.
      configuration: Option<Configuration>,
      /// Classifies the evidence certainty.
      bucket: Bucket,
      /// Explains the evidence classification.
      reason: String,
   },
   /// Records evidence derived from CNA affected-product data.
   Cna {
      /// Names the advisory data source.
      source: String,
      /// Reports whether the source issued the advisory.
      primary: bool,
      /// Records the affected-product claim.
      affected: AffectedProduct,
      /// Classifies the evidence certainty.
      bucket: Bucket,
      /// Explains the evidence classification.
      reason: String,
   },
   /// Records evidence derived from an OSV ecosystem package claim.
   Osv {
      /// Names the OSV record.
      source: String,
      /// Names the ecosystem qualifying the package.
      ecosystem: Ecosystem,
      /// Records the affected-package claim.
      affected: AffectedProduct,
      /// Classifies the evidence certainty.
      bucket: Bucket,
      /// Explains the evidence classification.
      reason: String,
   },
}

impl Evidence {
   /// Serializes the stable claim fields used by fingerprints.
   fn encoded_claim(&self) -> Result<String> {
      Ok(match *self {
         Self::Cpe {
            ref source,
            ref criteria,
            ref conditions,
            ref configuration,
            bucket,
            ..
         } => serde_json::to_string(&("cpe", source, criteria, conditions, configuration, bucket))?,
         Self::Cna {
            ref source,
            primary,
            ref affected,
            bucket,
            ..
         } => serde_json::to_string(&("cna", source, primary, affected, bucket))?,
         Self::Osv {
            ref source,
            ecosystem,
            ref affected,
            bucket,
            ..
         } => serde_json::to_string(&("osv", source, ecosystem, affected, bucket))?,
      })
   }

   /// Returns the certainty assigned to this evidence.
   const fn bucket(&self) -> Bucket {
      match *self {
         Self::Cpe { bucket, .. } | Self::Cna { bucket, .. } | Self::Osv { bucket, .. } => bucket,
      }
   }

   /// Leaves CPE matches for review when the assigning CNA's own version data
   /// excludes the installed version, since NVD often widens CPE ranges from
   /// description prose.
   fn defer_to_cna(&mut self) {
      if let Self::Cpe {
         ref mut bucket,
         ref mut reason,
         ..
      } = *self
         && *bucket == Bucket::Affected
      {
         *bucket = Bucket::Unknown;
         "The CPE version rule includes the installed version but the assigning \
          CNA's version data excludes it"
            .clone_into(reason);
      }
   }

   /// Returns the raw version ranges represented by this evidence.
   fn ranges(&self) -> Vec<String> {
      match *self {
         Self::Cna { ref affected, .. } | Self::Osv { ref affected, .. } => affected
            .versions
            .iter()
            .flat_map(|entry| {
               iter::once(&entry.version)
                  .chain(&entry.less_than)
                  .chain(&entry.less_than_or_equal)
                  .chain(entry.changes.iter().map(|change| &change.at))
                  .cloned()
            })
            .collect(),
         Self::Cpe { ref criteria, .. } => iter::once(&criteria.criteria)
            .chain(&criteria.version_start_including)
            .chain(&criteria.version_start_excluding)
            .chain(&criteria.version_end_including)
            .chain(&criteria.version_end_excluding)
            .cloned()
            .collect(),
      }
   }
}

/// Finds advisory evidence that applies to an installed package.
#[expect(
   clippy::little_endian_bytes,
   reason = "Evidence fingerprints encode claim lengths in little endian"
)]
pub fn scan_package(
   database: &Database,
   package: &Package,
   config: &Config,
) -> Result<Vec<Finding>> {
   let mut identity = Identity::new(package, config);
   let candidates = database.candidates(&identity.names)?;
   identity.ambiguous = candidates.ambiguous_products;
   let mut findings = Vec::new();

   for vulnerability in candidates.vulnerabilities {
      let mut collected = Vec::new();
      let mut analysis = Analysis::default();
      collect_cpes(&vulnerability, &identity, &mut analysis, &mut collected);

      if collect_claims(&vulnerability, package, &identity, analysis, &mut collected) {
         for entry in &mut collected {
            entry.defer_to_cna();
         }
      }

      let mut encoded = collected
         .into_iter()
         .map(|entry| Ok((entry.encoded_claim()?, entry)))
         .collect::<Result<Vec<_>>>()?;

      encoded.sort_by(|left, right| left.0.cmp(&right.0));
      encoded.dedup_by(|left, right| left.0 == right.0);

      if encoded.is_empty() {
         continue;
      }

      let mut hasher = Hash::new();

      for entry in &encoded {
         let serialized = &entry.0;
         let length = u64::try_from(serialized.len())?;
         hasher.update(length.to_le_bytes());
         hasher.update(serialized);
      }

      let evidence = encoded
         .into_iter()
         .map(|(_serialized, entry)| entry)
         .collect::<Vec<_>>();

      let raw_ranges = evidence
         .iter()
         .flat_map(Evidence::ranges)
         .collect::<BTreeSet<_>>()
         .into_iter()
         .collect();

      let bucket = if !vulnerability.disputed
         && evidence
            .iter()
            .any(|entry| entry.bucket() == Bucket::Affected)
      {
         Bucket::Affected
      } else {
         Bucket::Unknown
      };

      let mut finding = Finding {
         package: package.name.clone(),
         version: package.version.clone(),
         derivation: package.derivation.clone(),
         store_paths: package.store_paths.clone(),
         metadata: package.metadata,
         source_urls: package.source_urls.clone(),
         id: vulnerability.id,
         aliases: vulnerability.aliases,
         bucket,
         cvss: vulnerability.cvss,
         known_exploited: vulnerability.known_exploited,
         disputed: vulnerability.disputed,
         description: vulnerability.description,
         evidence,
         raw_ranges,
         fingerprint: Sha256::from(hasher.finalize()),
         suppression: None,
      };

      finding.suppression = if iter::once(&finding.id)
         .chain(&finding.aliases)
         .any(|identifier| package.patches.contains(identifier))
      {
         Some("CVE identifier appears in the derivation's patches".to_owned())
      } else if config
         .kernel_scope(package)
         .is_some_and(|scope| unbuilt(scope, &finding.evidence))
      {
         Some("The kernel configuration builds none of the files the fix touches".to_owned())
      } else {
         config.ignored(&finding).map(str::to_owned)
      };

      findings.push(finding);
   }

   Ok(findings)
}

/// Reports whether the CNA claims name source files and Kbuild compiles
/// none of them.
fn unbuilt(scope: &BuildScope, evidence: &[Evidence]) -> bool {
   let mut files = evidence
      .iter()
      .filter_map(|entry| match *entry {
         Evidence::Cna { ref affected, .. } => Some(&affected.program_files),
         Evidence::Cpe { .. } | Evidence::Osv { .. } => None,
      })
      .flatten()
      .peekable();

   files.peek().is_some() && files.all(|file| scope.builds(file) == Match::No)
}

/// What NVD's CPE analysis establishes about the installed package.
#[derive(Clone, Copy, Default)]
struct Analysis {
   /// A CPE naming the package's product decides the installed version.
   decided: bool,
   /// A CPE names the product for the package's platform and collection.
   placed: bool,
   /// A CPE names the product for another platform or collection.
   elsewhere: bool,
}

/// Collects matching evidence from every source's CPE data. `VulnCheck`
/// derives CPEs from product names and drops NVD's target software, so its
/// CPEs only speak for products NVD's analysis does not place.
fn collect_cpes(
   vulnerability: &Vulnerability,
   identity: &Identity<'_>,
   analysis: &mut Analysis,
   evidence: &mut Vec<Evidence>,
) {
   let cpes = &vulnerability.claims.cpes;
   let analyst = cpes.iter().filter(|source| source.source == "nvd");
   let supplemental = cpes.iter().filter(|source| source.source != "nvd");

   for source in analyst.chain(supplemental) {
      if source.source != "nvd" && (analysis.placed || analysis.elsewhere) {
         break;
      }

      for configuration in &source.configurations {
         let conditions = configuration.conditions();

         for node in &configuration.nodes {
            node.visit(
               &mut |entry, restricted| {
                  collect_cpe(
                     &source.source,
                     entry,
                     restricted,
                     Some(configuration),
                     identity,
                     analysis,
                     evidence,
                  );
               },
               conditions,
            );
         }
      }

      if !source.configurations.is_empty() {
         continue;
      }

      for criteria in &source.vulnerable_cpes {
         collect_cpe(
            &source.source,
            &CpeMatch::from(criteria.as_str()),
            Conditions::default(),
            None,
            identity,
            analysis,
            evidence,
         );
      }
   }
}

/// Collects matching evidence from CNA and OSV affected-product data,
/// reporting whether the assigning CNA excludes the installed version. NVD
/// analysts translate CNA prose into CPEs, so claims whose versions cannot be
/// evaluated defer to CPE analysis that decides the installed version, and
/// claims about a product NVD places only in another collection describe
/// that product.
fn collect_claims(
   vulnerability: &Vulnerability,
   package: &Package,
   identity: &Identity<'_>,
   analysis: Analysis,
   evidence: &mut Vec<Evidence>,
) -> bool {
   let distributions = !vulnerability.claims.names_upstream(&identity.names);
   let mut claims = Vec::new();
   let mut settled = false;
   let mut decided = false;

   for source in &vulnerability.claims.affected {
      if let Some(ecosystem) = source.ecosystem {
         collect_osv(source, ecosystem, package, identity, evidence);
         continue;
      }

      let primary = vulnerability.source_identifier.as_deref() == Some(source.source.as_str());

      for product in &source.affected_data {
         if !identity.names_claim(product)
            || analysis.elsewhere && !analysis.placed
            || !distributions && Namespace::of(source, product) == Namespace::Distribution
         {
            continue;
         }

         let (verdict, found) = cna_claim(source, primary, product, package, identity);
         settled |= primary && verdict != Verdict::Open;
         decided |= primary && verdict == Verdict::Decided;

         if !analysis.decided || verdict != Verdict::Open {
            claims.extend(found);
         }
      }
   }

   // CISA's ADP container restates kernel CNA ranges as one product per
   // range with an affected default and drops the open-ended fixed release,
   // so contributors only speak where the assigning CNA leaves the version
   // open.
   let primary_claims = |entry: &Evidence| matches!(*entry, Evidence::Cna { primary: true, .. });
   let excluded = decided && !claims.iter().any(primary_claims);

   evidence.extend(
      claims
         .into_iter()
         .filter(|entry| !settled || primary_claims(entry)),
   );
   excluded
}

/// What one CNA product claim establishes about the installed package.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Verdict {
   /// The claim leaves the installed version open.
   Open,
   /// The claim describes another product or package collection.
   Foreign,
   /// The claim decides whether the installed version is affected.
   Decided,
}

/// Evaluates one CNA product claim, reporting what it establishes alongside
/// the evidence it contributes.
fn cna_claim(
   source: &AffectedSource,
   primary: bool,
   product: &AffectedProduct,
   package: &Package,
   identity: &Identity<'_>,
) -> (Verdict, Option<Evidence>) {
   let identity_conflict = match identity.cna(source, product) {
      Attribution::Consistent => None,
      Attribution::Doubtful(reason) => Some(reason),
      Attribution::Foreign => return (Verdict::Foreign, None),
   };

   let parallel_releases = source.affected_data.iter().any(|other| {
      NormalizedName::from(other.vendor.as_str()) == NormalizedName::from(product.vendor.as_str())
         && NormalizedName::from(other.product.as_str())
            == NormalizedName::from(product.product.as_str())
         && other.package_name == product.package_name
         && other.collection_url == product.collection_url
         && other.platforms == product.platforms
         && other.versions.iter().any(AffectedVersion::is_release)
   });

   let kernel = primary
      && NormalizedName::from(product.vendor.as_str()).as_ref() == "linux"
      && NormalizedName::from(product.product.as_str()).as_ref() == "linux";

   let unverified_version = package.metadata.version_uncertain();
   let version_match = product.matches_version(
      if unverified_version {
         None
      } else {
         Some(package.version.as_str())
      },
      if parallel_releases {
         CommitPolicy::SkipForRelease
      } else {
         CommitPolicy::Evaluate
      },
      if kernel {
         ProductKind::Kernel
      } else {
         ProductKind::Generic
      },
   );
   let platform = product.platform(package.system.as_deref());
   let verdict = if identity_conflict.is_none()
      && (version_match == Match::No
         || platform == Match::No
         || version_match == Match::Yes && platform == Match::Yes)
   {
      Verdict::Decided
   } else {
      Verdict::Open
   };

   if version_match == Match::No || platform == Match::No {
      return (verdict, None);
   }

   let matched = version_match
      & platform
      & if identity_conflict.is_some() {
         Match::Unknown
      } else {
         Match::Yes
      };

   let reason = identity_conflict.unwrap_or_else(|| {
      if unverified_version {
         "The package name does not establish a software version from the \
          available metadata"
      } else if platform == Match::Unknown {
         "The CNA platform restriction cannot be established from this \
          inventory"
      } else if matched == Match::Unknown {
         "The CNA version range or affected status cannot be established"
      } else {
         "The CNA version rule includes the installed version"
      }
   });

   (
      verdict,
      Some(Evidence::Cna {
         source: source.source.clone(),
         primary,
         affected: product.to_owned(),
         bucket: if matched == Match::Yes {
            Bucket::Affected
         } else {
            Bucket::Unknown
         },
         reason: reason.to_owned(),
      }),
   )
}

/// Collects OSV package claims whose ecosystem the installed package can belong to.
fn collect_osv(
   source: &AffectedSource,
   ecosystem: Ecosystem,
   package: &Package,
   identity: &Identity<'_>,
   evidence: &mut Vec<Evidence>,
) {
   for product in &source.affected_data {
      if !identity
         .names
         .contains(&NormalizedName::from(product.product.as_str()))
      {
         continue;
      }

      let membership = identity.ecosystem(ecosystem);

      if membership == Match::No {
         continue;
      }

      let unverified_version = package.metadata.version_uncertain();
      let version_match = product.matches_version(
         (!unverified_version).then_some(package.version.as_str()),
         CommitPolicy::Evaluate,
         ProductKind::Generic,
      );

      if version_match == Match::No {
         continue;
      }

      let matched = version_match & membership;
      let reason = if unverified_version {
         "The package name does not establish a software version from the available metadata"
      } else if membership == Match::Unknown {
         "The package ecosystem cannot be established from this inventory"
      } else if matched == Match::Unknown {
         "The OSV version range cannot be compared with the installed version"
      } else {
         "The OSV version range includes the installed version"
      };

      evidence.push(Evidence::Osv {
         source: source.source.clone(),
         ecosystem,
         affected: product.to_owned(),
         bucket: if matched == Match::Yes {
            Bucket::Affected
         } else {
            Bucket::Unknown
         },
         reason: reason.to_owned(),
      });
   }
}

/// Collects one applicable CPE claim as evidence and records what it
/// establishes about the package.
fn collect_cpe(
   source: &str,
   entry: &CpeMatch,
   conditions: Conditions,
   configuration: Option<&Configuration>,
   identity: &Identity<'_>,
   analysis: &mut Analysis,
   evidence: &mut Vec<Evidence>,
) {
   let package = identity.package;

   if !entry.vulnerable {
      return;
   }

   let Ok(cpe) = entry.criteria.parse::<Cpe>() else {
      return;
   };

   if !identity.names.contains(cpe.product()) {
      return;
   }

   if identity.target_conflict(cpe.target_sw()) {
      analysis.elsewhere = true;
      return;
   }

   let identity_conflict = match identity.cpe(&cpe) {
      Attribution::Consistent => None,
      Attribution::Doubtful(reason) => Some(reason),
      Attribution::Foreign => return,
   };
   analysis.placed = true;
   let mut matched = entry.matches_version(&package.version, &cpe);

   let unverified_version = package.metadata.version_uncertain();

   if unverified_version {
      matched = Match::Unknown;
   }

   if conditions.negated {
      matched = Match::Unknown;
   }

   analysis.decided |= identity_conflict.is_none()
      && (matched == Match::No
         || matched == Match::Yes && !conditions.additional && !cpe.restricted());

   if matched == Match::No {
      return;
   }

   let bucket = if matched == Match::Yes
      && !conditions.additional
      && !cpe.restricted()
      && identity_conflict.is_none()
   {
      Bucket::Affected
   } else {
      Bucket::Unknown
   };

   let reason = identity_conflict.unwrap_or_else(|| {
      if unverified_version {
         "The package name does not establish a software version from the \
          available metadata"
      } else if conditions.additional || conditions.negated || cpe.restricted() {
         "The CPE has additional platform or configuration requirements"
      } else if matched == Match::Unknown {
         "The CPE version rule cannot be compared with the installed version"
      } else {
         "The CPE version rule includes the installed version"
      }
   });

   evidence.push(Evidence::Cpe {
      source: source.to_owned(),
      criteria: entry.to_owned(),
      conditions,
      configuration: configuration
         .filter(|_| conditions.additional || conditions.negated)
         .cloned(),
      bucket,
      reason: reason.to_owned(),
   });
}
