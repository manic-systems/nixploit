//! Matches installed package versions against advisory version data.

#![expect(
   clippy::mod_module_files,
   reason = "self_named_module_files also warns, and oversized modules split into folders"
)]

mod nix;
mod pep440;

use std::{
   cmp::Ordering,
   iter,
   ops::{BitAnd, BitOr, Not},
   str::FromStr,
};

use jiff::civil::Date;
use misstep::{Report, ensure};
use semver::Version as SemanticVersion;

use crate::{
   advisory::{
      AffectedProduct, AffectedVersion, Status, VersionType,
      cpe::{Cpe, CpeMatch, CpeValue},
   },
   version::{nix::NixVersion, pep440::Pep440},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Records whether version evidence matches an installed package.
pub enum Match {
   /// The evidence matches.
   Yes,
   /// The evidence does not match.
   No,
   /// The evidence cannot be evaluated conclusively.
   Unknown,
}

impl BitAnd for Match {
   type Output = Self;

   /// Combines two requirements that must both match.
   fn bitand(self, rhs: Self) -> Self {
      match (self, rhs) {
         (Self::No, _) | (_, Self::No) => Self::No,
         (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
         (Self::Yes, Self::Yes) => Self::Yes,
      }
   }
}

impl BitOr for Match {
   type Output = Self;

   /// Combines two alternatives where either may match.
   fn bitor(self, rhs: Self) -> Self {
      match (self, rhs) {
         (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
         (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
         (Self::No, Self::No) => Self::No,
      }
   }
}

impl Not for Match {
   type Output = Self;

   /// Inverts a decided result and leaves an open one open.
   fn not(self) -> Self {
      match self {
         Self::Yes => Self::No,
         Self::No => Self::Yes,
         Self::Unknown => Self::Unknown,
      }
   }
}

impl From<Status> for Match {
   /// Converts an advisory status into a match result.
   fn from(status: Status) -> Self {
      match status {
         Status::Affected => Self::Yes,
         Status::Unaffected => Self::No,
         Status::Unknown => Self::Unknown,
      }
   }
}

/// Selects the ordering supported by a raw advisory version scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
   /// Uses numeric ordering and recognized prerelease markers.
   Custom,
   /// Uses semantic version ordering as declared by the source.
   Semver,
   /// Uses Nix component ordering.
   Nix,
   /// Uses Python package version ordering from PEP 440.
   Python,
   /// Normalizes kernel release candidates before comparison.
   Kernel,
   /// Includes CPE vendor release suffixes.
   Cpe,
   /// Permits exact equality without assuming an ordering.
   Unsupported,
}

impl From<Option<&VersionType>> for Scheme {
   fn from(version_type: Option<&VersionType>) -> Self {
      match version_type {
         None | Some(&(VersionType::Custom | VersionType::OriginalCommitForFix)) => Self::Custom,
         Some(&VersionType::Semver) => Self::Semver,
         Some(&VersionType::Nix) => Self::Nix,
         Some(&VersionType::Python) => Self::Python,
         Some(&(VersionType::Git | VersionType::Other(_))) => Self::Unsupported,
      }
   }
}

impl Scheme {
   /// Binds a version to its comparison scheme.
   const fn version(self, text: &str) -> Version<'_> {
      Version { text, scheme: self }
   }

   /// Reports whether distinct releases can be ordered.
   const fn supports_ordering(self) -> bool {
      !matches!(self, Self::Unsupported)
   }
}

/// Keeps comparison operands within the same version scheme.
#[derive(Clone, Copy, Debug)]
struct Version<'input> {
   /// Original release text retained for uncertain comparisons.
   text: &'input str,
   /// Ordering rules supplied by the advisory context.
   scheme: Scheme,
}

/// Restricts version comparisons to supported operators.
#[derive(Clone, Copy)]
enum Comparison {
   /// Excludes the upper endpoint.
   Less,
   /// Includes the upper endpoint.
   LessEqual,
   /// Excludes the lower endpoint.
   Greater,
   /// Includes the lower endpoint.
   GreaterEqual,
   /// Requires an equivalent version.
   Equal,
}

impl Comparison {
   /// Evaluates a known ordering without an invalid operator fallback.
   const fn accepts(self, ordering: Ordering) -> bool {
      match self {
         Self::Less => matches!(ordering, Ordering::Less),
         Self::LessEqual => !matches!(ordering, Ordering::Greater),
         Self::Greater => matches!(ordering, Ordering::Greater),
         Self::GreaterEqual => !matches!(ordering, Ordering::Less),
         Self::Equal => matches!(ordering, Ordering::Equal),
      }
   }
}

impl PartialEq for Version<'_> {
   fn eq(&self, other: &Self) -> bool {
      self.partial_cmp(other) == Some(Ordering::Equal)
   }
}

impl PartialOrd for Version<'_> {
   /// Compares advisory releases without treating uncertainty as an ordering.
   fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
      if self.scheme != other.scheme {
         return None;
      }

      let left_folded = (self.scheme == Scheme::Cpe).then(|| self.text.to_ascii_lowercase());
      let right_folded = (self.scheme == Scheme::Cpe).then(|| other.text.to_ascii_lowercase());
      let left_trimmed = left_folded.as_deref().unwrap_or(self.text).trim();
      let right_trimmed = right_folded.as_deref().unwrap_or(other.text).trim();

      if left_trimmed == right_trimmed {
         return Some(Ordering::Equal);
      }

      if !self.scheme.supports_ordering() {
         return None;
      }

      if self.scheme == Scheme::Nix {
         return parsed_order::<NixVersion>(left_trimmed, right_trimmed);
      }

      if self.scheme == Scheme::Python {
         return parsed_order::<Pep440>(left_trimmed, right_trimmed);
      }

      let left_clean = left_trimmed.strip_prefix('v').unwrap_or(left_trimmed);
      let right_clean = right_trimmed.strip_prefix('v').unwrap_or(right_trimmed);

      if left_clean == right_clean {
         return Some(Ordering::Equal);
      }

      let calendar_date = |value: &str| {
         matches!(value.as_bytes(), [_, _, _, _, b'-', _, _, b'-', _, _])
            .then(|| Date::strptime("%Y-%m-%d", value).ok())
            .flatten()
      };

      match (calendar_date(left_clean), calendar_date(right_clean)) {
         (Some(left_date), Some(right_date)) => {
            return Some(left_date.cmp(&right_date));
         }
         (Some(_), None) | (None, Some(_)) => return None,
         (None, None) => {}
      }

      if dotted(left_clean) && dotted(right_clean) {
         let mut left_parts = left_clean.split('.');
         let mut right_parts = right_clean.split('.');

         loop {
            let left_next = left_parts.next();
            let right_next = right_parts.next();

            if left_next.is_none() && right_next.is_none() {
               return Some(Ordering::Equal);
            }

            let left_number = left_next.unwrap_or("0").trim_start_matches('0');
            let right_number = right_next.unwrap_or("0").trim_start_matches('0');
            let order = left_number
               .len()
               .cmp(&right_number.len())
               .then_with(|| left_number.cmp(right_number));

            if order != Ordering::Equal {
               return Some(order);
            }
         }
      }

      if self.scheme == Scheme::Kernel {
         return parsed_order::<KernelVersion>(left_clean, right_clean);
      }

      let unhyphenated = matches!(self.scheme, Scheme::Custom | Scheme::Cpe);
      let left_prerelease = unhyphenated
         .then(|| Self::unhyphenated_prerelease(left_clean))
         .flatten();
      let right_prerelease = unhyphenated
         .then(|| Self::unhyphenated_prerelease(right_clean))
         .flatten();

      match (
         self
            .scheme
            .version(left_prerelease.as_deref().unwrap_or(left_clean))
            .semantic(),
         self
            .scheme
            .version(right_prerelease.as_deref().unwrap_or(right_clean))
            .semantic(),
      ) {
         (Some(left_version), Some(right_version)) => {
            Some(left_version.cmp_precedence(&right_version))
         }
         (Some(semantic_version), None) | (None, Some(semantic_version))
            if !semantic_version.pre.is_empty() =>
         {
            None
         }
         _ if left_prerelease.is_some() || right_prerelease.is_some() => None,
         _ if self.scheme == Scheme::Cpe => parsed_order::<CpeRelease>(left_clean, right_clean),
         _ if self.scheme == Scheme::Custom => numbered_release_order(left_clean, right_clean),
         _ => None,
      }
   }
}

impl Version<'_> {
   /// Parses semantic releases without treating vendor patches as prereleases.
   fn semantic(self) -> Option<SemanticVersion> {
      let input = self.text;
      let release_end = input.find(['-', '+']).unwrap_or(input.len());
      let release = input.get(..release_end)?;
      let suffix = input.get(release_end..)?;
      let short = dotted(release) && release.split('.').count() < 3;

      let version = if short {
         let padding = ".0".repeat(3 - release.split('.').count());
         SemanticVersion::parse(&format!("{release}{padding}{suffix}")).ok()
      } else {
         SemanticVersion::parse(input).ok()
      }?;

      if matches!(self.scheme, Scheme::Custom | Scheme::Cpe) && !version.pre.is_empty() {
         let marker = version
            .pre
            .split('.')
            .next()?
            .trim_end_matches(|character: char| character.is_ascii_digit());

         if !matches!(
            marker,
            "alpha" | "beta" | "rc" | "pre" | "preview" | "dev" | "snapshot" | "next"
         ) {
            return None;
         }
      }

      Some(version)
   }

   /// Normalizes prerelease markers written without a hyphen, as CPEs and CNA
   /// custom versions do, before numeric comparison.
   fn unhyphenated_prerelease(input: &str) -> Option<String> {
      let release_end =
         input.find(|character: char| !character.is_ascii_digit() && character != '.')?;
      let release = input.get(..release_end)?;
      let suffix = input.get(release_end..)?;
      let update = suffix
         .strip_prefix('-')
         .or_else(|| suffix.strip_prefix('_'))
         .unwrap_or(suffix);
      let marker_end = update
         .find(|character: char| !character.is_ascii_alphabetic())
         .unwrap_or(update.len());
      let marker = update.get(..marker_end)?.to_ascii_lowercase();

      if !dotted(release) {
         return None;
      }

      let remainder = update.get(marker_end..)?;

      if matches!(marker.as_str(), "a" | "b")
         && !remainder.starts_with(|character: char| character.is_ascii_digit())
      {
         return None;
      }

      let normalized_marker = match marker.as_str() {
         "a" | "alpha" => "alpha",
         "b" | "beta" => "beta",
         "rc" | "pre" | "preview" | "dev" | "snapshot" => marker.as_str(),
         _ => return None,
      };

      let separator = if remainder.starts_with(|character: char| character.is_ascii_digit()) {
         "."
      } else {
         ""
      };
      let padding = ".0".repeat(3_usize.saturating_sub(release.split('.').count()));
      Some(format!(
         "{release}{padding}-{normalized_marker}{separator}{remainder}"
      ))
   }

   /// Evaluates an installed version against a version boundary.
   fn bound(self, endpoint: &str, operator: Comparison) -> Match {
      let installed = self.text;

      if endpoint == "*" && matches!(operator, Comparison::Less | Comparison::LessEqual) {
         return Match::Yes;
      }

      if let Some(prefix) = endpoint.strip_suffix(".*") {
         if !dotted(prefix) || !self.scheme.supports_ordering() {
            return Match::Unknown;
         }

         let components = prefix.split('.').count();

         let installed_prefix = installed
            .split('.')
            .take(components)
            .collect::<Vec<_>>()
            .join(".");

         return match self
            .scheme
            .version(&installed_prefix)
            .partial_cmp(&self.scheme.version(prefix))
         {
            Some(Ordering::Less)
               if matches!(operator, Comparison::Less | Comparison::LessEqual) =>
            {
               Match::Yes
            }
            Some(Ordering::Equal) if matches!(operator, Comparison::LessEqual) => Match::Yes,
            Some(Ordering::Equal | Ordering::Greater)
               if matches!(operator, Comparison::Less | Comparison::LessEqual) =>
            {
               Match::No
            }
            _ => Match::Unknown,
         };
      }

      // nixpkgs names interface wrappers such as lapack-3 after their API
      // level, so a bare major cannot place the build among that major's
      // releases.
      if !installed.is_empty()
         && installed.bytes().all(|byte| byte.is_ascii_digit())
         && endpoint
            .split_once('.')
            .is_some_and(|(major, _)| major == installed)
      {
         return Match::Unknown;
      }

      let Some(order) = self.partial_cmp(&self.scheme.version(endpoint)) else {
         return Match::Unknown;
      };

      if operator.accepts(order) {
         Match::Yes
      } else {
         Match::No
      }
   }

   /// Evaluates an installed version against an advisory version expression.
   fn expression(self, specification: &str) -> Match {
      let installed = self.text;
      let trimmed = specification.trim();

      if unspecified(trimmed) {
         return Match::Unknown;
      }

      if trimmed.contains("||") {
         return trimmed
            .split("||")
            .fold(Match::No, |result, branch| result | self.expression(branch));
      }

      let operators = [
         ("<=", Comparison::LessEqual),
         (">=", Comparison::GreaterEqual),
         ("<", Comparison::Less),
         (">", Comparison::Greater),
         ("=", Comparison::Equal),
         ("before ", Comparison::Less),
         ("prior to ", Comparison::Less),
         ("through ", Comparison::LessEqual),
         ("up to ", Comparison::LessEqual),
      ];

      if trimmed.contains(',') {
         let mut items = trimmed.split(',').map(str::trim).peekable();
         let is_comparison = |item: &str| {
            operators
               .iter()
               .any(|&(prefix, _)| item.starts_with(prefix))
         };
         let conjunction = items.peek().is_some_and(|item| is_comparison(item));
         let mut result = if conjunction { Match::Yes } else { Match::No };

         for item in items {
            if is_comparison(item) != conjunction {
               return Match::Unknown;
            }

            let matched = self.expression(item);
            result = if conjunction {
               result & matched
            } else {
               result | matched
            };
         }

         return result;
      }

      for (prefix, operator) in operators {
         if let Some(endpoint) = trimmed.strip_prefix(prefix) {
            return self.bound(endpoint.trim(), operator);
         }
      }

      if let Some((lower, upper)) = trimmed.split_once(" through ") {
         return self.bound(lower, Comparison::GreaterEqual)
            & self.bound(upper, Comparison::LessEqual);
      }

      if let Some((lower, upper)) = trimmed.split_once(" - ") {
         return self.bound(lower, Comparison::GreaterEqual)
            & self.bound(upper, Comparison::LessEqual);
      }

      if let Some(upper) = trimmed
         .strip_suffix(" and prior")
         .or_else(|| trimmed.strip_suffix(" and earlier"))
      {
         return self.bound(upper, Comparison::LessEqual);
      }

      if let Some(prefix) = trimmed
         .strip_suffix(".*")
         .or_else(|| trimmed.strip_suffix(".x"))
         && dotted(prefix)
         && dotted(installed)
      {
         return if !self.scheme.supports_ordering() {
            Match::Unknown
         } else if installed == prefix || installed.starts_with(&format!("{prefix}.")) {
            Match::Yes
         } else {
            Match::No
         };
      }

      if installed == trimmed {
         return Match::Yes;
      }

      self.bound(trimmed, Comparison::Equal)
   }

   /// Matches an installed version against an exact CPE version value.
   fn cpe_exact(self, criteria: &Cpe) -> Match {
      let installed = self.text;
      let combined = match *criteria.update() {
         CpeValue::Literal(ref update) => {
            let CpeValue::Literal(ref release) = *criteria.version() else {
               return Match::Unknown;
            };

            Some(format!("{release}-{update}"))
         }
         CpeValue::Any | CpeValue::NotApplicable => None,
         CpeValue::Pattern(_) => return Match::Unknown,
      };
      let matched = match *criteria.version() {
         CpeValue::Literal(ref value) => {
            let specified = combined.as_deref().unwrap_or(value);

            if specified.contains(['*', '?']) {
               if installed.eq_ignore_ascii_case(specified) {
                  Match::Yes
               } else {
                  Match::No
               }
            } else {
               self.bound(specified, Comparison::Equal)
            }
         }
         CpeValue::Pattern(ref pattern) => {
            if pattern.strip_suffix(".*").is_some_and(dotted) {
               self.expression(pattern)
            } else {
               Match::Unknown
            }
         }
         CpeValue::Any | CpeValue::NotApplicable => Match::Unknown,
      };

      let CpeValue::Literal(ref version) = *criteria.version() else {
         return matched;
      };

      if matched != Match::No || !matches!(criteria.update(), CpeValue::Any) || !dotted(version) {
         return matched;
      }

      let folded = installed.to_ascii_lowercase();
      let trimmed = folded.trim();
      let cleaned = trimmed.strip_prefix('v').unwrap_or(trimmed);
      let prefix_end = cleaned
         .find(|character: char| !character.is_ascii_digit() && character != '.')
         .unwrap_or(cleaned.len());
      let Some(prefix) = cleaned.get(..prefix_end) else {
         return Match::Unknown;
      };
      let release = prefix.trim_end_matches('.');

      if !dotted(release) {
         return Match::Unknown;
      }

      let Some(suffix) = cleaned.get(prefix_end..) else {
         return Match::Unknown;
      };
      let update = suffix.trim_start_matches(['-', '_']);

      if update.is_empty() {
         return matched;
      }

      let marker = update
         .split('.')
         .next()
         .unwrap_or_default()
         .trim_end_matches(|character: char| character.is_ascii_digit());
      let recognized = (Self::unhyphenated_prerelease(cleaned).is_some()
         || matches!(marker, "p" | "patch" | "sp" | "update" | "u"))
         && update
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.');

      self
         .scheme
         .version(release)
         .bound(version, Comparison::Equal)
         & if recognized {
            Match::Yes
         } else {
            Match::Unknown
         }
   }
}

/// A CPE release with a vendor suffix, ordered by Nix after trailing zero
/// components before a lettered suffix drop so `1.2.0p1` and `1.2p1` name the
/// same release while `7.1.0-29` stays below `7.1.2`.
#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct CpeRelease(NixVersion);

impl FromStr for CpeRelease {
   type Err = Report;

   fn from_str(input: &str) -> Result<Self, Report> {
      let prefix_end = input
         .find(|character: char| !character.is_ascii_digit() && character != '.')
         .unwrap_or(input.len());
      let (prefix, suffix) = input.split_at(prefix_end);

      ensure!(dotted(prefix), "{} has no numeric release", input);

      let mut canonical = prefix;
      let lettered =
         suffix.is_empty() || suffix.starts_with(|character: char| character.is_ascii_alphabetic());

      while lettered && let Some((remaining, component)) = canonical.rsplit_once('.') {
         if component.bytes().any(|digit| digit != b'0') {
            break;
         }

         canonical = remaining;
      }

      Ok(Self(format!("{canonical}{suffix}").parse()?))
   }
}

/// A kernel release or release candidate ordered as semantic versioning.
#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct KernelVersion(SemanticVersion);

impl FromStr for KernelVersion {
   type Err = Report;

   fn from_str(input: &str) -> Result<Self, Report> {
      let (release, candidate) = input
         .split_once("-rc")
         .map_or((input, None), |(release, candidate)| {
            (release, Some(candidate))
         });

      ensure!(
         dotted(release) && release.split('.').count() <= 3,
         "{} is not a kernel release",
         input
      );

      let mut normalized = format!("{release}{}", ".0".repeat(3 - release.split('.').count()));

      if let Some(number) = candidate {
         ensure!(
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()),
            "{} has an invalid release candidate",
            input
         );

         normalized.push_str("-rc.");
         normalized.push_str(number);
      }

      Ok(Self(SemanticVersion::parse(&normalized)?))
   }
}

/// Orders two versions in a scheme with its own parser, or not at all when
/// either side does not parse.
fn parsed_order<Parsed>(left: &str, right: &str) -> Option<Ordering>
where
   Parsed: FromStr + Ord,
{
   Some(left.parse::<Parsed>().ok()?.cmp(&right.parse().ok()?))
}

/// Orders releases with a numeric suffix such as `ImageMagick`'s `7.1.2-31`.
/// Semver reads the suffix as a prerelease and patch-level schemes read it as
/// a later build, but both agree whenever the releases differ or both carry a
/// suffix.
fn numbered_release_order<'text>(left: &'text str, right: &'text str) -> Option<Ordering> {
   let split = |value: &'text str| {
      let (release, suffix) = match value.split_once('-') {
         Some((release, suffix)) => (release, Some(suffix.parse::<u64>().ok()?)),
         None => (value, None),
      };
      dotted(release).then_some((release, suffix))
   };
   let (left_release, left_suffix) = split(left)?;
   let (right_release, right_suffix) = split(right)?;

   match Scheme::Custom
      .version(left_release)
      .partial_cmp(&Scheme::Custom.version(right_release))?
   {
      Ordering::Equal => Some(left_suffix?.cmp(&right_suffix?)),
      order @ (Ordering::Less | Ordering::Greater) => Some(order),
   }
}

/// Reports whether a version contains only dot-separated numbers.
fn dotted(value: &str) -> bool {
   !value.is_empty()
      && value
         .split('.')
         .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Reports whether an expression lacks a specific version.
fn unspecified(expression: &str) -> bool {
   matches!(
      expression.to_ascii_lowercase().as_str(),
      "*" | "0" | "all" | "all versions" | "n/a" | "unspecified" | "-" | "?"
   )
}

/// Recognizes full SHA-1 and SHA-256 commit hashes used in place of versions.
fn is_commit_hash(value: &str) -> bool {
   [40, 64].contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl CpeMatch {
   /// Evaluates CPE release bounds without discarding update restrictions.
   pub fn matches_version(&self, installed: &str, criteria: &Cpe) -> Match {
      let update_restricted = matches!(criteria.version(), CpeValue::Any)
         && !matches!(criteria.update(), CpeValue::Any | CpeValue::NotApplicable);
      let release = match *criteria.update() {
         CpeValue::Literal(ref update) if update_restricted => installed
            .len()
            .checked_sub(update.len())
            .and_then(|start| {
               let _suffix = installed
                  .get(start..)
                  .filter(|suffix| suffix.eq_ignore_ascii_case(update))?;

               installed.get(..start)
            })
            .map(|prefix| prefix.trim_end_matches(['-', '_', '.']))
            .filter(|prefix| {
               dotted(prefix)
                  && update.starts_with(|character: char| character.is_ascii_alphabetic())
            }),
         CpeValue::Any | CpeValue::NotApplicable | CpeValue::Literal(_) | CpeValue::Pattern(_) => {
            None
         }
      };
      let bound_version = if update_restricted {
         release.or_else(|| dotted(installed).then_some(installed))
      } else {
         Some(installed)
      };

      let mut matched = match *criteria.version() {
         CpeValue::Any => {
            if self.version_start_including.is_none()
               && self.version_start_excluding.is_none()
               && self.version_end_including.is_none()
               && self.version_end_excluding.is_none()
            {
               Match::Unknown
            } else {
               Match::Yes
            }
         }
         CpeValue::NotApplicable => Match::Unknown,
         CpeValue::Literal(_) | CpeValue::Pattern(_) => {
            Scheme::Cpe.version(installed).cpe_exact(criteria)
         }
      };

      for (endpoint, operator) in [
         (&self.version_start_including, Comparison::GreaterEqual),
         (&self.version_start_excluding, Comparison::Greater),
         (&self.version_end_including, Comparison::LessEqual),
         (&self.version_end_excluding, Comparison::Less),
      ] {
         if let Some(value) = endpoint.as_deref() {
            matched = matched
               & bound_version.map_or(Match::Unknown, |version| {
                  Scheme::Cpe.version(version).bound(value, operator)
               });
         }
      }

      if update_restricted && release.is_none() {
         matched & Match::Unknown
      } else {
         matched
      }
   }
}

impl AffectedVersion {
   /// Selects release ordering without reinterpreting commit hashes.
   fn scheme(&self, kind: ProductKind) -> Scheme {
      if self.is_commit() {
         Scheme::Unsupported
      } else if kind == ProductKind::Kernel {
         Scheme::Kernel
      } else {
         Scheme::from(self.version_type.as_ref())
      }
   }

   /// Evaluates whether an affected-version entry contains an installed
   /// version.
   fn contains(&self, installed: Version<'_>) -> Match {
      match (
         self.less_than.as_deref(),
         self.less_than_or_equal.as_deref(),
      ) {
         (Some(_), Some(_)) => Match::Unknown,
         (Some(upper), None) | (None, Some(upper)) => {
            let lower = if unspecified(self.version.trim()) {
               Match::Yes
            } else {
               installed.bound(&self.version, Comparison::GreaterEqual)
            };

            let operator = if self.less_than.is_some() {
               Comparison::Less
            } else {
               Comparison::LessEqual
            };

            lower & installed.bound(upper, operator)
         }
         (None, None) => installed.expression(&self.version),
      }
   }

   /// Returns the bound of an entry that caps affected releases from the start
   /// of history, whether given as a range or a comparison expression.
   fn upper_bound(&self) -> Option<(&str, Comparison)> {
      if self.status != Status::Affected || !self.changes.is_empty() {
         return None;
      }

      let version = self.version.trim();

      match (
         self.less_than.as_deref(),
         self.less_than_or_equal.as_deref(),
      ) {
         (Some(end), None) if unspecified(version) => Some((end, Comparison::Less)),
         (None, Some(end)) if unspecified(version) => Some((end, Comparison::LessEqual)),
         (None, None) => version
            .strip_prefix("<=")
            .map(|end| (end.trim(), Comparison::LessEqual))
            .or_else(|| {
               version
                  .strip_prefix('<')
                  .map(|end| (end.trim(), Comparison::Less))
            })
            .filter(|&(end, _)| !end.contains([',', '|', '<', '>', '='])),
         _ => None,
      }
      .filter(|&(end, _)| end != "*")
   }

   /// Reports whether an affected-version entry describes a release.
   pub fn is_release(&self) -> bool {
      if self.is_commit() {
         return false;
      }

      let release = |value: &str| {
         let trimmed = value.trim();
         let cleaned = trimmed.strip_prefix('v').unwrap_or(trimmed);
         dotted(cleaned)
            || SemanticVersion::parse(cleaned).is_ok()
            || cleaned.parse::<KernelVersion>().is_ok()
            || cleaned.strip_suffix(".*").is_some_and(dotted)
      };

      (release(&self.version)
         || unspecified(self.version.trim())
            && (self.less_than.is_some() || self.less_than_or_equal.is_some()))
         && self
            .less_than
            .iter()
            .chain(&self.less_than_or_equal)
            .all(|endpoint| endpoint == "*" || release(endpoint))
   }

   /// Reports whether an affected-version entry describes a commit.
   fn is_commit(&self) -> bool {
      self.version_type == Some(VersionType::Git)
         || iter::once(self.version.as_str())
            .chain(self.less_than.as_deref())
            .chain(self.less_than_or_equal.as_deref())
            .chain(self.changes.iter().map(|change| change.at.as_str()))
            .any(is_commit_hash)
   }
}

/// Selects the release syntax established by a product claim.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ProductKind {
   /// Uses the version scheme declared by each entry.
   Generic,
   /// Uses kernel release syntax for entries that do not describe commits.
   Kernel,
}

/// Selects whether parallel commit encodings need separate evaluation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommitPolicy {
   /// Keeps commit entries when no parallel release evidence exists.
   Evaluate,
   /// Skips parallel commit entries for an installed release version.
   SkipForRelease,
}

impl AffectedProduct {
   /// Matches the claim's platform restrictions against the installed system.
   pub fn platform(&self, system: Option<&str>) -> Match {
      if self.platforms.is_empty() {
         return Match::Yes;
      }

      let Some(active) = system else {
         return Match::Unknown;
      };

      let mut unknown = false;

      for platform in &self.platforms {
         let matches = match platform.to_ascii_lowercase().as_str() {
            "linux" => active.ends_with("-linux"),
            "windows" => active.ends_with("-windows"),
            "macos" | "mac os" | "darwin" => active.ends_with("-darwin"),
            "android" => active.ends_with("-android"),
            "x86_64" | "x64-based systems" => active.starts_with("x86_64-"),
            "aarch64" | "arm64-based systems" => active.starts_with("aarch64-"),
            _ => {
               unknown = true;
               false
            }
         };

         if matches {
            return Match::Yes;
         }
      }

      if unknown { Match::Unknown } else { Match::No }
   }

   /// Evaluates an installed version against a product's affected versions.
   pub fn matches_version(
      &self,
      known_version: Option<&str>,
      commits: CommitPolicy,
      kind: ProductKind,
   ) -> Match {
      if self.default_status == Status::Unaffected
         && self.versions.iter().all(|entry| {
            entry.status == Status::Unaffected
               && entry
                  .changes
                  .iter()
                  .all(|change| change.status == Status::Unaffected)
         })
      {
         return Match::No;
      }

      let Some(installed) = known_version else {
         return Match::Unknown;
      };

      if self.versions.is_empty() {
         return Match::Unknown;
      }

      if self.fixed_on_line(installed, kind) {
         return Match::No;
      }

      let release_installed = !is_commit_hash(installed);
      let mut evaluated = false;
      let mut unknown = false;

      for entry in &self.versions {
         if commits == CommitPolicy::SkipForRelease
            && release_installed
            && entry.is_commit()
            && installed.trim() != entry.version.trim()
         {
            continue;
         }

         evaluated = true;

         let version = entry.scheme(kind).version(installed);

         match entry.contains(version) {
            Match::No => continue,
            Match::Unknown => {
               unknown = true;
               continue;
            }
            Match::Yes => {}
         }

         let mut status = entry.status;
         let mut latest = Option::<Version<'_>>::None;

         for change in &entry.changes {
            let at = version.scheme.version(&change.at);
            let Some(position) = version.partial_cmp(&at) else {
               return Match::Unknown;
            };

            if position == Ordering::Less {
               continue;
            }

            if let Some(previous) = latest {
               match at.partial_cmp(&previous) {
                  Some(Ordering::Less) => continue,
                  Some(Ordering::Equal) if status != change.status => {
                     return Match::Unknown;
                  }
                  None => return Match::Unknown,
                  _ => {}
               }
            }

            latest = Some(at);
            status = change.status;
         }

         return if unknown {
            Match::Unknown
         } else {
            Match::from(status)
         };
      }

      if !evaluated {
         return Match::No;
      }

      if unknown {
         return Match::Unknown;
      }

      let mut releases = self
         .versions
         .iter()
         .filter(|entry| !entry.is_commit())
         .peekable();
      let enumerated = releases.peek().is_some()
         && releases.all(|entry| entry.status == Status::Affected && entry.changes.is_empty());

      // VulnCheck and MITRE records pair purely affected release ranges with an
      // affected default, where the default would make the ranges pointless.
      // Fix commits beside them carve nothing out of release numbering.
      match self.default_status {
         Status::Affected if enumerated => Match::No,
         Status::Affected if kind == ProductKind::Kernel && self.fixed_in_mainline(installed) => {
            Match::No
         }
         Status::Affected => Match::Yes,
         Status::Unaffected | Status::Unknown => Match::No,
      }
   }

   /// Advisories covering several release lines give each line its own upper
   /// bound, so a release past every bound on its own line is fixed even when
   /// a later line's bound still exceeds it.
   fn fixed_on_line(&self, installed: &str, kind: ProductKind) -> bool {
      let line = |version: &str| {
         let mut components = version
            .trim()
            .trim_start_matches('v')
            .split(['.', '-'])
            .map(str::parse::<u64>);
         Some((components.next()?.ok()?, components.next()?.ok()?))
      };
      let bounds = self
         .versions
         .iter()
         .filter_map(|entry| Some((entry, entry.upper_bound()?)))
         .collect::<Vec<_>>();
      let mut own_line = bounds
         .iter()
         .filter(|&&(_, (end, _))| line(end).is_some() && line(end) == line(installed))
         .peekable();

      bounds.len() > 1
         && own_line.peek().is_some()
         && own_line.all(|&(entry, (end, comparison))| {
            entry.scheme(kind).version(installed).bound(end, comparison) == Match::No
         })
   }

   /// Kernel stable series only take fixes already merged into mainline, so
   /// a record listing only stable backports still implies a fix in every
   /// series released after the one following its newest listed series.
   fn fixed_in_mainline(&self, installed: &str) -> bool {
      let series = |version: &str| {
         let mut components = version.split('.').map(str::parse::<u64>);
         Some((components.next()?.ok()?, components.next()?.ok()?))
      };

      let Some((major, minor)) = self
         .versions
         .iter()
         .filter(|entry| {
            entry.status == Status::Unaffected
               && entry
                  .less_than_or_equal
                  .as_deref()
                  .is_some_and(|end| end.ends_with(".*"))
         })
         .filter_map(|entry| series(&entry.version))
         .max()
      else {
         return false;
      };

      series(installed).is_some_and(|(current_major, current_minor)| {
         if current_major == major {
            current_minor > minor.saturating_add(1)
         } else {
            (current_major, current_minor) > (major.saturating_add(1), 0)
         }
      })
   }
}
