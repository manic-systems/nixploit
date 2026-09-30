//! Package source locations and the package collections they identify.

use std::{
   fmt::{Display, Formatter, Result as FormatResult},
   str::FromStr,
};

use misstep::{Report, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::identifier::NormalizedName;

/// Code forges whose first path segment names the repository owner.
const FORGES: [&str; 4] = ["github.com", "gitlab.com", "codeberg.org", "bitbucket.org"];

/// Language package namespaces shared by registries, Nix builders, and CPE
/// target software.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Collection {
   /// Python packages.
   Python,
   /// Perl modules.
   Perl,
   /// Node.js packages.
   NodeJs,
   /// Rust crates.
   Rust,
   /// Go modules.
   Go,
   /// `WordPress` plugins and themes.
   WordPress,
}

impl FromStr for Collection {
   type Err = Report;

   /// Parses the CPE `target_sw` values that name a collection.
   fn from_str(target: &str) -> Result<Self, Report> {
      Ok(match target {
         "python" => Self::Python,
         "perl" => Self::Perl,
         "nodejs" | "node.js" => Self::NodeJs,
         "rust" => Self::Rust,
         "wordpress" => Self::WordPress,
         _ => return Err(Report::msg(format!("Unknown package collection {target}"))),
      })
   }
}

impl Collection {
   /// Names the collection a CNA covers exclusively, keyed by the source label
   /// NVD records for it.
   pub fn published_by(source: &str) -> Option<Self> {
      matches!(source, "audit@patchstack.com" | "security@wordfence.com").then_some(Self::WordPress)
   }
}

/// A source or homepage URL split once into host and path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceUrl {
   /// The URL as the derivation or advisory recorded it.
   text: String,
   /// Host without user information or port.
   host: String,
   /// Path without leading slash, query, or fragment.
   path: String,
}

impl SourceUrl {
   /// Identifies the package registry hosting this URL.
   pub fn registry(&self) -> Option<Collection> {
      [
         ("cpan.org", Collection::Perl),
         ("metacpan.org", Collection::Perl),
         ("npmjs.org", Collection::NodeJs),
         ("npmjs.com", Collection::NodeJs),
         ("pypi.org", Collection::Python),
         ("pythonhosted.org", Collection::Python),
         ("crates.io", Collection::Rust),
         ("wordpress.org", Collection::WordPress),
      ]
      .into_iter()
      .find(|&(domain, _)| {
         self.host == domain
            || self
               .host
               .strip_suffix(domain)
               .is_some_and(|prefix| prefix.ends_with('.'))
      })
      .map(|(_, collection)| collection)
   }

   /// Identifies a distribution package browser, whose package versions carry
   /// the distribution's own release numbering.
   pub fn distribution(&self) -> bool {
      matches!(
         self.host.as_str(),
         "access.redhat.com" | "packages.ubuntu.com" | "packages.debian.org"
      )
   }

   /// Names the organization owning the URL, from a forge path or the
   /// registrable domain.
   pub fn owner(&self) -> Option<NormalizedName> {
      if FORGES.contains(&self.host.as_str()) {
         self.path.split('/').next()
      } else {
         self.host.split('.').rev().nth(1)
      }
      .map(NormalizedName::from)
   }

   /// Derives the Go module path of a forge repository. Go publishes v2 and
   /// later releases only under a `/vN` suffix, so a bare path names v1.
   pub fn module_path(&self, major: Option<u32>) -> Option<NormalizedName> {
      if !FORGES.contains(&self.host.as_str()) {
         return None;
      }

      let mut segments = self.path.split('/').filter(|segment| !segment.is_empty());
      let (owner, repository) = (segments.next()?, segments.next()?);
      let base = format!(
         "{}/{owner}/{}",
         self.host,
         repository.trim_end_matches(".git")
      );

      Some(NormalizedName::from(
         match major {
            Some(version) => format!("{base}/v{version}"),
            None => base,
         }
         .as_str(),
      ))
   }

   /// Names a repository by lowercased host and path without a `.git`
   /// suffix.
   pub fn repository(&self) -> String {
      let path = self.path.trim_end_matches('/').trim_end_matches(".git");
      format!("{}/{path}", self.host).to_ascii_lowercase()
   }

   /// Matches a source archive URL to a repository URL without crossing owner
   /// boundaries.
   pub fn same_repository(&self, repository: &Self) -> bool {
      if self.host != repository.host || self.registry().is_some() {
         return false;
      }

      let expected = repository
         .path
         .trim_end_matches('/')
         .trim_end_matches(".git");
      let source = self.path.trim_end_matches('/').trim_end_matches(".git");

      !expected.is_empty()
         && (source == expected
            || source
               .strip_prefix(expected)
               .is_some_and(|suffix| suffix.starts_with('/')))
   }
}

impl FromStr for SourceUrl {
   type Err = Report;

   /// Parses a URL without accepting user information or ports as a host.
   fn from_str(text: &str) -> Result<Self, Report> {
      let (_scheme, location) = text
         .split_once("://")
         .ok_or_else(|| Report::msg(format!("URL {text} has no scheme")))?;
      let (host, path) = location.split_once('/').unwrap_or((location, ""));

      ensure!(
         !host.is_empty() && !host.contains(['@', ':']),
         "URL {} has no plain host",
         text
      );

      Ok(Self {
         text: text.to_owned(),
         host: host.to_owned(),
         path: path.split(['?', '#']).next().unwrap_or_default().to_owned(),
      })
   }
}

impl Display for SourceUrl {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(&self.text)
   }
}

impl Serialize for SourceUrl {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      serializer.serialize_str(&self.text)
   }
}

impl<'de> Deserialize<'de> for SourceUrl {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer)?
         .parse()
         .map_err(Decoder::Error::custom)
   }
}
