use std::{
   collections::BTreeMap,
   fs,
   path::{Path, PathBuf},
};

use jiff::{Timestamp, civil::Date, tz::TimeZone};
use misstep::{Result, ResultExt as _, ensure};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use toml::Value;

use crate::{
   digest::Sha256,
   identifier::{NormalizedName, VulnerabilityId},
   inventory::Package,
   kbuild::BuildScope,
   matching::{Bucket, Finding},
};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
/// User configuration with aliases and suppression rules.
pub struct Config {
   #[serde(default)]
   /// Product aliases keyed by package name.
   aliases: BTreeMap<String, Vec<ProductAlias>>,
   #[serde(default)]
   /// Suppression rules for accepted findings.
   ignore: Vec<IgnoreRule>,
   #[serde(default)]
   /// Kernel build whose configuration decides which kernel files compile.
   kernel: Option<KernelBuild>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// Kernel output paired with its Kbuild files and `.config`.
struct KernelBuild {
   /// Store path of the kernel output the build applies to.
   output: String,
   #[serde(deserialize_with = "KernelBuild::deserialize_scope")]
   /// Kbuild evaluation of the directory holding the Kbuild files and `.config`.
   build: BuildScope,
}

impl KernelBuild {
   /// Loads the Kbuild files and `.config` under the configured directory.
   fn deserialize_scope<'de, DeserializerType>(
      deserializer: DeserializerType,
   ) -> Result<BuildScope, DeserializerType::Error>
   where
      DeserializerType: Deserializer<'de>,
   {
      let directory = PathBuf::deserialize(deserializer)?;

      BuildScope::load(&directory).map_err(|error| {
         DeserializerType::Error::custom(format!(
            "Loading the kernel build {}: {error}",
            directory.display()
         ))
      })
   }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
/// Alternative vendor product identity for a package.
pub struct ProductAlias {
   /// Product name used by the advisory source.
   pub product: NormalizedName,
   /// Vendor name when the alias needs one.
   pub vendor: Option<NormalizedName>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Suppression rule matching one finding with review metadata.
pub struct IgnoreRule {
   /// Package name matched by the rule.
   pub package: String,
   /// Vulnerability identifier matched by the rule.
   pub id: VulnerabilityId,
   /// Finding bucket matched by the rule.
   pub bucket: Bucket,
   /// Review reason shown for the suppression.
   pub reason: String,
   /// Optional package version matched by the rule.
   pub version: Option<String>,
   #[serde(
      default,
      deserialize_with = "IgnoreRule::deserialize_expiry",
      skip_serializing
   )]
   /// Optional expiry date supplied by the user.
   pub until: Option<Date>,
   /// Optional evidence fingerprint matched by the rule.
   pub fingerprint: Option<Sha256>,
   /// Optional raw version ranges matched by the rule.
   pub ranges: Option<Vec<String>>,
}

impl IgnoreRule {
   /// Whether the rule applies to a finding on the given day.
   fn matches(&self, finding: &Finding, today: Date) -> bool {
      self.package == finding.package.name
         && self.id == finding.id
         && self.bucket == finding.bucket
         && self
            .version
            .as_ref()
            .is_none_or(|version| *version == finding.package.version)
         && self.until.is_none_or(|until| today < until)
         && self
            .fingerprint
            .is_none_or(|fingerprint| fingerprint == finding.fingerprint)
         && self
            .ranges
            .as_ref()
            .is_none_or(|ranges| *ranges == finding.raw_ranges)
   }

   /// Parse an expiry date in the accepted calendar form.
   fn deserialize_expiry<'de, DeserializerType>(
      deserializer: DeserializerType,
   ) -> Result<Option<Date>, DeserializerType::Error>
   where
      DeserializerType: Deserializer<'de>,
   {
      let value = match Option::<Value>::deserialize(deserializer)? {
         None => return Ok(None),
         Some(Value::String(text)) => text,
         Some(Value::Datetime(datetime)) => datetime.to_string(),
         Some(other) => {
            return Err(DeserializerType::Error::custom(format!(
               "Invalid expiry date {other}"
            )));
         },
      };
      let bytes = value.as_bytes();

      if bytes.len() != 10
         || !bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
         })
      {
         return Err(DeserializerType::Error::custom(format!(
            "Invalid expiry date {value}"
         )));
      }

      Date::strptime("%Y-%m-%d", &value)
         .map(Some)
         .map_err(DeserializerType::Error::custom)
   }
}

impl Config {
   /// Exposes aliases without allowing mutation after validation.
   pub fn aliases(&self, package: &str) -> Option<&[ProductAlias]> {
      self.aliases.get(package).map(Vec::as_slice)
   }

   /// Load and validate configuration from an optional path.
   pub fn load(filter: Option<&Path>) -> Result<Self> {
      let Some(path) = filter else {
         return Ok(Self::default());
      };
      let text = fs::read_to_string(path).with_context(|| format!("Reading {}", path.display()))?;
      let config =
         toml::from_str::<Self>(&text).with_context(|| format!("Parsing {}", path.display()))?;

      for rule in &config.ignore {
         ensure!(
            !rule.package.trim().is_empty() && rule.package != "*",
            "Ignore rules must name a package"
         );
         ensure!(
            !rule.reason.trim().is_empty(),
            "Ignore rules need a review reason"
         );
         ensure!(
            rule.bucket != Bucket::Unknown || rule.fingerprint.is_some(),
            "Unknown ignore rules need the finding fingerprint so revised \
             evidence is reported again"
         );
      }

      for (package, aliases) in &config.aliases {
         ensure!(
            !package.trim().is_empty() && !aliases.is_empty(),
            "Empty product alias"
         );

         for alias in aliases {
            ensure!(
               !alias.product.is_placeholder(),
               "Product aliases must name a product"
            );
         }
      }

      Ok(config)
   }

   /// Returns the Kbuild evaluation for a package built from the configured kernel.
   pub fn kernel_scope(&self, package: &Package) -> Option<&BuildScope> {
      let kernel = self.kernel.as_ref()?;
      package
         .store_paths
         .contains(&kernel.output)
         .then_some(&kernel.build)
   }

   /// Return the suppression reason when a finding matches.
   pub fn ignored(&self, finding: &Finding) -> Option<&str> {
      let today = Timestamp::now().to_zoned(TimeZone::UTC).date();

      self
         .ignore
         .iter()
         .find(|rule| rule.matches(finding, today))
         .map(|rule| rule.reason.as_str())
   }

   /// Rules that match none of the findings, usually because the package
   /// they name has moved to another version.
   pub fn unused_rules(&self, findings: &[&Finding<'_>]) -> Vec<&IgnoreRule> {
      let today = Timestamp::now().to_zoned(TimeZone::UTC).date();

      self
         .ignore
         .iter()
         .filter(|rule| {
            rule.until.is_none_or(|until| today < until)
               && !findings.iter().any(|finding| rule.matches(finding, today))
         })
         .collect()
   }
}
