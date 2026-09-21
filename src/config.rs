use std::{
   collections::BTreeMap,
   fs,
   path::{Path, PathBuf},
};

use jiff::{Timestamp, civil::Date, tz::TimeZone};
use misstep::{Result, ResultExt as _, ensure};
use serde::{Deserialize, Deserializer, de::Error as _};
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
            "Loading the kernel build {}: {error:?}",
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// Suppression rule matching one finding with review metadata.
struct IgnoreRule {
   /// Package name matched by the rule.
   package: String,
   /// Vulnerability identifier matched by the rule.
   id: VulnerabilityId,
   /// Finding bucket matched by the rule.
   bucket: Bucket,
   /// Review reason shown for the suppression.
   reason: String,
   /// Optional package version matched by the rule.
   version: Option<String>,
   #[serde(default, deserialize_with = "IgnoreRule::deserialize_expiry")]
   /// Optional expiry date supplied by the user.
   until: Option<Date>,
   /// Optional evidence fingerprint matched by the rule.
   fingerprint: Option<Sha256>,
   /// Optional raw version ranges matched by the rule.
   ranges: Option<Vec<String>>,
}

impl IgnoreRule {
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
         }
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
      let config = toml::from_str::<Self>(&fs::read_to_string(path)?)
         .with_context(|| format!("Reading {}", path.display()))?;

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
         .find(|rule| {
            rule.package == finding.package
               && rule.id == finding.id
               && rule.bucket == finding.bucket
               && rule
                  .version
                  .as_ref()
                  .is_none_or(|version| *version == finding.version)
               && rule.until.is_none_or(|until| today < until)
               && rule
                  .fingerprint
                  .is_none_or(|fingerprint| fingerprint == finding.fingerprint)
               && rule
                  .ranges
                  .as_ref()
                  .is_none_or(|ranges| *ranges == finding.raw_ranges)
         })
         .map(|rule| rule.reason.as_str())
   }
}
