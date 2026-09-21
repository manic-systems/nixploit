use std::{
   collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
   fs::{self, File},
   io::Read as _,
   path::{Path, PathBuf},
   process::Command,
   slice,
};

use misstep::{OptionExt as _, Report, Result, ResultExt as _, bail, ensure};
use serde::{Deserialize, Serialize, de::IgnoredAny};

use crate::{advisory::Ecosystem, identifier::VulnerabilityId, source::SourceUrl};

/// Largest patch read while looking for CVE identifiers.
const PATCH_LIMIT: u64 = 64 * 1024 * 1024;

/// Tracks whether inventory metadata establishes a software version.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionOrigin {
   /// Package attributes or an explicit inventory entry supply the version.
   #[default]
   Declared,
   /// An unavailable derivation still provides its recorded package basename.
   Deriver,
   /// Output names may include suffixes unrelated to package versions.
   Output,
   /// An available derivation has no declared version to support its name.
   Unversioned,
}

impl VersionOrigin {
   /// Unversioned names cannot establish release applicability.
   pub const fn version_uncertain(self) -> bool {
      matches!(self, Self::Output | Self::Unversioned)
   }
}

/// Package inventory selection from CLI arguments.
pub struct InventoryArgs {
   /// Nix paths to inspect.
   pub paths: Vec<PathBuf>,
   /// Whether to include the running NixOS system.
   pub system: bool,
   /// Whether to traverse build dependencies.
   pub build_deps: bool,
   /// Whether to skip runtime requisites.
   pub no_requisites: bool,
   /// Explicit package specifications.
   pub package: Vec<String>,
   /// Saved inventory file to read.
   pub inventory: Option<PathBuf>,
}

/// One versioned package in a Nix closure.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
   /// Package name.
   pub name: String,
   /// Package version.
   pub version: String,
   #[serde(default)]
   /// Target system when known.
   pub system: Option<String>,
   #[serde(default)]
   /// Source derivation when available.
   pub derivation: Option<String>,
   #[serde(default)]
   /// Store outputs attributed to this package.
   pub store_paths: BTreeSet<String>,
   #[serde(default)]
   /// CVEs named by package patches.
   pub patches: BTreeSet<VulnerabilityId>,
   #[serde(default)]
   /// Source and homepage URLs recovered from stored derivations.
   pub source_urls: BTreeSet<SourceUrl>,
   #[serde(default)]
   /// Evidence for interpreting the package version.
   pub metadata: VersionOrigin,
   #[serde(default)]
   /// Language ecosystems whose Nix builders produced the package.
   pub ecosystems: BTreeSet<Ecosystem>,
}

impl Package {
   /// Validates package identity.
   pub fn validate(&self) -> Result<()> {
      ensure!(
         !self.name.trim().is_empty() && !self.version.trim().is_empty(),
         "Package name and version must not be empty"
      );

      Ok(())
   }
}

/// Collected package inventory and unresolved paths.
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
   /// Versioned packages.
   pub packages: Vec<Package>,
   #[serde(default)]
   /// Paths without usable package metadata.
   pub skipped: BTreeSet<String>,
   #[serde(default)]
   /// Store paths whose derivations were unavailable.
   pub missing_derivations: BTreeSet<String>,
}

impl TryFrom<&InventoryArgs> for Inventory {
   type Error = Report;

   /// Collects packages from explicit entries, files, and Nix paths.
   fn try_from(arguments: &InventoryArgs) -> Result<Self> {
      let mut inventory = if let Some(path) = arguments.inventory.as_ref() {
         serde_json::from_slice::<Self>(&fs::read(path)?)?
      } else {
         Self::default()
      };

      for specification in &arguments.package {
         let (name, version) = specification
            .rsplit_once('@')
            .context("Package must have the form NAME@VERSION")?;

         inventory.packages.push(Package {
            name: name.to_owned(),
            version: version.to_owned(),
            system: None,
            derivation: None,
            store_paths: BTreeSet::new(),
            patches: BTreeSet::new(),
            source_urls: BTreeSet::new(),
            metadata: VersionOrigin::Declared,
            ecosystems: BTreeSet::new(),
         });
      }

      let mut roots = arguments
         .paths
         .iter()
         .map(|path| {
            fs::canonicalize(path).with_context(|| format!("Resolving {}", path.display()))
         })
         .collect::<Result<BTreeSet<_>>>()?;

      if arguments.system
         || (roots.is_empty() && arguments.inventory.is_none() && arguments.package.is_empty())
      {
         roots.insert(
            fs::canonicalize("/run/current-system")
               .context("Resolving the running NixOS system")?,
         );
      }

      if !roots.is_empty() {
         inventory.extend_from_nix(roots, arguments)?;
      }

      for package in &inventory.packages {
         package.validate()?;
      }

      inventory.packages.sort_by(|left, right| {
         (
            &left.name,
            &left.version,
            &left.derivation,
            &left.system,
            &left.patches,
            left.metadata,
         )
            .cmp(&(
               &right.name,
               &right.version,
               &right.derivation,
               &right.system,
               &right.patches,
               right.metadata,
            ))
      });

      inventory.packages.dedup_by(|current, previous| {
         if current.name == previous.name
            && current.version == previous.version
            && current.derivation == previous.derivation
            && current.system == previous.system
            && current.patches == previous.patches
            && current.metadata == previous.metadata
         {
            previous.store_paths.append(&mut current.store_paths);
            previous.source_urls.append(&mut current.source_urls);
            previous.ecosystems.append(&mut current.ecosystems);
            true
         } else {
            false
         }
      });

      ensure!(
         !inventory.packages.is_empty(),
         "No versioned packages found in the selected inventory"
      );
      Ok(inventory)
   }
}

impl Inventory {
   #[expect(
      clippy::too_many_lines,
      reason = "inventory traversal keeps its shared derivation state in one \
                scope"
   )]
   /// Adds package metadata obtained from Nix commands.
   fn extend_from_nix(
      &mut self,
      roots: BTreeSet<PathBuf>,
      arguments: &InventoryArgs,
   ) -> Result<()> {
      let mut derivations = BTreeSet::new();
      let mut direct_derivations = BTreeSet::new();
      let mut output_roots = Vec::new();
      let mut outputs = BTreeMap::<String, BTreeSet<String>>::new();
      let mut store_directory = None;
      let mut sources = Sources::default();
      let mut package_indices = HashMap::new();
      let mut orphans = BTreeMap::new();

      for (index, package) in self.packages.iter().enumerate() {
         if let Some(path) = package.derivation.as_ref() {
            package_indices.entry(path.clone()).or_insert(index);
         }
      }

      for root in roots {
         if root.extension().is_some_and(|extension| extension == "drv") {
            direct_derivations.insert(root.clone());
            derivations.insert(root);
         } else {
            output_roots.push(root);
         }
      }

      if !output_roots.is_empty() {
         let closure = Closure::load(&output_roots, !arguments.no_requisites)?;

         for (basename, entry) in closure.info {
            let store_path = closure.store_dir.join(&basename);
            let deriver = entry.deriver.map(|deriver| closure.store_dir.join(deriver));

            if let Some(path) = deriver.as_ref().filter(|candidate| candidate.is_file()) {
               derivations.insert(path.clone());
               outputs
                  .entry(path.to_string_lossy().into_owned())
                  .or_default()
                  .insert(store_path.to_string_lossy().into_owned());
            } else {
               orphans.insert(store_path, (basename, deriver));
            }
         }

         derivations.extend(valid_derivers(orphans.keys())?);
         store_directory = Some(closure.store_dir);
      }

      let paths = derivations.into_iter().collect::<Vec<_>>();

      if paths.is_empty() {
         self.extend_from_names(orphans);
         return Ok(());
      }

      let store_dir = match store_directory {
         Some(directory) => directory,
         None => Closure::load(&paths[..1], false)?.store_dir,
      };
      let mut pending = VecDeque::from(paths);
      let mut scheduled = pending
         .iter()
         .map(|path| path.to_string_lossy().into_owned())
         .collect::<HashSet<_>>();
      let mut inspected = HashSet::new();

      while !pending.is_empty() {
         let chunk = pending.drain(..pending.len().min(128)).collect::<Vec<_>>();
         let envelope = Derivations::load(&chunk, false)?;

         for (basename, derivation) in envelope.derivations {
            let path = store_dir.join(&basename).to_string_lossy().into_owned();

            if !inspected.insert(path.clone()) {
               continue;
            }

            if arguments.build_deps {
               for input in derivation.inputs.drvs.keys() {
                  let input_path = store_dir.join(input);
                  let displayed = input_path.to_string_lossy().into_owned();

                  if scheduled.insert(displayed) {
                     pending.push_back(input_path);
                  }
               }
            }

            let mut owned_outputs = outputs.remove(&path).unwrap_or_default();

            for output in derivation.outputs.values() {
               if let Some(output_path) = output.path.as_ref()
                  && orphans.remove(&store_dir.join(output_path)).is_some()
               {
                  owned_outputs.insert(store_dir.join(output_path).to_string_lossy().into_owned());
               }
            }

            if arguments.build_deps || direct_derivations.contains(Path::new(&path)) {
               owned_outputs.extend(derivation.outputs.values().filter_map(|output| {
                  output
                     .path
                     .as_ref()
                     .map(|output_path| store_dir.join(output_path).to_string_lossy().into_owned())
               }));
            }

            if let Some(&index) = package_indices.get(&path) {
               self.packages[index].store_paths.append(&mut owned_outputs);

               let source_urls = sources.register(index, &derivation, &store_dir);
               self.packages[index].source_urls.extend(source_urls);
               self.packages[index]
                  .ecosystems
                  .extend(derivation.ecosystems());
               continue;
            }

            let attributes = &derivation.structured_attrs;

            if attributes.chosen_outputs.is_some() {
               self.skipped.insert(path);
               continue;
            }

            let get = |key: &str| derivation.env.get(key).filter(|value| !value.is_empty());
            let split = split_name(&derivation.name);

            let package_name = attributes
               .pname
               .as_ref()
               .or_else(|| get("pname"))
               .map(String::as_str)
               .or_else(|| split.map(|(split_name, _split_version)| split_name));
            let declared_version = attributes
               .version
               .as_ref()
               .or_else(|| get("version"))
               .filter(|version| !version.is_empty());
            let version = declared_version
               .map(String::as_str)
               .or_else(|| split.map(|(_split_name, split_version)| split_version));

            let (Some(name), Some(package_version)) = (package_name, version) else {
               self.skipped.insert(path);
               continue;
            };

            if [
               ".tar.gz", ".tar.xz", ".tar.bz2", ".zip", ".patch", ".diff", ".tgz", ".gem",
            ]
            .iter()
            .any(|suffix| derivation.name.ends_with(suffix))
            {
               self.skipped.insert(path);
               continue;
            }

            let patches = derivation.patched_cves(&store_dir);

            let source_urls = sources.register(self.packages.len(), &derivation, &store_dir);

            let index = self.packages.len();
            package_indices.insert(path.clone(), index);

            self.packages.push(Package {
               name: name.to_owned(),
               version: package_version.to_owned(),
               system: None,
               store_paths: owned_outputs,
               derivation: Some(path),
               patches,
               source_urls,
               metadata: if declared_version.is_some() {
                  VersionOrigin::Declared
               } else {
                  VersionOrigin::Unversioned
               },
               ecosystems: derivation.ecosystems(),
            });
         }
      }

      self.extend_from_names(orphans);
      sources.enrich(&mut self.packages)?;
      Ok(())
   }

   /// Adds outputs without a readable derivation under the package name their
   /// deriver or store basename records.
   fn extend_from_names(&mut self, orphans: BTreeMap<PathBuf, (String, Option<PathBuf>)>) {
      for (store_path, (basename, deriver)) in orphans {
         let displayed = store_path.to_string_lossy().into_owned();
         self.missing_derivations.insert(displayed.clone());

         let identity = deriver.as_ref().map_or(Some(basename.as_str()), |path| {
            path.file_name()?.to_str()?.strip_suffix(".drv")
         });

         if let Some((package_name, version)) = identity.and_then(store_package) {
            let metadata = if deriver.is_some() {
               VersionOrigin::Deriver
            } else {
               VersionOrigin::Output
            };

            self.packages.push(Package {
               name: package_name,
               version,
               system: None,
               derivation: deriver.map(|path| path.to_string_lossy().into_owned()),
               store_paths: BTreeSet::from([displayed]),
               patches: BTreeSet::new(),
               source_urls: BTreeSet::new(),
               metadata,
               ecosystems: BTreeSet::new(),
            });
         } else {
            self.skipped.insert(displayed);
         }
      }
   }
}

/// Finds stored derivations producing outputs whose recorded deriver is gone.
/// Garbage collection often removes the recorded one while an equivalent
/// derivation for the same output path stays valid.
fn valid_derivers<'path>(paths: impl Iterator<Item = &'path PathBuf>) -> Result<Vec<PathBuf>> {
   let mut derivers = Vec::new();

   for chunk in paths.collect::<Vec<_>>().chunks(128) {
      let mut command = Command::new("nix-store");
      command.args(["--query", "--valid-derivers"]);
      derivers.extend(
         String::from_utf8(run(command.args(chunk))?)?
            .lines()
            .map(PathBuf::from),
      );
   }

   Ok(derivers)
}

/// Builds a Nix command with the required experimental feature.
fn nix_command() -> Command {
   let mut command = Command::new("nix");
   command.args(["--extra-experimental-features", "nix-command"]);
   command
}

/// Runs a Nix inventory command and returns stdout.
fn run(command: &mut Command) -> Result<Vec<u8>> {
   let output = command
      .output()
      .context("Running Nix to read the local inventory")?;

   if !output.status.success() {
      bail!(
         "Nix inventory query failed\n{}",
         String::from_utf8_lossy(&output.stderr).trim()
      );
   }

   Ok(output.stdout)
}

/// Splits a Nix package name at its numeric version suffix.
fn split_name(name: &str) -> Option<(&str, &str)> {
   name.char_indices().find_map(|(index, character)| {
      if character != '-' {
         return None;
      }

      let (package_name, version_with_separator) = name.split_at(index);
      let package_version = version_with_separator.strip_prefix('-')?;
      package_version
         .as_bytes()
         .first()
         .is_some_and(u8::is_ascii_digit)
         .then_some((package_name, package_version))
   })
}

/// Extracts a package name and version from a store basename.
fn store_package(basename: &str) -> Option<(String, String)> {
   let (_hash, suffix) = basename.split_once('-')?;
   let (package_name, package_version) = split_name(suffix)?;
   Some((package_name.to_owned(), package_version.to_owned()))
}

/// Nix path-info response envelope.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Closure {
   /// Path-info schema version.
   version: u32,
   /// Store directory reported by Nix.
   store_dir: PathBuf,
   /// Store entries keyed by basename.
   info: BTreeMap<String, StoreInfo>,
}

impl Closure {
   /// Queries Nix path information using schema version two.
   fn load(paths: &[PathBuf], recursive: bool) -> Result<Self> {
      let mut command = nix_command();
      command.args(["path-info", "--json", "--json-format", "2"]);

      if recursive {
         command.arg("--recursive");
      }

      let closure = serde_json::from_slice::<Self>(&run(command.args(paths))?)?;

      ensure!(
         closure.version == 2,
         "Unsupported Nix path-info schema {}",
         closure.version
      );
      Ok(closure)
   }
}

/// Relevant metadata for one store path.
#[derive(Deserialize)]
struct StoreInfo {
   /// Derivation basename when known.
   deriver: Option<String>,
}

/// Nix derivation-show response envelope.
#[derive(Deserialize)]
struct Derivations {
   /// Derivation schema version.
   version: u32,
   /// Derivations keyed by basename.
   derivations: BTreeMap<String, Derivation>,
}

impl Derivations {
   /// Reads stored derivations without evaluating package expressions.
   fn load(paths: &[PathBuf], recursive: bool) -> Result<Self> {
      let mut command = nix_command();
      command.args(["derivation", "show"]);

      if recursive {
         command.arg("--recursive");
      }

      let envelope = serde_json::from_slice::<Self>(&run(command.args(paths))?)?;

      ensure!(
         envelope.version == 4,
         "Unsupported Nix derivation schema {}, expected 4",
         envelope.version
      );
      Ok(envelope)
   }
}

/// Package metadata from one Nix derivation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Derivation {
   /// Derivation name.
   name: String,
   /// Derivation environment variables.
   env: BTreeMap<String, String>,
   #[serde(default)]
   /// Structured derivation attributes.
   structured_attrs: Attributes,
   /// Input derivations naming the package source fetcher.
   inputs: Inputs,
   /// Declared outputs used to resolve source paths without building.
   outputs: BTreeMap<String, SourceOutput>,
}

impl Derivation {
   /// Recognizes the nixpkgs language builders from the attributes they set.
   fn ecosystems(&self) -> BTreeSet<Ecosystem> {
      let attributes = &self.structured_attrs;

      [
         (
            Ecosystem::PyPi,
            "dontWrapPythonPrograms",
            attributes.python_programs.is_some(),
         ),
         (Ecosystem::Npm, "npmDeps", attributes.npm_deps.is_some()),
         (
            Ecosystem::CratesIo,
            "cargoDeps",
            attributes.cargo_deps.is_some(),
         ),
         (Ecosystem::Go, "goModules", attributes.go_modules.is_some()),
      ]
      .into_iter()
      .filter(|&(_, key, structured)| structured || self.env.contains_key(key))
      .map(|(ecosystem, _, _)| ecosystem)
      .collect()
   }

   /// Collects CVE identifiers from patch names and the contents of patches
   /// present in the store.
   fn patched_cves(&self, store_dir: &Path) -> BTreeSet<VulnerabilityId> {
      let mut identifiers = BTreeSet::new();

      for patch in self
         .structured_attrs
         .patches
         .iter()
         .chain(self.env.get("patches"))
         .flat_map(|patches| patches.split_whitespace())
      {
         identifiers.extend(VulnerabilityId::find_cves(patch));

         // nixpkgs follows glibc and similar release branches through one
         // patch whose commit subjects name the CVEs each backport fixes.
         let mut contents = Vec::new();

         if Path::new(patch).starts_with(store_dir)
            && File::open(patch)
               .and_then(|file| file.take(PATCH_LIMIT).read_to_end(&mut contents))
               .is_ok()
         {
            identifiers.extend(VulnerabilityId::find_cves(&String::from_utf8_lossy(
               &contents,
            )));
         }
      }

      identifiers
   }

   /// Collects only explicit URLs from stored source and homepage attributes.
   fn source_urls(&self) -> BTreeSet<SourceUrl> {
      let attributes = &self.structured_attrs.source;
      let mut urls = BTreeSet::new();

      let metadata = self
         .env
         .get("meta")
         .and_then(|value| serde_json::from_str::<Metadata>(value).ok());

      for value in attributes
         .url
         .iter()
         .chain(&attributes.urls)
         .chain(&attributes.homepage)
         .flat_map(TextValues::strings)
         .map(String::as_str)
         .chain(
            ["url", "urls", "homepage"]
               .iter()
               .filter_map(|key| self.env.get(*key))
               .map(String::as_str),
         )
         .chain(attributes.meta.iter().flat_map(Metadata::homepages))
         .chain(metadata.iter().flat_map(Metadata::homepages))
      {
         urls.extend(value.split_whitespace().filter_map(|url| url.parse().ok()));
      }

      urls
   }
}

/// Input derivation references in the Nix schema.
#[derive(Deserialize)]
struct Inputs {
   /// Derivation basenames and selected outputs.
   drvs: BTreeMap<String, InputDerivation>,
}

/// Static outputs selected from a source derivation input.
#[derive(Deserialize)]
struct InputDerivation {
   /// Outputs contributing to the package build.
   outputs: BTreeSet<String>,
}

/// Structured package attributes exposed by Nix.
#[derive(Default, Deserialize)]
struct Attributes {
   #[serde(flatten)]
   /// Optional source identity preserved by structured derivations.
   source: SourceAttributes,
   #[serde(default, rename = "chosenOutputs")]
   /// Selected build environment outputs.
   chosen_outputs: Option<Vec<IgnoredAny>>,
   #[serde(default)]
   /// Package name attribute.
   pname: Option<String>,
   #[serde(default)]
   /// Package version attribute.
   version: Option<String>,
   #[serde(default)]
   /// Package patch paths.
   patches: Vec<String>,
   #[serde(default, rename = "dontWrapPythonPrograms")]
   /// Set by every nixpkgs Python package and application builder.
   python_programs: Option<IgnoredAny>,
   #[serde(default, rename = "npmDeps")]
   /// Vendored npm dependencies from `buildNpmPackage`.
   npm_deps: Option<IgnoredAny>,
   #[serde(default, rename = "cargoDeps")]
   /// Vendored crates from `buildRustPackage`.
   cargo_deps: Option<IgnoredAny>,
   #[serde(default, rename = "goModules")]
   /// Vendored modules from `buildGoModule`.
   go_modules: Option<IgnoredAny>,
}

/// Pending source lookups shared across the collected inventory.
#[derive(Default)]
struct Sources {
   /// Package indices requiring each source output.
   packages: BTreeMap<String, BTreeSet<usize>>,
   /// Available derivations that may produce those outputs.
   derivations: BTreeSet<PathBuf>,
}

impl Sources {
   /// Records local fetcher candidates while retaining direct identity URLs.
   fn register(
      &mut self,
      index: usize,
      derivation: &Derivation,
      store_dir: &Path,
   ) -> BTreeSet<SourceUrl> {
      let mut urls = derivation.source_urls();

      for source in derivation
         .structured_attrs
         .source
         .src
         .iter()
         .flat_map(TextValues::strings)
         .map(String::as_str)
         .chain(derivation.env.get("src").map(String::as_str))
      {
         if let Ok(url) = source.parse::<SourceUrl>() {
            urls.insert(url);
            continue;
         }

         let Some(basename) = Path::new(source)
            .strip_prefix(store_dir)
            .ok()
            .and_then(|relative| relative.components().next())
            .and_then(|component| component.as_os_str().to_str())
         else {
            continue;
         };
         let Some((_hash, name)) = basename.split_once('-') else {
            continue;
         };

         self
            .packages
            .entry(store_dir.join(basename).to_string_lossy().into_owned())
            .or_default()
            .insert(index);

         for (input, selection) in &derivation.inputs.drvs {
            if selection.outputs.is_empty() {
               continue;
            }

            let candidate = store_dir.join(input);

            if candidate
               .file_name()
               .and_then(|filename| filename.to_str())
               .and_then(|filename| filename.strip_suffix(".drv"))
               .and_then(|filename| filename.split_once('-'))
               .is_some_and(|(_input_hash, input_name)| input_name == name)
               && candidate.is_file()
            {
               self.derivations.insert(candidate);
            }
         }
      }

      urls
   }

   /// Resolves fetcher output paths before attributing their URLs to packages.
   fn enrich(self, packages: &mut [Package]) -> Result<()> {
      let paths = self.derivations.into_iter().collect::<Vec<_>>();

      for chunk in paths.chunks(128) {
         let envelope = Derivations::load(chunk, false)?;
         let mut fetchers = Vec::new();

         for (basename, derivation) in envelope.derivations {
            let urls = derivation.source_urls();

            if derivation.outputs.len() != 1
               || !derivation.outputs.values().all(SourceOutput::known_path)
               || urls.is_empty()
            {
               continue;
            }

            if let Some(path) = chunk.iter().find(|path| {
               path
                  .file_name()
                  .is_some_and(|filename| filename == basename.as_str())
            }) {
               fetchers.push((path, urls));
            }
         }

         if fetchers.is_empty() {
            continue;
         }

         let mut command = Command::new("nix-store");
         command.args(["--query", "--outputs"]);

         let output =
            String::from_utf8(run(command.args(fetchers.iter().map(|&(path, _)| path)))?)?;

         ensure!(
            output.lines().count() == fetchers.len(),
            "Nix returned an unexpected number of source output paths"
         );

         for (source, (_path, urls)) in output.lines().zip(fetchers) {
            if let Some(indices) = self.packages.get(source) {
               for index in indices {
                  packages[*index].source_urls.extend(urls.iter().cloned());
               }
            }
         }
      }

      Ok(())
   }
}

/// Only fixed or input-addressed outputs have paths before a build.
#[derive(Deserialize)]
struct SourceOutput {
   /// Input-addressed output path.
   path: Option<String>,
   /// Fixed-output content hash.
   hash: Option<String>,
}

impl SourceOutput {
   /// Excludes floating and deferred outputs from local output-path queries.
   const fn known_path(&self) -> bool {
      self.path.is_some() || self.hash.is_some()
   }
}

/// Optional identity attributes that survive derivation lowering.
#[derive(Default, Deserialize)]
struct SourceAttributes {
   /// Source paths or explicit source URLs.
   #[serde(default)]
   src: Option<TextValues>,
   /// One source fetch URL.
   #[serde(default)]
   url: Option<TextValues>,
   /// Alternative source fetch URLs.
   #[serde(default)]
   urls: Option<TextValues>,
   /// A homepage explicitly retained by the derivation.
   #[serde(default)]
   homepage: Option<TextValues>,
   /// Package metadata explicitly retained by the derivation.
   #[serde(default)]
   meta: Option<Metadata>,
}

/// Optional metadata shapes preserve strings without rejecting other Nix
/// values.
#[derive(Deserialize)]
#[serde(untagged)]
enum TextValues {
   /// A scalar string attribute.
   Text(String),
   /// A list of string attributes.
   List(Vec<String>),
   /// Values without usable URL evidence.
   Other(IgnoredAny),
}

impl TextValues {
   /// Exposes the strings retained from an optional attribute.
   fn strings(&self) -> &[String] {
      match *self {
         Self::Text(ref value) => slice::from_ref(value),
         Self::List(ref values) => values,
         Self::Other(_ignored) => &[],
      }
   }
}

/// Homepage metadata is optional and may be absent after lowering.
#[derive(Deserialize)]
#[serde(untagged)]
enum Metadata {
   /// Metadata containing an optional homepage.
   Fields {
      /// Homepage values retained by the package expression.
      homepage: Option<TextValues>,
   },
   /// Other metadata shapes provide no homepage evidence.
   Other(IgnoredAny),
}

impl Metadata {
   /// Exposes homepage strings while leaving unavailable metadata empty.
   fn homepages(&self) -> impl Iterator<Item = &str> {
      match *self {
         Self::Fields { ref homepage } => homepage.as_ref(),
         Self::Other(_ignored) => None,
      }
      .into_iter()
      .flat_map(TextValues::strings)
      .map(String::as_str)
   }
}
