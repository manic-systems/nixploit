//! Scans Nix package inventories against NVD and CNA vulnerability evidence.

#![expect(
   clippy::multiple_crate_versions,
   reason = "Selected dependencies require incompatible transitive crate \
             versions"
)]

/// NVD and CNA advisory representations.
mod advisory;
/// User aliases and suppression rules.
mod config;
/// Persistent advisory index.
mod database;
mod digest;
/// Streamed vulnerability feed decoding.
mod feed;
mod history;
mod identifier;
mod identity;
/// Nix closure inventory collection.
mod inventory;
mod kbuild;
/// Advisory and package matching.
mod matching;
/// Prometheus report rendering.
mod metrics;
mod nvd;
mod osv;
/// Text and JSON report rendering.
mod output;
mod source;
mod update;
mod version;

use std::{
   collections::BTreeSet,
   env, fs,
   io::{self, Write as _},
   path::{Path, PathBuf},
   process::ExitCode,
   time::Instant,
};

use jiff::Timestamp;
use mimalloc::MiMalloc;
use misstep::{OptionExt as _, Report as ErrorReport, Result, ensure};
use pound::{Error as ParseError, Parse};

use crate::{
   config::Config,
   database::{Database, FeedState, Provider},
   history::History,
   inventory::{Inventory, InventoryArgs},
   matching::Bucket,
   osv::Dump,
   output::Report,
};

/// Allocator shared by parallel feed preparation workers.
#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

/// Scan Nix packages against CPE and CNA vulnerability data.
#[derive(Parse)]
#[pound(name = "nixploit")]
struct Cli {
   /// Use this cache directory.
   #[pound(long, global, value_name = "DIRECTORY")]
   cache_dir: Option<PathBuf>,
   #[pound(subcommand)]
   /// Operation to perform.
   command: Option<Command>,
}

/// Available scanner operations.
#[derive(Parse)]
enum Command {
   /// Scan the runtime closure using the imported database.
   Scan {
      #[pound(positional, value_name = "PATH")]
      /// Nix paths to scan.
      paths: Vec<PathBuf>,
      /// Include the running NixOS system.
      #[pound(long)]
      system: bool,
      /// Include build dependencies.
      #[pound(long, conflicts_with = "no_requisites")]
      build_deps: bool,
      /// Inspect only the named paths.
      #[pound(short = 'R', long)]
      no_requisites: bool,
      /// Add a package without querying Nix.
      #[pound(long, value_name = "NAME@VERSION")]
      package: Vec<String>,
      /// Read a saved nixploit inventory.
      #[pound(long, value_name = "JSON")]
      inventory: Option<PathBuf>,
      #[pound(long, value_name = "TOML")]
      /// Configuration file to load.
      config: Option<PathBuf>,
      #[pound(long)]
      /// Emit JSON output.
      json: bool,
      /// Atomically write Prometheus metrics to this file.
      #[pound(long, value_name = "PATH")]
      prometheus_file: Option<PathBuf>,
      /// Show descriptions with findings.
      #[pound(long)]
      descriptions: bool,
      /// Show findings suppressed by patches or ignore rules.
      #[pound(long)]
      show_suppressed: bool,
      /// Report only CVEs marked as known exploited by CISA in the feed.
      #[pound(long)]
      kev_only: bool,
   },
   /// Download and index vulnerability feeds.
   Update {
      #[pound(long, default = "nvd")]
      /// Feed provider to update.
      provider: Provider,
      #[pound(long)]
      /// NVD archive or OSV bucket mirror base URL.
      mirror: Option<String>,
      #[pound(long)]
      /// First NVD archive year, 2002 when omitted.
      from_year: Option<i32>,
      #[pound(long)]
      /// Last NVD archive year.
      through_year: Option<i32>,
      #[pound(long, value_name = "ECOSYSTEM")]
      /// OSV ecosystem dump to refresh, every supported one when omitted.
      ecosystem: Vec<Dump>,
   },
   /// Clone or refresh the upstream repositories that can decide affected
   /// findings.
   History {
      #[pound(positional, value_name = "PATH")]
      /// Nix paths to scan.
      paths: Vec<PathBuf>,
      /// Include the running NixOS system.
      #[pound(long)]
      system: bool,
      /// Include build dependencies.
      #[pound(long, conflicts_with = "no_requisites")]
      build_deps: bool,
      /// Inspect only the named paths.
      #[pound(short = 'R', long)]
      no_requisites: bool,
      /// Add a package without querying Nix.
      #[pound(long, value_name = "NAME@VERSION")]
      package: Vec<String>,
      /// Read a saved nixploit inventory.
      #[pound(long, value_name = "JSON")]
      inventory: Option<PathBuf>,
      #[pound(long, value_name = "TOML")]
      /// Configuration file to load.
      config: Option<PathBuf>,
   },
   /// Import JSON, gzip, or ZIP feeds without network access.
   Import {
      #[pound(positional, value_name = "FILE", min_values = 1)]
      /// Feed files to import.
      files: Vec<PathBuf>,
      #[pound(long, default = "nvd")]
      /// Provider represented by the files.
      provider: Provider,
   },
   /// Export package and patch metadata from Nix.
   Inventory {
      #[pound(positional, value_name = "PATH")]
      /// Nix paths to inspect.
      paths: Vec<PathBuf>,
      /// Include the running NixOS system.
      #[pound(long)]
      system: bool,
      /// Include build dependencies.
      #[pound(long, conflicts_with = "no_requisites")]
      build_deps: bool,
      /// Inspect only the named paths.
      #[pound(short = 'R', long)]
      no_requisites: bool,
      /// Add a package without querying Nix.
      #[pound(long, value_name = "NAME@VERSION")]
      package: Vec<String>,
      /// Read a saved nixploit inventory.
      #[pound(long, value_name = "JSON")]
      inventory: Option<PathBuf>,
   },
   /// Show database coverage and feed check times.
   Stats,
}

/// Inputs used by the scanner.
struct ScanArgs {
   /// Package inventory selection.
   inventory: InventoryArgs,
   /// Optional scanner configuration.
   config: Option<PathBuf>,
   /// Report formatting options.
   output: OutputArgs,
   /// Whether to retain only known exploited vulnerabilities.
   kev_only: bool,
}

/// Provider options for one feed update.
struct UpdateArgs {
   /// Mirror replacing the provider's default base URL.
   mirror: Option<String>,
   /// First NVD archive year.
   from_year: Option<i32>,
   /// Last NVD archive year.
   through_year: Option<i32>,
   /// OSV dumps to refresh.
   ecosystems: Vec<Dump>,
}

/// Report formatting options.
struct OutputArgs {
   /// Whether to emit JSON.
   json: bool,
   /// Optional Prometheus textfile destination.
   prometheus_file: Option<PathBuf>,
   /// Whether to include descriptions.
   descriptions: bool,
   /// Whether to include suppressed findings.
   show_suppressed: bool,
}

/// Parses arguments and maps scanner results to process exit codes.
fn main() -> ExitCode {
   let raw_arguments = match raw_arguments() {
      Ok(arguments) => arguments,
      Err(error) => {
         let _result = writeln!(io::stderr().lock(), "{error}");
         return ExitCode::from(2);
      }
   };
   let parsed = Cli::try_parse_from(raw_arguments.iter().map(String::as_str));

   let cli = match parsed {
      Ok(cli) => cli,
      Err(error) => return parse_exit(&error),
   };

   match run(cli) {
      Ok(code) => code,
      Err(error) => {
         let _result = writeln!(io::stderr().lock(), "{error}");
         ExitCode::from(2)
      }
   }
}

/// Collects command-line arguments without replacing invalid UTF-8.
fn raw_arguments() -> Result<Vec<String>> {
   env::args_os()
      .skip(1)
      .map(|argument| {
         argument
            .into_string()
            .map_err(|_argument| ErrorReport::msg("Command-line argument is not valid UTF-8"))
      })
      .collect()
}

/// Renders a parser outcome and returns its process status.
fn parse_exit(error: &ParseError) -> ExitCode {
   let written = if error.is_exit() {
      writeln!(io::stdout().lock(), "{}", error.render())
   } else {
      writeln!(io::stderr().lock(), "{}", error.render())
   };

   if written.is_err() || !error.is_exit() {
      ExitCode::from(2)
   } else {
      ExitCode::SUCCESS
   }
}

/// Executes one parsed command.
#[expect(
   clippy::too_many_lines,
   reason = "pound supports neither flattened nor tuple subcommand arguments, so each arm \
             destructures its own flags"
)]
fn run(cli: Cli) -> Result<ExitCode> {
   let command = cli
      .command
      .context("A command is required. Use --help to list commands")?;
   let cache = || {
      cli.cache_dir
         .as_deref()
         .map_or_else(default_cache, |directory| Ok(directory.to_owned()))
   };
   let open_database = || Database::open(&cache()?);

   match command {
      Command::Inventory {
         paths,
         system,
         build_deps,
         no_requisites,
         package,
         inventory,
      } => {
         let arguments = InventoryArgs {
            paths,
            system,
            build_deps,
            no_requisites,
            package,
            inventory,
         };

         write_json(&Inventory::try_from(&arguments)?)?;
         Ok(ExitCode::SUCCESS)
      }
      Command::Scan {
         paths,
         system,
         build_deps,
         no_requisites,
         package,
         inventory,
         config,
         json,
         prometheus_file,
         descriptions,
         show_suppressed,
         kev_only,
      } => {
         let database = open_database()?;

         scan(
            &database,
            &History::new(&cache()?),
            &ScanArgs {
               inventory: InventoryArgs {
                  paths,
                  system,
                  build_deps,
                  no_requisites,
                  package,
                  inventory,
               },
               config,
               output: OutputArgs {
                  json,
                  prometheus_file,
                  descriptions,
                  show_suppressed,
               },
               kev_only,
            },
         )
      }
      Command::Update {
         provider,
         mirror,
         from_year,
         through_year,
         ecosystem,
      } => {
         let mut database = open_database()?;

         update_database(
            &mut database,
            provider,
            UpdateArgs {
               mirror,
               from_year,
               through_year,
               ecosystems: ecosystem,
            },
         )?;

         write_json(&database.stats()?)?;
         Ok(ExitCode::SUCCESS)
      }
      Command::History {
         paths,
         system,
         build_deps,
         no_requisites,
         package,
         inventory,
         config,
      } => {
         let database = open_database()?;

         sync_history(
            &database,
            &History::new(&cache()?),
            &InventoryArgs {
               paths,
               system,
               build_deps,
               no_requisites,
               package,
               inventory,
            },
            config.as_deref(),
         )
      }
      Command::Import { files, provider } => {
         let mut database = open_database()?;

         import_files(&mut database, files, provider)?;
         write_json(&database.stats()?)?;
         Ok(ExitCode::SUCCESS)
      }
      Command::Stats => {
         let database = open_database()?;

         write_json(&database.stats()?)?;
         Ok(ExitCode::SUCCESS)
      }
   }
}

/// Updates the database from the selected remote provider.
fn update_database(
   database: &mut Database,
   provider: Provider,
   arguments: UpdateArgs,
) -> Result<()> {
   let years = arguments.from_year.is_some() || arguments.through_year.is_some();

   ensure!(
      provider == Provider::Nvd || !years,
      "--from-year and --through-year only apply to the NVD provider"
   );
   ensure!(
      provider == Provider::Osv || arguments.ecosystems.is_empty(),
      "--ecosystem only applies to the OSV provider"
   );
   ensure!(
      provider != Provider::Vulncheck || arguments.mirror.is_none(),
      "--mirror does not apply to the VulnCheck provider"
   );

   match provider {
      Provider::Nvd => update::nvd(
         database,
         arguments.mirror.as_deref().unwrap_or(update::NVD_MIRROR),
         arguments.from_year.unwrap_or(2002),
         arguments.through_year,
      ),
      Provider::Vulncheck => update::vulncheck(database),
      Provider::Osv => {
         let ecosystems = if arguments.ecosystems.is_empty() {
            Dump::ALL.to_vec()
         } else {
            arguments.ecosystems
         };

         update::osv(
            database,
            arguments.mirror.as_deref().unwrap_or(update::OSV_MIRROR),
            &ecosystems,
         )
      }
   }
}

/// Imports local feed files and reports their record counts.
fn import_files(database: &mut Database, files: Vec<PathBuf>, provider: Provider) -> Result<()> {
   let mut total_records = 0;
   let name = format!("{provider}/import");

   for path in files {
      let canonical = fs::canonicalize(&path)?;
      let records = database.import(&canonical, provider, &name)?;
      ensure!(
         records > 0,
         "Feed {} contains no vulnerability records",
         path.display()
      );
      total_records += records;

      writeln!(
         io::stderr().lock(),
         "Imported {records} records from {}",
         path.display()
      )?;
   }

   database.activate_feeds(
      provider,
      &[FeedState {
         name,
         digest: "local".to_owned(),
         checked_at: Timestamp::now().as_second(),
         records: u32::try_from(total_records)?,
      }],
   )
}

/// Refreshes one clone per affected finding whose commit ranges name an
/// upstream repository, preferring GitHub and then a mirror already chosen.
fn sync_history(
   database: &Database,
   history: &History,
   arguments: &InventoryArgs,
   config_path: Option<&Path>,
) -> Result<ExitCode> {
   let config = Config::load(config_path)?;
   let inventory = Inventory::try_from(arguments)?;
   let snapshot = database.snapshot()?;
   let mut repositories = BTreeSet::new();

   for package in &inventory.packages {
      for finding in matching::scan_package(database, package, &config, history)? {
         if finding.bucket != Bucket::Affected || finding.suppression.is_some() {
            continue;
         }

         let chosen = finding
            .repositories
            .iter()
            .find(|repository| repository.starts_with("https://github.com/"))
            .or_else(|| {
               finding
                  .repositories
                  .iter()
                  .find(|repository| repositories.contains(*repository))
            })
            .or_else(|| finding.repositories.first());

         if let Some(repository) = chosen {
            repositories.insert(repository.to_owned());
         }
      }
   }

   snapshot.commit()?;

   let failures = repositories
      .iter()
      .filter(|repository| match history.sync(repository) {
         Ok(()) => false,
         Err(error) => {
            let _result = writeln!(io::stderr().lock(), "{error}");
            true
         }
      })
      .count();

   if failures > 0 {
      writeln!(
         io::stderr().lock(),
         "{} of {} repositories failed to sync, their findings stay unsuppressed",
         failures,
         repositories.len()
      )?;
      return Ok(ExitCode::from(1));
   }

   writeln!(
      io::stderr().lock(),
      "Synced {} repositories",
      repositories.len()
   )?;
   Ok(ExitCode::SUCCESS)
}

/// Scans one collected inventory against the advisory database.
fn scan(database: &Database, history: &History, arguments: &ScanArgs) -> Result<ExitCode> {
   let config = Config::load(arguments.config.as_deref())?;
   let inventory_started = Instant::now();
   let inventory = Inventory::try_from(&arguments.inventory)?;
   let inventory_duration_seconds = inventory_started.elapsed().as_secs_f64();
   let snapshot = database.snapshot()?;
   let stats = database.stats()?;

   ensure!(
      stats.providers.iter().any(|provider| provider.records > 0),
      "No vulnerability data is cached. Run nixploit update or nixploit \
       import first"
   );

   let mut report = Report {
      scanned_packages: inventory.packages.len(),
      skipped_paths: inventory.skipped,
      missing_derivations: inventory.missing_derivations,
      inventory_duration_seconds,
      database: stats,
      affected: Vec::new(),
      unknown: Vec::new(),
      suppressed: Vec::new(),
   };

   for package in &inventory.packages {
      for finding in matching::scan_package(database, package, &config, history)? {
         if arguments.kev_only && !finding.known_exploited {
            continue;
         }

         if finding.suppression.is_some() {
            report.suppressed.push(finding);
         } else {
            match finding.bucket {
               Bucket::Affected => report.affected.push(finding),
               Bucket::Unknown => report.unknown.push(finding),
            }
         }
      }
   }

   snapshot.commit()?;
   report.sort();

   let exit_status = if report.affected.is_empty() {
      ExitCode::SUCCESS
   } else {
      ExitCode::FAILURE
   };

   if arguments.output.json {
      write_json(&report)?;
   } else {
      report.write(
         &mut io::stdout().lock(),
         arguments.output.descriptions,
         arguments.output.show_suppressed,
      )?;
   }

   if let Some(path) = arguments.output.prometheus_file.as_deref() {
      metrics::write(&report, path)?;
   }

   Ok(exit_status)
}

/// Writes a serializable value as pretty JSON.
fn write_json(value: &impl serde::Serialize) -> Result<()> {
   let mut stdout = io::stdout().lock();
   serde_json::to_writer_pretty(&mut stdout, value)?;
   writeln!(stdout)?;
   Ok(())
}

/// Resolves the default cache directory.
fn default_cache() -> Result<PathBuf> {
   if let Some(path) = env::var_os("XDG_CACHE_HOME") {
      let directory = PathBuf::from(path);

      if directory.is_absolute() {
         return Ok(directory.join("nixploit"));
      }
   }

   let home_directory = env::var_os("HOME").context("Set XDG_CACHE_HOME or pass --cache-dir")?;

   Ok(PathBuf::from(home_directory).join(".cache/nixploit"))
}
