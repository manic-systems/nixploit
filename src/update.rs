//! Feed downloads, checksum verification, and archive size limits.

use std::{
   collections::VecDeque,
   env,
   fs::File,
   io::{Read, Seek as _, Write as _, stderr},
   panic::resume_unwind,
   sync::atomic::{AtomicBool, Ordering},
   thread::{Builder, scope},
   time::Duration,
};

use flate2::read::MultiGzDecoder;
use hmac_sha256::Hash;
use jiff::{Timestamp, tz::TimeZone};
use misstep::{OptionExt as _, Report, Result, ResultExt as _, ensure, report};
use rustls_native_certs::load_native_certs;
use serde::Deserialize;
use tempfile::NamedTempFile;
use ureq::{
   Agent, Error as HttpError,
   tls::{Certificate, RootCerts, TlsConfig},
};

use crate::{
   database::{Database, FeedState, Provider},
   digest::Sha256,
   osv::Dump,
};

/// Default directory containing NVD yearly archives and metadata.
pub const NVD_MIRROR: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
/// Default bucket publishing OSV per-ecosystem dumps.
pub const OSV_MIRROR: &str = "https://osv-vulnerabilities.storage.googleapis.com";
/// Maximum compressed download or decompressed checksum input size.
const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Refresh the requested yearly NVD archives after checking their digests.
pub fn nvd(
   database: &mut Database,
   mirror: &str,
   first_year: i32,
   through_year: Option<i32>,
) -> Result<()> {
   let current_year = i32::from(Timestamp::now().to_zoned(TimeZone::UTC).year());
   let last_year = through_year.unwrap_or(current_year);

   ensure!(
      first_year >= 2002_i32 && first_year <= last_year && last_year <= current_year,
      "Feed years must be between 2002 and {}",
      current_year
   );
   ensure!(
      mirror.starts_with("https://") || mirror.starts_with("http://"),
      "Invalid mirror URL"
   );
   let client = &client()?;
   let cancelled = &AtomicBool::new(false);

   let mut pending = (first_year..=last_year)
      .map(|year| {
         let base = format!("{}/nvdcve-2.0-{year}", mirror.trim_end_matches('/'));

         let name = format!("nvd/{year}");
         let cached = database.feed(&name)?;
         let unpublished = year == current_year && !database.has_feed(&name)?;
         Ok((year, base, cached, unpublished))
      })
      .collect::<Result<Vec<_>>>()?
      .into_iter();

   let checked = scope(|workers| {
      let start = |(year, base, cached, unpublished): (i32, String, Option<FeedState>, bool)| {
         Builder::new().spawn_scoped(workers, move || {
            let archive = download_nvd(client, year, &base, cached, unpublished, cancelled)?;
            Ok::<_, Report>(archive.map(|(state, file)| (year, state, file, unpublished)))
         })
      };

      let mut active = VecDeque::new();
      let mut completed = Vec::new();

      for feed in pending.by_ref().take(4) {
         active.push_back(start(feed)?);
      }

      let mut drain = || {
         while let Some(worker) = active.pop_front() {
            let downloaded = worker.join().unwrap_or_else(|panic| resume_unwind(panic))?;

            if let Some(feed) = pending.next() {
               active.push_back(start(feed)?);
            }

            let Some((year, mut state, archive, unpublished)) = downloaded else {
               continue;
            };

            if let Some(file) = archive {
               let records = database.import(file.path(), Provider::Nvd, &state.name)?;

               if records == 0 && unpublished {
                  writeln!(
                     stderr().lock(),
                     "Warning, NVD {year} is empty, skipping until publication"
                  )?;
                  continue;
               }

               ensure!(records > 0, "NVD {} contains no CVE records", year);
               state.records = u32::try_from(records)?;

               writeln!(stderr().lock(), "NVD {year} indexed {records} CVEs")?;
            } else {
               writeln!(stderr().lock(), "NVD {year} unchanged")?;
            }

            completed.push(state);
         }

         Ok::<_, Report>(())
      };

      // Scoped workers are joined before an error leaves the scope, so stop
      // their downloads instead of waiting for whole archives.
      if let Err(error) = drain() {
         cancelled.store(true, Ordering::Relaxed);
         return Err(error);
      }

      ensure!(
         !completed.is_empty(),
         "No NVD feeds are available for the requested years"
      );
      Ok::<_, Report>(completed)
   })?;

   database.activate_feeds(Provider::Nvd, &checked)
}

/// Downloads and verifies one yearly archive before the database writer sees it.
fn download_nvd(
   client: &Agent,
   year: i32,
   base: &str,
   cached: Option<FeedState>,
   unpublished: bool,
   cancelled: &AtomicBool,
) -> Result<Option<(FeedState, Option<NamedTempFile>)>> {
   let fetch = |suffix| -> Result<_> {
      match client.get(format!("{base}.{suffix}")).call() {
         Err(HttpError::StatusCode(404)) if unpublished => {
            writeln!(
               stderr().lock(),
               "Warning, NVD {year} is not published yet, skipping"
            )?;
            Ok(None)
         },
         response => response
            .map(Some)
            .with_context(|| format!("Fetching NVD {year} {suffix}"))
            .erase(),
      }
   };
   let mut retried = false;

   let (digest_text, archive) = loop {
      let Some(mut metadata_response) = fetch("meta")? else {
         return Ok(None);
      };
      let metadata = metadata_response.body_mut().read_to_string()?;
      let digest = metadata
         .lines()
         .find_map(|line| line.strip_prefix("sha256:"))
         .with_context(|| format!("NVD metadata for {year} has no checksum"))?
         .trim()
         .parse::<Sha256>()
         .with_context(|| format!("Invalid NVD checksum for {year}"))?;
      let digest_text = digest.to_string();

      if cached
         .as_ref()
         .is_some_and(|state| state.digest == digest_text)
      {
         break (digest_text, None);
      }

      writeln!(stderr().lock(), "Downloading NVD {year}")?;
      let Some(mut response) = fetch("json.gz")? else {
         return Ok(None);
      };
      let compressed = download(response.body_mut().as_reader(), cancelled)?;
      let mut decoded = MultiGzDecoder::new(File::open(compressed.path())?);

      if Sha256::read_from(&mut decoded, MAX_ARCHIVE_BYTES)? == digest {
         break (digest_text, Some(compressed));
      }

      // NVD regenerates archives in place, so the metadata fetched first can
      // describe an older archive than the body that followed it.
      ensure!(!retried, "NVD checksum mismatch for {}", year);
      retried = true;
      writeln!(
         stderr().lock(),
         "NVD {year} changed during download, retrying"
      )?;
   };
   let state = FeedState {
      name: format!("nvd/{year}"),
      digest: digest_text,
      checked_at: Timestamp::now().as_second(),
      records: cached.map_or(0, |state| state.records),
   };

   Ok(Some((state, archive)))
}

/// Refresh `VulnCheck` backups using the environment token.
pub fn vulncheck(database: &mut Database) -> Result<()> {
   let token = env::var("VULNCHECK_API_TOKEN")
      .context("Set VULNCHECK_API_TOKEN to download VulnCheck NVD++")?;
   ensure!(!token.trim().is_empty(), "VULNCHECK_API_TOKEN is empty");
   let client = client()?;
   let endpoint = "https://api.vulncheck.com/v3/backup/nist-nvd2";

   let response = client
      .get(endpoint)
      .header("Authorization", format!("Bearer {token}"))
      .call()
      .context("Requesting VulnCheck NVD++ backup")?
      .body_mut()
      .read_json::<BackupResponse>()?;

   ensure!(
      !response.data.is_empty(),
      "VulnCheck returned no backup URLs"
   );

   for backup in &response.data {
      ensure!(
         backup.url.starts_with("https://"),
         "VulnCheck backup URL must use HTTPS"
      );
   }

   let mut checksums = response
      .data
      .iter()
      .map(|backup| backup.sha256)
      .collect::<Vec<_>>();
   checksums.sort_unstable();
   let mut hasher = Hash::new();

   for checksum in checksums {
      hasher.update(checksum.to_string());
   }

   let digest = Sha256::from(hasher.finalize()).to_string();
   let key = "vulncheck/nist-nvd2";
   let timestamp = Timestamp::now().as_second();

   if let Some(mut cached) = database.feed(key)?
      && cached.digest == digest
   {
      cached.checked_at = timestamp;
      database.activate_feeds(Provider::Vulncheck, &[cached])?;
      writeln!(stderr().lock(), "VulnCheck backup unchanged")?;
      return Ok(());
   }

   let mut records = 0;

   for backup in response.data {
      writeln!(stderr().lock(), "Downloading VulnCheck NVD++")?;
      let mut download_response = client
         .get(&backup.url)
         .call()
         .map_err(|error| {
            // Presigned URLs grant access to the backup, so keep them out of
            // error reports.
            if matches!(error, HttpError::BadUri(_) | HttpError::RequireHttpsOnly(_)) {
               report!("Invalid VulnCheck backup URL")
            } else {
               Report::new(error)
            }
         })
         .context("Downloading VulnCheck NVD++ backup")?;
      let mut archive = download(
         download_response.body_mut().as_reader(),
         &AtomicBool::new(false),
      )?;
      archive.rewind()?;
      let archive_digest = Sha256::read_from(&mut archive, MAX_ARCHIVE_BYTES)?;

      ensure!(
         archive_digest == backup.sha256,
         "VulnCheck backup checksum mismatch"
      );

      let imported = database.import(archive.path(), Provider::Vulncheck, key)?;
      ensure!(imported > 0, "VulnCheck backup contains no CVE records");
      records += imported;
   }

   database.activate_feeds(
      Provider::Vulncheck,
      &[FeedState {
         name: key.to_owned(),
         digest,
         checked_at: timestamp,
         records: u32::try_from(records)?,
      }],
   )?;

   writeln!(stderr().lock(), "Indexed {records} CVEs from VulnCheck")?;

   Ok(())
}

/// Refresh the requested OSV dumps when their stored object changed.
pub fn osv(database: &mut Database, mirror: &str, ecosystems: &[Dump]) -> Result<()> {
   ensure!(
      mirror.starts_with("https://") || mirror.starts_with("http://"),
      "Invalid mirror URL"
   );

   let client = client()?;
   let mut checked = Vec::new();

   for ecosystem in ecosystems {
      let name = format!("osv/{ecosystem}");
      let cached = database.feed(&name)?;
      let mut response = client
         .get(format!(
            "{}/{ecosystem}/all.zip",
            mirror.trim_end_matches('/')
         ))
         .call()
         .with_context(|| format!("Fetching OSV {ecosystem}"))?;
      let header = |key| {
         response
            .headers()
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
      };
      let digest = header("x-goog-generation")
         .or_else(|| header("etag"))
         .with_context(|| format!("OSV {ecosystem} response has no generation or ETag"))?;
      let checked_at = Timestamp::now().as_second();

      if let Some(state) = cached.filter(|state| state.digest == digest) {
         writeln!(stderr().lock(), "OSV {ecosystem} unchanged")?;
         checked.push(FeedState {
            checked_at,
            ..state
         });
         continue;
      }

      writeln!(stderr().lock(), "Downloading OSV {ecosystem}")?;
      let archive = download(response.body_mut().as_reader(), &AtomicBool::new(false))?;
      let records = database.import(archive.path(), Provider::Osv, &name)?;

      ensure!(records > 0, "OSV {} contains no records", ecosystem);
      writeln!(stderr().lock(), "OSV {ecosystem} indexed {records} records")?;
      checked.push(FeedState {
         name,
         digest,
         checked_at,
         records: u32::try_from(records)?,
      });
   }

   database.activate_feeds(Provider::Osv, &checked)
}

/// Set deadlines for request setup while allowing large response bodies.
fn client() -> Result<Agent> {
   let loaded = load_native_certs();

   for error in &loaded.errors {
      writeln!(stderr().lock(), "Loading CA certificates: {error}")?;
   }

   ensure!(
      !loaded.certs.is_empty(),
      "No CA certificates found, set SSL_CERT_FILE to a PEM bundle"
   );
   let roots = loaded
      .certs
      .iter()
      .map(|der| Certificate::from_der(der).to_owned())
      .collect::<Vec<_>>();
   let tls = TlsConfig::builder()
      .root_certs(RootCerts::new_with_certs(&roots))
      .build();

   let config = Agent::config_builder()
      .tls_config(tls)
      .timeout_resolve(Some(Duration::from_secs(30)))
      .timeout_connect(Some(Duration::from_secs(30)))
      .timeout_send_request(Some(Duration::from_secs(30)))
      .timeout_recv_response(Some(Duration::from_secs(60)))
      .timeout_per_read(Some(Duration::from_secs(60)))
      .user_agent(concat!("nixploit/", env!("CARGO_PKG_VERSION")))
      .build();

   Ok(Agent::new_with_config(config))
}

/// Store a bounded response body in a temporary file.
fn download<R>(mut reader: R, cancelled: &AtomicBool) -> Result<NamedTempFile>
where
   R: Read,
{
   let mut file = NamedTempFile::new()?;
   let mut buffer = vec![0; 64 * 1024].into_boxed_slice();
   let mut size = 0;

   loop {
      ensure!(
         !cancelled.load(Ordering::Relaxed),
         "Download stopped because another feed failed"
      );

      let count = reader.read(&mut buffer)?;

      if count == 0 {
         break;
      }

      size += u64::try_from(count)?;

      if size > MAX_ARCHIVE_BYTES {
         break;
      }

      file.write_all(&buffer[..count])?;
   }

   ensure!(
      size <= MAX_ARCHIVE_BYTES,
      "Feed archive exceeds the 2 GiB size limit"
   );
   file.flush()?;

   Ok(file)
}

/// Backup files returned by the `VulnCheck` index endpoint.
#[derive(Deserialize)]
struct BackupResponse {
   /// Signed archive locations and their expected checksums.
   data: Vec<Backup>,
}

/// Download metadata for one `VulnCheck` backup archive.
#[derive(Deserialize)]
struct Backup {
   /// Expected archive digest in hexadecimal.
   sha256: Sha256,
   /// Signed HTTPS address for the archive body.
   url: String,
}
