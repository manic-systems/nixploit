use std::{
   collections::{BTreeMap, BTreeSet},
   fmt::{Display, Formatter, Result as FormatResult},
   fs,
   path::Path,
   time::Duration,
};

use lz4_flex::block::{compress_prepend_size, decompress_size_prepended, uncompressed_size};
use misstep::{Report, Result, ResultExt as _, ensure};
use pound::ValueEnum;
use rusqlite::{
   Connection, OptionalExtension as _, Result as SqlResult, ToSql, Transaction, params,
   types::{FromSql, FromSqlResult, ToSqlOutput, ValueRef},
};
use serde::Serialize;

use crate::{
   advisory::{Advisory, Vulnerability},
   feed::{self, BufferedRecord, Format},
   identifier::{NormalizedName, VulnerabilityId},
};

/// Layout of the cache tables and record payloads, bumped whenever either
/// changes shape.
const SCHEMA_VERSION: i64 = 6;

/// Vulnerability feed provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
   /// The NIST National Vulnerability Database.
   Nvd,
   /// The `VulnCheck` NVD++ feed.
   Vulncheck,
   /// The OSV per-ecosystem vulnerability dumps.
   Osv,
}

impl Provider {
   /// Returns the provider's storage label.
   const fn as_str(self) -> &'static str {
      match self {
         Self::Nvd => "nvd",
         Self::Vulncheck => "vulncheck",
         Self::Osv => "osv",
      }
   }

   /// Selects the record layout this provider publishes.
   const fn format(self) -> Format {
      match self {
         Self::Nvd | Self::Vulncheck => Format::Nvd,
         Self::Osv => Format::Osv,
      }
   }
}

impl Display for Provider {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      formatter.write_str(self.as_str())
   }
}

impl ToSql for Provider {
   fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
      Ok(self.as_str().into())
   }
}

/// SQLite-backed advisory index.
pub struct Database {
   /// Open connection to the advisory cache.
   connection: Connection,
}

/// Compressed canonical JSON of one cached record.
struct Payload(Vec<u8>);

impl TryFrom<&Advisory> for Payload {
   type Error = Report;

   fn try_from(advisory: &Advisory) -> Result<Self> {
      Ok(Self(compress_prepend_size(&serde_json::to_vec(advisory)?)))
   }
}

impl TryFrom<Payload> for Advisory {
   type Error = Report;

   /// Decodes a payload within the feed's decompressed size bound.
   fn try_from(payload: Payload) -> Result<Self> {
      let (size, _compressed) = uncompressed_size(&payload.0)?;

      ensure!(
         size <= 2 * 1024 * 1024 * 1024,
         "Cached advisory exceeds the 2 GiB size limit"
      );
      Ok(serde_json::from_slice(&decompress_size_prepended(
         &payload.0,
      )?)?)
   }
}

impl ToSql for Payload {
   fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
      self.0.to_sql()
   }
}

impl FromSql for Payload {
   fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
      Vec::column_result(value).map(Self)
   }
}

/// Validated and compressed record ready for the database writer.
struct PreparedAdvisory {
   /// Record identifier within its provider.
   id: VulnerabilityId,
   /// Vulnerability identifiers the record describes.
   vulnerabilities: Vec<VulnerabilityId>,
   /// Canonical record revision timestamp.
   modified: String,
   /// Compressed canonical JSON retained for offline scans.
   payload: Payload,
   /// Distinct names indexed for candidate lookup.
   products: Vec<NormalizedName>,
   /// Presence of CPE claims.
   has_cpe: bool,
   /// Presence of product claims.
   has_claims: bool,
   /// Whether the publisher rejected or withdrew this record.
   rejected: bool,
}

impl TryFrom<Advisory> for PreparedAdvisory {
   type Error = Report;

   fn try_from(advisory: Advisory) -> Result<Self> {
      let products = if advisory.rejected {
         Vec::new()
      } else {
         advisory.claims.products().into_iter().collect()
      };

      Ok(Self {
         modified: advisory.modified.to_string(),
         payload: Payload::try_from(&advisory)?,
         products,
         has_cpe: !advisory.claims.cpes.is_empty(),
         has_claims: !advisory.claims.affected.is_empty(),
         rejected: advisory.rejected,
         vulnerabilities: advisory.vulnerabilities.into_iter().collect(),
         id: advisory.id,
      })
   }
}

impl BufferedRecord for PreparedAdvisory {
   fn heap_bytes(&self) -> usize {
      self.id.as_ref().len()
         + self.modified.capacity()
         + self.payload.0.capacity()
         + self.products.capacity() * size_of::<NormalizedName>()
         + self.vulnerabilities.capacity() * size_of::<VulnerabilityId>()
         + self
            .products
            .iter()
            .map(|product| product.as_ref().len())
            .chain(
               self
                  .vulnerabilities
                  .iter()
                  .map(|identifier| identifier.as_ref().len()),
            )
            .sum::<usize>()
   }
}

/// Merged vulnerabilities and identity ambiguity in their cached claims.
pub struct Candidates {
   /// Vulnerabilities with claims from every provider that describes them.
   pub vulnerabilities: Vec<Vulnerability>,
   /// Requested product names claimed by multiple vendors.
   pub ambiguous_products: BTreeSet<NormalizedName>,
}

/// Aggregate advisory database coverage.
#[derive(Serialize)]
pub struct Stats {
   /// Distinct vulnerabilities described by a non-rejected record.
   pub vulnerabilities: u32,
   /// Record coverage for each provider with cached data.
   pub providers: Vec<ProviderStats>,
   /// Imported feed state.
   pub feeds: Vec<FeedState>,
}

/// Record coverage for one provider.
#[derive(Serialize)]
pub struct ProviderStats {
   /// Provider storage label.
   pub provider: String,
   /// Cached records including rejected ones.
   pub records: u32,
   /// Records the publisher rejected or withdrew.
   pub rejected: u32,
   /// Non-rejected records carrying CPE claims.
   pub with_cpe: u32,
   /// Non-rejected records carrying product claims.
   pub with_claims: u32,
   /// Non-rejected records without an indexed product.
   pub without_product: u32,
}

/// Last imported state for one feed archive.
#[derive(Serialize)]
pub struct FeedState {
   /// Stable archive name.
   pub name: String,
   #[serde(skip_serializing)]
   /// Digest used to recognize an unchanged archive.
   pub digest: String,
   /// Last successful check as a Unix timestamp.
   pub checked_at: i64,
   /// Number of records covered by this state.
   pub records: u32,
}

impl Database {
   /// Opens or creates an advisory database.
   pub fn open(directory: &Path) -> Result<Self> {
      fs::create_dir_all(directory)?;

      let connection = Connection::open(directory.join("advisories.sqlite3"))?;

      connection.busy_timeout(Duration::from_secs(60))?;
      connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA cache_size = -65536;")?;

      let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;

      // Every table is rebuilt from the feeds, so a layout change discards the
      // cache and the next update or import repopulates it.
      if version != SCHEMA_VERSION {
         connection.execute_batch(&format!(
            "DROP TABLE IF EXISTS advisory_checks;
             DROP TABLE IF EXISTS record_checks;
             DROP TABLE IF EXISTS products;
             DROP TABLE IF EXISTS aliases;
             DROP TABLE IF EXISTS advisories;
             DROP TABLE IF EXISTS records;
             DROP TABLE IF EXISTS feeds;
             PRAGMA user_version = {SCHEMA_VERSION};"
         ))?;
      }

      connection.execute_batch(
         "PRAGMA foreign_keys = ON;
          CREATE TABLE IF NOT EXISTS records (
             id TEXT NOT NULL,
             provider TEXT NOT NULL,
             modified TEXT NOT NULL,
             payload BLOB NOT NULL,
             revision INTEGER NOT NULL,
             has_cpe INTEGER NOT NULL,
             has_claims INTEGER NOT NULL,
             rejected INTEGER NOT NULL,
             PRIMARY KEY (id, provider)
          );
          CREATE TABLE IF NOT EXISTS aliases (
             vulnerability TEXT NOT NULL,
             id TEXT NOT NULL,
             provider TEXT NOT NULL,
             PRIMARY KEY (vulnerability, id, provider),
             FOREIGN KEY (id, provider) REFERENCES records (id, provider) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS aliases_record ON aliases(id, provider);
          CREATE TABLE IF NOT EXISTS products (
             name TEXT NOT NULL,
             id TEXT NOT NULL,
             provider TEXT NOT NULL,
             PRIMARY KEY (name, id, provider),
             FOREIGN KEY (id, provider) REFERENCES records (id, provider) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS products_record ON products(id, provider);
          CREATE TABLE IF NOT EXISTS feeds (
             name TEXT PRIMARY KEY,
             digest TEXT NOT NULL,
             checked_at INTEGER NOT NULL,
             records INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS record_checks (
             id TEXT NOT NULL,
             provider TEXT NOT NULL,
             feed TEXT NOT NULL REFERENCES feeds(name),
             modified TEXT NOT NULL,
             digest TEXT NOT NULL,
             checked_at INTEGER NOT NULL,
             PRIMARY KEY (id, provider),
             FOREIGN KEY (id, provider) REFERENCES records (id, provider) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS record_checks_feed ON record_checks(feed, digest);
          CREATE TEMP TABLE pending_feeds (
             provider TEXT NOT NULL,
             name TEXT PRIMARY KEY
          );
          CREATE TEMP TABLE pending_record_checks (
             id TEXT NOT NULL,
             provider TEXT NOT NULL,
             feed TEXT NOT NULL,
             revision INTEGER NOT NULL,
             PRIMARY KEY (id, provider)
          );",
      )?;

      Ok(Self { connection })
   }

   /// Imports one feed file atomically.
   pub fn import(&mut self, path: &Path, provider: Provider, name: &str) -> Result<usize> {
      let transaction = self.connection.transaction()?;

      transaction.execute(
         "INSERT OR IGNORE INTO pending_feeds VALUES (?1, ?2)",
         params![provider, name],
      )?;

      let count = feed::read_file(
         path,
         provider.format(),
         &PreparedAdvisory::try_from,
         &mut |advisory| {
            if let Some(revision) = advisory.insert(&transaction, provider)? {
               transaction
                  .prepare_cached(
                     "INSERT INTO pending_record_checks VALUES (?1, ?2, ?3, ?4)
                      ON CONFLICT(id, provider) DO UPDATE SET feed=excluded.feed,
                         revision=excluded.revision",
                  )?
                  .execute(params![advisory.id, provider, name, revision])?;
            }

            Ok(())
         },
      )
      .with_context(|| format!("Importing {}", path.display()))?;

      if count == 0 {
         return Ok(0);
      }

      transaction.commit()?;
      Ok(count)
   }

   /// Returns reusable archive state backed by retained record checks.
   pub fn feed(&self, name: &str) -> Result<Option<FeedState>> {
      Ok(self
         .connection
         .query_row(
            "SELECT name, digest, checked_at, records FROM feeds WHERE name=?1
             AND EXISTS (SELECT 1 FROM record_checks
                WHERE record_checks.feed=feeds.name
                   AND record_checks.digest=feeds.digest)",
            [name],
            |row| {
               Ok(FeedState {
                  name: row.get(0)?,
                  digest: row.get(1)?,
                  checked_at: row.get(2)?,
                  records: row.get(3)?,
               })
            },
         )
         .optional()?)
   }

   /// Distinguishes an unpublished feed from a previously cached archive.
   pub fn has_feed(&self, name: &str) -> Result<bool> {
      Ok(self.connection.query_row(
         "SELECT EXISTS(SELECT 1 FROM feeds WHERE name=?1)",
         [name],
         |row| row.get(0),
      )?)
   }

   /// Publishes retained revision checks after the entire refresh succeeds.
   pub fn activate_feeds(&mut self, provider: Provider, feeds: &[FeedState]) -> Result<()> {
      let transaction = self.connection.transaction()?;

      for state in feeds {
         transaction.execute(
            "INSERT INTO feeds VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET digest=excluded.digest,
                checked_at=excluded.checked_at, records=excluded.records",
            params![state.name, state.digest, state.checked_at, state.records],
         )?;
         transaction.execute(
            "UPDATE record_checks SET checked_at=?3
             WHERE provider=?1 AND feed=?2 AND digest=?4
                AND NOT EXISTS (SELECT 1 FROM pending_feeds
                   WHERE provider=?1 AND name=?2)
                AND EXISTS (SELECT 1 FROM records
                   WHERE records.id=record_checks.id
                      AND records.provider=record_checks.provider
                      AND records.modified=record_checks.modified)",
            params![provider, state.name, state.checked_at, state.digest],
         )?;
         transaction.execute(
            "INSERT INTO record_checks
             SELECT pending.id, pending.provider, pending.feed,
                records.modified, ?4, ?3
             FROM pending_record_checks AS pending JOIN records
                ON records.id=pending.id AND records.provider=pending.provider
             WHERE pending.provider=?1 AND pending.feed=?2
                AND pending.revision=records.revision
             ON CONFLICT(id, provider) DO UPDATE SET feed=excluded.feed,
                modified=excluded.modified, digest=excluded.digest,
                checked_at=excluded.checked_at",
            params![provider, state.name, state.checked_at, state.digest],
         )?;
      }

      transaction.execute(
         "DELETE FROM pending_record_checks WHERE provider=?1",
         [provider],
      )?;
      transaction.execute("DELETE FROM pending_feeds WHERE provider=?1", [provider])?;

      transaction.commit()?;
      Ok(())
   }

   /// Keeps report freshness and candidate reads on one retained revision set.
   pub fn snapshot(&self) -> Result<Transaction<'_>> {
      Ok(self.connection.unchecked_transaction()?)
   }

   /// Loads the vulnerabilities whose records claim a candidate product name.
   pub fn candidates(&self, names: &BTreeSet<NormalizedName>) -> Result<Candidates> {
      let mut identifiers = BTreeSet::new();
      let mut query = self.connection.prepare_cached(
         "SELECT aliases.vulnerability FROM products JOIN aliases
             ON aliases.id=products.id AND aliases.provider=products.provider
          WHERE products.name=?1",
      )?;

      for name in names {
         for identifier in query.query_map([name], |row| row.get::<_, VulnerabilityId>(0))? {
            identifiers.insert(identifier?);
         }
      }

      let mut vulnerabilities = Vec::new();
      let mut fetch = self.connection.prepare_cached(
         "SELECT records.payload FROM aliases JOIN records
             ON records.id=aliases.id AND records.provider=aliases.provider
          WHERE aliases.vulnerability=?1
          ORDER BY records.modified DESC, records.provider",
      )?;

      for identifier in identifiers {
         let records = fetch
            .query_map([&identifier], |row| row.get::<_, Payload>(0))?
            .map(|payload| Advisory::try_from(payload?))
            .collect::<Result<Vec<_>>>()?;

         vulnerabilities.extend(Vulnerability::merge(identifier, records));
      }

      let mut vendors = BTreeMap::new();

      for vulnerability in &vulnerabilities {
         for (product, vendor) in vulnerability.claims.product_vendors() {
            if names.contains(&product) {
               vendors
                  .entry(product)
                  .or_insert_with(BTreeSet::new)
                  .insert(vendor);
            }
         }
      }

      let ambiguous_products = vendors
         .into_iter()
         .filter_map(|(product, owners)| (owners.len() > 1).then_some(product))
         .collect();

      Ok(Candidates {
         vulnerabilities,
         ambiguous_products,
      })
   }

   /// Computes database coverage statistics.
   pub fn stats(&self) -> Result<Stats> {
      let mut feeds = self.connection.prepare(
         "SELECT COALESCE(checks.feed, records.provider || '/untracked') AS name,
             COALESCE(feeds.digest, ''),
             MIN(CASE WHEN checks.modified=records.modified
                THEN checks.checked_at ELSE 0 END), COUNT(*)
          FROM records LEFT JOIN record_checks AS checks
             ON checks.id=records.id AND checks.provider=records.provider
          LEFT JOIN feeds ON feeds.name=checks.feed
          GROUP BY COALESCE(checks.feed, records.provider || '/untracked')
          ORDER BY name",
      )?;
      let feed_states = feeds
         .query_map([], |row| {
            Ok(FeedState {
               name: row.get(0)?,
               digest: row.get(1)?,
               checked_at: row.get(2)?,
               records: row.get(3)?,
            })
         })?
         .collect::<Result<Vec<_>, _>>()?;

      let mut providers = self.connection.prepare(
         "SELECT provider, COUNT(*), SUM(rejected), SUM(has_cpe AND NOT rejected),
             SUM(has_claims AND NOT rejected),
             SUM(NOT rejected AND NOT EXISTS (SELECT 1 FROM products
                WHERE products.id=records.id AND products.provider=records.provider))
          FROM records GROUP BY provider ORDER BY provider",
      )?;
      let provider_stats = providers
         .query_map([], |row| {
            Ok(ProviderStats {
               provider: row.get(0)?,
               records: row.get(1)?,
               rejected: row.get(2)?,
               with_cpe: row.get(3)?,
               with_claims: row.get(4)?,
               without_product: row.get(5)?,
            })
         })?
         .collect::<Result<Vec<_>, _>>()?;

      let vulnerabilities = self.connection.query_row(
         "SELECT COUNT(DISTINCT aliases.vulnerability) FROM aliases JOIN records
             ON records.id=aliases.id AND records.provider=aliases.provider
          WHERE NOT records.rejected",
         [],
         |row| row.get(0),
      )?;

      Ok(Stats {
         vulnerabilities,
         providers: provider_stats,
         feeds: feed_states,
      })
   }
}

impl PreparedAdvisory {
   /// Inserts or refreshes one provider record.
   fn insert(&self, transaction: &Transaction<'_>, provider: Provider) -> Result<Option<i64>> {
      let retained = transaction
         .prepare_cached(
            "SELECT modified>?3, payload=?4, revision FROM records
             WHERE id=?1 AND provider=?2",
         )?
         .query_row(
            params![self.id, provider, self.modified, self.payload],
            |row| {
               Ok((
                  row.get::<_, bool>(0)?,
                  row.get::<_, bool>(1)?,
                  row.get::<_, i64>(2)?,
               ))
            },
         )
         .optional()?;

      match retained {
         Some((true, _, _)) => return Ok(None),
         Some((false, true, revision)) => return Ok(Some(revision)),
         Some((false, false, _)) => {
            transaction
               .prepare_cached(
                  "UPDATE feeds SET digest='' WHERE digest!='' AND name IN (
                   SELECT feed FROM record_checks WHERE id=?1 AND provider=?2)",
               )?
               .execute(params![self.id, provider])?;

            transaction
               .prepare_cached("DELETE FROM record_checks WHERE id=?1 AND provider=?2")?
               .execute(params![self.id, provider])?;
         }
         None => {}
      }

      let revision = transaction
         .prepare_cached(
            "INSERT INTO records (
                id, provider, modified, payload, revision, has_cpe, has_claims, rejected
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)
             ON CONFLICT(id, provider) DO UPDATE SET modified=excluded.modified,
                payload=excluded.payload, revision=records.revision + 1,
                has_cpe=excluded.has_cpe, has_claims=excluded.has_claims,
                rejected=excluded.rejected
             WHERE excluded.modified >= records.modified
             RETURNING revision",
         )?
         .query_row(
            params![
               self.id,
               provider,
               self.modified,
               self.payload,
               self.has_cpe,
               self.has_claims,
               self.rejected,
            ],
            |row| row.get(0),
         )?;

      for table in ["aliases", "products"] {
         transaction
            .prepare_cached(&format!("DELETE FROM {table} WHERE id=?1 AND provider=?2"))?
            .execute(params![self.id, provider])?;
      }

      let mut aliases = transaction.prepare_cached("INSERT INTO aliases VALUES (?1, ?2, ?3)")?;

      for vulnerability in &self.vulnerabilities {
         aliases.execute(params![vulnerability, self.id, provider])?;
      }

      let mut index = transaction.prepare_cached("INSERT INTO products VALUES (?1, ?2, ?3)")?;

      for product in &self.products {
         index.execute(params![product, self.id, provider])?;
      }

      Ok(Some(revision))
   }
}
