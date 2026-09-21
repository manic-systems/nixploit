use std::{
   fs::File,
   io::{BufReader, Read, Seek as _},
   mem,
   path::Path,
   sync::mpsc::{Receiver, SyncSender, sync_channel},
   thread,
};

use flate2::read::MultiGzDecoder;
use misstep::{Report, Result, ResultExt as _, ensure};
use serde::{Deserialize as _, de::DeserializeSeed as _};
use serde_json::Deserializer as JsonDeserializer;
use zip::ZipArchive;

use crate::{advisory::Advisory, nvd::FeedSeed, osv::Record as OsvRecord};

/// Bounds normal batches while larger individual records travel alone.
const BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Record layout shared by every JSON document in a feed file.
#[derive(Clone, Copy)]
pub enum Format {
   /// NVD 2.0 feeds, API pages, and `VulnCheck` envelopes.
   Nvd,
   /// One OSV record per document.
   Osv,
}

/// Accounts for memory retained while a prepared record waits for its consumer.
pub trait BufferedRecord: Send {
   /// Includes every owned heap allocation but excludes the inline record.
   fn heap_bytes(&self) -> usize;
}

/// Read and prepare records from gzip, ZIP, or plain JSON feeds.
pub fn read_file<Item, Prepare, Consume>(
   path: &Path,
   format: Format,
   prepare: &Prepare,
   consume: &mut Consume,
) -> Result<usize>
where
   Item: BufferedRecord,
   Prepare: Fn(Advisory) -> Result<Item> + Sync,
   Consume: FnMut(Item) -> Result<()>,
{
   let mut file = File::open(path).with_context(|| format!("Opening {}", path.display()))?;
   let mut magic = [0; 4];
   let count = file.read(&mut magic)?;

   file.rewind()?;

   let mut pages = if count >= 2 && magic[..2] == [0x1F, 0x8B] {
      vec![read_json(
         BufReader::new(MultiGzDecoder::new(file)),
         format,
         prepare,
         consume,
      )?]
   } else if count == 4 && magic == *b"PK\x03\x04" {
      let members = ZipArchive::new(file)?.len();
      read_zip(path, format, members, prepare, consume)?
   } else {
      vec![read_json(BufReader::new(file), format, prepare, consume)?]
   };

   let records = pages.iter().map(|page| page.records).sum::<usize>();

   pages.retain(|page| page.start != 0 || page.records != page.total);
   pages.sort_unstable_by_key(|page| page.start);

   let expected = pages.first().map_or(0, |page| page.total);
   let mut offset = 0;

   for page in pages {
      ensure!(
         page.total == expected,
         "Feed pages disagree on totalResults"
      );
      ensure!(
         page.start == offset,
         "Feed pages have a gap or overlap at record {}",
         offset
      );
      offset += page.records;
   }

   ensure!(
      offset == expected,
      "Incomplete feed, expected {} records and got {}",
      expected,
      offset
   );

   Ok(records)
}

/// Bounded output from one ZIP worker.
enum WorkerMessage<Item> {
   /// Prepared records in source order.
   Records(Vec<Item>),
   /// End of one assigned member and its optional page metadata.
   Complete(Option<FeedPage>),
   /// Terminal worker failure.
   Failed(Report),
}

/// Reads ZIP members concurrently and consumes them in archive order.
fn read_zip<Item, Prepare, Consume>(
   path: &Path,
   format: Format,
   member_count: usize,
   prepare: &Prepare,
   consume: &mut Consume,
) -> Result<Vec<FeedPage>>
where
   Item: BufferedRecord,
   Prepare: Fn(Advisory) -> Result<Item> + Sync,
   Consume: FnMut(Item) -> Result<()>,
{
   let available = thread::available_parallelism().map_or(1, usize::from);
   let worker_count = available.min(8).min(member_count.max(1));

   thread::scope(|scope| {
      let mut receivers = Vec::with_capacity(worker_count);
      let mut handles = Vec::with_capacity(worker_count);

      for worker in 0..worker_count {
         let (sender, receiver) = sync_channel(1);
         receivers.push(receiver);
         handles.push(
            thread::Builder::new()
               .name(format!("feed-{worker}"))
               .spawn_scoped(scope, move || {
                  if let Err(error) = read_zip_worker(
                     path,
                     format,
                     member_count,
                     worker,
                     worker_count,
                     prepare,
                     &sender,
                  ) {
                     drop(sender.send(WorkerMessage::Failed(error)));
                  }
               })
               .with_context(|| format!("Spawning ZIP feed worker {worker}"))?,
         );
      }

      let result = consume_zip_members(member_count, &receivers, consume);

      drop(receivers);

      let mut panicked = false;
      for handle in handles {
         panicked |= handle.join().is_err();
      }

      if panicked {
         return Err(Report::msg("ZIP feed worker panicked"));
      }

      result
   })
}

/// Reads the strided member sequence assigned to one worker.
fn read_zip_worker<Item, Prepare>(
   path: &Path,
   format: Format,
   member_count: usize,
   worker: usize,
   worker_count: usize,
   prepare: &Prepare,
   sender: &SyncSender<WorkerMessage<Item>>,
) -> Result<()>
where
   Item: BufferedRecord,
   Prepare: Fn(Advisory) -> Result<Item> + Sync,
{
   let file = File::open(path).with_context(|| format!("Opening {}", path.display()))?;
   let mut archive = ZipArchive::new(file)?;

   for index in (worker..member_count).step_by(worker_count) {
      let member = archive.by_index(index)?;

      if member.is_dir() || !is_json_member(member.name()) {
         send_worker_message(sender, WorkerMessage::Complete(None))?;
         continue;
      }

      let mut batch = Vec::new();
      let mut batch_bytes = 0;
      let heap_budget = BATCH_BYTES.saturating_sub(2048 * size_of::<Item>());
      let flush_batch = |records: &mut Vec<Item>| {
         send_worker_message(sender, WorkerMessage::Records(mem::take(records)))
      };
      let is_json = Path::new(member.name())
         .extension()
         .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
      let page = {
         let mut send_record = |item: Item| {
            let item_bytes = item.heap_bytes();

            if !batch.is_empty() && item_bytes > heap_budget.saturating_sub(batch_bytes) {
               flush_batch(&mut batch)?;
               batch_bytes = 0;
            }

            batch_bytes += item_bytes;
            batch.push(item);

            if batch.len() == 2048 || batch_bytes >= heap_budget {
               flush_batch(&mut batch)?;
               batch_bytes = 0;
            }

            Ok(())
         };

         if is_json {
            read_json(BufReader::new(member), format, prepare, &mut send_record)?
         } else {
            read_json(
               BufReader::new(MultiGzDecoder::new(member)),
               format,
               prepare,
               &mut send_record,
            )?
         }
      };

      if !batch.is_empty() {
         send_worker_message(sender, WorkerMessage::Records(batch))?;
      }
      send_worker_message(sender, WorkerMessage::Complete(Some(page)))?;
   }

   Ok(())
}

/// Drains worker messages in original member and record order.
fn consume_zip_members<Item>(
   member_count: usize,
   receivers: &[Receiver<WorkerMessage<Item>>],
   consume: &mut impl FnMut(Item) -> Result<()>,
) -> Result<Vec<FeedPage>> {
   let mut pages = Vec::new();

   for index in 0..member_count {
      let receiver = &receivers[index % receivers.len()];

      loop {
         match receiver.recv() {
            Ok(WorkerMessage::Records(records)) => {
               for record in records {
                  consume(record)?;
               }
            }
            Ok(WorkerMessage::Complete(page)) => {
               pages.extend(page);
               break;
            }
            Ok(WorkerMessage::Failed(error)) => return Err(error),
            Err(_) => return Err(Report::msg("ZIP feed worker stopped")),
         }
      }
   }

   Ok(pages)
}

/// Sends one worker message or reports that consumption stopped.
fn send_worker_message<Item>(
   sender: &SyncSender<WorkerMessage<Item>>,
   message: WorkerMessage<Item>,
) -> Result<()> {
   sender
      .send(message)
      .map_err(|_disconnected| Report::msg("ZIP feed consumer stopped"))
}

/// Reports whether a ZIP member contains JSON directly or through gzip.
fn is_json_member(name: &str) -> bool {
   let path = Path::new(name);
   let is_json = |candidate: &Path| {
      candidate
         .extension()
         .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
   };

   is_json(path)
      || path
         .extension()
         .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
         && path
            .file_stem()
            .is_some_and(|stem| is_json(Path::new(stem)))
}

/// Read advisories from one JSON stream.
fn read_json<Item, Prepare, Consume>(
   reader: impl Read,
   format: Format,
   prepare: &Prepare,
   consume: &mut Consume,
) -> Result<FeedPage>
where
   Prepare: Fn(Advisory) -> Result<Item>,
   Consume: FnMut(Item) -> Result<()>,
{
   let mut limited = reader.take(2 * 1024 * 1024 * 1024 + 1);
   let mut deserializer = JsonDeserializer::from_reader(&mut limited);
   let mut prepare_record = |advisory| consume(prepare(advisory)?);
   let page = match format {
      Format::Nvd => FeedSeed {
         consume: &mut prepare_record,
      }
      .deserialize(&mut deserializer)?,
      Format::Osv => {
         prepare_record(Advisory::from(OsvRecord::deserialize(&mut deserializer)?))?;
         FeedPage::from(1)
      }
   };

   deserializer.end()?;

   ensure!(
      limited.limit() > 0,
      "Feed JSON exceeds the 2 GiB size limit"
   );
   Ok(page)
}

/// Record counts and position within a feed snapshot.
pub struct FeedPage {
   /// Number of records decoded from this page.
   pub records: usize,
   /// Position of the first record within the snapshot.
   pub start: usize,
   /// Number of records expected across the snapshot.
   pub total: usize,
}

impl From<usize> for FeedPage {
   fn from(records: usize) -> Self {
      Self {
         records,
         start: 0,
         total: records,
      }
   }
}
