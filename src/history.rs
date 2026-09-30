//! Upstream commit history deciding whether an installed release contains a
//! vulnerability's fix.

use std::{
   cell::RefCell,
   collections::{BTreeSet, HashMap},
   fs,
   io::{Write as _, stderr},
   path::{Path, PathBuf},
   process::{Command, Output, Stdio},
};

use misstep::{OptionExt as _, Result, ResultExt as _, ensure};

use crate::{
   advisory::{CommitRange, CommitSource},
   identifier::NormalizedName,
   identity::Identity,
   source::SourceUrl,
   version::Match,
};

/// Aborts transfers that stay under 1 KiB/s for a minute.
const STALL_LIMIT: [&str; 4] = [
   "-c",
   "http.lowSpeedLimit=1024",
   "-c",
   "http.lowSpeedTime=60",
];

/// Commit-only clones of upstream repositories under the cache directory.
pub struct History {
   /// Directory holding one bare clone per repository.
   root: PathBuf,
   /// Release tags of each clone, peeled to their commits.
   tags: RefCell<HashMap<PathBuf, Vec<(String, String)>>>,
   /// Commits between a merge base and a tag, keyed by both.
   branches: RefCell<HashMap<(PathBuf, String, String), Vec<Commit>>>,
}

/// The fields a backport keeps from the commit it was picked from.
struct Commit {
   /// Full commit hash.
   id: String,
   /// Author email.
   author: String,
   /// First line of the message.
   subject: String,
   /// Remaining message, which holds `cherry picked from` trailers.
   body: String,
}

/// How a release relates to one commit range.
enum Verdict {
   /// A fixing commit is an ancestor of the release.
   Fixed(String),
   /// A commit with a fixing commit's author and subject is in the release.
   Backported {
      /// The fixing commit the advisory names.
      fix: String,
      /// The release branch commit carrying it.
      backport: String,
   },
   /// No introducing commit reaches the release.
   Absent,
}

impl History {
   /// Uses the clones under a cache directory.
   pub fn new(cache: &Path) -> Self {
      Self {
         root: cache.join("git"),
         tags: RefCell::new(HashMap::new()),
         branches: RefCell::new(HashMap::new()),
      }
   }

   /// Lists the repositories whose ranges can decide a package, skipping
   /// kernel trees because kernel records already carry stable backports.
   pub fn repositories(identity: &Identity<'_>, commits: &[CommitSource]) -> BTreeSet<String> {
      commits
         .iter()
         .flat_map(|source| &source.ranges)
         .filter(|range| range.repository.starts_with("https://"))
         .filter_map(|range| range.repository.parse::<SourceUrl>().ok())
         .filter(|url| {
            let repository = url.repository();
            let name = repository.rsplit('/').next().unwrap_or_default();

            !repository.contains("/linux/kernel/git/")
               && (identity.names.contains(&NormalizedName::from(name))
                  || identity
                     .package
                     .source_urls
                     .iter()
                     .any(|source| source.same_repository(url)))
         })
         .map(|url| url.to_string())
         .collect()
   }

   /// Explains why the installed release is unaffected, when every range one
   /// repository lists shows it. Mirrors of a project list the same commits
   /// with varying completeness, so each mirror's ranges are read alone.
   pub fn unaffected(
      &self,
      identity: &Identity<'_>,
      commits: &[CommitSource],
   ) -> Result<Option<String>> {
      let repositories = Self::repositories(identity, commits);
      let Some(clone) = repositories
         .iter()
         .filter_map(|repository| self.clone_path(repository))
         .find(|path| path.is_dir())
      else {
         return Ok(None);
      };
      let Some((tag, release)) = self.tag(&clone, &identity.package.version)? else {
         return Ok(None);
      };
      let mut decided = None;

      'mirrors: for repository in &repositories {
         let mut verdicts = Vec::new();

         for range in commits
            .iter()
            .flat_map(|source| &source.ranges)
            .filter(|range| range.repository == *repository)
         {
            match self.verdict(&clone, range, &release)? {
               Some(verdict) => verdicts.push(verdict),
               None => continue 'mirrors,
            }
         }

         if !verdicts.is_empty() {
            decided = verdicts.into_iter().next();
            break;
         }
      }

      Ok(decided.map(|verdict| match verdict {
         Verdict::Fixed(fix) => format!("Fix {} is in {tag}", short(&fix)),
         Verdict::Backported { fix, backport } => format!(
            "Fix {} is backported to {tag} as {}",
            short(&fix),
            short(&backport)
         ),
         Verdict::Absent => format!("No commit introducing the vulnerability is in {tag}"),
      }))
   }

   /// Clones a repository or refreshes its branches and tags.
   pub fn sync(&self, repository: &str) -> Result<()> {
      let clone = self
         .clone_path(repository)
         .with_context(|| format!("{repository} is not an HTTPS repository URL"))?;

      let output = if clone.is_dir() {
         writeln!(stderr().lock(), "Fetching {repository}")?;
         git(&clone)
            .args(STALL_LIMIT)
            .args([
               "fetch",
               "--prune",
               "--tags",
               "--filter=tree:0",
               "origin",
               "+refs/heads/*:refs/heads/*",
            ])
            .output()
      } else {
         writeln!(stderr().lock(), "Cloning {repository}")?;

         if let Some(parent) = clone.parent() {
            fs::create_dir_all(parent)?;
         }

         git(&clone)
            .args(STALL_LIMIT)
            .args(["clone", "--bare", "--filter=tree:0", "--", repository])
            .arg(&clone)
            .output()
      }
      .context("Running git")?;

      ensure!(
         output.status.success(),
         "git failed for {}: {}",
         repository,
         String::from_utf8_lossy(&output.stderr).trim()
      );
      Ok(())
   }

   /// Locates the clone of an HTTPS repository, refusing paths that would
   /// leave the clone directory.
   fn clone_path(&self, repository: &str) -> Option<PathBuf> {
      let name = repository
         .starts_with("https://")
         .then(|| repository.parse::<SourceUrl>().ok())??
         .repository();

      name
         .split('/')
         .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
         .then(|| self.root.join(format!("{name}.git")))
   }

   /// Finds the tag naming an installed version and its commit, when exactly
   /// one commit carries that version.
   fn tag(&self, clone: &Path, version: &str) -> Result<Option<(String, String)>> {
      let mut cache = self.tags.borrow_mut();

      if !cache.contains_key(clone) {
         let output = run(
            clone,
            &[
               "for-each-ref",
               "--format=%(refname:strip=2)%00%(objectname)%00%(*objectname)",
               "refs/tags",
            ],
         )?;
         let tags = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
               let mut fields = line.split('\0');
               let (name, object, peeled) = (fields.next()?, fields.next()?, fields.next()?);
               let commit = if peeled.is_empty() { object } else { peeled };
               Some((name.to_owned(), commit.to_owned()))
            })
            .collect();
         cache.insert(clone.to_owned(), tags);
      }

      let mut matches = cache
         .get(clone)
         .into_iter()
         .flatten()
         .filter(|entry| names_release(&entry.0, version));
      let Some(first) = matches.next() else {
         return Ok(None);
      };

      Ok(matches
         .all(|entry| entry.1 == first.1)
         .then(|| first.clone()))
   }

   /// Reports whether a release tag points at a commit, which may be
   /// abbreviated.
   fn tagged(&self, clone: &Path, commit: &str) -> bool {
      self
         .tags
         .borrow()
         .get(clone)
         .is_some_and(|tags| tags.iter().any(|entry| entry.1.starts_with(commit)))
   }

   /// Decides one range for a release commit, or nothing when the history
   /// cannot settle it.
   fn verdict(&self, clone: &Path, range: &CommitRange, release: &str) -> Result<Option<Verdict>> {
      if !range.last_affected.is_empty() {
         return Ok(None);
      }

      // OSV converts advisory version ranges into the commits their release
      // tags point at, which restate the version data the finding already
      // contradicts rather than naming a fix.
      let tagged = |commit: &String| self.tagged(clone, commit);
      let introduced = range
         .introduced
         .iter()
         .filter(|commit| !tagged(commit))
         .collect::<Vec<_>>();

      for fix in range.fixed.iter().filter(|commit| !tagged(commit)) {
         if ancestor(clone, fix, release)? == Match::Yes {
            return Ok(Some(Verdict::Fixed(fix.clone())));
         }

         if let Some(backport) = self.backport(clone, fix, release)? {
            return Ok(Some(Verdict::Backported {
               fix: fix.clone(),
               backport,
            }));
         }
      }

      if introduced.is_empty() {
         return Ok(None);
      }

      for commit in introduced {
         if ancestor(clone, commit, release)? != Match::No
            || self.backport(clone, commit, release)?.is_some()
         {
            return Ok(None);
         }
      }

      Ok(Some(Verdict::Absent))
   }

   /// Finds a commit on the release's branch that carries another commit,
   /// by a `cherry picked from` trailer or a matching author and subject.
   fn backport(&self, clone: &Path, commit: &str, release: &str) -> Result<Option<String>> {
      let Some(original) = commit_info(clone, commit)? else {
         return Ok(None);
      };
      let merged = run(clone, &["merge-base", commit, release])?;

      if !merged.status.success() {
         return Ok(None);
      }

      let base = String::from_utf8_lossy(&merged.stdout).trim().to_owned();
      let key = (clone.to_owned(), base, release.to_owned());
      let mut cache = self.branches.borrow_mut();

      if !cache.contains_key(&key) {
         let output = run(
            clone,
            &[
               "log",
               "--format=%H%x00%ae%x00%s%x00%b%x1e",
               &format!("{}..{}", key.1, key.2),
            ],
         )?;
         ensure!(
            output.status.success(),
            "git log failed in {}: {}",
            clone.display(),
            String::from_utf8_lossy(&output.stderr).trim()
         );
         let commits = parse_commits(&String::from_utf8_lossy(&output.stdout));
         cache.insert(key.clone(), commits);
      }

      Ok(cache.get(&key).into_iter().flatten().find_map(|candidate| {
         (candidate.body.contains(&original.id)
            || candidate.author == original.author && candidate.subject == original.subject)
            .then(|| candidate.id.clone())
      }))
   }
}

/// Prepares a git command that ignores user configuration and never fetches
/// missing objects, so scans stay offline.
fn git(clone: &Path) -> Command {
   let mut command = Command::new("git");
   command
      .arg("--git-dir")
      .arg(clone)
      .env("GIT_NO_LAZY_FETCH", "1")
      .env("GIT_CONFIG_NOSYSTEM", "1")
      .env("GIT_CONFIG_GLOBAL", "/dev/null")
      .env("GIT_TERMINAL_PROMPT", "0")
      .env("GIT_ALLOW_PROTOCOL", "https")
      .stdin(Stdio::null());
   command
}

/// Runs a git command in a clone.
fn run(clone: &Path, arguments: &[&str]) -> Result<Output> {
   git(clone)
      .args(arguments)
      .output()
      .with_context(|| format!("Running git in {}", clone.display()))
}

/// Tests ancestry, with missing commits left undecided.
fn ancestor(clone: &Path, commit: &str, release: &str) -> Result<Match> {
   let output = run(clone, &["merge-base", "--is-ancestor", commit, release])?;

   Ok(match output.status.code() {
      Some(0) => Match::Yes,
      Some(1) => Match::No,
      _ => Match::Unknown,
   })
}

/// Reads the author and subject of a commit present in the clone.
fn commit_info(clone: &Path, commit: &str) -> Result<Option<Commit>> {
   let output = run(
      clone,
      &["log", "-1", "--format=%H%x00%ae%x00%s%x00%b%x1e", commit],
   )?;

   if !output.status.success() {
      return Ok(None);
   }

   Ok(parse_commits(&String::from_utf8_lossy(&output.stdout))
      .into_iter()
      .next())
}

/// Splits `git log` output written with NUL-separated fields and record
/// separators.
fn parse_commits(text: &str) -> Vec<Commit> {
   text
      .split('\u{1e}')
      .filter_map(|record| {
         let mut fields = record.trim_start_matches('\n').splitn(4, '\0');
         Some(Commit {
            id: fields.next().filter(|id| !id.is_empty())?.to_owned(),
            author: fields.next()?.to_owned(),
            subject: fields.next()?.to_owned(),
            body: fields.next().unwrap_or_default().to_owned(),
         })
      })
      .collect()
}

/// Reports whether a tag names a release, allowing a prefix such as `v`,
/// `n`, or `project-` and underscores between components.
fn names_release(tag: &str, version: &str) -> bool {
   tag.char_indices()
      .filter(|&(_, character)| character.is_ascii_digit())
      .any(|(index, _)| {
         let (prefix, release) = tag.split_at(index);

         (prefix.is_empty()
            || prefix.ends_with(['-', '_', '/'])
            || prefix.chars().all(char::is_alphabetic))
            && release.replace('_', ".") == version
      })
}

/// Abbreviates a commit hash for messages.
fn short(commit: &str) -> &str {
   commit.get(..12).unwrap_or(commit)
}
