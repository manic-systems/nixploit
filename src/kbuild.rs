//! Kbuild evaluation deciding which kernel sources a configuration compiles.

use std::{
   collections::HashMap,
   fs, iter, mem,
   path::{Path, PathBuf},
};

use misstep::{OptionExt as _, Result, ResultExt as _, ensure};

use crate::version::Match;

/// Composite objects nest only a few levels, so deeper chains are cycles.
const COMPOSITE_DEPTH: usize = 8;

/// Kbuild files and the `.config` of one kernel build.
pub struct BuildScope {
   /// Architecture substituted for `$(SRCARCH)`.
   arch: String,
   /// Symbols set in `.config`, with `CONFIG_` kept.
   symbols: HashMap<String, String>,
   /// Object and directory assignments of each Kbuild file, keyed by source
   /// directory with the root being empty.
   makefiles: HashMap<String, Vec<Assignment>>,
}

/// One `target-suffix += items` line and the conditionals around it.
struct Assignment {
   /// What the listed items become part of.
   target: Target,
   /// Whether the configuration enables the line.
   gate: Match,
   /// Objects and directories the line lists.
   items: Vec<String>,
}

/// The variable an assignment extends.
enum Target {
   /// `obj-` and `lib-` lines link their items into the kernel or modules.
   Linked,
   /// `name-` lines build their items into the composite object `name.o`.
   Composite(String),
}

impl BuildScope {
   /// Loads every Kbuild file and the `.config` under a kernel build tree.
   pub fn load(root: &Path) -> Result<Self> {
      let config_path = root.join(".config");
      let config = fs::read_to_string(&config_path)
         .with_context(|| format!("Reading {}", config_path.display()))?;

      let arch = match config
         .lines()
         .find_map(|line| line.strip_prefix("# Linux/")?.split_whitespace().next())
         .context("The kernel .config does not name its architecture")?
      {
         "i386" | "x86_64" => "x86",
         "sparc32" | "sparc64" => "sparc",
         "parisc64" => "parisc",
         "sh64" => "sh",
         other => other,
      }
      .to_owned();

      let symbols = config
         .lines()
         .filter_map(|line| {
            let (symbol, value) = line.split_once('=')?;
            symbol
               .starts_with("CONFIG_")
               .then(|| (symbol.to_owned(), value.trim_matches('"').to_owned()))
         })
         .collect::<HashMap<_, _>>();

      ensure!(!symbols.is_empty(), "The kernel .config sets no symbols");

      let mut scope = Self {
         arch,
         symbols,
         makefiles: HashMap::new(),
      };
      let mut pending = vec![PathBuf::new()];

      while let Some(relative) = pending.pop() {
         let directory = root.join(&relative);
         let mut kbuild = None;
         let mut makefile = None;

         for listing in
            fs::read_dir(&directory).with_context(|| format!("Reading {}", directory.display()))?
         {
            let entry = listing?;
            let name = entry.file_name();

            if entry.file_type()?.is_dir() {
               pending.push(relative.join(name));
            } else if name == "Kbuild" {
               kbuild = Some(entry.path());
            } else if name == "Makefile" {
               makefile = Some(entry.path());
            }
         }

         // Kbuild reads a directory's Kbuild file in place of its Makefile.
         let Some(path) = kbuild.or(makefile) else {
            continue;
         };
         let text = fs::read(&path).with_context(|| format!("Reading {}", path.display()))?;
         let parsed = scope.parse(&String::from_utf8_lossy(&text));
         scope
            .makefiles
            .insert(relative.to_string_lossy().into_owned(), parsed);
      }

      Ok(scope)
   }

   /// Decides whether the configuration compiles a source path. Headers
   /// outside `include` directories belong to the nearest directory with a
   /// Kbuild file.
   pub fn builds(&self, path: &str) -> Match {
      let (directory, file) = path.rsplit_once('/').unwrap_or(("", path));
      let mut components = directory.split('/');

      match components.next() {
         Some("tools" | "scripts" | "Documentation") => return Match::No,
         Some("arch") if components.next().is_some_and(|arch| arch != self.arch) => {
            return Match::No;
         }
         _ => {}
      }

      match file.rsplit_once('.') {
         Some((stem, "c" | "S" | "rs")) => self.object(directory, &format!("{stem}.o"), 0),
         Some((_stem, "h")) if !directory.split('/').any(|component| component == "include") => {
            let owner = iter::successors(Some(directory), |current| {
               (!current.is_empty())
                  .then(|| current.rsplit_once('/').map_or("", |(parent, _)| parent))
            })
            .find(|candidate| self.makefiles.contains_key(*candidate))
            .unwrap_or("");

            if self.directory(owner) == Match::No {
               Match::No
            } else {
               Match::Unknown
            }
         }
         _ => Match::Unknown,
      }
   }

   /// Decides whether Kbuild descends into a directory.
   fn directory(&self, directory: &str) -> Match {
      if directory.is_empty() {
         return Match::Yes;
      }

      self
         .references(directory, "/")
         .map(|(ancestor, assignment)| match assignment.target {
            Target::Linked => self.directory(ancestor) & assignment.gate,
            Target::Composite(_) => Match::Unknown,
         })
         .reduce(|left, right| left | right)
         .unwrap_or(Match::Unknown)
   }

   /// Decides whether an object in a directory is compiled, following the
   /// composite objects that include it.
   fn object(&self, directory: &str, object: &str, depth: usize) -> Match {
      if depth > COMPOSITE_DEPTH {
         return Match::Unknown;
      }

      if self.directory(directory) == Match::No {
         return Match::No;
      }

      let path = if directory.is_empty() {
         object.to_owned()
      } else {
         format!("{directory}/{object}")
      };

      self
         .references(&path, "")
         .map(|(ancestor, assignment)| match assignment.target {
            Target::Linked => self.directory(ancestor) & assignment.gate,
            Target::Composite(ref name) => {
               self.object(ancestor, &format!("{name}.o"), depth + 1) & assignment.gate
            }
         })
         .reduce(|left, right| left | right)
         .unwrap_or(Match::Unknown)
   }

   /// Lists assignments in ancestor Kbuild files naming a path relative to
   /// the ancestor, with the item suffix Kbuild uses for its kind.
   fn references<'scope>(
      &'scope self,
      path: &'scope str,
      suffix: &'scope str,
   ) -> impl Iterator<Item = (&'scope str, &'scope Assignment)> {
      let parents = path
         .match_indices('/')
         .map(|(index, _separator)| index)
         .chain([0]);

      parents.flat_map(move |index| {
         let (ancestor, remainder) = path.split_at(index);
         let relative = remainder.strip_prefix('/').unwrap_or(remainder);

         self
            .makefiles
            .get(ancestor)
            .into_iter()
            .flatten()
            .filter(move |assignment| {
               assignment.items.iter().any(|item| {
                  item
                     .strip_suffix(suffix)
                     .is_some_and(|stripped| stripped == relative)
               })
            })
            .map(move |assignment| (ancestor, assignment))
      })
   }

   /// Evaluates a symbol the way `ifdef` and `obj-$(CONFIG_...)` read it.
   fn enabled(&self, symbol: &str) -> Match {
      match self.symbols.get(symbol).map(String::as_str) {
         Some("y" | "m") => Match::Yes,
         _ => Match::No,
      }
   }

   /// Evaluates `ifeq`/`ifneq` arguments comparing one symbol to a literal.
   fn compare(&self, arguments: &str) -> Match {
      let Some((left, right)) = arguments
         .trim()
         .strip_prefix('(')
         .and_then(|inner| inner.strip_suffix(')'))
         .and_then(|inner| inner.split_once(','))
      else {
         return Match::Unknown;
      };

      let value = |argument: &str| {
         let mut expanded = String::new();
         let mut rest = argument.trim();

         while let Some((literal, reference)) = rest.split_once("$(") {
            let (name, after) = reference.split_once(')')?;

            if !name.starts_with("CONFIG_") || name.contains(['$', '(']) {
               return None;
            }

            expanded.push_str(literal);
            expanded.push_str(self.symbols.get(name).map_or("", String::as_str));
            rest = after;
         }

         expanded.push_str(rest);
         (!rest.contains('$')).then_some(expanded)
      };

      match (value(left), value(right)) {
         (Some(first), Some(second)) if first == second => Match::Yes,
         (Some(_), Some(_)) => Match::No,
         _ => Match::Unknown,
      }
   }

   /// Parses the assignments of one Kbuild file under its conditionals.
   fn parse(&self, text: &str) -> Vec<Assignment> {
      let mut assignments = Vec::new();
      let mut conditions = Vec::<Match>::new();

      for logical in logical_lines(text) {
         let line = logical.trim();
         let (keyword, rest) = line
            .split_once(char::is_whitespace)
            .map_or((line, ""), |(keyword, rest)| (keyword, rest.trim()));

         match keyword {
            "ifdef" => conditions.push(self.enabled(rest)),
            "ifndef" => conditions.push(!self.enabled(rest)),
            "ifeq" => conditions.push(self.compare(rest)),
            "ifneq" => conditions.push(!self.compare(rest)),
            "else" => {
               if let Some(condition) = conditions.pop() {
                  conditions.push(if rest.is_empty() {
                     !condition
                  } else if condition == Match::Yes {
                     Match::No
                  } else {
                     Match::Unknown
                  });
               }
            }
            "endif" => {
               conditions.pop();
            }
            _ => {
               let gate = conditions
                  .iter()
                  .fold(Match::Yes, |gate, &condition| gate & condition);

               if let Some(assignment) = self.assignment(line, gate) {
                  assignments.push(assignment);
               }
            }
         }
      }

      assignments
   }

   /// Parses an `obj-y`, `obj-$(CONFIG_...)` or composite object line.
   fn assignment(&self, line: &str, gate: Match) -> Option<Assignment> {
      let (left, items) = line.split_once('=')?;
      let variable = left.strip_suffix(['+', ':', '?']).unwrap_or(left).trim();

      if variable.contains(char::is_whitespace) {
         return None;
      }

      let (name, condition) = if let Some((name, symbol)) = variable
         .strip_suffix(')')
         .and_then(|stripped| stripped.split_once("-$("))
         .or_else(|| variable.strip_suffix('}')?.split_once("-${"))
      {
         let condition = if symbol.starts_with("CONFIG_") && !symbol.contains('$') {
            self.enabled(symbol)
         } else {
            Match::Unknown
         };
         (name, condition)
      } else {
         let (name, suffix) = variable.rsplit_once('-')?;

         match suffix {
            "y" | "m" | "objs" => (name, Match::Yes),
            _ => return None,
         }
      };

      let target = match name {
         "obj" | "lib" => Target::Linked,
         "subdir" | "always" | "extra" | "targets" | "hostprogs" | "userprogs" | "ccflags"
         | "asflags" | "ldflags" | "subdir-ccflags" | "subdir-asflags" => return None,
         _ => Target::Composite(name.to_owned()),
      };

      Some(Assignment {
         target,
         gate: gate & condition,
         items: items
            .split_whitespace()
            .map(|item| item.replace("$(SRCARCH)", &self.arch))
            .collect(),
      })
   }
}

/// Joins backslash continuations and drops comments.
fn logical_lines(text: &str) -> Vec<String> {
   let mut lines = Vec::new();
   let mut current = String::new();

   for raw in text.lines() {
      let content = raw
         .split_once('#')
         .map_or(raw, |(content, _comment)| content);

      if let Some(continued) = content.trim_end().strip_suffix('\\') {
         current.push_str(continued);
         current.push(' ');
         continue;
      }

      current.push_str(content);
      lines.push(mem::take(&mut current));
   }

   if !current.is_empty() {
      lines.push(current);
   }

   lines
}
