//! Nix `builtins.compareVersions` ordering.

use std::{cmp::Ordering, str::FromStr};

use misstep::{Report, ensure};

use crate::version::is_commit_hash;

/// A version split into the components Nix compares one by one.
pub struct NixVersion(Vec<Component>);

/// One version component in ascending Nix precedence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Component {
   /// The `pre` marker, which sorts before everything else.
   Pre,
   /// Padding for the shorter of two versions.
   Missing,
   /// Letters, compared lexically.
   Text(String),
   /// Digits without leading zeros, compared by length and then lexically.
   Number(usize, String),
}

impl From<&str> for Component {
   fn from(part: &str) -> Self {
      if part == "pre" {
         Self::Pre
      } else if part.bytes().all(|byte| byte.is_ascii_digit()) {
         let digits = part.trim_start_matches('0');

         Self::Number(digits.len(), digits.to_owned())
      } else {
         Self::Text(part.to_owned())
      }
   }
}

impl FromStr for NixVersion {
   type Err = Report;

   fn from_str(value: &str) -> Result<Self, Report> {
      ensure!(
         value.as_bytes().first().is_some_and(u8::is_ascii_digit)
            && value.bytes().all(
               |byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+')
            )
            && !is_commit_hash(value),
         "{} is not a Nix release version",
         value
      );

      let mut components = Vec::new();
      let mut start = 0;

      for (index, character) in value.char_indices() {
         if matches!(character, '.' | '-') {
            if start < index {
               components.extend(value.get(start..index).map(Component::from));
            }

            start = index + 1;
         } else if start < index
            && character.is_ascii_digit() != value.as_bytes()[start].is_ascii_digit()
         {
            components.extend(value.get(start..index).map(Component::from));
            start = index;
         }
      }

      if start < value.len() {
         components.extend(value.get(start..).map(Component::from));
      }

      Ok(Self(components))
   }
}

impl Ord for NixVersion {
   fn cmp(&self, other: &Self) -> Ordering {
      let component =
         |version: &Self, index: usize| version.0.get(index).unwrap_or(&Component::Missing).clone();

      (0..self.0.len().max(other.0.len()))
         .map(|index| component(self, index).cmp(&component(other, index)))
         .find(|order| order.is_ne())
         .unwrap_or(Ordering::Equal)
   }
}

impl PartialOrd for NixVersion {
   fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
      Some(self.cmp(other))
   }
}

impl PartialEq for NixVersion {
   fn eq(&self, other: &Self) -> bool {
      self.cmp(other).is_eq()
   }
}

impl Eq for NixVersion {}
