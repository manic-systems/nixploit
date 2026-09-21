//! Python package version ordering from PEP 440.

use std::str::FromStr;

use misstep::Report;

/// A Python package version with PEP 440 ordering.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Pep440 {
   /// Epoch overriding the release ordering.
   epoch: u64,
   /// Release components without trailing zeros.
   release: Vec<u64>,
   /// Prerelease position, where a bare development release sorts first.
   stage: Stage,
   /// Post-release number when present.
   post: Option<u64>,
   /// Development release number, sorting before the matching release.
   development: Development,
   /// Local version label, sorting after the public version it extends.
   local: Vec<LocalSegment>,
}

/// Prerelease position of a PEP 440 version.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Stage {
   /// A development release of a final version, such as `1.0.dev1`.
   DevelopmentOnly,
   /// An alpha, beta, or release candidate.
   Prerelease(Phase, u64),
   /// Any version without a prerelease marker.
   Final,
}

/// Prerelease phases in ascending order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Phase {
   /// `a`, `alpha`.
   Alpha,
   /// `b`, `beta`.
   Beta,
   /// `rc`, `c`, `pre`, `preview`.
   Candidate,
}

/// Development release marker of a PEP 440 version.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Development {
   /// A `.devN` release.
   Release(u64),
   /// No development marker.
   Final,
}

/// One dot-separated local version segment.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LocalSegment {
   /// Alphanumeric segments sort before numeric ones.
   Text(String),
   /// Numeric segment.
   Number(u64),
}

impl FromStr for Pep440 {
   type Err = Report;

   fn from_str(value: &str) -> Result<Self, Report> {
      let invalid = || Report::msg(format!("Invalid PEP 440 version {value}"));
      let lowered = value.trim().to_ascii_lowercase();
      let body = lowered.strip_prefix('v').unwrap_or(&lowered);
      let (public, label) = body
         .split_once('+')
         .map_or((body, None), |(public, label)| (public, Some(label)));
      let (epoch, mut rest) = match public.split_once('!') {
         Some((epoch, release)) => (epoch.parse::<u64>().map_err(|_error| invalid())?, release),
         None => (0, public),
      };

      let mut release = vec![digits(&mut rest).ok_or_else(invalid)?];

      while let Some(tail) = rest.strip_prefix('.')
         && tail.starts_with(|character: char| character.is_ascii_digit())
      {
         rest = tail;
         release.push(digits(&mut rest).ok_or_else(invalid)?);
      }

      while release.last() == Some(&0) && release.len() > 1 {
         release.pop();
      }

      let prerelease = marker(
         &mut rest,
         &[
            ("alpha", Phase::Alpha),
            ("beta", Phase::Beta),
            ("preview", Phase::Candidate),
            ("pre", Phase::Candidate),
            ("rc", Phase::Candidate),
            ("a", Phase::Alpha),
            ("b", Phase::Beta),
            ("c", Phase::Candidate),
         ],
      );
      let implicit_post = rest
         .strip_prefix('-')
         .filter(|tail| tail.starts_with(|character: char| character.is_ascii_digit()))
         .map(|tail| {
            rest = tail;
            digits(&mut rest)
         });
      let post = match implicit_post {
         Some(number) => Some(number.ok_or_else(invalid)?),
         None => {
            marker(&mut rest, &[("post", ()), ("rev", ()), ("r", ())]).map(|((), number)| number)
         }
      };
      let development = marker(&mut rest, &[("dev", ())]).map(|((), number)| number);

      if !rest.is_empty() {
         return Err(invalid());
      }

      let local = label
         .map(|text| {
            text
               .split(['.', '-', '_'])
               .map(|segment| {
                  if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
                  {
                     Err(invalid())
                  } else if let Ok(number) = segment.parse::<u64>() {
                     Ok(LocalSegment::Number(number))
                  } else {
                     Ok(LocalSegment::Text(segment.to_owned()))
                  }
               })
               .collect::<Result<Vec<_>, _>>()
         })
         .transpose()?
         .unwrap_or_default();

      Ok(Self {
         epoch,
         release,
         stage: match (prerelease, post, development) {
            (Some((phase, number)), _, _) => Stage::Prerelease(phase, number),
            (None, None, Some(_)) => Stage::DevelopmentOnly,
            (None, _, _) => Stage::Final,
         },
         post,
         development: development.map_or(Development::Final, Development::Release),
         local,
      })
   }
}

/// Consumes a leading run of digits as a number.
fn digits(rest: &mut &str) -> Option<u64> {
   let end = rest
      .find(|character: char| !character.is_ascii_digit())
      .unwrap_or(rest.len());
   let number = rest.get(..end)?.parse().ok()?;

   *rest = rest.get(end..)?;
   Some(number)
}

/// Consumes an optionally separated marker and its optional number, leaving
/// the input untouched when no marker matches.
fn marker<Kind>(rest: &mut &str, markers: &[(&str, Kind)]) -> Option<(Kind, u64)>
where
   Kind: Copy,
{
   let separated = rest.strip_prefix(['.', '-', '_']).unwrap_or(rest);
   let (kind, mut tail) = markers
      .iter()
      .find_map(|&(name, kind)| separated.strip_prefix(name).map(|tail| (kind, tail)))?;

   tail = tail.strip_prefix(['.', '-', '_']).unwrap_or(tail);

   let number = if tail.starts_with(|character: char| character.is_ascii_digit()) {
      digits(&mut tail)?
   } else {
      0
   };

   *rest = tail;
   Some((kind, number))
}
