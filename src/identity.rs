//! Uses advisory identity evidence to qualify package name matches.

use std::{collections::BTreeSet, iter};

use crate::{
   advisory::{AffectedProduct, AffectedSource, Ecosystem, Namespace, cpe::Cpe},
   config::{Config, ProductAlias},
   identifier::NormalizedName,
   inventory::{Package, VersionOrigin},
   source::{Collection, SourceUrl},
   version::Match,
};

/// Advisory products and their vendor for Nix packages whose own names
/// advisories never use.
const BUILTIN_ALIASES: &[(&[&str], &str, &[&str])] = &[
   (
      &[
         "linux",
         "linux-bunker",
         "linux-hardened",
         "linux-zen",
         "linux-rt",
         "linux-libre",
         "linux-xanmod",
         "linux-lqx",
      ],
      "linux",
      &["linux-kernel", "linux"],
   ),
   (
      &[
         "chromium",
         "chromium-unwrapped",
         "ungoogled-chromium",
         "ungoogled-chromium-unwrapped",
         "google-chrome",
      ],
      "google",
      &["chrome"],
   ),
];

/// How a claim's vendor and namespace relate to the installed package.
pub enum Attribution {
   /// Nothing in the claim contradicts the package identity.
   Consistent,
   /// The claim may describe a different product sharing the name.
   Doubtful(&'static str),
   /// An alias fixes the product's vendor and the claim names another one.
   Foreign,
}

/// Shares package identity evidence across the advisory candidates for a scan.
pub struct Identity<'data> {
   /// The inventory owns source metadata for the duration of matching.
   pub package: &'data Package,
   /// Built-in and configured aliases remain authoritative for their named
   /// products.
   pub aliases: Vec<ProductAlias>,
   /// Names determine candidate retrieval without vendor assumptions.
   pub names: BTreeSet<NormalizedName>,
   /// Vendor collisions are computed from current cached advisory revisions.
   pub ambiguous: BTreeSet<NormalizedName>,
}

impl<'data> Identity<'data> {
   /// Builds candidate names while retaining the metadata needed for review.
   pub fn new(package: &'data Package, config: &'data Config) -> Self {
      let mut names = BTreeSet::from([NormalizedName::from(package.name.as_str())]);
      let mut aliases = BUILTIN_ALIASES
         .iter()
         .filter(|&&(packages, _, _)| packages.contains(&package.name.as_str()))
         .flat_map(|&(_, vendor, products)| {
            products.iter().map(move |&product| ProductAlias {
               product: NormalizedName::from(product),
               vendor: Some(NormalizedName::from(vendor)),
            })
         })
         .collect::<Vec<_>>();

      aliases.extend(config.aliases(&package.name).into_iter().flatten().cloned());
      names.extend(aliases.iter().map(|alias| alias.product.clone()));

      if matches!(
         package.metadata,
         VersionOrigin::Deriver | VersionOrigin::Output | VersionOrigin::Unversioned
      ) && let Some((_, upstream)) = Self::prefixed_package(&package.name)
      {
         names.insert(NormalizedName::from(upstream));
      }

      let major = package
         .version
         .split('.')
         .next()
         .and_then(|component| component.parse::<u32>().ok())
         .filter(|major| *major >= 2);

      names.extend(
         package
            .source_urls
            .iter()
            .filter_map(|url| url.module_path(major)),
      );

      Self {
         package,
         aliases,
         names,
         ambiguous: BTreeSet::new(),
      }
   }

   /// Whether a CNA claim names the package by product, package, or CPE.
   pub fn names_claim(&self, product: &AffectedProduct) -> bool {
      iter::once(product.product.as_str())
         .chain(product.package_name.as_deref())
         .any(|name| self.names.contains(&NormalizedName::from(name)))
         || product
            .cpes
            .iter()
            .filter_map(|criteria| criteria.parse::<Cpe>().ok())
            .any(|cpe| self.names.contains(cpe.product()))
   }

   /// Establishes whether the package belongs to the ecosystem of an OSV claim.
   pub fn ecosystem(&self, ecosystem: Ecosystem) -> Match {
      let collection = ecosystem.collection();

      if self.package_collections().contains(&collection) {
         Match::Yes
      } else if self.collection_conflict(collection) {
         Match::No
      } else {
         Match::Unknown
      }
   }

   /// Splits a strict Nix language package prefix from its upstream name.
   fn prefixed_package(name: &str) -> Option<(Collection, &str)> {
      let (collection, suffix) = [("python", Collection::Python), ("perl", Collection::Perl)]
         .into_iter()
         .find_map(|(prefix, collection)| {
            name.strip_prefix(prefix).map(|suffix| (collection, suffix))
         })?;
      let (version, package) = suffix.split_once('-')?;

      if package.is_empty()
         || version.is_empty()
         || !version.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
         })
      {
         return None;
      }

      Some((collection, package))
   }

   /// Qualifies a candidate without requiring every advisory to prove its
   /// identity.
   fn product(
      &self,
      product: &NormalizedName,
      vendor: &NormalizedName,
      identity_matches: bool,
   ) -> Attribution {
      let mut restricted = false;

      for alias in self
         .aliases
         .iter()
         .filter(|alias| alias.product == *product)
      {
         restricted = true;

         if alias
            .vendor
            .as_ref()
            .is_none_or(|expected| expected == vendor)
         {
            return Attribution::Consistent;
         }
      }

      if restricted && !vendor.is_placeholder() {
         return Attribution::Foreign;
      }

      if !self.ambiguous.contains(product) || identity_matches || self.source_vendor(vendor) {
         return Attribution::Consistent;
      }

      Attribution::Doubtful(
         "Multiple vendors claim this product name and the package source \
          does not resolve its identity",
      )
   }

   /// Checks CPE identity restrictions before applying its version interval.
   pub fn cpe(&self, cpe: &Cpe) -> Attribution {
      self.product(cpe.product(), cpe.vendor(), false)
   }

   /// Rejects claims about another package collection and keeps weaker
   /// contradictions visible in the unknown bucket.
   pub fn cna(&self, source: &AffectedSource, product: &AffectedProduct) -> Attribution {
      let collection = product
         .collection_url
         .as_deref()
         .and_then(|url| url.parse::<SourceUrl>().ok());

      if collection
         .as_ref()
         .and_then(SourceUrl::registry)
         .or_else(|| Collection::published_by(&source.source))
         .is_some_and(|registry| self.collection_conflict(registry))
      {
         return Attribution::Foreign;
      }

      let vendor = NormalizedName::from(product.vendor.as_str());
      let names = iter::once(product.product.as_str())
         .chain(product.package_name.as_deref())
         .map(NormalizedName::from)
         .collect::<Vec<_>>();

      let repository_matches = collection.as_ref().is_some_and(|repository| {
         self
            .package
            .source_urls
            .iter()
            .any(|archive| archive.same_repository(repository))
      });

      let alias_matches = self.aliases.iter().any(|alias| {
         names.contains(&alias.product)
            && alias
               .vendor
               .as_ref()
               .is_none_or(|expected| *expected == vendor)
      });

      let identity_matches = repository_matches || alias_matches;

      for name in names.iter().filter(|name| self.names.contains(*name)) {
         match self.product(name, &vendor, identity_matches) {
            Attribution::Consistent => {}
            other @ (Attribution::Doubtful(_) | Attribution::Foreign) => return other,
         }
      }

      if Namespace::of(source, product) == Namespace::Distribution {
         // Distributions ship language packages under prefixed names such as
         // python3-foo, so a bare name match on one is another package.
         if !self.package_collections().is_empty() {
            return Attribution::Foreign;
         }

         return Attribution::Doubtful(
            "The CNA claim describes a distribution package with a different \
             version namespace",
         );
      }

      self.cna_cpes(product, identity_matches)
   }

   /// A supplied CPE cannot contradict the product selected through the CNA
   /// name.
   fn cna_cpes(&self, product: &AffectedProduct, identity_matches: bool) -> Attribution {
      if product.cpes.is_empty()
         || product
            .cpes
            .iter()
            .filter_map(|criteria| criteria.parse::<Cpe>().ok())
            .any(|cpe| {
               self.names.contains(cpe.product())
                  && !self.target_conflict(cpe.target_sw())
                  && matches!(
                     self.product(cpe.product(), cpe.vendor(), identity_matches),
                     Attribution::Consistent
                  )
            })
      {
         return Attribution::Consistent;
      }

      Attribution::Doubtful(
         "The CNA CPE identities do not agree with the installed package \
          identity",
      )
   }

   /// Source ownership can disambiguate vendor names without a package identity
   /// map.
   fn source_vendor(&self, vendor: &NormalizedName) -> bool {
      !vendor.as_ref().is_empty()
         && self
            .package
            .source_urls
            .iter()
            .any(|source| source.owner().as_ref() == Some(vendor))
   }

   /// Registry URLs, Nix language builders, and Nix ecosystem prefixes
   /// identify language package namespaces.
   fn package_collections(&self) -> BTreeSet<Collection> {
      let mut collections = self
         .package
         .source_urls
         .iter()
         .filter_map(SourceUrl::registry)
         .chain(
            self
               .package
               .ecosystems
               .iter()
               .map(|ecosystem| ecosystem.collection()),
         )
         .collect::<BTreeSet<_>>();

      for name in iter::once(self.package.name.as_str()).chain(
         self.package.store_paths.iter().filter_map(|path| {
            path
               .rsplit('/')
               .next()?
               .split_once('-')
               .map(|(_, name)| name)
         }),
      ) {
         if let Some((collection, _)) = Self::prefixed_package(name) {
            collections.insert(collection);
         }
      }

      collections
   }

   /// Absent inventory metadata cannot establish a conflicting collection.
   fn collection_conflict(&self, collection: Collection) -> bool {
      let collections = self.package_collections();
      // An inspected derivation records every nixpkgs language builder it
      // used, so a C library sharing a repository with Go or Python bindings
      // stays out of those ecosystems.
      let inspected = self.package.derivation.is_some()
         && matches!(
            self.package.metadata,
            VersionOrigin::Declared | VersionOrigin::Unversioned
         );

      !collections.contains(&collection) && (inspected || !collections.is_empty())
   }

   /// CPE target software can contradict a known operating system or ecosystem.
   pub fn target_conflict(&self, target: &str) -> bool {
      let system_differs = |suffix: &str| {
         self
            .package
            .system
            .as_ref()
            .is_some_and(|system| !system.ends_with(suffix))
      };

      match target {
         "windows" => system_differs("-windows"),
         "linux" => system_differs("-linux"),
         "macos" | "mac_os" | "darwin" => system_differs("-darwin"),
         _ => target
            .parse::<Collection>()
            .is_ok_and(|collection| self.collection_conflict(collection)),
      }
   }
}
