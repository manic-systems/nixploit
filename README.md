# nixploit

Nixploit is a Nix vulnerability scanner. It checks packages in a
Nix closure against NVD, OSV, and optional VulnCheck data.

It reads NVD's CPE records alongside affected-version data from CVE Numbering
Authorities (CNAs), so advisories can be matched before they receive CPE
enrichment. Updates build a local database, and scans run offline.

## Quick Start

From a checkout, build the scanner and scan the running NixOS system.

```sh
nix build
./result/bin/nixploit update
./result/bin/nixploit scan --system
```

The remaining examples assume `nixploit` is on your `PATH`. You can use
`nix shell .` from the checkout to get a shell with it available.

The first update imports every NVD archive from 2002 through the current year.
Unchanged archives are skipped on later updates. Use `--from-year` for a smaller
download at the cost of older advisory coverage.

If the current year's archive is not published yet, an update warns
and keeps the available years. It retries that year on the next update. This
exception only covers a missing or empty archive that has never been cached.
Older years and previously cached archives must still be available.

```sh
nixploit update --from-year 2026
nixploit stats
```

`stats` shows database coverage and feed check times. The cache lives in
`$XDG_CACHE_HOME/nixploit`, or `~/.cache/nixploit` if unset. Pass `--cache-dir` to
use a different directory.

## Usage

Scan a build result, include its build dependencies, or check a package by name
and version without querying Nix.

```sh
nixploit scan ./result
nixploit scan --build-deps ./result
nixploit scan --package libheif@1.21.2
```

Store outputs include their runtime closure by default. `--no-requisites` limits
collection to the named paths. Explicit `.drv` inputs inspect those derivations,
with dependencies included only when `--build-deps` is set.

You can also save an inventory and scan it elsewhere.

```sh
nixploit inventory --system > inventory.json
nixploit scan --inventory inventory.json --json > report.json
```

Generated inventories leave `system` unset because a derivation records its
build platform. Set a package's `system` in a saved inventory only when its
output platform is known, for example `aarch64-linux`.

### Reading the results

- `affected` means the advisory's rules include the installed version.
- `unknown` means the product matched, but its identity, version range, platform,
  or configuration requirements couldn't be established. Vulnerabilities that
  NVD tags as disputed also land here, marked `Disputed`.
- `suppressed` holds findings covered by patches or ignore rules.

A match still needs review against your build and configuration. A clean report
only covers the advisories you've imported. JSON includes all three arrays,
feed coverage, missing derivations, and paths without usable versions. Text
output hides suppressed findings unless you pass `--show-suppressed`.

The exit code is `1` when there are unsuppressed affected findings, `0` when
there aren't, and `2` for an error. Unknown findings don't change the exit code.
Use `--kev-only` to limit results to CVEs marked as known exploited by CISA in
the feed.

## Feeds

NVD is the default provider. To use VulnCheck NVD++, set `VULNCHECK_API_TOKEN` in
the environment and update that provider.

```sh
nixploit update --provider vulncheck
```

VulnCheck's generated CPEs only count for products NVD's analysis of the CVE
doesn't place, and are dropped when the assigning CNA excludes the version.

The OSV provider downloads OSV's public per-ecosystem dumps for PyPI, npm,
crates.io, and Go. These carry GHSA, PYSEC, RUSTSEC, and Go advisories with
upstream package versions, including ones that never received a CVE. It also
downloads the GIT dump, which gives the commits introducing and fixing a CVE in
its upstream repository. Pass `--ecosystem` to refresh only some of them.

```sh
nixploit update --provider osv
nixploit update --provider osv --ecosystem PyPI --ecosystem GIT
```

OSV claims only match packages built by the matching nixpkgs language builder,
or Python packages named with a `python3.x-` prefix. Go modules match through
the package's GitHub, GitLab, Codeberg, or Bitbucket source URL.

Each provider's records are stored separately, so updating one doesn't remove
another's claims. A scan merges every record that names the same vulnerability,
so a CVE's NVD, VulnCheck, and OSV claims appear in one finding. Local JSON,
gzip, and ZIP feeds can be imported without network access.

```sh
nixploit import nvdcve-2.0-2026.json.gz
nixploit import --provider vulncheck nist-nvd2.zip
nixploit import --provider osv PyPI-all.zip
```

## Configuration

Pass a TOML file with `nixploit scan --config config.toml`. It accepts package
aliases and ignore rules.

### Package aliases

Matching normalizes case, spaces, hyphens, and underscores, then compares exact
product names. Nix package names sometimes need an alias to match the upstream
product. A vendor can also be supplied to distinguish unrelated products with
the same name.

Names inferred from Nix store paths also match without a Python or Perl version
prefix. For example, `python3.13-cryptography` matches `cryptography`, while the
report retains the original package name.

```toml
[aliases]
my-openldap = [{ product = "openldap", vendor = "openldap" }]
my-linux = [
   { product = "linux", vendor = "linux" },
   { product = "linux_kernel", vendor = "linux" },
]
```

Aliases for `linux`, `linux-bunker`, `linux-hardened`, `linux-zen`, `linux-rt`,
`linux-libre`, `linux-xanmod`, and `linux-lqx` are built in. Other kernel package
names need both upstream product aliases, as above. Chromium, ungoogled-chromium,
and google-chrome match NVD's `chrome` product, whose versions follow Chromium's.
An alias with a vendor drops claims from other named vendors for that product,
so Red Hat Linux advisories never reach the kernel. Unresolved vendor collisions
stay in `unknown`.

Claims about distribution packages, such as Red Hat's per-release entries, only
count when nothing describes the upstream release. When the assigning CNA's own
version data settles the installed version, contributor claims such as CISA's
ADP restatements are ignored, and NVD CPE matches it contradicts move to
`unknown`. When NVD places a product only in another language collection,
same-named CNA claims are read as that product too. Records that give each
release line its own upper bound count a release past its own line's bound as
fixed.

### Ignoring findings

Ignore rules need a package, vulnerability id, bucket, and review reason. The id
is the finding's CVE, or its OSV identifier when no CVE exists. For an `unknown`
finding, copy its fingerprint from the report into the rule. Replace the
placeholder below with the full 64-character value.

```toml
[[ignore]]
package = "example-package"
id = "CVE-2026-12345"
bucket = "unknown"
reason = "Reviewed the advisory against our package configuration"
fingerprint = "paste the fingerprint from the finding"
until = "2026-12-01"
```

The fingerprint ties the rule to the reviewed evidence. If that evidence
changes, the finding appears again. Affected rules can pin a fingerprint too.
Use `version` to restrict a rule to one installed version, and `until` to expire
it at the start of that date in UTC. Optional `ranges` must match the report's `raw_ranges`.

Patch filenames containing a CVE identifier suppress that CVE for the
derivation, following vulnix's convention. So do CVE identifiers inside patches
present in the store, which covers release-branch patches such as glibc's.
These findings remain in the report's `suppressed` array.

### Kernel configuration

Given the kernel's Kbuild files and `.config`, nixploit suppresses kernel
findings whose fix touches only files the configuration never compiles.

```toml
[kernel]
output = "/nix/store/...-linux-7.2.0"
build = "/nix/store/...-linux-kbuild-7.2.0"
```

`output` is the kernel store path the build applies to, and `build` is a
directory holding the patched tree's `Kbuild` and `Makefile` files plus
`.config`. The NixOS module fills this in for the running kernel.

### Upstream history

Advisory ranges often name only the release that first shipped a fix, while a
release branch took it earlier. `nixploit history` takes the same arguments as
`scan` and keeps a commit-only clone of each upstream repository that the GIT
dump names for an affected finding. It needs `git` and network access.

```sh
nixploit history --system
nixploit scan --system
```

A scan then looks up the tag naming the installed version and suppresses the
finding when a fixing commit is in that tag, when the tag's branch carries a
commit with the fix's author and subject or a `cherry picked from` trailer
naming it, or when no introducing commit reaches the tag. Scans never fetch.
Kernel repositories are skipped because kernel records already list stable
backports.

## NixOS

Add this flake to your configuration as `inputs.nixploit`, then import its
module to schedule scans.

```nix
{ inputs, ... }:
{
   imports = [ inputs.nixploit.nixosModules.default ];

   services.nixploit = {
      enable = true;
      calendar = "daily";
   };
}
```

The service updates the feeds and scans the running system's runtime closure.
Set `buildDependencies = true` to include build dependencies, `fromYear` to
limit NVD coverage, `nvdMirror` to fetch NVD archives from a mirror, and
`settings` for the aliases and ignore rules above. `kbuild.enable` turns on the
kernel configuration filter, and `history.enable` runs `nixploit history` before
each scan. These options live under `services.nixploit`. The timer persists
across reboots and adds up to 15 minutes of jitter.

Start a scan immediately with `sudo systemctl start nixploit`. The last completed
report is saved at `/var/lib/nixploit/report.json`, readable by root and the
`nixploit` user. Failed updates still allow a scan against the cache. Failed
scans preserve the last completed report and its finding metrics.

Set `providers` to refresh more than NVD, for example `[ "nvd" "osv" ]`, and
`ecosystems` to limit which OSV dumps are downloaded. For VulnCheck, add
`"vulncheck"` to `services.nixploit.providers` and set
`services.nixploit.tokenFile = "/run/secrets/vulncheck-token"`. The file contains
only the API token. Systemd loads it as a credential, and the service passes it
to the update process. Keep the token out of Nix expressions, which become
readable store files.

### Monitoring

The module enables node_exporter's textfile collector and writes metrics to
`/var/lib/nixploit/metrics`. Have Prometheus scrape that node_exporter instance.
For a local Prometheus server, the configuration can look like this.

```nix
services.prometheus.scrapeConfigs = [
   {
      job_name = "node";
      static_configs = [{ targets = [ "127.0.0.1:9100" ]; }];
   }
];
```

On the Grafana host, import the module and enable
`services.nixploit.dashboard.enable` alongside your Grafana service. The scanner
doesn't need to run on that host. You can also import the
[dashboard](monitoring/dashboard.json) manually.

[Alert rules](monitoring/alerts.yml) cover failed jobs, stale data, and affected
known-exploited CVEs. Load them on the Prometheus host and adjust the freshness
thresholds if you change the daily schedule.

```nix
services.prometheus.ruleFiles = [ "${inputs.nixploit}/monitoring/alerts.yml" ];
```

Outside the module, `--prometheus-file` writes metrics for node_exporter after a
completed scan, including scans that return `1`. The destination directory must
exist. An error leaves the previous metrics file intact.

Invalid CVSS scores are ignored when choosing a score. Findings without a valid
score remain in their original bucket and appear as `unscored` in metrics.

```sh
nixploit scan --system --prometheus-file /var/lib/nixploit/metrics/scan.prom
```

## Development

```sh
nix develop --command cargo build --release
nix develop --command cargo clippy --all-targets -- -D warnings
```

## License

[EUPL-1.2](LICENSE).
