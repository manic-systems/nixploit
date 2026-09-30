flake:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.nixploit;
  toml = pkgs.formats.toml { };
  textfileDirectory = "/var/lib/nixploit/metrics";
  kernel = config.boot.kernelPackages.kernel;

  kbuild = pkgs.stdenvNoCC.mkDerivation {
    pname = "${kernel.pname}-kbuild";
    inherit (kernel) version src patches;
    dontConfigure = true;
    dontBuild = true;
    dontFixup = true;
    installPhase = ''
      find . \( -name Kbuild -o -name Makefile \) -exec install -Dm444 {} $out/{} \;
      install -Dm444 ${kernel.configfile} $out/.config
    '';
  };

  scanConfig = toml.generate "nixploit.toml" (
    lib.recursiveUpdate (lib.optionalAttrs cfg.kbuild.enable {
      kernel = {
        output = "${kernel}";
        build = "${kbuild}";
      };
    }) cfg.settings
  );

  enabledMetric = pkgs.writeText "nixploit-enabled.prom" ''
    # HELP nixploit_enabled Whether scheduled scanning is enabled on this host
    # TYPE nixploit_enabled gauge
    nixploit_enabled 1
  '';

  jobConfig = pkgs.writeText "nixploit-service.json" (
    builtins.toJSON {
      scanner = lib.getExe cfg.package;
      inherit textfileDirectory;
      scanArguments = [
        "--system"
        "--config"
        (toString scanConfig)
      ]
      ++ lib.optional cfg.buildDependencies "--build-deps";
      updates = map (provider: {
        arguments = [
          "--provider"
          provider
        ]
        ++ lib.optionals (provider == "nvd") [
          "--from-year"
          (toString cfg.fromYear)
        ]
        ++ lib.optionals (provider == "nvd" && cfg.nvdMirror != null) [
          "--mirror"
          cfg.nvdMirror
        ]
        ++ lib.optionals (provider == "osv") (
          lib.concatMap (ecosystem: [
            "--ecosystem"
            ecosystem
          ]) cfg.ecosystems
        );
        credential = lib.optionalString (provider == "vulncheck") "vulncheck-api-token";
      }) cfg.providers;
    }
  );
in
{
  options.services.nixploit = {
    enable = lib.mkEnableOption "scheduled Nix vulnerability scans and Prometheus metrics";

    package = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "nixploit.packages.<system>.default";
      description = "The nixploit package used by the scheduled scanner.";
    };

    calendar = lib.mkOption {
      type = lib.types.str;
      default = "daily";
      description = "The systemd calendar expression for feed updates and scans.";
    };

    buildDependencies = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Include build dependencies alongside the running system runtime closure.";
    };

    providers = lib.mkOption {
      type = lib.types.nonEmptyListOf (
        lib.types.enum [
          "nvd"
          "vulncheck"
          "osv"
        ]
      );
      default = [ "nvd" ];
      example = [
        "nvd"
        "osv"
      ];
      description = "Feed providers to refresh before scanning.";
    };

    ecosystems = lib.mkOption {
      type = lib.types.nonEmptyListOf (
        lib.types.enum [
          "PyPI"
          "npm"
          "crates.io"
          "Go"
        ]
      );
      default = [
        "PyPI"
        "npm"
        "crates.io"
        "Go"
      ];
      description = "OSV ecosystems to refresh when the osv provider is enabled.";
    };

    tokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/keys/vulncheck-api-token";
      description = "Absolute path to the VulnCheck API token file.";
    };

    fromYear = lib.mkOption {
      type = lib.types.ints.between 2002 9999;
      default = 2002;
      description = "First NVD archive year to import, which limits advisory coverage.";
    };

    nvdMirror = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "https://nvd-mirror.example.internal/feeds/json/cve/2.0";
      description = "Base URL serving the NVD JSON archives in place of nvd.nist.gov.";
    };

    settings = lib.mkOption {
      inherit (toml) type;
      default = { };
      description = "Package aliases and reviewed ignore rules in nixploit configuration format.";
    };

    kbuild.enable = lib.mkOption {
      type = lib.types.bool;
      default = config.boot.kernelPackages.kernel ? configfile;
      defaultText = lib.literalExpression "config.boot.kernelPackages.kernel ? configfile";
      description = "Suppress kernel findings whose fixes touch only files the kernel's Kbuild configuration does not compile.";
    };

    dashboard.enable = lib.mkEnableOption "the nixploit dashboard in an existing Grafana service";
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = !builtins.elem "textfile" config.services.prometheus.exporters.node.disabledCollectors;
          message = "nixploit requires the node_exporter textfile collector to be enabled";
        }
        {
          assertion = !builtins.elem "vulncheck" cfg.providers || cfg.tokenFile != null;
          message = "services.nixploit.tokenFile is required for the VulnCheck provider";
        }
        {
          assertion = cfg.tokenFile == null || lib.hasPrefix "/" cfg.tokenFile;
          message = "services.nixploit.tokenFile must be an absolute path";
        }
      ];

      users.groups.nixploit = { };
      users.users.nixploit = {
        isSystemUser = true;
        group = "nixploit";
      };

      systemd.tmpfiles.rules = [
        "d ${textfileDirectory} 0755 nixploit nixploit -"
        "L+ ${textfileDirectory}/nixploit-enabled.prom - - - - ${enabledMetric}"
      ];

      systemd.services.nixploit = {
        description = "Update advisory feeds and scan the running NixOS system";
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        path = [
          config.nix.package
          pkgs.coreutils
        ];
        serviceConfig = {
          Type = "oneshot";
          User = "nixploit";
          Group = "nixploit";
          ExecStartPre = "${lib.getExe pkgs.nushell} --no-config-file ${./report.nu} start ${jobConfig}";
          ExecStart = "${lib.getExe pkgs.nushell} --no-config-file ${./report.nu} run ${jobConfig}";
          ExecStopPost = "${lib.getExe pkgs.nushell} --no-config-file ${./report.nu} finish ${jobConfig}";
          CacheDirectory = "nixploit";
          CacheDirectoryMode = "0700";
          StateDirectory = "nixploit";
          StateDirectoryMode = "0755";
          LoadCredential = lib.optionals (builtins.elem "vulncheck" cfg.providers && cfg.tokenFile != null) [
            "vulncheck-api-token:${cfg.tokenFile}"
          ];
          UMask = "0022";
          TimeoutStartSec = "6h";
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = "read-only";
        };
      };

      systemd.timers.nixploit = {
        description = "Schedule Nix vulnerability scans";
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = cfg.calendar;
          Persistent = true;
          RandomizedDelaySec = "15m";
        };
      };

      services.prometheus.exporters.node = {
        enable = true;
        enabledCollectors = [ "textfile" ];
        extraFlags = [ "--collector.textfile.directory=${textfileDirectory}" ];
      };
    })

    (lib.mkIf cfg.dashboard.enable {
      assertions = [
        {
          assertion = config.services.grafana.enable;
          message = "The nixploit dashboard requires services.grafana.enable";
        }
      ];

      services.grafana.provision = {
        enable = true;
        dashboards.settings.providers = [
          {
            name = "nixploit";
            options.path = ../monitoring;
          }
        ];
      };
    })
  ];
}
