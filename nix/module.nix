{ config, lib, pkgs, ... }:

let
  cfg = config.services.xmorph;

  # Args accepted by BOTH `build` and `pivot`. SSH flags are deliberately
  # NOT here: the build subcommand doesn't bind them (`xmorph build --ssh.enable`
  # errors with "unknown flag"), so they must go to `pivot` only.
  commonArgs =
    (map (img: "--image=${img}") cfg.images)
    ++ (map (r: "--rootfs=${r}") cfg.rootfs)
    ++ lib.optional cfg.tailscale.enable "--tailscale.enable"
    ++ lib.optional (cfg.tailscale.enable && cfg.tailscale.server != null) "--tailscale.server=${cfg.tailscale.server}"
    ++ lib.optional (cfg.tailscale.enable && cfg.tailscale.args != null) "--tailscale.args=${cfg.tailscale.args}"
    ++ lib.optional cfg.verbose "--verbose";

  # SSH args — pivot only.
  sshArgs =
    lib.optional cfg.ssh.enable "--ssh.enable"
    ++ lib.optional (cfg.ssh.enable && cfg.ssh.port != null) "--ssh.port=${toString cfg.ssh.port}"
    ++ lib.optional (cfg.ssh.enable && cfg.ssh.authorizedKeys != null) "--ssh.authorized-keys=${cfg.ssh.authorizedKeys}";

  buildArgs = [ "build" ] ++ commonArgs;

  pivotArgs =
    [ "pivot" "--systemd-mode" "--force" ]
    ++ commonArgs
    ++ sshArgs
    ++ lib.optional (cfg.entrypoint != null) "--entrypoint=${cfg.entrypoint}"
    ++ (map (c: "--command=${c}") cfg.command)
    ++ lib.optional (cfg.workDir != null) "--work-dir=${cfg.workDir}"
    ++ lib.optional (cfg.logDir != null) "--log-dir=${cfg.logDir}";

  needAuthKey = cfg.tailscale.enable && cfg.tailscale.authKeyFile != null;

  # systemd's ExecStart is not a shell, so `--tailscale.authkey=$(cat ...)`
  # would be passed literally. Wrap the invocation in a small script that
  # reads the key file at runtime (keeping the secret out of the nix store)
  # and appends it as a real argument.
  mkExecStart = name: baseArgs: passwordFile: pkgs.writeShellScript name ''
    set -euo pipefail
    ${lib.optionalString needAuthKey
      ''authkey="$(cat ${lib.escapeShellArg (toString cfg.tailscale.authKeyFile)})"''}
    ${lib.optionalString (passwordFile != null) ''
      password="$(cat ${lib.escapeShellArg passwordFile})"
      if [ -z "$password" ]; then
        echo "SSH password file is empty" >&2
        exit 1
      fi
    ''}
    exec ${cfg.package}/bin/xmorph ${lib.escapeShellArgs baseArgs} ${
      lib.optionalString needAuthKey ''--tailscale.authkey="$authkey"''
    } ${
      lib.optionalString (passwordFile != null) ''--ssh.password="$password"''
    }
  '';
in
{
  imports = [
    (lib.mkRemovedOptionModule [ "services" "xmorph" "ssh" "password" ]
      "Use services.xmorph.ssh.passwordFile with a root-readable runtime file; inline passwords expose the root credential in the Nix store.")
  ];

  options.services.xmorph = {
    enable = lib.mkEnableOption "xmorph rescue pivot service";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The xmorph package to use.";
    };

    images = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "docker.io/library/alpine:latest" ];
      description = "OCI images to merge into the rootfs (in order).";
    };

    rootfs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Local rootfs paths/tarballs to merge (in order with images).";
    };

    entrypoint = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Entrypoint override. Null uses the image default.";
    };

    command = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Command/arguments passed to the entrypoint.";
    };

    verbose = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable verbose logging.";
    };

    workDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Working directory for rootfs extraction.";
    };

    logDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Log directory.";
    };

    warmupBuildCache = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Populate the build cache on boot; registry-image pivots do not reuse it.";
    };

    ssh = {
      enable = lib.mkEnableOption "SSH in the new rootfs (tsnet-backed)";

      port = lib.mkOption {
        type = lib.types.nullOr lib.types.port;
        default = null;
        description = "SSH port (default: 22).";
      };

      passwordFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Runtime path to a root-only file containing the SSH password, with an
          optional trailing newline. Use a quoted path outside the Nix store;
          the file is read only when starting the pivot service. Missing or
          empty files abort startup. Null generates a password if no usable
          authorized keys are configured.
        '';
      };

      authorizedKeys = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "SSH authorized public keys (inline, one per line). Key options are unsupported and rejected before pivot.";
      };
    };

    tailscale = {
      enable = lib.mkEnableOption "Tailscale (tsnet) integration";

      authKeyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = ''
          Path to a file containing the Tailscale auth key.
          The file is read at runtime to avoid storing keys in the nix store.
        '';
      };

      server = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Tailscale coordination server URL (for Headscale).";
      };

      args = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
      description = "Legacy Tailscale arguments; only --hostname=NAME is used (default: <host>-xmorph).";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.xmorph-pivot = {
      description = "xmorph rootfs pivot";
      documentation = [ "https://github.com/ananthb/xmorph" ];

      after = [ "rescue.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "rescue.target" ];
      requires = [ "network-online.target" ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;

        ExecStart = mkExecStart "xmorph-pivot-start" pivotArgs
          (if cfg.ssh.enable then cfg.ssh.passwordFile else null);

        CacheDirectory = "xmorph";
        RuntimeDirectory = "xmorph";

        TimeoutStartSec = "infinity";
        Restart = "no";

        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

    systemd.services.xmorph-cache-warm = lib.mkIf cfg.warmupBuildCache {
      description = "xmorph cache pre-warm";
      documentation = [ "https://github.com/ananthb/xmorph" ];

      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = mkExecStart "xmorph-cache-warm-start" buildArgs null;
        CacheDirectory = "xmorph";
        RuntimeDirectory = "xmorph";
        TimeoutStartSec = "infinity";
        Restart = "no";
      };
    };
  };
}
