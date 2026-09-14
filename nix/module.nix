{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.jaynshare;

  inherit (lib)
    literalExpression
    mkEnableOption
    mkIf
    mkOption
    optional
    optionalAttrs
    optionalString
    types
    ;

  defaultPackage = pkgs.callPackage ./package.nix { };
  configFile =
    if cfg.configFile == null then "/var/lib/${cfg.stateDirectory}/jaynshare.json" else cfg.configFile;

  serverArgs = [
    "server"
    "--headless"
  ]
  ++ lib.optionals (cfg.logDirectory != null) [
    "--log-to"
    cfg.logDirectory
  ]
  ++ cfg.extraArgs;
in
{
  options.services.jaynshare = {
    enable = mkEnableOption "Jaynshare proxy service";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = literalExpression "pkgs.callPackage ./nix/package.nix { }";
      description = "Jaynshare package to run.";
    };

    installPackage = mkOption {
      type = types.bool;
      default = true;
      description = "Whether to add the Jaynshare CLI package to systemPackages.";
    };

    user = mkOption {
      type = types.str;
      default = "jaynshare";
      description = "User account that runs the Jaynshare service.";
    };

    group = mkOption {
      type = types.str;
      default = "jaynshare";
      description = "Group account that runs the Jaynshare service.";
    };

    stateDirectory = mkOption {
      type = types.str;
      default = "jaynshare";
      description = "systemd StateDirectory name used for mutable Jaynshare state.";
    };

    configFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/var/lib/jaynshare/jaynshare.json";
      description = ''
        Mutable Jaynshare config path. When null, the module uses
        /var/lib/<stateDirectory>/jaynshare.json.

        This should be writable by the service because Jaynshare persists
        refreshed OAuth tokens, account changes, routes, quota settings, and
        runtime state next to the config.
      '';
    };

    configSource = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/secrets/jaynshare.json";
      description = ''
        Optional seed config copied to configFile only when configFile does not
        already exist. This is intended for sops-nix or another secret provider.

        The source must be readable during service pre-start; normal sops-nix
        root-readable secrets work. It is not copied again after the mutable
        config exists, so runtime token refreshes are not overwritten on
        restart.
      '';
    };

    host = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "0.0.0.0";
      description = ''
        Optional bind host override passed through JAYNSHARE_HOST. Leave null
        to use Jaynshare's config/default behavior. Set 0.0.0.0 for LAN access
        and make sure the proxy config has a secret proxy.apiKey.
      '';
    };

    port = mkOption {
      type = types.port;
      default = 3456;
      description = ''
        Proxy port used only for firewall opening. Jaynshare reads its actual
        listen port from configFile.
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Whether to open services.jaynshare.port in the NixOS firewall.";
    };

    logDirectory = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/var/log/jaynshare";
      description = "Optional request/response log directory passed via --log-to.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "--no-tui" ];
      description = "Extra command-line arguments appended to jaynshare server --headless.";
    };

    environment = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = {
        JAYNSHARE_UPSTREAM_HEADERS_TIMEOUT_MS = "120000";
      };
      description = "Extra environment variables for the Jaynshare service.";
    };

    serviceConfig = mkOption {
      type = types.attrsOf types.anything;
      default = { };
      example = literalExpression ''
        {
          RestartSec = "10s";
        }
      '';
      description = "Extra systemd serviceConfig values merged into jaynshare.service.";
    };
  };

  config = mkIf cfg.enable {
    warnings = optional (cfg.openFirewall && cfg.host == null) ''
      services.jaynshare.openFirewall is true, but services.jaynshare.host is
      null. Jaynshare may still bind only to 127.0.0.1 unless the config file
      sets proxy.host or JAYNSHARE_HOST is set elsewhere.
    '';

    environment.systemPackages = mkIf cfg.installPackage [ cfg.package ];

    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [ cfg.port ];

    users.groups = mkIf (cfg.group == "jaynshare") {
      jaynshare = { };
    };

    users.users = mkIf (cfg.user == "jaynshare") {
      jaynshare = {
        isSystemUser = true;
        group = cfg.group;
        home = "/var/lib/${cfg.stateDirectory}";
        createHome = true;
      };
    };

    systemd.services.jaynshare = {
      description = "Jaynshare proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        JAYNSHARE_CONFIG = configFile;
        JAYNSHARE_DISABLE_AUTOUPDATE = "1";
      }
      // optionalAttrs (cfg.host != null) {
        JAYNSHARE_HOST = cfg.host;
      }
      // cfg.environment;

      preStart = ''
        config_dir="$(${pkgs.coreutils}/bin/dirname ${lib.escapeShellArg configFile})"
        ${pkgs.coreutils}/bin/install -d -m 0700 -o ${lib.escapeShellArg cfg.user} -g ${lib.escapeShellArg cfg.group} "$config_dir"
      ''
      + optionalString (cfg.configSource != null) ''
        if [ ! -e ${lib.escapeShellArg configFile} ]; then
          ${pkgs.coreutils}/bin/install -m 0600 -o ${lib.escapeShellArg cfg.user} -g ${lib.escapeShellArg cfg.group} \
            ${lib.escapeShellArg cfg.configSource} ${lib.escapeShellArg configFile}
        fi
      ''
      + optionalString (cfg.logDirectory != null) ''
        ${pkgs.coreutils}/bin/install -d -m 0700 -o ${lib.escapeShellArg cfg.user} -g ${lib.escapeShellArg cfg.group} \
          ${lib.escapeShellArg cfg.logDirectory}
      '';

      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} ${lib.escapeShellArgs serverArgs}";
        Restart = "on-failure";
        RestartSec = "5s";
        PermissionsStartOnly = true;
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = cfg.stateDirectory;
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/${cfg.stateDirectory}";
      }
      // cfg.serviceConfig;
    };
  };
}
