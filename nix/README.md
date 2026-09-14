# Nix packaging and modules

This directory contains the Nix package, NixOS module, and Home Manager module
for Jaynshare.

## Flake outputs

For each supported system, `flake.nix` exports:

- `packages.${system}.jaynshare`
- `packages.${system}.default`
- `apps.${system}.jaynshare`
- `apps.${system}.default`

It also exports:

- `nixosModules.jaynshare`
- `nixosModules.default`
- `homeManagerModules.jaynshare`
- `homeManagerModules.default`
- `checks.${system}.package` (the package build)
- `checks.${system}.nixos-module` (NixOS VM test; Linux only)

Supported package systems are:

- `x86_64-linux`
- `aarch64-linux`
- `x86_64-darwin`
- `aarch64-darwin`

## Package

`package.nix` packages Jaynshare as a direct Node application.

- `version` comes from `package.json`.
- `src` is the repository checkout via `lib.cleanSource ../.`.
- The install phase copies runtime files into `$out/share/jaynshare`.
- The wrapper runs `src/index.js` with pinned Nixpkgs `nodejs_24`.
- The build does not run `npm install`, invoke Bun, or fetch package registry
  dependencies. Jaynshare currently uses Node built-ins and local source files
  at runtime.
- The wrapper sets `JAYNSHARE_DISABLE_AUTOUPDATE=1` by default so Nix package
  invocations do not check npm or attempt a global mutable self-update.

Build the package from this repository:

```sh
nix build --no-update-lock-file .#jaynshare
```

Run the packaged CLI:

```sh
nix run --no-update-lock-file .#jaynshare -- help
```

Run a server manually:

```sh
nix run --no-update-lock-file .#jaynshare -- server --headless
```

This is intentionally a clean wrapper around the repository source. There is no
separate source tarball hash in `package.nix`; the Jaynshare source state is
pinned by Git history.

## NixOS module

Import the module and enable `services.jaynshare`:

```nix
{
  inputs.jaynshare.url = "github:jaynlabs/jaynshare";

  outputs =
    { nixpkgs, jaynshare, ... }:
    {
      nixosConfigurations.host = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          jaynshare.nixosModules.default
          ({ config, ... }: {
            services.jaynshare = {
              enable = true;
              host = "0.0.0.0";
              port = 3456;
              openFirewall = true;
              configSource = config.sops.secrets.jaynshare-config.path;
            };

            sops.secrets.jaynshare-config = {
              owner = "jaynshare";
              group = "jaynshare";
              mode = "0400";
            };
          })
        ];
      };
    };
}
```

The NixOS module creates `jaynshare.service`, a `jaynshare` system user/group
by default, a private `/var/lib/jaynshare` state directory, and optionally
installs the CLI into `environment.systemPackages`.

Important options:

- `services.jaynshare.package`: package to run.
- `services.jaynshare.installPackage`: install the CLI system-wide.
- `services.jaynshare.configFile`: mutable Jaynshare config path. Defaults to
  `/var/lib/jaynshare/jaynshare.json`.
- `services.jaynshare.configSource`: optional seed config copied only when
  `configFile` does not already exist.
- `services.jaynshare.host`: optional `JAYNSHARE_HOST` override. Use
  `0.0.0.0` for LAN access.
- `services.jaynshare.port`: port used for firewall opening. Jaynshare reads
  the actual listen port from its config file.
- `services.jaynshare.openFirewall`: open `port` in the NixOS firewall.
- `services.jaynshare.logDirectory`: optional `--log-to` directory.
- `services.jaynshare.environment`: extra service environment.
- `services.jaynshare.serviceConfig`: extra systemd settings.

The module runs `jaynshare server --headless`. The config file must remain
mutable because Jaynshare persists refreshed OAuth tokens, account changes,
routes, quota settings, and runtime state next to the config.

## Home Manager module

Import the Home Manager module when you want Jaynshare as a user service:

```nix
{ config, inputs, ... }:

{
  imports = [
    inputs.jaynshare.homeManagerModules.default
  ];

  services.jaynshare = {
    enable = true;
    configSource = config.sops.secrets.jaynshare-config.path;
  };

  sops.secrets.jaynshare-config = {
    mode = "0400";
  };
}
```

The Home Manager module creates `systemd.user.services.jaynshare`, optionally
adds the CLI to `home.packages`, and defaults the mutable config path to
`${XDG_CONFIG_HOME}/jaynshare.json`.

Important options:

- `services.jaynshare.package`: package to run.
- `services.jaynshare.installPackage`: install the CLI in `home.packages`.
- `services.jaynshare.configFile`: mutable Jaynshare config path.
- `services.jaynshare.configSource`: optional user-readable seed config copied
  only when `configFile` does not already exist.
- `services.jaynshare.stateDirectory`: user service working directory. Defaults
  to `${XDG_STATE_HOME}/jaynshare`.
- `services.jaynshare.host`: optional `JAYNSHARE_HOST` override.
- `services.jaynshare.logDirectory`: optional `--log-to` directory.
- `services.jaynshare.environment`: extra user service environment.
- `services.jaynshare.serviceConfig`: extra systemd user service settings.

Start or inspect the user service with:

```sh
systemctl --user start jaynshare.service
systemctl --user status jaynshare.service
```

## Secrets, LAN access, and MITM CA

Jaynshare's config contains sensitive data: `proxy.apiKey`, OAuth refresh
tokens, access tokens, optional API-key accounts, account routing, and sx.org
settings. Keep the seed config in sops-nix or an equivalent secret system.

For LAN access:

- set `services.jaynshare.host = "0.0.0.0"` or set `proxy.host` in the config;
- set a strong `proxy.apiKey` in the config;
- open the firewall only on the intended network path;
- give clients both the proxy URL and `proxy.apiKey`.

For normal base-URL clients:

```sh
ANTHROPIC_BASE_URL=http://jaynshare-host:3456 \
ANTHROPIC_API_KEY='<proxy.apiKey>' \
claude -p 'Reply with exactly: ok'
```

For MITM/forward-proxy mode, clients also need Jaynshare's generated CA
certificate. Jaynshare stores MITM files next to `JAYNSHARE_CONFIG`:

- `jaynshare-ca.pem`: CA certificate clients must trust;
- `jaynshare-leaf.pem`: generated server leaf certificate;
- `jaynshare-leaf.key`: generated server leaf private key.

The CA private key is not persisted. If the MITM files are missing or no longer
cover the upstream host, Jaynshare regenerates the chain, which changes the CA
certificate clients need to trust.

Practical sops guidance:

- store the initial `jaynshare.json` seed in sops because it contains
  `proxy.apiKey` and account credentials;
- after the first MITM run, export `jaynshare-ca.pem` to the client machines
  through sops-nix if those clients should use forward-proxy mode;
- back up or manage `jaynshare-ca.pem`, `jaynshare-leaf.pem`, and
  `jaynshare-leaf.key` if you need the CA trust anchor to survive service state
  replacement or host migration;
- do not put these files in the Nix store.

Example client-side environment for MITM mode:

```sh
HTTPS_PROXY=http://<proxy.apiKey>@jaynshare-host:3456 \
NODE_EXTRA_CA_CERTS=/run/secrets/jaynshare-ca.pem \
claude -p 'Reply with exactly: ok'
```

For curl validation:

```sh
curl --proxy http://<proxy.apiKey>@jaynshare-host:3456 \
  --cacert /run/secrets/jaynshare-ca.pem \
  https://www.example.org/
```

## Tests

The flake exposes its tests as `checks`, so `nix flake check` runs them all:

```sh
nix flake check --no-update-lock-file -L
```

- `checks.${system}.package` builds the package on every supported system.
- `checks.${system}.nixos-module` (Linux only) is a full NixOS VM test
  (`nix/tests/module.nix`): it boots a VM with `services.jaynshare` enabled and
  a seeded config, waits for the unit and its port, and asserts
  `/jaynshare/status` responds with the seeded account — end-to-end coverage of
  the package, the module wiring, and config seeding. It uses an `apikey`
  account so startup makes no network calls (VM tests have no network).

The VM test needs KVM on the runner (GitHub-hosted `ubuntu-latest` provides
`/dev/kvm`).

## CI

The `CI` workflow runs on pushes and pull requests for `master`, and can also be
dispatched manually. Alongside the Node test/lint matrix it runs:

- `nix flake check` (package build on the runner's system + the NixOS VM test);
- a smoke test of the CLI wrapper with
  `nix run --no-update-lock-file .#jaynshare -- help`;
- a stable aggregate `test` job that branch protection can require.

## Updating the flake lock

Because the package uses the repository checkout as `src`, there is no upstream
source hash to manage — the Jaynshare source is pinned by the Git commit
itself. The only Nix hash in play is the nixpkgs lock in `flake.lock`; refresh it
with `nix flake update` when you want a newer nixpkgs pin.
