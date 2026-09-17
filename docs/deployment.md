# Deployment

This guide installs Jaynshare on a private Linux host and enrolls macOS or
Windows clients. Keep the service off the public internet; the supported setup
uses a Tailscale address and shares only the Jaynshare host with each client.

Before enrolling anyone, read the [security and privacy model](security-and-privacy.md)
with them. The private network encrypts transport and client credentials prevent
unauthorized use, but the Jaynshare server still receives routed content in
plaintext. Every participant must trust the server operator and deployed code.

## Server

### Prerequisites

- Linux with systemd
- Node.js 26+
- Tailscale connected on the host
- A dedicated, unprivileged `jaynshare` user

Run the remaining server commands as that user from the repository root.

### Configure and add accounts

```sh
mkdir -p ~/.config
cp deploy/server/jaynshare.example.json ~/.config/jaynshare.json
chmod 600 ~/.config/jaynshare.json
tailscale ip -4
```

Set `proxy.host` in `~/.config/jaynshare.json` to the host's Tailscale IPv4
address. See [configuration.md](configuration.md) for every available option.

Each account owner should complete their own OAuth authorization. Callback URLs
are credentials; do not paste them into chat or issue trackers.

```sh
node src/index.ts login --oauth --name account-1
node src/index.ts login --oauth --name account-2
node src/index.ts accounts
```

### Install the service

```sh
deploy/server/install.sh
```

An administrator must enable lingering once:

```sh
sudo loginctl enable-linger jaynshare
```

Then start and validate the user service:

```sh
systemctl --user enable --now jaynshare.service
deploy/server/preflight.sh
```

Do not enroll clients until the preflight check ends with `READY`.

## Enroll a client

Use a stable lowercase client ID and the server's full Tailscale MagicDNS name:

```sh
umask 077
deploy/server/prepare-client.sh alice 'Alice Example' jaynshare-host.tailXXXX.ts.net
```

This creates two files under `onboarding/`:

- `jaynshare-alice.tar.gz` contains the installer and public CA, but no secret.
- `jaynshare-alice.secret` contains the one-time client secret.

Send them through separate private channels. Delete the transferred secret
after the client confirms that `jaynshare status` works.

An enrolled client can see fleet names, organization names, quota, aggregate
usage, and session counts, but not other clients' prompts or responses. Use
separate deployments if even that metadata or shared-quota influence should not
cross between groups.

### macOS

The client needs Node.js 26+, Claude Code, and Tailscale. Extract the bundle and
run its installer through Bash:

```sh
tar -xzf jaynshare-alice.tar.gz
cd jaynshare-alice
bash ./install.sh
```

Paste the secret at the hidden prompt. The commands are installed in
`~/.local/bin`; add that directory to `PATH` if necessary.

### Windows 10/11

Install native Windows builds of Node.js 26+, Claude Code, Tailscale, and Git
for Windows. Use Git Bash, not WSL, PowerShell, or Command Prompt:

```sh
tar -xzf jaynshare-alice.tar.gz
cd jaynshare-alice
bash ./install.sh
```

Use the command path printed by the installer. The installer restricts the
enrollment files to the current Windows account and `SYSTEM`.

## Daily use

```sh
jaynshare-claude                         # choose an account, then launch Claude
jaynshare-claude --auto                  # let the server choose
jaynshare-claude -- --model opus         # pass arguments after --
jaynshare status                         # one-shot fleet status
jaynshare dashboard                      # live read-only status
```

If the server is unavailable, `jaynshare-claude` stops instead of silently
using the client's personal quota. `jaynshare-claude --direct` is the explicit
bypass.

## Operations

```sh
node src/index.ts client list
node src/index.ts client disable alice
node src/index.ts client enable alice
node src/index.ts client rotate alice
node src/index.ts client revoke alice
journalctl --user --unit jaynshare.service --follow
```

Deliver rotated secrets privately. After revocation, also remove the client's
Tailscale share.

To deploy an update, pull a reviewed revision, restart the service, and rerun
the preflight check:

```sh
git pull --ff-only
systemctl --user restart jaynshare.service
deploy/server/preflight.sh
```

Upgrade the server before clients run `bash ./install.sh --upgrade` from a new
bundle. Full CLI details are in [usage.md](usage.md).

## Removal

Remove a macOS enrollment and restore the saved Claude settings, if present:

```sh
rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/jaynshare" \
  ~/.local/bin/jaynshare ~/.local/bin/jaynshare-claude
if [ -f ~/.claude/settings.json.before-jaynshare ]; then
  mv ~/.claude/settings.json.before-jaynshare ~/.claude/settings.json
fi
```

On Windows, run the equivalent from Git Bash using the native Windows profile:

```sh
profile=$(cygpath -u -- "$(node -p 'require("os").homedir()')")
rm -rf "$profile/.config/jaynshare" \
  "$profile/.local/bin/jaynshare" "$profile/.local/bin/jaynshare-claude"
if [ -f "$profile/.claude/settings.json.before-jaynshare" ]; then
  mv "$profile/.claude/settings.json.before-jaynshare" \
    "$profile/.claude/settings.json"
fi
```

Tell the operator to revoke the client credential and remove its Tailscale
share. Claude Code itself is not removed.

Remove the server service while preserving state:

```sh
deploy/server/uninstall.sh
```

`deploy/server/uninstall.sh --purge-state` also removes server state and must be
used deliberately.
