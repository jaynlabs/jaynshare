# Jaynshare

Jaynshare is a self-hosted Claude subscription pool. One Linux host holds the
pooled Claude identities and routes authenticated Claude Code traffic to
whichever account has quota. Every engineer keeps Claude Code, repositories,
transcripts and credentials on their own machine — macOS or Windows — and
reaches the host over a private network.

Node.js 26+, no runtime dependencies.

This file is the onboarding guide. It contains every command, in order, for
each role. Everything else in the repository is reference.

| You are | Read |
| --- | --- |
| Setting up or running the server | [1. Server](#1-server-linux-operator), [2. Enrol a person](#2-enrol-a-person-operator), [6. Operate](#6-operate-operator) |
| An engineer on a Mac | [3. macOS](#3-macos-desktop), [5. Daily use](#5-daily-use-both-platforms) |
| An engineer on Windows | [4. Windows](#4-windows-1011-desktop), [5. Daily use](#5-daily-use-both-platforms) |
| Changing the code | [7. Develop and test](#7-develop-and-test) |
| Stuck | [8. Troubleshooting](#8-troubleshooting) |

**Read before anything else.** Pooling subscription identities may conflict with
your provider's terms of service — read [compliance](docs/compliance.md) before
you deploy this. Enrol only accounts whose owners consent and personally
authorize, and never put a real secret, token, account state, machine address
or transcript into this repository.

---

## 1. Server (Linux, operator)

The server is one process on one Linux host, run by an unprivileged
`jaynshare` user, listening only on the host's Tailscale address, TCP/3456.
It installs from this checkout: no npm, no curl, no updater.

Every command in this section runs **as the `jaynshare` user, from the root of
the checkout** (for example `/home/jaynshare/app`). `node src/index.ts` is the
CLI; the docs call it `jaynshare` for short.

### 1.1 Prerequisites

- Linux with systemd, and an administrator who can run one `loginctl` command.
- Node.js 26 or newer available to the `jaynshare` user.
- Tailscale installed and connected on the host.
- The dedicated user:

```sh
sudo useradd --create-home --shell /bin/bash jaynshare
sudo -iu jaynshare
git clone <this repository> ~/app      # or copy the checkout in
cd ~/app
node --version                          # must print v20 or newer
```

### 1.2 Configure

```sh
mkdir -p ~/.config
cp deploy/server/jaynshare.example.json ~/.config/jaynshare.json
chmod 600 ~/.config/jaynshare.json
tailscale ip -4                         # the address to put in proxy.host
```

Edit `~/.config/jaynshare.json` and replace `100.x.y.z` with the host's own
Tailscale IPv4 address. The installer refuses anything that is not a concrete
`100.64.0.0/10` address. The other fields are documented in
[configuration.md](docs/configuration.md); the defaults are right
for this deployment.

### 1.3 Authorize the pooled accounts

Run one `login` per Claude account. The operator starts the command; **the
account's owner** opens the printed URL in their own browser, signs in, and
returns the one-time callback URL or code. Never ask for or watch anyone's
Claude password. Callback URLs are credentials — do not paste them into chat.

```sh
node src/index.ts login --oauth --name account-1
node src/index.ts login --oauth --name account-2
node src/index.ts accounts               # both listed with tier and token state
```

### 1.4 Install the service

```sh
deploy/server/install.sh
```

Then, as an administrator (once):

```sh
sudo loginctl enable-linger jaynshare
```

Back as `jaynshare`:

```sh
systemctl --user enable --now jaynshare.service
systemctl --user status jaynshare.service
deploy/server/preflight.sh               # must end with READY
```

`preflight.sh` checks the process, the Tailscale address, the CA certificate,
privacy settings, configured accounts and the live status endpoint. **Do not
issue any client access until it prints `READY`.** The first start also
writes the public CA to `~/.config/jaynshare-ca.pem`, which the enrolment
bundles need.

### 1.5 Create the operator credential

```sh
umask 077
node src/index.ts client admin rotate > ~/operator.secret
```

This is the only credential that can read `jaynshare status` on the server and
mutate state. Keep it on the server side; never send it to a tester.

### 1.6 Tailscale access

In the Tailscale admin console, open **Machines → (this host) → Share** and
share the machine with each tester individually. Do not invite testers into
the tailnet: a shared machine is quarantined, so the tester gets a route to
the host without the host getting a route back.

Set the tailnet policy's `grants` so share recipients can reach only this
port. Keep any existing `ssh`, `groups` or other sections:

```json
"grants": [
  { "src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"] },
  { "src": ["autogroup:shared"], "dst": ["*"],              "ip": ["tcp:3456"] }
]
```

No public DNS, no router port-forward, no public firewall rule. The service
must never be reachable from the internet.

---

## 2. Enrol a person (operator)

One command builds everything a person needs, with the secret kept apart from
the bundle. Use a stable lowercase ID and the server's **full MagicDNS name**
(`<host>.<tailnet>.ts.net`), not its `100.x` address — a shared machine can
show a different `100.x` address in the recipient's tailnet.

```sh
cd ~/app
umask 077
deploy/server/prepare-client.sh alice 'Alice Example' jaynshare-host.tailXXXX.ts.net
```

Output, in `./onboarding/`, all mode 0600:

```text
jaynshare-alice.tar.gz    installer + public CA + START-HERE.txt — no secret
jaynshare-alice.secret    Alice's one-time client secret
```

Send the archive and the secret through **two different private channels**.
The secret never goes in Git, a shared chat, or a ticket. Delete your copy of
the secret once the person confirms `jaynshare status` works; the server keeps
only its SHA-256 hash.

If the server is already running, nothing needs restarting: `client add`
notifies the service and the new credential works immediately.

---

## 3. macOS desktop

### 3.1 Prerequisites

```sh
node --version        # v20 or newer
claude --version      # Claude Code already installed and working
```

Install Tailscale from the App Store or tailscale.com, sign in with your
**own** Tailscale account, and accept the machine share the operator sent.
Confirm you can see the host:

```sh
tailscale status | grep jaynshare
```

Have the one-time secret ready from the separate channel.

### 3.2 Install from the bundle

```sh
tar -xzf jaynshare-alice.tar.gz
cd jaynshare-alice
bash ./install.sh
```

Use the `bash` form even on macOS. Some messaging and file-transfer services
strip the archive's Unix executable bit; invoking the readable script through
`bash` works in both cases.

Paste the secret at the hidden prompt (nothing is echoed). The installer stages
everything in a private directory, verifies your credential against the server,
and only then writes the enrolment. If anything fails you are left with your
previous working client or no client — never a half-written one. It ends by
printing your account table and the two commands you will use.

### 3.3 Put the commands on your PATH

The installer writes to `~/.local/bin` and never edits your shell profile. Add
it once:

```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
jaynshare status
```

### 3.4 Manual install (recovery, or from a checkout)

Only needed if you do not have a bundle. You need the public
`jaynshare-ca.pem` from the server, which is not secret.

```sh
deploy/client/install.sh alice jaynshare-host.tailXXXX.ts.net ./jaynshare-ca.pem
```

### 3.5 Upgrade an existing enrolment

Re-installs the launcher, client and Claude UI settings without re-entering the
secret or copying the CA again. The operator upgrades and restarts the server
first.

```sh
bash ./install.sh --upgrade           # from a new bundle, or
deploy/client/install.sh --upgrade    # from a checkout
```

### 3.6 Uninstall

```sh
rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/jaynshare" ~/.local/bin/jaynshare ~/.local/bin/jaynshare-claude
mv ~/.claude/settings.json.before-jaynshare ~/.claude/settings.json
```

Claude Code itself is untouched. Tell the operator so your credential can be
revoked.

---

## 4. Windows 10/11 desktop

Jaynshare runs on **native Windows through Git for Windows**. Installation
runs in **Git Bash only** — not WSL, not PowerShell, not CMD, not a container —
against the native Windows Node that Claude Code itself uses. It never needs
Administrator rights. Both x64 and ARM64 are supported.

### 4.1 Prerequisites

1. **Git for Windows** — <https://git-scm.com/download/win>. This provides
   Git Bash. Any recent build works; 2.55 or newer gives the arrow-key
   picker, older builds give the numbered one (see 4.5).
2. **Node.js 26 or newer, native Windows build** — <https://nodejs.org>. Not
   inside WSL.
3. **Claude Code, native Windows build**, installed and working.
4. **Tailscale for Windows** — sign in with your **own** account and accept
   the machine share the operator sent.

Open **Git Bash** and confirm all four:

```sh
node --version                         # v20 or newer
node -p 'process.platform'             # must print win32, not linux
claude --version
tailscale status | grep jaynshare
```

If `claude` is not found in Git Bash but works elsewhere, close **every** Git
Bash window and open a new one — PATH changes from the Claude installer only
reach new shells.

Have the one-time secret ready from the separate channel.

### 4.2 Install from the bundle

Extract the archive with Explorer (Windows 11 opens `.tar.gz` directly) or
from Git Bash:

```sh
tar -xzf jaynshare-alice.tar.gz
```

Then **right-click the extracted `jaynshare-alice` folder → "Open Git Bash
here"** and run:

```sh
bash ./install.sh
```

Always invoke it through `bash`: Explorer drops Unix executable bits, and
this form does not depend on them.

Paste the secret at the hidden prompt. A trailing carriage return from the
Windows clipboard is stripped automatically. The installer:

- stores the enrolment under your **Windows profile**
  (`%USERPROFILE%\.config\jaynshare`), which is where the client will look;
- locks that directory and its three files with an NTFS access rule
  (`icacls`, by SID): inheritance removed, full control to you and SYSTEM only;
- reads the access list back and **fails the install** if any other principal
  can reach the secret;
- verifies your credential against the server before keeping anything;
- prints the **full path** of the two installed commands.

### 4.3 Use the path the installer printed

Git Bash's `~` is not always your Windows profile (roaming profiles and
`HOMEDRIVE` overrides change it). The installer resolves the profile the same
way the client does — by asking Node — and prints the resulting directory. Use
exactly that. Normally it is:

```sh
~/.local/bin/jaynshare status
~/.local/bin/jaynshare-claude
```

To avoid typing the path, add the directory the installer printed to
`~/.bashrc`:

```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc    # adjust if the printed path differs
source ~/.bashrc
jaynshare status
```

### 4.4 Manual install (recovery, or from a checkout)

```sh
bash deploy/client/install.sh alice jaynshare-host.tailXXXX.ts.net ./jaynshare-ca.pem
```

### 4.5 Which picker you will see

`jaynshare-claude` opens an account picker before Claude starts. On Windows
the form it takes depends on the **Git for Windows build**, not on which
terminal you opened:

- Git for Windows **2.55 or newer**: mintty wraps a ConPTY, Node gets a real
  console, you get the **arrow-key** picker.
- **Older** builds: mintty hands Node a pipe with no raw mode, you get the
  **numbered** picker and type a number.

Both are supported. Ask which you have, or force one:

```sh
node -p "typeof process.stdin.setRawMode === 'function' ? 'arrow-key picker' : 'numbered picker'"
JAYNSHARE_PICKER=line jaynshare-claude     # force numbered
JAYNSHARE_PICKER=raw  jaynshare-claude     # force arrow keys
```

### 4.6 Upgrade an existing enrolment

```sh
bash ./install.sh --upgrade                 # from a new bundle, or
bash deploy/client/install.sh --upgrade     # from a checkout
```

### 4.7 Uninstall

Resolve the profile the way the installer did, then remove the enrolment and
both launchers and restore the saved Claude settings:

```sh
profile=$(cygpath -u -- "$(node -p 'require("os").homedir()')")
rm -rf "$profile/.config/jaynshare" "$profile/.local/bin/jaynshare" "$profile/.local/bin/jaynshare-claude"
mv "$profile/.claude/settings.json.before-jaynshare" "$profile/.claude/settings.json"
```

Claude Code itself is untouched. Tell the operator so your credential can be
revoked.

### 4.8 What has been verified on Windows

The Windows client passed three test layers before merge (PR #7,
2026-09-12): the platform-independent suite with stubbed Windows tools, the
`windows-client` CI job on `windows-latest` under Git Bash on Node 26,
and an interactive pass on a real Windows 11 ARM64 desktop (Git for Windows
2.55, Node 24) covering install with a typed secret, both picker modes,
cancellation, `Ctrl-C`, `--auto`, `--direct`, refusal with the proxy down,
Explorer extraction, and uninstall. Two things that pass caught, now covered
by tests: an NTFS rename converting an inherited ACE into an explicit one the
lock could not remove, and the picker drawing as mojibake on an OEM-codepage
console.

Not yet verified in a Windows desktop session: the yellow `◆ JAYNSHARE`
status line inside Claude Code (Claude Code was not installed in the VM). No
Windows tester has been enrolled yet. Internals — profile resolution, ACLs,
path conversion, why there is no `.cmd` shim — are in
[windows-client.md](docs/windows-client.md).

---

## 5. Daily use (both platforms)

Use `jaynshare-claude` in place of `claude`. Everything after `--` goes to
Claude unchanged.

```sh
jaynshare-claude                                   # picker, then Claude
jaynshare-claude -- --model opus                   # picker, Claude with args
jaynshare-claude --auto -- --model opus            # no picker, fleet routing
jaynshare-claude --account alice@example.com       # no picker, prefer that account
```

In the picker, `Automatic` keeps fleet routing. Choosing an account is a
**preference for this Claude process, not a lock** — quota, health, per-model
routes and failover still apply. Disabled, exhausted and errored accounts are
listed but cannot be chosen. `Escape` (arrow-key) or `q` (numbered) cancels
and nothing launches.

Account selectors accept a display name, email, account UUID, org UUID, or
`accountUuid/orgUuid`. Numeric indexes are rejected.

```sh
jaynshare status         # one-shot table of every pooled account and quota
jaynshare dashboard      # live read-only view, refreshes every 2 s, Ctrl-C to close
```

Both use your own credential and show quota and aggregate counters only — no
tokens, routing controls or upstream addresses. The dashboard's diamond marks
the server's global default, not your session.

Inside Claude Code you get a yellow `◆ JAYNSHARE` status line that refreshes
every 15 s, names the account that served your latest request, shows
`pending` before the first one and `offline` if the server is unreachable
(without blocking your turn). The tab title is branded and keeps a short
preview of your latest prompt.

**If the server is down, `jaynshare-claude` refuses to start.** It never
silently falls back to your own Claude account. The one explicit escape hatch:

```sh
jaynshare-claude --direct        # plain Claude Code on your own login
```

---

## 6. Operate (operator)

From the checkout as `jaynshare`. These take effect immediately; the CLI
notifies the running service.

```sh
node src/index.ts client list                     # enrolments, no hashes or secrets
node src/index.ts status                          # fleet view: quota, routing, current account
journalctl --user --unit jaynshare.service --follow

node src/index.ts client disable alice            # pause one person
node src/index.ts client enable alice

umask 077
node src/index.ts client rotate alice > ~/alice-replacement.secret   # after a leak
node src/index.ts client revoke alice             # permanent
```

After `rotate`, deliver the new secret privately and have the person re-run the
full installer (not `--upgrade`). After `revoke`, also remove their Tailscale
share.

Server-side account commands (`accounts`, `switch`, `disable`, `enable`,
`priority`, `route`, `probe`), the TUI, and headless control are in
[usage.md](docs/usage.md). Routing policy is in
[routing.md](docs/routing.md), quota behaviour in
[quota.md](docs/quota.md).

### Acceptance check for a new enrolment

Do all four before calling someone onboarded:

1. `jaynshare status` succeeds from their machine.
2. `jaynshare-claude` completes one harmless prompt.
3. Their request appears under the right `clientId` in
   `~/.local/state/jaynshare/audit.ndjson` on the server.
4. `client disable <id>` blocks their next request; then `enable` again.

For a Windows tester, run 1 and 2 from Git Bash and confirm the picker they get
is legible and usable (section 4.5).

### Upgrading the server

Updates are deliberate: pull the reviewed commit into the checkout, then
restart. Do not use `jaynshare update`; self-update is disabled on purpose.

```sh
cd ~/app && git pull --ff-only
systemctl --user restart jaynshare.service
deploy/server/preflight.sh
```

Restart the server **before** anyone runs `install.sh --upgrade`. A client
that is newer than its server fails account selection with
`server upgrade required`; `--auto` keeps working.

### Uninstall the server

```sh
deploy/server/uninstall.sh                 # stops and removes the service, keeps state and audit log
deploy/server/uninstall.sh --purge-state   # destructive; only for the dedicated-user paths
```

---

## 7. Develop and test

Node 26+ and no runtime dependencies. All commands from the repository root.

**macOS / Linux:**

```sh
npm install                                   # eslint only
npm test                                      # full suite, includes the win32 paths via stubs
npm run lint
bash test-support/client-install-check.sh     # end-to-end client install in a throwaway profile
```

**Windows (Git Bash, native Node):**

```sh
bash test-support/client-install-check.sh     # the only suite that runs on native Windows
```

`npm test` does not run on native Windows: the suite spawns `/bin/sh` and
asserts POSIX mode bits. The install check is what the `windows-client` CI job
runs, against real `icacls` and native paths. No test uses a real secret,
server or Anthropic account.

**Before shipping a client bundle to a Windows user**, run the interactive
pass in [windows-vm-smoke-test.md](docs/windows-vm-smoke-test.md) on a
disposable Windows 11 VM. It covers what CI cannot: a real terminal, Explorer,
a real profile, and ARM64.

**Nix** (optional): `nix flake check` and `nix run .#jaynshare -- help`; see
[nix/README.md](nix/README.md).

CI (`.github/workflows/ci.yml`) runs the Node suite on 20/22/24, lint on 24,
the Windows install check on `windows-latest`, and the Nix flake check. The
`test` job is the single required status.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `jaynshare-claude` refuses to start, "proxy unreachable" | Tailscale not connected, or the share was not accepted, or the server is down. `tailscale status`, then `jaynshare status`. `--direct` if you must work now. |
| `server upgrade required` on account selection | Client is newer than the server. Operator restarts the upgraded server; `--auto` works meanwhile. |
| Install: `the enrolled credential could not reach the server; nothing was kept` | Wrong secret, wrong host, or Tailscale not up. Nothing was written; fix and re-run. |
| macOS: `zsh: operation not permitted: .../install.sh` | Direct execution was blocked after transfer, commonly because the executable bit was not preserved. From the extracted directory, run `bash ./install.sh`. |
| Install: `claude was not found in Git Bash` | Close all Git Bash windows and reopen; if it persists, reinstall the native Windows Claude Code. |
| Install: `this shell runs on Windows but node reports "linux"` | Node from WSL is first on PATH. Install the native Windows Node and reopen Git Bash. |
| Install: `cygpath was not found` / `icacls.exe was not found` | You are not in Git Bash. Open Git Bash and run `bash ./install.sh`. |
| Install: `the client secret is not restricted to your account` | The NTFS lock could not be verified. Do not proceed; report it with the printed access list. |
| `~/.local/bin/jaynshare: No such file` on Windows | `~` is not your Windows profile. Use the path the installer printed, or `cygpath -u -- "$(node -p 'require("os").homedir()')"`. |
| Picker shows `Γåæ` or other garbage | Fixed in PR #7; run `install.sh --upgrade` from a current bundle or checkout. |
| Arrow keys do nothing in the picker | Older Git for Windows — use the numbered picker (type a number), or `JAYNSHARE_PICKER=line`. |
| Status line says `offline` | The server is unreachable from this machine right now. Claude still works for the current turn; check Tailscale. |
| Server `install.sh`: `proxy.host must be a concrete Tailscale IPv4 address` | Put the host's `100.x.y.z` (from `tailscale ip -4`) in `~/.config/jaynshare.json`. |
| `preflight.sh` does not end with `READY` | Read its first failing line; the usual causes are no enrolled account, service not started, or a wrong `proxy.host`. |

---

## Repository map

```text
README.md              this guide
SOURCES.md             provenance: imported revisions and licenses
src/                   server, proxy, CLI
deploy/server/         install.sh, preflight.sh, prepare-client.sh, uninstall.sh
deploy/client/         install.sh, jaynshare-claude, jaynshare-client.mjs
docs/                  reference, listed below
test/, test-support/   node --test suite and the client install check
nix/                   flake, NixOS and home-manager modules
```

Reference documentation:

- [usage.md](docs/usage.md) — full CLI reference, TUI keys, headless control
- [configuration.md](docs/configuration.md) — every config field
- [routing.md](docs/routing.md) — rotation, priorities, per-model routes
- [quota.md](docs/quota.md) — quota probing and thresholds
- [accounts.md](docs/accounts.md) — account identity and resolution
- [proxy-modes.md](docs/proxy-modes.md) — MITM vs base-URL mode
- [windows-client.md](docs/windows-client.md) — how the native Windows client works
- [windows-vm-smoke-test.md](docs/windows-vm-smoke-test.md) — pre-release interactive Windows pass
- [compliance.md](docs/compliance.md) — terms-of-service considerations
- [nix/README.md](nix/README.md) — flake, NixOS and home-manager modules

Runtime locations, for reference:

| | Server (Linux) | macOS client | Windows client |
| --- | --- | --- | --- |
| Config | `~/.config/jaynshare.json` | `~/.config/jaynshare/` | `%USERPROFILE%\.config\jaynshare\` |
| State | `~/.config/jaynshare.state.json` | — | — |
| CA | `~/.config/jaynshare-ca.pem` | `~/.config/jaynshare/jaynshare-ca.pem` | same, under the profile |
| Audit log | `~/.local/state/jaynshare/audit.ndjson` | — | — |
| Launchers | — | `~/.local/bin/` | `<profile>/.local/bin/` |
| Service | `jaynshare.service` (user unit) | — | — |

## Contributing and security

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a
vulnerability, follow [SECURITY.md](SECURITY.md); please do not open a public
issue for it.

## License and attribution

MIT. Jaynshare is derived from TeamClaude (MIT, KarpelesLab); see
[LICENSE](LICENSE), [NOTICE.md](NOTICE.md) and [SOURCES.md](SOURCES.md).
