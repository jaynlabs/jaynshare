# Windows VM smoke test

The third and last layer of Windows testing: a short interactive pass on a
disposable Windows 11 machine, run before any client bundle is issued. The first
two layers are the platform-independent suite and the `windows-latest` install
check, both in CI. This layer exists because CI cannot prove what only a desktop
session has — an interactive terminal, Explorer, a real user profile, and ARM64.

Nothing here needs a real client secret, an Anthropic account, Tailscale, or a
production server. The only secret involved is the synthetic string below, which
authenticates against a fake server running on loopback inside the VM.

## What this layer adds over CI

The `windows-client` job on `windows-latest` already runs the whole end-to-end
check on a real Windows kernel under Git for Windows Bash. It cannot cover:

- **the picker, interactively** — CI's bash is not a terminal, so both picker
  modes are only driven through pipes;
- **ARM64** — GitHub's Windows runners are x64 only, and the client claims
  support for both;
- **Explorer** — CI runs from a checkout, never from the shipped zip opened the
  way a recipient opens it;
- **a real profile** — PATH after reopening the shell, Claude's status line, and
  an unprivileged account with UAC enabled.

## Choosing a VM

Any disposable Windows 11 machine works. On an Apple Silicon Mac the guest is
Windows 11 ARM64, which is also the only way this project covers that
architecture at all:

| Host | Notes |
| --- | --- |
| Parallels Desktop trial | Fetches and installs Windows 11 ARM64 itself; least setup for a one-off pass. Its shared folders put the Mac checkout at `//Mac/Home` inside the guest, and `prlctl exec` runs the non-interactive steps from the Mac. |
| VMware Fusion | Free for personal use; check Broadcom's current terms for commercial use. |
| UTM (`brew install --cask utm`) | Free and permanent, but drivers, networking, and the ISO are yours to wire up. |
| Hourly cloud Windows | No large download and genuinely disposable, but x64 only, so it does not cover ARM64. |

Snapshot the VM once it is set up, so a failed run can be repeated from a clean
state rather than from a half-installed one.

## Prepare the guest

1. Install **Git for Windows**, which provides Git Bash. Which picker you get
   follows what Node is handed, and that is a property of the Git for Windows
   build rather than of the terminal you start:
   - mintty used to hand Node an MSYS pipe with no raw mode, so the **numbered
     picker was the normal Windows path**, not a fallback;
   - since mintty began wrapping a ConPTY — 2.55 does — even the Git Bash
     shortcut gives Node a real console, and the arrow-key picker is used.

   So do not predict the mode from the terminal. Run the probe below in the
   shell you will actually use, take the answer it gives, then cover the other
   mode with `JAYNSHARE_PICKER` rather than by hunting for a second terminal.
2. Install the **native Windows build of Node 20 or newer** — the one Claude Code
   itself runs on. Do not install Node inside WSL.
3. Copy the repository into the guest, or clone it. Everything below runs from
   the `jaynshare/` directory in **Git Bash**, never PowerShell, CMD, or WSL, and
   never as Administrator.

Record the environment before starting:

```sh
cmd //c ver                       # Windows build
git --version                     # Git for Windows version
node -p 'process.version + " " + process.arch'
git rev-parse HEAD                # candidate commit

# The terminal host, in the only terms that matter here:
node -p "typeof process.stdin.setRawMode === 'function' ? 'arrow-key picker' : 'numbered picker'"
```

That last line asks exactly what the client asks (`pickerMode()` in
`deploy/client/jaynshare-client.mjs`). Run it from the shell you will use for the
checklist, not through a pipe, or it will answer for the pipe.

## 1. The automated check, on real Windows

```sh
bash test-support/client-install-check.sh
```

This installs into a throwaway profile under `TMPDIR`, never the real one, and
exercises real `icacls.exe` access rules, native paths, the launcher, and the
picker through pipes. It must end with `All desktop client checks passed.`

Run it a second time from a directory whose path contains a space (copy the
repository to `~/Jayn share/` and run it from there) to cover quoting.

## 2. Interactive install into the real profile

The remaining checks need an enrollment in the actual Windows profile.

Give the launcher something to start **first**: the installer refuses with
`claude was not found in Git Bash` if it cannot see one, so the stand-in has to
be on PATH before the install, not after it. It prints the proxy with the
password masked, so even a synthetic credential is not left in scrollback:

```sh
mkdir -p ~/.local/bin
cat > ~/.local/bin/claude <<'STUB'
#!/bin/sh
printf 'claude: proxy=%s\n' "$(printf '%s' "${HTTPS_PROXY:-none}" | sed 's/:[^:@]*@/:***@/')"
printf 'claude: args=%s\n' "$*"
STUB
chmod +x ~/.local/bin/claude
export PATH="$HOME/.local/bin:$PATH"
```

Now start the fake server and install by hand, so the secret prompt itself is
exercised:

```sh
secret=jaynshare-client-SYNTHETIC0000000000000000000000

node test-support/fake-usage-server.mjs --port-file port.txt --secret "$secret" &
port=$(cat port.txt)

printf -- '-----BEGIN CERTIFICATE-----\nsynthetic-public-ca\n-----END CERTIFICATE-----\n' > ca.pem
bash deploy/client/install.sh vm-smoke 127.0.0.1 "$PWD/ca.pem" "$port"
```

Paste the synthetic secret at the prompt. Confirm:

- [ ] nothing is echoed while typing it;
- [ ] the install ends by reporting a successful `jaynshare status`;
- [ ] it never asked for Administrator rights.

The installed launcher and client are **copies taken at install time**, so
pulling a fix into the checkout does not change what runs. Re-run the installer
after every change, and confirm the new copy landed rather than assuming it —
the fake server binds an ephemeral port, so a restart needs a fresh install
rather than `--upgrade`, which reuses the port already recorded.

## 3. Interactive checklist

Close Git Bash and open a new window before starting, which also covers the
first item. Copy any output you still need before running the arrow-key picker:
it clears the screen, and on a terminal that puts that clear on the primary
buffer everything above it scrolls away.

- [ ] `~/.local/bin/jaynshare status` runs from a freshly opened shell. The
      installer prints that path and the shipped instructions use it verbatim;
      nothing here assumes `~/.local/bin` is on PATH, because the installer
      never edits it.

Once that item passes, shorten the rest by putting the directory on PATH for this
shell only. If Git Bash's `$HOME` is not the Windows profile — a roaming profile
or a `HOMEDRIVE` override — use the directory the installer printed instead:

```sh
PATH="$HOME/.local/bin:$PATH"
```

- [ ] `jaynshare-claude` presents the picker the probe predicted, and every
      character of it is legible. The picker is drawn with a raw byte write, so
      the console decodes it with its OEM codepage (`cmd //c chcp`, usually 437)
      rather than as UTF-8: anything outside ASCII arrives as mojibake, an up
      arrow reaching the user as `Γåæ`;
- [ ] selecting an account starts the stand-in Claude with a proxy URL for that
      account, its password masked, and the account encoded in the preference —
      `JAYNSHARE-PREF-v1-` followed by base64 of the row that was selected;
- [ ] cancelling refuses to launch rather than choosing for you — `Escape` in the
      arrow-key picker, `q` in the numbered one;
- [ ] `Ctrl-C` at the picker leaves the terminal usable: the cursor is back, and
      typed characters echo normally;
- [ ] `JAYNSHARE_PICKER=line jaynshare-claude` forces the numbered picker, and
      `JAYNSHARE_PICKER=raw` the arrow-key one, whichever the probe reported —
      this is how both modes get covered from one shell;
- [ ] `jaynshare-claude --auto -- --version` passes `--version` through unchanged;
- [ ] `jaynshare-claude --direct -- --version` reports `proxy=none`;
- [ ] stopping the fake server makes `jaynshare-claude --auto` refuse to launch
      Claude at all, rather than falling back to the local account;
- [ ] Claude Code shows the yellow `◆ JAYNSHARE` status line, if Claude Code is
      installed in the VM.

## 4. Explorer extraction

On the Mac, zip the client directory and copy it into the guest. Build the zip
from the commit under test rather than reusing an earlier one, or this section
certifies code that is not being shipped. Extract it with **Explorer**, not with
`unzip` from Git Bash, because that is how a tester will really open it:

- [ ] `bash ./install.sh …` works from the extracted folder.

Explorer discards the archive's Unix modes entirely. What `ls -l` then reports
is not what Explorer preserved: Git Bash mounts these drives `noacl` (confirm
with `mount`), and on a `noacl` mount it synthesizes the executable bit from the
file's first bytes, so everything starting `#!` reads as executable and
`windows-acl.sh`, which is sourced and starts with a comment, does not. Do not
expect a missing `x` bit here, and do not read the presence of one as proof that
running the installer directly is supported — on an `acl` mount nothing would
grant it. Invoking through `bash` is what makes the instruction independent of
any of that.

## 5. Uninstall

Run the documented cleanup from [the onboarding guide](../README.md#47-uninstall),
then prove nothing survived:

```sh
profile=$(cygpath -u -- "$(node -p 'require("os").homedir()')")
grep -ril SYNTHETIC "$profile/.config" "$profile/.claude" "$profile/.local/bin" 2>/dev/null
```

- [ ] the cleanup removes the enrollment and both launchers;
- [ ] Claude Code itself is untouched, and the saved settings are restored;
- [ ] the `grep` prints nothing.

## Recording the result

Put this in the pull request, as the plan requires:

```
Windows build:        (cmd //c ver)
Git for Windows:      (git --version)
Node:                 (version and arch)
Terminal host:        (terminal, and which picker it gave)
Candidate commit:     (git rev-parse HEAD)
Result:               pass | fail, with the failing checklist items
```

A failure here is reproduced and covered by a test in
`test/windows-client.test.js` or `test-support/client-install-check.sh` before
the branch merges. The VM exists so that a tester's machine is never the first
place a defect is found.
