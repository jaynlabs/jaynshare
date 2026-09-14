# Windows client internals

How and why the desktop client works on native Windows. Installation and daily
use are in the [onboarding guide](../README.md#4-windows-1011-desktop);
this is the reference for anyone changing `deploy/client/`.

The supported environment is Git for Windows Bash on Windows 10/11, x64 or
ARM64, against the native Windows builds of Node 20+ and Claude Code. WSL,
containers, PowerShell and CMD are out of scope. Nothing needs Administrator
rights.

## Profile resolution

Enrolment lives under the Windows profile at `%USERPROFILE%\.config\jaynshare`,
not at an `XDG_CONFIG_HOME` location: Git Bash exports MSYS spellings such as
`/c/Users/name/.config`, which native Windows Node cannot open.

The installer and the launcher both ask Node for that profile rather than
trusting `$HOME`: with a roaming profile or a `HOMEDRIVE` override, Git Bash
exports a `HOME` that is not the directory `os.homedir()` reports, and the
client reads enrolment from `os.homedir()`. Resolving it the same way in both
places is what keeps an install from writing where the client will never look.
That is also why the installer prints the full path of what it installed and
the shipped instructions say to use that path verbatim.

Paths written into Claude's settings and into `NODE_EXTRA_CA_CERTS` are
converted with `cygpath -w` for the same reason.

## Platform detection

`uname` reports the Git Bash compatibility layer (`MINGW64_NT`), not how the
Node that will read the files interprets paths, so the platform decision comes
from `node -p process.platform`. If the shell is MSYS but Node says `linux`, a
WSL Node is first on PATH and the installer refuses.

`JAYNSHARE_PLATFORM` overrides that for the test harness and for installer
diagnostics only. It selects path and terminal conventions; it changes nothing
about credential handling.

## The MSYS → native boundary

Two things Git Bash does on the way into a native program bit the first
Windows run and are now handled explicitly (`deploy/client/windows-acl.sh`):

1. **Argument rewriting.** Git Bash rewrites POSIX-looking arguments before
   handing them to a native executable, so `/inheritance:r` reached `icacls`
   as `C:/Program Files/Git/inheritance:r`. The ACL helpers run with
   `MSYS_NO_PATHCONV=1` and `MSYS2_ARG_CONV_EXCL='*'`.
2. **Coreutils impostors.** MSYS ships GNU coreutils as `.exe` in `/usr/bin`,
   ahead of `C:\Windows\System32` on PATH, so `whoami.exe /user` was asking GNU
   `whoami` for a SID. Windows tools are resolved from `%SYSTEMROOT%\System32`
   by absolute path, never by PATH lookup.

The stub harness reproduces both: the stubs reject unconverted switches, and
the test PATH is ordered the way Git Bash orders it, with a coreutils impostor
ahead of a stand-in `System32`.

## NTFS access rules

`chmod 600` is not a security boundary on NTFS, so the installer additionally
locks the enrolment directory and all three files with `icacls.exe`:
inheritance is removed and full control is granted to the installing user's
SID and to SYSTEM only. Grants are made by SID because account names are
localized. The installer then reads back the access list — never the secret
itself — and fails the install if anything but those two principals can reach
it.

The lock `/reset`s the path before `/inheritance:r`. The installer stages the
secret and renames it into place; NTFS preserves the staged file's ACEs across
the rename but re-evaluates them against the new parent, converting an
inherited ACE the new parent does not advertise into an *explicit* one, which
`/inheritance:r` then leaves behind. The interactive VM pass found this on the
second install into the same profile; the reset closes the failure mode rather
than avoiding it, and the read-back verification is what would catch a
regression.

## Terminal and picker

Which picker a Windows user gets follows the Git for Windows build, not the
terminal they open. mintty used to hand Node an MSYS pipe with no `setRawMode`,
so the numbered picker was the normal Windows path. Since mintty began wrapping
a ConPTY — 2.55 does — even the Git Bash shortcut gives Node a real console and
the arrow-key picker is used. `pickerMode()` in `jaynshare-client.mjs` asks
exactly `typeof process.stdin.setRawMode === 'function'`. `JAYNSHARE_PICKER=line`
or `=raw` forces either.

The picker is drawn with a raw byte write to a descriptor, which is what makes
cursor and screen restoration reach the terminal synchronously on error and
signal exits. That path skips the UTF-8 → UTF-16 conversion libuv does for a
stream it knows is a TTY, so a Windows console decoded the bytes with its OEM
codepage (437) and an up arrow arrived as `Γåæ`. The terminal adapter now
declares what its descriptor can carry and the Windows one asks for ASCII; the
launcher does not reconfigure a console it does not own. Only the picker was
ever affected — status and dashboard go through `process.stdout`.

## Entry points and the missing `.cmd` shim

Claude Code's status line and hooks run the client as `node "<native path>"`.
That single spelling is parsed identically by Git Bash and by cmd.exe, so it
does not matter which one Claude uses.

A `.cmd` companion for `jaynshare-claude` is deliberately not shipped: Git for
Windows provides `/usr/bin/env`, so the extensionless `#!/usr/bin/env node` and
`#!/bin/sh` entry points execute directly from Git Bash, and the
`windows-client` CI job proves it on every push. If that ever stops holding,
add the shim then rather than carrying it unused.

`.gitattributes` keeps the shipped shell and JavaScript as LF so a CRLF
checkout cannot break the `#!/bin/sh` lines.

## Explorer extraction

Explorer discards an archive's Unix modes entirely. What `ls -l` then reports
is not what Explorer preserved: Git Bash mounts these drives `noacl` (confirm
with `mount`), and on a `noacl` mount it synthesizes the executable bit from
the file's first bytes, so everything starting `#!` reads as executable and
`windows-acl.sh`, which is sourced and starts with a comment, does not. That
is why every instruction says `bash ./install.sh` and the bundle's wrapper
invokes the inner installer through `sh`: the instruction is independent of
whether the bit survived.

## Installed files are copies

The installed launcher and client are copies taken at install time. Pulling a
fix into a checkout does not change what runs; re-run the installer (or
`--upgrade`) and confirm the new copy landed. `--upgrade` reuses the recorded
host and port, so a fake server on a fresh ephemeral port needs a full
re-install rather than an upgrade.

## Testing

`npm test` covers the Windows code paths on any platform by driving the shipped
scripts with `JAYNSHARE_PLATFORM=win32` and stub `cygpath`, `icacls`, and
`whoami.exe` executables (`test/windows-client.test.js`).

`test-support/client-install-check.sh` is the end-to-end check: it installs
into a throwaway profile, exercises the launcher and both picker modes through
pipes, and asserts the access rules. On macOS it runs with the stubs; the
`windows-client` CI job runs it on `windows-latest` under `shell: bash` against
the real tools on Node 20, 22 and 24. It is the only suite that runs on native
Windows: the Node suite spawns `/bin/sh` in many places and asserts POSIX mode
bits.

What CI cannot prove — an interactive terminal, Explorer, a real profile, and
ARM64 — is covered once per candidate by
[windows-vm-smoke-test.md](windows-vm-smoke-test.md). A defect found there is
reproduced in one of the two automated layers before the branch merges, so a
tester's machine is never the first place it is seen.

The last recorded pass, from PR #7 (2026-09-12):

```text
Windows build:        10.0.26200.9445 (Windows 11 ARM64, Parallels guest)
Git for Windows:      2.55.0.windows.5
Node:                 v24.21.0 arm64
Terminal host:        mintty wrapping a ConPTY — arrow-key picker
Candidate commit:     2bf269d
Result:               pass, all five sections
```

The yellow `◆ JAYNSHARE` status line inside Claude Code was not part of that
pass because Claude Code was not installed in the VM; it is verified by test
only.
