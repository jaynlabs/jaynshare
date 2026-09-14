#!/usr/bin/env bash
#
# End-to-end check of the desktop client install, launcher, and picker.
#
# On Windows this runs under Git for Windows Bash against native Windows Node,
# which is the environment the client actually ships into, and additionally
# asserts the NTFS access rules. On macOS and Linux the same script runs with
# JAYNSHARE_PLATFORM=win32 and stub cygpath/icacls/whoami.exe executables, so the
# Windows code paths stay exercised on every push rather than only on Windows.
#
# `set -e` is deliberately not used: every assertion is reported and the run ends
# with a count, rather than stopping at the first failure.
#
# No real client secret, server, or Anthropic account is involved.

set -u

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
real_platform=$(node -p 'process.platform' | tr -d '\r')

# Native Windows Node cannot open the MSYS spellings Git Bash uses, so every path
# handed to node — or exported for os.homedir() — is converted first. Off Windows
# this is the identity, and the stub cygpath is never consulted for it.
native() {
  if [ "$real_platform" = win32 ]; then cygpath -w -- "$1" | tr -d '\r'; else printf '%s' "$1"; fi
}
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/jaynshare-windows-check.XXXXXX") || exit 1
synthetic_secret='jaynshare-client-SYNTHETIC0000000000000000000000'

failures=0
server_pid=

cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null
    # Reaping here keeps the shell from printing its own job notice after the
    # final result line.
    wait "$server_pid" 2>/dev/null
  fi
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; failures=$((failures + 1)); }
check() { if [ "$1" = 0 ]; then pass "$2"; else fail "$2"; fi; }
section() { printf '\n== %s\n' "$1"; }
contains() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; }
abort() { printf 'jaynshare check: %s\n' "$1" >&2; exit 1; }

wait_for_file() {
  _n=0
  while [ "$_n" -lt 60 ]; do
    [ -s "$1" ] && return 0
    _n=$((_n + 1))
    sleep 0.25
  done
  return 1
}

# ------------------------------------------------------------- environment --

home="$fixture_root/home"
stub_bin="$fixture_root/stubs"
mkdir -p "$home" "$stub_bin" || abort 'could not create the fixture'

# The installer learns the profile from os.homedir(), which answers with a native
# path it converts back with cygpath. Making the same round trip here leaves both
# halves spelling the profile identically, so paths recorded by one can be
# compared as text against the other.
if [ "$real_platform" = win32 ]; then
  canonical_home=$(cygpath -u -- "$(cygpath -w -- "$home" | tr -d '\r')" | tr -d '\r')
  if [ -n "$canonical_home" ] && [ -d "$canonical_home" ]; then home="$canonical_home"; fi

  # A real Windows profile hands its children an inheritable Administrators
  # entry. TMPDIR on a CI runner does not always carry one, and without it the
  # staged secret and an already-locked config directory advertise the same
  # entries, so nothing is converted when the installer renames the secret into
  # place. Granting it here makes the fixture model the profile the client is
  # actually installed into, which is where that conversion bites.
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
    icacls.exe "$(cygpath -w -- "$home" | tr -d '\r')" \
    /grant "*S-1-5-32-544:(OI)(CI)F" > /dev/null 2>&1 \
    || abort 'could not give the fixture profile an inheritable Administrators entry'
fi

# This stands in for Claude Code: it records its arguments and an explicit
# allow-list of environment variables, never the whole environment, so the
# launcher can be asserted against without any artifact carrying a credential it
# was not meant to see.
claude_log="$fixture_root/claude-invocation.txt"
cat > "$stub_bin/claude" <<'STUB'
#!/bin/sh
: > "$JAYNSHARE_CHECK_CLAUDE_LOG"
for arg in "$@"; do printf 'arg=%s\n' "$arg" >> "$JAYNSHARE_CHECK_CLAUDE_LOG"; done
for name in HTTPS_PROXY HTTP_PROXY NO_PROXY NODE_EXTRA_CA_CERTS ANTHROPIC_BASE_URL ANTHROPIC_API_KEY; do
  eval "value=\${$name:-}"
  printf 'env %s=%s\n' "$name" "$value" >> "$JAYNSHARE_CHECK_CLAUDE_LOG"
done
STUB
chmod 755 "$stub_bin/claude"

cygpath_log="$fixture_root/cygpath.log"
icacls_log="$fixture_root/icacls.log"
: > "$cygpath_log"
: > "$icacls_log"

stub_path="$stub_bin"

if [ "$real_platform" != win32 ]; then
  # cygpath, icacls and the Windows whoami exist only on Windows. The stubs keep
  # the interface the client depends on: cygpath records what was converted and
  # returns a path this host can still open, and icacls reports a two-principal
  # access list. The Windows tools live in a stand-in System32, and PATH is
  # ordered the way Git Bash orders it, with its own coreutils first, so a
  # Windows tool reached for by name is shadowed here exactly as it is there.
  stub_system32="$fixture_root/windows/System32"
  mkdir -p "$stub_system32" || abort 'could not create the fixture'
  stub_path="$stub_bin:$stub_system32"
  export SYSTEMROOT="$fixture_root/windows"
  unset WINDIR
  cat > "$stub_bin/cygpath" <<'STUB'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in -w|-u|--) shift ;; *) break ;; esac
done
printf '%s\n' "$1" >> "$JAYNSHARE_CHECK_CYGPATH_LOG"
printf '%s\n' "$1"
STUB
  # Git Bash rewrites /switch arguments into paths unless conversion is turned
  # off, and icacls.exe and whoami.exe then reject them. These stubs fail the
  # same way, so losing that guard fails here too and not only on Windows.
  cat > "$stub_system32/icacls.exe" <<'STUB'
#!/bin/sh
[ "${MSYS_NO_PATHCONV:-}" = 1 ] || { printf 'ERROR: Invalid argument/option - %s\n' "$1" >&2; exit 1; }
printf '%s\n' "$*" >> "$JAYNSHARE_CHECK_ICACLS_LOG"
case "$*" in
  *grant:r*)
    printf 'processed file: %s\nSuccessfully processed 1 files.\n' "$1"
    exit 0 ;;
esac
printf '%s NT AUTHORITY\\SYSTEM:(F)\n' "$1"
printf '                     MACHINE\\tester:(F)\n'
printf 'Successfully processed 1 files; Failed processing 0 files\n'
STUB
  cat > "$stub_system32/whoami.exe" <<'STUB'
#!/bin/sh
[ "${MSYS_NO_PATHCONV:-}" = 1 ] || { printf 'ERROR: Invalid argument/option - %s\n' "$1" >&2; exit 1; }
printf '"machine\\tester","S-1-5-21-1111111111-2222222222-3333333333-1001"\n'
STUB
  # The whoami.exe PATH finds first in Git Bash is GNU coreutils, which has
  # never heard of /user and cannot report a SID.
  cat > "$stub_bin/whoami.exe" <<'STUB'
#!/bin/sh
[ "$#" -eq 0 ] || { printf "whoami: extra operand '%s'\n" "$1" >&2; exit 1; }
printf 'machine\\tester\n'
STUB
  chmod 755 "$stub_bin/cygpath" "$stub_bin/whoami.exe" \
    "$stub_system32/icacls.exe" "$stub_system32/whoami.exe"
fi

export PATH="$stub_path:$PATH"
export HOME="$home"
# Native Windows Node resolves os.homedir() from USERPROFILE, which is where the
# installed client reads its enrollment from.
export USERPROFILE="$(native "$home")"
export JAYNSHARE_CHECK_CLAUDE_LOG="$claude_log"
export JAYNSHARE_CHECK_CYGPATH_LOG="$cygpath_log"
export JAYNSHARE_CHECK_ICACLS_LOG="$icacls_log"
# The client ignores XDG_CONFIG_HOME on Windows; unset it so a developer's own
# setting cannot move the fixture out from under these assertions.
unset XDG_CONFIG_HOME
export JAYNSHARE_PLATFORM=win32

config_dir="$home/.config/jaynshare"
bin_dir="$home/.local/bin"
# The client is always started through native Node, never the MSYS spelling.
client_native=$(native "$bin_dir/jaynshare")

ca_file="$fixture_root/jaynshare-ca.pem"
printf -- '-----BEGIN CERTIFICATE-----\nsynthetic-public-ca\n-----END CERTIFICATE-----\n' > "$ca_file"

printf 'Jaynshare desktop client check\n'
printf '  node      %s\n' "$(node --version)"
printf '  platform  %s (JAYNSHARE_PLATFORM=win32)\n' "$real_platform"
printf '  fixture   %s\n' "$fixture_root"

# -------------------------------------------------------------- fake server --

port_file="$fixture_root/port"
node "$(native "$repo_dir/test-support/fake-usage-server.mjs")" \
  --port-file "$port_file" --secret "$synthetic_secret" > /dev/null &
server_pid=$!
wait_for_file "$port_file" || abort 'the fake server never reported a port'
port=$(cat "$port_file")

# ------------------------------------------------------------ fresh install --

section 'fresh install'

printf '%s\n' "$synthetic_secret" \
  | bash "$repo_dir/deploy/client/install.sh" windows-check 127.0.0.1 "$ca_file" "$port" \
    > "$fixture_root/install.out" 2> "$fixture_root/install.err"
check $? 'install.sh completes without administrator rights'
[ "$failures" -eq 0 ] || sed 's/^/       /' "$fixture_root/install.err" >&2

[ -f "$config_dir/client.env" ] && [ -f "$config_dir/client.secret" ] && [ -f "$config_dir/jaynshare-ca.pem" ]
check $? 'enrollment lands under the Windows profile'

[ -f "$bin_dir/jaynshare" ] && [ -f "$bin_dir/jaynshare-claude" ]
check $? 'launcher and client helper land in ~/.local/bin'

grep -q "JAYNSHARE_CLIENT_ID='windows-check'" "$config_dir/client.env" 2>/dev/null
check $? 'client.env records the enrolled client ID'

[ "$(sed -n 1p "$config_dir/client.secret" 2>/dev/null)" = "$synthetic_secret" ]
check $? 'the secret is stored verbatim'

ls -d "$home"/.jaynshare-install.* > /dev/null 2>&1
[ $? -ne 0 ]
check $? 'no staging directory with plaintext material survives'

# ---------------------------------------------------------------- ACL rules --

section 'windows access rules'

if [ "$real_platform" = win32 ]; then
  acl=$(icacls.exe "$(cygpath -w -- "$config_dir/client.secret")" 2>&1)
  entries=$(printf '%s\n' "$acl" | awk '/:\(/ { n++ } END { print n + 0 }')
  [ "$entries" = 2 ]
  check $? "the secret grants access to exactly two principals (found $entries)"
  printf '%s\n' "$acl" | grep -qi 'S-1-1-0\|Everyone'
  [ $? -ne 0 ]
  check $? 'the secret has no Everyone entry'
else
  grep -q 'inheritance:r' "$icacls_log"
  check $? 'inherited permissions are removed'
  [ "$(grep -c '/reset' "$icacls_log")" -ge 4 ]
  check $? 'every locked path is reset before access is granted'
  [ "$(command -v whoami.exe)" = "$stub_bin/whoami.exe" ]
  check $? 'the MSYS whoami.exe shadows the Windows one on PATH, as in Git Bash'
  grep -q 'grant:r \*S-1-5-21-1111111111-2222222222-3333333333-1001:' "$icacls_log"
  check $? 'access is granted by SID rather than by localized account name'
  grep -q 'grant:r .*\*S-1-5-18:' "$icacls_log"
  check $? 'SYSTEM retains access'
  [ "$(grep -c 'grant:r' "$icacls_log")" -ge 4 ]
  check $? 'the directory and all three enrollment files are locked'
  grep -q 'client.secret' "$cygpath_log"
  check $? 'paths handed to icacls are converted with cygpath'
fi

grep -q "$synthetic_secret" "$icacls_log"
[ $? -ne 0 ]
check $? 'no icacls command line contains the secret'

# ------------------------------------------------------------ native paths --

section 'native paths and Claude settings'

settings="$home/.claude/settings.json"
[ -f "$settings" ]
check $? 'Claude settings were written'

status_command=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).statusLine.command)' "$(native "$settings")" 2>/dev/null)
case "$status_command" in
  'node "'*'jaynshare" status --line') true ;;
  *) false ;;
esac
check $? 'the status line runs the client through node by absolute path'

if [ "$real_platform" = win32 ]; then
  # Inside single quotes the backslash is literal, so this is C:\ exactly.
  case "$status_command" in 'node "'[A-Za-z]':\'*) true ;; *) false ;; esac
  check $? "the status line path is a native Windows path ($status_command)"
else
  grep -q "$bin_dir/jaynshare" "$cygpath_log"
  check $? 'the installed client path is converted with cygpath'
fi

grep -q "$synthetic_secret" "$settings"
[ $? -ne 0 ]
check $? 'settings.json contains no secret'

grep -qi 'proxy\|://' "$settings"
[ $? -ne 0 ]
check $? 'settings.json contains no proxy URL'

# --------------------------------------------------------------- status CLI --

section 'authenticated status'

node "$client_native" status > "$fixture_root/status.txt" 2>&1
check $? 'jaynshare status authenticates against the server'
contains 'JAYNSHARE' "$(cat "$fixture_root/status.txt")"
check $? 'status renders the fleet table'

node "$client_native" status --json > "$fixture_root/status.json" 2>"$fixture_root/status-json.err"
check $? 'jaynshare status --json succeeds'
node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' "$(native "$fixture_root/status.json")" 2>/dev/null
check $? 'status --json emits valid JSON'

# START-HERE.txt tells testers to run the installed command itself, so the
# extensionless shebang has to work from the shell, not only through node.
"$bin_dir/jaynshare" status > /dev/null 2>&1
check $? 'the installed client runs directly through its shebang'

# ------------------------------------------------------------ line picker --

section 'line-mode picker'

selection=$(printf '2\n' | JAYNSHARE_PICKER=line node "$client_native" pick-account 2>"$fixture_root/picker.err")
contains 'JAYNSHARE-PREF-v1-' "$selection"
check $? 'a numbered choice returns an encoded account preference'
contains ' 1)' "$(cat "$fixture_root/picker.err")"
check $? 'the numbered list renders on stderr, leaving stdout for the selection'

printf 'q\n' | JAYNSHARE_PICKER=line node "$client_native" pick-account > "$fixture_root/cancel.out" 2>&1
[ $? -ne 0 ]
check $? 'cancelling fails rather than choosing for the user'

printf '' | JAYNSHARE_PICKER=line node "$client_native" pick-account > "$fixture_root/eof.out" 2>&1
[ $? -ne 0 ]
check $? 'closed input never silently picks an account'
contains 'explicit choice' "$(cat "$fixture_root/eof.out")"
check $? 'the closed-input message points at --account and --auto'

retried=$(printf '4\n1\n' | JAYNSHARE_PICKER=line node "$client_native" pick-account 2>"$fixture_root/disabled.err")
[ "$retried" = 'windows-check' ]
check $? 'an unavailable account is refused and the prompt is retried'
contains 'cannot be selected' "$(cat "$fixture_root/disabled.err")"
check $? 'the refusal names the unavailable account'

# ---------------------------------------------------------------- launcher --

section 'launcher'

"$bin_dir/jaynshare-claude" --auto -- --model opus 'two words'
check $? 'the launcher starts Claude in --auto mode'
log=$(cat "$claude_log")
contains 'arg=--model' "$log" && contains 'arg=opus' "$log" && contains 'arg=two words' "$log"
check $? 'arguments after -- reach Claude unchanged'
contains "http://windows-check:$synthetic_secret@127.0.0.1:$port" "$log"
check $? 'the authenticated proxy URL is built for this client'
contains 'env NO_PROXY=localhost,127.0.0.1,::1' "$log"
check $? 'loopback traffic bypasses the proxy'
ca_env=$(printf '%s\n' "$log" | sed -n 's/^env NODE_EXTRA_CA_CERTS=//p')
node -e 'require("fs").readFileSync(process.argv[1])' "$ca_env" 2>/dev/null
check $? "NODE_EXTRA_CA_CERTS is readable by native Node ($ca_env)"
if [ "$real_platform" = win32 ]; then
  case "$ca_env" in [A-Za-z]':\'*) true ;; *) false ;; esac
  check $? 'NODE_EXTRA_CA_CERTS is a native Windows path'
fi

"$bin_dir/jaynshare-claude" --account second@example.com -- --print
check $? 'the launcher starts Claude in --account mode'
contains 'http://JAYNSHARE-PREF-v1-' "$(cat "$claude_log")"
check $? '--account sends an encoded per-session preference'

"$bin_dir/jaynshare-claude" --direct -- --version
check $? 'the launcher starts Claude in --direct mode'
log=$(cat "$claude_log")
contains 'env HTTPS_PROXY=' "$log"
check $? '--direct still reaches the Claude executable'
contains 'env HTTPS_PROXY=http' "$log"
[ $? -ne 0 ]
check $? '--direct clears every Jaynshare proxy variable'
contains "$synthetic_secret" "$log"
[ $? -ne 0 ]
check $? '--direct leaks no credential'

"$bin_dir/jaynshare-claude" --auto --account x -- --version > "$fixture_root/conflict.out" 2>&1
[ $? -eq 2 ]
check $? 'conflicting selection flags are rejected'

section 'refuses to fall back when the server is down'

kill "$server_pid" 2>/dev/null
wait "$server_pid" 2>/dev/null
server_pid=

: > "$claude_log"
"$bin_dir/jaynshare-claude" --auto -- --version > "$fixture_root/unreachable.out" 2>&1
[ $? -ne 0 ]
check $? 'an unreachable proxy fails the launch'
[ ! -s "$claude_log" ]
check $? 'Claude is never started through an implicit fallback'
contains 'refusing direct fallback' "$(cat "$fixture_root/unreachable.out")"
check $? 'the refusal explains itself'

# ----------------------------------------------------------------- upgrade --

section 'upgrade'

port_file2="$fixture_root/port2"
node "$(native "$repo_dir/test-support/fake-usage-server.mjs")" \
  --port-file "$port_file2" --secret "$synthetic_secret" > /dev/null &
server_pid=$!
wait_for_file "$port_file2" || abort 'the second fake server never reported a port'
port2=$(cat "$port_file2")

# The enrollment pins the first port, so repoint it the way a restarted server
# would be reached. This is also the state the rollback assertions restore to.
node -e '
  const fs = require("fs");
  const [file, port] = process.argv.slice(1);
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace(/JAYNSHARE_PORT=.*/, `JAYNSHARE_PORT=\x27${port}\x27`));
' "$(native "$config_dir/client.env")" "$port2"

before_env=$(cat "$config_dir/client.env")
before_secret=$(cat "$config_dir/client.secret")

bash "$repo_dir/deploy/client/install.sh" --upgrade < /dev/null \
  > "$fixture_root/upgrade.out" 2> "$fixture_root/upgrade.err"
check $? 'install.sh --upgrade completes with no input available'

contains 'Client secret:' "$(cat "$fixture_root/upgrade.err")"
[ $? -ne 0 ]
check $? 'upgrade never prompts for a credential'
[ "$(cat "$config_dir/client.env")" = "$before_env" ]
check $? 'upgrade keeps the existing enrollment'
[ "$(cat "$config_dir/client.secret")" = "$before_secret" ]
check $? 'upgrade keeps the existing secret'
contains 'desktop client' "$(cat "$fixture_root/upgrade.out")"
check $? 'upgrade reports the desktop client, not a Mac-only one'

# The secret is renamed into a directory the previous install already locked.
# Windows turns an inherited entry the new parent does not advertise into an
# explicit one, which /inheritance:r cannot remove, so a second install used to
# leave Administrators on the secret. Only real NTFS reproduces the conversion.
if [ "$real_platform" = win32 ]; then
  acl=$(icacls.exe "$(cygpath -w -- "$config_dir/client.secret" | tr -d '\r')" 2>&1)
  entries=$(printf '%s\n' "$acl" | awk '/:\(/ { n++ } END { print n + 0 }')
  [ "$entries" = 2 ]
  check $? "the upgraded secret still grants access to exactly two principals (found $entries)"
fi

# ---------------------------------------------------------------- rollback --

section 'rollback'

printf '%s\n' 'not a valid secret!!' \
  | bash "$repo_dir/deploy/client/install.sh" windows-check 127.0.0.1 "$ca_file" "$port2" \
    > /dev/null 2>&1
[ $? -ne 0 ]
check $? 'a malformed secret fails the install'
[ "$(cat "$config_dir/client.secret")" = "$before_secret" ]
check $? 'a rejected secret never replaces the working enrollment'

# Port 9 (discard) is closed on these runners, so the authenticated check at the
# end of the install cannot pass and the whole install has to be undone.
printf '%s\n' "$synthetic_secret" \
  | bash "$repo_dir/deploy/client/install.sh" other-client 127.0.0.1 "$ca_file" 9 \
    > "$fixture_root/rollback.out" 2>&1
[ $? -ne 0 ]
check $? 'an install that cannot authenticate fails'
contains 'rolled back' "$(cat "$fixture_root/rollback.out")"
check $? 'the failed install reports the rollback'
[ "$(cat "$config_dir/client.env")" = "$before_env" ]
check $? 'the previously working enrollment is restored'
[ "$(cat "$config_dir/client.secret")" = "$before_secret" ]
check $? 'the previously working secret is restored'

node "$client_native" status > /dev/null 2>&1
check $? 'the restored client still authenticates'

# ------------------------------------------------------------ secret hygiene --

section 'secret hygiene'

grep -rq "$synthetic_secret" "$home/.claude" 2>/dev/null
[ $? -ne 0 ]
check $? 'no secret reaches Claude configuration'

grep -lq "$synthetic_secret" \
  "$fixture_root/install.out" "$fixture_root/install.err" \
  "$fixture_root/upgrade.out" "$fixture_root/upgrade.err" \
  "$fixture_root/rollback.out" "$fixture_root/status.txt" "$fixture_root/status.json" \
  "$fixture_root/picker.err" "$fixture_root/unreachable.out" 2>/dev/null
[ $? -ne 0 ]
check $? 'no secret reaches captured installer, status, or picker output'

grep -rq "$synthetic_secret" "$repo_dir/deploy" 2>/dev/null
[ $? -ne 0 ]
check $? 'no secret is written back into the shipped client files'

printf '\n'
if [ "$failures" -eq 0 ]; then
  printf 'All desktop client checks passed.\n'
else
  printf '%s check(s) failed.\n' "$failures" >&2
  exit 1
fi
