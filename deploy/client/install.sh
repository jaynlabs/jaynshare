#!/bin/sh
set -eu

usage() {
  printf '%s\n' 'usage: install.sh <client-id> <tailscale-host> <ca-file> [port]' >&2
  printf '%s\n' '       install.sh --upgrade' >&2
  exit 1
}
die() { printf '%s\n' "jaynshare install: $*" >&2; exit 1; }

umask 077
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

command -v node >/dev/null 2>&1 || die 'Node.js 26 or newer is required'
node_major=$(node -e 'process.stdout.write(process.versions.node.split(".")[0])' | tr -d '\r')
case "$node_major" in ''|*[!0-9]*) die 'could not read the Node.js version' ;; esac
[ "$node_major" -ge 26 ] || die 'Node.js 26 or newer is required'

# Node, not uname: it is what interprets the paths. JAYNSHARE_PLATFORM is for the tests.
platform=${JAYNSHARE_PLATFORM:-$(node -p 'process.platform' | tr -d '\r')}

case "$(uname -s 2>/dev/null || printf 'unknown')" in
  MINGW*|MSYS*|CYGWIN*)
    [ "$platform" = win32 ] || die "this shell runs on Windows but node reports \"$platform\";
install the Windows build of Node.js 26+ and rerun this from Git Bash" ;;
esac

if [ "$platform" = win32 ]; then
  command -v cygpath >/dev/null 2>&1 \
    || die 'cygpath was not found; open Git Bash (Git for Windows) and run: bash ./install.sh'
  command -v icacls.exe >/dev/null 2>&1 || command -v icacls >/dev/null 2>&1 \
    || die 'icacls.exe was not found; open Git Bash (Git for Windows) and run: bash ./install.sh'
  command -v claude >/dev/null 2>&1 \
    || die 'claude was not found in Git Bash; install Claude Code, reopen Git Bash, then rerun this'
  [ -r "$script_dir/windows-acl.sh" ] || die "missing $script_dir/windows-acl.sh"
  . "$script_dir/windows-acl.sh"
  # Where the client will look: Git Bash's HOME and XDG_CONFIG_HOME are not what native Node sees.
  home_dir=$(cygpath -u -- "$(node -p 'require("os").homedir()' | tr -d '\r')" | tr -d '\r')
  [ -n "$home_dir" ] && [ -d "$home_dir" ] || die 'could not resolve your Windows profile directory'
  config_dir="$home_dir/.config/jaynshare"
else
  home_dir=$HOME
  config_dir=${XDG_CONFIG_HOME:-"$home_dir/.config"}/jaynshare
fi
bin_dir="$home_dir/.local/bin"

native_path() {
  case "$platform" in
    win32) cygpath -w -- "$1" | tr -d '\r' ;;
    *) printf '%s' "$1" ;;
  esac
}

# ---------------------------------------------------------------- arguments --

mode=install
client_id=
proxy_host=
proxy_port=
source_ca=

if [ "${1:-}" = --upgrade ]; then
  [ "$#" -eq 1 ] || usage
  mode=upgrade
else
  [ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage
  client_id=$1
  proxy_host=$2
  source_ca=$3
  proxy_port=${4:-3456}
fi

validate_enrollment() {
  case "$client_id" in *[!a-z0-9_-]*|'') die 'client ID must use lowercase letters, numbers, _ or -' ;; esac
  case "$proxy_host" in *[!A-Za-z0-9.-]*|'') die 'the server host must be a DNS name or IPv4 address' ;; esac
  case "$proxy_port" in ''|*[!0-9]*) die 'the server port must be a number' ;; esac
  [ "$proxy_port" -ge 1 ] && [ "$proxy_port" -le 65535 ] || die 'the server port must be between 1 and 65535'
}

# ------------------------------------------------------- staging + rollback --

# A failure past this point leaves the previous client or none, never a half-written secret.
work_dir=$(mktemp -d "$home_dir/.jaynshare-install.XXXXXX") || die 'could not create a private staging directory'
chmod 700 "$work_dir" 2>/dev/null || true
stage="$work_dir/stage"
backup="$work_dir/backup"
mkdir -p "$stage" "$backup"

cleaned=false
committed=false
completed=false

backup_of() { printf '%s' "$backup/$1"; }

save_file() { # path label
  if [ -e "$1" ]; then cp -p "$1" "$(backup_of "$2")"
  else : > "$(backup_of "$2").absent"
  fi
}

restore_file() { # path label
  if [ -f "$(backup_of "$2")" ]; then
    cp -p "$(backup_of "$2")" "$1" 2>/dev/null || true
  elif [ -f "$(backup_of "$2").absent" ]; then
    rm -f -- "$1" 2>/dev/null || true
  fi
}

rollback() {
  restore_file "$config_dir/client.env" client.env
  restore_file "$config_dir/client.secret" client.secret
  restore_file "$config_dir/jaynshare-ca.pem" jaynshare-ca.pem
  restore_file "$bin_dir/jaynshare" bin-jaynshare
  restore_file "$bin_dir/jaynshare-claude" bin-jaynshare-claude
  restore_file "$home_dir/.claude/settings.json" claude-settings.json
  rmdir "$config_dir" 2>/dev/null || true
  printf '%s\n' 'jaynshare install: rolled back; the previous state was restored.' >&2
}

cleanup() {
  [ "$cleaned" = false ] || return 0
  cleaned=true
  if [ "$committed" = true ] && [ "$completed" = false ]; then rollback; fi
  rm -rf -- "$work_dir" 2>/dev/null || true
}

trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

# ---------------------------------------------------------------- staging ----

if [ "$mode" = upgrade ]; then
  [ -r "$config_dir/client.env" ] || die "missing $config_dir/client.env; run the full installer instead"
  [ -r "$config_dir/client.secret" ] || die "missing $config_dir/client.secret; run the full installer instead"
  [ -r "$config_dir/jaynshare-ca.pem" ] || die "missing $config_dir/jaynshare-ca.pem; run the full installer instead"
  cp "$config_dir/client.env" "$stage/client.env"
  cp "$config_dir/client.secret" "$stage/client.secret"
  cp "$config_dir/jaynshare-ca.pem" "$stage/jaynshare-ca.pem"
  # Never sourced.
  field() { sed -n "s/^$1='\\([^']*\\)'\$/\\1/p" "$stage/client.env" | tr -d '\r' | sed -n '1p'; }
  client_id=$(field JAYNSHARE_CLIENT_ID)
  proxy_host=$(field JAYNSHARE_HOST)
  proxy_port=$(field JAYNSHARE_PORT)
  validate_enrollment
else
  validate_enrollment
  [ -r "$source_ca" ] || die "cannot read the CA file: $source_ca"
  cp "$source_ca" "$stage/jaynshare-ca.pem"

  printf '%s' 'Client secret: ' >&2
  stty -echo 2>/dev/null || true
  IFS= read -r client_secret || client_secret=
  stty echo 2>/dev/null || true
  printf '\n' >&2
  client_secret=$(printf '%s' "$client_secret" | tr -d '\r\n')
  case "$client_secret" in
    '') die 'the client secret must not be empty' ;;
    *[!A-Za-z0-9._~+/=-]*) die 'the client secret contains unexpected characters; paste it exactly as delivered' ;;
  esac

  printf '%s\n' "$client_secret" > "$stage/client.secret"
  unset client_secret
  printf "JAYNSHARE_CLIENT_ID='%s'\nJAYNSHARE_HOST='%s'\nJAYNSHARE_PORT='%s'\n" \
    "$client_id" "$proxy_host" "$proxy_port" > "$stage/client.env"
fi

grep -q 'BEGIN CERTIFICATE' "$stage/jaynshare-ca.pem" \
  || die 'the CA file does not look like a PEM certificate'
[ -s "$stage/client.secret" ] || die 'the staged client secret is empty'
[ -s "$stage/client.env" ] || die 'the staged client enrollment is empty'

cp "$script_dir/jaynshare-claude" "$stage/jaynshare-claude"
cp "$script_dir/jaynshare-client.mjs" "$stage/jaynshare"
[ -s "$stage/jaynshare-claude" ] || die 'the launcher is missing from this bundle'
[ -s "$stage/jaynshare" ] || die 'the client helper is missing from this bundle'

# ----------------------------------------------------------------- commit ----

save_file "$config_dir/client.env" client.env
save_file "$config_dir/client.secret" client.secret
save_file "$config_dir/jaynshare-ca.pem" jaynshare-ca.pem
save_file "$bin_dir/jaynshare" bin-jaynshare
save_file "$bin_dir/jaynshare-claude" bin-jaynshare-claude
save_file "$home_dir/.claude/settings.json" claude-settings.json

mkdir -p "$config_dir" "$bin_dir"
chmod 700 "$config_dir" 2>/dev/null || true
committed=true

mv "$stage/jaynshare-claude" "$bin_dir/jaynshare-claude"
mv "$stage/jaynshare" "$bin_dir/jaynshare"
chmod 755 "$bin_dir/jaynshare-claude" "$bin_dir/jaynshare"

mv "$stage/client.env" "$config_dir/client.env"
mv "$stage/client.secret" "$config_dir/client.secret"
mv "$stage/jaynshare-ca.pem" "$config_dir/jaynshare-ca.pem"
chmod 600 "$config_dir/client.env" "$config_dir/client.secret" "$config_dir/jaynshare-ca.pem" 2>/dev/null || true

if [ "$platform" = win32 ]; then
  sid=$(jaynshare_win_sid) || die 'could not resolve your Windows account SID (whoami.exe /user)'
  acl_out=$(jaynshare_lock_dir "$sid" "$config_dir") \
    || die "icacls could not protect the Jaynshare directory: $acl_out"
  for name in client.env client.secret jaynshare-ca.pem; do
    acl_out=$(jaynshare_lock_file "$sid" "$config_dir/$name") \
      || die "icacls could not protect $name: $acl_out"
  done
  verify_out=$(jaynshare_verify_locked "$config_dir/client.secret") \
    || die "the client secret is not restricted to your account: $verify_out"
  unset sid acl_out verify_out
fi

# ------------------------------------------------- Claude + authenticated check --

client_native=$(native_path "$bin_dir/jaynshare")

if [ "$platform" = win32 ]; then
  node "$(native_path "$script_dir/configure-claude.mjs")" --platform win32 --client-path "$client_native"
else
  node "$script_dir/configure-claude.mjs"
fi

printf '%s\n' 'Checking the server and your individual credential...'
if ! node "$client_native" status --json > /dev/null 2> "$work_dir/status.err"; then
  printf '%s\n' "jaynshare install: $(cat "$work_dir/status.err")" >&2
  die 'the enrolled credential could not reach the server; nothing was kept'
fi

completed=true
cleanup

if [ "$mode" = upgrade ]; then
  printf '%s\n' 'Updated the Jaynshare desktop client; open a new Claude session.'
else
  printf '%s\n' "Installed $bin_dir/jaynshare-claude and $bin_dir/jaynshare"
  printf '%s\n' 'Open a new Claude session to see the yellow fleet status line.'
fi
