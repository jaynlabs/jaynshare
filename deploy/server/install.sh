#!/bin/sh
set -eu

die() { printf '%s\n' "jaynshare install: $*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die 'the server package supports Linux only'
[ "$(id -un)" = jaynshare ] || die 'run this script as the dedicated jaynshare user'
command -v node >/dev/null 2>&1 || die 'Node.js 26+ must already be installed'
node_major=$(node -e 'process.stdout.write(process.versions.node.split(".")[0])')
[ "$node_major" -ge 26 ] || die 'Node.js 26+ is required'
command -v systemctl >/dev/null 2>&1 || die 'systemd is required'

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
config_path=${JAYNSHARE_CONFIG:-"$HOME/.config/jaynshare.json"}

[ -f "$config_path" ] || die "create $config_path from deploy/server/jaynshare.example.json first"
node -e '
  const fs = require("fs");
  const c = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const h = c.proxy && c.proxy.host;
  const match = /^100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h || "");
  if (!match || Number(match[1]) < 64 || Number(match[1]) > 127
      || Number(match[2]) > 255 || Number(match[3]) > 255) process.exit(2);
' "$config_path" || die 'proxy.host must be a concrete Tailscale IPv4 address'

mkdir -p "$HOME/.local/state/jaynshare"
chmod 700 "$HOME/.config" "$HOME/.local/state/jaynshare" 2>/dev/null || true
chmod 600 "$config_path"

JAYNSHARE_CONFIG=$config_path JAYNSHARE_DISABLE_AUTOUPDATE=1 \
  node "$repo_dir/src/index.ts" service install --config "$config_path"

printf '%s\n' 'Installed the pinned local checkout.'
printf '%s\n' 'An administrator must run: loginctl enable-linger jaynshare'
