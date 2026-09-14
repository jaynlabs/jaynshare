#!/bin/sh
set -eu

die() { printf '%s\n' "jaynshare prepare-client: $*" >&2; exit 1; }
usage() {
  printf '%s\n' 'usage: prepare-client.sh <client-id> <display-name> <tailscale-host> [output-dir]' >&2
  exit 1
}

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage

client_id=$1
display_name=$2
proxy_host=$3
output_dir=${4:-"$PWD/onboarding"}

case "$client_id" in *[!a-z0-9_-]*|'') die 'client ID must use lowercase letters, numbers, _ or -' ;; esac
[ -n "$display_name" ] || die 'display name must not be empty'
case "$proxy_host" in *[!A-Za-z0-9.-]*|'') die 'Tailscale host must be a DNS name or IPv4 address' ;; esac

command -v node >/dev/null 2>&1 || die 'Node.js 26+ is required'
node_major=$(node -e 'process.stdout.write(process.versions.node.split(".")[0])')
[ "$node_major" -ge 26 ] || die 'Node.js 26+ is required'
command -v tar >/dev/null 2>&1 || die 'tar is required'

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
config_path=${JAYNSHARE_CONFIG:-"$HOME/.config/jaynshare.json"}
ca_path=${JAYNSHARE_CA_FILE:-"$HOME/.config/jaynshare-ca.pem"}

[ -r "$config_path" ] || die "cannot read server config: $config_path"
[ -r "$ca_path" ] || die "cannot read public CA: $ca_path (start Jaynshare once to create it)"
grep -q 'BEGIN CERTIFICATE' "$ca_path" || die "$ca_path does not look like a PEM certificate"

proxy_port=$(node -e '
  const fs = require("fs");
  const config = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const port = Number(config.proxy?.port || 3456);
  if (!Number.isInteger(port) || port < 1 || port > 65535) process.exit(2);
  process.stdout.write(String(port));
' "$config_path") || die 'server config has an invalid proxy.port'

umask 077
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
archive_path="$output_dir/jaynshare-$client_id.tar.gz"
secret_path="$output_dir/jaynshare-$client_id.secret"
[ ! -e "$archive_path" ] || die "refusing to overwrite $archive_path"
[ ! -e "$secret_path" ] || die "refusing to overwrite $secret_path"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/jaynshare-client.XXXXXX")
bundle_dir="$work_dir/jaynshare-$client_id"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$bundle_dir/client"
cp "$repo_dir/deploy/client/install.sh" "$bundle_dir/client/install.sh"
cp "$repo_dir/deploy/client/configure-claude.mjs" "$bundle_dir/client/configure-claude.mjs"
cp "$repo_dir/deploy/client/jaynshare-claude" "$bundle_dir/client/jaynshare-claude"
cp "$repo_dir/deploy/client/jaynshare-client.mjs" "$bundle_dir/client/jaynshare-client.mjs"
cp "$repo_dir/deploy/client/windows-acl.sh" "$bundle_dir/client/windows-acl.sh"
cp "$ca_path" "$bundle_dir/jaynshare-ca.pem"

sed \
  -e "s/__CLIENT_ID__/$client_id/g" \
  -e "s/__PROXY_HOST__/$proxy_host/g" \
  -e "s/__PROXY_PORT__/$proxy_port/g" \
  "$script_dir/client-install.template.sh" > "$bundle_dir/install.sh"
chmod 755 "$bundle_dir/install.sh" "$bundle_dir/client/install.sh" "$bundle_dir/client/jaynshare-claude" "$bundle_dir/client/jaynshare-client.mjs"
chmod 644 "$bundle_dir/client/windows-acl.sh" "$bundle_dir/client/configure-claude.mjs"
chmod 600 "$bundle_dir/jaynshare-ca.pem"

sed \
  -e "s/__CLIENT_ID__/$client_id/g" \
  -e "s/__PROXY_HOST__/$proxy_host/g" \
  "$script_dir/client-readme.template.txt" > "$bundle_dir/START-HERE.txt"

tar -C "$work_dir" -czf "$archive_path" "jaynshare-$client_id"
chmod 600 "$archive_path"

# Last, so a packaging failure leaves no client record.
if ! JAYNSHARE_CONFIG="$config_path" node "$repo_dir/src/index.ts" client add "$client_id" --name "$display_name" > "$secret_path"; then
  rm -f -- "$archive_path" "$secret_path"
  die 'could not register client (does that ID already exist?)'
fi
chmod 600 "$secret_path"

printf '%s\n' "Prepared tester $client_id:"
printf '  bundle: %s\n' "$archive_path"
printf '  secret: %s\n' "$secret_path"
printf '%s\n' 'Send these through separate private channels. The bundle contains no client secret.'
printf '%s\n' 'Delete the transferred secret copy after the tester confirms `jaynshare status` works.'
