#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

command -v node >/dev/null 2>&1 || {
  printf '%s\n' 'Node.js 26+ is required. Install it, then run this file again.' >&2
  exit 1
}
node_major=$(node -e 'process.stdout.write(process.versions.node.split(".")[0])' | tr -d '\r')
[ "$node_major" -ge 26 ] || {
  printf '%s\n' 'Node.js 26+ is required. Upgrade it, then run this file again.' >&2
  exit 1
}
command -v claude >/dev/null 2>&1 || {
  printf '%s\n' 'Claude Code must already be installed and available as `claude`.' >&2
  exit 1
}

printf '%s\n' 'Installing Jaynshare for __CLIENT_ID__ via __PROXY_HOST__...'
# Through the shell: extracting with Explorer on Windows can drop the executable bit.
sh "$script_dir/client/install.sh" '__CLIENT_ID__' '__PROXY_HOST__' "$script_dir/jaynshare-ca.pem" '__PROXY_PORT__'

printf '\n%s\n' 'Enrollment succeeded. Your pooled account status:'
"$HOME/.local/bin/jaynshare" status

printf '\n%s\n' 'Start with: ~/.local/bin/jaynshare-claude'
printf '%s\n' 'Local-account rollback: ~/.local/bin/jaynshare-claude --direct'
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) printf '%s\n' 'Tip: add $HOME/.local/bin to PATH to use `jaynshare` and `jaynshare-claude` without the full path.' ;;
esac
