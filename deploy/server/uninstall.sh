#!/bin/sh
set -eu

[ "$(id -un)" = jaynshare ] || { printf '%s\n' 'run as the jaynshare user' >&2; exit 1; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
node "$repo_dir/src/index.ts" service uninstall

if [ "${1:-}" = --purge-state ]; then
  state_dir="$HOME/.local/state/jaynshare"
  config_file="$HOME/.config/jaynshare.json"
  [ "$state_dir" = /home/jaynshare/.local/state/jaynshare ] || { printf '%s\n' 'refusing unexpected state path' >&2; exit 1; }
  [ "$config_file" = /home/jaynshare/.config/jaynshare.json ] || { printf '%s\n' 'refusing unexpected config path' >&2; exit 1; }
  rm -rf -- "$state_dir"
  rm -f -- "$config_file" "$HOME/.config/jaynshare.state.json" "$HOME/.config/jaynshare-ca.pem" "$HOME/.config/jaynshare-leaf.pem" "$HOME/.config/jaynshare-leaf.key"
  printf '%s\n' 'Removed configuration, OAuth state, certificates and audit logs; this cannot be undone.'
else
  printf '%s\n' 'Preserved configuration, OAuth state, certificates and audit logs.'
fi
