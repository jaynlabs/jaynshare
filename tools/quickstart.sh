#!/usr/bin/env bash
# A whole pool on one Mac: a server and an enrolled client, each under its own
# scratch home, so neither touches a real installation or your Claude Code
# settings. Claude Code runs in the client's home too, but reads your own login
# from the keychain (the pool drops it). Codex runs in your real home, with its
# own login and config (the pool drops that login too).
#
# In a checkout it builds that checkout into .quickstart/; with --release, or
# when the script was downloaded alone, it runs a published release in
# ~/.jaynshare-quickstart/ instead, on ports of its own.
#
# Usage: quickstart.sh [--release[=<version>]] [up]   build or download, (re)start the server, update the client
#        quickstart.sh [--release] claude [args]      run `jaynshare claude` as the client
#        quickstart.sh codex [args]                    run `jaynshare codex` as the client
#        quickstart.sh [--release] op <verb...>       an operator verb on the server
#        quickstart.sh [--release] client <verb...>
#        quickstart.sh [--release] logs | down
#
# The server home persists, so an account logged in once stays logged in.
# Removing the scratch home's client/ joins the client again; removing it all starts over.
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
ORIGIN=https://github.com/jaynlabs/jaynshare/releases
ARCH=$(uname -m | sed 's/arm64/aarch64/')

RELEASE=
case ${1:-} in
--release) RELEASE=latest; shift ;;
--release=*) RELEASE=${1#--release=}; RELEASE=${RELEASE#v}; shift ;;
esac
SELF=$0
[ -x "$0" ] || SELF="bash $0"
if [ ! -f "$HERE/make-client-kit.py" ]; then
    RELEASE=${RELEASE:-latest}
elif [ -n "$RELEASE" ]; then
    SELF="$SELF --release"
fi

if [ -n "$RELEASE" ]; then
    SCRATCH="$HOME/.jaynshare-quickstart"
    BIN="$SCRATCH/jaynshare"
    LISTEN=127.0.0.1:27423
    PROXY_LISTEN=127.0.0.1:27424
else
    SCRATCH="$REPO/.quickstart"
    BIN="$REPO/target/debug/jaynshare"
    LISTEN=127.0.0.1:27421
    PROXY_LISTEN=127.0.0.1:27422
fi
SERVER_HOME="$SCRATCH/server"
CLIENT_HOME="$SCRATCH/client"
KIT="$SCRATCH/client-kit.zip"
CLIENT_ID=quickstart

die() { echo "quickstart: $1" >&2; exit 2; }

require() { command -v "$1" >/dev/null || die "$1 is missing; $2"; }

config_root() { echo "$1/Library/Application Support/Jaynshare"; }

as_server() { HOME="$SERVER_HOME" "$BIN" "$@"; }

client_bin() { echo "$(config_root "$CLIENT_HOME")/bin/jaynshare"; }

as_client() { HOME="$CLIENT_HOME" "$(client_bin)" "$@"; }

# Claude Code calls `security` from PATH for its login; this one runs it with
# your real home, so it finds your keychain. Its first run is marked done, or
# Claude Code would ask for a login before looking.
prepare_claude() {
    mkdir -p "$SCRATCH/bin"
    printf '#!/bin/bash\nHOME=%q exec /usr/bin/security "$@"\n' "$HOME" >"$SCRATCH/bin/security"
    chmod +x "$SCRATCH/bin/security"
    python3 - "$CLIENT_HOME/.claude.json" <<'EOF'
import json, os, sys
path = sys.argv[1]
config = json.load(open(path)) if os.path.exists(path) else {}
if not config.get("hasCompletedOnboarding"):
    config["hasCompletedOnboarding"] = True
    json.dump(config, open(path, "w"), indent=2)
EOF
}

# The launcher finds `codex` on PATH; this one runs it with your real home.
prepare_codex() {
    local codex
    codex=$(command -v codex) || die "codex is missing; install Codex and log in to it first"
    mkdir -p "$SCRATCH/bin"
    printf '#!/bin/bash\nHOME=%q exec %q "$@"\n' "$HOME" "$codex" >"$SCRATCH/bin/codex"
    chmod +x "$SCRATCH/bin/codex"
}

result_field() { python3 -c 'import json, sys; print(json.load(sys.stdin)["result"][sys.argv[1]])' "$1"; }

server_pid() {
    local pid
    pid=$(cat "$SCRATCH/server.pid" 2>/dev/null) || return 1
    kill -0 "$pid" 2>/dev/null && echo "$pid"
}

stop_server() {
    local pid
    pid=$(server_pid) || return 0
    kill "$pid"
    while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done
    rm -f "$SCRATCH/server.pid"
}

start_server() {
    HOME="$SERVER_HOME" "$BIN" serve >>"$SCRATCH/server.log" 2>&1 &
    echo $! >"$SCRATCH/server.pid"
    for _ in $(seq 50); do
        server_pid >/dev/null || break
        as_server status --check >/dev/null 2>&1 && server_pid >/dev/null && return 0
        sleep 0.2
    done
    tail -n 20 "$SCRATCH/server.log" >&2
    die "the server did not start; see $SCRATCH/server.log"
}

prepare_homes() {
    local server_root
    server_root=$(config_root "$SERVER_HOME")
    mkdir -p "$server_root" "$(config_root "$CLIENT_HOME")"
    if [ ! -f "$server_root/config.toml" ]; then
        printf 'version = 1\n\n[data_plane]\nlisten = "%s"\ntls = "identity"\n\n[mitm]\nenabled = true\nlisten = "%s"\n' \
            "$LISTEN" "$PROXY_LISTEN" >"$server_root/config.toml"
    fi
    # A machine joins only over TLS; a scratch home from before turns it on.
    if ! grep -q '^tls' "$server_root/config.toml"; then
        awk '{ print } /^\[data_plane\]$/ { print "tls = \"identity\"" }' "$server_root/config.toml" >"$server_root/config.toml.new"
        mv "$server_root/config.toml.new" "$server_root/config.toml"
    fi
    # The client follows the kit the server offers: this script's own.
    grep -q '^kit_file' "$server_root/config.toml" ||
        printf '\n[clients]\nkit_file = "%s"\n' "$KIT" >>"$server_root/config.toml"
}

# A throwaway release key replaces the embedded one in both homes, so the
# local kit is signed and verified like a real one.
build_from_source() {
    require cargo "install Rust from https://rustup.rs"
    cd "$REPO"
    cargo build --quiet
    mkdir -p "$SCRATCH/key"
    if [ ! -f "$SCRATCH/key/seed" ]; then
        python3 tools/make-client-kit.py keygen --pub "$SCRATCH/key/release.pub" --seed "$SCRATCH/key/seed" >/dev/null
    fi
    cp "$SCRATCH/key/release.pub" "$(config_root "$SERVER_HOME")/release.pub"
    cp "$SCRATCH/key/release.pub" "$(config_root "$CLIENT_HOME")/release.pub"
    build_kit
}

build_kit() {
    local payload="$SCRATCH/kit"
    rm -rf "$payload"
    mkdir -p "$payload/payload/macos-aarch64" "$payload/payload/macos-x86_64" "$payload/payload/windows-x86_64"
    cp deploy/kit/* "$payload/"
    echo "not in a quickstart kit" >"$payload/payload/macos-aarch64/jaynshare"
    echo "not in a quickstart kit" >"$payload/payload/macos-x86_64/jaynshare"
    echo "not in a quickstart kit" >"$payload/payload/windows-x86_64/jaynshare.exe"
    cp "$BIN" "$payload/payload/macos-$ARCH/jaynshare"
    local version commit
    version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)-local"
    commit=$(git rev-parse HEAD)
    rm -f "$KIT"
    python3 tools/make-client-kit.py build --payload-dir "$payload" --key "$SCRATCH/key/seed" \
        --out "$KIT" --version "$version" --commit "$commit" >/dev/null
}

# The published binary is trusted as GitHub serves it over HTTPS; the client
# kit is checked at the join against the release key that binary embeds.
fetch_release() {
    local version=$RELEASE dir
    if [ "$version" = latest ]; then
        version=$(curl -fsSLo /dev/null -w '%{url_effective}' "$ORIGIN/latest")
        version=${version##*/v}
    fi
    dir="$SCRATCH/release/$version"
    if [ ! -f "$dir/client-kit.zip" ]; then
        echo "quickstart: downloading jaynshare $version" >&2
        rm -rf "$dir"
        mkdir -p "$dir"
        curl -fsSL "$ORIGIN/download/v$version/jaynshare-$version-$ARCH-apple-darwin.tar.gz" |
            tar -xz -C "$dir" --strip-components 1
        curl -fsSL -o "$dir/client-kit.partial" "$ORIGIN/download/v$version/jaynshare-$version-client-kit.zip"
        mv "$dir/client-kit.partial" "$dir/client-kit.zip"
    fi
    ln -sf "$dir/jaynshare" "$BIN"
    ln -sf "$dir/client-kit.zip" "$KIT"
}

ensure_account() {
    [ "$(as_server account list --json | result_field accounts)" != "[]" ] && return 0
    if [ -t 0 ]; then
        echo "quickstart: no account yet; logging one in (once, kept in $SERVER_HOME)" >&2
        as_server account login
    else
        echo "quickstart: no account yet; run: $SELF op account login" >&2
    fi
}

# The client joins with an invite, as an engineer's machine would.
join_client() {
    local verb invite
    if as_server client show "$CLIENT_ID" >/dev/null 2>&1; then
        verb=(client reissue "$CLIENT_ID")
    else
        verb=(client invite "$CLIENT_ID" --name "Quickstart client")
    fi
    invite=$(as_server "${verb[@]}" --json | result_field invite)
    HOME="$CLIENT_HOME" "$BIN" join "$invite" || die "the client join failed"
}

up() {
    require python3 "run xcode-select --install"
    require claude "install Claude Code and log in to it first"
    prepare_homes
    if [ -n "$RELEASE" ]; then fetch_release; else build_from_source; fi
    stop_server
    start_server
    if [ -f "$(config_root "$CLIENT_HOME")/client/client.toml" ]; then
        as_client update --from "$KIT" >/dev/null
    else
        join_client
    fi
    ensure_account
    echo "pool up on $LISTEN (proxy $PROXY_LISTEN); $SELF claude to use it"
}

[ "$(uname)" = Darwin ] || die "the quickstart is macOS-only"
case ${1:-up} in
up) up ;;
down) stop_server ;;
logs) tail -f "$SCRATCH/server.log" ;;
claude) shift; prepare_claude; HOME="$CLIENT_HOME" PATH="$SCRATCH/bin:$PATH" exec "$(client_bin)" claude "$@" ;;
codex) shift; prepare_codex; HOME="$CLIENT_HOME" PATH="$SCRATCH/bin:$PATH" exec "$(client_bin)" codex "$@" ;;
op) shift; as_server "$@" ;;
client) shift; as_client "$@" ;;
*) die "unknown command $1; see the usage at the top of $0" ;;
esac
