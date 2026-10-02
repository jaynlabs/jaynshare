#!/bin/sh
# Builds this clone and installs it as the native server; run it again after
# `git pull` to update. It builds as you and installs with sudo, with the
# official client kit of the build's version; a first install ends with an
# invite named after you (sudo passes SUDO_USER). Arguments go to
# `jaynshare server install`, e.g. --kit <zip> for a kit your fork's CI built,
# or --listen <ip>.
set -eu

die() { echo "install-server: $1" >&2; exit 2; }

[ "$(uname)" = Linux ] || die "the server runs only on Linux"
[ "$(id -u)" -ne 0 ] || die "run it as yourself: it builds as you and installs with sudo"
command -v cargo >/dev/null || die "cargo is missing; install Rust from https://rustup.rs"

cd "$(dirname "$0")/.."
cargo build --release --locked
exec sudo target/release/jaynshare server install --binary target/release/jaynshare "$@"
