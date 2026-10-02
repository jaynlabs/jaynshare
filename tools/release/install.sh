#!/bin/sh
set -eu

origin=https://github.com/jaynlabs/jaynshare/releases/download
origin_given=false
version=
tls_ca=
invite=

usage() {
    echo "usage: install.sh [--version <version>] [--release-origin <https-origin>] [--tls-ca <pem>] [join] [<invite>]" >&2
    exit 2
}

die() { echo "jaynshare install: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
    case $1 in
        --version) [ "$#" -ge 2 ] || usage; version=${2#v}; shift 2 ;;
        --release-origin) [ "$#" -ge 2 ] || usage; origin=${2%/}; origin_given=true; shift 2 ;;
        --tls-ca) [ "$#" -ge 2 ] || usage; tls_ca=$2; shift 2 ;;
        join) shift; [ "$#" -eq 1 ] || usage; invite=$1; shift ;;
        jsi1_*) [ -z "$invite" ] || usage; invite=$1; shift ;;
        *) usage ;;
    esac
done

case $origin in https://*) ;; *) die "--release-origin must be https://" ;; esac
case $origin in *\?*|*\#*) die "--release-origin must not contain a query or fragment" ;; esac
authority=${origin#https://}
authority=${authority%%/*}
case $authority in ''|*@*) die "--release-origin must have a plain host" ;; esac
[ -z "$tls_ca" ] || [ -r "$tls_ca" ] || die "cannot read the TLS CA: $tls_ca"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

fetch() {
    if [ -n "$tls_ca" ]; then
        curl --cacert "$tls_ca" -fsSL "$@"
    else
        curl -fsSL "$@"
    fi
}

if [ -z "$version" ]; then
    case $origin in
        */download) latest=${origin%/download}/latest ;;
        *) latest=$origin/latest ;;
    esac
    effective=$(fetch -o /dev/null -w '%{url_effective}' "$latest") || die "could not find the latest release"
    tag=${effective##*/}
    case $tag in v*) version=${tag#v} ;; *) die "the latest release URL names no version" ;; esac
fi
case $version in ''|*[!0-9A-Za-z.+-]*|.*|-*) die "invalid release version: $version" ;; esac

system=$(uname -s)
machine=$(uname -m)
case "$system:$machine" in
    Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-musl ;;
    Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-musl ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    Darwin:arm64|Darwin:aarch64) target=aarch64-apple-darwin ;;
    *) die "unsupported platform: $system $machine" ;;
esac

if [ "$system" = Linux ]; then
    [ -z "$invite" ] || die "client install is supported on macOS and Windows only"
elif [ "$system" = Darwin ]; then
    [ -n "$invite" ] || usage
else
    die "unsupported platform: $system"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/jaynshare-install.XXXXXX") || die "could not create a temporary directory"
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
archive="jaynshare-$version-$target.tar.gz"
base="$origin/v$version"
fetch -o "$work/SHA256SUMS" "$base/SHA256SUMS" || die "could not download SHA256SUMS"
fetch -o "$work/$archive" "$base/$archive" || die "could not download $archive"

expected=$(awk -v name="$archive" '
    $2 == name { count++; digest = $1 }
    END { if (count != 1) exit 1; print digest }
' "$work/SHA256SUMS") || die "SHA256SUMS does not name $archive exactly once"
[ "${#expected}" -eq 64 ] || die "SHA256SUMS has an invalid digest for $archive"
case $expected in *[!0-9a-f]*) die "SHA256SUMS has an invalid digest for $archive" ;; esac
case $system in
    Linux) actual=$(sha256sum "$work/$archive" | awk '{ print $1 }') ;;
    Darwin) actual=$(shasum -a 256 "$work/$archive" | awk '{ print $1 }') ;;
esac
[ "$actual" = "$expected" ] || die "$archive failed its SHA-256 check"

tar -xzf "$work/$archive" -C "$work"
binary="$work/jaynshare-$version-$target/jaynshare"
[ -f "$binary" ] || die "$archive contains no jaynshare executable"
chmod +x "$binary"

# Piped into sh, stdin is this script: the join and the install ask on the terminal.
asking() {
    if [ ! -t 0 ] && [ -t 2 ] && (exec </dev/tty) 2>/dev/null; then
        "$@" </dev/tty
    else
        "$@"
    fi
}

if [ "$system" = Darwin ]; then
    asking "$binary" join "$invite"
    exit
fi

set -- server install --version "$version"
[ "$origin_given" = false ] || set -- "$@" --release-origin "$origin"
[ -z "$tls_ca" ] || set -- "$@" --tls-ca "$tls_ca"
if [ "$(id -u)" -eq 0 ]; then
    asking "$binary" "$@"
    exit
fi
command -v sudo >/dev/null 2>&1 || die "sudo is required"
asking sudo "$binary" "$@"
