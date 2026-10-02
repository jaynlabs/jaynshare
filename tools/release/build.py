#!/usr/bin/env python3
"""Build one release set from given binaries.

    build.py --version <semver> --commit <40 hex> --key <seed file>
             --bin <rust-target>=<path> (repeat)
             --out <dir> [--allow-placeholder] [--next-key <seed file>]
    build.py --self-test

Writes into `--out`:

- the five platform archives (`.tar.gz`, windows `.zip`), each
  rooted in one directory named like the archive without its extension and
  holding exactly the executable, LICENSE, NOTICE.md and a README.txt;
- `jaynshare-<version>-client-kit.zip`, with the README of
  `deploy/kit/` plus the client executables;
- `SHA256SUMS`, canonical `release.json` and `release.json.minisig`;
- with `--next-key`, the key-rotation overlap: `release.json` names the
  next key id, and `release.json.<next-key-id>.minisig` and
  `release-key-<next-key-id>.pub` join the set, unlisted in the manifest.

Pure python3 standard library; the minisign signing and the client-kit
builder are `tools/make-client-kit.py`'s, imported so both tools produce
byte-identical file formats. The signing seed is only ever read, never
copied into the output, the workspace or a log.
"""

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import time
import zipfile
from datetime import datetime, timezone

# ------------------------------------------------------------------ constants

RELEASE_TARGETS = [
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
]
WINDOWS_TARGET = "x86_64-pc-windows-msvc"

SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
COMMIT = re.compile(r"^[0-9a-f]{40}$")

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_spec = importlib.util.spec_from_file_location(
    "make_client_kit", os.path.join(REPO, "tools", "make-client-kit.py")
)
mk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mk)

# ------------------------------------------------------------------ pieces


def archive_name(version: str, target: str) -> str:
    extension = "zip" if target == WINDOWS_TARGET else "tar.gz"
    return f"jaynshare-{version}-{target}.{extension}"


def root_of(name: str) -> str:
    return re.sub(r"\.(tar\.gz|zip)$", "", name)


def release_readme(version: str, target: str) -> bytes:
    key_file = open(os.path.join(REPO, "deploy", "release-key.pub"), "rb").read()
    body = key_file.decode().splitlines()[-1]
    public = base64.b64decode(body)[8:]
    fingerprint = hashlib.sha256(public).hexdigest()[:16]
    return (
        f"jaynshare {version}\n"
        f"Target: {target}\n"
        "\n"
        "Verification: fetch this archive together with release.json,\n"
        "release.json.minisig and SHA256SUMS, then run\n"
        "\n"
        "    jaynshare release verify <directory that holds them>\n"
        "\n"
        f"Release key fingerprint: {fingerprint}\n"
        "Release key (deploy/release-key.pub):\n"
        f"{key_file.decode()}"
    ).encode()


def placeholder_executable(target: str) -> bytes:
    return (
        f"placeholder: no {target} build in this release set "
        "(written with --allow-placeholder)\n"
    ).encode()


def platform_archive(target: str, version: str, executable: bytes) -> bytes:
    """One root directory holding exactly four files."""
    root = root_of(archive_name(version, target))
    executable_name = "jaynshare.exe" if target == WINDOWS_TARGET else "jaynshare"
    entries = [
        (executable_name, executable, 0o755),
        ("LICENSE", open(os.path.join(REPO, "LICENSE"), "rb").read(), 0o644),
        ("NOTICE.md", open(os.path.join(REPO, "NOTICE.md"), "rb").read(), 0o644),
        (
            "README.txt",
            release_readme(version, target),
            0o644,
        ),
    ]
    if target == WINDOWS_TARGET:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data, mode in entries:
                info = zipfile.ZipInfo(f"{root}/{name}", time.localtime(time.time())[:6])
                info.external_attr = mode << 16
                archive.writestr(info, data)
        return buffer.getvalue()
    buffer = io.BytesIO()
    mtime = int(time.time())
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        # The root's own entry first, as the installer's staging expects
        # (an installer refuses an archive without it).
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.mtime = mtime
        directory.uid = directory.gid = 0
        directory.uname = directory.gname = ""
        archive.addfile(directory)
        for name, data, mode in entries:
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            info.mode = mode
            info.mtime = mtime
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def client_kit(version: str, commit: str, seed_path: str, bins: dict, allow: bool) -> tuple:
    """The client kit, built by `make-client-kit.py build`."""
    work = tempfile.mkdtemp(prefix="jaynshare-kit-")
    try:
        payload = os.path.join(work, "payload")
        os.makedirs(payload)
        kit_dir = os.path.join(REPO, "deploy", "kit")
        for name in ["README.txt"]:
            with open(os.path.join(kit_dir, name), "rb") as source:
                data = source.read()
            with open(os.path.join(payload, name), "wb") as sink:
                sink.write(data)
        for platform, member, exe_name in [
            ("macos-aarch64", "aarch64-apple-darwin", "jaynshare"),
            ("macos-x86_64", "x86_64-apple-darwin", "jaynshare"),
            ("windows-x86_64", WINDOWS_TARGET, "jaynshare.exe"),
        ]:
            directory = os.path.join(payload, "payload", platform)
            os.makedirs(directory)
            if bins.get(member) is not None:
                data = bins[member]
            elif allow:
                data = placeholder_executable(member)
            else:
                sys.exit(f"{member}: no --bin for the client kit (and no --allow-placeholder)")
            with open(os.path.join(directory, exe_name), "wb") as sink:
                sink.write(data)
        out = os.path.join(work, "kit.zip")
        mk.build(payload, seed_path, out, version=version, commit=commit)
        with open(out, "rb") as handle:
            kit_bytes = handle.read()
    finally:
        import shutil

        shutil.rmtree(work, ignore_errors=True)
    with zipfile.ZipFile(io.BytesIO(kit_bytes)) as archive:
        members = []
        for info in archive.infolist():
            data = archive.read(info)
            members.append(
                {
                    "path": info.filename,
                    "length": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
    members.sort(key=lambda m: m["path"].encode())
    return kit_bytes, members


# ------------------------------------------------------------------ the build


def build_release(version: str, commit: str, seed_path: str, bins: dict,
                  out: str, allow: bool,
                  next_seed_path: str | None = None) -> None:
    def read_seed(path: str) -> bytes:
        with open(path, "rb") as handle:
            data = handle.read()
        if len(data) != 32:
            sys.exit(f"{path}: the seed is {len(data)} bytes, expected 32")
        return data

    seed = read_seed(seed_path)
    public = mk.public_key(seed)
    key_id = public[:8].hex().upper()
    # An overlap release is signed by both keys and names the next.
    next_seed = read_seed(next_seed_path) if next_seed_path is not None else None
    if next_seed is not None:
        next_public = mk.public_key(next_seed)
        next_id = next_public[:8].hex().upper()
        if next_id == key_id:
            sys.exit("--next-key: the next key is the signing key")

    artifacts: list[tuple[str, str, str | None, bytes, list]] = []  # name, purpose, target, data, members
    for target in RELEASE_TARGETS:
        if bins.get(target) is not None:
            executable = bins[target]
        elif allow:
            executable = placeholder_executable(target)
            print(f"{target}: placeholder executable written (--allow-placeholder)",
                  file=sys.stderr)
        else:
            sys.exit(f"{target}: no --bin given (and no --allow-placeholder)")
        name = archive_name(version, target)
        artifacts.append((name, "platform", target,
                          platform_archive(target, version, executable), []))

    kit_bytes, kit_members = client_kit(version, commit, seed_path, bins, allow)
    artifacts.append((f"jaynshare-{version}-client-kit.zip", "client-kit", None,
                      kit_bytes, kit_members))

    artifacts.sort(key=lambda a: a[0].encode())
    sums = b"".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n".encode()
        for name, _, _, data, _ in artifacts
    )
    manifest_root = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "key_id": key_id,
        "sha256sums_sha256": hashlib.sha256(sums).hexdigest(),
        "artifacts": [
            {
                "filename": name,
                "purpose": purpose,
                "target": target,
                "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "members": members,
            }
            for name, purpose, target, data, members in artifacts
        ],
    }
    if next_seed is not None:
        manifest_root["next_key_id"] = next_id
    manifest = mk.canonical_json(manifest_root)
    signature = mk.minisign_signature_file(seed, manifest)
    overlap = [] if next_seed is None else [
        (f"release.json.{next_id}.minisig", mk.minisign_signature_file(next_seed, manifest)),
        (f"release-key-{next_id}.pub",
         mk.minisign_pubkey_file(next_public, "jaynshare release key")),
    ]

    os.makedirs(out, exist_ok=True)
    for name, data in [(name, data) for name, _, _, data, _ in artifacts] + [
        ("SHA256SUMS", sums),
        ("release.json", manifest),
        ("release.json.minisig", signature),
    ] + overlap:
        with open(os.path.join(out, name), "wb") as handle:
            handle.write(data)
    print(f"{out}: {len(artifacts)} artifacts, SHA256SUMS, release.json, release.json.minisig"
          + "".join(f", {name}" for name, _ in overlap))


# ------------------------------------------------------------------ self-test


def self_test() -> None:
    mk.self_test()
    with tempfile.TemporaryDirectory(prefix="jaynshare-build-") as work:
        seed = os.path.join(work, "seed.bin")
        with open(seed, "wb") as handle:
            handle.write(os.urandom(32))
        out = os.path.join(work, "out")
        build_release(
            "1.2.3", "0123456789abcdef0123456789abcdef01234567",
            seed, {}, out, True,
        )
        names = sorted(os.listdir(out))
        expected = sorted(
            [archive_name("1.2.3", t) for t in RELEASE_TARGETS]
            + [
                "jaynshare-1.2.3-client-kit.zip",
                "SHA256SUMS",
                "release.json",
                "release.json.minisig",
            ]
        )
        assert names == expected, f"file list mismatch: {names}"

        def read(name: str) -> bytes:
            with open(os.path.join(out, name), "rb") as handle:
                return handle.read()

        # SHA256SUMS agrees with the files, line grammar holds.
        for line in read("SHA256SUMS").decode().splitlines():
            digest, name = line.split("  ", 1)
            assert hashlib.sha256(read(name)).hexdigest() == digest, name
        # release.json parses, agrees with the sums, and its signature holds.
        manifest = json.loads(read("release.json"))
        assert manifest["schema_version"] == 1
        assert manifest["version"] == "1.2.3"
        assert manifest["commit"] == "0123456789abcdef0123456789abcdef01234567"
        assert re.fullmatch(r"[0-9A-F]{16}", manifest["key_id"])
        assert manifest["sha256sums_sha256"] == hashlib.sha256(read("SHA256SUMS")).hexdigest()
        assert len(manifest["artifacts"]) == 6
        kit_entry = next(a for a in manifest["artifacts"] if a["purpose"] == "client-kit")
        with zipfile.ZipFile(io.BytesIO(read("jaynshare-1.2.3-client-kit.zip"))) as archive:
            assert [m["path"] for m in kit_entry["members"]] == sorted(archive.namelist())
            inner = json.loads(archive.read("release.json"))
            assert (inner["version"], inner["commit"]) == (manifest["version"], manifest["commit"])
        # minisign: the second line is base64("Ed" ‖ key id ‖ signature).
        body = read("release.json.minisig").decode().splitlines()[1]
        decoded = base64.b64decode(body)
        assert decoded[:2] == b"Ed"
        assert decoded[2:10].hex().upper() == manifest["key_id"]
        assert mk.verify(
            mk.public_key(open(seed, "rb").read()), read("release.json"), decoded[10:]
        ), "release.json.minisig does not verify"
        # Exactly four entries under the archive root.
        for target in RELEASE_TARGETS:
            name = archive_name("1.2.3", target)
            root = root_of(name)
            expected_entries = {
                f"{root}/{('jaynshare.exe' if target == WINDOWS_TARGET else 'jaynshare')}",
                f"{root}/LICENSE", f"{root}/NOTICE.md", f"{root}/README.txt",
            }
            if target == WINDOWS_TARGET:
                with zipfile.ZipFile(io.BytesIO(read(name))) as archive:
                    assert set(archive.namelist()) == expected_entries, name
            else:
                with tarfile.open(fileobj=io.BytesIO(read(name)), mode="r:gz") as archive:
                    assert set(archive.getnames()) == expected_entries | {root}, name

        # The overlap names the next key and both signatures hold.
        next_seed = os.path.join(work, "next.bin")
        with open(next_seed, "wb") as handle:
            handle.write(os.urandom(32))
        overlap_out = os.path.join(work, "overlap")
        build_release(
            "1.2.4", "0123456789abcdef0123456789abcdef01234567",
            seed, {}, overlap_out, True, next_seed_path=next_seed,
        )
        next_public = mk.public_key(open(next_seed, "rb").read())
        next_id = next_public[:8].hex().upper()
        overlap_manifest = open(os.path.join(overlap_out, "release.json"), "rb").read()
        assert json.loads(overlap_manifest)["next_key_id"] == next_id
        for name, public in [("release.json.minisig", mk.public_key(open(seed, "rb").read())),
                             (f"release.json.{next_id}.minisig", next_public)]:
            with open(os.path.join(overlap_out, name), "rb") as handle:
                decoded = base64.b64decode(handle.read().decode().splitlines()[1])
            assert mk.verify(public, overlap_manifest, decoded[10:]), name
        with open(os.path.join(overlap_out, f"release-key-{next_id}.pub"), "rb") as handle:
            assert base64.b64decode(handle.read().decode().splitlines()[1])[10:] == next_public
    print("self-test: one release set and one rotation overlap built and checked")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version")
    parser.add_argument("--commit")
    parser.add_argument("--key")
    parser.add_argument("--bin", action="append", default=[])
    parser.add_argument("--out")
    parser.add_argument("--allow-placeholder", action="store_true")
    parser.add_argument("--next-key")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.version or not SEMVER.fullmatch(args.version):
        sys.exit(f"{args.version!r}: not a SemVer 2.0.0 version")
    if not args.commit or not COMMIT.fullmatch(args.commit):
        sys.exit(f"{args.commit!r}: not a 40-digit lowercase hex commit")
    if not args.key:
        sys.exit("--key <seed file> is required")
    if not args.out:
        sys.exit("--out <dir> is required")
    bins: dict = {target: None for target in RELEASE_TARGETS}
    for item in args.bin:
        target, separator, path = item.partition("=")
        if separator != "=" or target not in bins or bins[target] is not None:
            sys.exit(f"--bin {item!r}: expected one <rust-target>=<path> per "
                     f"target of {RELEASE_TARGETS}")
        with open(path, "rb") as handle:
            bins[target] = handle.read()
    build_release(args.version, args.commit, args.key, bins, args.out,
                  args.allow_placeholder, args.next_key)


if __name__ == "__main__":
    main()
