#!/usr/bin/env python3
"""Build a client-kit ZIP the way the release pipeline does, and mint the
minisign key pair it signs with.

This tool is the manual path and a cross-check that `src/bundle.rs` reads
what an independent writer produces.

    make-client-kit.py keygen --pub release.pub --seed seed.bin
    make-client-kit.py build --payload-dir payload/ --key seed.bin --out kit.zip
        [--version <semver>] [--commit <id>]
    make-client-kit.py --self-test

Pure python3: zipfile, hashlib, json — and a small RFC 8032 Ed25519 so the
tool needs nothing beyond the standard library.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import zipfile

# ------------------------------------------------------------------ Ed25519 (RFC 8032)

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def inv(x: int) -> int:
    return pow(x, P - 2, P)


def xrecover(y: int) -> int:
    xx = (y * y - 1) * inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I % P
    if x % 2 != 0:
        x = P - x
    return x


By = 4 * inv(5) % P
Bx = xrecover(By)
B = (Bx, By, 1, Bx * By % P)  # extended coordinates


def edwards_add(P1, P2):
    x1, y1, z1, t1 = P1
    x2, y2, z2, t2 = P2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def scalarmult(point, n):
    result = (0, 1, 1, 0)
    while n > 0:
        if n & 1:
            result = edwards_add(result, point)
        point = edwards_add(point, point)
        n >>= 1
    return result


def compress(point):
    x, y, z, _ = point
    zi = inv(z)
    x = x * zi % P
    y = y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def secret_expand(seed: bytes) -> tuple[bytes, int]:
    digest = sha512(seed)
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return digest[32:], a


def public_key(seed: bytes) -> bytes:
    _, a = secret_expand(seed)
    return compress(scalarmult(B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    prefix, a = secret_expand(seed)
    public = compress(scalarmult(B, a))
    r = int.from_bytes(sha512(prefix + message), "little") % L
    rp = scalarmult(B, r)
    rs = int.from_bytes(compress(rp), "little")
    k = int.from_bytes(sha512(compress(rp) + public + message), "little") % L
    s = (r + k * a) % L
    return compress(rp) + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    # One self-check path (RFC 8032 §5.1.9–11 style); the CLI's verifier is ring.
    if len(signature) != 64:
        return False
    r_bytes, s_bytes = signature[:32], signature[32:]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False
    y = int.from_bytes(public, "little") & ((1 << 255) - 1)
    x = xrecover(y)
    if x & 1 != (int.from_bytes(public, "little") >> 255) & 1:
        x = P - x
    a_point = (x, y, 1, x * y % P)
    r_y = int.from_bytes(r_bytes, "little") & ((1 << 255) - 1)
    r_x = xrecover(r_y)
    if r_x & 1 != (int.from_bytes(r_bytes, "little") >> 255) & 1:
        r_x = P - r_x
    r_point = (r_x, r_y, 1, r_x * r_y % P)
    k = int.from_bytes(sha512(r_bytes + public + message), "little") % L
    return compress(scalarmult(B, s)) == compress(
        edwards_add(r_point, scalarmult(a_point, k))
    )


def self_test() -> None:
    vector_1 = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    vector_2 = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    for seed, message, pk, sig in [
        (
            vector_1,
            b"",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            vector_2,
            bytes([0x72]),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ]:
        assert public_key(seed).hex() == pk, "RFC 8032 public key mismatch"
        assert sign(seed, message).hex() == sig, "RFC 8032 signature mismatch"
        assert verify(public_key(seed), message, sign(seed, message))


# ------------------------------------------------------------------ minisign files


def minisign_pubkey_file(public: bytes, comment: str) -> bytes:
    # base64("Ed" ‖ key id ‖ key); the key id is the key's first eight bytes,
    # as minisign_signature_file's signature line names it.
    body = base64.b64encode(b"Ed" + public[:8] + public).decode()
    return (f"untrusted comment: {comment}\n{body}\n").encode()


def minisign_signature_file(seed: bytes, message: bytes) -> bytes:
    public = public_key(seed)
    signature = sign(seed, message)
    trusted = f"timestamp:{int(time.time())} file:release.json"
    global_signature = sign(seed, signature + trusted.encode())
    sig_body = base64.b64encode(b"Ed" + public[:8] + signature).decode()
    global_body = base64.b64encode(global_signature).decode()
    return (
        f"untrusted comment: signature\n{sig_body}\n"
        f"trusted comment: {trusted}\n{global_body}\n"
    ).encode()


# ------------------------------------------------------------------ kit contents


def canonical_json(value) -> bytes:
    # RFC 8785 as far as this manifest goes: sorted keys, no whitespace.
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def build(payload_dir: str, key_path: str, out_path: str,
          version: str = "0.0.0-m4kit", commit: str = "local") -> None:
    with open(key_path, "rb") as handle:
        seed = handle.read()
    if len(seed) != 32:
        sys.exit(f"{key_path}: the seed is {len(seed)} bytes, expected 32")
    members: dict[str, bytes] = {}
    for root, _, files in os.walk(payload_dir):
        for name in files:
            path = os.path.join(root, name)
            member = os.path.relpath(path, payload_dir)
            with open(path, "rb") as handle:
                members[member] = handle.read()
    required = [
        "README.txt",
        "payload/macos-x86_64/jaynshare",
        "payload/macos-aarch64/jaynshare",
        "payload/windows-x86_64/jaynshare.exe",
    ]
    missing = [name for name in required if name not in members]
    if missing:
        sys.exit(f"{payload_dir}: the payload directory is missing {missing}")
    # The kit's own release.json binds every member; its file-level
    # length/digest are null (the outer release set's concern), and
    # SHA256SUMS agrees with it. A release build stamps its own version and
    # commit; placeholder kits keep the placeholders.
    member_map = [
        {
            "path": name,
            "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for name, data in sorted(members.items())
    ]
    sums = b"".join(
        f"{hashlib.sha256(members[name]).hexdigest()}  {name}\n".encode()
        for name in sorted(members)
    )
    release = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "sha256sums_sha256": hashlib.sha256(sums).hexdigest(),
        "artifacts": [{"purpose": "client-kit", "members": member_map}],
    }
    release_bytes = canonical_json(release)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_STORED) as archive:
        fixed = {
            "release.json": release_bytes,
            "release.json.minisig": minisign_signature_file(seed, release_bytes),
            "SHA256SUMS": sums,
        }
        for name in ["release.json", "release.json.minisig", "SHA256SUMS"] + required:
            archive.writestr(name, fixed[name] if name in fixed else members[name])
    print(f"{out_path}: {len(required) + 3} members")


def keygen(pub_path: str, seed_path: str) -> None:
    seed = os.urandom(32)
    public = public_key(seed)
    with open(seed_path, "wb") as handle:
        handle.write(seed)
    os.chmod(seed_path, 0o600)
    with open(pub_path, "wb") as handle:
        handle.write(
            minisign_pubkey_file(public, "jaynshare client-kit release key")
        )
    print(f"{pub_path}: fingerprint {hashlib.sha256(public).hexdigest()[:16]}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    key = sub.add_parser("keygen")
    key.add_argument("--pub", required=True)
    key.add_argument("--seed", required=True)
    build_parser = sub.add_parser("build")
    build_parser.add_argument("--payload-dir", required=True)
    build_parser.add_argument("--key", required=True)
    build_parser.add_argument("--out", required=True)
    build_parser.add_argument("--version", default="0.0.0-m4kit")
    build_parser.add_argument("--commit", default="local")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("RFC 8032 test vectors 1 and 2 pass")
        return
    if args.command == "keygen":
        keygen(args.pub, args.seed)
    elif args.command == "build":
        build(args.payload_dir, args.key, args.out, args.version, args.commit)
    else:
        parser.error("one of --self-test, keygen or build")


if __name__ == "__main__":
    main()
