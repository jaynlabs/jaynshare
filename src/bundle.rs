//! The client kit: its verification against the pinned minisign key, the
//! minisign and canonical-JSON primitives the release verifier shares, and
//! the CA update ZIP. The kit is produced by a repository tool
//! (`tools/make-client-kit.py`) and by the signed release pipeline; this
//! code does not change between the two.
//!
//! # Kit self-containment
//! The kit carries its own `release.json`, whose client-kit entry digests
//! every member; the entry's file-level length/digest are `null` (they are
//! the outer release's concern), and `SHA256SUMS` agrees with `release.json`
//! (its bytes hash to the recorded digest) while carrying the outer
//! artifacts the kit does not build.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The release-set members of a kit.
const RELEASE_SET_MEMBERS: [&str; 3] = ["release.json", "release.json.minisig", "SHA256SUMS"];

/// The kit members that are not the release set: the platform
/// instructions and the executables.
const KIT_ONLY_MEMBERS: [&str; 4] = [
    "README.txt",
    "payload/macos-x86_64/jaynshare",
    "payload/macos-aarch64/jaynshare",
    "payload/windows-x86_64/jaynshare.exe",
];

/// Each client platform, `<os>-<arch>`, and its payload member.
pub const PAYLOADS: [(&str, &str); 3] = [
    ("macos-x86_64", "payload/macos-x86_64/jaynshare"),
    ("macos-aarch64", "payload/macos-aarch64/jaynshare"),
    ("windows-x86_64", "payload/windows-x86_64/jaynshare.exe"),
];

/// This machine's client platform and payload member: `None` is an
/// unsupported client platform.
fn native() -> Option<(&'static str, &'static str)> {
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    PAYLOADS.into_iter().find(|(name, _)| *name == platform)
}

pub fn native_platform() -> Option<&'static str> {
    native().map(|(platform, _)| platform)
}

pub fn native_payload() -> Option<&'static str> {
    native().map(|(_, member)| member)
}

// ------------------------------------------------------------------ the pinned key and minisign

/// The pinned release public key: a minisign key id plus the raw
/// 32-byte Ed25519 key.
pub struct PinnedKey {
    id: [u8; 8],
    key: Vec<u8>,
}

impl PinnedKey {
    /// The decoded body of a minisign public-key file: `Ed` ‖ key id ‖ key.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() != 42 || &bytes[..2] != b"Ed" {
            return Err(format!(
                "the pinned release key is {} bytes, expected 42 starting with the `Ed` algorithm",
                bytes.len()
            ));
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&bytes[2..10]);
        Ok(Self {
            id,
            key: bytes[10..].to_vec(),
        })
    }

    /// The minisign key id, 8 bytes.
    pub fn key_id(&self) -> [u8; 8] {
        self.id
    }

    /// The key as a minisign public-key file's second line spells it.
    pub fn encoded(&self) -> String {
        let mut bytes = b"Ed".to_vec();
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.key);
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// The minisign public-key file holding this key.
    pub fn file_text(&self) -> String {
        format!(
            "untrusted comment: minisign public key {}\n{}\n",
            key_id_hex(&self.id),
            self.encoded()
        )
    }

    /// The active release key: `<config root>/release.pub` when
    /// present, else the key embedded in the verifier.
    pub fn load() -> Result<Self, String> {
        crate::deploy::release::active_key()
    }
}

/// A key id as the manifest and the messages spell it: 16 uppercase hex digits.
fn key_id_hex(id: &[u8; 8]) -> String {
    id.iter().map(|b| format!("{b:02X}")).collect()
}

/// A minisign public-key file: untrusted comment, then base64(`Ed` ‖ key id ‖
/// 32-byte key). The 42-byte `Ed` form only.
pub fn parse_public_key_file(bytes: &[u8]) -> Option<PinnedKey> {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("untrusted comment:") {
            continue;
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(line)
            .ok()?;
        return PinnedKey::from_bytes(decoded).ok();
    }
    None
}

/// One parsed minisign signature file: the primary signature and the
/// trusted comment it is bound to, plus the global signature over
/// (signature ‖ trusted-comment text).
pub struct MinisignSignature {
    pub key_id: [u8; 8],
    pub signature: [u8; 64],
    pub trusted_comment: String,
    pub global_signature: [u8; 64],
}

/// A minisign signature file: untrusted comment, then base64(`Ed` ‖ key id ‖
/// 64-byte signature), then `trusted comment: <text>`, then the base64 global
/// signature. Legacy `Ed` only — the prehashed `ED` form needs BLAKE2b, which
/// is not a dependency.
pub fn parse_signature(bytes: &[u8]) -> Result<MinisignSignature, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("untrusted comment:"));
    let body = lines
        .next()
        .ok_or_else(|| "no signature line".to_string())
        .and_then(|line| {
            base64::engine::general_purpose::STANDARD
                .decode(line)
                .map_err(|e| format!("the signature line does not decode: {e}"))
        })?;
    if body.len() != 74 || (&body[..2] != b"Ed" && &body[..2] != b"ED") {
        return Err(format!(
            "the signature is {} bytes with algorithm {:?}, expected 74 starting with `Ed`",
            body.len(),
            String::from_utf8_lossy(body.get(..2).unwrap_or(&[]))
        ));
    }
    if &body[..2] == b"ED" {
        return Err(
            "the prehashed `ED` signature form needs BLAKE2b, which is not supported".into(),
        );
    }
    let trusted_comment = lines
        .next()
        .and_then(|line| line.strip_prefix("trusted comment: "))
        .ok_or_else(|| "no `trusted comment: ` line".to_string())?
        .to_string();
    let global = lines
        .next()
        .ok_or_else(|| "no global signature line".to_string())
        .and_then(|line| {
            base64::engine::general_purpose::STANDARD
                .decode(line)
                .map_err(|e| format!("the global signature line does not decode: {e}"))
        })?;
    if global.len() != 64 {
        return Err(format!(
            "the global signature is {} bytes, expected 64",
            global.len()
        ));
    }
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&body[2..10]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&body[10..74]);
    let mut global_signature = [0u8; 64];
    global_signature.copy_from_slice(&global);
    Ok(MinisignSignature {
        key_id,
        signature,
        trusted_comment,
        global_signature,
    })
}

/// Signature verification: the key ids agree, the signature covers the
/// exact bytes, and the global signature covers (signature ‖ trusted comment).
pub fn verify_release_signature(
    release_json: &[u8],
    minisig: &[u8],
    key: &PinnedKey,
) -> Result<(), String> {
    let parsed = parse_signature(minisig).map_err(|why| format!("release.json.minisig: {why}"))?;
    if parsed.key_id != key.key_id() {
        return Err(format!(
            "release.json.minisig: signature key id {} does not match the active key id {}",
            key_id_hex(&parsed.key_id),
            key_id_hex(&key.key_id())
        ));
    }
    let verifier = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key.key);
    verifier
        .verify(release_json, &parsed.signature)
        .map_err(|_| {
            "release.json.minisig: signature check failed against the pinned key".to_string()
        })?;
    verifier
        .verify(
            &[&parsed.signature[..], parsed.trusted_comment.as_bytes()].concat(),
            &parsed.global_signature,
        )
        .map_err(|_| {
            "release.json.minisig: the global signature does not match the trusted comment".into()
        })
}

// ------------------------------------------------------------------ canonical JSON (RFC 8785)

/// RFC 8785 canonical JSON: sorted object keys (UTF-16 code-unit order), no
/// whitespace, ECMAScript string escaping, integers as-is. Manifest values are
/// strings, integers and nulls; floats are not part of the manifest.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|k| k.encode_utf16().collect::<Vec<_>>());
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ------------------------------------------------------------------ digests

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The fingerprint is the SHA-256 of the DER certificate, rendered as
/// colon-separated upper-case hex pairs.
pub fn fingerprint(pem: &str) -> Result<String, String> {
    let der = pem_to_der(pem).ok_or("the CA certificate is not a PEM block")?;
    let digest = Sha256::digest(&der);
    Ok(digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    if body.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

// ------------------------------------------------------------------ the verified kit

/// One kit member's binding from the signed release manifest.
#[derive(Debug, Clone)]
pub struct MemberBinding {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

/// A client kit that passed signature verification.
#[derive(Debug)]
pub struct VerifiedKit {
    pub version: String,
    /// Bytes of every kit member, keyed by path.
    pub members: BTreeMap<String, Vec<u8>>,
}

impl VerifiedKit {
    pub fn member(&self, path: &str) -> Option<&[u8]> {
        self.members.get(path).map(Vec::as_slice)
    }
}

/// A ZIP the way the kit and the bundle are written: one flat map of path →
/// bytes, refusing duplicates, absolute or `..` paths, non-regular entries and
/// names that collide only by ASCII or Unicode case.
pub fn read_zip(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("{}: not a readable ZIP archive: {e}", path.display()))?;
    let mut members = BTreeMap::new();
    let mut seen_folded: Vec<String> = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| format!("{}: damaged member: {e}", path.display()))?;
        let name = entry.name().to_string();
        if name.starts_with('/') || name.contains("..") || name.contains('\\') {
            return Err(format!(
                "archive member {name:?} is not a relative kit path"
            ));
        }
        if !entry.is_file() {
            return Err(format!(
                "archive member {name:?} is a directory, link or non-regular entry"
            ));
        }
        if members.contains_key(&name) {
            return Err(format!(
                "archive contains {name:?} twice (duplicate filename)"
            ));
        }
        let folded = name.to_lowercase();
        if seen_folded.contains(&folded) {
            return Err(format!(
                "archive member {name:?} differs from another only by case"
            ));
        }
        seen_folded.push(folded);
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("archive member {name:?}: {e}"))?;
        members.insert(name, bytes);
    }
    Ok(members)
}

/// Kit verification against a client-kit ZIP: signature, then SHA256SUMS agreement, then
/// every member's length and digest. A failure names the artifact and the
/// failed check and carries no manifest-adjacent secret.
pub fn verify_kit_zip(path: &Path, key: &PinnedKey) -> Result<VerifiedKit, String> {
    let members = read_zip(path)?;
    for required in ["release.json", "release.json.minisig", "SHA256SUMS"]
        .iter()
        .chain(KIT_ONLY_MEMBERS.iter())
    {
        if !members.contains_key(*required) {
            return Err(format!("the client kit is missing {required:?}"));
        }
    }
    for name in members.keys() {
        if !RELEASE_SET_MEMBERS.contains(&name.as_str())
            && !KIT_ONLY_MEMBERS.contains(&name.as_str())
        {
            return Err(format!("the client kit carries unlisted file {name:?}"));
        }
    }
    let release_bytes = members["release.json"].as_slice();
    verify_release_signature(release_bytes, &members["release.json.minisig"], key)?;
    let release: Value =
        serde_json::from_slice(release_bytes).map_err(|e| format!("release.json: {e}"))?;
    if release["schema_version"] != json!(1) {
        return Err("release.json: unsupported schema version".into());
    }
    let sums_digest = release["sha256sums_sha256"]
        .as_str()
        .ok_or("release.json: sha256sums_sha256 missing")?;
    if sha256_hex(&members["SHA256SUMS"]) != sums_digest {
        return Err("SHA256SUMS: disagrees with release.json".into());
    }
    let entry = release["artifacts"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|e| e["purpose"] == json!("client-kit"))
                .cloned()
        })
        .ok_or("release.json: no client-kit artifact entry")?;
    let bindings: Vec<MemberBinding> = entry["members"]
        .as_array()
        .ok_or("release.json: the client-kit entry has no member map")?
        .iter()
        .map(|m| {
            Ok(MemberBinding {
                path: m["path"]
                    .as_str()
                    .ok_or("release.json: a member binding has no path")?
                    .to_string(),
                length: m["length"]
                    .as_u64()
                    .ok_or("release.json: a member binding has no length")?,
                sha256: m["sha256"]
                    .as_str()
                    .ok_or("release.json: a member binding has no digest")?
                    .to_string(),
            })
        })
        .collect::<Result<_, String>>()?;
    for binding in &bindings {
        let bytes = members.get(&binding.path).ok_or_else(|| {
            format!(
                "release.json: the member map names {:?}, which the kit does not carry",
                binding.path
            )
        })?;
        if bytes.len() as u64 != binding.length {
            return Err(format!(
                "{}: length {} does not match the manifest's {}",
                binding.path,
                bytes.len(),
                binding.length
            ));
        }
        if sha256_hex(bytes) != binding.sha256 {
            return Err(format!(
                "{0}: digest does not match the manifest's",
                binding.path
            ));
        }
    }
    let unbound: Vec<&str> = KIT_ONLY_MEMBERS
        .iter()
        .copied()
        .filter(|name| !bindings.iter().any(|b| &b.path == name))
        .collect();
    if !unbound.is_empty() {
        return Err(format!(
            "release.json: the member map does not bind {unbound:?}"
        ));
    }
    Ok(VerifiedKit {
        version: release["version"].as_str().unwrap_or_default().to_string(),
        members,
    })
}

/// Everything the CA update ZIP carries. No enrolment code, no
/// release identity — after a rotate only the certificate, the fingerprint
/// and the server identity change.
pub struct CaUpdateInputs<'a> {
    pub certificate_pem: &'a str,
    pub fingerprint: &'a str,
    pub origins: [&'a str; 2],
    pub issued_at: &'a str, // RFC 3339
}

/// The CA update ZIP's name — the first 12 hex of the
/// fingerprint, colons removed, lower-case.
pub fn ca_update_name(fingerprint: &str) -> String {
    let hex: String = fingerprint.chars().filter(|c| *c != ':').collect();
    format!("jaynshare-ca-update-{}.zip", hex[..12].to_lowercase())
}

/// Writes the CA update ZIP: exactly `ca-update.json` (canonical
/// JSON), `ca.pem` and `README.txt`. The destination must not
/// exist; on failure the partial file is removed.
pub fn write_ca_update_zip(
    out_dir: &Path,
    inputs: &CaUpdateInputs<'_>,
) -> Result<(PathBuf, Value), String> {
    let hex: String = inputs.fingerprint.chars().filter(|c| *c != ':').collect();
    let manifest = json!({
        "schema": 1,
        "origins": inputs.origins,
        "issued_at": inputs.issued_at,
        "ca_sha256": hex.to_lowercase(),
        "fingerprint": inputs.fingerprint,
    });
    let destination = out_dir.join(ca_update_name(inputs.fingerprint));
    let readme = "This is a Jaynshare CA update bundle: it replaces the certificate authority \
your client trusts after the server rotated its CA.\n\
Run `jaynshare ca-update --from <this zip>` on each enrolled machine.\n\
Compare the fingerprint with the operator through an independent channel before your next MITM launch.\n";
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        open.mode(0o600);
    }
    let file = open.open(&destination).map_err(|e| {
        format!(
            "{}: cannot create the CA update bundle: {e}",
            destination.display()
        )
    })?;
    let mut zip = zip::ZipWriter::new(file);
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
    let written = |zip: &mut zip::ZipWriter<std::fs::File>| -> Result<(), String> {
        let mut add = |name: &str, bytes: &[u8]| -> Result<(), String> {
            zip.start_file(name, options)
                .and_then(|_| zip.write_all(bytes).map_err(zip::result::ZipError::from))
                .map_err(|e| format!("archive member {name:?}: {e}"))
        };
        add("ca-update.json", canonical_json(&manifest).as_bytes())?;
        add("ca.pem", inputs.certificate_pem.as_bytes())?;
        add("README.txt", readme.as_bytes())?;
        Ok(())
    };
    if let Err(e) = written(&mut zip) {
        drop(zip);
        let _ = std::fs::remove_file(&destination);
        return Err(e);
    }
    if let Err(e) = zip.finish() {
        let _ = std::fs::remove_file(&destination);
        return Err(format!("cannot finish the CA update bundle: {e}"));
    }
    Ok((destination, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair as _;

    fn key_pair() -> (Vec<u8>, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
        (pkcs8.as_ref().to_vec(), pair.public_key().as_ref().to_vec())
    }

    #[allow(dead_code)] // helper kept for tests that do not all run on every feature set
    fn sign(pkcs8: &[u8], message: &[u8]) -> Vec<u8> {
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8).expect("parse");
        pair.sign(message).as_ref().to_vec()
    }

    #[test]
    fn canonical_json_sorts_and_escapes() {
        let value = json!({ "b": "line\nbreak", "a": 1, "c": null, "\u{e9}": "q\"uote" });
        assert_eq!(
            canonical_json(&value),
            "{\"a\":1,\"b\":\"line\\nbreak\",\"c\":null,\"é\":\"q\\\"uote\"}"
        );
    }

    #[test]
    fn minisign_files_roundtrip_through_the_parsers() {
        let (pkcs8, public) = key_pair();
        let message = b"release.json bytes";
        let key = PinnedKey::from_bytes([b"Ed".as_slice(), &public[..8], &public].concat())
            .expect("42 bytes");
        let signature_file = minisign_file(&pkcs8, &public, message);
        verify_release_signature(message, signature_file.as_bytes(), &key).expect("verifies");
        let bad = minisign_file(&pkcs8, &public, b"other");
        assert!(
            verify_release_signature(message, bad.as_bytes(), &key).is_err(),
            "a signature over other bytes must fail"
        );
    }

    fn kit_zip(path: &Path, pkcs8: &[u8], members: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for (name, bytes) in members {
            zip.start_file(*name, options).expect("start");
            zip.write_all(bytes).expect("write");
        }
        zip.finish().expect("finish");
        let _ = pkcs8;
    }

    #[test]
    fn read_zip_refuses_case_collisions_and_traversal() {
        let dir = std::env::temp_dir().join(format!("bundle-l1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("collide.zip");
        kit_zip(
            &path,
            &[],
            &[
                ("README.txt", b"one".as_slice()),
                ("readme.txt", b"two".as_slice()),
            ],
        );
        let why = read_zip(&path).expect_err("case collision");
        assert!(why.contains("only by case"), "{why}");
        let path = dir.join("traversal.zip");
        kit_zip(&path, &[], &[("../x", b"escape".as_slice())]);
        let why = read_zip(&path).expect_err("traversal");
        assert!(why.contains("not a relative kit path"), "{why}");
        let path = dir.join("absolute.zip");
        kit_zip(&path, &[], &[("/x", b"escape".as_slice())]);
        let why = read_zip(&path).expect_err("absolute");
        assert!(why.contains("not a relative kit path"), "{why}");
        // A symbolic-link entry is refused, whatever it points at.
        let path = dir.join("symlink.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).expect("create"));
        zip.add_symlink(
            "ca.pem",
            "/etc/passwd",
            zip::write::SimpleFileOptions::default(),
        )
        .expect("symlink entry");
        zip.finish().expect("finish");
        let why = read_zip(&path).expect_err("symlink");
        assert!(why.contains("link"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ca_update_test_inputs<'a>() -> (std::path::PathBuf, CaUpdateInputs<'a>) {
        (
            std::env::temp_dir().join(format!("ca-update-l1-{}", std::process::id())),
            CaUpdateInputs {
                certificate_pem: "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
                fingerprint: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
                origins: ["http://127.0.0.1:8080", "127.0.0.1:8081"],
                issued_at: "2026-09-21T00:00:00Z",
            },
        )
    }

    #[test]
    fn ca_update_zip_members_order_name_and_canonical_manifest() {
        let (dir, inputs) = ca_update_test_inputs();
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (archive, manifest) = write_ca_update_zip(&dir, &inputs).expect("write");
        assert_eq!(
            archive.file_name().unwrap().to_str(),
            Some("jaynshare-ca-update-abcdef012345.zip")
        );
        let mut zip =
            zip::ZipArchive::new(std::fs::File::open(&archive).expect("open")).expect("read");
        let names: Vec<String> = (0..zip.len())
            .map(|i| zip.by_index(i).expect("member").name().to_string())
            .collect();
        assert_eq!(names, ["ca-update.json", "ca.pem", "README.txt"]);
        let expected = json!({
            "schema": 1,
            "origins": inputs.origins,
            "issued_at": inputs.issued_at,
            "ca_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "fingerprint": inputs.fingerprint,
        });
        assert_eq!(manifest, expected);
        let mut written = String::new();
        zip.by_index(0)
            .expect("manifest")
            .read_to_string(&mut written)
            .expect("read");
        assert_eq!(written, canonical_json(&expected));
        let readme = {
            let mut text = String::new();
            zip.by_index(2)
                .expect("readme")
                .read_to_string(&mut text)
                .expect("read");
            text
        };
        assert_eq!(readme.lines().count(), 3);
        // An existing bundle is never overwritten.
        let why = write_ca_update_zip(&dir, &inputs).expect_err("second write");
        assert!(why.contains("cannot create"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A real minisign signature file: `Ed` ‖ key id ‖ signature, trusted
    // comment, global signature over (signature ‖ comment text).
    fn minisign_file(pkcs8: &[u8], public: &[u8], message: &[u8]) -> String {
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8).expect("parse");
        let signature = pair.sign(message);
        let trusted = "timestamp:1760000000 file:release.json";
        let global = pair.sign(&[signature.as_ref(), trusted.as_bytes()].concat());
        format!(
            "untrusted comment: signature\n{}\ntrusted comment: {trusted}\n{}\n",
            base64::engine::general_purpose::STANDARD
                .encode([b"Ed".as_slice(), &public[..8], signature.as_ref()].concat()),
            base64::engine::general_purpose::STANDARD.encode(global.as_ref()),
        )
    }

    #[test]
    fn key_id_ed_refusal_and_global_signature_are_checked() {
        let (pkcs8, public) = key_pair();
        let key = PinnedKey::from_bytes([b"Ed".as_slice(), &public[..8], &public].concat())
            .expect("42 bytes");
        assert_eq!(
            key.key_id(),
            <[u8; 8]>::try_from(&public[..8]).expect("8 bytes")
        );
        let message = b"release.json bytes";
        let good = minisign_file(&pkcs8, &public, message);
        verify_release_signature(message, good.as_bytes(), &key).expect("verifies");

        // The trusted comment is bound: one flipped byte in it fails.
        let tampered = good.replacen("timestamp:1760", "timestamp:9999", 1);
        let why = verify_release_signature(message, tampered.as_bytes(), &key)
            .expect_err("the trusted comment is signed");
        assert!(why.contains("global signature"), "{why}");

        // A public key file whose key id differs from the signer's fails and
        // names both ids.
        let mut other = public.clone();
        other[0] ^= 0xff;
        let other_key = PinnedKey::from_bytes([b"Ed".as_slice(), &other[..8], &other].concat())
            .expect("42 bytes");
        let why = verify_release_signature(message, good.as_bytes(), &other_key)
            .expect_err("key id mismatch");
        let (ours, theirs) = (key_id_hex(&key.key_id()), key_id_hex(&other_key.key_id()));
        assert!(why.contains(&ours) && why.contains(&theirs), "{why}");

        // The prehashed `ED` form needs BLAKE2b and is refused by name.
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8).expect("parse");
        let signature = pair.sign(message);
        let prehashed = format!(
            "untrusted comment: signature\n{}\n",
            base64::engine::general_purpose::STANDARD
                .encode([b"ED".as_slice(), &public[..8], signature.as_ref()].concat())
        );
        let why = verify_release_signature(message, prehashed.as_bytes(), &key)
            .expect_err("prehashed form");
        assert!(why.contains("BLAKE2b"), "{why}");
    }
}
