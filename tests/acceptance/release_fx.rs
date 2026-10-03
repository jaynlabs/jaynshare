//! Release fixtures: the per-run signing key (planted through the
//! production `release.pub` store), the independent RFC 8785 writer,
//! minisign files, and [`write_release`], a whole release directory with
//! hooks to damage it before or after signing. `bundle.rs`'s client-kit
//! fixtures sign with the same functions.
#![allow(dead_code)] // the release installers use the release half

use std::path::{Path, PathBuf};

use base64::Engine as _;
use ring::signature::KeyPair as _;
use sha2::{Digest, Sha256};

use crate::enrol::config_root;
use crate::harness::{Value, json, private_dir};

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// RFC 8785 as far as this manifest goes: sorted keys, no whitespace. The
/// product's own writer is `bundle::canonical_json`; this is the fixture's
/// independent one, so a disagreement shows up as a failed signature.
pub(crate) fn canonical(value: &Value) -> Vec<u8> {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_by_key(|k| k.encode_utf16().collect::<Vec<u16>>());
                out.push('{');
                for (i, key) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).expect("key"));
                    out.push(':');
                    write(&map[*key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&serde_json::to_string(other).expect("scalar")),
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out.into_bytes()
}

/// The per-run signing key. Returns the PKCS#8 document to sign with and the
/// raw 32-byte public key the `release.pub` file carries.
pub(crate) fn release_key_pair() -> (Vec<u8>, Vec<u8>) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
    (pkcs8.as_ref().to_vec(), pair.public_key().as_ref().to_vec())
}

/// The minisign public-key file: untrusted comment, then base64(`Ed` ‖ key id ‖ key).
pub(crate) fn public_key_file(public: &[u8]) -> Vec<u8> {
    let body = base64::engine::general_purpose::STANDARD
        .encode([b"Ed".as_slice(), &public[..8], public].concat());
    format!("untrusted comment: jaynshare acceptance release key\n{body}\n").into_bytes()
}

/// The minisign signature file over exactly `message`: base64(`Ed` ‖ key id ‖
/// signature), the trusted comment `timestamp:<unix> file:release.json`, and
/// the global signature over (signature ‖ comment text).
pub(crate) fn signature_file(pkcs8: &[u8], public: &[u8], message: &[u8]) -> Vec<u8> {
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8).expect("parse");
    let signature = pair.sign(message);
    let trusted = format!(
        "timestamp:{} file:release.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    );
    let global = pair.sign(&[signature.as_ref(), trusted.as_bytes()].concat());
    let sig_body = base64::engine::general_purpose::STANDARD
        .encode([b"Ed".as_slice(), &public[..8], signature.as_ref()].concat());
    let global_body = base64::engine::general_purpose::STANDARD.encode(global.as_ref());
    format!("untrusted comment: signature\n{sig_body}\ntrusted comment: {trusted}\n{global_body}\n")
        .into_bytes()
}

/// One release signing key: the PKCS#8 document and the raw public key.
pub(crate) struct ReleaseKey {
    pub(crate) pkcs8: Vec<u8>,
    pub(crate) public: Vec<u8>,
}

impl ReleaseKey {
    pub(crate) fn generate() -> Self {
        let (pkcs8, public) = release_key_pair();
        Self { pkcs8, public }
    }

    /// The key id the fixture's files carry (the public key's first eight
    /// bytes), as `release.json`'s `key_id` spells it: 16 uppercase hex digits.
    pub(crate) fn id(&self) -> String {
        self.public[..8]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }

    /// The minisign public-key file.
    pub(crate) fn public_file(&self) -> Vec<u8> {
        public_key_file(&self.public)
    }

    /// A minisign signature over exactly `message`.
    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        signature_file(&self.pkcs8, &self.public, message)
    }

    /// plants this key as the active key under `home`'s configuration
    /// root — the production store, not a seam.
    pub(crate) fn plant(&self, home: &Path) {
        let root = config_root(home);
        private_dir(&root);
        std::fs::write(root.join("release.pub"), self.public_file()).expect("release.pub");
    }
}

/// The release version every fixture release carries.
pub(crate) const FIXTURE_VERSION: &str = "0.7.0-acceptance";

/// The fixture's source commit: a full lowercase object id.
pub(crate) const FIXTURE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// the five targets, in the order.
pub(crate) const TARGETS: [&str; 5] = [
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

pub(crate) fn host_target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        other => panic!("no release target for {other:?}"),
    }
}

/// The nine artifact file names of `version`, with their
/// purpose and target.
pub(crate) fn artifact_names(version: &str) -> Vec<(String, &'static str, Option<&'static str>)> {
    let mut names: Vec<(String, &'static str, Option<&'static str>)> = TARGETS
        .iter()
        .map(|target| {
            let extension = if target.contains("windows") {
                "zip"
            } else {
                "tar.gz"
            };
            (
                format!("jaynshare-{version}-{target}.{extension}"),
                "platform",
                Some(*target),
            )
        })
        .collect();
    names.push((
        format!("jaynshare-{version}-client-kit.zip"),
        "client-kit",
        None,
    ));
    names.extend([
        ("install.ps1".into(), "bootstrap", None),
        ("install.sh".into(), "bootstrap", None),
        ("quickstart.sh".into(), "bootstrap", None),
    ]);
    names
}

/// A release under construction: the artifacts' bytes and the manifest that
/// will be signed. [`write_release`]'s hooks edit it.
pub(crate) struct ReleaseParts {
    /// Artifact file name → filler bytes: the verifier reads bytes, not
    /// archive contents.
    pub(crate) artifacts: Vec<(String, Vec<u8>)>,
    /// `release.json` before canonicalisation.
    pub(crate) manifest: Value,
}

/// The `SHA256SUMS` text for `artifacts`: bytewise filename order, one
/// `<digest> <name>` line each.
pub(crate) fn sha256sums(artifacts: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(String, Vec<u8>)> = artifacts.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    sorted
        .iter()
        .flat_map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)).into_bytes())
        .collect()
}

/// A valid release of [`FIXTURE_VERSION`] signed by `key`.
pub(crate) fn release_parts(key: &ReleaseKey) -> ReleaseParts {
    release_parts_of(key, FIXTURE_VERSION)
}

/// A valid release of `version` signed by `key`.
pub(crate) fn release_parts_of(key: &ReleaseKey, version: &str) -> ReleaseParts {
    let artifacts: Vec<(String, Vec<u8>)> = artifact_names(version)
        .into_iter()
        .map(|(name, _, _)| {
            let source = match name.as_str() {
                "install.ps1" => Some("tools/release/install.ps1"),
                "install.sh" => Some("tools/release/install.sh"),
                "quickstart.sh" => Some("tools/quickstart.sh"),
                _ => None,
            };
            let bytes = source.map_or_else(
                || format!("{name}: acceptance filler\n").into_bytes(),
                |path| {
                    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                        .unwrap_or_else(|error| panic!("{path}: {error}"))
                },
            );
            (name, bytes)
        })
        .collect();
    let entries: Vec<Value> = artifact_names(version)
        .into_iter()
        .zip(&artifacts)
        .map(|((name, purpose, target), (_, bytes))| {
            let mut entry = json!({
                "filename": name,
                "purpose": purpose,
                "target": target,
                "length": bytes.len(),
                "sha256": sha256_hex(bytes),
            });
            if purpose == "client-kit" {
                entry["members"] = json!([]);
            }
            entry
        })
        .collect();
    let manifest = json!({
        "schema_version": 1,
        "version": version,
        "commit": FIXTURE_COMMIT,
        "published_at": "2026-09-23T00:00:00Z",
        "key_id": key.id(),
        "sha256sums_sha256": sha256_hex(&sha256sums(&artifacts)),
        "artifacts": entries,
    });
    ReleaseParts {
        artifacts,
        manifest,
    }
}

/// Writes a release directory: the artifacts, `SHA256SUMS`, the canonical
/// `release.json` and `release.json.minisig` by `key`. `before_signing`
/// edits the parts (the manifest is signed as edited, so a wrong length or
/// digest there is a signed lie); `after_signing` edits the final file list
/// (name → bytes) just before it is written, which is how a flipped byte, an
/// unlisted file or a bad signature is produced.
pub(crate) fn write_release(
    dir: &Path,
    key: &ReleaseKey,
    before_signing: impl FnOnce(&mut ReleaseParts),
    after_signing: impl FnOnce(&mut Vec<(String, Vec<u8>)>),
) -> PathBuf {
    write_release_of(dir, key, FIXTURE_VERSION, before_signing, after_signing)
}

/// [`write_release`] for a release of `version`.
pub(crate) fn write_release_of(
    dir: &Path,
    key: &ReleaseKey,
    version: &str,
    before_signing: impl FnOnce(&mut ReleaseParts),
    after_signing: impl FnOnce(&mut Vec<(String, Vec<u8>)>),
) -> PathBuf {
    let mut parts = release_parts_of(key, version);
    before_signing(&mut parts);
    let manifest = canonical(&parts.manifest);
    let mut files = parts.artifacts.clone();
    files.push(("SHA256SUMS".into(), sha256sums(&parts.artifacts)));
    files.push(("release.json.minisig".into(), key.sign(&manifest)));
    files.push(("release.json".into(), manifest));
    after_signing(&mut files);
    std::fs::create_dir_all(dir).expect("release directory");
    for (name, bytes) in files {
        std::fs::write(dir.join(&name), bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    dir.to_path_buf()
}

/// A local TLS release origin serving `directory`, including its `latest`
/// redirect. The returned CA file is for curl and `--tls-ca`.
pub(crate) async fn serve_release(
    directory: &Path,
    host: &str,
    version: &str,
) -> (String, PathBuf) {
    use http::Request;
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    let bind = if host == "localhost" {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    };
    let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
    let port = listener.local_addr().expect("release host address").port();
    let tls = directory
        .parent()
        .expect("release parent")
        .join(format!("release-host-{port}"));
    std::fs::create_dir_all(&tls).expect("release TLS directory");

    let ca_key = rcgen::KeyPair::generate().expect("release CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "jaynshare release test CA");
    let ca = ca_params.self_signed(&ca_key).expect("release CA");
    let leaf_key = rcgen::KeyPair::generate().expect("release leaf key");
    let mut leaf_params =
        rcgen::CertificateParams::new(vec![host.to_owned()]).expect("release leaf params");
    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("release leaf");
    let ca_file = tls.join("ca.pem");
    let cert_file = tls.join("cert.pem");
    let key_file = tls.join("key.pem");
    std::fs::write(&ca_file, ca.pem()).expect("release CA file");
    std::fs::write(&cert_file, format!("{}{}", leaf.pem(), ca.pem()))
        .expect("release certificate chain");
    std::fs::write(&key_file, leaf_key.serialize_pem()).expect("release key file");

    let acceptor = release_acceptor(&cert_file, &key_file);
    let directory = directory.to_path_buf();
    let host = host.to_owned();
    let origin = format!("https://{host}:{port}");
    let version = version.to_owned();
    tokio::spawn(async move {
        loop {
            let Ok((plain, _)) = listener.accept().await else {
                return;
            };
            let Ok(stream) = acceptor.accept(plain).await else {
                continue;
            };
            let directory = directory.clone();
            let host = host.clone();
            let version = version.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<_>| {
                    let directory = directory.clone();
                    let host = host.clone();
                    let version = version.clone();
                    async move {
                        let path = request.uri().path();
                        let prefix = format!("/v{version}/");
                        let mut response = http::Response::builder();
                        let bytes = if path == "/latest" {
                            response = response.status(http::StatusCode::FOUND).header(
                                http::header::LOCATION,
                                format!("https://{host}:{port}/releases/tag/v{version}"),
                            );
                            Vec::new()
                        } else if path == format!("/releases/tag/v{version}") {
                            Vec::new()
                        } else if let Some(name) = path.strip_prefix(&prefix) {
                            if name.contains('/') {
                                response = response.status(http::StatusCode::NOT_FOUND);
                                Vec::new()
                            } else {
                                match std::fs::read(directory.join(name)) {
                                    Ok(bytes) => bytes,
                                    Err(_) => {
                                        response = response.status(http::StatusCode::NOT_FOUND);
                                        Vec::new()
                                    }
                                }
                            }
                        } else {
                            response = response.status(http::StatusCode::NOT_FOUND);
                            Vec::new()
                        };
                        Ok::<_, std::convert::Infallible>(
                            response
                                .body(Full::new(Bytes::from(bytes)))
                                .expect("release response"),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (origin, ca_file)
}

fn release_acceptor(cert: &Path, key: &Path) -> tokio_rustls::TlsAcceptor {
    use rustls_pki_types::pem::PemObject;

    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key).expect("release key parses");
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(cert)
        .expect("release certificate")
        .collect::<Result<_, _>>()
        .expect("release certificate parses");
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("the release pair loads");
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
}

// A real platform archive (part C)

/// the platform archive for a Linux or macOS `target`: a `.tar.gz` whose
/// entries are rooted in `jaynshare-<version>-<target>/` and are exactly the
/// executable (mode 0755), `LICENSE`, `NOTICE.md` and a README naming the
/// version, target and verification procedure.
pub(crate) fn platform_archive(version: &str, target: &str, executable: &[u8]) -> Vec<u8> {
    let root = format!("jaynshare-{version}-{target}");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = format!(
        "jaynshare {version} for {target}.\nVerify the release with `jaynshare release verify <dir>` before running it.\n"
    );
    let files: Vec<(&str, Vec<u8>, u32)> = vec![
        ("jaynshare", executable.to_vec(), 0o755),
        (
            "LICENSE",
            std::fs::read(repository.join("LICENSE")).expect("LICENSE"),
            0o644,
        ),
        (
            "NOTICE.md",
            std::fs::read(repository.join("NOTICE.md")).expect("NOTICE.md"),
            0o644,
        ),
        ("README.txt", readme.into_bytes(), 0o644),
    ];
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(encoder);
    let mut directory = tar::Header::new_gnu();
    directory.set_entry_type(tar::EntryType::Directory);
    directory.set_mode(0o755);
    directory.set_size(0);
    directory.set_mtime(0);
    archive
        .append_data(&mut directory, format!("{root}/"), std::io::empty())
        .expect("archive root");
    for (name, bytes, mode) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_mtime(0);
        archive
            .append_data(&mut header, format!("{root}/{name}"), bytes.as_slice())
            .expect("archive member");
    }
    archive.into_inner().expect("tar").finish().expect("gzip")
}

/// Replaces `target`'s platform archive in `parts` by a real one around
/// `executable`, and its manifest entry's length and digest with it, before
/// signing (so the release stays valid).
pub(crate) fn with_platform_archive(parts: &mut ReleaseParts, target: &str, executable: &[u8]) {
    let version = parts.manifest["version"]
        .as_str()
        .expect("version")
        .to_string();
    let bytes = platform_archive(&version, target, executable);
    let name = format!("jaynshare-{version}-{target}.tar.gz");
    let slot = parts
        .artifacts
        .iter_mut()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("no artifact {name}"));
    slot.1 = bytes.clone();
    let entry = parts.manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts")
        .iter_mut()
        .find(|e| e["filename"] == json!(name))
        .expect("the artifact's manifest entry");
    entry["length"] = json!(bytes.len());
    entry["sha256"] = json!(sha256_hex(&bytes));
    parts.manifest["sha256sums_sha256"] = json!(sha256_hex(&sha256sums(&parts.artifacts)));
}
