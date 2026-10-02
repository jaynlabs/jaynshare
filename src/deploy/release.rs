//! The release set, `release verify` and
//! `release fetch <version>` (the explicit release-host contact, which
//! then verifies the fetched set).
//!
//! The verify order: the manifest signature against the active key, then
//! `release.json` against `SHA256SUMS`, then each artifact's length and
//! digest. The first failure stops the verification and names the artifact
//! and the check; nothing after it runs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::Value;

use super::result::{Check, DeployResult};
use crate::bundle::{PinnedKey, canonical_json, sha256_hex};

/// The official release origin; version `<v>` lives below
/// `v<v>/`, so an asset is `<origin>/v<version>/<artifact>`.
pub const OFFICIAL_ORIGIN: &str = "https://github.com/jaynlabs/jaynshare/releases/download";

/// The hosts the official origin redirects an asset download to.
const OFFICIAL_ASSET_HOSTS: [&str; 2] = [
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];

/// Exactly the five release targets.
pub const TARGETS: [&str; 5] = [
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

const BOOTSTRAPS: [&str; 3] = ["install.ps1", "install.sh", "quickstart.sh"];

/// The release key a fresh installation trusts, embedded in
/// the verifier. Its fingerprint is printed in the release README and the
/// install documentation.
const EMBEDDED_KEY: &[u8] = include_bytes!("../../deploy/release-key.pub");

/// The per-file request deadline: the control verbs' 30 s applies
/// here too.
const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The platform archive's file name for `version` and `target`.
fn archive_name(version: &str, target: &str) -> String {
    let extension = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("jaynshare-{version}-{target}.{extension}")
}

fn client_kit_name(version: &str) -> String {
    format!("jaynshare-{version}-client-kit.zip")
}

/// `--target`'s default: the target triple this machine runs, from
/// the OS/ARCH pair the five targets cover.
pub fn native_target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        // Unsupported client platforms have no release target.
        _ => "unknown",
    }
}

/// `release fetch`'s origin — `release_origin`, else the official
/// one. A mirror must be `https://` with no user information, query or
/// fragment (see `--release-origin`).
fn origin(release_origin: Option<&str>) -> Result<String, String> {
    let Some(origin) = release_origin else {
        return Ok(OFFICIAL_ORIGIN.to_string());
    };
    // A scheme, a host and no `://`-adjacent surprises: exactly the five
    // `https://` forms the rule accepts. Everything else is `://`-free text
    // (a bare host), a query, a fragment, user information or a scheme that
    // is not https.
    let Some(rest) = origin.strip_prefix("https://") else {
        return Err(format!(
            "--release-origin {origin:?} is not https:// (a mirror is fetched over TLS)"
        ));
    };
    // User information is anything before the first `@` inside the authority;
    // a query or fragment is the first `?` or `#` anywhere after the scheme.
    if rest.split(['?', '#']).next().is_none() || origin.contains(['?', '#']) {
        return Err(format!(
            "--release-origin {origin:?} carries a query or fragment (a mirror names only its root)"
        ));
    }
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') || authority.is_empty() {
        return Err(format!(
            "--release-origin {origin:?} is not an https origin with a plain host"
        ));
    }
    Ok(origin.to_string())
}

/// `release fetch`'s one file: `GET <origin>/v<version>/<name>`, 30 s per
/// step. A status answer carries the status only, never a body, which may
/// carry manifest-adjacent material; the host not answering at all
/// is [`FetchFailure::Unreachable`].
enum FetchFailure {
    /// No HTTP answer: connection refused, TLS rejected, deadline passed.
    Unreachable(String),
    /// An HTTP answer that is not a success, named by file and status.
    Status {
        name: String,
        status: http::StatusCode,
    },
}

impl FetchFailure {
    /// The check this failure lands in (`cli/deploy.rs::exit_row`):
    /// unreachable is the verb's exit-4 row, a status answer is
    /// `release.download` (17).
    fn check(&self) -> Check {
        match self {
            Self::Unreachable(why) => Check::fail("release.unreachable", why.clone()),
            Self::Status { name, status } => Check::fail(
                "release.download",
                format!("{name}: the release host answered {status}"),
            ),
        }
    }
}

type ReleaseClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

async fn get(
    client: &ReleaseClient,
    url: &str,
    name: &str,
) -> Result<http::Response<hyper::body::Incoming>, FetchFailure> {
    let request = http::Request::get(url)
        .body(Full::new(Bytes::new()))
        .map_err(|e| FetchFailure::Unreachable(format!("{name}: {e}")))?;
    tokio::time::timeout(DOWNLOAD_TIMEOUT, client.request(request))
        .await
        .map_err(|_| {
            FetchFailure::Unreachable(format!(
                "{name}: {url} did not answer within {DOWNLOAD_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| FetchFailure::Unreachable(format!("{name}: {url}: {e}")))
}

/// The one redirect `download` follows: https to the origin's own host or,
/// from the official origin, to GitHub's asset hosts. Anywhere else would be
/// a connection the operator cannot explain (SEC-25).
fn redirect_target(origin: &str, location: &str) -> Option<String> {
    let origin_uri: http::Uri = origin.parse().ok()?;
    let target: http::Uri = location.parse().ok()?;
    let host = target.authority()?.as_str();
    let own_host = origin_uri.authority().map(|a| a.as_str()) == Some(host);
    let asset_host = origin == OFFICIAL_ORIGIN && OFFICIAL_ASSET_HOSTS.contains(&host);
    (target.scheme_str() == Some("https") && (own_host || asset_host)).then(|| location.to_string())
}

async fn download(
    client: &ReleaseClient,
    origin: &str,
    version: &str,
    name: &str,
) -> Result<Vec<u8>, FetchFailure> {
    let mut response = get(client, &format!("{origin}/v{version}/{name}"), name).await?;
    let redirect = response
        .headers()
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .filter(|_| response.status().is_redirection())
        .and_then(|location| redirect_target(origin, location));
    if let Some(target) = redirect {
        response = get(client, &target, name).await?;
    }
    let status = response.status();
    if !status.is_success() {
        return Err(FetchFailure::Status {
            name: name.to_string(),
            status,
        });
    }
    let body = tokio::time::timeout(DOWNLOAD_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| {
            FetchFailure::Unreachable(format!(
                "{name}: the release host did not answer within {DOWNLOAD_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| FetchFailure::Unreachable(format!("{name}: {e}")))?
        .to_bytes();
    Ok(body.to_vec())
}

/// The newest published version: one GET to the origin's `latest` endpoint
/// — the origin with a final `download` path segment replaced by `latest`
/// (GitHub's release page answers 302 with `Location:
/// .../releases/tag/v<semver>`), or `<origin>/latest` when the origin does
/// not end in `download` — reading only the redirect target, never a body
/// (a body could carry manifest-adjacent material).
async fn latest_version(client: &ReleaseClient, origin: &str) -> Result<String, FetchFailure> {
    let name = "release latest";
    let url = if origin.ends_with("/download") {
        origin
            .strip_suffix("/download")
            .map(|base| format!("{base}/latest"))
            .unwrap_or_else(|| origin.to_string())
    } else {
        format!("{origin}/latest")
    };
    let response = get(client, &url, name).await?;
    if !response.status().is_redirection() {
        return Err(FetchFailure::Unreachable(format!(
            "{name}: {} did not redirect to a release (status {})",
            url,
            response.status()
        )));
    }
    let location = response
        .headers()
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            FetchFailure::Unreachable(format!("{name}: the redirect names no location"))
        })?;
    // `.../tag/v<semver>`; anything else is refused, never guessed.
    let (_, version) = location.rsplit_once("/tag/v").ok_or_else(|| {
        FetchFailure::Unreachable(format!(
            "{name}: the redirect does not name a release tag: {location}"
        ))
    })?;
    let version = version.split(['?', '#']).next().unwrap_or(version);
    if version.is_empty()
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
    {
        return Err(FetchFailure::Unreachable(format!(
            "{name}: the redirect names no plain version: {version}"
        )));
    }
    Ok(version.to_string())
}

/// The newest published version from the origin (or `--release-origin`
/// mirror), for `release latest` and `client update`'s no-argument form.
pub async fn newest_version(
    release_origin: Option<&str>,
    tls_ca: Option<&Path>,
) -> Result<String, String> {
    let origin = origin(release_origin)?;
    let client = crate::cli::http_client(tls_ca).map_err(|failure| {
        failure.error["message"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    })?;
    latest_version(&client, &origin)
        .await
        .map_err(|failure| match failure {
            FetchFailure::Unreachable(why) => why,
            FetchFailure::Status { name, status } => {
                format!("{name}: the release host answered {status}")
            }
        })
}

/// The client kit of one version, fetched from the origin to a private
/// temporary file (the kit is `update`'s one explicit download).
/// The caller deletes the file when done.
pub async fn fetch_client_kit(
    version: &str,
    release_origin: Option<&str>,
    tls_ca: Option<&Path>,
) -> Result<std::path::PathBuf, String> {
    let origin = origin(release_origin)?;
    let client = crate::cli::http_client(tls_ca).map_err(|failure| {
        failure.error["message"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    })?;
    let name = client_kit_name(version);
    let bytes =
        download(&client, &origin, version, &name)
            .await
            .map_err(|failure| match failure {
                FetchFailure::Unreachable(why) => why,
                FetchFailure::Status { name, status } => {
                    format!("{name}: the release host answered {status}")
                }
            })?;
    let dir =
        std::env::temp_dir().join(format!("jaynshare-kit-{}-{}", version, std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(&name);
    std::fs::write(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(path)
}

/// `release fetch <version> --out <dir> [--target <rust-target>]
/// [--release-origin <https-origin>]`: `version`'s release set, the
/// target's archive and the client kit, from the official or a mirror
/// origin, then verified.
pub async fn fetch(
    version: &str,
    out: &Path,
    target: Option<&str>,
    release_origin: Option<&str>,
    tls_ca: Option<&Path>,
) -> DeployResult {
    let mut result = DeployResult::new("release fetch");
    let origin = match origin(release_origin) {
        Ok(origin) => origin,
        Err(why) => {
            result.checks.push(Check::fail("release.origin", why));
            return result;
        }
    };
    let target = target
        .map(str::to_owned)
        .unwrap_or_else(|| native_target().to_owned());
    let archive = archive_name(version, &target);
    let kit = client_kit_name(version);
    let client = match crate::cli::http_client(tls_ca) {
        Ok(client) => client,
        Err(failure) => {
            result.checks.push(Check::fail(
                "configuration",
                failure.error["message"].as_str().unwrap_or_default(),
            ));
            return result;
        }
    };
    // An existing non-empty `--out` is a conflict, never a silent overwrite.
    let occupied = out.is_dir()
        && std::fs::read_dir(out)
            .map(|entries| entries.count() > 0)
            .unwrap_or(false);
    if occupied {
        result.checks.push(Check::fail(
            "conflict.out",
            format!(
                "{} already holds files; the release set is written into an empty directory",
                out.display()
            ),
        ));
        return result;
    }
    if let Err(why) = crate::state::ensure_private_dir(out) {
        result.checks.push(Check::fail(
            "release.out",
            format!("{}: {why}", out.display()),
        ));
        return result;
    }
    result.paths.push(out.display().to_string());
    for name in [
        "release.json",
        "release.json.minisig",
        "SHA256SUMS",
        &archive,
        &kit,
    ] {
        match download(&client, &origin, version, name).await {
            Ok(bytes) => {
                if let Err(why) = std::fs::write(out.join(name), &bytes) {
                    result
                        .checks
                        .push(Check::fail("release.download", format!("{name}: {why}")));
                    return result;
                }
            }
            Err(failure) => {
                result.checks.push(failure.check());
                return result;
            }
        }
    }
    result.checks.extend(verify(out, None).checks);
    result
}

/// `release verify <dir|file> [--key-id <id>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Platform,
    ClientKit,
    Bootstrap,
}

/// One client-kit member binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

/// One artifact entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub filename: String,
    pub purpose: Purpose,
    /// The Rust target of a platform archive; `None` for other artifacts.
    pub target: Option<String>,
    pub length: u64,
    pub sha256: String,
    /// The client kit's members; empty for other artifacts.
    pub members: Vec<Member>,
}

/// `release.json`, schema version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub version: String,
    pub commit: String,
    /// RFC 3339 UTC.
    pub published_at: String,
    /// The signing key's minisign key id, 16 uppercase hexadecimal digits.
    pub key_id: String,
    /// The next key's id, present only in an overlap release.
    pub next_key_id: Option<String>,
    /// The SHA-256 of `SHA256SUMS`'s bytes.
    pub sha256sums_sha256: String,
    pub artifacts: Vec<Artifact>,
}

impl ReleaseManifest {
    /// Parses `release.json`. Field names: `schema_version` (1), `version`,
    /// `commit`, `published_at`, `key_id`, `next_key_id` (optional),
    /// `sha256sums_sha256`, `artifacts[] { filename, purpose, target,
    /// length, sha256, members[] { path, length, sha256 } }`.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("release.json: not JSON: {e}"))?;
        if value["schema_version"] != 1 {
            return Err("release.json: schema_version is not 1".into());
        }
        let text = |object: &Value, key: &str| -> Result<String, String> {
            object[key]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("release.json: `{key}` is missing or not a string"))
        };
        let number = |object: &Value, key: &str| -> Result<u64, String> {
            object[key]
                .as_u64()
                .ok_or_else(|| format!("release.json: `{key}` is missing or not an integer"))
        };
        let mut artifacts = Vec::new();
        for entry in value["artifacts"]
            .as_array()
            .ok_or("release.json: `artifacts` is missing or not an array")?
        {
            let purpose = match entry["purpose"].as_str() {
                Some("platform") => Purpose::Platform,
                Some("client-kit") => Purpose::ClientKit,
                Some("bootstrap") => Purpose::Bootstrap,
                _ => return Err("release.json: an artifact has an unknown `purpose`".into()),
            };
            let mut members = Vec::new();
            if let Some(list) = entry["members"].as_array() {
                for member in list {
                    members.push(Member {
                        path: text(member, "path")?,
                        length: number(member, "length")?,
                        sha256: text(member, "sha256")?,
                    });
                }
            }
            artifacts.push(Artifact {
                filename: text(entry, "filename")?,
                purpose,
                target: entry["target"].as_str().map(str::to_string),
                length: number(entry, "length")?,
                sha256: text(entry, "sha256")?,
                members,
            });
        }
        Ok(Self {
            version: text(&value, "version")?,
            commit: text(&value, "commit")?,
            published_at: text(&value, "published_at")?,
            key_id: text(&value, "key_id")?,
            next_key_id: value["next_key_id"].as_str().map(str::to_string),
            sha256sums_sha256: text(&value, "sha256sums_sha256")?,
            artifacts,
        })
    }
}

/// A release directory as `release verify` reads it: every regular file at
/// its top level by name. A file argument selects that one artifact from its
/// directory (the release set sits beside it).
pub struct ReleaseDir {
    pub root: PathBuf,
    pub files: BTreeMap<String, Vec<u8>>,
    pub selected: Option<String>,
}

pub fn read_release(target: &Path) -> Result<ReleaseDir, String> {
    let (root, selected) = if target.is_dir() {
        (target.to_path_buf(), None)
    } else {
        let name = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{}: not a file name", target.display()))?
            .to_string();
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        (parent.to_path_buf(), Some(name))
    };
    let entries =
        std::fs::read_dir(&root).map_err(|e| format!("{}: cannot read: {e}", root.display()))?;
    let mut files = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", root.display()))?;
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        if !kind.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let bytes =
            std::fs::read(entry.path()).map_err(|e| format!("{}: {e}", entry.path().display()))?;
        files.insert(name, bytes);
    }
    if let Some(name) = &selected
        && !files.contains_key(name)
    {
        return Err(format!("{}: not a regular file", target.display()));
    }
    Ok(ReleaseDir {
        root,
        files,
        selected,
    })
}

/// The active key. A present `<config root>/release.pub` is the
/// single active-key store and replaces the embedded key; an invalid file is
/// a verification failure, never a fallback.
pub fn active_key() -> Result<PinnedKey, String> {
    let path = crate::config::platform::release_key_file();
    match std::fs::read(&path) {
        Ok(bytes) => crate::bundle::parse_public_key_file(&bytes)
            .ok_or_else(|| format!("{}: not a minisign public key file", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            crate::bundle::parse_public_key_file(EMBEDDED_KEY)
                .ok_or_else(|| "the embedded release key does not parse".to_string())
        }
        Err(e) => Err(format!(
            "{}: cannot read the release key: {e}",
            path.display()
        )),
    }
}

/// Step 1: `release.json.minisig` over the exact bytes of
/// `release.json` under the active key. With `key_id` (a rotation overlap,
/// the `--key-id` flag): the manifest names that next key id, and
/// `release.json.<key_id>.minisig` verifies under the next key's public file
/// `release-key-<key_id>.pub`, which the overlap release carries — then the
/// active-key store is atomically replaced with it (the store holds one key).
pub fn verify_signature(release: &ReleaseDir, key: &PinnedKey, key_id: Option<&str>) -> Check {
    let (Some(manifest), Some(signature)) = (
        release.files.get("release.json"),
        release.files.get("release.json.minisig"),
    ) else {
        return Check::fail(
            "signature",
            "release.json or release.json.minisig is missing",
        );
    };
    if let Err(why) = crate::bundle::verify_release_signature(manifest, signature, key) {
        return Check::fail("signature", why);
    }
    let Some(next_id) = key_id else {
        return Check::pass(
            "signature",
            "release.json.minisig verifies under the active key",
        );
    };
    if let Err(why) =
        next_key_check(release, manifest, next_id).and_then(|bytes| admit_next_key(&bytes))
    {
        return Check::fail("signature", why);
    }
    Check::pass(
        "signature",
        format!("the overlap verifies under the active key and the next key {next_id} is admitted"),
    )
}

/// The next key's file verifies the overlap manifest that names it.
fn next_key_check(release: &ReleaseDir, manifest: &[u8], next_id: &str) -> Result<Vec<u8>, String> {
    let manifest_value: Value =
        serde_json::from_slice(manifest).map_err(|why| format!("release.json: {why}"))?;
    if manifest_value["next_key_id"].as_str() != Some(next_id) {
        return Err(format!(
            "release.json: next_key_id is {:?}, not the requested key id {next_id}",
            manifest_value["next_key_id"].as_str()
        ));
    }
    let name = format!("release-key-{next_id}.pub");
    let public_file = release
        .files
        .get(&name)
        .ok_or_else(|| format!("the overlap release is missing {name:?}"))?;
    let next_key = crate::bundle::parse_public_key_file(public_file)
        .ok_or_else(|| format!("{name}: not a minisign public key file"))?;
    let next_hex: String = next_key
        .key_id()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    if next_hex != next_id {
        return Err(format!("{name}: key id {next_hex} is not {next_id}"));
    }
    let signature_name = format!("release.json.{next_id}.minisig");
    let signature = release
        .files
        .get(&signature_name)
        .ok_or_else(|| format!("the overlap release is missing {signature_name:?}"))?;
    crate::bundle::verify_release_signature(manifest, signature, &next_key)
        .map_err(|why| format!("{signature_name}: {why}"))?;
    Ok(public_file.clone())
}

/// The active-key store holds exactly one key, so admitting the
/// next key atomically replaces `<config root>/release.pub` (temp file, then
/// rename, mode 0644).
pub fn admit_next_key(public_file: &[u8]) -> Result<(), String> {
    if crate::bundle::parse_public_key_file(public_file).is_none() {
        return Err("the next key's public file is not a minisign public key file".into());
    }
    store_active_key(&crate::config::platform::release_key_file(), public_file)
}

/// [`admit_next_key`]'s write: a host still on the embedded key has no
/// config root yet, so the store's directory is created private
/// first.
fn store_active_key(path: &Path, public_file: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        crate::state::ensure_private_dir(dir)
            .map_err(|e| format!("{}: cannot create the key store: {e}", dir.display()))?;
    }
    let temp = path.with_extension("pub.new");
    std::fs::write(&temp, public_file)
        .map_err(|e| format!("{}: cannot write the next key: {e}", temp.display()))?;
    #[cfg(unix)]
    if let Err(e) =
        std::fs::set_permissions(&temp, std::os::unix::fs::PermissionsExt::from_mode(0o644))
    {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("{}: cannot set the mode: {e}", temp.display()));
    }
    std::fs::rename(&temp, path)
        .map_err(|e| format!("{}: cannot replace the active key: {e}", path.display()))?;
    Ok(())
}

/// Steps 2–3: `SHA256SUMS` agrees with the manifest (digest,
/// mapping, bytewise order, line grammar, no duplicates), no unlisted file,
/// and each selected artifact's length and digest. One check per step, in
/// that order, stopping at the first failure.
pub fn verify_manifest(release: &ReleaseDir, manifest: &ReleaseManifest) -> Vec<Check> {
    let mut checks = Vec::new();

    // `release.json`'s bytes equal the canonical form of their parse.
    let canonical = release
        .files
        .get("release.json")
        .map(|bytes| {
            serde_json::from_slice::<Value>(bytes)
                .map(|value| canonical_json(&value).into_bytes() == bytes.as_slice())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if !canonical {
        checks.push(Check::fail(
            "release.canonical",
            "release.json is not canonical RFC 8785 JSON",
        ));
        return checks;
    }
    checks.push(Check::pass(
        "release.canonical",
        "release.json is canonical RFC 8785 JSON",
    ));

    // `SHA256SUMS` agrees with the manifest.
    let Some(sums) = release.files.get("SHA256SUMS") else {
        checks.push(Check::fail("release.sums", "SHA256SUMS is missing"));
        return checks;
    };
    if sha256_hex(sums) != manifest.sha256sums_sha256 {
        checks.push(Check::fail(
            "release.sums",
            "SHA256SUMS's digest does not match release.json's sha256sums_sha256",
        ));
        return checks;
    }
    let entries = match sums_entries(sums) {
        Ok(entries) => entries,
        Err(why) => {
            checks.push(Check::fail("release.sums", why));
            return checks;
        }
    };
    let observed_names: std::collections::BTreeSet<&str> =
        entries.iter().map(|(name, _)| name.as_str()).collect();
    let expected_names: std::collections::BTreeSet<&str> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.filename.as_str())
        .collect();
    if observed_names != expected_names {
        checks.push(Check::fail(
            "release.sums",
            "SHA256SUMS does not name exactly release.json's artifacts",
        ));
        return checks;
    }
    let sums_digests: BTreeMap<String, String> = entries.into_iter().collect();
    checks.push(Check::pass(
        "release.sums",
        "SHA256SUMS matches release.json: digest, line grammar, file-name order and artifact names",
    ));

    // The artifact file names of this version.
    if let Some((name, _)) = manifest.artifacts.iter().enumerate().find_map(|(i, a)| {
        manifest.artifacts[..i]
            .iter()
            .find(|other| other.filename == a.filename)
            .map(|_| (a.filename.clone(), ()))
    }) {
        checks.push(Check::fail(
            "release.names",
            format!("{name}: release.json lists it twice"),
        ));
        return checks;
    }
    let client_kit = client_kit_name(&manifest.version);
    for artifact in &manifest.artifacts {
        let expected = match artifact.purpose {
            Purpose::Platform => {
                let Some(target) = artifact.target.as_deref() else {
                    checks.push(Check::fail(
                        "release.names",
                        format!("{}: a platform archive without a target", artifact.filename),
                    ));
                    return checks;
                };
                if !TARGETS.contains(&target) {
                    checks.push(Check::fail(
                        "release.names",
                        format!(
                            "{}: {target} is not one of the release's five targets",
                            artifact.filename
                        ),
                    ));
                    return checks;
                }
                let extension = if target.contains("windows") {
                    "zip"
                } else {
                    "tar.gz"
                };
                format!("jaynshare-{}-{target}.{extension}", manifest.version)
            }
            Purpose::ClientKit => client_kit.clone(),
            Purpose::Bootstrap => {
                if !BOOTSTRAPS.contains(&artifact.filename.as_str()) {
                    checks.push(Check::fail(
                        "release.names",
                        format!("{}: is not a bootstrap file name", artifact.filename),
                    ));
                    return checks;
                }
                artifact.filename.clone()
            }
        };
        if artifact.filename != expected {
            checks.push(Check::fail(
                "release.names",
                format!(
                    "{}: is not the release's file name ({expected})",
                    artifact.filename
                ),
            ));
            return checks;
        }
    }
    for target in TARGETS {
        let count = manifest
            .artifacts
            .iter()
            .filter(|a| a.purpose == Purpose::Platform && a.target.as_deref() == Some(target))
            .count();
        if count != 1 {
            checks.push(Check::fail(
                "release.names",
                format!(
                    "{target}: {count} platform archives in release.json, exactly one required"
                ),
            ));
            return checks;
        }
    }
    let client_kits = manifest
        .artifacts
        .iter()
        .filter(|a| a.purpose == Purpose::ClientKit)
        .count();
    if client_kits != 1 {
        checks.push(Check::fail(
            "release.names",
            format!("{client_kits} client kit archives in release.json, exactly one required"),
        ));
        return checks;
    }
    for bootstrap in BOOTSTRAPS {
        let count = manifest
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.purpose == Purpose::Bootstrap && artifact.filename == bootstrap
            })
            .count();
        if count != 1 {
            checks.push(Check::fail(
                "release.names",
                format!("{bootstrap}: {count} bootstrap artifacts, exactly one required"),
            ));
            return checks;
        }
    }
    checks.push(Check::pass(
        "release.names",
        "every artifact file name follows the release layout: one archive per target, one client kit and three bootstraps",
    ));

    // Every file present is listed. The overlap adds the next
    // key's signature and its public-key file, named by exactly 16 uppercase
    // hexadecimal digits.
    let key_id = |id: &str| {
        id.len() == 16
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    };
    let overlap = |name: &str| {
        name.strip_prefix("release.json.")
            .and_then(|rest| rest.strip_suffix(".minisig"))
            .is_some_and(key_id)
            || name
                .strip_prefix("release-key-")
                .and_then(|rest| rest.strip_suffix(".pub"))
                .is_some_and(key_id)
    };
    for name in release.files.keys() {
        if name == "release.json"
            || name == "release.json.minisig"
            || name == "SHA256SUMS"
            || overlap(name)
            || manifest.artifacts.iter().any(|a| a.filename == *name)
        {
            continue;
        }
        checks.push(Check::fail(
            "release.unlisted",
            format!("{name} is not a release artifact or release-metadata file"),
        ));
        return checks;
    }
    checks.push(Check::pass(
        "release.unlisted",
        "every file in the directory is a release artifact or release metadata",
    ));

    // Each present artifact's length and digest. A file argument
    // verifies that one artifact; a directory skips the artifacts it does not
    // hold, since a release directory may hold only what one machine needs.
    let selected: Vec<&Artifact> = match release.selected.as_deref() {
        Some(name) => manifest
            .artifacts
            .iter()
            .filter(|a| a.filename == name)
            .collect(),
        None => manifest.artifacts.iter().collect(),
    };
    if let Some(name) = release.selected.as_deref()
        && selected.is_empty()
    {
        checks.push(Check::fail(
            "release.artifact",
            format!("{name} is not an artifact named by release.json"),
        ));
        return checks;
    }
    let mut verified = 0usize;
    for artifact in &selected {
        let Some(bytes) = release.files.get(&artifact.filename) else {
            if release.selected.as_deref() == Some(artifact.filename.as_str()) {
                checks.push(Check::fail(
                    "release.artifact",
                    format!(
                        "{}: selected for verification but absent from the directory",
                        artifact.filename
                    ),
                ));
                return checks;
            }
            continue;
        };
        if bytes.len() as u64 != artifact.length {
            checks.push(Check::fail(
                "release.artifact",
                format!(
                    "{}: the byte length differs from release.json",
                    artifact.filename
                ),
            ));
            return checks;
        }
        if sha256_hex(bytes) != artifact.sha256 {
            checks.push(Check::fail(
                "release.artifact",
                format!(
                    "{}: the SHA-256 digest differs from release.json",
                    artifact.filename
                ),
            ));
            return checks;
        }
        if sums_digests
            .get(&artifact.filename)
            .is_some_and(|sums_digest| *sums_digest != artifact.sha256)
        {
            checks.push(Check::fail(
                "release.artifact",
                format!(
                    "{}: the SHA-256 digest differs between release.json and SHA256SUMS",
                    artifact.filename
                ),
            ));
            return checks;
        }
        verified += 1;
    }
    let noun = if verified == 1 {
        "artifact"
    } else {
        "artifacts"
    };
    checks.push(Check::pass(
        "release.artifact",
        format!("{verified} {noun} verified: byte length and SHA-256 digest match release.json"),
    ));
    checks
}

/// One parsed `SHA256SUMS` line: `(file name, digest)`. Its grammar:
/// 64 lowercase hex digits, two spaces, a bare file name, LF; the lines are
/// in bytewise file-name order and no name repeats.
fn sums_entries(sums: &[u8]) -> Result<Vec<(String, String)>, String> {
    let text = std::str::from_utf8(sums).map_err(|_| "SHA256SUMS is not UTF-8".to_string())?;
    let Some(body) = text.strip_suffix('\n') else {
        return Err("SHA256SUMS does not end in LF".into());
    };
    let mut entries = Vec::new();
    let mut previous = "";
    for line in body.lines() {
        let bytes = line.as_bytes();
        if bytes.len() < 67
            || !bytes[..64]
                .iter()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            || bytes[64] != b' '
            || bytes[65] != b' '
        {
            return Err("a SHA256SUMS line is not `<64 lowercase hex digits>  <file name>`".into());
        }
        let name = &line[66..];
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            return Err(format!(
                "the SHA256SUMS line for {name:?} is not a bare file name"
            ));
        }
        if previous.as_bytes() >= name.as_bytes() {
            return Err(
                "SHA256SUMS's lines are not in bytewise file-name order (a name may repeat)".into(),
            );
        }
        previous = name;
        entries.push((name.to_string(), line[..64].to_string()));
    }
    Ok(entries)
}

/// `release verify <dir|file> [--key-id <id>]`.
pub fn verify(target: &Path, key_id: Option<&str>) -> DeployResult {
    let mut result = DeployResult::new("release verify");
    let release = match read_release(target) {
        Ok(release) => release,
        Err(why) => {
            result.checks.push(Check::fail("read", why));
            return result;
        }
    };
    result.paths.push(release.root.display().to_string());
    let key = match active_key() {
        Ok(key) => key,
        Err(why) => {
            result.checks.push(Check::fail("key", why));
            return result;
        }
    };
    let signature = verify_signature(&release, &key, key_id);
    let signed = signature.passed;
    result.checks.push(signature);
    if !signed {
        return result;
    }
    let manifest = match ReleaseManifest::parse(&release.files["release.json"]) {
        Ok(manifest) => manifest,
        Err(why) => {
            result.checks.push(Check::fail("manifest", why));
            return result;
        }
    };
    result.version = Some(manifest.version.clone());
    result.commit = Some(manifest.commit.clone());
    result.checks.extend(verify_manifest(&release, &manifest));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_origin_official_when_absent() {
        assert_eq!(
            origin(None).as_deref(),
            Ok(OFFICIAL_ORIGIN),
            "no --release-origin means the official origin"
        );
    }

    #[test]
    fn release_origin_accepts_a_plain_https_mirror() {
        assert_eq!(
            origin(Some("https://mirror.example.com/r")).as_deref(),
            Ok("https://mirror.example.com/r")
        );
    }

    #[test]
    fn release_origin_rejects_the_forbidden_forms() {
        for bad in [
            "http://mirror.example.com/r",
            "https://user@localhost:1/r",
            "https://user:secret@localhost:1",
            "https://localhost:1/r?y",
            "https://localhost:1/r#f",
            "ftp://localhost:1/r",
            "not a url at all",
        ] {
            assert!(
                origin(Some(bad)).is_err(),
                "the origin rule must reject {bad:?}"
            );
        }
    }

    #[test]
    fn the_official_origin_redirects_to_the_github_asset_hosts() {
        for host in OFFICIAL_ASSET_HOSTS {
            let location = format!("https://{host}/github-production-release-asset/1?sig=x");
            assert_eq!(
                redirect_target(OFFICIAL_ORIGIN, &location),
                Some(location.clone())
            );
        }
    }

    #[test]
    fn a_mirror_redirects_within_its_own_host() {
        let location = "https://localhost:1/assets/release.json";
        assert_eq!(
            redirect_target("https://localhost:1/r", location),
            Some(location.to_string())
        );
    }

    #[test]
    fn a_redirect_anywhere_else_is_not_followed() {
        for (origin, location) in [
            (OFFICIAL_ORIGIN, "https://evil.example.com/release.json"),
            (
                OFFICIAL_ORIGIN,
                "http://release-assets.githubusercontent.com/release.json",
            ),
            (
                OFFICIAL_ORIGIN,
                "https://release-assets.githubusercontent.com@evil.example.com/x",
            ),
            (
                OFFICIAL_ORIGIN,
                "https://release-assets.githubusercontent.com:8443/x",
            ),
            (OFFICIAL_ORIGIN, "/relative/release.json"),
            (
                "https://localhost:1",
                "https://release-assets.githubusercontent.com/x",
            ),
            ("https://localhost:1", "https://localhost:2/x"),
            ("https://localhost:1", "https://user@localhost:1/x"),
        ] {
            assert_eq!(
                redirect_target(origin, location),
                None,
                "{origin} must not follow {location}"
            );
        }
    }

    #[test]
    fn release_archive_names_the_five_targets() {
        assert_eq!(
            archive_name("1.2.3", "x86_64-unknown-linux-musl"),
            "jaynshare-1.2.3-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            archive_name("1.2.3", "x86_64-pc-windows-msvc"),
            "jaynshare-1.2.3-x86_64-pc-windows-msvc.zip"
        );
    }

    use serde_json::json;

    const VERSION: &str = "1.4.2";
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn filler(name: &str) -> Vec<u8> {
        format!("{name}: test bytes\n").into_bytes()
    }

    fn sums_bytes(artifacts: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut sorted: Vec<&(String, Vec<u8>)> = artifacts.iter().collect();
        sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        sorted
            .iter()
            .flat_map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)).into_bytes())
            .collect()
    }

    struct Parts {
        artifacts: Vec<(String, Vec<u8>)>,
        manifest: Value,
    }

    fn parts() -> Parts {
        let mut artifacts = Vec::new();
        let mut entries = Vec::new();
        for target in TARGETS {
            let extension = if target.contains("windows") {
                "zip"
            } else {
                "tar.gz"
            };
            let name = format!("jaynshare-{VERSION}-{target}.{extension}");
            let bytes = filler(&name);
            entries.push(json!({
                "filename": name,
                "purpose": "platform",
                "target": target,
                "length": bytes.len(),
                "sha256": sha256_hex(&bytes),
            }));
            artifacts.push((name, bytes));
        }
        let name = format!("jaynshare-{VERSION}-client-kit.zip");
        let bytes = filler(&name);
        entries.push(json!({
            "filename": name,
            "purpose": "client-kit",
            "length": bytes.len(),
            "sha256": sha256_hex(&bytes),
        }));
        artifacts.push((name, bytes));
        for name in BOOTSTRAPS {
            let bytes = filler(name);
            entries.push(json!({
                "filename": name,
                "purpose": "bootstrap",
                "length": bytes.len(),
                "sha256": sha256_hex(&bytes),
            }));
            artifacts.push((name.to_string(), bytes));
        }
        let manifest = json!({
            "schema_version": 1,
            "version": VERSION,
            "commit": COMMIT,
            "published_at": "2026-01-01T00:00:00Z",
            "key_id": "0123456789ABCDEF",
            "sha256sums_sha256": sha256_hex(&sums_bytes(&artifacts)),
            "artifacts": entries,
        });
        Parts {
            artifacts,
            manifest,
        }
    }

    fn files_of(parts: &Parts) -> Vec<(String, Vec<u8>)> {
        let mut files = parts.artifacts.clone();
        files.push(("SHA256SUMS".into(), sums_bytes(&parts.artifacts)));
        files.push((
            "release.json".into(),
            canonical_json(&parts.manifest).into_bytes(),
        ));
        files.push(("release.json.minisig".into(), b"sig".to_vec()));
        files
    }

    fn dir(files: Vec<(String, Vec<u8>)>, selected: Option<&str>) -> ReleaseDir {
        ReleaseDir {
            root: PathBuf::from("test-release"),
            files: files.into_iter().collect(),
            selected: selected.map(str::to_string),
        }
    }

    fn manifest_of(parts: &Parts) -> ReleaseManifest {
        ReleaseManifest::parse(&canonical_json(&parts.manifest).into_bytes())
            .expect("the test manifest parses")
    }

    fn names(checks: &[Check]) -> Vec<&str> {
        checks.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn a_good_release_passes_every_check() {
        let parts = parts();
        let checks = verify_manifest(&dir(files_of(&parts), None), &manifest_of(&parts));
        assert_eq!(
            names(&checks),
            [
                "release.canonical",
                "release.sums",
                "release.names",
                "release.unlisted",
                "release.artifact"
            ]
        );
        assert!(checks.iter().all(|c| c.passed), "{checks:?}");
        assert!(
            checks[4].message.contains("9 artifacts verified"),
            "{checks:?}"
        );
    }

    #[test]
    fn a_selected_artifact_verifies_alone() {
        let parts = parts();
        let selected = format!("jaynshare-{VERSION}-client-kit.zip");
        let checks = verify_manifest(
            &dir(files_of(&parts), Some(&selected)),
            &manifest_of(&parts),
        );
        assert!(checks.iter().all(|c| c.passed), "{checks:?}");
        assert!(
            checks[4].message.contains("1 artifact verified"),
            "{checks:?}"
        );
    }

    #[test]
    fn a_non_canonical_release_json_fails_first() {
        let parts = parts();
        let mut files = files_of(&parts);
        let pretty = serde_json::to_string_pretty(&parts.manifest).unwrap();
        files.retain(|(name, _)| name != "release.json");
        files.push(("release.json".into(), pretty.into_bytes()));
        let checks = verify_manifest(&dir(files, None), &manifest_of(&parts));
        assert_eq!(checks.len(), 1, "{checks:?}");
        assert_eq!(checks[0].name, "release.canonical");
        assert!(!checks[0].passed);
    }

    #[test]
    fn a_sums_digest_mismatch_stops_before_the_name_checks() {
        let mut parts = parts();
        parts.manifest["sha256sums_sha256"] = json!("0".repeat(64));
        let checks = verify_manifest(&dir(files_of(&parts), None), &manifest_of(&parts));
        assert_eq!(checks.len(), 2, "{checks:?}");
        assert_eq!(checks[1].name, "release.sums");
        assert!(!checks[1].passed);
    }

    #[test]
    fn a_sums_name_mismatch_is_release_sums() {
        let mut parts = parts();
        // SHA256SUMS without one artifact's line, with the manifest's digest
        // of the sums updated, so only the mapping is off.
        let without_last = &parts.artifacts[..parts.artifacts.len() - 1];
        let sums = sums_bytes(without_last);
        parts.manifest["sha256sums_sha256"] = json!(sha256_hex(&sums));
        let mut files = files_of(&parts);
        files.retain(|(name, _)| name != "SHA256SUMS");
        files.push(("SHA256SUMS".into(), sums));
        let checks = verify_manifest(&dir(files, None), &manifest_of(&parts));
        assert_eq!(checks.len(), 2, "{checks:?}");
        assert_eq!(checks[1].name, "release.sums");
        assert!(!checks[1].passed);
    }

    #[test]
    fn a_sums_digest_disagreement_with_the_manifest_is_release_artifact() {
        let mut parts = parts();
        // One sums line's digest corrupted (still grammar-valid), the
        // manifest's digest of the sums updated, so only the per-artifact
        // agreement between release.json and SHA256SUMS is off.
        let mut sums = sums_bytes(&parts.artifacts);
        sums[0] = b'0';
        parts.manifest["sha256sums_sha256"] = json!(sha256_hex(&sums));
        let mut files = files_of(&parts);
        files.retain(|(name, _)| name != "SHA256SUMS");
        files.push(("SHA256SUMS".into(), sums));
        let checks = verify_manifest(&dir(files, None), &manifest_of(&parts));
        assert_eq!(checks.len(), 5, "{checks:?}");
        assert_eq!(checks[4].name, "release.artifact");
        assert!(!checks[4].passed);
        assert!(checks[4].message.contains("differs between"), "{checks:?}");
    }

    #[test]
    fn a_duplicate_artifact_entry_is_release_names() {
        let mut parts = parts();
        let duplicate = parts.manifest["artifacts"][0].clone();
        parts.manifest["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        let checks = verify_manifest(&dir(files_of(&parts), None), &manifest_of(&parts));
        assert_eq!(checks.len(), 3, "{checks:?}");
        assert_eq!(checks[2].name, "release.names");
        assert!(!checks[2].passed);
    }

    #[test]
    fn a_renamed_artifact_is_release_names() {
        let mut parts = parts();
        let old = format!("jaynshare-{VERSION}-x86_64-apple-darwin.tar.gz");
        let new = format!("jaynshare-{VERSION}-x86_64-apple-darwin.tgz");
        for entry in parts.manifest["artifacts"].as_array_mut().unwrap() {
            if entry["filename"] == old.as_str() {
                entry["filename"] = json!(new);
            }
        }
        for (name, _) in parts.artifacts.iter_mut() {
            if *name == old {
                *name = new.clone();
            }
        }
        parts.manifest["sha256sums_sha256"] = json!(sha256_hex(&sums_bytes(&parts.artifacts)));
        let checks = verify_manifest(&dir(files_of(&parts), None), &manifest_of(&parts));
        assert_eq!(checks.len(), 3, "{checks:?}");
        assert_eq!(checks[2].name, "release.names");
        assert!(!checks[2].passed);
    }

    #[test]
    fn an_unlisted_file_is_release_unlisted() {
        let parts = parts();
        let mut files = files_of(&parts);
        files.push(("notes.txt".into(), b"scratch\n".to_vec()));
        let checks = verify_manifest(&dir(files, None), &manifest_of(&parts));
        assert_eq!(checks.len(), 4, "{checks:?}");
        assert_eq!(checks[3].name, "release.unlisted");
        assert!(!checks[3].passed);
        assert!(checks[3].message.contains("notes.txt"), "{checks:?}");
    }

    /// The first rotation on a host that still
    /// uses the embedded key has no config root to write the store into.
    #[test]
    fn the_first_admitted_key_creates_a_private_store() {
        let root = std::env::temp_dir().join(format!("jaynshare-keystore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join(".config").join("jaynshare").join("release.pub");
        store_active_key(&path, b"untrusted comment: k\nkey\n").expect("stored");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"untrusted comment: k\nkey\n"
        );
        assert!(!path.with_extension("pub.new").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(path.parent().unwrap()), 0o700);
            assert_eq!(mode(&path), 0o644);
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn only_uppercase_16_digit_overlap_files_go_unlisted() {
        let parts = parts();
        for (name, admitted) in [
            ("release.json.0123456789ABCDEF.minisig", true),
            ("release-key-0123456789ABCDEF.pub", true),
            ("release.json.0123456789abcdef.minisig", false),
            ("release-key-0123456789abcdef.pub", false),
            ("release-key-0123456789ABCDE.pub", false),
        ] {
            let mut files = files_of(&parts);
            files.push((name.into(), b"overlap\n".to_vec()));
            let checks = verify_manifest(&dir(files, None), &manifest_of(&parts));
            let unlisted = checks
                .iter()
                .find(|c| c.name == "release.unlisted")
                .expect("the unlisted check");
            assert_eq!(unlisted.passed, admitted, "{name}: {checks:?}");
        }
    }

    #[test]
    fn a_flipped_artifact_byte_is_release_artifact_naming_the_file_and_digest() {
        let parts = parts();
        let mut files = files_of(&parts);
        let kit = format!("jaynshare-{VERSION}-client-kit.zip");
        let position = files.iter().position(|(name, _)| *name == kit).unwrap();
        files[position].1[0] ^= 0xff;
        let checks = verify_manifest(&dir(files, None), &manifest_of(&parts));
        assert_eq!(checks.len(), 5, "{checks:?}");
        assert_eq!(checks[4].name, "release.artifact");
        assert!(!checks[4].passed);
        assert!(
            checks[4].message.contains(&kit) && checks[4].message.contains("digest"),
            "{checks:?}"
        );
    }

    #[test]
    fn a_manifest_length_lie_is_release_artifact_naming_the_file_and_length() {
        let mut parts = parts();
        let kit = format!("jaynshare-{VERSION}-client-kit.zip");
        for entry in parts.manifest["artifacts"].as_array_mut().unwrap() {
            if entry["filename"] == kit.as_str() {
                entry["length"] = json!(entry["length"].as_u64().unwrap() + 1);
            }
        }
        let checks = verify_manifest(&dir(files_of(&parts), None), &manifest_of(&parts));
        assert_eq!(checks.len(), 5, "{checks:?}");
        assert_eq!(checks[4].name, "release.artifact");
        assert!(!checks[4].passed);
        assert!(
            checks[4].message.contains(&kit) && checks[4].message.contains("length"),
            "{checks:?}"
        );
    }

    #[test]
    fn a_selected_artifact_absent_from_the_directory_fails() {
        let parts = parts();
        let selected = format!("jaynshare-{VERSION}-client-kit.zip");
        let files: Vec<(String, Vec<u8>)> = files_of(&parts)
            .into_iter()
            .filter(|(name, _)| *name != selected)
            .collect();
        let checks = verify_manifest(&dir(files, Some(&selected)), &manifest_of(&parts));
        assert_eq!(checks.len(), 5, "{checks:?}");
        assert_eq!(checks[4].name, "release.artifact");
        assert!(!checks[4].passed);
    }

    #[test]
    fn an_unlisted_artifact_present_but_not_in_the_manifest_is_release_unlisted() {
        let parts = parts();
        let mut files = files_of(&parts);
        files.push((format!("jaynshare-{VERSION}-extra.tar.gz"), filler("extra")));
        let checks = verify_manifest(&dir(files, None), &manifest_of(&parts));
        assert_eq!(checks.len(), 4, "{checks:?}");
        assert_eq!(checks[3].name, "release.unlisted");
        assert!(!checks[3].passed);
    }
}
