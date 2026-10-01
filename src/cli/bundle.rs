//! The operator's bundle verbs: `client bundle`
//! (the packaging half alone), `client enrol` (issue + package as one
//! transaction) and the packaging half of `client reissue --kit/--out`. The
//! registry verbs themselves are `verbs`.

use std::path::Path;

use http::Method;
use serde_json::{Value, json};

use super::control::Control;
use super::{Failure, Outcome};
use crate::bundle::{
    self, BundleInputs, BundleManifest, CaUpdateInputs, VerifiedKit, write_ca_update_zip,
};

/// Validated locally before any request: a client id is 1–63
/// ASCII lowercase letters, digits, `_` or `-`, beginning with a letter or
/// digit; a display name is 1–128 UTF-8 bytes after trimming, no control
/// character.
pub(super) fn validate_client_id(id: &str) -> Result<(), Failure> {
    let valid = !id.is_empty()
        && id.len() <= 63
        && id
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if valid {
        return Ok(());
    }
    Err(Failure::local(
        2,
        "cli_usage",
        format!(
            "invalid client id {id:?}: 1-63 ASCII lowercase letters, digits, `_` or `-`, beginning with a letter or digit"
        ),
    ))
}

pub(super) fn validate_display_name(name: &str) -> Result<(), Failure> {
    let trimmed = name.trim();
    let valid =
        !trimmed.is_empty() && trimmed.len() <= 128 && !trimmed.chars().any(char::is_control);
    if valid {
        return Ok(());
    }
    Err(Failure::local(
        2,
        "cli_usage",
        "invalid display name: 1-128 UTF-8 bytes after surrounding whitespace is removed, no control character",
    ))
}

/// `--out` is an existing directory, owner-only, writable, holding no
/// output of this id yet.
fn check_out(out: &Path, client_id: Option<&str>) -> Result<(), Failure> {
    let metadata = std::fs::metadata(out).map_err(|_| {
        Failure::local(
            8,
            "cli_conflict",
            format!("--out {}: does not exist", out.display()),
        )
    })?;
    if !metadata.is_dir() {
        return Err(Failure::local(
            8,
            "cli_conflict",
            format!("--out {}: not a directory", out.display()),
        ));
    }
    crate::state::check_private(out)
        .map_err(|why| Failure::local(8, "cli_conflict", format!("--out {why}")))?;
    if client_id.is_some_and(|id| !id.is_empty()) {
        let id = client_id.expect("checked");
        for entry in std::fs::read_dir(out).map_err(|e| {
            Failure::local(8, "cli_conflict", format!("--out {}: {e}", out.display()))
        })? {
            let name = entry
                .map_err(|e| {
                    Failure::local(8, "cli_conflict", format!("--out {}: {e}", out.display()))
                })?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if name.starts_with(&format!("jaynshare-client-{id}-g")) {
                return Err(Failure::local(
                    8,
                    "cli_conflict",
                    format!("{}: output for {id} already exists", out.display()),
                ));
            }
        }
    }
    Ok(())
}

/// The origins from the configuration read: the base-URL and proxy
/// listener origins the manifest records, or the advertised origins
/// the operator configured for a forwarded listener. An
/// origin is derived when its key is unset, and refused beside a wildcard
/// bind — an unspecified listener address embeds an origin no client can
/// reach.
async fn origins(control: &Control) -> Result<(String, Option<String>), Failure> {
    origins_and_anchor(control)
        .await
        .map(|(base_url, proxy, _)| (base_url, proxy))
}

/// The base-URL listener trust anchor as packaging embeds it: the PEM,
/// its SHA-256 and its certificate fingerprint.
struct BaseUrlAnchor {
    pem: String,
    sha256: String,
    fingerprint: String,
}

/// The origins plus, for an `https` base URL, `clients.base_url_ca_certificate_file`
/// read and checked: required, exactly one CA certificate, no private
/// key. An `http` origin ignores the key.
async fn origins_and_anchor(
    control: &Control,
) -> Result<(String, Option<String>, Option<BaseUrlAnchor>), Failure> {
    let body = control
        .expect(Method::GET, "/control/v1/configuration", None)
        .await?;
    let (base_url, proxy) = origins_from(&body)?;
    if !base_url.starts_with("https://") {
        return Ok((base_url, proxy, None));
    }
    let key = "clients.base_url_ca_certificate_file";
    let refuse = |why: String| {
        Failure::local(
            3,
            "cli_configuration_invalid",
            format!(
                "{key}: {why}; an https base URL ({base_url}) packages its listener's trust anchor"
            ),
        )
    };
    let Some(path) = body["configuration"]["effective"]["clients"]["base_url_ca_certificate_file"]
        .as_str()
        .filter(|p| !p.is_empty())
    else {
        return Err(refuse("is unset".into()));
    };
    let pem = std::fs::read_to_string(path).map_err(|e| refuse(format!("{path}: {e}")))?;
    let fingerprint = check_anchor(&pem).map_err(|why| refuse(format!("{path}: {why}")))?;
    Ok((
        base_url,
        proxy,
        Some(BaseUrlAnchor {
            sha256: bundle::sha256_hex(pem.as_bytes()),
            pem,
            fingerprint,
        }),
    ))
}

/// Requires exactly one CA certificate and no private key; returns its
/// fingerprint.
fn check_anchor(pem: &str) -> Result<String, String> {
    if pem.contains("PRIVATE KEY-----") {
        return Err("carries a private key".into());
    }
    let blocks = pem.matches("-----BEGIN ").count();
    let certificates = pem.matches("-----BEGIN CERTIFICATE-----").count();
    if blocks != 1 || certificates != 1 {
        return Err(format!(
            "must hold exactly one certificate, found {certificates} among {blocks} PEM blocks"
        ));
    }
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|_| "is not a PEM certificate".to_string())?;
    let certificate = block
        .parse_x509()
        .map_err(|_| "is not an X.509 certificate".to_string())?;
    if !certificate.is_ca() {
        return Err("is not a CA certificate (no CA basic constraint)".into());
    }
    bundle::fingerprint(pem)
}

fn origins_from(body: &Value) -> Result<(String, Option<String>), Failure> {
    let effective = &body["configuration"]["effective"];
    if effective["data_plane"]["tls"] == "identity" {
        return Err(Failure::local(
            3,
            "cli_configuration_invalid",
            "data_plane.tls is \"identity\", whose pin an enrollment bundle cannot carry",
        ));
    }
    let listen = effective["data_plane"]["listen"]
        .as_str()
        .unwrap_or_default();
    let tls = body["configuration"]["secrets"]["data_plane.tls_private_key_file"]["set"]
        .as_bool()
        .unwrap_or(false);
    let advertised_base_url = effective["clients"]["advertised_base_url"]
        .as_str()
        .filter(|s| !s.is_empty());
    let mitm_listen = effective["mitm"]["listen"].as_str();
    let advertised_proxy_url = effective["clients"]["advertised_proxy_url"]
        .as_str()
        .filter(|s| !s.is_empty());
    // Unset keys derive from the listener, but a wildcard bind makes
    // the derived origin unreachable, so packaging refuses instead.
    let unspecified = |listen: &str| {
        listen
            .parse::<std::net::SocketAddr>()
            .map(|addr| addr.ip().is_unspecified())
            .unwrap_or(false)
    };
    if advertised_base_url.is_none() && unspecified(listen) {
        return Err(Failure::local(
            3,
            "cli_configuration_invalid",
            format!(
                "clients.advertised_base_url is unset and data_plane.listen is the wildcard {listen}, which no client can reach; set clients.advertised_base_url"
            ),
        ));
    }
    if let Some(mitm_listen) = mitm_listen
        && advertised_proxy_url.is_none()
        && unspecified(mitm_listen)
    {
        return Err(Failure::local(
            3,
            "cli_configuration_invalid",
            format!(
                "clients.advertised_proxy_url is unset and mitm.listen is the wildcard {mitm_listen}, which no client can reach; set clients.advertised_proxy_url"
            ),
        ));
    }
    let mut base_url = format!("{}://{listen}", if tls { "https" } else { "http" });
    let mut proxy = mitm_listen.map(|l| format!("http://{l}"));
    if let Some(advertised) = advertised_base_url {
        base_url = advertised.to_string();
    }
    if let (Some(advertised), true) = (advertised_proxy_url, proxy.is_some()) {
        proxy = Some(advertised.to_string());
    }
    Ok((base_url, proxy))
}

/// The CA: `(pem, fingerprint)` or `None` while MITM was never
/// enabled (every member null — the bundle's `ca.pem` member is written empty).
async fn ca(control: &Control) -> Result<Option<(String, String)>, Failure> {
    let body = control.expect(Method::GET, "/control/v1/ca", None).await?;
    let pem = body["ca"]["certificate_pem"].as_str().map(String::from);
    let fingerprint = body["ca"]["fingerprint"].as_str().map(String::from);
    Ok(match (pem, fingerprint) {
        (Some(pem), Some(fp)) => Some((pem, fp)),
        _ => None,
    })
}

fn pinned_key() -> Result<crate::bundle::PinnedKey, Failure> {
    crate::bundle::PinnedKey::load().map_err(|why| {
        Failure::local(
            17,
            "cli_release_unverified",
            format!("the client kit cannot be verified: {why}"),
        )
    })
}

fn verify_kit(kit: &Path) -> Result<VerifiedKit, Failure> {
    let key = pinned_key()?;
    bundle::verify_kit_zip(kit, &key).map_err(|why| {
        Failure::local(
            17,
            "cli_release_unverified",
            format!("{}: {why}", kit.display()),
        )
    })
}

/// The single-entry read, wrapper member `client` (`account show`'s shape).
async fn entry(control: &Control, id: &str) -> Result<Value, Failure> {
    let body = control
        .expect(Method::GET, &format!("/control/v1/clients/{id}"), None)
        .await?;
    Ok(body["client"].clone())
}

/// `--disclose-to`: a fresh mode-0600 file, refusing an existing path.
pub(super) fn write_disclosure(path: &Path, value: &str) -> Result<(), Failure> {
    if path.exists() {
        return Err(Failure::local(
            8,
            "cli_conflict",
            format!("{}: the disclosure file already exists", path.display()),
        ));
    }
    crate::state::write_private_atomic(path, value.as_bytes())
        .map_err(|e| Failure::local(1, "cli_internal", format!("{}: {e}", path.display())))
}

/// The manifest from the entry, the CA and the origins.
fn manifest_from(
    entry: &Value,
    id: &str,
    ca: &Option<(String, String)>,
    base_url: &str,
    proxy: Option<&str>,
    anchor: Option<&BaseUrlAnchor>,
    kit: &VerifiedKit,
) -> BundleManifest {
    let payloads: Vec<(String, String)> = bundle::BUNDLE_MEMBERS
        .iter()
        .filter(|name| name.starts_with("payload/"))
        .map(|name| {
            // `payload/<target>/jaynshare[.exe]` → `<target>`; the extension
            // goes first so the Windows member does not keep its file name.
            let target = name
                .trim_start_matches("payload/")
                .trim_end_matches(".exe")
                .trim_end_matches("/jaynshare")
                .replace('/', "-");
            (target, name.to_string())
        })
        .collect();
    BundleManifest {
        client_id: id.to_string(),
        display_name: entry["display_name"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        generation: entry["generation"].as_u64().unwrap_or(1),
        base_url: base_url.to_string(),
        proxy: proxy.map(String::from),
        pending_expires_at: entry["expires_at"].as_str().map(String::from),
        ca_sha256: ca
            .as_ref()
            .map(|(pem, _)| bundle::sha256_hex(pem.as_bytes())),
        ca_fingerprint: ca.as_ref().map(|(_, fp)| fp.clone()),
        base_url_ca_sha256: anchor.map(|a| a.sha256.clone()),
        base_url_ca_fingerprint: anchor.map(|a| a.fingerprint.clone()),
        release_version: kit.version.clone(),
        release_commit: kit.commit.clone(),
        kit_file: kit.file.clone(),
        kit_sha256: kit.sha256.clone(),
        payloads,
    }
}

/// Write the ZIP into a temporary file in `out`, then rename; the
/// code file (when packaging `client enrol`) is written fresh, mode 0600.
fn package(
    out: &Path,
    inputs: &BundleInputs<'_>,
    code: Option<&str>,
    client_id: &str,
    generation: u64,
) -> Result<(std::path::PathBuf, Option<std::path::PathBuf>, Value), String> {
    let zip_path = out.join(bundle::bundle_name(client_id, generation));
    let tmp_path = out.join(format!(
        ".{}.{}.tmp",
        bundle::bundle_name(client_id, generation),
        std::process::id()
    ));
    let manifest_bytes = bundle::write_bundle_zip(&tmp_path, inputs).inspect_err(|_why| {
        let _ = std::fs::remove_file(&tmp_path);
    })?;
    std::fs::rename(&tmp_path, &zip_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!(
            "{}: cannot put the bundle in place: {e}",
            zip_path.display()
        )
    })?;
    let code_file: Option<std::path::PathBuf> = match code {
        Some(value) => {
            let path = out.join(bundle::code_file_name(client_id, generation));
            if let Err(e) = crate::state::write_private_atomic(&path, value.as_bytes()) {
                let _ = std::fs::remove_file(&zip_path);
                return Err(format!("{}: {e}", path.display()));
            }
            Some(path)
        }
        None => None,
    };
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("the written manifest does not parse: {e}"))?;
    Ok((zip_path, code_file, manifest))
}

async fn rollback<'a>(control: &'a Control, id: &'a str, out: &'a Path) {
    // A packaging failure revokes the pending generation and
    // removes every partial output. The revoke's own outcome cannot mend
    // the packaging failure; a failed revoke is reported best-effort.
    let _ = control
        .expect(
            Method::POST,
            &format!("/control/v1/clients/{id}/revoke"),
            Some(&json!({})),
        )
        .await;
    remove_outputs(out, id);
}

fn remove_outputs(out: &Path, client_id: &str) {
    let Ok(entries) = std::fs::read_dir(out) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&format!("jaynshare-client-{client_id}-g"))
            || name.starts_with(&format!(".jaynshare-client-{client_id}-g"))
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn package_result(archive: &Path, code_file: Option<&Path>, manifest: Value) -> Value {
    json!({
        "archive": archive.display().to_string(),
        "code_file": code_file.map(|p| p.display().to_string()),
        "manifest": manifest,
    })
}

fn human_package(archive: &Path, code_file: Option<&Path>) -> String {
    match code_file {
        Some(path) => format!(
            "bundle written to {}\ncode written to {} (send archive and code through separate channels)",
            archive.display(),
            path.display()
        ),
        None => format!("bundle written to {}", archive.display()),
    }
}

/// `client bundle <id> --kit <zip> --out <dir>`: the packaging half
/// alone, for an entry issued elsewhere. Refuses a non-pending entry (exit 8)
/// and writes no code file.
pub(super) async fn client_bundle(control: &Control, id: &str, kit: &Path, out: &Path) -> Outcome {
    check_out(out, Some(id))?;
    let verified = verify_kit(kit)?;
    let entry = entry(control, id).await?;
    if entry["state"] != json!("pending") {
        return Err(Failure::local(
            8,
            "conflict",
            format!(
                "client {id} is {} ; only a pending entry can be packaged (the manifest carries the pending expiry)",
                entry["state"].as_str().unwrap_or("not pending")
            ),
        ));
    }
    let (base_url, proxy, anchor) = origins_and_anchor(control).await?;
    let ca = ca(control).await?;
    let manifest = manifest_from(
        &entry,
        id,
        &ca,
        &base_url,
        proxy.as_deref(),
        anchor.as_ref(),
        &verified,
    );
    let generation = manifest.generation;
    let inputs = BundleInputs {
        manifest: &manifest,
        kit: &verified,
        ca_pem: ca.as_ref().map(|(pem, _)| pem.as_str()),
        base_url_ca_pem: anchor.as_ref().map(|a| a.pem.as_str()),
    };
    let (archive, code_file, manifest_value) = package(out, &inputs, None, id, generation)
        .map_err(|why| Failure::local(1, "cli_internal", format!("packaging failed: {why}")))?;
    Ok((
        package_result(&archive, code_file.as_deref(), manifest_value),
        human_package(&archive, code_file.as_deref()),
    ))
}

/// `ca update-bundle --out <dir>`: the operator half of a CA rotation —
/// package the current CA for clients to apply after the
/// rotation. No enrolment code: only the certificate, the fingerprint and
/// the server identity travel. The old fingerprint that matters is the one
/// each machine has installed, which `ca-update --from` shows.
pub(super) async fn ca_update_bundle(control: &Control, out: &Path) -> Outcome {
    check_out(out, None)?;
    let ca = control.expect(Method::GET, "/control/v1/ca", None).await?;
    let (certificate_pem, fingerprint) = match (
        ca["ca"]["certificate_pem"].as_str(),
        ca["ca"]["fingerprint"].as_str(),
    ) {
        (Some(pem), Some(fp)) => (pem.to_string(), fp.to_string()),
        _ => {
            return Err(Failure::local(
                8,
                "mitm_disabled",
                "MITM mode is off: there is no CA to package",
            ));
        }
    };
    let (base_url, proxy) = origins(control).await?;
    let issued_at = crate::timestamp::rfc3339(time::OffsetDateTime::now_utc());
    let inputs = CaUpdateInputs {
        certificate_pem: &certificate_pem,
        fingerprint: &fingerprint,
        origins: [&base_url, proxy.as_deref().unwrap_or_default()],
        issued_at: &issued_at,
    };
    let (archive, manifest) = write_ca_update_zip(out, &inputs)
        .map_err(|why| Failure::local(8, "cli_conflict", format!("--out {why}")))?;
    Ok((
        json!({
            "archive": archive.display().to_string(),
            "code_file": null,
            "manifest": manifest,
        }),
        format!("wrote {}", archive.display()),
    ))
}

/// `client enrol <id> --name <name> --kit <zip> --out <dir>`:
/// verify the kit, create the pending generation, package the ZIP and the
/// separate code file — one transaction, revoked and cleaned on failure.
pub(super) async fn client_enrol(
    control: &Control,
    id: &str,
    name: &str,
    kit: &Path,
    out: &Path,
) -> Outcome {
    validate_client_id(id)?;
    validate_display_name(name)?;
    check_out(out, Some(id))?;
    let verified = verify_kit(kit)?;
    // The origins are read before anything is issued, so a wildcard
    // bind without its advertised key refuses before the generation exists.
    let (base_url, proxy, anchor) = origins_and_anchor(control).await?;
    // The pending generation is created only after the kit verified.
    let issued = control
        .expect(
            Method::POST,
            "/control/v1/clients",
            Some(&json!({ "id": id, "display_name": name.trim() })),
        )
        .await?;
    let code = issued["enrollment_code"]
        .as_str()
        .ok_or_else(|| {
            Failure::local(
                10,
                "cli_incompatible_server",
                "the issue response carries no enrollment_code",
            )
        })?
        .to_string();
    let entry = issued["client"].clone();
    let generation = entry["generation"].as_u64().unwrap_or(1);
    let ca = ca(control).await?;
    let manifest = manifest_from(
        &entry,
        id,
        &ca,
        &base_url,
        proxy.as_deref(),
        anchor.as_ref(),
        &verified,
    );
    let inputs = BundleInputs {
        manifest: &manifest,
        kit: &verified,
        ca_pem: ca.as_ref().map(|(pem, _)| pem.as_str()),
        base_url_ca_pem: anchor.as_ref().map(|a| a.pem.as_str()),
    };
    let packaged = package(out, &inputs, Some(&code), id, generation);
    let (archive, code_file, manifest_value) = match packaged {
        Ok(tuple) => tuple,
        Err(why) => {
            // Revoke the pending generation, remove every partial output.
            rollback(control, id, out).await;
            return Err(Failure::local(
                1,
                "cli_internal",
                format!("packaging failed: {why}; the pending generation was revoked"),
            ));
        }
    };
    // The enrol disclosure is the code file; the code is never
    // printed. The registry entry is the human summary.
    let mut human = format!("issued client {id} (generation {generation}, pending)\n",);
    human.push_str(&human_package(&archive, code_file.as_deref()));
    let result = package_result(&archive, code_file.as_deref(), manifest_value);
    // The code itself only in code_file, never in the result; the
    // disclosure is the code file.
    Ok((result, human))
}

/// `client reissue <id> --kit <zip> --out <dir>`: the new code is
/// disclosed once, then the bundle is repacked for the
/// new generation with no code file.
pub(super) async fn client_reissue(
    control: &Control,
    cli: &super::args::Cli,
    id: &str,
    kit: &Path,
    out: &Path,
    disclose_to: Option<&Path>,
) -> Outcome {
    check_out(out, Some(id))?;
    let verified = verify_kit(kit)?;
    // The origins are read before anything is issued, so a wildcard
    // bind without its advertised key refuses before the generation exists.
    let (base_url, proxy, anchor) = origins_and_anchor(control).await?;
    let issued = control
        .expect(
            Method::POST,
            &format!("/control/v1/clients/{id}/reissue"),
            Some(&json!({})),
        )
        .await?;
    let code = issued["enrollment_code"]
        .as_str()
        .ok_or_else(|| {
            Failure::local(
                10,
                "cli_incompatible_server",
                "the reissue response carries no enrollment_code",
            )
        })?
        .to_string();
    let entry = issued["client"].clone();
    let generation = entry["generation"].as_u64().unwrap_or(1);
    let ca = ca(control).await?;
    let manifest = manifest_from(
        &entry,
        id,
        &ca,
        &base_url,
        proxy.as_deref(),
        anchor.as_ref(),
        &verified,
    );
    let inputs = BundleInputs {
        manifest: &manifest,
        kit: &verified,
        ca_pem: ca.as_ref().map(|(pem, _)| pem.as_str()),
        base_url_ca_pem: anchor.as_ref().map(|a| a.pem.as_str()),
    };
    let (archive, code_file, manifest_value) = package(out, &inputs, None, id, generation)
        .map_err(|why| Failure::local(1, "cli_internal", format!("packaging failed: {why}")))?;
    // The disclosure is written once — into `--disclose-to` when given,
    // inside `result` with `--json`, otherwise as standard output's last line.
    let mut result = package_result(&archive, code_file.as_deref(), manifest_value);
    let disclosure_path = match disclose_to {
        Some(path) => {
            write_disclosure(path, &code)?;
            result["disclosure_file"] = json!(path.display().to_string());
            None
        }
        None if cli.json => Some(code.clone()),
        None => None,
    };
    let mut human = human_package(&archive, code_file.as_deref());
    if let Some(code) = &disclosure_path {
        result["enrollment_code"] = json!(code);
    }
    if !cli.json && disclose_to.is_none() {
        human.push_str(&format!(
            "\nenrollment code (send separately, disclose once): {code}"
        ));
    }
    Ok((result, human))
}
