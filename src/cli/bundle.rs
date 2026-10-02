//! The client id and display-name rules every client verb checks before a
//! request, the `--disclose-to` file, and `ca update-bundle`.

use std::path::Path;

use http::Method;
use serde_json::json;

use super::control::Control;
use super::{Failure, Outcome};
use crate::bundle::{CaUpdateInputs, write_ca_update_zip};

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

/// `--out` is an existing directory, owner-only and writable.
fn check_out(out: &Path) -> Result<(), Failure> {
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
        .map_err(|why| Failure::local(8, "cli_conflict", format!("--out {why}")))
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

/// `ca update-bundle --out <dir>`: the operator half of a CA rotation —
/// package the current CA for clients to apply after the
/// rotation. No enrolment code: only the certificate, the fingerprint and
/// the server identity travel. The old fingerprint that matters is the one
/// each machine has installed, which `ca-update --from` shows.
pub(super) async fn ca_update_bundle(control: &Control, out: &Path) -> Outcome {
    check_out(out)?;
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
    let configuration = control
        .expect(Method::GET, "/control/v1/configuration", None)
        .await?;
    let (base_url, proxy) = super::invite::origins_from(&configuration)?;
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
