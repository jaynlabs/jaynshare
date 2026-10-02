//! The client id and display-name rules every client verb checks before a
//! request, and the `--disclose-to` file.

use std::path::Path;

use super::Failure;

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
