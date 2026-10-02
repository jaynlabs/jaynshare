//! `trust-ca add|remove`: the optional OS trust-store
//! step over an existing installation. `add` explains the broader effect and
//! asks before `deploy::trust_store::add`; `remove` shows `client.toml`'s
//! fingerprint and asks before removing exactly it.

use serde_json::json;
use std::io::IsTerminal as _;

use super::{Cli, Failure, Outcome};
use crate::client;

fn local(code: i32, slug: &str, message: impl Into<String>) -> Failure {
    Failure::local(code, slug, message)
}

/// The installed CA certificate and the fingerprint `client.toml` names for
/// it; both are needed for either direction.
fn installed_ca() -> Result<(std::path::PathBuf, String), Failure> {
    let installation =
        client::read_installation().map_err(|(code, why)| local(code, "cli_not_enrolled", why))?;
    let ca = installation.directory.join("ca.pem");
    if !ca.is_file() {
        return Err(local(
            11,
            "cli_not_enrolled",
            format!(
                "the client installation is incomplete: {} is missing; uninstall, then {}",
                ca.display(),
                client::JOIN_HINT
            ),
        ));
    }
    match installation.ca_fingerprint.as_deref() {
        Some(f) if !f.is_empty() => Ok((ca, f.to_string())),
        _ => Err(local(
            1,
            "cli_internal",
            "client.toml names no CA fingerprint",
        )),
    }
}

pub(super) async fn trust_ca(_cli: &Cli, add: bool) -> Outcome {
    // The confirmation is read on the terminal; `later_verb_refusal`
    // keeps `--yes` from answering for this verb.
    if !std::io::stdin().is_terminal() {
        return Err(local(
            21,
            "cli_confirmation_required",
            "`jaynshare trust-ca` needs a terminal for its confirmation",
        ));
    }
    let (ca, fingerprint) = installed_ca()?;
    eprintln!("CA fingerprint: {fingerprint}");
    if add {
        eprintln!(
            "the CA will be trusted by every program of this user, not only the launched Claude Code"
        );
    }
    let action = if add { "add" } else { "remove" };
    let prompt = if add {
        "Add this CA to the OS trust store? [y/N] "
    } else {
        "Remove this CA from the OS trust store? [y/N] "
    };
    if !super::verbs::confirm(prompt)? {
        return Err(local(21, "cli_confirmation_required", "not confirmed"));
    }
    let result = if add {
        crate::deploy::trust_store::add(&ca, &fingerprint)
    } else {
        crate::deploy::trust_store::remove(&fingerprint)
    };
    match result {
        Ok(()) => Ok((
            json!({ "action": action, "fingerprint": fingerprint }),
            format!("{action}ed the CA in the OS trust store: {fingerprint}"),
        )),
        Err(why) => Err(local(1, "cli_internal", why)),
    }
}
