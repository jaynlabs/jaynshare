//! Account intent: a named reference resolved against the
//! catalogue, or the picker's choice, as the `pin.` intent token of the
//! canonical handle — never the string the engineer typed.

use crate::client::{self, CatalogueEntry, ClientInstallation};
use crate::data_plane::intent::encode_token;
use crate::picker;
use crate::provider::Provider;

use super::{READ_TIMEOUT, Refusal};

/// Resolve `reference` read-only; the token pins its handle.
/// Nothing matched → 6, ambiguous → 7 naming the display names; resolved but
/// unselectable → a warning, and the launch proceeds (the first prompt gets
/// the 429 naming it).
pub(super) async fn resolve(
    installation: &ClientInstallation,
    secret: &str,
    reference: &str,
    provider: Provider,
    notices: &mut Vec<String>,
) -> Result<Option<String>, Refusal> {
    let entry = client::resolve(installation, secret, reference, provider, READ_TIMEOUT)
        .await
        .map_err(|(code, message)| {
            let slug = match code {
                6 => "cli_not_found",
                7 => "cli_ambiguous",
                4 => "cli_unreachable",
                5 => "cli_refused",
                _ => "cli_incompatible_server",
            };
            Refusal::new(code, slug, message)
        })?;
    if !entry.selectable {
        notices.push(format!(
            "jaynshare: warning: {} cannot serve right now; the session is pinned to it, so the first prompt fails naming it — quit and relaunch to switch",
            entry.display_name
        ));
    }
    Ok(Some(encode_token(true, &entry.handle)))
}

/// The picker over `provider`'s part of the catalogue; its selection is a
/// pin, its automatic row is no token.
pub(super) async fn pick(
    installation: &ClientInstallation,
    secret: &str,
    provider: Provider,
    kind: picker::Kind,
) -> Result<Option<String>, Refusal> {
    let entries = client::catalogue(installation, secret, READ_TIMEOUT)
        .await
        .map_err(|(code, message)| {
            let slug = if code == 4 {
                "cli_unreachable"
            } else {
                "cli_refused"
            };
            Refusal::new(code, slug, message)
        })?;
    match picker::pick(&rows(entries, provider), kind) {
        Ok(picker::Choice::Automatic) => Ok(None),
        Ok(picker::Choice::Account(handle)) => Ok(Some(encode_token(true, &handle))),
        Err(picker::PickError::Cancelled) => {
            Err(Refusal::new(15, "cli_picker_cancelled", picker::CANCELLED))
        }
        Err(picker::PickError::NoTerminal) => Err(Refusal::new(
            16,
            "cli_no_terminal",
            "there is no terminal for the account picker; launch with --account <reference> or --auto",
        )),
        Err(picker::PickError::Io(why)) => Err(Refusal::new(
            1,
            "cli_internal",
            format!("the account picker failed: {why}"),
        )),
    }
}

/// The picker's rows: the catalogue entries of `provider`, in order.
fn rows(entries: Vec<CatalogueEntry>, provider: Provider) -> Vec<picker::Row> {
    entries
        .into_iter()
        .filter(|e| e.provider == provider)
        .map(|e| picker::Row {
            handle: e.handle,
            display_name: e.display_name,
            selectable: e.selectable,
            five_hour: e.five_hour,
            weekly: e.weekly,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_picker_shows_one_provider_s_accounts() {
        let entry = |handle: &str, provider| CatalogueEntry {
            handle: handle.into(),
            display_name: handle.into(),
            selectable: true,
            five_hour: None,
            weekly: None,
            provider,
        };
        let catalogue = vec![
            entry("claude-1", Provider::Anthropic),
            entry("codex-1", Provider::Codex),
            entry("claude-2", Provider::Anthropic),
        ];
        let handles = |provider| -> Vec<String> {
            rows(catalogue.clone(), provider)
                .into_iter()
                .map(|r| r.handle)
                .collect()
        };
        assert_eq!(handles(Provider::Anthropic), ["claude-1", "claude-2"]);
        assert_eq!(handles(Provider::Codex), ["codex-1"]);
    }
}
