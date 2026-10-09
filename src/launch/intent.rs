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

/// The picker over `provider`'s part of the catalogue, or with no provider
/// over every provider's; its selection is a pin, its automatic row is no
/// token, and the section chosen in names the provider whose tool launches.
pub(super) async fn pick(
    installation: &ClientInstallation,
    secret: &str,
    provider: Option<Provider>,
    kind: picker::Kind,
) -> Result<(Provider, Option<String>), Refusal> {
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
    let (providers, sections): (Vec<Provider>, Vec<picker::Section>) =
        sections(&entries, provider).into_iter().unzip();
    match picker::pick(&sections, kind) {
        Ok((section, picker::Choice::Automatic)) => Ok((providers[section], None)),
        Ok((section, picker::Choice::Account(handle))) => {
            Ok((providers[section], Some(encode_token(true, &handle))))
        }
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

/// `provider`'s section, unheaded; with no provider, one section per
/// provider holding accounts (each provider when none does), headed by its
/// tool's name. The entries keep the catalogue's order.
fn sections(
    entries: &[CatalogueEntry],
    provider: Option<Provider>,
) -> Vec<(Provider, picker::Section)> {
    let section = |of: Provider| {
        let rows = entries
            .iter()
            .filter(|e| e.provider == of)
            .map(picker::Row::from)
            .collect();
        let heading = provider.is_none().then_some(of.tool().name);
        (of, picker::Section { heading, rows })
    };
    if let Some(provider) = provider {
        return vec![section(provider)];
    }
    let mut all: Vec<_> = Provider::ALL.into_iter().map(section).collect();
    if all.iter().any(|(_, s)| !s.rows.is_empty()) {
        all.retain(|(_, s)| !s.rows.is_empty());
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(handle: &str, provider: Provider) -> CatalogueEntry {
        CatalogueEntry {
            handle: handle.into(),
            display_name: handle.into(),
            selectable: true,
            five_hour: Default::default(),
            weekly: Default::default(),
            provider,
        }
    }

    /// Each section as its provider, heading and handles.
    fn shown(
        entries: &[CatalogueEntry],
        provider: Option<Provider>,
    ) -> Vec<(Provider, Option<&'static str>, Vec<String>)> {
        sections(entries, provider)
            .into_iter()
            .map(|(of, s)| {
                let handles = s.rows.into_iter().map(|r| r.handle).collect();
                (of, s.heading, handles)
            })
            .collect()
    }

    #[test]
    fn the_picker_shows_one_provider_s_accounts() {
        let catalogue = [
            entry("claude-1", Provider::Anthropic),
            entry("codex-1", Provider::Codex),
            entry("claude-2", Provider::Anthropic),
        ];
        assert_eq!(
            shown(&catalogue, Some(Provider::Anthropic)),
            [(
                Provider::Anthropic,
                None,
                vec!["claude-1".to_string(), "claude-2".to_string()]
            )]
        );
        assert_eq!(
            shown(&catalogue, Some(Provider::Codex)),
            [(Provider::Codex, None, vec!["codex-1".to_string()])]
        );
    }

    #[test]
    fn with_no_provider_each_provider_holding_accounts_has_a_headed_section() {
        let catalogue = [
            entry("codex-1", Provider::Codex),
            entry("claude-1", Provider::Anthropic),
        ];
        assert_eq!(
            shown(&catalogue, None),
            [
                (
                    Provider::Anthropic,
                    Some("Claude Code"),
                    vec!["claude-1".to_string()]
                ),
                (Provider::Codex, Some("Codex"), vec!["codex-1".to_string()]),
            ]
        );
        let claude_only = [entry("claude-1", Provider::Anthropic)];
        assert_eq!(
            shown(&claude_only, None),
            [(
                Provider::Anthropic,
                Some("Claude Code"),
                vec!["claude-1".to_string()]
            )]
        );
        let providers: Vec<Provider> = shown(&[], None).into_iter().map(|s| s.0).collect();
        assert_eq!(providers, Provider::ALL, "an empty pool offers each tool");
    }
}
