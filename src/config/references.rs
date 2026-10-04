//! The running configuration's account references — every
//! route `accounts` entry and every priority `account` — resolved against a
//! pool. Pure; the account handlers call `conflicts` around an operation
//! inside the `mutate_pool` closure, and `errors` is the check at start and
//! reload (the state cross-references).

use super::{Config, ConfigError, ReferenceSite, Site};
use crate::pool::{Pool, ReferenceConflict, Resolve, Why, references};

/// Route and priority references against the state: a reference that
/// resolves to no account or to several, and a second priority entry
/// resolving to an account another already covers, each as a validation error
/// under the dotted key the document wrote it at.
pub fn errors(sites: &[ReferenceSite], pool: &Pool) -> Vec<ConfigError> {
    let mut out = Vec::new();
    let mut covered = Vec::new();
    for site in sites {
        let target = site.target.clone();
        match (pool.resolve(&site.literal), &site.site) {
            (Ok(account), Site::Priority) if covered.contains(&account.handle) => {
                out.push(ConfigError {
                    target,
                    message: format!(
                        "{:?} resolves to {}, which an earlier entry already covers",
                        site.literal, account.display_name
                    ),
                });
            }
            (Ok(account), Site::Priority) => covered.push(account.handle),
            (Ok(_), Site::Route(_)) => {}
            (Err(why), Site::Route(route)) => out.push(ConfigError {
                target,
                message: format!("route {route}: {}", describe(&site.literal, &why)),
            }),
            (Err(why), Site::Priority) => out.push(ConfigError {
                target,
                message: describe(&site.literal, &why),
            }),
        }
    }
    out
}

fn describe(reference: &str, why: &Resolve) -> String {
    match why {
        Resolve::NotFound => format!("no account matches {reference:?}"),
        Resolve::Ambiguous(names) => format!(
            "{reference:?} matches several accounts: {}",
            names.join(", ")
        ),
    }
}

/// Every route and priority reference that resolves to no account or to several.
pub fn conflicts(config: &Config, pool: &Pool) -> Vec<ReferenceConflict> {
    let selection = &config.selection;
    let mut out = Vec::new();
    for route in &selection.routes {
        for reference in route.accounts.iter().flatten() {
            if let Some(why) = resolution(pool, reference) {
                out.push(ReferenceConflict {
                    entry: format!("route {}", route.name),
                    reference: reference.clone(),
                    why,
                });
            }
        }
    }
    for (index, priority) in selection.priorities.iter().enumerate() {
        if let Some(why) = resolution(pool, &priority.account) {
            out.push(ReferenceConflict {
                entry: format!("priority {index}"),
                reference: priority.account.clone(),
                why,
            });
        }
    }
    out
}

fn resolution(pool: &Pool, reference: &str) -> Option<Why> {
    match pool
        .accounts()
        .iter()
        .filter(|a| references(a, reference))
        .count()
    {
        0 => Some(Why::Unresolvable),
        1 => None,
        _ => Some(Why::Ambiguous),
    }
}

/// The reference rule: refuse only what the operation breaks. A reference already
/// broken before it is not this operation's fault and does not block it.
pub fn introduced(
    before: &[ReferenceConflict],
    after: &[ReferenceConflict],
) -> Vec<ReferenceConflict> {
    after
        .iter()
        .filter(|c| {
            !before
                .iter()
                .any(|b| b.entry == c.entry && b.reference == c.reference)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::config::{Priority, Route};
    use crate::pool::{Account, Credential, Profile, Secret, Source};

    fn config(routes: Vec<Route>, priorities: Vec<Priority>) -> Config {
        let mut config = crate::config::parse(b"version = 1\n", std::path::Path::new("/"))
            .expect("default configuration");
        config.selection.routes = routes;
        config.selection.priorities = priorities;
        config
    }

    fn route(name: &str, accounts: Option<&[&str]>) -> Route {
        Route {
            name: name.into(),
            patterns: vec!["*".into()],
            accounts: accounts.map(|a| a.iter().map(|s| s.to_string()).collect()),
            bucket: None,
        }
    }

    fn priority(account: &str) -> Priority {
        Priority {
            account: account.into(),
            value: 0,
        }
    }

    fn oauth(email: &str, org: &str) -> Account {
        Account::new(
            crate::provider::Provider::Anthropic,
            String::new(),
            Profile {
                email: Some(email.into()),
                account_uuid: Some(Uuid::new_v4()),
                organization_uuid: None,
                organization_name: Some(org.into()),
                chatgpt_account_id: None,
            },
            Source::PortableJson,
            Credential::OAuth(crate::pool::OAuthCredential {
                access_token: Secret::new("t".into()),
                refresh_token: None,
                expires_at: time::macros::datetime!(2027-01-01 00:00 UTC),
                last_refresh_attempt_at: None,
                last_refresh_success_at: None,
                refresh_not_before: None,
            }),
        )
    }

    fn conflict(entry: &str, reference: &str, why: Why) -> ReferenceConflict {
        ReferenceConflict {
            entry: entry.into(),
            reference: reference.into(),
            why,
        }
    }

    #[test]
    fn a_shared_email_is_ambiguous_and_a_gone_name_unresolvable() {
        let mut pool = Pool::default();
        let first = pool
            .add(oauth("a@x.io", "One"), Some("FSUB".into()))
            .unwrap();
        pool.add(oauth("A@x.io", "Two"), Some("FSUB2".into()))
            .unwrap();
        let config = config(
            vec![
                route("by-email", Some(&["a@x.io"])),
                route("open", None),
                route("exclusive-empty", Some(&[])),
                route("by-handle", Some(&[&first.to_string()])),
            ],
            vec![priority("fsub"), priority("Gone")],
        );
        assert_eq!(
            conflicts(&config, &pool),
            vec![
                conflict("route by-email", "a@x.io", Why::Ambiguous),
                conflict("priority 1", "Gone", Why::Unresolvable),
            ]
        );
        pool.remove(first);
        assert_eq!(
            conflicts(&config, &pool),
            vec![
                conflict("route by-handle", &first.to_string(), Why::Unresolvable),
                conflict("priority 0", "fsub", Why::Unresolvable),
                conflict("priority 1", "Gone", Why::Unresolvable),
            ]
        );
    }

    /// At start and reload: every broken reference under its
    /// dotted key, and a second entry for one account.
    #[test]
    fn errors_carry_dotted_keys_and_the_priority_duplicate() {
        let mut pool = Pool::default();
        let first = pool
            .add(oauth("a@x.io", "One"), Some("FSUB".into()))
            .unwrap();
        pool.add(oauth("A@x.io", "Two"), Some("FSUB2".into()))
            .unwrap();
        let document = format!(
            "version = 1\n[selection]\nroutes = [{{ name = \"h\", patterns = [\"*\"], accounts = [\"FSUB\", \"ghost\", \"a@x.io\"] }}, {{ name = \"open\", patterns = [\"*\"] }}]\n\
             priorities = [{{ account = \"fsub\", value = 0 }}, {{ account = \"{first}\", value = 0 }}, {{ account = \"Gone\", value = 0 }}]\n"
        );
        let sites = crate::config::parse_document(document.as_bytes(), std::path::Path::new("/"))
            .expect("parses")
            .references;
        let found = errors(&sites, &pool);
        let targets: Vec<&str> = found.iter().map(|e| e.target.as_str()).collect();
        // Table order: priorities, then routes.
        assert_eq!(
            targets,
            [
                "selection.priorities[1].account",
                "selection.priorities[2].account",
                "selection.routes[0].accounts[1]",
                "selection.routes[0].accounts[2]",
            ]
        );
        assert!(found[0].message.contains("earlier entry"));
        assert!(found[2].message.contains("route h") && found[2].message.contains("ghost"));
        assert!(found[3].message.contains("several"));
        assert_eq!(errors(&sites, &Pool::default()).len(), 6);
    }

    /// A broken sibling entry never shifts a site's index: the cross-
    /// reference is reported under the key the operator wrote.
    #[test]
    fn sites_keep_the_document_indexes_beside_local_errors() {
        let document = "version = 1\n[selection]\nroutes = [{ name = \"h\", patterns = [\"*\"], accounts = [\"\", 7, \"ghost\"] }]\n\
                        priorities = [{ account = 3, value = 0 }, { account = \"Gone\", value = 0 }]\n";
        let parsed = crate::config::parse_document(document.as_bytes(), std::path::Path::new("/"))
            .expect("parses");
        assert!(!parsed.errors.is_empty(), "the local errors are reported");
        let targets: Vec<&str> = parsed
            .references
            .iter()
            .map(|r| r.target.as_str())
            .collect();
        assert_eq!(
            targets,
            [
                "selection.priorities[1].account",
                "selection.routes[0].accounts[2]"
            ]
        );
        let found = errors(&parsed.references, &Pool::default());
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].target, "selection.routes[0].accounts[2]");
    }

    /// The rule is "introduces": the entry broken before the operation is not
    /// its fault, whether or not the kind of breakage changed.
    #[test]
    fn introduced_is_the_difference_by_entry_and_reference() {
        let before = vec![
            conflict("priority 1", "Gone", Why::Unresolvable),
            conflict("route r", "x", Why::Unresolvable),
        ];
        let after = vec![
            conflict("priority 1", "Gone", Why::Unresolvable),
            conflict("route r", "x", Why::Ambiguous),
            conflict("route by-email", "a@x.io", Why::Ambiguous),
        ];
        assert_eq!(
            introduced(&before, &after),
            vec![conflict("route by-email", "a@x.io", Why::Ambiguous)]
        );
        assert!(introduced(&after, &before).is_empty());
        assert!(introduced(&[], &[]).is_empty());
    }
}
