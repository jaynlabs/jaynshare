//! The client surface under `/control/v1/client`: read-only,
//! assembled by naming each allow-listed member rather than by removing
//! fields from the operator projection.
//!
//! # The status read only
//! Later work gives the whole client surface — the `session_id` form,
//! the catalogue and resolve, the CSRF guard and the trail — to wave B.
//! `status` is here already because `enrol`'s last check and
//! `status --client` need it, and both call it.
//! Wave B adds the rest beside it.

use std::sync::Arc;

use http::{Response, StatusCode};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::audit::Principal;
use crate::data_plane::relay::ResponseBody;
use crate::mitm::ca::Ca;
use crate::pool::quota::{SESSION, WEEKLY};
use crate::pool::{Account, Resolve, SessionKey, selection};
use crate::server::{Server, VERSION};

use super::{API_VERSION, error, percent_decode, provider_named, read};
use crate::timestamp::rfc3339;

/// The client projection. Every member below is named on purpose;
/// only shared rate-limit usage and resets are exposed per account; identity,
/// health, routes, configuration and other clients have no path into it.
/// With `?session_id=` the read
/// adds `session`: this principal's most recent serving account and when it
/// was last routed, or `null` when it has no such session (the lookup
/// is keyed by the client id too, so another client's session id yields
/// nothing).
pub(super) fn status(
    server: &Arc<Server>,
    principal: &Principal,
    query: Option<&str>,
) -> Response<ResponseBody> {
    let loaded = server.config();
    let config = &loaded.config;
    let now = OffsetDateTime::now_utc();
    let include_rate_limits =
        query.is_some_and(|query| query.split('&').any(|member| member == "rate_limits=true"));
    let (accounts_configured, accounts_selectable, sessions, rate_limits) = {
        let mut pool = server.pool.lock().expect("pool lock");
        if pool.expire_quota(now) {
            server.mark_quota_dirty();
        }
        let counts = pool.sessions(now).counts(now);
        let accounts = pool.accounts().to_vec();
        let selectable = accounts
            .iter()
            .filter(|account| {
                let hold = pool.organisation_hold(account, now);
                // Selectable is the same predicate the
                // catalogue shows.
                selection::selectable(account, &config.selection, pool.families(), now, hold)
            })
            .count();
        let rate_limits = include_rate_limits.then(|| {
            accounts
                .iter()
                .map(|account| {
                    json!({
                        "display_name": account.display_name,
                        "provider": account.provider,
                        "rate_limits": rate_limits(account),
                    })
                })
                .collect::<Vec<_>>()
        });
        (accounts.len(), selectable, counts, rate_limits)
    };
    let egress_on = config.data_plane.egress.mode != crate::config::EgressMode::Off;
    let session_id = query.and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("session_id="))
            .map(percent_decode)
            .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
    });
    let session = session_id.map(|session_id| {
        let mut pool = server.pool.lock().expect("pool lock");
        let key = SessionKey {
            principal: principal.key(),
            session_id,
        };
        pool.sessions(now)
            .record(&key)
            .map(|record| (record.last_served.or(record.bound), record.last_seen))
            .and_then(|(served, seen)| {
                pool.get(served?)
                    .map(|account| (account.display_name.clone(), seen))
            })
            .map_or(json!(null), |(display_name, last_routed_at)| {
                json!({
                    "serving_account_display_name": display_name,
                    "last_routed_at": rfc3339(last_routed_at),
                })
            })
    });
    // The closed capability list — the optional features the client adapts
    // to, each present only when it is on.
    let mut capabilities: Vec<&str> = Vec::new();
    if config.mitm.enabled {
        capabilities.push("mitm");
    }
    if config.selection.distribute_sessions {
        capabilities.push("distribution");
    }
    if config.quota.probe_enabled {
        capabilities.push("usage_probe");
    }
    if egress_on {
        capabilities.push("egress_guard");
    }
    // The greater of the data-plane hold budget and the egress hold,
    // `0` when neither holds.
    let hold_hint_seconds = config.data_plane.hold_budget_seconds.max(if egress_on {
        config.data_plane.egress.hold_seconds
    } else {
        0
    });
    let authorities = server.mitm_authorities().clone();
    let fingerprint = |ca: &Option<Arc<Ca>>| ca.as_ref().map(|ca| ca.fingerprint());
    let mut body = json!({
        "client": {
            "id": principal.id,
            "display_name": display_name(server, principal),
        },
        "server": {
            "version": VERSION,
            "available": !server.stopping(),
            "control_api_version": API_VERSION,
            // The pin a client keeps, so turning TLS on later does not strand it.
            "tls_pin": server.client_pin(),
        },
        "capabilities": capabilities,
        // A client trusts both while a rotation is staged.
        "ca_fingerprint": fingerprint(&authorities.current),
        "ca_next_fingerprint": fingerprint(&authorities.next),
        "pool": {
            "accounts_configured": accounts_configured,
            "accounts_selectable": accounts_selectable,
        },
        "sessions": { "known": sessions.known, "active": sessions.active },
        "wire_capture_enabled": server.capture.is_some(),
        "hold_hint_seconds": hold_hint_seconds,
    });
    if let Some(offer) = super::client_kit::offer(server) {
        for (name, value) in offer.members() {
            body["client"][name] = value;
        }
    }
    if let Some(session) = session {
        body["session"] = session;
    }
    if let Some(rate_limits) = rate_limits {
        body["accounts"] = json!(rate_limits);
    }
    read(body)
}

pub(super) fn rate_limits(account: &Account) -> Value {
    let bucket = |name| account.quota.iter().find(|bucket| bucket.name == name);
    let utilisation = |name| bucket(name).and_then(|bucket| bucket.effective_utilization());
    let reset = |name| bucket(name).and_then(|bucket| bucket.reset_at).map(rfc3339);
    json!({
        "five_hour": utilisation(SESSION),
        "weekly": utilisation(WEEKLY),
        "five_hour_reset_at": reset(SESSION),
        "weekly_reset_at": reset(WEEKLY),
    })
}

/// The client's own display name, from the registry entry its stable
/// id names. A rename moves the name, never the id.
pub(crate) fn display_name(server: &Server, principal: &Principal) -> Value {
    let Some(id) = principal.id.as_deref() else {
        return Value::Null;
    };
    server
        .registry()
        .clients
        .iter()
        .find(|entry| entry.id == id)
        .map_or(Value::Null, |entry| json!(entry.display_name))
}

/// The client catalogue: handle, display name, the selectable
/// boolean, and the two shared subscription rate-limit windows. Read-only:
/// nothing is resolved, moved or updated by this read.
pub(super) fn accounts(server: &Arc<Server>) -> Response<ResponseBody> {
    let loaded = server.config();
    let settings = &loaded.config.selection;
    let now = OffsetDateTime::now_utc();
    let mut pool = server.pool.lock().expect("pool lock");
    if pool.expire_quota(now) {
        server.mark_quota_dirty();
    }
    let accounts: Vec<Value> = pool
        .accounts()
        .iter()
        .map(|account| {
            json!({
                "handle": account.handle,
                "display_name": account.display_name,
                "provider": account.provider,
                "selectable": selection::selectable(
                    account,
                    settings,
                    pool.families(),
                    now,
                    pool.organisation_hold(account, now),
                ),
                "rate_limits": rate_limits(account),
            })
        })
        .collect();
    read(json!({ "accounts": accounts }))
}

/// The catalogue's read-only resolve within one provider (`&provider=`,
/// absent meaning `anthropic`, as a 2.1.x client sends it) — the catalogue
/// members for the account the reference names, `400`
/// `ambiguous_account_reference` with the matching display names, `404`
/// `account_not_found`.
pub(super) fn resolve(server: &Arc<Server>, query: Option<&str>) -> Response<ResponseBody> {
    let member = |name: &str| query.and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix(name)));
    let reference = member("reference=")
        .map(percent_decode)
        .filter(|r| !r.is_empty() && r.len() <= 1024 && !r.chars().any(char::is_control));
    let Some(reference) = reference else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "reference is required: one display name, email, UUID or handle",
            Some("reference".into()),
            vec![],
        );
    };
    let provider = match provider_named(&json!(member("provider="))) {
        Ok(provider) => provider.unwrap_or_default(),
        Err(refusal) => return *refusal,
    };
    let now = OffsetDateTime::now_utc();
    let resolved = {
        let mut pool = server.pool.lock().expect("pool lock");
        if pool.expire_quota(now) {
            server.mark_quota_dirty();
        }
        pool.resolve_in(provider, &reference).cloned()
    };
    match resolved {
        Ok(account) => {
            let settings = &server.config().config.selection;
            let selectable = {
                let pool = server.pool.lock().expect("pool lock");
                selection::selectable(
                    &account,
                    settings,
                    pool.families(),
                    now,
                    pool.organisation_hold(&account, now),
                )
            };
            read(json!({
                "account": {
                    "handle": account.handle,
                    "display_name": account.display_name,
                    "provider": account.provider,
                    "selectable": selectable,
                }
            }))
        }
        Err(Resolve::NotFound) => error(
            StatusCode::NOT_FOUND,
            "account_not_found",
            "no account matches the reference",
            Some(reference.clone()),
            vec![],
        ),
        Err(Resolve::Ambiguous(names)) => error(
            StatusCode::BAD_REQUEST,
            "ambiguous_account_reference",
            &format!(
                "the reference matches several accounts: {}; an organisation name or full organisation UUID is the qualifier",
                Resolve::listed(&names)
            ),
            Some(reference),
            vec![],
        ),
    }
}
