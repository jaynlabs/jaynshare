//! Third-party facts about the Codex backend on chatgpt.com, as the Codex CLI
//! speaks to it under a ChatGPT login.

use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::{Value, json};

use crate::pool::quota::Observation;
use crate::pool::{Account, Credential};

pub const API_HOST: &str = "chatgpt.com";
pub const API_ORIGIN: &str = "https://chatgpt.com";
pub const SESSION_ID: HeaderName = HeaderName::from_static("session-id");
pub const CHATGPT_ACCOUNT_ID: HeaderName = HeaderName::from_static("chatgpt-account-id");
/// Codex's own paths; the rest of chatgpt.com is account features.
const CODEX_PREFIX: &str = "/backend-api/codex/";
const TELEMETRY_PATH: &str = "/backend-api/codex/analytics-events";
/// The workspace check Codex makes before a turn.
const ACCOUNTS_CHECK_PATH: &str = "/backend-api/wham/accounts/check";
/// Codex falls back from its WebSocket to HTTP on this answer at once.
pub const UPGRADE_REFUSAL: StatusCode = StatusCode::UPGRADE_REQUIRED;
/// The one 429 type Codex shows rather than retrying silently.
const USAGE_LIMIT_REACHED: &str = "usage_limit_reached";

/// The telemetry path and anything under it.
pub fn is_telemetry(path: &str) -> bool {
    path.strip_prefix(TELEMETRY_PATH)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Everything outside Codex's own paths, and any path a dot segment or an
/// escape could move out of them upstream.
pub fn is_account_bound(path: &str) -> bool {
    !path.starts_with(CODEX_PREFIX) || path.contains("..") || path.contains('%')
}

/// Codex refuses a turn unless the check lists its own login's account, so
/// the proxy answers it for the caller's account id, whatever the pool holds.
pub fn local_answer(path: &str, headers: &HeaderMap) -> Option<Value> {
    if path != ACCOUNTS_CHECK_PATH {
        return None;
    }
    let id = headers
        .get(CHATGPT_ACCOUNT_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    Some(json!({
        "accounts": [{
            "id": id,
            "workspace_backend_origin": "NO_CONSTRAINT",
            "account_routing_override": "NO_CONSTRAINT",
        }],
        "account_ordering": [id],
        "default_account_id": id,
    }))
}

/// Codex shows `error.message`. A 429 carries `resets_at` (Unix seconds)
/// under the type Codex reports instead of retrying.
pub fn error_envelope(error_type: &str, message: &str, resets_at: Option<i64>) -> Value {
    match resets_at {
        Some(at) => json!({
            "error": { "type": USAGE_LIMIT_REACHED, "message": message, "resets_at": at },
        }),
        None => json!({ "error": { "type": error_type, "message": message } }),
    }
}

/// Codex accounts are ChatGPT logins; an API key has no Codex form, so it
/// injects nothing and upstream answers 401.
pub fn inject_credential(headers: &mut HeaderMap, account: &Account) {
    if let Credential::OAuth(c) = &account.credential
        && let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", c.access_token.expose()))
    {
        headers.insert(AUTHORIZATION, v);
    }
    if let Some(v) = account
        .profile
        .chatgpt_account_id
        .as_deref()
        .and_then(|id| HeaderValue::from_str(id).ok())
    {
        headers.insert(CHATGPT_ACCOUNT_ID, v);
    }
}

// Lane B: `x-codex-{primary,secondary}-*` onto `session` and `weekly`.
pub fn observe_headers(_headers: &HeaderMap) -> Vec<Observation> {
    Vec::new()
}

// Lane B: `/backend-api/wham/usage`.
pub fn observe_usage(_usage: &Value) -> Result<Vec<Observation>, String> {
    Err("Codex usage is not read yet".into())
}

// Lane B: the usage-limit 429 body.
pub fn is_spend_cap_429(_body: Option<&[u8]>) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{OAuthCredential, Profile, Secret, Source};
    use crate::provider::Provider;
    use time::macros::datetime;

    #[test]
    fn the_pooled_login_replaces_the_client_s_bearer_and_workspace() {
        let account = Account::new(
            Provider::Codex,
            String::new(),
            Profile {
                chatgpt_account_id: Some("acct-pool".into()),
                ..Profile::default()
            },
            Source::PortableJson,
            Credential::OAuth(OAuthCredential {
                access_token: Secret::new("pooled".into()),
                refresh_token: None,
                expires_at: datetime!(2027-01-01 00:00 UTC),
                last_refresh_attempt_at: None,
                last_refresh_success_at: None,
                refresh_not_before: None,
            }),
        );
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer own"));
        h.insert(CHATGPT_ACCOUNT_ID, HeaderValue::from_static("acct-own"));
        inject_credential(&mut h, &account);
        assert_eq!(h[AUTHORIZATION], "Bearer pooled");
        assert_eq!(h[CHATGPT_ACCOUNT_ID], "acct-pool");
    }

    #[test]
    fn only_codex_s_own_paths_are_pooled_and_its_analytics_are_telemetry() {
        for pooled in ["/backend-api/codex/responses", "/backend-api/codex/models"] {
            assert!(!is_account_bound(pooled), "{pooled}");
        }
        for bound in [
            "/backend-api/wham/settings/user",
            "/backend-api/ps/mcp",
            "/backend-api/codex",
            "/backend-api/codex/../wham/usage",
            "/backend-api/codex/%2e%2e/wham/usage",
        ] {
            assert!(is_account_bound(bound), "{bound}");
        }
        assert!(is_telemetry("/backend-api/codex/analytics-events/events"));
        assert!(is_telemetry(TELEMETRY_PATH));
        assert!(!is_telemetry("/backend-api/codex/analytics-eventsx"));
    }

    #[test]
    fn the_accounts_check_echoes_the_caller_s_own_account() {
        let mut h = HeaderMap::new();
        h.insert(CHATGPT_ACCOUNT_ID, HeaderValue::from_static("acct-own"));
        let answer = local_answer(ACCOUNTS_CHECK_PATH, &h).expect("answered");
        assert_eq!(answer["accounts"][0]["id"], "acct-own");
        assert_eq!(answer["default_account_id"], "acct-own");
        assert!(local_answer("/backend-api/codex/responses", &h).is_none());
    }
}
