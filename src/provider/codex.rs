//! Third-party facts about the Codex backend on chatgpt.com, as the Codex CLI
//! speaks to it under a ChatGPT login.

use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{Grant, TokenRequest, Tool, form, jwt_claims};
use crate::pool::quota::{Observation, SESSION, Scope, WEEKLY, parse_reset};
use crate::pool::{Account, Credential, Profile};

pub const API_HOST: &str = "chatgpt.com";
pub const API_ORIGIN: &str = "https://chatgpt.com";
pub const TOOL: Tool = Tool {
    executable: "codex",
    name: "Codex",
    home: "https://github.com/openai/codex",
    missing: "cli_codex_missing",
    account: "ChatGPT account",
    ca_variable: "CODEX_CA_CERTIFICATE",
    upstream_variables: &["OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL"],
    // Its shared background server keeps the environment of whichever
    // `codex` started it, so a turn handed to it would bypass the pool.
    pooled_args: &["--no-daemon"],
    deadline: None,
};
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
/// escape could move out of them upstream. Reading the usage is the one
/// exception: Codex's limits display shows nothing else.
pub fn is_account_bound(method: &Method, path: &str) -> bool {
    if method == Method::GET && path == USAGE_PATH {
        return false;
    }
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

pub const USAGE_PATH: &str = "/backend-api/wham/usage";
pub const AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
pub const TOKEN_ORIGIN: &str = "https://auth.openai.com";
pub const TOKEN_PATH: &str = "/oauth/token";
pub const OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const OAUTH_SCOPES: &str =
    "openid profile email offline_access api.connectors.read api.connectors.invoke";
const ORIGINATOR: &str = "codex_cli_rs";
/// Codex's own login server; the OAuth client allows no other redirect.
pub const CALLBACK_PORT: u16 = 1455;
pub const CALLBACK_PATH: &str = "/auth/callback";
const AUTH_CLAIM: &str = "https://api.openai.com/auth";
const PROFILE_CLAIM: &str = "https://api.openai.com/profile";
const REFRESH_FAILURE_CODES: [&str; 3] = [
    "refresh_token_expired",
    "refresh_token_reused",
    "refresh_token_invalidated",
];

/// `x-codex-{primary,secondary}-*`, each window onto the bucket its length names.
pub fn observe_headers(headers: &HeaderMap) -> Vec<Observation> {
    ["primary", "secondary"]
        .into_iter()
        .filter_map(|window| {
            let field = |name: &str| {
                headers
                    .get(format!("x-codex-{window}-{name}").as_str())
                    .and_then(|v| v.to_str().ok())
            };
            observation(
                field("window-minutes")?.trim().parse().ok()?,
                field("used-percent").and_then(|v| v.trim().parse().ok()),
                field("reset-at").and_then(parse_reset),
            )
        })
        .collect()
}

/// `rate_limit.{primary,secondary}_window` of the usage response.
pub fn observe_usage(usage: &Value) -> Result<Vec<Observation>, String> {
    let observations: Vec<Observation> = ["primary_window", "secondary_window"]
        .into_iter()
        .filter_map(|key| {
            let window = &usage["rate_limit"][key];
            observation(
                window["limit_window_seconds"].as_i64()? / 60,
                window["used_percent"].as_f64(),
                window["reset_at"]
                    .as_i64()
                    .and_then(|at| OffsetDateTime::from_unix_timestamp(at).ok()),
            )
        })
        .collect();
    if observations.is_empty() {
        Err("usage response contains no recognised quota observations".into())
    } else {
        Ok(observations)
    }
}

/// The 5-hour window is the session bucket, the 7-day one the weekly.
fn observation(
    window_minutes: i64,
    used_percent: Option<f64>,
    reset_at: Option<OffsetDateTime>,
) -> Option<Observation> {
    let name = match window_minutes {
        300 => SESSION,
        10_080 => WEEKLY,
        _ => return None,
    };
    let mut observation = Observation::new(name.to_string(), Scope::Account);
    observation.utilization = used_percent
        .filter(|percent| percent.is_finite() && *percent >= 0.0)
        .map(|percent| percent / 100.0);
    observation.reset_at = reset_at;
    (!observation.is_empty()).then_some(observation)
}

/// Codex has no organisation cap: `usage_limit_reached` is the account's
/// own windows, which its headers report.
pub fn is_spend_cap_429(_body: Option<&[u8]>) -> bool {
    false
}

pub fn authorization_url(challenge: &str, redirect_uri: &str, state: &str) -> String {
    let query = form(&[
        ("response_type", "code"),
        ("client_id", OAUTH_CLIENT_ID),
        ("redirect_uri", redirect_uri),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("scope", OAUTH_SCOPES),
        ("id_token_add_organizations", "true"),
        ("codex_cli_simplified_flow", "true"),
        ("originator", ORIGINATOR),
    ]);
    format!("{AUTHORIZE_URL}?{query}")
}

pub fn redirect_uri(port: u16) -> String {
    format!("http://127.0.0.1:{port}{CALLBACK_PATH}")
}

/// A form-encoded code exchange and a JSON refresh, as Codex sends them.
pub fn token_request(grant: Grant<'_>) -> TokenRequest {
    let (content_type, body) = match grant {
        Grant::Code {
            code,
            verifier,
            redirect_uri,
            ..
        } => (
            "application/x-www-form-urlencoded",
            form(&[
                ("grant_type", "authorization_code"),
                ("client_id", OAUTH_CLIENT_ID),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", verifier),
            ]),
        ),
        Grant::Refresh { refresh_token } => (
            "application/json",
            json!({
                "grant_type": "refresh_token",
                "client_id": OAUTH_CLIENT_ID,
                "refresh_token": refresh_token,
            })
            .to_string(),
        ),
    };
    TokenRequest {
        path: TOKEN_PATH,
        content_type,
        accept: "application/json",
        user_agent: None,
        body,
    }
}

/// The code sits in `error`, `error.code` or `code`.
pub fn refresh_failure_code(body: &[u8]) -> Option<&'static str> {
    let body: Value = serde_json::from_slice(body).ok()?;
    [&body["error"], &body["error"]["code"], &body["code"]]
        .into_iter()
        .filter_map(Value::as_str)
        .find_map(|code| {
            REFRESH_FAILURE_CODES
                .into_iter()
                .find(|known| known.eq_ignore_ascii_case(code))
        })
}

/// The identity a token response's id_token names; no workspace, no account.
pub fn profile(tokens: &Value) -> Result<Profile, String> {
    let claims = tokens["id_token"]
        .as_str()
        .and_then(jwt_claims)
        .ok_or_else(|| {
            "the token response carries no readable id_token; the account was not saved".to_string()
        })?;
    let workspace = claims[AUTH_CLAIM]["chatgpt_account_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            "the id_token names no ChatGPT workspace; the account was not saved".to_string()
        })?;
    let email = claims["email"]
        .as_str()
        .or_else(|| claims[PROFILE_CLAIM]["email"].as_str());
    Ok(Profile {
        email: email.map(String::from),
        chatgpt_account_id: Some(workspace.to_string()),
        ..Profile::default()
    })
}

#[cfg(test)]
pub(crate) fn fixture_jwt(claims: Value) -> String {
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("e30.{payload}.fixture-signature")
}

#[cfg(test)]
mod upstream_tests {
    use super::*;
    use crate::pool::Kind;
    use crate::pool::quota::{Classification, classify};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| (k.parse().unwrap(), HeaderValue::from_str(v).unwrap()))
            .collect()
    }

    #[test]
    fn each_header_window_lands_on_the_bucket_its_length_names() {
        let h = headers(&[
            ("x-codex-primary-used-percent", "42.5"),
            ("x-codex-primary-window-minutes", "300"),
            ("x-codex-primary-reset-at", "1757900000"),
            ("x-codex-secondary-used-percent", "7"),
            ("x-codex-secondary-window-minutes", "10080"),
            ("x-codex-other-used-percent", "99"),
            ("x-codex-other-window-minutes", "300"),
        ]);
        let obs = observe_headers(&h);
        assert_eq!(obs.len(), 2);
        assert_eq!(
            (obs[0].name.as_str(), obs[0].scope),
            (SESSION, Scope::Account)
        );
        assert_eq!(obs[0].utilization, Some(0.425));
        assert_eq!(obs[0].reset_at.unwrap().unix_timestamp(), 1_757_900_000);
        assert_eq!(
            (obs[1].name.as_str(), obs[1].utilization),
            (WEEKLY, Some(0.07))
        );

        // A weekly-only plan sends its one window as primary.
        let h = headers(&[
            ("x-codex-primary-used-percent", "50"),
            ("x-codex-primary-window-minutes", "10080"),
        ]);
        assert_eq!(observe_headers(&h)[0].name, WEEKLY);
    }

    #[test]
    fn a_window_of_unknown_or_missing_length_is_not_observed() {
        let h = headers(&[
            ("x-codex-primary-used-percent", "50"),
            ("x-codex-primary-window-minutes", "60"),
            ("x-codex-secondary-used-percent", "50"),
        ]);
        assert!(observe_headers(&h).is_empty());
    }

    #[test]
    fn a_full_window_classifies_a_429_as_exhaustion() {
        let h = headers(&[
            ("x-codex-primary-used-percent", "100"),
            ("x-codex-primary-window-minutes", "300"),
            ("x-codex-primary-reset-at", "4070908800"),
        ]);
        assert_eq!(
            classify(Kind::OAuth, None, &observe_headers(&h), &[]),
            Classification::Exhaustion {
                buckets: vec![SESSION.to_string()]
            }
        );
    }

    #[test]
    fn the_usage_payload_becomes_session_and_weekly_observations() {
        let usage = json!({
            "plan_type": "plus",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": {
                    "used_percent": 25,
                    "limit_window_seconds": 18000,
                    "reset_after_seconds": 600,
                    "reset_at": 1_757_900_000,
                },
                "secondary_window": {
                    "used_percent": 40,
                    "limit_window_seconds": 604800,
                    "reset_after_seconds": 6000,
                    "reset_at": 1_757_990_000,
                },
            },
            "credits": null,
        });
        let obs = observe_usage(&usage).expect("valid usage");
        assert_eq!(
            obs.iter()
                .map(|o| (o.name.as_str(), o.utilization))
                .collect::<Vec<_>>(),
            [(SESSION, Some(0.25)), (WEEKLY, Some(0.4))]
        );
        assert_eq!(obs[1].reset_at.unwrap().unix_timestamp(), 1_757_990_000);
    }

    #[test]
    fn a_usage_payload_without_windows_is_an_error() {
        assert!(observe_usage(&json!({ "plan_type": "free", "rate_limit": null })).is_err());
        assert!(observe_usage(&json!([])).is_err());
    }

    #[test]
    fn the_code_exchange_is_a_form_and_the_refresh_is_json() {
        let exchange = token_request(Grant::Code {
            code: "the code",
            state: "unsent",
            verifier: "the-verifier",
            redirect_uri: "http://127.0.0.1:1455/auth/callback",
        });
        assert_eq!(exchange.path, "/oauth/token");
        assert_eq!(exchange.content_type, "application/x-www-form-urlencoded");
        assert_eq!(
            exchange.body,
            "grant_type=authorization_code&client_id=app_EMoamEEZ73f0CkXaXp7hrann\
             &code=the%20code&redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback\
             &code_verifier=the-verifier"
        );

        let refresh = token_request(Grant::Refresh {
            refresh_token: "rt",
        });
        assert_eq!(refresh.content_type, "application/json");
        assert_eq!(
            serde_json::from_str::<Value>(&refresh.body).unwrap(),
            json!({
                "grant_type": "refresh_token",
                "client_id": OAUTH_CLIENT_ID,
                "refresh_token": "rt",
            })
        );
    }

    #[test]
    fn a_rejected_refresh_names_its_known_code_wherever_the_body_puts_it() {
        for (body, code) in [
            (
                r#"{"error":{"code":"refresh_token_reused"}}"#,
                Some("refresh_token_reused"),
            ),
            (
                r#"{"error":"refresh_token_expired"}"#,
                Some("refresh_token_expired"),
            ),
            (
                r#"{"error":"invalid_grant","code":"REFRESH_TOKEN_INVALIDATED"}"#,
                Some("refresh_token_invalidated"),
            ),
            (r#"{"error":"invalid_grant"}"#, None),
            ("<html>", None),
        ] {
            assert_eq!(refresh_failure_code(body.as_bytes()), code, "{body}");
        }
    }

    #[test]
    fn the_profile_is_read_from_the_id_token_claims() {
        let tokens = |claims: Value| json!({ "id_token": fixture_jwt(claims) });
        let flat = profile(&tokens(json!({
            "email": "dev@fixture.invalid",
            AUTH_CLAIM: { "chatgpt_account_id": "acct-fixture", "chatgpt_plan_type": "plus" },
        })))
        .expect("profile");
        assert_eq!(flat.email.as_deref(), Some("dev@fixture.invalid"));
        assert_eq!(flat.chatgpt_account_id.as_deref(), Some("acct-fixture"));
        assert_eq!(flat.account_uuid, None);

        let nested = profile(&tokens(json!({
            PROFILE_CLAIM: { "email": "nested@fixture.invalid" },
            AUTH_CLAIM: { "chatgpt_account_id": "acct-fixture" },
        })))
        .expect("profile");
        assert_eq!(nested.email.as_deref(), Some("nested@fixture.invalid"));

        assert!(profile(&tokens(json!({ "email": "dev@fixture.invalid" }))).is_err());
        assert!(profile(&json!({ "id_token": "not-a-jwt" })).is_err());
        assert!(profile(&json!({})).is_err());
    }
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
    fn only_codex_s_own_paths_and_the_usage_read_are_pooled_and_its_analytics_are_telemetry() {
        for pooled in ["/backend-api/codex/responses", "/backend-api/codex/models"] {
            assert!(!is_account_bound(&Method::POST, pooled), "{pooled}");
        }
        assert!(!is_account_bound(&Method::GET, USAGE_PATH));
        assert!(is_account_bound(&Method::POST, USAGE_PATH));
        for bound in [
            "/backend-api/wham/settings/user",
            "/backend-api/wham/usage/credit-usage-events",
            "/backend-api/wham/rate-limit-reset-credits",
            "/backend-api/ps/mcp",
            "/backend-api/codex",
            "/backend-api/codex/../wham/usage",
            "/backend-api/codex/%2e%2e/wham/usage",
        ] {
            assert!(is_account_bound(&Method::GET, bound), "{bound}");
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
