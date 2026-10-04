//! Third-party facts about the Anthropic API, and the pool's side of its
//! wire format. None of the facts are ours to change.

use bytes::Bytes;
use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Deadline, Grant, TokenRequest, Tool};
use crate::pool::quota::{
    API_KEY_BUCKETS, FAMILY_FABLE, Observation, SESSION, Scope, WEEKLY, parse_reset,
};
use crate::pool::{Account, Credential, Kind};

/// the API host; inference and telemetry.
pub const API_HOST: &str = "api.anthropic.com";
pub const TOOL: Tool = Tool {
    executable: "claude",
    name: "Claude Code",
    home: "https://code.claude.com",
    missing: "cli_claude_missing",
    account: "Claude account",
    ca_variable: "NODE_EXTRA_CA_CERTS",
    upstream_variables: &[
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_CUSTOM_HEADERS",
    ],
    deadline: Some(Deadline {
        variable: "API_TIMEOUT_MS",
        default_ms: 600_000,
    }),
};
pub const API_ORIGIN: &str = "https://api.anthropic.com";
/// the beta an OAuth (subscription) bearer needs in `anthropic-beta`.
pub const OAUTH_BETA: &str = "oauth-2025-04-20";
/// profile endpoint path on the API host.
pub const PROFILE_PATH: &str = "/api/oauth/profile";
/// the zero-spend OAuth usage endpoint.
pub const USAGE_PATH: &str = "/api/oauth/usage";
/// Claude Code's telemetry path.
pub const TELEMETRY_PATH: &str = "/api/event_logging";
/// The answer to an upgrade inside an intercepted tunnel.
pub const UPGRADE_REFUSAL: http::StatusCode = http::StatusCode::NOT_IMPLEMENTED;

/// The telemetry path and anything under it.
pub fn is_telemetry(path: &str) -> bool {
    path.strip_prefix(TELEMETRY_PATH)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}
/// account-bound paths on the API host, as observed; the list is
/// open and grows with the live gates. `<org>` is one path segment.
const ACCOUNT_BOUND_PATHS: &[&str] = &[
    "/api/oauth/account/settings",
    "/api/oauth/organizations/<org>/marketplaces",
    "/api/oauth/organizations/<org>/plugins/list-plugins",
    "/api/oauth/organizations/<org>/skills/list-skills",
    "/api/claude_code_grove",
    "/v1/mcp_servers",
];

/// whether `path` (no query) answers for one account.
pub fn is_account_bound(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    ACCOUNT_BOUND_PATHS.iter().any(|form| {
        let form: Vec<&str> = form.split('/').collect();
        form.len() == segments.len()
            && form
                .iter()
                .zip(&segments)
                .all(|(f, s)| if *f == "<org>" { !s.is_empty() } else { f == s })
    })
}

/// the two paths whose tool pairs are made consistent.
pub const MESSAGES_PATH: &str = "/v1/messages";
pub const COUNT_TOKENS_PATH: &str = "/v1/messages/count_tokens";

pub const ANTHROPIC_BETA: HeaderName = HeaderName::from_static("anthropic-beta");
pub const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
pub const X_CLAUDE_CODE_SESSION_ID: HeaderName =
    HeaderName::from_static("x-claude-code-session-id");
pub const RATELIMIT_PREFIX: &str = "anthropic-ratelimit-";
pub const RATELIMIT_UNIFIED_PREFIX: &str = "anthropic-ratelimit-unified-";
/// The unified window of the one verified family, `fable`.
pub const FAMILY_FABLE_HEADER: &str = "7d_oi";
/// The error code that classifies a 429 as organisation spend-cap exhaustion.
pub const SPEND_CAP_CODE: &str = "enforced_spend_limit_reached";

/// the browser authorisation page.
pub const AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
/// the OAuth token endpoint host and path.
pub const TOKEN_ORIGIN: &str = "https://platform.claude.com";
pub const TOKEN_PATH: &str = "/v1/oauth/token";
/// the public client id the login and refresh calls carry.
pub const OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// the scopes one browser login asks for, space separated.
pub const OAUTH_SCOPES: &str = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
/// where the browser may land after a completed login.
pub const OAUTH_SUCCESS_URL: &str =
    "https://platform.claude.com/oauth/code/success?app=claude-code";

pub fn authorization_url(challenge: &str, redirect_uri: &str, state: &str) -> String {
    let query = super::form(&[
        ("code", "true"),
        ("client_id", OAUTH_CLIENT_ID),
        ("response_type", "code"),
        ("redirect_uri", redirect_uri),
        ("scope", OAUTH_SCOPES),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
    ]);
    format!("{AUTHORIZE_URL}?{query}")
}

pub fn redirect_uri(port: u16) -> String {
    format!("http://localhost:{port}/callback")
}

/// JSON both ways; the refresh call looks like Claude Code's own.
pub fn token_request(grant: Grant<'_>) -> TokenRequest {
    match grant {
        Grant::Code {
            code,
            state,
            verifier,
            redirect_uri,
        } => TokenRequest {
            path: TOKEN_PATH,
            content_type: "application/json",
            accept: "application/json",
            user_agent: None,
            body: serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "state": state,
                "client_id": OAUTH_CLIENT_ID,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            })
            .to_string(),
        },
        Grant::Refresh { refresh_token } => TokenRequest {
            path: TOKEN_PATH,
            content_type: "application/json",
            accept: "application/json, text/plain, */*",
            user_agent: Some("axios/1.13.6"),
            body: serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": OAUTH_CLIENT_ID,
            })
            .to_string(),
        },
    }
}

/// error classes by status, plus our own `proxy_error`.
pub mod error_type {
    pub const INVALID_REQUEST: &str = "invalid_request_error";
    pub const AUTHENTICATION: &str = "authentication_error";
    pub const REQUEST_TOO_LARGE: &str = "request_too_large";
    pub const NOT_FOUND: &str = "not_found_error";
    pub const RATE_LIMIT: &str = "rate_limit_error";
    pub const PROXY: &str = "proxy_error";
}

/// error envelope: `{"type":"error","error":{"type":…,"message":…},"request_id":…}`.
pub fn error_envelope(error_type: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "error",
        "error": { "type": error_type, "message": message },
        "request_id": serde_json::Value::Null,
    })
}

/// Exactly one credential header, plus the OAuth beta for a bearer.
pub fn inject_credential(headers: &mut HeaderMap, credential: &Credential) {
    match credential {
        Credential::ApiKey(key) => {
            headers.insert(X_API_KEY, header_value(key.expose()));
        }
        Credential::OAuth(c) => {
            headers.insert(
                AUTHORIZATION,
                header_value(&format!("Bearer {}", c.access_token.expose())),
            );
            append_beta(headers, OAUTH_BETA);
        }
    }
}

fn header_value(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Existing entries kept in order; the value appended once when absent.
fn append_beta(headers: &mut HeaderMap, beta: &str) {
    let existing: Vec<String> = headers
        .get_all(ANTHROPIC_BETA)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .collect();
    if existing.iter().any(|b| b == beta) {
        return;
    }
    let mut joined = existing;
    joined.push(beta.to_string());
    headers.insert(ANTHROPIC_BETA, header_value(&joined.join(",")));
}

/// The account-UUID rewrite applies to an OAuth account only.
pub fn rewrite_body(body: Bytes, path: &str, account: &Account) -> Bytes {
    let account_uuid = match account.credential {
        Credential::OAuth(_) => account.profile.account_uuid,
        Credential::ApiKey(_) => None,
    };
    rewrite(body, path, account_uuid)
}

/// Checks and rewrites together. Returns the original bytes when nothing changed, so a
/// well-formed body is forwarded byte-for-byte.
fn rewrite(body: Bytes, path: &str, account_uuid: Option<Uuid>) -> Bytes {
    let Ok(Value::Object(mut top)) = serde_json::from_slice::<Value>(&body) else {
        return body;
    };
    let mut changed = false;
    if let Some(uuid) = account_uuid
        && rewrite_account_uuid(&mut top, uuid)
    {
        changed = true;
    }
    if (path == MESSAGES_PATH || path == COUNT_TOKENS_PATH)
        && contains_either(&body, b"tool_use", b"tool_result")
        && let Some(Value::Array(messages)) = top.get_mut("messages")
        && sanitize_tool_pairs(messages)
    {
        changed = true;
    }
    if changed {
        Bytes::from(serde_json::to_vec(&Value::Object(top)).expect("value serializes"))
    } else {
        body
    }
}

fn contains_either(haystack: &[u8], a: &[u8], b: &[u8]) -> bool {
    let find = |needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    find(a) || find(b)
}

/// The account-UUID rewrite: `metadata.user_id` is a JSON string holding an object.
fn rewrite_account_uuid(top: &mut serde_json::Map<String, Value>, uuid: Uuid) -> bool {
    let Some(Value::String(user_id)) = top.get_mut("metadata").and_then(|m| m.get_mut("user_id"))
    else {
        return false;
    };
    let Ok(Value::Object(mut inner)) = serde_json::from_str::<Value>(user_id) else {
        return false;
    };
    let wanted = Value::String(uuid.to_string());
    match inner.get_mut("account_uuid") {
        Some(current) if *current != wanted => {
            *current = wanted;
            *user_id = serde_json::to_string(&Value::Object(inner)).expect("serializes");
            true
        }
        _ => false,
    }
}

fn block_ids<'a>(message: &'a Value, block_type: &str, id_key: &str) -> Vec<&'a str> {
    message
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some(block_type))
        .filter_map(|b| b.get(id_key).and_then(Value::as_str))
        .collect()
}

/// Remove orphans, drop emptied messages, merge same-role neighbours,
/// and re-examine until stable. Returns whether anything changed.
fn sanitize_tool_pairs(messages: &mut Vec<Value>) -> bool {
    let mut changed = false;
    loop {
        let mut pass_changed = false;
        for i in 0..messages.len() {
            let next_results: Vec<String> = messages
                .get(i + 1)
                .map(|m| {
                    block_ids(m, "tool_result", "tool_use_id")
                        .into_iter()
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let prev_uses: Vec<String> = i
                .checked_sub(1)
                .and_then(|p| messages.get(p))
                .map(|m| {
                    block_ids(m, "tool_use", "id")
                        .into_iter()
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let Some(Value::Array(content)) = messages[i].get_mut("content") else {
                continue;
            };
            let before = content.len();
            content.retain(|b| match b.get("type").and_then(Value::as_str) {
                Some("tool_use") => b
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| next_results.iter().any(|r| r == id)),
                Some("tool_result") => b
                    .get("tool_use_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| prev_uses.iter().any(|u| u == id)),
                _ => true,
            });
            pass_changed |= content.len() != before;
        }
        let before = messages.len();
        messages.retain(|m| {
            m.get("content")
                .and_then(Value::as_array)
                .is_none_or(|c| !c.is_empty())
        });
        pass_changed |= messages.len() != before;
        let mut i = 1;
        while i < messages.len() {
            if messages[i].get("role") == messages[i - 1].get("role") {
                let mut moved = messages.remove(i);
                if let (Some(Value::Array(dst)), Some(Value::Array(src))) =
                    (messages[i - 1].get_mut("content"), moved.get_mut("content"))
                {
                    dst.append(src);
                }
                pass_changed = true;
            } else {
                i += 1;
            }
        }
        changed |= pass_changed;
        if !pass_changed {
            return changed;
        }
    }
}

/// Parse one usage response. Percent values become the
/// fractions used by the shared quota model; omitted windows remain omitted.
pub fn observe_usage(value: &Value) -> Result<Vec<Observation>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "usage response is not a JSON object".to_string())?;
    let mut observations = Vec::new();
    for (key, name, scope) in [
        ("five_hour", SESSION, Scope::Account),
        ("seven_day", WEEKLY, Scope::Account),
        ("seven_day_sonnet", "weekly:sonnet", Scope::Family),
    ] {
        let Some(window) = object.get(key).filter(|value| !value.is_null()) else {
            continue;
        };
        observations.push(usage_window(window, name, scope)?);
    }
    if let Some(limits) = object.get("limits") {
        let limits = limits
            .as_array()
            .ok_or_else(|| "usage response limits is not an array".to_string())?;
        for limit in limits {
            let is_fable = limit["group"] == "weekly"
                && limit
                    .pointer("/scope/model/display_name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.to_ascii_lowercase().contains(FAMILY_FABLE));
            if is_fable {
                observations.push(usage_limit(limit, "weekly:fable")?);
            }
        }
    }
    observations.retain(|observation| !observation.is_empty());
    if observations.is_empty() {
        Err("usage response contains no recognised quota observations".into())
    } else {
        Ok(observations)
    }
}

fn usage_window(value: &Value, name: &str, scope: Scope) -> Result<Observation, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("usage response {name} window is not an object"))?;
    let mut observation = Observation::new(name.to_string(), scope);
    observation.utilization = object
        .get("utilization")
        .or_else(|| object.get("used_percentage"))
        .and_then(percent);
    observation.reset_at = object.get("resets_at").and_then(reset_value);
    Ok(observation)
}

fn usage_limit(value: &Value, name: &str) -> Result<Observation, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "usage response limit is not an object".to_string())?;
    let mut observation = Observation::new(name.to_string(), Scope::Family);
    observation.utilization = object.get("percent").and_then(percent);
    observation.reset_at = object.get("resets_at").and_then(reset_value);
    Ok(observation)
}

fn percent(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .filter(|percent| percent.is_finite() && (0.0..=100.0).contains(percent))
        .map(|percent| percent / 100.0)
}

fn reset_value(value: &Value) -> Option<OffsetDateTime> {
    match value {
        Value::String(value) => parse_reset(value),
        Value::Number(value) => parse_reset(&value.to_string()),
        _ => None,
    }
}

/// What one attempt's response headers say about the serving account.
pub fn observe_headers(kind: Kind, headers: &HeaderMap) -> Vec<Observation> {
    let mut found: Vec<Observation> = Vec::new();
    fn slot(found: &mut Vec<Observation>, name: &str, scope: Scope) -> usize {
        match found.iter().position(|o| o.name == name) {
            Some(i) => i,
            None => {
                found.push(Observation::new(name.to_string(), scope));
                found.len() - 1
            }
        }
    }
    for (header, value) in headers {
        let Ok(value) = value.to_str() else { continue };
        let name = header.as_str();
        match kind {
            Kind::OAuth => {
                // anthropic-ratelimit-unified-<window>-<field>
                let Some(rest) = name.strip_prefix(RATELIMIT_UNIFIED_PREFIX) else {
                    continue;
                };
                let Some((window, field)) = rest.rsplit_once('-') else {
                    continue;
                };
                let (bucket, scope) = match window {
                    "5h" => (SESSION.to_string(), Scope::Account),
                    "7d" => (WEEKLY.to_string(), Scope::Account),
                    w if w == FAMILY_FABLE_HEADER => {
                        (format!("weekly:{FAMILY_FABLE}"), Scope::Family)
                    }
                    _ => continue,
                };
                let i = slot(&mut found, &bucket, scope);
                match field {
                    "utilization" => {
                        found[i].utilization =
                            value.trim().parse::<f64>().ok().filter(|u| u.is_finite())
                    }
                    "status" => found[i].status = Some(value.trim().to_string()),
                    "reset" => found[i].reset_at = parse_reset(value),
                    _ => {}
                }
            }
            Kind::ApiKey => {
                // anthropic-ratelimit-<bucket>-<limit|remaining|reset>
                let Some(rest) = name.strip_prefix(RATELIMIT_PREFIX) else {
                    continue;
                };
                if rest.starts_with("unified-") {
                    continue;
                }
                let Some((bucket, field)) = rest.rsplit_once('-') else {
                    continue;
                };
                if !API_KEY_BUCKETS.contains(&bucket) {
                    continue;
                }
                let i = slot(&mut found, bucket, Scope::Account);
                let number = || {
                    value
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .filter(|n| n.is_finite() && *n >= 0.0)
                };
                match field {
                    "limit" => found[i].limit = number(),
                    "remaining" => found[i].remaining = number(),
                    "reset" => found[i].reset_at = parse_reset(value),
                    _ => {}
                }
            }
        }
    }
    found.retain(|o| !o.is_empty());
    found
}

/// The spend-cap 429 carries the code under `error.details`.
pub fn is_spend_cap_429(body: Option<&[u8]>) -> bool {
    let Some(bytes) = body else { return false };
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| {
            v.pointer("/error/details/error_code")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .is_some_and(|code| code == SPEND_CAP_CODE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::quota::{Source, apply, expected_buckets};
    use serde_json::json;
    use time::macros::datetime;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                k.parse::<http::HeaderName>().unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn the_listed_forms_are_account_bound() {
        assert!(is_account_bound("/api/oauth/account/settings"));
        assert!(is_account_bound(
            "/api/oauth/organizations/org-1/skills/list-skills"
        ));
        assert!(is_account_bound("/v1/mcp_servers"));
    }

    #[test]
    fn neighbours_of_the_forms_are_not() {
        assert!(!is_account_bound("/api/oauth/organizations//marketplaces"));
        assert!(!is_account_bound(
            "/api/oauth/organizations/a/b/marketplaces"
        ));
        assert!(!is_account_bound("/v1/mcp_servers/extra"));
        assert!(!is_account_bound("/api/event_logging/v2/batch"));
        assert!(!is_account_bound("/v1/messages"));
    }

    #[test]
    fn oauth_injects_bearer_and_appends_beta_once_in_order() {
        let cred = Credential::OAuth(crate::pool::account::OAuthCredential {
            access_token: crate::pool::Secret::new("tok".into()),
            refresh_token: None,
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
            last_refresh_attempt_at: None,
            last_refresh_success_at: None,
            refresh_not_before: None,
        });
        let mut h = HeaderMap::new();
        h.insert(ANTHROPIC_BETA, HeaderValue::from_static("a-1,b-2"));
        inject_credential(&mut h, &cred);
        assert_eq!(h[AUTHORIZATION], "Bearer tok");
        assert_eq!(h[ANTHROPIC_BETA], "a-1,b-2,oauth-2025-04-20");
        inject_credential(&mut h, &cred);
        assert_eq!(h[ANTHROPIC_BETA], "a-1,b-2,oauth-2025-04-20");
        assert!(h.get(X_API_KEY).is_none());

        let mut h = HeaderMap::new();
        h.insert(ANTHROPIC_BETA, HeaderValue::from_static("a-1"));
        inject_credential(
            &mut h,
            &Credential::ApiKey(crate::pool::Secret::new("sk".into())),
        );
        assert_eq!(h[X_API_KEY], "sk");
        assert_eq!(h[ANTHROPIC_BETA], "a-1");
        assert!(h.get(AUTHORIZATION).is_none());
    }

    #[test]
    fn account_uuid_is_rewritten_only_inside_metadata_user_id() {
        let uuid = Uuid::new_v4();
        let body = json!({
            "system": [{"type": "text", "text": "x-anthropic-billing-header: cc_version=1;"}],
            "metadata": {"user_id": "{\"device_id\":\"d\",\"account_uuid\":\"\",\"session_id\":\"s\"}"},
            "account_uuid": "elsewhere",
        });
        let out = rewrite(
            Bytes::from(serde_json::to_vec(&body).unwrap()),
            "/v1/messages",
            Some(uuid),
        );
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["account_uuid"], "elsewhere");
        assert_eq!(v["system"], body["system"]);
        let inner: Value =
            serde_json::from_str(v["metadata"]["user_id"].as_str().unwrap()).unwrap();
        assert_eq!(inner["account_uuid"], uuid.to_string());
        assert_eq!(inner["device_id"], "d");
    }

    #[test]
    fn well_formed_body_is_forwarded_byte_for_byte() {
        let raw = Bytes::from_static(b"{\"model\":\"m\", \"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]}]}");
        assert_eq!(rewrite(raw.clone(), "/v1/messages", Some(Uuid::nil())), raw);
    }

    #[test]
    fn orphan_tool_pairs_are_removed_and_neighbours_merged() {
        let body = json!({
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "q"}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "a", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "b", "content": "x"}]},
                {"role": "assistant", "content": [{"type": "text", "text": "done"}]},
            ]
        });
        let out = rewrite(
            Bytes::from(serde_json::to_vec(&body).unwrap()),
            "/v1/messages",
            None,
        );
        let v: Value = serde_json::from_slice(&out).unwrap();
        let messages = v["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[1]["content"][0]["text"], "done");

        let other_path = rewrite(
            Bytes::from(serde_json::to_vec(&body).unwrap()),
            "/v1/other",
            None,
        );
        assert_eq!(serde_json::from_slice::<Value>(&other_path).unwrap(), body);
    }

    #[test]
    fn removing_one_pair_re_examines_the_exposed_neighbour() {
        let body = json!({
            "messages": [
                {"role": "assistant", "content": [{"type": "tool_use", "id": "a", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a", "content": "x"}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "b", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "zzz", "content": "y"}]},
            ]
        });
        let out = rewrite(
            Bytes::from(serde_json::to_vec(&body).unwrap()),
            "/v1/messages",
            None,
        );
        let v: Value = serde_json::from_slice(&out).unwrap();
        let messages = v["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["content"][0]["id"], "a");
        assert_eq!(messages[1]["content"][0]["tool_use_id"], "a");
    }

    #[test]
    fn unified_headers_become_session_and_weekly_observations() {
        let h = headers(&[
            ("anthropic-ratelimit-unified-5h-utilization", "0.42"),
            ("anthropic-ratelimit-unified-5h-status", "allowed"),
            ("anthropic-ratelimit-unified-5h-reset", "1757900000"),
            ("anthropic-ratelimit-unified-7d-utilization", "0.9"),
            ("anthropic-ratelimit-unified-7d_oi-utilization", "1.2"),
            ("anthropic-ratelimit-unified-status", "allowed"),
            (
                "anthropic-ratelimit-unified-representative-claim",
                "five_hour",
            ),
        ]);
        let obs = observe_headers(Kind::OAuth, &h);
        let names: Vec<&str> = obs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, ["session", "weekly", "weekly:fable"]);
        assert_eq!(obs[0].utilization, Some(0.42));
        assert_eq!(obs[0].status.as_deref(), Some("allowed"));
        assert_eq!(obs[0].reset_at.unwrap().unix_timestamp(), 1_757_900_000);
        assert_eq!(obs[2].scope, Scope::Family);
        assert_eq!(obs[2].utilization, Some(1.2));
    }

    #[test]
    fn api_key_headers_keep_four_independent_windows() {
        let h = headers(&[
            ("anthropic-ratelimit-requests-limit", "50"),
            ("anthropic-ratelimit-requests-remaining", "10"),
            ("anthropic-ratelimit-requests-reset", "2026-09-16T10:00:00Z"),
            ("anthropic-ratelimit-tokens-limit", "1000"),
            ("anthropic-ratelimit-tokens-remaining", "1000"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.5"),
        ]);
        let obs = observe_headers(Kind::ApiKey, &h);
        let names: Vec<&str> = obs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, ["requests", "tokens"]);
        let mut buckets = expected_buckets(Kind::ApiKey);
        apply(
            &mut buckets,
            obs,
            Source::ResponseHeaders,
            datetime!(2026-09-16 09:00 UTC),
        );
        assert_eq!(buckets[0].effective_utilization(), Some(0.8));
        assert_eq!(buckets[1].effective_utilization(), Some(0.0));
        assert_eq!(buckets[2].effective_utilization(), None);
    }

    #[test]
    fn usage_percent_and_reset_shapes_become_shared_observations() {
        let usage = serde_json::json!({
            "five_hour": { "utilization": 25.0, "resets_at": 1_757_900_000 },
            "seven_day": { "used_percentage": 40.0, "resets_at": 1_757_900_000_123_i64 },
            "seven_day_sonnet": { "utilization": 12.5, "resets_at": "2025-09-15T01:33:20Z" },
            "limits": [{
                "group": "weekly",
                "scope": { "model": { "display_name": "Claude Fable" } },
                "percent": 110.0,
                "resets_at": "2025-09-15T01:33:20Z",
            }],
        });

        let observations = observe_usage(&usage).expect("valid usage response");

        assert_eq!(
            observations
                .iter()
                .map(|observation| observation.name.as_str())
                .collect::<Vec<_>>(),
            ["session", "weekly", "weekly:sonnet", "weekly:fable"]
        );
        assert_eq!(observations[0].utilization, Some(0.25));
        assert_eq!(observations[1].utilization, Some(0.4));
        assert_eq!(observations[2].utilization, Some(0.125));
        assert_eq!(
            observations[3].utilization, None,
            "percent is bounded to 0…100"
        );
        assert_eq!(observations[0].reset_at, observations[1].reset_at);
        assert_eq!(observations[1].reset_at, observations[2].reset_at);
    }
}
