//! The upstreams the pool draws from, and everything their wire formats
//! make differ: hosts, headers, credentials, request rewrites and quota
//! grammar.

pub mod anthropic;
pub mod codex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{HeaderMap, HeaderName};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::percent_encode;
use crate::pool::quota::Observation;
use crate::pool::{Account, Kind};

/// What one call to the OAuth token endpoint asks for.
pub enum Grant<'a> {
    Code {
        code: &'a str,
        state: &'a str,
        verifier: &'a str,
        redirect_uri: &'a str,
    },
    Refresh {
        refresh_token: &'a str,
    },
}

/// One token-endpoint call as its provider's client sends it.
pub struct TokenRequest {
    pub path: &'static str,
    pub content_type: &'static str,
    pub accept: &'static str,
    pub user_agent: Option<&'static str>,
    pub body: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    Anthropic,
    Codex,
}

impl Provider {
    pub const ALL: [Provider; 2] = [Provider::Anthropic, Provider::Codex];

    pub fn is_anthropic(&self) -> bool {
        *self == Provider::Anthropic
    }

    /// The serialised name, as messages and query parameters spell it.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::Codex => "codex",
        }
    }

    /// The provider whose API host the MITM listener intercepted.
    pub fn for_intercepted_host(host: &str) -> Option<Provider> {
        Self::ALL.into_iter().find(|p| p.api_host() == host)
    }

    fn api_host(self) -> &'static str {
        match self {
            Provider::Anthropic => anthropic::API_HOST,
            Provider::Codex => codex::API_HOST,
        }
    }

    /// The company answering upstream, as refusals name it.
    pub fn upstream_name(self) -> &'static str {
        match self {
            Provider::Anthropic => "Anthropic",
            Provider::Codex => "OpenAI",
        }
    }

    pub fn api_origin(self) -> &'static str {
        match self {
            Provider::Anthropic => anthropic::API_ORIGIN,
            Provider::Codex => codex::API_ORIGIN,
        }
    }

    /// The header naming the client's session.
    pub fn session_header(self) -> HeaderName {
        match self {
            Provider::Anthropic => anthropic::X_CLAUDE_CODE_SESSION_ID,
            Provider::Codex => codex::SESSION_ID,
        }
    }

    /// Telemetry, answered locally under the `block` policy.
    pub fn is_telemetry(self, path: &str) -> bool {
        match self {
            Provider::Anthropic => anthropic::is_telemetry(path),
            Provider::Codex => codex::is_telemetry(path),
        }
    }

    /// A path answering for one account, never served through the pool.
    pub fn is_account_bound(self, path: &str) -> bool {
        match self {
            Provider::Anthropic => anthropic::is_account_bound(path),
            Provider::Codex => codex::is_account_bound(path),
        }
    }

    /// The pooled account's credential headers on a credential-free request.
    pub fn inject_credential(self, headers: &mut HeaderMap, account: &Account) {
        match self {
            Provider::Anthropic => anthropic::inject_credential(headers, &account.credential),
            Provider::Codex => codex::inject_credential(headers, account),
        }
    }

    /// The body as the pooled account must send it; unchanged bytes when
    /// nothing needs rewriting.
    pub fn rewrite_body(self, body: Bytes, path: &str, account: &Account) -> Bytes {
        match self {
            Provider::Anthropic => anthropic::rewrite_body(body, path, account),
            Provider::Codex => body,
        }
    }

    /// What one response's headers say about the serving account's quota.
    pub fn observe_headers(self, kind: Kind, headers: &HeaderMap) -> Vec<Observation> {
        match self {
            Provider::Anthropic => anthropic::observe_headers(kind, headers),
            Provider::Codex => codex::observe_headers(headers),
        }
    }

    /// One usage-endpoint response as quota observations.
    pub fn observe_usage(self, usage: &Value) -> Result<Vec<Observation>, String> {
        match self {
            Provider::Anthropic => anthropic::observe_usage(usage),
            Provider::Codex => codex::observe_usage(usage),
        }
    }

    /// Whether a 429 body reports the organisation's spend cap.
    pub fn is_spend_cap_429(self, body: Option<&[u8]>) -> bool {
        match self {
            Provider::Anthropic => anthropic::is_spend_cap_429(body),
            Provider::Codex => codex::is_spend_cap_429(body),
        }
    }

    /// The zero-spend usage endpoint on the API origin.
    pub fn usage_path(self) -> &'static str {
        match self {
            Provider::Anthropic => anthropic::USAGE_PATH,
            Provider::Codex => codex::USAGE_PATH,
        }
    }

    pub fn token_origin(self) -> &'static str {
        match self {
            Provider::Anthropic => anthropic::TOKEN_ORIGIN,
            Provider::Codex => codex::TOKEN_ORIGIN,
        }
    }

    pub fn token_request(self, grant: Grant<'_>) -> TokenRequest {
        match self {
            Provider::Anthropic => anthropic::token_request(grant),
            Provider::Codex => codex::token_request(grant),
        }
    }

    /// The reason a rejected refresh's body names, when it names a known one.
    pub fn refresh_failure_code(self, body: &[u8]) -> Option<&'static str> {
        match self {
            Provider::Anthropic => None,
            Provider::Codex => codex::refresh_failure_code(body),
        }
    }

    pub fn authorization_url(self, challenge: &str, redirect_uri: &str, state: &str) -> String {
        match self {
            Provider::Anthropic => anthropic::authorization_url(challenge, redirect_uri, state),
            Provider::Codex => codex::authorization_url(challenge, redirect_uri, state),
        }
    }

    /// The one loopback port the OAuth client allows; `None` allows any.
    pub fn callback_port(self) -> Option<u16> {
        match self {
            Provider::Anthropic => None,
            Provider::Codex => Some(codex::CALLBACK_PORT),
        }
    }

    pub fn redirect_uri(self, port: u16) -> String {
        match self {
            Provider::Anthropic => anthropic::redirect_uri(port),
            Provider::Codex => codex::redirect_uri(port),
        }
    }
}

/// `key=value&…` with both sides percent-encoded: a query or a form body.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A JWT's claims, unverified: the token came from the token endpoint over TLS.
pub(crate) fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_provider_is_found_by_its_own_api_host_only() {
        for provider in Provider::ALL {
            assert_eq!(
                Provider::for_intercepted_host(provider.api_host()),
                Some(provider)
            );
            assert_eq!(
                provider.api_origin(),
                format!("https://{}", provider.api_host())
            );
        }
        assert_eq!(
            Provider::for_intercepted_host("probe.jaynshare.invalid"),
            None
        );
    }

    #[test]
    fn providers_serialize_lowercase() {
        for provider in Provider::ALL {
            assert_eq!(serde_json::to_value(provider).unwrap(), provider.as_str());
        }
        assert_eq!(Provider::Codex.as_str(), "codex");
        assert_eq!(
            serde_json::from_value::<Provider>(serde_json::json!("anthropic")).unwrap(),
            Provider::Anthropic
        );
    }
}
