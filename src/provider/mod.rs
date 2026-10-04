//! The upstreams the pool draws from, and everything their wire formats
//! make differ: hosts, headers, credentials, request rewrites and quota
//! grammar.

pub mod anthropic;
pub mod codex;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pool::quota::Observation;
use crate::pool::{Account, Kind};

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

    /// A request the proxy answers itself, whatever the pool's state.
    pub fn local_answer(self, path: &str, headers: &HeaderMap) -> Option<Value> {
        match self {
            Provider::Anthropic => None,
            Provider::Codex => codex::local_answer(path, headers),
        }
    }

    /// The proxy's own error body; `resets_at` (Unix seconds) on a 429.
    pub fn error_envelope(self, error_type: &str, message: &str, resets_at: Option<i64>) -> Value {
        match self {
            Provider::Anthropic => anthropic::error_envelope(error_type, message),
            Provider::Codex => codex::error_envelope(error_type, message, resets_at),
        }
    }

    /// The status refusing an upgrade inside an intercepted tunnel.
    pub fn upgrade_refusal(self) -> StatusCode {
        match self {
            Provider::Anthropic => anthropic::UPGRADE_REFUSAL,
            Provider::Codex => codex::UPGRADE_REFUSAL,
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
        assert_eq!(
            serde_json::to_value(Provider::Codex).unwrap(),
            serde_json::json!("codex")
        );
        assert_eq!(
            serde_json::from_value::<Provider>(serde_json::json!("anthropic")).unwrap(),
            Provider::Anthropic
        );
    }
}
