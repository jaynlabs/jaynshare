//! Third-party facts about the Codex backend on chatgpt.com, as the Codex CLI
//! speaks to it under a ChatGPT login.

use http::{HeaderMap, HeaderName};
use serde_json::Value;

use crate::pool::Account;
use crate::pool::quota::Observation;

pub const API_HOST: &str = "chatgpt.com";
pub const API_ORIGIN: &str = "https://chatgpt.com";
pub const SESSION_ID: HeaderName = HeaderName::from_static("session-id");

pub fn is_telemetry(_path: &str) -> bool {
    todo!("lane C: /backend-api/codex/analytics-events and below")
}

pub fn is_account_bound(_path: &str) -> bool {
    todo!("lane C: everything outside /backend-api/codex/")
}

pub fn inject_credential(_headers: &mut HeaderMap, _account: &Account) {
    todo!("lane C: bearer plus ChatGPT-Account-ID")
}

pub fn observe_headers(_headers: &HeaderMap) -> Vec<Observation> {
    todo!("lane B: x-codex-{{primary,secondary}}-* onto session and weekly")
}

pub fn observe_usage(_usage: &Value) -> Result<Vec<Observation>, String> {
    todo!("lane B: /backend-api/wham/usage")
}

pub fn is_spend_cap_429(_body: Option<&[u8]>) -> bool {
    todo!("lane B: the usage-limit 429 body")
}
