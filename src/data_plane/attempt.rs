//! Turning a client request into an attempt: the provider-neutral header
//! rules and body facts. Everything here is pure; the exchange loop calls it.

use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, TE, TRAILER,
    TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use super::intent::X_JAYNSHARE_ACCOUNT;
use crate::provider::anthropic::X_API_KEY;

/// The hop-by-hop set plus what the proxy consumes itself.
const HOP_BY_HOP: [HeaderName; 8] = [
    CONNECTION,
    HeaderName::from_static("keep-alive"),
    TRANSFER_ENCODING,
    TE,
    TRAILER,
    UPGRADE,
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("proxy-authenticate"),
];
const PROXY_AUTHORIZATION: HeaderName = HeaderName::from_static("proxy-authorization");

/// Removed before the attempt is built.
pub fn strip_request_headers(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(str::trim).map(str::to_ascii_lowercase))
        .filter_map(|n| n.parse().ok())
        .collect();
    for name in named.into_iter().chain(HOP_BY_HOP).chain([
        PROXY_AUTHORIZATION,
        HOST,
        AUTHORIZATION,
        X_API_KEY,
        X_JAYNSHARE_ACCOUNT,
        ACCEPT_ENCODING,
    ]) {
        headers.remove(&name);
    }
}

/// `content-length` describes the attempt body.
pub fn set_content_length(headers: &mut HeaderMap, len: usize) {
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
}

/// What the request body says about the exchange.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyFacts {
    pub model: Option<String>,
    pub advisor_model: Option<String>,
}

pub fn body_facts(body: &[u8]) -> BodyFacts {
    let Ok(Value::Object(top)) = serde_json::from_slice::<Value>(body) else {
        return BodyFacts::default();
    };
    let model = top.get("model").and_then(Value::as_str).map(String::from);
    let advisor_model = top
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|t| {
            t.get("type")
                .and_then(Value::as_str)
                .is_some_and(|ty| ty.starts_with("advisor"))
        })
        .and_then(|t| t.get("model"))
        .and_then(Value::as_str)
        .map(String::from);
    BodyFacts {
        model,
        advisor_model,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strips_hop_by_hop_credentials_and_connection_named_headers() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("connection", "x-test, keep-alive"),
            ("x-test", "1"),
            ("te", "trailers"),
            ("proxy-authorization", "Basic x"),
            ("authorization", "Bearer client"),
            ("x-api-key", "client"),
            ("x-jaynshare-account", "pin.x"),
            ("accept-encoding", "gzip"),
            ("host", "proxy"),
            ("anthropic-version", "2023-06-01"),
            ("x-stainless-os", "MacOS"),
        ] {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        strip_request_headers(&mut h);
        let mut left: Vec<&str> = h.keys().map(HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["anthropic-version", "x-stainless-os"]);
    }

    #[test]
    fn model_is_top_level_only_and_advisor_is_read_from_tools() {
        let body = json!({
            "messages": [{"model": "nested"}],
            "model": "claude-haiku",
            "tools": [{"type": "advisor_20260301", "model": "claude-opus"}],
        });
        let facts = body_facts(&serde_json::to_vec(&body).unwrap());
        assert_eq!(facts.model.as_deref(), Some("claude-haiku"));
        assert_eq!(facts.advisor_model.as_deref(), Some("claude-opus"));
        assert_eq!(body_facts(b"not json"), BodyFacts::default());
        assert_eq!(
            body_facts(b"{\"messages\":[{\"model\":\"x\"}]}"),
            BodyFacts::default()
        );
    }
}
