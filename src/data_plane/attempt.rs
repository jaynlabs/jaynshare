//! Turning a client request into an attempt: the provider-neutral header
//! rules and body facts. Everything here is pure; the exchange loop calls it.

use std::io::Read as _;

use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, TE,
    TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use ruzstd::decoding::StreamingDecoder;
use serde_json::Value;

use super::exchange::BODY_LIMIT;
use super::intent::X_JAYNSHARE_ACCOUNT;
use crate::provider::anthropic::X_API_KEY;
use crate::provider::codex::CHATGPT_ACCOUNT_ID;

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
        CHATGPT_ACCOUNT_ID,
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

/// A zstd body (Codex's `/responses`) is read from a bounded decoded copy;
/// the bytes forwarded stay the client's.
pub fn body_facts(headers: &HeaderMap, body: &[u8]) -> BodyFacts {
    let zstd = headers
        .get(CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"zstd"));
    if !zstd {
        return json_facts(body);
    }
    zstd_decoded(body).map_or_else(BodyFacts::default, |decoded| json_facts(&decoded))
}

// ponytail: a body decoding past BODY_LIMIT yields no facts (no model, so no
// route or block match); stream-parse the leading keys if sessions outgrow it.
fn zstd_decoded(body: &[u8]) -> Option<Vec<u8>> {
    let limit = BODY_LIMIT as u64;
    let decoder = StreamingDecoder::new_with_max_window_size(body, limit).ok()?;
    let mut decoded = Vec::new();
    decoder.take(limit).read_to_end(&mut decoded).ok()?;
    Some(decoded)
}

fn json_facts(body: &[u8]) -> BodyFacts {
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
            ("chatgpt-account-id", "acct-client"),
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
        let plain = HeaderMap::new();
        let facts = body_facts(&plain, &serde_json::to_vec(&body).unwrap());
        assert_eq!(facts.model.as_deref(), Some("claude-haiku"));
        assert_eq!(facts.advisor_model.as_deref(), Some("claude-opus"));
        assert_eq!(body_facts(&plain, b"not json"), BodyFacts::default());
        assert_eq!(
            body_facts(&plain, b"{\"messages\":[{\"model\":\"x\"}]}"),
            BodyFacts::default()
        );
    }

    #[test]
    fn a_zstd_body_is_read_decoded_and_garbage_teaches_nothing() {
        use ruzstd::encoding::{CompressionLevel, compress_to_vec};
        let mut zstd = HeaderMap::new();
        zstd.insert(CONTENT_ENCODING, HeaderValue::from_static("zstd"));
        let compressed = compress_to_vec(
            &br#"{"model":"gpt-5-codex"}"#[..],
            CompressionLevel::Fastest,
        );
        let facts = body_facts(&zstd, &compressed);
        assert_eq!(facts.model.as_deref(), Some("gpt-5-codex"));
        assert_eq!(body_facts(&zstd, b"not zstd"), BodyFacts::default());
        assert_eq!(
            body_facts(&HeaderMap::new(), &compressed),
            BodyFacts::default()
        );
    }
}
