//! Turning a client request into an attempt: the provider-neutral header
//! rules and body facts. Everything here is pure; the exchange loop calls it.

use std::io::Read as _;
use std::io::Write as _;

use bytes::Bytes;
use flate2::{
    Compression,
    read::{MultiGzDecoder, ZlibDecoder},
    write::{GzEncoder, ZlibEncoder},
};
use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, TE,
    TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};
use serde_json::Value;

use super::exchange::BODY_LIMIT;
use super::intent::X_JAYNSHARE_ACCOUNT;
use crate::pool::Account;
use crate::provider::Provider;
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
    let identifying: Vec<_> = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-jaynshare-")
                || name.as_str().starts_with("x-forwarded-")
                || matches!(
                    name.as_str(),
                    "cookie"
                        | "cookie2"
                        | "forwarded"
                        | "x-forwarded-for"
                        | "x-forwarded-host"
                        | "x-forwarded-proto"
                        | "x-forwarded-port"
                        | "x-real-ip"
                        | "client-ip"
                        | "true-client-ip"
                        | "cf-connecting-ip"
                        | "fastly-client-ip"
                        | "x-client-ip"
                        | "x-cluster-client-ip"
                        | "x-original-forwarded-for"
                        | "via"
                        | "x-claude-gateway-user-id"
                        | "x-claude-gateway-user-email"
                        | "x-litellm-end-user-id"
                        | "anthropic-user-profile-id"
                        | "anthropic-workspace-id"
                        | "anthropic-organization-id"
                        | "openai-organization"
                        | "openai-project"
                        | "traceparent"
                        | "tracestate"
                        | "sentry-trace"
                        | "baggage"
                        | "b3"
                        | "x-b3-traceid"
                        | "x-b3-spanid"
                        | "x-b3-parentspanid"
                        | "x-b3-sampled"
                        | "x-b3-flags"
                        | "x-datadog-trace-id"
                        | "x-datadog-parent-id"
                        | "x-datadog-origin"
                        | "x-datadog-sampling-priority"
                        | "x-datadog-tags"
                        | "x-envoy-external-address"
                        | "x-original-client-ip"
                        | "x-amzn-trace-id"
                )
        })
        .cloned()
        .collect();
    for name in identifying {
        headers.remove(name);
    }
}

pub fn normalize(
    provider: Provider,
    headers: &mut HeaderMap,
    body: Bytes,
    path: &str,
    account: &Account,
) -> Result<Bytes, String> {
    if provider == Provider::Codex {
        crate::provider::codex::rewrite_headers(headers, account)?;
    }
    if provider == Provider::Anthropic
        && !matches!(path, "/v1/messages" | "/v1/messages/count_tokens")
    {
        return provider.rewrite_body(body, path, account);
    }
    let decoded = decode_body(headers, &body)?;
    let decoded = Bytes::from(decoded);
    let rewritten = provider.rewrite_body(decoded.clone(), path, account)?;
    if rewritten == decoded {
        return Ok(body);
    }
    if rewritten.len() > BODY_LIMIT {
        return Err("normalized request exceeds 32 MiB".into());
    }
    let encoding = encoding(headers)?;
    let encoded = match encoding.as_str() {
        "identity" => rewritten,
        "zstd" => Bytes::from(compress_to_vec(&rewritten[..], CompressionLevel::Fastest)),
        "gzip" => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(&rewritten)
                .map_err(|_| "could not encode normalized body")?;
            Bytes::from(
                encoder
                    .finish()
                    .map_err(|_| "could not encode normalized body")?,
            )
        }
        "deflate" => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(&rewritten)
                .map_err(|_| "could not encode normalized body")?;
            Bytes::from(
                encoder
                    .finish()
                    .map_err(|_| "could not encode normalized body")?,
            )
        }
        _ => unreachable!("decode_body accepted the encoding"),
    };
    if encoded.len() > BODY_LIMIT {
        return Err("normalized request exceeds 32 MiB".into());
    }
    Ok(encoded)
}

fn encoding(headers: &HeaderMap) -> Result<String, String> {
    if headers.get_all(CONTENT_ENCODING).iter().count() > 1 {
        return Err("multiple content encodings are unsupported".into());
    }
    Ok(headers
        .get(CONTENT_ENCODING)
        .map(|v| v.to_str().map(|s| s.trim().to_ascii_lowercase()))
        .transpose()
        .map_err(|_| "invalid content encoding")?
        .unwrap_or_else(|| "identity".into()))
}

pub fn decode_body(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, String> {
    let encoding = encoding(headers)?;
    match encoding.as_str() {
        "identity" => read_bounded(body),
        "gzip" => read_bounded(MultiGzDecoder::new(body)),
        "deflate" => {
            let mut decoder = ZlibDecoder::new(body);
            let decoded = read_bounded(&mut decoder)?;
            if decoder.total_in() != body.len() as u64 {
                return Err("trailing data in deflate request body".into());
            }
            Ok(decoded)
        }
        "zstd" => {
            let mut decoder = StreamingDecoder::new_with_max_window_size(body, BODY_LIMIT as u64)
                .map_err(|_| "invalid zstd request body")?;
            let decoded = read_bounded(&mut decoder)?;
            // shortcut: pinned Codex sends one frame; support concatenated frames if a client starts emitting them.
            if !decoder.into_inner().is_empty() {
                return Err("multiple zstd frames or trailing data are unsupported".into());
            }
            Ok(decoded)
        }
        _ => {
            Err("unsupported request content encoding; use identity, gzip, deflate or zstd".into())
        }
    }
}

fn read_bounded(reader: impl std::io::Read) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    reader
        .take(BODY_LIMIT as u64 + 1)
        .read_to_end(&mut decoded)
        .map_err(|_| "invalid compressed request body")?;
    if decoded.len() > BODY_LIMIT {
        return Err("decoded request exceeds 32 MiB".into());
    }
    Ok(decoded)
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

/// Read routing facts from the same bounded decoded representation used for normalization.
pub fn body_facts(headers: &HeaderMap, body: &[u8]) -> BodyFacts {
    decode_body(headers, body).map_or_else(|_| BodyFacts::default(), |decoded| json_facts(&decoded))
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
            ("cookie", "own-login"),
            ("forwarded", "for=192.0.2.1"),
            ("x-real-ip", "192.0.2.1"),
            ("x-claude-gateway-user-email", "synthetic@example.test"),
            ("x-litellm-end-user-id", "synthetic-user"),
            ("traceparent", "synthetic-trace"),
            ("baggage", "user=synthetic"),
            ("x-jaynshare-extra", "private"),
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

    fn account(provider: Provider, handle: u128) -> Account {
        let mut account = Account::new(
            provider,
            "synthetic".into(),
            crate::pool::Profile::default(),
            crate::pool::Source::ApiKeyEntry,
            crate::pool::Credential::ApiKey(crate::pool::Secret::new("synthetic-key".into())),
        );
        account.handle = uuid::Uuid::from_u128(handle);
        account
    }

    fn compressed(body: &[u8], encoding: &str) -> Bytes {
        match encoding {
            "gzip" => {
                let mut writer = GzEncoder::new(Vec::new(), Compression::default());
                writer.write_all(body).unwrap();
                Bytes::from(writer.finish().unwrap())
            }
            "deflate" => {
                let mut writer = ZlibEncoder::new(Vec::new(), Compression::default());
                writer.write_all(body).unwrap();
                Bytes::from(writer.finish().unwrap())
            }
            "zstd" => Bytes::from(compress_to_vec(body, CompressionLevel::Fastest)),
            _ => Bytes::copy_from_slice(body),
        }
    }

    #[test]
    fn one_account_has_one_machine_across_clients_paths_encodings_and_saved_state() {
        let account = account(Provider::Anthropic, 1);
        let machine = account.provider.machine_id(account.handle);
        assert_eq!(machine.len(), 64);
        assert!(machine.bytes().all(|b| b.is_ascii_hexdigit()));
        let mut restored = Account::from_record(&account.to_record()).unwrap();
        restored.display_name = "renamed".into();
        restored.credential =
            crate::pool::Credential::ApiKey(crate::pool::Secret::new("refreshed".into()));
        assert_eq!(restored.provider.machine_id(restored.handle), machine);
        assert_ne!(
            account.provider.machine_id(uuid::Uuid::from_u128(2)),
            machine
        );
        for path in ["/v1/messages", "/v1/messages/count_tokens"] {
            for encoding in ["identity", "gzip", "deflate", "zstd"] {
                for session in ["client-one-session", "client-two-session"] {
                    let original = json!({"model":"m", "system":[{"text":"billing cc_prompt_id=unchanged"}],
                        "metadata":{"user_id":json!({"device_id":session,"account_uuid":"own","session_id":session}).to_string()},
                        "messages":[{"role":"assistant","content":[{"type":"thinking","signature":"opaque","thinking":"synthetic"}]}]});
                    let mut headers = HeaderMap::new();
                    headers.insert(CONTENT_ENCODING, encoding.parse().unwrap());
                    let body = normalize(
                        account.provider,
                        &mut headers,
                        compressed(original.to_string().as_bytes(), encoding),
                        path,
                        &account,
                    )
                    .unwrap();
                    let normalized: Value =
                        serde_json::from_slice(&decode_body(&headers, &body).unwrap()).unwrap();
                    let identity: Value =
                        serde_json::from_str(normalized["metadata"]["user_id"].as_str().unwrap())
                            .unwrap();
                    assert_eq!(
                        identity,
                        json!({"device_id":machine, "account_uuid":"", "session_id":session})
                    );
                    assert_eq!(normalized["system"], original["system"]);
                    assert_eq!(normalized["messages"], original["messages"]);
                    assert_eq!(headers[CONTENT_ENCODING], encoding);
                }
            }
        }
    }

    #[test]
    fn missing_identity_is_created_and_malformed_identity_never_crosses() {
        let account = account(Provider::Anthropic, 1);
        let normalized = normalize(
            account.provider,
            &mut HeaderMap::new(),
            Bytes::from_static(b"{}"),
            "/v1/messages",
            &account,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&normalized).unwrap();
        let identity: Value =
            serde_json::from_str(value["metadata"]["user_id"].as_str().unwrap()).unwrap();
        assert_eq!(
            identity["device_id"],
            account.provider.machine_id(account.handle)
        );
        for body in [
            json!(null),
            json!({"metadata":null}),
            json!({"metadata":{"user_id":"not-json"}}),
            json!({"metadata":{"user_id":json!({"device_id":42}).to_string()}}),
        ] {
            assert!(
                normalize(
                    account.provider,
                    &mut HeaderMap::new(),
                    Bytes::from(body.to_string()),
                    "/v1/messages",
                    &account
                )
                .is_err()
            );
        }
        for encoding in ["br", "gzip,zstd", "gzip", "deflate", "zstd"] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_ENCODING, encoding.parse().unwrap());
            assert!(
                normalize(
                    account.provider,
                    &mut headers,
                    Bytes::from_static(b"invalid"),
                    "/v1/messages",
                    &account
                )
                .is_err()
            );
        }
        let oversized = vec![b' '; BODY_LIMIT + 1];
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(decode_body(&headers, &compressed(&oversized, "gzip")).is_err());
    }

    #[test]
    fn token_counts_without_identity_keep_the_documented_schema() {
        let account = account(Provider::Anthropic, 1);
        let body = Bytes::from_static(b"{\"model\":\"synthetic\",\"messages\":[]}");
        let normalized = normalize(
            account.provider,
            &mut HeaderMap::new(),
            body.clone(),
            "/v1/messages/count_tokens",
            &account,
        )
        .unwrap();
        assert_eq!(normalized, body);
    }

    #[test]
    fn decoder_rejects_trailing_data_and_duplicate_encoding_headers() {
        for encoding in ["deflate", "zstd"] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_ENCODING, encoding.parse().unwrap());
            let mut body = compressed(b"{}", encoding).to_vec();
            body.extend_from_slice(b"trailing");
            assert!(decode_body(&headers, &body).is_err());
        }
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        assert!(decode_body(&headers, b"{}").is_err());
    }

    #[test]
    fn codex_header_and_body_projections_agree_without_rewriting_conversation_content() {
        let account = account(Provider::Codex, 1);
        let machine = account.provider.machine_id(account.handle);
        assert!(uuid::Uuid::parse_str(&machine).is_ok());
        let turn = json!({
            "installation_id":"own", "session_id":"session", "thread_id":"thread",
            "turn_id":"turn", "window_id":"window", "source":"synthetic-é",
            "workspaces": {"/Users/synthetic-alice/private-repository": {
                "associated_remote_urls":{"origin":"https://github.com/synthetic-owner/private-repository.git"},
                "latest_git_commit_hash":"synthetic-commit", "has_changes":false
            }},
            "email":"synthetic@example.test", "user_email":"synthetic@example.test",
            "user_id":"own-user", "username":"synthetic-alice", "user_name":"synthetic-alice",
            "account_id":"own-account", "account_uuid":"own-account",
            "organization_id":"own-organization", "organization_uuid":"own-organization",
            "device_id":"own-device"
        }).to_string().replace('é', "\\u00e9");
        let original = json!({"client_metadata":{"x-codex-installation-id":"own", "x-codex-turn-metadata":turn,
            "session_id":"session", "thread_id":"thread", "workspaces":{"/Users/synthetic-alice/private-repository":{}},
            "email":"synthetic@example.test", "user_email":"synthetic@example.test", "account_id":"own-account"},
            "prompt_cache_key":"cache", "previous_response_id":"response",
            "input":[{"type":"message","content":"installation_id: context stays untouched"},{"type":"reasoning","encrypted_content":"opaque"}]});
        for encoding in ["identity", "gzip", "deflate", "zstd"] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_ENCODING, encoding.parse().unwrap());
            headers.insert("x-codex-installation-id", HeaderValue::from_static("own"));
            headers.insert("x-codex-turn-metadata", turn.parse().unwrap());
            headers.insert("x-codex-turn-state", HeaderValue::from_static("opaque"));
            let normalized = normalize(
                account.provider,
                &mut headers,
                compressed(original.to_string().as_bytes(), encoding),
                "/backend-api/codex/responses",
                &account,
            )
            .unwrap();
            let value: Value =
                serde_json::from_slice(&decode_body(&headers, &normalized).unwrap()).unwrap();
            let turn_metadata = value["client_metadata"]["x-codex-turn-metadata"]
                .as_str()
                .unwrap();
            assert!(turn_metadata.is_ascii());
            let canonical: Value = serde_json::from_str(turn_metadata).unwrap();
            assert_eq!(headers["x-codex-installation-id"], machine);
            assert_eq!(value["client_metadata"]["x-codex-installation-id"], machine);
            assert_eq!(
                canonical,
                json!({
                    "installation_id":machine, "session_id":"session", "thread_id":"thread",
                    "turn_id":"turn", "window_id":"window", "source":"synthetic-é"
                })
            );
            assert_eq!(
                value["client_metadata"],
                json!({
                    "x-codex-installation-id":machine, "x-codex-turn-metadata":turn_metadata,
                    "session_id":"session", "thread_id":"thread"
                })
            );
            assert_eq!(
                canonical,
                serde_json::from_str::<Value>(headers["x-codex-turn-metadata"].to_str().unwrap())
                    .unwrap()
            );
            assert_eq!(value["input"], original["input"]);
            assert_eq!(value["prompt_cache_key"], original["prompt_cache_key"]);
            assert_eq!(
                value["previous_response_id"],
                original["previous_response_id"]
            );
            assert_eq!(headers["x-codex-turn-state"], "opaque");
        }
        for body in [
            json!({"client_metadata":null}),
            json!({"client_metadata":{"x-codex-turn-metadata":"invalid"}}),
            json!({"client_metadata":{"x-codex-installation-id":42}}),
        ] {
            assert!(
                normalize(
                    account.provider,
                    &mut HeaderMap::new(),
                    Bytes::from(body.to_string()),
                    "/backend-api/codex/responses",
                    &account
                )
                .is_err()
            );
        }
        let mut headers = HeaderMap::new();
        for _ in 0..2 {
            headers.append("x-codex-turn-metadata", HeaderValue::from_static("{}"));
        }
        assert!(
            normalize(
                account.provider,
                &mut headers,
                Bytes::from_static(b"{}"),
                "/backend-api/codex/responses",
                &account
            )
            .is_err()
        );
    }
}
