//! Proxy responses: the envelope with our error classes.

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full};
use time::OffsetDateTime;

use crate::provider::Provider;
use crate::provider::anthropic::error_type;

use super::relay::ResponseBody;

/// A refusal outside any provider's exchange, in the Anthropic envelope.
pub fn proxy_response(
    status: StatusCode,
    error_type: &str,
    message: &str,
) -> Response<ResponseBody> {
    error(Provider::Anthropic, status, error_type, message)
}

/// A refusal in the envelope the provider's client reads.
pub fn error(
    provider: Provider,
    status: StatusCode,
    error_type: &str,
    message: &str,
) -> Response<ResponseBody> {
    json_response(status, &provider.error_envelope(error_type, message, None))
}

/// The proxy's own 429 and its `retry-after`.
pub fn rate_limited(provider: Provider, message: &str, retry_after: u64) -> Response<ResponseBody> {
    let resets_at = OffsetDateTime::now_utc()
        .unix_timestamp()
        .saturating_add_unsigned(retry_after);
    let envelope = provider.error_envelope(error_type::RATE_LIMIT, message, Some(resets_at));
    let mut response = json_response(StatusCode::TOO_MANY_REQUESTS, &envelope);
    response
        .headers_mut()
        .insert(RETRY_AFTER, retry_after.into());
    response
}

/// The one refusal every unauthenticated caller sees, byte for byte.
pub fn unauthenticated() -> Response<ResponseBody> {
    proxy_response(
        StatusCode::UNAUTHORIZED,
        error_type::AUTHENTICATION,
        "the proxy credential is missing or invalid: this is the Jaynshare client secret, not an Anthropic key; re-enrol if it was rotated or revoked",
    )
}

pub fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .body(
            Full::new(Bytes::from(value.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response builds")
}
