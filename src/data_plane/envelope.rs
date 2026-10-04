//! Proxy responses: the envelope with our error classes.

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full};

use crate::provider::anthropic::{error_envelope, error_type};

use super::relay::ResponseBody;

pub fn proxy_response(
    status: StatusCode,
    error_type: &str,
    message: &str,
) -> Response<ResponseBody> {
    let body = error_envelope(error_type, message).to_string();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response builds")
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
