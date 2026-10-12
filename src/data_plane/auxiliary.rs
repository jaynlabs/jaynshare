//! Anonymous provider checks and public downloads share the server's transport.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use hyper::body::Incoming;

use super::{attempt, egress, envelope, relay};
use crate::provider::anthropic::{API_HOST, error_type};
use crate::provider::codex;
use crate::server::Server;

pub const DOWNLOAD_HOST: &str = "downloads.claude.ai";
pub const DOMAIN_PATH: &str = "/api/web/domain_info";

pub fn supports(host: &str, path: &str) -> bool {
    host == DOWNLOAD_HOST
        || (host == API_HOST
            && matches!(path, DOMAIN_PATH | "/api/web/domain_info/browser_extension"))
        || (host == codex::API_HOST && codex::INSTALLERS.contains(&path))
}

pub async fn run(
    server: Arc<Server>,
    host: &str,
    request: Request<Incoming>,
) -> Response<relay::ResponseBody> {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return envelope::proxy_response(
            StatusCode::METHOD_NOT_ALLOWED,
            error_type::INVALID_REQUEST,
            "this anonymous route supports GET and HEAD only",
        );
    }
    let config = server.config();
    let settings = &config.config;
    if server.stopping()
        || egress::gate(&server, &settings.data_plane.egress)
            .await
            .is_err()
    {
        return envelope::proxy_response(
            StatusCode::SERVICE_UNAVAILABLE,
            error_type::PROXY,
            "the server's egress route is unavailable",
        );
    }
    let (parts, _) = request.into_parts();
    if !parts.uri.path().starts_with('/') {
        return envelope::proxy_response(
            StatusCode::BAD_REQUEST,
            error_type::INVALID_REQUEST,
            "this anonymous route requires an origin path",
        );
    }
    let origin: Uri = server
        .upstream
        .override_origin()
        .cloned()
        .unwrap_or_else(|| {
            format!("https://{host}")
                .parse()
                .expect("fixed public origin")
        });
    let uri = match Uri::builder()
        .scheme(origin.scheme().expect("origin scheme").clone())
        .authority(origin.authority().expect("origin authority").clone())
        .path_and_query(parts.uri.path_and_query().map_or("/", |p| p.as_str()))
        .build()
    {
        Ok(uri) => uri,
        Err(_) => {
            return envelope::proxy_response(
                StatusCode::BAD_REQUEST,
                error_type::INVALID_REQUEST,
                "this anonymous route requires a valid origin path",
            );
        }
    };
    let mut incoming = parts.headers;
    attempt::strip_request_headers(&mut incoming);
    let mut headers = HeaderMap::new();
    for name in [
        "accept",
        "range",
        "if-range",
        "if-none-match",
        "if-match",
        "if-modified-since",
        "if-unmodified-since",
        "cache-control",
    ] {
        for value in incoming.get_all(name) {
            headers.append(http::HeaderName::from_static(name), value.clone());
        }
    }
    headers.insert(
        "host",
        HeaderValue::from_str(origin.authority().expect("origin authority").as_str())
            .expect("authority header"),
    );
    headers.insert(
        "user-agent",
        HeaderValue::from_static(concat!("jaynshare/", env!("CARGO_PKG_VERSION"))),
    );
    let mut outbound = Request::new(Bytes::new());
    *outbound.method_mut() = parts.method;
    *outbound.uri_mut() = uri;
    *outbound.headers_mut() = headers;
    let timeout = Duration::from_secs(settings.data_plane.first_byte_timeout_seconds);
    let (response, permit) = match server.upstream.send(outbound, timeout).await {
        Ok(response) => response,
        Err(_) => {
            return envelope::proxy_response(
                StatusCode::BAD_GATEWAY,
                error_type::PROXY,
                "the public upstream could not be reached",
            );
        }
    };
    let (mut parts, body) = response.into_parts();
    relay::strip_response_headers(&mut parts.headers);
    parts.headers.remove("set-cookie");
    let body = relay::RelayBody::new(
        body,
        Duration::from_secs(settings.data_plane.body_idle_timeout_seconds),
        super::usage::UsageExtractor::None,
        None,
        Box::new(move |_| drop(permit)),
    )
    .boxed();
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_routes_do_not_include_account_paths_or_lookalikes() {
        assert!(supports(API_HOST, DOMAIN_PATH));
        assert!(supports(DOWNLOAD_HOST, "/artifact"));
        assert!(!supports(API_HOST, "/api/web/domain_info/account"));
        assert!(!supports(API_HOST, "/api/oauth/profile"));
        assert!(!supports("downloads.claude.ai.example", "/artifact"));
        assert!(supports(codex::API_HOST, "/codex/install.sh"));
        assert!(supports(codex::API_HOST, "/codex/install.ps1"));
        assert!(!supports(codex::API_HOST, "/codex/install.sh/x"));
        assert!(!supports(codex::API_HOST, "/backend-api/codex/responses"));
        assert!(!supports(API_HOST, "/codex/install.sh"));
    }
}
