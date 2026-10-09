//! Authenticated loopback inference only; the enrolled credential never reaches Desktop.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use http::header::{AUTHORIZATION, CONTENT_LENGTH, HOST, ORIGIN, USER_AGENT};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use serde_json::Value;

use crate::client::{self, ClientInstallation, ClientRequest};
use crate::data_plane::envelope::proxy_response;
use crate::data_plane::relay::{self, RelayBody, ResponseBody};
use crate::data_plane::usage::UsageExtractor;
use crate::secret::{Role, Verifier};

use super::{
    app::App,
    config::{Integration, MODEL},
    monitor::{Monitor, Output},
    probe,
};

const BODY_LIMIT: usize = 32 * 1024 * 1024;
pub const DEADLINE: Duration = Duration::from_secs(120);
const TITLE_SYSTEM: &str =
    "You write short session titles. Reply with only the tagged fields the prompt asks for.";

pub struct Adapter {
    pub app: App,
    pub integration: Integration,
    /// The record's selector, switched while the adapter runs.
    pub selector: RwLock<Option<String>>,
    pub installation: ClientInstallation,
    pub http: ClientRequest,
    pub output: Output,
    pub monitor: Arc<Monitor>,
    pub probes: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    pub verifier: Verifier,
}

impl Adapter {
    pub fn selector(&self) -> Option<String> {
        self.selector.read().expect("selector").clone()
    }

    /// Every conversation's next request uses `selector`, once the record holds it.
    pub fn switch(&self, selector: Option<String>) -> Result<(), String> {
        let directory = &self.installation.directory;
        let mut record = Integration::read(directory)?
            .ok_or_else(|| "the Desktop recovery record is missing".to_string())?;
        record.selector = selector.clone();
        record.save(directory)?;
        *self.selector.write().expect("selector") = selector;
        self.monitor.switched();
        Ok(())
    }

    pub async fn handle(
        self: Arc<Self>,
        request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, std::convert::Infallible> {
        let started = Instant::now();
        let mut operation = "rejected";
        let response = self.dispatch(request, started, &mut operation).await;
        let status = response.status().as_u16();
        if matches!(operation, "inference" | "startup") {
            self.monitor.answered(operation, status, started.elapsed());
        }
        if self.output == Output::Log {
            eprintln!(
                "desktop request: operation={operation} status={status} elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }
        Ok(response)
    }

    async fn dispatch(
        &self,
        request: Request<Incoming>,
        started: Instant,
        operation: &mut &'static str,
    ) -> Response<ResponseBody> {
        let (parts, body) = request.into_parts();
        let Some(secret) = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return error(
                StatusCode::UNAUTHORIZED,
                "the local Gateway bearer is required",
            );
        };
        if parts.headers.get_all(AUTHORIZATION).iter().count() != 1
            || !self.verifier.matches(Role::ClientSecret, secret)
        {
            return error(
                StatusCode::UNAUTHORIZED,
                "the local Gateway bearer is invalid",
            );
        }
        let authority = self.integration.origin.trim_start_matches("http://");
        if parts.headers.get(HOST).and_then(|v| v.to_str().ok()) != Some(authority)
            || parts
                .uri
                .authority()
                .is_some_and(|a| a.as_str() != authority)
            || parts.uri.scheme_str().is_some_and(|s| s != "http")
            || parts
                .headers
                .get(ORIGIN)
                .is_some_and(|v| v.as_bytes() != self.integration.origin.as_bytes())
        {
            return error(
                StatusCode::FORBIDDEN,
                "the request authority must match the configured loopback origin",
            );
        }
        let counting = parts.uri.path() == "/v1/messages/count_tokens";
        match (parts.method.clone(), parts.uri.path()) {
            (Method::HEAD, "/api/hello") => {
                *operation = "hello";
                let mut response = error(StatusCode::NO_CONTENT, "");
                response.headers_mut().insert(
                    "x-jaynshare-desktop-instance",
                    self.integration.id.parse().expect("UUID header"),
                );
                return response;
            }
            (Method::POST, "/v1/messages/count_tokens") => {
                *operation = "count_tokens";
            }
            (Method::GET, "/v1/models") => {
                *operation = "models";
                return error(
                    StatusCode::NOT_IMPLEMENTED,
                    "this Desktop integration uses explicit models",
                );
            }
            (Method::POST, "/v1/messages") => *operation = "messages",
            (_, "/v1/messages" | "/v1/messages/count_tokens" | "/v1/models" | "/api/hello") => {
                return error(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "unsupported inference method",
                );
            }
            _ => {
                return error(
                    StatusCode::NOT_FOUND,
                    "this local Gateway exposes inference only",
                );
            }
        }
        if self.app.unchanged().is_err() {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Desktop or its managed runtime changed; restart the adapter",
            );
        }
        if parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
            .is_some_and(|n| n > BODY_LIMIT)
        {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds 32 MiB");
        }
        let bytes =
            match tokio::time::timeout(DEADLINE, Limited::new(body, BODY_LIMIT).collect()).await {
                Ok(Ok(body)) => body.to_bytes(),
                Ok(Err(_)) => {
                    return error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "could not read the request within the 32 MiB limit",
                    );
                }
                Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "request body stalled"),
            };
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "Messages requests must contain JSON",
                );
            }
        };
        if value["model"] != MODEL {
            return error(
                StatusCode::BAD_REQUEST,
                "only the configured Sonnet 4.6 model has been checked",
            );
        }
        let engine = parts
            .headers
            .get("x-claude-code-session-id")
            .is_some_and(|v| !v.as_bytes().is_empty())
            && parts
                .headers
                .get(USER_AGENT)
                .is_some_and(|v| v.as_bytes().starts_with(b"claude-cli/"));
        if !engine {
            if counting {
                return error(
                    StatusCode::NOT_IMPLEMENTED,
                    "token counting requires the managed Claude Code engine",
                );
            }
            if startup(&value) {
                *operation = "startup";
                return probe::run(
                    &self.app,
                    &self.integration,
                    &self.installation.directory,
                    &self.probes,
                )
                .await;
            }
            if title(&value) {
                *operation = "title_fallback";
                return error(
                    StatusCode::NOT_IMPLEMENTED,
                    "direct title inference is unavailable; use Desktop's Claude Code fallback",
                );
            }
            *operation = "unsupported_direct";
            return error(
                StatusCode::NOT_IMPLEMENTED,
                "unrecognized direct Desktop request; this version supports Chat through the managed Claude Code engine",
            );
        }
        if !counting {
            *operation = "inference";
            self.monitor.session(
                parts
                    .headers
                    .get("x-claude-code-session-id")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
            );
        }
        let secret = match client::read_secret(&self.installation) {
            Ok(secret) if secret.starts_with(Role::ClientSecret.prefix()) => secret,
            _ => {
                return error(
                    StatusCode::UNAUTHORIZED,
                    "the enrolled client credential is unavailable; check `jaynshare status --client`",
                );
            }
        };
        let mut headers = parts.headers;
        relay::strip_response_headers(&mut headers);
        for field in [
            "authorization",
            "x-api-key",
            "cookie",
            "cookie2",
            "host",
            "content-length",
            "proxy-authorization",
            "proxy-authenticate",
        ] {
            headers.remove(field);
        }
        let owned: Vec<_> = headers
            .keys()
            .filter(|k| k.as_str().starts_with("x-jaynshare-"))
            .cloned()
            .collect();
        for field in owned {
            headers.remove(field);
        }
        if let Some(selector) = self.selector() {
            headers.insert(
                "x-jaynshare-account",
                selector.parse().expect("resolved account selector"),
            );
        }
        let headers: Vec<_> = headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let path = parts.uri.path_and_query().expect("Messages URI").as_str();
        let response = match self
            .http
            .send(Method::POST, path, Some(&secret), Some(bytes), &headers)
            .await
        {
            Ok(response) => response,
            Err(_) => {
                return error(
                    StatusCode::BAD_GATEWAY,
                    "the enrolled pool could not be reached or its server identity was refused",
                );
            }
        };
        let (mut parts, body) = response.into_parts();
        relay::strip_response_headers(&mut parts.headers);
        let usage = UsageExtractor::for_content_type(
            parts
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
        );
        let status = parts.status.as_u16();
        let output = self.output;
        let monitor = Arc::clone(&self.monitor);
        let body = RelayBody::new(
            body,
            DEADLINE,
            usage,
            None,
            Box::new(move |end| {
                if counting {
                    return;
                }
                let completion = match end {
                    relay::BodyEnd::Complete(_) => "complete",
                    relay::BodyEnd::Failed(_) => "failed",
                    relay::BodyEnd::Dropped(_) => "cancelled",
                };
                monitor.finished(status, completion, started.elapsed());
                if output == Output::Log {
                    eprintln!(
                        "desktop inference: status={status} completion={completion} elapsed_ms={}",
                        started.elapsed().as_millis()
                    );
                }
            }),
        )
        .boxed();
        Response::from_parts(parts, body)
    }
}

fn error(status: StatusCode, message: &str) -> Response<ResponseBody> {
    let mut response = proxy_response(
        status,
        if status == StatusCode::UNAUTHORIZED {
            "authentication_error"
        } else {
            "api_error"
        },
        message,
    );
    if status == StatusCode::NOT_IMPLEMENTED {
        response
            .headers_mut()
            .insert("x-should-retry", http::HeaderValue::from_static("false"));
    }
    response
}

fn simple_user(value: &Value) -> bool {
    value["messages"].as_array().is_some_and(|messages| {
        messages.len() == 1
            && messages[0].as_object().is_some_and(|m| m.len() == 2)
            && messages[0]["role"] == "user"
            && messages[0]["content"].is_string()
    })
}

fn startup(value: &Value) -> bool {
    value.as_object().is_some_and(|m| m.len() == 3)
        && value["model"] == MODEL
        && value["max_tokens"] == 1
        && simple_user(value)
        && value["messages"][0]["content"] == "."
}

fn title(value: &Value) -> bool {
    value.as_object().is_some_and(|m| m.len() == 4)
        && value["model"] == MODEL
        && value["max_tokens"] == 200
        && value["system"] == TITLE_SYSTEM
        && simple_user(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn auxiliary_shapes_are_exact() {
        let probe =
            json!({"model": MODEL, "max_tokens": 1, "messages": [{"role":"user", "content":"."}]});
        let title_request = json!({"model": MODEL, "max_tokens": 200, "system": TITLE_SYSTEM,
            "messages": [{"role":"user", "content":"Generate a title"}]});
        assert!(startup(&probe));
        assert!(title(&title_request));
        for value in [probe, title_request] {
            for field in ["stream", "tools", "metadata"] {
                let mut changed = value.clone();
                changed[field] = json!(false);
                assert!(!startup(&changed) && !title(&changed));
            }
            let mut changed = value;
            changed["model"] = json!("unverified-model");
            assert!(!startup(&changed) && !title(&changed));
        }
    }
}
