//! Shared harness: the fake upstream, the instance under test, the client side.
//! Everything the bricks need imports through [`crate::harness`] as a glob.

// Everything below is both harness's own imports and the brick re-exports.

pub(crate) use std::collections::VecDeque;
pub(crate) use std::convert::Infallible;
pub(crate) use std::fs;
pub(crate) use std::io::{Read as _, Write as _};
pub(crate) use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::pin::Pin;
pub(crate) use std::process::{Child, Command, Stdio};
pub(crate) use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
pub(crate) use std::sync::{Arc, Mutex, OnceLock};
pub(crate) use std::task::{Context, Poll, ready};
pub(crate) use std::time::{Duration, Instant};

pub(crate) use bytes::Bytes;
pub(crate) use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
pub(crate) use http_body_util::combinators::BoxBody;
pub(crate) use http_body_util::{BodyExt, Full};
pub(crate) use hyper::body::{Body, Frame, Incoming};
pub(crate) use hyper::service::service_fn;
pub(crate) use hyper_util::rt::TokioIo;
pub(crate) use serde_json::{Value, json};
pub(crate) use time::OffsetDateTime;
pub(crate) use tokio::net::{TcpListener, TcpStream};
pub(crate) use tokio::sync::Notify;
pub(crate) use tokio::time::Sleep;
pub(crate) use uuid::Uuid;
// ------------------------------------------------------------------ needles

/// the forms a redaction bug could leave behind.
pub(crate) fn encodings(needle: &str) -> Vec<String> {
    vec![
        needle.to_string(),
        needle.replace('-', "%2D"),
        serde_json::to_string(needle).expect("JSON string")[1..needle.len() + 1].to_string(),
    ]
}

/// Every file under `directory` outside `allowed` is swept for the needles;
/// hits collect the paths.
pub(crate) fn sweep(
    directory: &Path,
    allowed: &[PathBuf],
    needles: &[&str],
    hits: &mut Vec<String>,
) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if allowed.iter().any(|a| path.starts_with(a)) {
            continue;
        }
        if path.is_dir() {
            sweep(&path, allowed, needles, hits);
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        for needle in needles {
            if encodings(needle).iter().any(|form| contents.contains(form)) {
                hits.push(path.display().to_string());
            }
        }
    }
}

/// A distinct per-run value for every secret-shaped fixture, so a hit in the
/// sweep of names the role that leaked.
#[derive(Debug, Clone)]
pub(crate) struct Needles {
    pub(crate) api_key: String,
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
}

impl Needles {
    pub(crate) fn new() -> Self {
        // Shaped like the real thing, valid nowhere.
        Self {
            api_key: needle("pooled API key", "fixture"),
            access_token: needle("pooled access token", "oat-fixture"),
            refresh_token: needle("pooled refresh token", "ort-fixture"),
        }
    }

    pub(crate) fn all(&self) -> [&str; 3] {
        [&self.api_key, &self.access_token, &self.refresh_token]
    }
}

/// Mints one per-run needle shaped like a real secret
/// (`sk-ant-{shape}-<uuid>`) and registers it with the runner's whole-run sweep,
/// so a hit anywhere in the run names the role that leaked.
pub(crate) fn needle(role: &str, shape: &str) -> String {
    let value = format!("sk-ant-{shape}-{}", Uuid::new_v4());
    crate::leaks::register_needle(role, &value);
    value
}

// ------------------------------------------------------------------ fake upstream

/// One request the fake received, kept for assertion.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) at: Instant,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Bytes,
}

impl Seen {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("upstream body is JSON")
    }
}

/// What the fake answers next. An empty script means the default of [`default_reply`].
#[derive(Debug, Clone)]
pub(crate) enum Reply {
    /// Any status, any body, any header set.
    Raw {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    /// A scripted event sequence written chunk by chunk with a gap.
    Sse { events: Vec<String> },
    /// The same, with a settable inter-frame gap and shared counters for the
    /// frames the proxy has pulled and the drop of the fake's stream task
    /// the deadline and backpressure rows' observability.
    SseWatched {
        events: Vec<String>,
        gap_ms: u64,
        delivered: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
    },
    /// Drop the connection before any response byte.
    ResetBeforeHeaders,
    /// Answer, then reset mid-body: headers and one chunk, then the
    /// connection is gone with no clean end.
    ResetMidBody,
    /// Keep the connection open without answering.
    Stall,
    /// Hold the reply until the scenario releases the gate, then answer the
    /// default (the attempt already sent upstream finishes after the
    /// operator's write lands).
    Hold(Arc<Notify>),
    /// The default's status and headers at once; the body only once the gate
    /// is released (a slot frees at response headers, not stream end).
    HoldBody(Arc<Notify>),
    /// Hold until the gate is released, then answer the boxed reply (for
    /// concurrent observations finishing out of order).
    HoldThen(Arc<Notify>, Box<Reply>),
}

impl Reply {
    pub(crate) fn status(status: u16, body: impl Into<String>) -> Self {
        Reply::Raw {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.into(),
        }
    }
}

pub(crate) type FakeBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
pub(crate) struct Fake {
    pub(crate) addr: SocketAddr,
    pub(crate) seen: Arc<Mutex<Vec<Seen>>>,
    pub(crate) script: Arc<Mutex<VecDeque<Reply>>>,
    pub(crate) token_script: Arc<Mutex<VecDeque<Reply>>>,
    pub(crate) usage_script: Arc<Mutex<VecDeque<Reply>>>,
    pub(crate) token_delay: Arc<Mutex<Option<Duration>>>,
    pub(crate) usage_delay: Arc<Mutex<Option<Duration>>>,
}

impl Fake {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("fake bind");
        let fake = Fake {
            addr: listener.local_addr().expect("fake addr"),
            seen: Arc::new(Mutex::new(Vec::new())),
            script: Arc::new(Mutex::new(VecDeque::new())),
            token_script: Arc::new(Mutex::new(VecDeque::new())),
            usage_script: Arc::new(Mutex::new(VecDeque::new())),
            token_delay: Arc::new(Mutex::new(None)),
            usage_delay: Arc::new(Mutex::new(None)),
        };
        let accept = fake.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let connection = accept.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let fake = connection.clone();
                        async move { fake.answer(request).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        fake
    }

    /// The same fake behind its own TLS handshake (/52: TLS
    /// terminating at the fake upstream). The committed test pair answers;
    /// the product stages its trust through `SSL_CERT_FILE` (`server_env`),
    /// which is the platform's own convention the product already honours
    /// (`tls.rs`), never a product seam.
    pub(crate) async fn start_tls() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("fake bind");
        let fake = Fake {
            addr: listener.local_addr().expect("fake addr"),
            seen: Arc::new(Mutex::new(Vec::new())),
            script: Arc::new(Mutex::new(VecDeque::new())),
            token_script: Arc::new(Mutex::new(VecDeque::new())),
            usage_script: Arc::new(Mutex::new(VecDeque::new())),
            token_delay: Arc::new(Mutex::new(None)),
            usage_delay: Arc::new(Mutex::new(None)),
        };
        let (cert, key) = stage_tls_pair(&fake_addr_dir(&fake.addr));
        let acceptor = test_acceptor(&cert, &key);
        let accept = fake.clone();
        tokio::spawn(async move {
            loop {
                let Ok((plain, _)) = listener.accept().await else {
                    return;
                };
                let Ok(stream) = acceptor.accept(plain).await else {
                    continue;
                };
                let connection = accept.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let fake = connection.clone();
                        async move { fake.answer(request).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        fake
    }

    pub(crate) fn script(&self, replies: impl IntoIterator<Item = Reply>) {
        self.script.lock().expect("script").extend(replies);
    }

    pub(crate) fn script_token(&self, replies: impl IntoIterator<Item = Reply>) {
        self.token_script
            .lock()
            .expect("token script")
            .extend(replies);
    }

    pub(crate) fn script_usage(&self, replies: impl IntoIterator<Item = Reply>) {
        self.usage_script
            .lock()
            .expect("usage script")
            .extend(replies);
    }

    pub(crate) fn delay_token(&self, delay: Duration) {
        *self.token_delay.lock().expect("token delay") = Some(delay);
    }

    pub(crate) fn delay_usage(&self, delay: Duration) {
        *self.usage_delay.lock().expect("usage delay") = Some(delay);
    }

    pub(crate) fn token_calls(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|seen| seen.path == "/v1/oauth/token")
            .collect()
    }

    pub(crate) fn usage_calls(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|seen| seen.path == "/api/oauth/usage")
            .collect()
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }

    pub(crate) fn last(&self) -> Seen {
        self.seen().pop().expect("the fake upstream was called")
    }

    pub(crate) fn calls(&self) -> usize {
        self.seen.lock().expect("seen").len()
    }

    pub(crate) async fn answer(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<FakeBody>, Reset> {
        let (parts, body) = request.into_parts();
        let body = body
            .collect()
            .await
            .expect("fake reads the body")
            .to_bytes();
        let seen = Seen {
            at: Instant::now(),
            method: parts.method.to_string(),
            path: parts.uri.path().to_string(),
            headers: parts
                .headers
                .iter()
                .map(|(n, v)| {
                    (
                        n.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            body,
        };
        let path = seen.path.clone();
        self.seen.lock().expect("seen").push(seen);
        let token_delay = (path == "/v1/oauth/token")
            .then(|| *self.token_delay.lock().expect("token delay"))
            .flatten();
        if let Some(delay) = token_delay {
            tokio::time::sleep(delay).await;
        }
        let usage_delay = (path == "/api/oauth/usage")
            .then(|| *self.usage_delay.lock().expect("usage delay"))
            .flatten();
        if let Some(delay) = usage_delay {
            tokio::time::sleep(delay).await;
        }
        let reply = if path == "/v1/oauth/token" {
            self.token_script.lock().expect("token script").pop_front()
        } else if path == "/api/oauth/usage" {
            self.usage_script.lock().expect("usage script").pop_front()
        } else {
            self.script.lock().expect("script").pop_front()
        };
        let reply = match reply.unwrap_or_else(|| default_reply(&path)) {
            Reply::Hold(gate) => {
                gate.notified().await;
                default_reply(&path)
            }
            Reply::HoldThen(gate, then) => {
                gate.notified().await;
                *then
            }
            other => other,
        };
        Ok(match reply {
            Reply::Raw {
                status,
                headers,
                body,
            } => {
                let mut response = Response::builder().status(status);
                for (name, value) in headers {
                    response = response.header(name, value);
                }
                response
                    .body(Full::new(Bytes::from(body)).map_err(|i| match i {}).boxed())
                    .expect("fake response builds")
            }
            Reply::Sse { events } => {
                let (delivered, dropped) = (
                    Arc::new(AtomicUsize::new(0)),
                    Arc::new(AtomicBool::new(false)),
                );
                watched_sse(events, Duration::from_millis(30), delivered, dropped)
            }
            Reply::SseWatched {
                events,
                gap_ms,
                delivered,
                dropped,
            } => watched_sse(events, Duration::from_millis(gap_ms), delivered, dropped),
            Reply::HoldBody(gate) => {
                let Reply::Raw {
                    status,
                    headers,
                    body,
                } = default_reply(&path)
                else {
                    unreachable!("the default reply is raw")
                };
                let mut response = Response::builder().status(status);
                for (name, value) in headers {
                    response = response.header(name, value);
                }
                response
                    .body(
                        GatedBody::new(gate, Bytes::from(body))
                            .map_err(|i| match i {})
                            .boxed(),
                    )
                    .expect("fake response builds")
            }
            // Failing the service drops the connection with no response written.
            Reply::ResetBeforeHeaders => return Err(Reset),
            Reply::ResetMidBody => {
                let body = FailMidBody::new(message_body().to_string().into());
                return Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(body.boxed())
                    .map_err(|_| Reset);
            }
            Reply::Stall => return std::future::pending().await,
            // The gates above are consumed before this match.
            Reply::Hold(_) | Reply::HoldThen(..) => unreachable!("the gate was consumed"),
        })
    }
}

/// A body whose one frame waits for the scenario's gate: the response headers
/// are on the wire while the body is not (the slot boundary).
pub(crate) struct GatedBody {
    gate: Pin<Box<dyn std::future::Future<Output = Bytes> + Send + Sync>>,
    done: bool,
}

impl GatedBody {
    fn new(gate: Arc<Notify>, body: Bytes) -> Self {
        Self {
            gate: Box::pin(async move {
                gate.notified().await;
                body
            }),
            done: false,
        }
    }
}

impl Body for GatedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        let body = ready!(this.gate.as_mut().poll(cx));
        this.done = true;
        Poll::Ready(Some(Ok(Frame::data(body))))
    }
}

/// The fake dropped the connection on purpose.
#[derive(Debug)]
pub(crate) struct Reset;

impl std::fmt::Display for Reset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scripted reset")
    }
}

impl std::error::Error for Reset {}

/// The fixture identity the profile, inference and token-exchange shapes
/// carry.
pub(crate) const FIXTURE_ACCOUNT_UUID: &str = "3c1f5a7e-0000-4000-8000-0000000000a1";
pub(crate) const FIXTURE_ORG_UUID: &str = "3c1f5a7e-0000-4000-8000-0000000000b2";
pub(crate) const FIXTURE_LOGIN_ACCESS: &str = "sk-ant-oat-fixture-login";
pub(crate) const FIXTURE_LOGIN_REFRESH: &str = "sk-ant-ort-fixture-login";

pub(crate) fn default_reply(path: &str) -> Reply {
    if path == "/api/oauth/profile" {
        return Reply::status(
            200,
            json!({
                "account": { "email": "fsub@fixture.invalid", "uuid": FIXTURE_ACCOUNT_UUID },
                "organization": { "uuid": FIXTURE_ORG_UUID, "name": "Fixture Org" },
            })
            .to_string(),
        );
    }
    if path == "/v1/oauth/token" {
        return Reply::status(
            200,
            json!({
                "access_token": FIXTURE_LOGIN_ACCESS,
                "refresh_token": FIXTURE_LOGIN_REFRESH,
                "expires_in": 3600,
            })
            .to_string(),
        );
    }
    if path == "/api/oauth/usage" {
        return reply_usage("25", "40");
    }
    if path == CODEX_RESPONSES_PATH {
        return reply_codex_responses();
    }
    if path == "/backend-api/codex/models" {
        return Reply::status(200, json!({ "models": [] }).to_string());
    }
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("request-id".to_string(), "req_fixture_0001".to_string()),
    ];
    headers.extend(ratelimit_headers_oauth());
    Reply::Raw {
        status: 200,
        headers,
        body: message_body().to_string(),
    }
}

/// Percent units and every verified window shape.
pub(crate) fn reply_usage(session: &str, weekly: &str) -> Reply {
    Reply::status(
        200,
        json!({
            "five_hour": { "utilization": session.parse::<f64>().expect("percent"), "resets_at": "2099-01-01T00:00:00Z" },
            "seven_day": { "used_percentage": weekly.parse::<f64>().expect("percent"), "resets_at": 4_070_908_800_i64 },
            "seven_day_sonnet": { "utilization": 10, "resets_at": 4_070_908_800_000_i64 },
            "limits": [{
                "group": "weekly",
                "scope": { "model": { "display_name": "Fable" } },
                "percent": 15,
                "resets_at": "2099-01-01T00:00:00Z",
            }],
        })
        .to_string(),
    )
}

/// A non-streamed `message` with the usage object.
pub(crate) fn message_body() -> Value {
    json!({
        "id": "msg_fixture",
        "type": "message",
        "role": "assistant",
        "model": "claude-haiku-4-5-20251001",
        "content": [{ "type": "text", "text": "hi there friend" }],
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 11, "output_tokens": 7 },
    })
}

/// utilisation is a fraction of the window (0–1), reset is absolute.
pub(crate) fn ratelimit_headers_oauth() -> Vec<(String, String)> {
    ratelimit_headers("0.12", "0.03", "2099-01-01T00:00:00Z")
}

/// with the weekly window where the scenario needs it; `status` follows
/// the utilisation (`rejected` at or above 1).
pub(crate) fn ratelimit_headers(session: &str, weekly: &str, reset: &str) -> Vec<(String, String)> {
    let status = |u: &str| {
        if u.parse::<f64>().is_ok_and(|u| u >= 1.0) {
            "rejected"
        } else {
            "allowed"
        }
    };
    [
        ("anthropic-ratelimit-unified-5h-utilization", session),
        ("anthropic-ratelimit-unified-5h-status", status(session)),
        ("anthropic-ratelimit-unified-5h-reset", reset),
        ("anthropic-ratelimit-unified-7d-utilization", weekly),
        ("anthropic-ratelimit-unified-7d-status", status(weekly)),
        ("anthropic-ratelimit-unified-7d-reset", reset),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_string(), v.to_string()))
    .collect()
}

/// A successful answer teaching the weekly window: utilisation and reset.
pub(crate) fn reply_teaching_weekly(weekly: &str, reset: &str) -> Reply {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("request-id".to_string(), "req_fixture_0002".to_string()),
    ];
    headers.extend(ratelimit_headers("0.12", weekly, reset));
    Reply::Raw {
        status: 200,
        headers,
        body: message_body().to_string(),
    }
}

/// The upstream's own exhaustion 429 with its `retry-after`.
pub(crate) fn reply_exhausted_429(retry_after: u64) -> Reply {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("request-id".to_string(), "req_fixture_0429".to_string()),
        ("retry-after".to_string(), retry_after.to_string()),
    ];
    headers.extend(ratelimit_headers("0.40", "1.0", "2099-01-01T00:00:00Z"));
    Reply::Raw {
        status: 429,
        headers,
        body: json!({
            "type": "error",
            "error": { "type": "rate_limit_error", "message": "This request would exceed your organization's rate limit" },
            "request_id": "req_fixture_0429",
        })
        .to_string(),
    }
}

/// A pure burst throttle — every governing bucket far
/// from exhaustion — whatever `retry-after` says or whether it exists.
pub(crate) fn reply_throttle_429(retry_after: Option<u64>) -> Reply {
    let seconds = retry_after.map(|s| s.to_string());
    let mut reply = reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "0.03"),
            ("7d-status", "allowed"),
        ],
        seconds.as_deref(),
    );
    if let Reply::Raw { headers, .. } = &mut reply {
        headers.push(("x-should-retry".into(), "true".into()));
    }
    reply
}

/// the organisation spend-cap 429 — no `retry-after`, the code under
/// `error.details`, the governing windows healthy.
pub(crate) fn reply_spend_cap_429() -> Reply {
    reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "0.03"),
            ("7d-status", "allowed"),
        ],
        None,
    )
    .with_body(
        json!({
            "type": "error",
            "error": {
                "type": "rate_limit_error",
                "message": "Your organization has reached its spend limit",
                "details": { "error_code": "enforced_spend_limit_reached" },
            },
            "request_id": "req_fixture_0429",
        })
        .to_string(),
    )
}

/// A 429 carrying exactly the named unified rate-limit fields; each entry is
/// `(suffix, value)` after `anthropic-ratelimit-unified-`. `retry_after` of
/// `None` omits the header; `Some` is relayed verbatim, malformed values
/// included, so the clamps can be exercised.
pub(crate) fn reply_429_unified(fields: &[(&str, &str)], retry_after: Option<&str>) -> Reply {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("request-id".to_string(), "req_fixture_0429".to_string()),
    ];
    for (suffix, value) in fields {
        headers.push((
            format!("anthropic-ratelimit-unified-{suffix}"),
            (*value).to_string(),
        ));
    }
    if let Some(seconds) = retry_after {
        headers.push(("retry-after".to_string(), seconds.to_string()));
    }
    Reply::Raw {
        status: 429,
        headers,
        body: json!({
            "type": "error",
            "error": { "type": "rate_limit_error", "message": "Rate limited" },
            "request_id": "req_fixture_0429",
        })
        .to_string(),
    }
}

/// A 429 with API-key counter headers; entries are `(suffix, value)`
/// after `anthropic-ratelimit-`. `retry_after` may be malformed on purpose.
pub(crate) fn reply_429_apikey(fields: &[(&str, &str)], retry_after: Option<&str>) -> Reply {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("request-id".to_string(), "req_fixture_0429".to_string()),
    ];
    for (suffix, value) in fields {
        headers.push((
            format!("anthropic-ratelimit-{suffix}"),
            (*value).to_string(),
        ));
    }
    if let Some(seconds) = retry_after {
        headers.push(("retry-after".to_string(), seconds.to_string()));
    }
    Reply::Raw {
        status: 429,
        headers,
        body: json!({
            "type": "error",
            "error": { "type": "rate_limit_error", "message": "Rate limited" },
            "request_id": "req_fixture_0429",
        })
        .to_string(),
    }
}

/// A 200 teaching API-key counters (limit/remaining pairs in seconds'
/// company of a reset when one is wanted).
pub(crate) fn reply_teaching_apikey(fields: &[(&str, &str)]) -> Reply {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("request-id".to_string(), "req_fixture_0002".to_string()),
    ];
    for (suffix, value) in fields {
        headers.push((
            format!("anthropic-ratelimit-{suffix}"),
            (*value).to_string(),
        ));
    }
    Reply::Raw {
        status: 200,
        headers,
        body: message_body().to_string(),
    }
}

/// A 200 that also carries the `7d_oi` family window, teaching the
/// model→family mapping alongside the shared windows.
pub(crate) fn reply_teaching_family(fable_util: &str, fable_status: &str) -> Reply {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("request-id".to_string(), "req_fixture_0002".to_string()),
    ];
    headers.extend(ratelimit_headers("0.12", "0.03", "2099-01-01T00:00:00Z"));
    headers.push((
        "anthropic-ratelimit-unified-7d_oi-utilization".into(),
        fable_util.into(),
    ));
    headers.push((
        "anthropic-ratelimit-unified-7d_oi-status".into(),
        fable_status.into(),
    ));
    headers.push((
        "anthropic-ratelimit-unified-7d_oi-reset".into(),
        "2099-01-01T00:00:00Z".into(),
    ));
    Reply::Raw {
        status: 200,
        headers,
        body: message_body().to_string(),
    }
}

/// A successful answer with no quota facts at all: a headerless
/// revalidation.
pub(crate) fn reply_headerless_200() -> Reply {
    Reply::Raw {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: message_body().to_string(),
    }
}

/// A credential the upstream refuses.
pub(crate) fn reply_auth_401() -> Reply {
    Reply::status(
        401,
        json!({
            "type": "error",
            "error": { "type": "authentication_error", "message": "Invalid bearer token" },
            "request_id": "req_fixture_0401",
        })
        .to_string(),
    )
}
/// A reply with its body replaced, for the byte-identical relays.
impl Reply {
    pub(crate) fn with_body(self, body: String) -> Self {
        match self {
            Reply::Raw {
                status, headers, ..
            } => Reply::Raw {
                status,
                headers,
                body,
            },
            other => other,
        }
    }
}

/// A response the proxy's client cannot parse — more header fields
/// than hyper accepts — so the attempt fails with neither a network failure
/// nor an upstream status (the class).
pub(crate) fn reply_unparseable() -> Reply {
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    headers.extend((0..150).map(|i| (format!("x-injected-{i}"), "v".to_string())));
    Reply::Raw {
        status: 200,
        headers,
        body: message_body().to_string(),
    }
}

/// Unix seconds `from_now` seconds ahead, as the absolute reset.
pub(crate) fn reset_in(from_now: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    (now + from_now).to_string()
}

/// The `x-jaynshare-account` token for a reference.
pub(crate) fn token(pin: bool, reference: &str) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reference.as_bytes());
    format!("{}.{encoded}", if pin { "pin" } else { "pref" })
}

/// the SSE sequence a streamed answer carries.
pub(crate) fn sse_events() -> Vec<String> {
    [
        json!({"type":"message_start","message":{"id":"msg_fixture","usage":{"input_tokens":11,"output_tokens":1}}}),
        json!({"type":"ping"}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi there friend"}}),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}),
        json!({"type":"message_stop"}),
    ]
    .iter()
    .map(|event| {
        format!(
            "event: {}\ndata: {event}\n\n",
            event["type"].as_str().expect("event type")
        )
    })
    .collect()
}

/// Codex's turn on the fake chatgpt.com.
pub(crate) const CODEX_RESPONSES_PATH: &str = "/backend-api/codex/responses";

/// The fake chatgpt.com's Codex turn: one SSE answer with its
/// `x-codex-*` quota headers.
pub(crate) fn reply_codex_responses() -> Reply {
    let events: String = [
        json!({"type":"response.created","response":{"id":"resp_fixture"}}),
        json!({"type":"response.output_item.done","item":{"type":"message","role":"assistant","id":"msg_fixture","content":[{"type":"output_text","text":"hello from the fake chatgpt"}]}}),
        json!({"type":"response.completed","response":{"id":"resp_fixture","usage":{"input_tokens":11,"output_tokens":7,"total_tokens":18}}}),
    ]
    .iter()
    .map(|event| format!("event: {}\ndata: {event}\n\n", event["type"].as_str().expect("event type")))
    .collect();
    let mut headers = vec![("content-type".to_string(), "text/event-stream".to_string())];
    headers.extend(
        [
            ("x-codex-primary-used-percent", "12.5"),
            ("x-codex-primary-window-minutes", "300"),
            ("x-codex-primary-reset-at", "1900000000"),
            ("x-codex-secondary-used-percent", "40"),
            ("x-codex-secondary-window-minutes", "10080"),
            ("x-codex-secondary-reset-at", "1900500000"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string())),
    );
    Reply::Raw {
        status: 200,
        headers,
        body: events,
    }
}

/// A body that yields one frame per scripted chunk with a gap between them, so
/// "relayed chunk by chunk" is observable and not an artefact of buffering.
pub(crate) struct ScriptedBody {
    chunks: VecDeque<Bytes>,
    gap: Pin<Box<Sleep>>,
    gap_for_next: Duration,
    delivered: Option<Arc<AtomicUsize>>,
    dropped: Option<Arc<AtomicBool>>,
    waited: bool,
}

impl ScriptedBody {
    fn new(
        chunks: Vec<String>,
        gap: Duration,
        delivered: Option<Arc<AtomicUsize>>,
        dropped: Option<Arc<AtomicBool>>,
    ) -> Self {
        Self {
            chunks: chunks.into_iter().map(Bytes::from).collect(),
            gap: Box::pin(tokio::time::sleep(Duration::ZERO)),
            gap_for_next: gap,
            delivered,
            dropped,
            waited: true,
        }
    }
}

impl Drop for ScriptedBody {
    fn drop(&mut self) {
        if let Some(dropped) = &self.dropped {
            dropped.store(true, Ordering::Relaxed);
        }
    }
}

impl Body for ScriptedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if !this.waited {
            ready!(this.gap.as_mut().poll(cx));
            this.waited = true;
        }
        match this.chunks.pop_front() {
            Some(chunk) => {
                if let Some(delivered) = &this.delivered {
                    delivered.fetch_add(1, Ordering::Relaxed);
                }
                this.gap = Box::pin(tokio::time::sleep(this.gap_for_next));
                this.waited = false;
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            None => Poll::Ready(None),
        }
    }
}

/// The shared counters a `Reply::SseWatched` body reports: the frames the
/// proxy pulled, and whether the fake's stream task was dropped.
pub(crate) fn watched() -> (Arc<AtomicUsize>, Arc<AtomicBool>) {
    (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
    )
}

/// An SSE-shaped response with the scripted chunks, the gap between them and
/// the shared counters the streaming tests read.
fn watched_sse(
    events: Vec<String>,
    gap: Duration,
    delivered: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
) -> Response<FakeBody> {
    let mut response = Response::builder()
        .status(200)
        .header("content-type", "text/event-stream");
    for (name, value) in ratelimit_headers_oauth() {
        response = response.header(name, value);
    }
    response
        .body(
            ScriptedBody::new(events, gap, Some(delivered), Some(dropped))
                .map_err(|i| match i {})
                .boxed(),
        )
        .expect("fake response builds")
}

/// A body that yields one data frame, idles a moment so the head and the chunk
/// are on the wire, then fails: the fake's connection ends mid-body with no
/// clean end.
struct FailMidBody {
    chunk: Option<Bytes>,
    gap: Pin<Box<Sleep>>,
    waited: bool,
}

impl FailMidBody {
    fn new(chunk: Bytes) -> Self {
        Self {
            chunk: Some(chunk),
            gap: Box::pin(tokio::time::sleep(Duration::ZERO)),
            waited: true,
        }
    }

    fn boxed(self) -> FakeBody {
        BoxBody::new(self.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>))
    }
}

impl Body for FailMidBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        if !this.waited {
            ready!(this.gap.as_mut().poll(cx));
            this.waited = true;
        }
        match this.chunk.take() {
            Some(chunk) => {
                // Let the head and the chunk reach the proxy before the cut.
                this.gap = Box::pin(tokio::time::sleep(Duration::from_millis(100)));
                this.waited = false;
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            // The connection ends mid-body, as a dropped upstream socket would.
            None => Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "scripted mid-body reset",
            )))),
        }
    }
}

// ------------------------------------------------------------------ the instance

/// What a scenario varies in the configuration document it owns.
#[derive(Clone)]
pub(crate) struct Setup {
    pub(crate) telemetry_policy: &'static str,
    pub(crate) blocked_models: Vec<String>,
    pub(crate) capture: bool,
    /// bind the wildcard address so a connection to the host's own
    /// non-loopback address arrives with a non-loopback TCP peer.
    pub(crate) wildcard: bool,
    /// MITM mode on. The proxy listener is bound either way, on a
    /// port the harness reserves — `Instance::mitm_addr` is that address
    /// and answers only the while the mode is off.
    pub(crate) mitm: bool,
    /// `None` uses the fake's own loopback origin; `Some` overrides it verbatim.
    pub(crate) upstream_origin: Option<String>,
    /// omit the `upstream_origin` key altogether, so the override is
    /// *not* active and the product carries the origin. The fake is then
    /// unreachable — only a scenario about the override's own effect asks for
    /// this (the exception).
    pub(crate) no_upstream_override: bool,
    /// Further `[selection]` lines: priorities, routes, `distribute_sessions`.
    pub(crate) selection: String,
    /// Further `[data_plane]` lines: `hold_budget_seconds` and the like.
    pub(crate) data_plane: String,
    /// Further `[quota]` lines: the revalidation floor and interval.
    pub(crate) quota: String,
    /// Further `[data_plane.egress]` lines.
    pub(crate) egress: String,
    /// Further `[logging]` lines: `max_bytes`, `retained_files`.
    /// Not `level`: the template fixes it at `debug` for every instance, so a
    /// `level` here is a duplicate TOML key and the server exits 3. A row that
    /// needs a quieter server unsets the key and reloads, as
    /// `s_mtm_19_…` does.
    pub(crate) logging: String,
    /// `[audit]` lines: `max_bytes`, `retained_files`.
    pub(crate) audit: String,
    /// `[clients]` lines: `enrollment_lifetime_seconds`.
    pub(crate) clients: String,
    /// Extra environment for the server process, beyond the standard
    /// isolation: the TLS trust store (`SSL_CERT_FILE`) the upstream TLS
    /// scenarios stage. Never read by the product as configuration.
    pub(crate) server_env: Vec<(String, String)>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            telemetry_policy: "forward",
            blocked_models: Vec::new(),
            capture: false,
            wildcard: false,
            mitm: false,
            upstream_origin: None,
            no_upstream_override: false,
            selection: String::new(),
            data_plane: String::new(),
            quota: String::new(),
            egress: String::new(),
            logging: String::new(),
            audit: String::new(),
            clients: String::new(),
            server_env: Vec::new(),
        }
    }
}

/// pool notation as `[selection]` lines: `("FSUB", 0)` is `A0`.
pub(crate) fn priorities(tiers: &[(&str, i64)]) -> String {
    let entries = tiers
        .iter()
        .map(|(name, value)| format!("{{ account = \"{name}\", value = {value} }}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("priorities = [{entries}]\n")
}

/// One route of: `(name, patterns, accounts, bucket)`; `accounts: None`
/// is an unrestricted route.
pub(crate) type RouteSpec<'a> = (
    &'a str,
    &'a [&'a str],
    Option<&'a [&'a str]>,
    Option<&'a str>,
);

/// one `routes = [...]` line.
pub(crate) fn routes(specs: &[RouteSpec<'_>]) -> String {
    let quoted = |items: &[&str]| {
        items
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let entries = specs
        .iter()
        .map(|(name, patterns, accounts, bucket)| {
            let mut entry = format!("name = \"{name}\", patterns = [{}]", quoted(patterns));
            if let Some(list) = accounts {
                entry += &format!(", accounts = [{}]", quoted(list));
            }
            if let Some(bucket) = bucket {
                entry += &format!(", bucket = \"{bucket}\"");
            }
            format!("{{ {entry} }}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("routes = [{entries}]\n")
}

/// the two key placements a credentials file is seen in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    Nested,
    TopLevel,
}

/// One running binary on a root of its own, with the fake it talks to.
pub(crate) struct Instance {
    pub(crate) root: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) addr: SocketAddr,
    /// The proxy listener's address; always `Some` — it is bound
    /// with the mode off too.
    pub(crate) mitm_addr: Option<SocketAddr>,
    pub(crate) child: Option<Child>,
    pub(crate) upstream: Fake,
    pub(crate) needles: Needles,
    /// The scenario's fault fixture, injected into every child
    /// this instance spawns. `None` spawns plainly.
    pub(crate) faults: Option<Arc<crate::faults::Faults>>,
    /// The setup's extra server environment, carried across respawns.
    server_env: Vec<(String, String)>,
}

/// CI points this at the release artefact; a bare `cargo test`
/// uses the binary cargo just built.
pub(crate) fn binary() -> PathBuf {
    match std::env::var_os("JAYNSHARE_BIN") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(env!("CARGO_BIN_EXE_jaynshare")),
    }
}

/// A port nobody else holds. Reserved and released so the CLI, which reads the
/// listen address out of the configuration, can find the instance.
///
/// The reservation has to be released before the server can take it, and the
/// suite runs tests in parallel, so the gap between the two is a race: a second
/// test reserving in that window gets the same port and one of the two servers
/// exits with `Address already in use`. `PORT_HANDOFF` closes the window by
/// letting only one instance be between reservation and a bound listener.
pub(crate) static PORT_HANDOFF: Mutex<()> = Mutex::new(());

/// Starts of one instance before a port taken under it is the scenario's failure.
const STARTUP_ATTEMPTS: u32 = 3;

/// Ports come from a band below every platform's ephemeral range (macOS
/// 49152–65535, Linux 32768–60999) and are handed out once per run. Each test
/// process starts at a PID-derived point so back-to-back or concurrent suite
/// processes do not immediately reuse listeners still represented in TCP
/// state.
static NEXT_PORT: OnceLock<Mutex<u16>> = OnceLock::new();
const PORT_BAND: (u16, u16) = (20_000, 30_000);

pub(crate) fn reserve_port() -> u16 {
    let next_port = NEXT_PORT.get_or_init(|| {
        let offset = std::process::id().wrapping_mul(2_654_435_761) % 8_000;
        Mutex::new(PORT_BAND.0 + offset as u16)
    });
    loop {
        let port = {
            let mut next = next_port.lock().unwrap_or_else(|e| e.into_inner());
            let port = *next;
            assert!(port < PORT_BAND.1, "the harness ran out of its port band");
            *next += 1;
            port
        };
        // Another run's suite may hold it; ours never asks twice.
        if StdTcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

pub(crate) fn write_private(path: &Path, contents: &str) {
    crate::leaks::register_planted(path);
    fs::write(path, contents).expect("write fixture file");
    make_private(path);
}

pub(crate) fn private_dir(path: &Path) {
    fs::create_dir_all(path).expect("create fixture directory");
    make_private(path);
}

/// Narrows `path` to the user: mode 0600 (0700 for a directory) on Unix,
/// and on Windows an ACL granting the user and `SYSTEM` alone, which a
/// directory hands down to what is created inside it.
pub(crate) fn make_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("narrow the fixture");
    }
    #[cfg(windows)]
    {
        let inherit = if path.is_dir() { "(OI)(CI)" } else { "" };
        let grant = |sid: &str| format!("*{sid}:{inherit}F");
        icacls(
            path,
            &[
                "/inheritance:r",
                "/grant:r",
                &grant(user_sid()),
                &grant("S-1-5-18"),
            ],
        );
    }
}

/// Opens `path` to every local user and returns what its refusal names:
/// the Unix mode, or the SID of Windows' `Users` group.
pub(crate) fn widen(path: &Path) -> &'static str {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let (mode, named) = if path.is_dir() {
            (0o755, "mode 755")
        } else {
            (0o644, "mode 644")
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("widen the fixture");
        named
    }
    #[cfg(windows)]
    {
        icacls(path, &["/grant", "*S-1-5-32-545:R"]);
        "S-1-5-32-545"
    }
}

/// Undoes [`widen`].
pub(crate) fn unwiden(path: &Path) {
    #[cfg(unix)]
    make_private(path);
    #[cfg(windows)]
    icacls(path, &["/remove:g", "*S-1-5-32-545"]);
}

/// `icacls <path> <args>`, which must succeed.
#[cfg(windows)]
fn icacls(path: &Path, args: &[&str]) {
    let output = Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .expect("run icacls");
    assert!(
        output.status.success(),
        "icacls {} {args:?}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stdout)
    );
}

/// The SID of the user running the suite.
#[cfg(windows)]
fn user_sid() -> &'static str {
    static SID: OnceLock<String> = OnceLock::new();
    SID.get_or_init(|| {
        // One CSV row: `"DOMAIN\name","S-1-5-21-…"`.
        let output = Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .expect("run whoami");
        let row = String::from_utf8_lossy(&output.stdout);
        let sid = row.trim().rsplit(',').next().unwrap_or_default();
        sid.trim_matches('"').to_string()
    })
}

pub(crate) fn api_fixture(
    scenario: &str,
    respond: impl FnOnce(StdTcpStream) + Send + 'static,
) -> (Child, std::thread::JoinHandle<()>, PathBuf, PathBuf) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind CLI fixture");
    let addr = listener.local_addr().expect("CLI fixture address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept CLI request");
        let mut request = [0; 4096];
        let request_bytes = stream.read(&mut request).expect("read CLI request");
        assert!(request_bytes > 0, "CLI sent an empty request");
        respond(stream);
    });

    let root = claim_scenario_root(scenario);
    private_dir(&root.join("state"));
    private_dir(&root.join("log"));
    let config = root.join("config.toml");
    write_private(
        &config,
        &format!(
            "version = 1\n\n[data_plane]\nlisten = \"{addr}\"\n\n\
             [storage]\nstate_file = {}\n\n[logging]\ndirectory = {}\n",
            toml_path(&root.join("state/state.json")),
            toml_path(&root.join("log")),
        ),
    );
    let stdout = root.join("api.stdout");
    let stderr = root.join("api.stderr");
    let child = Command::new(binary())
        .args([
            "--config",
            &config.display().to_string(),
            "--timeout",
            "1",
            "api",
            "GET",
            "/slow",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            fs::File::create(&stdout).expect("create CLI stdout"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr).expect("create CLI stderr"),
        ))
        .spawn()
        .expect("run API CLI");
    (child, server, stdout, stderr)
}

/// The configuration document a scenario's `Setup` becomes, at a root.
fn config_document(setup: &Setup, port: u16, mitm_port: u16, origin: &str, root: &Path) -> String {
    let host = if setup.wildcard {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let listen = format!("{host}:{port}");
    // The two proxy keys, always written. The proxy listener binds
    // with the mode off too, so every instance holds a reserved
    // port for it, and stays off unless the scenario asked for it.
    let mitm = format!(
        "\n[mitm]\nenabled = {}\nlisten = \"{host}:{mitm_port}\"\n",
        setup.mitm
    );
    let blocked = setup
        .blocked_models
        .iter()
        .map(|m| format!("\"{m}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let capture = if setup.capture {
        format!(
            "\n[diagnostics]\nwire_capture_directory = {}\n",
            toml_path(&root.join("cap"))
        )
    } else {
        String::new()
    };
    let egress = if setup.egress.is_empty() {
        String::new()
    } else {
        // `{fake}` stands for the scenario's own fake upstream (its origin).
        format!(
            "\n[data_plane.egress]\n{}",
            setup.egress.replace("{fake}", origin)
        )
    };
    let audit = if setup.audit.is_empty() {
        String::new()
    } else {
        format!("\n[audit]\n{}", setup.audit)
    };
    let clients = if setup.clients.is_empty() {
        String::new()
    } else {
        format!("\n[clients]\n{}", setup.clients)
    };
    let upstream_origin = if setup.no_upstream_override {
        String::new()
    } else {
        format!("upstream_origin = \"{origin}\"\n")
    };
    format!(
        "version = 1\n\n\
         [data_plane]\n\
         listen = \"{listen}\"\n\
         {upstream_origin}\
         telemetry_policy = \"{}\"\n{}\n\
         [quota]\n\
{}\n\
         [selection]\n\
         blocked_models = [{blocked}]\n{}\n\
         [storage]\n\
         state_file = {}\n\n\
         [logging]\n\
         directory = {}\n\
         level = \"debug\"\n{}{audit}{capture}{egress}{clients}{mitm}",
        setup.telemetry_policy,
        setup.data_plane,
        setup.quota,
        setup.selection,
        toml_path(&root.join("state/state.json")),
        toml_path(&root.join("log")),
        setup.logging,
    )
}

/// `path` as a TOML string: a Windows path's backslashes are escaped.
pub(crate) fn toml_path(path: &Path) -> String {
    toml::Value::String(path.display().to_string()).to_string()
}

impl Instance {
    pub(crate) async fn start(scenario: &str) -> Self {
        Self::start_with(scenario, Setup::default()).await
    }

    /// An instance an enrolled client launches against: MITM mode on, since
    /// every launch is MITM mode and `install_client` installs the
    /// instance's CA.
    pub(crate) async fn start_client(scenario: &str) -> Self {
        Self::start_with(
            scenario,
            Setup {
                mitm: true,
                ..Setup::default()
            },
        )
        .await
    }

    /// The server's process id, for the "one process throughout" assertions.
    pub(crate) fn pid(&self) -> u32 {
        self.child.as_ref().expect("running child").id()
    }

    /// makes a route or priority reference to an account the state
    /// lacks a startup error, so a scenario whose policy names accounts
    /// starts without the `[selection]` lines, adds the accounts with `add`,
    /// then puts the policy in force through the reload.
    pub(crate) async fn start_with_accounts(
        scenario: &str,
        setup: Setup,
        add: impl FnOnce(&Instance),
    ) -> Self {
        let bare = Setup {
            selection: String::new(),
            ..setup.clone()
        };
        let instance = Self::start_with(scenario, bare).await;
        add(&instance);
        instance.reload_with_setup(&setup);
        instance
    }

    /// A fresh root, its own ports, nothing carried from another scenario.
    pub(crate) async fn start_with(scenario: &str, setup: Setup) -> Self {
        Self::start_faulted(scenario, setup, None, None).await
    }

    /// A scenario that supplies its own fake as the upstream (a TLS fake):
    /// the document's origin is the setup's `upstream_origin`, the
    /// fake stays reachable for scripting on the instance.
    pub(crate) async fn start_with_upstream(scenario: &str, setup: Setup, upstream: Fake) -> Self {
        Self::start_faulted(scenario, setup, None, Some(upstream)).await
    }

    /// The same, with the scenario's fault fixture injected into every
    /// spawned child (the moved clock, the write boundaries).
    pub(crate) async fn start_with_faults(
        scenario: &str,
        setup: Setup,
        faults: Arc<crate::faults::Faults>,
    ) -> Self {
        Self::start_faulted(scenario, setup, Some(faults), None).await
    }

    async fn start_faulted(
        scenario: &str,
        setup: Setup,
        faults: Option<Arc<crate::faults::Faults>>,
        supplied_upstream: Option<Fake>,
    ) -> Self {
        let upstream = match supplied_upstream {
            Some(fake) => fake,
            None => Fake::start().await,
        };
        let root = claim_scenario_root(scenario);
        private_dir(&root.join("state"));
        private_dir(&root.join("log"));
        private_dir(&root.join("home"));
        if setup.capture {
            private_dir(&root.join("cap"));
        }

        // Held until the server has printed its startup line, so no other test
        // can reserve this port in the window where nobody is bound to it.
        let handoff = PORT_HANDOFF.lock().unwrap_or_else(|e| e.into_inner());
        let origin = setup
            .upstream_origin
            .clone()
            .unwrap_or_else(|| format!("http://{}", upstream.addr));
        let config = root.join("config.toml");
        let mut instance = Instance {
            root,
            config,
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            mitm_addr: None,
            child: None,
            upstream,
            needles: Needles::new(),
            faults,
            server_env: setup.server_env.clone(),
        };
        // A reserved port can still be taken between the probe and the child's
        // bind by something outside the handoff; fresh ports, then retry.
        for attempt in 1..=STARTUP_ATTEMPTS {
            let port = reserve_port();
            let mitm_port = reserve_port();
            write_private(
                &instance.config,
                &config_document(&setup, port, mitm_port, &origin, &instance.root),
            );
            instance.addr = SocketAddr::from(([127, 0, 0, 1], port));
            instance.mitm_addr = Some(SocketAddr::from(([127, 0, 0, 1], mitm_port)));
            instance.child = Some(instance.spawn_server());
            match instance.startup() {
                Ok(()) => break,
                Err(stderr)
                    if attempt < STARTUP_ATTEMPTS && stderr.contains("Address already in use") => {}
                Err(stderr) => panic!(
                    "the server exited during startup: {stderr}{}",
                    instance.port_holders(&stderr)
                ),
            }
        }
        drop(handoff);
        instance
    }

    fn spawn_server(&self) -> Child {
        let stdout = fs::File::create(self.root.join("stdout.txt")).expect("stdout file");
        let stderr = fs::File::create(self.root.join("stderr.txt")).expect("stderr file");
        let mut command = Command::new(binary());
        command
            .args(["--config", &self.config.display().to_string(), "serve"])
            // No platform opener is reachable from the release binary.
            .env("PATH", self.root.join("no-browser-on-path"))
            // The managed store the server reads is this root's
            // home, never the developer's.
            .envs(platform_home(&self.root.join("home")));
        for (name, value) in &self.server_env {
            command.env(name, value);
        }
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some(faults) = &self.faults {
            faults.inject(&mut command);
        }
        command.spawn().expect("restart the binary under test")
    }

    pub(crate) fn restart(&mut self) {
        self.stop();
        self.child = Some(self.spawn_server());
        self.await_startup();
    }

    /// The configuration document for the setup, written over the running
    /// instance's file; nothing reads it until a reload or a restart.
    pub(crate) fn write_setup(&self, setup: &Setup) {
        write_private(
            &self.config,
            &config_document(
                setup,
                self.addr.port(),
                // A setup that turns the mode off keeps the port: a restart
                // on it binds the proxy listener to answer 405.
                self.mitm_addr.map_or_else(reserve_port, |a| a.port()),
                &format!("http://{}", self.upstream.addr),
                &self.root,
            ),
        );
    }

    /// the setup's document written and reloaded through `config
    /// reload`, which must apply.
    pub(crate) fn reload_with_setup(&self, setup: &Setup) {
        self.write_setup(setup);
        let envelope = self.cli_json(&["config", "reload"], None);
        assert_eq!(envelope["ok"], true, "the reload applied: {envelope}");
    }

    /// `SIGHUP`, the second reload trigger.
    #[cfg(unix)]
    pub(crate) fn sighup(&self) {
        assert!(
            Command::new("kill")
                .args(["-HUP", &self.pid().to_string()])
                .status()
                .expect("send SIGHUP")
                .success(),
            "SIGHUP was accepted"
        );
    }

    /// SIGTERM and wait; the instance is down until `respawn`.
    pub(crate) fn stop(&mut self) {
        let mut child = self.child.take().expect("running child");
        #[cfg(unix)]
        assert!(
            Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .expect("send SIGTERM")
                .success(),
            "SIGTERM was accepted"
        );
        #[cfg(not(unix))]
        child.kill().expect("stop child");
        child.wait().expect("wait for stopped child");
    }

    /// Spawns on the current file and lets it fail: the exit code and
    /// standard error. The instance stays down.
    pub(crate) fn spawn_expecting_failure(&self) -> (i32, String) {
        let output = self
            .spawn_server()
            .wait_with_output()
            .expect("wait for the refused start");
        (output.status.code().unwrap_or(-1), self.stderr())
    }

    /// Restarts after applying an edit to the persisted state: the process is
    /// down between the SIGTERM and the respawn, so the edit is what the
    /// restarted server loads (strips a refresh token).
    pub(crate) fn restart_with_state(&mut self, edit: impl FnOnce(&mut Value)) {
        let mut child = self.child.take().expect("running child");
        #[cfg(unix)]
        assert!(
            Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .expect("send SIGTERM")
                .success(),
            "SIGTERM was accepted"
        );
        #[cfg(not(unix))]
        child.kill().expect("stop child");
        child.wait().expect("wait for stopped child");
        let path = self.root.join("state/state.json");
        let mut state: Value =
            serde_json::from_slice(&fs::read(&path).expect("read state for edit"))
                .expect("state JSON");
        edit(&mut state);
        fs::write(&path, serde_json::to_vec(&state).expect("state serialises"))
            .expect("write edited state");
        self.child = Some(self.spawn_server());
        self.await_startup();
    }

    pub(crate) fn crash_and_restart(&mut self) {
        let mut child = self.child.take().expect("running child");
        child.kill().expect("kill child");
        child.wait().expect("wait for killed child");
        self.child = Some(self.spawn_server());
        self.await_startup();
    }

    /// waits for the running server to exit on its own and returns
    /// its exit status — a code when it exits, a signal when one killed it
    /// (the filled destination).
    pub(crate) fn await_exit_status(&mut self) -> std::process::ExitStatus {
        let mut child = self.child.take().expect("running child");
        for _ in 0..200 {
            if let Some(status) = child.try_wait().expect("poll the child") {
                return status;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the server never exited: {}", self.stderr());
    }

    /// waits for the running server to exit on its own and returns
    /// its exit code (the `chmod 0500` fail-stop).
    pub(crate) fn await_exit(&mut self) -> i32 {
        self.await_exit_status().code().expect("exit code")
    }

    /// Respawns after a self-exit or a crash (the child is already gone).
    pub(crate) fn respawn(&mut self) {
        self.kill_child();
        self.child = Some(self.spawn_server());
        self.await_startup();
    }

    /// Respawns and lets it fail: the exit status of a process the fixture
    /// kills at a write boundary (the filled destination).
    pub(crate) fn respawn_expecting_exit_status(&mut self) -> std::process::ExitStatus {
        self.kill_child();
        self.child = Some(self.spawn_server());
        self.await_exit_status()
    }

    /// Ends a child still running, so no respawn leaves one behind holding the
    /// port: `Child`'s own drop reaps nothing and the orphan outlives the run.
    /// Teardown ends the server the way an operator would, not with a
    /// kill: a `SIGKILL` between `write_private_atomic`'s temporary and its
    /// rename leaves that temporary behind, and it carries the pooled
    /// credentials the whole-run needle sweep looks for. The two
    /// scenarios that kill at the rename boundary do it deliberately and
    /// delete what their fault leaves; no other scenario should create one.
    fn kill_child(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        #[cfg(unix)]
        {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                    Err(_) => break,
                }
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    pub(crate) fn state_file(&self) -> Value {
        serde_json::from_slice(
            &fs::read(self.root.join("state/state.json")).expect("read fixture state"),
        )
        .expect("fixture state is JSON")
    }

    /// The state file's bytes, for every "unchanged" assertion.
    pub(crate) fn state_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let bytes = fs::read(self.root.join("state/state.json")).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    pub(crate) fn managed_path(&self) -> PathBuf {
        self.root.join("home/.claude/.credentials.json")
    }

    /// the document under the server's home, in either key placement,
    /// with `expiresAt` in unix milliseconds.
    pub(crate) fn plant_managed_file(
        &self,
        placement: Placement,
        access: &str,
        refresh: &str,
        expires_at: OffsetDateTime,
    ) {
        crate::leaks::register_needle("planted managed access token", access);
        crate::leaks::register_needle("planted managed refresh token", refresh);
        let family = json!({
            "accessToken": access,
            "refreshToken": refresh,
            "expiresAt": expires_at.unix_timestamp() * 1_000,
            "subscriptionType": "max",
        });
        let document = match placement {
            Placement::Nested => json!({ "claudeAiOauth": family }),
            Placement::TopLevel => family,
        };
        self.plant_managed_bytes(document.to_string().as_bytes());
    }

    /// The malformed rows plant bytes of their own (the causes).
    pub(crate) fn plant_managed_bytes(&self, bytes: &[u8]) {
        let path = self.managed_path();
        private_dir(path.parent().expect("the .claude directory"));
        fs::write(&path, bytes).expect("plant the managed credentials file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("chmod the managed credentials file");
        }
    }

    pub(crate) fn remove_managed_file(&self) {
        let _ = fs::remove_file(self.managed_path());
    }

    /// Start and let it fail: the scenario reads the exit code and standard error.
    pub(crate) async fn start_expecting_failure(scenario: &str, setup: Setup) -> (i32, String) {
        let upstream = Fake::start().await;
        let root = claim_scenario_root(scenario);
        private_dir(&root.join("state"));
        private_dir(&root.join("log"));
        let port = reserve_port();
        let origin = setup
            .upstream_origin
            .clone()
            .unwrap_or_else(|| format!("http://{}", upstream.addr));
        let config = root.join("config.toml");
        let mitm_port = reserve_port();
        write_private(
            &config,
            &config_document(&setup, port, mitm_port, &origin, &root),
        );
        let output = Command::new(binary())
            .args(["--config", &config.display().to_string(), "serve"])
            .output()
            .expect("start the binary under test");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// Who else is on the port, for the one startup failure that is never the
    /// product's fault: a reserved port taken between the probe and the child's
    /// bind leaves nothing behind to look at once the test has panicked.
    fn port_holders(&self, stderr: &str) -> String {
        if !stderr.contains("Address already in use") {
            return String::new();
        }
        // The port the server names in its bind error (either listener),
        // falling back to the base-URL one.
        let port = stderr
            .split_whitespace()
            .find_map(|word| {
                word.trim_end_matches(':')
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok())
            })
            .unwrap_or(self.addr.port());
        let holders = Command::new("lsof")
            .args(["-nP", &format!("-iTCP:{port}")])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        format!("\n--- lsof -iTCP:{port} at the failure:\n{holders}")
    }

    /// the single startup line is the readiness signal; no polling on a socket.
    pub(crate) fn await_startup(&mut self) {
        if let Err(stderr) = self.startup() {
            panic!(
                "the server exited during startup: {stderr}{}",
                self.port_holders(&stderr)
            );
        }
    }

    /// `Err` carries the standard error of a server that exited before its
    /// startup line; one that never prints it panics here.
    fn startup(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let line = self.stdout();
            if line.contains("listening on") {
                return Ok(());
            }
            if let Some(status) = self
                .child
                .as_mut()
                .expect("child")
                .try_wait()
                .expect("try_wait")
            {
                return Err(format!("{status}: {}", self.stderr()));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "the server never printed its startup line: {}",
            self.stderr()
        );
    }

    pub(crate) fn stdout(&self) -> String {
        fs::read_to_string(self.root.join("stdout.txt")).unwrap_or_default()
    }

    pub(crate) fn stderr(&self) -> String {
        fs::read_to_string(self.root.join("stderr.txt")).unwrap_or_default()
    }

    /// One CLI invocation against this instance: exit code, stdout, stderr.
    pub(crate) fn cli(&self, args: &[&str], stdin: Option<&str>) -> (i32, String, String) {
        self.cli_env(args, stdin, &[])
    }

    /// The same with extra environment (`EDITOR` for `config edit`).
    pub(crate) fn cli_env(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        env: &[(&str, &str)],
    ) -> (i32, String, String) {
        let mut command = Command::new(binary());
        command
            .args(["--config", &self.config.display().to_string()])
            .args(args)
            // The developer's editor never opens on a fixture file.
            .env_remove("VISUAL")
            .env_remove("EDITOR")
            // An inherited home puts the developer's own client directory
            // under a verb that writes it — `secret set` did exactly that.
            // The scenario's own home is the floor; `isolated_env` still
            // overrides.
            .envs(platform_home(&self.root.join("home")))
            .envs(env.iter().copied())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(faults) = &self.faults {
            faults.inject(&mut command);
        }
        let mut child = command.spawn().expect("run the CLI");
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write stdin");
        }
        let output = child.wait_with_output().expect("CLI output");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// A usage exit with stdin an open pipe the test never writes
    /// to — the process must not read stdin, or it would block forever.
    pub(crate) fn cli_usage(&self, args: &[&str]) -> (i32, String) {
        let mut command = Command::new(binary());
        command
            .args(["--config", &self.config.display().to_string()])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(faults) = &self.faults {
            faults.inject(&mut command);
        }
        let mut child = command.spawn().expect("run the CLI");
        let stdin = child.stdin.take().expect("stdin");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let output = child.wait_with_output();
            drop(stdin); // the pipe stayed open for as long as the child ran
            let _ = sender.send(output);
        });
        let output = receiver
            .recv_timeout(Duration::from_secs(60))
            .expect("the CLI exited without reading stdin")
            .expect("CLI output");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    pub(crate) fn cli_json(&self, args: &[&str], stdin: Option<&str>) -> Value {
        let mut args = args.to_vec();
        args.push("--json");
        let (_, stdout, stderr) = self.cli(&args, stdin);
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("CLI JSON envelope ({e}): {stdout}{stderr}"))
    }

    /// `FSUB`, the subscription account whose quota the fake drives.
    pub(crate) fn add_fsub(&self) {
        let portable = json!({
            "access_token": self.needles.access_token,
            "refresh_token": self.needles.refresh_token,
            "expires_at": "2099-01-01T00:00:00Z",
        })
        .to_string();
        let envelope = self.cli_json(
            &["account", "add", "--portable", "--stdin", "--name", "FSUB"],
            Some(&portable),
        );
        assert_eq!(envelope["ok"], true, "adding FSUB: {envelope}");
    }

    /// A further subscription account in its own organisation, so an
    /// organisation-scoped hold can be shown not to reach it.
    pub(crate) fn add_other_org(
        &self,
        name: &str,
        email: &str,
        account_uuid: &str,
        org_uuid: &str,
    ) {
        self.upstream.script([Reply::status(
            200,
            json!({
                "account": { "email": email, "uuid": account_uuid },
                "organization": { "uuid": org_uuid, "name": "Other Org" },
            })
            .to_string(),
        )]);
        let portable = json!({
            "access_token": needle("imported access token", "oat-fixture"),
            "refresh_token": needle("imported refresh token", "ort-fixture"),
            "expires_at": "2099-01-01T00:00:00Z",
        })
        .to_string();
        let envelope = self.cli_json(
            &["account", "add", "--portable", "--stdin", "--name", name],
            Some(&portable),
        );
        assert_eq!(envelope["ok"], true, "adding {name}: {envelope}");
    }

    /// A further subscription account for the tier scenarios, with an
    /// identity of its own (would otherwise replace `FSUB` in place) in
    /// the same organisation as `FSUB`.
    pub(crate) fn add_oauth(&self, name: &str, email: &str, account_uuid: &str) {
        self.add_other_org(name, email, account_uuid, FIXTURE_ORG_UUID);
    }

    pub(crate) fn add_oauth_family(
        &self,
        name: &str,
        email: &str,
        account_uuid: &str,
        access: &str,
        refresh: &str,
        expires_at: OffsetDateTime,
    ) {
        crate::leaks::register_needle("family access token", access);
        crate::leaks::register_needle("family refresh token", refresh);
        self.upstream.script([Reply::status(
            200,
            json!({
                "account": { "email": email, "uuid": account_uuid },
                "organization": { "uuid": FIXTURE_ORG_UUID, "name": "Fixture Org" },
            })
            .to_string(),
        )]);
        let portable = json!({
            "access_token": access,
            "refresh_token": refresh,
            "expires_at": expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .expect("fixture timestamp formats"),
        })
        .to_string();
        let envelope = self.cli_json(
            &["account", "add", "--portable", "--stdin", "--name", name],
            Some(&portable),
        );
        assert_eq!(envelope["ok"], true, "adding {name}: {envelope}");
    }

    /// `FKEY`, the API-key account.
    pub(crate) fn add_fkey(&self) {
        let envelope = self.cli_json(
            &["account", "add", "--api-key", "--stdin", "--name", "FKEY"],
            Some(&self.needles.api_key),
        );
        assert_eq!(envelope["ok"], true, "adding FKEY: {envelope}");
    }

    /// Drives a pinned request that 401s, so `name` ends `errored`: the
    /// refresh-failure path several tests reuse (the no-material branch).
    pub(crate) async fn error_via_401(&self, name: &str) {
        self.upstream.script([reply_auth_401()]);
        let answer = send(self.addr, pinned(messages(haiku_prompt()), name)).await;
        assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
        self.settle();
        assert_eq!(self.account(name)["health"]["state"], "errored");
    }

    pub(crate) fn status(&self) -> Value {
        self.cli_json(&["status"], None)["result"]["status"].clone()
    }

    pub(crate) fn account(&self, display_name: &str) -> Value {
        self.status()["accounts"]
            .as_array()
            .expect("accounts array")
            .iter()
            .find(|a| a["display_name"] == display_name)
            .unwrap_or_else(|| panic!("no account named {display_name}"))
            .clone()
    }

    pub(crate) fn handle(&self, display_name: &str) -> String {
        self.account(display_name)["handle"]
            .as_str()
            .expect("handle string")
            .to_string()
    }

    /// The snapshot's route object by name.
    pub(crate) fn route_view(&self, name: &str) -> Value {
        self.status()["routes"]
            .as_array()
            .expect("routes array")
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("no route named {name}"))
            .clone()
    }

    pub(crate) fn default_account(&self) -> String {
        self.status()["default_account"]["handle"]
            .as_str()
            .expect("a default account")
            .to_string()
    }

    /// the server log lines carrying this `event`, oldest first.
    pub(crate) fn events(&self, event: &str) -> Vec<Value> {
        fs::read_to_string(self.root.join("log/server.ndjson"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|line| line["event"] == event)
            .collect()
    }

    /// the audit records this instance has written, oldest first.
    pub(crate) fn audit(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("log/exchanges.ndjson"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("audit record is JSON"))
            .collect()
    }

    /// The audit records once `count` exist: a relayed body's record lands when
    /// the body is released, which can trail the client's last byte by a tick.
    pub(crate) fn audit_settled(&self, count: usize) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let records = self.audit();
            if records.len() >= count || Instant::now() > deadline {
                assert_eq!(records.len(), count, "one record per exchange");
                return records;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The most recent audit record, once `count` exist.
    pub(crate) fn last_record(&self, count: usize) -> Value {
        self.audit_settled(count).pop().expect("a record")
    }

    /// coalesces quota writes; give the flusher its second before reading state.
    pub(crate) fn settle(&self) {
        std::thread::sleep(Duration::from_millis(1_400));
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.kill_child();
    }
}
// ------------------------------------------------------------------ the client side

/// What the caller saw: status, headers, and the body as it arrived, frame by frame.
#[derive(Debug)]
pub(crate) struct Answer {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) frames: Vec<Bytes>,
}

impl Answer {
    pub(crate) fn body(&self) -> Bytes {
        let mut out = Vec::new();
        for frame in &self.frames {
            out.extend_from_slice(frame);
        }
        Bytes::from(out)
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body()).into_owned()
    }

    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body())
            .unwrap_or_else(|e| panic!("response body is not JSON ({e}): {}", self.text()))
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// One request on a connection of its own: no pooling, so header order and frame
/// boundaries are the product's and not a client cache's. Panics on failure;
/// [`try_send`] is the variant for cases where the proxy closes the connection.
pub(crate) async fn send(addr: SocketAddr, request: Request<Full<Bytes>>) -> Answer {
    try_send(addr, request).await.expect("send the request")
}

/// Like [`send`], but reports a connection the proxy closed instead of panicking.
pub(crate) async fn try_send(
    addr: SocketAddr,
    request: Request<Full<Bytes>>,
) -> Result<Answer, String> {
    let stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| e.to_string())?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    // Bounded: a request the server never answers fails its scenario instead
    // of hanging the run. The longest awaited answer is about 50 s.
    let answer = tokio::time::timeout(Duration::from_secs(120), async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| e.to_string())?;
        let (parts, mut body) = response.into_parts();
        let mut frames = Vec::new();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        frames.push(data);
                    }
                }
                Err(_) => break,
            }
        }
        Ok::<Answer, String>(Answer {
            status: parts.status,
            headers: parts.headers,
            frames,
        })
    })
    .await
    .expect("an answer or a closed connection within 120 s");
    driver.abort();
    answer
}

/// A request whose response body the caller holds without reading — the stall
/// half of. [`StalledAnswer::drain`] reads it later on the same
/// connection; dropping the value disconnects it.
pub(crate) struct StalledAnswer {
    body: Incoming,
    status: StatusCode,
    headers: HeaderMap,
}

pub(crate) async fn open_without_reading(
    addr: SocketAddr,
    request: Request<Full<Bytes>>,
) -> StalledAnswer {
    let stream = TcpStream::connect(addr)
        .await
        .expect("connect to the proxy");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(request)
        .await
        .expect("send the request");
    let (parts, body) = response.into_parts();
    StalledAnswer {
        body,
        status: parts.status,
        headers: parts.headers,
    }
}

impl StalledAnswer {
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    /// The next body frame, or None at the clean end or on an error.
    pub(crate) async fn next_frame(&mut self) -> Option<Bytes> {
        match self.body.frame().await {
            Some(Ok(frame)) => frame.into_data().ok(),
            _ => None,
        }
    }

    /// Read the body to its end; errors end it.
    pub(crate) async fn drain(mut self) -> Answer {
        let mut frames = Vec::new();
        while let Some(frame) = self.body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        frames.push(data);
                    }
                }
                Err(_) => break,
            }
        }
        Answer {
            status: self.status,
            headers: self.headers,
            frames,
        }
    }
}

/// A request written by hand, for the cases where the caller's *declared* size is
/// the point: the proxy refuses on `content-length` alone and never reads the rest,
/// so a full-size write would race the refusal into a broken pipe.
pub(crate) async fn send_declared(addr: SocketAddr, path: &str, declared: usize) -> Answer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to the proxy");
    let head = format!(
        "POST {path} HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\n\
         content-length: {declared}\r\n\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write the head");
    let _ = stream
        .write_all(b"{\"model\":\"claude-haiku-4-5-20251001\"}")
        .await;
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw)).await;
    parse_answer(&raw)
}

pub(crate) fn parse_answer(raw: &[u8]) -> Answer {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header terminator in {:?}", String::from_utf8_lossy(raw)));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| StatusCode::from_bytes(c.as_bytes()).ok())
        .expect("a status line");
    let mut headers = HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.append(
                HeaderName::from_bytes(name.trim().as_bytes()).expect("header name"),
                HeaderValue::from_str(value.trim()).expect("header value"),
            );
        }
    }
    Answer {
        status,
        headers,
        frames: vec![Bytes::copy_from_slice(&raw[split + 4..])],
    }
}

/// A `POST /v1/messages` the way Claude Code sends one.
pub(crate) fn messages(body: Value) -> Request<Full<Bytes>> {
    post("/v1/messages", body)
}

pub(crate) fn post(path: &str, body: Value) -> Request<Full<Bytes>> {
    let bytes = Bytes::from(body.to_string());
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .body(Full::new(bytes))
        .expect("request builds")
}

pub(crate) fn with(
    mut request: Request<Full<Bytes>>,
    headers: &[(&str, &str)],
) -> Request<Full<Bytes>> {
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    request
}

/// the request as one turn of session `id`.
pub(crate) fn in_session(request: Request<Full<Bytes>>, id: &str) -> Request<Full<Bytes>> {
    with(request, &[("x-claude-code-session-id", id)])
}

/// the request pinned to `reference`.
pub(crate) fn pinned(request: Request<Full<Bytes>>, reference: &str) -> Request<Full<Bytes>> {
    with(request, &[("x-jaynshare-account", &token(true, reference))])
}

/// the request preferring `reference`.
pub(crate) fn preferred(request: Request<Full<Bytes>>, reference: &str) -> Request<Full<Bytes>> {
    with(
        request,
        &[("x-jaynshare-account", &token(false, reference))],
    )
}

pub(crate) fn prompt_for(model: &str) -> Value {
    json!({
        "model": model,
        "max_tokens": 32,
        "messages": [{ "role": "user", "content": "say hi in three words" }],
    })
}

pub(crate) fn haiku_prompt() -> Value {
    json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 32,
        "messages": [{ "role": "user", "content": "say hi in three words" }],
    })
}
// ------------------------------------------------------------------ binding, intent, one candidate

pub(crate) const FSUB2_UUID: &str = "3c1f5a7e-0000-4000-8000-0000000000a2";
pub(crate) const FSUB3_UUID: &str = "3c1f5a7e-0000-4000-8000-0000000000a3";

/// `FSUB` first, so it is the initial default, then `FSUB2`
/// in the same organisation.
pub(crate) fn add_two(instance: &Instance) {
    instance.add_fsub();
    instance.add_oauth("FSUB2", "fsub2@fixture.invalid", FSUB2_UUID);
}
/// Drives `FSUB` over the threshold with a weekly reset `seconds` ahead, so
/// its bucket is unknown — and the account eligible — again after that.
pub(crate) async fn exhaust_fsub_until(instance: &Instance, seconds: u64) {
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", &reset_in(seconds))]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], false);
}
/// Seconds between an RFC 3339 status timestamp and now.
pub(crate) fn crate_time(rfc3339: &str) -> i64 {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(rfc3339, &Rfc3339)
        .expect("parsable")
        .unix_timestamp()
}

/// The egress check URL's plain-text answer: one line, one address.
pub(crate) fn reply_egress(address: &str) -> Reply {
    Reply::Raw {
        status: 200,
        headers: vec![],
        body: format!("{address}\n"),
    }
}

// ------------------------------------------------------------------ the TLS fakes

/// The directory a fake stages its TLS fixture pair into, keyed by port so
/// parallel scenarios never share one.
fn fake_addr_dir(addr: &SocketAddr) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/acceptance/tls-fakes")
        .join(addr.port().to_string())
}

/// Copies the committed test pair into `directory`, the key 0600 (the
/// own rule, applied to the fake's copy too).
pub(crate) fn stage_tls_pair(directory: &Path) -> (PathBuf, PathBuf) {
    fs::create_dir_all(directory).expect("staging directory");
    let fixture = |name: &str| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/acceptance/fixtures/tls")
            .join(name)
    };
    let cert = directory.join("test-leaf.pem");
    let key = directory.join("test-leaf-key.pem");
    let mut chain = fs::read(fixture("test-leaf.pem")).expect("read the leaf certificate");
    chain.extend(fs::read(fixture("test-ca.pem")).expect("read the test CA"));
    fs::write(&cert, chain).expect("stage the certificate chain");
    fs::copy(fixture("test-leaf-key.pem"), &key).expect("stage the key");
    make_private(&key);
    (cert, key)
}

/// A server acceptor with the test pair, offering both HTTP versions
/// the same shape the product's own listener builds (`tls.rs`).
fn test_acceptor(cert: &Path, key: &Path) -> tokio_rustls::TlsAcceptor {
    let mut config = test_server_config(cert, key);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// A TLS front for `backend` with the test pair staged under `directory`: it
/// terminates TLS and forwards the bytes, as a TLS-terminating proxy in front
/// of a plain listener does. HTTP/1.1 only, so what crosses it is what the
/// plain listener speaks. The `https` origin; runs until the test ends.
pub(crate) async fn tls_front(backend: SocketAddr, directory: &Path) -> String {
    let (cert, key) = stage_tls_pair(directory);
    tls_front_with(backend, &cert, &key).await
}

/// [`tls_front`] with a given certificate chain and key.
pub(crate) async fn tls_front_with(backend: SocketAddr, cert: &Path, key: &Path) -> String {
    let mut config = test_server_config(cert, key);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("front bind");
    let origin = format!("https://{}", listener.local_addr().expect("front addr"));
    tokio::spawn(async move {
        while let Ok((plain, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(plain).await else {
                    return;
                };
                if let Ok(mut upstream) = tokio::net::TcpStream::connect(backend).await {
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                }
            });
        }
    });
    origin
}

fn test_server_config(cert: &Path, key: &Path) -> rustls::ServerConfig {
    use rustls_pki_types::pem::PemObject;
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key).expect("fake key parses");
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(cert)
        .expect("fake certificate")
        .collect::<Result<_, _>>()
        .expect("fake certificate parses");
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("the fake pair loads")
}

/// A client config trusting the test CA, offered `h2` when asked. The test
/// CA is the committed fixture; nothing else is trusted.
fn test_client_config(h2: bool) -> Arc<rustls::ClientConfig> {
    use rustls_pki_types::pem::PemObject;
    let ca: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance/fixtures/tls/test-ca.pem"),
    )
    .expect("test CA")
    .collect::<Result<_, _>>()
    .expect("test CA parses");
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(ca);
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    Arc::new(config)
}

/// One exchange over TLS to the proxy's own listener, as the real client is
/// over the configured base URL. `h2` negotiates HTTP/2.
pub(crate) async fn send_tls(addr: SocketAddr, request: Request<Full<Bytes>>, h2: bool) -> Answer {
    let stream = TcpStream::connect(addr)
        .await
        .expect("connect to the proxy");
    let connector = tokio_rustls::TlsConnector::from(test_client_config(h2));
    let stream = connector
        .connect("localhost".try_into().expect("a server name"), stream)
        .await
        .expect("TLS to the proxy");
    let io = TokioIo::new(stream);
    if h2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .expect("http2 handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await.expect("send over TLS");
        collect_answer(response).await
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("http1 handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await.expect("send over TLS");
        collect_answer(response).await
    }
}

/// The frames of a response read to the end; errors end the body silently
/// (the same tolerance `try_send` has for a proxy-reset body).
pub(crate) async fn collect_answer(response: Response<Incoming>) -> Answer {
    let (parts, mut body) = response.into_parts();
    let mut frames = Vec::new();
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    frames.push(data);
                }
            }
            Err(_) => break,
        }
    }
    Answer {
        status: parts.status,
        headers: parts.headers,
        frames,
    }
}

/// The CONNECT corporate proxy: records every tunnel
/// request and then relays bytes, so TLS terminates at the target, not here.
pub(crate) struct ProxyFake {
    pub(crate) addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl ProxyFake {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
        let proxy = ProxyFake {
            addr: listener.local_addr().expect("proxy addr"),
            seen: Arc::new(Mutex::new(Vec::new())),
        };
        let seen = proxy.seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let seen = seen.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    // The CONNECT head, read one byte at a time so the relay
                    // never swallows a byte of the tunneled TLS.
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let mut lines = head.lines();
                    let request_line = lines.next().unwrap_or_default().to_string();
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let target = parts.next().unwrap_or("").to_string();
                    seen.lock().expect("seen").push(Seen {
                        at: Instant::now(),
                        method,
                        path: target.clone(),
                        headers: lines
                            .map(|l| {
                                let (n, v) = l.split_once(':').unwrap_or((l, ""));
                                (n.trim().to_owned(), v.trim().to_owned())
                            })
                            .collect(),
                        body: Bytes::new(),
                    });
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .expect("the CONNECT is accepted");
                    let mut target = tokio::net::TcpStream::connect(&target)
                        .await
                        .expect("the proxy reaches its target");
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
                });
            }
        });
        proxy
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }
}

// ------------------------------------------------------------------ the CLI surface

/// A scratch root for a scenario that runs the CLI without an instance.
pub(crate) fn scratch(scenario: &str) -> PathBuf {
    claim_scenario_root(scenario)
}

/// the root, claimed once and emptied. Two scenarios sharing a name
/// would delete each other's root and `config.toml` under the parallel
/// runner — the later writer owning the path a `--config` argument names, so
/// one scenario's CLI reaches the other's server — which reads as a flake
/// wherever the two happen to interleave. The second claim fails instead.
fn claim_scenario_root(scenario: &str) -> PathBuf {
    static CLAIMED: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    let claimed = CLAIMED.get_or_init(Mutex::default);
    assert!(
        claimed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(scenario.to_owned()),
        "two scenarios claim the root `target/acceptance/{scenario}`; \
         give each one its own name"
    );
    // Joined part by part, so a Windows path has only native separators.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("acceptance")
        .join(scenario);
    let _ = fs::remove_dir_all(&root);
    private_dir(&root);
    root
}

/// Every variable the platform paths resolve from, pointed under `home`:
/// an inherited `XDG_CONFIG_HOME` or `APPDATA` would otherwise send a
/// server or a CLI run to the developer's own directories.
pub(crate) fn platform_home(home: &Path) -> Vec<(String, String)> {
    let mut env = vec![
        ("HOME".into(), home.display().to_string()),
        (
            "XDG_CONFIG_HOME".into(),
            home.join(".config").display().to_string(),
        ),
        (
            "XDG_STATE_HOME".into(),
            home.join(".local/state").display().to_string(),
        ),
    ];
    if cfg!(windows) {
        env.extend(crate::profile_fx::windows_profile(home));
    }
    env
}

/// The environment that isolates a CLI run from the developer's machine:
/// a scratch home (so the platform paths resolve under it, the Windows
/// profile included), the fake Windows `Path` editor, and no
/// `JAYNSHARE_CONFIG` unless the scenario sets one.
pub(crate) fn isolated_env(home: &Path) -> Vec<(String, String)> {
    let mut env = platform_home(home);
    if cfg!(windows) {
        env.extend(crate::profile_fx::path_editor(home).env());
    }
    env
}

/// One CLI invocation with exactly these arguments and environment (no
/// `--config` injected): exit code, standard output, standard error.
pub(crate) fn cli_raw(
    args: &[&str],
    env: &[(String, String)],
    stdin: Option<&str>,
) -> (i32, String, String) {
    let mut command = Command::new(binary());
    command
        .args(args)
        .env_remove("JAYNSHARE_CONFIG")
        .env_remove("NO_COLOR")
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("run the CLI");
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
    }
    let output = child.wait_with_output().expect("CLI output");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// One CLI invocation on a pseudo-terminal (the suite docs: hidden prompts, typed
/// confirmations and colour need one), through the platform's `script`.
/// Both streams share the terminal, so the output is one transcript; the
/// exit code is the CLI's. `answer` is typed once `prompt` has appeared in
/// the transcript, so an echo-off prompt is already in force when the
/// secret arrives.
pub(crate) fn cli_pty(
    scenario: &str,
    args: &[&str],
    env: &[(String, String)],
    answer: Option<(&str, &str)>,
) -> (i32, String) {
    cli_pty_answers(scenario, args, env, answer.as_slice())
}

/// The same, for a verb that prompts more than once: each pair is typed when
/// its own prompt appears, in order.
pub(crate) fn cli_pty_answers(
    scenario: &str,
    args: &[&str],
    env: &[(String, String)],
    answers: &[(&str, &str)],
) -> (i32, String) {
    let bin = binary().display().to_string();
    let argv = [&[bin.as_str()], args].concat();
    pty_answers(scenario, &argv, env, answers)
}

/// The same for any program: `argv[0]` runs with the rest as arguments.
pub(crate) fn pty_answers(
    scenario: &str,
    argv: &[&str],
    env: &[(String, String)],
    answers: &[(&str, &str)],
) -> (i32, String) {
    let root = scratch(scenario);
    let transcript = root.join("transcript");
    let mut command = Command::new("script");
    if cfg!(target_os = "macos") {
        command
            .args(["-q", "-F", &transcript.display().to_string()])
            .args(argv);
    } else {
        // util-linux `script -c` runs the line under a shell; `exec` leaves
        // the program alone in the terminal's foreground group, as on macOS,
        // so a Ctrl-C reaches only it.
        let mut line = String::from("exec");
        for arg in argv {
            line.push(' ');
            line.push_str(&shell_quote(arg));
        }
        command.args([
            "-q",
            "-f",
            "-e",
            "-c",
            &line,
            &transcript.display().to_string(),
        ]);
    }
    command
        .env_remove("JAYNSHARE_CONFIG")
        .env_remove("NO_COLOR")
        .env("TERM", "xterm")
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("run the CLI under `script`");
    let mut stdin = child.stdin.take().expect("script stdin");
    // Each answer waits for its own prompt, so a verb that asks twice (a
    // confirmation and then a hidden secret) is driven in order.
    for (prompt, reply) in answers {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !fs::read_to_string(&transcript)
            .unwrap_or_default()
            .contains(prompt)
        {
            if let Ok(Some(status)) = child.try_wait() {
                panic!(
                    "the CLI exited with {status} before the prompt {prompt:?}: {}",
                    fs::read_to_string(&transcript).unwrap_or_default()
                );
            }
            assert!(
                Instant::now() < deadline,
                "the prompt {prompt:?} never appeared: {}",
                fs::read_to_string(&transcript).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        stdin.write_all(reply.as_bytes()).expect("type the answer");
        stdin.flush().expect("flush the answer");
    }
    // `script` on macOS ends the session at its stdin's EOF only after the
    // command exits; keep the pipe open until then.
    let output = child.wait_with_output().expect("script output");
    drop(stdin);
    let code = output.status.code().unwrap_or(-1);
    let combined = fs::read_to_string(&transcript)
        .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).into_owned());
    // util-linux `script` writes its own "Script started/done" banner into
    // the transcript file even under `-q`; only the command's bytes count.
    let combined = combined
        .split_inclusive('\n')
        .filter(|l| !l.starts_with("Script started on ") && !l.starts_with("Script done on "))
        .collect::<String>();
    (code, combined)
}

fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The bytes of a transcript without ANSI escape sequences and carriage
/// returns: what a human read, for "the same facts" comparisons.
pub(crate) fn strip_ansi(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if c != '\r' {
            out.push(c);
        }
    }
    out
}

/// A raw HTTP/1.1 server for `--server`: each accepted
/// connection reads one request and gets `reply(request)` back verbatim,
/// with `connection: close` so the CLI never reuses it. The requests seen
/// are recorded. Runs until dropped.
pub(crate) struct FakeControl {
    pub(crate) addr: SocketAddr,
    pub(crate) requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl FakeControl {
    pub(crate) fn start(reply: impl Fn(&str) -> String + Send + 'static) -> Self {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind fake control");
        listener
            .set_nonblocking(true)
            .expect("non-blocking fake control");
        let addr = listener.local_addr().expect("fake control address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, done) = (Arc::clone(&requests), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // A BSD accept hands back a socket that inherited the
                        // listener's non-blocking flag, so the first read can
                        // return WouldBlock before the request has arrived and
                        // record an empty one. The read timeout below is the
                        // bound we actually want.
                        stream
                            .set_nonblocking(false)
                            .expect("blocking fake control stream");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("read timeout");
                        let mut raw = Vec::new();
                        let mut buffer = [0; 4096];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(n) => {
                                    raw.extend_from_slice(&buffer[..n]);
                                    if request_complete(&raw) {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let request = String::from_utf8_lossy(&raw).into_owned();
                        seen.lock().unwrap().push(request.clone());
                        let _ = stream.write_all(reply(&request).as_bytes());
                        let _ = stream.flush();
                        // The answer ends with a FIN the client can read: a
                        // close with bytes still in the receive queue is an
                        // RST instead, and the CLI reports the server as
                        // unreachable rather than reading the answer.
                        let _ = stream.shutdown(std::net::Shutdown::Write);
                        while matches!(stream.read(&mut buffer), Ok(n) if n > 0) {}
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        FakeControl {
            addr,
            requests,
            stop,
        }
    }

    /// A fake answering every request with one status and JSON body.
    pub(crate) fn answering(status: u16, body: Value) -> Self {
        Self::start(move |_| http_reply(status, "application/json", &body.to_string()))
    }

    pub(crate) fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn seen(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for FakeControl {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

fn request_complete(raw: &[u8]) -> bool {
    let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    raw.len() >= head_end + 4 + length
}

/// One raw HTTP/1.1 response.
pub(crate) fn http_reply(status: u16, content_type: &str, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        418 => "I'm a teapot",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// the envelope with one slug, for the fake to answer.
pub(crate) fn control_error(code: &str, message: &str) -> Value {
    json!({ "control_api_version": 1, "error": { "code": code, "message": message, "target": null, "details": [] } })
}

/// An owner-only file holding `contents`, for `--file` and
/// `--operator-secret-file` (c).
pub(crate) fn secret_file(root: &Path, name: &str, contents: &str) -> PathBuf {
    let path = root.join(name);
    write_private(&path, contents);
    path
}

// ------------------------------------------------------------------ JSON Schema

/// The draft 2020-12 subset the binary's schemas use: `type` (one or a
/// list), `const`, `enum`, `properties`, `required`, `additionalProperties`
/// (a boolean or a schema), `items`, `oneOf`, `$ref` into `#/$defs`,
/// `minimum` and `maximum`. `Err` names the first violation by path.
pub(crate) fn validate(schema: &Value, instance: &Value) -> Result<(), String> {
    fn check(root: &Value, schema: &Value, instance: &Value, path: &str) -> Result<(), String> {
        if let Some(reference) = schema["$ref"].as_str() {
            let name = reference
                .strip_prefix("#/$defs/")
                .unwrap_or_else(|| panic!("unsupported $ref {reference}"));
            let target = &root["$defs"][name];
            assert!(!target.is_null(), "dangling $ref {reference}");
            return check(root, target, instance, path);
        }
        if let Some(kinds) = schema.get("type") {
            let allowed: Vec<&str> = match kinds {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            let actual = match instance {
                Value::Null => "null",
                Value::Bool(_) => "boolean",
                Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };
            let ok = allowed
                .iter()
                .any(|k| *k == actual || (*k == "number" && actual == "integer"));
            if !ok {
                return Err(format!("{path}: type {actual} is not {allowed:?}"));
            }
        }
        if let Some(expected) = schema.get("const")
            && expected != instance
        {
            return Err(format!("{path}: {instance} is not the constant {expected}"));
        }
        if let Some(values) = schema["enum"].as_array()
            && !values.contains(instance)
        {
            return Err(format!("{path}: {instance} is not one of {values:?}"));
        }
        if let Some(minimum) = schema["minimum"].as_f64()
            && instance.as_f64().is_some_and(|v| v < minimum)
        {
            return Err(format!("{path}: {instance} < {minimum}"));
        }
        if let Some(maximum) = schema["maximum"].as_f64()
            && instance.as_f64().is_some_and(|v| v > maximum)
        {
            return Err(format!("{path}: {instance} > {maximum}"));
        }
        if let Some(options) = schema["oneOf"].as_array() {
            let outcomes: Vec<Result<(), String>> = options
                .iter()
                .map(|o| check(root, o, instance, path))
                .collect();
            let matching = outcomes.iter().filter(|o| o.is_ok()).count();
            if matching != 1 {
                let why: Vec<&str> = outcomes
                    .iter()
                    .filter_map(|o| o.as_ref().err().map(String::as_str))
                    .collect();
                return Err(format!(
                    "{path}: {matching} of {} oneOf branches match ({why:?})",
                    options.len()
                ));
            }
        }
        if let Some(object) = instance.as_object() {
            if let Some(required) = schema["required"].as_array() {
                for name in required.iter().filter_map(Value::as_str) {
                    if !object.contains_key(name) {
                        return Err(format!("{path}: missing required member {name}"));
                    }
                }
            }
            let properties = schema["properties"].as_object();
            for (name, value) in object {
                let child = format!("{path}/{name}");
                match properties.and_then(|p| p.get(name)) {
                    Some(sub) => check(root, sub, value, &child)?,
                    None => match schema.get("additionalProperties") {
                        Some(Value::Bool(false)) => {
                            return Err(format!("{path}: member {name} is not allowed"));
                        }
                        Some(sub @ Value::Object(_)) => check(root, sub, value, &child)?,
                        _ => {}
                    },
                }
            }
        }
        if let (Some(items), Some(array)) = (schema.get("items"), instance.as_array()) {
            for (index, value) in array.iter().enumerate() {
                check(root, items, value, &format!("{path}/{index}"))?;
            }
        }
        Ok(())
    }
    check(schema, schema, instance, "")
}

// ------------------------------------------------------------------ peers and clients

/// One control request with arbitrary headers and body (the peer
/// fixture: the scenario chooses `origin`, `sec-fetch-site`,
/// X -forwarded-for`, `forwarded` and any credential).
pub(crate) async fn control(
    addr: SocketAddr,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Answer {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", addr.to_string());
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let request = request
        .body(Full::new(Bytes::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        )))
        .expect("control request builds");
    send(addr, request).await
}

/// `POST` with a JSON body, the common mutation shape.
pub(crate) async fn control_post(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> Answer {
    control(addr, Method::POST, path, headers, Some(body)).await
}

/// the host's own non-loopback address, discovered without another
/// dependency — a UDP `connect` names the default route's source. `None` on
/// A host with no non-loopback address: the scenario skips.
pub(crate) fn non_loopback_addr() -> Option<std::net::IpAddr> {
    let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") else {
        return None;
    };
    socket.connect("8.8.8.8:80").ok()?;
    let local = socket.local_addr().ok()?;
    (!local.ip().is_loopback()).then_some(local.ip())
}

/// The destination that makes the instance see a non-loopback TCP peer: the
/// instance must be started with `Setup::wildcard`.
pub(crate) fn non_loopback_dest(instance: &Instance) -> Option<SocketAddr> {
    non_loopback_addr().map(|ip| SocketAddr::new(ip, instance.addr.port()))
}

/// one enrolled client — id, its disclosed-once secret, and the
/// generation the claim activated.
pub(crate) struct Enrolled {
    pub(crate) id: String,
    pub(crate) secret: String,
    pub(crate) generation: u64,
}

impl Enrolled {
    pub(crate) fn bearer(&self) -> String {
        format!("Bearer {}", self.secret)
    }
}

/// two enrolled clients under distinct principals and one unenrolled
/// peer (any connection without a credential). Claim runs as the one
/// anonymous operation.
pub(crate) async fn enroll_two_clients(instance: &Instance) -> (Enrolled, Enrolled) {
    let alpha = enroll(instance, "alpha", "Alpha Desk").await;
    let beta = enroll(instance, "beta", "Alpha Desk").await;
    (alpha, beta)
}

/// Issue and claim one client; the code is used once, its plaintext dropped.
pub(crate) async fn enroll(instance: &Instance, id: &str, name: &str) -> Enrolled {
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": id, "display_name": name }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "issue {id}: {issued:?}");
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("the code is disclosed once")
        .to_string();
    // Both disclosures are needles for the whole-run sweep — a
    // code or secret in any file the run wrote names the role that leaked.
    crate::leaks::register_needle("enrollment-code", &code);
    let claimed = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": id, "code": code }),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK, "claim {id}: {claimed:?}");
    let body = claimed.json();
    let secret = body["client_secret"]
        .as_str()
        .expect("the client secret")
        .to_string();
    crate::leaks::register_needle("client-secret", &secret);
    Enrolled {
        id: body["client_id"].as_str().expect("client id").to_string(),
        secret,
        generation: body["generation"].as_u64().expect("generation"),
    }
}
