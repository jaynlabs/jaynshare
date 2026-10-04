//! The browser login: the server's flows, and the loopback callback a
//! client catches for a flow it started.
//!
//! One started flow is one atomic account operation: the pool moves
//! only when the exchange and the profile lookup have both succeeded, and the
//! state value, PKCE verifier and any pasted code are never logged, persisted
//! or returned in an operation object.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::LOCATION;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::control::percent_decode;
use crate::pool::{Account, Credential, OperationError, Source};
use crate::provider::Provider;
use crate::provider::anthropic::{AUTHORIZE_URL, OAUTH_CLIENT_ID, OAUTH_SCOPES, OAUTH_SUCCESS_URL};
use crate::server::{MutateError, Server};
use crate::timestamp::rfc3339;

/// How long a started login waits for its authorisation. The CLI's poll
/// is capped at `expires_at`; no external rule fixes the duration, so the
/// value is the server's to set.
const TTL: Duration = Duration::minutes(15);

/// An ended operation's record is kept for one hour, then forgotten.
const RETENTION: Duration = Duration::hours(1);

/// The operation states; a timed-out flow ends `failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpState {
    Awaiting,
    Exchanging,
    Succeeded,
    Failed,
    Cancelled,
}

impl OpState {
    fn as_str(self) -> &'static str {
        match self {
            OpState::Awaiting => "awaiting_authorization",
            OpState::Exchanging => "exchanging",
            OpState::Succeeded => "succeeded",
            OpState::Failed => "failed",
            OpState::Cancelled => "cancelled",
        }
    }
}

/// What one flow receives. The value is parsed with [`parse_paste`] before
/// anything in it is trusted.
#[derive(Debug)]
enum Event {
    /// A paste from the operator (`…/code`): a bare code, a full callback URL
    /// or a query string — all three are the one path.
    Code(String),
    Cancel,
}

/// How a paste maps onto the flow.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Paste {
    Code(String),
    /// A safe reason: the authorisation was refused, or the state mismatches.
    Refused(String),
    /// Neither a callback nor a bare code; the flow keeps waiting.
    Other,
}

fn parse_paste(text: &str, expected_state: &str) -> Paste {
    let text = text.trim();
    if text.is_empty() {
        return Paste::Other;
    }
    // A pasted full callback URL is reduced to its query; a bare code has none.
    let query = match text.split_once('?') {
        Some((_, q)) if text.contains("://") || q.contains('=') => q,
        _ if text.contains('=') => text,
        _ => return Paste::Code(text.to_string()),
    };
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let decoded = percent_decode(value);
        match percent_decode(key).as_str() {
            "code" => code = Some(decoded),
            "state" => state = Some(decoded),
            "error" => {
                return Paste::Refused(format!(
                    "the authorisation request was refused ({decoded})"
                ));
            }
            _ => {}
        }
    }
    let Some(code) = code else {
        return Paste::Refused("the callback carries no authorisation code".into());
    };
    if state.is_some_and(|s| s != expected_state) {
        return Paste::Refused(
            "the callback's state value does not match this login; the pool is unchanged".into(),
        );
    }
    Paste::Code(code)
}

/// The PKCE challenge: S256 over the verifier's ASCII bytes, base64url without
/// padding.
fn challenge_of(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The per-flow values that outlive nothing: they are owned by the driver task
/// alone and dropped when it ends.
struct LoginSecret {
    state: String,
    verifier: String,
    redirect_uri: String,
    display_name: Option<String>,
    owner: Option<String>,
}

impl LoginSecret {
    fn generate(display_name: Option<String>, redirect_uri: String) -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("system randomness");
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("system randomness");
        Self {
            state: URL_SAFE_NO_PAD.encode(bytes),
            verifier,
            redirect_uri,
            display_name,
            owner: None,
        }
    }
}

/// The authorisation URL with every required parameter.
fn authorization_url(challenge: &str, redirect_uri: &str, state: &str) -> String {
    format!(
        "{AUTHORIZE_URL}?code=true&client_id={}&response_type=code&redirect_uri={}&scope={}&code_challenge={challenge}&code_challenge_method=S256&state={state}",
        url_encode(OAUTH_CLIENT_ID),
        url_encode(redirect_uri),
        url_encode(OAUTH_SCOPES),
    )
}

/// RFC 3986 unreserved characters stay; everything else is percent-encoded.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The `state` parameter of an authorisation URL.
pub(crate) fn state_of(url: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("state="))
        .map(percent_decode)
}

/// Attempt to open the authorisation URL; when no browser answers the
/// attempt, the flow reports itself as manual (`manual_code_required`).
pub(crate) fn open_browser(url: &str) -> bool {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "linux") {
        // A session without an X or Wayland display (an ssh shell on the
        // host) has nowhere for xdg-open to put a browser; it exits 0 all the
        // same, which would skip the paste prompt. Headless is manual.
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return false;
        }
        "xdg-open"
    } else {
        return false;
    };
    let Ok(mut child) = std::process::Command::new(program)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    // A short synchronous wait reads the opener's exit; one still
    // starting after 2 s counts as opened.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if std::time::Instant::now() >= deadline => return true,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(_) => return false,
        }
    }
}

/// Who starts a login, and so where its callback lands.
pub enum Starter {
    /// The server catches the callback and opens the browser itself.
    Operator,
    /// The client catches the callback on its loopback port and forwards it;
    /// the account is the client's.
    Client { id: String, port: u16 },
}

/// What a started flow looks like in the response.
pub struct Started {
    pub id: Uuid,
    pub url: String,
    pub manual_code_required: bool,
    pub expires_at: OffsetDateTime,
}

/// Why an operation call was refused: the state does not admit it (`409`) or
/// the operation does not exist (`404`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Unknown,
    Conflict,
}

#[derive(Clone)]
struct Inner {
    state: OpState,
    ended_at: Option<OffsetDateTime>,
    account: Option<Uuid>,
    reason: Option<String>,
    events: tokio::sync::mpsc::UnboundedSender<Event>,
}

#[derive(Clone)]
struct Operation {
    expires_at: OffsetDateTime,
    owner: Option<String>,
    inner: std::sync::Arc<Mutex<Inner>>,
}

/// The started flows, held by [`crate::server::Server`]. Ended records stay for
/// [`RETENTION`] and are then forgotten.
#[derive(Default)]
pub struct Logins(Mutex<HashMap<Uuid, Operation>>);

impl Logins {
    /// Start a flow — fresh state and PKCE, and for the operator a
    /// loopback callback listener and one browser-open attempt — and hand the
    /// URL back.
    pub async fn start(
        &self,
        server: std::sync::Arc<Server>,
        starter: Starter,
        display_name: Option<String>,
    ) -> Result<Started, String> {
        self.sweep();
        let (listener, port, owner) = match starter {
            Starter::Operator => {
                let (listener, port) = callback_listener().await?;
                (Some(listener), port, None)
            }
            Starter::Client { id, port } => (None, port, Some(id)),
        };
        let redirect_uri = format!("http://localhost:{port}/callback");
        let secret = LoginSecret {
            owner: owner.clone(),
            ..LoginSecret::generate(display_name, redirect_uri)
        };
        let url = authorization_url(
            &challenge_of(&secret.verifier),
            &secret.redirect_uri,
            &secret.state,
        );
        // A client opens the browser on its own machine.
        let manual_code_required = listener.is_some() && !open_browser(&url);
        let expires_at = OffsetDateTime::now_utc() + TTL;
        let (events, rx) = tokio::sync::mpsc::unbounded_channel();
        let id = Uuid::new_v4();
        self.0.lock().expect("login registry").insert(
            id,
            Operation {
                expires_at,
                owner: owner.clone(),
                inner: std::sync::Arc::new(Mutex::new(Inner {
                    state: OpState::Awaiting,
                    ended_at: None,
                    account: None,
                    reason: None,
                    events: events.clone(),
                })),
            },
        );
        tracing::info!(event = "login_started", operation = %id, manual_code_required, owner = owner.as_deref().unwrap_or(""), "a browser login was started");
        tokio::spawn(drive(server, id, secret, listener, rx, expires_at));
        Ok(Started {
            id,
            url,
            manual_code_required,
            expires_at,
        })
    }

    /// The operation object — state, expiry, and on success the new
    /// account as `project` shows it; on failure the safe reason and retry
    /// action.
    pub fn show(&self, id: Uuid, project: impl FnOnce(Uuid) -> Option<Value>) -> Option<Value> {
        let operation = self.0.lock().expect("login registry").get(&id)?.clone();
        let (state, account, error) = {
            let inner = operation.inner.lock().expect("operation lock");
            let error = (inner.state == OpState::Failed).then(|| {
                json!({
                    "code": "login_failed",
                    "message": inner.reason.clone().unwrap_or_default(),
                    "target": id.to_string(),
                    "details": [{ "code": "retry", "message": "start a new login" }],
                })
            });
            (inner.state, inner.account, error)
        };
        Some(json!({
            "operation_id": id,
            "state": state.as_str(),
            "expires_at": rfc3339(operation.expires_at),
            "account": account.and_then(project).unwrap_or(Value::Null),
            "error": error.unwrap_or(Value::Null),
        }))
    }

    /// Whether the client started this operation.
    pub fn started_by(&self, id: Uuid, client: &str) -> bool {
        self.0
            .lock()
            .expect("login registry")
            .get(&id)
            .is_some_and(|operation| operation.owner.as_deref() == Some(client))
    }

    /// Submit a pasted code; only an awaiting flow admits it.
    pub fn submit(&self, id: Uuid, paste: String) -> Result<(), Refused> {
        let registry = self.0.lock().expect("login registry");
        let operation = registry.get(&id).ok_or(Refused::Unknown)?;
        let inner = operation.inner.lock().expect("operation lock");
        if inner.state != OpState::Awaiting {
            return Err(Refused::Conflict);
        }
        inner
            .events
            .send(Event::Code(paste))
            .map_err(|_| Refused::Conflict)
    }

    /// Cancel an awaiting flow; anything else is `409`.
    pub fn cancel(&self, id: Uuid) -> Result<(), Refused> {
        let registry = self.0.lock().expect("login registry");
        let operation = registry.get(&id).ok_or(Refused::Unknown)?;
        let inner = operation.inner.lock().expect("operation lock");
        if inner.state != OpState::Awaiting {
            return Err(Refused::Conflict);
        }
        inner
            .events
            .send(Event::Cancel)
            .map_err(|_| Refused::Conflict)
    }

    fn set_state(&self, id: Uuid, state: OpState) {
        if let Some(operation) = self.0.lock().expect("login registry").get(&id) {
            operation.inner.lock().expect("operation lock").state = state;
        }
    }

    fn finish(&self, id: Uuid, state: OpState, reason: Option<String>, account: Option<Uuid>) {
        if let Some(operation) = self.0.lock().expect("login registry").get(&id) {
            let mut inner = operation.inner.lock().expect("operation lock");
            inner.state = state;
            inner.ended_at = Some(OffsetDateTime::now_utc());
            inner.account = account;
            inner.reason = reason;
        }
    }

    /// Ended records older than the retention window are forgotten.
    fn sweep(&self) {
        let horizon = OffsetDateTime::now_utc() - RETENTION;
        self.0
            .lock()
            .expect("login registry")
            .retain(|_, operation| {
                operation
                    .inner
                    .lock()
                    .expect("operation lock")
                    .ended_at
                    .is_none_or(|t| t > horizon)
            });
    }
}

/// The driver: one answered callback or submitted code decides the flow, then
/// the exchange and the profile run it to an end. The listener dies with the
/// task, so no flow outlives its answer (the listener closes on success,
/// refusal and cancellation).
async fn drive(
    server: std::sync::Arc<Server>,
    id: Uuid,
    secret: LoginSecret,
    listener: Option<TcpListener>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Event>,
    expires_at: OffsetDateTime,
) {
    let wait = (expires_at - OffsetDateTime::now_utc())
        .try_into()
        .unwrap_or_default();
    let monotonic = tokio::time::Instant::now() + wait;
    let end = loop {
        // `expires_at` is a wall-clock fact (it is in the response),
        // so the expiry is judged on the wall clock: capped each round by the
        // time the wall clock still grants, a moved wall clock ends a flow at
        // its printed expiry (the test harness moves the wall clock).
        let wall_remaining = (expires_at - OffsetDateTime::now_utc())
            .try_into()
            .unwrap_or_default();
        let deadline = monotonic.min(tokio::time::Instant::now() + wall_remaining);
        tokio::select! {
            event = rx.recv() => match event {
                Some(Event::Cancel) => break End::Cancelled,
                Some(Event::Code(paste)) => {
                    break match parse_paste(&paste, &secret.state) {
                        Paste::Code(code) => complete(&server, id, &secret, code).await,
                        Paste::Refused(reason) => End::Failed { reason },
                        Paste::Other => continue,
                    };
                }
                None => break End::Failed { reason: "the login operation lost its channels".into() },
            },
            accepted = accept(listener.as_ref()) => match accepted {
                Ok((stream, _)) => match answer_callback(stream, &secret.state).await {
                    Ok(Some(query)) => {
                        break match parse_paste(&query, &secret.state) {
                            Paste::Code(code) => complete(&server, id, &secret, code).await,
                            Paste::Refused(reason) => End::Failed { reason },
                            Paste::Other => continue,
                        };
                    }
                    Ok(None) => {}
                    Err(e) => {
                        // A broken browser connection is not the flow's end; keep waiting.
                        tracing::debug!(event = "callback_error", error = %e, "the callback connection failed");
                    }
                },
                Err(e) => break End::Failed { reason: format!("the callback listener failed: {e}") },
            },
            _ = tokio::time::sleep_until(deadline) => {
                break End::Failed { reason: "the login expired before it was completed".into() };
            }
        }
    };
    drop(listener);
    let (state, reason, account) = match end {
        End::Cancelled => (OpState::Cancelled, None, None),
        End::Failed { reason } => (OpState::Failed, Some(reason), None),
        End::Succeeded { account } => (OpState::Succeeded, None, Some(account)),
    };
    // The reason is a safe classification: no code, token or body.
    match (&state, &account, &reason) {
        (OpState::Succeeded, Some(handle), _) => {
            tracing::info!(event = "login_succeeded", operation = %id, account = %handle, "a browser login added or updated an account");
        }
        (OpState::Cancelled, ..) => {
            tracing::info!(event = "login_ended", operation = %id, state = "cancelled", "a browser login was cancelled");
        }
        (_, _, Some(why)) => {
            tracing::warn!(event = "login_ended", operation = %id, state = "failed", reason = %why, "a browser login failed");
        }
        _ => {}
    }
    server.logins.finish(id, state, reason, account);
}

enum End {
    Cancelled,
    Failed { reason: String },
    Succeeded { account: Uuid },
}

async fn callback_listener() -> Result<(TcpListener, u16), String> {
    let listener = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .map_err(|e| format!("cannot open the loopback callback listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("cannot read the callback listener's port: {e}"))?
        .port();
    Ok((listener, port))
}

/// The server-side callback's next connection; a client's flow has none.
async fn accept(
    listener: Option<&TcpListener>,
) -> std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

/// Exchanging, then the token family, then the profile, then the pool move, in
/// that order; every failure is a safe reason and the pool stays as it was.
async fn complete(
    server: &std::sync::Arc<Server>,
    id: Uuid,
    secret: &LoginSecret,
    code: String,
) -> End {
    server.logins.set_state(id, OpState::Exchanging);
    let tokens = match server
        .upstream
        .exchange_code(&code, &secret.state, &secret.verifier, &secret.redirect_uri)
        .await
    {
        Ok(tokens) => tokens,
        Err(reason) => return End::Failed { reason },
    };
    // The profile comes first; without an account UUID nothing is saved.
    let profile = match server
        .upstream
        .fetch_profile(tokens.access_token.expose())
        .await
    {
        Ok(profile) if profile.account_uuid.is_some() => profile,
        Ok(_) => {
            return End::Failed {
                reason: "the profile carries no account UUID; the account was not saved".into(),
            };
        }
        Err(reason) => {
            return End::Failed {
                reason: format!("profile lookup failed: {reason}"),
            };
        }
    };
    let name = secret.display_name.clone();
    let account = Account {
        owner: secret.owner.clone(),
        ..Account::new(
            Provider::Anthropic,
            // `pool.add` derives the name from the profile when none is given.
            name.clone().unwrap_or_default(),
            profile,
            Source::Browser,
            Credential::OAuth(tokens),
        )
    };
    let adds = secret
        .owner
        .as_deref()
        .is_none_or(|client| server.registry().adds_accounts(client));
    match server.mutate_pool(|pool| {
        if adds {
            pool.add(account, name)
        } else {
            pool.relogin(account, name)
        }
    }) {
        Ok(handle) => End::Succeeded { account: handle },
        Err(MutateError::Refused(OperationError::NameConflict(name))) => End::Failed {
            reason: format!("an account already has the display name {name:?}"),
        },
        // A login into an identity the pool already holds under another
        // name is a conflict, not a rename.
        Err(MutateError::Refused(OperationError::NameMismatch { existing })) => End::Failed {
            reason: format!(
                "this identity is already the account {existing:?}; rename it with the name operation"
            ),
        },
        Err(MutateError::Refused(OperationError::NotOwner)) => End::Failed {
            reason: "this identity is another owner's account; the pool is unchanged".into(),
        },
        Err(MutateError::Refused(OperationError::NewAccount)) => End::Failed {
            reason: "this client's invite adds no new account, and this identity is none of its own; the pool is unchanged".into(),
        },
        Err(MutateError::Refused(_)) => End::Failed {
            reason: "the account could not be added".into(),
        },
        Err(MutateError::Persist(e)) => {
            tracing::error!(event = "state_write_failed", error = %e, "state write failed; stopping");
            server.request_stop(crate::server::Stop::Unwritable);
            End::Failed {
                reason: "the state file could not be written; the server is shutting down".into(),
            }
        }
    }
}

/// Serve the client's loopback callback until one request carries a code or
/// a refusal; that request's query.
pub(crate) async fn await_callback(
    listener: &TcpListener,
    expected_state: &str,
) -> Result<String, String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("the callback listener failed: {e}"))?;
        // A broken browser connection or a stray request keeps the wait going.
        if let Ok(Some(query)) = answer_callback(stream, expected_state).await
            && parse_paste(&query, expected_state) != Paste::Other
        {
            return Ok(query);
        }
    }
}

/// The captured callback: one request is served, the browser is sent
/// to the success page when the parameters look complete, and the query is
/// handed back to the driver. `Ok(None)` — nothing callback-shaped arrived.
async fn answer_callback(
    stream: tokio::net::TcpStream,
    expected_state: &str,
) -> Result<Option<String>, String> {
    let (query_tx, query_rx) = tokio::sync::oneshot::channel::<String>();
    let expected = expected_state.to_string();
    // service_fn needs Fn; the sender is handed over exactly once.
    let pending = std::sync::Mutex::new(Some(query_tx));
    let service = service_fn(move |request: Request<Incoming>| {
        let expected = expected.clone();
        let query = request.uri().query().unwrap_or("").to_string();
        if let Some(tx) = pending.lock().expect("query cell").take() {
            let _ = tx.send(query.clone());
        }
        async move {
            let paste = parse_paste(&query, &expected);
            let status = match paste {
                Paste::Code(_) => StatusCode::FOUND,
                _ => StatusCode::BAD_REQUEST,
            };
            let mut builder = Response::builder().status(status);
            if status == StatusCode::FOUND {
                builder = builder.header(LOCATION, OAUTH_SUCCESS_URL);
            }
            Ok::<_, std::convert::Infallible>(
                builder
                    .body(Full::new(Bytes::new()))
                    .expect("a static response builds"),
            )
        }
    });
    // A browser would otherwise hold the connection, and with it the query, for minutes.
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), service)
        .await
        .map_err(|e| e.to_string())?;
    Ok(query_rx.await.ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pkce_challenge_matches_the_rfc_7636_reference_vector() {
        // Appendix B of RFC 7636: a pre-generated verifier and its S256 challenge.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge_of(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn every_flow_has_fresh_url_safe_values() {
        let a = LoginSecret::generate(None, "http://localhost:1/callback".into());
        let b = LoginSecret::generate(None, "http://localhost:2/callback".into());
        // 32 random bytes → 43 base64url characters, no padding.
        assert_eq!(a.verifier.len(), 43);
        assert_eq!(a.state.len(), 43);
        assert!(!a.verifier.contains(['+', '/', '=']));
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.state, b.state);
        assert_ne!(challenge_of(&a.verifier), challenge_of(&b.verifier));
    }

    #[test]
    fn the_authorisation_url_carries_every_required_parameter() {
        let url = authorization_url(
            "the-challenge",
            "http://localhost:5173/callback",
            "the-state",
        );
        assert!(url.starts_with("https://claude.ai/oauth/authorize?"));
        let query = url.split_once('?').expect("query").1;
        let params: HashMap<String, String> = query
            .split('&')
            .map(|p| p.split_once('=').expect("every parameter has a value"))
            .map(|(k, v)| (k.to_string(), percent_decode(v)))
            .collect();
        assert_eq!(params["code"], "true");
        assert_eq!(params["client_id"], OAUTH_CLIENT_ID);
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["redirect_uri"], "http://localhost:5173/callback");
        assert_eq!(params["scope"], OAUTH_SCOPES);
        assert_eq!(params["code_challenge"], "the-challenge");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["state"], "the-state");
    }

    #[test]
    fn the_state_comes_back_out_of_the_authorisation_url() {
        let url = authorization_url("c", "http://localhost:1/callback", "a-b_c");
        assert_eq!(state_of(&url).as_deref(), Some("a-b_c"));
        assert_eq!(state_of("https://claude.ai/oauth/authorize"), None);
    }

    #[test]
    fn a_paste_is_a_bare_code_a_full_callback_or_a_refusal() {
        assert_eq!(
            parse_paste(" oabc-123 ", "s"),
            Paste::Code("oabc-123".into())
        );
        assert_eq!(
            parse_paste("http://localhost:9/callback?code=oabc&state=s", "s"),
            Paste::Code("oabc".into())
        );
        assert_eq!(
            parse_paste("code=oabc&state=wrong", "s"),
            Paste::Refused(
                "the callback's state value does not match this login; the pool is unchanged"
                    .into()
            )
        );
        assert!(matches!(
            parse_paste("http://localhost:9/callback?error=access_denied&error_description=no", "s"),
            Paste::Refused(reason) if reason == "the authorisation request was refused (access_denied)"
        ));
        assert_eq!(
            parse_paste("no-equals-sign", "s"),
            Paste::Code("no-equals-sign".into())
        );
        assert_eq!(parse_paste("", "s"), Paste::Other);
    }
}
