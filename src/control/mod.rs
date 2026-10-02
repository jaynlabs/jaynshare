//! The control plane under `/control/v1`: the router, the envelope,
//! the snapshot and the login operations. The account operations are
//! `accounts`.

mod accounts;
mod ca;
mod client_accounts;
pub(crate) mod client_kit;
pub(crate) mod client_surface;
mod clients;
mod operator;
mod probe;
pub mod reload;
mod selection;

use std::net::SocketAddr;
use std::sync::Arc;

use http::header::{ALLOW, CONTENT_TYPE, ORIGIN};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::Principal;
use crate::data_plane::envelope::json_response;
use crate::data_plane::principal::is_loopback_peer;
use crate::data_plane::relay::ResponseBody;
use crate::login::{Refused, Started, Starter};
use crate::pool::Account;
use crate::pool::selection::{self as sel, RequestFacts};
use crate::server::{Server, VERSION};
use crate::state;
use crate::timestamp::rfc3339;
use accounts::{
    account_object, add_account, disable_account, enable_account, remove_account, rename_account,
    replace_account, resolve,
};
use selection::{clear_route_preference, set_route_preference, switch_default};

pub const API_VERSION: u64 = 1;
/// Control bodies are a handful of scalars.
const BODY_LIMIT: usize = 1024 * 1024;

pub async fn handle(
    server: &Arc<Server>,
    principal: Option<&Principal>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    if server.stopping() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "the server is shutting down because audit or state became unwritable",
            None,
            vec![],
        );
    }
    let path = request.uri().path().to_string();
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (Some(&"control"), Some(&"v1")) = (segments.first(), segments.get(1)) else {
        return not_found();
    };
    // Every endpoint declares exactly one principal class. The claim
    // is the one operation reachable without a principal; everything
    // else in this router is operator-only, and a client credential answers
    // `403 operator_required` — never `404`, never a filtered success.
    let method = request.method().clone();
    if segments[2..] == ["enrollment", "claim"] {
        if method == Method::POST {
            return clients::claim(server, peer, request).await;
        }
        return method_not_allowed("POST");
    }
    let Some(principal) = principal else {
        // Byte-identical with a data-plane refusal.
        return unauthenticated_refusal(peer);
    };
    // The client surface declares the **client** class, and an operator
    // reads it too, except a client's own accounts and logins. It is matched
    // before the operator-only gate below.
    if let ["client", "accounts", "owned" | "login" | "operations", ..] = segments[2..] {
        return client_accounts::route(server, peer, principal, &segments[4..], request).await;
    }
    if segments[2..].first() == Some(&"client") {
        return match (&segments[2..], &method) {
            (["client", "status"], &Method::GET) => {
                client_surface::status(server, principal, request.uri().query())
            }
            (["client", "accounts"], &Method::GET) => client_surface::accounts(server),
            (["client", "accounts", "resolve"], &Method::GET) => {
                client_surface::resolve(server, request.uri().query())
            }
            (["client", "kit"], &Method::GET) => client_kit::download(server).await,
            (
                ["client", "status"]
                | ["client", "accounts"]
                | ["client", "accounts", "resolve"]
                | ["client", "kit"],
                _,
            ) => method_not_allowed("GET"),
            _ => not_found(),
        };
    }
    // The CA read's declared class is **client**; an operator reads it
    // too. It is a read, so no guard and no mutation here.
    if segments[2..] == ["ca"] {
        return match method {
            Method::GET => ca::read(server),
            _ => method_not_allowed("GET"),
        };
    }
    if !principal.is_operator() {
        refusal_line(server, peer, Some(principal), "operator_required");
        return error(
            StatusCode::FORBIDDEN,
            "operator_required",
            "this operation is operator-only",
            None,
            vec![],
        );
    }
    match (&segments[2..], &method) {
        (["status"], &Method::GET) => read(json!({ "status": snapshot(server) })),
        (["accounts"], &Method::GET) => read(json!({ "accounts": snapshot(server)["accounts"] })),
        (["accounts"], &Method::POST) => add_account(server, peer, principal, request).await,
        (["accounts", "resolve"], &Method::GET) => resolve(server, request.uri().query()),
        (["accounts", "login"], &Method::POST) => {
            login_start(server, peer, principal, request).await
        }
        (["clients"], &Method::GET) => clients::list(server),
        (["clients"], &Method::POST) => clients::issue(server, peer, principal, request).await,
        (["clients", id], &Method::GET) => clients::show(server, id),
        (["clients", id, "reissue"], &Method::POST) => {
            clients::reissue(server, peer, principal, id, request).await
        }
        (["clients", id, "rotate"], &Method::POST) => {
            clients::rotate(server, peer, principal, id, request).await
        }
        (["clients", id, "revoke"], &Method::POST) => {
            clients::revoke(server, peer, principal, id, request).await
        }
        (["clients", id, "name"], &Method::POST) => {
            clients::rename(server, peer, principal, id, request).await
        }
        (["operator", "secret"], &Method::POST) => {
            operator::set(server, peer, principal, request).await
        }
        (["operator", "secret"], &Method::DELETE) => {
            operator::remove(server, peer, principal, request).await
        }
        (["accounts", handle], &Method::GET) => match handle.parse::<Uuid>() {
            Ok(handle) => match account_object(server, handle) {
                Some(account) => read(json!({ "account": account })),
                None => error(
                    StatusCode::NOT_FOUND,
                    "account_not_found",
                    "no account has this handle",
                    Some(handle.to_string()),
                    vec![],
                ),
            },
            Err(_) => error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "an account path segment is its handle, a UUID",
                Some((*handle).to_string()),
                vec![],
            ),
        },
        (
            [
                "accounts",
                handle,
                operation @ ("credential" | "name" | "enable" | "disable"),
            ],
            &Method::POST,
        ) => {
            let Ok(handle) = handle.parse::<Uuid>() else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "an account path segment is its handle, a UUID",
                    Some((*handle).to_string()),
                    vec![],
                );
            };
            match *operation {
                "credential" => replace_account(server, peer, principal, handle, request).await,
                "name" => rename_account(server, peer, principal, handle, request).await,
                "enable" => enable_account(server, peer, principal, handle, request).await,
                _ => disable_account(server, peer, principal, handle, request).await,
            }
        }
        (["accounts", handle], &Method::DELETE) => {
            let Ok(handle) = handle.parse::<Uuid>() else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "an account path segment is its handle, a UUID",
                    Some((*handle).to_string()),
                    vec![],
                );
            };
            remove_account(server, peer, principal, handle, request.headers())
        }
        (["selection", "default"], &Method::POST) => {
            switch_default(server, peer, principal, request).await
        }
        (["selection", "routes", name, "preference"], &Method::POST) => {
            set_route_preference(server, peer, principal, name, request).await
        }
        (["selection", "routes", name, "preference"], &Method::DELETE) => {
            clear_route_preference(server, peer, principal, name, request.headers())
        }
        (["configuration"], &Method::GET) => configuration_read(server),
        (["reload"], &Method::POST) => reload::handle(server, peer, principal, request).await,
        (["mitm", "ca", "rotate"], &Method::POST) => {
            ca::rotate(server, peer, principal, request).await
        }
        (["quota", "probe"], &Method::POST) => {
            probe::handle(server, peer, principal, request).await
        }
        (["operations", id], &Method::GET) => operation_show(server, principal, id),
        (["operations", id, "code"], &Method::POST) => {
            operation_code(server, peer, principal, id, request).await
        }
        (["operations", id, "cancel"], &Method::POST) => {
            operation_cancel(server, peer, principal, id, request).await
        }
        (["status"] | ["accounts", "resolve"], _) => method_not_allowed("GET"),
        (["accounts"], _) => method_not_allowed("GET, POST"),
        (["accounts", "login"], _) => method_not_allowed("POST"),
        (["accounts", _], _) => method_not_allowed("GET, DELETE"),
        (["clients"] | ["clients", _], _) => method_not_allowed("GET, POST"),
        (["clients", _, "reissue" | "rotate" | "revoke" | "name"], _) => method_not_allowed("POST"),
        (["operator", "secret"], _) => method_not_allowed("POST, DELETE"),
        (["accounts", _, "credential" | "name" | "enable" | "disable"], _) => {
            method_not_allowed("POST")
        }
        (["selection", "default"], _) => method_not_allowed("POST"),
        (["selection", "routes", _, "preference"], _) => method_not_allowed("POST, DELETE"),
        (["configuration"], _) => method_not_allowed("GET"),
        (["ca"], _) => method_not_allowed("GET"),
        (["reload"], _) => method_not_allowed("POST"),
        (["mitm", "ca", "rotate"], _) => method_not_allowed("POST"),
        (["quota", "probe"], _) => method_not_allowed("POST"),
        (["operations", _], _) => method_not_allowed("GET"),
        (["operations", _, _], _) => method_not_allowed("POST"),
        _ => not_found(),
    }
}

pub(super) fn base(status: StatusCode, mut body: Value) -> Response<ResponseBody> {
    body["control_api_version"] = json!(API_VERSION);
    json_response(status, &body)
}

/// A read carries `captured_at` and its payload under a named member.
pub(super) fn read(mut payload: Value) -> Response<ResponseBody> {
    payload["captured_at"] = json!(rfc3339(OffsetDateTime::now_utc()));
    base(StatusCode::OK, payload)
}

/// The control error envelope.
pub fn error(
    status: StatusCode,
    code: &str,
    message: &str,
    target: Option<String>,
    details: Vec<Value>,
) -> Response<ResponseBody> {
    base(
        status,
        json!({ "error": { "code": code, "message": message, "target": target, "details": details } }),
    )
}

fn not_found() -> Response<ResponseBody> {
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        "no control endpoint at this path under version 1",
        None,
        vec![],
    )
}

/// The refusal an unauthenticated caller sees: a byte-identical
/// answer an anonymous caller gets on any control path but the claim.
pub(crate) fn unauthenticated_refusal(peer: SocketAddr) -> Response<ResponseBody> {
    let response = crate::data_plane::envelope::unauthenticated();
    refusal_line_plain("authentication_error", peer);
    response
}

/// A revoked credential still reaches the client surface: the projection
/// answers with the caller's own facts (a revoked id is simply not in the
/// registry), so the launcher's reachability check reports the refusal
/// itself instead of a bare 401.
/// One log line per control refusal, with the caller's address and the
/// refusal's code. The claim logs its real cause itself.
pub(super) fn refusal_line(
    server: &Server,
    peer: SocketAddr,
    principal: Option<&Principal>,
    code: &str,
) {
    tracing::info!(
        event = "control_refusal",
        code,
        principal = principal.map_or("", |p| p.role()),
        principal_id = principal.and_then(|p| p.id.as_deref()).unwrap_or(""),
        source_address = %peer,
        "a control request was refused"
    );
    let _ = server;
}

/// The pre-principal refusal: the caller's address is all there is.
fn refusal_line_plain(code: &str, peer: SocketAddr) {
    tracing::info!(
        event = "control_refusal",
        code,
        source_address = %peer,
        "a control request was refused without a principal"
    );
}

/// One log line per mutation — role, stable id, source address,
/// target, outcome; never a secret.
pub(super) fn mutation_line(
    server: &Server,
    peer: SocketAddr,
    principal: &Principal,
    operation: &str,
    target: &str,
    outcome: &str,
) {
    tracing::info!(
        event = "control_mutation",
        operation,
        principal = principal.role(),
        principal_id = principal.id.as_deref().unwrap_or(""),
        source_address = %peer,
        target,
        outcome,
        "a control mutation completed"
    );
    let _ = server;
}

fn method_not_allowed(allow: &'static str) -> Response<ResponseBody> {
    let mut response = error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "this path does not accept the method",
        None,
        vec![],
    );
    response
        .headers_mut()
        .insert(ALLOW, http::HeaderValue::from_static(allow));
    response
}

/// `sec-fetch-site` is authoritative; without it, any `origin` is
/// refused. The refusal leaves its log line here, at the one place
/// every mutation passes through the guard.
pub(super) fn csrf_refusal(
    server: &Server,
    peer: SocketAddr,
    principal: Option<&Principal>,
    headers: &HeaderMap,
) -> Option<Response<ResponseBody>> {
    let refused = match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        Some(site) => !matches!(site, "same-origin" | "none"),
        None => headers.contains_key(ORIGIN),
    };
    if !refused {
        return None;
    }
    refusal_line(server, peer, principal, "cross_origin_control");
    Some(error(
        StatusCode::FORBIDDEN,
        "cross_origin_control",
        "cross-origin control mutations are refused",
        None,
        vec![],
    ))
}

/// The `403 insecure_channel` refusal, logged once where it is raised.
pub(super) fn insecure_channel_refusal(
    server: &Server,
    peer: SocketAddr,
    principal: Option<&Principal>,
) -> Response<ResponseBody> {
    refusal_line(server, peer, principal, "insecure_channel");
    error(
        StatusCode::FORBIDDEN,
        "insecure_channel",
        "a secret-bearing operation is refused off loopback on a plaintext listener; run the operation on the host",
        None,
        vec![],
    )
}

/// The guard, then the body. `Err` carries the refusal response.
pub(super) async fn mutation_body(
    server: &Server,
    peer: SocketAddr,
    principal: Option<&Principal>,
    request: Request<Incoming>,
) -> Result<Value, Response<ResponseBody>> {
    if let Some(refusal) = csrf_refusal(server, peer, principal, request.headers()) {
        return Err(refusal);
    }
    let is_json = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
        });
    if !is_json {
        return Err(error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "a mutation carries content-type: application/json",
            None,
            vec![],
        ));
    }
    let body = match Limited::new(request.into_body(), BODY_LIMIT)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Err(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "a control body is at most 1 MiB",
                None,
                vec![],
            ));
        }
    };
    match serde_json::from_slice(&body) {
        Ok(value @ Value::Object(_)) => Ok(value),
        _ => Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the body is not a JSON object",
            None,
            vec![],
        )),
    }
}

/// Unknown, mistyped and missing members all named at once.
pub(super) fn member_errors(object: &Value, allowed: &[(&str, &str, bool)]) -> Vec<Value> {
    let map = object.as_object().expect("object");
    let mut details: Vec<Value> = map
        .keys()
        .filter(|k| !allowed.iter().any(|(name, _, _)| name == k))
        .map(|k| json!({ "target": k, "code": "unknown_member", "message": "this member is not part of the request" }))
        .collect();
    for (name, kind, required) in allowed {
        match map.get(*name) {
            None if *required => details.push(json!({ "target": name, "code": "missing_member", "message": "this member is required" })),
            None => {}
            Some(v) => {
                let ok = match *kind {
                    "string" => v.is_string(),
                    "object" => v.is_object(),
                    "integer" => v.is_u64() || v.is_i64(),
                    "boolean" => v.is_boolean(),
                    _ => true,
                };
                if !ok {
                    details.push(json!({ "target": name, "code": "wrong_type", "message": format!("this member must be a {kind}") }));
                }
            }
        }
    }
    details
}

/// The operations that carry a pooled credential or an authorisation
/// code are refused off-loopback on a plaintext listener.
pub(super) fn insecure_channel(server: &Server, peer: SocketAddr) -> bool {
    !is_loopback_peer(peer) && !server.config().config.data_plane.tls.is_on()
}

/// Start the browser flow and answer `202` with the login operation.
async fn login_start(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let body = match mutation_body(server, peer, Some(principal), request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    if insecure_channel(server, peer) {
        return insecure_channel_refusal(server, peer, Some(principal));
    }
    let details = member_errors(&body, &[("display_name", "string", false)]);
    if !details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            details,
        );
    }
    match server
        .logins
        .start(
            Arc::clone(server),
            Starter::Operator,
            login_display_name(&body),
        )
        .await
    {
        Ok(started) => {
            mutation_line(
                server,
                peer,
                principal,
                "login_start",
                &started.id.to_string(),
                "started",
            );
            login_started(&started)
        }
        Err(message) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &message,
            None,
            vec![],
        ),
    }
}

/// A login's `display_name` member, trimmed; blank is none.
fn login_display_name(body: &Value) -> Option<String> {
    body["display_name"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// The `202` that answers a started login.
fn login_started(started: &Started) -> Response<ResponseBody> {
    base(
        StatusCode::ACCEPTED,
        json!({
            "operation_id": started.id,
            "state": "awaiting_authorization",
            "authorization_url": started.url,
            "expires_at": rfc3339(started.expires_at),
            "manual_code_required": started.manual_code_required,
        }),
    )
}

/// The operation an id names, if the caller may reach it: an operator
/// reaches every one, a client only those it started.
fn reachable_operation(
    server: &Server,
    principal: &Principal,
    id: &str,
) -> Result<Uuid, Box<Response<ResponseBody>>> {
    let Ok(id) = id.parse::<Uuid>() else {
        return Err(Box::new(error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "an operation path segment is its id, a UUID",
            Some(id.to_string()),
            vec![],
        )));
    };
    match principal.client_id() {
        Some(client) if !server.logins.started_by(id, client) => {
            Err(Box::new(operation_unknown(id)))
        }
        _ => Ok(id),
    }
}

/// The read of one login operation; the read is not secret-bearing.
fn operation_show(server: &Arc<Server>, principal: &Principal, id: &str) -> Response<ResponseBody> {
    let id = match reachable_operation(server, principal, id) {
        Ok(id) => id,
        Err(refusal) => return *refusal,
    };
    let operation = match principal.client_id() {
        Some(client) => server.logins.show(id, |handle| {
            client_accounts::owned_account(server, client, handle)
        }),
        None => server
            .logins
            .show(id, |handle| account_object(server, handle)),
    };
    match operation {
        Some(operation) => read(json!({ "operation": operation })),
        None => operation_unknown(id),
    }
}

/// The pasted code, a secret-bearing submission.
async fn operation_code(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    id: &str,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let body = match mutation_body(server, peer, Some(principal), request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    if insecure_channel(server, peer) {
        return insecure_channel_refusal(server, peer, Some(principal));
    }
    let details = member_errors(&body, &[("code", "string", true)]);
    if !details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            details,
        );
    }
    let id = match reachable_operation(server, principal, id) {
        Ok(id) => id,
        Err(refusal) => return *refusal,
    };
    match server
        .logins
        .submit(id, body["code"].as_str().unwrap_or_default().to_string())
    {
        Ok(()) => {
            tracing::info!(event = "login_code_submitted", operation = %id, "a login code was submitted");
            mutation_line(
                server,
                peer,
                principal,
                "login_code",
                &id.to_string(),
                "submitted",
            );
            base(StatusCode::ACCEPTED, json!({ "submitted": true }))
        }
        Err(Refused::Unknown) => operation_unknown(id),
        Err(Refused::Conflict) => error(
            StatusCode::CONFLICT,
            "conflict",
            "the operation's state does not admit a code submission",
            Some(id.to_string()),
            vec![],
        ),
    }
}

/// Cancel; the cancel is not secret-bearing but is still a mutation.
async fn operation_cancel(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    id: &str,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    if let Some(refusal) = mutation_body(server, peer, Some(principal), request)
        .await
        .err()
    {
        return refusal;
    }
    let id = match reachable_operation(server, principal, id) {
        Ok(id) => id,
        Err(refusal) => return *refusal,
    };
    match server.logins.cancel(id) {
        Ok(()) => {
            tracing::info!(event = "login_cancelled", operation = %id, "a login operation was cancelled");
            mutation_line(
                server,
                peer,
                principal,
                "login_cancel",
                &id.to_string(),
                "cancelled",
            );
            base(StatusCode::OK, json!({ "cancelled": true }))
        }
        Err(Refused::Unknown) => operation_unknown(id),
        Err(Refused::Conflict) => error(
            StatusCode::CONFLICT,
            "conflict",
            "the operation's state does not admit a cancellation",
            Some(id.to_string()),
            vec![],
        ),
    }
}

fn operation_unknown(id: Uuid) -> Response<ResponseBody> {
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        "no login operation has this id",
        Some(id.to_string()),
        vec![],
    )
}

/// A failed state write is a shutdown, reported as `503`.
pub(super) fn persist_failed(server: &Server, e: std::io::Error) -> Response<ResponseBody> {
    tracing::error!(event = "state_write_failed", error = %e, "state write failed; stopping");
    server.request_stop(crate::server::Stop::Unwritable);
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "the state file could not be written; the server is shutting down",
        None,
        vec![],
    )
}

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) fn time_or_null(t: Option<OffsetDateTime>) -> Value {
    t.map_or(Value::Null, |t| json!(rfc3339(t)))
}

/// The CA's fingerprint, expiry and state. With the mode
/// off every member is `null`; with it on and the material unusable
/// the state says so and the rest stays unknown.
fn mitm_ca_object(server: &Server, enabled: bool) -> Value {
    if !enabled {
        return json!({ "fingerprint": null, "not_after": null, "state": null });
    }
    match server.mitm_ca() {
        Some(ca) => json!({
            "fingerprint": ca.fingerprint(),
            "not_after": rfc3339(ca.not_after()),
            "state": ca.expiry_state(OffsetDateTime::now_utc()),
        }),
        None => json!({ "fingerprint": null, "not_after": null, "state": "unusable" }),
    }
}

/// The configuration in force — path, digest, load time, the
/// effective view of every key by its configuration name (secret-bearing keys as
/// presence), readability of the private key, and the last
/// reload's result.
fn configuration_object(
    server: &Server,
    loaded: &crate::config::LoadedConfig,
    last_reload: Value,
) -> Value {
    let config = &loaded.config;
    json!({
        "path": loaded.path.display().to_string(),
        "digest": loaded.digest,
        "loaded_at": rfc3339(*server.configuration.loaded_at.read().expect("configuration lock")),
        "effective": crate::config::effective_view(config),
        "secrets": {
            "data_plane.tls_private_key_file": config.data_plane.tls.files().map(|t| json!({ "set": true, "readable": t.private_key_file.is_file() })).unwrap_or(json!({ "set": false, "readable": null })),
            "data_plane.corporate_proxy_url": { "set": config.data_plane.corporate_proxy_url.is_some(), "readable": null },
        },
        "last_reload": last_reload,
    })
}

/// `GET /control/v1/configuration`, the configuration object alone.
fn configuration_read(server: &Server) -> Response<ResponseBody> {
    let loaded = server.config();
    let last_reload = reload::last_reload(server);
    read(json!({ "configuration": configuration_object(server, &loaded, last_reload) }))
}

/// One assembly under one lock; `null` for every section this build does not have.
fn snapshot(server: &Server) -> Value {
    let now = OffsetDateTime::now_utc();
    let loaded = server.config();
    let config = &loaded.config;
    // Before the pool lock: a reload holds its own lock and then the pool's.
    let last_reload = reload::last_reload(server);
    let probe = server.probes.snapshot();
    let egress = server.egress.view(&config.data_plane.egress);
    // The open-tunnel gauges and the counters since start.
    let mitm = server.mitm.snapshot();
    let mut pool = server.pool.lock().expect("pool lock");
    if pool.expire_quota(now) {
        server.mark_quota_dirty();
    }
    let session_counts = pool.sessions(now).counts(now);
    let active_per_account = pool.sessions(now).active_per_account(now);
    let runtime = accounts::Runtime {
        config,
        probe: &probe,
        active_per_account: &active_per_account,
        refreshes: &server.refreshes,
        now,
    };
    let accounts: Vec<Value> = pool
        .accounts()
        .iter()
        .map(|a| accounts::project_pool_account(&pool, a, &runtime))
        .collect();
    // The default and who set it.
    let operator = pool.operator();
    let default_account = operator.default.map(|h| {
        json!({ "handle": h, "operator_chosen": operator.chosen, "since": time_or_null(operator.since) })
    });
    let routes: Vec<Value> = config
        .selection
        .routes
        .iter()
        .map(|r| {
            let first = r.patterns.first().map(String::as_str);
            let facts = RequestFacts {
                model: first,
                ..RequestFacts::default()
            };
            // Computed read-only; `predict` moves nothing.
            let predicted = pool
                .predict(&facts, &config.selection, now)
                .ok()
                .map(|c| c.handle);
            let listed: Vec<&Account> = pool
                .accounts()
                .iter()
                .filter(|a| {
                    r.accounts
                        .as_ref()
                        .is_none_or(|names| names.iter().any(|n| crate::pool::references(a, n)))
                })
                .collect();
            json!({
                "name": r.name,
                "patterns": r.patterns,
                "bucket": r.bucket,
                "preference": pool.route_preferences().get(&r.name),
                "accounts": listed.iter().map(|a| json!({
                    "handle": a.handle,
                    "display_name": a.display_name,
                    // Eligible for a model matching the route's first pattern.
                    "eligible": sel::eligibility_for_route(a, r, &config.selection, pool.families(), now, pool.organisation_hold(a, now)).is_ok(),
                })).collect::<Vec<_>>(),
                "predicted_target": predicted,
            })
        })
        .collect();
    let audit = server.audit.health();
    json!({
        "server": {
            "version": VERSION,
            "build": { "commit": crate::server::COMMIT, "target": crate::server::TARGET },
            "started_at": rfc3339(server.started_at),
            "listen": config.data_plane.listen.to_string(),
            "tls": config.data_plane.tls.is_on(),
            "tls_pin": server.client_pin(),
            "signing_key": crate::deploy::release::active_key().ok().map(|key| key.encoded()),
            "control_api_versions": [API_VERSION],
            "telemetry_policy": config.data_plane.telemetry_policy,
            "upstream_origin_override": server.upstream.override_active().then(|| server.upstream.origin().to_string()),
            "egress": {
                "mode": config.data_plane.egress.mode,
                "pinned_addresses": egress.pinned_addresses,
                "observed_address": egress.observed_address.map(|a| a.to_string()),
                "observed_at": time_or_null(egress.observed_at),
                "held_now": egress.held_now,
            },
        },
        "capture": {
            "enabled": server.capture.is_some(),
            "directory": server.capture.as_ref().map(|c| c.directory().display().to_string()),
        },
        "mitm": {
            "enabled": config.mitm.enabled,
            "listen": config.mitm.listen.to_string(),
            "ca": mitm_ca_object(server, config.mitm.enabled),
            "tunnels": mitm.tunnels,
            "counters": mitm.counters,
        },
        "accounts": accounts,
        "default_account": default_account,
        "routes": routes,
        "blocked_models": config.selection.blocked_models,
        "sessions": { "known": session_counts.known, "active": session_counts.active, "distribution_enabled": config.selection.distribute_sessions },
        "usage_probe": {
            "enabled": config.quota.probe_enabled,
            "interval_seconds": config.quota.probe_interval_seconds,
            "last_started": time_or_null(probe.last_started),
            "last_finished": time_or_null(probe.last_finished),
            "next_run": time_or_null(probe.next_run),
            "pending_reason": null,
        },
        "configuration": configuration_object(server, &loaded, last_reload),
        "storage": {
            "state": { "path": server.state_path.display().to_string(), "last_write": time_or_null(state::last_write(&server.state_path)) },
            "audit": { "path": audit.path, "last_record": time_or_null(audit.last_record), "active_file_bytes": audit.active_file_bytes, "retained_files": audit.retained_files },
            "log": { "path": config.logging.directory.join(crate::logging::SERVER_LOG).display().to_string(), "level": config.logging.level },
            "unwritable": server.stopping(),
        },
        "clients": server.registry().clients.iter().map(clients::entry_object).collect::<Vec<_>>(),
    })
}
