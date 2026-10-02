//! The client registry endpoints:
//! issue, reissue, rotate, revoke, rename, the registry reads, and the one
//! claim operation that needs no principal. The remote-operator secret is
//! `operator`.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::audit::Principal;
use crate::data_plane::relay::ResponseBody;
use crate::registry::{RegistryEntry, ReissueError};
use crate::server::{MutateError, Server};
use crate::timestamp::rfc3339;

use super::{
    base, error, insecure_channel, member_errors, mutation_body, mutation_line, persist_failed,
    read, refusal_line,
};

/// The registry entry: the lifecycle facts and the hash algorithm's
/// name, never a digest, code or secret.
pub(crate) fn entry_object(entry: &RegistryEntry) -> Value {
    json!({
        "id": entry.id,
        "display_name": entry.display_name,
        "state": entry.state.name(),
        "generation": entry.generation,
        "issued_at": rfc3339(entry.issued_at),
        "expires_at": entry.expires_at.map(rfc3339),
        "activated_at": entry.activated_at.map(rfc3339),
        "revoked_at": entry.revoked_at.map(rfc3339),
        "hash_algorithm": "sha256",
        "no_account": entry.no_account,
    })
}

fn disclosure_refused(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    what: &str,
) -> Response<ResponseBody> {
    refusal_line(server, peer, Some(principal), "insecure_channel");
    error(
        StatusCode::FORBIDDEN,
        "insecure_channel",
        &format!(
            "{what} is disclosed only from loopback or over TLS; run the operation on the host"
        ),
        None,
        vec![],
    )
}

fn invalid_members(details: Vec<Value>) -> Response<ResponseBody> {
    error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "the request has invalid members",
        None,
        details,
    )
}

/// The bounds `clients.enrollment_lifetime_seconds` has.
const LIFETIME_SECONDS: std::ops::RangeInclusive<u64> = 60..=604_800;

/// What an invite sets beside its code: how long the code lives and
/// whether the client may add accounts of its own.
struct Terms {
    lifetime_seconds: u64,
    no_account: bool,
}

/// The optional `lifetime_seconds` and `no_account` members, or the
/// detail refusing them.
fn terms(server: &Server, body: &Value) -> Result<Terms, Vec<Value>> {
    let lifetime_seconds = match body.get("lifetime_seconds") {
        None => server.config().config.clients.enrollment_lifetime_seconds,
        Some(value) => match value.as_u64().filter(|s| LIFETIME_SECONDS.contains(s)) {
            Some(seconds) => seconds,
            None => {
                return Err(vec![json!({
                    "target": "lifetime_seconds",
                    "code": "out_of_range",
                    "message": "an invite lives 60 to 604800 seconds",
                })]);
            }
        },
    };
    Ok(Terms {
        lifetime_seconds,
        no_account: body["no_account"].as_bool().unwrap_or(false),
    })
}

const TERMS_MEMBERS: [(&str, &str, bool); 2] = [
    ("lifetime_seconds", "integer", false),
    ("no_account", "boolean", false),
];

/// The registry entry read back after a mutation, for the response body.
fn entry_now(server: &Server, id: &str) -> Value {
    server
        .registry()
        .entry(id)
        .map(entry_object)
        .unwrap_or_else(|| json!({ "id": id }))
}

/// Create a pending enrollment; the code is disclosed once.
pub(super) async fn issue(
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
        return disclosure_refused(server, peer, principal, "an enrollment code");
    }
    let details = member_errors(
        &body,
        &[
            ("id", "string", true),
            ("display_name", "string", true),
            TERMS_MEMBERS[0],
            TERMS_MEMBERS[1],
        ],
    );
    if !details.is_empty() {
        return invalid_members(details);
    }
    let terms = match terms(server, &body) {
        Ok(terms) => terms,
        Err(details) => return invalid_members(details),
    };
    let id = body["id"].as_str().unwrap_or_default().to_string();
    let display_name = body["display_name"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let result = server.mutate_registry(|registry| {
        let issued = registry
            .issue(
                &id,
                &display_name,
                OffsetDateTime::now_utc(),
                terms.lifetime_seconds,
            )
            .map_err(|why| {
                why.unwrap_or_else(|| {
                    "a client with this id already exists; re-enrol it with reissue".to_string()
                })
            })?;
        registry.set_no_account(&id, terms.no_account);
        Ok::<_, String>(issued)
    });
    let (code, expires_at) = match result {
        Ok(disclosed) => disclosed,
        Err(MutateError::Refused(message)) => {
            let (status, slug) = refusal_slug(&message, &id);
            refusal_line(server, peer, Some(principal), slug);
            return error(status, slug, &message, Some(id), vec![]);
        }
        Err(MutateError::Persist(e)) => return persist_failed(server, e),
    };
    mutation_line(server, peer, principal, "client_issue", &id, "issued");
    base(
        StatusCode::CREATED,
        json!({
            "client": entry_now(server, &id),
            "enrollment_code": code,
            "expires_at": rfc3339(expires_at),
        }),
    )
}

/// Reissue — a new pending generation for a pending, active or revoked
/// id; the previous code dies.
pub(super) async fn reissue(
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
        return disclosure_refused(server, peer, principal, "an enrollment code");
    }
    let details = member_errors(&body, &TERMS_MEMBERS);
    if !details.is_empty() {
        return invalid_members(details);
    }
    let terms = match terms(server, &body) {
        Ok(terms) => terms,
        Err(details) => return invalid_members(details),
    };
    let id = id.to_string();
    let result = server.mutate_registry(|registry| {
        let reissued = registry
            .reissue(&id, OffsetDateTime::now_utc(), terms.lifetime_seconds)
            .map_err(|e| match e {
                ReissueError::Unknown => "no client has this id".to_string(),
            })?;
        registry.set_no_account(&id, terms.no_account);
        Ok::<_, String>(reissued)
    });
    match result {
        Ok((code, expires_at)) => {
            mutation_line(server, peer, principal, "client_reissue", &id, "reissued");
            base(
                StatusCode::CREATED,
                json!({
                    "client": entry_now(server, &id),
                    "enrollment_code": code,
                    "expires_at": rfc3339(expires_at),
                }),
            )
        }
        Err(MutateError::Refused(message)) => {
            let (status, slug) = refusal_slug(&message, &id);
            refusal_line(server, peer, Some(principal), slug);
            error(status, slug, &message, Some(id), vec![])
        }
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

/// Rotate an active client; the old secret fails on the next request.
pub(super) async fn rotate(
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
        return disclosure_refused(server, peer, principal, "a client secret");
    }
    let details = member_errors(&body, &[]);
    if !details.is_empty() {
        return invalid_members(details);
    }
    let id = id.to_string();
    let result = server.mutate_registry(|registry| {
        registry.rotate(&id).map_err(|()| {
            "only an active client can rotate; reissue a pending or revoked id".to_string()
        })
    });
    match result {
        Ok(secret) => {
            mutation_line(server, peer, principal, "client_rotate", &id, "rotated");
            base(
                StatusCode::OK,
                json!({ "client": entry_now(server, &id), "client_secret": secret }),
            )
        }
        Err(MutateError::Refused(message)) => {
            let (status, slug) = refusal_slug(&message, &id);
            refusal_line(server, peer, Some(principal), slug);
            error(status, slug, &message, Some(id), vec![])
        }
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

/// Revoke — every code and secret for the id dies; the entry stays
/// visible. Revoking an already-revoked id is `200` and changes nothing.
pub(super) async fn revoke(
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
    let id = id.to_string();
    let result = server.mutate_registry(|registry| {
        registry
            .revoke(&id, OffsetDateTime::now_utc())
            .map_err(|()| "no client has this id".to_string())
    });
    match result {
        Ok(()) => {
            mutation_line(server, peer, principal, "client_revoke", &id, "revoked");
            base(StatusCode::OK, json!({ "client": entry_now(server, &id) }))
        }
        Err(MutateError::Refused(message)) => {
            let (status, slug) = refusal_slug(&message, &id);
            refusal_line(server, peer, Some(principal), slug);
            error(status, slug, &message, Some(id), vec![])
        }
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

/// Rename the display name only.
pub(super) async fn rename(
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
    let details = member_errors(&body, &[("display_name", "string", true)]);
    if !details.is_empty() {
        return invalid_members(details);
    }
    let name = body["display_name"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let id = id.to_string();
    let result = server.mutate_registry(|registry| registry.rename(&id, &name));
    match result {
        Ok(()) => {
            mutation_line(server, peer, principal, "client_rename", &id, "renamed");
            base(StatusCode::OK, json!({ "client": entry_now(server, &id) }))
        }
        Err(MutateError::Refused(message)) => {
            let (status, slug) = refusal_slug(&message, &id);
            refusal_line(server, peer, Some(principal), slug);
            error(status, slug, &message, Some(id), vec![])
        }
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

/// `404 client_not_found` for an unknown id, `400` for a client id the CLI
/// should have caught, `409 conflict` for a state that does not admit the call.
fn refusal_slug(message: &str, id: &str) -> (StatusCode, &'static str) {
    if message.starts_with("no client has this id") {
        (StatusCode::NOT_FOUND, "client_not_found")
    } else if message.starts_with("a client id") {
        (StatusCode::BAD_REQUEST, "invalid_client_id")
    } else if message.starts_with("a display name") {
        (StatusCode::BAD_REQUEST, "invalid_display_name")
    } else if message.starts_with("only an active client")
        || message.starts_with("a client with this id")
    {
        (StatusCode::CONFLICT, "conflict")
    } else {
        let _ = id;
        (StatusCode::BAD_REQUEST, "invalid_request")
    }
}

/// The registry array and one entry; a revoked id is found,
/// a never-issued id is `404 client_not_found`.
pub(super) fn list(server: &Server) -> Response<ResponseBody> {
    let registry = server.registry();
    read(json!({ "clients": registry.clients.iter().map(entry_object).collect::<Vec<_>>() }))
}

pub(super) fn show(server: &Server, id: &str) -> Response<ResponseBody> {
    match server.registry().entry(id) {
        Some(entry) => read(json!({ "client": entry_object(entry) })),
        None => error(
            StatusCode::NOT_FOUND,
            "client_not_found",
            "no client has this id",
            Some(id.to_string()),
            vec![],
        ),
    }
}

/// The one operation reachable without a principal. Every failure
/// is one identical refusal; the real cause goes to the log.
pub(super) async fn claim(
    server: &Arc<Server>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let body = match mutation_body(server, peer, None, request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    if insecure_channel(server, peer) {
        return disclosure_refused(server, peer, &anonymous(), "a claim");
    }
    let details = member_errors(&body, &[("id", "string", true), ("code", "string", true)]);
    if !details.is_empty() {
        return invalid_members(details);
    }
    let id = body["id"].as_str().unwrap_or_default().to_string();
    let code = body["code"].as_str().unwrap_or_default().to_string();
    let mut claimed = None;
    let cause = server.mutate_registry(|registry| {
        match registry.claim(&id, &code, OffsetDateTime::now_utc()) {
            Ok((entry, secret)) => {
                claimed = Some((entry, secret));
                Ok(())
            }
            Err(why) => Err(why),
        }
    });
    let cause = match cause {
        Ok(()) => None,
        Err(MutateError::Refused(cause)) => Some(cause),
        Err(MutateError::Persist(e)) => return persist_failed(server, e),
    };
    if let Some(cause) = cause {
        // One identical refusal; the log names the real cause.
        tracing::info!(
            event = "control_refusal",
            code = "enrollment_claim_refused",
            source_address = %peer,
            cause = %cause,
            "an enrollment claim was refused"
        );
        return error(
            StatusCode::FORBIDDEN,
            "enrollment_claim_refused",
            "the enrollment claim was refused; ask the operator to issue a new code",
            None,
            vec![],
        );
    }
    let (entry, secret) = claimed.expect("the claim succeeded");
    let principal = Principal {
        kind: crate::audit::PrincipalKind::Client,
        id: Some(entry.id.clone()),
    };
    mutation_line(
        server,
        peer,
        &principal,
        "enrollment_claim",
        &entry.id,
        "claimed",
    );
    let ca = server.mitm_ca().map(
        |ca| json!({ "certificate_pem": ca.certificate_pem(), "fingerprint": ca.fingerprint() }),
    );
    base(
        StatusCode::OK,
        json!({
            "client_id": entry.id,
            "display_name": entry.display_name,
            "client_secret": secret,
            "generation": entry.generation,
            "no_account": entry.no_account,
            "proxy_url": proxy_origin(&server.config().config),
            "ca": ca,
        }),
    )
}

/// The proxy origin a client is given: the advertised one, else the proxy
/// listener's own address, which a wildcard bind leaves without one.
fn proxy_origin(config: &crate::config::Config) -> Option<String> {
    if let Some(advertised) = &config.clients.advertised_proxy_url {
        return Some(advertised.clone());
    }
    let listen = config.mitm.listen;
    (!listen.ip().is_unspecified()).then(|| format!("http://{listen}"))
}

fn anonymous() -> Principal {
    Principal {
        kind: crate::audit::PrincipalKind::Loopback,
        id: None,
    }
}
