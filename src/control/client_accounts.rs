//! A client's own accounts under `/control/v1/client/accounts`: the
//! listing, and the browser login whose callback the client catches and
//! forwards. These routes are the client's alone, and reach only the
//! accounts and operations it owns.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::Principal;
use crate::config::SelectionSettings;
use crate::data_plane::relay::ResponseBody;
use crate::login::Starter;
use crate::pool::{Account, Pool, selection};
use crate::server::Server;

use super::accounts::health_of;
use super::client_surface::rate_limits;
use super::{
    error, insecure_channel, insecure_channel_refusal, login_display_name, login_provider,
    login_started, member_errors, method_not_allowed, mutation_body, mutation_line, not_found,
    operation_cancel, operation_code, operation_show, read, refusal_line, time_or_null,
};

/// `path` is what follows `/control/v1/client/accounts/`.
pub(super) async fn route(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    path: &[&str],
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let Some(client) = principal.client_id() else {
        refusal_line(server, peer, Some(principal), "client_required");
        return error(
            StatusCode::FORBIDDEN,
            "client_required",
            "this operation is an enrolled client's own; the operator's login is /control/v1/accounts/login",
            None,
            vec![],
        );
    };
    let method = request.method().clone();
    match (path, &method) {
        (["owned"], &Method::GET) => owned(server, client),
        (["login"], &Method::POST) => login_start(server, peer, principal, request).await,
        (["operations", id], &Method::GET) => operation_show(server, principal, id),
        (["operations", id, "code"], &Method::POST) => {
            operation_code(server, peer, principal, id, request).await
        }
        (["operations", id, "cancel"], &Method::POST) => {
            operation_cancel(server, peer, principal, id, request).await
        }
        (["owned"] | ["operations", _], _) => method_not_allowed("GET"),
        (["login"] | ["operations", _, "code" | "cancel"], _) => method_not_allowed("POST"),
        _ => not_found(),
    }
}

/// The accounts this client owns, in the pool's order.
fn owned(server: &Server, client: &str) -> Response<ResponseBody> {
    let loaded = server.config();
    let now = OffsetDateTime::now_utc();
    let mut pool = server.pool.lock().expect("pool lock");
    if pool.expire_quota(now) {
        server.mark_quota_dirty();
    }
    let accounts: Vec<Value> = pool
        .accounts()
        .iter()
        .filter(|account| account.owner.as_deref() == Some(client))
        .map(|account| owned_object(server, &pool, account, &loaded.config.selection))
        .collect();
    read(json!({ "accounts": accounts }))
}

fn owns_any(server: &Server, client: &str) -> bool {
    let pool = server.pool.lock().expect("pool lock");
    pool.accounts()
        .iter()
        .any(|account| account.owner.as_deref() == Some(client))
}

/// One account the client owns, or `None` when it is not the client's.
pub(super) fn owned_account(server: &Server, client: &str, handle: Uuid) -> Option<Value> {
    let loaded = server.config();
    let pool = server.pool.lock().expect("pool lock");
    pool.get(handle)
        .filter(|account| account.owner.as_deref() == Some(client))
        .map(|account| owned_object(server, &pool, account, &loaded.config.selection))
}

/// The catalogue entry plus the identity and health only the owner sees.
fn owned_object(
    server: &Server,
    pool: &Pool,
    account: &Account,
    settings: &SelectionSettings,
) -> Value {
    let now = OffsetDateTime::now_utc();
    let hold = pool.organisation_hold(account, now);
    let (state, reason, since) =
        health_of(account, server.refreshes.in_flight(account.handle), now);
    json!({
        "handle": account.handle,
        "display_name": account.display_name,
        "selectable": selection::selectable(account, settings, pool.families(), now, hold),
        "rate_limits": rate_limits(account),
        "profile": account.profile,
        "health": { "state": state, "reason": reason, "since": time_or_null(since) },
    })
}

/// Start a login whose callback lands on the client's own loopback port.
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
    let details = member_errors(
        &body,
        &[
            ("redirect_port", "integer", true),
            ("display_name", "string", false),
            ("provider", "string", false),
        ],
    );
    if !details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            details,
        );
    }
    let Some(port) = body["redirect_port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_port is the client's loopback callback port, 1 to 65535",
            Some("redirect_port".into()),
            vec![],
        );
    };
    let provider = match login_provider(&body) {
        Ok(provider) => provider,
        Err(refusal) => return *refusal,
    };
    if let Some(fixed) = provider.callback_port()
        && fixed != port
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("this provider's login redirect is fixed at port {fixed}"),
            Some("redirect_port".into()),
            vec![],
        );
    }
    let client = principal
        .client_id()
        .expect("the route admits clients only");
    if !server.registry().adds_accounts(client) && !owns_any(server, client) {
        refusal_line(server, peer, Some(principal), "new_account_refused");
        return error(
            StatusCode::FORBIDDEN,
            "new_account_refused",
            "this client's invite adds no account of its own, and it owns none to log in again",
            None,
            vec![],
        );
    }
    let starter = Starter::Client {
        id: client.to_string(),
        port,
    };
    match server
        .logins
        .start(
            Arc::clone(server),
            starter,
            provider,
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
