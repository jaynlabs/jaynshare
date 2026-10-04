//! The operator's steer: the global switch and the per-route preference.
//! Both are one pool write each and never touch the state file.

use std::sync::Arc;

use http::{HeaderMap, Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::Principal;
use crate::config::Route;
use crate::data_plane::relay::ResponseBody;
use crate::pool::operator::RouteRefusal;
use crate::pool::{Resolve, fold};
use crate::server::Server;

use super::{account_object, base, error, member_errors, mutation_body, mutation_line};
use std::net::SocketAddr;

/// `{ "reference" }` → the named account is the default at once.
pub(super) async fn switch_default(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let handle = match reference_body(server, peer, Some(principal), request).await {
        Ok(handle) => handle,
        Err(refusal) => return refusal,
    };
    let previous = server
        .pool
        .lock()
        .expect("pool lock")
        .switch_default(handle, OffsetDateTime::now_utc());
    let answer = will_serve(server, handle);
    tracing::info!(
        event = "default_switched",
        account = %handle,
        from = previous.map(|h| h.to_string()).unwrap_or_default(),
        will_serve = answer["will_serve"].as_bool().unwrap_or(false),
        reason = answer["reason"].as_str().unwrap_or(""),
        reason_detail = answer["reason_detail"].as_str().unwrap_or(""),
        "default account switched by the operator"
    );
    mutation_line(
        server,
        peer,
        principal,
        "selection_switch",
        &handle.to_string(),
        "switched",
    );
    base(StatusCode::OK, answer)
}

/// `POST`: the operator's preference for one configured route.
pub(super) async fn set_route_preference(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    name: &str,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let Some(route) = configured_route(server, name) else {
        return route_not_found(name);
    };
    let handle = match reference_body(server, peer, Some(principal), request).await {
        Ok(handle) => handle,
        Err(refusal) => return refusal,
    };
    let set = server
        .pool
        .lock()
        .expect("pool lock")
        .set_route_preference(&route, handle);
    match set {
        Ok(()) => {}
        Err(RouteRefusal::NotListed) => {
            return error(
                StatusCode::CONFLICT,
                "conflict",
                "the route's account list does not contain this account",
                Some(route.name),
                vec![],
            );
        }
    }
    let mut answer = will_serve(server, handle);
    answer["route"] = json!(route.name);
    tracing::info!(
        event = "route_preference_set",
        route = %route.name,
        account = %handle,
        will_serve = answer["will_serve"].as_bool().unwrap_or(false),
        reason = answer["reason"].as_str().unwrap_or(""),
        "route preference set by the operator"
    );
    mutation_line(
        server,
        peer,
        principal,
        "route_preference_set",
        &route.name,
        "set",
    );
    base(StatusCode::OK, answer)
}

/// `DELETE`: clears the preference.
pub(super) fn clear_route_preference(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    name: &str,
    headers: &HeaderMap,
) -> Response<ResponseBody> {
    if let Some(refusal) = super::csrf_refusal(server, peer, Some(principal), headers) {
        return refusal;
    }
    let Some(route) = configured_route(server, name) else {
        return route_not_found(name);
    };
    let dropped = server
        .pool
        .lock()
        .expect("pool lock")
        .clear_route_preference(&route.name);
    tracing::info!(
        event = "route_preference_cleared",
        route = %route.name,
        account = dropped.map(|h| h.to_string()).unwrap_or_default(),
        "route preference cleared by the operator"
    );
    mutation_line(
        server,
        peer,
        principal,
        "route_preference_clear",
        &route.name,
        "cleared",
    );
    base(
        StatusCode::OK,
        json!({ "route": route.name, "account": dropped }),
    )
}

/// A preference exists only for a configured route; the name matches under
/// the same folding that makes route names unique.
fn configured_route(server: &Server, name: &str) -> Option<Route> {
    let folded = fold(name);
    server
        .config()
        .config
        .selection
        .routes
        .iter()
        .find(|r| fold(&r.name) == folded)
        .cloned()
}

fn route_not_found(name: &str) -> Response<ResponseBody> {
    error(
        StatusCode::NOT_FOUND,
        "route_not_found",
        "no configured route has this name",
        Some(name.to_string()),
        vec![],
    )
}

/// The `{ "reference" }` body, resolved to a handle.
async fn reference_body(
    server: &Server,
    peer: SocketAddr,
    principal: Option<&Principal>,
    request: Request<Incoming>,
) -> Result<Uuid, Response<ResponseBody>> {
    let body = mutation_body(server, peer, principal, request).await?;
    let details = member_errors(&body, &[("reference", "string", true)]);
    if !details.is_empty() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request body has invalid members",
            None,
            details,
        ));
    }
    let reference = body["reference"].as_str().unwrap_or_default();
    let resolved = server
        .pool
        .lock()
        .expect("pool lock")
        .resolve(reference)
        .map(|a| a.handle);
    match resolved {
        Ok(handle) => Ok(handle),
        Err(Resolve::NotFound) => Err(error(
            StatusCode::NOT_FOUND,
            "account_not_found",
            "no account matches the reference",
            Some(reference.to_string()),
            vec![],
        )),
        Err(Resolve::Ambiguous(names)) => Err(error(
            StatusCode::BAD_REQUEST,
            "ambiguous_account_reference",
            &format!(
                "the reference matches several accounts: {}; an organisation name or full organisation UUID is the qualifier",
                Resolve::listed(&names)
            ),
            Some(reference.to_string()),
            vec![],
        )),
    }
}

/// The switch's answer: the model-less projection of the account.
fn will_serve(server: &Server, handle: Uuid) -> Value {
    let account = account_object(server, handle).unwrap_or(Value::Null);
    json!({
        "account": { "handle": account["handle"], "display_name": account["display_name"] },
        "will_serve": account["eligibility"]["eligible"].as_bool().unwrap_or(false),
        "reason": account["eligibility"]["reason"],
        "reason_detail": account["eligibility"]["reason_detail"],
    })
}
