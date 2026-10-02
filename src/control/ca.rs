//! The MITM certificate authority's read and rotate endpoints. The CA
//! objects are `src/mitm/ca.rs`'s; no key material is returned, and the CA
//! private key never touches the disk in the first place.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::audit::Principal;
use crate::data_plane::relay::ResponseBody;
use crate::mitm::ca::{Authorities, Ca};
use crate::server::Server;
use crate::timestamp::rfc3339;

use super::{base, error, member_errors, mutation_body, mutation_line};

/// `GET /control/v1/ca` — the CA presented and the staged one, each with its
/// certificate, which is how a client follows a rotation. Every member is
/// `null` while MITM has never been enabled. The declared principal class
/// is **client**; the router's client-or-operator arm serves it.
pub(super) fn read(server: &Arc<Server>) -> Response<ResponseBody> {
    let enabled = server.config().config.mitm.enabled;
    let authorities = match enabled {
        true => server.mitm_authorities().clone(),
        false => Authorities::default(),
    };
    let ca = match &authorities.current {
        Some(ca) => {
            let mut next = next_object(&authorities);
            if let Some(staged) = &authorities.next {
                next["certificate_pem"] = json!(staged.certificate_pem());
            }
            json!({
                "certificate_pem": ca.certificate_pem(),
                "fingerprint": ca.fingerprint(),
                "not_after": rfc3339(ca.not_after()),
                "state": ca.expiry_state(OffsetDateTime::now_utc()),
                "next": next,
            })
        }
        None => json!({
            "certificate_pem": null,
            "fingerprint": null,
            "not_after": null,
            "state": if enabled { json!("unusable") } else { json!(null) },
            "next": null,
        }),
    };
    base(StatusCode::OK, json!({ "ca": ca }))
}

/// The staged CA's fingerprint, expiry and switch time, `null` without one.
pub(super) fn next_object(authorities: &Authorities) -> Value {
    match (&authorities.next, authorities.switch_at()) {
        (Some(next), Some(switch_at)) => json!({
            "fingerprint": next.fingerprint(),
            "not_after": rfc3339(next.not_after()),
            "switch_at": rfc3339(switch_at),
        }),
        _ => Value::Null,
    }
}

/// `POST /control/v1/mitm/ca/rotate`, with an optional `now` boolean. By
/// default it stages the next CA, presented once the overlap ends; `now`,
/// or an unusable current CA, replaces the CA at once. `409 mitm_disabled`
/// when the mode is off, `409 rotation_pending` when a CA is already staged.
pub(super) async fn rotate(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let body = match mutation_body(server, peer, Some(principal), request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    let member_details = member_errors(&body, &[("now", "boolean", false)]);
    if !member_details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            member_details,
        );
    }
    if !server.config().config.mitm.enabled {
        return error(
            StatusCode::CONFLICT,
            "mitm_disabled",
            "MITM mode is off; there is no certificate authority to rotate",
            None,
            vec![],
        );
    }
    let state_dir = server.state_dir();
    let now = OffsetDateTime::now_utc();
    let mut authorities = server.mitm_authorities();
    let previous = authorities.current.as_ref().map(|ca| ca.fingerprint());
    let staging = !body["now"].as_bool().unwrap_or(false) && authorities.current.is_some();
    if staging && let (Some(next), Some(switch_at)) = (&authorities.next, authorities.switch_at()) {
        return error(
            StatusCode::CONFLICT,
            "rotation_pending",
            &format!(
                "CA {} is already staged and takes over at {}; `ca rotate --now` replaces the CA at once",
                next.fingerprint(),
                rfc3339(switch_at)
            ),
            None,
            vec![],
        );
    }
    let rotated = match staging {
        true => Ca::stage(&state_dir, now).map(|next| authorities.next = Some(Arc::new(next))),
        // Tunnels already established keep the leaf they negotiated.
        false => Ca::rotate(&state_dir, now).map(|ca| {
            authorities.current = Some(Arc::new(ca));
            authorities.next = None;
        }),
    };
    if let Err(e) = rotated {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_unwritable",
            &format!("the certificate authority could not be rotated: {e}"),
            None,
            vec![],
        );
    }
    let current = authorities.current.clone().expect("kept or rotated");
    let answer = json!({
        "previous_fingerprint": previous,
        "fingerprint": current.fingerprint(),
        "not_after": rfc3339(current.not_after()),
        "next": next_object(&authorities),
    });
    drop(authorities);
    let outcome = if staging { "staged" } else { "rotated" };
    mutation_line(server, peer, principal, "ca_rotate", "ca", outcome);
    base(StatusCode::OK, answer)
}
