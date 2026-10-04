//! The probe host: the proxy answers it itself and never forwards it. It
//! answers in both proxy forms, so a client can tell "credential refused"
//! from "CA not trusted": only the intercepted form needs the handshake to
//! succeed.

use http::{Response, StatusCode};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::data_plane::envelope;
use crate::data_plane::relay::ResponseBody;
use crate::mitm::ca::STATE_UNUSABLE;
use crate::mitm::tunnel::Credential;
use crate::provider::anthropic::error_type;
use crate::server::{Server, VERSION};

/// The name reserved for this purpose, so no real host is ever shadowed. It
/// is one of the two intercepted names.
pub const PROBE_HOST: &str = "probe.jaynshare.invalid";

/// `GET /` answers the object, any other path `404`. `tls` is `true`
/// inside an intercepted tunnel and `false` in absolute form.
pub fn answer(
    server: &Server,
    credential: &Credential,
    path: &str,
    tls: bool,
) -> Response<ResponseBody> {
    if path != "/" {
        return envelope::proxy_response(
            StatusCode::NOT_FOUND,
            error_type::NOT_FOUND,
            &format!("the probe host answers / only, not {path}"),
        );
    }
    envelope::json_response(StatusCode::OK, &object(server, credential, tls))
}

/// The object itself, so the two forms cannot drift apart.
pub fn object(server: &Server, credential: &Credential, tls: bool) -> Value {
    let ca = server.mitm_ca();
    let principal = &credential.principal;
    json!({
        "ca_fingerprint": ca.as_ref().map(|ca| ca.fingerprint()),
        "ca_not_after": ca.as_ref().and_then(|ca| ca.not_after().format(&Rfc3339).ok()),
        "ca_state": ca.as_ref().map_or(STATE_UNUSABLE, |ca| ca.expiry_state(OffsetDateTime::now_utc())),
        "principal": {
            "display_name": crate::control::client_surface::display_name(server, principal),
            // The role and the stable id the audit log uses.
            "role": principal.role(),
            "id": principal.id,
        },
        // Exactly as received, `null` when the field was empty.
        "user_field": (!credential.user_field.is_empty()).then(|| credential.user_field.clone()),
        "tls": tls,
        "version": VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_host_is_one_of_the_intercepted_names() {
        assert!(crate::mitm::ca::INTERCEPT_NAMES.contains(&PROBE_HOST));
    }
}
