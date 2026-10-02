//! `client invite` and `client reissue`: a pending generation and the
//! invite that carries it, disclosed once. What the joining machine checks
//! (the TLS base URL, the identity pin, the signing key) is read from the
//! server before anything is issued, so a server no machine could join
//! refuses before a code exists.

use http::Method;
use serde_json::{Value, json};

use super::args::{Cli, InviteArgs, InviteTerms};
use super::control::Control;
use super::{Failure, Outcome};
use crate::invite::Invite;

/// `--expires`: seconds, or a number followed by `s`, `m`, `h` or `d`.
pub(super) fn expiry_seconds(text: &str) -> Result<u64, String> {
    let (number, unit) = match text.char_indices().last() {
        Some((at, unit)) if unit.is_ascii_alphabetic() => (&text[..at], unit),
        _ => (text, 's'),
    };
    let scale = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return Err(format!("{text:?}: the unit is s, m, h or d")),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .ok_or_else(|| format!("{text:?} is not a duration such as 24h"))
}

/// The base-URL and proxy origins clients are given: the advertised ones,
/// else the listeners' own addresses, refused beside a wildcard bind, whose
/// address no client can reach.
pub(super) fn origins_from(body: &Value) -> Result<(String, Option<String>), Failure> {
    let effective = &body["configuration"]["effective"];
    let listen = effective["data_plane"]["listen"]
        .as_str()
        .unwrap_or_default();
    let tls = effective["data_plane"]["tls"].as_str() != Some("off");
    let advertised_base_url = effective["clients"]["advertised_base_url"]
        .as_str()
        .filter(|s| !s.is_empty());
    let mitm_listen = effective["mitm"]["listen"].as_str();
    let advertised_proxy_url = effective["clients"]["advertised_proxy_url"]
        .as_str()
        .filter(|s| !s.is_empty());
    let unspecified = |listen: &str| {
        listen
            .parse::<std::net::SocketAddr>()
            .map(|addr| addr.ip().is_unspecified())
            .unwrap_or(false)
    };
    if advertised_base_url.is_none() && unspecified(listen) {
        return Err(Failure::local(
            3,
            "cli_configuration_invalid",
            format!(
                "clients.advertised_base_url is unset and data_plane.listen is the wildcard {listen}, which no client can reach; set clients.advertised_base_url"
            ),
        ));
    }
    if let Some(mitm_listen) = mitm_listen
        && advertised_proxy_url.is_none()
        && unspecified(mitm_listen)
    {
        return Err(Failure::local(
            3,
            "cli_configuration_invalid",
            format!(
                "clients.advertised_proxy_url is unset and mitm.listen is the wildcard {mitm_listen}, which no client can reach; set clients.advertised_proxy_url"
            ),
        ));
    }
    let base_url = advertised_base_url.map_or_else(
        || format!("{}://{listen}", if tls { "https" } else { "http" }),
        String::from,
    );
    let proxy = mitm_listen
        .map(|l| advertised_proxy_url.map_or_else(|| format!("http://{l}"), String::from));
    Ok((base_url, proxy))
}

/// What an invite says about its server besides the claim.
struct ServerFacts {
    base_url: String,
    identity: Option<String>,
    signing_key: String,
}

async fn server_facts(control: &Control) -> Result<ServerFacts, Failure> {
    let configuration = control
        .expect(Method::GET, "/control/v1/configuration", None)
        .await?;
    let (base_url, _) = origins_from(&configuration)?;
    if !base_url.starts_with("https://") {
        return Err(Failure::local(
            3,
            "cli_configuration_invalid",
            format!(
                "the base URL {base_url} is plain HTTP, and a machine joins only over TLS; set `tls = \"identity\"` under [data_plane] and restart the server"
            ),
        ));
    }
    let status = control
        .expect(Method::GET, "/control/v1/status", None)
        .await?;
    let status = &status["status"];
    if status["mitm"]["ca"]["fingerprint"].is_null() {
        return Err(Failure::local(
            14,
            "cli_transport_unavailable",
            "MITM mode is off, and every client launches through the proxy; turn it on with `enabled = true` under [mitm]",
        ));
    }
    // A TLS front before a plain listener, or an operator certificate,
    // presents another key than the identity's: its clients check the
    // certificate instead.
    let identity_tls =
        configuration["configuration"]["effective"]["data_plane"]["tls"] == "identity";
    let identity = match status["server"]["tls_pin"].as_str() {
        Some(pin) if identity_tls => Some(pin.to_string()),
        None if identity_tls => {
            return Err(Failure::local(
                10,
                "cli_incompatible_server",
                "the server serves its identity TLS but names no pin",
            ));
        }
        _ => None,
    };
    let signing_key = status["server"]["signing_key"]
        .as_str()
        .ok_or_else(|| {
            Failure::local(
                17,
                "cli_release_unverified",
                "the server cannot read the release key its client kit is verified with",
            )
        })?
        .to_string();
    Ok(ServerFacts {
        base_url,
        identity,
        signing_key,
    })
}

/// The request members an invite's terms set.
fn terms_body(terms: &InviteTerms) -> Value {
    let mut body = json!({});
    if let Some(seconds) = terms.expires {
        body["lifetime_seconds"] = json!(seconds);
    }
    if terms.no_account {
        body["no_account"] = json!(true);
    }
    body
}

/// `client invite <id> [--name] [--expires] [--no-account]`.
pub(super) async fn client_invite(control: &Control, cli: &Cli, args: &InviteArgs) -> Outcome {
    super::bundle::validate_client_id(&args.id)?;
    let name = args.name.as_deref().unwrap_or(&args.id);
    super::bundle::validate_display_name(name)?;
    let facts = server_facts(control).await?;
    let mut request = terms_body(&args.terms);
    request["id"] = json!(args.id);
    request["display_name"] = json!(name.trim());
    let issued = control
        .expect(Method::POST, "/control/v1/clients", Some(&request))
        .await?;
    disclose(cli, &args.terms, &facts, issued)
}

/// `client reissue <id> [--expires] [--no-account]`: a new pending
/// generation and its invite; the previous code dies.
pub(super) async fn client_reissue(
    control: &Control,
    cli: &Cli,
    id: &str,
    terms: &InviteTerms,
) -> Outcome {
    super::bundle::validate_client_id(id)?;
    let facts = server_facts(control).await?;
    let issued = control
        .expect(
            Method::POST,
            &format!("/control/v1/clients/{id}/reissue"),
            Some(&terms_body(terms)),
        )
        .await?;
    disclose(cli, terms, &facts, issued)
}

/// The invite in place of the code: into `--disclose-to`, inside `result`
/// with `--json`, or as the last line of the human output, ready to run.
fn disclose(cli: &Cli, terms: &InviteTerms, facts: &ServerFacts, issued: Value) -> Outcome {
    let code = issued["enrollment_code"].as_str().ok_or_else(|| {
        Failure::local(
            10,
            "cli_incompatible_server",
            "the response carries no enrollment_code",
        )
    })?;
    let client = &issued["client"];
    let invite = Invite {
        base_url: facts.base_url.clone(),
        identity: facts.identity.clone(),
        signing_key: facts.signing_key.clone(),
        client_id: client["id"].as_str().unwrap_or_default().to_string(),
        code: code.to_string(),
    }
    .encode();
    let mut result = json!({ "client": client, "expires_at": issued["expires_at"] });
    if let Some(path) = &terms.disclose_to {
        super::bundle::write_disclosure(path, &invite)?;
        result["disclosure_file"] = json!(path.display().to_string());
        return Ok((result, path.display().to_string()));
    }
    let human = format!(
        "{} ({}), generation {}\nthe invite works once, until {}; on the joining machine, run:\njaynshare join {invite}",
        client["id"].as_str().unwrap_or_default(),
        client["display_name"].as_str().unwrap_or_default(),
        client["generation"],
        issued["expires_at"].as_str().unwrap_or_default(),
    );
    result["invite"] = json!(invite);
    Ok((result, if cli.json { String::new() } else { human }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_expiry_takes_a_unit_or_seconds() {
        assert_eq!(expiry_seconds("90"), Ok(90));
        assert_eq!(expiry_seconds("30m"), Ok(1_800));
        assert_eq!(expiry_seconds("24h"), Ok(86_400));
        assert_eq!(expiry_seconds("7d"), Ok(604_800));
        assert!(expiry_seconds("1w").is_err());
        assert!(expiry_seconds("h").is_err());
        assert!(expiry_seconds("-1h").is_err());
    }
}
