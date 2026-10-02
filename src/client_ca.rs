//! The installation's `ca.pem` follows its server's CAs: the one the proxy
//! presents and, while a rotation is staged, the next one. They are fetched
//! only over a channel that authenticates the server.

use std::time::Duration;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use serde_json::Value;

use crate::client::{self, ClientInstallation};
use crate::mitm::ca::fingerprint;

const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Brings `ca.pem` in line with the CAs `snapshot` names, saying so on
/// standard error, or saying why it could not.
pub async fn follow(installation: &mut ClientInstallation, secret: &str, snapshot: &Value) {
    let wanted: Vec<&str> = ["ca_fingerprint", "ca_next_fingerprint"]
        .iter()
        .map_while(|member| snapshot[member].as_str())
        .collect();
    let presented = wanted.first().copied();
    if presented.is_none()
        || (held(installation) == wanted && installation.ca_fingerprint.as_deref() == presented)
    {
        return;
    }
    if let Err(why) = refresh(installation, secret).await {
        eprintln!("jaynshare: the server's CA changed, but {why}");
    }
}

/// Fetches the server's CAs into `ca.pem` and `client.toml`. `Ok(false)`:
/// this installation already held exactly them.
pub async fn refresh(installation: &mut ClientInstallation, secret: &str) -> Result<bool, String> {
    // The snapshot may have just moved the base URL onto `https`.
    *installation = client::read_installation().map_err(|(_, why)| why)?;
    if !authenticated(&installation.base_url) {
        return Err(
            "this machine reaches its server over plain HTTP, which cannot carry a CA safely; the operator turns on `data_plane.tls = \"identity\"`".into(),
        );
    }
    let body = client::client_read(installation, secret, "/control/v1/ca", READ_TIMEOUT)
        .await
        .map_err(|(_, why)| why)?;
    let presented = &body["ca"];
    let fingerprint = presented["fingerprint"]
        .as_str()
        .ok_or("the server has no usable CA")?;
    let mut pem = certificate(presented)?;
    let next = &presented["next"];
    if !next.is_null() {
        pem.push_str(&certificate(next)?);
    }
    let path = installation.directory.join("ca.pem");
    if std::fs::read_to_string(&path).is_ok_and(|held| held == pem)
        && installation.ca_fingerprint.as_deref() == Some(fingerprint)
    {
        return Ok(false);
    }
    crate::state::write_private_atomic(&path, pem.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    client::set_toml(&installation.directory, &[("ca_fingerprint", fingerprint)])?;
    installation.ca_fingerprint = Some(fingerprint.to_string());
    match next["fingerprint"].as_str() {
        Some(next) => eprintln!(
            "jaynshare: now trusting the server's CA {fingerprint} and its next CA {next}"
        ),
        None => eprintln!("jaynshare: now trusting the server's CA {fingerprint}"),
    }
    Ok(true)
}

/// The fingerprints of the certificates in `ca.pem`, in order.
fn held(installation: &ClientInstallation) -> Vec<String> {
    CertificateDer::pem_file_iter(installation.directory.join("ca.pem"))
        .map(|certificates| {
            certificates
                .filter_map(Result::ok)
                .map(|der| fingerprint(der.as_ref()))
                .collect()
        })
        .unwrap_or_default()
}

/// An `https` base URL is checked against its pin or anchor; plain HTTP is
/// trusted on loopback only.
fn authenticated(base_url: &str) -> bool {
    base_url.starts_with("https://")
        || base_url
            .parse::<http::Uri>()
            .ok()
            .and_then(|uri| uri.host().map(crate::config::validate::is_loopback_host))
            .unwrap_or(false)
}

/// One CA object's certificate, once it parses as a CA whose digest is the
/// fingerprint beside it.
fn certificate(object: &Value) -> Result<String, String> {
    let (Some(pem), Some(named)) = (
        object["certificate_pem"].as_str(),
        object["fingerprint"].as_str(),
    ) else {
        return Err("the server's CA answer carries no certificate".into());
    };
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| format!("the server's CA {named} is not PEM: {e}"))?;
    let is_ca = parsed
        .parse_x509()
        .is_ok_and(|certificate| certificate.is_ca());
    if !is_ca || fingerprint(&parsed.contents) != named {
        return Err(format!("the server's certificate is not the CA {named}"));
    }
    Ok(pem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_carries_a_ca() {
        assert!(authenticated("https://pool.example:8443"));
        assert!(authenticated("http://127.0.0.1:8080"));
        assert!(authenticated("http://[::1]:8080"));
        assert!(authenticated("http://localhost:8080"));
        assert!(!authenticated("http://100.64.0.1:8080"));
        assert!(!authenticated("http://pool.example"));
    }
}
