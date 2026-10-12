//! Loopback forward proxy with the enrollment credential added only at the next hop.

use std::io::IsTerminal as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};

use super::transport::Adapter;
use crate::client;
use crate::data_plane::{connect::Connector, envelope::proxy_response, relay::ResponseBody, tls};
use crate::mitm::tunnel;

const DEADLINE: Duration = Duration::from_secs(30);

pub async fn check_trust(installation: &client::ClientInstallation) -> Result<(), String> {
    if installation.proxy.is_none() {
        return Err("Desktop requires an enrolled forward proxy for downloads and WebFetch; re-enrol with a server that exposes its proxy listener".into());
    }
    let ca_path = installation.directory.join("ca.pem");
    let ca =
        std::fs::read_to_string(&ca_path).map_err(|_| "the enrolled pool CA is unavailable")?;
    if installation.ca_fingerprint.as_deref() != Some(crate::bundle::fingerprint(&ca)?.as_str()) {
        return Err("the enrolled pool CA does not match its recorded fingerprint; re-enrol before Desktop setup".into());
    }
    for certificate in CertificateDer::pem_slice_iter(ca.as_bytes()) {
        let certificate = certificate.map_err(|_| "the enrolled CA bundle is invalid")?;
        let path = installation
            .directory
            .join(format!("desktop-ca-check-{}.pem", uuid::Uuid::new_v4()));
        let pem = crate::mitm::ca::pem("CERTIFICATE", &certificate);
        crate::state::write_private_atomic(&path, pem.as_bytes())
            .map_err(|e| format!("could not prepare the Desktop CA check: {e}"))?;
        let result = trust_certificate(&path, &crate::mitm::ca::fingerprint(&certificate)).await;
        std::fs::remove_file(&path)
            .map_err(|e| format!("could not remove the Desktop CA check: {e}"))?;
        result?;
    }
    Ok(())
}

async fn trust_certificate(path: &Path, fingerprint: &str) -> Result<(), String> {
    if trusted(path).await? {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err("installing the pool CA globally for Claude Desktop requires confirmation in a terminal".into());
    }
    eprintln!("Pool CA fingerprint: {fingerprint}");
    eprintln!("This CA will be trusted by other applications using your macOS trust settings.");
    let prompt = "Install CA globally (needed for Claude Desktop) [y/N] ";
    let confirmed = crate::cli::confirm(prompt).map_err(|failure| {
        failure.error["message"]
            .as_str()
            .unwrap_or("could not read the CA installation confirmation")
            .to_string()
    })?;
    if !confirmed {
        return Err(
            "CA installation cancelled; Claude Desktop needs macOS trust for the pool CA".into(),
        );
    }
    crate::deploy::trust_store::add(path, fingerprint)?;
    if !trusted(path).await? {
        return Err(format!(
            "macOS still does not trust pool CA {fingerprint} after installation"
        ));
    }
    Ok(())
}

async fn trusted(path: &Path) -> Result<bool, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new("security")
            .args(["verify-cert", "-L", "-l", "-c"])
            .arg(path)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "checking macOS CA trust timed out")?
    .map_err(|e| format!("could not check macOS CA trust: {e}"))?;
    Ok(output.status.success())
}

pub async fn handle(
    adapter: Arc<Adapter>,
    mut request: Request<Incoming>,
) -> Response<ResponseBody> {
    let Some(proxy) = adapter.installation.proxy.as_deref() else {
        return error("the enrollment has no upstream proxy");
    };
    let Ok(secret) = client::read_secret(&adapter.installation) else {
        return error("the enrolled proxy credential is unavailable");
    };
    let authority = proxy
        .strip_prefix("http://")
        .unwrap_or(proxy)
        .trim_end_matches('/');
    let url: Uri = match format!("http://:{}@{authority}", client::percent_encode(&secret)).parse()
    {
        Ok(url) => url,
        Err(_) => return error("the enrolled proxy address is invalid"),
    };
    let connector = match tls::client_config().and_then(|tls| Connector::new(tls, Some(&url))) {
        Ok(connector) => connector,
        Err(_) => return error("could not prepare the upstream proxy connection"),
    };
    if request.method() == Method::CONNECT {
        let Some(target) = request.uri().authority() else {
            return error("CONNECT requires a target authority");
        };
        if target.port_u16().is_none() || target.as_str().contains('@') {
            return error("CONNECT requires a host and port without credentials");
        }
        let connected = tokio::time::timeout(DEADLINE, connector.tunnel(target.as_str())).await;
        let Ok(Ok(mut upstream)) = connected else {
            return error("the upstream proxy could not open the tunnel");
        };
        let upgraded = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            if let Ok(Ok(stream)) = tokio::time::timeout(DEADLINE, upgraded).await {
                let mut downstream = TokioIo::new(stream);
                let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
            }
        });
        return Response::new(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        );
    }
    if request.uri().scheme_str() != Some("http")
        || request
            .uri()
            .authority()
            .is_none_or(|a| a.as_str().contains('@'))
    {
        return error("forward requests require an absolute HTTP URL");
    }
    tunnel::strip_request_hop_by_hop(request.headers_mut());
    tunnel::strip_proxy_metadata(request.headers_mut());
    let Some(auth) = connector.proxy_authorization().and_then(|v| v.parse().ok()) else {
        return error("the enrolled proxy credential is invalid");
    };
    request.headers_mut().insert("proxy-authorization", auth);
    let client: Client<Connector, Incoming> =
        Client::builder(TokioExecutor::new()).build(connector);
    match tokio::time::timeout(DEADLINE, client.request(request)).await {
        Ok(Ok(response)) => {
            let (mut parts, body) = response.into_parts();
            crate::data_plane::relay::strip_response_headers(&mut parts.headers);
            Response::from_parts(
                parts,
                body.map_err(|e| Box::new(e) as crate::data_plane::relay::BoxError)
                    .boxed(),
            )
        }
        _ => error("the upstream proxy could not forward the request"),
    }
}

fn error(message: &str) -> Response<ResponseBody> {
    proxy_response(StatusCode::BAD_GATEWAY, "proxy_error", message)
}
