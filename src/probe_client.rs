//! Engineer `status`'s MITM probe — the probe host asked
//! twice, once through an intercepted tunnel (`CONNECT` with the proxy
//! credential, TLS trusting only the installation's `ca.pem`) and once in absolute form
//! over plain HTTP, so that the four outcomes the probe host makes distinguishable
//! are told apart.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use serde_json::Value;

use crate::client::ClientInstallation;

const PROBE_HOST: &str = "probe.jaynshare.invalid";
const TIMEOUT: Duration = Duration::from_secs(3);

/// One form's answer: the status line when a head was read at all, the
/// parsed JSON of a `200`, and whether the tunnel's TLS handshake against
/// `ca.pem` failed after the `CONNECT` was accepted.
#[derive(Debug, Default)]
struct Answer {
    status: Option<u16>,
    json: Option<Value>,
    handshake_failed: bool,
}

impl Answer {
    fn unanswered() -> Self {
        Self::default()
    }
}

/// The status code of a response head (`HTTP/1.1 <code> …`).
fn status_of(head: &str) -> Option<u16> {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
}

/// Splits a raw answer into head and body; a `200` body must be JSON.
fn parse_answer(raw: &[u8]) -> Answer {
    let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Answer::unanswered();
    };
    let head = String::from_utf8_lossy(&raw[..end]);
    let Some(status) = status_of(&head) else {
        return Answer::unanswered();
    };
    if status != 200 {
        return Answer {
            status: Some(status),
            json: None,
            handshake_failed: false,
        };
    }
    let body = String::from_utf8_lossy(&raw[end + 4..]);
    match serde_json::from_str(body.trim()) {
        Ok(json) => Answer {
            status: Some(200),
            json: Some(json),
            handshake_failed: false,
        },
        Err(_) => Answer::unanswered(),
    }
}

/// Reads a response head one byte at a time, so a tunnel's first bytes after
/// it are left for the TLS handshake.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// The intercepted form: `CONNECT` with the credential, then TLS trusting
/// only `ca.pem`, then `GET /`. A handshake failure is no answer.
async fn tunnel_form(authority: &str, credential: &str, ca: &Path) -> Answer {
    let Ok(mut stream) = TcpStream::connect(authority).await else {
        return Answer::unanswered();
    };
    let head = format!(
        "CONNECT {PROBE_HOST}:443 HTTP/1.1\r\nhost: {PROBE_HOST}:443\r\nproxy-authorization: {credential}\r\n\r\n"
    );
    if stream.write_all(head.as_bytes()).await.is_err() {
        return Answer::unanswered();
    }
    let status = status_of(&read_head(&mut stream).await);
    match status {
        Some(200) => (),
        other => {
            return Answer {
                status: other,
                json: None,
                handshake_failed: false,
            };
        }
    }
    let untrusted = Answer {
        status: Some(200),
        json: None,
        handshake_failed: true,
    };
    let mut roots = RootCertStore::empty();
    let Ok(certificates) =
        CertificateDer::pem_file_iter(ca).and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
    else {
        return untrusted;
    };
    roots.add_parsable_certificates(certificates);
    let Ok(config) = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions() else {
        return Answer::unanswered();
    };
    let connector: TlsConnector =
        Arc::new(config.with_root_certificates(roots).with_no_client_auth()).into();
    let Ok(name) = ServerName::try_from(PROBE_HOST.to_owned()) else {
        return Answer::unanswered();
    };
    let mut tls = match connector.connect(name, stream).await {
        Ok(tls) => tls,
        Err(_) => return untrusted,
    };
    let head = format!("GET / HTTP/1.1\r\nhost: {PROBE_HOST}\r\nconnection: close\r\n\r\n");
    if tls.write_all(head.as_bytes()).await.is_err() {
        return Answer::unanswered();
    }
    let mut raw = Vec::new();
    if tls.read_to_end(&mut raw).await.is_err() {
        return Answer::unanswered();
    }
    parse_answer(&raw)
}

/// The plain-HTTP form: one absolute-form `GET` on the proxy listener.
async fn absolute_form(authority: &str, credential: &str) -> Answer {
    let Ok(mut stream) = TcpStream::connect(authority).await else {
        return Answer::unanswered();
    };
    let head = format!(
        "GET http://{PROBE_HOST}/ HTTP/1.1\r\nhost: {PROBE_HOST}\r\nproxy-authorization: {credential}\r\nconnection: close\r\n\r\n"
    );
    if stream.write_all(head.as_bytes()).await.is_err() {
        return Answer::unanswered();
    }
    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).await.is_err() {
        return Answer::unanswered();
    }
    parse_answer(&raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Neither form answered.
    Unreachable,
    /// Both forms answered `407`.
    CredentialRefused,
    /// Only the plain-HTTP form answered.
    CaNotTrusted,
    /// Both answered; `matches` compares the probe's fingerprint with
    /// `client.toml`'s.
    Healthy { fingerprint: String, matches: bool },
}

/// Both answers as received (the status `probe` member) and the outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub outcome: Outcome,
    pub tunnel: Option<Value>,
    pub absolute: Option<Value>,
}

/// The proxy listener's authority, the automatic credential (an empty
/// user field) and the installation's `ca.pem`.
fn proxy_parts(installation: &ClientInstallation, secret: &str) -> (String, String, PathBuf) {
    let authority = installation
        .proxy
        .as_deref()
        .and_then(|proxy| proxy.strip_prefix("http://"))
        .unwrap_or_default()
        .to_owned();
    let credential = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!(":{secret}"))
    );
    (authority, credential, installation.directory.join("ca.pem"))
}

/// A MITM launch's check — one intercepted probe-host request
/// answered within `within`. `Err` is the exit code: 4 no answer, 5 the
/// credential refused (`407`), 12 the TLS handshake against `ca.pem` failed.
pub async fn launch_check(
    installation: &ClientInstallation,
    secret: &str,
    within: Duration,
) -> Result<(), i32> {
    let (authority, credential, ca) = proxy_parts(installation, secret);
    match tokio::time::timeout(within, tunnel_form(&authority, &credential, &ca)).await {
        Ok(Answer { json: Some(_), .. }) => Ok(()),
        Ok(Answer {
            status: Some(407), ..
        }) => Err(5),
        Ok(Answer {
            handshake_failed: true,
            ..
        }) => Err(12),
        _ => Err(4),
    }
}

/// Both probe forms against the installation's proxy listener.
pub async fn probe(installation: &ClientInstallation, secret: &str) -> Probe {
    let (authority, credential, ca) = proxy_parts(installation, secret);
    let tunnel = tokio::time::timeout(TIMEOUT, tunnel_form(&authority, &credential, &ca))
        .await
        .unwrap_or_else(|_| Answer::unanswered());
    let absolute = tokio::time::timeout(TIMEOUT, absolute_form(&authority, &credential))
        .await
        .unwrap_or_else(|_| Answer::unanswered());
    let outcome = match (&tunnel.json, &absolute.json) {
        (Some(answered), _) => {
            let fingerprint = answered["ca_fingerprint"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let matches = installation.ca_fingerprint.as_deref() == Some(fingerprint.as_str());
            Outcome::Healthy {
                fingerprint,
                matches,
            }
        }
        (None, Some(_)) => Outcome::CaNotTrusted,
        (None, None) if tunnel.status == Some(407) || absolute.status == Some(407) => {
            Outcome::CredentialRefused
        }
        (None, None) => Outcome::Unreachable,
    };
    Probe {
        outcome,
        tunnel: tunnel.json,
        absolute: absolute.json,
    }
}

/// The `probe` member: both answers as received and the outcome
/// (`src/cli/schema.rs` publishes its shape).
pub fn member(probe: &Probe) -> Value {
    let (outcome, matches) = match &probe.outcome {
        Outcome::Unreachable => ("unreachable", None),
        Outcome::CredentialRefused => ("credential_refused", None),
        Outcome::CaNotTrusted => ("ca_not_trusted", None),
        Outcome::Healthy { matches, .. } => ("healthy", Some(*matches)),
    };
    serde_json::json!({
        "outcome": outcome,
        "tunnel": probe.tunnel,
        "absolute": probe.absolute,
        "fingerprint_matches": matches,
    })
}

/// The failure class for the outcome: `(code, slug, message)`,
/// or `None` when healthy with a matching fingerprint.
pub fn failure(probe: &Probe) -> Option<(i32, &'static str, String)> {
    match &probe.outcome {
        Outcome::Unreachable => Some((
            4,
            "cli_unreachable",
            "the proxy answered neither probe form; the pool is unreachable in MITM mode"
                .to_owned(),
        )),
        Outcome::CredentialRefused => Some((
            5,
            "cli_refused",
            "the proxy refused this machine's credential (407) on both probe forms; the enrollment may be revoked"
                .to_owned(),
        )),
        Outcome::CaNotTrusted => Some((
            12,
            "cli_ca_untrusted",
            "the proxy answers, but the TLS form failed: the CA in ca.pem is not the CA the server presents"
                .to_owned(),
        )),
        Outcome::Healthy {
            matches: false,
            fingerprint,
        } => Some((
            12,
            "cli_ca_mismatch",
            format!(
                "the server presents CA {fingerprint}, not the one client.toml records"
            ),
        )),
        Outcome::Healthy { matches: true, .. } => None,
    }
}
