//! The control client: the loopback
//! operator through the configured listener's port, or with `--server` the
//! remote operator carrying its bearer secret.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{Value, json};

use crate::config::{self, ListenerTls, LoadedConfig};
use crate::control::API_VERSION;
use crate::identity::{self, Identity, PinnedVerifier};

use super::Failure;
use super::args::Cli;
use super::verbs::read_input;

/// One instance, addressed on loopback or through `--server`.
pub(super) struct Control {
    pub(super) origin: String,
    /// Where the loopback default connects when that is not
    /// `origin` — `127.0.0.1` on the configured port, the implicit loopback bind —
    /// while `origin` stays the HTTP host and the TLS identity.
    dial: Option<String>,
    pub(super) client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    pub(super) timeout: Duration,
    /// The selected configuration; `None` under `--server`, where nothing is read.
    pub(super) config_path: Option<PathBuf>,
    /// The state file the configuration names, for the one local
    /// fact a loopback operator command needs: whether the remote-operator
    /// secret exists (for `operator secret set`'s confirmation). `None` under `--server`.
    pub(super) state_path: Option<PathBuf>,
    /// The bearer for a remote operator; the loopback operator sends none.
    bearer: Option<HeaderValue>,
}

impl Control {
    pub(super) fn connect(cli: &Cli) -> Result<Self, Failure> {
        if let Some(origin) = &cli.server {
            return Self::remote(cli, origin);
        }
        Self::loopback(
            config::config_path(cli.config.as_deref()),
            Duration::from_secs(cli.timeout),
        )
    }

    /// The loopback operator of the instance `config_path` configures.
    pub(super) fn loopback(config_path: PathBuf, timeout: Duration) -> Result<Self, Failure> {
        let bytes = config::read(&config_path).map_err(|e| {
            // An operator verb needs a readable configuration or --server.
            Failure::local(
                3,
                "cli_configuration_invalid",
                format!(
                    "{}: {e}; give --config <path> or JAYNSHARE_CONFIG, or address a running instance with --server <origin>",
                    config_path.display()
                ),
            )
        })?;
        // Only the listener address and the TLS pair are needed here, so a file
        // with local errors still addresses the running instance — the server
        // answers `config reload` on such a file with the reload's own verdict and
        // `status` keeps working while the operator repairs it.
        // A document that is not TOML at all cannot name the address.
        let parsed = config::parse_document(&bytes, config::base_dir(&config_path)).map_err(|e| {
            Failure::local(
                3,
                "cli_configuration_invalid",
                format!(
                    "{}: {e}; the file must parse as TOML to name the listener address — repair it (`jaynshare config validate`) or address a running instance with --server <origin>",
                    config_path.display()
                ),
            )
        })?;
        let state_path = parsed.config.storage.state_file.clone();
        let loaded = LoadedConfig {
            path: config_path.clone(),
            digest: config::sha256_hex(&bytes),
            config: parsed.config,
        };
        // The TCP peer is always 127.0.0.1, so the call resolves
        // as the loopback operator; a non-loopback address stays the HTTP host
        // and the TLS identity, reached through the implicit loopback bind.
        let listen = loaded.config.data_plane.listen;
        let port = listen.port();
        let (host, address) = if listen.ip().is_unspecified() || listen.ip().is_loopback() {
            ("127.0.0.1".to_string(), None)
        } else {
            (listen.ip().to_string(), Some(listen.ip()))
        };
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        // Https on an operator certificate trusts the system store plus every
        // certificate of the configured chain.
        let (scheme, client) = match &loaded.config.data_plane.tls {
            ListenerTls::Off => ("http", http_client_plain()?),
            ListenerTls::Identity => ("https", http_client_pinned(&server_pin(&state_path)?)?),
            ListenerTls::Certificate(tls) => (
                "https",
                http_client_identity(&[tls.certificate_file.as_path()], address)?,
            ),
        };
        Ok(Self {
            origin: format!("{scheme}://{host}:{port}"),
            dial: address.map(|_| format!("{scheme}://127.0.0.1:{port}")),
            client,
            timeout,
            config_path: Some(config_path),
            state_path: Some(state_path),
            bearer: None,
        })
    }

    /// `--server <origin>` as a remote operator; the secret by the secret
    /// channels (a protected file, or a hidden prompt on a terminal).
    fn remote(cli: &Cli, origin: &str) -> Result<Self, Failure> {
        let uri: http::Uri = origin.parse().map_err(|_| {
            Failure::local(
                2,
                "cli_usage",
                format!("--server {origin:?} is not an origin"),
            )
        })?;
        let scheme = uri.scheme_str().unwrap_or("");
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        if !matches!(scheme, "http" | "https")
            || authority.is_empty()
            || (uri.path() != "/" && !uri.path().is_empty())
            || uri.query().is_some()
        {
            return Err(Failure::local(
                2,
                "cli_usage",
                format!("--server takes an origin such as https://<host>:<port>, not {origin:?}"),
            ));
        }
        let secret = read_input(
            cli.operator_secret_file.as_ref(),
            false,
            "remote-operator secret (hidden): ",
        )
        .map_err(|mut f| {
            // Only the no-channel refusal is reworded; a file that is not
            // regular or too broad keeps its own reason.
            let no_channel = f.error["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("no terminal"));
            if f.code == 2 && no_channel {
                f.error["message"] = json!(
                    "the remote-operator secret comes from --operator-secret-file <path> or a hidden prompt on a terminal"
                );
            }
            f
        })?;
        let bearer = HeaderValue::from_str(&format!("Bearer {secret}")).map_err(|_| {
            Failure::local(2, "cli_usage", "the operator secret is not a header value")
        })?;
        Ok(Self {
            origin: format!("{scheme}://{authority}"),
            dial: None,
            client: http_client(cli.tls_ca.as_deref())?,
            timeout: Duration::from_secs(cli.timeout),
            config_path: None,
            state_path: None,
            bearer: Some(bearer),
        })
    }

    /// Exit 4 naming the origin and, for the loopback default, the
    /// configuration path the address came from and the verbs to check.
    pub(super) fn unreachable(&self, why: &str) -> Failure {
        let tried = match &self.dial {
            Some(dial) => format!("{} (through {dial})", self.origin),
            None => self.origin.clone(),
        };
        let message = match &self.config_path {
            Some(path) => format!(
                "{tried}: {why}; the address comes from {} (data_plane.listen); check `jaynshare service status`",
                path.display()
            ),
            None => format!("{}: {why}", self.origin),
        };
        Failure::local(4, "cli_unreachable", message)
    }

    /// The configuration path an editing verb writes; `--server` has none.
    pub(super) fn config_path(&self) -> Result<&Path, Failure> {
        self.config_path.as_deref().ok_or_else(|| {
            Failure::local(
                2,
                "cli_usage",
                "this verb edits the configuration file on this machine and does not take --server",
            )
        })
    }

    /// One control request; the body is the control envelope or the call fails at the request deadline.
    pub(super) async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value), Failure> {
        let (status, _, bytes) = self
            .raw(method, path, body.map(|b| Bytes::from(b.to_string())), &[])
            .await?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            Failure::local(
                10,
                "cli_incompatible_server",
                format!(
                    "{} answered {} with a body that is not a control envelope (control API version {API_VERSION} expected)",
                    self.origin, status
                ),
            )
        })?;
        // The pre-principal answer carries no version member by
        // design: a refused operator secret is exit 5, not exit 10.
        if status == StatusCode::UNAUTHORIZED && value["error"]["type"] == "authentication_error" {
            return Ok((status, value));
        }
        let served = value.get("control_api_version").and_then(Value::as_u64);
        if served != Some(API_VERSION) {
            return Err(Failure::local(
                10,
                "cli_incompatible_server",
                format!(
                    "{} serves control API version {}; this build speaks {API_VERSION}",
                    self.origin,
                    served.map_or("none".to_string(), |v| v.to_string())
                ),
            ));
        }
        Ok((status, value))
    }

    pub(super) async fn raw(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<(StatusCode, http::HeaderMap, Bytes), Failure> {
        let response = self.request(method, path, body, headers).await?;
        let (parts, body) = response.into_parts();
        let bytes = tokio::time::timeout(self.timeout, body.collect())
            .await
            .map_err(|_| self.unreachable("the response body stalled"))?
            .map_err(|e| self.unreachable(&e.to_string()))?
            .to_bytes();
        Ok((parts.status, parts.headers, bytes))
    }

    /// A mutation carries `content-type: application/json`, no `origin`
    /// and no `sec-fetch-site`; a remote operator carries the bearer.
    pub(super) async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<http::Response<hyper::body::Incoming>, Failure> {
        let mut request = http::Request::builder()
            .method(method)
            .uri(format!(
                "{}{path}",
                self.dial.as_ref().unwrap_or(&self.origin)
            ))
            .header(ACCEPT, "application/json");
        if self.dial.is_some() {
            let authority = self.origin.split_once("://").map_or("", |(_, a)| a);
            request = request.header(HOST, authority);
        }
        if body.is_some() {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        if let Some(bearer) = &self.bearer {
            request = request.header(AUTHORIZATION, bearer.clone());
        }
        let mut request = request
            .body(Full::new(body.unwrap_or_default()))
            .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?;
        for (name, value) in headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        let response = tokio::time::timeout(self.timeout, self.client.request(request))
            .await
            .map_err(|_| {
                self.unreachable(&format!("no response within {} s", self.timeout.as_secs()))
            })?
            .map_err(|e| self.unreachable(&error_chain(&e)))?;
        Ok(response)
    }

    /// A control envelope to an outcome: `2xx` is the result; anything else maps to its exit code.
    pub(super) async fn expect(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, Failure> {
        let (status, value) = self.call(method, path, body).await?;
        if status.is_success() {
            return Ok(value);
        }
        Err(Self::failure(status, &value))
    }

    /// A reload's verdict as an exit code: 3 with the details when the candidate is invalid, 8
    /// when it changes restart keys (named in the details).
    pub(super) async fn reload(&self) -> Result<Value, Failure> {
        let (status, value) = self
            .call(Method::POST, "/control/v1/reload", Some(&json!({})))
            .await?;
        if status.is_success() {
            return Ok(value);
        }
        let mut failure = Self::failure(status, &value);
        let restart_keys = value["rejected_restart_keys"]
            .as_array()
            .is_some_and(|keys| !keys.is_empty());
        if failure.code == 3 && restart_keys {
            failure.code = 8;
        }
        Err(failure)
    }

    /// An editing verb asks the server before it writes, so an
    /// unreachable server leaves the file untouched (exit 4).
    pub(super) async fn reachable(&self) -> Result<(), Failure> {
        match self.expect(Method::GET, "/control/v1/accounts", None).await {
            Ok(_) => Ok(()),
            Err(mut failure) if failure.code == 4 => {
                let message = failure.error["message"].as_str().unwrap_or("").to_string();
                failure.error["message"] = json!(format!(
                    "{message}; the file was not written — `config edit --offline` edits without a server"
                ));
                Err(failure)
            }
            Err(failure) => Err(failure),
        }
    }

    /// The server's error envelope to the exit code; a slug the
    /// table lacks maps by HTTP status class and passes through in `--json`.
    fn failure(status: StatusCode, value: &Value) -> Failure {
        let mut error = value.get("error").cloned().unwrap_or(json!({ "code": "internal_error", "message": "no error object", "target": null, "details": [] }));
        // The pre-principal answer is Anthropic-shaped, with no control error
        // code: the local slug of exit code 5.
        if status == StatusCode::UNAUTHORIZED && error.get("code").is_none() {
            error = json!({ "code": "cli_refused", "message": error["message"], "target": null, "details": [] });
        }
        let code = match error["code"].as_str().unwrap_or("") {
            "configuration_invalid" => 3,
            "operator_required"
            | "insecure_channel"
            | "loopback_required"
            | "cross_origin_control"
            | "enrollment_claim_refused" => 5,
            "not_found" | "account_not_found" | "client_not_found" | "route_not_found" => 6,
            "ambiguous_account_reference" => 7,
            "conflict"
            | "account_reference_conflict"
            | "sweep_in_progress"
            | "mitm_disabled"
            | "probe_unavailable"
            | "method_not_allowed" => 8,
            "invalid_request"
            | "invalid_client_id"
            | "invalid_display_name"
            | "credential_rejected"
            | "import_failed"
            | "request_too_large"
            | "unsupported_media_type" => 9,
            "internal_error" | "unavailable" => 10,
            _ => match status.as_u16() {
                400 | 422 => 9,
                401 | 403 => 5,
                404 => 6,
                405 | 409 => 8,
                s if s >= 500 => 10,
                _ => 1,
            },
        };
        Failure { code, error }
    }

    /// A reference becomes a handle before the verb uses it; nothing
    /// matching lists the display names the operator could have meant.
    pub(super) async fn resolve(&self, reference: &str) -> Result<Value, Failure> {
        self.resolve_within(reference, None).await
    }

    /// [`Control::resolve`] among one provider's accounts, `None` among all.
    pub(super) async fn resolve_within(
        &self,
        reference: &str,
        provider: Option<&str>,
    ) -> Result<Value, Failure> {
        let mut encoded: String = reference
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        if let Some(provider) = provider {
            encoded += &format!("&provider={provider}");
        }
        match self
            .expect(
                Method::GET,
                &format!("/control/v1/accounts/resolve?reference={encoded}"),
                None,
            )
            .await
        {
            Ok(body) => Ok(body),
            Err(mut f) if f.code == 6 => {
                let names = self
                    .expect(Method::GET, "/control/v1/accounts", None)
                    .await
                    .ok()
                    .and_then(|b| {
                        b["accounts"].as_array().map(|a| {
                            a.iter()
                                .filter_map(|x| x["display_name"].as_str().map(String::from))
                                .collect::<Vec<_>>()
                        })
                    })
                    .unwrap_or_default();
                let position = if reference.chars().all(|c| c.is_ascii_digit()) {
                    " (positions are not references)"
                } else {
                    ""
                };
                f.error["message"] = json!(format!(
                    "no account matches {reference:?}{position}; accounts: {}",
                    if names.is_empty() {
                        "none".to_string()
                    } else {
                        names.join(", ")
                    }
                ));
                Err(f)
            }
            Err(f) => Err(f),
        }
    }
}

/// The pin of the identity key the server writes beside its state on its
/// first start.
fn server_pin(state_path: &Path) -> Result<String, Failure> {
    let state_dir = state_path.parent().unwrap_or(Path::new("."));
    let key = state_dir.join(identity::KEY_FILE);
    if !key.exists() {
        return Err(Failure::local(
            4,
            "cli_unreachable",
            format!(
                "{} does not exist: the server has not started yet",
                key.display()
            ),
        ));
    }
    Identity::load(state_dir)
        .map(|identity| identity.pin().to_string())
        .map_err(|why| {
            Failure::local(
                3,
                "cli_configuration_invalid",
                format!("server identity: {why}"),
            )
        })
}

/// The error and every cause under it, so a refused TLS handshake reads as
/// its reason (`invalid peer certificate: CaUsedAsEndEntity`) and not as the
/// connector's bare `client error (Connect)`.
pub(crate) fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// The same client with an empty trust store, for an `http` origin: no
/// certificate is ever loaded, so a client read of a plain-HTTP origin opens
/// no file beyond the caller's own.
pub(crate) fn http_client_plain()
-> Result<Client<HttpsConnector<HttpConnector>, Full<Bytes>>, Failure> {
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
    Ok(client_over(tls))
}

/// The same client checking the server against its identity pin alone.
pub(crate) fn http_client_pinned(
    pin: &str,
) -> Result<Client<HttpsConnector<HttpConnector>, Full<Bytes>>, Failure> {
    let provider = rustls::crypto::ring::default_provider();
    let verifier = PinnedVerifier::new(pin, provider.signature_verification_algorithms);
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(client_over(tls))
}

fn client_over(tls: ClientConfig) -> Client<HttpsConnector<HttpConnector>, Full<Bytes>> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// An `http`-or-`https` client trusting the system store plus, when given,
/// one PEM file (the configured certificate, or `--tls-ca`). Also the client
/// side's builder (`client::ClientRequest`).
pub(crate) fn http_client(
    extra_anchor: Option<&Path>,
) -> Result<Client<HttpsConnector<HttpConnector>, Full<Bytes>>, Failure> {
    http_client_anchors(&extra_anchor.into_iter().collect::<Vec<_>>())
}

/// The same client with every anchor in `extra_anchors` added to the OS
/// store (an installation's `base-url-ca.pem` beside `--tls-ca`).
pub(crate) fn http_client_anchors(
    extra_anchors: &[&Path],
) -> Result<Client<HttpsConnector<HttpConnector>, Full<Bytes>>, Failure> {
    http_client_identity(extra_anchors, None)
}

/// The same client, verifying the server's certificate for `identity` when
/// given rather than for the host it dials.
fn http_client_identity(
    extra_anchors: &[&Path],
    identity: Option<IpAddr>,
) -> Result<Client<HttpsConnector<HttpConnector>, Full<Bytes>>, Failure> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    for path in extra_anchors {
        let certificates = CertificateDer::pem_file_iter(path)
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .map_err(|e| {
                Failure::local(
                    3,
                    "cli_configuration_invalid",
                    format!("trust anchor {}: {e}", path.display()),
                )
            })?;
        roots.add_parsable_certificates(certificates);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?;
    let tls = match identity {
        None => builder.with_root_certificates(roots).with_no_client_auth(),
        Some(ip) => {
            let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ConfiguredIdentity {
                    inner,
                    name: ServerName::IpAddress(ip.into()),
                }))
                .with_no_client_auth()
        }
    };
    Ok(client_over(tls))
}

/// The full WebPKI verification, for the configured address
/// rather than the `127.0.0.1` the loopback default dials.
#[derive(Debug)]
struct ConfiguredIdentity {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for ConfiguredIdentity {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _dialled: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
