//! The enrolled client's side of the wall: the installation files, the claim transaction the
//! engineer's `enrol --bundle` performs, and the client-authenticated reads
//! (`status`, the post-rotation check).

use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use serde_json::{Value, json};
use toml::Table;

use crate::config::platform;

/// The client result: the installation facts and the files it wrote.
pub struct ClientInstallation {
    pub directory: PathBuf,
    pub client_id: String,
    pub display_name: String,
    pub base_url: String,
    pub proxy: Option<String>,
    pub ca_fingerprint: Option<String>,
    /// The server identity pin, which replaces the trust anchor when held.
    pub server_identity: Option<String>,
    /// The client-side no-proxy members; the launcher adds
    /// loopback itself.
    pub no_proxy: Vec<String>,
}

/// The base-URL listener's trust anchor, installed exactly
/// when the base-URL origin is `https`.
pub const BASE_URL_CA_FILE: &str = "base-url-ca.pem";

impl ClientInstallation {
    /// The trust anchor every installed client HTTP call adds for the
    /// base-URL origin: `base-url-ca.pem` for an unpinned `https`
    /// origin, nothing otherwise.
    pub fn base_url_ca(&self) -> Option<PathBuf> {
        (self.server_identity.is_none() && self.base_url.starts_with("https://"))
            .then(|| self.directory.join(BASE_URL_CA_FILE))
    }
}

/// A missing installation file is named. An `https` base URL requires
/// `base-url-ca.pem` or a `server_identity` pin. `ca.pem` is the launcher's
/// to require: an enrollment from before base-URL mode was removed lacks it,
/// while `status` and `ca-update` must still read the installation. Its
/// `mode` key, if any, is ignored.
pub fn read_installation() -> Result<ClientInstallation, (i32, String)> {
    let directory = platform::client_directory();
    let toml_path = directory.join("client.toml");
    let text = std::fs::read_to_string(&toml_path).map_err(|_| {
        (
            11,
            format!(
                "this machine is not enrolled: {} is missing; run the enrollment bundle's installer",
                toml_path.display()
            ),
        )
    })?;
    let parsed: Table = text
        .parse()
        .map_err(|e| (3, format!("{}: {e}", toml_path.display())))?;
    let string = |key: &str| -> Result<String, (i32, String)> {
        parsed
            .get(key)
            .and_then(toml::Value::as_str)
            .map(String::from)
            .ok_or_else(|| (3, format!("{}: {key} missing", toml_path.display())))
    };
    let secret = directory.join("client-secret");
    if !secret.is_file() {
        return Err((
            11,
            format!(
                "the client installation is incomplete: {} is missing; run the enrollment bundle's installer",
                secret.display()
            ),
        ));
    }
    let ca_fingerprint = parsed
        .get("ca_fingerprint")
        .and_then(toml::Value::as_str)
        .map(String::from);
    let base_url = string("base_url")?;
    let server_identity = parsed
        .get("server_identity")
        .and_then(toml::Value::as_str)
        .filter(|pin| !pin.is_empty())
        .map(String::from);
    if let Some(pin) = &server_identity
        && !crate::identity::is_pin(pin)
    {
        return Err((
            3,
            format!(
                "{}: server_identity {pin:?} is not a sha256/ pin",
                toml_path.display()
            ),
        ));
    }
    if base_url.starts_with("https://") && server_identity.is_none() {
        let anchor = directory.join(BASE_URL_CA_FILE);
        if !anchor.is_file() {
            return Err((
                11,
                format!(
                    "the client installation is incomplete: {} is missing; run the enrollment bundle's installer",
                    anchor.display()
                ),
            ));
        }
    }
    Ok(ClientInstallation {
        directory,
        client_id: string("client_id")?,
        display_name: string("display_name")?,
        base_url,
        proxy: parsed
            .get("proxy_url")
            .and_then(toml::Value::as_str)
            .map(String::from),
        ca_fingerprint,
        server_identity,
        no_proxy: parsed
            .get("no_proxy")
            .and_then(toml::Value::as_array)
            .map(|members| {
                members
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// The client secret's file, read for one request.
pub fn read_secret(installation: &ClientInstallation) -> Result<String, (i32, String)> {
    let path = installation.directory.join("client-secret");
    crate::state::check_private(&path).map_err(|why| (5, why))?;
    let text =
        std::fs::read_to_string(&path).map_err(|e| (11, format!("{}: {e}", path.display())))?;
    let trimmed = text.trim_end_matches(['\n', '\r']).to_string();
    if trimmed.is_empty() {
        return Err((11, format!("{} is empty", path.display())));
    }
    Ok(trimmed)
}

/// The `client.toml` document. `ca_fingerprint` is present when the
/// bundle named one. `base_url_ca_fingerprint` is the base-URL anchor's,
/// written only for an `https` base URL.
pub fn client_toml(
    client_id: &str,
    display_name: &str,
    base_url: &str,
    proxy: Option<&str>,
    ca_fingerprint: Option<&str>,
    base_url_ca_fingerprint: Option<&str>,
    no_proxy: &[String],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("client_id = {client_id:?}\n"));
    out.push_str(&format!("display_name = {display_name:?}\n"));
    out.push_str(&format!("base_url = {base_url:?}\n"));
    match proxy {
        Some(url) => out.push_str(&format!("proxy_url = {url:?}\n")),
        None => out.push_str("proxy_url = \"\"\n"),
    }
    match ca_fingerprint {
        Some(fp) => out.push_str(&format!("ca_fingerprint = {fp:?}\n")),
        None => out.push_str("ca_fingerprint = \"\"\n"),
    }
    if let Some(fp) = base_url_ca_fingerprint {
        out.push_str(&format!("base_url_ca_fingerprint = {fp:?}\n"));
    }
    // The engineer's no-proxy members survive every rewrite (a CA
    // update replaces the fingerprint only).
    let members: Vec<String> = no_proxy.iter().map(|m| format!("{m:?}")).collect();
    out.push_str(&format!("no_proxy = [{}]\n", members.join(", ")));
    out
}

/// Set `client.toml` keys in place, every other line kept.
pub fn set_toml(directory: &Path, entries: &[(&str, &str)]) -> Result<(), String> {
    let path = directory.join("client.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut document: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    for (key, value) in entries {
        document[key] = toml_edit::value(*value);
    }
    crate::state::write_private_atomic(&path, document.to_string().as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The server's identity pin, kept by a plain-HTTP installation the first
/// time a snapshot names one, so it follows its server onto TLS. An `https`
/// installation already checks what it reaches, possibly a TLS front with
/// a certificate of its own, and a held pin is never replaced.
pub fn keep_identity(installation: &ClientInstallation, snapshot: &Value) {
    if installation.server_identity.is_some() || !installation.base_url.starts_with("http://") {
        return;
    }
    if let Some(pin) = snapshot["server"]["tls_pin"]
        .as_str()
        .filter(|pin| crate::identity::is_pin(pin))
    {
        let _ = set_toml(&installation.directory, &[("server_identity", pin)]);
    }
}

fn failure_message(failure: crate::cli::Failure) -> String {
    failure.error["message"]
        .as_str()
        .unwrap_or("no HTTP client")
        .to_string()
}

/// Stage the executable and the non-secret client files under an
/// owner-only directory, before the claim. Everything staged lands under the
/// platform roots (`bin/`, `client/`); the caller removes it on rollback.
pub fn stage(
    toml: &str,
    payload: &[u8],
    ca_pem: Option<&[u8]>,
    base_url_ca_pem: Option<&[u8]>,
) -> Result<PathBuf, String> {
    let directory = platform::client_directory();
    crate::state::ensure_private_dir(&directory)
        .map_err(|e| format!("{}: {e}", directory.display()))?;
    let bin = platform::client_binary();
    if let Some(parent) = bin.parent() {
        crate::state::ensure_private_dir(parent)
            .map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(&bin, payload).map_err(|e| format!("{}: {e}", bin.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", bin.display()))?;
    }
    let toml_path = directory.join("client.toml");
    std::fs::write(&toml_path, toml).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    if let Some(ca) = ca_pem {
        let ca_path = directory.join("ca.pem");
        std::fs::write(&ca_path, ca).map_err(|e| format!("{}: {e}", ca_path.display()))?;
    }
    if let Some(anchor) = base_url_ca_pem {
        let path = directory.join(BASE_URL_CA_FILE);
        std::fs::write(&path, anchor).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(directory)
}

/// Write the claimed secret into the staged protected file, then erase
/// every trace of the staging decision. The atomic replacement is
/// `state::write_private_atomic` (mode 0600, same directory, rename).
pub fn commit_secret(directory: &Path, secret: &str) -> Result<(), String> {
    let path = directory.join("client-secret");
    crate::state::write_private_atomic(&path, secret.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Remove everything this claim staged (the installation never
/// committed). The staged binary and directory only exist when we created
/// them; `enrol` refuses an existing installation, so removal is safe.
pub fn remove_staged() {
    let _ = std::fs::remove_file(platform::client_binary());
    let _ = std::fs::remove_dir_all(platform::client_directory());
}

// ------------------------------------------------------------------ the client's HTTP

/// One client-side control request: the base-URL origin, the client
/// secret as the bearer, the control envelope back. Failures are `(exit code,
/// message)` pairs the verbs surface as-is.
pub struct ClientRequest {
    origin: String,
    http: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    timeout: Duration,
    /// Where a pinned installation still on `http` finds its server once
    /// that serves TLS.
    upgrade: Option<Upgrade>,
}

struct Upgrade {
    origin: String,
    directory: PathBuf,
}

enum NoResponse {
    Timeout,
    Failed(hyper_util::client::legacy::Error),
}

impl ClientRequest {
    /// A request trusting the system store plus `anchors`.
    pub fn new(origin: &str, timeout: Duration, anchors: &[&Path]) -> Result<Self, String> {
        let plain = anchors.is_empty() && origin.starts_with("http://");
        let http = if plain {
            crate::cli::http_client_plain()
        } else {
            crate::cli::http_client_anchors(anchors)
        };
        Ok(Self {
            origin: origin.trim_end_matches('/').to_string(),
            http: http.map_err(failure_message)?,
            timeout,
            upgrade: None,
        })
    }

    /// A request to the installation's server, checked against its pin when
    /// it holds one, else against its `base-url-ca.pem` and `extra_anchor`.
    /// A pinned `http` installation follows its server onto TLS: when the
    /// plain exchange fails on an open connection, it retries over `https`
    /// and, once the pin answers there, keeps the `https` base URL.
    pub fn for_installation(
        installation: &ClientInstallation,
        timeout: Duration,
        extra_anchor: Option<&Path>,
    ) -> Result<Self, String> {
        let Some(pin) = &installation.server_identity else {
            let anchor = installation.base_url_ca();
            let anchors: Vec<&Path> = anchor.as_deref().into_iter().chain(extra_anchor).collect();
            return Self::new(&installation.base_url, timeout, &anchors);
        };
        let origin = installation.base_url.trim_end_matches('/');
        Ok(Self {
            origin: origin.to_string(),
            http: crate::cli::http_client_pinned(pin).map_err(failure_message)?,
            timeout,
            upgrade: origin.strip_prefix("http://").map(|authority| Upgrade {
                origin: format!("https://{authority}"),
                directory: installation.directory.clone(),
            }),
        })
    }

    /// The client form: one arbitrary request to the base-URL origin
    /// with the installation's secret in the intent header, the response handed back
    /// unread so `api` can stream the body.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        secret: Option<&str>,
        body: Option<Bytes>,
        headers: &[(http::HeaderName, http::HeaderValue)],
    ) -> Result<http::Response<hyper::body::Incoming>, (i32, String)> {
        let request = |origin: &str| {
            let mut request = http::Request::builder()
                .method(method.clone())
                .uri(format!("{origin}{path}"))
                .header(ACCEPT, "application/json");
            if body.is_some() {
                request = request.header(CONTENT_TYPE, "application/json");
            }
            if let Some(secret) = secret {
                let value = format!("Bearer {secret}");
                let value = http::HeaderValue::from_str(&value)
                    .map_err(|_| (2, "the client secret is not a header value".to_string()))?;
                request = request.header(AUTHORIZATION, value);
            }
            let mut request = request
                .body(Full::new(body.clone().unwrap_or_default()))
                .map_err(|e| (1, e.to_string()))?;
            for (name, value) in headers {
                request.headers_mut().insert(name.clone(), value.clone());
            }
            Ok::<_, (i32, String)>(request)
        };
        let first = match self.round_trip(request(&self.origin)?).await {
            Ok(response) => return Ok(response),
            Err(why) => why,
        };
        let upgrade = match (&first, &self.upgrade) {
            (NoResponse::Failed(e), Some(upgrade)) if !e.is_connect() => upgrade,
            _ => return Err((4, self.failure(&self.origin, first))),
        };
        match self.round_trip(request(&upgrade.origin)?).await {
            Ok(response) => {
                let _ = set_toml(&upgrade.directory, &[("base_url", &upgrade.origin)]);
                Ok(response)
            }
            Err(why) => Err((
                4,
                format!(
                    "{}; {}",
                    self.failure(&self.origin, first),
                    self.failure(&upgrade.origin, why)
                ),
            )),
        }
    }

    async fn round_trip(
        &self,
        request: http::Request<Full<Bytes>>,
    ) -> Result<http::Response<hyper::body::Incoming>, NoResponse> {
        match tokio::time::timeout(self.timeout, self.http.request(request)).await {
            Err(_) => Err(NoResponse::Timeout),
            Ok(answer) => answer.map_err(NoResponse::Failed),
        }
    }

    fn failure(&self, origin: &str, why: NoResponse) -> String {
        match why {
            NoResponse::Timeout => {
                format!("{origin}: no response within {} s", self.timeout.as_secs())
            }
            NoResponse::Failed(e) => format!("{origin}: {}", crate::cli::error_chain(&e)),
        }
    }

    /// `Ok((status, body))` or `Err((4, message))` for anything that is no
    /// answer at all — the connectivity/claim distinction enrolment needs.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        secret: Option<&str>,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value), (i32, String)> {
        let body = body.map(|b| Bytes::from(b.to_string()));
        let response = self.send(method, path, secret, body, &[]).await?;
        let status = response.status();
        let bytes = tokio::time::timeout(self.timeout, response.into_body().collect())
            .await
            .map_err(|_| (4, format!("{}: the response body stalled", self.origin)))?
            .map_err(|e| {
                (
                    4,
                    format!("{}: {}", self.origin, crate::cli::error_chain(&e)),
                )
            })?
            .to_bytes();
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            (
                10,
                format!(
                    "{} answered {} with a body that is not a control envelope",
                    self.origin, status
                ),
            )
        })?;
        // The pre-principal answer carries no version member by
        // design: a refused credential is exit 5, not exit 10.
        if status == StatusCode::UNAUTHORIZED && value["error"]["type"] == "authentication_error" {
            return Ok((status, value));
        }
        let served = value.get("control_api_version").and_then(Value::as_u64);
        if served != Some(1) {
            return Err((
                10,
                format!(
                    "{} serves control API version {}; this build speaks 1",
                    self.origin,
                    served.map_or("none".to_string(), |v| v.to_string())
                ),
            ));
        }
        Ok((status, value))
    }
}

/// The failure mapping of an unsuccessful client read (the exit codes a
/// client credential can produce).
pub fn client_failure(status: StatusCode, value: &Value) -> (i32, String) {
    let message = value["error"]["message"]
        .as_str()
        .unwrap_or("the server refused the request")
        .to_string();
    let code = match value["error"]["code"].as_str().unwrap_or("") {
        "operator_required"
        | "insecure_channel"
        | "loopback_required"
        | "cross_origin_control"
        | "enrollment_claim_refused" => 5,
        "not_found" | "account_not_found" | "client_not_found" | "route_not_found" => 6,
        "internal_error" | "unavailable" => 10,
        _ => match status.as_u16() {
            401 | 403 => 5,
            404 => 6,
            s if s >= 500 => 10,
            _ => 5,
        },
    };
    (code, message)
}

/// The JSON `result` of an engineer verb (`client_result`).
pub fn client_result(installation: &ClientInstallation) -> Value {
    json!({
        "client_id": installation.client_id,
        "display_name": installation.display_name,
        "origins": { "base_url": installation.base_url, "proxy": installation.proxy },
        "ca_fingerprint": installation.ca_fingerprint,
        "files": client_files(installation),
    })
}

fn client_files(installation: &ClientInstallation) -> Vec<String> {
    let mut files = vec![
        installation
            .directory
            .join("client.toml")
            .display()
            .to_string(),
        installation
            .directory
            .join("client-secret")
            .display()
            .to_string(),
    ];
    files.push(installation.directory.join("ca.pem").display().to_string());
    if let Some(anchor) = installation.base_url_ca() {
        files.push(anchor.display().to_string());
    }
    files
}

// ------------------------------------------------------------------ the client reads

/// One catalogue entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogueEntry {
    pub handle: String,
    pub display_name: String,
    pub selectable: bool,
    pub five_hour: Option<f64>,
    pub weekly: Option<f64>,
}

impl CatalogueEntry {
    fn from_value(value: &Value) -> Option<Self> {
        Some(Self {
            handle: value["handle"].as_str()?.to_string(),
            display_name: value["display_name"].as_str()?.to_string(),
            selectable: value["selectable"].as_bool()?,
            five_hour: value["rate_limits"]["five_hour"].as_f64(),
            weekly: value["rate_limits"]["weekly"].as_f64(),
        })
    }
}

/// RFC 3986 unreserved characters pass; every other byte is `%XX`.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

async fn client_read(
    installation: &ClientInstallation,
    secret: &str,
    path: &str,
    timeout: Duration,
) -> Result<Value, (i32, String)> {
    let request =
        ClientRequest::for_installation(installation, timeout, None).map_err(|e| (1, e))?;
    let (status, body) = request.call(Method::GET, path, Some(secret), None).await?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(client_failure(status, &body))
    }
}

/// The client snapshot, with `session` when a session id is given; the
/// server's identity pin is kept from it. `Err` carries the exit code:
/// 4 unreachable, 5 refused, 10 incompatible.
pub async fn snapshot(
    installation: &ClientInstallation,
    secret: &str,
    session: Option<&str>,
    timeout: Duration,
) -> Result<Value, (i32, String)> {
    let mut path = "/control/v1/client/status".to_string();
    if let Some(session) = session {
        path.push_str("?session_id=");
        path.push_str(&percent_encode(session));
    }
    let snapshot = client_read(installation, secret, &path, timeout).await?;
    keep_identity(installation, &snapshot);
    Ok(snapshot)
}

/// The status-line snapshot adds only the two account rate-limit windows.
pub async fn statusline_snapshot(
    installation: &ClientInstallation,
    secret: &str,
    session: Option<&str>,
    timeout: Duration,
) -> Result<Value, (i32, String)> {
    let mut path = "/control/v1/client/status?rate_limits=true".to_string();
    if let Some(session) = session {
        path.push_str("&session_id=");
        path.push_str(&percent_encode(session));
    }
    client_read(installation, secret, &path, timeout).await
}

/// The catalogue, in the server's order.
pub async fn catalogue(
    installation: &ClientInstallation,
    secret: &str,
    timeout: Duration,
) -> Result<Vec<CatalogueEntry>, (i32, String)> {
    let body = client_read(installation, secret, "/control/v1/client/accounts", timeout).await?;
    body["accounts"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(CatalogueEntry::from_value)
                .collect()
        })
        .ok_or_else(|| {
            (
                10,
                "the catalogue answer carries no accounts array".to_string(),
            )
        })
}

/// The read-only resolve: the entry, or 6 (nothing matched) /
/// 7 (ambiguous, the message carries the server's safe display names).
pub async fn resolve(
    installation: &ClientInstallation,
    secret: &str,
    reference: &str,
    timeout: Duration,
) -> Result<CatalogueEntry, (i32, String)> {
    let path = format!(
        "/control/v1/client/accounts/resolve?reference={}",
        percent_encode(reference)
    );
    let request =
        ClientRequest::for_installation(installation, timeout, None).map_err(|e| (1, e))?;
    let (status, body) = request.call(Method::GET, &path, Some(secret), None).await?;
    if status.is_success() {
        return CatalogueEntry::from_value(&body["account"])
            .ok_or_else(|| (10, "the resolve answer carries no account".to_string()));
    }
    let message = body["error"]["message"]
        .as_str()
        .unwrap_or("the server refused the reference")
        .to_string();
    match body["error"]["code"].as_str().unwrap_or("") {
        "account_not_found" => Err((6, format!("no account matches {reference:?}"))),
        "ambiguous_account_reference" => Err((7, message)),
        _ => Err(client_failure(status, &body)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_toml_holds_the_installation_facts() {
        let toml = client_toml("mac-1", "Mac One", "http://h:1", None, None, None, &[]);
        let parsed: Table = toml.parse().expect("parses");
        assert_eq!(parsed["client_id"], toml::Value::String("mac-1".into()));
        assert!(parsed.get("mode").is_none());
        assert_eq!(parsed["proxy_url"], toml::Value::String(String::new()));
        assert_eq!(parsed["no_proxy"], toml::Value::Array(vec![]));
    }
}
