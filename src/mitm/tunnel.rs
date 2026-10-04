//! CONNECT tunnelled targets: the self-target refusal, the route through a
//! corporate proxy and the byte relay. The absolute-form forwarder shares the
//! target classification.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONNECTION;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;

use crate::audit::{Principal, PrincipalKind};
use crate::data_plane::connect::{Connector, Wire, enable_keepalive};
use crate::data_plane::envelope;
use crate::data_plane::intent::{self, Intent};
use crate::data_plane::principal;
use crate::data_plane::relay::ResponseBody;
use crate::mitm::ca::{Ca, INTERCEPT_NAMES};
use crate::mitm::counters::Kind;
use crate::mitm::tls;
use crate::provider::anthropic::error_type;
use crate::server::Server;

/// No connection to the target within 30 s → 504. Not configurable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The route a tunnelled target takes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Path {
    Direct,
    ViaProxy,
}

/// A target the proxy refuses before any connection, or cannot
/// reach: the status and the message of the refusal.
pub(crate) type Refusal = (StatusCode, String);

/// Who the proxy caller is, and what its user field asked for.
pub struct Credential {
    /// The principal the exchanges inside are audited under.
    pub principal: Principal,
    /// The user field exactly as received, empty when absent.
    pub user_field: String,
    /// The decoded intent, resolved against the pool only inside the
    /// tunnel, so a pin naming no account is a 404 per request.
    /// `Err` is a user field that is neither empty nor one token —
    /// the tunnel still opens, every request inside is a 400.
    pub intent: Result<Option<Intent>, String>,
    /// What a re-check per request resolves against.
    authenticator: Authenticator,
}

/// How the principal is re-validated inside an open tunnel: a
/// loopback caller stays the loopback operator, a presented secret is
/// re-resolved, so revocation and rotation land mid-tunnel.
enum Authenticator {
    Loopback,
    Secret(String),
}

/// What the `CONNECT` fixes for the tunnel's whole life. The target
/// names decide the authority check inside it.
pub struct Tunnel {
    pub credential: Credential,
    /// The authority exactly as the client sent it, for the log lines.
    pub target: String,
    /// The intercepted name, lower-cased and without a trailing dot.
    pub host: String,
}

impl Credential {
    /// The principal as it stands *now*. `None` is a
    /// secret that has been revoked or rotated since the `CONNECT`.
    pub fn principal_now(&self, server: &Server) -> Option<Principal> {
        match &self.authenticator {
            Authenticator::Loopback => Some(self.principal.clone()),
            Authenticator::Secret(secret) => resolve_secret(&server.registry(), secret),
        }
    }
}

/// The Basic password is a client secret or the
/// remote-operator secret, and nothing else.
fn resolve_secret(registry: &crate::registry::Registry, secret: &str) -> Option<Principal> {
    if let Some(id) = registry.client_by_secret(secret) {
        Some(Principal {
            kind: PrincipalKind::Client,
            id: Some(id),
        })
    } else if registry.operator_by_secret(secret) {
        Some(Principal {
            kind: PrincipalKind::Operator,
            id: None,
        })
    } else {
        None
    }
}

/// The value of `proxy-authorization` when it is `Basic <base64>`
/// over `<user>:<password>`; `None` for any other scheme, padding or not.
fn parse_basic(value: &str) -> Option<(String, String)> {
    use base64::Engine as _;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    if password.is_empty() {
        return None;
    }
    Some((user.to_string(), password.to_string()))
}

/// The credential gate both proxy forms share. The Basic
/// password resolves against the registry — operator slot first, then the
/// active client entries; a loopback caller without a credential is the
/// loopback operator, one that presents a credential is resolved normally
/// and refused when invalid, never promoted. The user field is an
/// intent: empty or exactly one token parses here; anything else is
/// an `Err` — it authenticates, and every request inside the tunnel
/// is a 400 instead (the 407 covers only the Basic credential
/// itself). Its reference is resolved only inside the tunnel.
pub(crate) fn authorize(
    server: &Server,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<Credential, Box<Response<ResponseBody>>> {
    let loopback = principal::is_loopback_peer(peer);
    let credential = match headers.get("proxy-authorization") {
        None => {
            if !loopback {
                return Err(proxy_refusal(peer));
            }
            Credential {
                principal: principal::resolve(&server.registry(), peer, headers).unwrap_or(
                    Principal {
                        kind: PrincipalKind::Loopback,
                        id: None,
                    },
                ),
                user_field: String::new(),
                intent: Ok(None),
                authenticator: Authenticator::Loopback,
            }
        }
        Some(value) => {
            let Some((user, password)) = value.to_str().ok().and_then(parse_basic) else {
                return Err(proxy_refusal(peer));
            };
            // A credential a loopback caller presents is resolved
            // normally and refused when invalid, never promoted.
            let Some(principal) = resolve_secret(&server.registry(), &password) else {
                return Err(proxy_refusal(peer));
            };
            let intent = match user.as_str() {
                "" => Ok(None),
                token => intent::parse_token(token)
                    .map(Some)
                    .map_err(|e| e.replace("x-jaynshare-account", "the proxy URL's user field")),
            };
            Credential {
                principal,
                user_field: user,
                intent,
                authenticator: Authenticator::Secret(password),
            }
        }
    };
    Ok(credential)
}

/// The 407 both proxy forms answer a bad credential with.
fn proxy_refusal(peer: SocketAddr) -> Box<Response<ResponseBody>> {
    let mut response = refusal(
        peer,
        "",
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "the proxy credential is missing or invalid: this is a client secret, not an Anthropic key",
    );
    response.headers_mut().insert(
        "proxy-authenticate",
        HeaderValue::from_static("Basic realm=\"jaynshare\""),
    );
    Box::new(response)
}

/// Every refusal leaves one log line with the client address and the
/// target; successful tunnels leave none.
pub(crate) fn refusal(
    peer: SocketAddr,
    target: &str,
    status: StatusCode,
    message: &str,
) -> Response<ResponseBody> {
    tracing::info!(
        event = "proxy_refused",
        peer = %peer,
        target,
        status = status.as_u16(),
        "proxy target refused"
    );
    let mut response = envelope::proxy_response(status, error_type::PROXY, message);
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

/// An address rule, and `::ffff:a.b.c.d` is the same address as
/// `a.b.c.d`: the connector reaches the IPv4 host either way, so the
/// classification must see the mapped form. (`Ipv6Addr::is_loopback` is
/// false for `::ffff:127.0.0.1`.) `to_ipv4_mapped` rather than
/// `to_ipv4`: the latter also converts IPv4-compatible addresses and
/// `::1` itself, which have their own classes.
pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        ip => ip,
    }
}

/// Is `ip` a loopback address or an address of the proxy host itself?
/// The host set holds only non-loopback addresses; the loopback class is
/// decided first so it can take the override exception.
fn self_target(host_addresses: &[IpAddr], ip: IpAddr) -> Option<bool> {
    let ip = canonical_ip(ip);
    if ip.is_loopback() {
        Some(true)
    } else if ip.is_unspecified() || host_addresses.contains(&ip) {
        Some(false)
    } else {
        None
    }
}

/// The verdict over a resolved address set: forbidden unless the override
/// active-exception allows loopback (the acceptance harness stages
/// tunnelled services on loopback; the self-target rule's exception).
fn verdict(
    server: &Server,
    addresses: &[IpAddr],
    host_addresses: &[IpAddr],
) -> Result<Path, Refusal> {
    let forbidden =
        "the target is the proxy host itself and would reach the exempted loopback plane";
    // The host's own non-loopback addresses stay refused under the override.
    if addresses
        .iter()
        .map(|&ip| canonical_ip(ip))
        .any(|ip| ip.is_unspecified() || host_addresses.contains(&ip))
    {
        return Err((StatusCode::FORBIDDEN, forbidden.to_owned()));
    }
    if addresses
        .iter()
        .map(|&ip| canonical_ip(ip))
        .any(|ip| ip.is_loopback())
    {
        if server.upstream.override_active() {
            return Ok(Path::Direct);
        }
        return Err((StatusCode::FORBIDDEN, forbidden.to_owned()));
    }
    Ok(Path::Direct)
}

/// The classification of one target host, then the route.
/// Literal targets are classified directly; names are resolved by the proxy
/// host on the direct route.
pub(crate) async fn route_target(
    server: &Server,
    host_addresses: &[IpAddr],
    host: &str,
    port: u16,
) -> Result<Path, Refusal> {
    let settings = &server.config().config.data_plane;
    let via_proxy = match &settings.corporate_proxy_url {
        Some(_) => !no_proxy_match(&settings.no_proxy, host),
        None => false,
    };
    let literal = host.parse::<IpAddr>().ok();
    if let Some(ip) = literal {
        return match self_target(host_addresses, ip) {
            Some(true) if server.upstream.override_active() => Ok(Path::Direct),
            Some(_) => Err((
                StatusCode::FORBIDDEN,
                "the target is the proxy host itself and would reach the exempted loopback plane"
                    .to_owned(),
            )),
            None if via_proxy => Ok(Path::ViaProxy),
            None => Ok(Path::Direct),
        };
    }
    if via_proxy {
        // A name behind a corporate proxy is not resolved here — the
        // corporate proxy resolves it (it sees names and ports only),
        // so the self-target name check covers the direct route only; a
        // proxy-side resolver policy is the upgrade path.
        return Ok(Path::ViaProxy);
    }
    let addresses = resolve(host, port).await?;
    verdict(server, &addresses, host_addresses)
}

/// Name resolution failure is a 502 before any connection.
async fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, Refusal> {
    tokio::net::lookup_host((host, port))
        .await
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("the target {host}:{port} cannot be resolved: {e}"),
            )
        })
}

/// Exact DNS names or leading-dot suffixes, case-insensitive, one
/// trailing dot stripped; IP literals never match.
fn no_proxy_match(entries: &[String], host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    entries.iter().any(|entry| {
        let entry = entry.trim_end_matches('.').to_ascii_lowercase();
        match entry.strip_prefix('.') {
            Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            None => host == entry,
        }
    })
}

/// The authority-form string of a target, IPv6 literals bracketed.
fn target_string(host: &str, port: u16) -> String {
    match host.parse::<Ipv6Addr>() {
        Ok(_) => format!("[{host}]:{port}"),
        Err(_) => format!("{host}:{port}"),
    }
}

/// The target host as [`http::Uri::host`] reports it, minus IPv6 brackets.
/// `Uri::host` gives an IPv6 literal in the bracketed authority form
/// (`[::1]`); the self-target check is an address rule and [`open`]'s `target_string`
/// re-brackets, so the brackets come off here.
pub(crate) fn target_host(uri: &http::Uri) -> String {
    let host = uri.host().unwrap_or_default();
    match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => inner.to_owned(),
        None => host.to_owned(),
    }
}

/// Connect to the target first — direct, or CONNECT through the
/// corporate proxy — within the 30 s timeout; the caller answers 200 only after.
pub(crate) async fn open(
    path: Path,
    connector: Option<&Connector>,
    host: &str,
    port: u16,
) -> Result<Wire, Refusal> {
    let target = target_string(host, port);
    let attempt = async {
        match path {
            Path::ViaProxy => {
                let connector =
                    connector.expect("a corporate proxy is configured for the proxy route");
                connector.tunnel(&target).await
            }
            Path::Direct => tokio::net::TcpStream::connect((host, port))
                .await
                .map(|tcp| {
                    enable_keepalive(&tcp);
                    Wire::Plain(tcp)
                })
                .map_err(|e| format!("the target {target} is unreachable: {e}")),
        }
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
        Ok(Ok(wire)) => Ok(wire),
        Ok(Err(message)) => Err((StatusCode::BAD_GATEWAY, message)),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            format!("no connection to {target} within 30 s"),
        )),
    }
}

/// The whole CONNECT path, with the refusal classes counted once at the
/// exit — a `200` counts nothing here; the tunnel counts itself.
pub(crate) async fn handle(
    server: Arc<Server>,
    connector: Option<Arc<Connector>>,
    host_addresses: Arc<[IpAddr]>,
    ca: Option<Arc<Ca>>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let response = connect(
        Arc::clone(&server),
        connector,
        host_addresses,
        ca,
        peer,
        request,
    )
    .await;
    server.mitm.record_connect(response.status());
    response
}

/// Authorize, classify, connect, then 200 and the byte relay. Intercepted
/// names never reach [`route_target`].
async fn connect(
    server: Arc<Server>,
    connector: Option<Arc<Connector>>,
    host_addresses: Arc<[IpAddr]>,
    ca: Option<Arc<Ca>>,
    peer: SocketAddr,
    mut request: Request<Incoming>,
) -> Response<ResponseBody> {
    let target = request
        .uri()
        .authority()
        .map(ToString::to_string)
        .unwrap_or_default();
    let upgrade = hyper::upgrade::on(&mut request);
    let credential = match authorize(&server, peer, request.headers()) {
        Ok(credential) => credential,
        Err(response) => return *response,
    };
    let host = target_host(request.uri());
    let port = request.uri().port_u16().unwrap_or(443);
    if host.is_empty() {
        return refusal(
            peer,
            &target,
            StatusCode::BAD_REQUEST,
            "the CONNECT target has no host",
        );
    }
    // The intercept set, matched as the client sent the name, port
    // 443 only, never resolved; an IP literal is always tunnelled.
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    if port == 443
        && host.parse::<IpAddr>().is_err()
        && INTERCEPT_NAMES.iter().any(|set| *set == name)
    {
        let tunnel = Tunnel {
            credential,
            target: target.clone(),
            host: name,
        };
        return intercepted(server, peer, tunnel, ca, upgrade);
    }
    let path = match route_target(&server, &host_addresses, &host, port).await {
        Ok(path) => path,
        Err((status, message)) => return refusal(peer, &target, status, &message),
    };
    match open(path, connector.as_deref(), &host, port).await {
        Ok(wire) => {
            // The 200 only now; the relay is the tunnel's whole life —
            // bytes unchanged, half-closes propagated, no idle limit, and
            // no audit record and no log line on any of it.
            tokio::spawn(async move {
                let _open = server.mitm.open(Kind::Tunnelled);
                if let Ok(upgraded) = upgrade.await {
                    let mut client = hyper_util::rt::TokioIo::new(upgraded);
                    let mut wire = wire;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut wire).await;
                }
            });
            Response::new(empty_body())
        }
        Err((status, message)) => refusal(peer, &target, status, &message),
    }
}

/// An intercepted name is never tunnelled — the `200` is followed
/// by our own TLS server on the bytes. The CA the tunnel takes here is the one
/// it keeps, so a rotation under it does not change its leaf.
fn intercepted(
    server: Arc<Server>,
    peer: SocketAddr,
    tunnel: Tunnel,
    ca: Option<Arc<Ca>>,
    upgrade: hyper::upgrade::OnUpgrade,
) -> Response<ResponseBody> {
    match ca {
        Some(ca) => {
            let tunnel = Arc::new(tunnel);
            tokio::spawn(async move {
                let _open = server.mitm.open(Kind::Intercepted);
                if let Ok(upgraded) = upgrade.await {
                    tls::serve(server, ca, tunnel, peer, upgraded).await;
                }
            });
            Response::new(empty_body())
        }
        // Unusable trust material keeps serving, intercepted targets answer 503.
        None => refusal(
            peer,
            &tunnel.target,
            StatusCode::SERVICE_UNAVAILABLE,
            "the CA trust material is unusable; intercepted targets cannot be served",
        ),
    }
}

pub(crate) fn empty_body() -> ResponseBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

/// The request-side hop-by-hop rule: connection-named headers plus the
/// fixed set, `proxy-connection` and `proxy-authorization` — and nothing
/// else, so the caller's own headers go through unchanged.
pub(crate) fn strip_request_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<http::HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(str::trim).map(str::to_ascii_lowercase))
        .filter_map(|n| n.parse().ok())
        .collect();
    for name in named.into_iter().chain([
        http::header::CONNECTION,
        http::HeaderName::from_static("keep-alive"),
        http::header::TRANSFER_ENCODING,
        http::header::TE,
        http::header::TRAILER,
        http::header::UPGRADE,
        http::HeaderName::from_static("proxy-connection"),
        http::HeaderName::from_static("proxy-authenticate"),
        http::HeaderName::from_static("proxy-authorization"),
    ]) {
        headers.remove(&name);
    }
}

/// No proxy metadata reaches a decoded destination — the intent
/// header is removed on every decoded request, intercepted or absolute-form,
/// and cannot add to or replace the tunnel's fixed intent.
pub(crate) fn strip_proxy_metadata(headers: &mut HeaderMap) {
    headers.remove(intent::X_JAYNSHARE_ACCOUNT);
}

#[cfg(test)]
mod tests {
    use super::parse_basic;

    /// `Basic <base64("user:pass")>`, padded, unpadded, and the
    /// shapes that are not it at all.
    #[test]
    fn parse_basic_accepts_only_well_formed_basic() {
        assert_eq!(
            parse_basic("Basic dXNlcjpwYXNz"),
            Some(("user".to_string(), "pass".to_string()))
        );
        assert_eq!(
            parse_basic("Basic dXNlcjpwYXNzd29yZA=="),
            Some(("user".to_string(), "password".to_string()))
        );
        assert_eq!(parse_basic("Bearer x"), None);
        assert_eq!(parse_basic("Basic dXNlcjBwYXNz"), None);
    }
}
