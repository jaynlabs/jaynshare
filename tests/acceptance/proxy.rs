//! The proxy listener, tunnelled targets and interception.
//!
//! The fixtures are: a raw `CONNECT` client, because nothing in the suite's
//! HTTP stack will hand back the socket a tunnel is made of, and a loopback
//! echo target reached under the loopback exception. Two more ride beside
//! them — a corporate proxy that answers itself, so the tunnelled set can
//! be named without leaving loopback, and a plain-HTTP target for the
//! absolute form.
//!
//! What stays out for the interception tests: everything an intercepted
//! target does *after* its handshake — the TLS server, the leaf, the probe
//! host. These tests assert only which class a target falls in.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::harness::{
    Answer, Arc, Bytes, Command, Duration, Full, Instance, Instant, Method, Mutex, Path, PathBuf,
    Request, Setup, SocketAddr, StdTcpListener, StdTcpStream, Stdio, TcpListener, TcpStream,
    TokioIo, Value, binary, collect_answer, enroll, fs, haiku_prompt, json, messages,
    non_loopback_addr, private_dir, reserve_port, scratch, send, write_private,
};

/// MITM mode on, everything else at the suite's defaults.
fn mitm_on() -> Setup {
    Setup {
        mitm: true,
        ..Setup::default()
    }
}

/// The proxy listener of an instance the setup turned the mode on for.
fn proxy_addr(instance: &Instance) -> SocketAddr {
    instance
        .mitm_addr
        .expect("the setup asked for the proxy listener")
}

// ------------------------------------------------------------------ the echo target

/// What the echo writes once its peer half-closes, before closing its own
/// side: a tunnel that propagates the half-close shows this to the
/// client, one that does not shows nothing at all.
const HALF_CLOSE_MARK: &[u8] = b"<half-close>";

/// A loopback TCP echo target. Every byte comes back unchanged, so a
/// tunnel's transparency is assertable without an intercepted host.
struct Echo {
    addr: SocketAddr,
    opened: Arc<AtomicUsize>,
}

impl Echo {
    async fn start() -> Echo {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
        let addr = listener.local_addr().expect("echo address");
        let opened = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&opened);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 64 * 1024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => {
                                if stream.write_all(&buffer[..read]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    let _ = stream.write_all(HALF_CLOSE_MARK).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Echo { addr, opened }
    }

    /// The authority-form target a `CONNECT` names it by.
    fn target(&self) -> String {
        self.addr.to_string()
    }

    /// How many connections reached it — proves a refusal was made before
    /// any connection.
    fn opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }
}

// ------------------------------------------------------------------ the CONNECT client

/// One `CONNECT` and what came back: the proxy's answer, and — when it was a
/// `200` — the socket, which is from then on the tunnel itself.
struct Tunnel {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    stream: TcpStream,
}

impl Tunnel {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("the refusal body is JSON ({e}): {}", self.body))
    }

    /// Writes `payload` into the tunnel and reads exactly as many bytes back.
    async fn round_trip(&mut self, payload: &[u8]) -> Vec<u8> {
        self.stream
            .write_all(payload)
            .await
            .expect("write into the tunnel");
        let mut back = vec![0u8; payload.len()];
        self.stream
            .read_exact(&mut back)
            .await
            .expect("read the echo back out of the tunnel");
        back
    }

    /// Half-closes the client side and drains what the far end sends before it
    /// closes its own.
    async fn half_close(&mut self) -> Vec<u8> {
        self.stream
            .shutdown()
            .await
            .expect("half-close the client side");
        let mut rest = Vec::new();
        self.stream
            .read_to_end(&mut rest)
            .await
            .expect("drain the tunnel");
        rest
    }
}

/// Reads a response head one byte at a time, so nothing of a tunnel's first
/// bytes is swallowed with it.
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

fn parse_head(head: &str) -> (u16, Vec<(String, String)>) {
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default().to_owned();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in {head:?}"));
    let headers = lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            (name.trim().to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    (status, headers)
}

async fn read_counted_body(stream: &mut TcpStream, headers: &[(String, String)]) -> String {
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        stream
            .read_exact(&mut body)
            .await
            .expect("read the counted body");
    }
    String::from_utf8_lossy(&body).into_owned()
}

/// the `CONNECT` client. The head is written by hand: describes
/// exactly what a client puts on the wire, including nothing at all.
async fn connect_through(proxy: SocketAddr, target: &str, credential: Option<&str>) -> Tunnel {
    let mut stream = TcpStream::connect(proxy)
        .await
        .expect("reach the proxy listener");
    let mut head = format!("CONNECT {target} HTTP/1.1\r\nhost: {target}\r\n");
    if let Some(credential) = credential {
        head.push_str(&format!("proxy-authorization: {credential}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write the CONNECT");
    let raw = read_head(&mut stream).await;
    let (status, headers) = parse_head(&raw);
    let body = match status {
        200 => String::new(),
        _ => read_counted_body(&mut stream, &headers).await,
    };
    Tunnel {
        status,
        headers,
        body,
        stream,
    }
}

// ------------------------------------------------------------------ the intercepted tunnel

/// The CA certificate the instance generated (the name), as a client
/// imports it: `NODE_EXTRA_CA_CERTS` for Claude Code, a root store here.
pub(crate) fn ca_file(instance: &Instance) -> PathBuf {
    instance.root.join("state").join("mitm-ca.pem")
}

/// What a client offers at the handshake. The default is what Claude Code
/// does — the CA trusted, both protocols, SNI sent, both TLS versions
/// available — and a row varies one thing at a time from it.
pub(crate) struct Offer {
    /// `false` is the row: a client that does not trust the CA.
    trust_ca: bool,
    /// The ALPN protocols offered; empty sends no ALPN extension.
    alpn: Vec<Vec<u8>>,
    /// `None` leaves rustls's default set (TLS 1.2 and 1.3).
    versions: Option<&'static [&'static rustls::SupportedProtocolVersion]>,
    /// the leaf is the CONNECT target's, so a client sending no SNI
    /// still gets it.
    sni: bool,
}

impl Default for Offer {
    fn default() -> Offer {
        Offer {
            trust_ca: true,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            versions: None,
            sni: true,
        }
    }
}

impl Offer {
    pub(crate) fn alpn(protocols: &[&str]) -> Offer {
        Offer {
            alpn: protocols.iter().map(|p| p.as_bytes().to_vec()).collect(),
            ..Offer::default()
        }
    }

    /// One version only, so the row proves each is accepted on its own.
    fn tls12() -> Offer {
        Offer {
            versions: Some(TLS12_ONLY),
            ..Offer::default()
        }
    }

    fn tls13() -> Offer {
        Offer {
            versions: Some(TLS13_ONLY),
            ..Offer::default()
        }
    }
}

const TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// An intercepted tunnel from the client's side: what the handshake settled
/// and a sender for the requests inside it.
pub(crate) struct Intercepted {
    /// The negotiated protocol, `None` when the client offered no ALPN.
    alpn: Option<String>,
    /// `TLSv1.2` or `TLSv1.3`, as the proxy's own debug line names it.
    version: String,
    /// The chain the proxy presented; the leaf is the first certificate.
    presented: Vec<rustls_pki_types::CertificateDer<'static>>,
    sender: Sender,
}

enum Sender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

impl Intercepted {
    /// One request inside the tunnel. The authority is the request's own, so
    /// a row can send a foreign one.
    pub(crate) async fn send(&mut self, request: Request<Full<Bytes>>) -> Answer {
        let response = match &mut self.sender {
            Sender::H1(sender) => sender.send_request(request).await,
            Sender::H2(sender) => sender.send_request(request).await,
        };
        collect_answer(response.expect("send inside the intercepted tunnel")).await
    }

    /// A second handle on the same HTTP/2 connection, so a row can
    /// hold several streams open at once. Panics on an HTTP/1.1 tunnel,
    /// which has no concurrent streams to open.
    fn stream(&self) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
        match &self.sender {
            Sender::H2(sender) => sender.clone(),
            Sender::H1(_) => panic!("this tunnel negotiated HTTP/1.1"),
        }
    }

    /// The shape Claude Code puts inside a tunnel: origin-form path, the
    /// authority in `host`, the client's own credential headers included
    /// the proxy removes them unread.
    pub(crate) fn request(
        &self,
        method: Method,
        authority: &str,
        path: &str,
        body: &str,
    ) -> Request<Full<Bytes>> {
        let uri = match &self.sender {
            // HTTP/2 carries the authority in `:authority`, which hyper reads
            // off an absolute URI.
            Sender::H2(_) => format!("https://{authority}{path}"),
            Sender::H1(_) => path.to_string(),
        };
        Request::builder()
            .method(method)
            .uri(uri)
            .header("host", authority)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body.to_owned())))
            .expect("the in-tunnel request builds")
    }
}

/// The client config a row's [`Offer`] describes, with the instance's own CA
/// as the only root.
fn intercept_config(ca: &Path, offer: &Offer) -> Arc<rustls::ClientConfig> {
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    if offer.trust_ca {
        let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(ca)
            .expect("the CA file the instance wrote")
            .collect::<Result<_, _>>()
            .expect("the CA file parses");
        roots.add_parsable_certificates(certs);
    }
    let mut config = match offer.versions {
        Some(versions) => rustls::ClientConfig::builder_with_protocol_versions(versions),
        None => rustls::ClientConfig::builder(),
    }
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = offer.alpn.clone();
    config.enable_sni = offer.sni;
    Arc::new(config)
}

/// `CONNECT` an intercepted name, then meet the proxy's own TLS server on the
/// tunnel bytes. `Err` carries the handshake failure itself — these
/// tests are about the failure, not about what follows it.
pub(crate) async fn intercept(
    proxy: SocketAddr,
    target: &str,
    credential: Option<&str>,
    ca: &Path,
    offer: Offer,
) -> Result<Intercepted, String> {
    let tunnel = connect_through(proxy, target, credential).await;
    assert_eq!(
        tunnel.status, 200,
        "the CONNECT was refused: {}",
        tunnel.body
    );
    handshake(tunnel.stream, target, ca, offer).await
}

/// The TLS half of [`intercept`], over bytes already inside a tunnel.
async fn handshake(
    stream: TcpStream,
    target: &str,
    ca: &Path,
    offer: Offer,
) -> Result<Intercepted, String> {
    let name = target.rsplit_once(':').map_or(target, |(host, _)| host);
    let connector = tokio_rustls::TlsConnector::from(intercept_config(ca, &offer));
    let name: rustls_pki_types::ServerName<'static> = name
        .to_owned()
        .try_into()
        .expect("the CONNECT target is a server name");
    let stream = connector
        .connect(name, stream)
        .await
        .map_err(|e| e.to_string())?;
    let (alpn, version, presented) = {
        let (_, connection) = stream.get_ref();
        (
            connection
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
            match connection.protocol_version() {
                Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
                Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
                other => format!("{other:?}"),
            },
            connection
                .peer_certificates()
                .map(|chain| chain.to_vec())
                .unwrap_or_default(),
        )
    };
    let io = TokioIo::new(stream);
    let sender = if alpn.as_deref() == Some("h2") {
        let (sender, connection) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Sender::H2(sender)
    } else {
        let (sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Sender::H1(sender)
    };
    Ok(Intercepted {
        alpn,
        version,
        presented,
        sender,
    })
}

// ------------------------------------------------------------------ absolute form

struct Forwarded {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Forwarded {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("the envelope is JSON ({e}): {}", self.body))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One absolute-form request on the proxy listener: `GET http://host/path`,
/// the form the proxy URL makes Claude Code use for plain HTTP.
async fn absolute_form(
    proxy: SocketAddr,
    method: &str,
    target: &str,
    extra: &[(&str, &str)],
    body: Option<&str>,
) -> Forwarded {
    let mut stream = TcpStream::connect(proxy)
        .await
        .expect("reach the proxy listener");
    let authority = target.split('/').nth(2).unwrap_or_default().to_owned();
    let mut head = format!("{method} {target} HTTP/1.1\r\nhost: {authority}\r\n");
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!(
            "content-type: application/json\r\ncontent-length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("connection: close\r\n\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write the request");
    if let Some(body) = body {
        stream
            .write_all(body.as_bytes())
            .await
            .expect("write the body");
    }
    let raw = read_head(&mut stream).await;
    let (status, headers) = parse_head(&raw);
    let mut rest = Vec::new();
    stream
        .read_to_end(&mut rest)
        .await
        .expect("read the response");
    Forwarded {
        status,
        headers,
        body: String::from_utf8_lossy(&rest).into_owned(),
    }
}

// ------------------------------------------------------------------ the corporate proxy

/// the corporate proxy, as far as the test can see it: it records every
/// head it is handed and then answers itself — a `CONNECT` becomes an echo
/// tunnel, an absolute-form request a fixed. It connects nowhere, so a
/// scenario may name a public host (the tunnelled set) and still never
/// leave the loopback plane.
struct Chain {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

/// What a chained tunnel carries once the corporate proxy has accepted it:
/// opaque bytes to echo, or one HTTP exchange, recorded like the head above
/// it. A plain-HTTP target is not a tunnel at all — sends it to the
/// proxy in absolute form, which the non-`CONNECT` branch below answers.
#[derive(Clone, Copy)]
enum Inside {
    Opaque,
    Http,
}

impl Chain {
    async fn start() -> Chain {
        Chain::start_carrying(Inside::Opaque).await
    }

    async fn start_carrying(inside: Inside) -> Chain {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("corporate proxy bind");
        let addr = listener.local_addr().expect("corporate proxy address");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&heads);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let head = read_head(&mut stream).await;
                    recorded
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(head.clone());
                    if !head.starts_with("CONNECT ") {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\
                                  content-type: text/plain\r\nconnection: close\r\n\r\nchained",
                            )
                            .await;
                        return;
                    }
                    if stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if let Inside::Http = inside {
                        let inner = read_head(&mut stream).await;
                        recorded
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(inner);
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\
                                  content-type: text/plain\r\nconnection: close\r\n\r\nchained",
                            )
                            .await;
                        return;
                    }
                    let mut buffer = vec![0u8; 64 * 1024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => {
                                if stream.write_all(&buffer[..read]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    let _ = stream.write_all(HALF_CLOSE_MARK).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Chain { addr, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The request line of every head it was handed, oldest first.
    fn request_lines(&self) -> Vec<String> {
        self.heads()
            .iter()
            .map(|head| head.lines().next().unwrap_or_default().to_owned())
            .collect()
    }

    /// The `[data_plane]` lines that point the product at it.
    fn settings(&self, no_proxy: &[&str]) -> String {
        let entries = no_proxy
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "corporate_proxy_url = \"http://{}\"\nno_proxy = [{entries}]\n",
            self.addr
        )
    }
}

// A plain-HTTP target

/// The target of an absolute-form forward: it records the request line, the
/// headers and the body exactly as they arrive, and answers a fixed.
struct HttpTarget {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

impl HttpTarget {
    async fn start() -> HttpTarget {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("http target bind");
        let addr = listener.local_addr().expect("http target address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let head = read_head(&mut stream).await;
                    let length = head
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut body = vec![0u8; length];
                    if length > 0 && stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    recorded
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((head, String::from_utf8_lossy(&body).into_owned()));
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 201 Created\r\ncontent-length: 9\r\n\
                              content-type: text/plain\r\nconnection: close\r\n\r\nforwarded",
                        )
                        .await;
                });
            }
        });
        HttpTarget { addr, seen }
    }

    fn last(&self) -> (String, String) {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last()
            .cloned()
            .expect("the target was reached")
    }

    fn calls(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ------------------------------------------------------------------ shared assertions

/// A refusal carries the envelope with `proxy_error`
/// and closes the connection it refused on.
fn assert_proxy_refusal(status: u16, expected: u16, connection: Option<&str>, body: &Value) {
    assert_eq!(status, expected, "the refusal's status: {body}");
    assert_eq!(connection, Some("close"), "a refusal closes the connection");
    assert_eq!(body["type"], "error", "the envelope: {body}");
    assert_eq!(body["error"]["type"], "proxy_error", "its class: {body}");
}

/// The server log this instance has written, whole.
fn server_log(instance: &Instance) -> String {
    fs::read_to_string(instance.root.join("log/server.ndjson")).unwrap_or_default()
}

/// Proxy traffic is served on the proxy
/// listener and nowhere else: the base-URL listener answers to both
/// proxy forms whether the mode is on or off, opens nothing, and goes on
/// serving base-URL exchanges; with the mode off the proxy listener stays
/// bound and answers to both forms too, so a stale proxy URL fails
/// diagnosably rather than on a dead port.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_forms_are_405_off_the_proxy_listener() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_with("proxy-forms-405-off", mitm_on()).await;
    instance.add_fsub();
    let echo = Echo::start().await;

    // The mode is on, and the base-URL listener is still not a forward proxy.
    let tunnel = connect_through(instance.addr, &echo.target(), None).await;
    assert_proxy_refusal(
        tunnel.status,
        405,
        tunnel.header("connection"),
        &tunnel.json(),
    );
    let forwarded = absolute_form(
        instance.addr,
        "GET",
        &format!("http://{}/", echo.target()),
        &[],
        None,
    )
    .await;
    assert_proxy_refusal(
        forwarded.status,
        405,
        forwarded.header("connection"),
        &forwarded.json(),
    );
    assert_eq!(
        echo.opened(),
        0,
        "a 405 opens nothing: the target was never connected to"
    );
    // The listener's own traffic is unaffected.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, 200, "the base-URL exchange is still served");
    // And the proxy listener does serve them, so the 405s above are about the
    // listener and not about the build.
    let mut tunnel = connect_through(proxy_addr(&instance), &echo.target(), None).await;
    assert_eq!(tunnel.status, 200, "the proxy listener tunnels");
    assert_eq!(tunnel.round_trip(b"through").await, b"through");

    // Mode off: every listener refuses both forms, the proxy listener
    // included — it stays bound and serves only this 405.
    instance.write_setup(&Setup::default());
    instance.restart();
    for listener in [instance.addr, proxy_addr(&instance)] {
        let tunnel = connect_through(listener, &echo.target(), None).await;
        assert_proxy_refusal(
            tunnel.status,
            405,
            tunnel.header("connection"),
            &tunnel.json(),
        );
        let forwarded = absolute_form(
            listener,
            "GET",
            &format!("http://{}/", echo.target()),
            &[],
            None,
        )
        .await;
        assert_proxy_refusal(
            forwarded.status,
            405,
            forwarded.header("connection"),
            &forwarded.json(),
        );
    }
    // The refusal is the mode's, not the credential's: a probe-host request
    // that would be answered locally with the mode on is refused the same.
    let probe = absolute_form(
        proxy_addr(&instance),
        "GET",
        "http://probe.jaynshare.invalid/",
        &[],
        None,
    )
    .await;
    assert_eq!(probe.status, 405, "{}", probe.body);
    assert!(
        probe.body.contains("disabled"),
        "the message says the mode is off: {}",
        probe.body
    );
    assert_eq!(
        echo.opened(),
        1,
        "still only the one tunnel of the mode-on half"
    );
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(
        answer.status, 200,
        "the base-URL exchange is served with the mode off too"
    );
}

/// One process serves both modes at
/// once: a base-URL exchange runs to completion while a tunnel on the proxy
/// listener is open, and the tunnel is still live afterwards.
///
/// One process, two listeners, concurrently: a base-URL exchange runs to
/// completion while a tunnel on the proxy listener is open, and the tunnel
/// is still live afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn one_process_serves_both_modes_at_once() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("process-serves-modes", mitm_on()).await;
    instance.add_fsub();
    let echo = Echo::start().await;
    let pid = instance.pid();

    let mut tunnel = connect_through(proxy_addr(&instance), &echo.target(), None).await;
    assert_eq!(tunnel.status, 200, "the tunnel is open");
    assert_eq!(tunnel.round_trip(b"before").await, b"before");

    // With the tunnel open and idle, the base-URL listener answers.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, 200, "the base-URL exchange is served");
    assert!(
        answer.json()["content"][0]["text"].is_string(),
        "and it is the upstream's answer: {}",
        answer.text()
    );

    // The tunnel outlived it, and it was the same process throughout.
    assert_eq!(tunnel.round_trip(b"after").await, b"after");
    assert_eq!(instance.pid(), pid, "one process served both modes");
}

/// Everything outside
/// the two-name-on-443 intercept set is tunnelled: an IP literal and a name
/// both reach a staged echo with their bytes unchanged and their half-close
/// propagated, an intercept name on another port is resolved like any other
/// target, and the names of leave the proxy as `CONNECT`s of
/// their own.
#[tokio::test(flavor = "multi_thread")]
async fn targets_outside_the_intercept_set_are_tunnelled() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("targets-outside-intercept", mitm_on()).await;
    let proxy = proxy_addr(&instance);
    let echo = Echo::start().await;

    // An IP-literal target is always tunnelled, and the tunnel is
    // the whole of: connect first, then 200, then unchanged bytes.
    let mut tunnel = connect_through(proxy, &echo.target(), None).await;
    assert_eq!(tunnel.status, 200, "an IP literal is tunnelled");
    assert_eq!(
        echo.opened(),
        1,
        "the target was connected to before the 200"
    );
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        tunnel.round_trip(&payload).await,
        payload,
        "64 KiB through the tunnel, unchanged both ways"
    );
    assert_eq!(
        tunnel.half_close().await,
        HALF_CLOSE_MARK,
        "the client's half-close reached the target, whose own close ended the tunnel"
    );

    // A name is resolved by the proxy host and tunnelled the same way.
    let mut named = connect_through(proxy, &format!("localhost:{}", echo.addr.port()), None).await;
    assert_eq!(named.status, 200, "a name is tunnelled");
    assert_eq!(named.round_trip(b"by name").await, b"by name");
    assert_eq!(echo.opened(), 2);

    // An intercept-set name is intercepted on 443 and nowhere else.
    // On 443 the answer is immediate and no lookup happens; on another port
    // the proxy resolves the name like any other target, and this one — the
    // product's own probe host, in a reserved TLD — never resolves.
    let intercepted = connect_through(proxy, "probe.jaynshare.invalid:443", None).await;
    assert_eq!(
        intercepted.status, 200,
        "the probe host on 443 is intercepted"
    );
    assert!(
        instance.events("proxy_refused").is_empty(),
        "nothing was refused, so nothing was resolved"
    );
    let off_port = connect_through(proxy, "probe.jaynshare.invalid:8443", None).await;
    assert_proxy_refusal(
        off_port.status,
        502,
        off_port.header("connection"),
        &off_port.json(),
    );
    assert_eq!(
        instance.events("proxy_refused").len(),
        1,
        "the same name off 443 went down the tunnelled path and was resolved"
    );

    // `claude.ai`, `platform.claude.com` and `claude.com` are
    // tunnelled targets like any other. With a corporate proxy configured
    // the proxy hands them on by name, which is how the suite names
    // A public host without ever leaving loopback.
    let chain = Chain::start().await;
    let elsewhere = Instance::start_with(
        "targets-outside-intercept-names",
        Setup {
            data_plane: chain.settings(&[]),
            ..mitm_on()
        },
    )
    .await;
    let proxy = proxy_addr(&elsewhere);
    for name in ["claude.ai:443", "platform.claude.com:443", "claude.com:443"] {
        let mut tunnel = connect_through(proxy, name, None).await;
        assert_eq!(tunnel.status, 200, "{name} is tunnelled");
        assert_eq!(tunnel.round_trip(b"opaque").await, b"opaque");
    }
    assert_eq!(
        chain.request_lines(),
        [
            "CONNECT claude.ai:443 HTTP/1.1",
            "CONNECT platform.claude.com:443 HTTP/1.1",
            "CONNECT claude.com:443 HTTP/1.1",
        ],
        "each left the proxy as a CONNECT of its own"
    );
    let api = connect_through(proxy, "api.anthropic.com:443", None).await;
    assert_eq!(api.status, 200, "the API host answers on 443");
    assert_eq!(
        chain.request_lines().len(),
        3,
        "and it never became a tunnel: the intercept set is these two names on 443"
    );
}

/// An unreachable target is a proxy
/// status before any, with `connection: close`: for a name that
/// does not resolve and for a refused connection, at 30 s for an
/// address that answers nothing.
#[tokio::test(flavor = "multi_thread")]
async fn unreachable_targets_are_502_and_504_before_any_200() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("unreachable-targets-502", mitm_on()).await;
    let proxy = proxy_addr(&instance);

    // A name that does not resolve: 502 before any connection.
    let unresolvable = connect_through(proxy, "nowhere.jaynshare.invalid:443", None).await;
    assert_proxy_refusal(
        unresolvable.status,
        502,
        unresolvable.header("connection"),
        &unresolvable.json(),
    );
    assert!(
        unresolvable.json()["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("nowhere.jaynshare.invalid"),
        "the message names the target: {}",
        unresolvable.body
    );

    // A refused connection: 502 as well.
    let closed = reserve_port();
    let refused = connect_through(proxy, &format!("127.0.0.1:{closed}"), None).await;
    assert_proxy_refusal(
        refused.status,
        502,
        refused.header("connection"),
        &refused.json(),
    );

    // An address that answers nothing: 504, and only after the 30 s.
    // TEST-NET-1 is documentation space (RFC 5737) and reaches no service;
    // A host whose network answers it outright has no 30 s wait to observe,
    // and that half is checked by hand.
    if cfg!(windows) {
        eprintln!("skipping: Windows gives up a connection at about 21 s, before the 30 s");
        return;
    }
    let unroutable: SocketAddr = "192.0.2.1:443".parse().expect("TEST-NET-1");
    let answered_fast = tokio::task::spawn_blocking(move || {
        let at = Instant::now();
        let _ = StdTcpStream::connect_timeout(&unroutable, Duration::from_secs(2));
        at.elapsed() < Duration::from_millis(1500)
    })
    .await
    .expect("probe the fixture host's route to TEST-NET-1");
    if answered_fast {
        eprintln!("skipping: the fixture host answers TEST-NET-1 outright; there is no 30 s wait");
        return;
    }
    let started = Instant::now();
    let timed_out = connect_through(proxy, "192.0.2.1:443", None).await;
    let waited = started.elapsed();
    assert_proxy_refusal(
        timed_out.status,
        504,
        timed_out.header("connection"),
        &timed_out.json(),
    );
    assert!(
        waited >= Duration::from_secs(28) && waited <= Duration::from_secs(50),
        "the 504 came at the 30 s, not sooner and not later: {waited:?}"
    );
}

/// The loopback exemption holds on the
/// proxy listener too: a loopback caller that presents no credential is
/// served, while a remote one is not.
///
/// The loopback caller's user-field pinning is the proxy-credential tests',
/// which own the token on this channel; what is here is the channel's own
/// half.
#[tokio::test(flavor = "multi_thread")]
async fn loopback_needs_no_proxy_credential() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "loopback-needs-no-proxy",
        Setup {
            wildcard: true,
            ..mitm_on()
        },
    )
    .await;
    // the bootstrap exception would answer for the loopback caller on
    // its own, so it is ended first: with a client enrolled, the 200 below is
    // the exemption and nothing else.
    let client = enroll(&instance, "desk", "The Desk").await;
    assert!(!client.secret.is_empty(), "the client was enrolled");
    let echo = Echo::start().await;

    let mut tunnel = connect_through(proxy_addr(&instance), &echo.target(), None).await;
    assert_eq!(
        tunnel.status, 200,
        "a loopback caller needs no proxy credential"
    );
    assert_eq!(tunnel.round_trip(b"loopback").await, b"loopback");

    // The exemption is the loopback peer's, not everyone's.
    let Some(address) = non_loopback_addr() else {
        return;
    };
    let remote = SocketAddr::new(address, proxy_addr(&instance).port());
    let refused = connect_through(remote, &echo.target(), None).await;
    assert_eq!(
        refused.status, 407,
        "a remote caller without a credential is not exempt: {}",
        refused.body
    );
    assert!(
        refused
            .header("proxy-authenticate")
            .is_some_and(|value| value.starts_with("Basic ")),
        "with the challenge the scheme requires: {:?}",
        refused.header("proxy-authenticate")
    );
    assert_eq!(
        echo.opened(),
        1,
        "and nothing was opened for the refused caller"
    );
}

/// A target that resolves to loopback
/// or to an address of the proxy host itself is refused before any
/// connection; under the active override loopback is tunnelled, which is
/// the exception the acceptance harness stages its targets behind.
#[tokio::test(flavor = "multi_thread")]
async fn self_targets_are_403_before_any_connection() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let echo = Echo::start().await;
    let t0 = Instant::now();
    eprintln!("[t] echo {:?}", t0.elapsed());

    // No override: the product carries the origin and is whole.
    let strict = Instance::start_with(
        "self-targets-403-strict",
        Setup {
            no_upstream_override: true,
            ..mitm_on()
        },
    )
    .await;
    eprintln!("[t] strict up {:?}", t0.elapsed());
    let proxy = proxy_addr(&strict);
    let mut targets = vec![
        echo.target(),
        format!("localhost:{}", echo.addr.port()),
        format!("127.0.0.1:{}", strict.addr.port()),
    ];
    if let Some(address) = non_loopback_addr() {
        targets.push(format!("{address}:{}", echo.addr.port()));
    }
    for target in &targets {
        eprintln!("[t] before {target} {:?}", t0.elapsed());
        let refused = connect_through(proxy, target, None).await;
        eprintln!("[t] after {target} {:?}", t0.elapsed());
        assert_proxy_refusal(
            refused.status,
            403,
            refused.header("connection"),
            &refused.json(),
        );
    }
    assert_eq!(echo.opened(), 0, "every refusal came before any connection");
    let refusals = strict.events("proxy_refused");
    assert_eq!(
        refusals.len(),
        targets.len(),
        "one line per refusal: {refusals:?}"
    );

    // The exception: with the override active, loopback targets tunnel.
    eprintln!("[t] refusals done {:?}", t0.elapsed());
    let staged = Instance::start_with("self-targets-403", mitm_on()).await;
    eprintln!("[t] staged up {:?}", t0.elapsed());
    let mut tunnel = connect_through(proxy_addr(&staged), &echo.target(), None).await;
    assert_eq!(
        tunnel.status, 200,
        "the override lets the harness stage a tunnelled service"
    );
    assert_eq!(tunnel.round_trip(b"exempt").await, b"exempt");
    eprintln!("[t] tunnel ok {:?}", t0.elapsed());
    assert_eq!(echo.opened(), 1);
    // The exception is loopback's alone: the host's own routable addresses
    // stay refused under it.
    if let Some(address) = non_loopback_addr() {
        let refused = connect_through(
            proxy_addr(&staged),
            &format!("{address}:{}", echo.addr.port()),
            None,
        )
        .await;
        assert_proxy_refusal(
            refused.status,
            403,
            refused.header("connection"),
            &refused.json(),
        );
    }
    eprintln!("[t] end {:?}", t0.elapsed());
}

/// A tunnel that works leaves no audit
/// record and no log line naming its target; every refusal leaves one line
/// carrying the client's address and the target.
#[tokio::test(flavor = "multi_thread")]
async fn tunnels_are_private_and_refusals_are_logged() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("tunnels-private-refusals", mitm_on()).await;
    let proxy = proxy_addr(&instance);
    let echo = Echo::start().await;

    let mut tunnel = connect_through(proxy, &echo.target(), None).await;
    assert_eq!(tunnel.status, 200);
    assert_eq!(tunnel.round_trip(b"private").await, b"private");
    assert_eq!(tunnel.half_close().await, HALF_CLOSE_MARK);
    instance.settle();

    assert!(
        instance.audit().is_empty(),
        "a tunnel is no exchange: it leaves no audit record"
    );
    let log = server_log(&instance);
    assert!(
        !log.contains(&echo.target()),
        "and no log line names the host the engineer reached: {log}"
    );
    assert!(
        instance.events("proxy_refused").is_empty(),
        "nothing was refused"
    );

    // A refusal is the operator's business, and is logged as one line.
    let target = "nowhere.jaynshare.invalid:443";
    let refused = connect_through(proxy, target, None).await;
    assert_eq!(refused.status, 502);
    let lines = instance.events("proxy_refused");
    assert_eq!(lines.len(), 1, "one line for the refusal: {lines:?}");
    assert_eq!(lines[0]["fields"]["target"], target, "naming the target");
    assert_eq!(lines[0]["fields"]["status"], 502, "and its status");
    assert!(
        lines[0]["fields"]["peer"]
            .as_str()
            .expect("the client address")
            .starts_with("127.0.0.1:"),
        "and the client's address: {}",
        lines[0]
    );
    assert!(
        instance.audit().is_empty(),
        "a refusal is not an exchange either"
    );
}

/// With a corporate proxy configured a
/// tunnelled target is reached by chaining a `CONNECT` through it, carrying
/// the name and port and nothing else; a target its no-proxy list matches is
/// reached directly.
#[tokio::test(flavor = "multi_thread")]
async fn tunnels_chain_through_the_corporate_proxy() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let chain = Chain::start().await;
    let echo = Echo::start().await;
    let instance = Instance::start_with(
        "tunnels-chain-through",
        Setup {
            data_plane: chain.settings(&["localhost"]),
            ..mitm_on()
        },
    )
    .await;
    let proxy = proxy_addr(&instance);

    // Not excluded: chained, by name — the corporate proxy resolves it.
    let mut chained = connect_through(proxy, "elsewhere.example.com:443", None).await;
    assert_eq!(chained.status, 200, "the chained tunnel is open");
    assert_eq!(chained.round_trip(b"end to end").await, b"end to end");
    assert_eq!(
        chain.request_lines(),
        ["CONNECT elsewhere.example.com:443 HTTP/1.1"],
        "the corporate proxy saw the name and the port"
    );
    let head = chain.heads().remove(0);
    assert!(
        !head.to_ascii_lowercase().contains("authorization"),
        "and no credential of ours: {head}"
    );
    assert_eq!(echo.opened(), 0, "nothing went direct");

    // Excluded by the no-proxy list: direct, and the corporate proxy never
    // hears about it.
    let mut direct = connect_through(proxy, &format!("localhost:{}", echo.addr.port()), None).await;
    assert_eq!(direct.status, 200, "the direct tunnel is open");
    assert_eq!(direct.round_trip(b"direct").await, b"direct");
    assert_eq!(echo.opened(), 1, "the target was reached directly");
    assert_eq!(
        chain.request_lines().len(),
        1,
        "a no-proxy match never reaches the corporate proxy"
    );
}

/// Absolute-form `http://` is forwarded
/// plain with method, path, query and body unchanged, the proxy headers
/// removed and no credential added, whatever the target's name;
/// absolute-form `https://` is and an unreachable target.
#[tokio::test(flavor = "multi_thread")]
async fn absolute_form_http_is_forwarded_plain() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let chain = Chain::start_carrying(Inside::Http).await;
    let target = HttpTarget::start().await;
    let instance = Instance::start_with(
        "absolute-form-http",
        Setup {
            data_plane: chain.settings(&["localhost"]),
            ..mitm_on()
        },
    )
    .await;
    let proxy = proxy_addr(&instance);
    // A real credential: an invalid one is refused even from
    // loopback, and the point here is that a valid one is stripped.
    let desk = enroll(&instance, "desk", "Desk").await;
    let credential = {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!(":{}", desk.secret))
        )
    };

    // The forward itself: everything of the request survives it but the
    // hop-by-hop headers and the proxy credential.
    let body = json!({ "note": "unchanged" }).to_string();
    let forwarded = absolute_form(
        proxy,
        "POST",
        &format!(
            "http://localhost:{}/tools/run?trace=1&q=a%20b",
            target.addr.port()
        ),
        &[
            ("proxy-authorization", &credential),
            ("proxy-connection", "keep-alive"),
            ("x-engineer", "kept"),
        ],
        Some(&body),
    )
    .await;
    assert_eq!(forwarded.status, 201, "the target's own status is relayed");
    assert_eq!(forwarded.body, "forwarded", "and its body");
    let (head, sent) = target.last();
    assert_eq!(
        head.lines().next(),
        Some("POST /tools/run?trace=1&q=a%20b HTTP/1.1"),
        "method, path and query unchanged, in origin form: {head}"
    );
    assert_eq!(sent, body, "and the body byte for byte");
    let lowered = head.to_ascii_lowercase();
    assert!(
        !lowered.contains("proxy-authorization") && !head.contains(&desk.secret),
        "the proxy credential never reaches the target: {head}"
    );
    assert!(
        !lowered.contains("proxy-connection"),
        "nor the proxy's own hop-by-hop headers: {head}"
    );
    assert!(
        !lowered.contains("\nauthorization"),
        "and nothing pooled is injected: {head}"
    );
    assert!(lowered.contains("x-engineer: kept"), "the rest is: {head}");

    // `https://` is refused: the proxy does not open TLS for a client.
    let https = absolute_form(
        proxy,
        "GET",
        &format!("https://localhost:{}/", target.addr.port()),
        &[],
        None,
    )
    .await;
    assert_proxy_refusal(https.status, 400, https.header("connection"), &https.json());
    assert_eq!(target.calls(), 1, "and nothing was forwarded");

    // An unreachable target is the envelope, `proxy_error`.
    let closed = reserve_port();
    let unreachable = absolute_form(
        proxy,
        "GET",
        &format!("http://localhost:{closed}/"),
        &[],
        None,
    )
    .await;
    assert_proxy_refusal(
        unreachable.status,
        502,
        unreachable.header("connection"),
        &unreachable.json(),
    );

    // The API host in absolute form is forwarded like any other name — never
    // intercepted, never credential-injected. It is not excluded by the
    // no-proxy list, so it is sent to the corporate proxy, in absolute form
    // and on a direct connection to it, never tunnelled.
    let api = absolute_form(
        proxy,
        "GET",
        "http://api.anthropic.com/v1/messages",
        &[],
        None,
    )
    .await;
    assert_eq!(api.status, 200, "forwarded, not intercepted: {}", api.body);
    assert_eq!(api.body, "chained", "and the target's answer came back");
    let heads = chain.heads();
    assert_eq!(
        heads.len(),
        1,
        "the excluded targets above never reached the corporate proxy: {heads:?}"
    );
    let head = &heads[0];
    assert_eq!(
        head.lines().next(),
        Some("GET http://api.anthropic.com/v1/messages HTTP/1.1"),
        "the request line itself reached the corporate proxy, unchanged: {head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("authorization"),
        "with no credential of ours on it — nothing pooled travels in clear: {head}"
    );
}

/// A listener address that
/// cannot be bound exits naming the address and the port, prints no
/// startup line, and leaves nothing bound: for the base-URL listener, and
/// for the proxy listener beside it.
#[tokio::test(flavor = "multi_thread")]
async fn an_unbindable_listener_exits_22_and_binds_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("unbindable-listener-exits");
    private_dir(&root.join("state"));
    private_dir(&root.join("log"));

    // Whoever holds the address is held for the whole attempt, so the bind
    // that must fail cannot succeed by luck.
    let held = StdTcpListener::bind("127.0.0.1:0").expect("hold an address");
    let taken = held.local_addr().expect("the held address").port();

    // The base-URL listener first: the proxy listener is free and must stay
    // that way, because the base-URL bind is attempted first and fails.
    let free_proxy = reserve_port();
    let (code, out, err) = serve_once(&root, taken, Some(free_proxy));
    assert_eq!(code, 22, "the exit code: {err}");
    assert!(
        err.contains(&taken.to_string()) && err.contains("127.0.0.1"),
        "the message names the address and the port: {err}"
    );
    assert!(out.is_empty(), "and no startup line was printed: {out}");
    let free_again = StdTcpListener::bind(("127.0.0.1", free_proxy));
    assert!(
        free_again.is_ok(),
        "nothing was left partially bound: the proxy listener is free"
    );
    drop(free_again);

    // Then the proxy listener, which binds second: the base-URL listener is
    // bound and must be given back.
    let free_base = reserve_port();
    let (code, out, err) = serve_once(&root, free_base, Some(taken));
    assert_eq!(code, 22, "is handled as: {err}");
    assert!(
        err.contains(&taken.to_string()) && err.contains("127.0.0.1"),
        "the message names the proxy address and port: {err}"
    );
    assert!(out.is_empty(), "and no startup line was printed: {out}");
    assert!(
        StdTcpListener::bind(("127.0.0.1", free_base)).is_ok(),
        "nothing was left partially bound: the base-URL listener is free"
    );
    drop(held);
}

/// One `serve` over a hand-written document at `root`: the exit code, what it
/// printed and what it reported. Hand-written because the two addresses are
/// the scenario's subject, and `Setup` reserves them for itself.
fn serve_once(root: &std::path::Path, listen: u16, proxy: Option<u16>) -> (i32, String, String) {
    let mitm = match proxy {
        Some(port) => format!("\n[mitm]\nenabled = true\nlisten = \"127.0.0.1:{port}\"\n"),
        None => String::new(),
    };
    let config = root.join("config.toml");
    write_private(
        &config,
        &format!(
            "version = 1\n\n\
             [data_plane]\n\
             listen = \"127.0.0.1:{listen}\"\n\n\
             [storage]\n\
             state_file = {}\n\n\
             [logging]\n\
             directory = {}\n{mitm}",
            crate::harness::toml_path(&root.join("state/state.json")),
            crate::harness::toml_path(&root.join("log")),
        ),
    );
    let output = Command::new(binary())
        .args(["--config", &config.display().to_string(), "serve"])
        .env("PATH", root.join("no-browser-on-path"))
        .envs(crate::harness::platform_home(&root.join("home")))
        .stdin(Stdio::null())
        .output()
        .expect("start the binary under test");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The proxy credential is a
/// `Basic` one whose password resolves against the registry: a wrong client
/// secret (the never-promoted refusal), a `Bearer` scheme, and the
/// secret parked in the user field are each with the challenge, the
/// close and no connection, one refusal line each, while the well-formed
/// credential tunnels to the target.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_credential_refusals_are_407() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("proxy-credential-refusals", mitm_on()).await;
    // Enrolled first so the loopback refusals below are real refusals, not
    // the bootstrap answering for everything.
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let echo = Echo::start().await;
    let proxy = proxy_addr(&instance);
    let ca = ca_file(&instance);

    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    };

    for (name, credential) in [
        //A presented credential that resolves to nothing is refused
        // even from loopback — never promoted.
        ("wrong secret", basic("user", "jsc2_wrong")),
        // No other scheme.
        ("bearer scheme", format!("Bearer {}", alpha.secret)),
        // The secret is the password, not the user field.
        ("secret as user", basic(&alpha.secret, "")),
    ] {
        let refused = connect_through(proxy, &echo.target(), Some(&credential)).await;
        assert_proxy_refusal(
            refused.status,
            407,
            refused.header("connection"),
            &refused.json(),
        );
        assert!(
            refused
                .header("proxy-authenticate")
                .is_some_and(|value| value.starts_with("Basic realm=")),
            "{name}: with the challenge the scheme requires: {:?}",
            refused.header("proxy-authenticate")
        );
    }
    assert_eq!(echo.opened(), 0, "every refusal came before any connection");
    let refusals = instance.events("proxy_refused");
    assert_eq!(
        refusals.len(),
        3,
        "one refusal line per refused credential: {refusals:?}"
    );
    for line in &refusals {
        assert!(
            line["fields"]["peer"]
                .as_str()
                .is_some_and(|p| !p.is_empty()),
            "each refusal names the peer: {line}"
        );
        assert_eq!(
            line["fields"]["status"], 407,
            "each refusal is a 407: {line}"
        );
    }

    // The positive half of the row: the well-formed credential tunnels.
    let mut tunnel = connect_through(
        proxy,
        &echo.target(),
        Some(&basic("pin.QUJD", &alpha.secret)),
    )
    .await;
    assert_eq!(
        tunnel.status, 200,
        "a resolvable Basic credential is served"
    );
    assert_eq!(tunnel.round_trip(b"credential").await, b"credential");
    assert_eq!(
        echo.opened(),
        1,
        "the tunnelled target saw exactly the one connection"
    );
    assert_eq!(
        instance.events("proxy_refused").len(),
        3,
        "the successful tunnel left no refusal line"
    );

    // A well-formed Basic whose user field is not a token is not a
    // refusal — the tunnel opens, and every request inside it is a 400
    // `invalid_request_error`, with no new refusal line.
    let mut tunnel = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic("pin.QUJD~.", &alpha.secret)),
        &ca,
        Offer::default(),
    )
    .await
    .expect("a malformed user field authenticates");
    let answer = exchange_in(&mut tunnel).await;
    assert_eq!(answer.status, 400, "{}", answer.text());
    assert_eq!(
        answer.json()["error"]["type"],
        "invalid_request_error",
        "the refusal type: {}",
        answer.text()
    );
    assert_eq!(
        instance.events("proxy_refused").len(),
        3,
        "the tunnel opening is not a refusal"
    );
}

/// A `CONNECT` to the
/// API host on 443 is answered and the bytes after it are the proxy's
/// own TLS server: the handshake completes against a root store holding
/// nothing but the CA file the instance wrote, and the leaf it presents
/// carries both intercept names.
#[tokio::test(flavor = "multi_thread")]
async fn an_intercepted_target_is_served_by_our_own_tls() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("intercepted-target-served", mitm_on()).await;
    let ca = ca_file(&instance);

    // rustls hands back a stream only once the chain verified, and the only
    // root it was given is the CA file (the leaf, the server).
    let tunnel = intercept(
        proxy_addr(&instance),
        "api.anthropic.com:443",
        None,
        &ca,
        Offer::default(),
    )
    .await
    .expect("the leaf verifies against the CA file");

    let leaf = tunnel.presented.first().expect("a leaf was presented");
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).expect("the leaf parses");
    let mut names = crate::mtm::dns_names(&parsed);
    names.sort();
    assert_eq!(
        names,
        vec![
            "api.anthropic.com",
            "chatgpt.com",
            "probe.jaynshare.invalid"
        ],
        "the leaf names the whole intercept set"
    );
}

/// A request decoded from an
/// intercepted tunnel is an ordinary exchange: forwarded under a pooled
/// credential with the caller's own `authorization` gone, answered by the
/// upstream, and recorded with `mode` `mitm`.
#[tokio::test(flavor = "multi_thread")]
async fn an_intercepted_request_is_an_ordinary_exchange() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("intercepted-request-ordinary", mitm_on()).await;
    instance.add_fsub();
    let ca = ca_file(&instance);
    let mut tunnel = intercept(
        proxy_addr(&instance),
        "api.anthropic.com:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the handshake succeeds");

    let mut request = tunnel.request(
        Method::POST,
        "api.anthropic.com",
        "/v1/messages",
        &haiku_prompt().to_string(),
    );
    request
        .headers_mut()
        .insert("authorization", "Bearer caller-own-token".parse().unwrap());
    let answer = tunnel.send(request).await;

    assert_eq!(
        answer.status,
        200,
        "the exchange was served: {}",
        answer.text()
    );
    assert!(
        answer.json()["content"][0]["text"].is_string(),
        "and the body is the upstream's answer: {}",
        answer.text()
    );
    let seen = instance.upstream.last();
    assert_ne!(
        seen.header("authorization"),
        Some("Bearer caller-own-token"),
        "the caller's own credential was removed unread"
    );
    assert!(
        seen.header("authorization").is_some() || seen.header("x-api-key").is_some(),
        "and a pooled credential was injected instead"
    );
    let record = instance.last_record(1);
    assert_eq!(record["mode"], "mitm", "the record names the mode");
    assert_eq!(record["path"], "/v1/messages");
}

/// The interception TLS
/// server's whole matrix: TLS 1.2 and 1.3 both accepted, `h2` and
/// `http/1.1` both offered and either honoured, no ALPN served as HTTP/1.1,
/// A client sending no SNI still given the leaf, and bytes that are not a
/// client hello ending the tunnel.
#[tokio::test(flavor = "multi_thread")]
async fn every_version_and_protocol_the_intercepted_tunnel_accepts() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("version-protocol-intercepted", mitm_on()).await;
    instance.add_fsub();
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);
    let target = "api.anthropic.com:443";

    // An exchange over each offer, so holds whichever carried it.
    let exchange = async |offer: Offer| -> Intercepted {
        let mut tunnel = intercept(proxy, target, None, &ca, offer)
            .await
            .expect("the handshake completes");
        let request = tunnel.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        );
        let answer = tunnel.send(request).await;
        assert_eq!(answer.status, 200, "served: {}", answer.text());
        tunnel
    };

    assert_eq!(exchange(Offer::tls12()).await.version, "TLSv1.2");
    assert_eq!(exchange(Offer::tls13()).await.version, "TLSv1.3");
    assert_eq!(
        exchange(Offer::alpn(&["h2"])).await.alpn.as_deref(),
        Some("h2"),
        "the client offering h2 alone is served HTTP/2"
    );
    assert_eq!(
        exchange(Offer::alpn(&["http/1.1"])).await.alpn.as_deref(),
        Some("http/1.1")
    );
    let bare = exchange(Offer::alpn(&[])).await;
    assert_eq!(
        bare.alpn, None,
        "no ALPN extension, and the exchange above was framed as HTTP/1.1"
    );
    let anonymous = exchange(Offer {
        sni: false,
        ..Offer::default()
    })
    .await;
    assert!(
        !anonymous.presented.is_empty(),
        "a client sending no SNI still gets the leaf"
    );

    // Bytes that are not a client hello end the tunnel.
    let mut plain = connect_through(proxy, target, None).await;
    assert_eq!(plain.status, 200, "the CONNECT itself was answered");
    plain
        .stream
        .write_all(b"GET / HTTP/1.1\r\nhost: api.anthropic.com\r\n\r\n")
        .await
        .expect("write plain bytes into an intercepted tunnel");
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), plain.stream.read_to_end(&mut rest))
        .await
        .expect("the tunnel is closed rather than left open")
        .expect("the tunnel ends cleanly");
    // A TLS server's answer to bytes that are not a hello is its own alert,
    // then the close. What it is never is an HTTP response.
    assert!(
        !rest.starts_with(b"HTTP/"),
        "nothing HTTP was served on the plain bytes: {}",
        String::from_utf8_lossy(&rest)
    );
}

/// The probe host answers itself in
/// both proxy forms and is never forwarded: inside an intercepted tunnel
/// `GET /` is the JSON object with `tls` `true`, any other path (so
/// `/v1/messages` too — the probe host shadows nothing of the API host), and
/// absolute form over plain HTTP returns the same object with `tls` `false`.
/// With a client credential the `user_field` is shown exactly as received.
#[tokio::test(flavor = "multi_thread")]
async fn the_probe_host_answers_itself_in_both_forms() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("probe-host-answers", mitm_on()).await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);
    let fingerprint = crate::mtm::ca_fingerprint(&instance.root.join("state"));
    let version = instance.status()["server"]["version"]
        .as_str()
        .expect("the snapshot carries the server version")
        .to_owned();

    // The intercepted form: an anonymous tunnel (loopback principal), `GET /`.
    let mut tunnel = intercept(
        proxy,
        "probe.jaynshare.invalid:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the probe host is an intercepted name");
    let answer = tunnel
        .send(tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await;
    assert_eq!(answer.status, 200, "answered: {}", answer.text());
    let object = answer.json();
    assert_eq!(object["tls"], true, "inside a tunnel TLS was used");
    assert_eq!(
        object["ca_fingerprint"], fingerprint,
        "the fingerprint of the CA file the instance wrote"
    );
    time::OffsetDateTime::parse(
        object["ca_not_after"].as_str().expect("an RFC 3339 string"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("ca_not_after parses as RFC 3339");
    assert_eq!(object["ca_state"], "ok", "the CA is not near expiry");
    assert_eq!(
        object["user_field"],
        Value::Null,
        "no credential: the user field is null"
    );
    assert_eq!(
        object["version"], version,
        "the same version the client snapshot shows"
    );
    assert_eq!(
        object["principal"]["role"], "loopback-operator",
        "the anonymous tunnel's principal"
    );

    // Any other path 404s — including the API host's own, so the probe host
    // is never forwarded anywhere.
    for path in ["/probe", "/v1/messages"] {
        let other = tunnel
            .send(tunnel.request(Method::GET, "probe.jaynshare.invalid", path, ""))
            .await;
        assert_eq!(other.status, 404, "{path} is refused: {}", other.text());
    }

    // The absolute form: the same object, `tls` `false`.
    let forwarded = absolute_form(proxy, "GET", "http://probe.jaynshare.invalid/", &[], None).await;
    assert_eq!(forwarded.status, 200, "answered: {}", forwarded.body);
    let plain_object = forwarded.json();
    assert_eq!(plain_object["tls"], false, "plain HTTP: no TLS");
    assert_eq!(plain_object["ca_fingerprint"], fingerprint);
    assert_eq!(plain_object["version"], version);
    assert_eq!(plain_object["principal"]["role"], "loopback-operator");
    let other = absolute_form(
        proxy,
        "GET",
        "http://probe.jaynshare.invalid/other",
        &[],
        None,
    )
    .await;
    assert_eq!(other.status, 404, "only / answers: {}", other.body);

    // A client credential: the user field shown as received.
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let token = {
        use base64::Engine as _;
        format!(
            "pin.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("Alpha Desk")
        )
    };
    let credential = {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{token}:{}", alpha.secret))
        )
    };
    let mut client_tunnel = intercept(
        proxy,
        "probe.jaynshare.invalid:443",
        Some(&credential),
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the credential resolves");
    let answer = client_tunnel
        .send(client_tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await;
    assert_eq!(answer.status, 200, "answered: {}", answer.text());
    let object = answer.json();
    assert_eq!(
        object["user_field"], token,
        "the user field verbatim, as received"
    );
    assert_eq!(object["principal"]["role"], "client");
    assert_eq!(object["principal"]["id"], "alpha");
}

/// The probe object is one object in two
/// forms: both the tunnel's answer and absolute form's answer carry exactly
/// the key set lists (and so does `principal`), and they are equal member
/// for member except `tls`, which only tells the forms apart.
#[tokio::test(flavor = "multi_thread")]
async fn the_probe_object_is_the_same_in_both_forms() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("probe-object-forms", mitm_on()).await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);

    // `Offer::default` offers `h2`, so the object is read through the
    // tunnel's second stream handle — the shape a concurrent client uses.
    let tunnel = intercept(
        proxy,
        "probe.jaynshare.invalid:443",
        None,
        &ca,
        Offer::default(),
    )
    .await
    .expect("the probe host is an intercepted name");
    let mut handle = tunnel.stream();
    let response = handle
        .send_request(tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await
        .expect("send inside the intercepted tunnel");
    let answer = collect_answer(response).await;
    assert_eq!(answer.status, 200, "answered: {}", answer.text());
    let tunnelled = answer.json();
    let forwarded = absolute_form(proxy, "GET", "http://probe.jaynshare.invalid/", &[], None).await;
    assert_eq!(forwarded.status, 200, "answered: {}", forwarded.body);
    let plain = forwarded.json();

    // Exactly the keys lists, in the object and in `principal`.
    fn keys(object: &Value) -> Vec<&String> {
        let mut keys: Vec<&String> = object.as_object().unwrap().keys().collect();
        keys.sort();
        keys
    }
    assert_eq!(
        keys(&tunnelled),
        [
            "ca_fingerprint",
            "ca_not_after",
            "ca_state",
            "principal",
            "tls",
            "user_field",
            "version"
        ]
    );
    assert_eq!(
        keys(&tunnelled["principal"]),
        ["display_name", "id", "role"]
    );

    // One object, two forms: equal member for member but `tls`.
    let mut without_tls = tunnelled.clone();
    without_tls["tls"] = Value::Null;
    let mut plain_without_tls = plain.clone();
    plain_without_tls["tls"] = Value::Null;
    assert_eq!(
        without_tls, plain_without_tls,
        "the two forms differ in `tls` alone"
    );
}

/// `status --json`'s `mitm`
/// section carries every field, and the numbers move: the open-tunnel
/// gauges follow tunnels opened and closed, the totals only rise, and each
/// refusal class (407, 403, unreachable, failed handshake) lands in its own
/// counter.
#[tokio::test(flavor = "multi_thread")]
async fn the_status_section_carries_every_field_and_the_counters_move() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("status-section-carries", mitm_on()).await;
    instance.add_fsub();
    let proxy = proxy_addr(&instance);
    let ca = ca_file(&instance);
    let echo = Echo::start().await;

    // Every field, before anything has happened.
    let mitm = instance.status()["mitm"].clone();
    assert_eq!(mitm["enabled"], json!(true));
    assert_eq!(mitm["listen"], json!(proxy.to_string()));
    assert_eq!(
        mitm["ca"]["fingerprint"],
        json!(crate::mtm::ca_fingerprint(&instance.root.join("state"))),
        "the fingerprint is the one over the CA file the instance wrote"
    );
    let not_after = time::OffsetDateTime::parse(
        mitm["ca"]["not_after"]
            .as_str()
            .expect("a not_after string"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("not_after parses as RFC 3339");
    assert!(
        not_after - time::OffsetDateTime::now_utc() > time::Duration::days(700),
        "the CA is fresh: {not_after}"
    );
    assert_eq!(mitm["ca"]["state"], json!("ok"));
    assert_eq!(
        mitm["tunnels"],
        json!({ "intercepted": 0, "tunnelled": 0 }),
        "nothing open yet: {mitm}"
    );
    assert_eq!(
        mitm["counters"],
        json!({
            "intercepted_exchanges": 0,
            "tunnels_opened": 0,
            "connect_refused_407": 0,
            "connect_refused_403": 0,
            "connect_unreachable": 0,
            "failed_handshakes": 0,
        }),
        "no counter has moved: {mitm}"
    );

    // One tunnelled tunnel: the gauge moves and the total with it.
    let tunnel = connect_through(proxy, &echo.target(), None).await;
    assert_eq!(tunnel.status, 200);
    let mitm = instance.status()["mitm"].clone();
    assert_eq!(
        mitm["tunnels"],
        json!({ "intercepted": 0, "tunnelled": 1 }),
        "one tunnelled tunnel is open: {mitm}"
    );
    assert_eq!(mitm["counters"]["tunnels_opened"], json!(1));
    drop(tunnel);
    let deadline = Instant::now() + Duration::from_secs(3);
    while instance.status()["mitm"]["tunnels"]["tunnelled"] != json!(0) {
        assert!(
            Instant::now() < deadline,
            "the gauge fell back to 0 once the tunnel closed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let mitm = instance.status()["mitm"].clone();
    assert_eq!(
        mitm["counters"]["tunnels_opened"],
        json!(1),
        "the total never falls: {mitm}"
    );

    // One intercepted tunnel with one exchange inside it.
    let mut intercepted = intercept(
        proxy,
        "api.anthropic.com:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the handshake succeeds");
    let request = intercepted.request(
        Method::POST,
        "api.anthropic.com",
        "/v1/messages",
        &haiku_prompt().to_string(),
    );
    let answer = intercepted.send(request).await;
    assert_eq!(
        answer.status,
        200,
        "the exchange was served: {}",
        answer.text()
    );
    let mitm = instance.status()["mitm"].clone();
    assert_eq!(
        mitm["tunnels"],
        json!({ "intercepted": 1, "tunnelled": 0 }),
        "the intercepted tunnel is open, the tunnelled one is gone: {mitm}"
    );
    assert_eq!(mitm["counters"]["tunnels_opened"], json!(2));
    assert_eq!(mitm["counters"]["intercepted_exchanges"], json!(1));

    // Each refusal class, one CONNECT each.

    // 407: a credential that resolves to nothing, with the bootstrap
    // exemption closed by one enrollment (as does).
    enroll(&instance, "alpha", "Alpha").await;
    use base64::Engine as _;
    let credential = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("u:jsc2_wrong")
    );
    let refused = connect_through(proxy, &echo.target(), Some(&credential)).await;
    assert_proxy_refusal(
        refused.status,
        407,
        refused.header("connection"),
        &refused.json(),
    );
    assert_eq!(
        instance.status()["mitm"]["counters"]["connect_refused_407"],
        json!(1)
    );

    // 403: a non-loopback target, refused even under the override
    // (as the end of shows). The assertion is skipped on a runner
    // with no routable address at all.
    if let Some(address) = non_loopback_addr() {
        let refused =
            connect_through(proxy, &format!("{address}:{}", echo.addr.port()), None).await;
        assert_proxy_refusal(
            refused.status,
            403,
            refused.header("connection"),
            &refused.json(),
        );
        assert_eq!(
            instance.status()["mitm"]["counters"]["connect_refused_403"],
            json!(1)
        );
    }

    // Unreachable: a loopback port nobody listens on. 502 and 504 are one
    // class.
    let dead_port = reserve_port();
    let refused = connect_through(proxy, &format!("127.0.0.1:{dead_port}"), None).await;
    assert_proxy_refusal(
        refused.status,
        502,
        refused.header("connection"),
        &refused.json(),
    );
    assert_eq!(
        instance.status()["mitm"]["counters"]["connect_unreachable"],
        json!(1)
    );

    // A failed handshake: the client trusts nothing, so the leaf verifies
    // against no root and the handshake fails.
    let result = intercept(
        proxy,
        "api.anthropic.com:443",
        None,
        &ca,
        Offer {
            trust_ca: false,
            ..Offer::default()
        },
    )
    .await;
    assert!(
        result.is_err(),
        "the handshake fails against an empty root store"
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while instance.status()["mitm"]["counters"]["failed_handshakes"] != json!(1) {
        assert!(
            Instant::now() < deadline,
            "the failed handshake was counted within 3 s"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // The totals only rise, and tunnels_opened counts exactly the tunnels
    // that were opened: the two in the steps above plus the failed
    // handshake's CONNECT, which is answered 200 before the handshake fails
    // — the three refusals produced no 200 and so opened nothing.
    let after = instance.status()["mitm"].clone();
    assert_eq!(
        after["counters"],
        json!({
            "intercepted_exchanges": 1,
            "tunnels_opened": 3,
            "connect_refused_407": 1,
            "connect_refused_403": 1,
            "connect_unreachable": 1,
            "failed_handshakes": 1,
        }),
        "every counter moved exactly once: {after}"
    );
    assert_eq!(
        after["tunnels"]["intercepted"],
        json!(1),
        "the intercepted tunnel is still open"
    );
}

/// Over one intercepted HTTP/2
/// connection, eight streams held at the fake upstream are eight overlapping
/// exchanges, each its own audit record with `mode` `mitm`;
/// aborting a held ninth stream cancels its attempt and the
/// connection keeps serving.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_streams_are_concurrent_exchanges() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("concurrent-streams-concurrent", mitm_on()).await;
    instance.add_fsub();
    let ca = ca_file(&instance);
    let tunnel = intercept(
        proxy_addr(&instance),
        "api.anthropic.com:443",
        None,
        &ca,
        Offer::alpn(&["h2"]),
    )
    .await
    .expect("the handshake completes");
    assert_eq!(
        tunnel.alpn.as_deref(),
        Some("h2"),
        "the tunnel negotiated HTTP/2"
    );

    // Eight overlapping exchanges: every upstream answer is held, so the fake
    // sees all eight calls only if all eight streams were in flight at once.
    let gates: Vec<Arc<tokio::sync::Notify>> = (0..8)
        .map(|_| Arc::new(tokio::sync::Notify::new()))
        .collect();
    let before = instance.upstream.calls();
    instance.upstream.script(
        gates
            .iter()
            .map(|g| crate::harness::Reply::Hold(Arc::clone(g))),
    );
    let mut handles = Vec::new();
    for _ in 0..8 {
        let mut sender = tunnel.stream();
        let request = tunnel.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        );
        handles.push(tokio::spawn(async move {
            let response = sender.send_request(request).await.expect("stream sent");
            crate::harness::collect_answer(response).await
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let seen = instance.upstream.calls() - before;
        if seen >= 8 || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        instance.upstream.calls() - before,
        8,
        "eight concurrent streams are eight exchanges the fake saw together"
    );
    for gate in &gates {
        gate.notify_one();
    }
    let mut answers = Vec::new();
    for handle in handles {
        answers.push(handle.await.expect("the stream task"));
    }
    for answer in &answers {
        assert_eq!(
            answer.status,
            200,
            "every stream was served: {}",
            answer.text()
        );
    }
    let records = instance.audit_settled(8);
    assert_eq!(records.len(), 8, "one record per exchange");
    for record in &records {
        assert_eq!(record["mode"], "mitm", "the record names the mode");
    }

    // A reset stream cancels its attempt without wrecking the connection.
    let gate9 = Arc::new(tokio::sync::Notify::new());
    instance
        .upstream
        .script(std::iter::once(crate::harness::Reply::Hold(Arc::clone(
            &gate9,
        ))));
    let mut sender = tunnel.stream();
    let request = tunnel.request(
        Method::POST,
        "api.anthropic.com",
        "/v1/messages",
        &haiku_prompt().to_string(),
    );
    let handle = tokio::spawn(async move {
        let response = sender.send_request(request).await.expect("stream sent");
        crate::harness::collect_answer(response).await
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while instance.upstream.calls() < before + 9 && Instant::now() <= deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        instance.upstream.calls(),
        before + 9,
        "the ninth attempt reached the fake"
    );
    handle.abort();
    gate9.notify_one();
    let mut sender = tunnel.stream();
    let request = tunnel.request(
        Method::POST,
        "api.anthropic.com",
        "/v1/messages",
        &haiku_prompt().to_string(),
    );
    let response = sender
        .send_request(request)
        .await
        .expect("the tunnel still serves after a reset stream");
    let answer = crate::harness::collect_answer(response).await;
    assert_eq!(answer.status, 200, "served: {}", answer.text());

    // The cancelled attempt's record, if one exists, does not say 200.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut records = instance.audit();
    while records.len() < 9 && Instant::now() <= deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        records = instance.audit();
    }
    assert!(
        records.len() >= 9,
        "eight exchanges plus the served tenth are on record"
    );
    let not_200: Vec<&Value> = records
        .iter()
        .filter(|r| r["status"].as_u64() != Some(200))
        .collect();
    assert!(
        not_200.len() <= 1,
        "only the cancelled attempt may miss a 200: {not_200:?}"
    );
    for record in &records {
        assert_eq!(record["mode"], "mitm");
    }
}

/// A request whose authority is
/// neither the tunnel's target nor the probe host gets and is never
/// forwarded: a tunnel to the API host name serves only the API host name
/// (and the probe host), on HTTP/1.1 and HTTP/2 alike, and the refusal
/// leaves no audit record.
#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_authority_inside_a_tunnel_is_421() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("foreign-authority-inside", mitm_on()).await;
    instance.add_fsub();
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);
    let target = "api.anthropic.com:443";

    let mut tunnel = intercept(proxy, target, None, &ca, Offer::alpn(&["http/1.1"]))
        .await
        .expect("the handshake succeeds");
    // The fixture's own fsub validation (`/api/oauth/profile`) can land at
    // any tick after `add_fsub`; only a forwarded `/v1/messages` is ours.
    let messages_calls = |i: &Instance| {
        i.upstream
            .seen()
            .iter()
            .filter(|s| s.path == "/v1/messages")
            .count()
    };
    let before = messages_calls(&instance);

    let request = tunnel.request(
        Method::POST,
        "claude.ai",
        "/v1/messages",
        &haiku_prompt().to_string(),
    );
    let answer = tunnel.send(request).await;
    assert_eq!(answer.status, 421, "the foreign authority is refused");
    let body = answer.json();
    assert_eq!(body["error"]["type"], "proxy_error");
    let message = body["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("claude.ai"),
        "the refusal names the tunnel's own host: {message}"
    );
    assert_eq!(
        messages_calls(&instance),
        before,
        "nothing was forwarded for the foreign authority"
    );

    // The refusal was the request's, not the tunnel's: its own authority
    // still serves.
    let own = tunnel
        .send(tunnel.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await;
    assert_eq!(own.status, 200, "the tunnel still serves its target");

    // The probe host is the one other authority a tunnel accepts.
    let probe = tunnel
        .send(tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await;
    assert_eq!(
        probe.status, 200,
        "the probe host is answered in the tunnel"
    );
    // The count the h2 refusal must not have moved.
    let served = messages_calls(&instance);

    // The 421 left no audit record; the probe host answers before
    // the exchange layer and is not a data-plane exchange, so exactly the
    // one served `/v1/messages` is recorded.
    let records = instance.audit_settled(1);
    assert_eq!(records[0]["path"], "/v1/messages");
    assert_eq!(records[0]["status"], 200);

    // On HTTP/2 the authority is `:authority`, not `host`; hyper reads it
    // off the absolute URI `request` writes, so the same call covers it.
    let mut h2 = intercept(proxy, target, None, &ca, Offer::alpn(&["h2"]))
        .await
        .expect("the HTTP/2 handshake succeeds");
    assert_eq!(h2.alpn.as_deref(), Some("h2"));
    let answer = h2
        .send(h2.request(
            Method::POST,
            "claude.ai",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await;
    assert_eq!(answer.status, 421, "the foreign authority is refused on h2");
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    assert_eq!(messages_calls(&instance), served, "still nothing forwarded");
}

/// No upgrade is carried inside an
/// intercepted tunnel: `upgrade: websocket` and any other token (`h2c`)
/// both get proxy response `proxy_error`, nothing is forwarded, and
/// the tunnel still serves an ordinary exchange afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn an_upgrade_on_an_intercepted_target_is_501() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("upgrade-intercepted-target", mitm_on()).await;
    instance.add_fsub();
    let ca = ca_file(&instance);
    let mut tunnel = intercept(
        proxy_addr(&instance),
        "api.anthropic.com:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the handshake succeeds");
    let before = instance.upstream.calls();

    for token in ["websocket", "h2c"] {
        let mut request = tunnel.request(
            Method::GET,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        );
        let headers = request.headers_mut();
        headers.insert("upgrade", token.parse().unwrap());
        headers.insert("connection", "upgrade".parse().unwrap());
        let answer = tunnel.send(request).await;
        assert_eq!(answer.status, 501, "{token} is refused");
        assert_eq!(
            answer.json()["error"]["type"],
            "proxy_error",
            "{token}: a proxy refusal, not an upstream answer"
        );
    }
    assert_eq!(
        instance.upstream.calls(),
        before,
        "neither upgrade reached the upstream"
    );

    let after = tunnel
        .send(tunnel.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await;
    assert_eq!(
        after.status, 200,
        "the tunnel still serves ordinary requests"
    );
}

/// A client that does not trust the
/// interception CA fails the handshake, and the one log line the failure
/// leaves names the client address, the target and the unknown-CA class; a
/// different failure — bytes that are not a client hello — carries a
/// different class, so the two are told apart in the log.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_does_not_trust_the_ca_is_one_log_line() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("client-does-not-trust", mitm_on()).await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);
    let target = "api.anthropic.com:443";

    let rejected = intercept(
        proxy,
        target,
        None,
        &ca,
        Offer {
            trust_ca: false,
            ..Offer::default()
        },
    )
    .await;
    assert!(
        rejected.is_err(),
        "the client rejects the leaf: {:?}",
        rejected.map(|_| ())
    );

    // A log line can trail the handshake by a tick.
    let deadline = Instant::now() + Duration::from_secs(3);
    let lines = loop {
        let lines = instance.events("mitm_handshake_failed");
        if !lines.is_empty() || Instant::now() > deadline {
            assert_eq!(
                lines.len(),
                1,
                "one line for the failed handshake: {lines:?}"
            );
            break lines;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let line = &lines[0];
    assert_eq!(
        line["fields"]["class"], "unknown_ca",
        "the unknown-CA alert is its own class: {line}"
    );
    assert_eq!(line["fields"]["target"], target, "naming the target");
    assert!(
        line["fields"]["address"]
            .as_str()
            .expect("the client address")
            .starts_with("127.0.0.1:"),
        "and the client's address: {line}"
    );

    // The class is distinguished: another failed handshake, another class.
    let mut plain = connect_through(proxy, target, None).await;
    assert_eq!(plain.status, 200, "the CONNECT itself was answered");
    plain
        .stream
        .write_all(b"not a client hello at all\r\n\r\n")
        .await
        .expect("write the plain bytes");
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), plain.stream.read_to_end(&mut rest))
        .await
        .expect("the tunnel ends")
        .expect("the tunnel ends cleanly");
    let deadline = Instant::now() + Duration::from_secs(3);
    let lines = loop {
        let lines = instance.events("mitm_handshake_failed");
        if lines.len() >= 2 || Instant::now() > deadline {
            assert_eq!(lines.len(), 2, "one line per failed handshake: {lines:?}");
            break lines;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        lines[1]["fields"]["class"], "not_a_tls_client_hello",
        "not a client hello is not the unknown-CA class: {}",
        lines[1]
    );

    // Claude Code's spelling: a real hello, the server's flight read, then the
    // connection closed with no alert — the silent abort of an untrusting
    // client, a class of its own that says it is a probable trust failure.
    let mut silent = connect_through(proxy, target, None).await;
    assert_eq!(silent.status, 200, "the CONNECT itself was answered");
    let untrusting = Offer {
        trust_ca: false,
        ..Offer::default()
    };
    let mut client = rustls::ClientConnection::new(
        intercept_config(&ca, &untrusting),
        "api.anthropic.com".try_into().expect("server name"),
    )
    .expect("client connection");
    let mut hello = Vec::new();
    client.write_tls(&mut hello).expect("the client hello");
    silent
        .stream
        .write_all(&hello)
        .await
        .expect("send the hello");
    // Read the flight until the certificate is rejected, as node does, and
    // never write the alert rustls queued for it.
    let mut flight = [0u8; 4096];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), silent.stream.read(&mut flight))
            .await
            .expect("the server answers the hello")
            .expect("read the server's flight");
        assert!(read > 0, "the server's flight ended before its certificate");
        client
            .read_tls(&mut &flight[..read])
            .expect("buffer the flight");
        if client.process_new_packets().is_err() {
            break;
        }
    }
    silent
        .stream
        .shutdown()
        .await
        .expect("close without an alert");
    drop(silent);

    // And an end of stream before any hello is transport, never either class.
    let mut early = connect_through(proxy, target, None).await;
    assert_eq!(early.status, 200, "the CONNECT itself was answered");
    early
        .stream
        .shutdown()
        .await
        .expect("close before the hello");
    drop(early);

    let deadline = Instant::now() + Duration::from_secs(3);
    let lines = loop {
        let lines = instance.events("mitm_handshake_failed");
        if lines.len() >= 4 || Instant::now() > deadline {
            assert_eq!(lines.len(), 4, "one line per failed handshake: {lines:?}");
            break lines;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        lines[2]["fields"]["class"], "client_closed_during_handshake",
        "the silent abort after the hello: {}",
        lines[2]
    );
    assert!(
        lines[2]["message"]
            .as_str()
            .is_some_and(|m| m.contains("probable trust failure") && m.contains("CA file")),
        "the line says what the signature probably means: {}",
        lines[2]
    );
    assert_eq!(
        lines[3]["fields"]["class"], "transport",
        "an end of stream before the hello is not a trust failure: {}",
        lines[3]
    );
}

/// Each intercepted tunnel
/// leaves one `debug` line naming the principal, the negotiated TLS version
/// and the ALPN protocol; once `logging.level` is unset (the live key,
/// the suite's template pins every instance at `debug`) no such line.
#[tokio::test(flavor = "multi_thread")]
async fn every_intercepted_tunnel_leaves_one_debug_line() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("intercepted-tunnel-leaves-debug", mitm_on()).await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);
    let target = "api.anthropic.com:443";

    intercept(proxy, target, None, &ca, Offer::alpn(&["h2"]))
        .await
        .expect("the h2 tunnel completes");
    intercept(
        proxy,
        target,
        None,
        &ca,
        Offer {
            versions: Some(TLS12_ONLY),
            alpn: vec![b"http/1.1".to_vec()],
            ..Offer::default()
        },
    )
    .await
    .expect("the TLS 1.2 tunnel completes");

    let deadline = Instant::now() + Duration::from_secs(3);
    let lines = loop {
        let lines = instance.events("mitm_tunnel");
        if lines.len() >= 2 || Instant::now() > deadline {
            assert_eq!(lines.len(), 2, "one line per tunnel: {lines:?}");
            break lines;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let pairs: Vec<(String, String)> = lines
        .iter()
        .map(|line| {
            (
                line["fields"]["tls_version"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                line["fields"]["alpn"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    assert!(
        pairs.contains(&("TLSv1.3".to_string(), "h2".to_string())),
        "the h2 tunnel's line: {pairs:?}"
    );
    assert!(
        pairs.contains(&("TLSv1.2".to_string(), "http/1.1".to_string())),
        "the TLS 1.2 tunnel's line: {pairs:?}"
    );
    for line in &lines {
        assert_eq!(
            line["fields"]["principal_role"], "loopback-operator",
            "naming the principal: {line}"
        );
        assert_eq!(line["level"], "debug", "at debug severity: {line}");
    }

    // is what enables the line: with `logging.level` unset (the
    // default `info`) the equivalent tunnel on the same instance leaves no
    // second line.
    let quiet = instance;
    let before = quiet.events("mitm_tunnel").len();
    let envelope = quiet.cli_json(&["config", "unset", "logging.level"], None);
    assert_eq!(envelope["ok"], true, "the level is unset: {envelope}");
    intercept(proxy, target, None, &ca, Offer::default())
        .await
        .expect("the equivalent tunnel completes");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        quiet.events("mitm_tunnel").len(),
        before,
        "at the default level no per-tunnel line is written"
    );
}

/// The pin is not validated at
/// `CONNECT` time: a credential whose pin names no account still tunnels,
/// and inside the tunnel the request is answered by the, naming
/// the pin so Claude Code can print it, with nothing reaching the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_pin_is_404_inside_the_tunnel() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("unknown-pin-404-inside", mitm_on()).await;
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let ca = ca_file(&instance);

    let token = |reference: &str| {
        use base64::Engine as _;
        format!(
            "pin.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reference)
        )
    };
    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    };

    // The CONNECT is answered 200 — the pin names nothing, and that
    // is nobody's business yet — and the handshake completes.
    let mut tunnel = intercept(
        proxy_addr(&instance),
        "api.anthropic.com:443",
        Some(&basic(&token("no-such-account"), &alpha.secret)),
        &ca,
        Offer::default(),
    )
    .await
    .expect("the pin was not validated at CONNECT time");

    let calls = instance.upstream.calls();
    let answer = tunnel
        .send(tunnel.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await;
    assert_eq!(answer.status, 404, "{}", answer.text());
    assert_eq!(
        answer.json()["error"]["type"],
        "not_found_error",
        "the refusal type: {}",
        answer.text()
    );
    let message = answer.json()["error"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(
        message.contains("no-such-account"),
        "the message names the pin: {message}"
    );
    assert_eq!(
        instance.upstream.calls(),
        calls,
        "nothing reached the upstream"
    );

    // The refused exchange is on record as a mitm exchange that served
    // nobody.
    let record = instance.last_record(1);
    assert_eq!(record["mode"], "mitm");
    assert_eq!(record["status"], 404);
    assert_eq!(record["serving_account"], Value::Null);
}

/// The tunnel fixes its pin at
/// `CONNECT` and serves every request under it: two intercepted tunnels from
/// one client, pinned to the pool's two accounts, are two independent
/// selection contexts, each request served by its tunnel's account, and a
/// `x-jaynshare-account` header inside a tunnel is removed and ignored
/// — it cannot replace the tunnel's fixed intent.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_tunnel_serves_that_account_and_two_pins_are_independent() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("pinned-tunnel-serves", mitm_on()).await;
    crate::harness::add_two(&instance);
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);

    let token = |reference: &str| {
        use base64::Engine as _;
        format!(
            "pin.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reference)
        )
    };
    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    };

    // Two intercepted tunnels at once, one pinned to each account.
    let mut a = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic(&token("FSUB"), &alpha.secret)),
        &ca,
        Offer::default(),
    )
    .await
    .expect("tunnel A, pinned to FSUB");
    let mut b = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic(&token("FSUB2"), &alpha.secret)),
        &ca,
        Offer::default(),
    )
    .await
    .expect("tunnel B, pinned to FSUB2");

    // Two requests in each, one at a time, each attributed to its tunnel's
    // own account.
    let mut served: Vec<(String, &str)> = Vec::new();
    for (which, expected) in [("a", "FSUB"), ("a", "FSUB"), ("b", "FSUB2"), ("b", "FSUB2")] {
        let tunnel = match which {
            "a" => &mut a,
            _ => &mut b,
        };
        let answer = tunnel
            .send(tunnel.request(
                Method::POST,
                "api.anthropic.com",
                "/v1/messages",
                &haiku_prompt().to_string(),
            ))
            .await;
        assert_eq!(answer.status, 200, "served: {}", answer.text());
        let deadline = Instant::now() + Duration::from_secs(3);
        let records = loop {
            let records = instance.audit();
            if records.len() > served.len() || Instant::now() > deadline {
                break records;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let record = records
            .get(served.len())
            .expect("the exchange is on record");
        assert_eq!(record["mode"], "mitm", "{record}");
        assert_eq!(record["pinned"], true, "the tunnel's pin: {record}");
        let by = record["serving_account"]["display_name"]
            .as_str()
            .expect("an account")
            .to_owned();
        assert_eq!(
            by, expected,
            "{which}: served by its own pin, never the other's: {record}"
        );
        served.push((by, expected));
    }

    // The intent is the tunnel's, not the request's: a request
    // inside tunnel A carrying a pin header for B is still served by A, and
    // the header never reaches the decoded destination.
    let mut request = a.request(
        Method::POST,
        "api.anthropic.com",
        "/v1/messages",
        &haiku_prompt().to_string(),
    );
    request
        .headers_mut()
        .insert("x-jaynshare-account", token("FSUB2").parse().unwrap());
    let answer = a.send(request).await;
    assert_eq!(answer.status, 200, "served: {}", answer.text());
    let record = instance.last_record(5);
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB",
        "the header cannot replace the tunnel's fixed intent: {record}"
    );
    assert_eq!(record["pinned"], true, "still the tunnel's pin: {record}");
    assert!(
        instance
            .upstream
            .last()
            .header("x-jaynshare-account")
            .is_none(),
        "no proxy metadata reaches a decoded destination"
    );
}

/// No control plane through the proxy: a request
/// decoded from an intercepted tunnel and an absolute-form forwarded request
/// are requests for Anthropic's host and reach the data plane only — the
/// upstream sees the path, the answer is the upstream's, and the audit
/// record is a data-plane record — while the same path on the base-URL
/// listener is still the control read.
#[tokio::test(flavor = "multi_thread")]
async fn a_control_path_through_the_proxy_is_a_data_plane_request() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("control-path-through", mitm_on()).await;
    instance.add_fsub();
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);

    // Inside a tunnel: the path reaches the fake upstream as an ordinary
    // exchange, and the answer is the upstream's, not a control envelope.
    let mut tunnel = intercept(
        proxy,
        "api.anthropic.com:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the handshake succeeds");
    let request = tunnel.request(Method::GET, "api.anthropic.com", "/control/v1/status", "");
    let answer = tunnel.send(request).await;
    assert_eq!(
        answer.status,
        200,
        "the exchange was served: {}",
        answer.text()
    );
    assert_eq!(
        instance.upstream.last().path,
        "/control/v1/status",
        "the fake upstream saw the path: forwarded, not answered"
    );
    let body = answer.json();
    assert!(
        body["control_api_version"].is_null(),
        "no control envelope inside the tunnel: {body}"
    );
    let record = instance.last_record(1);
    assert_eq!(record["mode"], "mitm", "a data-plane exchange, on record");
    assert_eq!(record["path"], "/control/v1/status");

    // In absolute form: forwarded plain to the staged target, unanswered by
    // the proxy and carrying nothing injected.
    let target = HttpTarget::start().await;
    let forwarded = absolute_form(
        proxy,
        "GET",
        &format!("http://{}/control/v1/status", target.addr),
        &[],
        None,
    )
    .await;
    assert_eq!(forwarded.status, 201, "the target's own answer is relayed");
    assert_eq!(forwarded.body, "forwarded", "and its body");
    assert_eq!(
        target.calls(),
        1,
        "the proxy forwarded the request rather than answering it"
    );
    let (head, _) = target.last();
    assert_eq!(
        head.lines().next(),
        Some("GET /control/v1/status HTTP/1.1"),
        "the path unchanged: {head}"
    );
    let lowered = head.to_ascii_lowercase();
    assert!(
        !lowered.contains("proxy-authorization") && !lowered.contains("\nauthorization"),
        "no credential was injected: {head}"
    );
    assert!(!lowered.contains("x-api-key"), "nor a pooled key: {head}");

    // The control plane is still the base-URL listener's: the same path
    // there is the control read, envelope and all.
    let control = send(
        instance.addr,
        Request::builder()
            .method(Method::GET)
            .uri("/control/v1/status")
            .body(Full::new(Bytes::new()))
            .expect("the control read builds"),
    )
    .await;
    assert_eq!(control.status, 200, "{}", control.text());
    assert_eq!(
        control.json()["control_api_version"],
        1,
        "the control read is the control plane's: {}",
        control.text()
    );
}

/// The user field of the proxy
/// credential survives the proxy URL's user information either way: the
/// token uses only URL-unreserved characters, so percent-encoding
/// the userinfo changes nothing; presented as the credential's user field
/// inside a tunnel and as the base-URL header, it decodes to the same
/// reference and both exchanges are served by `FSUB2`; a user field whose
/// dot has been over-encoded is not a token, so it authenticates but every
/// request inside that tunnel is refused and the upstream
/// sees nothing. The generation half — a token never leaves the unreserved
/// set — is the unit tests of `src/data_plane/intent.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn the_user_field_survives_the_proxy_url_either_way() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("user-field-survives", mitm_on()).await;
    crate::harness::add_two(&instance);
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);

    let token = |pin: bool, reference: &str| {
        use base64::Engine as _;
        let d = if pin { "pin" } else { "pref" };
        format!(
            "{d}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reference)
        )
    };
    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    };
    // What a correct client does to a proxy URL's user information
    // percent-encode everything outside the unreserved set — is the identity
    // on a token, so both presentations reach the proxy byte-identical.
    let userinfo_encode = |s: &str| -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    let pin = token(true, "FSUB2");
    assert_eq!(
        userinfo_encode(&pin),
        pin,
        "the token is unreserved, so encoding it changes nothing"
    );

    // Presented as the proxy credential's user field, inside a tunnel.
    let mut tunnel = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic(&pin, &alpha.secret)),
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the credential resolves and the handshake succeeds");
    let request = tunnel.request(
        Method::POST,
        "api.anthropic.com",
        "/v1/messages",
        &haiku_prompt().to_string(),
    );
    let answer = tunnel.send(request).await;
    assert_eq!(answer.status, 200, "served: {}", answer.text());
    let record = instance.last_record(1);
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB2",
        "the user field decoded to FSUB2's reference: {record}"
    );

    // Presented as the base-URL header: the same token, the same account.
    let answer = send(
        instance.addr,
        crate::harness::pinned(messages(haiku_prompt()), "FSUB2"),
    )
    .await;
    assert_eq!(answer.status, 200, "served: {}", answer.text());
    let record = instance.last_record(2);
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB2",
        "the header decoded to the same reference: {record}"
    );

    // Nothing depends on percent-encoding surviving: an over-encoded user
    // field is not a token, so it authenticates and every request inside
    // that tunnel is the 400; the upstream sees nothing.
    let before = instance.upstream.calls();
    let over_encoded = pin.replace('.', "%2E");
    let mut tunnel = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic(&over_encoded, &alpha.secret)),
        &ca,
        Offer::default(),
    )
    .await
    .expect("a malformed user field authenticates");
    let answer = exchange_in(&mut tunnel).await;
    assert_eq!(answer.status, 400, "{}", answer.text());
    assert_eq!(
        answer.json()["error"]["type"],
        "invalid_request_error",
        "the refusal type: {}",
        answer.text()
    );
    assert_eq!(
        instance.upstream.calls(),
        before,
        "the fake upstream saw nothing new"
    );
}

/// The credential is
/// re-validated on every request decoded inside an open tunnel: revoked
/// mid-tunnel, the next exchange is the envelope, answered inside
/// the still-open tunnel with nothing forwarded; rotated mid-tunnel, the old
/// secret dies the same way while the replacement opens a fresh tunnel.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_client_loses_its_open_tunnel() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("revoked-client-loses", mitm_on()).await;
    instance.add_fsub();
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);
    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    };
    // An open tunnel under alpha's secret; one exchange served.
    let mut tunnel = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic("", &alpha.secret)),
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the credential resolves");
    let served = exchange_in(&mut tunnel).await;
    assert_eq!(served.status, 200, "served: {}", served.text());
    let seen = instance.upstream.calls();

    // Revoked while the tunnel is open: the next exchange inside it is the
    // envelope, and nothing was forwarded for it.
    let revoked = crate::harness::control_post(
        instance.addr,
        "/control/v1/clients/alpha/revoke",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(revoked.status, 200, "{revoked:?}");
    let refused = exchange_in(&mut tunnel).await;
    assert_eq!(refused.status, 401, "{}", refused.text());
    let body = refused.json();
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "the class: {body}"
    );
    assert_eq!(
        body["error"]["message"],
        "the proxy credential is missing or invalid: this is the Jaynshare client secret, not an Anthropic key; re-enrol if it was rotated or revoked",
        "the envelope::unauthenticated() message, byte for byte: {body}"
    );
    assert_eq!(
        instance.upstream.calls(),
        seen,
        "the revoked credential's exchange never reached the upstream"
    );
    // The tunnel itself was not torn down: the 401 came as an HTTP response
    // inside it, and the same connection still answers.
    let again = exchange_in(&mut tunnel).await;
    assert_eq!(
        again.status,
        401,
        "still refused, still inside the tunnel: {}",
        again.text()
    );

    // The same for rotation, on a second client and a second tunnel: the old
    // secret dies inside the open tunnel, the replacement opens a new one.
    let beta = enroll(&instance, "beta", "Beta").await;
    let mut old = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic("", &beta.secret)),
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the credential resolves");
    let served = exchange_in(&mut old).await;
    assert_eq!(served.status, 200, "served: {}", served.text());
    let rotated = crate::harness::control_post(
        instance.addr,
        "/control/v1/clients/beta/rotate",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(rotated.status, 200, "{rotated:?}");
    let replacement = rotated.json()["client_secret"]
        .as_str()
        .expect("the new secret")
        .to_string();
    assert_eq!(rotated.json()["client"]["id"], "beta", "the id is retained");
    let stale = exchange_in(&mut old).await;
    assert_eq!(
        stale.status,
        401,
        "the old secret is dead inside its own tunnel: {}",
        stale.text()
    );
    assert_eq!(stale.json()["error"]["type"], "authentication_error");
    let mut fresh = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic("", &replacement)),
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the replacement secret resolves");
    let answer = exchange_in(&mut fresh).await;
    assert_eq!(answer.status, 200, "served: {}", answer.text());
}

/// The Basic password
/// authenticates the principal and the Basic user field carries the intent:
/// an empty user field with a good password opens a tunnel audited under its
/// client id, a bad password is the; a user field holding one
/// token pins the tunnel to that account even though the pool default
/// differs, a user field that is neither empty nor one token opens the
/// tunnel but gets per request, and `x-jaynshare-account`
/// inside the tunnel can neither replace the pin nor reach the decoded
/// destination with any proxy metadata.
#[tokio::test(flavor = "multi_thread")]
async fn the_basic_password_authenticates_and_the_user_field_carries_intent() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("basic-password-authenticates", mitm_on()).await;
    crate::harness::add_two(&instance);
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);

    let token = |pin: bool, reference: &str| {
        use base64::Engine as _;
        let d = if pin { "pin" } else { "pref" };
        format!(
            "{d}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reference)
        )
    };
    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    };

    // The password authenticates: an empty user field and alpha's secret
    // open a tunnel, and its exchange is audited under alpha's principal.
    let mut tunnel = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic("", &alpha.secret)),
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the password resolves");
    let answer = tunnel
        .send(tunnel.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await;
    assert_eq!(answer.status, 200, "served: {}", answer.text());

    // A password that resolves to nothing is refused before any connection.
    let before = instance.upstream.calls();
    let refused = connect_through(
        proxy,
        "api.anthropic.com:443",
        Some(&basic("", "jsc2_not_a_secret")),
    )
    .await;
    assert_proxy_refusal(
        refused.status,
        407,
        refused.header("connection"),
        &refused.json(),
    );
    assert_eq!(
        instance.upstream.calls(),
        before,
        "the fake upstream saw nothing new"
    );

    // The user field carries the intent: this tunnel's exchange is served by
    // FSUB2 even though FSUB is the pool's default.
    let mut pinned = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic(&token(true, "FSUB2"), &alpha.secret)),
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the credential and token resolve");
    let answer = pinned
        .send(pinned.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await;
    assert_eq!(answer.status, 200, "served: {}", answer.text());

    // The in-tunnel header cannot override the tunnel's fixed intent.
    let mut request = pinned.request(
        Method::POST,
        "api.anthropic.com",
        "/v1/messages",
        &haiku_prompt().to_string(),
    );
    request
        .headers_mut()
        .insert("x-jaynshare-account", token(true, "FSUB").parse().unwrap());
    let answer = pinned.send(request).await;
    assert_eq!(answer.status, 200, "served: {}", answer.text());

    // Three records: alpha's tunnel under its principal, both pinned
    // exchanges served by FSUB2.
    let records = instance.audit_settled(3);
    assert_eq!(
        records[0]["principal"]["kind"], "client",
        "the empty user field's principal: {}",
        records[0]
    );
    assert_eq!(records[0]["principal"]["id"], "alpha");
    for record in &records[1..] {
        assert_eq!(
            record["serving_account"]["display_name"], "FSUB2",
            "the user field's intent served the exchange: {record}"
        );
    }
    // No proxy metadata reaches a decoded destination.
    assert!(
        instance
            .upstream
            .last()
            .header("x-jaynshare-account")
            .is_none(),
        "the intent header was removed"
    );
    assert!(
        instance
            .upstream
            .last()
            .header("proxy-authorization")
            .is_none(),
        "the credential was removed"
    );

    //A user field that is neither empty nor one token opens the
    // tunnel, and every request inside it is the 400; nothing moves.
    let before = instance.upstream.calls();
    let mut tunnel = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&basic("junk", &alpha.secret)),
        &ca,
        Offer::default(),
    )
    .await
    .expect("a malformed user field authenticates");
    let answer = exchange_in(&mut tunnel).await;
    assert_eq!(answer.status, 400, "{}", answer.text());
    assert_eq!(
        answer.json()["error"]["type"],
        "invalid_request_error",
        "the refusal type: {}",
        answer.text()
    );
    assert_eq!(
        instance.upstream.calls(),
        before,
        "the fake upstream saw nothing new"
    );
}

/// One `POST /v1/messages` inside an intercepted tunnel.
async fn exchange_in(tunnel: &mut Intercepted) -> Answer {
    tunnel
        .send(tunnel.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await
}

/// What a real Claude Code does with a launch environment: `CONNECT`
/// the API host through `HTTPS_PROXY` with the URL's userinfo as the Basic
/// credential, trust only `NODE_EXTRA_CA_CERTS`, and send one Messages
/// request. The fake Claude cannot (it has no TLS), so the client scenarios
/// send it from the environment the fake recorded. The launcher's tokens and
/// secrets are unreserved characters, so the userinfo needs no decoding.
pub(crate) async fn claude_request(env: &std::collections::BTreeMap<String, String>) -> Answer {
    use base64::Engine as _;
    let url = env
        .get("HTTPS_PROXY")
        .expect("a MITM launch sets HTTPS_PROXY");
    let (userinfo, authority) = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split_once('@'))
        .expect("http://<user>:<secret>@<proxy>");
    let credential = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(userinfo)
    );
    let proxy: SocketAddr = authority
        .trim_end_matches('/')
        .parse()
        .expect("the proxy authority is a socket address");
    let ca = PathBuf::from(
        env.get("NODE_EXTRA_CA_CERTS")
            .expect("a MITM launch sets NODE_EXTRA_CA_CERTS"),
    );
    let mut tunnel = intercept(
        proxy,
        "api.anthropic.com:443",
        Some(&credential),
        &ca,
        Offer::default(),
    )
    .await
    .expect("TLS inside the tunnel, trusting the launch's CA");
    exchange_in(&mut tunnel).await
}

/// Every refusal is traceable to a
/// caller's address: a 401 through its audit record's `source_address`
///A 407, a 403, an unreachable tunnel target and a failed
/// handshake each through its own log line naming the caller. The
/// counter-claim of: a successful tunnel leaves no refusal line and
/// no log line naming its target — it is counted, not logged.
#[tokio::test(flavor = "multi_thread")]
async fn every_refusal_class_names_the_caller() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("refusal-class-names-caller", mitm_on()).await;
    // Enrolled first so the bootstrap exemption is closed and every
    // refusal below is its own class, not the bootstrap answering.
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let echo = Echo::start().await;
    let proxy = proxy_addr(&instance);

    // 401: a base-URL exchange with a bad bearer. Its audit
    // record is asserted at the end of the scenario, so a red there does
    // not hide the other refusal classes.
    let refused = send(
        instance.addr,
        crate::harness::with(
            messages(haiku_prompt()),
            &[("authorization", "Bearer jsc2_wrong")],
        ),
    )
    .await;
    assert_eq!(refused.status, 401);
    assert_eq!(refused.json()["error"]["type"], "authentication_error");

    // 407: a presented credential that resolves to nothing.
    use base64::Engine as _;
    let bad_basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("u:jsc2_wrong")
    );
    let refused = connect_through(proxy, &echo.target(), Some(&bad_basic)).await;
    assert_proxy_refusal(
        refused.status,
        407,
        refused.header("connection"),
        &refused.json(),
    );
    let refusals = instance.events("proxy_refused");
    assert_eq!(refusals.len(), 1, "one line for the refusal: {refusals:?}");
    assert_eq!(refusals[0]["fields"]["status"], 407);
    assert!(
        refusals[0]["fields"]["peer"]
            .as_str()
            .expect("the caller's address")
            .starts_with("127.0.0.1:"),
        "the 407 names the caller: {refusals:?}"
    );

    // 403: a CONNECT to the proxy host's own non-loopback address, refused
    // before any connection. The clause is skipped on a runner with no
    // routable address at all.
    if let Some(address) = non_loopback_addr() {
        let refused =
            connect_through(proxy, &format!("{address}:{}", echo.addr.port()), None).await;
        assert_proxy_refusal(
            refused.status,
            403,
            refused.header("connection"),
            &refused.json(),
        );
        let refusals = instance.events("proxy_refused");
        assert_eq!(refusals.len(), 2, "one line per refusal: {refusals:?}");
        assert_eq!(refusals[1]["fields"]["status"], 403);
        assert!(
            refusals[1]["fields"]["peer"]
                .as_str()
                .expect("the caller's address")
                .starts_with("127.0.0.1:"),
            "the 403 names the caller: {refusals:?}"
        );
    }

    // An unreachable tunnel target: a loopback port nobody listens on.
    let dead_port = reserve_port();
    let refused = connect_through(proxy, &format!("127.0.0.1:{dead_port}"), None).await;
    assert_proxy_refusal(
        refused.status,
        502,
        refused.header("connection"),
        &refused.json(),
    );
    let refusals = instance.events("proxy_refused");
    assert_eq!(refusals.len(), 3, "one line per refusal: {refusals:?}");
    assert!(
        refusals[2]["fields"]["peer"]
            .as_str()
            .expect("the caller's address")
            .starts_with("127.0.0.1:"),
        "the unreachable target's refusal names the caller: {refusals:?}"
    );

    // A failed handshake: the client does not trust the CA.
    let rejected = intercept(
        proxy,
        "api.anthropic.com:443",
        None,
        &ca_file(&instance),
        Offer {
            trust_ca: false,
            ..Offer::default()
        },
    )
    .await;
    assert!(
        rejected.is_err(),
        "the client rejects the leaf: {:?}",
        rejected.map(|_| ())
    );
    // A log line can trail the handshake by a tick.
    let deadline = Instant::now() + Duration::from_secs(3);
    let lines = loop {
        let lines = instance.events("mitm_handshake_failed");
        if !lines.is_empty() || Instant::now() > deadline {
            break lines;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        lines.len(),
        1,
        "one line for the failed handshake: {lines:?}"
    );
    assert_eq!(
        lines[0]["fields"]["class"], "unknown_ca",
        "the unknown-CA alert is its own class: {lines:?}"
    );
    assert!(
        lines[0]["fields"]["address"]
            .as_str()
            .expect("the caller's address")
            .starts_with("127.0.0.1:"),
        "the failed handshake names the caller: {lines:?}"
    );

    // the counter-claim: a successful tunnel is counted, not logged. A
    // fresh echo, so the refusal lines above — which name the refused
    // targets — cannot mask the assertion.
    let quiet = Echo::start().await;
    let credential = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("pin.QUJD:{}", alpha.secret)),
    );
    let mut tunnel = connect_through(proxy, &quiet.target(), Some(&credential)).await;
    assert_eq!(tunnel.status, 200, "the resolvable credential is served");
    assert_eq!(tunnel.round_trip(b"traceable").await, b"traceable");
    assert_eq!(
        instance.events("proxy_refused").len(),
        3,
        "the successful tunnel left no refusal line"
    );
    assert!(
        !server_log(&instance).contains(&quiet.target()),
        "the successful tunnel's target is nowhere in the log"
    );

    // the first clause: the 401 is traced through its audit record
    // — the record makes every exchange leave, with the
    // caller's source address in it. Asserted last so a red here does not
    // hide the classes above.
    let records = instance.audit_settled(1);
    assert_eq!(records.len(), 1, "the refusal left its record");
    assert!(
        records[0]["source_address"]
            .as_str()
            .expect("the caller's address")
            .starts_with("127.0.0.1:"),
        "a 401 is traced to its caller: {records:?}"
    );
}

#[tokio::test]
async fn advertised_origins_are_self_targets() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let echo = Echo::start().await;

    // 203.0.113.7 is TEST-NET-3: nothing connects there, so a refusal that
    // arrives before any connection is the only passable assertion. The
    // advertised origin is not the host's own address, yet it is self
    // it is the published address an enrolled client reaches back on.
    let instance = Instance::start_with(
        "self-targets-403-a",
        Setup {
            no_upstream_override: true,
            clients: "advertised_base_url = \"http://203.0.113.7:17421\"\n".into(),
            ..mitm_on()
        },
    )
    .await;
    let proxy = proxy_addr(&instance);
    for target in ["203.0.113.7:17421", "203.0.113.7:9"] {
        let refused = connect_through(proxy, target, None).await;
        assert_proxy_refusal(
            refused.status,
            403,
            refused.header("connection"),
            &refused.json(),
        );
    }

    // A different address on the same network is not a self target: the
    // guard lets it through to the connector, which cannot reach TEST-NET-3.
    let through = connect_through(proxy, "203.0.113.8:9", None).await;
    assert_ne!(
        through.status, 403,
        "an unrelated routable address is not a self target"
    );
    assert!(
        matches!(through.status, 502 | 504),
        "the unreachable target fails in the connector: {}",
        through.status
    );
    assert_eq!(echo.opened(), 0);
}

#[tokio::test]
async fn bracketed_ipv6_literals_are_classified() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let echo = Echo::start().await;

    // the override stays off: loopback is then a self target.
    let instance = Instance::start_with(
        "self-targets-403-b",
        Setup {
            no_upstream_override: true,
            ..mitm_on()
        },
    )
    .await;
    let proxy = proxy_addr(&instance);

    // A bracketed IPv6 literal is parsed as an address, not sent to the
    // resolver: loopback is refused with 403 before any connection,
    // in the short and the long form alike.
    for target in ["[::1]:443", "[0:0:0:0:0:0:0:1]:443"] {
        let refused = connect_through(proxy, target, None).await;
        assert_proxy_refusal(
            refused.status,
            403,
            refused.header("connection"),
            &refused.json(),
        );
    }

    // `::ffff:127.0.0.1` is the same address as `127.0.0.1` (is an
    // address rule), so the mapped loopback form is refused with 403 before
    // any connection, exactly like the plain form above.
    let mapped = connect_through(proxy, "[::ffff:127.0.0.1]:443", None).await;
    assert_proxy_refusal(
        mapped.status,
        403,
        mapped.header("connection"),
        &mapped.json(),
    );

    // A routable IPv6 literal is not a self target and reaches the connector;
    // 2001:db8:: is TEST-NET/documentation space, so the connector's failure
    // is the expected outcome.
    let through = connect_through(proxy, "[2001:db8::1]:9", None).await;
    assert_ne!(
        through.status, 403,
        "a routable literal is not a self target: {}",
        through.body
    );
    assert!(
        !through.body.contains("cannot be resolved"),
        "a literal target is never resolved: {}",
        through.body
    );
    assert_eq!(echo.opened(), 0);
}

#[tokio::test]
async fn a_mapped_host_address_is_a_self_target() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let echo = Echo::start().await;

    // The advertised origin 203.0.113.7 (TEST-NET-3) is a self target,
    // and is an address rule: `::ffff:203.0.113.7` is the same
    // address, so the mapped form is refused with 403 before any connection.
    let instance = Instance::start_with(
        "self-targets-403-c",
        Setup {
            no_upstream_override: true,
            clients: "advertised_base_url = \"http://203.0.113.7:17421\"\n".into(),
            ..mitm_on()
        },
    )
    .await;

    let refused = connect_through(proxy_addr(&instance), "[::ffff:203.0.113.7]:17421", None).await;
    assert_proxy_refusal(
        refused.status,
        403,
        refused.header("connection"),
        &refused.json(),
    );

    assert_eq!(echo.opened(), 0);
}

/// An absolute-form `http://` request
/// is *sent to* the corporate proxy on a direct connection to it: the proxy's
/// log carries the request line itself, not a `CONNECT` to the target; an
/// `https` target is still tunnelled by `CONNECT`; and a proxy URL with user
/// information puts the same `proxy-authorization` on the absolute-form
/// request the CONNECT carries.
#[tokio::test(flavor = "multi_thread")]
async fn absolute_form_is_sent_to_the_corporate_proxy() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let chain = Chain::start_carrying(Inside::Http).await;
    let instance = Instance::start_with(
        "tunnels-chain-through-absolute-form",
        Setup {
            data_plane: chain.settings(&[]),
            ..mitm_on()
        },
    )
    .await;
    let proxy = proxy_addr(&instance);

    // Plain `http://`: sent to the corporate proxy in absolute-form — the
    // proxy's log carries `GET http://…`, never a `CONNECT`.
    let forwarded = absolute_form(
        proxy,
        "GET",
        "http://api.anthropic.com/v1/messages",
        &[],
        None,
    )
    .await;
    assert_eq!(forwarded.status, 200, "forwarded through the proxy");
    assert_eq!(
        forwarded.body, "chained",
        "and the target's answer came back"
    );
    let lines = chain.request_lines();
    assert_eq!(
        lines.first().map(String::as_str),
        Some("GET http://api.anthropic.com/v1/messages HTTP/1.1"),
        "the request line itself reached the corporate proxy: {lines:?}"
    );
    assert!(
        lines.iter().all(|line| !line.starts_with("CONNECT ")),
        "no tunnel was chained for a plain `http://` target: {lines:?}"
    );

    // `https://`: still tunnelled — one `CONNECT` with the name and the port
    // (the tunnelled half, asserted so the split cannot regress).
    let tunnelled = connect_through(proxy, "elsewhere.example.com:443", None).await;
    assert_eq!(tunnelled.status, 200, "the chained tunnel is open");
    assert_eq!(
        chain.request_lines()[1],
        "CONNECT elsewhere.example.com:443 HTTP/1.1",
        "an `https` target is reached by CONNECT: {:?}",
        chain.request_lines()
    );

    // A proxy URL with user information: the absolute-form request carries
    // the proxy's own credential, the same value the CONNECT carries.
    let authorized = Chain::start_carrying(Inside::Http).await;
    let password = "lure-374m";
    crate::leaks::register_needle("corporate-proxy-password", password);
    let instance = Instance::start_with(
        "tunnels-chain-through-credential",
        Setup {
            data_plane: format!(
                "corporate_proxy_url = \"http://raven:{password}@{}\"\nno_proxy = []\n",
                authorized.addr
            ),
            ..mitm_on()
        },
    )
    .await;
    let proxy = proxy_addr(&instance);
    let forwarded = absolute_form(
        proxy,
        "GET",
        "http://api.anthropic.com/v1/messages",
        &[],
        None,
    )
    .await;
    assert_eq!(forwarded.status, 200, "forwarded through the proxy");
    let heads = authorized.heads();
    assert_eq!(
        heads[0].lines().next(),
        Some("GET http://api.anthropic.com/v1/messages HTTP/1.1"),
        "sent to the proxy in absolute-form: {}",
        heads[0]
    );
    let proxy_credential = heads[0]
        .lines()
        .find(|line| {
            line.to_ascii_lowercase()
                .starts_with("proxy-authorization:")
        })
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim().to_owned())
        .expect("the absolute-form request carries the proxy's credential");
    let tunnelled = connect_through(proxy, "elsewhere.example.com:443", None).await;
    assert_eq!(tunnelled.status, 200, "the chained tunnel is open");
    let connect_credential = authorized
        .heads()
        .iter()
        .find(|head| head.starts_with("CONNECT "))
        .and_then(|head| {
            head.lines().find(|line| {
                line.to_ascii_lowercase()
                    .starts_with("proxy-authorization:")
            })
        })
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim().to_owned())
        .expect("the CONNECT carries the proxy's credential");
    assert_eq!(
        proxy_credential, connect_credential,
        "the same credential on both forms"
    );
    assert!(
        proxy_credential.starts_with("Basic "),
        "and it is the userinfo credential: {proxy_credential}"
    );
}

/// A staged CA leaves the presented leaf alone; `ca rotate --now` while the
/// proxy listener serves, and the next intercepted handshake presents the new
/// leaf: made with the new CA file as the only trust anchor, it succeeds
/// and the probe host reports the new fingerprint, while the tunnel opened
/// before the rotation keeps serving on the leaf it negotiated. The
/// listener reads the CA from the server at the moment the request
/// arrives, so the rotation is live without a restart.
#[tokio::test(flavor = "multi_thread")]
async fn a_rotated_ca_is_live_on_the_listener() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("rotate-replaces-material-rotate", mitm_on()).await;
    let proxy = proxy_addr(&instance);
    let ca = ca_file(&instance);
    let old = crate::mtm::ca_fingerprint(&instance.root.join("state"));

    // The handshake before the rotation presents the old fingerprint.
    let mut tunnel = intercept(
        proxy,
        "probe.jaynshare.invalid:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the probe host is an intercepted name");
    let answer = tunnel
        .send(tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await;
    assert_eq!(answer.status, 200, "answered: {}", answer.text());
    assert_eq!(
        answer.json()["ca_fingerprint"],
        old,
        "the leaf in force at start"
    );

    // A staged CA: new handshakes still present the current leaf.
    let envelope = instance.cli_json(&["ca", "rotate", "--yes"], None);
    assert_eq!(envelope["ok"], true, "staged: {envelope}");
    let mut staged_tunnel = intercept(
        proxy,
        "probe.jaynshare.invalid:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the current CA still validates the leaf");
    let answer = staged_tunnel
        .send(staged_tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await;
    assert_eq!(answer.json()["ca_fingerprint"], old, "{}", answer.text());

    // Rotate now while the listener serves.
    let envelope = instance.cli_json(&["ca", "rotate", "--now", "--yes"], None);
    assert_eq!(envelope["ok"], true, "the rotation applied: {envelope}");
    let new = envelope["result"]["fingerprint"]
        .as_str()
        .or_else(|| envelope["fingerprint"].as_str())
        .expect("the rotate answer carries the new fingerprint")
        .to_owned();
    assert_ne!(new, old, "the rotation changed the CA");

    // The tunnel established before the rotation keeps the leaf it
    // negotiated until it closes, so it still serves — under the
    // old trust anchor, which this client is still holding. What it reports
    // is the CA now in force, which is how a client learns it changed.
    let answer = tunnel
        .send(tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await;
    assert_eq!(
        answer.status,
        200,
        "the open tunnel survives the rotation: {}",
        answer.text()
    );
    assert_eq!(
        answer.json()["ca_fingerprint"],
        new,
        "and reports the CA now in force"
    );

    // A new handshake, made with the new CA as the only trust anchor
    // (the intercepting config re-reads the rotated file), succeeds and
    // the probe host reports the new fingerprint.
    let mut rotated_tunnel = intercept(
        proxy,
        "probe.jaynshare.invalid:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the new CA validates the new leaf");
    let answer = rotated_tunnel
        .send(rotated_tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await;
    assert_eq!(answer.status, 200, "answered: {}", answer.text());
    assert_eq!(
        answer.json()["ca_fingerprint"],
        new,
        "the new handshake presents the new leaf"
    );
    assert_eq!(
        instance.status()["mitm"]["ca"]["fingerprint"],
        new,
        "status reports the CA in force"
    );
}

/// A user field that is
/// neither empty nor one token does not fail authentication: the
/// tunnel opens, and every request decoded inside it — the first and any
/// later one — is the `invalid_request_error`, with nothing
/// reaching the upstream, while the probe host still answers and
/// echoes the user field byte-identically. stays for a credential
/// whose password does not resolve: the secret parked in the user field
/// with an empty password is refused as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_user_field_opens_the_tunnel_and_400s_inside() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("malformed-user-field", mitm_on()).await;
    crate::harness::add_two(&instance);
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let ca = ca_file(&instance);
    let proxy = proxy_addr(&instance);

    let basic = |user: &str, password: &str| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    };

    // Each malformed user field authenticates, opens the tunnel,
    // and both requests inside it are the 400 — "every request".
    let before = instance.upstream.calls();
    for user_field in [
        "junk",
        "pinned.QUJD",
        "pin.QUJD~.",
        "pin.QUJ%44",
        "pin.QUJD,pref.QUJD",
    ] {
        let mut tunnel = intercept(
            proxy,
            "api.anthropic.com:443",
            Some(&basic(user_field, &alpha.secret)),
            &ca,
            Offer::default(),
        )
        .await
        .unwrap_or_else(|e| panic!("{user_field}: the tunnel opens: {e}"));
        for i in [1, 2] {
            let answer = exchange_in(&mut tunnel).await;
            assert_eq!(
                answer.status,
                400,
                "{user_field}: request {i} is the: {}",
                answer.text()
            );
            assert_eq!(
                answer.json()["error"]["type"],
                "invalid_request_error",
                "{user_field}: request {i}: {}",
                answer.text()
            );
        }
    }
    assert_eq!(
        instance.upstream.calls(),
        before,
        "nothing reached the upstream across the whole loop"
    );

    // The probe host still answers itself, echoing the user field
    // byte-identically even though it is not a token.
    let mut tunnel = intercept(
        proxy,
        "probe.jaynshare.invalid:443",
        Some(&basic("pin.QUJD~.", &alpha.secret)),
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the probe host is an intercepted name");
    let answer = tunnel
        .send(tunnel.request(Method::GET, "probe.jaynshare.invalid", "/", ""))
        .await;
    assert_eq!(answer.status, 200, "answered: {}", answer.text());
    assert_eq!(
        answer.json()["user_field"],
        "pin.QUJD~.",
        "the user field verbatim, as received"
    );

    // Stays for a credential that does not resolve — the
    // secret parked in the user field with an empty password.
    let refused = connect_through(
        proxy,
        "api.anthropic.com:443",
        Some(&basic(&alpha.secret, "")),
    )
    .await;
    assert_proxy_refusal(
        refused.status,
        407,
        refused.header("connection"),
        &refused.json(),
    );
}

// ------------------------------------------------------------------ the account-bound refusal

/// Every account-bound path is refused `403` `proxy_error` in both modes
/// before any attempt: nothing reaches the upstream, each refusal leaves its
/// audit record, and the API-key account a family 401 used to error stays
/// eligible. Its MITM half needs this file's tunnel, as the control-plane and
/// client-token tests above do.
#[tokio::test(flavor = "multi_thread")]
async fn an_account_bound_path_is_refused_in_both_modes() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("account-bound-path", mitm_on()).await;
    instance.add_fkey();
    let org = "0b0c0d0e-1111-4222-8333-444455556666";
    let paths = [
        "/api/oauth/account/settings".to_string(),
        format!("/api/oauth/organizations/{org}/marketplaces"),
        format!("/api/oauth/organizations/{org}/plugins/list-plugins"),
        format!("/api/oauth/organizations/{org}/skills/list-skills"),
        "/api/claude_code_grove".to_string(),
        "/v1/mcp_servers?limit=1000".to_string(),
    ];
    let get = |uri: &str| {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .expect("request builds")
    };
    let assert_refused = |answer: &Answer, what: &str| {
        assert_eq!(answer.status, 403, "{what}: {}", answer.text());
        assert_eq!(
            answer.json()["error"]["type"],
            "proxy_error",
            "{what}: {}",
            answer.text()
        );
        assert!(
            answer.text().contains("not served through the pool"),
            "{what}: the message names the pool: {}",
            answer.text()
        );
    };

    for path in &paths {
        let answer = send(instance.addr, get(path)).await;
        assert_refused(&answer, &format!("base-url {path}"));
    }
    let ca = ca_file(&instance);
    let mut tunnel = intercept(
        proxy_addr(&instance),
        "api.anthropic.com:443",
        None,
        &ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
    .expect("the handshake succeeds");
    for path in &paths {
        let answer = tunnel
            .send(tunnel.request(Method::GET, "api.anthropic.com", path, ""))
            .await;
        assert_refused(&answer, &format!("mitm {path}"));
    }
    assert_eq!(
        instance.upstream.calls(),
        0,
        "no account-bound path reached the upstream"
    );

    let records = instance.audit_settled(2 * paths.len());
    for (record, mode) in records.iter().zip(
        std::iter::repeat_n("base-url", paths.len())
            .chain(std::iter::repeat_n("mitm", paths.len())),
    ) {
        assert_eq!(record["status"], 403, "{record}");
        assert_eq!(
            record["attempts"], 0,
            "refused before any attempt: {record}"
        );
        assert_eq!(record["serving_account"], Value::Null, "{record}");
        assert_eq!(record["error_class"], "request", "{record}");
        assert_eq!(record["mode"], mode, "{record}");
        assert!(
            !record["path"].as_str().unwrap_or("").contains('?'),
            "the path without its query: {record}"
        );
    }

    instance.settle();
    let fkey = instance.account("FKEY");
    assert_eq!(fkey["health"]["state"], "ready", "never ran: {fkey}");
    let served = tunnel
        .send(tunnel.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await;
    assert_eq!(
        served.status,
        200,
        "inference is still served: {}",
        served.text()
    );
}
