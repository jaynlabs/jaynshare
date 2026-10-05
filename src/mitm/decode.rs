//! From the intercepted tunnel into the data plane. A decoded request is an
//! ordinary exchange: the tunnel's principal and intent, the caller's own
//! metadata removed.

use std::net::SocketAddr;
use std::sync::Arc;

use http::header::{HOST, UPGRADE};
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};

use crate::audit::Mode;
use crate::data_plane::envelope;
use crate::data_plane::exchange::{self, Entry};
use crate::data_plane::relay::ResponseBody;
use crate::mitm::probe::{self, PROBE_HOST};
use crate::mitm::tunnel::{self, Tunnel};
use crate::provider::Provider;
use crate::provider::anthropic::error_type;
use crate::server::Server;

/// The ALPN chosen at the handshake decides the framing; concurrent HTTP/2
/// streams are concurrent exchanges, and a shutdown sends GOAWAY
/// before letting what is in flight finish.
pub async fn serve<I>(
    server: Arc<Server>,
    tunnel: Arc<Tunnel>,
    peer: SocketAddr,
    stream: I,
    h2: bool,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let io = TokioIo::new(stream);
    let mut stop = server.stop_signal();
    let service =
        service_fn(move |request| one(Arc::clone(&server), Arc::clone(&tunnel), peer, request));
    macro_rules! drive {
        ($connection:expr) => {{
            let connection = $connection;
            let mut connection = std::pin::pin!(connection);
            tokio::select! {
                result = connection.as_mut() => result,
                _ = stop.changed() => {
                    connection.as_mut().graceful_shutdown();
                    connection.await
                }
            }
        }};
    }
    let served = if h2 {
        drive!(
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
        )
    } else {
        drive!(hyper::server::conn::http1::Builder::new().serve_connection(io, service))
    };
    if let Err(e) = served {
        tracing::debug!(event = "mitm_connection_ended", error = %e, "an intercepted connection ended with an error");
    }
}

/// One decoded request: the principal as it stands now, the
/// authority check, the probe host, then the exchange.
async fn one(
    server: Arc<Server>,
    tunnel: Arc<Tunnel>,
    peer: SocketAddr,
    mut request: Request<Incoming>,
) -> Result<Response<ResponseBody>, exchange::CloseConnection> {
    // `None` only for the probe host, which never reaches the exchange.
    let provider = Provider::for_intercepted_host(&tunnel.host);
    // Re-validated per request, so a revoke or a rotate
    // lands inside an open tunnel.
    let Some(principal) = tunnel.credential.principal_now(&server) else {
        // This refusal too is traced through its record.
        return Ok(exchange::unauthenticated(
            &server,
            peer,
            &request,
            Mode::Mitm,
            provider,
        ));
    };
    let Some(authority) = authority(&request) else {
        return Ok(envelope::proxy_response(
            StatusCode::BAD_REQUEST,
            error_type::INVALID_REQUEST,
            "the request names no authority",
        ));
    };
    if authority == PROBE_HOST {
        // Answered here, never forwarded.
        return Ok(probe::answer(
            &server,
            &tunnel.credential,
            request.uri().path(),
            true,
        ));
    }
    if authority != tunnel.host {
        // A tunnel to one name serves that name alone.
        return Ok(envelope::proxy_response(
            StatusCode::MISDIRECTED_REQUEST,
            error_type::PROXY,
            &format!(
                "this tunnel serves {} only; nothing was forwarded for {authority}",
                tunnel.host
            ),
        ));
    }
    let provider = provider.expect("every intercepted host but the probe's is a provider's");
    // No upgrade is carried inside an intercepted tunnel; the status is the
    // one that makes the provider's client fall back fastest.
    if request.headers().contains_key(UPGRADE) || request.method() == Method::CONNECT {
        return Ok(envelope::error(
            provider,
            provider.upgrade_refusal(),
            error_type::PROXY,
            "the proxy does not carry protocol upgrades on an intercepted target",
        ));
    }
    if server.stopping() {
        // Admission stops once audit or state is unwritable.
        return Ok(envelope::proxy_response(
            StatusCode::SERVICE_UNAVAILABLE,
            error_type::PROXY,
            "the proxy is shutting down",
        ));
    }
    // The caller's own proxy metadata reaches no decoded destination.
    tunnel::strip_proxy_metadata(request.headers_mut());
    server.mitm.record_intercepted_exchange();
    exchange::run(
        server,
        Entry {
            principal,
            mode: Mode::Mitm,
            provider,
            // The tunnel's intent, never the request's.
            intent: tunnel.credential.intent.clone(),
        },
        peer,
        request,
    )
    .await
}

/// The tunnel-host comparison value: `host` on HTTP/1.1, `:authority` on HTTP/2,
/// without the port and case- and trailing-dot-insensitive (the name is
/// matched as sent, so the tunnel's own host is already in this shape).
fn authority(request: &Request<Incoming>) -> Option<String> {
    let raw = match request.uri().authority() {
        Some(authority) => authority.host().to_string(),
        // A `host` header may carry a port, and an IPv6 literal its brackets.
        None => request
            .headers()
            .get(HOST)?
            .to_str()
            .ok()?
            .parse::<http::uri::Authority>()
            .ok()?
            .host()
            .to_string(),
    };
    let name = raw.trim_end_matches('.').to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}
