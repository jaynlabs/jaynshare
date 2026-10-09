//! The base-URL listener: accept, resolve the principal, carve out `/control`,
//! run the exchange.

pub mod attempt;
pub mod connect;
pub mod egress;
pub mod envelope;
pub mod exchange;
pub mod intent;
pub mod principal;
pub mod relay;
pub mod tls;
pub mod upstream;
pub mod usage;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

use crate::provider::Provider;
use crate::provider::anthropic::error_type;
use crate::server::Server;

use exchange::CloseConnection;
use relay::ResponseBody;
use tls::TlsAcceptor;

/// The listener could not bind.
pub const EXIT_BIND_FAILED: i32 = 22;

pub async fn bind(listen: SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(listen)
        .await
        .map_err(|e| format!("cannot bind {listen}: {e}"))
}

/// A listener on one non-loopback address also binds its port
/// on `127.0.0.1`, unadvertised, so a local operator call's peer is genuinely
/// loopback. A wildcard bind already includes loopback.
pub fn implicit_loopback(bound: SocketAddr) -> Option<SocketAddr> {
    let ip = bound.ip();
    (!ip.is_loopback() && !ip.is_unspecified())
        .then(|| SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, bound.port())))
}

/// Serves until the stop signal, then lets in-flight connections drain briefly.
/// With TLS the stream is decrypted before the same HTTP service runs;
/// HTTP/2 clients are served HTTP/2.
pub async fn serve(server: Arc<Server>, listener: TcpListener, tls: Option<TlsAcceptor>) {
    let mut stop = server.stop_signal();
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(event = "accept_failed", error = %e, "accept failed");
                    continue;
                }
            },
            _ = stop.changed() => break,
        };
        let server = Arc::clone(&server);
        let watcher = graceful.watcher();
        match &tls {
            None => {
                let service =
                    service_fn(move |request| dispatch(Arc::clone(&server), peer, request));
                tokio::spawn(serve_one(watcher, TokioIo::new(stream), service));
            }
            Some(acceptor) => {
                let acceptor = acceptor.clone();
                let mut stop = server.stop_signal();
                tokio::spawn(async move {
                    if server.stopping() {
                        return;
                    }
                    let handshake = tokio::select! {
                        result = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)) =>
                            result.unwrap_or_else(|_| Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "TLS handshake timed out",
                            ))),
                        _ = stop.changed() => return,
                    };
                    let secure = match handshake {
                        Ok(secure) => secure,
                        Err(e) => {
                            tracing::warn!(
                                event = "tls_handshake_failed",
                                source_address = %peer,
                                error = %e,
                                "TLS handshake failed"
                            );
                            return;
                        }
                    };
                    let service =
                        service_fn(move |request| dispatch(Arc::clone(&server), peer, request));
                    serve_one(watcher, TokioIo::new(secure), service).await;
                });
            }
        }
    }
    tokio::select! {
        _ = graceful.shutdown() => {}
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
    }
}

/// Watches one connection under the graceful shutdown.
async fn serve_one<I, S>(watcher: hyper_util::server::graceful::Watcher, io: I, service: S)
where
    I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    S: hyper::service::Service<Request<Incoming>, Response = Response<ResponseBody>>
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let builder = auto::Builder::new(TokioExecutor::new());
    if let Err(e) = watcher
        .watch(builder.serve_connection(io, service).into_owned())
        .await
    {
        tracing::debug!(event = "connection_ended", error = %e, "connection ended with an error");
    }
}

/// Principal before path; the prefix decides the
/// plane. The one anonymous operation is the enrollment claim.
async fn dispatch(
    server: Arc<Server>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Result<Response<ResponseBody>, CloseConnection> {
    // The base-URL listener is never a forward proxy, whatever the
    // mode — CONNECT and absolute-form belong to the proxy listener alone.
    // Absolute-form is HTTP/1.x's request target; an HTTP/2 request always
    // carries `:scheme` and `:authority`, which hyper presents as an
    // absolute URI, so the version decides (RFC 9113 §8.3.1).
    let absolute_form =
        request.version() <= http::Version::HTTP_11 && request.uri().scheme_str().is_some();
    if request.method() == http::Method::CONNECT || absolute_form {
        let mut response = envelope::proxy_response(
            StatusCode::METHOD_NOT_ALLOWED,
            error_type::PROXY,
            "CONNECT and absolute-form requests are only served on the proxy listener",
        );
        response.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
        return Ok(response);
    }
    let principal = principal::resolve(&server.registry(), peer, request.headers());
    let first_segment = request
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("");
    if first_segment == "control" {
        // An anonymous caller gets the data-plane refusal whatever the
        // control path — existing, absent or a client id — except the claim.
        let is_claim = request.uri().path() == "/control/v1/enrollment/claim"
            && request.method() == http::Method::POST;
        if principal.is_none() && !is_claim {
            // The pre-principal refusal leaves its line here too.
            return Ok(crate::control::unauthenticated_refusal(peer));
        }
        return Ok(crate::control::handle(&server, principal.as_ref(), peer, request).await);
    }
    let Some(principal) = principal else {
        // The refusal leaves its record, address and all.
        return Ok(exchange::unauthenticated(
            &server,
            peer,
            &request,
            crate::audit::Mode::BaseUrl,
            Some(Provider::Anthropic),
        ));
    };
    if server.stopping() {
        // Admission stops once audit or state is unwritable.
        return Ok(envelope::proxy_response(
            StatusCode::SERVICE_UNAVAILABLE,
            error_type::PROXY,
            "the proxy is shutting down",
        ));
    }
    exchange::run(server, exchange::Entry::base_url(principal), peer, request).await
}
