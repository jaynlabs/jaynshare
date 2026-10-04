//! The proxy listener: plain HTTP/1.1, CONNECT and absolute-form, one
//! process beside the base-URL listener.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::data_plane::connect::{Connector, enable_keepalive};
use crate::data_plane::relay::ResponseBody;
use crate::mitm::absolute::Forwarder;
use crate::mitm::tunnel;
use crate::server::Server;

/// The proxy listener binds beside the base-URL listener, and
/// on failure the process exits with code 22; the message names the address and port.
pub async fn bind(listen: SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(listen)
        .await
        .map_err(|e| format!("cannot bind the proxy listener {listen}: {e}"))
}

/// Serves until the stop signal, then lets in-flight connections drain. The
/// CA is read per request from the server, so a rotation is live
/// and an unusable state is simply `None` until a rotate fixes it.
/// With the mode off (`enabled` false, a restart key) every request is
/// refused with `405` and nothing is opened.
pub async fn serve(server: Arc<Server>, listener: TcpListener, enabled: bool) {
    // The corporate-proxy settings are restart keys, so one connector
    // over the start snapshot serves every tunnel and forwarded request.
    let settings = server.config().config.data_plane.clone();
    let connector = match enabled.then(|| {
        crate::data_plane::tls::client_config()
            .and_then(|tls| Connector::new(tls, settings.corporate_proxy_url.as_ref()))
    }) {
        None => None,
        Some(Ok(connector)) => Some(Arc::new(connector)),
        Some(Err(e)) => {
            tracing::error!(event = "mitm_connector_failed", error = %e, "the corporate proxy settings are unusable; tunnelled targets go direct or are refused");
            None
        }
    };
    let forwarder = match enabled.then(|| Forwarder::new(&settings)) {
        None => None,
        Some(Ok(forwarder)) => Some(Arc::new(forwarder)),
        Some(Err(e)) => {
            tracing::error!(event = "mitm_connector_failed", error = %e, "the corporate proxy settings are unusable; absolute-form forwarding is refused");
            None
        }
    };
    let host_addresses: Arc<[IpAddr]> = self_addresses(&server.config().config.clients).into();
    let mut stop = server.stop_signal();
    // A live count with a capped drain: hyper-util's GracefulShutdown cannot
    // watch an upgraded (with_upgrades) connection, so the drain is manual.
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
        // Keep-alive on the client side too; the socket option
        // survives the upgrade into the tunnel.
        enable_keepalive(&stream);
        let (server, connector, forwarder, host_addresses, live) = (
            Arc::clone(&server),
            connector.clone(),
            forwarder.clone(),
            Arc::clone(&host_addresses),
            Arc::clone(&live),
        );
        let service = service_fn(move |request: Request<Incoming>| {
            dispatch(
                enabled,
                Arc::clone(&server),
                connector.clone(),
                forwarder.clone(),
                Arc::clone(&host_addresses),
                peer,
                request,
            )
        });
        live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
            // A spawned tunnel relay outlives its connection task under the
            // same count, so the drain covers open tunnels too.
            live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while live.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

/// The non-loopback addresses of the proxy host itself, plus the
/// addresses of the advertised origins: the published address is the
/// one an enrolled client can reach back on, so a target on it is refused
/// too. Loopback has its own class.
// Enumerated once at start; a re-enumeration on reload matters only for
// hosts whose addresses change while serving.
fn self_addresses(clients: &crate::config::ClientSettings) -> Vec<IpAddr> {
    let mut addresses: Vec<IpAddr> = if_addrs::get_if_addrs()
        .map(|interfaces| {
            interfaces
                .into_iter()
                .map(|interface| interface.ip())
                .filter(|ip| !ip.is_loopback())
                .collect()
        })
        .unwrap_or_default();
    // The advertised URLs are origins, and the self-address rule is an address
    // rule: a host name would need resolution at start, so only IP literals
    // are taken.
    for url in [&clients.advertised_base_url, &clients.advertised_proxy_url] {
        if let Some(ip) = url
            .as_deref()
            .and_then(|url| url.parse::<http::Uri>().ok())
            .and_then(|uri| uri.host().map(str::to_owned))
            .and_then(|host| {
                host.trim_matches(|c| c == '[' || c == ']')
                    .parse::<IpAddr>()
                    .ok()
            })
            .filter(|ip| !ip.is_loopback())
        {
            addresses.push(ip);
        }
    }
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

/// This listener serves proxy traffic only — CONNECT and
/// absolute-form; everything else is 405 and opens nothing, and so is every
/// request while the mode is off.
async fn dispatch(
    enabled: bool,
    server: Arc<Server>,
    connector: Option<Arc<Connector>>,
    forwarder: Option<Arc<Forwarder>>,
    host_addresses: Arc<[IpAddr]>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Result<Response<ResponseBody>, std::convert::Infallible> {
    let response = if !enabled {
        // The mode is off, so this listener refuses whatever it is sent — the answer tells a stale proxy URL what happened.
        method_not_allowed(
            "MITM mode is disabled on this server: the proxy listener serves nothing",
        )
    } else if request.method() == Method::CONNECT {
        // The CA in force at the moment the request arrives, so a
        // rotation is live on the next handshake. The per-request clone is
        // what lets a tunnel already established keep the leaf it
        // negotiated until it closes.
        let ca = server.mitm_ca();
        tunnel::handle(server, connector, host_addresses, ca, peer, request).await
    } else if request.uri().scheme_str().is_some() {
        match &forwarder {
            Some(forwarder) => {
                forwarder
                    .handle(&server, &host_addresses, peer, request)
                    .await
            }
            None => tunnel::refusal(
                peer,
                "",
                StatusCode::INTERNAL_SERVER_ERROR,
                "absolute-form forwarding is unavailable",
            ),
        }
    } else {
        // The proxy listener 405s origin-form requests.
        method_not_allowed("the proxy listener serves CONNECT and absolute-form requests only")
    };
    Ok(response)
}

/// The refusal on this listener: `405`, nothing opened, the connection closed.
fn method_not_allowed(message: &str) -> Response<ResponseBody> {
    let mut response = crate::data_plane::envelope::proxy_response(
        StatusCode::METHOD_NOT_ALLOWED,
        crate::provider::anthropic::error_type::PROXY,
        message,
    );
    use http::header::CONNECTION;
    response
        .headers_mut()
        .insert(CONNECTION, http::HeaderValue::from_static("close"));
    response
}
