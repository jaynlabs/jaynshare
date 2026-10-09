//! macOS Desktop Chat through a foreground native Gateway adapter.

mod app;
mod config;
mod monitor;
mod probe;
mod transport;

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use http::Method;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::client::{ClientInstallation, ClientRequest};
use config::Integration;
use monitor::Output;

pub async fn restore_if_present(directory: &std::path::Path) -> Result<(), String> {
    let Some(_) = Integration::read(directory)? else {
        return Ok(());
    };
    let _lock = config::lock(directory)?;
    let Some(integration) = Integration::read(directory)? else {
        return Ok(());
    };
    if let Ok(bundle) = app::bundle()
        && app::running(&bundle).await?
    {
        return Err("quit Claude Desktop fully before restoring its Gateway configuration".into());
    }
    integration.restore(directory)
}

pub async fn restore() -> Result<(), String> {
    let directory = crate::config::platform::client_directory();
    if !directory.exists() {
        return Ok(());
    }
    restore_if_present(&directory).await
}

pub async fn run(
    installation: ClientInstallation,
    selector: Option<String>,
    quiet: bool,
    log: bool,
) -> Result<(), String> {
    let output = Output::new(quiet, log);
    let app = app::App::resolve().await?;
    let lock = match config::lock(&installation.directory) {
        Ok(lock) => lock,
        Err(why) => {
            if let Some(record) = Integration::read(&installation.directory)? {
                if !same_enrollment(&record, &installation) || !record.installed()? {
                    return Err("a Desktop adapter is active with a different enrollment or profile; stop its foreground command and quit Desktop fully before switching".into());
                }
                if record.selector != selector {
                    return Err("a Desktop adapter is active with another account; switch from its terminal, or stop it and launch again".into());
                }
                let http = ClientRequest::new(&record.origin, Duration::from_secs(2), &[])?;
                let response = http
                    .send(Method::HEAD, "/api/hello", Some(&record.key), None, &[])
                    .await
                    .map_err(|(_, why)| why)?;
                if response.status() != http::StatusCode::NO_CONTENT
                    || response
                        .headers()
                        .get("x-jaynshare-desktop-instance")
                        .and_then(|v| v.to_str().ok())
                        != Some(&record.id)
                {
                    return Err("the active Desktop adapter did not confirm its identity".into());
                }
                app.open().await?;
                if output != Output::Quiet {
                    eprintln!(
                        "reused the running Desktop adapter; its original foreground command owns the connection"
                    );
                }
                return Ok(());
            }
            return Err(why);
        }
    };
    let mut record = Integration::read(&installation.directory)?;
    if record.is_some() {
        config::cleanup_probes(&installation.directory)?;
    }
    let installed = record
        .as_ref()
        .map(|r| r.installed())
        .transpose()?
        .unwrap_or(false);
    // Desktop never sees the account, so only setup and a new enrollment need it closed.
    let moved = record
        .as_ref()
        .is_some_and(|r| !same_enrollment(r, &installation));
    if (!installed || moved) && app::running(&app.bundle).await? {
        return Err("quit Claude Desktop fully before Gateway setup or changing enrollment; an active conversation was left untouched".into());
    }
    let address = record
        .as_ref()
        .map(|r| r.origin.trim_start_matches("http://"))
        .unwrap_or("127.0.0.1:0");
    let listener = TcpListener::bind(address).await.map_err(|_| "the recorded Desktop loopback port is occupied; stop the process using it or restore the integration while Desktop is closed")?;
    let origin = format!(
        "http://{}",
        listener.local_addr().map_err(|e| e.to_string())?
    );
    let http = ClientRequest::for_installation(&installation, transport::DEADLINE, None)?;
    if record.is_none() {
        record = Some(Integration::new(&installation, origin, selector.clone())?);
    }
    let mut record = record.expect("created integration");
    record.selector = selector;
    if moved {
        record.client_id = installation.client_id.clone();
        record.server = installation.base_url.clone();
        record.pin = installation.server_identity.clone();
    }
    // The recovery record commits before any profile field is changed.
    record.save(&installation.directory)?;
    if !installed {
        record.install()?;
    }
    let adapter = Arc::new(transport::Adapter {
        verifier: crate::secret::Verifier::new(crate::secret::Role::ClientSecret, &record.key),
        app,
        selector: RwLock::new(record.selector.clone()),
        integration: record,
        installation,
        http,
        output,
        monitor: Arc::default(),
        probes: Mutex::new(Vec::new()),
    });
    serve(adapter, listener).await?;
    drop(lock);
    Ok(())
}

fn same_enrollment(record: &Integration, installation: &ClientInstallation) -> bool {
    record.client_id == installation.client_id
        && record.server == installation.base_url
        && record.pin == installation.server_identity
}

async fn serve(adapter: Arc<transport::Adapter>, listener: TcpListener) -> Result<(), String> {
    let mut connections = JoinSet::new();
    let mut compatibility = tokio::time::interval(Duration::from_secs(2));
    let open = adapter.app.open();
    tokio::pin!(open);
    let mut opened = false;
    let interrupt = tokio::signal::ctrl_c();
    let termination = terminate();
    tokio::pin!(interrupt, termination);
    // Raw mode turns Ctrl-C into a key, so the monitor sends it here.
    let (quit, mut quitting) = mpsc::unbounded_channel();
    let screen = match adapter.output {
        Output::Monitor => Some(monitor::Screen::start(Arc::clone(&adapter), quit.clone())?),
        _ => None,
    };
    let refresh = screen
        .is_some()
        .then(|| tokio::spawn(monitor::refresh(Arc::clone(&adapter))));
    if adapter.output == Output::Log {
        eprintln!(
            "Desktop Gateway ready at {}; keep this command open to stay connected",
            adapter.integration.origin
        );
    }
    let result = loop {
        tokio::select! {
            result = &mut open, if !opened => {
                if let Err(why) = result { break Err(why); }
                opened = true;
            }
            result = listener.accept() => {
                let (stream, peer) = match result { Ok(pair) => pair, Err(e) => break Err(e.to_string()) };
                if !peer.ip().is_loopback() { continue; }
                let adapter = Arc::clone(&adapter);
                connections.spawn(async move {
                    let service = service_fn(move |request| Arc::clone(&adapter).handle(request));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(10))
                        .serve_connection(TokioIo::new(stream), service).await;
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
            _ = compatibility.tick() => {
                if let Err(why) = adapter.app.unchanged() { break Err(why); }
            }
            _ = &mut interrupt => break Ok(()),
            _ = &mut termination => break Ok(()),
            _ = quitting.recv() => break Ok(()),
        }
    };
    if let Some(refresh) = refresh {
        refresh.abort();
    }
    if let Some(screen) = screen {
        screen.close().await;
    }
    drop(listener);
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let probes = std::mem::take(&mut *adapter.probes.lock().expect("probe jobs"));
    for probe in probes {
        let _ = probe.await;
    }
    result
}

async fn terminate() {
    #[cfg(unix)]
    {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await;
}
