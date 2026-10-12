//! A bounded streaming exchange with the genuine runtime and a local mock.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

use super::probe;

const MODEL: &str = "jaynshare-compatibility-check";

pub async fn check(runtime: &Path) -> Result<(), String> {
    let scratch =
        std::env::temp_dir().join(format!("jaynshare-desktop-check-{}", uuid::Uuid::new_v4()));
    crate::state::ensure_private_dir(&scratch).map_err(|e| e.to_string())?;
    let setup = async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let origin = format!(
            "http://{}",
            listener.local_addr().map_err(|e| e.to_string())?
        );
        let key = uuid::Uuid::new_v4().to_string();
        let child = probe::command(runtime, &scratch, &origin, &key, MODEL)
            .env("HTTP_PROXY", &origin)
            .env("HTTPS_PROXY", &origin)
            .env("NO_PROXY", "127.0.0.1,localhost")
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok::<_, String>((listener, key, child))
    }
    .await;
    let (listener, key, mut child) = match setup {
        Ok(setup) => setup,
        Err(why) => {
            let _ = std::fs::remove_dir_all(&scratch);
            return Err(format!("cannot start Desktop's local runtime check: {why}"));
        }
    };
    let (cancel, mut cancelled) = oneshot::channel::<()>();
    // The worker kills and reaps the child even when its caller disconnects.
    let result = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let seen = Arc::new(AtomicBool::new(false));
        let result = {
            let collect = probe::collect(&mut child);
            tokio::pin!(collect);
            loop {
                tokio::select! {
                    _ = &mut cancelled => break Err("runtime check cancelled".to_string()),
                    result = &mut collect => break result.map_err(|e| e.to_string()),
                    accepted = listener.accept() => {
                        let (socket, _) = match accepted {
                            Ok(pair) => pair,
                            Err(e) => break Err(e.to_string()),
                        };
                        let key = key.clone();
                        let seen = Arc::clone(&seen);
                        connections.spawn(async move {
                            let service = service_fn(move |request| mock(request, key.clone(), Arc::clone(&seen)));
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(socket), service).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        };
        let _ = child.kill().await;
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        let _ = std::fs::remove_dir_all(&scratch);
        match result {
            Ok((bytes, success)) if success && seen.load(Ordering::Relaxed) => {
                let result: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                if probe::healthy(&result) && result["result"] == "OK" {
                    return Ok(());
                }
            }
            Err(why) => return Err(format!("Desktop's managed runtime compatibility check failed: {why}")),
            _ => {}
        }
        Err("Desktop's managed runtime did not pass the local streaming compatibility check; update Jaynshare for this Desktop build".into())
    }).await.map_err(|e| format!("Desktop's managed runtime check stopped: {e}"))?;
    drop(cancel);
    result
}

async fn mock(
    request: Request<Incoming>,
    key: String,
    seen: Arc<AtomicBool>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let reject = || {
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::new()))
            .expect("empty response")
    };
    if request.method() != Method::POST
        || request.uri().scheme().is_some()
        || request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some(format!("Bearer {key}").as_str())
        || !request
            .headers()
            .get("user-agent")
            .is_some_and(|v| v.as_bytes().starts_with(b"claude-cli/"))
        || request
            .headers()
            .get("x-claude-code-session-id")
            .is_none_or(|v| v.as_bytes().is_empty())
    {
        return Ok(reject());
    }
    let (parts, body) = request.into_parts();
    let Ok(body) = Limited::new(body, 1024 * 1024).collect().await else {
        return Ok(reject());
    };
    let Ok(decoded) = crate::data_plane::attempt::decode_body(&parts.headers, &body.to_bytes())
    else {
        return Ok(reject());
    };
    let Ok(value) = serde_json::from_slice::<Value>(&decoded) else {
        return Ok(reject());
    };
    if value["model"] != MODEL {
        return Ok(reject());
    }
    if parts.uri.path() == "/v1/messages/count_tokens" {
        return Ok(Response::builder()
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(b"{\"input_tokens\":10}")))
            .expect("token count"));
    }
    if parts.uri.path() != "/v1/messages" || value["stream"] != true {
        return Ok(reject());
    }
    seen.store(true, Ordering::Relaxed);
    let events = [
        json!({"type":"message_start", "message":{"id":"msg_local_check", "type":"message", "role":"assistant", "model":MODEL, "content":[], "stop_reason":null, "stop_sequence":null, "usage":{"input_tokens":10, "output_tokens":0}}}),
        json!({"type":"content_block_start", "index":0, "content_block":{"type":"text", "text":""}}),
        json!({"type":"content_block_delta", "index":0, "delta":{"type":"text_delta", "text":"OK"}}),
        json!({"type":"content_block_stop", "index":0}),
        json!({"type":"message_delta", "delta":{"stop_reason":"end_turn", "stop_sequence":null}, "usage":{"input_tokens":10, "output_tokens":1}}),
        json!({"type":"message_stop"}),
    ];
    let stream = events
        .iter()
        .map(|event| {
            format!(
                "event: {}\ndata: {event}\n\n",
                event["type"].as_str().expect("event type")
            )
        })
        .collect::<String>();
    Ok(Response::builder()
        .header("content-type", "text/event-stream")
        .body(Full::new(Bytes::from(stream)))
        .expect("stream response"))
}
