//! One isolated, bounded genuine Claude Code startup check.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use http::{Response, StatusCode};
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::oneshot;

use crate::data_plane::envelope::{json_response, proxy_response};
use crate::data_plane::relay::ResponseBody;

use super::{app::App, config::Integration};

const OUTPUT_LIMIT: u64 = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(9);

pub async fn run(
    app: &App,
    integration: &Integration,
    directory: &Path,
    jobs: &std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
) -> Response<ResponseBody> {
    if app.unchanged().is_err() {
        return proxy_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "Desktop or its runtime changed; restart the adapter",
        );
    }
    let scratch = directory
        .join("desktop-probes")
        .join(uuid::Uuid::new_v4().to_string());
    if crate::state::ensure_private_dir(&scratch).is_err() {
        return proxy_response(
            StatusCode::BAD_GATEWAY,
            "api_error",
            "could not prepare the isolated Desktop startup check",
        );
    }
    let child = Command::new(&app.runtime)
        .args([
            "-p",
            "Reply with exactly OK. Do not use tools.",
            "--model",
            super::config::MODEL,
            "--tools",
            "",
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--mcp-config",
            "{\"mcpServers\":{}}",
            "--no-session-persistence",
            "--output-format",
            "json",
        ])
        .current_dir(&scratch)
        .env_clear()
        .env("HOME", &scratch)
        .env("TMPDIR", &scratch)
        .env("CLAUDE_CONFIG_DIR", &scratch)
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "en_US.UTF-8")
        .env("ANTHROPIC_BASE_URL", &integration.origin)
        .env("ANTHROPIC_AUTH_TOKEN", &integration.key)
        .env("ANTHROPIC_API_KEY", "")
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = child else {
        let _ = std::fs::remove_dir_all(&scratch);
        return proxy_response(
            StatusCode::BAD_GATEWAY,
            "api_error",
            "could not start Desktop's managed Claude Code runtime",
        );
    };
    let (cancel, cancelled) = oneshot::channel::<()>();
    let (answer, receiver) = oneshot::channel();
    // The worker owns the child so dropping an HTTP request still kills AND reaps it.
    let worker = tokio::spawn(async move {
        let stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let read = async {
            let mut bytes = Vec::new();
            stdout
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .await?;
            if bytes.len() as u64 > OUTPUT_LIMIT {
                return Err(std::io::Error::other("probe output exceeded its limit"));
            }
            Ok(bytes)
        };
        let completed = {
            let collect = async {
                let mut sink = tokio::io::sink();
                let (bytes, _, status) =
                    tokio::try_join!(read, tokio::io::copy(&mut stderr, &mut sink), child.wait())?;
                Ok::<_, std::io::Error>((bytes, status.success()))
            };
            tokio::select! {
                _ = cancelled => None,
                result = tokio::time::timeout(DEADLINE, collect) => Some(result),
            }
        };
        let response = match completed {
            Some(Ok(Ok((bytes, success)))) => convert(&bytes, success),
            Some(Err(_)) => proxy_response(
                StatusCode::GATEWAY_TIMEOUT,
                "timeout_error",
                "Claude Code startup check exceeded 9 seconds",
            ),
            _ => proxy_response(
                StatusCode::BAD_GATEWAY,
                "api_error",
                "Claude Code could not complete the Desktop startup check",
            ),
        };
        let _ = child.kill().await;
        let _ = std::fs::remove_dir_all(&scratch);
        let _ = std::fs::remove_dir(scratch.parent().expect("probe parent"));
        let _ = answer.send(response);
    });
    {
        let mut jobs = jobs.lock().expect("probe jobs");
        jobs.retain(|job| !job.is_finished());
        jobs.push(worker);
    }
    let response = receiver.await.unwrap_or_else(|_| {
        proxy_response(
            StatusCode::BAD_GATEWAY,
            "api_error",
            "Desktop startup check stopped",
        )
    });
    drop(cancel);
    response
}

fn convert(bytes: &[u8], success: bool) -> Response<ResponseBody> {
    let result: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    if success
        && result["type"] == "result"
        && result["subtype"] == "success"
        && result["is_error"] == false
        && result["num_turns"] == 1
        && result["result"].as_str().is_some_and(|s| !s.is_empty())
        && result["stop_reason"] == "end_turn"
        && result["usage"]["input_tokens"].as_u64().is_some()
        && result["usage"]["output_tokens"].as_u64().is_some()
    {
        return json_response(
            StatusCode::OK,
            &json!({
                "id": format!("msg_local_{}", uuid::Uuid::new_v4().simple()),
                "type": "message", "role": "assistant", "model": super::config::MODEL,
                "content": [{"type": "text", "text": result["result"]}],
                "stop_reason": result["stop_reason"], "stop_sequence": null, "usage": result["usage"],
            }),
        );
    }
    let status = result["api_error_status"]
        .as_u64()
        .filter(|s| (400..=599).contains(s))
        .and_then(|s| StatusCode::from_u16(s as u16).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    proxy_response(
        status,
        if status == StatusCode::TOO_MANY_REQUESTS {
            "rate_limit_error"
        } else {
            "api_error"
        },
        "Claude Code could not complete the Desktop startup check",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_valid_successful_results_become_healthy_messages() {
        let mut result = json!({"type":"result", "subtype":"success", "is_error":false,
            "num_turns":1, "result":"OK", "stop_reason":"end_turn",
            "usage":{"input_tokens":17, "output_tokens":1}});
        assert_eq!(
            convert(result.to_string().as_bytes(), true).status(),
            StatusCode::OK
        );
        assert_eq!(
            convert(result.to_string().as_bytes(), false).status(),
            StatusCode::BAD_GATEWAY
        );
        result["usage"]["input_tokens"] = json!(-1);
        assert_eq!(
            convert(result.to_string().as_bytes(), true).status(),
            StatusCode::BAD_GATEWAY
        );
    }
}
