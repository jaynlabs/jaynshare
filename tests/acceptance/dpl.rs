//! The deployment surface: listeners, egress, the data plane, and what a
//! rotating or failing upstream does to a served request.
use crate::harness::*;

fn permission_error_403() -> Reply {
    Reply::status(
        403,
        json!({
            "type": "error",
            "error": { "type": "permission_error", "message": "Request not allowed" },
            "request_id": "req_fixture_0403",
        })
        .to_string(),
        // ------------------------------------------------------------------ scenarios
    )
}

/// Caller sends both credential headers → neither reaches upstream,
/// one injected.
#[tokio::test(flavor = "multi_thread")]
async fn caller_credentials_never_reach_upstream() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("caller-credentials-never-reach").await;
    instance.add_fsub();

    let answer = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[
                ("authorization", "Bearer caller-bearer-value"),
                ("x-api-key", "caller-api-key-value"),
            ],
        ),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    let seen = instance.upstream.last();
    assert_eq!(
        seen.headers_named("authorization"),
        vec![format!("Bearer {}", instance.needles.access_token)],
        "exactly one injected bearer, and not the caller's"
    );
    assert!(
        seen.header("x-api-key").is_none(),
        "an OAuth account injects no api key"
    );
}

/// 32 MiB + 1 body → 413, upstream never called.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_body_is_refused_before_any_attempt() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("oversized-body-refused").await;
    instance.add_fsub();
    let calls_before = instance.upstream.calls();

    let answer = send_declared(instance.addr, "/v1/messages", 32 * 1024 * 1024 + 1).await;

    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(answer.json()["error"]["type"], "request_too_large");
    assert_eq!(
        instance.upstream.calls(),
        calls_before,
        "nothing was forwarded"
    );
    let record = instance.audit().pop().expect("an audit record");
    assert_eq!(record["status"], 413);
    assert_eq!(record["attempts"], 0);
}

/// A nested `model` earlier in the body loses to the top-level one.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_model_decides() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("top-level-model-decides").await;
    instance.add_fsub();

    let answer = send(
        instance.addr,
        messages(json!({
            "messages": [{ "role": "user", "model": "nested-decoy", "content": "hi" }],
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 32,
        })),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.audit().pop().expect("an audit record");
    assert_eq!(record["model"], "claude-haiku-4-5-20251001");
}

/// An advisor tool's `model` is a model the selector sees,
/// here proved by blocking it alone.
#[tokio::test(flavor = "multi_thread")]
async fn advisor_model_reaches_the_selector() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "advisor-model-reaches",
        Setup {
            blocked_models: vec!["*opus*".into()],
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let calls_before = instance.upstream.calls();

    let answer = send(
        instance.addr,
        messages(json!({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 32,
            "tools": [{ "type": "advisor_20260301", "model": "claude-opus-5" }],
            "messages": [{ "role": "user", "content": "hi" }],
        })),
    )
    .await;

    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        instance.upstream.calls(),
        calls_before,
        "the advisor model was examined before any attempt"
    );
    let record = instance.audit().pop().expect("an audit record");
    assert_eq!(record["blocked_pattern"], "*opus*");
}

/// X -jaynshare-account` and `proxy-authorization` are absent
/// upstream.
#[tokio::test(flavor = "multi_thread")]
async fn pin_and_proxy_authorization_are_consumed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("pin-proxy-authorization").await;
    instance.add_fsub();

    let answer = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[
                ("x-jaynshare-account", &token(true, "FSUB")),
                ("proxy-authorization", "Basic Zm9vOmJhcg=="),
            ],
        ),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    let seen = instance.upstream.last();
    assert!(seen.header("x-jaynshare-account").is_none());
    assert!(seen.header("proxy-authorization").is_none());
}

/// A blocked model is refused with 400 and never forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn blocked_model_is_refused_before_any_attempt() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "blocked-model-refused",
        Setup {
            blocked_models: vec!["*haiku*".into()],
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let calls_before = instance.upstream.calls();

    let answer = send(instance.addr, messages(haiku_prompt())).await;

    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.json()["error"]["type"], "invalid_request_error");
    assert_eq!(instance.upstream.calls(), calls_before);
    let record = instance.audit().pop().expect("an audit record");
    assert_eq!(record["blocked_pattern"], "*haiku*");
    assert_eq!(record["attempts"], 0);
}

/// Telemetry under `block` is answered locally, under `forward` is
/// relayed, and another path is relayed either way.
#[tokio::test(flavor = "multi_thread")]
async fn telemetry_policy_decides_only_the_telemetry_path() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let blocking = Instance::start_with(
        "telemetry-policy-decides-block",
        Setup {
            telemetry_policy: "block",
            ..Setup::default()
        },
    )
    .await;
    blocking.add_fsub();
    let before = blocking.upstream.calls();

    let answer = send(
        blocking.addr,
        post("/api/event_logging", json!({ "events": [] })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.json(), json!({}));
    assert_eq!(
        blocking.upstream.calls(),
        before,
        "blocked telemetry is never forwarded"
    );
    // A subpath under the telemetry path is telemetry too;
    // a sibling that merely shares the prefix text is not.
    let under = send(
        blocking.addr,
        post("/api/event_logging/batch", json!({ "events": [] })),
    )
    .await;
    assert_eq!(under.status, StatusCode::OK);
    assert_eq!(under.json(), json!({}));
    assert_eq!(
        blocking.upstream.calls(),
        before,
        "the subpath is blocked too"
    );
    let sibling = send(blocking.addr, post("/api/event_logging_v2", json!({}))).await;
    assert_ne!(sibling.json(), json!({}), "a sibling path is forwarded");
    assert_eq!(blocking.upstream.last().path, "/api/event_logging_v2");

    let other = send(blocking.addr, messages(haiku_prompt())).await;
    assert_eq!(other.status, StatusCode::OK);
    assert_eq!(blocking.upstream.last().path, "/v1/messages");

    let forwarding = Instance::start("telemetry-policy-decides-forward").await;
    forwarding.add_fsub();
    let answer = send(
        forwarding.addr,
        post("/api/event_logging", json!({ "events": [] })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(forwarding.upstream.last().path, "/api/event_logging");
}

/// Hop-by-hop headers stop at the proxy; the Anthropic and Claude
/// Code header families cross it verbatim.
#[tokio::test(flavor = "multi_thread")]
async fn hop_by_hop_stops_and_the_rest_crosses_verbatim() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("hop-hop-stops-rest").await;
    instance.add_fsub();

    let answer = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[
                ("connection", "x-listed"),
                ("x-listed", "1"),
                ("te", "trailers"),
                ("upgrade", "websocket"),
                ("keep-alive", "timeout=5"),
                ("anthropic-beta", "fine-grained-tool-streaming-2025-05-14"),
                ("x-stainless-os", "MacOS"),
                (
                    "x-claude-code-session-id",
                    "0f8a1c22-0000-4000-8000-00000000abcd",
                ),
            ],
        ),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    let seen = instance.upstream.last();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/v1/messages");
    for stopped in ["connection", "x-listed", "te", "upgrade", "keep-alive"] {
        assert!(
            seen.header(stopped).is_none(),
            "{stopped} must not cross the proxy"
        );
    }
    assert_eq!(seen.header("x-stainless-os"), Some("MacOS"));
    assert_eq!(
        seen.header("x-claude-code-session-id"),
        Some("0f8a1c22-0000-4000-8000-00000000abcd")
    );
    assert_eq!(seen.header("anthropic-version"), Some("2023-06-01"));
}

/// An OAuth account injects a bearer and appends the beta exactly
/// once; an API-key account injects `x-api-key` and leaves the beta list alone.
#[tokio::test(flavor = "multi_thread")]
async fn credential_injection_follows_the_account_kind() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let subscription = Instance::start("credential-injection-follows-oauth").await;
    subscription.add_fsub();
    let answer = send(
        subscription.addr,
        with(
            messages(haiku_prompt()),
            &[("anthropic-beta", "fine-grained-tool-streaming-2025-05-14")],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let seen = subscription.upstream.last();
    assert_eq!(
        seen.header("authorization"),
        Some(format!("Bearer {}", subscription.needles.access_token).as_str())
    );
    let beta = seen.header("anthropic-beta").expect("the beta header");
    assert_eq!(
        beta, "fine-grained-tool-streaming-2025-05-14,oauth-2025-04-20",
        "order kept, the OAuth beta appended once"
    );
    assert_eq!(beta.matches("oauth-2025-04-20").count(), 1);

    let api_key = Instance::start("credential-injection-follows-apikey").await;
    api_key.add_fkey();
    let answer = send(
        api_key.addr,
        with(
            messages(haiku_prompt()),
            &[("anthropic-beta", "fine-grained-tool-streaming-2025-05-14")],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let seen = api_key.upstream.last();
    assert_eq!(
        seen.header("x-api-key"),
        Some(api_key.needles.api_key.as_str())
    );
    assert!(seen.header("authorization").is_none());
    assert_eq!(
        seen.header("anthropic-beta"),
        Some("fine-grained-tool-streaming-2025-05-14"),
        "an API key adds no beta"
    );
}

/// `account_uuid` is rewritten only inside `metadata.user_id`,
/// `system[0]` crosses byte-identical, `content-length` describes the attempt.
#[tokio::test(flavor = "multi_thread")]
async fn account_uuid_rewrite_is_surgical() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("account-uuid-rewrite").await;
    instance.add_fsub();

    // the attribution text and the stringified user_id object.
    let attribution = "You are Claude Code, Anthropic's official CLI for Claude.";
    let user_id = json!({ "device_id": "d1", "account_uuid": "", "session_id": "s1" }).to_string();
    let answer = send(
        instance.addr,
        messages(json!({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 32,
            "system": [{ "type": "text", "text": attribution }],
            "metadata": { "user_id": user_id },
            "account_uuid": "elsewhere-untouched",
            "messages": [{ "role": "user", "content": "hi" }],
        })),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    let seen = instance.upstream.last();
    let body = seen.json();
    let inner: Value = serde_json::from_str(
        body["metadata"]["user_id"]
            .as_str()
            .expect("user_id stays a JSON string"),
    )
    .expect("user_id holds an object");
    assert_eq!(inner["account_uuid"], FIXTURE_ACCOUNT_UUID);
    assert_eq!(inner["device_id"], "d1", "the other members are untouched");
    assert_eq!(body["account_uuid"], "elsewhere-untouched");
    assert_eq!(body["system"][0]["text"], attribution);
    assert_eq!(
        seen.header("content-length")
            .expect("content-length")
            .parse::<usize>()
            .expect("a number"),
        seen.body.len(),
        "content-length describes the rewritten body"
    );
}

/// Orphaned tool blocks are removed and a well-formed body crosses
/// byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn tool_pairs_are_made_consistent() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("tool-pairs-made-consistent").await;
    instance.add_fsub();

    let orphaned = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 32,
        "messages": [
            { "role": "user", "content": [{ "type": "text", "text": "q" }] },
            { "role": "assistant", "content": [{ "type": "tool_use", "id": "a", "input": {} }] },
            { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "b", "content": "x" }] },
            { "role": "assistant", "content": [{ "type": "text", "text": "done" }] },
        ],
    });
    assert_eq!(
        send(instance.addr, messages(orphaned)).await.status,
        StatusCode::OK
    );
    let messages_sent = instance.upstream.last().json();
    let sent = messages_sent["messages"].as_array().expect("messages");
    assert_eq!(sent.len(), 2, "the orphans went and the neighbours merged");
    assert_eq!(sent[0]["role"], "user");
    assert_eq!(sent[1]["content"][0]["text"], "done");

    // A body with no tool blocks and nothing to rewrite crosses byte for byte.
    let exact = br#"{"model":"claude-haiku-4-5-20251001", "max_tokens":32,
        "messages":[{"role":"user","content":"hi"}]}"#;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(exact)))
        .expect("request builds");
    assert_eq!(send(instance.addr, request).await.status, StatusCode::OK);
    assert_eq!(
        instance.upstream.last().body,
        Bytes::from_static(exact),
        "a body with nothing to rewrite is forwarded unchanged"
    );
}

/// Only a loopback upstream origin is accepted, and it is announced
/// on startup and in `status --json`.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_override_is_loopback_only() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let (code, stderr) = Instance::start_expecting_failure(
        "upstream-override-loopback-refused",
        Setup {
            upstream_origin: Some("https://api.example.invalid".into()),
            ..Setup::default()
        },
    )
    .await;
    assert_eq!(code, 3, "an invalid configuration is the exit 3");
    assert!(
        stderr.contains("data_plane.upstream_origin"),
        "the refusal names the setting: {stderr}"
    );

    let instance = Instance::start("upstream-override-loopback-accepted").await;
    let origin = format!("http://{}/", instance.upstream.addr);
    assert!(
        instance.stdout().contains(&origin),
        "the startup line announces the override: {}",
        instance.stdout()
    );
    assert_eq!(
        instance.status()["server"]["upstream_origin_override"],
        origin
    );
}

/// A redirect is relayed to the caller and never followed.
#[tokio::test(flavor = "multi_thread")]
async fn redirects_are_relayed_never_followed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("redirects-relayed-never-followed").await;
    instance.add_fsub();
    let redirect_target = Fake::start().await;

    instance.upstream.script([Reply::Raw {
        status: 302,
        headers: vec![
            (
                "location".into(),
                format!("http://{}/v1/messages", redirect_target.addr),
            ),
            ("content-type".into(), "application/json".into()),
        ],
        body: json!({ "moved": true }).to_string(),
    }]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;

    assert_eq!(answer.status, StatusCode::FOUND);
    assert_eq!(
        answer.json(),
        json!({ "moved": true }),
        "the body is untouched"
    );
    assert!(answer.header("location").is_some());
    assert_eq!(
        redirect_target.calls(),
        0,
        "the redirect target was never connected to"
    );
}

/// A streamed answer reaches the caller chunk by chunk, keeps its
/// `ping` events, and carries no `content-encoding`.
#[tokio::test(flavor = "multi_thread")]
async fn streams_are_relayed_chunk_by_chunk() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("streams-relayed-chunk").await;
    instance.add_fsub();
    instance.upstream.script([Reply::Sse {
        events: sse_events(),
    }]);

    let answer = send(
        instance.addr,
        with(
            messages(json!({
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 32,
                "stream": true,
                "messages": [{ "role": "user", "content": "hi" }],
            })),
            &[("accept", "text/event-stream")],
        ),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.header("content-type"), Some("text/event-stream"));
    assert!(
        answer.header("content-encoding").is_none(),
        "nothing re-encodes the stream"
    );
    assert!(
        answer.frames.len() >= sse_events().len(),
        "each scripted event arrived as its own frame, got {} frames",
        answer.frames.len()
    );
    let text = answer.text();
    assert!(text.contains("event: ping"), "ping events survive");
    assert!(text.contains("\"type\":\"message_stop\""));
}

/// The rate-limit, `request-id` and `retry-after` headers reach the
/// caller unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_headers_reach_the_caller() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("upstream-headers-reach").await;
    instance.add_fsub();
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("request-id".to_string(), "req_fixture_0007".to_string()),
        ("retry-after".to_string(), "5".to_string()),
        ("connection".to_string(), "keep-alive".to_string()),
    ];
    headers.extend(ratelimit_headers_oauth());
    instance.upstream.script([Reply::Raw {
        status: 200,
        headers,
        body: message_body().to_string(),
    }]);

    let answer = send(instance.addr, messages(haiku_prompt())).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.header("request-id"), Some("req_fixture_0007"));
    assert_eq!(answer.header("retry-after"), Some("5"));
    assert_eq!(
        answer.header("anthropic-ratelimit-unified-5h-utilization"),
        Some("0.12")
    );
    assert!(
        answer.header("keep-alive").is_none(),
        "the connection-specific set stops at the proxy"
    );
}

/// After one streamed answer `status` shows the tokens it cost on the
/// serving account.
#[tokio::test(flavor = "multi_thread")]
async fn usage_and_quota_land_on_the_serving_account() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("usage-quota-land").await;
    instance.add_fsub();
    instance.upstream.script([Reply::Sse {
        events: sse_events(),
    }]);

    let answer = send(
        instance.addr,
        messages(json!({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 32,
            "stream": true,
            "messages": [{ "role": "user", "content": "hi" }],
        })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    instance.last_record(1);

    let account = instance.account("FSUB");
    assert_eq!(account["usage"]["input_tokens"], 11);
    assert_eq!(account["usage"]["output_tokens"], 7);
    assert_eq!(account["usage"]["requests"], 1);
    let session = account["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "session")
        .expect("the session bucket")
        .clone();
    assert_eq!(session["state"], "available");
    assert_eq!(session["utilisation"], 0.12);
    assert_eq!(session["observed_source"], "response-headers");
}

/// Every response the proxy writes itself validates against the
/// envelope.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_refusals_use_the_error_envelope() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "proxy-refusals-use",
        Setup {
            blocked_models: vec!["*haiku*".into()],
            ..Setup::default()
        },
    )
    .await;

    // No account yet: the pool has nobody to serve with.
    let empty_pool = send(instance.addr, messages(haiku_prompt())).await;
    instance.add_fsub();
    let blocked = send(instance.addr, messages(haiku_prompt())).await;
    let oversized = send_declared(instance.addr, "/v1/messages", 32 * 1024 * 1024 + 1).await;

    for answer in [empty_pool, blocked, oversized] {
        assert!(answer.status.is_client_error(), "{}", answer.status);
        assert_eq!(answer.header("content-type"), Some("application/json"));
        assert_eq!(answer.header("cache-control"), Some("no-store"));
        let body = answer.json();
        assert_eq!(body["type"], "error");
        assert!(body["error"]["type"].is_string(), "{body}");
        assert!(body["error"]["message"].is_string(), "{body}");
        assert!(body.get("request_id").is_some(), "{body}");
    }
}

/// Pool of 2, both OAuth, 401 with refresh failing → the
/// exchange's account is errored after its 2 attempts, then 502 naming it;
/// audit count matches.: the exchange has one
/// candidate — the 401 forces one refresh and one retry on the rotated
/// token, and the surviving 401 ends the exchange without ever trying
/// `FSUB2`.
#[tokio::test(flavor = "multi_thread")]
async fn http_401_surviving_the_refresh_errors_the_account_and_ends_502() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("http-401-surviving").await;
    add_two(&instance);

    // attempt (old bearer) → 401, token call → rotated, attempt → 401 again.
    let rotated_access = needle("access token", "oat-fixture");
    instance
        .upstream
        .script([reply_auth_401(), reply_auth_401()]);
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": rotated_access,
            "refresh_token": needle("refresh token", "ort-fixture"),
            "expires_in": 3600,
        })
        .to_string(),
    )]);

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{}", answer.text());
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    assert!(answer.text().contains("FSUB"), "{}", answer.text());

    // FSUB2 never attempted: both attempts carry FSUB's bearers, old then
    // rotated.
    let attempts = instance
        .upstream
        .seen()
        .into_iter()
        .filter(|s| s.path == "/v1/messages")
        .collect::<Vec<_>>();
    assert_eq!(
        attempts.len(),
        2,
        "attempt, refresh, attempt — nothing else"
    );
    assert_eq!(
        attempts
            .iter()
            .map(|s| s.header("authorization").expect("bearer"))
            .collect::<Vec<_>>(),
        vec![
            format!("Bearer {}", instance.needles.access_token).as_str(),
            format!("Bearer {rotated_access}").as_str(),
        ],
        "all seen bearers are FSUB's"
    );
    assert_eq!(instance.upstream.token_calls().len(), 1);

    let record = instance.last_record(1);
    assert_eq!(record["status"], 502);
    assert_eq!(record["attempts"], 2, "the refreshed retry counts");
    assert_eq!(record["failed_over"], false);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["error_class"], "authentication");

    let fsub = instance.account("FSUB");
    assert_eq!(fsub["health"]["state"], "errored");
    assert_eq!(
        fsub["health"]["reason"], "upstream 401 on oauth credential after a forced refresh",
        "the persisted reason names the forced refresh"
    );
    let fsub2 = instance.account("FSUB2");
    assert_eq!(fsub2["health"]["state"], "ready", "FSUB2 untouched");

    assert_eq!(instance.events("forced_refresh").len(), 1);
    assert_eq!(instance.events("refresh_succeeded").len(), 1);
    assert_eq!(instance.events("account_refused_401").len(), 1);
}

/// An upstream status the proxy has no rule for is relayed with its
/// body untouched.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_statuses_are_relayed_unchanged() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("upstream-statuses-relayed").await;
    instance.add_fsub();

    for (status, body) in [
        (
            400u16,
            json!({"type":"error","error":{"type":"invalid_request_error","message":"bad"}}),
        ),
        (
            500,
            json!({"type":"error","error":{"type":"api_error","message":"boom"}}),
        ),
        (
            529,
            json!({"type":"error","error":{"type":"overloaded_error","message":"overloaded"}}),
        ),
    ] {
        instance
            .upstream
            .script([Reply::status(status, body.to_string())]);
        let answer = send(instance.addr, messages(haiku_prompt())).await;
        assert_eq!(answer.status.as_u16(), status);
        assert_eq!(answer.json(), body, "the upstream body is not rewritten");
    }

    let records = instance.audit();
    let statuses: Vec<u64> = records
        .iter()
        .filter_map(|r| r["status"].as_u64())
        .collect();
    assert_eq!(statuses, vec![400, 500, 529]);
    assert!(
        records.iter().all(|r| r["attempts"] == 1),
        "no status above rotates an account at "
    );
}

/// One audit record per exchange, carrying the caller's source
/// address, on the served, refused and blocked paths.
#[tokio::test(flavor = "multi_thread")]
async fn every_exchange_leaves_one_record() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "exchange-leaves-record",
        Setup {
            blocked_models: vec!["*opus*".into()],
            ..Setup::default()
        },
    )
    .await;

    let refused = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    instance.add_fsub();
    let served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[(
                "x-claude-code-session-id",
                "0f8a1c22-0000-4000-8000-00000000abcd",
            )],
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);
    let blocked = send(
        instance.addr,
        messages(json!({ "model": "claude-opus-5", "max_tokens": 8, "messages": [] })),
    )
    .await;
    assert_eq!(blocked.status, StatusCode::BAD_REQUEST);

    let records = instance.audit();
    assert_eq!(records.len(), 3, "one record per exchange");
    for record in &records {
        for field in [
            "timestamp",
            "duration_ms",
            "principal",
            "source_address",
            "session_id",
            "method",
            "path",
            "model",
            "serving_account",
            "no_service_reason",
            "selection_cause",
            "status",
            "attempts",
            "failed_over",
            "error_class",
            "pinned",
            "mode",
            "blocked_pattern",
        ] {
            assert!(record.get(field).is_some(), "{field} missing from {record}");
        }
        assert!(
            record["source_address"]
                .as_str()
                .expect("source address")
                .starts_with("127.0.0.1:"),
            "every record carries the caller's source address"
        );
        assert_eq!(record["mode"], "base-url");
    }
    assert_eq!(records[0]["no_service_reason"], "no_account_configured");
    assert_eq!(records[0]["error_class"], "rate_limit");
    assert_eq!(records[1]["serving_account"]["display_name"], "FSUB");
    assert_eq!(
        records[1]["serving_account"]["account_uuid"],
        FIXTURE_ACCOUNT_UUID
    );
    assert_eq!(
        records[1]["session_id"],
        "0f8a1c22-0000-4000-8000-00000000abcd"
    );
    assert_eq!(records[1]["attempts"], 1);
    assert_eq!(records[1]["failed_over"], false);
    assert_eq!(records[2]["blocked_pattern"], "*opus*");

    // Across the new endings: an exhausted account's real 429
    // relayed, a bound-then-held synthetic 429 with no attempt, and a
    // refused exchange. Each leaves exactly one more record; every one names
    // its cause (a serving cause or a no-service reason), never both.
    instance.add_oauth("SECOND", "second@fixture.invalid", FSUB2_UUID);
    let baseline = instance.audit().len();

    // Bound the session, then relay its account's real exhaustion 429.
    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "kilo-b"),
    )
    .await;
    instance.upstream.script([reply_exhausted_429(90)]);
    let relayed = send(
        instance.addr,
        in_session(messages(haiku_prompt()), "kilo-b"),
    )
    .await;
    assert_eq!(relayed.status, StatusCode::TOO_MANY_REQUESTS);
    // The bound account is now held: the next attempt is a synthetic 429
    // computed for it, with no upstream attempt.
    let calls = instance.upstream.calls();
    let synthetic = send(
        instance.addr,
        in_session(messages(haiku_prompt()), "kilo-b"),
    )
    .await;
    assert_eq!(synthetic.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        instance.upstream.calls(),
        calls,
        "no attempt for the synthetic 429"
    );

    let records = instance.audit_settled(baseline + 3);
    for record in &records[baseline..] {
        let served = record["serving_account"].is_object();
        let refused = record["no_service_reason"].is_string();
        assert!(served ^ refused, "exactly one of cause/reason: {record}");
        if served {
            assert!(
                record["selection_cause"].is_string(),
                "a served record names its cause: {record}"
            );
        }
        assert_eq!(record["blocked_pattern"], Value::Null);
    }
    let relayed_record = &records[baseline + 1];
    assert_eq!(relayed_record["serving_account"]["display_name"], "FSUB");
    assert_eq!(relayed_record["selection_cause"], "session");
    assert_eq!(relayed_record["attempts"], 1);
    assert_eq!(relayed_record["error_class"], "rate_limit");
    // The synthetic 429 names the session as the cause and the
    // hold as the reason, with no serving account and no attempt.
    let synthetic_record = &records[baseline + 2];
    assert_eq!(synthetic_record["serving_account"], Value::Null);
    assert_eq!(
        synthetic_record["no_service_reason"],
        "all_held_or_over_threshold"
    );
    assert_eq!(synthetic_record["selection_cause"], "session");
    assert_eq!(synthetic_record["attempts"], 0, "no attempt made");
}

/// Wire capture writes one file per exchange with the credential
/// replaced by a placeholder, and `status --json` names the directory.
#[tokio::test(flavor = "multi_thread")]
async fn wire_capture_records_without_the_secret() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "wire-capture-records",
        Setup {
            capture: true,
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    assert_eq!(
        send(instance.addr, messages(haiku_prompt())).await.status,
        StatusCode::OK
    );

    let status = instance.status();
    assert_eq!(status["capture"]["enabled"], true);
    assert_eq!(
        status["capture"]["directory"],
        instance.root.join("cap").display().to_string()
    );

    let files: Vec<PathBuf> = fs::read_dir(instance.root.join("cap"))
        .expect("capture directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert_eq!(files.len(), 1, "one file per captured exchange");
    let captured = fs::read_to_string(&files[0]).expect("capture file");
    assert!(captured.contains("=== request"));
    assert!(captured.contains("=== attempt 1"));
    assert!(captured.contains("=== response"));
    assert!(
        captured.contains("authorization: Bearer <redacted>"),
        "the injected credential is a placeholder naming only the kind"
    );
    assert!(
        !captured.contains(&instance.needles.access_token),
        "no capture file holds the pooled credential"
    );
    assert_eq!(
        instance.audit().len(),
        1,
        "every captured exchange still has its audit record"
    );
}

/// The needle sweep: no fixture secret appears on any surface the
/// allow-list of the suite docs does not name.
#[tokio::test(flavor = "multi_thread")]
async fn no_secret_reaches_an_observable_surface() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "no-secret-reaches",
        Setup {
            capture: true,
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance.add_fkey();
    assert_eq!(
        send(instance.addr, messages(haiku_prompt())).await.status,
        StatusCode::OK
    );
    // the surfaces since: a 429 classification (its log line), a
    // usage probe (its outcome), an operator switch (its log line) and a
    // route preference — each touches the log, the audit and the snapshot.
    instance.upstream.script([reply_exhausted_429(90)]);
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FSUB"))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    instance.upstream.script_usage([reply_usage("25", "40")]);
    assert_eq!(instance.cli_json(&["probe", "--wait"], None)["ok"], true);
    assert_eq!(instance.cli(&["switch", "FKEY"], None).0, 0);
    let refused = instance.cli(&["account", "show", "nosuchaccount"], None);
    assert_ne!(refused.0, 0);
    instance.settle();

    // the allow-list: the state file may hold pooled credentials
    // and the wire-capture directory may hold what capture captures.
    let allowed = [
        instance.root.join("state/state.json"),
        instance.root.join("cap"),
    ];
    let mut hits = Vec::new();
    sweep(&instance.root, &allowed, &instance.needles.all(), &mut hits);
    // The CLI renderings are separate processes: sweep their stdout by hand.
    // The account snapshot in both forms carries only the
    // five credential timing facts, never a token.
    let mut renderings = vec![refused.1, refused.2, instance.stdout(), instance.stderr()];
    for args in [
        &["status", "--json"][..],
        &["status"][..],
        &["account", "list"][..],
        &["account", "show", "FSUB"][..],
        &["account", "show", "FKEY"][..],
    ] {
        renderings.push(instance.cli(args, None).1);
    }
    for surface in renderings {
        for needle in instance.needles.all() {
            if encodings(needle).iter().any(|form| surface.contains(form)) {
                hits.push(format!("a standard stream: {surface}"));
            }
        }
    }
    assert!(hits.is_empty(), "needle hits: {hits:#?}");
}

/// A connection failure before any response byte is retried once on a
/// fresh connection; a second failure closes the caller's connection with no
/// response at all.
#[tokio::test(flavor = "multi_thread")]
async fn one_network_retry_then_the_connection_closes() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("network-retry-connection").await;
    instance.add_fsub();

    instance.upstream.script([Reply::ResetBeforeHeaders]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "the retry served the caller");
    let record = instance.audit().pop().expect("an audit record");
    assert_eq!(record["attempts"], 2, "one retry, on a fresh connection");

    instance
        .upstream
        .script([Reply::ResetBeforeHeaders, Reply::ResetBeforeHeaders]);
    let outcome = try_send(instance.addr, messages(haiku_prompt())).await;
    assert!(
        outcome.is_err(),
        "the second failure closes the caller's connection with no response"
    );
    let record = instance.audit().pop().expect("an audit record");
    assert_eq!(record["status"], Value::Null, "no response was written");
    assert_eq!(record["attempts"], 2);
    assert_eq!(record["error_class"], "upstream");
}

/// Unknown pin → 404; pinned account exhausted → 429
/// `retry-after: 5`.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_pin_404_and_pinned_exhausted_429() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("unknown-pin-404-pinned").await;
    add_two(&instance);

    let calls = instance.upstream.calls();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "NOPE")).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.json()["error"]["type"], "not_found_error");
    assert_eq!(
        instance.upstream.calls(),
        calls,
        "no attempt for an unknown pin"
    );

    // FSUB2 learns a weekly window at 0.99: over the threshold.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::OK);

    let calls = instance.upstream.calls();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("5"));
    assert_eq!(answer.json()["error"]["type"], "rate_limit_error");
    assert!(answer.text().contains("FSUB2"), "{}", answer.text());
    assert_eq!(
        instance.upstream.calls(),
        calls,
        "a pin is served by that account or nobody"
    );
    let record = instance.last_record(3);
    assert_eq!(record["pinned"], true);
    assert_eq!(record["no_service_reason"], "pinned_unavailable");
    assert_eq!(record["attempts"], 0);
}

/// Malformed `x-jaynshare-account` → 400 before any attempt;
/// preference naming no account → 404; ambiguous reference → 400 listing
/// display names.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_token_missing_preference_and_ambiguous_reference() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("malformed-token-missing").await;
    add_two(&instance);
    let calls = instance.upstream.calls();

    let ok = token(true, "FSUB");
    for bad in [
        "FSUB",
        "pin.YQ==",
        "pref.",
        "pin.FSUB!",
        "pin.YR",
        "nope.YQ",
    ] {
        let answer = send(
            instance.addr,
            with(messages(haiku_prompt()), &[("x-jaynshare-account", bad)]),
        )
        .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{bad:?}");
        assert_eq!(answer.json()["error"]["type"], "invalid_request_error");
    }
    let answer = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("x-jaynshare-account", &ok), ("x-jaynshare-account", &ok)],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "two fields");

    let answer = send(
        instance.addr,
        preferred(messages(haiku_prompt()), "nobody@fixture.invalid"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.json()["error"]["type"], "not_found_error");

    // Both accounts share the organisation: its UUID names two of them.
    let answer = send(
        instance.addr,
        preferred(messages(haiku_prompt()), FIXTURE_ORG_UUID),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    let message = answer.json()["error"]["message"]
        .as_str()
        .expect("message")
        .to_string();
    assert!(
        message.contains("FSUB") && message.contains("FSUB2"),
        "{message}"
    );

    assert_eq!(
        instance.upstream.calls(),
        calls,
        "every refusal precedes any attempt"
    );
}
/// 403 on the bound account → 502 naming it, account not
/// errored, no second attempt.
#[tokio::test(flavor = "multi_thread")]
async fn http_403_on_the_bound_account_ends_with_502_naming_it() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("http-403-bound-account").await;
    add_two(&instance);

    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "delta")).await;
    assert_eq!(answer.status, StatusCode::OK);

    instance.upstream.script([permission_error_403()]);
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "delta")).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    assert!(answer.text().contains("FSUB"), "{}", answer.text());
    assert_eq!(instance.upstream.calls(), calls + 1, "no second attempt");
    assert_eq!(instance.account("FSUB")["health"]["state"], "ready");
    assert!(instance.events("default_moved").is_empty());
    let record = instance.last_record(2);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "session");
    assert_eq!(record["error_class"], "upstream");
}
/// Exhaustion 429 on the bound account: relayed byte-identical
/// with its `retry-after`, one attempt, nobody else tried.
#[tokio::test(flavor = "multi_thread")]
async fn exhaustion_429_on_the_bound_account_is_relayed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("exhaustion-429-bound").await;
    add_two(&instance);
    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "charlie"),
    )
    .await;

    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
            ("7d-reset", &reset_in(120)),
        ],
        Some("45"),
    )]);
    let answer = send(
        instance.addr,
        in_session(messages(haiku_prompt()), "charlie"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("45"));
    assert_eq!(answer.header("request-id"), Some("req_fixture_0429"));
    let record = instance.last_record(2);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "session");
    assert_eq!(record["error_class"], "rate_limit");
    assert!(instance.events("default_moved").is_empty());

    // The hold runs to the exact reset, and only the held account's models.
    let weekly = instance.account("FSUB")["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["state"], "exhausted");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    assert!(
        (crate_time(weekly["hold_end"].as_str().expect("hold")) - now - 120).abs() <= 3,
        "held to the reset: {:?}",
        weekly["hold_end"]
    );
}
/// Retried once after the wait and the caller sees only latency;
/// `retry-after: 90` is relayed at once.
#[tokio::test(flavor = "multi_thread")]
async fn throttle_retry_absorbed_then_relayed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let instance =
        Instance::start_with_faults("throttle-retry-absorbed", Setup::default(), faults.clone())
            .await;
    instance.add_fsub();

    instance
        .upstream
        .script([reply_throttle_429(Some(3)), reply_headerless_200()]);
    let base = instance.upstream.calls();
    let answer = send_after_wait(
        &instance,
        &faults,
        messages(haiku_prompt()),
        "throttle_wait",
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let elapsed = Duration::from_millis(
        instance.last_record(1)["duration_ms"]
            .as_u64()
            .expect("duration_ms"),
    );
    assert!(
        elapsed >= Duration::from_millis(2_800) && elapsed < Duration::from_secs(8),
        "the caller waited the 3 s: {elapsed:?}"
    );
    assert_eq!(
        instance.upstream.calls() - base,
        2,
        "two attempts, one account"
    );
    let record = instance.last_record(1);
    assert_eq!(record["attempts"], 2);
    assert_eq!(record["failed_over"], false);

    instance
        .upstream
        .script([reply_throttle_429(Some(90)), reply_headerless_200()]);
    let base = instance.upstream.calls();
    let started = Instant::now();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("90"));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "relayed without waiting"
    );
    assert_eq!(
        instance.upstream.calls() - base,
        1,
        "no retry beyond the absorb bound"
    );
    assert_eq!(instance.last_record(2)["attempts"], 1);
}
/// A held bound account: a hold end within the inline-wait bound
/// is waited once and the attempt re-made (200 if the reset landed); a hold
/// beyond it ends at once with the synthetic 429 naming the account.
#[tokio::test(flavor = "multi_thread")]
async fn inline_wait_then_reattempt_of_the_bound_account() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let instance =
        Instance::start_with_faults("inline-wait-reattempt", Setup::default(), faults.clone())
            .await;
    add_two(&instance);
    send(instance.addr, in_session(messages(haiku_prompt()), "golf")).await;

    // Reset 10 s out: one inline wait, then the attempt (now unheld) serves.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("5h-reset", &faults.reset_in(10)),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
            ("7d-reset", &faults.reset_in(10)),
        ],
        Some("10"),
    )]);
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "golf")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "held");

    instance.upstream.script([reply_headerless_200()]);
    let answer = send_after_wait(
        &instance,
        &faults,
        in_session(messages(haiku_prompt()), "golf"),
        "bound_account_held",
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "the reset landed during the wait"
    );
    let elapsed = Duration::from_millis(
        instance.last_record(3)["duration_ms"]
            .as_u64()
            .expect("duration_ms"),
    );
    assert!(
        elapsed >= Duration::from_millis(8_800) && elapsed < Duration::from_secs(15),
        "one inline wait of ~10 s: {elapsed:?}"
    );
    let record = instance.last_record(3);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");

    // Reset 20 s away: beyond the inline bound, the synthetic 429 at once.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("5h-reset", &faults.reset_in(20)),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
            ("7d-reset", &faults.reset_in(20)),
        ],
        Some("20"),
    )]);
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "golf")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    let calls = instance.upstream.calls();
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "golf")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = answer
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    assert!(
        (16..=21).contains(&retry_after),
        "retry-after ≈ the hold end: {retry_after}"
    );
    assert!(answer.text().contains("FSUB"), "{}", answer.text());
    assert_eq!(instance.upstream.calls(), calls, "no attempt");
    let record = instance.last_record(5);
    assert_eq!(record["attempts"], 0);
    assert_eq!(record["selection_cause"], "session");
}
/// Hold budget 30 s, hold 60 s: the caller is held ~30 s with the
/// connection open, then the 429 names the remaining ≈30 s.
#[tokio::test(flavor = "multi_thread")]
async fn hold_budget_holds_then_relays() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let instance = Instance::start_with_faults(
        "hold-budget-holds",
        Setup {
            data_plane: "hold_budget_seconds = 30\n".into(),
            ..Setup::default()
        },
        faults.clone(),
    )
    .await;
    instance.add_fsub();
    let base = instance.upstream.calls();
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("60"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    let answer = send_after_wait(
        &instance,
        &faults,
        messages(haiku_prompt()),
        "no_account_hold",
    )
    .await;
    let elapsed = Duration::from_millis(
        instance.last_record(2)["duration_ms"]
            .as_u64()
            .expect("duration_ms"),
    );
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        elapsed >= Duration::from_millis(28_000) && elapsed < Duration::from_secs(40),
        "held for the 30 s budget: {elapsed:?}"
    );
    let retry_after: u64 = answer
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    assert!(
        (25..=36).contains(&retry_after),
        "the remaining ≈30 s: {retry_after}"
    );
    assert_eq!(
        instance.upstream.calls() - base,
        1,
        "no attempt during the hold"
    );
}

/// The budget bounds the whole hold: with a 3 s
/// budget and a 10 s hold end, the caller is answered after ≈3 s naming the
/// ≈7 s left, never held on into the inline wait, which is for
/// exchanges "without a hold budget" (a 6 s budget once held 19 s).
#[tokio::test(flavor = "multi_thread")]
async fn a_spent_budget_answers_without_the_inline_wait() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let instance = Instance::start_with_faults(
        "spent-budget-answers",
        Setup {
            data_plane: "hold_budget_seconds = 3\n".into(),
            ..Setup::default()
        },
        faults.clone(),
    )
    .await;
    instance.add_fsub();
    let base = instance.upstream.calls();
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("10"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let answer = send_after_wait(
        &instance,
        &faults,
        messages(haiku_prompt()),
        "no_account_hold",
    )
    .await;
    let elapsed = Duration::from_millis(
        instance.last_record(2)["duration_ms"]
            .as_u64()
            .expect("duration_ms"),
    );
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        elapsed >= Duration::from_millis(2_500) && elapsed < Duration::from_secs(6),
        "held for the 3 s budget and no longer: {elapsed:?}"
    );
    let retry_after: u64 = answer
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    assert!(
        (5..=8).contains(&retry_after),
        "the remaining ≈7 s: {retry_after}"
    );
    assert_eq!(
        instance.upstream.calls() - base,
        1,
        "no attempt during the hold"
    );
}

/// The budget holds only a state that clears
/// on its own: an exclusive route whose one account is quota-barred waits
/// out a 3 s budget like the whole pool's, though `FKEY` outside the route
/// is usable; the same route with its account disabled, and a pool with no
/// account, answer at once.
#[tokio::test(flavor = "multi_thread")]
async fn only_a_state_that_clears_on_its_own_is_held() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "state-clears-held",
        Setup {
            data_plane: "hold_budget_seconds = 3\n".into(),
            selection:
                "routes = [{ name = \"haiku\", patterns = [\"*haiku*\"], accounts = [\"FSUB\"] }]\n"
                    .into(),
            ..Setup::default()
        },
        |instance| {
            instance.add_fsub();
            instance.add_fkey();
        },
    )
    .await;
    let base = instance.upstream.calls();
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("10"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    let started = Instant::now();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    let elapsed = started.elapsed();
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        elapsed >= Duration::from_millis(2_500) && elapsed < Duration::from_secs(6),
        "the quota-barred route is held for the 3 s budget: {elapsed:?}"
    );
    assert!(answer.text().contains("route"), "{}", answer.text());
    assert_eq!(
        instance.upstream.calls() - base,
        1,
        "no attempt during the hold"
    );

    let envelope = instance.cli_json(&["account", "disable", "FSUB"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let started = Instant::now();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        started.elapsed() < Duration::from_millis(1_500),
        "the route's only account disabled answers at once: {:?}",
        started.elapsed()
    );
    assert_eq!(instance.upstream.calls() - base, 1, "no attempt");

    let empty = Instance::start_with(
        "state-clears-held-2",
        Setup {
            data_plane: "hold_budget_seconds = 3\n".into(),
            ..Setup::default()
        },
    )
    .await;
    let started = Instant::now();
    let answer = send(empty.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        started.elapsed() < Duration::from_millis(1_500),
        "no account configured answers at once: {:?}",
        started.elapsed()
    );
}

/// A client that disconnects while its exchange is held makes no
/// attempt; the audit record is still written.
#[tokio::test(flavor = "multi_thread")]
async fn client_disconnect_while_held_makes_no_attempt() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "client-disconnect-while-held",
        Setup {
            data_plane: "hold_budget_seconds = 30\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("60"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    // Connect, deliver the request, then leave before any answer.
    let body = haiku_prompt().to_string();
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\n\
         anthropic-version: 2023-06-01\r\ncontent-length: {}\r\n\r\n",
        instance.addr,
        body.len()
    );
    let mut stream = StdTcpStream::connect(instance.addr).expect("connect");
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .and_then(|_| stream.flush())
        .expect("send the request");
    std::thread::sleep(Duration::from_millis(300));
    drop(stream);

    let calls = instance.upstream.calls();
    let records = instance.audit_settled(2);
    assert_eq!(
        instance.upstream.calls(),
        calls,
        "the held hold made no attempt"
    );
    let record = &records[1];
    assert_eq!(record["status"], Value::Null, "no response was written");
    assert_eq!(record["attempts"], 0);
}

/// A 401 on an OAuth credential forces one refresh
/// and one retry on the rotated token: the caller sees 200, `seen` is
/// attempt (old bearer), token call, attempt (new bearer), the audit record
/// counts both attempts with no failover, and the account stays usable.
#[tokio::test(flavor = "multi_thread")]
async fn http_401_forces_a_refresh_and_one_retry_on_the_rotated_token() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("http-401-forces-refresh").await;
    instance.add_fsub();

    let rotated_access = needle("access token", "oat-fixture");
    instance.upstream.script([reply_auth_401()]);
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": rotated_access,
            "refresh_token": needle("refresh token", "ort-fixture"),
            "expires_in": 3600,
        })
        .to_string(),
    )]);

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());

    // attempt (old bearer), token call, attempt (new bearer) — one account.
    // (The profile lookup of `account add` precedes; take the last three.)
    let seen = instance.upstream.seen();
    let seen = &seen[seen.len() - 3..];
    assert_eq!(seen[0].path, "/v1/messages", "attempt, token call, attempt");
    assert_eq!(seen[0].path, "/v1/messages");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {}", instance.needles.access_token).as_str())
    );
    assert_eq!(seen[1].path, "/v1/oauth/token");
    assert_eq!(seen[1].json()["grant_type"], "refresh_token");
    assert_eq!(
        seen[1].json()["refresh_token"],
        instance.needles.refresh_token
    );
    assert_eq!(seen[2].path, "/v1/messages");
    assert_eq!(
        seen[2].header("authorization"),
        Some(format!("Bearer {rotated_access}").as_str())
    );
    assert_eq!(instance.upstream.token_calls().len(), 1);

    let record = instance.last_record(1);
    assert_eq!(record["attempts"], 2, "the refreshed retry counts");
    assert_eq!(record["failed_over"], false);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["error_class"], Value::Null);

    let fsub = instance.account("FSUB");
    assert_eq!(
        fsub["health"]["state"], "ready",
        "FSUB usable after the refresh"
    );
    assert_eq!(fsub["eligibility"]["eligible"], true);
    assert!(
        fsub["credential"]["last_refresh_success"].is_string(),
        "last_refresh_success set: {fsub}"
    );

    assert_eq!(instance.events("forced_refresh").len(), 1, "");
    assert_eq!(instance.events("refresh_succeeded").len(), 1);
}

/// A 401 on an API key errors the account and ends the exchange
/// with the 502: class `authentication`, one attempt, no token call,
/// the account `errored` (the path / keep using). The same
/// ending through the engine's no-refresh-material branch: a `Forced`
/// trigger on an OAuth account without a refresh token comes back `Errored`
/// and takes the `Refused401 { errored_by_refresh: true }` arm,
/// so the exchange never even logs a token call.
#[tokio::test(flavor = "multi_thread")]
async fn api_key_401_errors_the_account_and_ends_with_502() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("api-key-401-errors").await;
    instance.add_fkey();
    instance.upstream.script([reply_auth_401()]);

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    assert!(answer.text().contains("FKEY"), "{}", answer.text());
    assert_eq!(instance.upstream.token_calls().len(), 0, "no token call");

    let record = instance.last_record(1);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["error_class"], "authentication");

    let fkey = instance.account("FKEY");
    assert_eq!(fkey["health"]["state"], "errored");
    assert_eq!(fkey["eligibility"]["reason"], "errored");

    // FSUB with its refresh token stripped from the state file while the
    // server is down: the forced refresh errors the account without a call.
    instance.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &instance.needles.access_token,
        &instance.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(3600),
    );
    instance.restart_with_state(|state| {
        let record = state["accounts"]
            .as_array_mut()
            .expect("accounts array")
            .iter_mut()
            .find(|r| r["display_name"] == "FSUB")
            .expect("FSUB record");
        record["refresh_token"] = Value::Null;
    });

    instance.error_via_401("FSUB").await;
    assert_eq!(instance.upstream.token_calls().len(), 0);
    assert!(
        instance.events("refresh_started").is_empty(),
        "the engine errored the account without a token call"
    );
    let fsub = instance.account("FSUB");
    assert_eq!(fsub["health"]["state"], "errored");
    assert_eq!(fsub["eligibility"]["reason"], "errored");
}

/// A candidate in refresh-wait. A floor
/// remainder above 15 s refuses at once with the synthetic 429: no token
/// call, `attempts` 0, `no_service_reason` `refresh_wait`, no serving
/// account, the account not errored. A remainder at or below 15 s waits out
/// the floor inline once, then the one shared refresh serves the attempt on
/// the rotated bearer.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_wait_refuses_long_floors_and_waits_out_short_ones() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let refused = Instance::start("refresh-wait-refuses-refused").await;
    refused.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &refused.needles.access_token,
        &refused.needles.refresh_token,
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );
    refused
        .upstream
        .script_token([503, 503, 503].map(|status| Reply::status(status, "{}")));

    let answer = send(refused.addr, messages(haiku_prompt())).await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        answer.text()
    );
    assert_eq!(answer.json()["error"]["type"], "rate_limit_error");
    assert!(answer.text().contains("FSUB"), "{}", answer.text());
    let retry_after: u64 = answer
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    assert!(
        (25..=30).contains(&retry_after),
        "retry-after is the floor's remainder: {retry_after}"
    );
    assert_eq!(
        refused.upstream.token_calls().len(),
        3,
        "no token call inside or after the floor"
    );
    let record = refused.last_record(1);
    assert_eq!(record["attempts"], 0);
    assert_eq!(record["error_class"], "rate_limit");
    assert_eq!(record["no_service_reason"], "refresh_wait");
    assert_eq!(record["serving_account"], Value::Null);
    assert_eq!(refused.events("refresh_wait_refused").len(), 1);
    assert_eq!(
        refused.account("FSUB")["health"]["state"],
        "refresh_wait",
        "the account is not errored"
    );

    // A remainder at or below the bound: one inline wait, then the refresh
    // and the attempt, as if the exchange had arrived after the floor.
    let waited_faults = crate::faults::Faults::new();
    let waited = Instance::start_with_faults(
        "refresh-wait-refuses-waited",
        Setup::default(),
        waited_faults.clone(),
    )
    .await;
    waited.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &waited.needles.access_token,
        &waited.needles.refresh_token,
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );
    waited
        .upstream
        .script_token([503, 503, 503].map(|status| Reply::status(status, "{}")));

    let answer = send(waited.addr, messages(haiku_prompt())).await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the floor starts"
    );

    let rotated_access = needle("access token", "oat-fixture");
    waited.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": rotated_access,
            "refresh_token": needle("refresh token", "ort-fixture"),
            "expires_in": 3600,
        })
        .to_string(),
    )]);
    waited_faults.elapse(Duration::from_secs(16)).await;

    let answer = send_after_inline_refresh_wait(&waited, &waited_faults).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(
        waited.upstream.token_calls().len(),
        4,
        "three first-floor calls, one post-wait"
    );
    let seen = waited.upstream.seen();
    let seen = &seen[seen.len() - 2..];
    assert_eq!(seen[0].path, "/v1/oauth/token");
    assert_eq!(seen[1].path, "/v1/messages");
    assert_eq!(
        seen[1].header("authorization"),
        Some(format!("Bearer {rotated_access}").as_str()),
        "the attempt carries the rotated bearer"
    );
    let record = waited.last_record(2);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(waited.events("refresh_wait_waited").len(), 1);
}

/// The endings after the inline wait, and the
/// 401 inside the floor: the forced trigger starts no refresh and
/// refuses with `attempts` 1; a further transient failure re-floors the
/// account and answers the 429 with the new remainder, the wait spent; a
/// permanent rejection errors the account and ends with the 502.
#[tokio::test(flavor = "multi_thread")]
async fn http_401_inside_the_floor_and_the_endings_after_a_wait() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // A 401 inside the floor: no token call, the 429 keeps the one attempt.
    let inside = Instance::start("refresh-wait-refuses-401").await;
    inside.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &inside.needles.access_token,
        &inside.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(240),
    );
    inside
        .upstream
        .script_token([503, 503, 503].map(|status| Reply::status(status, "{}")));
    inside.upstream.script([reply_headerless_200()]);

    let answer = send(inside.addr, messages(haiku_prompt())).await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "the unexpired token is attempted as is: {}",
        answer.text()
    );

    inside.upstream.script([reply_auth_401()]);
    let answer = send(inside.addr, messages(haiku_prompt())).await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        answer.text()
    );
    assert_eq!(
        inside.upstream.token_calls().len(),
        3,
        "a 401 inside the floor starts no refresh"
    );
    let record = inside.last_record(2);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["no_service_reason"], "refresh_wait");
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(inside.events("forced_refresh").len(), 1);

    // After the wait, another transient failure: the 429 carries the new floor.
    let transient_faults = crate::faults::Faults::new();
    let transient = Instance::start_with_faults(
        "refresh-wait-refuses-transient",
        Setup::default(),
        transient_faults.clone(),
    )
    .await;
    transient.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &transient.needles.access_token,
        &transient.needles.refresh_token,
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );
    transient
        .upstream
        .script_token([503, 503, 503, 503, 503, 503].map(|status| Reply::status(status, "{}")));

    let answer = send(transient.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    transient_faults.elapse(Duration::from_secs(16)).await;
    let answer = send_after_inline_refresh_wait(&transient, &transient_faults).await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        answer.text()
    );
    let retry_after: u64 = answer
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    assert!(
        (25..=30).contains(&retry_after),
        "the new floor's remainder: {retry_after}"
    );
    assert_eq!(
        transient.upstream.token_calls().len(),
        6,
        "the wait spent, one shared refresh"
    );
    let record = transient.last_record(2);
    assert_eq!(record["attempts"], 0);
    assert_eq!(record["no_service_reason"], "refresh_wait");
    assert_eq!(
        transient.events("refresh_wait_waited").len(),
        1,
        "the wait line"
    );

    // After the wait, a permanent rejection: the account errored, the 502.
    let permanent_faults = crate::faults::Faults::new();
    let permanent = Instance::start_with_faults(
        "refresh-wait-refuses-permanent",
        Setup::default(),
        permanent_faults.clone(),
    )
    .await;
    permanent.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &permanent.needles.access_token,
        &permanent.needles.refresh_token,
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );
    permanent.upstream.script_token([
        Reply::status(503, "{}".to_string()),
        Reply::status(503, "{}".to_string()),
        Reply::status(503, "{}".to_string()),
        Reply::status(400, "{}".to_string()),
    ]);

    let answer = send(permanent.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    permanent_faults.elapse(Duration::from_secs(16)).await;
    let answer = send_after_inline_refresh_wait(&permanent, &permanent_faults).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{}", answer.text());
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    let record = permanent.last_record(2);
    assert_eq!(record["error_class"], "authentication");
    let fsub = permanent.account("FSUB");
    assert_eq!(fsub["health"]["state"], "errored", "via ");
    assert!(fsub["eligibility"]["eligible"] == Value::Bool(false));
}

async fn send_after_inline_refresh_wait(
    instance: &Instance,
    faults: &crate::faults::Faults,
) -> Answer {
    send_after_wait(
        instance,
        faults,
        messages(haiku_prompt()),
        "refresh_wait_waited",
    )
    .await
}

/// Advance only after the product has entered its wait, retaining the real-wait
/// coverage on Windows and checking the product's elapsed time in its audit.
async fn send_after_wait(
    instance: &Instance,
    faults: &crate::faults::Faults,
    request: Request<Full<Bytes>>,
    event: &str,
) -> Answer {
    let waits = instance.events(event).len();
    let addr = instance.addr;
    let pending = tokio::spawn(async move { send(addr, request).await });
    let deadline = Instant::now() + Duration::from_secs(5);
    let seconds = loop {
        let events = instance.events(event);
        if let Some(wait) = events.get(waits) {
            break wait["fields"]["seconds"].as_u64().expect("wait seconds");
        }
        assert!(
            Instant::now() < deadline && !pending.is_finished(),
            "the product entered {event}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(!pending.is_finished(), "the request remains held");
    faults.elapse(Duration::from_secs(seconds)).await;
    instance.status();
    tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("the advanced wait completed")
        .expect("held request")
}

/// 8 concurrent 1 MiB uploads all reach the upstream before any is answered;
/// nothing queues behind one another at the transport.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_uploads_all_reach_the_upstream_before_any_answer() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("concurrent-uploads-complete").await;
    instance.add_fsub();

    let big = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 32,
        "messages": [{ "role": "user", "content": "x".repeat(1024 * 1024) }],
    });

    // One gate per reply: `Notify` stores one permit, so a reply released
    // before it reaches its gate still goes through.
    let gates: Vec<_> = (0..8).map(|_| Arc::new(Notify::new())).collect();
    instance
        .upstream
        .script(gates.iter().map(|gate| Reply::Hold(Arc::clone(gate))));
    let uploads = || {
        instance
            .upstream
            .seen()
            .iter()
            .filter(|seen| seen.path == "/v1/messages")
            .count()
    };
    let addr = instance.addr;
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let big = big.clone();
        set.spawn(async move { send(addr, messages(big)).await.status });
    }
    // The fake records a request once its whole body is in.
    let deadline = Instant::now() + Duration::from_secs(10);
    while uploads() < 8 {
        assert!(
            Instant::now() < deadline,
            "{} of 8 held uploads reached the upstream",
            uploads()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for gate in &gates {
        gate.notify_one();
    }
    while let Some(status) = set.join_next().await.transpose().expect("upload task") {
        assert_eq!(status, StatusCode::OK, "every concurrent upload is served");
    }
}

/// A reset mid-body closes the client connection abruptly, never
/// with a clean end of body: Claude Code must not believe the answer
/// was complete.
#[tokio::test(flavor = "multi_thread")]
async fn reset_mid_body_closes_the_client_connection_abruptly() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("reset-mid-body-closes").await;
    instance.add_fsub();

    instance.upstream.script([Reply::ResetMidBody]);
    // A raw socket, so the absence of a clean end is observable byte for byte:
    // the client connection ends without a final chunk and without the
    // terminating `0\r\n\r\n`.
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(instance.addr)
        .await
        .expect("connect to the proxy");
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\n\
         connection: close\r\ncontent-length: {}\r\n\r\n{}",
        instance.addr,
        haiku_prompt().to_string().len(),
        haiku_prompt()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the request");
    let mut raw = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .expect("the connection ends abruptly, not by hanging")
        .expect("read to the reset");
    let text = String::from_utf8_lossy(&raw);
    assert_ne!(read, 0, "headers and part of the body arrived");
    assert!(
        text.contains("200"),
        "the response head was written: {text:.80}"
    );
    assert!(text.contains("hi there friend"), "one body chunk arrived");
    assert!(
        !text.ends_with("0\r\n\r\n"),
        "no clean end of body: the connection is cut mid-stream"
    );
    let record = instance.last_record(1);
    assert_eq!(
        record["status"], 200,
        "the head was written before the reset"
    );
    assert_eq!(record["error_class"], "upstream", "a failure after bytes");
}

/// The proxy's own attempts the fake saw (the egress checks are `seen` too).
fn prompt_attempts(fake: &Fake) -> usize {
    fake.seen()
        .iter()
        .filter(|s| s.path == "/v1/messages")
        .count()
}

pub(crate) const PINNED: &str = "203.0.113.10";
const WRONG: &str = "198.51.100.9";

/// Egress pin `auto` with a fake check URL: the first observation
/// pins; a changed address holds the exchange with the upstream untouched and
/// serves once the pinned address is back; a check that fails is unknown and
/// never blocks; a wrong address past the hold budget is a 503 naming
/// both addresses.
#[tokio::test(flavor = "multi_thread")]
async fn egress_pin_holds_until_the_address_is_pinned_again() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "egress-pin-holds",
        Setup {
            egress: "mode = \"auto\"\ncheck_url = \"{fake}/egress\"\ncache_seconds = 1\nhold_seconds = 30\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance.upstream.script([reply_egress(PINNED)]);

    // The first observation pins the address.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(prompt_attempts(&instance.upstream), 1);
    assert_eq!(instance.events("egress_pinned").len(), 1);
    let egress = instance.status()["server"]["egress"].clone();
    assert_eq!(egress["pinned_addresses"], json!([PINNED]));
    assert_eq!(egress["observed_address"], PINNED);

    // The address changes: the exchange is held, upstream untouched, and
    // served as soon as the pinned address is back.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let attempts = prompt_attempts(&instance.upstream);
    instance
        .upstream
        .script([reply_egress(WRONG), reply_egress(PINNED)]);
    let answer = send(
        instance.addr,
        in_session(messages(haiku_prompt()), "juliet"),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "the return released the hold"
    );
    assert_eq!(
        prompt_attempts(&instance.upstream),
        attempts + 1,
        "upstream untouched while held"
    );
    assert_eq!(instance.events("egress_hold").len(), 1);
    assert_eq!(instance.events("egress_returned").len(), 1);
    let hold = &instance.events("egress_hold")[0];
    assert_eq!(hold["fields"]["observed"], WRONG);
    assert_eq!(hold["fields"]["pinned"], format!("[{PINNED}]"));

    // A check that fails is unknown, and unknown never blocks.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let attempts = prompt_attempts(&instance.upstream);
    instance.upstream.script([Reply::ResetBeforeHeaders]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "a dead check service never blocks"
    );
    assert_eq!(prompt_attempts(&instance.upstream), attempts + 1);
}

/// The second half: a wrong address that outlasts the hold budget
/// answers 503 `retry-after: 30`, naming the observed and pinned addresses,
/// with no attempt made.
#[tokio::test(flavor = "multi_thread")]
async fn egress_hold_budget_ends_in_a_503_naming_both_addresses() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "egress-pin-holds-budget",
        Setup {
            egress: "mode = \"auto\"\ncheck_url = \"{fake}/egress\"\ncache_seconds = 1\nhold_seconds = 6\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance.upstream.script([reply_egress(PINNED)]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let attempts = prompt_attempts(&instance.upstream);
    instance.upstream.script([
        reply_egress(WRONG),
        reply_egress(WRONG),
        reply_egress(WRONG),
        reply_egress(WRONG),
    ]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.header("retry-after"), Some("30"));
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    let message = answer.text();
    assert!(
        message.contains(WRONG) && message.contains(PINNED),
        "{message}"
    );
    assert!(message.contains("VPN"), "{message}");
    assert_eq!(
        prompt_attempts(&instance.upstream),
        attempts,
        "no attempt while the address is wrong"
    );
    let record = instance.last_record(2);
    assert_eq!(record["attempts"], 0);
    assert_eq!(record["error_class"], "upstream");
}

// ------------------------------------------------------------------ the deadlines and the client's pace

/// The MiB chunk an SSE frame of the streaming scripts carries: big enough
/// that no socket buffer masks the pause the scenario asserts.
fn big_chunk() -> String {
    "x".repeat(2 * 1024 * 1024)
}

/// The two idle deadlines and the flowing body:
/// upstream silent before headers fails the attempt at the configured
/// first-byte deadline; silent mid-body fails the relay at the configured
/// body-idle deadline; a body with chunks inside the idle window is never
/// cut. The configurable data-plane deadlines run in short real time.
#[tokio::test(flavor = "multi_thread")]
async fn the_deadlines_fire_and_a_flowing_body_is_never_cut() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "deadlines-fire-flowing",
        Setup {
            data_plane: "first_byte_timeout_seconds = 2\nbody_idle_timeout_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();

    // Silent before headers: the attempt fails at 2 s (never the 120 s
    // default), is retried once (the network class), and the caller's
    // connection closes with no response.
    let started = Instant::now();
    instance.upstream.script([Reply::Stall, Reply::Stall]);
    let outcome = try_send(instance.addr, messages(haiku_prompt())).await;
    let elapsed = started.elapsed();
    assert!(
        outcome.is_err(),
        "no response is written after the deadline: {outcome:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(8),
        "two 2 s deadlines, never the 120 s default: {elapsed:?}"
    );
    let record = instance.last_record(1);
    assert_eq!(record["attempts"], 2);
    assert_eq!(record["error_class"], "upstream");
    assert_eq!(record["status"], Value::Null);

    // Silent mid-body: headers and the first chunk arrive, then silence. The
    // relay fails at the 2 s body-idle deadline and the client's body ends.
    let started = Instant::now();
    let (delivered, dropped) = watched();
    instance.upstream.script([Reply::SseWatched {
        events: vec![big_chunk(), big_chunk()],
        gap_ms: 30_000,
        delivered: delivered.clone(),
        dropped: dropped.clone(),
    }]);
    let mut stalled = open_without_reading(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(stalled.status(), StatusCode::OK, "headers are relayed");
    // Read exactly the first scripted chunk; frames on the wire may split it.
    let mut got = 0usize;
    while got < 2 * 1024 * 1024 {
        got += stalled
            .next_frame()
            .await
            .expect("the first chunk arrives")
            .len();
    }
    let answer = stalled.drain().await;
    let total: usize = got + answer.frames.iter().map(|f| f.len()).sum::<usize>();
    assert!(
        total < 2 * 2 * 1024 * 1024,
        "the silent body ended at the deadline: {total} bytes"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(5),
        "the body-idle deadline, not the 120 s default: {elapsed:?}"
    );
    let record = instance.last_record(2);
    assert_eq!(record["status"], 200, "the response was relayed");
    assert_eq!(record["error_class"], "upstream");

    // A slow but flowing body is never cut: chunks a second apart,
    // every one of them delivered, well past the 2 s idle deadline.
    let started = Instant::now();
    let (delivered, dropped) = watched();
    instance.upstream.script([Reply::SseWatched {
        events: vec![big_chunk(), big_chunk(), big_chunk(), big_chunk()],
        gap_ms: 1_000,
        delivered,
        dropped,
    }]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let delivered_bytes: usize = answer.frames.iter().map(|f| f.len()).sum();
    assert_eq!(delivered_bytes, 8 * 1024 * 1024, "every chunk is delivered");
    assert!(
        started.elapsed() >= Duration::from_secs(3),
        "the body flowed past the 2 s idle window without being cut"
    );
}

/// The client's pace governs the upstream read: a
/// stalled client pauses the upstream read (the fake's stream is not pulled
/// to its end), and a client that disconnects mid-stream cancels the
/// upstream attempt promptly (the fake's stream task is dropped with chunks
/// still to give).
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_client_pauses_and_a_gone_client_cancels() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("stalled-client-pauses").await;
    instance.add_fsub();

    // The stalled client: eight 2 MiB chunks with 30 ms gaps. Nothing pulls
    // them past what the buffers hold, so the fake has frames undelivered
    // after half a second; once the client drains, everything arrives.
    let (delivered, dropped) = watched();
    instance.upstream.script([Reply::SseWatched {
        events: (0..8).map(|_| big_chunk()).collect(),
        gap_ms: 30,
        delivered: delivered.clone(),
        dropped: dropped.clone(),
    }]);
    let mut stalled = open_without_reading(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(stalled.status(), StatusCode::OK);
    let first = stalled
        .next_frame()
        .await
        .expect("the first chunk is relayed to the stalled caller");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let pulled = delivered.load(Ordering::Relaxed);
    assert!(
        pulled < 8,
        "backpressure pauses the upstream read: {pulled} of 8 chunks pulled"
    );
    let answer = stalled.drain().await;
    let bytes = first.len() + answer.frames.iter().map(|frame| frame.len()).sum::<usize>();
    assert_eq!(bytes, 16 * 1024 * 1024, "draining delivers everything");
    assert_eq!(delivered.load(Ordering::Relaxed), 8);

    // The disconnecting client: a long stream is still pending when the
    // caller goes away; the fake's stream task is dropped with most of its
    // chunks undelivered, promptly (well inside the 6 s the script needs).
    let (delivered, dropped) = watched();
    instance.upstream.script([Reply::SseWatched {
        events: (0..60).map(|_| big_chunk()).collect(),
        gap_ms: 100,
        delivered: delivered.clone(),
        dropped: dropped.clone(),
    }]);
    let mut leaving = open_without_reading(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(leaving.status(), StatusCode::OK);
    leaving.next_frame().await.expect("the first chunk");
    drop(leaving);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(
        dropped.load(Ordering::Relaxed),
        "the upstream attempt was cancelled promptly"
    );
    let pulled = delivered.load(Ordering::Relaxed);
    assert!(
        pulled < 30,
        "the cancelled attempt took only the first chunks: {pulled} of 60"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn incomplete_tls_handshake_does_not_block_other_clients() {
    use tokio::io::AsyncReadExt as _;

    let _leak_sweep = crate::leaks::LeakGuard::default();
    let pair = scratch("incomplete-tls-handshake-pair");
    let (certificate, private_key) = stage_tls_pair(&pair);
    let instance = Instance::start_with(
        "incomplete-tls-handshake",
        Setup {
            data_plane: format!(
                "tls_certificate_file = {}\ntls_private_key_file = {}\n",
                crate::harness::toml_path(&certificate),
                crate::harness::toml_path(&private_key)
            ),
            ..Setup::default()
        },
    )
    .await;
    let mut incomplete = TcpStream::connect(instance.addr)
        .await
        .expect("open a connection without completing TLS");
    let request = Request::builder()
        .uri("/control/v1/status")
        .body(Full::new(Bytes::new()))
        .expect("health request");
    let answer = tokio::time::timeout(
        Duration::from_secs(2),
        send_tls(instance.addr, request, false),
    )
    .await;
    assert_eq!(
        answer
            .expect("another client must not wait for the incomplete TLS handshake")
            .status,
        StatusCode::OK
    );
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(12), incomplete.read(&mut byte))
            .await
            .expect("the stalled handshake is closed within a bounded time")
            .expect("read the closed connection"),
        0
    );
}

/// The base-URL TLS listener serves the same exchange over
/// HTTP/1.1 and HTTP/2: status, headers but framing and date, body and audit
/// facts are identical.
#[tokio::test(flavor = "multi_thread")]
async fn tls_listener_agrees_over_http_1_and_http_2() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let pair = scratch("tls-listener-agrees-pair");
    let (certificate, private_key) = stage_tls_pair(&pair);
    let instance = Instance::start_with(
        "tls-listener-agrees",
        Setup {
            data_plane: format!(
                "tls_certificate_file = {}\ntls_private_key_file = {}\n",
                crate::harness::toml_path(&certificate),
                crate::harness::toml_path(&private_key)
            ),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();

    let http1 = send_tls(instance.addr, messages(haiku_prompt()), false).await;
    // An HTTP/2 client sends `:scheme` and `:authority` (curl, Node), which
    // the server sees as an absolute URI; the absolute-form refusal is
    // an HTTP/1.x rule and must not fire here.
    let mut absolute = messages(haiku_prompt());
    *absolute.uri_mut() = format!("https://{}/v1/messages", instance.addr)
        .parse()
        .expect("absolute uri");
    let http2 = send_tls(instance.addr, absolute, true).await;
    assert_eq!(http1.status, http2.status, "{}", http2.text());
    assert_eq!(http1.body(), http2.body());
    assert_eq!(
        stable_headers(&http1.headers),
        stable_headers(&http2.headers)
    );

    let mut records = instance.audit_settled(2);
    assert_eq!(
        stable_audit(records.remove(0)),
        stable_audit(records.remove(0))
    );
}

fn stable_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "connection" | "transfer-encoding" | "date"))
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().expect("response header is text").to_owned(),
            )
        })
        .collect();
    values.sort_unstable();
    values
}

fn stable_audit(mut record: Value) -> Value {
    let object = record.as_object_mut().expect("audit object");
    for dynamic in ["timestamp", "duration_ms", "source_address"] {
        object.remove(dynamic);
    }
    record
}

/// With a corporate proxy and an upstream host also
/// present in `no_proxy`, the attempt, token, profile and usage calls all use
/// one CONNECT transport and TLS still terminates at the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn every_server_opened_call_uses_the_corporate_proxy() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let upstream = Fake::start_tls().await;
    let proxy = ProxyFake::start().await;
    let target = format!("localhost:{}", upstream.addr.port());
    let ca =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance/fixtures/tls/test-ca.pem");
    let instance = Instance::start_with_upstream(
        "server-opened-call",
        Setup {
            upstream_origin: Some(format!("https://{target}")),
            data_plane: format!(
                "corporate_proxy_url = \"http://{}\"\nno_proxy = [\"localhost\"]\n",
                proxy.addr
            ),
            server_env: vec![("SSL_CERT_FILE".into(), ca.display().to_string())],
            ..Setup::default()
        },
        upstream,
    )
    .await;

    // Profile, attempt, token (plus its profile), and usage respectively.
    instance.add_fsub();
    assert_eq!(
        send(instance.addr, messages(haiku_prompt())).await.status,
        StatusCode::OK
    );
    let (operation, url) = crate::acc::start_login(&instance);
    let (callback, state) = crate::acc::callback_target(&url);
    assert_eq!(
        send(
            callback,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/callback?code=oat-through-proxy&state={state}"))
                .body(Full::new(Bytes::new()))
                .expect("callback request")
        )
        .await
        .status,
        StatusCode::FOUND
    );
    assert_eq!(
        crate::acc::await_operation(&instance, &operation)["state"],
        "succeeded"
    );
    let probe = instance.cli_json(&["probe", "--wait"], None);
    assert_eq!(probe["ok"], true, "usage probe: {probe}");

    let paths: Vec<_> = instance
        .upstream
        .seen()
        .into_iter()
        .map(|request| request.path)
        .collect();
    for path in [
        "/v1/messages",
        "/v1/oauth/token",
        "/api/oauth/profile",
        "/api/oauth/usage",
    ] {
        assert!(paths.iter().any(|seen| seen == path), "{path}: {paths:?}");
    }
    let tunnels = proxy.seen();
    assert!(!tunnels.is_empty(), "the configured proxy received CONNECT");
    assert!(
        tunnels
            .iter()
            .all(|request| request.method == "CONNECT" && request.path == target),
        "every server connection tunnels to the TLS upstream: {tunnels:?}"
    );
}
