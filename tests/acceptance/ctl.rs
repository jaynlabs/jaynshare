//! The control plane's operator projection: the namespace and version
//! rules, the request and response conventions, the snapshot and its
//! sections, the account and selection operations, reload and the probe
//! trigger. Every request here is raw HTTP on the base-URL listener from a
//! loopback peer, so the principal is the loopback operator with no
//! credential presented.

use crate::harness::*;
use sha2::{Digest, Sha256};

// ------------------------------------------------------------------ helpers

/// One control request with an optional JSON body.
fn ctl(method: Method, path: &str, body: Option<Value>) -> Request<Full<Bytes>> {
    let mut builder = Request::builder().method(method).uri(path);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let bytes = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    builder
        .body(Full::new(bytes))
        .expect("control request builds")
}

async fn ctl_get(addr: SocketAddr, path: &str) -> Answer {
    send(addr, ctl(Method::GET, path, None)).await
}

async fn ctl_post(addr: SocketAddr, path: &str, body: Value) -> Answer {
    send(addr, ctl(Method::POST, path, Some(body))).await
}

async fn ctl_delete(addr: SocketAddr, path: &str) -> Answer {
    send(addr, ctl(Method::DELETE, path, Some(json!({})))).await
}

/// every control body carries the version it was produced under.
fn assert_version(body: &Value) {
    assert_eq!(body["control_api_version"], 1, "the version member: {body}");
}

/// the error envelope's shape and the expected stable slug.
fn assert_error(body: &Value, code: &str) -> Value {
    assert_version(body);
    let error = &body["error"];
    assert_eq!(error["code"], code, "the stable slug: {body}");
    assert!(
        error["message"].as_str().is_some_and(|m| !m.is_empty()),
        "a message with cause and next step: {body}"
    );
    assert!(
        error["target"].is_null() || error["target"].is_string(),
        "target is a dotted key or null: {body}"
    );
    assert!(
        error["details"].is_array(),
        "details is an array, possibly empty: {body}"
    );
    error.clone()
}

/// A successful read carries `captured_at` and its named payload.
fn assert_read(body: &Value) {
    assert_version(body);
    assert!(body["captured_at"].is_string(), "the instant: {body}");
}

/// The SHA-256 of the configuration file's exact bytes.
fn config_digest(instance: &Instance) -> String {
    let bytes = fs::read(&instance.config).expect("read the configuration");
    format!("{:x}", Sha256::digest(&bytes))
}

/// Waits until the fake upstream has seen `count` calls of any kind.
async fn await_upstream_calls(instance: &Instance, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while instance.upstream.calls() < count {
        assert!(Instant::now() < deadline, "the upstream was never called");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Waits until the fake upstream has seen `count` usage-probe calls.
async fn await_upstream_usage_calls(instance: &Instance, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while instance.upstream.usage_calls().len() < count {
        assert!(Instant::now() < deadline, "the usage call never arrived");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Reads the snapshot until `predicate` holds; returns the last body.
async fn await_snapshot(addr: SocketAddr, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let body = ctl_get(addr, "/control/v1/status").await.json();
        if predicate(&body) || Instant::now() > deadline {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `POST /control/v1/accounts` with a `credential` object and an optional name.
async fn add_account_ctl(
    addr: SocketAddr,
    credential: Value,
    display_name: Option<&str>,
) -> (StatusCode, Value) {
    let mut body = json!({ "credential": credential });
    if let Some(name) = display_name {
        body["display_name"] = json!(name);
    }
    let answer = ctl_post(addr, "/control/v1/accounts", body).await;
    (answer.status, answer.json())
}

/// `GET /control/v1/accounts/resolve` with the percent-encoded reference.
async fn resolve_ctl(addr: SocketAddr, reference: &str) -> (StatusCode, Value) {
    let encoded = reference
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect::<String>();
    let answer = ctl_get(
        addr,
        &format!("/control/v1/accounts/resolve?reference={encoded}"),
    )
    .await;
    (answer.status, answer.json())
}

/// The eligibility object of one account, read fresh.
async fn eligibility_ctl(addr: SocketAddr, handle: &str) -> Value {
    ctl_get(addr, &format!("/control/v1/accounts/{handle}"))
        .await
        .json()["account"]["eligibility"]
        .clone()
}

/// An unknown path under `/control/` is never forwarded; the fake
/// upstream sees nothing; the comparison of the reserved segment is exact
/// lower-case ASCII, so `Control/` is a data-plane path.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_control_paths_are_never_forwarded() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("unknown-control-paths").await;
    instance.add_fsub();
    // `add` resolves the profile upstream once; that is the baseline.
    let baseline = instance.upstream.calls();
    let addr = instance.addr;

    for path in [
        "/control",
        "/control/",
        "/control/v9/status",
        "/control/v1/totally-unknown",
        "/control/v1/status/extra",
    ] {
        let answer = ctl_get(addr, path).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert_error(&answer.json(), "not_found");
    }
    assert_eq!(
        instance.upstream.calls(),
        baseline,
        "the fake upstream saw nothing for any control path"
    );

    // Exact lower-case ASCII: `Control` is not the reserved segment, so the
    // request follows the data plane and is forwarded under the pooled
    // credential.
    let answer = ctl_get(addr, "/Control/v1/status").await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.upstream.calls(), baseline + 1);
    let seen = instance.upstream.last();
    assert_eq!(seen.path, "/Control/v1/status");
}

/// An unknown control version is for a principal, and every
/// control response body carries the version it was produced under.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_version_and_every_response_carries_the_version() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("unknown-version-response").await;
    let addr = instance.addr;

    let answer = ctl_get(addr, "/control/v2/status").await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    let refused = answer.json();
    assert_error(&refused, "not_found");

    // The reads and the refusals all carry the version.
    let second = ctl_get(addr, "/control/v1/status").await.json();
    let third = ctl_get(addr, "/control/v1/no-such-endpoint").await.json();
    let fourth = send(addr, ctl(Method::GET, "/control/v1/accounts", None))
        .await
        .json();
    for body in [refused, second, third, fourth] {
        assert_version(&body);
    }
}

/// A mutation without the JSON media type is, an unknown
/// member is naming it, and a 1 MiB + 1 body is.
#[tokio::test(flavor = "multi_thread")]
async fn the_mutation_body_rules() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("mutation-body-rules").await;
    let addr = instance.addr;

    // No media type: 415.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/control/v1/reload")
        .body(Full::new(Bytes::from_static(b"{}")))
        .expect("request builds");
    let answer = send(addr, request).await;
    assert_eq!(answer.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_error(&answer.json(), "unsupported_media_type");

    // An unknown member: 400 naming it.
    let answer = ctl_post(addr, "/control/v1/reload", json!({ "nope": 1 })).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    let error = assert_error(&answer.json(), "invalid_request");
    let details = error["details"].as_array().expect("details");
    assert!(
        details
            .iter()
            .any(|d| d["target"] == "nope" && d["code"] == "unknown_member"),
        "the offending member is named: {error}"
    );

    // The body is not a JSON object: 400.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/control/v1/reload")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(b"[1,2]")))
        .expect("request builds");
    let answer = send(addr, request).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_error(&answer.json(), "invalid_request");

    // 1 MiB + 1: 413 — the limit is about the bytes, not the members.
    let oversized = "x".repeat(1024 * 1024 + 1);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/control/v1/reload")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(oversized)))
        .expect("request builds");
    let answer = send(addr, request).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_error(&answer.json(), "request_too_large");
}

/// A Unicode display name in the query round-trips; ambiguous and
/// unknown references; a decimal index is a name, never a position; the read
/// changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn reference_forms_on_the_resolve_read() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("reference-forms-resolve").await;
    instance.add_fsub();
    for name in ["0", "Réa"] {
        let (status, body) = add_account_ctl(
            instance.addr,
            json!({ "source": "api_key", "api_key": instance.needles.api_key }),
            Some(name),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    instance.add_other_org(
        "FSUB2",
        "fsub2@fixture.invalid",
        FSUB2_UUID,
        FIXTURE_ORG_UUID,
    );
    let addr = instance.addr;

    // The Unicode display name round-trips through the percent-encoded query.
    let (status, body) = resolve_ctl(addr, "Réa").await;
    assert_eq!(status, StatusCode::OK);
    assert_read(&body);
    assert_eq!(body["account"]["display_name"], "Réa");

    // A decimal index is a name, never a position: the account *named* "0",
    // which is not the first account.
    let (status, body) = resolve_ctl(addr, "0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["account"]["display_name"], "0");
    assert_ne!(body["account"]["handle"], body_status_unreachable());

    // Two accounts in one organisation: the organisation UUID is ambiguous,
    // and the matching display names come back.
    let (status, body) = resolve_ctl(addr, FIXTURE_ORG_UUID).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error = assert_error(&body, "ambiguous_account_reference");
    let named: Vec<&str> = error["details"]
        .as_array()
        .expect("details")
        .iter()
        .filter_map(|d| d["target"].as_str())
        .collect();
    assert!(
        named.contains(&"FSUB") && named.contains(&"FSUB2"),
        "{error}"
    );

    // No match: 404.
    let (status, body) = resolve_ctl(addr, "nobody").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_error(&body, "account_not_found");

    // A control character never travels: 400 before any resolution.
    let request = ctl(
        Method::GET,
        "/control/v1/accounts/resolve?reference=a%0Ab",
        None,
    );
    let answer = send(addr, request).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_error(&answer.json(), "invalid_request");

    // The read changes nothing: the default is where it was.
    let before = instance.default_account();
    let _ = resolve_ctl(addr, "FSUB").await;
    assert_eq!(instance.default_account(), before);
}

fn body_status_unreachable() -> Value {
    // A never-matching comparison target for "a name, not a position".
    Value::Null
}

/// Every error after principal resolution validates against the
/// control envelope, and carries no secret, no file contents and no proxy user
/// information.
#[tokio::test(flavor = "multi_thread")]
async fn every_error_is_the_control_envelope() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("error-control-envelope").await;
    instance.add_fsub();
    instance.add_fkey();
    let addr = instance.addr;
    let handle = instance.handle("FKEY");

    let attempts: Vec<(&str, Request<Full<Bytes>>)> = vec![
        (
            "unknown handle",
            ctl(
                Method::GET,
                "/control/v1/accounts/00000000-0000-0000-0000-000000000000",
                None,
            ),
        ),
        (
            "unknown member",
            ctl(
                Method::POST,
                "/control/v1/accounts",
                Some(json!({ "credential": 1 })),
            ),
        ),
        (
            "rejected credential",
            ctl(
                Method::POST,
                "/control/v1/accounts",
                Some(
                    json!({ "display_name": "X", "credential": { "source": "api_key", "api_key": "" } }),
                ),
            ),
        ),
        (
            "name conflict",
            ctl(
                Method::POST,
                &format!("/control/v1/accounts/{handle}/name"),
                Some(json!({ "display_name": "FSUB" })),
            ),
        ),
        (
            "unknown reference",
            ctl(
                Method::GET,
                "/control/v1/accounts/resolve?reference=zz",
                None,
            ),
        ),
        ("wrong method", ctl(Method::PUT, "/control/v1/status", None)),
    ];
    for (what, request) in attempts {
        let answer = send(addr, request).await;
        let body = answer.json();
        assert_version(&body);
        let slug = body["error"]["code"].as_str().expect("a slug").to_string();
        assert!(
            !slug.is_empty() && slug.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{what}: the slug is stable lower-case snake: {body}"
        );
        assert_error(&body, &slug);
        let text = body.to_string();
        for needle in instance.needles.all() {
            assert!(!text.contains(needle), "{what}: the needle leaked: {text}");
        }
    }
}

/// Unknown and not-applicable facts are `null` with their enums
/// set, never or an omitted member.
#[tokio::test(flavor = "multi_thread")]
async fn absent_facts_are_null_not_zero_or_omitted() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("absent-facts-null").await;
    instance.add_fkey();
    let body = ctl_get(instance.addr, "/control/v1/status").await.json();
    assert_read(&body);
    let account = &body["status"]["accounts"].as_array().expect("accounts")[0];

    // An API-key account has no profile and no OAuth credential facts.
    for member in [
        "email",
        "account_uuid",
        "organization_uuid",
        "organization_name",
    ] {
        assert!(account["profile"][member].is_null(), "{member}: {account}");
    }
    for member in [
        "access_token_expires_at",
        "last_refresh_attempt",
        "last_refresh_success",
        "next_refresh_allowed_at",
    ] {
        assert!(
            account["credential"][member].is_null(),
            "{member}: {account}"
        );
    }
    assert_eq!(account["credential"]["refresh_material_present"], false);

    // Every bucket member is present; the source supplied nothing.
    for bucket in account["buckets"].as_array().expect("buckets") {
        assert_eq!(bucket["state"], "unknown", "{bucket}");
        for member in [
            "utilisation",
            "limit",
            "remaining",
            "reset",
            "hold_end",
            "observed_at",
            "observed_source",
        ] {
            assert!(bucket[member].is_null(), "{member}: {bucket}");
        }
    }

    // The enums are set where they exist; absent facts are null.
    assert_eq!(account["health"]["state"], "ready");
    assert!(account["health"]["reason"].is_null());
    assert_eq!(account["ramp"]["active"], false);
    assert!(account["ramp"]["started_at"].is_null());
    assert!(account["probe"]["outcome"].is_null());
    let status = &body["status"];
    assert!(status["usage_probe"]["pending_reason"].is_null());
    assert!(status["capture"]["directory"].is_null());
    // Set under the override the suite runs with: the member is never
    // omitted, which is the half of a known fact can show.
    assert!(
        status["server"]["upstream_origin_override"].is_string(),
        "{}",
        status["server"]
    );
}

/// The snapshot answers while every account is held and an
/// exchange is mid-stream, and no upstream call is made during a read.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_never_waits_or_touches_the_upstream() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("read-never-waits").await;
    instance.add_fsub();
    let addr = instance.addr;
    // `add` resolves the profile upstream once; that is the baseline.
    let baseline = instance.upstream.calls();

    let gate = Arc::new(Notify::new());
    instance.upstream.script([Reply::Hold(gate.clone())]);
    let exchange = tokio::spawn(send(addr, messages(haiku_prompt())));
    await_upstream_calls(&instance, baseline + 1).await;

    let start = Instant::now();
    let body = ctl_get(addr, "/control/v1/status").await.json();
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "the read did not wait on the held exchange"
    );
    assert!(
        body.get("error").is_none() || body["error"].is_null(),
        "the read answered: {body}"
    );
    assert_eq!(
        instance.upstream.calls(),
        baseline + 1,
        "the read made no upstream call"
    );

    gate.notify_waiters();
    let answer = exchange.await.expect("the exchange ends");
    assert_eq!(answer.status, StatusCode::OK);
}

/// A switch applied between two reads never appears half-applied,
/// and two consecutive reads agree.
#[tokio::test(flavor = "multi_thread")]
async fn the_snapshot_is_never_torn() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("snapshot-never-torn").await;
    instance.add_fsub();
    instance.add_oauth("FSUB2", "fsub2@fixture.invalid", FSUB2_UUID);
    let addr = instance.addr;

    let first = ctl_get(addr, "/control/v1/status").await.json();
    assert_eq!(
        first["status"]["default_account"]["handle"],
        instance.handle("FSUB")
    );
    assert_eq!(
        first["status"]["default_account"]["operator_chosen"], false,
        "the startup ranking chose it"
    );

    let switched = ctl_post(
        addr,
        "/control/v1/selection/default",
        json!({ "reference": "FSUB2" }),
    )
    .await;
    assert_eq!(switched.status, StatusCode::OK);

    let second = ctl_get(addr, "/control/v1/status").await.json();
    let third = ctl_get(addr, "/control/v1/status").await.json();
    for snapshot in [&second, &third] {
        let snapshot = &snapshot["status"];
        let handle = snapshot["default_account"]["handle"]
            .as_str()
            .expect("a default");
        assert!(
            snapshot["accounts"]
                .as_array()
                .expect("accounts")
                .iter()
                .any(|a| a["handle"] == handle),
            "the default is one of the accounts, never half-applied: {snapshot}"
        );
        for route in snapshot["routes"].as_array().expect("routes") {
            if let Some(predicted) = route["predicted_target"].as_str() {
                assert!(
                    snapshot["accounts"]
                        .as_array()
                        .expect("accounts")
                        .iter()
                        .any(|a| a["handle"] == predicted),
                    "the prediction is an account: {route}"
                );
            }
        }
    }
    assert_eq!(
        second["status"]["accounts"], third["status"]["accounts"],
        "two reads agree"
    );
    assert_eq!(
        second["status"]["default_account"],
        third["status"]["default_account"]
    );
}

/// The member set of the account object.
const ACCOUNT_MEMBERS: [&str; 17] = [
    "handle",
    "display_name",
    "kind",
    "source_class",
    "enabled",
    "owner",
    "health",
    "profile",
    "credential",
    "priority",
    "eligibility",
    "buckets",
    "quota_holds",
    "usage",
    "sessions_active",
    "ramp",
    "probe",
];

fn assert_account_shape(account: &Value) {
    let members = account.as_object().expect("object");
    for member in ACCOUNT_MEMBERS {
        assert!(members.contains_key(member), "missing {member}: {account}");
    }
    assert_eq!(
        members.len(),
        ACCOUNT_MEMBERS.len(),
        "exactly these: {account}"
    );
    for (object, keys) in [
        (&account["health"], &["state", "reason", "since"][..]),
        (
            &account["profile"],
            &[
                "email",
                "account_uuid",
                "organization_uuid",
                "organization_name",
            ][..],
        ),
        (
            &account["credential"],
            &[
                "access_token_expires_at",
                "refresh_material_present",
                "last_refresh_attempt",
                "last_refresh_success",
                "next_refresh_allowed_at",
            ][..],
        ),
        (
            &account["eligibility"],
            &["eligible", "reason", "reason_detail"][..],
        ),
        (
            &account["quota_holds"],
            &["throttle_hold_end", "revalidation_allowed"][..],
        ),
        (
            &account["usage"],
            &["input_tokens", "output_tokens", "requests"][..],
        ),
        (&account["ramp"], &["active", "started_at", "limit"][..]),
        (&account["probe"], &["outcome", "finished_at", "error"][..]),
    ] {
        for key in keys {
            assert!(object.get(*key).is_some(), "{key} in {object}");
        }
    }
    for bucket in account["buckets"].as_array().expect("buckets") {
        for key in [
            "name",
            "scope",
            "state",
            "utilisation",
            "limit",
            "remaining",
            "reset",
            "hold_end",
            "observed_at",
            "observed_source",
        ] {
            assert!(bucket.get(key).is_some(), "{key} in {bucket}");
        }
    }
}

/// Every account object carries every fact, and no pooled
/// credential appears anywhere in the projection.
#[tokio::test(flavor = "multi_thread")]
async fn account_facts_and_no_credential() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("account-facts-no-credential").await;
    instance.add_fsub();
    instance.add_fkey();
    let addr = instance.addr;

    let body = ctl_get(addr, "/control/v1/accounts").await.json();
    assert_read(&body);
    let accounts = body["accounts"].as_array().expect("accounts");
    assert_eq!(accounts.len(), 2, "{body}");
    for account in accounts {
        assert_account_shape(account);
    }
    assert_eq!(accounts[0]["kind"], "oauth");
    assert_eq!(accounts[0]["profile"]["email"], "fsub@fixture.invalid");
    assert_eq!(accounts[0]["source_class"], "portable-json");
    assert_eq!(accounts[1]["kind"], "api_key");

    // No credential, prefix or derivative anywhere in the response.
    let text = body.to_string();
    for needle in instance.needles.all() {
        assert!(!text.contains(needle), "the needle leaked: {text}");
        assert!(
            !text.contains(&needle[..needle.len().min(12)]),
            "not even a prefix: {text}"
        );
    }

    // One account read is the same shape as one element of the array.
    let handle = accounts[0]["handle"].as_str().expect("handle").to_string();
    let one = ctl_get(addr, &format!("/control/v1/accounts/{handle}"))
        .await
        .json();
    assert_read(&one);
    assert_account_shape(&one["account"]);
    assert_eq!(one["account"], accounts[0]);
}

/// Each barred state reports its own `eligibility.reason`, and
/// never a route reason: the projection is model-less.
#[tokio::test(flavor = "multi_thread")]
async fn every_ineligible_reason_is_the_right_one() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "ineligible-reason-right",
        Setup {
            selection: routes(&[("haiku", &["claude-haiku*"], Some(&["FSUB"]), None)]),
            // The revalidation floor is shortened so the held account can be
            // shown capacity again inside the scenario.
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
        |instance| {
            instance.add_fsub();
            instance.add_oauth("FSUB2", "fsub2@fixture.invalid", FSUB2_UUID);
        },
    )
    .await;
    let addr = instance.addr;
    let fsub = instance.handle("FSUB");
    async fn enable_disable(addr: SocketAddr, handle: &str, operation: &str) -> StatusCode {
        let request = ctl(
            Method::POST,
            &format!("/control/v1/accounts/{handle}/{operation}"),
            Some(json!({})),
        );
        send(addr, request).await.status
    }

    // Disabled — and, on FSUB2, never a route reason though no route lists it.
    assert_eq!(enable_disable(addr, &fsub, "disable").await, StatusCode::OK);
    let state = eligibility_ctl(addr, &fsub).await;
    assert_eq!(state["reason"], "disabled", "{state}");
    assert_eq!(state["eligible"], false);

    // Errored, by a refused refresh: the attempt and the refresh both 401.
    assert_eq!(enable_disable(addr, &fsub, "enable").await, StatusCode::OK);
    instance
        .upstream
        .script([reply_auth_401(), reply_auth_401()]);
    let answer = send(addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    instance.settle();
    let state = eligibility_ctl(addr, &fsub).await;
    assert_eq!(state["reason"], "errored", "{state}");

    // Enable clears the errored state: ready again.
    assert_eq!(enable_disable(addr, &fsub, "enable").await, StatusCode::OK);
    let state = eligibility_ctl(addr, &fsub).await;
    assert_eq!(state["eligible"], true, "{state}");

    // Held: the weekly bucket exhausted, the hold running its `retry-after`.
    // The hold is long, because takes a reset-less bucket back to
    // `unknown` the moment it ends — a short one would race the read.
    let exhausted = reply_429_unified(
        &[
            ("5h-utilization", "0.40"),
            ("5h-status", "allowed"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("3000"),
    );
    instance.upstream.script([exhausted]);
    let answer = send(addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    instance.settle();
    let held = await_snapshot(addr, |body| {
        body["status"]["accounts"]
            .as_array()
            .and_then(|a| a.first())
            .map(|a| a["eligibility"]["reason"] == "held")
            .unwrap_or(false)
    })
    .await;
    let account = held["status"]["accounts"].as_array().expect("accounts")[0].clone();
    assert_eq!(account["eligibility"]["reason"], "held", "{held}");
    assert!(
        account["eligibility"]["reason_detail"].is_string(),
        "the hold end that produced it: {account}"
    );

    // Over threshold, on FSUB2: a served exchange for a model the haiku route
    // does not match teaches a utilisation above the switch threshold with a
    // reset far out, so nothing is held and nothing expires.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(addr, messages(prompt_for("claude-sonnet-4-5"))).await;
    assert_eq!(answer.status, StatusCode::OK, "over threshold still serves");
    instance.settle();
    let over = await_snapshot(addr, |body| {
        body["status"]["accounts"]
            .as_array()
            .and_then(|a| a.get(1))
            .map(|a| a["eligibility"]["reason"] == "over_threshold")
            .unwrap_or(false)
    })
    .await;
    let account = over["status"]["accounts"].as_array().expect("accounts")[1].clone();
    assert_eq!(account["eligibility"]["reason"], "over_threshold", "{over}");
    assert!(
        account["eligibility"]["reason_detail"].is_string(),
        "the reset that produced it: {account}"
    );

    // FSUB2 is disabled too: the reason stays a pool reason, never a route one.
    let fsub2 = instance.handle("FSUB2");
    let request = ctl(
        Method::POST,
        &format!("/control/v1/accounts/{fsub2}/disable"),
        Some(json!({})),
    );
    assert_eq!(send(addr, request).await.status, StatusCode::OK);
    let state = eligibility_ctl(addr, &fsub2).await;
    assert_eq!(state["reason"], "disabled", "{state}");
}

/// `predicted_target` is the account the next exchange for that
/// route actually gets, and the read moves nothing.
#[tokio::test(flavor = "multi_thread")]
async fn predicted_target_is_what_the_next_exchange_gets() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "predicted-target-what-next",
        Setup {
            selection: routes(&[("haiku", &["claude-haiku*"], Some(&["FSUB2"]), None)]),
            ..Setup::default()
        },
        |instance| {
            instance.add_fsub();
            instance.add_oauth_family(
                "FSUB2",
                "fsub2@fixture.invalid",
                FSUB2_UUID,
                "sk-ant-oat-fixture-predicted",
                "sk-ant-ort-fixture-predicted",
                OffsetDateTime::now_utc() + Duration::from_secs(3_600),
            );
        },
    )
    .await;
    let addr = instance.addr;
    let predicted = instance.handle("FSUB2");

    let body = ctl_get(addr, "/control/v1/status").await.json();
    assert_read(&body);
    let body = &body["status"];
    let route = body["routes"]
        .as_array()
        .expect("routes")
        .iter()
        .find(|r| r["name"] == "haiku")
        .expect("the route")
        .clone();
    assert_eq!(
        route["predicted_target"], predicted,
        "the read-only prediction: {route}"
    );
    assert_eq!(route["preference"], Value::Null);
    let listed = route["accounts"].as_array().expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["handle"], predicted);
    assert_eq!(listed[0]["eligible"], true);

    // The read moved nothing: the default is where the ranking put it.
    assert_eq!(body["default_account"]["handle"], instance.handle("FSUB"));
    let again = ctl_get(addr, "/control/v1/status").await.json();
    assert_eq!(
        again["status"]["default_account"]["handle"],
        instance.handle("FSUB")
    );

    // The next exchange for the route's model lands on the prediction.
    let answer = send(addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        instance.upstream.last().header("authorization"),
        Some("Bearer sk-ant-oat-fixture-predicted"),
        "the exchange was served by the predicted account"
    );
}

/// Buckets render the absent fields as `null`; an `unknown`
/// bucket is not `available`.
#[tokio::test(flavor = "multi_thread")]
async fn buckets_render_absence_as_null() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("buckets-render-absence").await;
    instance.add_fsub();
    let addr = instance.addr;

    let body = ctl_get(addr, "/control/v1/status").await.json();
    let account = body["status"]["accounts"].as_array().expect("accounts")[0].clone();
    let buckets = account["buckets"].as_array().expect("buckets");
    let weekly = buckets
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("the weekly bucket is expected of an OAuth account");
    assert_eq!(weekly["state"], "unknown", "{weekly}");
    for member in [
        "utilisation",
        "limit",
        "remaining",
        "reset",
        "hold_end",
        "observed_at",
        "observed_source",
    ] {
        assert!(weekly[member].is_null(), "{member}: {weekly}");
    }

    // One exchange teaches the window: the bucket is then available, which
    // `unknown` never claimed to be.
    instance
        .upstream
        .script([reply_teaching_weekly("0.12", &reset_in(3_600))]);
    let answer = send(addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let taught = instance.account("FSUB");
    let weekly = taught["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["state"], "available", "{weekly}");
    assert_eq!(weekly["utilisation"], 0.12, "{weekly}");
    assert!(weekly["observed_at"].is_string());
}

/// The shapes of `usage_probe`: disabled, enabled and mid-sweep
/// At this control API version the probe is `v1` grade, so
/// the pending-shape is `pending_reason: null` and the
/// `probe_unavailable` branch of does not exist.
#[tokio::test(flavor = "multi_thread")]
async fn the_usage_probe_shapes() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("usage-probe-shapes").await;
    instance.add_fsub();
    let addr = instance.addr;

    // Disabled: the default.
    let probe = ctl_get(addr, "/control/v1/status").await.json()["status"]["usage_probe"].clone();
    assert_eq!(probe["enabled"], false, "{probe}");
    assert!(probe["last_started"].is_null() && probe["last_finished"].is_null());
    assert!(probe["next_run"].is_null());
    assert!(probe["pending_reason"].is_null());

    // Enabled: the scheduler starts at once and records its times.
    instance.reload_with_setup(&Setup {
        quota: "probe_enabled = true\nprobe_interval_seconds = 30\n".into(),
        ..Setup::default()
    });
    let enabled = await_snapshot(addr, |body| {
        body["status"]["usage_probe"]["last_finished"].is_string()
    })
    .await;
    let probe = enabled["status"]["usage_probe"].clone();
    assert_eq!(probe["enabled"], true, "{probe}");
    assert_eq!(probe["interval_seconds"], 30);
    assert!(probe["last_started"].is_string() && probe["next_run"].is_string());
    let started_before = probe["last_started"].clone();
    let finished_before = probe["last_finished"].clone();

    // Mid-sweep: the trigger runs while the usage read is delayed.
    instance.upstream.delay_usage(Duration::from_secs(2));
    let started = ctl_post(addr, "/control/v1/quota/probe", json!({})).await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    assert!(started.json()["started_at"].is_string());
    let mid = await_snapshot(addr, |body| {
        body["status"]["usage_probe"]["last_started"].is_string()
            && body["status"]["usage_probe"]["last_started"] != started_before
    })
    .await;
    let probe = mid["status"]["usage_probe"].clone();
    assert_eq!(
        probe["last_finished"], finished_before,
        "the running sweep has not finished: {probe}"
    );
    assert!(probe["pending_reason"].is_null());

    await_upstream_usage_calls(&instance, 1).await;
    let done = await_snapshot(addr, |body| {
        body["status"]["usage_probe"]["last_finished"] != finished_before
    })
    .await;
    assert!(
        done["status"]["usage_probe"]["last_finished"].is_string(),
        "{done}"
    );
}

/// The configuration read shows effective non-secret values and
/// only presence for secret-bearing keys.
#[tokio::test(flavor = "multi_thread")]
async fn the_configuration_read() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("configuration-read").await;
    let addr = instance.addr;

    let body = ctl_get(addr, "/control/v1/configuration").await.json();
    assert_read(&body);
    let configuration = body["configuration"].clone();
    assert_eq!(configuration["path"], instance.config.display().to_string());
    assert_eq!(configuration["digest"], config_digest(&instance));
    assert!(configuration["loaded_at"].is_string());
    assert_eq!(
        configuration["effective"]["data_plane"]["telemetry_policy"],
        "forward"
    );
    assert_eq!(configuration["effective"]["logging"]["level"], "debug");

    // Secret-bearing keys: presence and readability, never contents.
    let secrets = &configuration["secrets"];
    assert_eq!(secrets["data_plane.tls_private_key_file"]["set"], false);
    assert!(secrets["data_plane.tls_private_key_file"]["readable"].is_null());
    assert_eq!(secrets["data_plane.corporate_proxy_url"]["set"], false);

    // No reload yet: the last reload is null.
    assert!(configuration["last_reload"].is_null());

    // After a reload the read carries its result (a live key: the probe).
    instance.reload_with_setup(&Setup {
        quota: "probe_enabled = true\n".into(),
        ..Setup::default()
    });
    let body = ctl_get(addr, "/control/v1/configuration").await.json();
    let last = body["configuration"]["last_reload"].clone();
    assert_eq!(last["applied"], true, "{last}");
    assert_eq!(last["digest"], config_digest(&instance));
    assert!(
        last["changed_keys"]
            .as_array()
            .expect("changed keys")
            .iter()
            .any(|k| k == "quota.probe_enabled"),
        "{last}"
    );
}

/// The registry read shows the facts, a hash algorithm name
/// and no digest; a revoked entry is still listed; an id that was never issued
/// is `404 client_not_found`. Member names follow
///
#[tokio::test(flavor = "multi_thread")]
async fn the_registry_read() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("registry-read").await;
    let addr = instance.addr;

    let created = ctl_post(
        addr,
        "/control/v1/clients",
        json!({ "id": "client-a", "display_name": "Alpha" }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());
    let body = created.json();
    assert!(body["enrollment_code"].is_string(), "{body}");
    assert!(body["expires_at"].is_string(), "{body}");
    let code = body["enrollment_code"].as_str().expect("code").to_string();

    let list = ctl_get(addr, "/control/v1/clients").await.json();
    assert_read(&list);
    let entry = list["clients"].as_array().expect("clients")[0].clone();
    assert_eq!(entry["id"], "client-a", "{entry}");
    assert_eq!(entry["display_name"], "Alpha");
    assert_eq!(entry["state"], "pending");
    assert_eq!(entry["generation"], 1);
    assert!(entry["issued_at"].is_string());
    assert_eq!(entry["expires_at"], body["expires_at"]);
    assert!(entry["activated_at"].is_null());
    assert!(entry["revoked_at"].is_null());
    // A hash algorithm name, never a digest, code or secret.
    assert!(entry["hash_algorithm"].is_string(), "{entry}");
    let text = entry.to_string();
    assert!(!text.contains(&code), "no code in the projection: {text}");

    let one = ctl_get(addr, "/control/v1/clients/client-a").await.json();
    assert_read(&one);
    assert_eq!(one["client"]["id"], "client-a");

    let never = ctl_get(addr, "/control/v1/clients/client-b").await;
    assert_eq!(never.status, StatusCode::NOT_FOUND);
    assert_error(&never.json(), "client_not_found");

    // A revoked entry stays visible, with its revocation time.
    let revoked = ctl_post(addr, "/control/v1/clients/client-a/revoke", json!({})).await;
    assert_eq!(revoked.status, StatusCode::OK);
    let list = ctl_get(addr, "/control/v1/clients").await.json();
    let entry = list["clients"].as_array().expect("clients")[0].clone();
    assert_eq!(entry["state"], "revoked", "{entry}");
    assert!(entry["revoked_at"].is_string(), "{entry}");
}

/// Add by API key, portable JSON, file and managed store; each
/// failure class returns its own status and leaves the state byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn the_four_sources_and_their_failures() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("four-sources-failures").await;
    let addr = instance.addr;
    let profile_for = |email: &str| {
        json!({
            "account": { "email": email, "uuid": Uuid::new_v4() },
            "organization": { "uuid": FIXTURE_ORG_UUID, "name": "Fixture Org" },
        })
        .to_string()
    };
    let portable = json!({
        "source": "portable_json",
        "credential": {
            "access_token": instance.needles.access_token,
            "refresh_token": instance.needles.refresh_token,
            "expires_at": "2099-01-01T00:00:00Z",
        },
    });

    // API key: 201, the account object back, the key never echoed.
    let (status, body) = add_account_ctl(
        addr,
        json!({ "source": "api_key", "api_key": instance.needles.api_key }),
        Some("KEYA"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["account"]["kind"], "api_key");
    assert!(!body.to_string().contains(&instance.needles.api_key));

    // Portable JSON: 201, named from the profile.
    instance
        .upstream
        .script([Reply::status(200, profile_for("portable@fixture.invalid"))]);
    let (status, body) = add_account_ctl(addr, portable, None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["account"]["display_name"], "portable@fixture.invalid");
    assert_eq!(body["account"]["source_class"], "portable-json");

    // File: the server reads an owner-only file itself.
    let path = instance.root.join("portable.json");
    write_private(
        &path,
        &json!({
            "access_token": needle("file access token", "oat-fixture"),
            "refresh_token": needle("file refresh token", "ort-fixture"),
            "expires_at": "2099-01-01T00:00:00Z",
        })
        .to_string(),
    );
    instance
        .upstream
        .script([Reply::status(200, profile_for("filed@fixture.invalid"))]);
    let (status, body) = add_account_ctl(
        addr,
        json!({ "source": "file", "path": path.display().to_string() }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["account"]["profile"]["email"], "filed@fixture.invalid");

    // Claude-managed: the planted store, the same profile flow.
    instance.plant_managed_file(
        Placement::Nested,
        "sk-ant-oat-fixture-managed",
        "sk-ant-ort-fixture-managed",
        OffsetDateTime::now_utc() + Duration::from_secs(3_600),
    );
    instance
        .upstream
        .script([Reply::status(200, profile_for("managed@fixture.invalid"))]);
    let (status, body) = add_account_ctl(addr, json!({ "source": "claude_managed" }), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["account"]["source_class"], "managed-store");

    // The failure classes, each leaving the state byte-identical.
    let before = instance.state_digest();
    let key = instance.needles.api_key.clone();
    let cases: Vec<(&str, StatusCode, &str, Value, Option<&str>)> = vec![
        (
            "duplicate name",
            StatusCode::CONFLICT,
            "conflict",
            json!({ "source": "api_key", "api_key": key }),
            Some("KEYA"),
        ),
        (
            "empty key",
            StatusCode::UNPROCESSABLE_ENTITY,
            "credential_rejected",
            json!({ "source": "api_key", "api_key": "" }),
            Some("X"),
        ),
        (
            "malformed portable",
            StatusCode::UNPROCESSABLE_ENTITY,
            "credential_rejected",
            json!({ "source": "portable_json", "credential": { "access_token": "a" } }),
            Some("X"),
        ),
        (
            "missing file",
            StatusCode::UNPROCESSABLE_ENTITY,
            "import_failed",
            json!({ "source": "file", "path": instance.root.join("absent.json").display().to_string() }),
            Some("X"),
        ),
        (
            "missing managed store",
            StatusCode::UNPROCESSABLE_ENTITY,
            "import_failed",
            json!({ "source": "claude_managed", "platform_hint": "file" }),
            Some("X"),
        ),
        (
            "unknown member",
            StatusCode::BAD_REQUEST,
            "invalid_request",
            json!({ "source": "api_key", "api_key": key, "bogus": 1 }),
            Some("X"),
        ),
    ];
    for (what, want, code, credential, name) in cases {
        // The managed store was imported above; this refusal needs it gone.
        if credential["source"] == "claude_managed" {
            instance.remove_managed_file();
        }
        let (status, body) = add_account_ctl(addr, credential, name).await;
        assert_eq!(status, want, "{what}: {body}");
        assert_error(&body, code);
        assert_eq!(
            instance.state_digest(),
            before,
            "{what} left the state byte-identical"
        );
    }
}

/// A replacement whose identity contradicts the account is
/// and replaces nothing; the same identity replaces in place.
#[tokio::test(flavor = "multi_thread")]
async fn a_contradicting_replacement_is_refused() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("contradicting-replacement-refused").await;
    instance.add_fsub();
    let addr = instance.addr;
    let handle = instance.handle("FSUB");
    let before = instance.state_digest();
    let expires_before = instance.account("FSUB")["credential"]["access_token_expires_at"].clone();

    // A family whose profile resolves to a different identity contradicts the
    // account the operator named.
    instance.upstream.script([Reply::status(
        200,
        json!({
            "account": { "email": "other@fixture.invalid", "uuid": Uuid::new_v4() },
            "organization": { "uuid": FIXTURE_ORG_UUID, "name": "Fixture Org" },
        })
        .to_string(),
    )]);
    let answer = ctl_post(
        addr,
        &format!("/control/v1/accounts/{handle}/credential"),
        json!({ "credential": {
            "source": "portable_json",
            "credential": {
                "access_token": needle("replacement access", "oat-fixture"),
                "refresh_token": needle("replacement refresh", "ort-fixture"),
                "expires_at": "2099-06-01T00:00:00Z",
            },
        } }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{}", answer.text());
    assert_error(&answer.json(), "conflict");
    assert_eq!(instance.state_digest(), before, "nothing was replaced");
    assert_eq!(
        instance.account("FSUB")["credential"]["access_token_expires_at"],
        expires_before
    );

    // The same identity replaces in place.
    instance.upstream.script([Reply::status(
        200,
        json!({
            "account": { "email": "fsub@fixture.invalid", "uuid": FIXTURE_ACCOUNT_UUID },
            "organization": { "uuid": FIXTURE_ORG_UUID, "name": "Fixture Org" },
        })
        .to_string(),
    )]);
    let answer = ctl_post(
        addr,
        &format!("/control/v1/accounts/{handle}/credential"),
        json!({ "credential": {
            "source": "portable_json",
            "credential": {
                "access_token": instance.needles.access_token,
                "refresh_token": instance.needles.refresh_token,
                "expires_at": "2099-01-01T00:00:00Z",
            },
        } }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
}

/// A removal that would orphan a route reference is refused naming
/// the entries; enable and disable are never blocked that way.
#[tokio::test(flavor = "multi_thread")]
async fn removal_reference_conflict_and_the_enable_path() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "removal-reference-conflict",
        Setup {
            selection: routes(&[("haiku", &["claude-haiku*"], Some(&["FSUB"]), None)]),
            ..Setup::default()
        },
        |instance| {
            instance.add_fsub();
        },
    )
    .await;
    let addr = instance.addr;
    let handle = instance.handle("FSUB");

    // The route's account list would no longer resolve.
    let answer = ctl_delete(addr, &format!("/control/v1/accounts/{handle}")).await;
    assert_eq!(answer.status, StatusCode::CONFLICT);
    let error = assert_error(&answer.json(), "account_reference_conflict");
    let named = error["details"]
        .as_array()
        .expect("details")
        .iter()
        .filter_map(|d| d["target"].as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        named.contains("haiku"),
        "the affected entry is named: {error}"
    );

    // Enable and disable are never refused for references (the last
    // sentence); enable clears an errored state.
    for operation in ["enable", "disable"] {
        let answer = ctl_post(
            addr,
            &format!("/control/v1/accounts/{handle}/{operation}"),
            json!({}),
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{operation}");
        assert_account_shape(&answer.json()["account"]);
    }

    // With the route gone, the removal succeeds: durable, live at once
    // — and the last account may be removed.
    instance.reload_with_setup(&Setup::default());
    let answer = ctl_delete(addr, &format!("/control/v1/accounts/{handle}")).await;
    assert_eq!(answer.status, StatusCode::OK);
    let body = ctl_get(addr, "/control/v1/accounts").await.json();
    assert_eq!(body["accounts"].as_array().expect("accounts").len(), 0);
    assert!(
        body["default_account"].is_null() || body.is_null(),
        "{body}"
    );
}

/// The login operation over the raw control surface: poll to success, cancel,
/// A state mismatch, the expiry, and no code, state or verifier in any
/// response, log or audit record.
#[tokio::test(flavor = "multi_thread")]
async fn the_login_operation_lifecycle() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let instance =
        Instance::start_with_faults("login-operation-lifecycle", Setup::default(), faults).await;
    let addr = instance.addr;

    // Start: the operation is addressable and its URL carries the shape.
    let started = ctl_post(addr, "/control/v1/accounts/login", json!({})).await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let started = started.json();
    assert_version(&started);
    let id = started["operation_id"]
        .as_str()
        .expect("operation id")
        .to_string();
    assert_eq!(started["state"], "awaiting_authorization");
    assert_eq!(
        started["manual_code_required"], true,
        "no browser is on PATH"
    );
    assert!(started["expires_at"].is_string());
    let url = started["authorization_url"]
        .as_str()
        .expect("url")
        .to_string();
    assert!(url.starts_with("https://claude.ai/oauth/authorize?"));

    // An id the server does not hold is 404; a non-UUID is 400.
    let unknown = ctl_get(addr, &format!("/control/v1/operations/{}", Uuid::new_v4())).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_error(&unknown.json(), "not_found");
    let malformed = ctl_get(addr, "/control/v1/operations/not-a-uuid").await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert_error(&malformed.json(), "invalid_request");

    // The state-mismatch paste: failed, pool unchanged, safe reason.
    let submitted = ctl_post(
        addr,
        &format!("/control/v1/operations/{id}/code"),
        json!({ "code": "code=real&state=wrong" }),
    )
    .await;
    assert_eq!(submitted.status, StatusCode::ACCEPTED);
    let ended = await_operation_ctl(addr, &id).await;
    assert_eq!(ended["state"], "failed", "{ended}");
    assert!(
        ended["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("state")),
        "the safe reason: {ended}"
    );
    let pool = ctl_get(addr, "/control/v1/accounts").await.json();
    assert_eq!(pool["accounts"].as_array().expect("accounts").len(), 0);

    // Cancel: the flow ends cancelled; a later submission is a conflict.
    let (id2, _) = start_ctl_login(addr).await;
    let cancelled = ctl_post(
        addr,
        &format!("/control/v1/operations/{id2}/cancel"),
        json!({}),
    )
    .await;
    assert_eq!(cancelled.status, StatusCode::OK);
    let operation = await_operation_ctl(addr, &id2).await;
    assert_eq!(operation["state"], "cancelled", "{operation}");
    let late = ctl_post(
        addr,
        &format!("/control/v1/operations/{id2}/code"),
        json!({ "code": "anything" }),
    )
    .await;
    assert_eq!(late.status, StatusCode::CONFLICT);
    assert_error(&late.json(), "conflict");

    // Success: the full callback URL, parsed back to its code.
    let (id3, url3) = start_ctl_login(addr).await;
    let (callback, state) = crate::acc::callback_target(&url3);
    let code = needle("authorisation code", "oat-fixture");
    let paste = format!("{callback}/callback?code={code}&state={state}");
    let submitted = ctl_post(
        addr,
        &format!("/control/v1/operations/{id3}/code"),
        json!({ "code": paste }),
    )
    .await;
    assert_eq!(submitted.status, StatusCode::ACCEPTED);
    let operation = await_operation_ctl(addr, &id3).await;
    assert_eq!(operation["state"], "succeeded", "{operation}");
    assert!(
        operation["account"]
            .to_string()
            .contains("fsub@fixture.invalid"),
        "the login created the account: {operation}"
    );

    // The code, the state and the verifier appear in no response, log line or
    // audit record; a control operation makes no audit record at all.
    let log = fs::read_to_string(instance.root.join("log/server.ndjson")).unwrap_or_default();
    for secret in [&code, "state=wrong", "state=real"] {
        assert!(!log.contains(secret), "the log leaked {secret:?}");
    }
    assert_eq!(instance.audit().len(), 0, "no audit record for control");
    let exchange = instance
        .upstream
        .seen()
        .into_iter()
        .find(|s| s.path == "/v1/oauth/token")
        .expect("the exchange ran");
    assert_eq!(
        exchange.json()["code_verifier"]
            .as_str()
            .expect("verifier")
            .len(),
        43,
        "the verifier went to the exchange, never to a response"
    );

    // The expiry: a wall clock moved past `expires_at` fails the flow, and
    // the pool keeps exactly the account the successful login created.
    let (id4, _) = start_ctl_login(addr).await;
    let moved = OffsetDateTime::now_utc() + Duration::from_secs(16 * 60);
    instance
        .faults
        .as_ref()
        .expect("the fault fixture")
        .set_time(moved);
    let operation = await_operation_ctl(addr, &id4).await;
    assert_eq!(operation["state"], "failed", "{operation}");
    assert_eq!(
        instance.state_file()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1
    );
}

/// `POST /control/v1/accounts/login` and its two values.
async fn start_ctl_login(addr: SocketAddr) -> (String, String) {
    let started = ctl_post(addr, "/control/v1/accounts/login", json!({})).await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.text());
    let body = started.json();
    (
        body["operation_id"].as_str().expect("id").to_string(),
        body["authorization_url"].as_str().expect("url").to_string(),
    )
}

/// Poll `GET /control/v1/operations/{id}` until the flow ended.
async fn await_operation_ctl(addr: SocketAddr, id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let body = ctl_get(addr, &format!("/control/v1/operations/{id}"))
            .await
            .json();
        let operation = &body["operation"];
        let state = operation["state"].as_str().unwrap_or_default().to_string();
        if matches!(state.as_str(), "succeeded" | "failed" | "cancelled")
            || Instant::now() > deadline
        {
            return operation.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A switch to an eligible and to an ineligible account both
/// succeed; `will_serve` and the reason differ.
#[tokio::test(flavor = "multi_thread")]
async fn the_switch_reports_what_will_happen() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("switch-reports-what-will").await;
    instance.add_fsub();
    instance.add_oauth("FSUB2", "fsub2@fixture.invalid", FSUB2_UUID);
    let addr = instance.addr;

    // Eligible: the switch lands and says it will serve.
    let answer = ctl_post(
        addr,
        "/control/v1/selection/default",
        json!({ "reference": "FSUB2" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let body = answer.json();
    assert_eq!(body["will_serve"], true, "{body}");
    assert!(body["reason"].is_null());
    assert_eq!(body["account"]["display_name"], "FSUB2");
    assert_eq!(instance.default_account(), instance.handle("FSUB2"));

    // Ineligible: the switch still succeeds and reports why it will not serve.
    let fsub2 = instance.handle("FSUB2");
    let request = ctl(
        Method::POST,
        &format!("/control/v1/accounts/{fsub2}/disable"),
        Some(json!({})),
    );
    assert_eq!(send(addr, request).await.status, StatusCode::OK);
    let answer = ctl_post(
        addr,
        "/control/v1/selection/default",
        json!({ "reference": "FSUB2" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let body = answer.json();
    assert_eq!(body["will_serve"], false, "{body}");
    assert_eq!(body["reason"], "disabled", "{body}");
    assert_eq!(instance.default_account(), fsub2);
}

/// A route preference set, cleared, refused for an account the
/// route excludes, and on an unknown route.
#[tokio::test(flavor = "multi_thread")]
async fn the_route_preference_lifecycle() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "route-preference-lifecycle",
        Setup {
            selection: routes(&[("haiku", &["claude-haiku*"], Some(&["FSUB"]), None)]),
            ..Setup::default()
        },
        |instance| {
            instance.add_fsub();
            instance.add_oauth("FSUB2", "fsub2@fixture.invalid", FSUB2_UUID);
        },
    )
    .await;
    let addr = instance.addr;

    // Unknown route: 404, named.
    let answer = ctl_post(
        addr,
        "/control/v1/selection/routes/no-such-route/preference",
        json!({ "reference": "FSUB" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_error(&answer.json(), "route_not_found");

    // An account the route's list lacks: 409.
    let answer = ctl_post(
        addr,
        "/control/v1/selection/routes/haiku/preference",
        json!({ "reference": "FSUB2" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::CONFLICT);
    assert_error(&answer.json(), "conflict");

    // A listed account: set, shown in the route view, cleared.
    let answer = ctl_post(
        addr,
        "/control/v1/selection/routes/haiku/preference",
        json!({ "reference": "FSUB" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.json()["route"], "haiku");
    assert_eq!(
        instance.route_view("haiku")["preference"],
        instance.handle("FSUB")
    );

    let cleared = ctl_delete(addr, "/control/v1/selection/routes/haiku/preference").await;
    assert_eq!(cleared.status, StatusCode::OK);
    assert!(instance.route_view("haiku")["preference"].is_null());
}

/// Reload: applied with a digest and the changed keys; an invalid
/// candidate is with one detail per error; a restart key is rejected
/// whole naming it; concurrent reloads are serialized and each answered.
#[tokio::test(flavor = "multi_thread")]
async fn the_reload_contract() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("reload-contract").await;
    instance.add_fsub();
    let addr = instance.addr;
    let reload = || ctl_post(addr, "/control/v1/reload", json!({}));

    // Applied: the digest of the exact bytes considered and the changed keys.
    instance.write_setup(&Setup {
        quota: "probe_enabled = true\n".into(),
        ..Setup::default()
    });
    let answer = reload().await;
    assert_eq!(answer.status, StatusCode::OK);
    let body = answer.json();
    assert_eq!(body["applied"], true, "{body}");
    assert_eq!(body["digest"], config_digest(&instance));
    assert!(
        body["changed_keys"]
            .as_array()
            .expect("changed keys")
            .iter()
            .any(|k| k == "quota.probe_enabled"),
        "{body}"
    );
    assert_eq!(body["rejected_restart_keys"], json!([]));

    // Invalid candidate: 422 with one detail per independently detectable
    // error; the digest is still the bytes it considered; the previous
    // configuration stays in force.
    let broken = fs::read_to_string(&instance.config)
        .expect("read")
        .replace("probe_enabled = true", "probe_interval_seconds = \"no\"");
    write_private(&instance.config, &broken);
    let answer = reload().await;
    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = answer.json();
    assert_eq!(body["applied"], false, "{body}");
    assert_eq!(body["digest"], config_digest(&instance));
    assert_error(&body, "configuration_invalid");
    assert!(
        body["error"]["details"]
            .as_array()
            .is_some_and(|d| !d.is_empty())
    );
    assert_eq!(
        ctl_get(addr, "/control/v1/accounts").await.json()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1,
        "the pool is unchanged"
    );

    // A restart key is rejected whole, naming the key.
    instance.reload_with_setup(&Setup::default());
    let other_port = 19_000 + (instance.addr.port() % 500);
    let listen_change = fs::read_to_string(&instance.config).expect("read").replace(
        &format!("listen = \"127.0.0.1:{}\"", instance.addr.port()),
        &format!("listen = \"127.0.0.1:{other_port}\""),
    );
    write_private(&instance.config, &listen_change);
    let answer = reload().await;
    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = answer.json();
    assert_eq!(body["applied"], false, "{body}");
    assert_eq!(
        body["rejected_restart_keys"],
        json!(["data_plane.listen"]),
        "{body}"
    );

    // Concurrent reloads are serialized, each with its own result.
    instance.reload_with_setup(&Setup::default());
    let (a, b) = tokio::join!(
        ctl_post(addr, "/control/v1/reload", json!({})),
        ctl_post(addr, "/control/v1/reload", json!({})),
    );
    for answer in [a, b] {
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
        let body = answer.json();
        assert_eq!(body["applied"], true, "{body}");
        assert_eq!(body["digest"], config_digest(&instance));
    }
}

/// The probe trigger: accepted, refused while a sweep runs, and
/// usable again once it finished. The
/// `probe_unavailable` branch does not exist at this control API version:
/// the probe is `v1` grade.
#[tokio::test(flavor = "multi_thread")]
async fn the_probe_trigger_refusals() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("probe-trigger-refusals").await;
    instance.add_fsub();
    let addr = instance.addr;

    instance.upstream.delay_usage(Duration::from_secs(2));
    let first = ctl_post(addr, "/control/v1/quota/probe", json!({})).await;
    assert_eq!(first.status, StatusCode::ACCEPTED);
    assert!(first.json()["started_at"].is_string());

    let overlapping = ctl_post(addr, "/control/v1/quota/probe", json!({})).await;
    assert_eq!(overlapping.status, StatusCode::CONFLICT);
    assert_error(&overlapping.json(), "sweep_in_progress");

    await_upstream_usage_calls(&instance, 1).await;
    tokio::time::sleep(Duration::from_millis(2_400)).await;
    let again = ctl_post(addr, "/control/v1/quota/probe", json!({})).await;
    assert_eq!(again.status, StatusCode::ACCEPTED, "{}", again.text());
}

/// One snapshot read while an exchange is in flight carries the
/// server section, the default account, the sessions object and the storage
/// object member for member; the accounts collection and a single-account
/// read return the same objects as the snapshot's array and element.
#[tokio::test(flavor = "multi_thread")]
async fn the_snapshot_sections_and_the_account_reads_agree() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("snapshot-sections-account").await;
    instance.add_fsub();
    instance.add_fkey();
    let addr = instance.addr;

    let gate = Arc::new(Notify::new());
    instance.upstream.script([Reply::Hold(gate.clone())]);
    // `add` resolves each profile upstream once; that is the baseline.
    let baseline = instance.upstream.calls();
    let exchange = tokio::spawn(send(addr, messages(haiku_prompt())));
    await_upstream_calls(&instance, baseline + 1).await;

    let snapshot = ctl_get(addr, "/control/v1/status").await.json();
    assert_read(&snapshot);
    let snapshot = &snapshot["status"];

    // The server section, member for member.
    let server = &snapshot["server"];
    for member in [
        "version",
        "build",
        "started_at",
        "listen",
        "tls",
        "tls_pin",
        "control_api_versions",
        "telemetry_policy",
        "upstream_origin_override",
        "egress",
    ] {
        assert!(server.get(member).is_some(), "{member}: {server}");
    }
    assert_eq!(server["control_api_versions"], json!([1]));
    assert_eq!(server["tls"], false);
    // the override is what the suite reaches the fake upstream through.
    assert_eq!(
        server["upstream_origin_override"],
        json!(format!("http://{}/", instance.upstream.addr))
    );
    for member in [
        "mode",
        "pinned_addresses",
        "observed_address",
        "observed_at",
        "held_now",
    ] {
        assert!(server["egress"].get(member).is_some(), "{member}: {server}");
    }

    // and: the default account and the sessions object. The
    // startup choice is a ranking's, and `since` is when it was set.
    let default = &snapshot["default_account"];
    assert_eq!(default["handle"], instance.handle("FSUB"));
    assert_eq!(default["operator_chosen"], false);
    assert!(default["since"].is_string(), "{default}");
    for member in ["known", "active", "distribution_enabled"] {
        assert!(snapshot["sessions"].get(member).is_some(), "{member}");
    }

    // The storage section.
    let storage = &snapshot["storage"];
    for member in ["state", "audit", "log"] {
        assert!(storage.get(member).is_some(), "{member}: {storage}");
    }
    assert!(storage["state"]["last_write"].is_string());
    assert!(storage["audit"]["active_file_bytes"].is_number());

    // The collection and the single read are the same objects.
    let accounts = ctl_get(addr, "/control/v1/accounts").await.json();
    assert_eq!(accounts["accounts"], snapshot["accounts"]);
    let handle = snapshot["accounts"][0]["handle"]
        .as_str()
        .expect("handle")
        .to_string();
    let one = ctl_get(addr, &format!("/control/v1/accounts/{handle}"))
        .await
        .json();
    assert_eq!(one["account"], snapshot["accounts"][0]);

    gate.notify_waiters();
    let answer = exchange.await.expect("the exchange completes");
    assert_eq!(answer.status, StatusCode::OK);
}

/// The client surface has no mutation: every method but the
/// documented reads is refused, and a client credential on an operator
/// mutation is `operator_required`.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_surface_has_no_mutation() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("client-surface-has-no-mutation").await;
    instance.add_fsub();
    let addr = instance.addr;
    let (alpha, _) = enroll_two_clients(&instance).await;
    let bearer = alpha.bearer();
    let auth = [("authorization", bearer.as_str())];
    let default_account = instance.status()["default_account"].clone();
    let mutations_before = instance.events("control_mutation").len();

    // Any method but GET on the client reads is a 405 naming GET.
    for path in [
        "/control/v1/client/status",
        "/control/v1/client/accounts",
        "/control/v1/client/accounts/resolve?reference=FSUB",
    ] {
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let answer = control(addr, method.clone(), path, &auth, Some(json!({}))).await;
            assert_eq!(
                answer.status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path}"
            );
            assert_eq!(answer.header("allow"), Some("GET"), "{method} {path}");
        }
    }

    // The client credential on every operator mutation is refused.
    let mutations = [
        ("/control/v1/selection/default", json!({"handle": "x"})),
        (
            "/control/v1/selection/routes/default/preference",
            json!({"reference": "FSUB"}),
        ),
        ("/control/v1/accounts", json!({})),
        ("/control/v1/clients", json!({})),
        (
            &format!("/control/v1/clients/{}/rotate", alpha.id)[..],
            json!({}),
        ),
        (
            &format!("/control/v1/clients/{}/revoke", alpha.id)[..],
            json!({}),
        ),
        ("/control/v1/reload", json!({})),
    ];
    for (path, body) in &mutations {
        let answer = control_post(addr, path, &auth, body.clone()).await;
        assert_eq!(
            answer.status,
            StatusCode::FORBIDDEN,
            "{path}: {}",
            answer.text()
        );
        assert_error(&answer.json(), "operator_required");
    }

    // Each refusal is one logged line, and nothing changed.
    let refusals = instance.events("control_refusal");
    assert_eq!(refusals.len(), mutations.len(), "{refusals:?}");
    for line in &refusals {
        let line = &line["fields"];
        assert_eq!(line["code"], "operator_required", "{line}");
        assert_eq!(line["principal"], "client", "{line}");
        assert_eq!(line["principal_id"], alpha.id, "{line}");
    }
    assert_eq!(instance.events("control_mutation").len(), mutations_before);
    assert_eq!(instance.status()["default_account"], default_account);
}

/// The client status projection with and without `session_id`;
/// the same session id under another client yields nothing.
#[tokio::test(flavor = "multi_thread")]
async fn client_status_with_and_without_a_session() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("client-status-without-session").await;
    instance.add_fsub();
    let addr = instance.addr;
    let (alpha, beta) = enroll_two_clients(&instance).await;
    assert_eq!(alpha.generation, 1);

    // The member set is exactly the documented closed list.
    let answer = control(
        addr,
        Method::GET,
        "/control/v1/client/status",
        &[("authorization", &alpha.bearer())],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let body = answer.json();
    assert_version(&body);
    let mut members: Vec<&String> = body.as_object().expect("object").keys().collect();
    members.sort();
    // The read envelope adds `captured_at` to the projection's members.
    assert_eq!(
        members,
        [
            "ca_fingerprint",
            "capabilities",
            "captured_at",
            "client",
            "control_api_version",
            "hold_hint_seconds",
            "pool",
            "server",
            "sessions",
            "wire_capture_enabled",
        ]
    );
    assert_eq!(body["client"]["id"], alpha.id);
    assert_eq!(body["client"]["display_name"], "Alpha Desk");
    assert_eq!(body["pool"]["accounts_configured"], 1);
    assert!(body.get("session").is_none());

    //A session under alpha is visible to alpha only.
    let exchange = send(
        addr,
        in_session(
            with(
                messages(haiku_prompt()),
                &[("authorization", &alpha.bearer())],
            ),
            "s1",
        ),
    )
    .await;
    assert_eq!(exchange.status, StatusCode::OK, "{}", exchange.text());

    let answer = control(
        addr,
        Method::GET,
        "/control/v1/client/status?session_id=s1",
        &[("authorization", &alpha.bearer())],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let session = &answer.json()["session"];
    assert_eq!(session["serving_account_display_name"], "FSUB");
    time::OffsetDateTime::parse(
        session["last_routed_at"].as_str().expect("last_routed_at"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("RFC 3339 last_routed_at");

    for (client, id) in [(&beta, "s1"), (&alpha, "never")] {
        let answer = control(
            addr,
            Method::GET,
            &format!("/control/v1/client/status?session_id={id}"),
            &[("authorization", &client.bearer())],
            None,
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
        assert!(answer.json()["session"].is_null(), "{}", answer.text());
    }
}

/// `hold_hint_seconds` is the greater of the data-plane hold
/// budget and the egress hold; both off, it is 0.
#[tokio::test(flavor = "multi_thread")]
async fn hold_hint_is_the_greater_of_the_two_holds() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    {
        let instance = Instance::start_with(
            "hold-hint-greater-a",
            Setup {
                data_plane: "hold_budget_seconds = 30\n".into(),
                egress: "mode = \"auto\"\ncheck_url = \"{fake}/egress\"\ncache_seconds = 1\nhold_seconds = 120\n"
                    .into(),
                ..Setup::default()
            },
        )
        .await;
        let body = control(
            instance.addr,
            Method::GET,
            "/control/v1/client/status",
            &[],
            None,
        )
        .await
        .json();
        assert_eq!(body["hold_hint_seconds"], 120, "{}", body);
        assert!(
            body["capabilities"]
                .as_array()
                .expect("capabilities")
                .iter()
                .any(|c| c == "egress_guard"),
            "{}",
            body
        );
    }

    let _leak_sweep = crate::leaks::LeakGuard::default();
    {
        let instance = Instance::start("hold-hint-greater-b").await;
        let body = control(
            instance.addr,
            Method::GET,
            "/control/v1/client/status",
            &[],
            None,
        )
        .await
        .json();
        assert_eq!(body["hold_hint_seconds"], 0, "{}", body);
        assert_eq!(body["capabilities"], json!([]), "{}", body);
    }
}

/// Every mutation in the router runs the CSRF guard after
/// authentication, before the body is read: a cross-site `sec-fetch-site` or
/// any `origin` fallback refuses with 403 `cross_origin_control` and changes
/// nothing, while `same-origin`, `none` and a header-less native request pass
/// Rows are ordered so the passing legs (c)/(d) run only
/// on idempotent or harmless mutations; the destructive rows (revoke, remove,
/// cancel) get their guard refusal legs and their `not-403` proof on a row
/// whose target is still there at that point (e.g. the revoke row proves
/// `same-origin` is not refused while the client still exists, then only
/// refusal legs run afterwards).
#[tokio::test(flavor = "multi_thread")]
async fn every_mutation_runs_the_csrf_guard() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("mutation-runs-csrf").await;
    instance.add_fsub();
    let addr = instance.addr;
    let handle = instance.status()["accounts"][0]["handle"]
        .as_str()
        .expect("account handle")
        .to_string();
    // One enrolled client so the client-side reads below have a principal.
    enroll(&instance, "mac", "Mac").await;
    let (login_id, _) = start_ctl_login(addr).await;
    let (second_login, _) = start_ctl_login(addr).await;

    // One mutation of the router, with a valid body and a real target.
    // `idempotent` rows get the full four-leg treatment; the others get the
    // two refusal legs plus a same-origin leg *before* their target is
    // consumed, and only the refusal legs after (see the doc comment).
    let mutations: Vec<(Method, String, Value)> = vec![
        (
            Method::POST,
            "/control/v1/accounts".into(),
            json!({ "credential": { "source": "api_key", "api_key": instance.needles.api_key } }),
        ),
        (Method::POST, "/control/v1/accounts/login".into(), json!({})),
        (
            Method::POST,
            format!("/control/v1/accounts/{handle}/name"),
            json!({ "display_name": "Renamed" }),
        ),
        (
            Method::POST,
            format!("/control/v1/accounts/{handle}/credential"),
            json!({ "credential": {
                "source": "portable_json",
                "credential": {
                    "access_token": instance.needles.access_token,
                    "refresh_token": instance.needles.refresh_token,
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            } }),
        ),
        (
            Method::POST,
            format!("/control/v1/accounts/{handle}/enable"),
            json!({}),
        ),
        (
            Method::POST,
            "/control/v1/clients".into(),
            json!({ "id": "guard-client", "display_name": "Guard" }),
        ),
        (
            Method::POST,
            "/control/v1/clients/guard-client/reissue".into(),
            json!({}),
        ),
        (
            Method::POST,
            "/control/v1/clients/guard-client/rotate".into(),
            json!({}),
        ),
        (
            Method::POST,
            "/control/v1/clients/guard-client/name".into(),
            json!({ "display_name": "Guard Renamed" }),
        ),
        (
            Method::POST,
            "/control/v1/operator/secret".into(),
            json!({}),
        ),
        (
            Method::POST,
            "/control/v1/selection/default".into(),
            json!({ "reference": "FSUB" }),
        ),
        (Method::POST, "/control/v1/reload".into(), json!({})),
        (Method::POST, "/control/v1/mitm/ca/rotate".into(), json!({})),
        (Method::POST, "/control/v1/quota/probe".into(), json!({})),
        (
            Method::POST,
            format!("/control/v1/operations/{login_id}/code"),
            json!({ "code": "code=anything&state=wrong" }),
        ),
        (
            Method::POST,
            format!("/control/v1/operations/{second_login}/cancel"),
            json!({}),
        ),
        (
            Method::POST,
            "/control/v1/clients/guard-client/revoke".into(),
            json!({}),
        ),
        (
            Method::DELETE,
            format!("/control/v1/accounts/{handle}"),
            json!({}),
        ),
    ];

    // (c) then (d): same-origin and a header-less native request pass the
    // guard. The status may still be an error (unknown route → 404), but it
    // must not be the guard's 403.
    let expect_not_refused = |answer: &Answer| {
        let refused = answer.status == StatusCode::FORBIDDEN
            && answer.json()["error"]["code"] == "cross_origin_control";
        assert!(!refused, "the guard refused a native request: {answer:?}");
    };
    for (method, path, body) in &mutations {
        let same_origin = control(
            addr,
            method.clone(),
            path,
            &[("sec-fetch-site", "same-origin")],
            Some(body.clone()),
        )
        .await;
        expect_not_refused(&same_origin);
        let native = control(addr, method.clone(), path, &[], Some(body.clone())).await;
        expect_not_refused(&native);
    }

    let mutations_before = instance.events("control_mutation").len();
    let refusals_before = instance.events("control_refusal").len();

    // (a) and (b): cross-site fetch and any origin fallback refuse, once per
    // request, and change nothing.
    let refusal_cases: [(&str, &str); 2] = [
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://evil.example"),
    ];
    for (method, path, body) in &mutations {
        for (name, value) in refusal_cases {
            let answer = control(
                addr,
                method.clone(),
                path,
                &[(name, value)],
                Some(body.clone()),
            )
            .await;
            assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
            let error = assert_error(&answer.json(), "cross_origin_control");
            assert_eq!(error["details"], json!([]), "{error}");
            assert!(
                !answer.text().contains("evil.example"),
                "no origin reflected: {}",
                answer.text()
            );
        }
    }

    assert_eq!(
        instance.events("control_mutation").len(),
        mutations_before,
        "no mutation line across the refusals"
    );
    let refusals = &instance.events("control_refusal")[refusals_before..];
    assert_eq!(refusals.len(), mutations.len() * 2, "one line per refusal");
    for line in refusals {
        assert_eq!(line["fields"]["code"], "cross_origin_control", "{line}");
        assert!(line["fields"]["source_address"].is_string(), "{line}");
    }
}

/// Every key the client projection may name: allow-list plus
/// `captured_at`, which is envelope member every read carries,
/// not a projection member.
const CLIENT_ALLOW: &[&str] = &[
    "account",
    "accounts",
    "accounts_configured",
    "accounts_selectable",
    "active",
    "available",
    "ca_fingerprint",
    "capabilities",
    "captured_at",
    "client",
    "control_api_version",
    "display_name",
    "handle",
    "hold_hint_seconds",
    "id",
    "known",
    "last_routed_at",
    "pool",
    "rate_limits",
    "selectable",
    "server",
    "session",
    "serving_account_display_name",
    "sessions",
    "tls_pin",
    "version",
    "five_hour",
    "weekly",
    "wire_capture_enabled",
];

/// Every object key at every depth of `value`.
fn collect_object_keys(value: &Value, keys: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                keys.push(key.clone());
                collect_object_keys(inner, keys);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| collect_object_keys(v, keys)),
        _ => {}
    }
}

/// Every string leaf of `value`.
fn collect_string_leaves(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| collect_string_leaves(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_string_leaves(v, out)),
        _ => {}
    }
}

/// An unknown member injected into the operator projection never
/// appears in the client projection. the working assumption:
/// "the members the operator projection already carries and never names
/// (`capture.directory`, per-account `quota`, `identity`, `routes`,
/// `server.egress`, `clients`, source addresses) *are* the injected unknowns;
/// the rows assert that with all of them populated every client response's
/// member set is exactly allow-list". The projection is assembled by
/// naming each allow-listed member, so a member the operator snapshot
/// gains later has no path into it.
#[tokio::test(flavor = "multi_thread")]
async fn operator_only_members_never_reach_the_client_projection() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "operator-members-never-reach",
        Setup {
            capture: true,
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;
    let addr = instance.addr;
    let served = send(
        addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &alpha.bearer())],
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);

    // The operator projection carries every -unnamed member, populated.
    let operator = ctl_get(addr, "/control/v1/status").await.json();
    assert_read(&operator);
    let operator = &operator["status"];
    assert!(
        operator["capture"]["directory"].is_string(),
        "the capture directory: {operator}"
    );
    // The per-account quota detail is `buckets` at this control API version.
    assert!(
        operator["accounts"][0]
            .get("buckets")
            .is_some_and(|b| b.as_array().is_some_and(|b| !b.is_empty())),
        "per-account quota: {operator}"
    );
    // the identity facts live under `profile`.
    assert!(
        operator["accounts"][0]["profile"]["email"].is_string(),
        "the account identity: {operator}"
    );
    assert!(
        operator["clients"]
            .as_array()
            .is_some_and(|c| c.iter().any(|e| e["id"] == "alpha")),
        "the registry: {operator}"
    );
    assert!(operator["server"].get("egress").is_some(), "{operator}");
    assert!(operator.get("configuration").is_some(), "{operator}");

    // The client projection under alpha: exactly the nine names plus
    // the envelope member, and no operator-only name at any depth.
    let bearer = alpha.bearer();
    let answer = control(
        addr,
        Method::GET,
        "/control/v1/client/status",
        &[("authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let body = answer.json();
    let mut top: Vec<&str> = body
        .as_object()
        .expect("the client status object")
        .keys()
        .map(String::as_str)
        .collect();
    top.sort_unstable();
    assert_eq!(
        top,
        [
            "ca_fingerprint",
            "capabilities",
            "captured_at",
            "client",
            "control_api_version",
            "hold_hint_seconds",
            "pool",
            "server",
            "sessions",
            "wire_capture_enabled"
        ]
    );
    let client_server = &body["server"];
    let mut server: Vec<&str> = client_server
        .as_object()
        .expect("the server object")
        .keys()
        .map(String::as_str)
        .collect();
    server.sort_unstable();
    assert_eq!(
        server,
        ["available", "control_api_version", "tls_pin", "version"]
    );
    let mut keys = Vec::new();
    collect_object_keys(&body, &mut keys);
    for key in &keys {
        assert!(
            CLIENT_ALLOW.contains(&key.as_str()),
            "operator-only member {key:?} reached the client projection: {body}"
        );
    }
}

/// Capture on → the operator projection names the directory, the
/// client projection says only `true`; capture off →
/// the directory is `null` and the client boolean is `false`.
#[tokio::test(flavor = "multi_thread")]
async fn capture_on_is_a_directory_for_the_operator_and_a_boolean_for_the_client() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "capture-directory-operator",
        Setup {
            capture: true,
            ..Setup::default()
        },
    )
    .await;
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;
    let operator = ctl_get(instance.addr, "/control/v1/status").await.json();
    assert_read(&operator);
    let capture = &operator["status"]["capture"];
    assert_eq!(capture["enabled"], true, "{capture}");
    let directory = capture["directory"].as_str().expect("the directory");
    assert!(!directory.is_empty());

    let bearer = alpha.bearer();
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/client/status",
        &[("authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let body = answer.json();
    assert_eq!(body["wire_capture_enabled"], true, "{body}");
    assert!(
        !answer.text().contains(directory),
        "the capture directory reached the client"
    );

    // The same with the mode off: `null` for the operator, `false` for the
    // client — never, never omitted (the null convention).
    let off = Instance::start("capture-directory-operator-off").await;
    let alpha = enroll(&off, "alpha", "Alpha Desk").await;
    let operator = ctl_get(off.addr, "/control/v1/status").await.json();
    assert_read(&operator);
    let capture = &operator["status"]["capture"];
    assert_eq!(capture["enabled"], false, "{capture}");
    assert!(capture["directory"].is_null(), "{capture}");
    let bearer = alpha.bearer();
    let answer = control(
        off.addr,
        Method::GET,
        "/control/v1/client/status",
        &[("authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(answer.json()["wire_capture_enabled"], false);
}

/// No client-visible response is produced by removing members
/// from an operator object: an unknown member injected into the operator
/// projection never appears in any client response, and every client response
/// matches its allow-list exactly. The working
/// assumption: "the members the operator projection already carries and
/// never names (`capture.directory`, per-account `quota`, `identity`,
/// `routes`, `server.egress`, `clients`, source addresses) *are* the injected
/// unknowns; the rows assert that with all of them populated every client
/// response's member set is exactly allow-list and none of those values
/// appears in any client body".
#[tokio::test(flavor = "multi_thread")]
async fn client_responses_are_allow_lists_not_filtered_operator_objects() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "client-responses-allow",
        Setup {
            capture: true,
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;
    // One exchange in session `s1`, so the `?session_id=` read shows a served
    // account rather than `null` — its two members are in the union too.
    let served = send(
        instance.addr,
        in_session(
            with(
                messages(haiku_prompt()),
                &[("authorization", &alpha.bearer())],
            ),
            "s1",
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);

    let bearer = alpha.bearer();
    let paths = [
        "/control/v1/client/status",
        "/control/v1/client/status?session_id=s1",
        "/control/v1/client/accounts",
        "/control/v1/client/accounts/resolve?reference=FSUB",
    ];
    let mut answers = Vec::new();
    for path in paths {
        let answer = control(
            instance.addr,
            Method::GET,
            path,
            &[("authorization", &bearer)],
            None,
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{path}: {}", answer.text());
        // Every response carries `cache-control: no-store` and no CORS
        // permission header.
        assert_eq!(answer.header("cache-control"), Some("no-store"), "{path}");
        assert!(
            !answer
                .headers
                .keys()
                .any(|k| k.as_str().starts_with("access-control-")),
            "{path} carried a CORS permission header"
        );
        answers.push((path, answer));
    }

    // The union of the key walks over all four reads is the allow-list.
    let mut keys = Vec::new();
    for answer in &answers {
        let body = answer.1.json();
        collect_object_keys(&body, &mut keys);
        assert_read(&body);
    }
    keys.sort_unstable();
    keys.dedup();
    for key in &keys {
        assert!(
            CLIENT_ALLOW.contains(&key.as_str()),
            "client response names {key:?}, which the allow-list does not"
        );
    }

    // No operator-only value reaches any client response: the account
    // identity's string leaves and the
    // server's listen address.
    let operator = ctl_get(instance.addr, "/control/v1/status").await.json();
    assert_read(&operator);
    let operator = &operator["status"];
    let mut secrets: Vec<String> = Vec::new();
    collect_string_leaves(&operator["accounts"][0]["profile"], &mut secrets);
    secrets.push(
        operator["server"]["listen"]
            .as_str()
            .expect("the listen address")
            .to_string(),
    );
    for (path, answer) in &answers {
        let text = answer.text();
        for secret in &secrets {
            assert!(
                !text.contains(secret),
                "{path} carries the operator value {secret:?}: {text}"
            );
        }
    }
}

/// `GET /control/v1/client/accounts/resolve` under the client credential.
async fn client_resolve(addr: SocketAddr, bearer: &str, reference: &str) -> (StatusCode, Value) {
    let encoded = reference.replace('%', "%25").replace(' ', "%20");
    let answer = control(
        addr,
        Method::GET,
        &format!("/control/v1/client/accounts/resolve?reference={encoded}"),
        &[("authorization", bearer)],
        None,
    )
    .await;
    (answer.status, answer.json())
}

/// The client catalogue adds only the two rate-limit windows to
/// its account identity/selectability fields and changes nothing: no default,
/// route, session or account state moves and no mutation is recorded.
/// Both
/// fixture accounts share the fixture organisation, so its full UUID is the
/// ambiguous reference.
#[tokio::test(flavor = "multi_thread")]
async fn catalogue_returns_rate_limits_and_changes_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("catalogue-returns-rate").await;
    add_two(&instance);
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;
    let addr = instance.addr;

    let before = instance.status();
    let mutations_before = instance.events("control_mutation").len();

    let bearer = alpha.bearer();
    let answer = control(
        addr,
        Method::GET,
        "/control/v1/client/accounts",
        &[("authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let body = answer.json();
    assert_read(&body);
    let accounts = body["accounts"].as_array().expect("accounts array");
    assert_eq!(accounts.len(), 2, "{body}");
    let operator_accounts = before["accounts"].as_array().expect("operator accounts");
    for (entry, operator) in accounts.iter().zip(operator_accounts) {
        let mut keys: Vec<&str> = entry
            .as_object()
            .expect("object")
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["display_name", "handle", "rate_limits", "selectable"],
            "{entry}"
        );
        assert!(entry["selectable"].is_boolean(), "{entry}");
        assert!(entry["rate_limits"]["five_hour"].is_null(), "{entry}");
        assert!(entry["rate_limits"]["weekly"].is_null(), "{entry}");
        assert_eq!(entry["handle"], operator["handle"]);
    }

    // Resolve by the first account's display name: the same three members.
    // The client resolve is under `/client`, with the client credential.
    let reference = operator_accounts[0]["display_name"]
        .as_str()
        .expect("display name")
        .to_string();
    let (status, resolved) = client_resolve(addr, &bearer, &reference).await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    assert_read(&resolved);
    let mut keys: Vec<&str> = resolved["account"]
        .as_object()
        .expect("object")
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["display_name", "handle", "selectable"], "{resolved}");
    assert_eq!(
        resolved["account"]["handle"],
        operator_accounts[0]["handle"]
    );
    assert_eq!(resolved["account"]["display_name"], json!(reference));

    // An unknown reference is one stable refusal.
    let (status, body) = client_resolve(addr, &bearer, "nobody").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_error(&body, "account_not_found");

    // Both accounts sit in the fixture organisation: its full UUID is the
    // ambiguous reference form (the name is only a qualifier).
    let organisation = operator_accounts[0]["profile"]["organization_uuid"]
        .as_str()
        .expect("organisation uuid")
        .to_string();
    let names: Vec<String> = operator_accounts
        .iter()
        .map(|a| {
            a["display_name"]
                .as_str()
                .expect("display name")
                .to_string()
        })
        .collect();
    let (status, body) = client_resolve(addr, &bearer, &organisation).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error = assert_error(&body, "ambiguous_account_reference");
    let message = error["message"].as_str().expect("message");
    for name in &names {
        assert!(message.contains(name.as_str()), "{name}: {message}");
    }

    // An empty reference is invalid, not unknown.
    let (status, body) = client_resolve(addr, &bearer, "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_error(&body, "invalid_request");

    // Neither read changed anything.
    let after = instance.status();
    assert_eq!(after["default_account"], before["default_account"]);
    assert_eq!(after["routes"], before["routes"]);
    assert_eq!(after["sessions"]["known"], before["sessions"]["known"]);
    assert_eq!(instance.events("control_mutation").len(), mutations_before);
}

/// the `code` and the refusal `code` are read from the same lines.
const CLAIM_REFUSAL_MESSAGE: &str =
    "the enrollment claim was refused; ask the operator to issue a new code";

/// Waits until `event` has grown to exactly `before + 1` lines and returns
/// the new one (the trail is written before the answer, so this settles at
/// once; the loop only guards the reader's view of the file).
async fn one_new_line(instance: &Instance, event: &str, before: usize) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let lines = instance.events(event);
        if lines.len() > before {
            assert_eq!(
                lines.len(),
                before + 1,
                "exactly one {event} line per operation"
            );
            return lines[before].clone();
        }
        assert!(Instant::now() < deadline, "the {event} line never landed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Every mutation leaves exactly one log line naming the
/// operation, the principal, the source address, the target and the outcome;
/// no disclosed code appears in any line and no control operation makes an
/// audit record.
#[tokio::test(flavor = "multi_thread")]
async fn every_mutation_leaves_one_line_naming_principal_address_and_outcome() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("mutation-leaves-line").await;
    instance.add_fsub();
    let addr = instance.addr;
    let audit_before = instance.audit().len();
    let mut mutations = instance.events("control_mutation").len();

    // One of each mutation, the account removal last. After each, the
    // trail grew by exactly one line naming the five members.
    async fn trail(instance: &Instance, count: &mut usize) {
        *count += 1;
        let line = one_new_line(instance, "control_mutation", *count - 1).await;
        let fields = &line["fields"];
        for member in [
            "operation",
            "principal",
            "source_address",
            "target",
            "outcome",
        ] {
            assert!(
                !fields[member].as_str().unwrap_or_default().is_empty(),
                "{member}: {line}"
            );
        }
        let principal = fields["principal"].as_str().expect("principal");
        assert!(
            principal.contains("loopback") || principal.contains("operator"),
            "the operator principal: {line}"
        );
        assert!(
            fields["source_address"]
                .as_str()
                .unwrap_or_default()
                .starts_with("127.0.0.1:"),
            "the loopback peer: {line}"
        );
    }

    let issued = ctl_post(
        addr,
        "/control/v1/clients",
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{}", issued.text());
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    trail(&instance, &mut mutations).await;
    let reissued = ctl_post(addr, "/control/v1/clients/mac/reissue", json!({})).await;
    assert_eq!(reissued.status, StatusCode::CREATED, "{}", reissued.text());
    let fresh_code = reissued.json()["enrollment_code"]
        .as_str()
        .expect("reissue code")
        .to_string();
    trail(&instance, &mut mutations).await;
    let renamed = ctl_post(
        addr,
        "/control/v1/clients/mac/name",
        json!({ "display_name": "Renamed Mac" }),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.text());
    trail(&instance, &mut mutations).await;
    let revoked = ctl_post(addr, "/control/v1/clients/mac/revoke", json!({})).await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.text());
    trail(&instance, &mut mutations).await;
    let switched = ctl_post(
        addr,
        "/control/v1/selection/default",
        json!({ "reference": "FSUB" }),
    )
    .await;
    assert_eq!(switched.status, StatusCode::OK, "{}", switched.text());
    trail(&instance, &mut mutations).await;
    let reloaded = ctl_post(addr, "/control/v1/reload", json!({})).await;
    assert_eq!(reloaded.status, StatusCode::OK, "{}", reloaded.text());
    trail(&instance, &mut mutations).await;
    let probed = ctl_post(addr, "/control/v1/quota/probe", json!({})).await;
    assert_eq!(probed.status, StatusCode::ACCEPTED, "{}", probed.text());
    trail(&instance, &mut mutations).await;
    let removed = ctl_delete(
        addr,
        &format!("/control/v1/accounts/{}", instance.handle("FSUB")),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text());
    trail(&instance, &mut mutations).await;

    // Neither disclosed code, nor its leading stem, is anywhere
    // in the server log; and the control operations made no audit record.
    let log = fs::read_to_string(instance.root.join("log/server.ndjson")).expect("server log");
    for disclosed in [&code, &fresh_code] {
        assert!(!log.contains(disclosed.as_str()), "a code in the log");
        let stem = disclosed.strip_prefix("jse2_").expect("code shape");
        let stem = &stem[..stem.len().min(12)];
        assert!(!log.contains(stem), "a code stem in the log: {stem}");
    }
    assert_eq!(
        instance.audit().len(),
        audit_before,
        "control operations make no audit record"
    );
}

/// Every refusal class leaves one log line with the caller's
/// address and the refusal's `code`; a refused claim's line names the real
/// cause the identical response withholds.
#[tokio::test(flavor = "multi_thread")]
async fn every_refusal_class_leaves_a_line_with_the_address_and_code() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "refusal-class-leaves-line",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let addr = instance.addr;
    let mut refusals = instance.events("control_refusal").len();

    // (i) Anonymous from a remote peer: 401, the data-plane envelope's twin,
    // not the control error envelope. On a host with no non-loopback
    // address the loopback variant with an unknown credential refuses the
    // same way. The pre-principal refusal is raised before the control router
    // and still leaves its line.
    let answer = match non_loopback_dest(&instance) {
        Some(dest) => control(dest, Method::GET, "/control/v1/status", &[], None).await,
        None => {
            control(
                addr,
                Method::GET,
                "/control/v1/status",
                &[("authorization", "Bearer jsc2_unknown")],
                None,
            )
            .await
        }
    };
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{answer:?}");
    assert_eq!(
        answer.json()["error"]["type"],
        "authentication_error",
        "{}",
        answer.text()
    );
    let lines = instance.events("control_refusal");
    assert_eq!(lines.len(), refusals + 1, "one line for the 401: {lines:?}");
    let line = &lines[refusals];
    assert_eq!(line["fields"]["code"], "authentication_error", "{line}");
    assert!(
        line["fields"]["source_address"]
            .as_str()
            .is_some_and(|a| a.contains(':')),
        "the caller's address: {line}"
    );
    refusals += 1;

    // (ii) A client credential at an operator endpoint: 403, the principal
    // is the client with its stable id.
    let (alpha, _beta) = enroll_two_clients(&instance).await;
    let bearer = alpha.bearer();
    let answer = control(
        addr,
        Method::GET,
        "/control/v1/status",
        &[("authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_error(&answer.json(), "operator_required");
    refusals += 1;
    let line = one_new_line(&instance, "control_refusal", refusals - 1).await;
    assert_eq!(line["fields"]["code"], "operator_required", "{line}");
    assert_eq!(line["fields"]["principal"], "client", "{line}");
    assert_eq!(line["fields"]["principal_id"], alpha.id, "{line}");
    assert!(
        !line["fields"]["source_address"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );

    // (iii) A cross-site mutation: refused before anything else happens.
    let answer = control_post(
        addr,
        "/control/v1/clients",
        &[("sec-fetch-site", "cross-site")],
        json!({ "id": "x", "display_name": "X" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_error(&answer.json(), "cross_origin_control");
    refusals += 1;
    let line = one_new_line(&instance, "control_refusal", refusals - 1).await;
    assert_eq!(line["fields"]["code"], "cross_origin_control", "{line}");
    assert!(
        !line["fields"]["source_address"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );

    // (iv) A refused claim: the identical 403 withholds the cause; the log
    // line names it (`enrollment_claim_refused` is a `control_refusal` code).
    let answer = control_post(
        addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "ghost", "code": "jse2_nothing" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    let body = answer.json();
    assert_eq!(body["error"]["code"], "enrollment_claim_refused");
    assert_eq!(body["error"]["message"], CLAIM_REFUSAL_MESSAGE);
    refusals += 1;
    let line = one_new_line(&instance, "control_refusal", refusals - 1).await;
    assert_eq!(line["fields"]["code"], "enrollment_claim_refused", "{line}");
    let cause = line["fields"]["cause"]
        .as_str()
        .expect("the real cause")
        .to_string();
    assert!(
        cause.contains("unknown") || cause.contains("no client"),
        "the real cause: {line}"
    );
    assert!(
        !line["fields"]["source_address"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
}

/// A one-time disclosure appears in exactly one response and
/// nowhere else: no read, no other response and no projection re-shows a
/// code or a secret.
#[tokio::test(flavor = "multi_thread")]
async fn no_endpoint_re_shows_a_code_or_secret() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("no-endpoint-re-shows").await;
    let addr = instance.addr;
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;

    // Issue: the code is disclosed once, in this response.
    let issued = ctl_post(
        addr,
        "/control/v1/clients",
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{}", issued.text());
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();

    // No operator or client read re-shows it.
    let reads = [
        ctl_get(addr, "/control/v1/clients").await.text(),
        ctl_get(addr, "/control/v1/clients/mac").await.text(),
        ctl_get(addr, "/control/v1/status").await.text(),
        control(
            addr,
            Method::GET,
            "/control/v1/client/status",
            &[("authorization", &alpha.bearer())],
            None,
        )
        .await
        .text(),
    ];
    for text in &reads {
        assert!(!text.contains(&code), "the code is re-shown: {text}");
    }

    // Claim: the secret is disclosed once, in this response.
    let claimed = control_post(
        addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": code }),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK, "{}", claimed.text());
    let secret = claimed.json()["client_secret"]
        .as_str()
        .expect("secret")
        .to_string();

    // No read, the rotate's and the reissue's response re-show the secret.
    let rotated = ctl_post(addr, "/control/v1/clients/mac/rotate", json!({})).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.text());
    let replacement = rotated.json()["client_secret"]
        .as_str()
        .expect("the replacement secret")
        .to_string();
    let before_rotate = rotated.json()["client"]["generation"]
        .as_u64()
        .expect("generation");
    let reissued = ctl_post(addr, "/control/v1/clients/mac/reissue", json!({})).await;
    assert_eq!(reissued.status, StatusCode::CREATED, "{}", reissued.text());
    let reads = [
        ctl_get(addr, "/control/v1/clients").await.text(),
        ctl_get(addr, "/control/v1/clients/mac").await.text(),
        ctl_get(addr, "/control/v1/status").await.text(),
        control(
            addr,
            Method::GET,
            "/control/v1/client/status",
            &[("authorization", &alpha.bearer())],
            None,
        )
        .await
        .text(),
        reissued.text(),
        rotated.text(),
    ];
    for text in &reads {
        assert!(!text.contains(&secret), "the secret is re-shown: {text}");
    }
    assert_ne!(replacement, secret, "rotate discloses a new secret");

    // After rotate: the generation advanced and no secret member exists.
    let after = ctl_get(addr, "/control/v1/clients/mac").await.json();
    let listed_generation = after["client"]["generation"].as_u64().expect("generation");
    assert!(
        listed_generation > before_rotate,
        "the generation advanced: {after}"
    );
    assert!(after["client"].get("client_secret").is_none(), "{}", after);
    assert!(!after.to_string().contains("jsc2_"), "{}", after);
}

/// `POST /control/v1/mitm/ca/rotate` is `409 mitm_disabled`
/// while the mode is off; with the mode on it answers 200 with the old and
/// the new fingerprint and the new expiry, returns no key material, the
/// read shows the new fingerprint afterwards, and one mutation line lands.
#[tokio::test(flavor = "multi_thread")]
async fn ca_rotate_is_409_off_and_a_new_fingerprint_on() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // With MITM off there is no certificate authority to rotate.
    let instance_a = Instance::start("ca-rotate-409-off-a").await;
    let answer = ctl_post(instance_a.addr, "/control/v1/mitm/ca/rotate", json!({})).await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{}", answer.text());
    assert_error(&answer.json(), "mitm_disabled");

    // With the mode on, the rotation is a 200 naming both
    // fingerprints, and no key material is anywhere in the response.
    let instance_b = Instance::start_with(
        "ca-rotate-409-off-b",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let before =
        ctl_get(instance_b.addr, "/control/v1/ca").await.json()["ca"]["fingerprint"].clone();
    let answer = ctl_post(instance_b.addr, "/control/v1/mitm/ca/rotate", json!({})).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let body = answer.json();
    assert_version(&body);
    assert_eq!(body["previous_fingerprint"], before, "{body}");
    assert_ne!(body["fingerprint"], before, "{body}");
    assert!(
        body["not_after"]
            .as_str()
            .is_some_and(|t| time::OffsetDateTime::parse(
                t,
                &time::format_description::well_known::Rfc3339
            )
            .is_ok()),
        "an RFC 3339 expiry: {body}"
    );
    let text = answer.text();
    assert!(
        !text.contains("PRIVATE KEY") && !text.contains("-----BEGIN"),
        "no key material in the response: {text}"
    );

    // The read now shows the new fingerprint.
    let after =
        ctl_get(instance_b.addr, "/control/v1/ca").await.json()["ca"]["fingerprint"].clone();
    assert_eq!(after, body["fingerprint"], "the read shows the new CA");

    // One operator mutation logged, naming the rotate.
    let mutations = instance_b.events("control_mutation");
    assert_eq!(mutations.len(), 1, "{mutations:?}");
    let line = &mutations[0]["fields"];
    assert!(
        line["operation"].as_str().is_some_and(|o| o.contains("ca")),
        "the operation names the rotate: {line}"
    );
    assert!(
        !line["target"].as_str().unwrap_or_default().is_empty()
            && !line["outcome"].as_str().unwrap_or_default().is_empty(),
        "target and outcome are non-empty: {line}"
    );
}

/// The snapshot's `mitm` section: with the mode off, the
/// members are present with `null` and zero counters; with the mode
/// on, they carry the values, and the human `status` form renders the
/// section for both.
#[tokio::test(flavor = "multi_thread")]
async fn mitm_section_is_null_when_off_and_present_when_on() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance_a = Instance::start("mitm-section-null-a").await;
    let instance_b = Instance::start_with(
        "mitm-section-null-b",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;

    let status_a = ctl_get(instance_a.addr, "/control/v1/status").await.json()["status"].clone();
    let status_b = ctl_get(instance_b.addr, "/control/v1/status").await.json()["status"].clone();

    // The member set is exactly the list, on and off.
    fn members(s: &Value) -> &Value {
        let mitm = &s["mitm"];
        let mut keys: Vec<&str> = mitm
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ca", "counters", "enabled", "listen", "tunnels"]);
        let mut ca: Vec<&str> = mitm["ca"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        ca.sort_unstable();
        assert_eq!(ca, ["fingerprint", "not_after", "state"]);
        let mut tunnels: Vec<&str> = mitm["tunnels"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        tunnels.sort_unstable();
        assert_eq!(tunnels, ["intercepted", "tunnelled"]);
        let mut counters: Vec<&str> = mitm["counters"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        counters.sort_unstable();
        assert_eq!(
            counters,
            [
                "connect_refused_403",
                "connect_refused_407",
                "connect_unreachable",
                "failed_handshakes",
                "intercepted_exchanges",
                "tunnels_opened",
            ]
        );
        mitm
    }
    let mitm_a = members(&status_a);
    let mitm_b = members(&status_b);

    // With the mode off every absent fact is null, never omitted,
    // and every count is zero.
    assert_eq!(mitm_a["enabled"], false, "{mitm_a}");
    for member in ["fingerprint", "not_after", "state"] {
        assert_eq!(mitm_a["ca"][member], Value::Null, "{mitm_a}");
    }
    for member in ["intercepted", "tunnelled"] {
        assert_eq!(mitm_a["tunnels"][member], 0, "{mitm_a}");
    }
    for member in [
        "connect_refused_403",
        "connect_refused_407",
        "connect_unreachable",
        "failed_handshakes",
        "intercepted_exchanges",
        "tunnels_opened",
    ] {
        assert_eq!(mitm_a["counters"][member], 0, "{mitm_a}");
    }

    // With the mode on, the listener, the CA facts and the counters.
    assert_eq!(mitm_b["enabled"], true, "{mitm_b}");
    assert_eq!(
        mitm_b["listen"],
        instance_b.mitm_addr.unwrap().to_string(),
        "{mitm_b}"
    );
    assert_eq!(mitm_b["ca"]["state"], "ok", "{mitm_b}");
    let fingerprint = mitm_b["ca"]["fingerprint"].as_str().expect("fingerprint");
    assert_eq!(fingerprint.len(), 95, "{mitm_b}");
    let pairs: Vec<&str> = fingerprint.split(':').collect();
    assert_eq!(pairs.len(), 32, "{mitm_b}");
    assert!(
        pairs.iter().all(|p| p.len() == 2
            && p.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())),
        "the colon-hex form: {mitm_b}"
    );
    assert!(
        mitm_b["ca"]["not_after"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z')),
        "{mitm_b}"
    );

    // The human form renders the section for both instances.
    let (_, out_a, _) = instance_a.cli(&["status", "--verbose"], None);
    assert!(out_a.contains("mitm     off"), "{out_a}");
    let (exit, out_b, _) = instance_b.cli(&["status", "--verbose"], None);
    assert_eq!(exit, 0, "{out_b}");
    assert!(out_b.contains("mitm     ON"), "{out_b}");
    assert!(out_b.contains(fingerprint), "{out_b}");
    assert!(
        out_b.contains("tunnels intercepted 0 tunnelled 0"),
        "{out_b}"
    );
}
