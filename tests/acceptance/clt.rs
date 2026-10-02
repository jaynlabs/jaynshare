//! Client principals and enrollment: issued secrets, enrollment codes,
//! bundles, and the client projection the control plane serves.

use crate::harness::*;

const CLAIM_REFUSAL_MESSAGE: &str =
    "the enrollment claim was refused; ask the operator to issue a new code";

/// One control request over TLS (a TLS-enabled instance's listener speaks no
/// plaintext, even on loopback); same shape as [`control`].
async fn control_tls(
    addr: SocketAddr,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Answer {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", addr.to_string());
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let request = request
        .body(Full::new(Bytes::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        )))
        .expect("control request builds");
    send_tls(addr, request, false).await
}

async fn control_post_tls(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> Answer {
    control_tls(addr, Method::POST, path, headers, Some(body)).await
}

/// The one `403 enrollment_claim_refused` envelope every failed claim returns,
/// byte-for-byte equal across causes.
fn expect_claim_refusal(answer: &Answer) {
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    let body = answer.json();
    assert_eq!(body["error"]["code"], "enrollment_claim_refused");
    assert_eq!(body["error"]["message"], CLAIM_REFUSAL_MESSAGE);
    assert_eq!(body["error"]["details"], json!([]));
    assert_eq!(body["control_api_version"], 1);
}

/// No registry and no credential from a remote peer → 401, never
/// an open listener or anonymous read.
#[tokio::test(flavor = "multi_thread")]
async fn no_remote_call_without_a_principal() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(_peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let instance = Instance::start_with(
        "no-remote-call-without-principal",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    // Every path an unauthenticated remote caller might probe reads nothing.
    for (method, path) in [
        (Method::GET, "/control/v1/status"),
        (Method::GET, "/control/v1/clients"),
        (Method::GET, "/control/v1/accounts"),
        (Method::GET, "/control/v1/nothing"),
        (Method::GET, "/v1/messages"),
    ] {
        let answer = control(remote, method, path, &[], None).await;
        assert_eq!(
            answer.status,
            StatusCode::UNAUTHORIZED,
            "{path}: {answer:?}"
        );
        let body = answer.json();
        assert_eq!(body["type"], "error", "{path}: the envelope");
    }
    // The fake upstream saw nothing: no path was forwarded.
    assert_eq!(instance.upstream.calls(), 0);
    // Loopback, still without a credential, is the operator.
    let local = control(instance.addr, Method::GET, "/control/v1/status", &[], None).await;
    assert_eq!(local.status, StatusCode::OK);
}

/// A client credential is authenticated, serves the data plane,
/// and every operator endpoint answers `403 operator_required`.
#[tokio::test(flavor = "multi_thread")]
async fn client_credential_is_isolated_from_operator_surface() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("client-credential-isolated").await;
    instance.add_fsub();
    let client = enroll(&instance, "mac", "Mac").await;
    // The client's credential serves the data plane.
    let served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &client.bearer())],
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);
    // Every operator read and mutation refuses with the same code.
    let operator_paths: [(Method, &str, Option<Value>); 9] = [
        (Method::GET, "/control/v1/status", None),
        (Method::GET, "/control/v1/accounts", None),
        (Method::GET, "/control/v1/configuration", None),
        (Method::GET, "/control/v1/clients", None),
        (
            Method::POST,
            "/control/v1/clients",
            Some(json!({ "id": "x2", "display_name": "X" })),
        ),
        (Method::POST, "/control/v1/reload", Some(json!({}))),
        (
            Method::POST,
            "/control/v1/selection/default",
            Some(json!({ "reference": "FSUB" })),
        ),
        (Method::POST, "/control/v1/operator/secret", Some(json!({}))),
        (Method::DELETE, "/control/v1/operator/secret", None),
    ];
    let bearer = client.bearer();
    for (method, path, body) in operator_paths {
        let headers: Vec<(&str, &str)> = vec![("authorization", &bearer)];
        let answer = control(instance.addr, method, path, &headers, body).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{path}: {answer:?}");
        assert_eq!(
            answer.json()["error"]["code"],
            "operator_required",
            "{path}"
        );
    }
}

/// The same session id under two clients is two sessions; a
/// display-name change never moves the stable id. The per-client
/// serving-account read is proven on the client surface (in the other
/// tests); the session identity it rests on is proven here.
#[tokio::test(flavor = "multi_thread")]
async fn session_identity_is_per_principal() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("session-identity-per").await;
    instance.add_fsub();
    let (alpha, beta) = enroll_two_clients(&instance).await;
    // The same session id under each principal.
    for client in [&alpha, &beta] {
        let bearer = client.bearer();
        let answer = send(
            instance.addr,
            in_session(
                with(messages(haiku_prompt()), &[("authorization", &bearer)]),
                "shared-session",
            ),
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK);
    }
    assert_eq!(
        instance.status()["sessions"]["known"],
        2,
        "two principals, two sessions"
    );
    assert_eq!(instance.status()["sessions"]["active"], 2);
    // A rename does not change the identity: the id stays, the sessions stay
    // the same principals'.
    let rename = control_post(
        instance.addr,
        "/control/v1/clients/alpha/name",
        &[],
        json!({ "display_name": "Renamed Desk" }),
    )
    .await;
    assert_eq!(rename.status, StatusCode::OK);
    assert_eq!(rename.json()["client"]["display_name"], "Renamed Desk");
    assert_eq!(rename.json()["client"]["id"], "alpha");
    let bearer = alpha.bearer();
    let answer = send(
        instance.addr,
        in_session(
            with(messages(haiku_prompt()), &[("authorization", &bearer)]),
            "shared-session",
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        instance.status()["sessions"]["known"],
        2,
        "the rename moved nothing"
    );
}

/// Forwarded loopback-looking headers from a remote peer do not
/// exempt it.
#[tokio::test(flavor = "multi_thread")]
async fn forwarded_headers_never_exempt_a_remote_peer() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(_peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let instance = Instance::start_with(
        "forwarded-headers-never-exempt",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    let headers = [
        ("x-forwarded-for", "127.0.0.1"),
        ("x-real-ip", "127.0.0.1"),
        ("forwarded", "for=127.0.0.1;by=127.0.0.1"),
    ];
    for (method, path) in [
        (Method::GET, "/control/v1/status"),
        (Method::GET, "/v1/messages"),
    ] {
        let answer = control(remote, method, path, &headers, None).await;
        assert_eq!(
            answer.status,
            StatusCode::UNAUTHORIZED,
            "{path}: {answer:?}"
        );
    }
}

/// Loopback with no credential → operator; a valid client
/// credential → client; a bad credential → 401; the bootstrap exception ends
/// at the first issue.
#[tokio::test(flavor = "multi_thread")]
async fn loopback_operator_and_the_bootstrap_exception() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("loopback-operator-bootstrap").await;
    // Bootstrap: while no entry and no operator secret exist, loopback is the
    // operator whatever it presents, and the server says so once.
    let garbage = "jsc2_garbage".to_string();
    let headers: Vec<(&str, &str)> = vec![("authorization", &garbage)];
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/status",
        &headers,
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "the bootstrap exception");
    assert_eq!(
        instance.events("bootstrap_authorisation").len(),
        1,
        "one startup line says the exception is in force"
    );
    // The first issue ends the exception for good.
    let client = enroll(&instance, "mac", "Mac").await;
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/status",
        &headers,
        None,
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::UNAUTHORIZED,
        "a mistyped credential is refused, never promoted"
    );
    assert_eq!(
        instance.events("bootstrap_authorisation").len(),
        1,
        "no new line"
    );
    instance.add_fsub();
    // A valid client credential resolves as the client (served data plane).
    let served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &client.bearer())],
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);
    // Loopback with no credential is still the operator.
    let answer = control(instance.addr, Method::GET, "/control/v1/status", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);
}

/// Duplicate/unsafe id and invalid display name refused; duplicate
/// display names accepted.
#[tokio::test(flavor = "multi_thread")]
async fn registry_id_and_name_rules() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("registry-id-name").await;
    async fn issue(instance: &Instance, id: &str, name: &str) -> Answer {
        control_post(
            instance.addr,
            "/control/v1/clients",
            &[],
            json!({ "id": id, "display_name": name }),
        )
        .await
    }
    let long = "a".repeat(64);
    for id in ["", "-lead", "Upper", long.as_str(), "sp ace", "é"] {
        let answer = issue(&instance, id, "Name").await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{id:?}");
        assert_eq!(
            answer.json()["error"]["code"],
            "invalid_client_id",
            "{id:?}"
        );
    }
    let long_name = "x".repeat(129);
    for name in ["", " ", "\u{7}bell", long_name.as_str()] {
        let answer = issue(&instance, "ok-id", name).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{name:?}");
        assert_eq!(
            answer.json()["error"]["code"],
            "invalid_display_name",
            "{name:?}"
        );
    }
    assert_eq!(
        issue(&instance, "desk", "First").await.status,
        StatusCode::CREATED
    );
    // Duplicate ids are refused, in any state; duplicate display names are not.
    let answer = issue(&instance, "desk", "Second").await;
    assert_eq!(answer.status, StatusCode::CONFLICT);
    assert_eq!(answer.json()["error"]["code"], "conflict");
    assert_eq!(
        issue(&instance, "desk2", "First").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        instance.status()["clients"]
            .as_array()
            .expect("clients array")
            .len(),
        2
    );
}

/// Issue → only the verifier persisted and the code shown once;
/// status pending with expiry.
#[tokio::test(flavor = "multi_thread")]
async fn issue_discloses_once_and_persists_the_verifier_only() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("issue-discloses-persists").await;
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let body = issued.json();
    let code = body["enrollment_code"]
        .as_str()
        .expect("the code once")
        .to_string();
    assert!(code.starts_with("jse2_"));
    assert!(body["expires_at"].is_string());
    assert_eq!(body["client"]["state"], "pending");

    // The durable form: exactly fields, the code's verifier and no
    // plaintext.
    let state = instance.state_file();
    let entry = &state["clients"][0];
    let keys: Vec<&str> = entry
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "id",
            "display_name",
            "state",
            "generation",
            "issued_at",
            "expires_at",
            "activated_at",
            "revoked_at",
            "verifier"
        ],
        "exactly the documented fields in documented order: {keys:?}"
    );
    assert_eq!(entry["state"], "pending");
    assert_eq!(entry["verifier"]["algorithm"], "sha256");
    assert_eq!(entry["verifier"]["domain"], "jaynshare/enrollment");

    // The code appears in no file the run wrote.
    let mut hits = Vec::new();
    sweep(&instance.root, &[], &[&code], &mut hits);
    assert!(hits.is_empty(), "the enrollment code leaked into {hits:?}");

    // The registry read shows the lifecycle facts and no digest.
    // The projection names the hash algorithm but is not a serde
    // projection of the verifier — there is no `verifier` member to find.
    let answer = control(instance.addr, Method::GET, "/control/v1/clients", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);
    let listed = answer.json()["clients"][0].clone();
    assert_eq!(listed["state"], "pending");
    assert_eq!(listed["hash_algorithm"], "sha256");
    assert!(listed.get("verifier").is_none(), "no verifier member");
    assert!(listed.get("digest").is_none(), "no digest");
    assert!(listed.get("client_secret").is_none());
}

/// The first claim returns a secret and activates; a concurrent
/// second claim loses atomically and returns no secret.
#[tokio::test(flavor = "multi_thread")]
async fn claim_is_atomic_and_one_time() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("claim-atomic-time").await;
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    // Two claims race; exactly one wins and the loser discloses nothing.
    let (first, second) = tokio::join!(
        control_post(
            instance.addr,
            "/control/v1/enrollment/claim",
            &[],
            json!({ "id": "mac", "code": code })
        ),
        control_post(
            instance.addr,
            "/control/v1/enrollment/claim",
            &[],
            json!({ "id": "mac", "code": code })
        ),
    );
    let (winner, loser) = if first.status == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(winner.status, StatusCode::OK, "{winner:?}");
    assert!(
        winner.json()["client_secret"]
            .as_str()
            .is_some_and(|s| s.starts_with("jsc2_"))
    );
    expect_claim_refusal(&loser);
    assert!(
        loser.json()["client_secret"].is_null(),
        "no secret in a refusal"
    );
    // A replay after the race is refused too.
    let replay = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": code }),
    )
    .await;
    expect_claim_refusal(&replay);
    assert_eq!(instance.state_file()["clients"][0]["state"], "active");
}

/// An expired code is refused; reissue invalidates the old code
/// and increments the generation.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn expired_code_and_reissue() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let instance = Instance::start_with_faults(
        "expired-code-reissue",
        Setup {
            clients: "enrollment_lifetime_seconds = 60".into(),
            ..Setup::default()
        },
        std::sync::Arc::clone(&faults),
    )
    .await;
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    // Past the 60 s lifetime the claim is refused with the one refusal.
    faults.set_deadline(std::time::Instant::now(), 61);
    let expired = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": code }),
    )
    .await;
    expect_claim_refusal(&expired);
    // Reissue: a new code, the next generation; the old code stays dead.
    let reissued = control_post(
        instance.addr,
        "/control/v1/clients/mac/reissue",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(reissued.status, StatusCode::CREATED, "{reissued:?}");
    let new_code = reissued.json()["enrollment_code"]
        .as_str()
        .expect("new code")
        .to_string();
    assert_ne!(code, new_code);
    assert_eq!(reissued.json()["client"]["generation"], 2);
    let old = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": code }),
    )
    .await;
    expect_claim_refusal(&old);
    let claimed = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": new_code }),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK, "{claimed:?}");
}

/// Rotate → the old secret fails on the next HTTP request and the
/// replacement succeeds under the same client id. The existing-tunnel
/// half extends the rotation test (no MITM yet).
#[tokio::test(flavor = "multi_thread")]
async fn rotate_kills_the_old_secret_on_the_next_request() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("rotate-kills-old").await;
    instance.add_fsub();
    let client = enroll(&instance, "mac", "Mac").await;
    let served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &client.bearer())],
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);
    let rotated = control_post(
        instance.addr,
        "/control/v1/clients/mac/rotate",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK, "{rotated:?}");
    let replacement = rotated.json()["client_secret"]
        .as_str()
        .expect("the new secret")
        .to_string();
    assert_eq!(rotated.json()["client"]["id"], "mac", "the id is retained");
    // The old secret fails on the very next request; the replacement serves.
    let old = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &client.bearer())],
        ),
    )
    .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED, "no grace period");
    // The data plane is the credential proof here; the client surface's own
    // rows are the other tests'.
    let renewed = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &format!("Bearer {replacement}"))],
        ),
    )
    .await;
    assert_eq!(renewed.status, StatusCode::OK);
}

/// Revoke pending and active generations → every code and secret
/// fails; the entries stay visible; re-enrol → only the new generation works.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_and_reenroll() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("revoke-reenroll").await;
    instance.add_fsub();
    let active = enroll(&instance, "active-one", "Active One").await;
    // A pending entry with an unclaimed code.
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "pending-one", "display_name": "Pending One" }),
    )
    .await;
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    // Revoke both.
    for id in ["active-one", "pending-one"] {
        let answer = control_post(
            instance.addr,
            &format!("/control/v1/clients/{id}/revoke"),
            &[],
            json!({}),
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{id}: {answer:?}");
    }
    // Every code and secret fails at once.
    let dead = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &active.bearer())],
        ),
    )
    .await;
    assert_eq!(dead.status, StatusCode::UNAUTHORIZED);
    let claim = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "pending-one", "code": code }),
    )
    .await;
    expect_claim_refusal(&claim);
    // The entries stay visible with their revocation time and no verifier.
    let answer = control(instance.addr, Method::GET, "/control/v1/clients", &[], None).await;
    let listed = answer.json()["clients"]
        .as_array()
        .expect("clients")
        .clone();
    assert_eq!(listed.len(), 2);
    for entry in &listed {
        assert_eq!(entry["state"], "revoked");
        assert!(entry["revoked_at"].is_string());
    }
    let raw = instance.state_file()["clients"]
        .as_array()
        .expect("state clients")
        .clone();
    assert!(
        raw.iter().all(|e| e["verifier"].is_null()),
        "a revoked entry holds no verifier"
    );
    // Re-enrolment: a higher pending generation under the same stable id.
    let reissued = control_post(
        instance.addr,
        "/control/v1/clients/active-one/reissue",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(reissued.status, StatusCode::CREATED);
    assert_eq!(reissued.json()["client"]["generation"], 2);
    let new_code = reissued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let claimed = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "active-one", "code": new_code }),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK, "{claimed:?}");
    let renewed = claimed.json()["client_secret"]
        .as_str()
        .expect("secret")
        .to_string();
    let served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &format!("Bearer {renewed}"))],
        ),
    )
    .await;
    assert_eq!(
        served.status,
        StatusCode::OK,
        "only the new generation works"
    );
}

/// A verifier copied between registry slots never changes roles
/// because the domains differ.
#[tokio::test(flavor = "multi_thread")]
async fn verifier_domains_never_cross_roles() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("verifier-domains-never-cross").await;
    instance.add_fsub();
    let client = enroll(&instance, "mac", "Mac").await;
    // A client secret presented at an operator endpoint is authenticated but
    // not authorised: 403, not 401.
    let bearer = client.bearer();
    let headers: Vec<(&str, &str)> = vec![("authorization", &bearer)];
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/configuration",
        &headers,
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.json()["error"]["code"], "operator_required");
    // Copy the client verifier into the operator slot and restart.
    instance.restart_with_state(|state| {
        let verifier = state["clients"][0]["verifier"].clone();
        let mut operator = verifier;
        operator["rotated_at"] = json!("2099-01-01T00:00:00Z");
        state["operator"] = operator;
    });
    // The client secret still resolves as the client — and only as the
    // client: the copied verifier's domain keeps it out of the operator slot.
    let served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &client.bearer())],
        ),
    )
    .await;
    assert_eq!(
        served.status,
        StatusCode::OK,
        "the client verifier still works in its slot"
    );
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/configuration",
        &headers,
        None,
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::FORBIDDEN,
        "a client secret never grants the operator role"
    );
    // The slot never authenticates a client secret as the operator.
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/clients",
        &headers,
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
}

/// Search config, state, logs, audit and failures for the fake
/// secrets → no hit outside the protected creation output. The
/// argv and bundle halves are the other tests'.
#[tokio::test(flavor = "multi_thread")]
async fn disclosed_secrets_never_reach_a_surface() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("disclosed-secrets-never-reach").await;
    let mut disclosed: Vec<String> = Vec::new();
    // Issue, claim, rotate, reissue, provision: every disclosed plaintext.
    for (path, body) in [
        (
            "/control/v1/clients",
            json!({ "id": "one", "display_name": "One" }),
        ),
        (
            "/control/v1/clients",
            json!({ "id": "two", "display_name": "Two" }),
        ),
    ] {
        let answer = control_post(instance.addr, path, &[], body).await;
        let code = answer.json()["enrollment_code"]
            .as_str()
            .expect("code")
            .to_string();
        disclosed.push(code.clone());
        let id = if disclosed.len() == 1 { "one" } else { "two" };
        let claimed = control_post(
            instance.addr,
            "/control/v1/enrollment/claim",
            &[],
            json!({ "id": id, "code": code }),
        )
        .await;
        disclosed.push(
            claimed.json()["client_secret"]
                .as_str()
                .expect("secret")
                .to_string(),
        );
    }
    let rotated = control_post(
        instance.addr,
        "/control/v1/clients/one/rotate",
        &[],
        json!({}),
    )
    .await;
    disclosed.push(
        rotated.json()["client_secret"]
            .as_str()
            .expect("secret")
            .to_string(),
    );
    let operator = control_post(instance.addr, "/control/v1/operator/secret", &[], json!({})).await;
    disclosed.push(
        operator.json()["operator_secret"]
            .as_str()
            .expect("secret")
            .to_string(),
    );

    // Every surface the run wrote: configuration, state (verifiers only),
    // server log, audit log, stdout and stderr.
    crate::leaks::register_needle("disclosed client material", &disclosed.join(" "));
    let needles: Vec<&str> = disclosed.iter().map(String::as_str).collect();
    let mut hits = Vec::new();
    sweep(&instance.root, &[], &needles, &mut hits);
    assert!(hits.is_empty(), "a disclosed secret leaked into {hits:?}");
}

/// Registry input or mutation requesting a disabled state is
/// refused; revoke and re-enrol remain available.
#[tokio::test(flavor = "multi_thread")]
async fn no_disabled_state() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("no-disabled-state").await;
    // A request carrying a disabled state is an unknown member.
    let answer = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac", "state": "disabled" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    let details = answer.json()["error"]["details"]
        .as_array()
        .expect("details")
        .clone();
    assert!(
        details
            .iter()
            .any(|d| d["target"] == "state" && d["code"] == "unknown_member")
    );
    // No endpoint can disable: the path does not exist.
    control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    let answer = control_post(
        instance.addr,
        "/control/v1/clients/mac/disable",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.json()["error"]["code"], "not_found");
    // Revocation and re-enrolment remain the two ways out.
    let answer = control_post(
        instance.addr,
        "/control/v1/clients/mac/revoke",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let answer = control_post(
        instance.addr,
        "/control/v1/clients/mac/reissue",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(answer.status, StatusCode::CREATED);
    assert_eq!(answer.json()["client"]["state"], "pending");
}

/// Bearer or x-api-key alone authenticate; both, missing, malformed
/// and unknown values refuse before the attempt.
#[tokio::test(flavor = "multi_thread")]
async fn data_plane_credential_shapes() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("data-plane-credential").await;
    instance.add_fsub();
    let client = enroll(&instance, "mac", "Mac").await;
    // Either header alone authenticates.
    let served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &client.bearer())],
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);
    let served = send(
        instance.addr,
        with(messages(haiku_prompt()), &[("x-api-key", &client.secret)]),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);
    let calls_after_auth = instance.upstream.calls();
    // Both together are malformed even when the values match.
    for headers in [
        vec![
            ("authorization", client.bearer()),
            ("x-api-key", client.secret.clone()),
        ],
        vec![("authorization", "Bearer jsc2_unknown".to_string())],
        vec![("x-api-key", "jsc2_unknown".to_string())],
        vec![("authorization", "Bearer".to_string())],
        vec![("authorization", "Basic abc".to_string())],
    ] {
        let refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let refused = send(instance.addr, with(messages(haiku_prompt()), &refs)).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{refs:?}");
    }
    // No credential at all, on loopback: the loopback operator — but from the
    // client's perspective the both-headers case never reached upstream.
    assert_eq!(
        instance.upstream.calls(),
        calls_after_auth,
        "every refusal came before the attempt"
    );
}

/// Without a principal, an existing control path, an absent
/// control path, an absent data path and `/v1/messages` all return
/// byte-identical refusals.
#[tokio::test(flavor = "multi_thread")]
async fn anonymous_refusals_are_identical() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(_peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let instance = Instance::start_with(
        "anonymous-refusals-identical",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    let mut first: Option<Answer> = None;
    for (method, path) in [
        (Method::GET, "/control/v1/status"),
        (Method::GET, "/control/v1/clients/never-issued"),
        (Method::GET, "/control/v1/absent"),
        (Method::GET, "/v1/absent"),
        (Method::POST, "/v1/messages"),
    ] {
        let answer = control(remote, method, path, &[], None).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{path}");
        match &first {
            None => first = Some(answer),
            Some(baseline) => {
                assert_eq!(answer.text(), baseline.text(), "{path} differs");
                assert_eq!(answer.headers, baseline.headers, "{path} differs");
            }
        }
    }
}

/// A client credential on every operator endpoint → 403
/// `operator_required`, nothing changed.
#[tokio::test(flavor = "multi_thread")]
async fn client_credential_on_every_operator_endpoint() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("client-credential-operator").await;
    instance.add_fsub();
    let client = enroll(&instance, "mac", "Mac").await;
    let digest_before = instance.state_digest();
    let bearer = client.bearer();
    let headers: Vec<(&str, &str)> = vec![("authorization", &bearer)];
    let endpoints: [(Method, &str, Option<Value>); 13] = [
        (Method::GET, "/control/v1/status", None),
        (Method::GET, "/control/v1/accounts", None),
        (
            Method::GET,
            &format!("/control/v1/accounts/{}", instance.handle("FSUB")),
            None,
        ),
        (
            Method::GET,
            "/control/v1/accounts/resolve?reference=FSUB",
            None,
        ),
        (Method::GET, "/control/v1/clients", None),
        (Method::GET, "/control/v1/clients/mac", None),
        (Method::GET, "/control/v1/configuration", None),
        // The CA read's class is client — proves the
        // client read, so it is not in this operator-only sweep.
        (
            Method::POST,
            "/control/v1/clients",
            Some(json!({ "id": "x", "display_name": "X" })),
        ),
        (
            Method::POST,
            "/control/v1/clients/mac/reissue",
            Some(json!({})),
        ),
        (
            Method::POST,
            "/control/v1/clients/mac/revoke",
            Some(json!({})),
        ),
        (
            Method::POST,
            "/control/v1/accounts",
            Some(json!({ "credential": { "source": "api_key", "api_key": "k" } })),
        ),
        (
            Method::POST,
            "/control/v1/selection/default",
            Some(json!({ "reference": "FSUB" })),
        ),
        (Method::POST, "/control/v1/reload", Some(json!({}))),
    ];
    for (method, path, body) in endpoints {
        let answer = control(instance.addr, method, path, &headers, body).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{path}: {answer:?}");
        assert_eq!(
            answer.json()["error"]["code"],
            "operator_required",
            "{path}"
        );
    }
    assert_eq!(instance.state_digest(), digest_before, "nothing changed");
}

/// A secret-bearing operation from a non-loopback peer on a
/// plaintext listener → 403 `insecure_channel`; over TLS → accepted; loopback
/// always accepted.
#[tokio::test(flavor = "multi_thread")]
async fn secret_bearing_needs_loopback_or_tls() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(_peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    // Plaintext listener, loopback and remote peers.
    let instance = Instance::start_with(
        "secret-bearing-needs",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    // An anonymous remote caller is refused before any channel rule;
    // provision an operator secret from loopback, then the remote operator's
    // secret-bearing POST meets `insecure_channel` on the plaintext listener.
    let provisioned =
        control_post(instance.addr, "/control/v1/operator/secret", &[], json!({})).await;
    assert_eq!(provisioned.status, StatusCode::OK, "{provisioned:?}");
    let operator_secret = provisioned.json()["operator_secret"]
        .as_str()
        .expect("operator secret")
        .to_string();
    let token = format!("Bearer {operator_secret}");
    let operator: Vec<(&str, &str)> = vec![("authorization", &token)];
    let answer = control_post(
        remote,
        "/control/v1/clients",
        &operator,
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.json()["error"]["code"], "insecure_channel");
    let answer = control_post(
        instance.addr,
        "/control/v1/clients",
        &operator,
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::CREATED,
        "loopback is always accepted"
    );
    // A TLS listener: the same secret-bearing operation is accepted from the
    // non-loopback peer.
    // Not the second instance's root: `Instance::start_with` wipes its
    // scenario directory, certs included.
    let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/acceptance/secret-bearing-needs-certs");
    let (cert, key) = stage_tls_pair(&directory);
    let tls_instance = Instance::start_with(
        "secret-bearing-needs-tls",
        Setup {
            wildcard: true,
            data_plane: format!(
                "tls_certificate_file = {}\ntls_private_key_file = {}\n",
                crate::harness::toml_path(&cert),
                crate::harness::toml_path(&key)
            ),
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&tls_instance).expect("checked above");
    // An anonymous remote caller is refused before any channel rule;
    // provision an operator secret from loopback (the TLS instance's listener
    // is TLS there too), then issue from the remote peer as the operator.
    let provisioned = control_tls(
        tls_instance.addr,
        Method::POST,
        "/control/v1/operator/secret",
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(provisioned.status, StatusCode::OK, "{provisioned:?}");
    let operator_secret = provisioned.json()["operator_secret"]
        .as_str()
        .expect("operator secret")
        .to_string();
    let token = format!("Bearer {operator_secret}");
    let answer = send_tls(
        remote,
        Request::builder()
            .method(Method::POST)
            .uri("/control/v1/clients")
            .header("content-type", "application/json")
            .header("authorization", &token)
            .body(Full::new(Bytes::from(
                json!({ "id": "remote", "display_name": "Remote" }).to_string(),
            )))
            .expect("request builds"),
        false,
    )
    .await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
}

/// Issue → one code, once; reissue invalidates it; rotate → one
/// new secret, the old fails the next request; revoke kills both generations.
#[tokio::test(flavor = "multi_thread")]
async fn registry_lifecycle_endpoints() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("registry-lifecycle-endpoints").await;
    instance.add_fsub();
    // Issue: 201, the entry plus code and expiry; the code's only appearance.
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{issued:?}");
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    assert!(issued.json()["expires_at"].is_string());
    // A never-issued id is 404 client_not_found; a revoked id is found.
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/clients/ghost",
        &[],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.json()["error"]["code"], "client_not_found");
    // Rotate a pending id: 409 conflict.
    let answer = control_post(
        instance.addr,
        "/control/v1/clients/mac/rotate",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(answer.status, StatusCode::CONFLICT);
    // Claim, then rotate: one new secret, the old fails the next request.
    let claimed = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": code }),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK);
    let first_secret = claimed.json()["client_secret"]
        .as_str()
        .expect("secret")
        .to_string();
    let rotated = control_post(
        instance.addr,
        "/control/v1/clients/mac/rotate",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let second_secret = rotated.json()["client_secret"]
        .as_str()
        .expect("secret")
        .to_string();
    assert_ne!(first_secret, second_secret);
    let old = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &format!("Bearer {first_secret}"))],
        ),
    )
    .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
    let renewed = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &format!("Bearer {second_secret}"))],
        ),
    )
    .await;
    assert_eq!(renewed.status, StatusCode::OK);
    // Reissue invalidates the outstanding code and advances the generation.
    let generation = rotated.json()["client"]["generation"]
        .as_u64()
        .expect("generation");
    let reissued = control_post(
        instance.addr,
        "/control/v1/clients/mac/reissue",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(reissued.status, StatusCode::CREATED);
    assert_eq!(reissued.json()["client"]["generation"], generation + 1);
    // Revoke kills everything at once; the entry stays visible.
    let revoked = control_post(
        instance.addr,
        "/control/v1/clients/mac/revoke",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert_eq!(revoked.json()["client"]["state"], "revoked");
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/clients/mac",
        &[],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "a revoked id is found");
    let dead = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &format!("Bearer {second_secret}"))],
        ),
    )
    .await;
    assert_eq!(dead.status, StatusCode::UNAUTHORIZED);
    // Revoking twice is 200 and changes nothing.
    let again = control_post(
        instance.addr,
        "/control/v1/clients/mac/revoke",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(again.status, StatusCode::OK);
}

/// The claim: the first succeeds; unknown id, wrong code, expired
/// code, replay and a lost concurrent race all give one identical refusal.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn every_failed_claim_is_one_refusal() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let instance = Instance::start_with_faults(
        "failed-claim-refusal",
        Setup {
            clients: "enrollment_lifetime_seconds = 60".into(),
            ..Setup::default()
        },
        std::sync::Arc::clone(&faults),
    )
    .await;
    // A reference refusal from an unknown id, captured before anything else.
    let unknown = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "ghost", "code": "jse2_whatever" }),
    )
    .await;
    expect_claim_refusal(&unknown);
    let baseline = unknown.text();

    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    // Wrong code.
    let wrong = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": "jse2_wrong" }),
    )
    .await;
    expect_claim_refusal(&wrong);
    assert_eq!(wrong.text(), baseline);
    // Expired code (the moved clock: past the 60 s lifetime).
    faults.set_deadline(std::time::Instant::now(), 61);
    let expired = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": code }),
    )
    .await;
    expect_claim_refusal(&expired);
    assert_eq!(expired.text(), baseline);
    // Reissue and claim, then replay and a lost concurrent race.
    let reissued = control_post(
        instance.addr,
        "/control/v1/clients/mac/reissue",
        &[],
        json!({}),
    )
    .await;
    let fresh = reissued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let (first, second) = tokio::join!(
        control_post(
            instance.addr,
            "/control/v1/enrollment/claim",
            &[],
            json!({ "id": "mac", "code": fresh })
        ),
        control_post(
            instance.addr,
            "/control/v1/enrollment/claim",
            &[],
            json!({ "id": "mac", "code": fresh })
        ),
    );
    let (winner, loser) = if first.status == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(winner.status, StatusCode::OK);
    let body = winner.json();
    assert_eq!(body["client_id"], "mac");
    assert!(body["client_secret"].is_string());
    assert_eq!(body["display_name"], "Mac");
    assert_eq!(body["generation"], 2);
    expect_claim_refusal(&loser);
    assert_eq!(loser.text(), baseline, "the lost race is the same refusal");
    // The replay after success.
    let replay = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": fresh }),
    )
    .await;
    expect_claim_refusal(&replay);
    assert_eq!(replay.text(), baseline);
}

/// The operator secret is provisioned from loopback, refused from
/// A remote peer even with TLS; rotation invalidates the old immediately.
#[tokio::test(flavor = "multi_thread")]
async fn operator_secret_is_loopback_managed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(_peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/acceptance/operator-secret-loopback-managed-tls");
    let (cert, key) = stage_tls_pair(&directory);
    let instance = Instance::start_with(
        "operator-secret-loopback-managed",
        Setup {
            wildcard: true,
            data_plane: format!(
                "tls_certificate_file = {}\ntls_private_key_file = {}\n",
                crate::harness::toml_path(&cert),
                crate::harness::toml_path(&key)
            ),
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    // The instance's listener is TLS-only (even on loopback): every request
    // below goes over TLS.
    // From the remote peer with no credential: 401 before any channel rule;
    // with a (non-operator) client credential or after the operator
    // secret exists, an operator secret call is 403 loopback_required whatever
    // the channel.
    let answer = control_post_tls(remote, "/control/v1/operator/secret", &[], json!({})).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{answer:?}");
    let bootstrap_token = "Bearer jso2_placeholder".to_string();
    let not_an_operator: Vec<(&str, &str)> = vec![("authorization", &bootstrap_token)];
    // While the registry is empty, loopback is the bootstrap operator: a
    // non-loopback peer presenting a credential is refused, never promoted.
    let answer = control_tls(
        remote,
        Method::POST,
        "/control/v1/operator/secret",
        &not_an_operator,
        Some(json!({})),
    )
    .await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{answer:?}");
    // Provision the real operator secret from loopback, then retry as the
    // remote operator: 403 loopback_required, TLS or not. The
    // provisioning itself discloses once.
    let provisioned =
        control_post_tls(instance.addr, "/control/v1/operator/secret", &[], json!({})).await;
    assert_eq!(provisioned.status, StatusCode::OK, "{provisioned:?}");
    let secret = provisioned.json()["operator_secret"]
        .as_str()
        .expect("disclosed once")
        .to_string();
    assert!(secret.starts_with("jso2_"));
    let operator_token = format!("Bearer {secret}");
    let operator: Vec<(&str, &str)> = vec![("authorization", &operator_token)];
    let answer = control_tls(
        remote,
        Method::POST,
        "/control/v1/operator/secret",
        &operator,
        Some(json!({})),
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "TLS does not help");
    assert_eq!(answer.json()["error"]["code"], "loopback_required");
    // The operator credential resolves as the remote operator.
    let token = format!("Bearer {secret}");
    let headers: Vec<(&str, &str)> = vec![("authorization", &token)];
    let answer = control_tls(remote, Method::GET, "/control/v1/status", &headers, None).await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "a remote operator reads the snapshot"
    );
    // Rotation invalidates the old secret immediately.
    let rotated =
        control_post_tls(instance.addr, "/control/v1/operator/secret", &[], json!({})).await;
    let replacement = rotated.json()["operator_secret"]
        .as_str()
        .expect("secret")
        .to_string();
    assert_ne!(secret, replacement);
    let answer = control_tls(remote, Method::GET, "/control/v1/status", &headers, None).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "no grace period");
    // DELETE removes it; only loopback callers are operators again.
    let remote_token = format!("Bearer {replacement}");
    let remote_headers: Vec<(&str, &str)> = vec![("authorization", &remote_token)];
    let answer = control_tls(
        remote,
        Method::DELETE,
        "/control/v1/operator/secret",
        &remote_headers,
        Some(json!({})),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::FORBIDDEN,
        "removal is loopback-only too"
    );
    let answer = control_tls(
        instance.addr,
        Method::DELETE,
        "/control/v1/operator/secret",
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let answer = control_tls(
        remote,
        Method::GET,
        "/control/v1/status",
        &remote_headers,
        None,
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::UNAUTHORIZED,
        "the secret is gone"
    );
}

/// After a run that creates a pending, an active and a revoked
/// client, an operator secret, holds, sessions and a default: each registry
/// entry carries exactly the fields for its state, and the state file
/// carries none of the forbidden facts.
#[tokio::test(flavor = "multi_thread")]
async fn state_registry_shape_and_no_forbidden_facts() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("state-registry-shape").await;
    // A default, a session and a throttle hold: one 429-driven exchange.
    instance.add_fsub();
    instance.upstream.script([reply_throttle_429(Some(120))]);
    let answer = send(
        instance.addr,
        in_session(messages(haiku_prompt()), "session-a"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    instance.settle();
    assert!(
        !instance.account("FSUB")["quota_holds"]["throttle_hold_end"].is_null(),
        "the run leaves a hold"
    );
    // Pending, active, revoked clients and an operator secret.
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "pending-one", "display_name": "Pending One" }),
    )
    .await;
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let enrolled = enroll(&instance, "active-one", "Active One").await;
    control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "later", "display_name": "Later" }),
    )
    .await;
    control_post(
        instance.addr,
        "/control/v1/clients/later/revoke",
        &[],
        json!({}),
    )
    .await;
    control_post(instance.addr, "/control/v1/operator/secret", &[], json!({})).await;

    let state = instance.state_file();
    // Exactly five top-level keys.
    let mut keys: Vec<&str> = state
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "accounts",
            "clients",
            "operator",
            "organization_quota",
            "version"
        ]
    );
    // Each entry carries exactly the fields for its state.
    let expected_keys = [
        "activated_at",
        "display_name",
        "expires_at",
        "generation",
        "id",
        "issued_at",
        "revoked_at",
        "state",
        "verifier",
    ];
    for entry in state["clients"].as_array().expect("clients") {
        let mut keys: Vec<&str> = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, expected_keys, "{entry}");
        let domain = entry["verifier"]["domain"].as_str().unwrap_or("");
        match entry["state"].as_str().expect("state") {
            "pending" => assert_eq!(domain, "jaynshare/enrollment", "{entry}"),
            "active" => assert_eq!(domain, "jaynshare/client", "{entry}"),
            "revoked" => assert!(entry["verifier"].is_null(), "{entry}"),
            other => panic!("no fourth state: {other}"),
        }
    }
    let operator = &state["operator"];
    let mut operator_keys: Vec<&str> = operator
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    operator_keys.sort_unstable();
    assert_eq!(
        operator_keys,
        ["algorithm", "digest", "domain", "rotated_at"]
    );
    assert_eq!(operator["domain"], "jaynshare/operator");
    // No ready/in-flight markers, holds, sessions, defaults or
    // plaintext secrets in the file. ("session" is not swept: it is a
    // legitimate quota bucket name the upstream reports.)
    let text = serde_json::to_string(&state).expect("state text");
    for forbidden in [
        "in_flight",
        "bound",
        "throttle",
        "last_served",
        "default",
        "preference",
        "session_k",
        &enrolled.secret,
        &code,
    ] {
        assert!(!text.contains(forbidden), "state carries {forbidden:?}");
    }
}

/// Registry entries round-trip through restart in every state; a
/// verifier copied into the `operator` slot or another domain never matches;
/// A revoked entry holds no verifier.
#[tokio::test(flavor = "multi_thread")]
async fn registry_round_trips_through_restart() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("registry-round-trips").await;
    instance.add_fsub();
    let active = enroll(&instance, "active-one", "Active One").await;
    control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "pending-one", "display_name": "Pending One" }),
    )
    .await;
    control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "revoked-one", "display_name": "Revoked One" }),
    )
    .await;
    control_post(
        instance.addr,
        "/control/v1/clients/revoked-one/revoke",
        &[],
        json!({}),
    )
    .await;
    let before = instance.state_file();
    // Restart: every state round-trips.
    instance.restart();
    assert_eq!(instance.state_file(), before, "the restart changed nothing");
    let served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &active.bearer())],
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK, "the active secret survived");
    let claim = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "pending-one", "code": "jse2_stale" }),
    )
    .await;
    expect_claim_refusal(&claim);
    // The revoked entry still holds no verifier, and stays visible.
    let raw = instance.state_file()["clients"]
        .as_array()
        .expect("clients")
        .clone();
    let revoked = raw
        .iter()
        .find(|e| e["id"] == "revoked-one")
        .expect("entry");
    assert_eq!(revoked["state"], "revoked");
    assert!(revoked["verifier"].is_null());
}

/// The lifetime key reloaded → the next issue uses it; an issued
/// code keeps its expiry.
#[tokio::test(flavor = "multi_thread")]
async fn lifetime_key_is_live() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "lifetime-key-live",
        Setup {
            clients: "enrollment_lifetime_seconds = 60".into(),
            ..Setup::default()
        },
    )
    .await;
    let first = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "one", "display_name": "One" }),
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let short_expiry = first.json()["expires_at"]
        .as_str()
        .expect("expiry")
        .to_string();
    // Reload with the lifetime at its maximum; the next issue uses it.
    instance.reload_with_setup(&Setup {
        clients: "enrollment_lifetime_seconds = 604800".into(),
        ..Setup::default()
    });
    let second = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "two", "display_name": "Two" }),
    )
    .await;
    let long_expiry = second.json()["expires_at"]
        .as_str()
        .expect("expiry")
        .to_string();
    let seconds = |stamp: &str| {
        time::OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339)
            .expect("rfc 3339")
            .unix_timestamp()
    };
    let gap = seconds(&long_expiry) - seconds(&short_expiry);
    assert!(
        gap > 86_400,
        "the reloaded lifetime applied to the next issue: {gap} s apart"
    );
    // The issued code keeps the expiry recorded at issue.
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/clients/one",
        &[],
        None,
    )
    .await;
    assert_eq!(answer.json()["client"]["expires_at"], json!(short_expiry));
}

const CSRF_REFUSAL_MESSAGE: &str = "cross-origin control mutations are refused";

/// The one `403 cross_origin_control` envelope every guarded mutation returns:
/// version, slug, message, no target, no details, no reflection.
fn expect_csrf_refusal(answer: Answer, id: &str) {
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{id}: {answer:?}");
    let body = answer.json();
    assert_eq!(body["control_api_version"], 1, "{id}: {body}");
    let error = &body["error"];
    assert_eq!(error["code"], "cross_origin_control", "{id}: {body}");
    assert_eq!(error["message"], CSRF_REFUSAL_MESSAGE, "{id}: {body}");
    assert_eq!(error["target"], json!(null), "{id}: {body}");
    assert_eq!(error["details"], json!([]), "{id}: {body}");
    assert!(
        !body.to_string().contains("evil.example"),
        "{id}: no origin reflected: {body}"
    );
}

/// The one read envelope: version and `captured_at`.
fn expect_read(body: &Value) {
    assert_eq!(body["control_api_version"], 1, "{body}");
    assert!(body["captured_at"].is_string(), "{body}");
}

/// One mutation (`POST /control/v1/clients`, a fresh id per
/// call) through every header shape: `sec-fetch-site` is authoritative
/// (`same-origin` and `none` pass, anything else refuses); with the header
/// absent, any `origin` — including `null` and the empty string — refuses and
/// A header-less native request passes; `same-origin` beats a lying `origin`
/// Every refusal is the bare envelope: no `evil.example`
/// reflection, `details == []`, no state change.
#[tokio::test(flavor = "multi_thread")]
async fn cross_site_mutations_are_refused_native_calls_pass() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("cross-site-mutations").await;
    let addr = instance.addr;

    let created = |answer: Answer, id: &str| {
        assert_eq!(answer.status, StatusCode::CREATED, "{id}: {answer:?}");
    };
    let refused = |answer: Answer, id: &str| {
        expect_csrf_refusal(answer, id);
    };
    let mutate = |id: &str| json!({ "id": id, "display_name": "Guard" });

    // The fetch-metadata header is authoritative.
    created(
        control_post(
            addr,
            "/control/v1/clients",
            &[("sec-fetch-site", "same-origin")],
            mutate("same-origin"),
        )
        .await,
        "same-origin",
    );
    created(
        control_post(
            addr,
            "/control/v1/clients",
            &[("sec-fetch-site", "none")],
            mutate("none"),
        )
        .await,
        "none",
    );
    refused(
        control_post(
            addr,
            "/control/v1/clients",
            &[("sec-fetch-site", "same-site")],
            mutate("same-site"),
        )
        .await,
        "same-site",
    );
    refused(
        control_post(
            addr,
            "/control/v1/clients",
            &[("sec-fetch-site", "cross-site")],
            mutate("cross-site"),
        )
        .await,
        "cross-site",
    );
    refused(
        control_post(
            addr,
            "/control/v1/clients",
            &[("sec-fetch-site", "bogus")],
            mutate("bogus"),
        )
        .await,
        "bogus",
    );

    // No header → any origin refuses, a native request passes.
    refused(
        control_post(
            addr,
            "/control/v1/clients",
            &[("origin", "https://x.example")],
            mutate("origin"),
        )
        .await,
        "origin",
    );
    refused(
        control_post(
            addr,
            "/control/v1/clients",
            &[("origin", "null")],
            mutate("origin-null"),
        )
        .await,
        "origin-null",
    );
    refused(
        control_post(
            addr,
            "/control/v1/clients",
            &[("origin", "")],
            mutate("origin-empty"),
        )
        .await,
        "origin-empty",
    );

    // The fetch-metadata header wins over a lying origin.
    created(
        control_post(
            addr,
            "/control/v1/clients",
            &[
                ("sec-fetch-site", "same-origin"),
                ("origin", "https://evil.example"),
            ],
            mutate("same-origin-beats-origin"),
        )
        .await,
        "same-origin-beats-origin",
    );

    // The passing calls created exactly these clients; refusals changed
    // nothing.
    let listed = control(addr, Method::GET, "/control/v1/clients", &[], None)
        .await
        .json();
    let mut ids: Vec<String> = listed["clients"]
        .as_array()
        .expect("clients")
        .iter()
        .filter_map(|c| c["id"].as_str().map(str::to_string))
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        vec!["none", "same-origin", "same-origin-beats-origin"],
        "{listed}"
    );
}

/// Reads are never guarded: a request with both cross-origin
/// headers is served to operator and client alike, without any CORS
/// permission header, and client-visible responses carry
/// `cache-control: no-store`.
#[tokio::test(flavor = "multi_thread")]
async fn cross_origin_reads_are_served_without_cors() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("cross-origin-reads").await;
    instance.add_fsub();
    let alpha = enroll(&instance, "mac", "Mac").await;
    let headers = [
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://evil.example"),
    ];

    let mut reads = Vec::new();
    let operator_read = control(
        instance.addr,
        Method::GET,
        "/control/v1/status",
        &headers,
        None,
    )
    .await;
    assert_eq!(operator_read.status, StatusCode::OK, "{operator_read:?}");
    expect_read(&operator_read.json());
    reads.push(operator_read);

    for path in [
        "/control/v1/client/status",
        "/control/v1/client/accounts",
        "/control/v1/ca",
    ] {
        let bearer = alpha.bearer();
        let answer = control(
            instance.addr,
            Method::GET,
            path,
            &[("authorization", &bearer)],
            None,
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{path}: {answer:?}");
        assert_eq!(answer.header("cache-control"), Some("no-store"), "{path}");
        let body = answer.json();
        // `ca` is a bare payload member; the other two are reads with the
        // version and `captured_at` envelope.
        if path == "/control/v1/ca" {
            assert_eq!(body["control_api_version"], 1, "{body}");
        } else {
            expect_read(&body);
        }
        reads.push(answer);
    }

    // No CORS permission header on any response, client or operator.
    for answer in &reads {
        for name in answer.headers.keys() {
            assert!(
                !name.as_str().starts_with("access-control-"),
                "a CORS header leaked: {name}"
            );
        }
    }
}

/// Pin and preference tokens decode a Unicode reference
/// byte-identically under an enrolled client; duplicate, comma-joined,
/// whitespace, padded, unknown-discriminator and over-length forms are 400
/// `invalid_request_error` before any attempt.
#[tokio::test(flavor = "multi_thread")]
async fn pin_and_preference_tokens_decode_unicode_byte_identically() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("pin-preference-tokens").await;
    add_two(&instance);
    let rename = instance.cli_json(&["account", "rename", "FSUB2", "Équipe Δ ✓"], None);
    assert_eq!(rename["ok"], true, "rename: {rename}");
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;

    let unicode = "Équipe Δ ✓";
    let answer = send(
        instance.addr,
        with(
            pinned(messages(haiku_prompt()), unicode),
            &[("authorization", &alpha.bearer())],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.audit().pop().expect("an audit record");
    assert_eq!(
        record["serving_account"]["display_name"],
        json!(unicode),
        "the Unicode reference named the renamed account"
    );
    let answer = send(
        instance.addr,
        with(
            preferred(messages(haiku_prompt()), unicode),
            &[("authorization", &alpha.bearer())],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());

    let calls = instance.upstream.calls();
    for bad in ["pin.QUJD,pin.QUJD", "pin.QUJD=", "fix.QUJD"] {
        let answer = send(
            instance.addr,
            with(
                messages(haiku_prompt()),
                &[
                    ("x-jaynshare-account", bad),
                    ("authorization", &alpha.bearer()),
                ],
            ),
        )
        .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{bad:?}");
        assert_eq!(answer.json()["error"]["type"], "invalid_request_error");
    }
    // Surrounding whitespace never reaches the token parser: RFC 9110 strips
    // leading/trailing OWS at the transport, so `" pin.QUJD"` arrives as the
    // canonical `pin.QUJD` — an unknown reference, the 404. the
    // whitespace clause stays as proxy-internal defence in depth.
    let answer = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[
                ("x-jaynshare-account", " pin.QUJD"),
                ("authorization", &alpha.bearer()),
            ],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", answer.text());
    assert_eq!(answer.json()["error"]["type"], "not_found_error");
    let duplicated = pinned(messages(haiku_prompt()), "FSUB");
    let answer = send(
        instance.addr,
        with(
            with(duplicated, &[("x-jaynshare-account", &token(true, "FSUB"))]),
            &[
                ("x-jaynshare-account", &token(true, "FSUB")),
                ("authorization", &alpha.bearer()),
            ],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "two fields");
    assert_eq!(answer.json()["error"]["type"], "invalid_request_error");
    let answer = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[
                ("x-jaynshare-account", &token(true, &"a".repeat(1025))),
                ("authorization", &alpha.bearer()),
            ],
        ),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::BAD_REQUEST,
        "a reference over 1,024 bytes"
    );
    assert_eq!(answer.json()["error"]["type"], "invalid_request_error");
    assert_eq!(
        instance.upstream.calls(),
        calls,
        "every malformed form is refused before any attempt"
    );
}

/// Under an enrolled client: an unknown pin or preference
/// reference is 404, an ambiguous reference is 400 naming both display
/// names, and an unavailable preference falls back while a pin never does.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_ambiguous_and_unavailable_references() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("unknown-ambiguous-unavailable").await;
    add_two(&instance);
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;
    let bearer = alpha.bearer();
    let calls = instance.upstream.calls();

    let answer = send(
        instance.addr,
        with(
            pinned(messages(haiku_prompt()), "nobody"),
            &[("authorization", &bearer)],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.json()["error"]["type"], "not_found_error");
    let answer = send(
        instance.addr,
        with(
            preferred(messages(haiku_prompt()), "nobody"),
            &[("authorization", &bearer)],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.json()["error"]["type"], "not_found_error");
    // Both accounts share the organisation: its UUID names two of them.
    for pinned_to in [true, false] {
        let request = messages(haiku_prompt());
        let request = if pinned_to {
            pinned(request, FIXTURE_ORG_UUID)
        } else {
            preferred(request, FIXTURE_ORG_UUID)
        };
        let answer = send(instance.addr, with(request, &[("authorization", &bearer)])).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{pinned_to}");
        assert_eq!(answer.json()["error"]["type"], "invalid_request_error");
        let message = answer.json()["error"]["message"]
            .as_str()
            .expect("message")
            .to_string();
        assert!(
            message.contains("FSUB") && message.contains("FSUB2"),
            "{message}"
        );
    }
    assert_eq!(
        instance.upstream.calls(),
        calls,
        "unknown and ambiguous references attempt nothing"
    );

    let disable = instance.cli_json(&["account", "disable", "FSUB2"], None);
    assert_eq!(disable["ok"], true, "disable: {disable}");
    //A uniquely-resolved unavailable preference continues with the
    // healthy sibling.
    let answer = send(
        instance.addr,
        with(
            preferred(messages(haiku_prompt()), "FSUB2"),
            &[("authorization", &bearer)],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.audit().pop().expect("an audit record");
    assert_eq!(
        record["serving_account"]["display_name"],
        json!("FSUB"),
        "the preference fell back to the other account"
    );
    //A pin is served by that account or nobody — it never falls back.
    let calls = instance.upstream.calls();
    let answer = send(
        instance.addr,
        with(
            pinned(messages(haiku_prompt()), "FSUB2"),
            &[("authorization", &bearer)],
        ),
    )
    .await;
    let status = answer.status.as_u16();
    assert!(
        (400..600).contains(&status),
        "pin of a disabled account: {status}"
    );
    let error_type = answer.json()["error"]["type"]
        .as_str()
        .expect("error type")
        .to_string();
    assert!(
        ["rate_limit_error", "api_error"].contains(&error_type.as_str()),
        "a proxy refusal, not an upstream one: {error_type}"
    );
    assert_eq!(instance.upstream.calls(), calls, "a pin never falls back");
}

/// Under an enrolled client the upstream receives none of the
/// proxy metadata headers, sees the pooled account's credential instead of
/// the caller's, and keeps `x-claude-code-session-id`.
#[tokio::test(flavor = "multi_thread")]
async fn the_upstream_never_sees_proxy_metadata_headers() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("upstream-never-sees").await;
    instance.add_fsub();
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;

    let answer = send(
        instance.addr,
        with(
            pinned(in_session(messages(haiku_prompt()), "s1"), "FSUB"),
            &[
                ("authorization", &alpha.bearer()),
                ("proxy-authorization", "Basic dXNlcjpwYXNz"),
            ],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let last = instance.upstream.last();
    assert!(last.header("x-jaynshare-account").is_none());
    assert!(last.header("proxy-authorization").is_none());
    let credential = last
        .header("authorization")
        .or_else(|| last.header("x-api-key"))
        .expect("the upstream saw a credential")
        .to_string();
    assert!(
        !credential.contains(&alpha.secret),
        "the caller's client secret never reaches the upstream: {credential}"
    );
    assert!(
        credential.contains(&instance.needles.access_token),
        "the upstream sees the pooled account's credential: {credential}"
    );
    assert_eq!(
        last.header("x-claude-code-session-id"),
        Some("s1"),
        "the session id is forwarded (/14 keep it)"
    );
}

/// One `GET /control/v1/ca`, as the loopback operator (`bearer = None`) or an
/// enrolled client.
async fn read_ca(addr: SocketAddr, bearer: Option<&str>) -> Answer {
    let headers: Vec<(&str, &str)> = bearer
        .map(|b| vec![("authorization", b)])
        .unwrap_or_default();
    control(addr, Method::GET, "/control/v1/ca", &headers, None).await
}

/// The CA read answers an operator and an enrolled client with
/// certificate, fingerprint, expiry and state, carries no key material under
/// the needle sweep, and with MITM off reports the documented state rather
/// than an error.
#[tokio::test(flavor = "multi_thread")]
async fn the_ca_read_answers_operator_and_client_without_key_material() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let off = Instance::start("ca-read-answers-operator-off").await;
    let alpha = enroll(&off, "alpha", "Alpha Desk").await;
    let off_alpha = alpha.bearer();
    // MITM never enabled: every member `null` — the documented state, not an
    // error — for the operator and the client alike.
    for (who, bearer) in [("operator", None), ("client", Some(off_alpha.as_str()))] {
        let answer = read_ca(off.addr, bearer).await;
        assert_eq!(answer.status, StatusCode::OK, "{who}: {}", answer.text());
        assert_eq!(
            answer.json()["ca"],
            json!({
                "certificate_pem": null,
                "fingerprint": null,
                "not_after": null,
                "state": null,
                "next": null,
            }),
            "{who}"
        );
    }

    // MITM on: the certificate, its fingerprint, the expiry and the
    // `ok` state — and no private key anywhere in the response.
    let on = Instance::start_with(
        "ca-read-answers-operator",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let alpha = enroll(&on, "alpha", "Alpha Desk").await;
    let on_alpha = alpha.bearer();
    let mut fingerprints = Vec::new();
    for (who, bearer) in [("operator", None), ("client", Some(on_alpha.as_str()))] {
        let answer = read_ca(on.addr, bearer).await;
        assert_eq!(answer.status, StatusCode::OK, "{who}: {}", answer.text());
        let text = answer.text();
        let ca = &answer.json()["ca"];
        let pem = ca["certificate_pem"]
            .as_str()
            .unwrap_or_else(|| panic!("{who}: the PEM is a string: {ca}"));
        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "{who}: {pem}"
        );
        let fingerprint = ca["fingerprint"]
            .as_str()
            .unwrap_or_else(|| panic!("{who}: the fingerprint is a string: {ca}"));
        // Colon-separated hex SHA-256 of the DER certificate.
        let pairs: Vec<&str> = fingerprint.split(':').collect();
        assert_eq!(pairs.len(), 32, "{who}: {fingerprint}");
        for pair in &pairs {
            assert!(
                pair.len() == 2 && pair.chars().all(|c| c.is_ascii_hexdigit()),
                "{who}: {fingerprint}"
            );
        }
        time::OffsetDateTime::parse(
            ca["not_after"].as_str().expect("the expiry"),
            &time::format_description::well_known::Rfc3339,
        )
        .expect("the expiry is RFC 3339");
        assert_eq!(ca["state"], "ok", "{who}");
        assert!(!text.contains("PRIVATE KEY"), "{who}: {text}");
        fingerprints.push(fingerprint.to_string());
    }
    assert_eq!(
        fingerprints[0], fingerprints[1],
        "operator and client agree"
    );
    assert_eq!(
        fingerprints[0],
        on.status()["mitm"]["ca"]["fingerprint"],
        "the snapshot shows the same CA"
    );
}

/// The exact member set of an allow-listed object: sorted keys, no extras.
fn assert_member_set(object: &Value, expected: &[&str]) {
    let mut keys: Vec<&str> = object
        .as_object()
        .expect("object")
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, expected, "{object}");
}

/// The client snapshot and the catalogue match the allow-lists
/// exactly: the computed hold hint, the selectable boolean and the pool
/// counts; no member outside the lists appears.
/// the envelope members sit beside the snapshot's own on every read.
#[tokio::test(flavor = "multi_thread")]
async fn client_snapshot_and_catalogue_match_the_allow_lists() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "client-snapshot-catalogue",
        Setup {
            data_plane: "hold_budget_seconds = 45\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;
    let bearer = alpha.bearer();
    let headers = [("authorization", bearer.as_str())];

    // The model→family mapping is learned from an attempt that
    // carries the family window; without one no account is selectable
    // (the families are empty).
    instance
        .upstream
        .script([reply_teaching_family("0.12", "allowed")]);
    let answer = send(
        instance.addr,
        with(messages(haiku_prompt()), &[("authorization", &bearer)]),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());

    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/client/status",
        &headers,
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let body = answer.json();
    assert!(body["captured_at"].is_string(), "{body}");
    assert_member_set(
        &body,
        &[
            "ca_fingerprint",
            "ca_next_fingerprint",
            "capabilities",
            "captured_at",
            "client",
            "control_api_version",
            "hold_hint_seconds",
            "pool",
            "server",
            "sessions",
            "wire_capture_enabled",
        ],
    );
    assert_member_set(&body["client"], &["display_name", "id"]);
    assert_member_set(
        &body["server"],
        &["available", "control_api_version", "tls_pin", "version"],
    );
    assert_member_set(
        &body["pool"],
        &["accounts_configured", "accounts_selectable"],
    );
    assert_member_set(&body["sessions"], &["active", "known"]);
    // the hold budget, computed, not copied from the configuration.
    assert_eq!(body["hold_hint_seconds"], 45, "{body}");
    assert_eq!(body["pool"]["accounts_selectable"], 1, "{body}");

    // The catalogue's selectable booleans are the, the same predicate.
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/client/accounts",
        &headers,
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let catalogue = answer.json();
    let selectable = catalogue["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .filter(|a| a["selectable"] == json!(true))
        .count();
    assert_eq!(body["pool"]["accounts_selectable"], json!(selectable));

    // Flip selectability: configured stays, selectable falls to zero.
    let envelope = instance.cli_json(&["account", "disable", "FSUB"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");

    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/client/status",
        &headers,
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let body = answer.json();
    assert_eq!(body["pool"]["accounts_selectable"], 0, "{body}");
    assert_eq!(body["pool"]["accounts_configured"], 1, "{body}");
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/client/accounts",
        &headers,
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let catalogue = answer.json();
    assert_eq!(catalogue["accounts"][0]["selectable"], false, "{catalogue}");
}

/// The client snapshot carries counts only; the operator view
/// carries the exact quota, identity, route and registry details the client
/// body never names.
#[tokio::test(flavor = "multi_thread")]
async fn client_snapshot_has_counts_only_operator_view_has_details() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("client-snapshot-has-counts").await;
    instance.add_fsub();
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;
    let answer = send(
        instance.addr,
        in_session(
            with(
                messages(haiku_prompt()),
                &[("authorization", &alpha.bearer())],
            ),
            "client-snapshot-has-counts-session",
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());

    // The operator view: per-account detail and the client registry.
    let op = control(instance.addr, Method::GET, "/control/v1/status", &[], None)
        .await
        .json();
    let operator_account = &op["status"]["accounts"][0];
    for member in [
        "profile",
        "credential",
        "health",
        "eligibility",
        "buckets",
        "quota_holds",
        "usage",
    ] {
        assert!(
            operator_account.get(member).is_some(),
            "{member}: {operator_account}"
        );
    }
    let clients = op["status"]["clients"].as_array().expect("clients array");
    assert!(
        clients.iter().any(|c| c["id"] == json!("alpha")),
        "{clients:?}"
    );

    // Everything the client body must never name.
    let profile = &operator_account["profile"];
    let secrets = [
        instance.handle("FSUB"),
        profile["email"].as_str().expect("email").to_string(),
        profile["account_uuid"]
            .as_str()
            .expect("account uuid")
            .to_string(),
        op["status"]["server"]["listen"]
            .as_str()
            .expect("listen")
            .to_string(),
    ];

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
    let text = answer.text();
    for secret in &secrets {
        assert!(!text.contains(secret.as_str()), "leaked {secret}: {text}");
    }
    for word in [
        "quota",
        "routes",
        "identity",
        "clients",
        "configuration",
        "audit",
        "source_address",
    ] {
        assert!(!text.contains(word), "{word} in the client body: {text}");
    }
    // Counts are all it carries.
    let body: Value = serde_json::from_str(&text).expect("client snapshot json");
    assert_eq!(body["pool"]["accounts_configured"], 1, "{body}");
    assert_eq!(body["sessions"]["known"], 1, "{body}");
}

/// Credential bytes travel only in the request body: the request
/// line, query and headers carry no needle, the body does, and no response
/// but the one disclosure, no log line and no audit record echoes any code
/// or secret.
#[tokio::test(flavor = "multi_thread")]
async fn credential_bytes_travel_only_in_the_body() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("credential-bytes-travel").await;
    let addr = instance.addr;

    // The harness is the caller: what we built is what the product saw. The
    // request line and query are the path we sent; the headers are the ones
    // we set — assert none carries the credential bytes.
    async fn assert_transport(needle: &str, path: &str, headers: &[(&str, &str)]) {
        assert!(
            !path.contains(needle),
            "the request line carries it: {path}"
        );
        assert!(!path.contains('?'), "an unexpected query: {path}");
        for (name, value) in headers {
            assert!(!value.contains(needle), "{name} carries the needle");
        }
    }

    // Add by API key: 201, the key never echoed back.
    let api_key = needle("api-key", "apikey");
    let path = "/control/v1/accounts";
    let headers: Vec<(&str, &str)> = vec![];
    assert_transport(&api_key, path, &headers).await;
    let added = control_post(
        addr,
        path,
        &headers,
        json!({
            "credential": { "source": "api_key", "api_key": api_key },
            "display_name": "Needle Key",
        }),
    )
    .await;
    assert_eq!(added.status, StatusCode::CREATED, "{}", added.text());
    assert!(
        !added.text().contains(&api_key),
        "the key is echoed: {added:?}"
    );

    // Enrollment claim: the code travels in the body; the response's one
    // disclosure is the secret, never the code.
    let issued = control_post(
        addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let claim_path = "/control/v1/enrollment/claim";
    assert_transport(&code, claim_path, &[]).await;
    let claimed = control_post(addr, claim_path, &[], json!({ "id": "mac", "code": code })).await;
    assert_eq!(claimed.status, StatusCode::OK, "{}", claimed.text());
    let secret = claimed.json()["client_secret"]
        .as_str()
        .expect("secret")
        .to_string();
    assert!(!claimed.text().contains(&code), "the code is echoed back");

    // Operator secret: no credential bytes in the request at all; the
    // disclosure is the response's whole job.
    let secret_path = "/control/v1/operator/secret";
    assert_transport(&secret, secret_path, &[]).await;
    let answer = control_post(addr, secret_path, &[], json!({})).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let operator_secret = answer.json()["operator_secret"]
        .as_str()
        .expect("the operator secret")
        .to_string();

    // No log line and no audit record echoes any needle or disclosure.
    let log = fs::read_to_string(instance.root.join("log/server.ndjson")).expect("server log");
    for banned in [&api_key, &code, &secret, &operator_secret] {
        assert!(!log.contains(banned.as_str()), "a log line echoes a secret");
    }
    for record in instance.audit() {
        let text = record.to_string();
        for banned in [&api_key, &code, &secret, &operator_secret] {
            assert!(
                !text.contains(banned.as_str()),
                "an audit record echoes a secret: {text}"
            );
        }
    }
}
