//! Cross-cutting security claims no single area owns on its own: what a
//! stolen bundle yields, what a refusal leaves behind, what the audit log
//! must never carry.
//!
//! These tests assert over surfaces the other areas already stage, so they
//! import the harness whole and add no fixture of their own. Where a test
//! needs a needle, it uses the per-run ones (`Instance::needles`,
//! `needle`): a hit anywhere in the run names the role that leaked.

use crate::harness::*;

const CLAIM_REFUSAL_MESSAGE: &str =
    "the enrollment claim was refused; ask the operator to issue a new code";

/// The operator is loopback or a credential on a safe channel
/// Loopback without a credential is the operator; from a
/// published port a client credential is never promoted, and the operator
/// credential is accepted only over TLS.
#[tokio::test(flavor = "multi_thread")]
async fn the_operator_is_loopback_or_a_credential_on_a_safe_channel() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(_peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let instance = Instance::start_with(
        "operator-loopback-credential",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    // (a) Loopback with no credential is the operator: an operator-only
    // mutation (the own surface) succeeds with no credential presented.
    let local = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac", "display_name": "Mac" }),
    )
    .await;
    assert_eq!(
        local.status,
        StatusCode::CREATED,
        "loopback needs no credential: {local:?}"
    );
    // (b) From a published port, a client credential is authenticated but
    // never promoted to the operator role: the same mutation is
    // `403 operator_required` (the code asserts).
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    let bearer = alpha.bearer();
    let answer = control_post(
        non_loopback_dest(&instance).expect("checked above"),
        "/control/v1/clients",
        &[("authorization", bearer.as_str())],
        json!({ "id": "remote", "display_name": "Remote" }),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::FORBIDDEN,
        "a client credential never grants the operator role: {answer:?}"
    );
    assert_eq!(answer.json()["error"]["code"], "operator_required");

    // (c) the observable in one line: loopback needs no credential, a
    // published port needs the operator credential on a channel that may
    // carry it. On the plaintext listener a secret-bearing mutation is
    // `403 insecure_channel`, so the operator half needs
    // the TLS listener; the same mutation from the non-loopback peer over
    // TLS is accepted.
    // Not the second instance's root: `Instance::start_with` wipes its
    // scenario directory, certs included.
    let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/acceptance/operator-loopback-credential-certs");
    let (cert, key) = stage_tls_pair(&directory);
    let tls_instance = Instance::start_with(
        "operator-loopback-credential-tls",
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
    // Provision the operator secret from loopback (the TLS instance's
    // listener is TLS there too); issue from the remote peer as the operator.
    let provisioned = send_tls(
        tls_instance.addr,
        Request::builder()
            .method(Method::POST)
            .uri("/control/v1/operator/secret")
            .header("host", tls_instance.addr.to_string())
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(json!({}).to_string())))
            .expect("request builds"),
        false,
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

/// Without a principal there is only the refusal and the claim:
/// every path an unauthenticated remote caller
/// probes answers the one identical refusal, the claim returns a secret once
/// and its refusal discloses nothing.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn without_a_principal_there_is_only_the_refusal_and_the_claim() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(_peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let instance = Instance::start_with(
        "without-principal-there-refusal",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    // Every path an unauthenticated remote caller might probe answers the
    // same refusal and nothing else: the bodies are byte-identical, so no
    // path leaks its existence (the anonymous read-only surface is empty).
    let mut bodies = Vec::new();
    for (method, path) in [
        (Method::GET, "/control/v1/status"),
        (Method::GET, "/control/v1/clients"),
        (Method::GET, "/control/v1/accounts"),
        (Method::GET, "/control/v1/nothing"),
        (Method::GET, "/v1/messages"),
        (Method::GET, "/control/v1/ca"),
        (Method::GET, "/control/v1/client/status"),
        (Method::POST, "/control/v1/mitm/ca/rotate"),
        (Method::GET, "/"),
    ] {
        let answer = control(remote, method, path, &[], None).await;
        assert_eq!(
            answer.status,
            StatusCode::UNAUTHORIZED,
            "{path}: {answer:?}"
        );
        bodies.push(answer.text());
    }
    let mut distinct = bodies.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        1,
        "every path answers one identical refusal: {bodies:?}"
    );
    // The fake upstream saw nothing: no path was forwarded.
    assert_eq!(instance.upstream.calls(), 0);

    // The one exception is the enrollment claim: with a valid pending code
    // the secret is returned once.
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
    crate::leaks::register_needle("enrollment-code", &code);
    let claimed = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": code }),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK, "{claimed:?}");
    let secret = claimed.json()["client_secret"]
        .as_str()
        .expect("the client secret")
        .to_string();
    crate::leaks::register_needle("client-secret", &secret);
    assert_eq!(claimed.json()["generation"], 1);

    // Then the same code returns no secret and no fact: the one
    // refusal envelope, no echo of what was claimed.
    let refusals = instance.events("control_refusal").len();
    let replay = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "mac", "code": code }),
    )
    .await;
    assert_eq!(replay.status, StatusCode::FORBIDDEN, "{replay:?}");
    let body = replay.json();
    assert_eq!(body["error"]["code"], "enrollment_claim_refused");
    assert_eq!(body["error"]["message"], CLAIM_REFUSAL_MESSAGE);
    assert_eq!(body["error"]["details"], json!([]));
    assert_eq!(body["control_api_version"], 1);
    assert!(body.get("client_secret").is_none(), "{body}");
    assert!(body.get("generation").is_none(), "{body}");
    assert!(body.get("client_id").is_none(), "{body}");
    assert!(
        !replay.text().contains(&secret),
        "no secret echo: {replay:?}"
    );
    assert!(!replay.text().contains("mac"), "no id echo: {replay:?}");
    // The refusal's log line names the real cause; the response does not.
    let lines = instance.events("control_refusal");
    assert_eq!(lines.len(), refusals + 1, "one refusal line: {lines:?}");
    let line = lines.last().expect("the refusal line");
    assert_eq!(line["fields"]["code"], "enrollment_claim_refused", "{line}");
    let cause = line["fields"]["cause"].as_str().expect("the real cause");
    assert!(cause.contains("consumed"), "the real cause: {line}");
    assert!(
        !replay.text().contains("consumed"),
        "the response does not name the cause: {replay:?}"
    );
    let consumed = replay.text();

    // An expired code: the same refusal body as the consumed one,
    // and the log line names that cause (the lifetime minimum is
    // 60 s, so the expiry is reached with the harness's moved clock, as
    // does).
    let faults = crate::faults::Faults::new();
    let instance = Instance::start_with_faults(
        "without-principal-there-refusal-expired",
        Setup {
            clients: "enrollment_lifetime_seconds = 60\n".into(),
            ..Setup::default()
        },
        std::sync::Arc::clone(&faults),
    )
    .await;
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "old", "display_name": "Old" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{issued:?}");
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    faults.set_deadline(std::time::Instant::now(), 61);
    let expired = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "old", "code": code }),
    )
    .await;
    assert_eq!(expired.status, StatusCode::FORBIDDEN, "{expired:?}");
    assert_eq!(expired.json()["error"]["code"], "enrollment_claim_refused");
    assert_eq!(expired.text(), consumed, "one identical refusal body");
    let line = instance
        .events("control_refusal")
        .last()
        .expect("the refusal line")
        .clone();
    let cause = line["fields"]["cause"].as_str().expect("the real cause");
    assert!(cause.contains("expired"), "the real cause: {line}");
}

/// A client secret used from a second machine → served from both
/// with distinct source addresses under one principal until rotation.
/// A stolen active secret is a bearer:
/// nothing binds it to the machine that claimed it, and the audit records
/// differ in the source address alone.
#[tokio::test(flavor = "multi_thread")]
async fn one_client_secret_serves_from_two_addresses_under_one_principal() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let instance = Instance::start_with(
        "client-secret-serves",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    instance.add_fsub();
    let alpha = enroll(&instance, "alpha", "Alpha").await;

    // The same bearer serves from the claiming machine and from a second one.
    let bearer = alpha.bearer();
    let local_served = send(
        instance.addr,
        with(messages(haiku_prompt()), &[("authorization", &bearer)]),
    )
    .await;
    let remote_served = send(
        remote,
        with(messages(haiku_prompt()), &[("authorization", &bearer)]),
    )
    .await;
    assert_eq!(
        local_served.status,
        StatusCode::OK,
        "{}",
        local_served.text()
    );
    assert_eq!(
        remote_served.status,
        StatusCode::OK,
        "{}",
        remote_served.text()
    );

    // Two records, one principal, two addresses: the address is the only
    // field that distinguishes the thief.
    let records = instance.audit_settled(2);
    for record in &records {
        assert_eq!(record["principal"]["kind"], "client", "{record}");
        assert_eq!(record["principal"]["id"], "alpha", "{record}");
    }
    let local_address = records[0]["source_address"]
        .as_str()
        .expect("the loopback caller's address");
    let remote_address = records[1]["source_address"]
        .as_str()
        .expect("the remote caller's address");
    assert!(local_address.starts_with("127.0.0.1:"), "{local_address}");
    assert!(
        remote_address.starts_with(&peer.to_string()),
        "{remote_address}"
    );
    assert_ne!(local_address, remote_address, "{records:?}");

    // Nothing about the second machine was needed: no second enrolment, no
    // second claim — the registry still holds one client at one generation.
    let status = instance.status();
    let clients = status["clients"].as_array().expect("clients array");
    assert_eq!(clients.len(), 1, "{clients:?}");
    assert_eq!(clients[0]["id"], "alpha", "{clients:?}");
    assert_eq!(clients[0]["generation"], alpha.generation, "{clients:?}");
}

/// A client secret used from a second source address → served;
/// both records carry their own address under one principal; after rotation
/// the old secret is refused from both addresses at the next request, and
/// both records remain attributed. Rotation is complete and prompt; accountability
/// survives it.
#[tokio::test(flavor = "multi_thread")]
async fn rotation_reaches_every_address_and_history_stays_attributed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(peer) = non_loopback_addr() else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let instance = Instance::start_with(
        "rotation-reaches-address",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    instance.add_fsub();
    let alpha = enroll(&instance, "alpha", "Alpha").await;

    // Both addresses are served under the old secret.
    let bearer = alpha.bearer();
    for addr in [instance.addr, remote] {
        let served = send(
            addr,
            with(messages(haiku_prompt()), &[("authorization", &bearer)]),
        )
        .await;
        assert_eq!(served.status, StatusCode::OK, "{}", served.text());
    }
    let before = instance.audit_settled(2);

    // Rotate: one new secret disclosed once, one generation step.
    let rotated = control_post(
        instance.addr,
        "/control/v1/clients/alpha/rotate",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK, "{rotated:?}");
    let replacement = rotated.json()["client_secret"]
        .as_str()
        .expect("the one-time disclosure")
        .to_string();
    let generation = rotated.json()["client"]["generation"]
        .as_u64()
        .expect("generation");
    assert_eq!(generation, alpha.generation + 1, "{rotated:?}");

    // The old secret is refused from both machines, with the envelope.
    for addr in [instance.addr, remote] {
        let refused = send(
            addr,
            with(messages(haiku_prompt()), &[("authorization", &bearer)]),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::UNAUTHORIZED,
            "{}",
            refused.text()
        );
        assert_eq!(
            refused.json()["error"]["type"],
            "authentication_error",
            "{}",
            refused.text()
        );
    }

    // The replacement serves from both machines under the same principal.
    for addr in [instance.addr, remote] {
        let served = send(
            addr,
            with(
                messages(haiku_prompt()),
                &[("authorization", &format!("Bearer {replacement}"))],
            ),
        )
        .await;
        assert_eq!(served.status, StatusCode::OK, "{}", served.text());
    }

    // History survived byte-identical and still attributed;
    // each refusal left its own record with its own source address.
    let records = instance.audit_settled(6);
    assert_eq!(&records[..2], &before[..], "the old records changed");
    for record in &records[2..4] {
        assert_eq!(record["status"], 401, "{record}");
        assert!(
            record["source_address"]
                .as_str()
                .is_some_and(|a| !a.is_empty()),
            "{record}"
        );
    }
    assert!(
        records[2]["source_address"]
            .as_str()
            .expect("address")
            .starts_with("127.0.0.1:"),
        "{}",
        records[2]
    );
    assert!(
        records[3]["source_address"]
            .as_str()
            .expect("address")
            .starts_with(&peer.to_string()),
        "{}",
        records[3]
    );
    for record in &records[4..6] {
        assert_eq!(record["status"], 200, "{record}");
        assert_eq!(record["principal"]["kind"], "client", "{record}");
        assert_eq!(record["principal"]["id"], "alpha", "{record}");
    }
    assert!(
        records[4]["source_address"]
            .as_str()
            .expect("address")
            .starts_with("127.0.0.1:"),
        "{}",
        records[4]
    );
    assert!(
        records[5]["source_address"]
            .as_str()
            .expect("address")
            .starts_with(&peer.to_string()),
        "{}",
        records[5]
    );
}

/// Wire capture must be impossible to run unnoticed:
/// the operator's `status` names the directory, the enrolled
/// client's snapshot says capture is on but never names the directory,
/// and capture never suspends the audit log. The negative:
/// with capture off, the snapshot says off and no capture directory exists.
#[tokio::test(flavor = "multi_thread")]
async fn capture_is_visible_on_every_surface_and_suspends_no_audit() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "capture-visible-surface",
        Setup {
            capture: true,
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let alpha = enroll(&instance, "alpha", "Alpha").await;

    // The operator surface names the directory.
    let status = instance.status();
    assert_eq!(status["capture"]["enabled"], true);
    assert_eq!(
        status["capture"]["directory"],
        instance.root.join("cap").display().to_string()
    );

    // The client surface says on, and never where.
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/client/status",
        &[("authorization", &alpha.bearer())],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let body = answer.json();
    assert_eq!(body["wire_capture_enabled"], true, "{body}");
    let directory = instance.root.join("cap").display().to_string();
    assert!(
        !body.to_string().contains(&directory),
        "the client snapshot never names the capture directory"
    );
    assert!(
        !body.to_string().contains("/cap"),
        "the client snapshot never carries the capture directory's name as a path"
    );

    // Three exchanges: three capture files, three audit records — capture
    // never suspends the audit log.
    for _ in 0..3 {
        assert_eq!(
            send(instance.addr, messages(haiku_prompt())).await.status,
            StatusCode::OK
        );
    }
    assert_eq!(instance.audit_settled(3).len(), 3);
    let files: Vec<PathBuf> = fs::read_dir(instance.root.join("cap"))
        .expect("capture directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert_eq!(files.len(), 3, "one capture file per exchange");

    // The negative: with capture off, every surface says off and no capture
    // directory was created.
    let quiet = Instance::start_with("capture-visible-surface-off", Setup::default()).await;
    quiet.add_fsub();
    let status = quiet.status();
    assert_eq!(status["capture"]["enabled"], false);
    assert_eq!(status["capture"]["directory"], Value::Null);
    let bearer = enroll(&quiet, "alpha", "Alpha").await.bearer();
    let answer = control(
        quiet.addr,
        Method::GET,
        "/control/v1/client/status",
        &[("authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(answer.json()["wire_capture_enabled"], false);
    assert!(
        !quiet.root.join("cap").exists(),
        "no capture directory without capture"
    );
}

/// The egress check URL is fetched only when a pin is configured:
/// with no pin, no request ever reaches the check path; with a pin, the only
/// outbound paths the fake sees are the check URL, the exchange, and the
/// documented endpoints; and a failing check never blocks an exchange.
#[tokio::test(flavor = "multi_thread")]
async fn the_check_url_is_fetched_only_when_a_pin_is_configured() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // With no egress pin, the check URL is never fetched: over a handful of
    // exchanges and the usage probe's own traffic, no request lands under
    // the check path.
    let unpinned = Instance::start_with("check-url-fetched-off", Setup::default()).await;
    unpinned.add_fsub();
    for _ in 0..3 {
        assert_eq!(
            send(unpinned.addr, messages(haiku_prompt())).await.status,
            StatusCode::OK
        );
    }
    unpinned.settle();
    let seen = unpinned.upstream.seen();
    assert!(
        seen.iter().all(|s| s.path != "/egress"),
        "no check request without a pin: {seen:?}"
    );

    // With a pin configured, the check URL is fetched, and the only other
    // paths the fake sees are the exchange and the documented endpoints
    // (taken from the fake's own `default_reply`).
    let pinned = Instance::start_with(
        "check-url-fetched",
        Setup {
            egress: "mode = \"auto\"\ncheck_url = \"{fake}/egress\"\ncache_seconds = 1\nhold_seconds = 30\n"
                .into(),
            ..Setup::default()
        },
    )
    .await;
    pinned.add_fsub();
    pinned.upstream.script([reply_egress(crate::dpl::PINNED)]);
    assert_eq!(
        send(pinned.addr, messages(haiku_prompt())).await.status,
        StatusCode::OK
    );
    let seen = pinned.upstream.seen();
    assert!(
        seen.iter().any(|s| s.path == "/egress"),
        "the pinned check URL is fetched"
    );
    let allowed = [
        "/egress",
        "/v1/messages",
        "/api/oauth/usage",
        "/api/oauth/profile",
        "/v1/oauth/token",
    ];
    for entry in &seen {
        assert!(
            allowed.contains(&entry.path.as_str()),
            "only the check URL, the exchange and the egress endpoints are reached: {}",
            entry.path
        );
    }

    // A failing check is unknown, and unknown never blocks: once the
    // cache has expired, a 500 from the check service leaves the next
    // exchange at 200.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    pinned.upstream.script([Reply::status(500, "boom")]);
    assert_eq!(
        send(pinned.addr, messages(haiku_prompt())).await.status,
        StatusCode::OK,
        "a failing check never blocks an exchange"
    );
}

/// After one instance has held and *used* all three kinds of
/// secret (the pooled credentials, a client secret with the enrollment code
/// that minted it, the operator secret), nothing it wrote anywhere but the
/// state file carries any of them: not the log, not the audit trail, not a
/// status answer, not its stdout or stderr, not its argv.
/// Hashes and verifiers are not secrets; the state file is
/// the row.
#[tokio::test(flavor = "multi_thread")]
async fn no_secret_reaches_any_surface_but_the_state_file() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("no-secret-reaches-surface", Setup::default()).await;

    // The pooled credentials go in (add_fsub uses the per-run needles), a
    // client is issued and claimed (its code and secret are needles via
    // `enroll`), and the operator secret is provisioned.
    instance.add_fsub();
    let alpha = enroll(&instance, "alpha", "Alpha Desk").await;
    let provisioned =
        control_post(instance.addr, "/control/v1/operator/secret", &[], json!({})).await;
    let operator_secret = provisioned.json()["operator_secret"]
        .as_str()
        .expect("the operator secret")
        .to_string();
    crate::leaks::register_needle("operator-secret", &operator_secret);

    // Every secret has been used: one pooled exchange, one under the client's
    // own credential, and one control read under the operator secret.
    let served = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(served.status, StatusCode::OK);
    let client_served = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &alpha.bearer())],
        ),
    )
    .await;
    assert_eq!(client_served.status, StatusCode::OK);
    let operator_bearer = format!("Bearer {operator_secret}");
    let operator_read = control(
        instance.addr,
        Method::GET,
        "/control/v1/clients",
        &[("authorization", operator_bearer.as_str())],
        None,
    )
    .await;
    assert_eq!(operator_read.status, StatusCode::OK, "{operator_read:?}");

    // Give the audit trail and the quota flusher their tick, then collect
    // everything the instance wrote outside the state file.
    instance.settle();
    let allowed = [instance.root.join("state/state.json")];
    let mut needles: Vec<String> = instance
        .needles
        .all()
        .into_iter()
        .map(String::from)
        .collect();
    needles.push(alpha.secret.clone());
    needles.push(operator_secret.clone());
    let refs: Vec<&str> = needles.iter().map(String::as_str).collect();
    let mut hits = Vec::new();
    sweep(&instance.root, &allowed, &refs, &mut hits);
    assert!(hits.is_empty(), "a secret leaked into {hits:?}");

    // The process's own stdout and stderr, and its argv.
    for surface in ["stdout.txt", "stderr.txt"] {
        let text = fs::read_to_string(instance.root.join(surface)).unwrap_or_default();
        for needle in &refs {
            assert!(
                !encodings(needle).iter().any(|f| text.contains(f)),
                "{surface} carries {needle}"
            );
        }
    }
    let argv = {
        let pid = instance.pid().to_string();
        let output = if cfg!(windows) {
            Command::new("powershell")
                .args(["-NoProfile", "-Command"])
                .arg(format!(
                    "(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"
                ))
                .output()
        } else {
            Command::new("/bin/ps")
                .args(["-o", "command=", "-p", &pid])
                .output()
        }
        .expect("the process's command line");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    assert!(!argv.trim().is_empty(), "the command line was read");
    for needle in &refs {
        assert!(
            !encodings(needle).iter().any(|f| argv.contains(f)),
            "argv carries {needle}: {argv}"
        );
    }
}

/// The trail carries no content, no
/// credential and no query: one instance is driven through the shapes that
/// could leak (a prompt with a sentinel, a model answer with another, a
/// query string with a third, and an upstream-refused exchange), then the
/// whole audit log and the whole server log are read back and none of the
/// sentinels, the enrolled bearer's secret, or the pooled-credential needles
/// appears anywhere, in any encoding a redaction bug would leave. The
/// positive side keeps the row from being vacuous: the audit records do
/// carry `path` (without its query) and the fields.
#[tokio::test(flavor = "multi_thread")]
async fn the_trail_carries_no_content_no_query_and_no_target() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with("trail-carries-no-content", Setup::default()).await;
    let alpha = enroll(&instance, "alpha", "Alpha").await;
    instance.add_fsub();

    const PROMPT: &str = "zzsentinel-prompt-4f2a";
    const ANSWER: &str = "zzsentinel-answer-4f2a";
    const QUERY: &str = "zzsentinel-query-4f2a";
    let prompt_body = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 32,
        "messages": [{ "role": "user", "content": PROMPT }],
    });
    let answer_body = json!({
        "id": "msg_fixture",
        "type": "message",
        "role": "assistant",
        "model": "claude-haiku-4-5-20251001",
        "content": [{ "type": "text", "text": ANSWER }],
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 11, "output_tokens": 7 },
    })
    .to_string();
    instance.upstream.script([
        Reply::status(200, answer_body),
        // The refused exchange: attempt → 401, forced refresh, attempt →
        // 401 again — the exchange ends 502, whose envelope is
        // the proxy's own, and the upstream 401 bodies must
        // vanish with the rest.
        reply_auth_401(),
        reply_auth_401(),
    ]);

    // The served exchange carries the prompt sentinel in its body, the
    // answer sentinel in the relayed response, and the query sentinel on
    // its request line.
    let served = send(
        instance.addr,
        with(
            post(&format!("/v1/messages?{QUERY}=1"), prompt_body.clone()),
            &[("authorization", &alpha.bearer())],
        ),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK, "{}", served.text());
    assert_eq!(served.json()["content"][0]["text"], ANSWER);

    // The refused exchange puts the error path on the trail too: the
    // upstream's 401 bodies reach nobody (the 502 is the proxy's own
    // envelope) and must leave nothing behind.
    let refused = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &alpha.bearer())],
        ),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_GATEWAY,
        "{}",
        refused.text()
    );
    assert_eq!(refused.json()["error"]["type"], "proxy_error");

    let trail = fs::read_to_string(instance.root.join("log/exchanges.ndjson")).unwrap_or_default()
        + &fs::read_to_string(instance.root.join("log/server.ndjson")).unwrap_or_default();
    for sentinel in [PROMPT, ANSWER, QUERY, alpha.secret.as_str()]
        .into_iter()
        .chain(instance.needles.all())
    {
        for form in encodings(sentinel) {
            assert!(
                !trail.contains(&form),
                "the trail carries {sentinel:?} as {form:?}"
            );
        }
    }

    // The positive side: the audit records do carry the path without its
    // query and every field, for both exchanges.
    let records = instance.audit_settled(2);
    assert_eq!(records.len(), 2, "one record per exchange");
    for record in &records {
        assert_eq!(
            record["path"], "/v1/messages",
            "the path is carried, the query string is not: {record}"
        );
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
    }
}

/// The pooled credential reaches the fixed origin and nowhere
/// else.
/// The row is a conjunction: a non-loopback override is refused at start
///A redirect is relayed, never followed, so no pooled credential
/// can reach whatever host it names; and an absolute-form forward is a plain
/// relay — no credential of ours on it, no audit record naming an account.
#[tokio::test(flavor = "multi_thread")]
async fn the_pooled_credential_reaches_the_fixed_origin_and_nowhere_else() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // (a) The override is loopback-only: anything else is refused at startup,
    // the refusal naming the setting.
    let (code, stderr) = Instance::start_expecting_failure(
        "pooled-credential-reaches-refused",
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

    // (b) A redirect is relayed as any other status and never followed: the
    // second fake is never connected to at all, so nothing pooled could have
    // reached it.
    let instance = Instance::start("pooled-credential-reaches-redirect").await;
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
    assert!(answer.header("location").is_some());
    assert_eq!(
        redirect_target.calls(),
        0,
        "no request reached the redirect target, so no pooled credential did"
    );
    let records = instance.audit_settled(1);
    assert_eq!(records[0]["status"], 302, "{records:?}");

    // (c) Absolute-form carries no credential of ours: with the
    // override active the fake is the API host for this instance, so the
    // request names the fake's own authority. A plain forward is not an
    // exchange under a pooled credential — no credential injected, no audit
    // record naming an account.
    let mitm = Instance::start_with(
        "pooled-credential-reaches-absolute",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let proxy = mitm
        .mitm_addr
        .expect("the setup asked for the proxy listener");
    let target = format!("http://{}/v1/messages", mitm.upstream.addr);
    let (status, head) = absolute_form_get(proxy, &target).await;
    assert_eq!(status, 200, "{head}");
    let seen = mitm.upstream.last();
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.path, "/v1/messages", "the forward happened: {head}");
    for name in ["authorization", "x-api-key", "anthropic-beta"] {
        assert!(
            seen.header(name).is_none(),
            "an absolute-form forward is never credentialled: {name} in {head}"
        );
    }
    assert!(
        mitm.audit().is_empty(),
        "a plain forward is not an exchange under a pooled credential: {:?}",
        mitm.audit()
    );
}

/// One absolute-form `GET` on the proxy listener: the request line, `host`
/// and `connection: close` on a raw `TcpStream`, the whole answer back. (The
/// proxy module's `absolute_form` is private to it; this row mints its own.)
async fn absolute_form_get(proxy: SocketAddr, target: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = TcpStream::connect(proxy)
        .await
        .expect("reach the proxy listener");
    let authority = target.split('/').nth(2).unwrap_or_default().to_owned();
    let head = format!("GET {target} HTTP/1.1\r\nhost: {authority}\r\nconnection: close\r\n\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write the request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read the answer");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in {text:?}"));
    (status, text)
}

/// What reaches Anthropic is what the client sent.
/// One exchange built the way Claude
/// Code sends it: the only two differences on the upstream wire are the pooled
/// credential replacing the caller's and `account_uuid` inside
/// `metadata.user_id`; and on the reply the serving organisation stays visible.
#[tokio::test(flavor = "multi_thread")]
async fn what_reaches_anthropic_is_what_the_client_sent() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("what-reaches-anthropic").await;
    instance.add_fsub();
    let pooled = format!("Bearer {}", instance.needles.access_token);

    let attribution = "You are Claude Code, Anthropic's official CLI for Claude.";
    let user_id =
        json!({ "device_id": "dev-sec-11", "account_uuid": "", "session_id": "sess-sec-11" })
            .to_string();
    let mut reply = vec![
        ("content-type".to_string(), "application/json".to_string()),
        (
            "anthropic-organization-id".to_string(),
            FIXTURE_ORG_UUID.to_string(),
        ),
        (
            "anthropic-ratelimit-unified-5h-utilization".to_string(),
            "0.12".to_string(),
        ),
    ];
    reply.extend(ratelimit_headers_oauth());
    instance.upstream.script([Reply::Raw {
        status: 200,
        headers: reply,
        body: message_body().to_string(),
    }]);

    let answer = send(
        instance.addr,
        with(
            messages(json!({
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 32,
                "system": [{ "type": "text", "text": attribution }],
                "metadata": { "user_id": user_id },
                "messages": [{ "role": "user", "content": "hi" }],
            })),
            &[
                ("user-agent", "claude-cli/2.0.1 (external, cli)"),
                ("x-app", "cli"),
                ("x-stainless-lang", "js"),
                ("x-claude-code-session-id", "sess-sec-11"),
                ("anthropic-beta", "oauth-2025-04-20"),
                ("authorization", "Bearer client-side-not-pooled"),
            ],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());

    // The upstream wire, one assertion per row of the table.
    let seen = instance.upstream.last();
    assert_eq!(
        seen.header("user-agent"),
        Some("claude-cli/2.0.1 (external, cli)"),
        "forwarded unchanged: {:?}",
        seen.headers
    );
    assert_eq!(seen.header("x-app"), Some("cli"), "forwarded unchanged");
    assert_eq!(
        seen.header("x-stainless-lang"),
        Some("js"),
        "forwarded unchanged"
    );
    assert_eq!(
        seen.header("x-claude-code-session-id"),
        Some("sess-sec-11"),
        "forwarded unchanged"
    );
    let body = seen.json();
    let inner: Value = serde_json::from_str(
        body["metadata"]["user_id"]
            .as_str()
            .expect("user_id stays a JSON string"),
    )
    .expect("user_id holds an object");
    assert_eq!(inner["device_id"], "dev-sec-11", "untouched");
    assert_eq!(inner["session_id"], "sess-sec-11", "untouched");
    assert_eq!(
        inner["account_uuid"], FIXTURE_ACCOUNT_UUID,
        "rewritten to the serving account, the metadata agrees with the credential"
    );
    assert_eq!(
        body["system"][0]["text"], attribution,
        "the attribution block is byte-identical"
    );
    assert_eq!(
        body["model"], "claude-haiku-4-5-20251001",
        "the requested model is never rewritten"
    );

    // The only two differences: the credential and the uuid inside user_id.
    assert_eq!(
        seen.header("authorization"),
        Some(pooled.as_str()),
        "the pooled credential replaced the caller's, it was not forwarded alongside"
    );
    assert!(
        !seen
            .headers
            .iter()
            .any(|(_, value)| value.contains("client-side-not-pooled")),
        "the caller's own credential appears nowhere upstream: {:?}",
        seen.headers
    );

    // The client side of the same claim: the serving organisation is
    // visible on the reply, with the rate-limit state beside it.
    assert_eq!(
        answer.header("anthropic-organization-id"),
        Some(FIXTURE_ORG_UUID)
    );
    assert_eq!(
        answer.header("anthropic-ratelimit-unified-5h-utilization"),
        Some("0.12")
    );
}
