//! Engineer `status` — the human, `--line` and `--json` forms, the MITM
//! probe's four outcomes, and one request per run. The enrollment refusal
//! lives in `bundle.rs`.

#[allow(unused_imports)]
use crate::client_fx::*;
#[allow(unused_imports)]
use crate::harness::*;

/// `status` shows the
/// allow-listed facts only, in both forms: no other account, no other
/// principal, no identity, no quota.
#[tokio::test(flavor = "multi_thread")]
async fn status_shows_the_allow_listed_facts_only() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("status-shows-allow").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let _other = enroll(&instance, "other-1", "Other Desk").await;
    const SID: &str = "3f7a2c1e-0000-4000-8000-00000000c0de";
    let answer = send(
        instance.addr,
        in_session(
            with(
                messages(haiku_prompt()),
                &[("authorization", &machine.client.bearer())],
            ),
            SID,
        ),
    )
    .await;
    assert_eq!(answer.status, 200, "the routed exchange: {answer:?}");

    let (code, stdout, stderr) =
        machine.jaynshare(&["status", "--json", "--session", SID], &[], None);
    assert_eq!(code, 0, "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
    assert_eq!(envelope["ok"], json!(true), "{envelope}");
    let result = &envelope["result"];
    let keys: Vec<&str> = result
        .as_object()
        .expect("result")
        .keys()
        .map(String::as_str)
        .collect();
    for key in keys {
        assert!(
            [
                "client",
                "server",
                "capabilities",
                "ca_fingerprint",
                "pool",
                "sessions",
                "wire_capture_enabled",
                "hold_hint_seconds",
                "session",
                "captured_at",
                // The probe host, which every status now asks.
                "probe",
                // Every read carries the envelope's version member.
                "control_api_version",
            ]
            .contains(&key),
            "an unexpected key {key}"
        );
    }
    for key in [
        "client",
        "server",
        "pool",
        "sessions",
        "wire_capture_enabled",
        "session",
        "probe",
    ] {
        assert!(result.get(key).is_some(), "missing {key}");
    }
    assert_eq!(
        result["client"]
            .as_object()
            .expect("client")
            .keys()
            .collect::<Vec<_>>(),
        ["id", "display_name", "origins"],
        "client's nested keys: {result}"
    );
    assert_eq!(
        result["server"]
            .as_object()
            .expect("server")
            .keys()
            .collect::<Vec<_>>(),
        ["version", "available", "control_api_version", "tls_pin"],
        "server's nested keys: {result}"
    );
    assert_eq!(
        result["pool"]
            .as_object()
            .expect("pool")
            .keys()
            .collect::<Vec<_>>(),
        ["accounts_configured", "accounts_selectable"],
        "pool's nested keys: {result}"
    );
    assert_eq!(
        result["sessions"]
            .as_object()
            .expect("sessions")
            .keys()
            .collect::<Vec<_>>(),
        ["known", "active"],
        "sessions' nested keys: {result}"
    );
    assert_eq!(
        result["session"]
            .as_object()
            .expect("session")
            .keys()
            .collect::<Vec<_>>(),
        ["serving_account_display_name", "last_routed_at"],
        "session's nested keys: {result}"
    );
    assert_eq!(
        result["session"]["serving_account_display_name"],
        json!("FSUB")
    );

    let (code, human, stderr) = machine.jaynshare(&["status", "--session", SID], &[], None);
    assert_eq!(code, 0, "{stderr}");
    let first = human.lines().next().expect("the first line");
    assert!(first.starts_with("client:"), "{human}");
    assert!(
        first.contains("engineer-1")
            && first.contains("Engineer One")
            && first.contains(&machine.base_url),
        "the first line names the client and the origins: {first}"
    );
    assert!(human.contains("served by FSUB"), "{human}");
    assert!(human.contains("capture:"), "{human}");
    assert!(human.contains("pool:"), "{human}");

    // No other account, no other principal, no identity, no quota.
    let forbidden = [
        "FSUB2",
        "other-1",
        "Other Desk",
        "@",
        "utilization",
        "reset",
        "eligib",
        FIXTURE_ORG_UUID,
    ];
    for needle in forbidden {
        assert!(!stdout.contains(needle), "the JSON form names {needle}");
        assert!(!human.contains(needle), "the human form names {needle}");
    }
}

/// `status` makes one request, then exits:
/// no further connection once the process is gone.
#[tokio::test(flavor = "multi_thread")]
async fn status_makes_one_request_and_exits() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("status-makes-request").await;
    let machine = install_client(&instance).await;
    let mut body = snapshot_body(None);
    body["control_api_version"] = json!(1);
    let fake = FakeControl::answering(200, body);
    machine.set("base_url", &format!("{:?}", fake.origin()));

    let started = Instant::now();
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(started.elapsed() < Duration::from_secs(5), "under 5 s");
    assert_eq!(fake.seen().len(), 1, "one request: {:?}", fake.seen());

    // The process has exited; it can open no further connection.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(fake.seen().len(), 1, "no further request after the exit");
}

const ZERO_FINGERPRINT: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The probe's four outcomes:
/// healthy, CA mismatch (the 12, `cli_ca_mismatch`), CA not trusted
/// (`cli_ca_untrusted`), credential refused (5, `cli_refused`) and
/// unreachable (4, `cli_unreachable`). The secret never reaches a stream.
#[tokio::test(flavor = "multi_thread")]
async fn the_probe_tells_the_four_outcomes_apart() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "probe-tells-four",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let machine = install_client(&instance).await;
    let secret = machine.client.secret.clone();

    // healthy: both forms answer, the fingerprint matches, and only the
    // tunnel form speaks TLS.
    let (code, stdout, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
    assert_eq!(code, 0, "status --json: {stderr}");
    assert!(!stdout.contains(&secret), "the secret never reaches stdout");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
    assert_eq!(envelope["ok"], json!(true), "{envelope}");
    let probe = &envelope["result"]["probe"];
    assert_eq!(probe["outcome"], "healthy", "{probe}");
    assert_eq!(probe["fingerprint_matches"], json!(true), "{probe}");
    assert_eq!(probe["tunnel"]["tls"], json!(true), "{probe}");
    assert_eq!(probe["absolute"]["tls"], json!(false), "{probe}");
    let (code, stdout, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 0, "status: {stderr}");
    assert!(
        stdout.contains("probe:"),
        "the human form names the probe: {stdout}"
    );
    assert!(!stdout.contains(&secret), "the secret never reaches stdout");
    assert!(!stderr.contains(&secret), "the secret never reaches stderr");

    // CA mismatch: the client.toml fingerprint names another CA.
    let toml = fs::read_to_string(machine.client_dir.join("client.toml")).expect("client.toml");
    let original = toml
        .lines()
        .find(|line| line.starts_with("ca_fingerprint = "))
        .expect("ca_fingerprint line")
        .trim_start_matches("ca_fingerprint = ")
        .to_owned();
    machine.set("ca_fingerprint", &format!("{ZERO_FINGERPRINT:?}"));
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 12, "mismatch exits the 12: {stderr}");
    assert!(
        stderr.starts_with("cli_ca_mismatch:"),
        "mismatch is cli_ca_mismatch: {stderr}"
    );
    assert!(
        stderr.contains("ca-update"),
        "mismatch names the CA update: {stderr}"
    );
    machine.set("ca_fingerprint", &original);

    // CA not trusted: the TLS form fails against another instance's CA.
    let other = Instance::start_with(
        "probe-tells-four-other",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let ca_pem = machine.client_dir.join("ca.pem");
    let original_ca = fs::read(&ca_pem).expect("the original ca.pem");
    fs::copy(other.root.join("state/mitm-ca.pem"), &ca_pem).expect("plant the other CA");
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 12, "untrusted exits the 12: {stderr}");
    assert!(
        stderr.starts_with("cli_ca_untrusted:"),
        "untrusted is cli_ca_untrusted: {stderr}"
    );
    fs::write(&ca_pem, original_ca).expect("restore ca.pem");

    // credential refused: a proxy answering 407 on both forms.
    let proxy = FakeControl::answering(407, json!({"error": "proxy auth"}));
    machine.set("proxy_url", &format!("{:?}", proxy.origin()));
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 5, "refused exits the 5: {stderr}");
    assert!(
        stderr.starts_with("cli_refused:"),
        "refused is cli_refused: {stderr}"
    );
    drop(proxy);

    // unreachable: nothing listens there.
    machine.set("proxy_url", "\"http://127.0.0.1:1\"");
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 4, "unreachable exits the 4: {stderr}");
    assert!(
        stderr.starts_with("cli_unreachable:"),
        "unreachable is cli_unreachable: {stderr}"
    );
}

/// One failure class of, both forms: the human refusal is
/// `<slug>: <message>` on stderr with the exit code; `--json` prints
/// the envelope with `ok == false` and `error.code == slug`. No stream
/// ever carries the client secret.
fn refuse_with(machine: &ClientHome, code: i32, slug: &str, needle: Option<&str>) {
    let (exit, stdout, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(exit, code, "{slug}: {stdout}{stderr}");
    assert!(
        stderr.starts_with(&format!("{slug}:")),
        "the human form is the slug: {stderr}"
    );
    if let Some(needle) = needle {
        assert!(stderr.contains(needle), "{slug} names {needle}: {stderr}");
    }
    assert!(!stdout.contains(&machine.client.secret), "{stdout}");
    assert!(!stderr.contains(&machine.client.secret), "{stderr}");

    let (exit, stdout, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
    assert_eq!(exit, code, "{slug} --json: {stdout}{stderr}");
    assert!(!stderr.contains(&machine.client.secret), "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
    assert_eq!(envelope["ok"], json!(false), "{envelope}");
    assert_eq!(envelope["error"]["code"], slug, "{envelope}");
    if let Some(needle) = needle {
        assert!(
            envelope["error"]["message"]
                .as_str()
                .expect("the message")
                .contains(needle),
            "{slug} names {needle}: {envelope}"
        );
    }
    assert!(!stdout.contains(&machine.client.secret), "{stdout}");
}

/// `status`'s four failure
/// classes each have their own exit code and slug, human and JSON forms
/// alike. The revoked-credential case lives in `bundle.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn each_status_failure_class_has_its_code() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // 11: not enrolled — first `client.toml` missing, then the secret file.
    let instance = Instance::start_client("refused-credential-exit-b").await;
    let machine = install_client(&instance).await;
    let toml_path = machine.client_dir.join("client.toml");
    let toml = fs::read(&toml_path).expect("client.toml");
    fs::remove_file(&toml_path).expect("remove client.toml");
    refuse_with(&machine, 11, "cli_not_enrolled", Some("client.toml"));
    fs::write(&toml_path, toml).expect("restore client.toml");

    let secret_path = machine.client_dir.join("client-secret");
    let secret_file = fs::read(&secret_path).expect("client-secret");
    fs::remove_file(&secret_path).expect("remove client-secret");
    refuse_with(&machine, 11, "cli_not_enrolled", Some("client-secret"));
    fs::write(&secret_path, &secret_file).expect("restore client-secret");
    write_private(
        &secret_path,
        &String::from_utf8(secret_file).expect("the restored secret"),
    );

    // 4: unreachable — nothing listens there.
    machine.set("base_url", "\"http://127.0.0.1:1\"");
    refuse_with(&machine, 4, "cli_unreachable", Some("http://127.0.0.1:1"));

    // 5: credential refused — the server answers 401 to everything.
    let fake = FakeControl::answering(
        401,
        json!({"error": {"type": "authentication_error", "message": "invalid x-api-key"}}),
    );
    machine.set("base_url", &format!("{:?}", fake.origin()));
    refuse_with(&machine, 5, "cli_refused", Some("x-api-key"));
    drop(fake);

    // 12, both slugs: a MITM installation whose fingerprint names another
    // CA, then one holding another instance's CA.
    let mitm = Instance::start_with(
        "refused-credential-exit-b-mitm",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let machine = install_client(&mitm).await;
    let toml_path = machine.client_dir.join("client.toml");
    let original = fs::read_to_string(&toml_path)
        .expect("client.toml")
        .lines()
        .find(|line| line.starts_with("ca_fingerprint = "))
        .expect("the ca_fingerprint line")
        .trim_start_matches("ca_fingerprint = ")
        .to_owned();
    machine.set("ca_fingerprint", &format!("{ZERO_FINGERPRINT:?}"));
    refuse_with(&machine, 12, "cli_ca_mismatch", None);
    machine.set("ca_fingerprint", &original);

    let other = Instance::start_with(
        "refused-credential-exit-b-other",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let ca_pem = machine.client_dir.join("ca.pem");
    let original_ca = fs::read(&ca_pem).expect("the original ca.pem");
    fs::copy(other.root.join("state/mitm-ca.pem"), &ca_pem).expect("plant the other CA");
    refuse_with(&machine, 12, "cli_ca_untrusted", None);
    fs::write(&ca_pem, original_ca).expect("restore ca.pem");
}

/// One failure class through the three forms of engineer `status` (the
/// exit codes are the same whichever form is asked for).
fn three_forms_refuse(machine: &ClientHome, code: i32, slug: &str) {
    for args in [
        &["status"][..],
        &["status", "--line"][..],
        &["status", "--json"][..],
    ] {
        let (exit, stdout, stderr) = machine.jaynshare(args, &[("NO_COLOR", "1")], None);
        assert_eq!(exit, code, "{args:?}: {stdout}{stderr}");
        if args.contains(&"--json") {
            let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
            assert_eq!(
                envelope["error"]["code"],
                json!(slug),
                "{args:?}: {envelope}"
            );
        } else {
            assert!(
                stderr.starts_with(&format!("{slug}:")),
                "{args:?}: {stderr}"
            );
        }
    }
}

/// `status --line` prints exactly the status-line
/// text, `--json` is the body plus the origins (and `probe` in MITM
/// mode), and the four exit codes hold for every form.
#[tokio::test(flavor = "multi_thread")]
async fn status_line_equals_the_status_line_text() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("status-line-equals").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    const SID: &str = "3f7a2c1e-0000-4000-8000-00000000c0de";
    let answer = send(
        instance.addr,
        in_session(
            with(
                messages(haiku_prompt()),
                &[("authorization", &machine.client.bearer())],
            ),
            SID,
        ),
    )
    .await;
    assert_eq!(answer.status, 200, "the routed exchange: {answer:?}");

    let plain = [("NO_COLOR", "1"), ("JAYNSHARE_STATUSLINE", "1")];
    let (code, line, stderr) =
        machine.jaynshare(&["status", "--line", "--session", SID], &plain, None);
    assert_eq!(code, 0, "{stderr}");
    let (code, hook_line, stderr) =
        machine.jaynshare(&["statusline"], &plain, Some(&statusline_payload(SID)));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        line, hook_line,
        "`status --line` is the status line, byte for byte"
    );
    assert_eq!(line.lines().count(), 1, "{line:?}");
    assert!(line.starts_with("jaynshare → FSUB "), "{line:?}");

    let (code, stdout, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
    let result = &envelope["result"];
    assert_eq!(
        result["client"]["origins"]["base_url"],
        json!(machine.base_url),
        "{result}"
    );
    assert!(
        result.get("probe").is_some(),
        "every status asks the probe host: {result}"
    );

    // 11, 4, 5 in every form.
    let toml_path = machine.client_dir.join("client.toml");
    let toml = fs::read(&toml_path).expect("client.toml");
    fs::remove_file(&toml_path).expect("remove client.toml");
    three_forms_refuse(&machine, 11, "cli_not_enrolled");
    fs::write(&toml_path, toml).expect("restore client.toml");
    machine.set("base_url", "\"http://127.0.0.1:1\"");
    three_forms_refuse(&machine, 4, "cli_unreachable");
    let fake = FakeControl::answering(
        401,
        json!({"error": {"type": "authentication_error", "message": "invalid x-api-key"}}),
    );
    machine.set("base_url", &format!("{:?}", fake.origin()));
    three_forms_refuse(&machine, 5, "cli_refused");

    // 12 in every form, from the MITM probe.
    let mitm = Instance::start_with(
        "status-line-equals-mitm",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let machine = install_client(&mitm).await;
    let (code, stdout, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
    assert_eq!(
        envelope["result"]["probe"]["outcome"],
        json!("healthy"),
        "{envelope}"
    );
    machine.set("ca_fingerprint", &format!("{ZERO_FINGERPRINT:?}"));
    three_forms_refuse(&machine, 12, "cli_ca_mismatch");
}

/// The human, one-line and JSON forms
/// each render their intended facts from one server answer. The compact line
/// carries only account selection and the two shared rate-limit windows. One
/// request per form.
#[tokio::test(flavor = "multi_thread")]
async fn the_three_forms_of_status_agree() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("three-forms-status").await;
    let machine = install_client(&instance).await;
    let mut body = snapshot_body(Some("Zed Account"));
    body["pool"] = json!({ "accounts_configured": 9, "accounts_selectable": 7 });
    body["sessions"] = json!({ "known": 11, "active": 4 });
    body["wire_capture_enabled"] = json!(true);
    body["hold_hint_seconds"] = json!(45);
    body["accounts"] = json!([
        {
            "display_name": "Zed Account",
            "rate_limits": { "five_hour": 0.12, "weekly": 0.34 },
        },
        {
            "display_name": "Other Account",
            "rate_limits": { "five_hour": null, "weekly": 1.0 },
        },
    ]);
    let fake = FakeControl::answering(200, body);
    machine.set("base_url", &format!("{:?}", fake.origin()));
    const SID: &str = "3f7a2c1e-0000-4000-8000-00000000c0de";
    let plain = [("NO_COLOR", "1")];

    let form = |args: &[&str]| {
        let before = fake.seen().len();
        let (code, stdout, stderr) = machine.jaynshare(args, &plain, None);
        assert_eq!(code, 0, "{args:?}: {stderr}");
        assert_eq!(
            fake.seen().len(),
            before + 1,
            "{args:?}: one request per form"
        );
        stdout
    };
    let line = form(&["status", "--line", "--session", SID]);
    let human = form(&["status", "--session", SID]);
    let json_out = form(&["status", "--json", "--session", SID]);
    let result =
        serde_json::from_str::<Value>(json_out.trim()).expect("the envelope")["result"].clone();

    // The line's only facts are the picked account, every account's limits
    // and the active count.
    for fact in [
        "→ Zed Account ",
        "12%/34%",
        "Other Account",
        "?/100%",
        "4 active",
    ] {
        assert!(line.contains(fact), "line lacks {fact:?}: {line}");
    }
    for unrelated in ["7/9", "capture", "hold"] {
        assert!(
            !line.contains(unrelated),
            "line includes {unrelated:?}: {line}"
        );
    }
    // The human form keeps its broader diagnostic facts.
    for fact in ["Zed Account", "7 of 9", "4 active", "11 known", "ON", "45"] {
        assert!(human.contains(fact), "human form lacks {fact:?}: {human}");
    }
    // And every human fact is in the JSON, at its path.
    assert_eq!(
        result["session"]["serving_account_display_name"],
        json!("Zed Account")
    );
    assert_eq!(result["pool"]["accounts_selectable"], json!(7));
    assert_eq!(result["pool"]["accounts_configured"], json!(9));
    assert_eq!(result["sessions"]["active"], json!(4));
    assert_eq!(result["sessions"]["known"], json!(11));
    assert_eq!(result["wire_capture_enabled"], json!(true));
    assert_eq!(result["hold_hint_seconds"], json!(45));
    for text in [&line, &human, &json_out] {
        assert!(
            !text.contains("FSUB"),
            "a value the server did not send: {text}"
        );
    }
}
