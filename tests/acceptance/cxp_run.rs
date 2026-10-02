//! The launcher — its grammar and pass-through, the checks before a launch,
//! account intent, and the environment each mode builds, plus `env` and
//! `alias`.
//!
//! Every test runs the release binary with a `ClientHome`: an enrolled
//! installation under a scratch home and the fake `claude` on `PATH`
//! (`client_fx`). What reached Claude Code is `machine.claude_ran`.

use crate::client_fx::*;
use crate::harness::*;
use crate::proxy::claude_request;

use std::fs;
use std::time::Duration;
use std::time::Instant;

/// No launch points Claude Code at the base URL: Claude Code trusts
/// only the proxy's CA, replacing an inherited anchor, while an unpinned
/// `https` base URL trusts the `base-url-ca.pem` for the launcher's own
/// calls, and without it the system store alone.
#[tokio::test(flavor = "multi_thread")]
async fn claude_code_never_gets_the_base_url() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("claude-code-never-gets-base").await;
    let machine = install_client(&instance).await;
    let ca = machine.client_dir.join("ca.pem").display().to_string();
    let (code, _, stderr) = machine.jaynshare(
        &["claude", "--auto", "--", "-p", "hello"],
        &[
            ("ANTHROPIC_BASE_URL", "http://stale.invalid:1"),
            ("NODE_EXTRA_CA_CERTS", "/stale/anchor.pem"),
        ],
        None,
    );
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.argv, ["-p", "hello"], "");
    assert!(
        !seen.env.contains_key("ANTHROPIC_BASE_URL"),
        "no base URL, inherited or not"
    );
    assert_eq!(
        seen.env.get("NODE_EXTRA_CA_CERTS"),
        Some(&ca),
        "the proxy's CA replaces an inherited anchor"
    );
    assert_eq!(
        seen.env.get("JAYNSHARE_STATUSLINE").map(String::as_str),
        Some("1"),
        "only a pooled `jaynshare claude` enables its installed status line"
    );

    // An `https` base URL is the launcher's own origin (snapshot,
    // catalogue); it trusts the `base-url-ca.pem` there, and Claude
    // Code still gets only the proxy's CA. A TLS front with the test pair
    // stands before the plain listener. An enrollment there carries no
    // pin, so the one the plain launch above learned goes.
    let https = tls_front(instance.addr, &instance.root.join("tls-front")).await;
    machine.set("base_url", &format!("{https:?}"));
    machine.set("server_identity", "\"\"");
    let anchor = machine.client_dir.join("base-url-ca.pem");
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/acceptance/fixtures/tls/test-ca.pem"),
        &anchor,
    )
    .expect("base-url-ca.pem");
    let (code, _, stderr) =
        machine.jaynshare(&["claude", "--auto", "--", "-p", "hello"], &[], None);
    assert_eq!(code, 0, "the https launch: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert!(!seen.env.contains_key("ANTHROPIC_BASE_URL"), "");
    assert_eq!(
        seen.env.get("NODE_EXTRA_CA_CERTS"),
        Some(&ca),
        "base-url-ca.pem is the launcher's anchor, not Claude Code's"
    );

    // Without the anchor only the system store is trusted, which does not
    // know the front's CA.
    std::fs::remove_file(&anchor).expect("move the anchor aside");
    let (code, _, stderr) = machine.jaynshare(&["status", "--client"], &[], None);
    assert_eq!(code, 4, "{stderr}");
}

/// Two intent flags in one launch are refused by
/// clap with exit 2, naming the conflict, before anything runs.
#[tokio::test(flavor = "multi_thread")]
async fn two_intent_flags_refuse_before_anything() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("two-intent-flags").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    for (first, second, args) in [
        (
            "--account",
            "--auto",
            vec!["claude", "--account", "FSUB", "--auto"],
        ),
        ("--auto", "--direct", vec!["claude", "--auto", "--direct"]),
        (
            "--account",
            "--direct",
            vec!["claude", "--account", "FSUB", "--direct"],
        ),
        (
            "--direct",
            "--auto",
            vec!["claude", "--direct", "--auto", "--", "-p", "x"],
        ),
    ] {
        let (code, _, stderr) = machine.jaynshare(&args, &[], None);
        assert_eq!(code, 2, "exit 2 for {first} with {second}: {stderr}");
        assert!(
            stderr.contains(first) && stderr.contains(second),
            "the message names both flags: {stderr}"
        );
        assert!(
            machine.claude_ran().is_none(),
            "nothing runs when the flags conflict"
        );
    }
}

/// `claude`'s exit rows
/// before it replaces itself, each printed as `<slug>: …`; after the
/// replacement the exit code is Claude Code's own.
#[tokio::test(flavor = "multi_thread")]
async fn run_exit_rows_before_the_replacement() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("run-exit-rows-replacement").await;
    add_two(&instance);
    let machine = install_client(&instance).await;

    // Claude Code's own exit code survives the replacement.
    let (code, _, stderr) =
        machine.jaynshare(&["claude", "--auto"], &[("FAKE_CLAUDE_EXIT", "3")], None);
    assert_eq!(code, 3, "the fake's exit code: {stderr}");
    assert!(machine.claude_ran().is_some(), "Claude Code was launched");

    // 6: an account reference nothing matches.
    let (code, _, stderr) =
        machine.jaynshare(&["claude", "--account", "no-such-account"], &[], None);
    assert_eq!(code, 6, "{stderr}");
    assert!(stderr.starts_with("cli_not_found:"), "{stderr}");
    assert!(machine.claude_ran().is_none(), "nothing ran");

    // 7: a reference that matches two accounts names them both.
    let (code, _, stderr) =
        machine.jaynshare(&["claude", "--account", FIXTURE_ORG_UUID], &[], None);
    assert_eq!(code, 7, "{stderr}");
    assert!(stderr.starts_with("cli_ambiguous:"), "{stderr}");
    assert!(
        stderr.contains("FSUB") && stderr.contains("FSUB2"),
        "names both matches: {stderr}"
    );
    assert!(machine.claude_ran().is_none(), "nothing ran");

    // 14: the installation has no `ca.pem`, which every launch needs, and
    // the server to fetch it from does not answer.
    let ca = machine.client_dir.join("ca.pem");
    let served = fs::read(&ca).expect("ca.pem");
    fs::remove_file(&ca).expect("remove ca.pem");
    machine.set("base_url", "\"http://127.0.0.1:1\"");
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 14, "{stderr}");
    assert!(stderr.starts_with("cli_transport_unavailable:"), "{stderr}");
    assert!(stderr.contains("could not be fetched"), "{stderr}");
    assert!(machine.claude_ran().is_none(), "nothing ran");
    machine.set("base_url", &format!("{:?}", machine.base_url));
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the server's CA is fetched: {stderr}");
    assert!(machine.claude_ran().is_some(), "Claude Code was launched");
    assert_eq!(fs::read(&ca).expect("ca.pem"), served);

    // 4: the proxy the launch check goes through is unreachable.
    machine.set("proxy_url", "\"http://127.0.0.1:1\"");
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 4, "{stderr}");
    assert!(stderr.starts_with("cli_unreachable:"), "{stderr}");
    assert!(machine.claude_ran().is_none(), "nothing ran");
    machine.set("proxy_url", &format!("{:?}", machine.proxy));

    // 13: no `claude` on the search path.
    machine.remove_claude();
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 13, "{stderr}");
    assert!(stderr.starts_with("cli_claude_missing:"), "{stderr}");

    // 11: the installation is gone.
    fs::remove_file(machine.client_dir.join("client.toml")).expect("remove client.toml");
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 11, "{stderr}");
    assert!(stderr.starts_with("cli_not_enrolled:"), "{stderr}");

    // 2: two intent flags — clap's own usage error, no slug line.
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto", "--direct"], &[], None);
    assert_eq!(code, 2, "{stderr}");
}

/// Every argument after the launcher's own
/// options, and everything after an explicit `--`, reaches Claude Code
/// unchanged and in order, even when it looks like a launcher option.
#[tokio::test(flavor = "multi_thread")]
async fn claude_arguments_pass_through_in_order() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("claude-arguments-pass").await;
    let machine = install_client(&instance).await;
    for (args, expected) in [
        (
            vec!["claude", "--auto", "-p", "--model", "haiku", "say hi"],
            vec!["-p", "--model", "haiku", "say hi"],
        ),
        (
            vec!["claude", "--auto", "--debug", "-p", "x"],
            vec!["--debug", "-p", "x"],
        ),
        (vec!["claude", "--auto", "--", "--debug"], vec!["--debug"]),
        (
            vec![
                "claude",
                "--auto",
                "--",
                "-p",
                "--",
                "--account",
                "FSUB",
                "--auto",
            ],
            vec!["-p", "--", "--account", "FSUB", "--auto"],
        ),
        (
            vec!["claude", "--direct", "--", "--mode", "mitm"],
            vec!["--mode", "mitm"],
        ),
        (vec!["claude", "--auto"], vec![]),
    ] {
        let (code, _, stderr) = machine.jaynshare(&args, &[], None);
        assert_eq!(code, 0, "the fake exits 0: {stderr}");
        let seen = machine.claude_ran().expect("Claude Code was launched");
        assert_eq!(seen.argv, expected, "{args:?}");
    }
}

/// The launcher replaces its own process with
/// Claude Code, so whatever exit code the fake `claude` produces reaches the
/// shell unchanged, in both modes.
#[tokio::test(flavor = "multi_thread")]
async fn claude_codes_exit_code_is_the_launchers() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("claude-codes-exit").await;
    let machine = install_client(&instance).await;
    for exit in ["0", "3", "42", "255"] {
        for mode in ["--auto", "--direct"] {
            let extra_env = [("FAKE_CLAUDE_EXIT", exit)];
            let args = ["claude", mode];
            let (code, _, stderr) = machine.jaynshare(&args, &extra_env, None);
            assert_eq!(
                code,
                exit.parse::<i32>().unwrap(),
                "the fake's exit {exit} reaches the shell: {stderr}"
            );
            assert!(machine.claude_ran().is_some(), ": Claude Code was launched");
        }
    }
}

/// With no `claude` on the search path, every
/// launch mode refuses before any pooled environment is built, naming what
/// to install.
#[tokio::test(flavor = "multi_thread")]
async fn no_claude_on_the_path_refuses() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("no-claude-path-refuses").await;
    let machine = install_client(&instance).await;
    machine.remove_claude();
    for args in [
        vec!["claude", "--auto"],
        vec!["claude", "--account", "anything"],
        vec!["claude", "--direct"],
    ] {
        let (code, stdout, stderr) = machine.jaynshare(&args, &[], None);
        assert_eq!(code, 13, ", for {args:?}: {stderr}");
        assert!(stdout.is_empty(), "nothing on stdout for {args:?}");
        assert!(
            stderr.starts_with("cli_claude_missing:"),
            "for {args:?}: {stderr}"
        );
        assert!(stderr.contains("Claude Code"), "for {args:?}: {stderr}");
        assert!(stderr.contains("install"), "for {args:?}: {stderr}");
        assert!(
            machine.claude_ran().is_none(),
            "Claude Code never started for {args:?}"
        );
    }
}

/// Each missing file is named
/// with the join to run, and the secret never appears; restoring the
/// file launches again. Without `ca.pem` the launch is impossible
/// (exit 14) and the refusal names the file and the CA update that installs
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn each_missing_client_file_is_named() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("missing-client-file").await;
    let machine = install_client(&instance).await;
    for name in ["client.toml", "client-secret"] {
        let path = machine.client_dir.join(name);
        let bytes = std::fs::read(&path).expect(name);
        std::fs::remove_file(&path).expect(name);
        let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
        assert_eq!(code, 11, ", without {name}: {stderr}");
        assert!(
            stderr.starts_with("cli_not_enrolled:"),
            "without {name}: {stderr}"
        );
        assert!(stderr.contains(name), "the missing file is named: {stderr}");
        assert!(
            stderr.contains("jaynshare join"),
            "the join is named: {stderr}"
        );
        assert!(
            !stderr.contains(&machine.client.secret),
            "the secret never appears: {stderr}"
        );
        assert!(
            machine.claude_ran().is_none(),
            "Claude Code never started without {name}"
        );
        std::fs::write(&path, &bytes).expect(name);
        #[cfg(unix)]
        if name == "client-secret" {
            // the original file is private; write restored it 0644
            let mut mode = std::fs::metadata(&path).expect(name).permissions();
            use std::os::unix::fs::PermissionsExt;
            mode.set_mode(0o600);
            std::fs::set_permissions(&path, mode).expect(name);
        }
        let (code, stdout, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
        assert_eq!(code, 0, "restored {name}: {stderr}");
        assert!(stdout.is_empty(), "restored {name}");
        assert!(
            machine.claude_ran().is_some(),
            "Claude Code launched again with {name} restored"
        );
    }

    // `ca.pem` is the server's to hand out: the launch fetches it.
    let ca = machine.client_dir.join("ca.pem");
    let bytes = std::fs::read(&ca).expect("ca.pem");
    std::fs::remove_file(&ca).expect("ca.pem");
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "without ca.pem: {stderr}");
    assert_eq!(std::fs::read(&ca).expect("ca.pem"), bytes);
    assert!(machine.claude_ran().is_some(), "launched again");
}

/// When the proxy the launch check
/// goes through refuses the connection or accepts it and gives no
/// application answer, the launcher
/// refuses within 1.5 s naming the origin and the `--direct` way out, and
/// never falls back to launching Claude Code outside the pool; a foreign CA
/// stays exit 12 and a revoked credential exit 5. `--direct` on a stopped
/// server still launches.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_listener_refuses_and_names_direct() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // 1. An enrolled machine whose server is stopped but still named in
    // `client.toml`: `claude --auto` refuses fast, naming the origin.
    let mut instance = Instance::start_client("unreachable-listener-refuses").await;
    let machine = install_client(&instance).await;
    instance.stop();

    let started = Instant::now();
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    let elapsed = started.elapsed();
    assert_eq!(code, 4, "cli_unreachable: {stderr}");
    assert!(
        stderr.starts_with("cli_unreachable:"),
        "the refusal names its slug: {stderr}"
    );
    assert!(
        stderr.contains(&machine.proxy),
        "the proxy origin is named: {stderr}"
    );
    assert!(
        stderr.contains("--direct"),
        "the way out is named: {stderr}"
    );
    assert!(
        machine.claude_ran().is_none(),
        "no direct launch behind the refusal"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the check is quick, not a hang: {elapsed:?}"
    );

    // 2. The reachability check precedes any account read: `--account` on the
    // stopped server refuses with the same code.
    let (code, _, stderr) = machine.jaynshare(&["claude", "--account", "FSUB"], &[], None);
    assert_eq!(code, 4, "still cli_unreachable: {stderr}");
    assert!(
        stderr.starts_with("cli_unreachable:"),
        "the refusal names its slug: {stderr}"
    );
    assert!(
        machine.claude_ran().is_none(),
        "no launch on the refusal either"
    );

    // 3. `--direct` is the explicit way out: it launches Claude Code even
    // though the server is stopped.
    let (code, _, stderr) = machine.jaynshare(&["claude", "--direct"], &[], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    assert!(
        machine.claude_ran().is_some(),
        "--direct launches outside the pool"
    );

    // 4. On a running server, pointing `proxy_url` at a dead port makes
    // `claude --auto` refuse naming it.
    let mitm = Instance::start_with(
        "unreachable-listener-refuses-mitm",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let mitm_machine = install_client(&mitm).await;
    mitm_machine.set("proxy_url", "\"http://127.0.0.1:1\"");
    let (code, _, stderr) = mitm_machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 4, "cli_unreachable: {stderr}");
    assert!(
        stderr.starts_with("cli_unreachable:"),
        "the refusal names its slug: {stderr}"
    );
    assert!(
        stderr.contains("http://127.0.0.1:1"),
        "the proxy origin is the one checked: {stderr}"
    );
    assert!(
        stderr.contains("--direct"),
        "the way out is named: {stderr}"
    );
    assert!(
        mitm_machine.claude_ran().is_none(),
        "no direct launch behind the refusal"
    );

    // 5.: a proxy that accepts and never answers the probe (a forwarder
    // in front of a hung server) is exit 4 within the deadline.
    let (silent, _acceptor) = silent_acceptor().await;
    mitm_machine.set("proxy_url", &format!("{silent:?}"));
    let started = Instant::now();
    let (code, _, stderr) = mitm_machine.jaynshare(&["claude", "--auto"], &[], None);
    let elapsed = started.elapsed();
    assert_eq!(code, 4, "no probe answer is cli_unreachable: {stderr}");
    assert!(
        stderr.starts_with("cli_unreachable:") && stderr.contains(&silent),
        "the silent proxy origin is named: {stderr}"
    );
    assert!(mitm_machine.claude_ran().is_none(), "nothing launches");
    assert!(
        elapsed < Duration::from_secs(3),
        "bounded by the 1.5 s deadline: {elapsed:?}"
    );

    // 6. The CA failure keeps its class: a `ca.pem` the proxy's leaf does not
    // chain to, with no server to fetch the right one from, is exit 12, not
    // "unreachable".
    mitm_machine.set("proxy_url", &format!("{:?}", mitm_machine.proxy));
    let ca = mitm_machine.client_dir.join("ca.pem");
    let pool_ca = fs::read(&ca).expect("ca.pem");
    let foreign = rcgen::generate_simple_self_signed(vec!["not-the-pool.invalid".into()])
        .expect("a foreign CA");
    fs::write(&ca, foreign.cert.pem()).expect("ca.pem");
    mitm_machine.set("base_url", "\"http://127.0.0.1:1\"");
    let (code, _, stderr) = mitm_machine.jaynshare(&["claude", "--auto"], &[], None);
    mitm_machine.set("base_url", &format!("{:?}", mitm_machine.base_url));
    assert_eq!(code, 12, "the CA failure stays distinct: {stderr}");
    assert!(
        stderr.starts_with("cli_ca_untrusted:") && stderr.contains(&mitm_machine.proxy),
        "the refusal names its slug and the origin: {stderr}"
    );
    assert!(mitm_machine.claude_ran().is_none(), "nothing launches");
    fs::write(&ca, pool_ca).expect("ca.pem");

    // 7. The credential failure keeps its class: a revoked client is exit 5.
    let (code, _, stderr) = mitm_machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the restored CA launches again: {stderr}");
    assert!(
        mitm_machine.claude_ran().is_some(),
        "the healthy launch ran"
    );
    mitm.cli_json(
        &["client", "revoke", &mitm_machine.client.id, "--yes"],
        None,
    );
    let (code, _, stderr) = mitm_machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 5, "the credential refusal stays distinct: {stderr}");
    assert!(
        stderr.starts_with("cli_refused:"),
        "the refusal names its slug: {stderr}"
    );
    assert!(mitm_machine.claude_ran().is_none(), "nothing launches");
}

/// A TCP acceptor that never answers: it accepts every connection and holds
/// it open, as a forwarder in front of a stopped or hung server does.
async fn silent_acceptor() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the acceptor");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (origin, task)
}

/// A MITM launch sets the four
/// proxy spellings carrying the account intent and the client secret and the
/// CA path, and no base URL, API key or ambient custom header reach Claude
/// Code even when the shell exported them. The secret travels only in the
/// proxy userinfo — no bearer-token variable.
#[tokio::test(flavor = "multi_thread")]
async fn a_mitm_launch_sets_the_proxy_the_ca_and_the_bearer() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "mitm-launch-sets",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let machine = install_client(&instance).await;
    add_two(&instance);
    let authority = machine.proxy.trim_start_matches("http://").to_string();

    // Pinned selection: the intent token travels in the proxy user field.
    let (code, _, stderr) = machine.jaynshare(
        &["claude", "--account", "FSUB2"],
        &[
            ("ANTHROPIC_BASE_URL", "http://stale.invalid"),
            ("ANTHROPIC_API_KEY", "sk-ant-stale"),
            ("HTTPS_PROXY", "http://stale.invalid:1"),
            (
                "ANTHROPIC_CUSTOM_HEADERS",
                "x-jaynshare-account: pin.c3RhbGU",
            ),
        ],
        None,
    );
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let pinned = format!(
        "http://{}:{}@{authority}",
        token(true, &instance.handle("FSUB2")),
        machine.client.secret
    );
    let seen = machine.claude_ran().expect("Claude Code was launched");
    for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"] {
        assert_eq!(
            seen.env.get(name),
            Some(&pinned),
            "{name} carries the token and the secret"
        );
    }
    assert_eq!(
        seen.env.get("NODE_EXTRA_CA_CERTS"),
        Some(&machine.client_dir.join("ca.pem").display().to_string()),
        "the CA path"
    );
    assert!(
        machine.client_dir.join("ca.pem").exists(),
        "the CA file exists"
    );
    assert!(
        !seen.env.keys().any(|k| k.contains("AUTH_TOKEN")),
        "the secret travels in the proxy userinfo only, not as a bearer"
    );
    for name in [
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_CUSTOM_HEADERS",
    ] {
        assert!(!seen.env.contains_key(name), "{name} reached Claude Code");
    }

    // Automatic selection: an empty proxy user field.
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let automatic = format!("http://:{}@{authority}", machine.client.secret);
    let seen = machine.claude_ran().expect("Claude Code was launched");
    for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"] {
        assert_eq!(
            seen.env.get(name),
            Some(&automatic),
            "{name} with an empty user field"
        );
    }
}

/// The launch sets both
/// no-proxy spellings to the loopback entries plus the engineer's
/// members, replacing whatever the shell exported.
#[tokio::test(flavor = "multi_thread")]
async fn the_no_proxy_list_is_loopback_plus_the_configured_entries() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "no-proxy-list-loopback",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let machine = install_client(&instance).await;

    let (code, _, stderr) = machine.jaynshare(
        &["claude", "--auto"],
        &[("NO_PROXY", "stale.example")],
        None,
    );
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    let loopback = "localhost,127.0.0.1,::1";
    assert_eq!(
        seen.env.get("NO_PROXY"),
        Some(&loopback.to_string()),
        "the stale export is replaced"
    );
    assert_eq!(seen.env.get("no_proxy"), Some(&loopback.to_string()), "");

    machine.set(
        "no_proxy",
        "[\"corp.example\", \".internal.example\", \"10.0.0.0/8\"]",
    );
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    let full = "localhost,127.0.0.1,::1,corp.example,.internal.example,10.0.0.0/8";
    assert_eq!(seen.env.get("NO_PROXY"), Some(&full.to_string()), ", ");
    assert_eq!(seen.env.get("no_proxy"), Some(&full.to_string()), ", ");
}

/// The request deadline follows
/// the hold hint: `API_TIMEOUT_MS` is raised to (hold hint + 60) × 1000 and
/// never lowered, Claude Code's 600000 ms default counting as the existing
/// value when none is inherited, and an unreadable snapshot leaves the
/// variable exactly as inherited: the launch check is the intercepted probe,
/// so the snapshot read is best-effort.
#[tokio::test(flavor = "multi_thread")]
async fn the_request_deadline_follows_the_hold_hint() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "request-deadline-follows",
        Setup {
            data_plane: "hold_budget_seconds = 30\n".into(),
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let machine = install_client(&instance).await;

    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        seen.env.get("API_TIMEOUT_MS"),
        None,
        "hold hint 30 → 90000 ms, below Claude Code's own 600000 ms default"
    );

    let (code, _, stderr) =
        machine.jaynshare(&["claude", "--auto"], &[("API_TIMEOUT_MS", "120000")], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        seen.env.get("API_TIMEOUT_MS"),
        Some(&"120000".to_string()),
        "a larger inherited value is never lowered"
    );

    let (code, _, stderr) =
        machine.jaynshare(&["claude", "--auto"], &[("API_TIMEOUT_MS", "5000")], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        seen.env.get("API_TIMEOUT_MS"),
        Some(&"90000".to_string()),
        "a smaller inherited value is raised"
    );

    // Hint 541 → 601000 ms, the first floor above the default.
    instance.reload_with_setup(&Setup {
        data_plane: "hold_budget_seconds = 541\n".into(),
        mitm: true,
        ..Setup::default()
    });
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        seen.env.get("API_TIMEOUT_MS"),
        Some(&"601000".to_string()),
        "hold hint 541 → 601000 ms"
    );

    // The control plane answers 500 for everything. The probe passes through
    // the proxy and the snapshot read is best-effort: unreadable, so the
    // variable stays exactly as inherited.
    let fake = FakeControl::answering(500, control_error("internal_error", "boom"));
    machine.set("base_url", &format!("{:?}", fake.origin()));
    let (code, _, stderr) =
        machine.jaynshare(&["claude", "--auto"], &[("API_TIMEOUT_MS", "1234")], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        seen.env.get("API_TIMEOUT_MS"),
        Some(&"1234".to_string()),
        "an unreadable snapshot leaves the variable untouched"
    );

    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert!(
        !seen.env.contains_key("API_TIMEOUT_MS"),
        "an unreadable snapshot sets nothing"
    );
}

/// `--direct` removes every variable the pool sets,
/// even when the shell exported them, prints one "pool is not in use" line,
/// keeps unrelated variables, and works with the server stopped.
#[tokio::test(flavor = "multi_thread")]
async fn direct_removes_every_pool_variable() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("direct-removes-pool").await;
    let machine = install_client(&instance).await;
    let stale = [
        ("https_proxy", "http://stale.invalid:1"),
        ("HTTPS_PROXY", "http://stale.invalid:1"),
        ("http_proxy", "http://stale.invalid:1"),
        ("HTTP_PROXY", "http://stale.invalid:1"),
        ("NO_PROXY", "stale.invalid"),
        ("no_proxy", "stale.invalid"),
        ("ANTHROPIC_BASE_URL", "http://stale.invalid:1"),
        ("ANTHROPIC_API_KEY", "sk-ant-stale-key"),
        ("NODE_EXTRA_CA_CERTS", "/stale/ca.pem"),
        ("ANTHROPIC_CUSTOM_HEADERS", "X-Stale: stale"),
        ("API_TIMEOUT_MS", "1"),
        ("JAYNSHARE_ACCOUNT", "FSUB"),
        ("JAYNSHARE_STATUSLINE", "stale"),
        ("KEEP_ME", "1"),
    ];
    let (code, stdout, stderr) =
        machine.jaynshare(&["claude", "--direct", "--", "-p", "x"], &stale, None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    assert_eq!(stdout, "", "the direct launch prints nothing on stdout");
    assert_eq!(
        stderr.matches("the pool is not in use").count(),
        1,
        "one line says the pool is not in use"
    );
    assert_eq!(
        stderr.lines().count(),
        1,
        "nothing else is on stderr: {stderr}"
    );
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.argv, ["-p", "x"], "");
    for &(name, _) in stale.iter().take(13) {
        assert!(!seen.env.contains_key(name), "{name} reached Claude Code");
    }
    assert_eq!(seen.env.get("KEEP_ME"), Some(&"1".to_string()));

    instance.stop();
    let (code, stdout, stderr) =
        machine.jaynshare(&["claude", "--direct", "--", "-p", "x"], &stale, None);
    assert_eq!(code, 0, "a direct launch needs no server: {stderr}");
    assert_eq!(stdout, "");
    assert_eq!(stderr.matches("the pool is not in use").count(), 1);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    let seen = machine
        .claude_ran()
        .expect("Claude Code was launched again");
    assert_eq!(seen.argv, ["-p", "x"]);
    for &(name, _) in stale.iter().take(13) {
        assert!(!seen.env.contains_key(name), "{name} reached Claude Code");
    }
    assert_eq!(seen.env.get("KEEP_ME"), Some(&"1".to_string()));
}

/// The account intent is a pin: the
/// `JAYNSHARE_ACCOUNT` variable is the same input as `--account`, the child
/// gets the pin as its proxy URL's user field and never the variable, and an
/// explicit flag wins over the environment.
#[tokio::test(flavor = "multi_thread")]
async fn jaynshare_account_is_a_pin_and_never_reaches_the_child() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("jaynshare-account-pin").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let expected = Some(token(true, &instance.handle("FSUB2")));

    // The variable alone pins; the request Claude Code sends answers 200.
    let (code, _, stderr) = machine.jaynshare(&["claude"], &[("JAYNSHARE_ACCOUNT", "FSUB2")], None);
    assert_eq!(code, 0, "{stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.pin(), expected, "the pin is the user field");
    assert!(
        !seen.env.contains_key("JAYNSHARE_ACCOUNT"),
        "the variable reached Claude Code"
    );
    let answer = claude_request(&seen.env).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(1);
    assert_eq!(record["pinned"], json!(true), "{record}");
    assert_eq!(
        record["serving_account"]["display_name"],
        json!("FSUB2"),
        "{record}"
    );

    // The flag gives the same pin as the variable: one token, two inputs.
    let (code, _, stderr) = machine.jaynshare(&["claude", "--account", "FSUB2"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.pin(), expected, ": --account is the same pin");

    // An explicit --auto wins over the variable, which is still removed.
    let (code, _, stderr) = machine.jaynshare(
        &["claude", "--auto"],
        &[("JAYNSHARE_ACCOUNT", "FSUB2")],
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert!(
        seen.pin().is_none(),
        "the explicit --auto must win: {seen:?}"
    );
    assert!(
        !seen.env.contains_key("JAYNSHARE_ACCOUNT"),
        "still consumed"
    );

    // Names compare under Unicode case folding.
    let (code, _, stderr) = machine.jaynshare(&["claude"], &[("JAYNSHARE_ACCOUNT", "fsub2")], None);
    assert_eq!(code, 0, "{stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.pin(), expected, "case-folded reference");
    instance.stop();
}

/// The pin travels in the proxy user field, and an inherited `ANTHROPIC_CUSTOM_HEADERS` never
/// reaches Claude Code, pinned or not, so no ambient header can reach the
/// proxy or Anthropic; the pin is the user field, and the proxy consumes it
/// before forwarding.
#[tokio::test(flavor = "multi_thread")]
async fn an_inherited_header_never_reaches_claude_code() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("inherited-header-never-reaches").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let inherited = "x-jaynshare-account: pin.c3RhbGU\nx-ambient-header: leak-me";

    for (round, args, pinned) in [
        (1, &["claude", "--account", "FSUB2"][..], true),
        (2, &["claude", "--auto"][..], false),
    ] {
        let (code, _, stderr) =
            machine.jaynshare(args, &[("ANTHROPIC_CUSTOM_HEADERS", inherited)], None);
        assert_eq!(code, 0, "{stderr}");
        let seen = machine.claude_ran().expect("Claude Code was launched");
        assert!(
            !seen.env.contains_key("ANTHROPIC_CUSTOM_HEADERS"),
            "the inherited value is removed: {seen:?}"
        );
        assert_eq!(
            seen.pin(),
            pinned.then(|| token(true, &instance.handle("FSUB2"))),
            "the pin, or an empty user field"
        );
        let answer = claude_request(&seen.env).await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
        let upstream = instance.upstream.last();
        assert!(
            upstream.header("x-jaynshare-account").is_none(),
            "no pin header reached Anthropic"
        );
        assert!(
            upstream.header("x-ambient-header").is_none(),
            "no ambient header reached Anthropic"
        );
        let record = instance.last_record(round);
        assert_eq!(record["pinned"], json!(pinned), "{record}");
        if pinned {
            assert_eq!(
                record["serving_account"]["display_name"],
                json!("FSUB2"),
                "{record}"
            );
        }
    }
    instance.stop();
}

/// The reference is resolved before Claude Code
/// starts: nothing matched refuses naming it, more than one match refuses
/// naming them, and a resolved but unselectable account only warns.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_ambiguous_and_unselectable_references() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("unknown-ambiguous-unselectable").await;
    add_two(&instance);
    let machine = install_client(&instance).await;

    // Nothing matched: the reference named, no launch.
    let (code, _, stderr) = machine.jaynshare(
        &["claude", "--account", "no-such-account"],
        &[("FAKE_CLAUDE_EXIT", "0")],
        None,
    );
    assert_eq!(code, 6, "{stderr}");
    assert!(
        stderr.starts_with("cli_not_found:"),
        "the slug on stderr: {stderr}"
    );
    assert!(stderr.contains("no-such-account"), "{stderr}");
    assert!(
        machine.claude_ran().is_none(),
        "refused before Claude Code started"
    );

    // The organisation UUID matches both accounts: both names shown.
    let (code, _, stderr) = machine.jaynshare(
        &["claude", "--account", FIXTURE_ORG_UUID],
        &[("FAKE_CLAUDE_EXIT", "0")],
        None,
    );
    assert_eq!(code, 7, "{stderr}");
    assert!(
        stderr.starts_with("cli_ambiguous:"),
        "the slug on stderr: {stderr}"
    );
    assert!(
        stderr.contains("FSUB") && stderr.contains("FSUB2"),
        "{stderr}"
    );
    assert!(
        machine.claude_ran().is_none(),
        "refused before Claude Code started"
    );

    // Resolved but unselectable: a warning naming it, and the launch proceeds.
    let (code, _, _) = instance.cli(&["account", "disable", "FSUB2"], None);
    assert_eq!(code, 0);
    let (code, _, stderr) = machine.jaynshare(
        &["claude", "--account", "FSUB2"],
        &[("FAKE_CLAUDE_EXIT", "0")],
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    let warned = stderr
        .lines()
        .any(|line| line.contains("warning") && line.contains("FSUB2"));
    assert!(warned, "one line warns naming FSUB2: {stderr}");
    let seen = machine.claude_ran().expect("the launch went ahead");
    assert_eq!(
        seen.pin(),
        Some(token(true, &instance.handle("FSUB2"))),
        "still FSUB2's pin"
    );
    instance.stop();
}

/// The client secret reaches only the
/// child's environment: no argv of launcher or child, no stream, no message.
#[tokio::test(flavor = "multi_thread")]
async fn the_secret_is_in_no_argument_vector_or_message() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("secret-no-argument").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let needles = encodings(&machine.client.secret);
    let leaks = |text: &str| needles.iter().any(|n| text.contains(n.as_str()));

    // 1. Launches: the secret travels in the child's environment only.
    for args in [
        vec!["claude", "--auto", "--", "-p", "hi"],
        vec!["claude", "--account", "FSUB2", "--", "--debug"],
    ] {
        let (code, stdout, stderr) = machine.jaynshare(&args, &[("FAKE_CLAUDE_EXIT", "0")], None);
        assert_eq!(code, 0, "launch {args:?}: {stderr}");
        let seen = machine.claude_ran().expect("Claude Code was launched");
        for word in &seen.argv {
            assert!(!leaks(word), "child argv leaks: {word:?}");
        }
        assert!(!leaks(&stdout), "stdout leaks");
        assert!(!leaks(&stderr), "stderr leaks");
        assert!(
            !seen.env.keys().any(|k| k.contains("AUTH_TOKEN")),
            "the secret travels in the proxy userinfo only, never as a bearer"
        );
    }

    // 2. Refusals: their exit code, and no leak on either stream.
    let refusals: [(&[&str], i32); 2] = [
        (&["claude", "--account", "no-such-account"], 6),
        (&["claude", "--account", FIXTURE_ORG_UUID], 7),
    ];
    for (args, code) in refusals {
        let (exit, stdout, stderr) = machine.jaynshare(args, &[], None);
        assert_eq!(exit, code, "refusal {args:?}: {stderr}");
        assert!(!leaks(&stdout), "stdout leaks on {args:?}");
        assert!(!leaks(&stderr), "stderr leaks on {args:?}");
        assert!(
            machine.claude_ran().is_none(),
            "refused before Claude Code started"
        );
    }

    let ca = machine.client_dir.join("ca.pem");
    let aside = machine.client_dir.join("ca.pem.aside");
    fs::rename(&ca, &aside).expect("move ca.pem aside");
    machine.set("base_url", "\"http://127.0.0.1:1\"");
    let (exit, stdout, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(exit, 14, "no ca.pem to fetch: {stderr}");
    assert!(!leaks(&stdout) && !leaks(&stderr));
    machine.set("base_url", &format!("{:?}", machine.base_url));
    fs::rename(&aside, &ca).expect("put ca.pem back");

    machine.set("proxy_url", "\"http://127.0.0.1:1\"");
    let (exit, stdout, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(exit, 4, "no proxy answer: {stderr}");
    assert!(!leaks(&stdout) && !leaks(&stderr));
    machine.set("proxy_url", &format!("{:?}", machine.proxy));

    machine.remove_claude();
    let (exit, stdout, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(exit, 13, "no Claude Code: {stderr}");
    assert!(!leaks(&stdout) && !leaks(&stderr));

    instance.stop();
}

/// `env` refuses a
/// terminal without `--show` and refuses `--json`; its output quotes every
/// value for the shell so a space in the CA path and a `'` in a no-proxy
/// member survive, and the environment is `claude`'s.
#[tokio::test(flavor = "multi_thread")]
async fn env_prints_the_launch_environment_quoted_for_each_shell() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("env-prints-run-environment").await;
    let machine = install_client(&instance).await;
    let ca = machine.client_dir.join("ca.pem").display().to_string();
    if cfg!(target_os = "macos") {
        assert!(
            ca.contains(' '),
            "the macOS client directory has a space: {ca}"
        );
    }

    // On a terminal without `--show`: refused, the secret not printed. The
    // terminal is a Unix pseudo-terminal.
    if cfg!(unix) {
        let (code, transcript) = machine.pty(&["env", "--auto", "--shell", "sh"], &[], &[]);
        assert_eq!(code, 2, "the terminal is refused: {transcript}");
        assert!(
            transcript.contains("--show"),
            "the refusal names --show: {transcript}"
        );
        assert!(
            !transcript.contains(machine.client.secret.as_str()),
            "the secret never reaches the terminal"
        );
    }

    // `env --json` is a usage error (refused before the verb runs).
    let (code, _, _) = machine.jaynshare(&["env", "--auto", "--json"], &[], None);
    assert_eq!(code, 2, "env --json exits 2");

    // sh: the lines quote for POSIX, and evaluating them sets the values.
    let (code, stdout, stderr) = machine.jaynshare(&["env", "--auto", "--shell", "sh"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout
            .lines()
            .any(|l| l == format!("export NODE_EXTRA_CA_CERTS='{ca}'")),
        "the CA line: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l == "unset ANTHROPIC_API_KEY"),
        "the API key is removed: {stdout}"
    );
    if cfg!(unix) {
        let round = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"eval "$1"; printf "%s" "$NODE_EXTRA_CA_CERTS""#)
            .arg("sh")
            .arg(&stdout)
            .output()
            .expect("sh runs");
        assert!(
            round.status.success(),
            "{}",
            String::from_utf8_lossy(&round.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&round.stdout),
            ca,
            "evaluating the lines gives the value"
        );
    }

    // A `'` in a no-proxy member survives quoting.
    machine.set("no_proxy", "[\"it's.example\"]");
    let odd = "localhost,127.0.0.1,::1,it's.example";
    let (code, stdout, stderr) = machine.jaynshare(&["env", "--auto", "--shell", "sh"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    if cfg!(unix) {
        let round = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"eval "$1"; printf "%s" "$NO_PROXY""#)
            .arg("sh")
            .arg(&stdout)
            .output()
            .expect("sh runs");
        assert!(
            round.status.success(),
            "{}",
            String::from_utf8_lossy(&round.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&round.stdout),
            odd,
            "the apostrophe survives"
        );
    }
    machine.set("no_proxy", "[]");

    // Each named shell gets its own spelling.
    let (code, fish_out, stderr) =
        machine.jaynshare(&["env", "--auto", "--shell", "fish"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        fish_out
            .lines()
            .any(|l| l == format!("set -gx NODE_EXTRA_CA_CERTS '{ca}'")),
        "fish's set line: {fish_out}"
    );
    let (code, ps_out, stderr) =
        machine.jaynshare(&["env", "--auto", "--shell", "powershell"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        ps_out
            .lines()
            .any(|l| l == format!("$env:NODE_EXTRA_CA_CERTS = '{ca}'")),
        "PowerShell's set line: {ps_out}"
    );
    let (code, cmd_out, stderr) =
        machine.jaynshare(&["env", "--auto", "--shell", "cmd"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        cmd_out
            .lines()
            .any(|l| l == format!("set \"NODE_EXTRA_CA_CERTS={ca}\"")),
        "cmd's set line: {cmd_out}"
    );

    // fish round-trips too, when fish is installed.
    if std::process::Command::new("fish")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let round = std::process::Command::new("fish")
            .arg("-c")
            .arg(r#"eval $argv[1]; printf "%s" "$NODE_EXTRA_CA_CERTS""#)
            .arg(&fish_out)
            .output()
            .expect("fish runs");
        assert!(
            round.status.success(),
            "{}",
            String::from_utf8_lossy(&round.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&round.stdout),
            ca,
            "fish evaluates the lines"
        );
    }

    // The environment is `claude`'s: an unconfigured account is refused with
    // nothing on stdout.
    let (code, stdout, stderr) =
        machine.jaynshare(&["env", "--account", "nope", "--shell", "sh"], &[], None);
    assert_eq!(code, 6, "{stderr}");
    assert!(stdout.is_empty(), "nothing on stdout: {stdout}");

    instance.stop();
}

/// `alias` prints one
/// line per shell that makes `claude` run `jaynshare claude`, quoting the
/// executable's absolute path when it is off the search path, and writes
/// nothing; without a installation it is the refusal.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn alias_prints_one_line_per_shell_and_writes_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("alias-prints-line").await;
    let machine = install_client(&instance).await;

    // Every file under `home` as `path (len)`, sorted, for a before/after diff.
    let files = |home: &std::path::Path| -> Vec<String> {
        let mut lines = Vec::new();
        for entry in walkdir(home) {
            if entry.is_file() {
                let len = std::fs::metadata(&entry).map(|m| m.len()).unwrap_or(0);
                lines.push(format!("{} ({len})", entry.display()));
            }
        }
        lines.sort();
        lines
    };
    fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return found;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walkdir(&path));
            } else {
                found.push(path);
            }
        }
        found
    }

    let exe = binary();
    let exe_path = exe.canonicalize().expect("the binary under test");
    let off_path_value = format!("{}:/usr/bin:/bin", machine.bin.display());
    let off_path = [("PATH", off_path_value.as_str())];

    // Off the search path: the path quoted for sh, one line, evaluable.
    let (code, stdout, stderr) = machine.jaynshare(&["alias", "--shell", "sh"], &off_path, None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout.lines().count(), 1, "exactly one line: {stdout}");
    let line = stdout.trim_end();
    assert!(
        line.starts_with("alias claude='")
            && line.contains(exe_path.display().to_string().as_str())
            && line.ends_with(" claude'"),
        "the sh line quotes the executable: {line}"
    );
    // Evaluate it: the quoting survives `/bin/sh`, and the alias holds the path.
    let home = machine.home.display().to_string();
    let (code, stdout, stderr) = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"eval "$1"; alias claude"#)
        .arg("sh")
        .arg(line)
        .env_clear()
        .envs([("PATH", "/usr/bin:/bin"), ("HOME", home.as_str())])
        .output()
        .map(|o| {
            (
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        })
        .expect("run /bin/sh");
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains(exe_path.display().to_string().as_str()),
        "the evaluated alias still names the executable: {stdout}"
    );

    // On the search path: the bare program name, exactly.
    let on_path_value = format!(
        "{}:{}:/usr/bin:/bin",
        exe.parent().unwrap().display(),
        machine.bin.display()
    );
    let on_path = [("PATH", on_path_value.as_str())];
    let (code, stdout, stderr) = machine.jaynshare(&["alias", "--shell", "sh"], &on_path, None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "alias claude='jaynshare claude'\n");

    // The other shells: one line each, in their own shape.
    for (shell, starts, ends) in [
        ("fish", "alias claude '", ""),
        ("powershell", "function claude { & ", " claude @args }"),
        ("cmd", "doskey claude=", " claude $*"),
    ] {
        let (code, stdout, stderr) =
            machine.jaynshare(&["alias", "--shell", shell], &off_path, None);
        assert_eq!(code, 0, "{shell}: {stderr}");
        assert_eq!(stdout.lines().count(), 1, "{shell}: one line: {stdout}");
        let line = stdout.trim_end();
        assert!(
            line.starts_with(starts) && line.ends_with(ends),
            "{shell} line shape: {line}"
        );
        assert!(
            line.contains(exe_path.display().to_string().as_str()),
            "{shell} line names the executable: {line}"
        );
    }

    // Nothing was written under the home, across all the runs above.
    let before = files(&machine.home);
    let (code, _, _) = machine.jaynshare(&["alias", "--shell", "sh"], &off_path, None);
    assert_eq!(code, 0);
    let after = files(&machine.home);
    assert_eq!(before, after, "alias writes no file");

    // An engineer verb without the installation exits 11.
    std::fs::remove_file(machine.client_dir.join("client.toml")).expect("remove client.toml");
    let (code, _, stderr) = machine.jaynshare(&["alias"], &off_path, None);
    assert_eq!(code, 11, "{stderr}");
    assert!(stderr.starts_with("cli_not_enrolled:"), "{stderr}");

    instance.stop();
}

/// The pin is the canonical handle
/// returned, never the typed name: a rename between launch and first prompt
/// still serves the pinned account, while the old name no longer resolves.
#[tokio::test(flavor = "multi_thread")]
async fn the_handle_travels_not_the_typed_name() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("handle-travels-not-typed").await;
    add_two(&instance);
    let machine = install_client(&instance).await;

    // The typed name "fsub2" resolves to the handle, which becomes the pin.
    let pin = token(true, &instance.handle("FSUB2"));
    assert_ne!(
        pin,
        token(true, "fsub2"),
        "the pin carries the handle, not the typed name"
    );
    assert_ne!(pin, token(true, "FSUB2"));
    let (code, _, stderr) = machine.jaynshare(&["claude", "--account", "fsub2"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.pin(), Some(pin.clone()), "the handle is the pin");

    // Renamed between launch and first prompt: the pinned request still
    // serves the account, and the audit record says so.
    let (code, _, stderr) = instance.cli(&["account", "rename", "FSUB2", "Renamed"], None);
    assert_eq!(code, 0, "{stderr}");
    let answer = claude_request(&seen.env).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(1);
    assert_eq!(record["pinned"], json!(true), "{record}");
    assert_eq!(
        record["serving_account"]["display_name"],
        json!("Renamed"),
        "{record}"
    );

    // The old typed name resolves against the current catalogue: nothing.
    let (code, _, stderr) = machine.jaynshare(&["claude", "--account", "FSUB2"], &[], None);
    assert_eq!(code, 6, "{stderr}");
    assert!(
        stderr.starts_with("cli_not_found:"),
        "the slug on stderr: {stderr}"
    );
    assert!(machine.claude_ran().is_none(), "nothing runs after refusal");
    instance.stop();
}

/// Every launch is MITM mode: there is no
/// `--mode` any more; an enrollment made before the change, whose
/// `client.toml` still records `mode = "base-url"` and which holds no
/// `ca.pem`, refuses naming the file and the CA update that installs it, then
/// launches in MITM mode once the CA is there; without a proxy origin the
/// launch refuses naming it.
#[tokio::test(flavor = "multi_thread")]
async fn every_launch_is_mitm_mode() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("launch-mitm-mode").await;
    let machine = install_client(&instance).await;

    // The per-launch override is gone: `env` refuses it as clap's usage
    // error (`claude` would hand an unknown flag to Claude Code).
    let (code, stdout, stderr) = machine.jaynshare(
        &["env", "--auto", "--mode", "base-url", "--shell", "sh"],
        &[],
        None,
    );
    assert_eq!(code, 2, "{stderr}");
    assert!(stdout.is_empty(), "nothing printed: {stdout}");

    // An enrollment from before the change: a recorded base-URL mode and no
    // CA. The launch fetches the CA, and the recorded mode is ignored: a
    // MITM launch.
    let toml = machine.client_dir.join("client.toml");
    let text = fs::read_to_string(&toml).expect("client.toml");
    fs::write(&toml, format!("{text}mode = \"base-url\"\n")).expect("client.toml");
    fs::remove_file(machine.client_dir.join("ca.pem")).expect("ca.pem");
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert!(
        !seen.env.contains_key("ANTHROPIC_BASE_URL") && seen.env.contains_key("HTTPS_PROXY"),
        ": MITM mode whatever client.toml records: {seen:?}"
    );

    // No proxy origin: the message names it.
    machine.set("proxy_url", "\"\"");
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 14, "{stderr}");
    assert!(
        stderr.starts_with("cli_transport_unavailable:") && stderr.contains("proxy origin"),
        "{stderr}"
    );
    assert!(machine.claude_ran().is_none());
    instance.stop();
}

/// On the Windows fixture: the
/// CA path handed to Claude Code is a native Windows path whatever shell
/// launched it, the client directory resolves from the Windows profile and
/// not from a shell's `HOME`, a missing prerequisite refuses with an
/// actionable message, and no launch falls back to the engineer's own login.
/// Elsewhere the fixture is absent and the skip is recorded. The
/// settings command's native path is checked by hand: the enrollment that
/// writes it needs a hidden prompt, which the Windows fixture has no
/// pseudo-terminal for.
#[tokio::test(flavor = "multi_thread")]
async fn windows_paths_profile_prerequisites_and_no_fallback() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !cfg!(windows) {
        eprintln!("skipping: the Windows fixture is absent");
        return;
    }
    let native = |path: &str| {
        let bytes = path.as_bytes();
        bytes.len() > 3
            && bytes[0].is_ascii_alphabetic()
            && &bytes[1..3] == b":\\"
            && !path.contains('/')
    };
    // A POSIX-flavoured shell's view of the machine: its own HOME and SHELL.
    let posix_shell = [
        ("HOME", "/c/Users/someone-else"),
        ("SHELL", "/usr/bin/bash"),
    ];

    let instance = Instance::start_with(
        "windows-paths-profile",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let machine = install_client(&instance).await;
    for extra in [&[][..], &posix_shell[..]] {
        let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], extra, None);
        assert_eq!(code, 0, "{extra:?}: {stderr}");
        let child = machine.claude_ran().expect("Claude Code ran");
        let ca = child.env.get("NODE_EXTRA_CA_CERTS").expect("the CA path");
        assert!(native(ca), "a native Windows path: {ca}");
        assert_eq!(
            ca,
            &machine.client_dir.join("ca.pem").display().to_string(),
            "the client directory is the profile's"
        );
        assert!(std::path::Path::new(ca).is_file(), "{ca}");
    }

    // The profile, not HOME, decides where the installation is.
    let (code, _, stderr) = machine.jaynshare(&["status", "--json"], &posix_shell, None);
    assert_eq!(code, 0, "{stderr}");

    // A missing prerequisite refuses, naming what to install.
    machine.remove_claude();
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 13, "{stderr}");
    assert!(stderr.contains("install Claude Code"), "{stderr}");
    assert!(machine.claude_ran().is_none());

    // No fallback to the engineer's own login when the pool is unreachable.
    let base = Instance::start_client("windows-paths-profile-base").await;
    let machine = install_client(&base).await;
    machine.set("base_url", "\"http://127.0.0.1:1\"");
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 4, "{stderr}");
    assert!(stderr.contains("--direct"), "{stderr}");
    assert!(machine.claude_ran().is_none(), "/57: nothing launched");
}
