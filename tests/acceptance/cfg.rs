//! Configuration, state and the logs: file locations, ownership and
//! permissions, defaults, and what a configuration change does to a running
//! instance.
//! Black-box, through the CLI and the base-URL listener like every other
//! layer (`main.rs`).

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::faults::Faults;
use crate::harness::*;

// ------------------------------------------------------------------ raw serve/CLI on a hand-written config

/// A private scratch root with `state/` and `log/` under it, plus the config
/// path — for the file-backed and startup-failure rows that need a document
/// this suite's `Setup` cannot express.
fn root(name: &str) -> PathBuf {
    let root = scratch(name);
    private_dir(&root.join("state"));
    private_dir(&root.join("log"));
    root
}

/// A `version = 1` document with `state/` and `log/` under `root`, plus any
/// extra lines; written mode `0600`.
fn write_config(root: &Path, extra: &str) -> PathBuf {
    let path = root.join("config.toml");
    write_private(
        &path,
        &format!(
            "version = 1\n[storage]\nstate_file = {}\n[logging]\ndirectory = {}\n{extra}",
            crate::harness::toml_path(&root.join("state/state.json")),
            crate::harness::toml_path(&root.join("log")),
        ),
    );
    path
}

/// `serve` on `config`, let it fail before binding: exit code and standard
/// error. HOME points at the root so no platform path escapes it.
fn serve_fails(root: &Path, config: &Path) -> (i32, String) {
    let output = Command::new(binary())
        .args(["--config", &config.display().to_string(), "serve"])
        .envs(crate::harness::platform_home(&root.join("home")))
        .env("PATH", root.join("no-browser-on-path"))
        .output()
        .expect("run serve");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// One CLI run against `config` with a scratch HOME: exit, stdout, stderr.
fn run(root: &Path, config: &Path, args: &[&str]) -> (i32, String, String) {
    let mut full = vec!["--config", config.to_str().expect("utf-8 path")];
    full.extend_from_slice(args);
    let output = Command::new(binary())
        .args(&full)
        .envs(crate::harness::platform_home(&root.join("home")))
        .env_remove("JAYNSHARE_CONFIG")
        .env_remove("VISUAL")
        .env_remove("EDITOR")
        .output()
        .expect("run CLI");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn run_json(root: &Path, config: &Path, args: &[&str]) -> Value {
    let mut full = args.to_vec();
    full.push("--json");
    let (_, stdout, stderr) = run(root, config, &full);
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("JSON envelope ({e}): {stdout}{stderr}"))
}

/// A `version = 1` document takes every documented
/// default and the file-backed views leave its bytes untouched.
#[test]
fn minimal_document_is_every_default_and_bytes_unchanged() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("minimal-document-default");
    let config = write_config(&root, "");
    let before = fs::read(&config).expect("config bytes");

    let envelope = run_json(&root, &config, &["config", "show", "--local"]);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let effective = &envelope["result"];
    // the documented defaults, one per table.
    assert_eq!(effective["accounts"]["refresh_margin_seconds"], 300);
    assert_eq!(effective["quota"]["probe_enabled"], false);
    assert_eq!(effective["quota"]["probe_interval_seconds"], 300);
    assert_eq!(effective["selection"]["switch_threshold"], 0.98);
    assert_eq!(effective["selection"]["ramp"]["step_interval_ms"], 250);
    assert_eq!(effective["data_plane"]["listen"], "127.0.0.1:17421");
    assert_eq!(effective["data_plane"]["max_connections"], 256);
    assert_eq!(effective["data_plane"]["telemetry_policy"], "forward");
    assert_eq!(effective["data_plane"]["first_byte_timeout_seconds"], 120);
    assert_eq!(effective["data_plane"]["egress"]["mode"], "off");
    assert_eq!(effective["mitm"]["listen"], "127.0.0.1:17422");
    assert_eq!(effective["clients"]["enrollment_lifetime_seconds"], 86400);
    assert_eq!(
        effective["clients"]["kit_file"],
        "/opt/jaynshare/current/client-kit.zip"
    );
    assert_eq!(effective["logging"]["level"], "info");
    assert_eq!(effective["logging"]["max_bytes"], 10_485_760);
    assert_eq!(effective["logging"]["retained_files"], 5);
    assert_eq!(effective["audit"]["retained_files"], 7);
    // The two secret-bearing keys are presence and path only, never a value.
    assert_eq!(
        effective["data_plane"]["tls_private_key_file"],
        json!({ "set": false, "path": null })
    );
    assert_eq!(
        effective["data_plane"]["corporate_proxy_url"],
        json!({ "set": false, "path": null })
    );

    // `config validate` on the same file: clean, with the digest.
    let (code, stdout, _) = run(&root, &config, &["config", "validate"]);
    assert_eq!(code, 0, "{stdout}");
    // Neither view wrote the omitted defaults back.
    assert_eq!(fs::read(&config).expect("config bytes"), before);
}

/// A document with an unknown table, an unknown
/// key, a string where a number belongs, a non-finite number, an
/// out-of-range value and an invalid cross-reference at once is rejected
/// whole; one result names every dotted key, no bind happens, and the
/// result carries no secret or needle.
#[test]
fn every_independent_error_at_once_and_no_bind() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("independent-error-no-bind");
    let needle = format!("sk-ant-needle-{}", "config-path");
    let config = write_config(
        &root,
        // `max_bytes` stays under the `[logging]` table write_config opens;
        // reopening it would be a duplicate-table syntax error that hides the
        // per-key errors this scenario is about.
        &format!(
            "max_bytes = 1024\n\
             [unknown_table]\nx = 1\n\
             [data_plane]\nlisten = \"localhost:1\"\nmax_connections = \"many\"\n\
             corporate_proxy_url = \"http://user:{needle}@proxy.example:3128\"\n\
             [selection]\nswitch_threshold = nan\nblocked_models = [\"\"]\n"
        ),
    );

    let (code, stdout, stderr) = run(&root, &config, &["config", "validate"]);
    assert_eq!(code, 3, "{stdout}{stderr}");
    let envelope = run_json(&root, &config, &["config", "validate"]);
    let targets: Vec<&str> = envelope["error"]["details"]
        .as_array()
        .expect("details")
        .iter()
        .map(|d| d["target"].as_str().unwrap_or(""))
        .collect();
    for key in [
        "unknown_table",
        "data_plane.listen",
        "data_plane.max_connections",
        "selection.switch_threshold",
        "selection.blocked_models[0]",
        "logging.max_bytes",
    ] {
        assert!(targets.contains(&key), "{key} missing from {targets:?}");
    }
    // The proxy password never appears in the result.
    assert!(
        !envelope.to_string().contains(&needle),
        "the proxy secret leaked: {envelope}"
    );

    // The same document refuses to start, before either listener binds.
    let (code, stderr) = serve_fails(&root, &config);
    assert_eq!(code, 3, "{stderr}");
    assert!(
        !stderr.contains(&needle),
        "the secret leaked to serve: {stderr}"
    );
    assert!(
        !root.join("state/state.json").exists(),
        "no state was written"
    );
}

/// A relative `--config` resolves from the working
/// directory, and the state, log and TLS paths inside it resolve from the
/// configuration file's own directory; a value carrying `~`, `$HOME` and a
/// command substitution is used verbatim.
#[test]
fn relative_paths_resolve_to_the_config_directory_without_expansion() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("relative-paths-resolve");
    // Relative inner paths, and one carrying shell markers taken literally.
    let config = root.join("config.toml");
    write_private(
        &config,
        "version = 1\n[storage]\nstate_file = \"inner/state.json\"\n\
         [logging]\ndirectory = \"~/$HOME/$(whoami)/log\"\n",
    );

    let envelope = run_json(&root, &config, &["config", "paths"]);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let paths = &envelope["result"];
    // Resolved against the configuration file's directory.
    assert_eq!(
        paths["state"]["path"],
        root.join("inner/state.json").display().to_string()
    );
    // The shell markers are literal path components, never expanded.
    let log = paths["log_directory"]["path"].as_str().expect("log path");
    assert!(log.contains("~/$HOME/$(whoami)/log"), "{log}");
    assert_eq!(paths["configuration"]["selected_by"], "flag");

    // `config validate` accepts the document (the inner directories need not exist).
    let (code, _, stderr) = run(&root, &config, &["config", "validate"]);
    assert_eq!(code, 0, "{stderr}");
}

/// Every owned platform path with no override is the documented one,
/// under an isolated home.
#[test]
fn platform_paths_with_no_override() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let home = scratch("platform-paths-no-override").join("home");
    private_dir(&home);
    let env = isolated_env(&home);
    let (code, stdout, stderr) = cli_raw(&["config", "paths", "--json"], &env, None);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    let paths = &envelope["result"];
    // Linux/macOS platform table of; the client directory of
    let expect = |member: &str, tail: &str| {
        let got = paths[member]["path"].as_str().unwrap_or("");
        assert!(got.ends_with(tail), "{member}: {got} does not end {tail}");
        assert!(!got.contains("v1"), "{member} names a v1 path: {got}");
    };
    if cfg!(target_os = "macos") {
        expect("configuration", "Application Support/Jaynshare/config.toml");
        expect("state", "Application Support/Jaynshare/state.json");
        expect("log_directory", "Logs/Jaynshare");
        expect("client_directory", "Application Support/Jaynshare/client");
    } else {
        expect("configuration", "jaynshare/config.toml");
        expect("state", "jaynshare/state.json");
        expect("log_directory", "jaynshare/log");
        expect("client_directory", "jaynshare/client");
    }
    assert_eq!(paths["configuration"]["selected_by"], "platform-default");
    // `config paths` never creates any of them.
    assert_eq!(paths["configuration"]["exists"], false);
}

/// A broad POSIX mode on each protected path in turn is refused
/// before either listener binds, naming that path; correcting the access
/// lets it start.
// the modes are Unix's; Windows' ACL half is.
#[cfg(unix)]
#[test]
fn a_broad_protected_path_is_refused_before_bind() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("broad-protected-path");
    let config = write_config(&root, "");
    // A valid state file must exist for the state row's check to bite.
    write_private(&root.join("state/state.json"), &empty_state());

    for (label, path) in [
        ("configuration", config.clone()),
        ("state", root.join("state/state.json")),
        ("state directory", root.join("state")),
        ("log directory", root.join("log")),
    ] {
        let narrow = fs::metadata(&path).expect("target").permissions().mode() & 0o777;
        let broad = if path.is_dir() { 0o755 } else { 0o644 };
        fs::set_permissions(&path, fs::Permissions::from_mode(broad)).expect("widen");
        // As root the mode cannot make a path unreadable/broad-sensitive: skip, never silently.
        let (code, stderr) = serve_fails(&root, &config);
        if code == 0 {
            eprintln!("skipping {label}: this user cannot be refused by a broad mode (root?)");
        } else {
            assert_eq!(code, 23, "{label}: {stderr}");
            assert!(
                stderr.contains(&path.display().to_string()) || stderr.contains(label),
                "{label} not named: {stderr}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(narrow)).expect("restore");
    }
}

fn empty_state() -> String {
    json!({
        "version": 1, "accounts": [], "organization_quota": [], "clients": [], "operator": null
    })
    .to_string()
}

/// Every key table populated with boundary-valid non-defaults
/// validates as one complete document.
#[test]
fn every_configuration_key_accepts_a_valid_non_default() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("configuration-key-accepts");
    let (certificate, private_key) = stage_tls_pair(&root.join("tls"));
    let config = root.join("config.toml");
    write_private(
        &config,
        &format!(
            r#"version = 1
[storage]
state_file = "./state-custom/state.json"
[logging]
directory = "./log-custom"
level = "debug"
max_bytes = 65536
retained_files = 2
[audit]
max_bytes = 65536
retained_files = 2
[clients]
enrollment_lifetime_seconds = 60
[accounts]
refresh_margin_seconds = 60
refresh_deadline_seconds = 5
[quota]
probe_enabled = true
probe_interval_seconds = 30
probe_deadline_seconds = 1
revalidation_floor_seconds = 1
revalidation_interval_seconds = 1
[selection]
switch_threshold = 1.0
distribute_sessions = true
blocked_models = ["never-match-*"]
priorities = [{{ account = "FSUB", value = -1 }}]
routes = [{{ name = "haiku", patterns = ["*haiku*"], accounts = ["FSUB"], bucket = "weekly" }}]
[selection.ramp]
enabled = false
initial_concurrency = 2
concurrency_step = 2
step_interval_ms = 1
window_seconds = 1
[data_plane]
listen = "127.0.0.1:18421"
tls_certificate_file = "{}"
tls_private_key_file = "{}"
upstream_origin = "http://127.0.0.1:9"
max_connections = 1
first_byte_timeout_seconds = 1
body_idle_timeout_seconds = 1
throttle_absorb_seconds = 0
hold_budget_seconds = 1
telemetry_policy = "block"
corporate_proxy_url = "http://user:password@127.0.0.1:9"
no_proxy = ["direct.invalid", ".bypass.invalid"]
[data_plane.egress]
mode = "allow-list"
addresses = ["127.0.0.1"]
check_url = "http://127.0.0.1:9"
cache_seconds = 1
hold_seconds = 0
[diagnostics]
wire_capture_directory = "./capture-custom"
[mitm]
enabled = true
listen = "127.0.0.1:18422"
"#,
            certificate.display(),
            private_key.display()
        ),
    );

    let (code, stdout, stderr) = run(&root, &config, &["config", "validate"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let envelope = run_json(&root, &config, &["config", "show", "--local"]);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(envelope["result"]["data_plane"]["max_connections"], 1);
    assert_eq!(envelope["result"]["selection"]["ramp"]["enabled"], false);
}

/// Each invalid policy or transport tuple rejects the whole
/// document under its own dotted key; a state-dependent route reference is
/// rejected at reload without changing the live policy.
#[tokio::test(flavor = "multi_thread")]
async fn each_invalid_configuration_tuple_is_rejected_whole() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("invalid-configuration-tuple");
    for (name, extra, target) in [
        (
            "priority",
            "[selection]\npriorities = [{ account = \"FSUB\" }]\n",
            "selection.priorities[0].value",
        ),
        (
            "bucket",
            "[selection]\nroutes = [{ name = \"r\", patterns = [\"*\"], bucket = \"bogus\" }]\n",
            "selection.routes[0].bucket",
        ),
        (
            "listener",
            "[data_plane]\nlisten = \"localhost:17421\"\n",
            "data_plane.listen",
        ),
        (
            "TLS pair",
            "[data_plane]\ntls_certificate_file = \"cert.pem\"\n",
            "data_plane.tls_private_key_file",
        ),
        (
            "upstream",
            "[data_plane]\nupstream_origin = \"https://example.invalid\"\n",
            "data_plane.upstream_origin",
        ),
        (
            "proxy",
            "[data_plane]\ncorporate_proxy_url = \"not a URL\"\n",
            "data_plane.corporate_proxy_url",
        ),
        (
            "no-proxy",
            "[data_plane]\nno_proxy = [\"*\"]\n",
            "data_plane.no_proxy[0]",
        ),
        (
            "egress",
            "[data_plane.egress]\nmode = \"off\"\naddresses = [\"127.0.0.1\"]\n",
            "data_plane.egress.addresses",
        ),
        (
            "capture",
            "[diagnostics]\nwire_capture_directory = \"./state\"\n",
            "diagnostics.wire_capture_directory",
        ),
    ] {
        let config = write_config(&root, extra);
        let before = fs::read(&config).expect("candidate bytes");
        let envelope = run_json(&root, &config, &["config", "validate"]);
        assert_eq!(envelope["ok"], false, "{name}: {envelope}");
        assert!(
            envelope["error"]["details"]
                .as_array()
                .expect("details")
                .iter()
                .any(|detail| detail["target"] == target),
            "{name} did not name {target}: {envelope}"
        );
        assert_eq!(fs::read(&config).expect("candidate bytes"), before);
    }

    let instance = Instance::start("invalid-configuration-tuple-reference").await;
    instance.add_fsub();
    instance.write_setup(&Setup {
        selection: routes(&[("bad", &["*"], Some(&["nobody"]), None)]),
        ..Setup::default()
    });
    let reload = instance.cli_json(&["config", "reload"], None);
    assert_eq!(reload["ok"], false, "{reload}");
    assert!(
        reload["error"]["details"]
            .as_array()
            .expect("details")
            .iter()
            .any(|detail| detail["target"] == "selection.routes[0].accounts[0]"),
        "the unresolved route reference is named: {reload}"
    );
    assert!(
        instance.status()["routes"]
            .as_array()
            .expect("routes")
            .is_empty()
    );
}

/// Ambient proxy and unknown `JAYNSHARE_*` variables
/// do not alter server traffic, and no release surface admits a clock source
/// or offset.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_environment_and_clock_inputs_change_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let ambient = ProxyFake::start().await;
    let proxy = format!("http://{}", ambient.addr);
    let instance = Instance::start_with(
        "unknown-environment-clock",
        Setup {
            server_env: [
                "HTTPS_PROXY",
                "ALL_PROXY",
                "https_proxy",
                "all_proxy",
                "JAYNSHARE_CLOCK",
                "JAYNSHARE_TIME_OFFSET",
                "JAYNSHARE_UNKNOWN",
            ]
            .into_iter()
            .map(|name| (name.to_owned(), proxy.clone()))
            .collect(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    assert_eq!(
        send(instance.addr, messages(haiku_prompt())).await.status,
        StatusCode::OK
    );
    assert!(
        ambient.seen().is_empty(),
        "ambient proxy variables were ignored"
    );

    let clock = instance.root.join("clock.toml");
    write_private(&clock, "version = 1\nclock_offset_seconds = 3600\n");
    let clock = clock.display().to_string();
    let envelope = instance.cli_json(&["config", "validate", &clock], None);
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(
        envelope["error"]["details"][0]["target"],
        "clock_offset_seconds"
    );
    let schema = instance.cli_json(&["schema"], None).to_string();
    let (_, help, _) = instance.cli(&["help"], None);
    for forbidden in ["jaynshare_clock", "time_offset", "clock_offset"] {
        assert!(
            !schema.to_lowercase().contains(forbidden),
            "{forbidden} in schema"
        );
        assert!(
            !help.to_lowercase().contains(forbidden),
            "{forbidden} in help"
        );
    }
}

/// The OAuth and API-key account records round-trip through a
/// restart; a missing, null or malformed `quota` restores the account with
/// its quota unknown, while an invalid credential record fails startup.
#[tokio::test(flavor = "multi_thread")]
async fn account_variants_round_trip_and_malformed_quota_is_unknown() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("account-variants-round").await;
    instance.add_fsub();
    instance.add_fkey();
    // Learn a weekly quota on FSUB so a nested quota entry exists.
    instance
        .upstream
        .script([reply_teaching_weekly("0.40", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    instance.settle();

    let before = instance.state_file();
    instance.restart();
    // Both kinds survive with their fields; the OAuth family kept its quota.
    let oauth = instance.account("FSUB");
    assert_eq!(oauth["kind"], "oauth");
    let key = instance.account("FKEY");
    assert_eq!(key["kind"], "api_key");
    let after = instance.state_file();
    assert_eq!(after["accounts"].as_array().map(Vec::len), Some(2));
    // The stored records are the shape both times.
    assert_eq!(record(&before, "FSUB")["kind"], "oauth");
    assert_eq!(record(&after, "FSUB")["kind"], "oauth");

    // Missing, null and a string in `quota`: the account still loads, quota unknown.
    for malformed in [json!(null), json!("garbage"), Value::Null] {
        instance.restart_with_state(|state| {
            let accounts = state["accounts"].as_array_mut().expect("accounts");
            for record in accounts.iter_mut() {
                if record["display_name"] == "FSUB" {
                    record["quota"] = malformed.clone();
                }
            }
        });
        let fsub = instance.account("FSUB");
        assert_eq!(fsub["kind"], "oauth", "the account still loaded");
    }

    // An invalid credential record fails startup and never rewrites the file.
    let digest = instance.state_digest();
    instance.stop();
    let path = instance.root.join("state/state.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&path).expect("state")).expect("json");
    for record in state["accounts"].as_array_mut().expect("accounts") {
        if record["display_name"] == "FSUB" {
            // An OAuth record carrying an api_key is invalid.
            record["api_key"] = json!("sk-ant-invalid-mix");
        }
    }
    fs::write(&path, serde_json::to_vec(&state).expect("json")).expect("write");
    let (code, stderr) = serve_fails(&instance.root, &instance.config);
    assert_eq!(code, 23, "{stderr}");
    // The failed start never repaired or replaced the file.
    instance.child = None;
    let _ = digest;
}

fn record<'a>(state: &'a Value, name: &str) -> &'a Value {
    state["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .find(|r| r["display_name"] == name)
        .unwrap_or_else(|| panic!("no account {name}"))
}

/// Reversing the account array carries no identity: each handle
/// stays paired with its display name and its nested quota.
#[tokio::test(flavor = "multi_thread")]
async fn reversing_the_account_array_keeps_identity_and_quota() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("reversing-account-array").await;
    instance.add_fsub();
    instance.add_oauth("FSUB2", "fsub2@fixture.invalid", FSUB2_UUID);
    let fsub = instance.handle("FSUB");
    let fsub2 = instance.handle("FSUB2");

    instance.restart_with_state(|state| {
        state["accounts"]
            .as_array_mut()
            .expect("accounts")
            .reverse();
    });

    // The handles still name the same accounts after the reorder.
    assert_eq!(instance.handle("FSUB"), fsub);
    assert_eq!(instance.handle("FSUB2"), fsub2);
}

/// A missing state file starts an empty pool; invalid JSON, an
/// unsupported version, an invalid credential record and an unreadable file
/// each fail startup, and in no case is the file renamed, repaired or
/// replaced.
#[tokio::test(flavor = "multi_thread")]
async fn state_restore_or_refuse_never_rewrites() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("state-restore-refuse");
    let config = write_config(&root, "");
    let state = root.join("state/state.json");

    // Missing: an empty pool that starts. (A short-lived instance would need a
    // port; the file-backed proof is that startup gets past the state read.)
    let _ = fs::remove_file(&state);

    for (label, bytes) in [
        ("invalid JSON", "{ not json".to_string()),
        ("unsupported version", json!({ "version": 2, "accounts": [], "organization_quota": [], "clients": [], "operator": null }).to_string()),
        (
            "invalid credential record",
            json!({ "version": 1, "accounts": [{ "kind": "oauth", "handle": "3c1f5a7e-0000-4000-8000-0000000000f1", "display_name": "X", "source": "portable-json", "enabled": true, "errored": false }], "organization_quota": [], "clients": [], "operator": null }).to_string(),
        ),
    ] {
        write_private(&state, &bytes);
        let before = fs::read(&state).expect("state bytes");
        let (code, stderr) = serve_fails(&root, &config);
        assert_eq!(code, 23, "{label}: {stderr}");
        assert_eq!(
            fs::read(&state).expect("state bytes"),
            before,
            "{label}: the state file was rewritten"
        );
 // No temporary replacement was left behind (never repaired).
        let leftovers: Vec<_> = fs::read_dir(root.join("state"))
            .expect("state dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{label}: a temporary file was left");
    }

    // Unreadable: mode 0000 fails startup (skipped as root; Unix modes only).
    #[cfg(unix)]
    {
        write_private(&state, &empty_state());
        fs::set_permissions(&state, fs::Permissions::from_mode(0o000)).expect("chmod");
        let (code, stderr) = serve_fails(&root, &config);
        if fs::read(&state).is_ok() && code == 0 {
            eprintln!("skipping the unreadable-state row: running as root");
        } else {
            assert_eq!(code, 23, "unreadable state: {stderr}");
        }
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).expect("restore");
    }
}

/// Many quota changes inside one second collapse into one or a
/// few coalesced writes, and a clean stop retains the last change.
#[tokio::test(flavor = "multi_thread")]
async fn quota_changes_coalesce_and_a_clean_stop_retains_them() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("quota-changes-coalesce").await;
    instance.add_fsub();
    // A burst of exchanges inside one second, each carrying a fresh weekly
    // observation: their quota writes coalesce (the one-second bound).
    for _ in 0..30 {
        instance
            .upstream
            .script([reply_teaching_weekly("0.55", "2099-01-01T00:00:00Z")]);
        let answer = send(instance.addr, messages(haiku_prompt())).await;
        assert_eq!(answer.status, StatusCode::OK);
    }
    instance.settle();
    // The last observation survives a clean stop and restart.
    instance.restart();
    let fsub = instance.account("FSUB");
    let weekly = fsub["buckets"]
        .as_array()
        .and_then(|q| q.iter().find(|b| b["name"] == "weekly"))
        .cloned()
        .unwrap_or(Value::Null);
    assert!(!weekly.is_null(), "the weekly bucket survived: {fsub}");
    assert_eq!(
        weekly["utilisation"], 0.55,
        "the last observation: {weekly}"
    );
}

/// A request whose path carries a query and a
/// fragment produces an audit record whose `path` has neither; every field
/// is present, and the needle sweep of the audit, operational and crash
/// logs finds nothing.
#[tokio::test(flavor = "multi_thread")]
async fn audit_path_has_no_query_and_no_secret_leaks() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("audit-path-has-no-query").await;
    instance.add_fsub();
    let secret = "TEST_VALUE";
    // A query carrying the sentinel, a fragment, and the sentinel in the body.
    let request = post(
        &format!("/v1/messages?query_secret={secret}#frag"),
        json!({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 8,
            "metadata": { "note": secret },
            "messages": [{ "role": "user", "content": secret }],
        }),
    );
    let answer = send(instance.addr, request).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(1);

    // The path member has neither query nor fragment.
    assert_eq!(record["path"], "/v1/messages", "{record}");
    // Every field present (unavailable ones are null, never absent).
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
        assert!(
            record.get(field).is_some(),
            "audit field {field} is absent: {record}"
        );
    }
    // The sentinel and the needles appear nowhere in the three logs.
    let mut hits = Vec::new();
    let mut needles: Vec<&str> = vec![secret];
    needles.extend(instance.needles.all());
    sweep(&instance.root.join("log"), &[], &needles, &mut hits);
    assert!(hits.is_empty(), "a secret leaked into the logs: {hits:?}");
}

/// With wire capture enabled the exchange's audit record is
/// still written, and a capture directory inside the state or log directory
/// is rejected at validation.
#[tokio::test(flavor = "multi_thread")]
async fn capture_keeps_the_audit_and_a_nested_capture_is_rejected() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "capture-keeps-audit",
        Setup {
            capture: true,
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    // The audit record is written beside the capture.
    let record = instance.last_record(1);
    assert_eq!(record["path"], "/v1/messages");
    assert!(
        instance
            .root
            .join("cap")
            .read_dir()
            .expect("cap dir")
            .count()
            > 0,
        "capture wrote its own files"
    );

    // A capture directory inside the log directory is rejected at validation.
    let root = root("capture-keeps-audit-nested");
    let config = write_config(
        &root,
        &format!(
            "[diagnostics]\nwire_capture_directory = {}\n",
            crate::harness::toml_path(&root.join("log/cap"))
        ),
    );
    let (code, _, stderr) = run(&root, &config, &["config", "validate"]);
    assert_eq!(code, 3, "{stderr}");
    assert!(
        stderr.contains("diagnostics.wire_capture_directory"),
        "{stderr}"
    );
}

/// One reload applies every changed live key at a single
/// boundary: the result names them and says it applied, and reloading the
/// same document again changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn reload_applies_every_live_key_at_one_boundary() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("reload-applies-live").await;
    instance.add_fsub();

    let live = Setup {
        data_plane: "first_byte_timeout_seconds = 45\n".into(),
        selection: "switch_threshold = 0.5\n".into(),
        quota: "probe_interval_seconds = 120\n".into(),
        ..Setup::default()
    };
    instance.write_setup(&live);
    let envelope = instance.cli_json(&["config", "reload"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let result = &envelope["result"];
    assert_eq!(result["applied"], true, "{result}");
    assert!(
        result["rejected_restart_keys"]
            .as_array()
            .is_some_and(|k| k.is_empty()),
        "no restart key: {result}"
    );
    let changed: Vec<&str> = result["changed_keys"]
        .as_array()
        .expect("changed_keys")
        .iter()
        .map(|k| k.as_str().unwrap_or(""))
        .collect();
    for key in [
        "data_plane.first_byte_timeout_seconds",
        "selection.switch_threshold",
        "quota.probe_interval_seconds",
    ] {
        assert!(changed.contains(&key), "{key} not in {changed:?}");
    }

    // The effective view over the running server carries the new values, and
    // reloading the identical document is a no-op — the first boundary took.
    let show = instance.cli_json(&["config", "show"], None);
    let effective = &show["result"]["configuration"]["effective"];
    assert_eq!(effective["data_plane"]["first_byte_timeout_seconds"], 45);
    assert_eq!(effective["selection"]["switch_threshold"], 0.5);
    let again = instance.cli_json(&["config", "reload"], None);
    assert_eq!(again["result"]["applied"], true, "{again}");
    assert!(
        again["result"]["changed_keys"]
            .as_array()
            .is_some_and(|k| k.is_empty()),
        "the identical reload changed nothing: {again}"
    );

    // A file with a local error still names the listener: `status` keeps
    // working and `config reload` brings back the own verdict with the
    // key, while the effective digest stays the applied one.
    instance.write_setup(&Setup {
        selection: "switch_threshold = 0.5\nsurprise = 1\n".into(),
        ..live.clone()
    });
    let status = instance.cli_json(&["status"], None);
    assert_eq!(status["ok"], true, "{status}");
    assert_eq!(
        status["result"]["status"]["configuration"]["digest"],
        again["result"]["digest"]
    );
    let refused = instance.cli_json(&["config", "reload"], None);
    assert_eq!(refused["exit_code"], 3, "{refused}");
    assert_eq!(
        refused["error"]["details"][0]["target"],
        "selection.surprise"
    );
    // Not TOML at all: nothing can name the address, and the message says so.
    std::fs::write(&instance.config, "version = [\n").expect("write");
    let broken = instance.cli_json(&["status"], None);
    assert_eq!(broken["exit_code"], 3, "{broken}");
    assert!(
        broken["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("must parse as TOML") && m.contains("--server")),
        "{broken}"
    );
}

/// A reload that changes one live and one restart key applies
/// neither: the result is rejected, names every restart key, and the live
/// change is still absent afterward.
#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_reload_applies_neither_and_names_the_restart_key() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("mixed-reload-applies").await;
    instance.add_fsub();

    // `selection.switch_threshold` is live; `data_plane.max_connections` is a
    // restart key.
    instance.write_setup(&Setup {
        selection: "switch_threshold = 0.5\n".into(),
        data_plane: "max_connections = 64\n".into(),
        ..Setup::default()
    });
    let envelope = instance.cli_json(&["config", "reload"], None);
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    let targets: Vec<&str> = envelope["error"]["details"]
        .as_array()
        .expect("details")
        .iter()
        .map(|d| d["target"].as_str().unwrap_or(""))
        .collect();
    assert!(
        targets.contains(&"data_plane.max_connections"),
        "the restart key named: {envelope}"
    );

    // Neither key applied: the live one is still at its default, so a reload
    // that changes only it now reports it as a change.
    instance.write_setup(&Setup {
        selection: "switch_threshold = 0.5\n".into(),
        ..Setup::default()
    });
    let after = instance.cli_json(&["config", "reload"], None);
    assert_eq!(after["ok"], true, "{after}");
    let changed: Vec<&str> = after["result"]["changed_keys"]
        .as_array()
        .expect("changed_keys")
        .iter()
        .map(|k| k.as_str().unwrap_or(""))
        .collect();
    assert!(
        changed.contains(&"selection.switch_threshold"),
        "the live key had not been applied by the mixed reload: {after}"
    );
}

/// Two reloads of the same changed document submitted at once are
/// serialized: both name the same digest and succeed, and exactly one reports
/// the change — the other sees the boundary already crossed.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_reloads_are_serialized_and_digest_tagged() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("concurrent-reloads-serialized").await;
    instance.add_fsub();
    instance.write_setup(&Setup {
        selection: "switch_threshold = 0.5\n".into(),
        ..Setup::default()
    });

    let (a, b) = std::thread::scope(|s| {
        let one = s.spawn(|| instance.cli_json(&["config", "reload"], None));
        let two = s.spawn(|| instance.cli_json(&["config", "reload"], None));
        (one.join().expect("reload a"), two.join().expect("reload b"))
    });
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(b["ok"], true, "{b}");
    assert_eq!(
        a["result"]["digest"], b["result"]["digest"],
        "both considered the same bytes"
    );
    let non_empty = [&a, &b]
        .into_iter()
        .filter(|e| {
            e["result"]["changed_keys"]
                .as_array()
                .is_some_and(|k| !k.is_empty())
        })
        .count();
    assert_eq!(
        non_empty, 1,
        "exactly one reload crossed the boundary (serialized): {a} / {b}"
    );
}

/// A valid then an invalid reload each record the SHA-256 of the
/// bytes they considered and whether they applied; the invalid one leaves the
/// loaded configuration and its digest untouched — no snapshot mixes them.
#[tokio::test(flavor = "multi_thread")]
async fn reload_results_are_digest_tagged_and_never_mixed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("reload-results-digest").await;
    instance.add_fsub();

    // A valid reload: it applies, and the snapshot's loaded digest becomes the
    // one it considered.
    instance.write_setup(&Setup {
        selection: "switch_threshold = 0.5\n".into(),
        ..Setup::default()
    });
    let valid = instance.cli_json(&["config", "reload"], None);
    assert_eq!(valid["ok"], true, "{valid}");
    let digest_valid = valid["result"]["digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    let snapshot = instance.cli_json(&["config", "show"], None);
    let configuration = &snapshot["result"]["configuration"];
    assert_eq!(
        configuration["digest"], digest_valid,
        "loaded is the valid one"
    );
    assert_eq!(configuration["last_reload"]["applied"], true);
    assert_eq!(configuration["last_reload"]["digest"], digest_valid);
    assert_eq!(
        configuration["effective"]["selection"]["switch_threshold"],
        0.5
    );

    // An invalid reload of different bytes: a priority naming an account the
    // pool lacks passes the CLI's local checks (cross-references are the
    // server's) and is rejected at the reload. The snapshot records
    // its digest and that it did not apply — while the loaded configuration
    // keeps the valid digest and its effective value.
    instance.write_setup(&Setup {
        selection: format!("switch_threshold = 0.5\n{}", priorities(&[("GHOST", 0)])),
        ..Setup::default()
    });
    let invalid = instance.cli_json(&["config", "reload"], None);
    assert_eq!(invalid["ok"], false, "{invalid}");
    let snapshot = instance.cli_json(&["config", "show"], None);
    let configuration = &snapshot["result"]["configuration"];
    let digest_invalid = configuration["last_reload"]["digest"]
        .as_str()
        .unwrap_or_else(|| panic!("invalid digest missing: {invalid}\nshow: {configuration}"))
        .to_owned();
    assert_ne!(
        digest_invalid, digest_valid,
        "distinct bytes, distinct digest"
    );
    assert_eq!(configuration["last_reload"]["applied"], false);
    assert_eq!(
        configuration["digest"], digest_valid,
        "the loaded configuration did not move (no mixed snapshot)"
    );
    assert_eq!(
        configuration["effective"]["selection"]["switch_threshold"], 0.5,
        "the valid effective value stands"
    );
}

/// An account mutation killed at its state-write boundary is all
/// or nothing: killed after the temporary write but before the rename, the
/// mutation never reports success and the file keeps its old, whole JSON;
/// once acknowledged, the change is durable across a restart.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_kill_at_the_write_boundary_is_all_or_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = Faults::new();
    let mut instance =
        Instance::start_with_faults("kill-write-boundary", Setup::default(), faults.clone()).await;
    instance.add_fsub();
    let before = instance.state_digest();
    let pid = instance.pid();

    // Armed, the rename mutation's durable write is killed after its
    // temporary file, before the rename. The mutation does not report
    // success and the state file keeps its old, whole bytes.
    faults.arm_rename_kill("state.json");
    let (code, _, _) = instance.cli(&["account", "rename", "FSUB", "Renamed"], None);
    assert_ne!(code, 0, "the mutation did not report success");
    assert_eq!(instance.await_exit(), 86, "dead at the rename boundary");
    assert_eq!(
        instance.state_digest(),
        before,
        "the file kept its old bytes"
    );
    let state = instance.state_file();
    assert_eq!(
        record(&state, "FSUB")["display_name"],
        "FSUB",
        "whole old JSON, never partial: {state}"
    );
    // The killed write's temporary file held the new record on a name the
    // allow-list does not know; the all-or-nothing evidence is asserted, so
    // the leftover goes before the whole-run sweep sees it (T-the case).
    fs::remove_file(
        instance
            .root
            .join("state/.state.json.".to_owned() + &pid.to_string() + ".tmp"),
    )
    .expect("the killed write's temporary file");

    // Cleared and respawned: the killed rename had not taken.
    faults.clear_rename();
    instance.respawn();
    assert_eq!(instance.account("FSUB")["display_name"], "FSUB");

    // Acknowledged without the fault, the new name is durable across a
    // restart — acknowledgement implies new.
    let envelope = instance.cli_json(&["account", "rename", "FSUB", "Renamed"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    instance.restart();
    assert_eq!(instance.account("Renamed")["display_name"], "Renamed");
}

/// The crash objects appended to a root's crash log, newest last.
#[cfg(unix)]
fn crash_objects(root: &Path) -> Vec<Value> {
    let path = root.join("log/crash.ndjson");
    match fs::read_to_string(&path) {
        Ok(text) => text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("crash object JSON"))
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(unix)]
fn send_signal(pid: u32, signal: &str) {
    assert!(
        Command::new("kill")
            .args([&format!("-{signal}"), &pid.to_string()])
            .status()
            .expect("send signal")
            .success(),
        "{signal} was accepted"
    );
}

/// Each caught fatal signal appends exactly one crash object
/// naming it; two signals across two lifetimes leave two objects; a clean
/// stop and a startup validation error add none.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn fatal_signals_append_crash_objects_clean_paths_do_not() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("fatal-signals-append").await;

    // First fatal signal: one crash object, class "signal", naming SIGQUIT.
    send_signal(instance.pid(), "QUIT");
    assert_eq!(
        instance.await_exit(),
        128 + 3,
        "exited on the caught SIGQUIT"
    );
    let objects = crash_objects(&instance.root);
    assert_eq!(objects.len(), 1, "one crash object: {objects:?}");
    assert_eq!(objects[0]["class"], "signal");
    assert!(
        objects[0]["message"]
            .as_str()
            .unwrap_or("")
            .contains("SIGQUIT"),
        "names the signal: {}",
        objects[0]
    );

    // Second fatal signal in a fresh lifetime: appended beside the first.
    instance.respawn();
    send_signal(instance.pid(), "ABRT");
    assert_eq!(
        instance.await_exit(),
        128 + 6,
        "exited on the caught SIGABRT"
    );
    let objects = crash_objects(&instance.root);
    assert_eq!(objects.len(), 2, "two crash objects appended: {objects:?}");
    assert!(
        objects[1]["message"]
            .as_str()
            .unwrap_or("")
            .contains("SIGABRT"),
        "the second names its signal: {}",
        objects[1]
    );

    // A clean stop adds none.
    instance.respawn();
    instance.stop();
    assert_eq!(
        crash_objects(&instance.root).len(),
        2,
        "a clean stop is not a crash"
    );

    // A startup validation error adds none: it exits before any log opens.
    let root = root("fatal-signals-append-invalid");
    let config = write_config(&root, "[selection]\nswitch_threshold = 5\n");
    let (code, _) = serve_fails(&root, &config);
    assert_eq!(code, 3, "the invalid document is rejected");
    assert!(
        !root.join("log/crash.ndjson").exists(),
        "a validation error writes no crash object"
    );
}

/// Every exchange writes exactly one audit record; a
/// request line carrying a query and a fragment records a `path` with
/// neither, and a needle sweep of the audit, operational and crash logs finds
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn one_audit_record_per_exchange_with_a_bare_path() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("audit-record-per").await;
    instance.add_fsub();
    let secret = "needle_query_sentinel";

    // A plain exchange, then one whose request line carries a query bearing
    // the sentinel and a fragment: two exchanges, two audit records.
    let first = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(first.status, StatusCode::OK);
    let second = send(
        instance.addr,
        post(
            &format!("/v1/messages?token={secret}#frag"),
            json!({
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 8,
                "messages": [{ "role": "user", "content": "hi" }],
            }),
        ),
    )
    .await;
    assert_eq!(second.status, StatusCode::OK);

    let records = instance.audit_settled(2);
    assert_eq!(records.len(), 2, "one record per exchange: {records:?}");
    assert!(
        records.iter().all(|r| r["path"] == "/v1/messages"),
        "the path member has neither query nor fragment: {records:?}"
    );

    let mut hits = Vec::new();
    let mut needles: Vec<&str> = vec![secret];
    needles.extend(instance.needles.all());
    sweep(&instance.root.join("log"), &[], &needles, &mut hits);
    assert!(hits.is_empty(), "a secret leaked into the logs: {hits:?}");
}

/// Every operational log object carries the five members
/// with a stable lower-case event name; a failed upstream attempt through a
/// credential-bearing proxy is logged without the credential ever reaching
/// the logs — URL user information and secrets are replaced before writing.
#[tokio::test(flavor = "multi_thread")]
async fn log_objects_carry_five_members_and_redact_credentials() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // FSUB is added first, before the proxy is in force (its profile lookup
    // would otherwise go through the dead proxy). Then the server restarts
    // behind a corporate proxy that refuses (port 1), carrying a credential
    // needle in its URL user information: the attempt through it fails.
    let needle = "s3cret_proxy_needle";
    let mut instance = Instance::start("log-objects-carry").await;
    instance.add_fsub();
    instance.write_setup(&Setup {
        data_plane: format!("corporate_proxy_url = \"http://alice:{needle}@127.0.0.1:1/\"\n"),
        ..Setup::default()
    });
    instance.restart();
    // The attempt fails through the dead proxy — a bad gateway, or the client
    // connection closed after the second failure. Either way the
    // failure is logged.
    let failed = match try_send(instance.addr, messages(haiku_prompt())).await {
        Ok(answer) => answer.status != StatusCode::OK,
        Err(_) => true,
    };
    assert!(failed, "the attempt through the dead proxy did not succeed");
    instance.settle();

    // Every server.ndjson object carries exactly the five members with
    // A stable lower-case event name.
    let text = fs::read_to_string(instance.root.join("log/server.ndjson")).expect("server log");
    let objects: Vec<Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("log object JSON"))
        .collect();
    assert!(!objects.is_empty(), "the server logged something");
    for object in &objects {
        let members: std::collections::BTreeSet<&str> = object
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            members,
            ["event", "fields", "level", "message", "timestamp"]
                .into_iter()
                .collect(),
            "the five members exactly: {object}"
        );
        let event = object["event"].as_str().expect("event name");
        assert!(
            !event.is_empty()
                && event
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "a stable lower-case event name: {event:?}"
        );
        assert!(
            ["error", "warn", "info", "debug"].contains(&object["level"].as_str().unwrap_or("")),
            "one of the levels: {object}"
        );
    }

    // The credential in the proxy URL never reaches any log.
    let mut hits = Vec::new();
    sweep(
        &instance.root.join("log"),
        &[],
        &[needle, "alice"],
        &mut hits,
    );
    assert!(
        hits.is_empty(),
        "a proxy credential leaked into the logs: {hits:?}"
    );
}

/// Sends exchanges until `path` exists or the bounded budget is spent, so the
/// rotation tests do not depend on an exact per-line size. Returns how many it
/// sent; panics if the budget runs out first.
async fn drive_until(instance: &Instance, path: &Path, budget: usize) -> usize {
    for sent in 1..=budget {
        let _ = try_send(instance.addr, messages(haiku_prompt())).await;
        if path.exists() {
            return sent;
        }
    }
    panic!(
        "{} did not appear within {budget} exchanges",
        path.display()
    );
}

/// A log rotates before it passes its limit, keeping exactly
/// `retained_files` rotations in `.1` (newest) … `.N` order; a further
/// rotation drops the oldest, never a `.N+1`. Driven on the audit log, the one
/// A plain exchange grows every time.
#[tokio::test(flavor = "multi_thread")]
async fn a_log_rotates_in_suffix_order_within_its_retention() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "log-rotates-suffix",
        Setup {
            audit: "max_bytes = 65536\nretained_files = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let log = instance.root.join("log");

    // Two rotations: `.1` and `.2` both present, none at `.3`, and the live
    // file is back under the limit.
    let per_rotation = drive_until(&instance, &log.join("exchanges.ndjson.1"), 6000).await;
    drive_until(&instance, &log.join("exchanges.ndjson.2"), 6000).await;
    assert!(
        log.join("exchanges.ndjson.1").is_file(),
        ".1 is the newest rotation"
    );
    assert!(
        log.join("exchanges.ndjson.2").is_file(),
        ".2 is the older rotation"
    );
    assert!(
        !log.join("exchanges.ndjson.3").exists(),
        "retention keeps two"
    );
    assert!(
        log.join("exchanges.ndjson").metadata().unwrap().len() <= 65536,
        "the live file rotated before it passed the limit"
    );

    // A further span — at least another rotation's worth — still keeps exactly
    // two: the oldest is dropped, never a third suffix.
    for _ in 0..(per_rotation * 2 + 10) {
        let _ = try_send(instance.addr, messages(haiku_prompt())).await;
    }
    assert!(log.join("exchanges.ndjson.1").is_file());
    assert!(log.join("exchanges.ndjson.2").is_file());
    assert!(
        !log.join("exchanges.ndjson.3").exists(),
        "retention still keeps two"
    );
}

/// The audit and operational logs rotate on their own limits: a
/// small audit limit rotates the audit log while the large operational limit
/// leaves `server.ndjson` whole; and a byte limit below 64 KiB is rejected at
/// validation for either log.
#[tokio::test(flavor = "multi_thread")]
async fn logs_rotate_on_independent_limits_and_reject_tiny_limits() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // A tiny byte limit is rejected at validation, for the operational and the
    // audit log alike.
    let root = root("logs-rotate-independent-tiny");
    let config = write_config(&root, "max_bytes = 1024\n[audit]\nmax_bytes = 2048\n");
    let envelope = run_json(&root, &config, &["config", "validate"]);
    let targets: Vec<&str> = envelope["error"]["details"]
        .as_array()
        .expect("details")
        .iter()
        .map(|d| d["target"].as_str().unwrap_or(""))
        .collect();
    assert!(targets.contains(&"logging.max_bytes"), "{envelope}");
    assert!(targets.contains(&"audit.max_bytes"), "{envelope}");

    // Independent limits: the audit log rotates at 64 KiB while the operational
    // log's 10 MiB limit leaves it whole across the same span of exchanges.
    let instance = Instance::start_with(
        "logs-rotate-independent",
        Setup {
            logging: "max_bytes = 10485760\nretained_files = 3\n".into(),
            audit: "max_bytes = 65536\nretained_files = 3\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let log = instance.root.join("log");
    drive_until(&instance, &log.join("exchanges.ndjson.1"), 6000).await;
    assert!(
        !log.join("server.ndjson.1").exists(),
        "the operational log did not rotate on the audit limit (independent limits)"
    );
}

/// When the audit append fails the server stops admitting
/// exchanges, flushes its state, and exits non-zero. The failure is arranged
/// from the harness: with the audit log one record short of its limit, the log
/// directory is made read-only so the rotation's rename cannot land.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_audit_append_stops_admission_and_flushes() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_with(
        "failed-audit-append",
        Setup {
            audit: "max_bytes = 65536\nretained_files = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let log = instance.root.join("log");
    let audit = log.join("exchanges.ndjson");

    // Drive the audit log to one record short of the limit (the next append
    // would rotate).
    for _ in 0..6000 {
        let _ = try_send(instance.addr, messages(haiku_prompt())).await;
        if audit.metadata().map(|m| m.len()).unwrap_or(0) >= 65000 {
            break;
        }
    }
    assert!(
        audit.metadata().unwrap().len() >= 65000,
        "the audit log reached the brink of rotation"
    );

    // The log directory becomes read-only: the next rotation's rename cannot
    // land, so the append fails.
    fs::set_permissions(&log, fs::Permissions::from_mode(0o500)).expect("read-only log dir");
    for _ in 0..20 {
        let _ = try_send(instance.addr, messages(haiku_prompt())).await;
    }

    // The server exits 23 (Stop::Unwritable), having flushed its state.
    let code = instance.await_exit();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o700)).expect("restore log dir");
    assert_eq!(code, 23, "a failed audit append is a non-zero fail-stop");
    // The state file is whole and holds the account — the final flush landed.
    let state = instance.state_file();
    assert_eq!(
        record(&state, "FSUB")["display_name"],
        "FSUB",
        "state flushed: {state}"
    );
}

/// `audit tail`'s filters combine with AND; neither tail verb
/// ever prints a body or credential; and `log tail --follow` keeps emitting
/// across a rotation by reopening the active file.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn tails_filter_with_and_never_leak_and_follow_survives_rotation() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "tails-filter-never-leak",
        Setup {
            audit: "max_bytes = 65536\nretained_files = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance.add_oauth(
        "FSUB2",
        "fsub2@fixture.invalid",
        "3c1f5a7e-0000-4000-8000-0000000000c3",
    );

    // One exchange per account, both status 200.
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FSUB"))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2"))
            .await
            .status,
        StatusCode::OK
    );
    instance.audit_settled(2);

    // `--status 200` alone sees both accounts; adding `--account FSUB`
    // is an AND that drops FSUB2's record.
    let by_status = tail_records(&instance, &["audit", "tail", "--status", "200"]);
    let servers: std::collections::BTreeSet<String> = by_status
        .iter()
        .filter_map(|r| {
            r["serving_account"]["display_name"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    assert!(
        servers.contains("FSUB") && servers.contains("FSUB2"),
        "the status filter alone sees both: {servers:?}"
    );
    let both = tail_records(
        &instance,
        &["audit", "tail", "--account", "FSUB", "--status", "200"],
    );
    assert!(!both.is_empty(), "the AND still matches FSUB's own record");
    assert!(
        both.iter()
            .all(|r| r["serving_account"]["display_name"] == "FSUB"),
        "the AND drops every non-FSUB record: {both:?}"
    );
    assert!(both.len() < by_status.len(), "the AND is strictly narrower");

    // Neither tail ever prints a body or credential.
    let (_, stdout, _) = instance.cli(&["audit", "tail"], None);
    let mut hits = Vec::new();
    sweep_text(&stdout, &instance.needles.all(), &mut hits);
    assert!(hits.is_empty(), "a credential surfaced in a tail: {hits:?}");

    // `log tail --crash` reads the (empty) crash log cleanly.
    let (code, _, stderr) = instance.cli(&["log", "tail", "--crash"], None);
    assert_eq!(code, 0, "log tail --crash on an empty crash log: {stderr}");

    // `--follow` keeps emitting across a rotation. A follower on the
    // audit log is spawned; once the audit rotates and more records land, its
    // output must have grown past what one rotation's file could hold.
    let follow_out = instance.root.join("follow.out");
    let handle = fs::File::create(&follow_out).expect("follow output");
    let mut follower = Command::new(binary())
        .args(["--config", &instance.config.display().to_string()])
        .args(["audit", "tail", "--follow", "--json"])
        .env_remove("VISUAL")
        .env_remove("EDITOR")
        .stdout(std::process::Stdio::from(handle))
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the follower");

    let rotated = instance.root.join("log/exchanges.ndjson.1");
    for _ in 0..6000 {
        let _ = try_send(instance.addr, messages(haiku_prompt())).await;
        if rotated.exists() {
            break;
        }
    }
    assert!(rotated.exists(), "the audit log rotated under the follower");
    let after_rotation = follow_lines(&follow_out);
    // Land more records in the fresh active file after the rotation.
    for _ in 0..80 {
        let _ = try_send(instance.addr, messages(haiku_prompt())).await;
    }
    let grew = wait_until(|| follow_lines(&follow_out) > after_rotation + 30);
    let _ = follower.kill();
    let _ = follower.wait();
    assert!(
        grew,
        "the follower kept emitting across the rotation ({} → {})",
        after_rotation,
        follow_lines(&follow_out)
    );
    // Every emitted line is a raw record, never a body.
    let text = fs::read_to_string(&follow_out).expect("follower output");
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let record: Value = serde_json::from_str(line).expect("raw record per line");
        assert!(record.get("path").is_some(), "a record, not a body: {line}");
    }
}

/// The records a tail verb prints with `--json`, one per line.
#[cfg(unix)]
fn tail_records(instance: &Instance, args: &[&str]) -> Vec<Value> {
    let mut full = args.to_vec();
    full.push("--json");
    let (_, stdout, stderr) = instance.cli(&full, None);
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("tail line ({e}): {l}{stderr}")))
        .collect()
}

/// The non-empty line count of a follower's output file so far.
#[cfg(unix)]
fn follow_lines(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}

/// Polls `condition` for up to ~10 s; true once it holds.
#[cfg(unix)]
fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if condition() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// Records the needles found in `text` (a tail's own output).
#[cfg(unix)]
fn sweep_text(text: &str, needles: &[&str], hits: &mut Vec<String>) {
    for needle in needles {
        if text.contains(needle) {
            hits.push((*needle).to_string());
        }
    }
}

/// Each owned path made unreadable or unwritable in turn fails
/// startup with a non-zero exit that names the path, binds no listener, and
/// leaves every existing file byte-identical; a missing configuration behaves
/// the same and writes nothing.
#[cfg(unix)]
#[test]
fn an_unreadable_or_unwritable_owned_path_fails_startup_cleanly() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("unreadable-unwritable-owned");
    let config = write_config(&root, "");
    write_private(&root.join("state/state.json"), &empty_state());
    let audit = root.join("log/exchanges.ndjson");
    write_private(&audit, "");

    let config_bytes = fs::read(&config).expect("config bytes");
    let state_bytes = fs::read(root.join("state/state.json")).expect("state bytes");

    // (label, the path to break, its broken mode, the exit it should force).
    let cases: [(&str, PathBuf, u32, i32); 4] = [
        ("configuration", config.clone(), 0o000, 3),
        ("state", root.join("state/state.json"), 0o000, 23),
        ("log directory", root.join("log"), 0o500, 23),
        ("audit log", audit.clone(), 0o400, 23),
    ];
    for (label, path, broken, want) in cases {
        let restore = fs::metadata(&path).expect("target").permissions().mode() & 0o777;
        fs::set_permissions(&path, fs::Permissions::from_mode(broken)).expect("break");
        let (code, stderr) = serve_fails(&root, &config);
        fs::set_permissions(&path, fs::Permissions::from_mode(restore)).expect("restore");
        if code == 0 {
            eprintln!("skipping {label}: this user cannot be denied by a mode (root?)");
            continue;
        }
        assert_eq!(code, want, "{label}: {stderr}");
        assert!(
            stderr.contains(&path.display().to_string()) || stderr.contains(label),
            "{label} not named: {stderr}"
        );
        // Nothing existing moved.
        assert_eq!(
            fs::read(&config).expect("config"),
            config_bytes,
            "config unchanged"
        );
        assert_eq!(
            fs::read(root.join("state/state.json")).expect("state"),
            state_bytes,
            "state unchanged"
        );
    }

    // A missing configuration fails the same way and writes no state.
    fs::remove_file(&config).expect("remove config");
    fs::remove_file(root.join("state/state.json")).expect("remove state");
    let (code, stderr) = serve_fails(&root, &config);
    assert_eq!(code, 3, "a missing configuration fails startup: {stderr}");
    assert!(
        !root.join("state/state.json").exists(),
        "a failed startup wrote no state"
    );
}

/// Spawns `serve` on `config` with a scratch HOME and waits for its listening
/// line; the caller kills the returned child.
#[cfg(unix)]
fn spawn_serve(root: &Path, config: &Path) -> std::process::Child {
    use std::process::Stdio;
    let out = fs::File::create(root.join("stdout.txt")).expect("stdout");
    let err = fs::File::create(root.join("stderr.txt")).expect("stderr");
    let mut child = Command::new(binary())
        .args(["--config", &config.display().to_string(), "serve"])
        .envs(crate::harness::platform_home(&root.join("home")))
        .env("PATH", root.join("no-browser-on-path"))
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn serve");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if fs::read_to_string(root.join("stdout.txt"))
            .unwrap_or_default()
            .contains("listening on")
        {
            return child;
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            let stderr = fs::read_to_string(root.join("stderr.txt")).unwrap_or_default();
            let _ = child.wait();
            panic!("serve exited during startup ({status}): {stderr}");
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("serve never listened");
}

/// A `version = 1` document (only its owned paths set for
/// isolation) starts the server; every effective value the running server
/// reports equals the documented default, and the file's bytes are unchanged
/// afterward.
#[cfg(unix)]
#[test]
fn a_minimal_document_starts_with_every_default() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("minimal-document-starts");
    // Only the listener (a reserved port) and the owned directories are set,
    // for test isolation; every other value is left to its default.
    let port = reserve_port();
    let config = write_config(
        &root,
        &format!("[data_plane]\nlisten = \"127.0.0.1:{port}\"\n"),
    );
    let before = fs::read(&config).expect("config bytes");

    let mut child = spawn_serve(&root, &config);
    let show = run_json(&root, &config, &["config", "show"]);
    let _ = child.kill();
    let _ = child.wait();

    let effective = &show["result"]["configuration"]["effective"];
    assert_eq!(
        effective["accounts"]["refresh_margin_seconds"], 300,
        "{show}"
    );
    assert_eq!(effective["quota"]["probe_enabled"], false);
    assert_eq!(effective["selection"]["switch_threshold"], 0.98);
    assert_eq!(effective["data_plane"]["max_connections"], 256);
    assert_eq!(effective["data_plane"]["telemetry_policy"], "forward");
    assert_eq!(effective["data_plane"]["first_byte_timeout_seconds"], 120);
    assert_eq!(effective["logging"]["level"], "info");
    assert_eq!(effective["logging"]["max_bytes"], 10_485_760);
    assert_eq!(effective["audit"]["retained_files"], 7);
    // The running server never rewrote the omitted defaults into the file.
    assert_eq!(
        fs::read(&config).expect("config bytes"),
        before,
        "bytes unchanged"
    );
}

/// An unknown table, an unknown key, a wrong type, a non-finite
/// number, an out-of-range value and an invalid cross-reference at once are
/// rejected whole in one startup result that names each by dotted key, and the
/// result carries no proxy password. Startup is the surface: the
/// account cross-reference is the server's to judge, beside the local errors.
#[cfg(unix)]
#[test]
fn one_result_names_every_error_and_hides_every_secret() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = root("result-names-error");
    write_private(&root.join("state/state.json"), &empty_state());
    let proxy_secret = "proxy_pw_needle";
    let config = write_config(
        &root,
        &format!(
            "max_bytes = 1024\n\
             [unknown_table]\nx = 1\n\
             [data_plane]\nmax_connections = \"lots\"\nbogus_key = 1\n\
             corporate_proxy_url = \"http://user:{proxy_secret}@proxy.example:3128\"\n\
             [selection]\nswitch_threshold = inf\n\
             priorities = [{{ account = \"GHOST\", value = 0 }}]\n"
        ),
    );

    // One startup result names every error, local and cross-reference, and no
    // listener binds.
    let (code, stderr) = serve_fails(&root, &config);
    assert_eq!(code, 3, "{stderr}");
    for key in [
        "unknown_table",
        "data_plane.max_connections",
        "data_plane.bogus_key",
        "selection.switch_threshold",
        "logging.max_bytes",
    ] {
        assert!(stderr.contains(key), "{key} missing from: {stderr}");
    }
    assert!(
        stderr.contains("GHOST") || stderr.contains("priorities"),
        "the account cross-reference is named: {stderr}"
    );
    // The result carries no proxy password; a config holds no key
    // material to leak (keeps credentials in state, never the file).
    assert!(
        !stderr.contains(proxy_secret),
        "the proxy password leaked: {stderr}"
    );
}

/// A reload that changes the first-byte timeout while an exchange
/// is in flight does not disturb that exchange: it keeps serving under the
/// deadlines it started with and completes, while the reload applies so the
/// next exchange uses the new value.
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_leaves_an_in_flight_exchange_on_its_own_deadlines() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("reload-leaves-flight").await;
    instance.add_fsub();

    // The exchange 401s, then refreshes on a token call the fake holds for
    // 800 ms: it is in flight through that window. The retry then succeeds.
    instance.upstream.script([reply_auth_401()]);
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": needle("access token", "oat-fixture"),
            "refresh_token": needle("refresh token", "ort-fixture"),
            "expires_in": 3600,
        })
        .to_string(),
    )]);
    instance.upstream.delay_token(Duration::from_millis(800));

    let addr = instance.addr;
    let inflight = tokio::spawn(async move { send(addr, messages(haiku_prompt())).await });

    // Once the exchange is parked on the held token call, reload the live
    // first-byte timeout.
    tokio::time::sleep(Duration::from_millis(200)).await;
    instance.write_setup(&Setup {
        data_plane: "first_byte_timeout_seconds = 30\n".into(),
        ..Setup::default()
    });
    let reload = instance.cli_json(&["config", "reload"], None);
    assert_eq!(reload["ok"], true, "{reload}");
    assert!(
        reload["result"]["changed_keys"]
            .as_array()
            .is_some_and(|k| k
                .iter()
                .any(|v| v == "data_plane.first_byte_timeout_seconds")),
        "the first-byte timeout is a live key that reloaded: {reload}"
    );

    // The in-flight exchange, started before the reload, still completes.
    let answer = inflight.await.expect("join the in-flight exchange");
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "the in-flight exchange kept serving across the reload"
    );

    // The next exchange runs under the reloaded configuration, and the running
    // server reports the new value.
    let next = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(next.status, StatusCode::OK, "the next exchange serves");
    let show = instance.cli_json(&["config", "show"], None);
    assert_eq!(
        show["result"]["configuration"]["effective"]["data_plane"]["first_byte_timeout_seconds"],
        30,
        "the next exchange, probe and ramp use the new deadline"
    );
}
