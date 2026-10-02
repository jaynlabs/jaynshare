//! The command-line surface: verbs, options, exit codes, JSON envelopes,
//! help and schemas.
use crate::harness::*;

/// The envelope members, in order, and nothing else but `role` on
/// the two dual-role verbs.
fn assert_envelope(envelope: &Value, command: &str, dual_role: bool) {
    let members: Vec<&str> = envelope
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected = vec![
        "cli_version",
        "command",
        "ok",
        "exit_code",
        "result",
        "error",
    ];
    if dual_role {
        expected.push("role");
    }
    assert_eq!(members, expected, "{envelope}");
    assert_eq!(envelope["command"], command, "{envelope}");
    assert_eq!(envelope["cli_version"], env!("CARGO_PKG_VERSION"));
    if envelope["ok"] == true {
        assert_eq!(envelope["exit_code"], 0);
        assert!(envelope["error"].is_null());
    } else {
        assert_ne!(envelope["exit_code"], 0);
        assert!(envelope["result"].is_null());
        assert!(envelope["error"]["code"].is_string());
    }
}

/// The release surface's top-level help, per-verb help and JSON
/// schemas agree on exactly one verb set; the retained vocabulary is present,
/// and there is no alias and no watch/full-screen status verb.
#[test]
fn help_grammar_and_schema_name_one_verb_set() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("help-grammar-schema");
    let env = isolated_env(&root);
    let (code, help, stderr) = cli_raw(&["help"], &env, None);
    assert_eq!(code, 0, "{stderr}");

    let mut help_paths: std::collections::BTreeSet<String> = help
        .lines()
        .filter(|line| line.starts_with("  "))
        .filter_map(|line| {
            let line = line.trim();
            (!line.starts_with('-') && !line.ends_with(':'))
                .then(|| line.split("  ").next().unwrap_or_default().to_owned())
        })
        .collect();
    let (code, stdout, stderr) = cli_raw(&["schema", "--json"], &env, None);
    assert_eq!(code, 0, "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("schema envelope");
    let mut schema_paths: std::collections::BTreeSet<String> = envelope["result"]
        .as_object()
        .expect("schema map")
        .keys()
        .cloned()
        .collect();
    schema_paths.extend(
        ["claude", "env", "statusline", "title-hook"]
            .into_iter()
            .map(str::to_owned),
    );
    assert_eq!(
        help_paths, schema_paths,
        "help, grammar and schema disagree"
    );

    for path in &help_paths {
        let mut args = vec!["help"];
        args.extend(path.split_whitespace());
        let (code, stdout, stderr) = cli_raw(&args, &env, None);
        assert_eq!(code, 0, "{path}: {stderr}");
        assert!(stdout.contains("Usage: jaynshare"), "{path}: {stdout}");
    }
    for word in [
        "status", "switch", "claude", "env", "probe", "route", "client", "service", "api", "alias",
    ] {
        assert!(
            help_paths
                .iter()
                .any(|path| path == word || path.starts_with(&format!("{word} ")))
        );
    }
    for alias in ["enroll", "watch", "tui", "routes", "logs", "account ls"] {
        let args: Vec<_> = alias.split_whitespace().collect();
        assert_eq!(cli_raw(&args, &env, None).0, 2, "unexpected alias {alias}");
    }
    assert!(!help_paths.remove("watch") && !help_paths.remove("tui"));
}

/// An unknown verb, an unknown option, a missing argument, a
/// value outside a closed set and two exclusive options are each one usage
/// line on standard error, exit 2 and no effect; with `--json` the envelope
/// says `cli_usage`.
#[tokio::test(flavor = "multi_thread")]
async fn usage_errors_exit_2_with_one_usage_line_and_no_effect() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("usage-errors-exit").await;
    instance.add_fsub();
    let state_before = instance.state_digest();
    let config_before = fs::read(&instance.config).expect("configuration");
    let cases: &[(&str, &[&str])] = &[
        ("unknown verb", &["statsu"]),
        ("unknown option", &["status", "--bogus"]),
        ("missing argument", &["account", "rename"]),
        (
            "value outside a closed set",
            &["claude", "--picker", "wheel"],
        ),
        ("two exclusive options", &["claude", "--auto", "--direct"]),
        (
            "two exclusive source flags",
            &["account", "add", "--api-key", "--portable", "--name", "x"],
        ),
        ("group word alone", &["account"]),
    ];
    for (label, args) in cases {
        let (code, stderr) = instance.cli_usage(args);
        assert_eq!(code, 2, "{label}: {stderr}");
        assert!(
            stderr.contains("Usage: jaynshare"),
            "{label}: the verb's usage line is on standard error: {stderr}"
        );
        let mut with_json = args.to_vec();
        with_json.push("--json");
        let (code, stdout, stderr) = instance.cli(&with_json, None);
        assert_eq!(code, 2, "{label} --json: {stderr}");
        let envelope: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{label}: {e}: {stdout}"));
        assert_eq!(envelope["ok"], false, "{label}: {envelope}");
        assert_eq!(envelope["exit_code"], 2, "{label}: {envelope}");
        assert_eq!(
            envelope["error"]["code"], "cli_usage",
            "{label}: {envelope}"
        );
        assert_eq!(stdout.trim().lines().count(), 1, "{label}: one document");
    }
    assert_eq!(
        instance.state_digest(),
        state_before,
        "no usage error touched state"
    );
    assert_eq!(
        fs::read(&instance.config).expect("configuration"),
        config_before,
        "no usage error touched the file"
    );
    assert_eq!(
        instance.audit().len(),
        0,
        "no usage error reached the server (nothing to audit)"
    );
}

/// Every global option is accepted before and after the verb
/// with one meaning; `--` stops option parsing for `claude`.
#[tokio::test(flavor = "multi_thread")]
async fn global_options_before_and_after_the_verb_and_double_dash() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("global-options-verb").await;
    instance.add_fsub();
    let config = instance.config.display().to_string();
    let home = instance.root.join("home");
    let env = isolated_env(&home);

    let before = cli_raw(
        &[
            "--json",
            "-q",
            "--no-color",
            "--timeout",
            "5",
            "--yes",
            "--config",
            &config,
            "account",
            "list",
        ],
        &env,
        None,
    );
    let after = cli_raw(
        &[
            "account",
            "list",
            "--json",
            "--quiet",
            "--no-color",
            "--timeout=5",
            "--yes",
            "--config",
            &config,
        ],
        &env,
        None,
    );
    assert_eq!(before.0, 0, "{}", before.2);
    assert_eq!(after.0, 0, "{}", after.2);
    let first: Value = serde_json::from_str(before.1.trim()).expect("envelope");
    let second: Value = serde_json::from_str(after.1.trim()).expect("envelope");
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(
        first["result"]["accounts"], second["result"]["accounts"],
        "the same reading either way"
    );

    // --server, --operator-secret-file and --tls-ca, before and after: both
    // reach the addressed instance with the bearer from the file, never argv.
    let secret = secret_file(
        &instance.root,
        "operator-secret",
        "jso2_fixture_operator_secret",
    );
    let anchor = secret_file(&instance.root, "anchor.pem", "");
    let fake = FakeControl::answering(
        200,
        json!({ "control_api_version": 1, "captured_at": "2026-01-01T00:00:00Z", "accounts": [] }),
    );
    let origin = fake.origin();
    let (secret_path, anchor_path) = (secret.display().to_string(), anchor.display().to_string());
    for args in [
        vec![
            "--server",
            &origin,
            "--operator-secret-file",
            &secret_path,
            "--tls-ca",
            &anchor_path,
            "account",
            "list",
            "--json",
        ],
        vec![
            "account",
            "list",
            "--json",
            "--server",
            &origin,
            "--operator-secret-file",
            &secret_path,
            "--tls-ca",
            &anchor_path,
        ],
    ] {
        let (code, stdout, stderr) = cli_raw(&args, &env, None);
        assert_eq!(code, 0, "{stderr}");
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
        assert_eq!(envelope["result"]["accounts"], json!([]), "{envelope}");
    }
    let seen = fake.seen();
    assert_eq!(seen.len(), 2, "one request per invocation");
    for request in &seen {
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer jso2_fixture_operator_secret"),
            "the bearer travels in the header: {request}"
        );
        assert!(
            !request.to_ascii_lowercase().contains("\norigin:")
                && !request.contains("sec-fetch-site"),
            "no origin or sec-fetch-site on a command-line call"
        );
    }

    // `--` ends parsing for `claude`: `--picker wheel` after it is Claude Code's
    // to judge, not a usage error; the launcher then fails on its own row
    // (11: not enrolled) rather than on the grammar.
    let (code, _, stderr) = cli_raw(&["claude", "--auto", "--", "--picker", "wheel"], &env, None);
    assert_eq!(code, 11, "{stderr}");
    let (code, _, stderr) = cli_raw(&["claude", "--picker", "wheel", "--auto"], &env, None);
    assert_eq!(code, 2, "before `--` the closed set is enforced: {stderr}");

    // A configuration that listens on the
    // wildcard address still reaches `127.0.0.1`, never a remote operator.
    let mut wild = Instance::start_with(
        "global-options-verb-wild",
        Setup {
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let envelope = wild.cli_json(&["account", "list"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    wild.stop();
}

/// A refused connection is exit 4 naming the origin and the
/// configuration path; a response that is not the control envelope, or one
/// carrying an unknown control version, is exit 10 and never 4.
#[tokio::test(flavor = "multi_thread")]
async fn unreachable_is_4_and_an_incompatible_answer_is_10() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("unreachable-4-incompatible");
    let env = isolated_env(&root);
    let (code, _, stderr) = cli_raw(&["status"], &env, None);
    assert_eq!(code, 3, "operator status without a configuration: {stderr}");

    let mut instance = Instance::start("unreachable-4-incompatible-answer").await;
    let origin = format!("http://{}", instance.addr);
    instance.stop();
    for verb in [vec!["status"], vec!["switch", "FSUB"]] {
        let envelope = instance.cli_json(&verb, None);
        assert_eq!(envelope["exit_code"], 4, "{envelope}");
        assert_eq!(envelope["error"]["code"], "cli_unreachable");
        let message = envelope["error"]["message"].as_str().expect("message");
        assert!(message.contains(&origin), "names the origin: {message}");
        assert!(
            message.contains(&instance.config.display().to_string()),
            "names the configuration path: {message}"
        );
        assert!(
            message.contains("service status"),
            "names the verbs to check: {message}"
        );
    }

    let env = isolated_env(&instance.root.join("home"));
    let secret = secret_file(&instance.root, "op-secret", "test-value");
    let secret = secret.display().to_string();

    // with `--server` the same verb needs no
    // configuration file at all.
    let live = FakeControl::answering(
        200,
        json!({ "control_api_version": 1, "captured_at": "2026-01-01T00:00:00Z", "accounts": [] }),
    );
    let (code, stdout, stderr) = cli_raw(
        &[
            "--server",
            &live.origin(),
            "--operator-secret-file",
            &secret,
            "account",
            "list",
            "--json",
        ],
        &env,
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["result"]["accounts"], json!([]), "{envelope}");

    let html =
        FakeControl::start(|_| http_reply(200, "text/html", "<html>not a control plane</html>"));
    let (code, stdout, _) = cli_raw(
        &[
            "--server",
            &html.origin(),
            "--operator-secret-file",
            &secret,
            "status",
            "--json",
        ],
        &env,
        None,
    );
    assert_eq!(code, 10);
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(
        envelope["error"]["code"], "cli_incompatible_server",
        "{envelope}"
    );
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("not a control envelope"),
        "{envelope}"
    );

    let future = FakeControl::answering(
        200,
        json!({ "control_api_version": 99, "captured_at": "2026-01-01T00:00:00Z", "status": {} }),
    );
    let (code, stdout, _) = cli_raw(
        &[
            "--server",
            &future.origin(),
            "--operator-secret-file",
            &secret,
            "status",
            "--json",
        ],
        &env,
        None,
    );
    assert_eq!(code, 10, "never 4: the server answered");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(
        envelope["error"]["code"], "cli_incompatible_server",
        "{envelope}"
    );
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("99") && message.contains('1'),
        "names the version served and the version expected: {message}"
    );
}

/// Standard output holds only the answer; a hint goes to
/// standard error and `--quiet` removes it; a warning survives `--quiet`;
/// `--json` standard output is one parseable document.
#[tokio::test(flavor = "multi_thread")]
async fn two_streams_quiet_and_one_document() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("two-streams-quiet").await;
    instance.add_fsub();

    // A verb with a hint: `config validate` notes what it did not check.
    let (code, stdout, stderr) = instance.cli(&["config", "validate"], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains("valid") && stdout.contains("digest"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("not checked"),
        "the hint is not on standard output: {stdout}"
    );
    assert!(
        stderr.contains("not checked"),
        "the hint is on standard error: {stderr}"
    );
    let (code, stdout_quiet, stderr) = instance.cli(&["config", "validate", "--quiet"], None);
    assert_eq!(code, 0);
    assert_eq!(
        stdout_quiet, stdout,
        "--quiet never touches standard output"
    );
    assert!(stderr.is_empty(), "--quiet removes the hint: {stderr}");

    // A verb with a warning: `switch` to an ineligible account.
    instance.cli_json(&["account", "disable", "FSUB"], None);
    let (code, stdout, stderr) = instance.cli(&["switch", "FSUB", "--quiet"], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("warning"),
        "--quiet keeps the warning: {stderr}"
    );
    assert!(
        !stdout.contains("warning"),
        "the warning is not the answer: {stdout}"
    );

    // A silent success writes nothing to standard output.
    let (code, stdout, _) = instance.cli(&["status", "--check"], None);
    assert_eq!(code, 0);
    assert!(stdout.is_empty());

    // A refusal is on standard error, --quiet or not.
    let (code, stdout, stderr) = instance.cli(&["account", "show", "nobody", "--quiet"], None);
    assert_eq!(code, 6);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("no account matches"), "{stderr}");

    // --json: one document, the envelope's members, nothing else on stdout.
    for (args, command, dual) in [
        (vec!["status"], "status", true),
        (vec!["account", "list"], "account list", true),
        (vec!["switch", "FSUB"], "switch", false),
        (vec!["account", "show", "nobody"], "account show", false),
        (vec!["config", "validate"], "config validate", false),
    ] {
        let mut with_json = args.clone();
        with_json.push("--json");
        let (_, stdout, _) = instance.cli(&with_json, None);
        assert_eq!(
            stdout.trim().lines().count(),
            1,
            "{args:?}: one line: {stdout}"
        );
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("one document");
        assert_envelope(&envelope, command, dual);
    }
}

/// Colour appears only on a terminal; `NO_COLOR`, `--no-color`
/// and a pipe each remove every escape sequence and leave the same facts.
#[tokio::test(flavor = "multi_thread")]
async fn colour_only_on_a_terminal_and_the_same_facts_without() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("colour-terminal-facts").await;
    instance.add_fsub();
    let config = instance.config.display().to_string();
    let env = isolated_env(&instance.root.join("home"));

    let (code, terminal) = cli_pty(
        "colour-terminal-facts-tty",
        &["--config", &config, "status"],
        &env,
        None,
    );
    assert_eq!(code, 0, "{terminal}");
    assert!(
        terminal.contains("\x1b["),
        "a terminal gets colour: {terminal:?}"
    );

    let mut no_color_env = env.clone();
    no_color_env.push(("NO_COLOR".into(), "1".into()));
    let (code, with_variable) = cli_pty(
        "colour-terminal-facts-var",
        &["--config", &config, "status"],
        &no_color_env,
        None,
    );
    assert_eq!(code, 0);
    assert!(
        !with_variable.contains('\x1b'),
        "NO_COLOR: {with_variable:?}"
    );

    let (code, with_flag) = cli_pty(
        "colour-terminal-facts-flag",
        &["--config", &config, "status", "--no-color"],
        &env,
        None,
    );
    assert_eq!(code, 0);
    assert!(!with_flag.contains('\x1b'), "--no-color: {with_flag:?}");

    let (code, piped, _) = instance.cli(&["status"], None);
    assert_eq!(code, 0);
    assert!(!piped.contains('\x1b'), "a pipe: {piped:?}");

    // The same facts: every line of every rendering, once the escapes
    // and the terminal's carriage returns are gone.
    let facts = |text: &str| {
        strip_ansi(text)
            .lines()
            .map(|l| l.trim_end().to_string())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
    };
    let reference = facts(&piped);
    assert!(reference.iter().any(|l| l.contains("FSUB")));
    for rendering in [&terminal, &with_variable, &with_flag] {
        assert_eq!(facts(rendering), reference, "the same facts either way");
    }
}

/// Help at each level exits 0 on standard output, reads no
/// file and makes no request; a bare invocation prints the top-level help
/// on standard error and exits 2.
#[tokio::test(flavor = "multi_thread")]
async fn help_never_reads_or_connects_and_bare_invocation_is_2() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("help-never-reads");
    let fake = FakeControl::answering(200, json!({ "control_api_version": 1 }));
    // A configuration that would point every verb at the fake — and a path
    // that does not exist, to show help never opens it either.
    let config = root.join("config.toml");
    write_private(
        &config,
        &format!("version = 1\n\n[data_plane]\nlisten = \"{}\"\n", fake.addr),
    );
    let config = config.display().to_string();
    let mut env = isolated_env(&root.join("home"));
    env.push(("JAYNSHARE_CONFIG".into(), "/nonexistent/config.toml".into()));

    let levels: &[&[&str]] = &[
        &["--help"],
        &["-h"],
        &["help"],
        &["help", "account"],
        &["help", "account", "add"],
        &["account", "--help"],
        &["account", "add", "--help"],
        &["status", "-h"],
        &["--config", &config, "help", "switch"],
        &["--config", "/nonexistent/config.toml", "switch", "--help"],
        &["serve", "--help"],
        &["claude", "--help"],
        &["server", "install", "--help"],
    ];
    for args in levels {
        let (code, stdout, stderr) = cli_raw(args, &env, None);
        assert_eq!(code, 0, "{args:?}: {stderr}");
        assert!(
            stdout.contains("Usage: jaynshare"),
            "{args:?}: help on standard output: {stdout}"
        );
        assert!(
            stderr.is_empty(),
            "{args:?}: nothing on standard error: {stderr}"
        );
    }
    // Verb help states exit rows beyond 0/1/2 and examples with placeholders.
    let (_, stdout, _) = cli_raw(&["help", "account", "remove"], &env, None);
    assert!(stdout.contains("Exit codes beyond 0/1/2"), "{stdout}");
    assert!(stdout.contains("21"), "the confirmation row: {stdout}");
    assert!(
        stdout.contains("Examples:") && stdout.contains("<reference>"),
        "{stdout}"
    );
    let (_, stdout, _) = cli_raw(&["help"], &env, None);
    for heading in [
        "Engineer verbs",
        "Operator verbs",
        "Deploy verbs",
        "Server verb",
    ] {
        assert!(stdout.contains(heading), "{heading}: {stdout}");
    }
    assert!(fake.seen().is_empty(), "help made no request");

    let (code, stdout, stderr) = cli_raw(&[], &env, None);
    assert_eq!(code, 2, "a bare invocation is a usage error");
    assert!(stdout.is_empty(), "nothing on standard output: {stdout}");
    assert!(
        stderr.contains("Usage: jaynshare") && stderr.contains("Operator verbs"),
        "{stderr}"
    );
    let (code, _, stderr) = cli_raw(&["--json"], &env, None);
    assert_eq!(code, 2, "a global option alone is still bare: {stderr}");
}

/// `version` and `--version` print the same single line
/// `jaynshare <semver> (<commit>, <target>)`; the `--json` result carries
/// exactly `version`, `commit` and `target`; nothing else is needed on the
/// machine. The release-manifest half waits for.
#[tokio::test(flavor = "multi_thread")]
async fn version_forms_agree_and_carry_the_build_identity() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("version-forms-agree");
    let mut env = isolated_env(&root.join("home"));
    env.push(("JAYNSHARE_CONFIG".into(), "/nonexistent/config.toml".into()));
    let (code, verb, stderr) = cli_raw(&["version"], &env, None);
    assert_eq!(code, 0, "{stderr}");
    let (code, flag, _) = cli_raw(&["--version"], &env, None);
    assert_eq!(code, 0);
    let (code, short, _) = cli_raw(&["-V"], &env, None);
    assert_eq!(code, 0);
    assert_eq!(verb, flag);
    assert_eq!(verb, short);
    assert_eq!(verb.lines().count(), 1, "one line: {verb}");
    let (code, stdout, _) = cli_raw(&["version", "--json"], &env, None);
    assert_eq!(code, 0);
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_envelope(&envelope, "version", false);
    let result = envelope["result"].as_object().expect("result object");
    let mut members: Vec<&str> = result.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(members, ["commit", "target", "version"]);
    assert_eq!(result["version"], env!("CARGO_PKG_VERSION"));
    let commit = result["commit"].as_str().expect("commit");
    assert!(
        commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit()),
        "a full commit: {commit}"
    );
    let target = result["target"].as_str().expect("target");
    assert_eq!(
        verb.trim(),
        format!(
            "jaynshare {} ({commit}, {target})",
            result["version"].as_str().unwrap()
        )
    );
}

/// Every verb's `--json` output validates against `schema
/// <verb>`, success and failure alike; the schema of a control-backed verb
/// binds the control body as served.
#[tokio::test(flavor = "multi_thread")]
async fn every_json_document_validates_against_its_schema() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("json-document-validates").await;
    instance.add_fsub();
    instance.add_fkey();
    let key_file = secret_file(
        &instance.root,
        "key",
        &needle("file channel API key", "test"),
    );
    let key_file = key_file.display().to_string();
    let empty = secret_file(&instance.root, "empty.toml", "version = 1\n")
        .display()
        .to_string();
    let all = instance.cli_json(&["schema"], None);
    assert_eq!(all["ok"], true, "{all}");
    let schema_of = |verb: &str| -> Value {
        let words: Vec<&str> = verb.split(' ').collect();
        let mut args = vec!["schema"];
        args.extend(words);
        let envelope = instance.cli_json(&args, None);
        assert_eq!(envelope["ok"], true, "schema {verb}: {envelope}");
        assert_eq!(
            envelope["result"], all["result"][verb],
            "one schema per verb, whole or alone"
        );
        envelope["result"].clone()
    };
    // Every verb once, with its stdin where one is needed; the FSUB
    // login row starts a flow and cancels it.
    let (login_id, _) = {
        let started = instance.cli_json(&["account", "login", "--no-wait"], None);
        assert_eq!(started["ok"], true, "{started}");
        (
            started["result"]["operation_id"]
                .as_str()
                .unwrap()
                .to_string(),
            (),
        )
    };
    let runs: Vec<(&str, Vec<&str>, Option<&str>)> = vec![
        ("status", vec!["status"], None),
        ("status", vec!["status", "--accounts"], None),
        ("account list", vec!["account", "list"], None),
        ("account show", vec!["account", "show", "FSUB"], None),
        ("account show", vec!["account", "show", "nobody"], None),
        (
            "account add",
            vec![
                "account",
                "add",
                "--api-key",
                "--name",
                "K2",
                "--file",
                &key_file,
            ],
            None,
        ),
        (
            "account add",
            vec![
                "account",
                "add",
                "--api-key",
                "--name",
                "K2",
                "--file",
                &key_file,
            ],
            None,
        ),
        (
            "account replace",
            vec!["account", "replace", "K2", "--api-key", "--stdin"],
            Some("sk-ant-api03-replacement"),
        ),
        (
            "account rename",
            vec!["account", "rename", "K2", "K3"],
            None,
        ),
        ("account disable", vec!["account", "disable", "K3"], None),
        ("account enable", vec!["account", "enable", "K3"], None),
        (
            "account remove",
            vec!["account", "remove", "K3", "--yes"],
            None,
        ),
        ("account login", vec!["account", "login", "--no-wait"], None),
        (
            "account operation show",
            vec!["account", "operation", "show", &login_id],
            None,
        ),
        (
            "account operation cancel",
            vec!["account", "operation", "cancel", &login_id],
            None,
        ),
        (
            "account operation code",
            vec!["account", "operation", "code", &login_id, "--stdin"],
            Some("code"),
        ),
        ("switch", vec!["switch"], None),
        ("switch", vec!["switch", "FKEY"], None),
        ("switch", vec!["switch", "nobody"], None),
        (
            "route add",
            vec![
                "route",
                "add",
                "h",
                "--pattern",
                "*haiku*",
                "--account",
                "FSUB",
            ],
            None,
        ),
        ("route list", vec!["route", "list"], None),
        ("route list", vec!["route", "list", "--local"], None),
        ("switch", vec!["switch", "--route", "h", "FSUB"], None),
        ("switch", vec!["switch", "--route", "h", "--clear"], None),
        ("route rm", vec!["route", "rm", "h"], None),
        ("priority set", vec!["priority", "set", "FSUB", "1"], None),
        ("priority list", vec!["priority", "list"], None),
        ("priority clear", vec!["priority", "clear", "FSUB"], None),
        ("block add", vec!["block", "add", "*opus*"], None),
        ("block list", vec!["block", "list"], None),
        ("block rm", vec!["block", "rm", "*opus*"], None),
        ("probe", vec!["probe"], None),
        ("config validate", vec!["config", "validate"], None),
        (
            "config validate",
            vec!["config", "validate", "/nonexistent"],
            None,
        ),
        ("config reload", vec!["config", "reload"], None),
        (
            "config set",
            vec!["config", "set", "logging.level", "info"],
            None,
        ),
        (
            "config unset",
            vec!["config", "unset", "logging.level"],
            None,
        ),
        (
            "config set",
            vec!["config", "set", "data_plane.listen", "\"127.0.0.1:1\""],
            None,
        ),
        ("api", vec!["api", "GET", "/control/v1/status"], None),
        ("api", vec!["api", "GET", "/v1/nothing"], None),
        ("version", vec!["version"], None),
        ("help", vec!["help", "status"], None),
        ("schema", vec!["schema", "status"], None),
        ("client list", vec!["client", "list"], None),
        ("service status", vec!["service", "status"], None),
        ("secret set", vec!["secret", "set", "--stdin"], Some("x")),
        ("config edit", vec!["config", "edit"], None),
        ("config edit", vec!["config", "edit", "--offline"], None),
        ("config paths", vec!["config", "paths"], None),
        ("config show", vec!["config", "show"], None),
        ("config show", vec!["config", "show", "--local"], None),
        ("log tail", vec!["log", "tail"], None),
        ("log tail", vec!["log", "tail", "--crash"], None),
        ("audit tail", vec!["audit", "tail"], None),
    ];
    for (verb, args, stdin) in runs {
        let schema = schema_of(verb);
        let mut with_json = args.clone();
        with_json.push("--json");
        // `config edit` runs a no-op editor: the file comes back as it was.
        let (code, stdout, stderr) = instance.cli_env(&with_json, stdin, &[("EDITOR", "true")]);
        if verb == "log tail" || verb == "audit tail" {
            // One raw object per line, no envelope (or nothing yet).
            assert_eq!(code, 0, "{args:?}: {stderr}");
            assert!(
                !stdout.is_empty() || verb == "log tail",
                "{args:?}: some lines"
            );
            for line in stdout.lines() {
                let object: Value =
                    serde_json::from_str(line).unwrap_or_else(|e| panic!("{args:?}: {e}: {line}"));
                validate(&schema, &object).unwrap_or_else(|why| panic!("{args:?}: {why}"));
            }
            continue;
        }
        let envelope: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{args:?} (exit {code}): {e}: {stdout}{stderr}"));
        validate(&schema, &envelope).unwrap_or_else(|why| panic!("{args:?}: {why}\n{envelope}"));
        assert_eq!(envelope["command"], verb, "{args:?}: {envelope}");
    }
    let _ = empty;
    // A verb with no --json has no schema.
    for verb in ["claude", "env", "statusline", "title-hook"] {
        let (code, _, _) = instance.cli(&["schema", verb], None);
        assert_eq!(code, 2, "schema {verb}");
        assert!(all["result"].get(verb).is_none());
    }
    // The control-backed schema binds the control body: the status result requires
    // control_api_version and captured_at, and every snapshot member.
    let status = all["result"]["status"].clone();
    let snapshot = &status["$defs"]["status_snapshot"];
    for member in [
        "server",
        "capture",
        "mitm",
        "accounts",
        "default_account",
        "routes",
        "blocked_models",
        "sessions",
        "usage_probe",
        "configuration",
        "storage",
        "clients",
    ] {
        assert!(
            snapshot["required"]
                .as_array()
                .unwrap()
                .contains(&json!(member)),
            "{member}"
        );
    }
    assert_eq!(
        status["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );

    let (code, body, stderr) = instance.cli(&["api", "GET", "/control/v1/status"], None);
    assert_eq!(code, 0, "{stderr}");
    let direct: Value = serde_json::from_str(body.trim()).expect("control body");
    let fake = FakeControl::answering(200, direct.clone());
    let secret = secret_file(&instance.root, "operator", "jso2_fixture_operator")
        .display()
        .to_string();
    let env = isolated_env(&instance.root.join("comparison-home"));
    let (code, stdout, stderr) = cli_raw(
        &[
            "--server",
            &fake.origin(),
            "--operator-secret-file",
            &secret,
            "status",
            "--json",
        ],
        &env,
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    let rendered: Value = serde_json::from_str(stdout.trim()).expect("status envelope");
    assert_eq!(
        rendered["result"], direct,
        "the CLI preserves the control body"
    );

    // the registry verbs too — a read and a
    // mutation — carry the control body byte-for-byte in content. The read
    // goes through a fake seeded with one body, so `captured_at` agrees.
    let seeded = FakeControl::answering(
        200,
        json!({ "control_api_version": 1, "captured_at": "2026-01-01T00:00:00Z", "clients": [] }),
    );
    let (code, stdout, stderr) = cli_raw(
        &[
            "--server",
            &seeded.origin(),
            "--operator-secret-file",
            &secret,
            "client",
            "list",
            "--json",
        ],
        &env,
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(
        envelope["result"],
        json!({ "control_api_version": 1, "captured_at": "2026-01-01T00:00:00Z", "clients": [] }),
        "{envelope}"
    );
    for (id, name) in [("cmp-1", "Cmp One"), ("cmp-2", "Cmp Two")] {
        let issued = control_post(
            instance.addr,
            "/control/v1/clients",
            &[],
            json!({ "id": id, "display_name": name }),
        )
        .await;
        assert_eq!(issued.status, StatusCode::CREATED, "{issued:?}");
    }
    let direct: Value = serde_json::from_str(
        &instance
            .cli(
                &[
                    "api",
                    "POST",
                    "/control/v1/clients/cmp-1/revoke",
                    "--body-stdin",
                ],
                Some("{}"),
            )
            .1,
    )
    .expect("control body");
    let envelope = instance.cli_json(&["client", "revoke", "cmp-2", "--yes"], None);
    // The body shape, exactly the server's members; the times are the
    // call's own (two calls never agree on a timestamp).
    let result = envelope["result"]
        .as_object()
        .unwrap_or_else(|| panic!("result object: {envelope}"));
    assert_eq!(envelope["result"]["client"]["id"], "cmp-2", "{envelope}");
    assert_eq!(envelope["result"]["client"]["display_name"], "Cmp Two");
    let mut members: Vec<&String> = result.keys().collect();
    members.sort_unstable();
    let mut expected: Vec<&String> = direct.as_object().expect("body").keys().collect();
    expected.sort_unstable();
    assert_eq!(members, expected, "{envelope}");
}

/// Each exit row that an operator host can produce is
/// produced once, by a fake server answer or a local condition, and maps to
/// its code; a slug the table lacks maps by HTTP status class and passes
/// through in `--json`.
#[tokio::test(flavor = "multi_thread")]
async fn every_exit_row_once_and_novel_slugs_by_class() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("exit-row-novel-slugs").await;
    instance.add_fsub();
    let env = isolated_env(&instance.root.join("home"));
    let secret = secret_file(&instance.root, "op", "jso2_fixture")
        .display()
        .to_string();
    let mut produced: Vec<(i32, String)> = Vec::new();
    fn run_json(instance: &Instance, args: &[&str], stdin: Option<&str>) -> (i32, String, Value) {
        let mut with_json = args.to_vec();
        with_json.push("--json");
        let (code, stdout, stderr) = instance.cli(&with_json, stdin);
        let envelope: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{args:?}: {e}: {stdout}{stderr}"));
        assert_eq!(envelope["exit_code"], code, "{envelope}");
        let slug = envelope["error"]["code"].as_str().unwrap_or("").to_string();
        (code, slug, envelope)
    }
    let mut local = |args: &[&str], stdin: Option<&str>| {
        let outcome = run_json(&instance, args, stdin);
        produced.push((outcome.0, outcome.1.clone()));
        outcome
    };
    // 0, 1, 2, 3, 6, 21 are local conditions on the live instance.
    assert_eq!(local(&["status"], None).0, 0);
    let (code, slug, _) = local(
        &[
            "api",
            "GET",
            "/v1/models",
            "--body-file",
            "/nonexistent/body",
        ],
        None,
    );
    assert_eq!((code, slug.as_str()), (1, "cli_internal"));
    let (code, slug, _) = local(&["account", "add", "--api-key", "--name", "x"], None);
    assert_eq!(
        (code, slug.as_str()),
        (2, "cli_usage"),
        "no terminal and no channel"
    );
    let (code, slug, _) = local(&["config", "validate", "/nonexistent"], None);
    assert_eq!((code, slug.as_str()), (3, "cli_configuration_invalid"));
    let (code, slug, _) = local(&["account", "show", "nobody"], None);
    assert_eq!((code, slug.as_str()), (6, "account_not_found"));
    let (code, slug, _) = local(&["account", "remove", "FSUB"], None);
    assert_eq!((code, slug.as_str()), (21, "cli_confirmation_required"));
    // 8 from the live server: an add whose name conflicts.
    let (code, slug, _) = local(
        &["account", "add", "--api-key", "--name", "FSUB", "--stdin"],
        Some("sk-ant-api03-x"),
    );
    assert_eq!((code, slug.as_str()), (8, "conflict"));
    let (code, slug, _) = local(
        &[
            "api",
            "GET",
            "/v1/models",
            "--body-file",
            "/nonexistent/body",
        ],
        None,
    );
    assert_eq!(code, 1, "{slug}");

    // 5, 7, 9, 10 and the novel slugs from a fake answer.
    let fakes: Vec<(u16, Value, i32, &str)> = vec![
        (
            403,
            control_error("operator_required", "this operation is operator-only"),
            5,
            "operator_required",
        ),
        (
            400,
            control_error("ambiguous_account_reference", "two match"),
            7,
            "ambiguous_account_reference",
        ),
        (
            422,
            control_error("credential_rejected", "the credential was refused upstream"),
            9,
            "credential_rejected",
        ),
        (
            500,
            control_error("internal_error", "boom"),
            10,
            "internal_error",
        ),
        (
            422,
            control_error("future_thing", "a slug this build does not know"),
            9,
            "future_thing",
        ),
        (401, control_error("future_thing", "-"), 5, "future_thing"),
        (404, control_error("future_thing", "-"), 6, "future_thing"),
        (409, control_error("future_thing", "-"), 8, "future_thing"),
        (503, control_error("future_thing", "-"), 10, "future_thing"),
        (418, control_error("future_thing", "-"), 1, "future_thing"),
        // the slugs the registry and the remote operator
        // add, each once by a fake server answer.
        (
            404,
            control_error("client_not_found", "no client has this id"),
            6,
            "client_not_found",
        ),
        (
            400,
            control_error("invalid_client_id", "a client id is 1-63…"),
            9,
            "invalid_client_id",
        ),
        (
            400,
            control_error(
                "invalid_display_name",
                "a display name is 1-128 UTF-8 bytes",
            ),
            9,
            "invalid_display_name",
        ),
        (
            403,
            control_error("loopback_required", "the host itself"),
            5,
            "loopback_required",
        ),
        (
            403,
            control_error("insecure_channel", "loopback or TLS"),
            5,
            "insecure_channel",
        ),
        (
            403,
            control_error("enrollment_claim_refused", "refused"),
            5,
            "enrollment_claim_refused",
        ),
    ];
    let mut fake_rows: Vec<(i32, String)> = Vec::new();
    for (status, body, expected_code, expected_slug) in fakes {
        let fake = FakeControl::answering(status, body);
        let (code, stdout, stderr) = cli_raw(
            &[
                "--server",
                &fake.origin(),
                "--operator-secret-file",
                &secret,
                "status",
                "--json",
            ],
            &env,
            None,
        );
        let envelope: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{status}: {e}: {stdout}{stderr}"));
        assert_eq!(code, expected_code, "{status} {expected_slug}: {envelope}");
        assert_eq!(
            envelope["error"]["code"], expected_slug,
            "the slug passes through: {envelope}"
        );
        fake_rows.push((code, expected_slug.to_string()));
    }
    // 11: an engineer verb on a machine with no installation.
    let (code, _, stderr) = cli_raw(&["alias"], &env, None);
    assert_eq!(code, 11, "{stderr}");
    assert!(
        stderr.contains("client.toml") && stderr.contains("jaynshare join"),
        "names the file and the join: {stderr}"
    );

    // the registry rows from the live instance — a
    // never-issued id is 6, a value the grammar cannot reject is 2
    // before any request, a rotate of a pending id is the server's 409 → 8.
    let (code, slug, _) = local(&["client", "show", "no-such"], None);
    assert_eq!((code, slug.as_str()), (6, "client_not_found"));
    let (code, slug, _) = local(&["client", "show", "BAD_ID"], None);
    assert_eq!((code, slug.as_str()), (2, "cli_usage"));
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "app-1", "display_name": "App" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{issued:?}");
    let (code, slug, _) = local(&["client", "rotate", "app-1"], None);
    assert_eq!((code, slug.as_str()), (8, "conflict"));
    produced.append(&mut fake_rows);
    produced.push((11, "cli_not_enrolled".into()));

    // 4, 22 and 23: the server down, a held port, a malformed state file.
    instance.stop();
    let (code, slug, _) = run_json(&instance, &["status"], None);
    assert_eq!((code, slug.as_str()), (4, "cli_unreachable"));
    produced.push((code, slug));
    let holder = StdTcpListener::bind(instance.addr).expect("hold the port");
    let (code, stderr) = instance.spawn_expecting_failure();
    assert_eq!(code, 22, "{stderr}");
    assert!(
        stderr.contains(&instance.addr.port().to_string()),
        "names the port: {stderr}"
    );
    drop(holder);
    produced.push((22, "cli_bind_failed".into()));
    let state = instance.root.join("state/state.json");
    let good_state = fs::read(&state).expect("state");
    fs::write(&state, b"{ not json").expect("corrupt state");
    let (code, stderr) = instance.spawn_expecting_failure();
    assert_eq!(code, 23, "{stderr}");
    assert!(stderr.contains("state"), "names the file: {stderr}");
    fs::write(&state, good_state).expect("restore state");
    produced.push((23, "cli_startup_failed".into()));

    let mut codes: Vec<i32> = produced.iter().map(|(c, _)| *c).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(
        codes,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 21, 22, 23],
        "every row once"
    );
}

/// A secret enters by hidden prompt, `--stdin` and `--file`; a
/// world-readable file is refused; 64 KiB + 1 on standard input is refused;
/// no terminal and no channel is exit 2 naming the three; the secret appears
/// in no argv, file the CLI writes, log or message.
#[tokio::test(flavor = "multi_thread")]
async fn secret_channels_and_no_leak() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("secret-channels-no-leak").await;
    let config = instance.config.display().to_string();
    let env = isolated_env(&instance.root.join("home"));
    let prompt_key = needle("hidden-prompt API key", "api03-prompt");
    let stdin_key = needle("stdin API key", "api03-stdin");
    let file_key = needle("file API key", "api03-file");

    // (a) the hidden prompt: typed once the prompt is on the terminal.
    let (code, transcript) = cli_pty(
        "secret-channels-no-leak-prompt",
        &[
            "--config",
            &config,
            "account",
            "add",
            "--api-key",
            "--name",
            "PROMPT",
        ],
        &env,
        Some(("API key (hidden)", &format!("{prompt_key}\n"))),
    );
    assert_eq!(code, 0, "{transcript}");
    assert!(
        !transcript.contains(&prompt_key),
        "echo was off: {transcript}"
    );
    assert!(
        transcript.contains("PROMPT"),
        "the new row printed: {transcript}"
    );

    // (b) standard input, one trailing line ending removed.
    let (code, stdout, stderr) = instance.cli(
        &["account", "add", "--api-key", "--name", "STDIN", "--stdin"],
        Some(&format!("{stdin_key}\n")),
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("STDIN"));

    // (c) an owner-only file.
    let file = secret_file(&instance.root, "key", &file_key);
    let (code, _, stderr) = instance.cli(
        &[
            "account",
            "add",
            "--api-key",
            "--name",
            "FILE",
            "--file",
            &file.display().to_string(),
        ],
        None,
    );
    assert_eq!(code, 0, "{stderr}");

    // The three keys are held: each account serves under its own key.
    for (name, key) in [
        ("PROMPT", &prompt_key),
        ("STDIN", &stdin_key),
        ("FILE", &file_key),
    ] {
        instance
            .upstream
            .script([Reply::status(200, message_body().to_string())]);
        let answer = send(instance.addr, pinned(messages(haiku_prompt()), name)).await;
        assert_eq!(answer.status, StatusCode::OK, "{name}");
        assert_eq!(
            instance.upstream.last().header("x-api-key"),
            Some(key.as_str()),
            "{name} served under its key"
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open = instance.root.join("open-key");
        fs::write(&open, &file_key).expect("write");
        crate::leaks::register_planted(&open);
        fs::set_permissions(&open, fs::Permissions::from_mode(0o644)).expect("chmod");
        let before = instance.state_digest();
        let (code, _, stderr) = instance.cli(
            &[
                "account",
                "add",
                "--api-key",
                "--name",
                "OPEN",
                "--file",
                &open.display().to_string(),
            ],
            None,
        );
        assert_eq!(
            code, 2,
            "a world-readable file is refused before any read: {stderr}"
        );
        assert!(
            stderr.contains("644") || stderr.contains("mode"),
            "names the mode: {stderr}"
        );
        assert_eq!(instance.state_digest(), before);
    }

    // 64 KiB + 1 on standard input is refused, nothing else read.
    let oversized = "k".repeat(64 * 1024 + 1);
    let (code, _, stderr) = instance.cli(
        &["account", "add", "--api-key", "--name", "BIG", "--stdin"],
        Some(&oversized),
    );
    assert_eq!(code, 9, "{stderr}");
    assert!(stderr.contains("64 KiB"), "{stderr}");
    // Exactly 64 KiB is accepted by the channel (the server judges the value).
    let exact = "k".repeat(64 * 1024);
    let (code, _, stderr) = instance.cli(
        &["account", "add", "--api-key", "--name", "EXACT", "--stdin"],
        Some(&exact),
    );
    assert_ne!(code, 9, "64 KiB passes the channel: {stderr}");

    // No terminal and no channel: exit 2 naming the three.
    let (code, _, stderr) = instance.cli(&["account", "add", "--api-key", "--name", "NONE"], None);
    assert_eq!(code, 2, "{stderr}");
    for channel in ["hidden prompt", "--stdin", "--file"] {
        assert!(stderr.contains(channel), "names {channel}: {stderr}");
    }

    // The secrets appear in no log, audit record, CLI output or message.
    let mut surfaces = vec![
        fs::read_to_string(instance.root.join("log/server.ndjson")).unwrap_or_default(),
        fs::read_to_string(instance.root.join("log/exchanges.ndjson")).unwrap_or_default(),
        instance.stdout(),
        instance.stderr(),
        transcript,
    ];

    // the remote-operator secret's
    // channels for `--server`. On a terminal, the hidden prompt.
    let fake = FakeControl::answering(
        200,
        json!({ "control_api_version": 1, "captured_at": "2026-01-01T00:00:00Z", "accounts": [] }),
    );
    let operator_secret = format!("jso2_pty_{}", Uuid::new_v4().simple());
    let (code, transcript) = cli_pty(
        "secret-channels-no-leak-op-prompt",
        &["--server", &fake.origin(), "account", "list"],
        &env,
        Some(("remote-operator secret", &format!("{operator_secret}\n"))),
    );
    assert_eq!(code, 0, "{transcript}");
    assert!(
        !transcript.contains(&operator_secret),
        "echo was off: {transcript}"
    );
    let seen = fake.seen();
    assert_eq!(seen.len(), 1, "one request per invocation");
    assert!(
        seen[0]
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {operator_secret}")),
        "the bearer travelled: {:?}",
        seen[0]
    );

    // A world-readable --operator-secret-file is refused before any read.
    let open = instance.root.join("open-op-secret");
    fs::write(&open, "jso2_open").expect("write");
    crate::leaks::register_planted(&open);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&open, fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    let (code, _, stderr) = cli_raw(
        &[
            "--server",
            &fake.origin(),
            "--operator-secret-file",
            &open.display().to_string(),
            "account",
            "list",
        ],
        &env,
        None,
    );
    assert_eq!(code, 2, "a world-readable file is refused: {stderr}");
    assert_eq!(fake.seen().len(), 1, "the file was refused before a read");

    // (into the leak sweep below)
    let (_, stdout, stderr) = instance.cli(&["status"], None);
    surfaces.push(stdout);
    surfaces.push(stderr);
    let (_, stdout, _) = instance.cli(&["account", "list", "--json"], None);
    surfaces.push(stdout);
    for key in [&prompt_key, &stdin_key, &file_key, &operator_secret] {
        for (index, surface) in surfaces.iter().enumerate() {
            assert!(
                !surface.contains(key.as_str()),
                "surface {index} carries a key: {surface}"
            );
        }
    }
}

/// A reference matching nothing is exit 6 listing the display
/// names; one matching several is exit 7 with the server's list; a decimal
/// number resolves as a name, never a position.
#[tokio::test(flavor = "multi_thread")]
async fn references_resolve_before_use() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("references-resolve-use").await;
    instance.add_fsub();
    instance.add_fkey();

    for verb in [
        vec!["switch", "nobody"],
        vec!["account", "rename", "nobody", "x"],
        vec!["priority", "set", "nobody", "1"],
        vec!["route", "add", "r", "--pattern", "*", "--account", "nobody"],
    ] {
        let envelope = instance.cli_json(&verb, None);
        assert_eq!(envelope["exit_code"], 6, "{verb:?}: {envelope}");
        let message = envelope["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("FSUB") && message.contains("FKEY"),
            "{verb:?} lists the names: {message}"
        );
    }
    assert_eq!(
        instance.status()["routes"],
        json!([]),
        "the route add wrote nothing"
    );

    instance.add_other_org(
        "FSUB2",
        "fsub@fixture.invalid",
        &Uuid::new_v4().to_string(),
        &Uuid::new_v4().to_string(),
    );
    let envelope = instance.cli_json(&["switch", "fsub@fixture.invalid"], None);
    assert_eq!(envelope["exit_code"], 7, "{envelope}");
    assert_eq!(envelope["error"]["code"], "ambiguous_account_reference");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("FSUB") && message.contains("FSUB2"),
        "the server's list: {message}"
    );
    let (_, _, stderr) = instance.cli(&["switch", "fsub@fixture.invalid"], None);
    assert!(
        stderr.contains("FSUB2"),
        "the human form lists them too: {stderr}"
    );

    // A number: names nothing → 6 with the position sentence; then an
    // account named exists and resolves to it.
    let envelope = instance.cli_json(&["switch", "1"], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("positions are not references")
    );
    instance.cli_json(&["account", "rename", "FKEY", "1"], None);
    let envelope = instance.cli_json(&["switch", "1"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(envelope["result"]["account"]["display_name"], "1");
}

/// A refused confirmation changes nothing; `--yes` is accepted
/// where allowed and no terminal without it is 21; the interactive-only
/// verbs refuse `--yes` (21) and exit 21 without a terminal. The
/// half: `account remove` live, the others at the grammar.
#[tokio::test(flavor = "multi_thread")]
async fn confirmations_refused_skipped_and_interactive_only() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("confirmations-refused-skipped").await;
    instance.add_fsub();
    instance.add_fkey();
    let config = instance.config.display().to_string();
    let env = isolated_env(&instance.root.join("home"));

    let (code, transcript) = cli_pty(
        "confirmations-refused-skipped-no",
        &["--config", &config, "account", "remove", "FKEY"],
        &env,
        Some(("[y/N]", "n\n")),
    );
    assert_eq!(code, 21, "{transcript}");
    assert_eq!(
        instance.status()["accounts"].as_array().unwrap().len(),
        2,
        "nothing removed"
    );

    let (code, transcript) = cli_pty(
        "confirmations-refused-skipped-yes",
        &["--config", &config, "account", "remove", "FKEY"],
        &env,
        Some(("[y/N]", "y\n")),
    );
    assert_eq!(code, 0, "{transcript}");
    assert_eq!(
        instance.status()["accounts"].as_array().unwrap().len(),
        1,
        "removed on yes"
    );

    let envelope = instance.cli_json(&["account", "remove", "FSUB"], None);
    assert_eq!(
        envelope["exit_code"], 21,
        "no terminal, no --yes: {envelope}"
    );
    assert_eq!(envelope["error"]["code"], "cli_confirmation_required");
    assert_eq!(instance.status()["accounts"].as_array().unwrap().len(), 1);
    let envelope = instance.cli_json(&["account", "remove", "FSUB", "--yes"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(instance.status()["accounts"].as_array().unwrap().len(), 0);

    // The interactive-only verb: --yes is never accepted, and no terminal is 21.
    // `server install` is not one: the trust statements live in the
    // deployment guide, it asks nothing; its refusals are the deploy exit rows.
    let (code, _, stderr) = cli_raw(&["server", "uninstall", "--purge", "--yes"], &env, None);
    assert_eq!(code, 21, "{stderr}");
    assert!(stderr.contains("--yes"), "--yes is not accepted: {stderr}");
    let (code, _, stderr) = cli_raw(&["server", "uninstall", "--purge"], &env, None);
    assert_eq!(code, 21, "without a terminal: {stderr}");

    // `client revoke` asks too. A refused
    // answer changes nothing; `--yes` is accepted without a terminal.
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "rev-1", "display_name": "Rev One" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{issued:?}");
    let (code, transcript) = cli_pty(
        "confirmations-refused-skipped-revoke-no",
        &["--config", &config, "client", "revoke", "rev-1"],
        &env,
        Some(("[y/N]", "n\n")),
    );
    assert_eq!(code, 21, "{transcript}");
    let envelope = instance.cli_json(&["client", "show", "rev-1"], None);
    assert_eq!(
        envelope["result"]["client"]["state"], "pending",
        "{envelope}"
    );
    let envelope = instance.cli_json(&["client", "revoke", "rev-1", "--yes"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let envelope = instance.cli_json(&["client", "show", "rev-1"], None);
    assert_eq!(
        envelope["result"]["client"]["state"], "revoked",
        "{envelope}"
    );
}

/// `status --check` prints zero bytes whether the read passes
/// or fails; the exit code carries the answer; `--json` is refused before
/// any read.
#[tokio::test(flavor = "multi_thread")]
async fn status_check_is_silent_and_answers_by_exit_code() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("status-check-silent").await;
    let (code, stdout, stderr) = instance.cli(&["status", "--check"], None);
    assert_eq!((code, stdout.as_str(), stderr.as_str()), (0, "", ""));
    instance.stop();
    let (code, stdout, stderr) = instance.cli(&["status", "--check"], None);
    assert_eq!((code, stdout.as_str(), stderr.as_str()), (4, "", ""));
    let (code, _, stderr) = instance.cli(&["status", "--check", "--accounts"], None);
    assert_eq!(code, 2, "no section flag with --check: {stderr}");

    let fake = FakeControl::answering(200, json!({ "control_api_version": 1 }));
    let env = isolated_env(&instance.root.join("home"));
    let secret = secret_file(&instance.root, "op", "jso2_fixture")
        .display()
        .to_string();
    for args in [
        vec![
            "--server",
            &fake.origin(),
            "--operator-secret-file",
            &secret,
            "status",
            "--check",
            "--json",
        ],
        vec![
            "--json",
            "--server",
            &fake.origin(),
            "--operator-secret-file",
            &secret,
            "status",
            "--check",
        ],
    ] {
        let (code, _, stderr) = cli_raw(&args, &env, None);
        assert_eq!(code, 2, "{args:?}: {stderr}");
    }
    assert!(
        fake.seen().is_empty(),
        "--json is refused without running the read"
    );
}
/// `api` times only the response head, streams a slow body, and
/// preserves bytes already written when that body ends early.
#[test]
fn api_streams_beyond_the_timeout_and_reports_truncation() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let (first_chunk, first_chunk_sent) = std::sync::mpsc::channel();
    let (mut child, server, stdout, stderr) =
        api_fixture("api-streams-beyond-slow", move |mut stream| {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nabc")
                .expect("write first chunk");
            stream.flush().expect("flush first chunk");
            first_chunk.send(()).expect("signal first chunk");
            std::thread::sleep(Duration::from_millis(1500));
            stream.write_all(b"def").expect("write final chunk");
        });
    first_chunk_sent.recv().expect("first chunk sent");
    let deadline = Instant::now() + Duration::from_millis(500);
    while fs::metadata(&stdout).map_or(0, |m| m.len()) < 3 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read(&stdout).expect("read partial stdout"),
        b"abc",
        "the first bytes are visible before EOF"
    );
    assert!(child.try_wait().expect("poll slow CLI").is_none());
    assert_eq!(child.wait().expect("wait for slow CLI").code(), Some(0));
    server.join().expect("join slow fixture");
    assert_eq!(fs::read(&stdout).expect("read slow stdout"), b"abcdef");
    assert!(
        fs::read_to_string(&stderr)
            .expect("read slow stderr")
            .contains("200 OK")
    );

    let (mut child, server, stdout, stderr) =
        api_fixture("api-streams-beyond-truncated", move |mut stream| {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nabc")
                .expect("write truncated body");
        });
    assert_eq!(
        child.wait().expect("wait for truncated CLI").code(),
        Some(4)
    );
    server.join().expect("join truncated fixture");
    assert_eq!(fs::read(&stdout).expect("read truncated stdout"), b"abc");
    assert!(
        fs::read_to_string(&stderr)
            .expect("read truncated stderr")
            .contains("response body interrupted")
    );

    let (mut child, server, stdout, stderr) =
        api_fixture("api-streams-beyond-no-head", move |_stream| {
            std::thread::sleep(Duration::from_millis(1500));
        });
    assert_eq!(child.wait().expect("wait for no-head CLI").code(), Some(4));
    server.join().expect("join no-head fixture");
    assert!(fs::read(&stdout).expect("read no-head stdout").is_empty());
    assert!(
        fs::read_to_string(&stderr)
            .expect("read no-head stderr")
            .contains("no response within 1 s")
    );
}

/// `client invite` and `client reissue` print the invite exactly
/// once; `client show` never has it; `--disclose-to` refuses an existing
/// path and writes a fresh `0600` file; with `--json` the invite is only in
/// `result`.
#[tokio::test(flavor = "multi_thread")]
async fn disclosures_are_printed_once_and_only_once() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "disclosures-printed",
        Setup {
            mitm: true,
            data_plane: "tls = \"identity\"\n".into(),
            ..Setup::default()
        },
    )
    .await;

    // The human form: the registry entry, then the join to run as the last line.
    let (code, stdout, stderr) =
        instance.cli(&["client", "invite", "web-one", "--name", "Web One"], None);
    assert_eq!(code, 0, "{stderr}");
    let lines: Vec<&str> = stdout.trim_end().lines().collect();
    assert!(lines.len() >= 3, "{stdout}");
    assert!(lines[0].contains("web-one"), "{stdout}");
    let last = *lines.last().expect("lines");
    let first_invite = last
        .strip_prefix("jaynshare join ")
        .unwrap_or_else(|| panic!("the join line: {stdout}"))
        .to_string();
    assert!(first_invite.starts_with("jsi1_"), "{stdout}");

    // `client show` never re-discloses it.
    let (code, stdout, _) = instance.cli(&["client", "show", "web-one"], None);
    assert_eq!(code, 0);
    assert!(!stdout.contains(&first_invite), "{stdout}");

    // `--json`: the invite travels only inside `result`.
    let envelope = instance.cli_json(&["client", "invite", "web-two", "--name", "Web Two"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let json_invite = envelope["result"]["invite"]
        .as_str()
        .expect("the result carries it once")
        .to_string();
    assert!(json_invite.starts_with("jsi1_"), "{envelope}");
    let (_, stdout, _) = instance.cli(&["client", "show", "web-two"], None);
    assert!(!stdout.contains(&json_invite));

    // `reissue` replaces an invite.
    let envelope = instance.cli_json(&["client", "reissue", "web-one"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let reissued = envelope["result"]["invite"]
        .as_str()
        .expect("the new invite is in result")
        .to_string();
    assert_ne!(reissued, first_invite);

    // `--disclose-to`: a fresh 0600 file, nothing printed but the path.
    let disclosure = instance.root.join("disclosed-invite");
    let (code, stdout, stderr) = instance.cli(
        &[
            "client",
            "invite",
            "web-three",
            "--name",
            "Web Three",
            "--disclose-to",
            &disclosure.display().to_string(),
        ],
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        stdout.trim(),
        disclosure.display().to_string(),
        "the path alone: {stdout}"
    );
    let contents = fs::read_to_string(&disclosure).expect("disclosure file");
    assert!(contents.starts_with("jsi1_"), "{contents}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&disclosure)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
    }
    let (code, _, stderr) = instance.cli(
        &[
            "client",
            "invite",
            "web-four",
            "--name",
            "Web Four",
            "--disclose-to",
            &disclosure.display().to_string(),
        ],
        None,
    );
    assert_eq!(code, 8, "{stderr}");
    assert!(stderr.contains("already exists"), "{stderr}");

    // `--json` plus `--disclose-to`: the file holds it, the envelope says
    // where, and the invite is in no output at all.
    let fresh = instance.root.join("disclosed-invite-2");
    let (code, stdout, stderr) = instance.cli(
        &[
            "client",
            "invite",
            "web-five",
            "--name",
            "Web Five",
            "--disclose-to",
            &fresh.display().to_string(),
            "--json",
        ],
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(
        envelope["result"]["disclosure_file"],
        fresh.display().to_string(),
        "{envelope}"
    );
    assert!(envelope["result"]["invite"].is_null(), "{envelope}");
    assert!(!stdout.contains("jsi1_"), "{stdout}");

    // The codes live nowhere durable: not the state file, not the logs.
    for surface in [
        fs::read_to_string(instance.root.join("state/state.json")).unwrap_or_default(),
        fs::read_to_string(instance.root.join("log/server.ndjson")).unwrap_or_default(),
        instance.stdout(),
        instance.stderr(),
    ] {
        for invite in [&first_invite, &reissued, &json_invite] {
            let decoded = crate::enrol::decode_invite(invite);
            let code = decoded["code"].as_str().expect("the code");
            assert!(!surface.contains(code), "a leaked code: {code}");
        }
    }
}

/// Validated locally before any request (exit 2);
/// `revoke` twice is 0; `show` on a revoked id is 0 and on a never-issued id
/// is 6.
#[tokio::test(flavor = "multi_thread")]
async fn registry_ids_validated_locally_and_lifecycle_rows() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("registry-ids-validated").await;
    let state_before = instance.state_digest();

    for (label, args) in [
        ("invalid id", vec!["client", "show", "BAD_ID"]),
        (
            "invalid display name",
            vec!["client", "invite", "ok-id", "--name", "bad\u{7}name"],
        ),
    ] {
        let envelope = instance.cli_json(&args, None);
        assert_eq!(envelope["exit_code"], 2, "{label}: {envelope}");
        assert_eq!(
            envelope["error"]["code"], "cli_usage",
            "{label}: {envelope}"
        );
    }
    assert_eq!(
        instance.state_digest(),
        state_before,
        "no request left the machine for an invalid id"
    );

    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "app-1", "display_name": "App One" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{issued:?}");

    // An unknown id is the server's 404 → 6.
    let envelope = instance.cli_json(&["client", "revoke", "no-such-id"], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    assert_eq!(envelope["error"]["code"], "client_not_found", "{envelope}");

    // Revoke twice: both exit 0, the entry stays visible.
    for _ in 0..2 {
        let envelope = instance.cli_json(&["client", "revoke", "app-1", "--yes"], None);
        assert_eq!(envelope["ok"], true, "{envelope}");
    }
    let envelope = instance.cli_json(&["client", "show", "app-1"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(
        envelope["result"]["client"]["state"], "revoked",
        "{envelope}"
    );

    // A never-issued id is 6.
    let envelope = instance.cli_json(&["client", "show", "never-issued"], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    assert_eq!(envelope["error"]["code"], "client_not_found", "{envelope}");
}

/// `operator secret set` from `--server` is exit 5 with the
/// server's `loopback_required`; on loopback it prints the secret once; a
/// second run asks the confirmation first and a refused answer
/// changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn operator_secret_loopback_only_and_confirmed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("operator-secret-loopback").await;
    let config = instance.config.display().to_string();
    let env = isolated_env(&instance.root.join("home"));

    // From `--server`: the CLI does not pre-empt; the server refuses.
    let fake = FakeControl::answering(
        403,
        control_error(
            "loopback_required",
            "the remote-operator secret is managed only from the host itself; an operator credential is the pool's master key",
        ),
    );
    let secret = secret_file(&instance.root, "op", "jso2_fixture")
        .display()
        .to_string();
    let (code, stdout, stderr) = cli_raw(
        &[
            "--server",
            &fake.origin(),
            "--operator-secret-file",
            &secret,
            "operator",
            "secret",
            "set",
            "--json",
        ],
        &env,
        None,
    );
    assert_eq!(code, 5, "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["error"]["code"], "loopback_required", "{envelope}");
    assert_eq!(fake.seen().len(), 1, "one request, then the refusal");

    // On loopback, first run: one disclosure, and the state gained the slot.
    let (code, stdout, stderr) = instance.cli(&["operator", "secret", "set"], None);
    assert_eq!(code, 0, "{stderr}");
    let lines: Vec<&str> = stdout.trim_end().lines().collect();
    let disclosure = *lines.last().expect("line");
    assert!(
        disclosure.starts_with("operator secret") && disclosure.contains("jso2_"),
        "{stdout}"
    );
    let state = fs::read_to_string(instance.root.join("state/state.json")).unwrap_or_default();
    assert!(
        state.contains("jaynshare/operator"),
        "the verifier slot exists: {state}"
    );

    // Second run without a terminal and without --yes: refused, unchanged.
    let before = instance.state_digest();
    let envelope = instance.cli_json(&["operator", "secret", "set"], None);
    assert_eq!(envelope["exit_code"], 21, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "cli_confirmation_required",
        "{envelope}"
    );
    assert_eq!(instance.state_digest(), before, "nothing rotated");

    // The confirmation on a terminal: a refused answer changes nothing.
    let (code, transcript) = cli_pty(
        "operator-secret-loopback-no",
        &["--config", &config, "operator", "secret", "set"],
        &env,
        Some(("[y/N]", "n\n")),
    );
    assert_eq!(code, 21, "{transcript}");
    assert_eq!(instance.state_digest(), before, "a no answers nothing");
    assert!(
        !transcript.contains("jso2_"),
        "no disclosure happened: {transcript}"
    );

    // Answered yes (or --yes): a new secret, disclosed once.
    let (code, transcript) = cli_pty(
        "operator-secret-loopback-yes",
        &["--config", &config, "operator", "secret", "set"],
        &env,
        Some(("[y/N]", "y\n")),
    );
    assert_eq!(code, 0, "{transcript}");
    assert!(transcript.contains("operator secret"), "{transcript}");
    let envelope = instance.cli_json(&["operator", "secret", "set", "--yes"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert!(
        envelope["result"]["operator_secret"].is_string(),
        "{envelope}"
    );

    // `remove` is loopback-only as well, and the CLI reports it plainly.
    let (code, _, stderr) = instance.cli(&["operator", "secret", "remove"], None);
    assert_eq!(code, 0, "{stderr}");
    let envelope = instance.cli_json(&["operator", "secret", "remove"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
}

/// `status` renders every section in order; the capture line is
/// present off and on; `--clients` prints that section alone and still
/// returns the whole body with `--json`.
#[tokio::test(flavor = "multi_thread")]
async fn status_renders_every_section_including_clients() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_with(
        "status-renders-section",
        Setup {
            blocked_models: vec!["*opus*".to_string()],
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let issued = control_post(
        instance.addr,
        "/control/v1/clients",
        &[],
        json!({ "id": "mac-1", "display_name": "Mac One" }),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{issued:?}");

    // The default view: routes, then the account table, then the
    // default line; the diagnostics are --verbose.
    let (code, stdout, stderr) = instance.cli(&["status"], None);
    assert_eq!(code, 0, "{stderr}");
    let mut order = 0;
    for marker in ["routes", "FSUB (oauth", "default"] {
        let at = stdout
            .lines()
            .position(|line| line.contains(marker))
            .expect(marker);
        assert!(at >= order, "{marker} out of order: {stdout}");
        order = at;
    }
    assert!(
        stdout.contains("*opus*"),
        "the blocked patterns line: {stdout}"
    );
    assert!(
        !stdout.contains("mac-1"),
        "the clients are --verbose: {stdout}"
    );

    // --verbose: every section in a fixed order.
    let (code, stdout, _) = instance.cli(&["status", "--verbose"], None);
    assert_eq!(code, 0);
    let headings = [
        "server", "egress", "capture", "mitm", "sessions", "probe", "routes", "default", "clients",
        "storage", "config",
    ];
    let mut order = 0;
    for heading in headings {
        let at = stdout
            .lines()
            .position(|line| line.contains(heading))
            .expect(heading);
        assert!(at >= order, "{heading} out of order: {stdout}");
        order = at;
    }
    assert!(
        stdout.contains("capture") && stdout.contains("off"),
        "{stdout}"
    );
    assert!(
        stdout.contains("mac-1") && stdout.contains("pending"),
        "the clients section: {stdout}"
    );

    // `--clients` alone; `--json` still carries the whole body.
    let (code, stdout, stderr) = instance.cli(&["status", "--clients"], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("mac-1"), "{stdout}");
    assert!(!stdout.contains("accounts"), "{stdout}");
    let envelope = instance.cli_json(&["status", "--clients"], None);
    assert!(
        envelope["result"]["status"]["clients"].as_array().is_some(),
        "{envelope}"
    );

    // Capture on: the line names the directory. It is a restart
    // key, so the setup lands on a restart.
    instance.write_setup(&Setup {
        capture: true,
        ..Setup::default()
    });
    instance.restart();
    let (code, stdout, _) = instance.cli(&["status", "--verbose"], None);
    assert_eq!(code, 0);
    let capture_line = stdout
        .lines()
        .find(|line| line.contains("capture"))
        .expect("the capture line");
    assert!(capture_line.contains("ON"), "{stdout}");
    instance.stop();
}

/// The CA verbs: with MITM off, `ca rotate` is the server's
/// exit 8, and `ca show`/`ca export` answer that there is no CA; with MITM
/// on, `ca show` names the CA, `ca export` prints the PEM or writes it into
/// A fresh `0644` file (exit 8 on an existing one), `ca rotate` stages the
/// next CA, which `ca show` names, and `ca rotate --now` replaces the CA.
#[tokio::test(flavor = "multi_thread")]
async fn the_ca_verbs() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // MITM off: rotate refuses; show and export have no CA to answer about.
    let instance = Instance::start("ca-verbs-a").await;
    let (code, _, stderr) = instance.cli(&["ca", "rotate", "--yes"], None);
    assert_eq!(code, 8, "{stderr}");
    let envelope = instance.cli_json(&["ca", "show"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(envelope["result"]["fingerprint"], Value::Null, "{envelope}");
    assert_eq!(envelope["result"]["state"], Value::Null, "{envelope}");
    let (code, _, stderr) = instance.cli(&["ca", "export"], None);
    assert_eq!(code, 8, "{stderr}");
    let envelope = instance.cli_json(&["ca", "export"], None);
    assert_eq!(envelope["error"]["code"], "cli_no_ca", "{envelope}");

    // MITM on: the CA exists and can be shown, exported and rotated.
    let mut instance = Instance::start_with(
        "ca-verbs-b",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let envelope = instance.cli_json(&["ca", "show"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let old_fingerprint = envelope["result"]["fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();
    assert_eq!(envelope["result"]["state"], "ok", "{envelope}");

    // Export to standard output: the PEM alone, and the full result.
    let (code, stdout, stderr) = instance.cli(&["ca", "export"], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("-----BEGIN CERTIFICATE-----"), "{stdout}");
    let stdout_pem = stdout.strip_suffix('\n').unwrap_or(&stdout).to_string();
    let envelope = instance.cli_json(&["ca", "export"], None);
    assert_eq!(envelope["result"]["path"], Value::Null, "{envelope}");
    assert_eq!(
        envelope["result"]["certificate_pem"].as_str().unwrap_or(""),
        stdout_pem,
        "{envelope}"
    );

    // Export into a fresh file: `0644`, the same PEM; a second time is exit 8.
    let out = scratch("ca-verbs").join("ca.pem");
    let out_str = out.display().to_string();
    let (code, stdout, stderr) = instance.cli(&["ca", "export", "--out", &out_str], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("wrote"), "{stdout}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&out).expect("the file");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o644, "{out:?}");
    }
    assert_eq!(fs::read_to_string(&out).unwrap_or_default(), stdout_pem);
    let (code, _, stderr) = instance.cli(&["ca", "export", "--out", &out_str], None);
    assert_eq!(code, 8, "{stderr}");
    let envelope = instance.cli_json(&["ca", "export", "--out", &out_str], None);
    assert_eq!(envelope["error"]["code"], "cli_output_exists", "{envelope}");

    // Rotate: the next CA is staged, the current one still presented.
    let envelope = instance.cli_json(&["ca", "rotate", "--yes"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(envelope["result"]["fingerprint"], old_fingerprint.as_str());
    let staged = envelope["result"]["next"]["fingerprint"]
        .as_str()
        .expect("the staged fingerprint")
        .to_string();
    assert_ne!(staged, old_fingerprint, "{envelope}");
    let envelope = instance.cli_json(&["ca", "show"], None);
    assert_eq!(envelope["result"]["fingerprint"], old_fingerprint.as_str());
    assert_eq!(envelope["result"]["next"]["fingerprint"], staged.as_str());
    let (code, stdout, stderr) = instance.cli(&["ca", "show"], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains(&format!("next CA {staged}")), "{stdout}");
    let (code, _, stderr) = instance.cli(&["ca", "rotate", "--yes"], None);
    assert_eq!(code, 8, "one staged CA at a time: {stderr}");

    // Rotate now: old and new fingerprints, the staged CA dropped.
    let (code, stdout, stderr) = instance.cli(&["ca", "rotate", "--now", "--yes"], None);
    assert_eq!(code, 0, "{stderr}");
    let envelope = instance.cli_json(&["ca", "show"], None);
    let new_fingerprint = envelope["result"]["fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();
    assert!(
        new_fingerprint != old_fingerprint && new_fingerprint != staged,
        "{envelope}"
    );
    assert_eq!(envelope["result"]["next"], Value::Null, "{envelope}");
    assert!(
        stdout.contains(&old_fingerprint) && stdout.contains(&new_fingerprint),
        "both fingerprints: {stdout}"
    );
    instance.stop();
}

/// With a configured private
/// listener the loopback default connects to `127.0.0.1` on the configured
/// port while HTTP and TLS keep the configured address: the request's host
/// is that address, no bearer is sent, the certificate is verified for that
/// address, and the trust comes from the configured chain file itself (a
/// root no system store holds, after the leaf). A leaf naming only
/// `127.0.0.1` fails, so the dialled address is never the identity.
#[tokio::test(flavor = "multi_thread")]
async fn a_private_listener_is_reached_through_loopback_as_itself() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/acceptance/private-listener-reached-private");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("scratch");
    let env = isolated_env(&root.join("home"));
    let fake = FakeControl::answering(
        200,
        json!({ "control_api_version": 1, "captured_at": "2026-01-01T00:00:00Z", "accounts": [] }),
    );
    const PRIVATE: &str = "10.255.255.1";
    let write_config = |port: u16, tls: Option<(&Path, &Path)>| {
        let tls = tls.map_or(String::new(), |(cert, key)| {
            format!(
                "tls_certificate_file = {:?}\ntls_private_key_file = {:?}\n",
                cert.display().to_string(),
                key.display().to_string()
            )
        });
        let path = root.join("config.toml");
        write_private(
            &path,
            &format!("version = 1\n\n[data_plane]\nlisten = \"{PRIVATE}:{port}\"\n{tls}"),
        );
        path.display().to_string()
    };

    // 1. http: the fake on 127.0.0.1 gets the call, addressed to the
    // configured host, with no bearer.
    let config = write_config(fake.addr.port(), None);
    let (code, _, stderr) = cli_raw(&["--config", &config, "account", "list"], &env, None);
    assert_eq!(code, 0, "the loopback default reaches 127.0.0.1: {stderr}");
    let seen = fake.seen();
    let request = seen
        .last()
        .expect("the fake saw the call")
        .to_ascii_lowercase();
    assert!(
        request.contains(&format!("\r\nhost: {PRIVATE}:{}\r\n", fake.addr.port())),
        "the HTTP host is the configured address: {request}"
    );
    assert!(
        !request.contains("\r\nauthorization:"),
        "the loopback operator sends no secret: {request}"
    );

    // 2. https: a leaf for the configured address only, issued by a root that
    // only the configured chain file carries (leaf first, then the root).
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "private root");
    let ca = ca_params.self_signed(&ca_key).expect("CA");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let mut leaf_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    leaf_params.subject_alt_names = vec![rcgen::SanType::IpAddress(
        PRIVATE.parse().expect("an address"),
    )];
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("the leaf");
    let chain = root.join("chain.pem");
    fs::write(&chain, format!("{}{}", leaf.pem(), ca.pem())).expect("chain");
    let key = root.join("key.pem");
    write_private(&key, &leaf_key.serialize_pem());
    let front = tls_front_with(fake.addr, &chain, &key).await;
    let port: u16 = front
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("port");
    let config = write_config(port, Some((&chain, &key)));
    let (code, _, stderr) = cli_raw(&["--config", &config, "account", "list"], &env, None);
    assert_eq!(
        code, 0,
        "https verified for the configured address against the chain: {stderr}"
    );
    let request = fake
        .seen()
        .last()
        .expect("the call crossed the front")
        .to_ascii_lowercase();
    assert!(
        request.contains(&format!("\r\nhost: {PRIVATE}:{port}\r\n")),
        "{request}"
    );

    // 3. A leaf naming only 127.0.0.1 and localhost fails: the dialled
    // address is not the identity.
    let (fixture_cert, fixture_key) = stage_tls_pair(&root.join("fixture"));
    let front = tls_front_with(fake.addr, &fixture_cert, &fixture_key).await;
    let port: u16 = front
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("port");
    let config = write_config(port, Some((&fixture_cert, &fixture_key)));
    let (code, _, stderr) = cli_raw(&["--config", &config, "account", "list"], &env, None);
    assert_ne!(
        code, 0,
        "a leaf for 127.0.0.1 is not the configured address: {stderr}"
    );
    assert!(
        stderr.contains(PRIVATE),
        "the configured origin is named: {stderr}"
    );
}
