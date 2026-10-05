//! The two commands Claude Code runs — `statusline` and `title-hook`.
//! Their input documents are `statusline_payload` and `hook_payload`
//! (`client_fx`).

#[allow(unused_imports)]
use crate::client_fx::*;
#[allow(unused_imports)]
use crate::harness::*;

const STATUSLINE_ACTIVE: &[(&str, &str)] = &[("JAYNSHARE_STATUSLINE", "1")];
const STATUSLINE_ACTIVE_PLAIN: &[(&str, &str)] =
    &[("JAYNSHARE_STATUSLINE", "1"), ("NO_COLOR", "1")];

#[tokio::test(flavor = "multi_thread")]
async fn the_title_is_cleaned_collapsed_and_capped() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let machine = install_client(&Instance::start_client("title-cleaned-collapsed").await).await;

    let text = |prompt: &str| -> (Value, String) {
        let (code, out, err) = machine.jaynshare(&["title-hook"], &[], Some(&hook_payload(prompt)));
        assert_eq!(code, 0, "the hook exits 0");
        assert!(err.is_empty(), "stderr empty: {err:?}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "one output line, got {out:?}");
        let v: Value = serde_json::from_str(lines[0]).expect("the line is one JSON object");
        assert_eq!(
            v["hookSpecificOutput"]["hookEventName"],
            json!("UserPromptSubmit")
        );
        let title = v["hookSpecificOutput"]["sessionTitle"]
            .as_str()
            .expect("sessionTitle is a string")
            .to_owned();
        (v, title)
    };

    let (_, title) = text("fix\tthe\n\nlogin   bug\u{7}");
    assert_eq!(title, "fix the login bug");

    let (_, title) = text(&"x".repeat(300));
    assert_eq!(title.chars().count(), 72);
    assert!(!title.contains("jaynshare"));
    assert!(title.ends_with('\u{2026}'));

    let (_, title) = text("  café  au  lait  ");
    assert_eq!(title, "café au lait");
}

#[tokio::test(flavor = "multi_thread")]
async fn instructions_and_empty_prompts_set_no_title() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let machine = install_client(&Instance::start_client("instructions-empty-prompts").await).await;

    for prompt in [
        "",
        "   ",
        "/help",
        "  /compact now",
        "# remember the port",
        "!ls -la",
    ] {
        let (code, out, err) = machine.jaynshare(&["title-hook"], &[], Some(&hook_payload(prompt)));
        assert_eq!(code, 0, "the hook exits 0 for {prompt:?}");
        assert!(out.is_empty(), "stdout empty for {prompt:?}");
        assert!(err.is_empty(), "stderr empty for {prompt:?}");
    }
}

/// A payload that is absent, too large,
/// not JSON, or carrying an empty, overlong or non-identifier session id is
/// *no session id*: `statusline` still exits 0 with one line and nothing on
/// standard error, but its one client-status request carries no session id.
/// A well-formed payload sends its id.
#[tokio::test(flavor = "multi_thread")]
async fn a_bad_payload_is_no_session_and_sends_none() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("bad-payload-no-session").await;
    let machine = install_client(&instance).await;
    let fake = FakeControl::answering(200, snapshot_body(None));
    machine.set("base_url", &format!("{:?}", fake.origin()));

    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        &[],
        Some(&statusline_payload("vanilla-claude")),
    );
    assert_eq!(code, 0);
    assert!(stdout.is_empty(), "vanilla Claude has no jaynshare line");
    assert!(stderr.is_empty());
    assert!(fake.seen().is_empty(), "the disabled line makes no request");

    let bad: Vec<Option<String>> = vec![
        None,
        Some(json!({"session_id": "abc", "pad": "x".repeat(65 * 1024)}).to_string()),
        Some("not json".to_string()),
        Some(json!({"session_id": ""}).to_string()),
        Some(json!({"session_id": "a".repeat(300)}).to_string()),
        Some(json!({"session_id": "abc\u{7}def"}).to_string()),
        Some(json!({"session_id": 42}).to_string()),
    ];
    let mut requests = 0;
    for payload in &bad {
        let before = fake.seen().len();
        let (code, stdout, stderr) =
            machine.jaynshare(&["statusline"], STATUSLINE_ACTIVE, payload.as_deref());
        assert_eq!(code, 0, "statusline exits 0: {stderr}");
        assert_eq!(stderr, "", "nothing on stderr: {stderr}");
        assert_eq!(stdout.lines().count(), 1, "one line: {stdout}");
        requests += 1;
        let seen = fake.seen();
        assert_eq!(seen.len(), before + 1, "one request per run");
        assert!(
            seen.last()
                .expect("a request")
                .starts_with("GET /control/v1/client/status?rate_limits=true HTTP/1.1"),
            "no session id is sent: {:?}",
            seen.last()
        );
    }
    assert_eq!(requests, bad.len());

    // Positive control: a well-formed payload sends its session id.
    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        STATUSLINE_ACTIVE,
        Some(&statusline_payload("3f7a2c1e-0000-4000-8000-00000000c0de")),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "");
    assert_eq!(stdout.lines().count(), 1, "one line: {stdout}");
    let seen = fake.seen();
    assert_eq!(seen.len(), requests + 1, "one request per run");
    assert!(
        seen.last().expect("a request").starts_with(
            "GET /control/v1/client/status?rate_limits=true&session_id=3f7a2c1e-0000-4000-8000-00000000c0de HTTP/1.1"
        ),
        "the session id travels in the query: {:?}",
        seen.last()
    );
}

/// `statusline` reads the
/// payload, makes the one read keyed by the payload's session id and
/// prints the one line: the serving account and every Claude Code account's
/// five-hour and weekly utilisation, with no unrelated pool or session details.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_names_the_serving_account_and_rate_limits() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("line-names-serving").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let sid = "3f7a2c1e-0000-4000-8000-00000000c0de";
    let answer = send(
        instance.addr,
        in_session(
            with(
                messages(haiku_prompt()),
                &[("authorization", &machine.client.bearer())],
            ),
            sid,
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "the routed exchange");

    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        STATUSLINE_ACTIVE_PLAIN,
        Some(&statusline_payload(sid)),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "");
    let expected = "jaynshare → FSUB 12%/3% · FSUB2 ?/? · 1 active\n";
    assert_eq!(
        stdout,
        expected,
        "the status snapshot: {:?}",
        machine.jaynshare(
            &["status", "--json", "--session", sid],
            &[("NO_COLOR", "1")],
            None
        )
    );
    for unrelated in ["pool", "capture", "reset", "token"] {
        assert!(!stdout.contains(unrelated), "only account rates: {stdout}");
    }

    // Wire capture is deliberately not part of this compact line.
    let instance = Instance::start_with(
        "line-names-serving-capture",
        Setup {
            capture: true,
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let answer = send(
        instance.addr,
        in_session(
            with(
                messages(haiku_prompt()),
                &[("authorization", &machine.client.bearer())],
            ),
            sid,
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "the routed exchange");
    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        STATUSLINE_ACTIVE_PLAIN,
        Some(&statusline_payload(sid)),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "");
    assert!(!stdout.contains("capture"), "only account rates: {stdout}");
}

/// Pending (the pool answers, no serving
/// account yet), a reachable pool with zero selectable accounts (still not
/// offline), offline (the connection is refused) and a (the enrollment
/// is refused, a state of its own) are four distinct lines.
#[tokio::test(flavor = "multi_thread")]
async fn pending_offline_and_refused_are_distinct() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("pending-offline-refused").await;
    let machine = install_client(&instance).await;
    let no_colour = STATUSLINE_ACTIVE_PLAIN;

    // Pending: the pool answers, but `session` names no serving account.
    let mut pending_body = snapshot_body(None);
    pending_body["control_api_version"] = json!(1);
    let pending = FakeControl::answering(200, pending_body);
    machine.set("base_url", &format!("{:?}", pending.origin()));
    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        no_colour,
        Some(&statusline_payload("3f7a2c1e-0000-4000-8000-00000000c0de")),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "");
    assert_eq!(stdout, "jaynshare → pending · 1 active\n", "pending");

    // Zero selectable: the reachable pool keeps the session state and 0/3.
    let mut zero = snapshot_body(Some("FSUB"));
    zero["control_api_version"] = json!(1);
    zero["pool"]["accounts_selectable"] = json!(0);
    let zero = FakeControl::answering(200, zero);
    machine.set("base_url", &format!("{:?}", zero.origin()));
    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        no_colour,
        Some(&statusline_payload("3f7a2c1e-0000-4000-8000-00000000c0de")),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "");
    assert!(stdout.contains("FSUB"), "{stdout}");
    assert!(stdout.contains("→"), "{stdout}");
    assert!(!stdout.contains("offline"), "{stdout}");

    // Offline: the connection is refused.
    machine.set("base_url", "\"http://127.0.0.1:1\"");
    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        no_colour,
        Some(&statusline_payload("3f7a2c1e-0000-4000-8000-00000000c0de")),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "");
    assert_eq!(stdout, "jaynshare: offline\n", "offline");

    // Refused: a 401 names the enrollment, not offline.
    // The real control plane's 401 is a envelope: with the version
    // member the client maps it to code 5 (refused), not 10.
    let refused = FakeControl::answering(
        401,
        json!({
            "control_api_version": 1,
            "error": {"code": "unauthenticated", "message": "no principal"},
        }),
    );
    machine.set("base_url", &format!("{:?}", refused.origin()));
    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        no_colour,
        Some(&statusline_payload("3f7a2c1e-0000-4000-8000-00000000c0de")),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "");
    assert!(stdout.contains("enrollment refused"), "{stdout}");
    assert!(!stdout.contains("offline"), "{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_hook_input_is_silent_and_sends_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let machine = install_client(&Instance::start_client("malformed-hook-input").await).await;
    let fake = FakeControl::answering(200, snapshot_body(None));
    machine.set("base_url", &format!("{:?}", fake.origin()));

    let big = "x".repeat(5 * 1024 * 1024);
    for stdin in [
        None,
        Some("not json".to_owned()),
        Some("[1, 2]".to_owned()),
        Some(json!({"prompt": 42}).to_string()),
        Some(json!({"no_prompt": true}).to_string()),
        Some("{\"prompt\": \"unterminated".to_owned()),
        Some(big),
    ] {
        let (code, out, err) = machine.jaynshare(&["title-hook"], &[], stdin.as_deref());
        assert_eq!(code, 0, "exit 0 for {stdin:?}");
        assert!(out.is_empty(), "stdout empty for {stdin:?}: {out:?}");
        assert!(err.is_empty(), "stderr empty for {stdin:?}: {err:?}");
    }
    assert!(
        fake.seen().is_empty(),
        "the hook makes no request: {:?}",
        fake.seen()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_hook_result_in_the_hook_shape_and_no_escape() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let machine = install_client(&Instance::start_client("hook-result-hook").await).await;

    let (code, out, err) = machine.jaynshare(
        &["title-hook"],
        &[],
        Some(&hook_payload("rename the login handler")),
    );
    assert_eq!(code, 0, "the hook exits 0");
    assert!(err.is_empty(), "stderr empty: {err:?}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 1, "exactly one line, got {out:?}");
    let v: Value = serde_json::from_str(lines[0]).expect("the line is one JSON object");
    assert_eq!(
        v,
        json!({
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "sessionTitle": "rename the login handler",
            }
        })
    );
    assert!(!out.contains('\u{1b}'), "no escape in stdout: {out:?}");
    assert!(!out.contains('\u{7}'), "no bell in stdout: {out:?}");
    assert!(!err.contains('\u{1b}'), "no escape in stderr: {err:?}");
    assert!(!err.contains('\u{7}'), "no bell in stderr: {err:?}");
}

use std::collections::BTreeMap;
use std::time::SystemTime;

/// What one status-line run may touch: `client.toml`, `client-secret`,
/// `ca.pem` in the client directory, and nothing else.
const STATUS_LINE_CLIENT_FILES: [&str; 3] = ["client.toml", "client-secret", "ca.pem"];

type FileStamp = (u64, SystemTime);

fn stamps_excluded(machine: &ClientHome, path: &Path) -> bool {
    path.starts_with(&machine.out)
        // The fake `powershell` the Windows environment places on first use.
        || path.starts_with(machine.home.join("fake-tools"))
        || path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("transcript-"))
}

fn stamps_walk(machine: &ClientHome, base: &Path, map: &mut BTreeMap<PathBuf, FileStamp>) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if stamps_excluded(machine, &path) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            stamps_walk(machine, &path, map);
        } else if meta.is_file() {
            map.insert(path, (meta.len(), meta.modified().expect("mtime")));
        }
    }
}

/// Every file under the machine's home and scratch root, with length and
/// modification time.
fn stamps_snapshot(machine: &ClientHome) -> BTreeMap<PathBuf, FileStamp> {
    let mut map = BTreeMap::new();
    stamps_walk(machine, &machine.home, &mut map);
    stamps_walk(machine, &machine.root, &mut map);
    map
}

/// Every `"…"` string in a strace call line (its path arguments).
fn trace_quoted(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        match after.find('"') {
            Some(end) => {
                out.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out
}

/// The flags text of a strace call whose `n`th quoted argument is `path`.
fn trace_flags(call: &str, path: &str) -> String {
    let needle = format!("\"{path}\"");
    match call.find(&needle) {
        Some(i) => call[i + needle.len()..]
            .split(") =")
            .next()
            .unwrap_or("")
            .to_string(),
        None => String::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_status_line_run_touches_only_the_client_files() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let machine = install_client(&Instance::start_client("status-line-run-touches").await).await;
    let fake = FakeControl::answering(200, snapshot_body(Some("FSUB")));
    machine.set("base_url", &format!("{:?}", fake.origin()));
    let sid = "3f7a2c1e-0000-4000-8000-00000000c0de";

    // Portable half: the whole scratch home and root, file set, lengths and
    // mtimes, before and after one run.
    let before = stamps_snapshot(&machine);
    let (code, _stdout, stderr) = machine.jaynshare(
        &["statusline"],
        STATUSLINE_ACTIVE,
        Some(&statusline_payload(sid)),
    );
    assert_eq!(code, 0, "statusline exits 0: {stderr}");
    assert!(stderr.is_empty(), "stderr empty: {stderr:?}");
    let after = stamps_snapshot(&machine);
    assert_eq!(before, after, "a status-line run changed a file");

    // Traced half (Linux only): every open under the home is one of
    // the three client files, read-only, and nothing under the home is
    // created, made, renamed or removed.
    if cfg!(target_os = "linux")
        && Command::new("strace")
            .arg("-V")
            .output()
            .is_ok_and(|o| o.status.success())
    {
        let trace = std::env::temp_dir().join("status-line-run-touches-strace.txt");
        let _ = fs::remove_file(&trace);
        let mut traced = Command::new("strace");
        traced
            .args(["-f", "-e", "trace=open,openat,creat,mkdir,rename,unlink"])
            .arg("-o")
            .arg(&trace)
            .arg(binary())
            .arg("statusline");
        traced
            .env_clear()
            .envs(machine.env())
            .env("JAYNSHARE_STATUSLINE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = traced.spawn().expect("strace jaynshare");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(statusline_payload(sid).as_bytes())
            .expect("write stdin");
        let status = child.wait().expect("strace wait");
        assert!(status.success(), "the traced run exits 0: {status:?}");
        let text = fs::read_to_string(&trace).expect("the strace output");
        for line in text.lines() {
            let call = line.split(") =").next().unwrap_or(line);
            let opens =
                call.contains("open(") || call.contains("openat(") || call.contains("openat2(");
            let touches = [
                "creat(",
                "mkdir(",
                "mkdirat(",
                "rename(",
                "renameat(",
                "renameat2(",
                "unlink(",
                "unlinkat(",
            ]
            .iter()
            .any(|s| call.contains(s));
            if !opens && !touches {
                continue;
            }
            let paths = trace_quoted(call);
            let under_home: Vec<&String> = paths
                .iter()
                .filter(|p| Path::new(p.as_str()).starts_with(&machine.home))
                .collect();
            if under_home.is_empty() {
                // A relative path (`openat` at a client-directory fd, say) is
                // still a write under the home when it has write intent.
                if opens {
                    for p in &paths {
                        if !Path::new(p).is_absolute() {
                            let flags = trace_flags(call, p);
                            assert!(
                                !flags.contains("O_CREAT")
                                    && !flags.contains("O_WRONLY")
                                    && !flags.contains("O_RDWR"),
                                "relative write open: {line}"
                            );
                        }
                    }
                }
                continue;
            }
            if opens {
                assert_eq!(under_home.len(), 1, "more than one home path in {line}");
                let path = under_home[0].as_str();
                let opened = Path::new(path);
                let name = opened.file_name().and_then(|n| n.to_str()).expect("a name");
                assert_eq!(
                    opened.parent().expect("a parent"),
                    machine.client_dir,
                    "statusline opened {path}"
                );
                assert!(
                    STATUS_LINE_CLIENT_FILES.contains(&name),
                    "statusline opened {path}"
                );
                let flags = trace_flags(call, path);
                assert!(
                    !flags.contains("O_CREAT")
                        && !flags.contains("O_WRONLY")
                        && !flags.contains("O_RDWR"),
                    "{path} opened {flags:?}"
                );
            } else {
                panic!("statusline touches the home: {line}");
            }
        }
    } else {
        eprintln!(": traced half skipped on this platform");
    }
}

/// A server that sleeps 5 s before answering:
/// the whole run is bounded, the line is written as **offline**, exit 0,
/// nothing on standard error, and exactly one request was made — never a
/// retry.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_server_gives_the_offline_line_in_time() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("slow-server-gives").await;
    let machine = install_client(&instance).await;
    let fake = FakeControl::start(|_| {
        std::thread::sleep(Duration::from_secs(5));
        http_reply(200, "application/json", &snapshot_body(None).to_string())
    });
    machine.set("base_url", &format!("{:?}", fake.origin()));

    let started = std::time::Instant::now();
    let (code, stdout, stderr) = machine.jaynshare(
        &["statusline"],
        STATUSLINE_ACTIVE_PLAIN,
        Some(&statusline_payload("3f7a2c1e-0000-4000-8000-00000000c0de")),
    );
    let elapsed = started.elapsed();
    assert_eq!(code, 0, "exit 0: {stderr}");
    assert_eq!(stdout, "jaynshare: offline\n", "the offline line: {stdout}");
    assert_eq!(stderr, "", "nothing on standard error: {stderr}");
    assert!(
        elapsed < Duration::from_millis(2_500),
        "the 1.5 s bound plus process start: {elapsed:?}"
    );
    // Give a retry (were there one) its chance to arrive, then count.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(fake.seen().len(), 1, "one request, never retried");
}

/// The line
/// names the account that actually served the latest routed request: after
/// one automatic exchange it names the default; after one the session pin
/// routed elsewhere it names that account; and after an operator switch and
/// one more automatic exchange it names whatever the binding rules
/// decided — asserted against the audit record, not a guess.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_follows_the_account_that_served_last() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("line-follows-account").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    const SID: &str = "3f7a2c1e-0000-4000-8000-00000000c0de";
    let line = || async {
        let (code, stdout, stderr) = machine.jaynshare(
            &["statusline"],
            STATUSLINE_ACTIVE_PLAIN,
            Some(&statusline_payload(SID)),
        );
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(stderr, "", "nothing on standard error: {stderr}");
        stdout
    };

    // One automatic exchange: the line names the default account.
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
    assert_eq!(answer.status, 200, "the first exchange: {answer:?}");
    assert!(
        line().await.starts_with("jaynshare → FSUB "),
        "the first line names the default"
    );

    // The same session, pinned to FSUB2: the pool serves it, and the next
    // line names the account that served it, not the default.
    let answer = send(
        instance.addr,
        in_session(
            with(
                messages(haiku_prompt()),
                &[
                    ("authorization", &machine.client.bearer()),
                    (
                        "x-jaynshare-account",
                        &token(true, &instance.handle("FSUB2")),
                    ),
                ],
            ),
            SID,
        ),
    )
    .await;
    assert_eq!(answer.status, 200, "the pinned exchange: {answer:?}");
    let record = instance.last_record(2);
    assert_eq!(
        record["serving_account"]["display_name"],
        json!("FSUB2"),
        "the audit record: {record}"
    );
    assert!(
        line().await.contains("→ FSUB2 "),
        "the line follows the account that served"
    );

    // The operator switch, then one more automatic exchange: the
    // line names whatever the binding rules decided, read from the
    // audit record.
    let (code, _, stderr) = instance.cli(&["switch", "FSUB"], None);
    assert_eq!(code, 0, "the switch: {stderr}");
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
    assert_eq!(answer.status, 200, "the third exchange: {answer:?}");
    let record = instance.last_record(3);
    let served = record["serving_account"]["display_name"]
        .as_str()
        .expect("a serving account in the record");
    assert!(
        line().await.contains(&format!("→ {served} ")),
        "the line names {served}, the record's serving account"
    );
}

/// The two hooks Claude Code runs take garbage on
/// standard input (exit 0, nothing on standard error), take no option
/// every option on them is a usage error — and are listed in help under a
/// heading saying Claude Code runs them.
#[tokio::test(flavor = "multi_thread")]
async fn the_hooks_never_fail_and_take_no_option() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("hooks-never-fail").await;
    let machine = install_client(&instance).await;

    // Garbage in: the hooks still exit 0 with nothing on standard error.
    let garbage = [
        "\u{0}\u{1}\u{2}binary".to_owned(),
        "{".to_owned(),
        "[]".to_owned(),
        "null".to_owned(),
        "x".repeat(100_000),
    ];
    for stdin in &garbage {
        let (code, out, err) = machine.jaynshare(&["statusline"], STATUSLINE_ACTIVE, Some(stdin));
        assert_eq!(code, 0, "statusline with {stdin:?}: {err}");
        assert!(err.is_empty(), "statusline with {stdin:?}: stderr {err:?}");
        assert_eq!(
            out.lines().count(),
            1,
            "statusline with {stdin:?} prints its one line: {out:?}"
        );
        let (code, out, err) = machine.jaynshare(&["title-hook"], &[], Some(stdin));
        assert_eq!(code, 0, "title-hook with {stdin:?}: {err}");
        assert!(out.is_empty(), "title-hook with {stdin:?}: stdout {out:?}");
        assert!(err.is_empty(), "title-hook with {stdin:?}: stderr {err:?}");
    }

    // No option: every option on the hooks is a usage error, exit 2. With
    // --json on the line the envelope names `cli_usage`; a plain
    // clap refusal writes the usage line on standard error only.
    for args in [
        ["statusline", "--json"],
        ["title-hook", "--json"],
        ["statusline", "--verbose"],
        ["title-hook", "extra"],
    ] {
        let (code, stdout, stderr) = machine.jaynshare(&args, &[], None);
        assert_eq!(code, 2, "{args:?}: {stdout}{stderr}");
        if args.contains(&"--json") {
            let envelope: Value = serde_json::from_str(stdout.trim())
                .unwrap_or_else(|e| panic!("{args:?}: {e}: {stdout}"));
            assert_eq!(envelope["ok"], json!(false), "{args:?}: {envelope}");
            assert_eq!(envelope["exit_code"], json!(2), "{args:?}: {envelope}");
            assert_eq!(
                envelope["error"]["code"], "cli_usage",
                "{args:?}: {envelope}"
            );
        } else {
            assert!(stdout.is_empty(), "{args:?}: stdout {stdout:?}");
            assert!(
                stderr.contains("Usage: jaynshare"),
                "{args:?}: the usage line on standard error: {stderr}"
            );
        }
    }

    // Help lists the two hooks under a heading saying Claude Code runs them.
    let (_, help, stderr) = machine.jaynshare(&["help"], &[], None);
    assert_eq!(help.lines().count() > 1, stderr.is_empty(), "{stderr}");
    let heading = help
        .lines()
        .position(|l| l.contains("Claude Code") && l.ends_with(':'))
        .expect("a heading containing Claude Code");
    let after: Vec<&str> = help
        .lines()
        .skip(heading + 1)
        .take_while(|l| !l.ends_with(':'))
        .collect();
    let verbs: Vec<&str> = after.iter().map(|l| l.trim()).collect();
    assert_eq!(
        verbs
            .first()
            .copied()
            .unwrap_or("")
            .split_whitespace()
            .next(),
        Some("statusline"),
        "statusline is listed first under the heading"
    );
    assert_eq!(
        verbs
            .get(1)
            .copied()
            .unwrap_or("")
            .split_whitespace()
            .next(),
        Some("title-hook"),
        "title-hook is listed second under the heading"
    );
}
