//! The engineer's side of the suite: the fake `claude`, an enrolled client
//! installation under a scratch home that the test's instance serves, the
//! pseudo-terminal with a clean environment, and the two payloads Claude
//! Code hands its extension points.
//!
//! Every child here starts from an **empty** environment plus the test's
//! own variables, so nothing the developer's shell exports (a proxy, a
//! `JAYNSHARE_*` value, a Claude Code variable) reaches a launch.

// Shared fixtures: each unit uses some of them.
#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::harness::*;

/// keystrokes for the keyboard picker, as a terminal sends them.
pub(crate) const KEY_UP: &str = "\x1b[A";
pub(crate) const KEY_DOWN: &str = "\x1b[B";
pub(crate) const KEY_ENTER: &str = "\r";
pub(crate) const KEY_ESC: &str = "\x1b";
pub(crate) const KEY_CTRL_C: &str = "\x03";

// ------------------------------------------------------------------ the fake `claude`

/// The fake, compiled once per run from `fixtures/fake_claude.rs` with the
/// pinned toolchain's `rustc`, outside `target/acceptance` so no sweep reads
/// it.
pub(crate) fn fake_claude_binary() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let source = manifest.join("tests/acceptance/fixtures/fake_claude.rs");
            let dir = manifest.join("target/acceptance-fixtures");
            fs::create_dir_all(&dir).expect("fixture directory");
            let out = dir.join(if cfg!(windows) {
                "claude.exe"
            } else {
                "claude"
            });
            let status = Command::new("rustc")
                .current_dir(&manifest)
                .args(["--edition", "2024", "-O", "-o"])
                .arg(&out)
                .arg(&source)
                .status()
                .expect("run rustc for the fake claude");
            assert!(status.success(), "the fake claude did not compile");
            out
        })
        .clone()
}

/// What one run of the fake saw.
#[derive(Debug, Clone)]
pub(crate) struct FakeClaudeRun {
    /// Its arguments, without argv[0].
    pub(crate) argv: Vec<String>,
    /// Its whole environment.
    pub(crate) env: BTreeMap<String, String>,
}

impl FakeClaudeRun {
    /// the account intent the launch carried — the user
    /// field of the proxy URL `http://<token>:<secret>@<proxy>`; `None` for
    /// automatic selection (an empty user field).
    pub(crate) fn pin(&self) -> Option<String> {
        let url = self.env.get("HTTPS_PROXY")?;
        let userinfo = url.strip_prefix("http://")?.split_once('@')?.0;
        let user = userinfo.split_once(':')?.0;
        (!user.is_empty()).then(|| user.to_string())
    }
}

// ------------------------------------------------------------------ the enrolled installation

/// One enrolled engineer machine: a scratch home whose directory the
/// instance's client secret lives in, and a search path holding the fake.
pub(crate) struct ClientHome {
    pub(crate) root: PathBuf,
    pub(crate) home: PathBuf,
    pub(crate) client_dir: PathBuf,
    /// The directory on `PATH` that holds `claude`.
    pub(crate) bin: PathBuf,
    /// `FAKE_CLAUDE_OUT`.
    pub(crate) out: PathBuf,
    pub(crate) client: Enrolled,
    /// The instance's base-URL origin and proxy origin, as `client.toml` has them.
    pub(crate) base_url: String,
    pub(crate) proxy: String,
}

/// the client directory under `home`.
pub(crate) fn client_dir(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Jaynshare/client")
    } else if cfg!(windows) {
        // Native separators throughout: the paths are compared as
        // Windows spells them.
        roaming(home).join("Jaynshare").join("client")
    } else {
        home.join(".config/jaynshare/client")
    }
}

/// The Windows profile's roaming folder under a scratch home (`APPDATA`).
pub(crate) fn roaming(home: &Path) -> PathBuf {
    home.join("AppData").join("Roaming")
}

/// Enrol one client on `instance` (issue + claim over the control API) and
/// write its files under `<instance root>/engineer/home` exactly as
/// `join` leaves them: `client.toml`, `client-secret` (`0600`) and
/// `ca.pem` with its fingerprint — the instance must run with
/// `Setup { mitm: true.. }` (`Instance::start_client`). The fake `claude` is
/// placed on `PATH`.
pub(crate) async fn install_client(instance: &Instance) -> ClientHome {
    let client = enroll(instance, "engineer-1", "Engineer One").await;
    let root = instance.root.join("engineer");
    let home = root.join("home");
    let bin = root.join("bin");
    let out = root.join("claude-out");
    for dir in [&home, &bin, &out] {
        fs::create_dir_all(dir).expect("engineer directory");
    }
    let dir = client_dir(&home);
    fs::create_dir_all(dir.parent().expect("parent")).expect("config root");
    private_dir(&dir);
    let base_url = format!("http://{}", instance.addr);
    let proxy = format!(
        "http://{}",
        instance
            .mitm_addr
            .expect("the proxy listener is always bound")
    );
    let ca = fs::read(instance.root.join("state/mitm-ca.pem")).expect(
        "the instance CA: start it with Instance::start_client or Setup { mitm: true, .. }",
    );
    fs::write(dir.join("ca.pem"), ca).expect("ca.pem");
    let fingerprint = crate::mtm::ca_fingerprint(&instance.root.join("state"));
    let toml = format!(
        "client_id = {:?}\ndisplay_name = {:?}\nbase_url = {base_url:?}\nproxy_url = {proxy:?}\nca_fingerprint = {fingerprint:?}\nno_proxy = []\n",
        client.id, "Engineer One",
    );
    fs::write(dir.join("client.toml"), toml).expect("client.toml");
    let secret_file = dir.join("client-secret");
    write_private(&secret_file, &client.secret);
    crate::leaks::register_planted(&secret_file);
    let claude = bin.join(if cfg!(windows) {
        "claude.exe"
    } else {
        "claude"
    });
    fs::copy(fake_claude_binary(), &claude).expect("place the fake claude");
    // The fake's own observation files hold the child environment — the
    // secret included, by design (allows the child's environment).
    for name in ["argv.json", "env.json"] {
        crate::leaks::register_planted(&out.join(name));
    }
    ClientHome {
        root,
        home,
        client_dir: dir,
        bin,
        out,
        client,
        base_url,
        proxy,
    }
}

impl ClientHome {
    /// The whole environment of a child: the scratch home, a search path of
    /// the fake plus the system directories, the fake's output directory and
    /// A UTF-8 locale. Nothing else.
    pub(crate) fn env(&self) -> Vec<(String, String)> {
        let mut env = isolated_env(&self.home);
        if cfg!(windows) {
            // `SystemRoot` is what any Windows process needs to reach the
            // network.
            let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            env.push((
                "PATH".into(),
                format!("{};{system_root}\\System32", self.bin.display()),
            ));
            env.push(("SystemRoot".into(), system_root));
        } else {
            env.push((
                "PATH".into(),
                format!("{}:/usr/bin:/bin", self.bin.display()),
            ));
        }
        env.push(("FAKE_CLAUDE_OUT".into(), self.out.display().to_string()));
        env.push(("LANG".into(), "en_US.UTF-8".into()));
        env
    }

    /// The binary with no controlling terminal at all: on Unix the child
    /// starts its own session (`setsid`, through perl's POSIX module — the
    /// suite has no `unsafe`), so `/dev/tty` cannot be opened and a picker
    /// can never draw on the developer's terminal.
    pub(crate) fn command(&self, extra: &[(&str, &str)]) -> Command {
        let mut command = if cfg!(unix) {
            let mut perl = Command::new("/usr/bin/perl");
            perl.args([
                "-MPOSIX",
                "-e",
                "POSIX::setsid(); exec { $ARGV[0] } @ARGV or exit 127",
            ])
            .arg(binary());
            perl
        } else {
            Command::new(binary())
        };
        command
            .env_clear()
            .envs(self.env())
            .envs(extra.iter().map(|(k, v)| (*k, *v)));
        command
    }

    /// Rewrite one `client.toml` key: `value` is TOML (`"\"http://…\""`,
    /// `"[\"corp.example\"]"`). Points this machine at a `FakeControl`, or
    /// changes its `no_proxy` or `ca_fingerprint`.
    pub(crate) fn set(&self, key: &str, value: &str) {
        let path = self.client_dir.join("client.toml");
        let text = fs::read_to_string(&path).expect("client.toml");
        let prefix = format!("{key} = ");
        assert!(
            text.lines().any(|l| l.starts_with(&prefix)),
            "client.toml has no {key}"
        );
        let text: String = text
            .lines()
            .map(|l| {
                if l.starts_with(&prefix) {
                    format!("{prefix}{value}\n")
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        fs::write(&path, text).expect("client.toml");
    }

    /// One `jaynshare` invocation with this machine's environment plus
    /// `extra`, no terminal: exit code, standard output, standard error.
    pub(crate) fn jaynshare(
        &self,
        args: &[&str],
        extra: &[(&str, &str)],
        stdin: Option<&str>,
    ) -> (i32, String, String) {
        let mut command = self.command(extra);
        command
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("run jaynshare");
        if let Some(text) = stdin {
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write stdin");
        }
        let output = child.wait_with_output().expect("jaynshare output");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// What the fake saw on its last run, or `None` when it never ran (the
    /// launch was refused). Clears the record, so the next call sees only
    /// the next run.
    pub(crate) fn claude_ran(&self) -> Option<FakeClaudeRun> {
        let argv = fs::read_to_string(self.out.join("argv.json")).ok()?;
        let env = fs::read_to_string(self.out.join("env.json")).expect("env.json beside argv.json");
        for name in ["argv.json", "env.json"] {
            let _ = fs::remove_file(self.out.join(name));
        }
        Some(FakeClaudeRun {
            argv: serde_json::from_str(&argv).expect("argv.json"),
            env: serde_json::from_str(&env).expect("env.json"),
        })
    }

    /// no `claude` on the search path any more.
    pub(crate) fn remove_claude(&self) {
        let _ = fs::remove_file(self.bin.join(if cfg!(windows) {
            "claude.exe"
        } else {
            "claude"
        }));
    }

    /// One `jaynshare` invocation on a pseudo-terminal: each
    /// `(prompt, keys)` pair is typed once `prompt` has appeared in the
    /// transcript. Both streams share the terminal; the result is the exit
    /// code and the transcript.
    pub(crate) fn pty(
        &self,
        args: &[&str],
        extra: &[(&str, &str)],
        answers: &[(&str, &str)],
    ) -> (i32, String) {
        let mut argv = vec![binary().display().to_string()];
        argv.extend(args.iter().map(|a| (*a).to_string()));
        self.pty_argv(&argv, extra, answers)
    }

    /// The same for a shell line (`/bin/sh -c <line>`), for the rows whose
    /// standard output is redirected while the terminal stays.
    /// `$JAYNSHARE` in the line is the binary under test.
    pub(crate) fn pty_shell(
        &self,
        line: &str,
        extra: &[(&str, &str)],
        answers: &[(&str, &str)],
    ) -> (i32, String) {
        let line = line.replace("$JAYNSHARE", &format!("'{}'", binary().display()));
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), line];
        self.pty_argv(&argv, extra, answers)
    }

    fn pty_argv(
        &self,
        argv: &[String],
        extra: &[(&str, &str)],
        answers: &[(&str, &str)],
    ) -> (i32, String) {
        static RUNS: AtomicUsize = AtomicUsize::new(0);
        let n = RUNS.fetch_add(1, Ordering::Relaxed);
        let transcript = self.root.join(format!("transcript-{n}"));
        let _ = fs::remove_file(&transcript);
        let mut command = Command::new("/usr/bin/script");
        if cfg!(target_os = "macos") {
            command
                .args(["-q", "-F", &transcript.display().to_string()])
                .args(argv);
        } else {
            // `exec`: the program alone in the terminal's foreground
            // group, as on macOS, not under `script -c`'s shell.
            let line = argv
                .iter()
                .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
                .collect::<Vec<_>>()
                .join(" ");
            let line = format!("exec {line}");
            command.args([
                "-q",
                "-f",
                "-e",
                "-c",
                &line,
                &transcript.display().to_string(),
            ]);
        }
        command
            .env_clear()
            .envs(self.env())
            .env("TERM", "xterm")
            .envs(extra.iter().map(|(k, v)| (*k, *v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("run under `script`");
        let mut stdin = child.stdin.take().expect("script stdin");
        for (prompt, keys) in answers {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !fs::read_to_string(&transcript)
                .unwrap_or_default()
                .contains(prompt)
            {
                if let Ok(Some(status)) = child.try_wait() {
                    panic!(
                        "exited with {status} before {prompt:?} appeared: {}",
                        fs::read_to_string(&transcript).unwrap_or_default()
                    );
                }
                assert!(
                    Instant::now() < deadline,
                    "{prompt:?} never appeared: {}",
                    fs::read_to_string(&transcript).unwrap_or_default()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            stdin.write_all(keys.as_bytes()).expect("type");
            stdin.flush().expect("flush");
        }
        let output = child.wait_with_output().expect("script output");
        drop(stdin);
        let code = output.status.code().unwrap_or(-1);
        let text = fs::read_to_string(&transcript)
            .unwrap_or_else(|_| String::from_utf8_lossy(&output.stdout).into_owned());
        let text = text
            .split_inclusive('\n')
            .filter(|l| !l.starts_with("Script started on ") && !l.starts_with("Script done on "))
            .collect::<String>();
        (code, text)
    }
}

/// The client snapshot as a `FakeControl` answers it: two of three
/// accounts selectable, one active session of two known, capture off, hold
/// hint 0; `session` is `{serving_account_display_name, last_routed_at}` when
/// `serving` is `Some`, `null` otherwise. Edit the returned value for a row's
/// own facts. A body a `FakeControl` serves without `control_api_version`
/// is refused as an incompatible server (exit 10), and a refused
/// credential is with `{"error": {"type": "authentication_error"}}`.
pub(crate) fn snapshot_body(serving: Option<&str>) -> Value {
    json!({
    // Every control answer carries the version it speaks.
           "control_api_version": 1,
           "client": { "id": "engineer-1", "display_name": "Engineer One" },
           "server": { "version": "0.1.0", "available": true, "control_api_version": 1 },
           "capabilities": [],
           "ca_fingerprint": null,
           "pool": { "accounts_configured": 3, "accounts_selectable": 2 },
           "sessions": { "known": 2, "active": 1 },
           "wire_capture_enabled": false,
           "hold_hint_seconds": 0,
           "session": serving.map(|name| json!({
               "serving_account_display_name": name,
               "last_routed_at": "2026-09-23T10:00:00Z",
           })),
           "captured_at": "2026-09-23T10:00:01Z",
       })
}

// ------------------------------------------------------------------ extension-point payloads

/// the status line's standard-input document for `session_id`.
pub(crate) fn statusline_payload(session_id: &str) -> String {
    json!({
        "session_id": session_id,
        "version": "2.1.280",
        "model": { "id": "claude-haiku-4-5-20251001", "display_name": "Haiku 4.5" },
        "workspace": { "current_dir": "/tmp/project", "project_dir": "/tmp/project" },
        "cost": { "total_cost_usd": 0.0, "total_duration_ms": 1200 },
    })
    .to_string()
}

/// the `UserPromptSubmit` hook's standard-input document.
pub(crate) fn hook_payload(prompt: &str) -> String {
    json!({
        "prompt": prompt,
        "session_id": "3f7a2c1e-0000-4000-8000-00000000c0de",
        "cwd": "/tmp/project",
        "transcript_path": "/tmp/project/transcript.jsonl",
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
    })
    .to_string()
}
