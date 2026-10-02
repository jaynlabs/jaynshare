//! The harness half of `fixtures/fake_tool.rs`: a directory of fake platform tools put first on `PATH`, their
//! scripted answers, and the calls they recorded. The product invokes each
//! tool by name through exactly one wrapper function, so a scenario scripts
//! only what that wrapper asks.
//!
//! `ignore
//! let tools = FakeTools::new(&root, &["systemctl"]);
//! tools.rule("systemctl", &["start"]).times(1).exit(1); // first start fails
//! let env = [isolated_env(&home), tools.env].concat;
//! let (code, out, err) = cli_raw(&["service", "start"], &env, None);
//! assert_eq!(tools.calls("systemctl")[0], ["start", "jaynshare.service"]);
//! `

#![allow(dead_code)] // the deploy units script the fakes

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use crate::harness::Value;

/// The fake, compiled once per run like the fake `claude`.
pub(crate) fn fake_tool_binary() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let source = manifest.join("tests/acceptance/fixtures/fake_tool.rs");
            let dir = manifest.join("target/acceptance-fixtures");
            fs::create_dir_all(&dir).expect("fixture directory");
            let out = dir.join(if cfg!(windows) {
                "fake-tool.exe"
            } else {
                "fake-tool"
            });
            let status = Command::new("rustc")
                .current_dir(&manifest)
                .args(["--edition", "2024", "-O", "-o"])
                .arg(&out)
                .arg(&source)
                .status()
                .expect("run rustc for the fake tool");
            assert!(status.success(), "the fake tool did not compile");
            out
        })
        .clone()
}

/// A set of fake tools under one scenario root.
pub(crate) struct FakeTools {
    /// `FAKE_TOOL_DIR`: the rules and `calls.ndjson`.
    pub(crate) dir: PathBuf,
    /// The directory put first on `PATH`.
    pub(crate) bin: PathBuf,
    next: Cell<u32>,
}

impl FakeTools {
    /// Places one copy of the fake per tool name under `root/fake-tools/`,
    /// unless one is already there.
    pub(crate) fn new(root: &Path, tools: &[&str]) -> Self {
        let dir = root.join("fake-tools");
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).expect("fake tool directory");
        for tool in tools {
            let name = if cfg!(windows) {
                format!("{tool}.exe")
            } else {
                (*tool).to_string()
            };
            if !bin.join(&name).exists() {
                fs::copy(fake_tool_binary(), bin.join(name)).expect("place a fake tool");
            }
            fs::create_dir_all(dir.join(tool)).expect("rule directory");
        }
        Self {
            dir,
            bin,
            next: Cell::new(0),
        }
    }

    /// `PATH` with the fakes first, then the system directories, and
    /// `FAKE_TOOL_DIR`. On Windows that is `System32` alone, which keeps the
    /// real `powershell` out of reach (see `profile_fx`).
    pub(crate) fn env(&self) -> Vec<(String, String)> {
        let path = if cfg!(windows) {
            let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            format!("{};{system_root}\\System32", self.bin.display())
        } else {
            let system = std::env::var("PATH").unwrap_or_default();
            format!("{}:{system}", self.bin.display())
        };
        vec![
            ("PATH".into(), path),
            ("FAKE_TOOL_DIR".into(), self.dir.display().to_string()),
        ]
    }

    /// A new rule for `tool`: calls whose argv contains `words` in order.
    /// Rules answer in the order they were added.
    pub(crate) fn rule(&self, tool: &str, words: &[&str]) -> Rule {
        let n = self.next.get();
        self.next.set(n + 1);
        let path = self.dir.join(tool).join(format!("{n:04}"));
        fs::create_dir_all(&path).expect("rule");
        fs::write(path.join("match"), words.join("\n")).expect("match");
        Rule { path }
    }

    /// Every recorded call of `tool`, in order: its argv without argv[0].
    pub(crate) fn calls(&self, tool: &str) -> Vec<Vec<String>> {
        self.records()
            .into_iter()
            .filter(|r| r["tool"] == tool)
            .map(|r| {
                r["argv"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|v| v.as_str().unwrap_or_default().to_string())
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Every recorded call of every tool, `{tool, argv, cwd}`, in order.
    pub(crate) fn records(&self) -> Vec<Value> {
        fs::read_to_string(self.dir.join("calls.ndjson"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("a call record"))
            .collect()
    }
}

/// One scripted answer; each setter writes its file at once.
pub(crate) struct Rule {
    path: PathBuf,
}

impl Rule {
    pub(crate) fn stdout(self, text: &str) -> Self {
        fs::write(self.path.join("stdout"), text).expect("stdout");
        self
    }

    pub(crate) fn stderr(self, text: &str) -> Self {
        fs::write(self.path.join("stderr"), text).expect("stderr");
        self
    }

    pub(crate) fn exit(self, code: i32) -> Self {
        fs::write(self.path.join("exit"), code.to_string()).expect("exit");
        self
    }

    /// The rule answers `n` more calls, then stops matching.
    pub(crate) fn times(self, n: u64) -> Self {
        fs::write(self.path.join("times"), n.to_string()).expect("times");
        self
    }

    /// Runs `program` with `args` (`{argv}` expands to the call's arguments
    /// after the matched words) and exits with its code.
    pub(crate) fn run(self, program: &Path, args: &[&str]) -> Self {
        let mut text = program.display().to_string();
        for arg in args {
            text.push('\n');
            text.push_str(arg);
        }
        fs::write(self.path.join("run"), text).expect("run");
        self
    }
}

/// The fixture itself: a rule answers in order, `times` retires it, `run`
/// forwards the call, and every call is recorded.
#[test]
fn the_fake_tool_answers_in_order_and_records_every_call() {
    let root = crate::harness::scratch("fake-tools-self-test");
    let tools = FakeTools::new(&root, &["systemctl"]);
    tools
        .rule("systemctl", &["start"])
        .times(1)
        .stderr("boom\n")
        .exit(3);
    tools.rule("systemctl", &["start"]).stdout("started\n");
    tools
        .rule("systemctl", &["show"])
        .run(Path::new("/bin/echo"), &["forwarded", "{argv}"]);
    let run = |args: &[&str]| {
        let output = Command::new(tools.bin.join("systemctl"))
            .args(args)
            .envs(tools.env())
            .output()
            .expect("run the fake");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };
    if cfg!(windows) {
        return;
    }
    assert_eq!(run(&["start", "jaynshare.service"]), (3, String::new()));
    assert_eq!(
        run(&["start", "jaynshare.service"]),
        (0, "started\n".into())
    );
    assert_eq!(
        run(&["show", "--property", "x"]),
        (0, "forwarded --property x\n".into())
    );
    assert_eq!(run(&["status"]), (0, String::new()));
    let calls = tools.calls("systemctl");
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[3], ["status"]);
}
