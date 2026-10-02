//! The scripted platform-tool fake: one executable,
//! copied under each tool's name (`systemctl`, `nft`, `security`,
//! `certutil`, …) into a directory the scenario puts first on
//! `PATH`. Compiled by the harness with `rustc` (std only), never part of the
//! product.
//!
//! When run as `<tool>` it:
//! - appends `{"tool": <tool>, "argv": [...], "cwd": <dir>}` as one line to
//!   `$FAKE_TOOL_DIR/calls.ndjson`;
//! - answers from the first rule in `$FAKE_TOOL_DIR/<tool>/`, a directory
//!   of rule directories taken in name order. A rule directory holds:
//!   - `match`: words, one per line, that must all appear in argv in that
//!     order (an empty or absent file matches everything);
//!   - `stdout`, `stderr`: bytes written as they are (optional);
//!   - `exit`: the exit code (default 0);
//!   - `times`: how many more calls the rule answers; decremented on use,
//!     and a rule at 0 no longer matches (optional: unlimited);
//!   - `run`: a program, then one argument per line, run with this call's
//!     standard streams inherited; its exit code is the fake's (optional,
//!     after `stdout`/`stderr` are written). `{argv}` in an argument line
//!     expands to every argument after the matched words;
//! - with no matching rule, exits 0 and writes nothing.

use std::io::Write;
use std::path::{Path, PathBuf};

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn tool_name() -> String {
    let argv0 = std::env::args().next().unwrap_or_default();
    let name = Path::new(&argv0)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.strip_suffix(".exe").unwrap_or(&name).to_string()
}

/// The index just past the matched words, when every word appears in order.
fn matches(words: &[String], argv: &[String]) -> Option<usize> {
    let mut at = 0;
    for word in words {
        let found = argv[at..].iter().position(|a| a == word)?;
        at += found + 1;
    }
    Some(at)
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::to_string)
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn answer(rule: &Path, rest: &[String]) -> i32 {
    if let Ok(bytes) = std::fs::read(rule.join("stdout")) {
        let _ = std::io::stdout().write_all(&bytes);
    }
    if let Ok(bytes) = std::fs::read(rule.join("stderr")) {
        let _ = std::io::stderr().write_all(&bytes);
    }
    let _ = std::io::stdout().flush();
    let run = lines(&rule.join("run"));
    if let Some((program, arguments)) = run.split_first() {
        let mut expanded = Vec::new();
        for argument in arguments {
            if argument == "{argv}" {
                expanded.extend(rest.iter().cloned());
            } else {
                expanded.push(argument.clone());
            }
        }
        return match std::process::Command::new(program).args(&expanded).status() {
            Ok(status) => status.code().unwrap_or(1),
            Err(e) => {
                eprintln!("fake {}: cannot run {program}: {e}", tool_name());
                127
            }
        };
    }
    std::fs::read_to_string(rule.join("exit"))
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0)
}

fn main() {
    let tool = tool_name();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Ok(dir) = std::env::var("FAKE_TOOL_DIR") else {
        eprintln!("fake {tool}: FAKE_TOOL_DIR is not set");
        std::process::exit(127);
    };
    let dir = PathBuf::from(dir);
    let cwd = std::env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    let record = format!(
        "{{\"tool\":{},\"argv\":[{}],\"cwd\":{}}}\n",
        json_string(&tool),
        argv.iter()
            .map(|a| json_string(a))
            .collect::<Vec<_>>()
            .join(","),
        json_string(&cwd)
    );
    if let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("calls.ndjson"))
    {
        let _ = log.write_all(record.as_bytes());
    }
    let mut rules: Vec<PathBuf> = std::fs::read_dir(dir.join(&tool))
        .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    rules.sort();
    for rule in rules {
        if !rule.is_dir() {
            continue;
        }
        let times = rule.join("times");
        let left: Option<u64> = std::fs::read_to_string(&times)
            .ok()
            .and_then(|t| t.trim().parse().ok());
        if left == Some(0) {
            continue;
        }
        let Some(end) = matches(&lines(&rule.join("match")), &argv) else {
            continue;
        };
        if let Some(n) = left {
            let _ = std::fs::write(&times, (n - 1).to_string());
        }
        std::process::exit(answer(&rule, &argv[end..]));
    }
}
