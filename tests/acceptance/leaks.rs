//! Credential-leak protection and the negative-control helper.
//!
//! The harness mints secrets as it goes; every mint is registered here as a
//! needle. A [`LeakGuard`] is alive for the length of each test body; the
//! last one to drop sweeps every file the run wrote under `target/acceptance`
//! for every needle in every encoding, and fails the run on a hit. Secrets
//! belong in the surfaces the product legitimately writes (a state file, a
//! client credentials file, a wire capture) and in input fixtures the suite
//! itself planted — nowhere else the run touches.

#![allow(clippy::items_after_test_module)]

use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

/// Guards alive right now: the last one to drop runs the leak sweep, because
/// only then has every test body ended and the run's file tree settled.
static LIVE: AtomicUsize = AtomicUsize::new(0);

fn run_start() -> std::time::SystemTime {
    static START: std::sync::OnceLock<std::time::SystemTime> = std::sync::OnceLock::new();
    *START.get_or_init(std::time::SystemTime::now)
}

fn written_by_this_run(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_or(true, |modified| modified >= run_start())
}

/// Every needle the suite has generated, as `(role, value)`; the sweep
/// searches every surface for all of them. Values come from the harness's
/// fixture generators, which register as they mint.
fn needles() -> &'static Mutex<Vec<(String, String)>> {
    static NEEDLES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    &NEEDLES
}

/// Registers a needle the harness minted: `role` names the secret's role,
/// `value` the per-run random value itself.
pub(crate) fn register_needle(role: &str, value: &str) {
    let mut needles = needles().lock().unwrap_or_else(|e| e.into_inner());
    needles.push((role.to_owned(), value.to_owned()));
}

/// Paths the harness wrote as scenario input fixtures — an imported portable
/// file, a hand-written configuration, a planted key. The sweep judges the
/// surfaces the binary wrote; an input the suite supplied is not one, and the
/// needle it carries is the delivery of the credential, not a leak.
fn planted() -> &'static Mutex<Vec<PathBuf>> {
    static PLANTED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    &PLANTED
}

pub(crate) fn register_planted(path: &Path) {
    planted()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(path.to_path_buf());
}

/// The constant fixture secrets the fake minted before the registry existed
/// or that live in the suite as literals.
static FIXED_NEEDLES: &[(&str, &str)] = &[
    ("login access token", crate::harness::FIXTURE_LOGIN_ACCESS),
    ("login refresh token", crate::harness::FIXTURE_LOGIN_REFRESH),
    (
        "probe rotated access token",
        "sk-ant-oat-fixture-probe-rotated",
    ),
    (
        "probe rotated refresh token",
        "sk-ant-ort-fixture-probe-rotated",
    ),
    ("config edit needle", "sk-ant-needle-config-path"),
];

/// Held for the length of one test body; the last guard to drop sweeps the
/// run's whole file tree for leaked credentials.
pub(crate) struct LeakGuard {
    _private: (),
}

impl LeakGuard {
    pub(crate) fn new() -> Self {
        run_start();
        LIVE.fetch_add(1, Ordering::Relaxed);
        LeakGuard { _private: () }
    }
}

impl Default for LeakGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LeakGuard {
    fn drop(&mut self) {
        if LIVE.fetch_sub(1, Ordering::Relaxed) == 1 {
            let hits = leak_sweep();
            if !hits.is_empty() {
                let message = format!("credentials leaked into run outputs: {hits:?}");
                // During an unwind the panic would abort the process; the
                // test that failed already fails the run.
                if !std::thread::panicking() {
                    panic!("{message}");
                }
                eprintln!("{message}");
            }
        }
    }
}

/// Sweeps every file under `target/acceptance` for every registered needle in
/// every encoding. Allowed surfaces: a server state file, the client
/// credentials file, and a wire-capture directory — the places a credential
/// legitimately lives.
fn leak_sweep() -> Vec<serde_json::Value> {
    let mut values: Vec<(String, String)> = needles()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect();
    values.extend(
        FIXED_NEEDLES
            .iter()
            .map(|(role, value)| ((*role).to_owned(), (*value).to_owned())),
    );
    let mut hits = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/acceptance");
    sweep_tree(&root, &needle_forms(&values), &mut hits);
    hits
}

struct NeedleForm {
    role: String,
    index: usize,
    value: String,
}

fn needle_forms(needles: &[(String, String)]) -> BTreeMap<String, Vec<NeedleForm>> {
    let mut groups: BTreeMap<String, Vec<NeedleForm>> = BTreeMap::new();
    for (role, value) in needles {
        let forms = crate::harness::encodings(value);
        for (index, value) in forms.iter().enumerate() {
            if forms[..index].contains(value) {
                continue;
            }
            let prefix_end = value.char_indices().nth(3).map_or(value.len(), |(i, _)| i);
            groups
                .entry(value[..prefix_end].to_owned())
                .or_default()
                .push(NeedleForm {
                    role: role.clone(),
                    index,
                    value: value.clone(),
                });
        }
    }
    groups
}

fn sweep_tree(
    directory: &Path,
    needles: &BTreeMap<String, Vec<NeedleForm>>,
    hits: &mut Vec<serde_json::Value>,
) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sweep_tree(&path, needles, hits);
        } else if !allowed_surface(&path)
            && written_by_this_run(&path)
            && !planted()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|p| p == &path)
            && let Ok(bytes) = fs::read(&path)
        {
            let contents = String::from_utf8_lossy(&bytes);
            // ponytail: comparisons scale with prefix hits; use Aho-Corasick for dense matches.
            for (prefix, forms) in needles {
                let mut pending: Vec<_> = forms.iter().collect();
                let mut remaining = contents.as_ref();
                while let Some(relative) = remaining.find(prefix.as_str()) {
                    let tail = &remaining[relative..];
                    let offset = contents.len() - tail.len();
                    pending.retain(|form| {
                        if !tail.starts_with(&form.value) {
                            return true;
                        }
                        hits.push(json!({
                            "needle_role": form.role,
                            "needle_form": form.index,
                            "surface": path.display().to_string(),
                            "offset": offset,
                        }));
                        false
                    });
                    if pending.is_empty() {
                        break;
                    }
                    let Some(first) = tail.chars().next() else {
                        break;
                    };
                    // Advance one character so overlapping prefixes are still found.
                    remaining = &tail[first.len_utf8()..];
                }
            }
        }
    }
}

fn allowed_surface(path: &Path) -> bool {
    path.ends_with("state/state.json")
        || path.ends_with("home/.claude/.credentials.json")
        || path
            .ancestors()
            .any(|ancestor| ancestor.file_name() == Some("cap".as_ref()))
}

/// Runs a body that must fail: a sabotage removes the behaviour it asserts,
/// and the control passes only when the body does fail. The panic the body
/// raises is expected; its print in the test output is the control's
/// evidence, not a failure.
pub(crate) async fn negative_control(body: impl Future<Output = ()> + Send + 'static) {
    match tokio::spawn(body).await {
        Err(joined) if joined.is_panic() => {}
        other => panic!(
            "the negative control must fail when the behaviour it asserts is removed: {other:?}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_needle_in_an_unallowed_surface_is_a_hit_and_an_allowed_one_is_not() {
        // The sweep only reads files written since the run started.
        run_start();
        let dir = std::env::temp_dir().join(format!("leak-sweep-test-{}", std::process::id()));
        fs::create_dir_all(dir.join("state")).expect("create the tree");
        fs::write(dir.join("log.txt"), "token sk-ant-oat-leak-test here").expect("write");
        fs::write(
            dir.join("state/state.json"),
            "token sk-ant-oat-leak-test here",
        )
        .expect("write the allowed surface");
        let needles = vec![("test token".to_owned(), "sk-ant-oat-leak-test".to_owned())];
        let mut hits = Vec::new();
        sweep_tree(&dir, &needle_forms(&needles), &mut hits);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            hits[0]["surface"],
            dir.join("log.txt").display().to_string()
        );
    }

    #[test]
    fn grouped_search_matches_individual_searches() {
        run_start();
        let dir = std::env::temp_dir().join(format!(
            "leak-prefix-test-{}",
            crate::harness::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("create the tree");
        let path = dir.join("output.bin");
        let contents = "\0é中d aaaaaab ababab xy sk-ant-oat-secret sk%2Dant%2Doat%2Dsecret";
        fs::write(&path, contents).expect("write the output");
        let needles: Vec<_> = [
            "",
            "x",
            "xy",
            "aaaaa",
            "aaaab",
            "aba",
            "ababa",
            "é中d",
            "missing",
            "sk-ant-oat-secret",
            "sk-ant-oat-other",
        ]
        .iter()
        .map(|value| (format!("role:{value}"), (*value).to_owned()))
        .collect();
        let mut expected = Vec::new();
        for (role, value) in &needles {
            let forms = crate::harness::encodings(value);
            for (index, form) in forms.iter().enumerate() {
                if !forms[..index].contains(form)
                    && let Some(offset) = contents.find(form.as_str())
                {
                    expected.push(json!({
                        "needle_role": role,
                        "needle_form": index,
                        "surface": path.display().to_string(),
                        "offset": offset,
                    }));
                }
            }
        }
        let mut hits = Vec::new();
        sweep_tree(&dir, &needle_forms(&needles), &mut hits);
        fs::remove_dir_all(&dir).expect("remove the test tree");
        hits.sort_by_key(serde_json::Value::to_string);
        expected.sort_by_key(serde_json::Value::to_string);
        assert_eq!(hits, expected);
    }

    #[test]
    fn the_allowed_surfaces_are_exactly_the_legitimate_ones() {
        let root = Path::new("/run/target/acceptance/acc-credentials");
        assert!(allowed_surface(&root.join("state/state.json")));
        assert!(allowed_surface(
            &root.join("home/.claude/.credentials.json")
        ));
        assert!(allowed_surface(&root.join("cap/exchange-1.bin")));
        assert!(!allowed_surface(&root.join("log/server.ndjson")));
        assert!(!allowed_surface(&root.join("stdout.txt")));
        assert!(!allowed_surface(&root.join("portable.json")));
    }
}
