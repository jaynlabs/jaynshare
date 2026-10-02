//! The Linux release binary for the tests that run the product inside a
//! container: built once per suite run in `rust:1.95-alpine` for the Docker
//! VM's own architecture (`aarch64-unknown-linux-musl` on Apple silicon),
//! with its own target directory `target/linux-musl`, or taken as given from
//! `JAYNSHARE_LINUX_BIN` (e.g. `tools/release/cross.sh`'s output).
//!
//! A test that needs it calls [`docker_available`] first and skips
//! explicitly when there is no daemon; a failed build is a failure.
#![allow(dead_code)] // the real-Docker tests and LinuxBox call these

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// `docker <args>` with standard input closed; `Err` when it cannot start.
pub(crate) fn docker(args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("docker: {e}"))
}

/// A Docker daemon that runs a container: `docker info` answers within 20
/// seconds and `docker run --rm alpine:3 true` exits 0 within 120 (a daemon
/// that answers but never starts a container is as absent as none). Asked
/// once per suite run.
pub(crate) fn docker_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        within(&["info", "--format", "{{.ServerVersion}}"], 20)
            && within(&["run", "--rm", "alpine:3", "true"], 120)
    })
}

/// `docker <args>` exits 0 within `seconds`; killed and `false` otherwise.
fn within(args: &[&str], seconds: u64) -> bool {
    let Ok(mut child) = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// The daemon's platform and the matching musl target:
/// `("linux/arm64", "aarch64-unknown-linux-musl")` or the amd64 pair.
pub(crate) fn docker_platform() -> Result<(&'static str, &'static str), String> {
    let output = docker(&["info", "--format", "{{.Architecture}}"])?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "aarch64" | "arm64" => Ok(("linux/arm64", "aarch64-unknown-linux-musl")),
        "x86_64" | "amd64" => Ok(("linux/amd64", "x86_64-unknown-linux-musl")),
        other => Err(format!("docker info: unsupported architecture {other:?}")),
    }
}

/// The repository root (the acceptance crate is the product crate).
fn repository() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The commit the binary reports: this checkout's `HEAD`, since the
/// build container has no `git`.
pub(crate) fn head_commit() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "0".repeat(40))
}

/// The musl `jaynshare` for the daemon's architecture: `JAYNSHARE_LINUX_BIN`
/// when set, else built once per suite run (incremental across runs; the
/// crate registry is the named volume `jaynshare-acceptance-cargo`).
pub(crate) fn linux_binary() -> Result<PathBuf, String> {
    static BINARY: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            if let Some(given) = std::env::var_os("JAYNSHARE_LINUX_BIN") {
                let given = PathBuf::from(given);
                return if given.is_file() {
                    given.canonicalize().map_err(|error| {
                        format!("JAYNSHARE_LINUX_BIN: {}: {error}", given.display())
                    })
                } else {
                    Err(format!("JAYNSHARE_LINUX_BIN: {} is not a file", given.display()))
                };
            }
            let (platform, target) = docker_platform()?;
            let target_dir = repository().join("target").join("linux-musl");
            std::fs::create_dir_all(&target_dir)
                .map_err(|e| format!("{}: {e}", target_dir.display()))?;
            let build = format!(
                "apk add --no-cache musl-dev >/dev/null && \
                 cargo build --release --locked --target {target} --target-dir /target --bin jaynshare"
            );
            let output = docker(&[
                "run",
                "--rm",
                "--platform",
                platform,
                "-v",
                &format!("{}:/src:ro", repository().display()),
                "-v",
                &format!("{}:/target", target_dir.display()),
                "-v",
                "jaynshare-acceptance-cargo:/usr/local/cargo/registry",
                "-e",
                &format!("JAYNSHARE_COMMIT={}", head_commit()),
                "-e",
                "CARGO_TERM_COLOR=never",
                "-w",
                "/src",
                "rust:1.95-alpine",
                "sh",
                "-c",
                &build,
            ])?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
                return Err(format!(
                    "the musl build failed ({}):\n{}",
                    output.status,
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                ));
            }
            let binary = target_dir.join(target).join("release").join("jaynshare");
            if binary.is_file() {
                Ok(binary)
            } else {
                Err(format!("the musl build wrote no {}", binary.display()))
            }
        })
        .clone()
}
