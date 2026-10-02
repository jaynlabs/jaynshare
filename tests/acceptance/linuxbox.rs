//! `LinuxBox`: a throwaway `debian:13-slim` container, run as root, in
//! which the native-server tests run the real installer against the real
//! fixed paths (`/opt/jaynshare`, `/var/lib/jaynshare`,
//! `/usr/local/bin`, `/etc/systemd/system`), so the assertions can be strict
//! without a path seam in the product.
//!
//! - The musl `jaynshare` ([`crate::linux_fx::linux_binary`]) is mounted at
//!   [`BOX_BIN`]; a release built by [`LinuxBox::release`] carries the same
//!   bytes in its Linux platform archive.
//! - `tests/acceptance/fixtures/box/{systemctl,nft}` are on `PATH`
//!   (`/usr/local/sbin`). The fake `systemctl` records calls in
//!   `/run/fake-systemd/calls`, runs a started unit's real `ExecStart` as its
//!   `User=`, and takes one-shot failures from [`LinuxBox::fail`] (`load`,
//!   `start`, `health`, `manager`, or any verb). The fake `nft` answers
//!   `list ruleset` from [`LinuxBox::set_ruleset`].
//! - `/run/systemd/system` exists (systemd's own "booted" test), unless the
//!   box was started with [`LinuxBox::start_without_systemd`].
//! - The kernel clock is kept marked synchronized (the product's check reads
//!   it) by `fixtures/box/kernel-clock keep`, with the box's `CAP_SYS_TIME`.
//!   That state is one per Docker VM, so every box holds a share of
//!   [`KERNEL_CLOCK`] and [`LinuxBox::with_unsynchronized_clock`] waits until
//!   no box does.
//!
//! A test calls [`LinuxBox::start`], which returns `None` (and prints a skip
//! reason) when there is no Docker daemon. A failed musl build or a box
//! that will not start is a failure, not a skip.
#![allow(dead_code)] // the native-server tests call these

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Condvar, Mutex, MutexGuard};

use crate::linux_fx::{docker, docker_available, docker_platform, linux_binary};
use crate::release_fx::{ReleaseKey, with_platform_archive, write_release_of};

/// The installer binary inside the box (the musl build, read-only).
pub(crate) const BOX_BIN: &str = "/usr/local/lib/jaynshare-box/jaynshare";
/// The fake tools inside the box.
const BOX_TOOLS: &str = "/usr/local/lib/jaynshare-box/tools";
/// The base image.
const BOX_IMAGE: &str = "debian:13-slim";

/// The Docker VM's one kernel clock state, owned by the harness:
/// how many boxes rely on it synchronized, or `None` while a leg holds it
/// unsynchronized. A share is never refused for a waiting leg, so a scenario
/// holding two boxes cannot deadlock against one.
static KERNEL_CLOCK: Mutex<Option<usize>> = Mutex::new(Some(0));
static KERNEL_CLOCK_CHANGED: Condvar = Condvar::new();

fn kernel_clock_state() -> MutexGuard<'static, Option<usize>> {
    KERNEL_CLOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Blocks while `busy` holds for the clock state, then returns it locked.
fn kernel_clock_when(busy: fn(&mut Option<usize>) -> bool) -> MutexGuard<'static, Option<usize>> {
    KERNEL_CLOCK_CHANGED
        .wait_while(kernel_clock_state(), busy)
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One box's reliance on a synchronized kernel clock.
struct ClockShare;

impl ClockShare {
    fn acquire() -> ClockShare {
        let mut state = kernel_clock_when(|state| state.is_none());
        *state = state.map(|boxes| boxes + 1);
        ClockShare
    }
}

impl Drop for ClockShare {
    fn drop(&mut self) {
        let mut state = kernel_clock_state();
        *state = state.map(|boxes| boxes - 1);
        KERNEL_CLOCK_CHANGED.notify_all();
    }
}

/// The kernel clock's state held by one unsynchronized leg.
struct ClockExclusive;

impl ClockExclusive {
    fn acquire() -> ClockExclusive {
        let mut state = kernel_clock_when(|state| *state != Some(0));
        *state = None;
        ClockExclusive
    }
}

impl Drop for ClockExclusive {
    fn drop(&mut self) {
        *kernel_clock_state() = Some(0);
        KERNEL_CLOCK_CHANGED.notify_all();
    }
}

pub(crate) struct LinuxBox {
    /// The container's name (unique per scenario and process).
    pub(crate) name: String,
    /// The scenario's scratch root on the host.
    pub(crate) root: PathBuf,
    /// The Rust target of the box's architecture.
    pub(crate) target: &'static str,
    /// Held while the box relies on the kernel clock being synchronized.
    clock: Option<ClockShare>,
}

impl LinuxBox {
    /// A box with systemd "booted", or `None` when there is no Docker daemon.
    /// `name` identifies the test in container names and paths.
    pub(crate) fn start(name: &str) -> Option<LinuxBox> {
        Self::start_with(name, true, None)
    }

    /// The same without `/run/systemd/system`, so systemd is not PID 1.
    pub(crate) fn start_without_systemd(name: &str) -> Option<LinuxBox> {
        Self::start_with(name, false, None)
    }

    /// A box whose `port` is published on this machine's loopback, for a
    /// client here to reach a server in the box ([`LinuxBox::published`]).
    pub(crate) fn start_publishing(name: &str, port: u16) -> Option<LinuxBox> {
        Self::start_with(name, true, Some(port))
    }

    fn start_with(name: &str, systemd: bool, published: Option<u16>) -> Option<LinuxBox> {
        if !docker_available() {
            eprintln!("skipping: linux: no Docker daemon runs a container within 120 s");
            return None;
        }
        let binary = linux_binary().unwrap_or_else(|why| panic!("the musl binary: {why}"));
        let (platform, target) = docker_platform().expect("the Docker platform");
        let root = crate::harness::scratch(name);
        let container = format!("jaynshare-box-{name}-{}", std::process::id());
        let _ = docker(&["rm", "-f", &container]);
        let tools = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance/fixtures/box");
        // A real server host has a root bundle (`ca-certificates`); the slim
        // image has none, so the host's is lent read-only. Its real path: on
        // macOS `/etc` is a link to `/private/etc`, which only Docker
        // Desktop's API proxy would translate.
        let roots = ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"]
            .into_iter()
            .find_map(|path| {
                std::fs::canonicalize(path)
                    .ok()
                    .filter(|real| real.is_file())
            })
            .expect("a host root bundle to lend the box");
        let roots = format!("{}:/etc/ssl/certs/ca-certificates.crt:ro", roots.display());
        let publish = published.map(|port| format!("127.0.0.1::{port}"));
        let binary_mount = format!("{}:{BOX_BIN}:ro", binary.display());
        let tools_mount = format!("{}:{BOX_TOOLS}:ro", tools.display());
        let mut run = vec![
            "run",
            "-d",
            "--rm",
            // A reaping PID 1: a crashed service must disappear, not linger
            // as a zombie the fake systemctl would still see as running.
            "--init",
            "--name",
            &container,
            "--platform",
            platform,
            "--label",
            "jaynshare-acceptance=linuxbox",
            "--add-host",
            "host.docker.internal:host-gateway",
            "--cap-add",
            "SYS_TIME",
            "-v",
            &binary_mount,
            "-v",
            &tools_mount,
            "-v",
            &roots,
        ];
        if let Some(publish) = &publish {
            run.extend(["-p", publish]);
        }
        run.extend([BOX_IMAGE, "sleep", "infinity"]);
        let output = docker(&run).expect("docker run");
        assert!(
            output.status.success(),
            "the box would not start: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let linux = LinuxBox {
            name: container,
            root,
            target,
            clock: Some(ClockShare::acquire()),
        };
        let setup = format!(
            "set -e; mkdir -p /run/kernel-clock; {BOX_TOOLS}/kernel-clock synced >/dev/null; \
             nohup {BOX_TOOLS}/kernel-clock keep >/dev/null 2>&1 & \
             ln -sf {BOX_TOOLS}/systemctl /usr/local/sbin/systemctl; \
             ln -sf {BOX_TOOLS}/nft /usr/local/sbin/nft; \
             mkdir -p /etc/systemd/system /run/fake-systemd/fail /run/fake-nft; {}",
            if systemd {
                "mkdir -p /run/systemd/system"
            } else {
                "rm -rf /run/systemd/system"
            }
        );
        let (code, _, stderr) = linux.sh(&setup);
        assert_eq!(code, 0, "box setup: {stderr}");
        Some(linux)
    }

    /// The `host:port` on this machine's loopback that reaches the box's
    /// published `port`.
    pub(crate) fn published(&self, port: u16) -> String {
        let output = docker(&["port", &self.name, &format!("{port}/tcp")]).expect("docker port");
        assert!(
            output.status.success(),
            "docker port: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .expect("the published address")
            .to_owned()
    }

    /// `docker exec <box> <args>` as root, standard input `stdin`.
    pub(crate) fn exec_input(&self, args: &[&str], stdin: Option<&[u8]>) -> (i32, String, String) {
        let mut command = Command::new("docker");
        command.arg("exec");
        if stdin.is_some() {
            command.arg("-i");
        }
        command
            .arg(&self.name)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("docker exec");
        if let Some(bytes) = stdin {
            let mut pipe = child.stdin.take().expect("stdin");
            pipe.write_all(bytes).expect("write stdin");
        }
        let output = child.wait_with_output().expect("docker exec output");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// `docker exec <box> <args>` as root.
    pub(crate) fn exec(&self, args: &[&str]) -> (i32, String, String) {
        self.exec_input(args, None)
    }

    /// `sh -c <script>` as root.
    pub(crate) fn sh(&self, script: &str) -> (i32, String, String) {
        self.exec(&["sh", "-c", script])
    }

    /// The installer: `jaynshare <args>` as root, from [`BOX_BIN`].
    pub(crate) fn cli(&self, args: &[&str]) -> (i32, String, String) {
        let mut full = vec![BOX_BIN];
        full.extend_from_slice(args);
        self.exec(&full)
    }

    /// Writes `bytes` at `path` (parents created) with `mode`, owned by root.
    pub(crate) fn write(&self, path: &str, bytes: &[u8], mode: u32) {
        let script = format!(
            "set -e; mkdir -p \"$(dirname '{path}')\"; cat > '{path}'; chmod {mode:o} '{path}'"
        );
        let (code, _, stderr) = self.exec_input(&["sh", "-c", &script], Some(bytes));
        assert_eq!(code, 0, "write {path}: {stderr}");
    }

    /// The bytes at `path`, `None` when it does not exist.
    pub(crate) fn read(&self, path: &str) -> Option<Vec<u8>> {
        let output = docker(&["exec", &self.name, "cat", path]).expect("docker exec cat");
        output.status.success().then_some(output.stdout)
    }

    /// `path` exists (a file, directory or link).
    pub(crate) fn exists(&self, path: &str) -> bool {
        self.exec(&["test", "-e", path]).0 == 0 || self.exec(&["test", "-L", path]).0 == 0
    }

    /// Copies the host path `from` to `to` in the box (`docker cp`), owned by
    /// root as an operator's download would be (`docker cp` keeps host ids).
    pub(crate) fn put(&self, from: &Path, to: &str) {
        let output = docker(&[
            "cp",
            &from.display().to_string(),
            &format!("{}:{to}", self.name),
        ])
        .expect("docker cp");
        assert!(
            output.status.success(),
            "docker cp {}: {}",
            from.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let (code, _, stderr) = self.exec(&["chown", "-R", "root:root", to]);
        assert_eq!(code, 0, "chown {to}: {stderr}");
    }

    /// One digest over every regular file below `path` (names, modes, owners
    /// and bytes), for "configuration and state unchanged byte-for-byte".
    pub(crate) fn tree_digest(&self, path: &str) -> String {
        let script = format!(
            "cd '{path}' 2>/dev/null || {{ echo absent; exit 0; }}; \
             find . -type f -print0 | sort -z | xargs -0 -r stat -c '%n %a %U:%G' ; \
             find . -type f -print0 | sort -z | xargs -0 -r sha256sum"
        );
        let (code, stdout, stderr) = self.sh(&script);
        assert_eq!(code, 0, "tree digest {path}: {stderr}");
        crate::release_fx::sha256_hex(stdout.as_bytes())
    }

    /// Makes the fake `systemctl`'s next `step` fail (`load`, `start`,
    /// `health`, `manager` — persistent — or any verb).
    pub(crate) fn fail(&self, step: &str) {
        let (code, _, stderr) = self.sh(&format!("touch /run/fake-systemd/fail/{step}"));
        assert_eq!(code, 0, "fail {step}: {stderr}");
    }

    /// Every fake `systemctl` call so far, one argv line each.
    pub(crate) fn systemctl_calls(&self) -> Vec<String> {
        self.read("/run/fake-systemd/calls")
            .map(|bytes| {
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The fake `nft`'s `list ruleset` answer (`nft -j` JSON).
    pub(crate) fn set_ruleset(&self, json: &str) {
        self.write("/run/fake-nft/ruleset.json", json.as_bytes(), 0o644);
    }

    /// What the running unit wrote to standard output and error (the fake's
    /// journal).
    pub(crate) fn journal(&self) -> String {
        self.read("/run/fake-systemd/journal-jaynshare.service")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    }

    /// A signed release of `version` (by `key`) whose Linux platform archive
    /// for this box's architecture holds the musl binary, copied into the box
    /// at `/releases/<version>`; returns that path.
    pub(crate) fn release(&self, key: &ReleaseKey, version: &str) -> String {
        let binary = std::fs::read(linux_binary().expect("the musl binary")).expect("read it");
        let host = self.root.join(format!("release-{version}"));
        let _ = std::fs::remove_dir_all(&host);
        write_release_of(
            &host,
            key,
            version,
            |parts| with_platform_archive(parts, self.target, &binary),
            |_| {},
        );
        let (code, _, stderr) = self.sh("mkdir -p /releases");
        assert_eq!(code, 0, "{stderr}");
        let inside = format!("/releases/{version}");
        self.put(&host, &inside);
        inside
    }

    /// Plants `key` as the active release key for root (`release.pub` under
    /// root's configuration directory), inside the box.
    pub(crate) fn plant_key(&self, key: &ReleaseKey) {
        self.write(
            "/root/.config/jaynshare/release.pub",
            &key.public_file(),
            0o600,
        );
    }
}

impl LinuxBox {
    /// Runs `leg` with the kernel clock marked unsynchronized, then marks it
    /// synchronized again. It waits until no other box relies on the clock.
    pub(crate) fn with_unsynchronized_clock<T>(&mut self, leg: impl FnOnce(&LinuxBox) -> T) -> T {
        drop(self.clock.take());
        let outcome = {
            let _exclusive = ClockExclusive::acquire();
            let _resync = Resync(self);
            let (code, _, stderr) = self.sh(&format!(
                "touch /run/kernel-clock/paused && {BOX_TOOLS}/kernel-clock unsynced"
            ));
            assert_eq!(code, 0, "kernel-clock unsynced: {stderr}");
            leg(self)
        };
        self.clock = Some(ClockShare::acquire());
        outcome
    }
}

/// Marks the kernel clock synchronized again when dropped, a failed leg too.
struct Resync<'a>(&'a LinuxBox);

impl Drop for Resync<'_> {
    fn drop(&mut self) {
        let _ = self.0.sh(&format!(
            "rm -f /run/kernel-clock/paused; {BOX_TOOLS}/kernel-clock synced"
        ));
    }
}

impl Drop for LinuxBox {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.name]);
    }
}
