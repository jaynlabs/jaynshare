//! `server auto-update on|off`: a nightly timer over `server update --yes`,
//! for release installs only, removed with the install. Each runs the real
//! installer as root inside a `LinuxBox`, which skips without Docker.

use crate::linuxbox::{BOX_BIN, LinuxBox};
use crate::release_fx::{FIXTURE_VERSION, ReleaseKey};

const TIMER: &str = "/etc/systemd/system/jaynshare-update.timer";
const SERVICE: &str = "/etc/systemd/system/jaynshare-update.service";

/// An input chain that drops what no rule admits, so every private
/// listener passes the firewall check.
const DROP_INPUT: &str = r#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}}]}"#;

fn systemctl(linux: &LinuxBox, args: &str) -> (i32, String) {
    let (code, stdout, stderr) = linux.sh(&format!("systemctl {args}"));
    (code, format!("{stdout}{stderr}"))
}

fn installed(linux: &LinuxBox) -> String {
    let (code, link, stderr) = linux.sh("readlink /opt/jaynshare/current");
    assert_eq!(code, 0, "readlink: {stderr}");
    link.trim().to_owned()
}

fn release_box(name: &str) -> Option<(LinuxBox, ReleaseKey)> {
    let linux = LinuxBox::start(name)?;
    let key = ReleaseKey::generate();
    linux.plant_key(&key);
    linux.set_ruleset(DROP_INPUT);
    Some((linux, key))
}

/// Refused before an install; once on, the timer is enabled and running, its
/// service runs the installed `server update --yes` against the recorded
/// origin, a clone build is refused, and `off` and `server uninstall` both
/// remove it.
#[tokio::test(flavor = "multi_thread")]
async fn the_timer_updates_a_release_install_and_leaves_with_it() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some((linux, key)) = release_box("auto-update") else {
        return;
    };
    let release = linux.release(&key, FIXTURE_VERSION);

    let (code, stdout, stderr) = linux.cli(&["server", "auto-update", "on"]);
    assert_eq!(code, 8, "before an install: {stdout}\n{stderr}");
    assert!(stderr.contains("conflict.install"), "{stderr}");
    assert!(!linux.exists(TIMER) && !linux.exists(SERVICE));

    let (code, stdout, stderr) = linux.cli(&["server", "install", "--from", &release]);
    assert_eq!(code, 0, "install: {stdout}\n{stderr}");
    for _ in 0..2 {
        let (code, stdout, stderr) = linux.cli(&["server", "auto-update", "on"]);
        assert_eq!(code, 0, "on: {stdout}\n{stderr}");
        assert!(
            stdout.contains("updates nightly to the newest official release"),
            "{stdout}"
        );
    }
    let service = String::from_utf8(linux.read(SERVICE).expect("the service")).expect("UTF-8");
    assert!(
        service
            .lines()
            .any(|line| line == "ExecStart=/opt/jaynshare/current/jaynshare server update --yes"),
        "{service}"
    );
    let (code, stat, stderr) = linux.sh(&format!("stat -c '%U %a' {TIMER} {SERVICE}"));
    assert_eq!(code, 0, "stat: {stderr}");
    assert_eq!(stat, "root 644\nroot 644\n");
    assert_eq!(
        systemctl(&linux, "is-enabled jaynshare-update.timer"),
        (0, "enabled\n".to_owned())
    );
    assert_eq!(
        systemctl(&linux, "is-active jaynshare-update.timer"),
        (0, "active\n".to_owned())
    );

    // A night's run: unattended, it follows the recorded origin, and a
    // failed update leaves the server as it was.
    linux.write(
        "/opt/jaynshare/origin.json",
        br#"{"mirror":"https://127.0.0.1:9"}"#,
        0o644,
    );
    let (code, output) = systemctl(&linux, "start jaynshare-update.service");
    assert_ne!(code, 0, "an unreachable origin fails the run: {output}");
    let journal = String::from_utf8(
        linux
            .read("/run/fake-systemd/journal-jaynshare-update.service")
            .expect("the run's journal"),
    )
    .expect("UTF-8");
    assert!(
        journal.contains("release.unreachable") && journal.contains("https://127.0.0.1:9/latest"),
        "{journal}"
    );
    assert_eq!(
        installed(&linux),
        format!("/opt/jaynshare/releases/{FIXTURE_VERSION}")
    );
    assert_eq!(systemctl(&linux, "is-active jaynshare.service").0, 0);

    let opt_digest = linux.tree_digest("/opt/jaynshare");
    let (code, stdout, stderr) = linux.cli(&["server", "install", "--binary", BOX_BIN]);
    assert_eq!(code, 8, "a build while on: {stdout}\n{stderr}");
    assert!(stderr.contains("conflict.auto_update"), "{stderr}");
    assert_eq!(opt_digest, linux.tree_digest("/opt/jaynshare"));

    for _ in 0..2 {
        let (code, stdout, stderr) = linux.cli(&["server", "auto-update", "off"]);
        assert_eq!(code, 0, "off: {stdout}\n{stderr}");
    }
    assert!(!linux.exists(TIMER) && !linux.exists(SERVICE));
    assert_ne!(systemctl(&linux, "is-enabled jaynshare-update.timer").0, 0);
    assert_ne!(systemctl(&linux, "is-active jaynshare-update.timer").0, 0);

    let (code, stdout, stderr) = linux.cli(&["server", "auto-update", "on"]);
    assert_eq!(code, 0, "on again: {stdout}\n{stderr}");
    let (code, stdout, stderr) = linux.cli(&["server", "uninstall"]);
    assert_eq!(code, 0, "uninstall: {stdout}\n{stderr}");
    assert!(!linux.exists(TIMER) && !linux.exists(SERVICE));
    assert_ne!(systemctl(&linux, "is-enabled jaynshare-update.timer").0, 0);
}

/// A clone's build updates by rebuilding, so its install is refused a timer
/// and nothing is written.
#[tokio::test(flavor = "multi_thread")]
async fn a_clone_build_is_refused_the_timer() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some((linux, key)) = release_box("auto-update-build") else {
        return;
    };
    let kit = crate::enrol::good_kit(&linux.root, &key.pkcs8, &key.public);
    linux.put(&kit, "/root/client-kit.zip");
    let (code, stdout, stderr) = linux.cli(&[
        "server",
        "install",
        "--binary",
        BOX_BIN,
        "--kit",
        "/root/client-kit.zip",
    ]);
    assert_eq!(code, 0, "install the build: {stdout}\n{stderr}");

    let (code, stdout, stderr) = linux.cli(&["server", "auto-update", "on"]);
    assert_eq!(code, 8, "on: {stdout}\n{stderr}");
    assert!(
        stderr.contains("conflict.origin") && stderr.contains(BOX_BIN),
        "{stderr}"
    );
    assert!(!linux.exists(TIMER) && !linux.exists(SERVICE));
}

/// The nightly run has no terminal to record a manual firewall check on, so
/// an update passes a firewall it cannot inspect, where an unattended install
/// refuses; a firewall admitting a public interface still refuses both.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_passes_a_firewall_it_cannot_inspect() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some((linux, key)) = release_box("auto-update-firewall") else {
        return;
    };
    let v070 = linux.release(&key, FIXTURE_VERSION);
    let v071 = linux.release(&key, "0.7.1-acceptance");
    let (code, stdout, stderr) = linux.cli(&["server", "install", "--from", &v070]);
    assert_eq!(code, 0, "install: {stdout}\n{stderr}");

    linux.set_ruleset(r#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"accept"}}]}"#);
    let (code, stdout, stderr) = linux.cli(&["server", "update", "--from", &v071, "--yes"]);
    assert_eq!(code, 18, "a public firewall: {stdout}\n{stderr}");
    assert!(stderr.contains("preflight.firewall.data_plane"), "{stderr}");

    // What tailscaled's iptables-nft rules look like to preflight.
    linux.set_ruleset(
        r#"{"nftables":[
            {"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input","policy":"drop"}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":3,"expr":[{"jump":{"target":"ts-input"}}]}}]}"#,
    );
    let (code, stdout, stderr) = linux.cli(&["server", "install", "--from", &v071]);
    assert_eq!(code, 18, "an unattended install: {stdout}\n{stderr}");
    assert!(stderr.contains("unresolved manual check"), "{stderr}");
    let (code, stdout, stderr) = linux.cli(&["server", "update", "--from", &v071, "--yes"]);
    assert_eq!(code, 0, "the update: {stdout}\n{stderr}");
    assert!(
        stdout.contains("an update keeps the installed configuration"),
        "{stdout}"
    );
    assert_eq!(
        installed(&linux),
        "/opt/jaynshare/releases/0.7.1-acceptance"
    );
}
