//! The one-command native install: with no configuration given it writes
//! one, running it again updates, and a clone's build installs with its
//! client kit. Each runs the real installer as root inside a `LinuxBox`
//! (see `linuxbox`), which skips explicitly without a Docker daemon.

use crate::linuxbox::{BOX_BIN, LinuxBox};
use crate::release_fx::{FIXTURE_VERSION, ReleaseKey};

const SERVICE_CFG: &str = "/var/lib/jaynshare/.config/jaynshare/config.toml";

/// An input chain that drops what no rule admits, so every private
/// listener passes the firewall check.
const DROP_INPUT: &str = r#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}}]}"#;

/// The box's address on its bridge: the only private one it carries.
fn box_ip(linux: &LinuxBox) -> String {
    let (code, ip, stderr) = linux.sh("hostname -i");
    assert_eq!(code, 0, "hostname: {stderr}");
    ip.split_whitespace()
        .next()
        .expect("the bridge address")
        .to_owned()
}

fn current(linux: &LinuxBox) -> String {
    let (code, link, stderr) = linux.sh("readlink /opt/jaynshare/current");
    assert_eq!(code, 0, "readlink: {stderr}");
    link.trim().to_owned()
}

fn owner_and_mode(linux: &LinuxBox, path: &str) -> String {
    let (code, stat, stderr) = linux.sh(&format!("stat -c '%U %a' '{path}'"));
    assert_eq!(code, 0, "stat {path}: {stderr}");
    stat.trim().to_owned()
}

/// `server install` with no `--config` writes a configuration on the box's
/// only private address and stores the release's client kit; running it
/// again with a newer release updates and keeps the configuration; a lower
/// release and a `--listen` beside an installed configuration are refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_box_installs_with_one_command_and_running_it_again_updates() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(linux) = LinuxBox::start("one-command-install") else {
        return;
    };
    let key = ReleaseKey::generate();
    linux.plant_key(&key);
    let v070 = linux.release(&key, FIXTURE_VERSION);
    let v071 = linux.release(&key, "0.7.1-acceptance");
    linux.set_ruleset(DROP_INPUT);
    let ip = box_ip(&linux);

    let (code, stdout, stderr) = linux.cli(&["server", "install", "--from", &v070]);
    assert_eq!(code, 0, "install: {stdout}\n{stderr}");
    let config = String::from_utf8(linux.read(SERVICE_CFG).expect("the written configuration"))
        .expect("UTF-8");
    assert!(
        config.contains(&format!("listen = \"{ip}:17421\"")),
        "{config}"
    );
    assert_eq!(owner_and_mode(&linux, SERVICE_CFG), "jaynshare 600");
    let (code, _, stderr) = linux.cli(&["--config", SERVICE_CFG, "status", "--check"]);
    assert_eq!(code, 0, "status: {stderr}");

    let kit = format!("/opt/jaynshare/releases/{FIXTURE_VERSION}/client-kit.zip");
    assert_eq!(
        linux.read(&kit).expect("the stored kit"),
        linux
            .read(&format!(
                "{v070}/jaynshare-{FIXTURE_VERSION}-client-kit.zip"
            ))
            .expect("the release's kit"),
    );
    assert_eq!(owner_and_mode(&linux, &kit), "root 644");

    let config_digest = linux.tree_digest("/var/lib/jaynshare/.config");
    let (code, stdout, stderr) = linux.cli(&["server", "install", "--from", &v071]);
    assert_eq!(code, 0, "install again: {stdout}\n{stderr}");
    assert_eq!(current(&linux), "/opt/jaynshare/releases/0.7.1-acceptance");
    assert_eq!(
        config_digest,
        linux.tree_digest("/var/lib/jaynshare/.config")
    );
    let (code, _, stderr) = linux.cli(&["--config", SERVICE_CFG, "status", "--check"]);
    assert_eq!(code, 0, "status after the update: {stderr}");

    let opt_digest = linux.tree_digest("/opt/jaynshare");
    let (code, stdout, stderr) = linux.cli(&["server", "install", "--from", &v070]);
    assert_eq!(code, 8, "downgrade: {stdout}\n{stderr}");
    assert!(stderr.contains("conflict.downgrade"), "{stderr}");
    let (code, stdout, stderr) =
        linux.cli(&["server", "install", "--from", &v071, "--listen", "10.1.2.3"]);
    assert_eq!(code, 3, "--listen over a configuration: {stdout}\n{stderr}");
    assert!(stderr.contains("configuration.listen"), "{stderr}");
    assert_eq!(opt_digest, linux.tree_digest("/opt/jaynshare"));
    assert_eq!(
        config_digest,
        linux.tree_digest("/var/lib/jaynshare/.config")
    );
}

/// `server install --binary` stages the build and its kit in a version
/// directory named by the build's version and digest, and records the build
/// for `server update`; a kit signed by another key is refused before
/// anything is written.
#[tokio::test(flavor = "multi_thread")]
async fn a_clone_build_installs_with_its_client_kit() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(linux) = LinuxBox::start("clone-build-install") else {
        return;
    };
    let key = ReleaseKey::generate();
    linux.plant_key(&key);
    linux.set_ruleset(DROP_INPUT);
    let good = crate::enrol::good_kit(&linux.root, &key.pkcs8, &key.public);
    linux.put(&good, "/root/client-kit.zip");
    let other = ReleaseKey::generate();
    let foreign_dir = linux.root.join("foreign");
    std::fs::create_dir_all(&foreign_dir).expect("foreign kit directory");
    let foreign = crate::enrol::good_kit(&foreign_dir, &other.pkcs8, &other.public);
    linux.put(&foreign, "/root/foreign-kit.zip");

    let (code, stdout, stderr) = linux.cli(&[
        "server",
        "install",
        "--binary",
        BOX_BIN,
        "--kit",
        "/root/foreign-kit.zip",
    ]);
    assert_eq!(code, 17, "a foreign kit: {stdout}\n{stderr}");
    assert!(stderr.contains("release.kit"), "{stderr}");
    assert!(!linux.exists("/opt/jaynshare"), "nothing was staged");

    let (code, stdout, stderr) = linux.cli(&[
        "server",
        "install",
        "--binary",
        BOX_BIN,
        "--kit",
        "/root/client-kit.zip",
    ]);
    assert_eq!(code, 0, "install the build: {stdout}\n{stderr}");
    let (code, digest, stderr) = linux.sh(&format!("sha256sum {BOX_BIN}"));
    assert_eq!(code, 0, "sha256sum: {stderr}");
    let dir = format!(
        "/opt/jaynshare/releases/{}+local.{}",
        env!("CARGO_PKG_VERSION"),
        &digest[..12]
    );
    assert_eq!(current(&linux), dir);
    let (code, listing, stderr) = linux.sh(&format!("ls -1 '{dir}'"));
    assert_eq!(code, 0, "listing: {stderr}");
    assert_eq!(
        listing.lines().collect::<Vec<_>>(),
        ["client-kit.zip", "jaynshare"]
    );
    assert_eq!(
        linux.read(&format!("{dir}/client-kit.zip")),
        Some(std::fs::read(&good).expect("the kit"))
    );
    assert_eq!(
        owner_and_mode(&linux, &format!("{dir}/jaynshare")),
        "root 755"
    );
    assert_eq!(
        linux.read("/opt/jaynshare/origin.json"),
        Some(format!(r#"{{"build":"{BOX_BIN}"}}"#).into_bytes())
    );
    let (code, _, stderr) = linux.cli(&["--config", SERVICE_CFG, "status", "--check"]);
    assert_eq!(code, 0, "status: {stderr}");
}
