//! The one-command native install: with no configuration given it writes
//! one, a fresh install ends with an invite, running it again updates, and a
//! clone's build installs with its client kit. Each runs the real installer
//! as root inside a `LinuxBox` (see `linuxbox`), which skips explicitly
//! without a Docker daemon.

use serde_json::{Value, json};

use crate::enrol::{client_platform, decode_invite, encode_invite, join_from};
use crate::harness::{private_dir, scratch, validate};
use crate::linuxbox::{BOX_BIN, LinuxBox};
use crate::release_fx::{FIXTURE_VERSION, ReleaseKey, serve_release};

const SERVICE_CFG: &str = "/var/lib/jaynshare/.config/jaynshare/config.toml";
const DATA_PLANE_PORT: u16 = 17421;

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

/// `server install <args>` as root through sudo by `user`.
fn install_as(linux: &LinuxBox, user: &str, args: &[&str]) -> (i32, String, String) {
    let sudo_user = format!("SUDO_USER={user}");
    let mut command = vec!["env", sudo_user.as_str(), BOX_BIN, "server", "install"];
    command.extend_from_slice(args);
    linux.exec(&command)
}

/// The `result` of one `--json` run of the installer's `args`.
fn result_of(linux: &LinuxBox, args: &[&str]) -> Value {
    let (code, stdout, stderr) = linux.cli(&[&["--json"], args].concat());
    assert_eq!(code, 0, "{args:?}: {stdout}\n{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
    envelope["result"].clone()
}

fn clients(linux: &LinuxBox) -> Value {
    result_of(linux, &["--config", SERVICE_CFG, "client", "list"])["clients"].clone()
}

/// A fresh install ends with an invite for the user who ran it, which a
/// machine joins with; installing again updates and invites no one; and a
/// fresh install over state that already holds that client leaves it as it is.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_install_invites_the_user_who_ran_it() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(linux) = LinuxBox::start_publishing("install-invites", DATA_PLANE_PORT) else {
        return;
    };
    let key = ReleaseKey::generate();
    linux.plant_key(&key);
    let v070 = linux.release(&key, FIXTURE_VERSION);
    let v071 = linux.release(&key, "0.7.1-acceptance");
    linux.set_ruleset(DROP_INPUT);
    let ip = box_ip(&linux);

    let (code, stdout, stderr) = install_as(&linux, "Alice.Smith", &["--from", &v070]);
    assert_eq!(code, 0, "install: {stdout}\n{stderr}");
    assert!(!stderr.contains("warning"), "{stderr}");
    let invite = stdout
        .lines()
        .last()
        .and_then(|line| line.strip_prefix("jaynshare join "))
        .unwrap_or_else(|| panic!("the last line runs the join: {stdout}"));
    let fields = decode_invite(invite);
    crate::leaks::register_needle("enrollment-code", fields["code"].as_str().expect("code"));
    let status = &result_of(&linux, &["--config", SERVICE_CFG, "status"])["status"];
    assert_eq!(fields["client_id"], "alice-smith", "{fields}");
    assert_eq!(
        fields["base_url"],
        format!("https://{ip}:{DATA_PLANE_PORT}"),
        "{fields}"
    );
    assert_eq!(fields["identity"], status["server"]["tls_pin"], "{fields}");
    assert_eq!(
        fields["signing_key"], status["server"]["signing_key"],
        "{fields}"
    );

    if client_platform() {
        // This machine reaches the box's listener through the published
        // port; the pin, not the address, names the server.
        let mut through = fields.clone();
        through["base_url"] = json!(format!("https://{}", linux.published(DATA_PLANE_PORT)));
        let home = scratch("install-invites-engineer").join("home");
        private_dir(&home);
        let (exit, transcript) = join_from(&home, &encode_invite(&through), &[]);
        assert_eq!(exit, 0, "{transcript}");
        assert!(
            transcript.contains("joined the pool as alice-smith"),
            "{transcript}"
        );
        assert_eq!(clients(&linux)[0]["state"], "active");
    } else {
        eprintln!("skipping the join: no client payload for this platform");
    }
    let invited = clients(&linux);
    assert_eq!(invited.as_array().map(Vec::len), Some(1), "{invited}");

    let schema = result_of(&linux, &["schema", "server", "install"]);
    let (code, stdout, stderr) = install_as(&linux, "bob", &["--from", &v071, "--json"]);
    assert_eq!(code, 0, "update: {stdout}\n{stderr}");
    assert!(!stderr.contains("warning"), "{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
    assert_eq!(envelope["result"]["invite"], Value::Null, "{envelope}");
    validate(&schema, &envelope).expect("the published install schema");
    assert_eq!(clients(&linux), invited);

    // The releases removed by hand, the state kept: the next install is
    // fresh, and the client it would invite already exists.
    let (code, _, stderr) = linux.sh("systemctl stop jaynshare.service");
    assert_eq!(code, 0, "stop: {stderr}");
    let (code, stdout, stderr) = linux.cli(&["server", "uninstall"]);
    assert_eq!(code, 0, "uninstall: {stdout}\n{stderr}");
    let (code, _, stderr) = linux.sh("rm -rf /opt/jaynshare");
    assert_eq!(code, 0, "{stderr}");
    let (code, stdout, stderr) = install_as(&linux, "alice.smith", &["--from", &v070, "--json"]);
    assert_eq!(code, 0, "reinstall: {stdout}\n{stderr}");
    assert!(
        stderr.contains("warning: no invite was issued: the client alice-smith already exists and was left as it is"),
        "{stderr}"
    );
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the envelope");
    assert_eq!(envelope["result"]["invite"], Value::Null, "{envelope}");
    assert_eq!(clients(&linux), invited);
}

/// The published shell bootstrap discovers the local origin's latest
/// release, checks its archive, and hands that same origin to server install.
#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_installs_from_a_local_release_origin() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let Some(linux) = LinuxBox::start("bootstrap-install") else {
        return;
    };
    let key = ReleaseKey::generate();
    linux.plant_key(&key);
    linux.set_ruleset(DROP_INPUT);
    let _inside = linux.release(&key, FIXTURE_VERSION);
    let served = linux.root.join(format!("release-{FIXTURE_VERSION}"));
    let (origin, ca) = serve_release(&served, "host.docker.internal", FIXTURE_VERSION).await;
    linux.put(&ca, "/root/release-ca.pem");

    // Without recommends: ca-certificates' postinst cannot replace the root
    // bundle the box lends read-only, and dpkg then fails.
    let (code, _, stderr) = linux.sh(
        "command -v curl >/dev/null || { apt-get update >/dev/null && apt-get install -y --no-install-recommends curl >/dev/null; }",
    );
    assert_eq!(code, 0, "install curl: {stderr}");
    let script_url = format!("{origin}/v{FIXTURE_VERSION}/install.sh");
    let (code, _, stderr) = linux.exec(&[
        "curl",
        "--cacert",
        "/root/release-ca.pem",
        "-fsSL",
        "-o",
        "/root/install.sh",
        &script_url,
    ]);
    assert_eq!(code, 0, "fetch install.sh: {stderr}");
    let (code, stdout, stderr) = linux.exec(&[
        "sh",
        "/root/install.sh",
        "--release-origin",
        &origin,
        "--tls-ca",
        "/root/release-ca.pem",
    ]);
    assert_eq!(code, 0, "bootstrap: {stdout}\n{stderr}");
    assert_eq!(
        current(&linux),
        format!("/opt/jaynshare/releases/{FIXTURE_VERSION}")
    );
    assert_eq!(
        linux.read("/opt/jaynshare/origin.json"),
        Some(format!(r#"{{"mirror":"{origin}"}}"#).into_bytes())
    );
    let (code, _, stderr) = linux.cli(&["--config", SERVICE_CFG, "status", "--check"]);
    assert_eq!(code, 0, "status: {stderr}");
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
