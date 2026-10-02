//! Clients follow their server: the client snapshot names the kit the
//! server offers, `GET /control/v1/client/kit` serves it, and an installed
//! client on another payload replaces itself on `claude` and `status`
//! after verifying the kit against its own pinned key. The status line
//! never updates.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::client_fx::{ClientHome, install_client, statusline_payload};
use crate::enrol::{
    KIT_MEMBERS, client_platform, installed_binary, kit_member_bytes, native_payload,
    write_kit_members,
};
use crate::harness::{
    Instance, Method, Setup, StatusCode, Value, binary, control, enroll, scratch, validate,
};
use crate::release_fx::{ReleaseKey, sha256_hex};

/// A kit signed by `key` whose native payload is `payload`; every other
/// member is filler.
fn write_kit(path: &Path, key: &ReleaseKey, payload: &[u8]) {
    let mut members: Vec<(String, Vec<u8>)> = KIT_MEMBERS
        .iter()
        .map(|name| {
            let bytes = if client_platform() && *name == native_payload() {
                payload.to_vec()
            } else {
                kit_member_bytes(name)
            };
            ((*name).to_string(), bytes)
        })
        .collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    write_kit_members(path, &key.pkcs8, &key.public, &members);
}

/// An instance whose `clients.kit_file` is `kit` and whose release key is
/// `key`, planted before anything asks for the kit.
async fn serving(scenario: &str, kit: &Path, key: &ReleaseKey) -> Instance {
    let instance = Instance::start_with(
        scenario,
        Setup {
            mitm: true,
            clients: format!("kit_file = {:?}\n", kit.display().to_string()),
            ..Setup::default()
        },
    )
    .await;
    key.plant(&instance.root.join("home"));
    instance
}

async fn client_get(instance: &Instance, path: &str, secret: &str) -> crate::harness::Answer {
    let bearer = format!("Bearer {secret}");
    control(
        instance.addr,
        Method::GET,
        path,
        &[("authorization", &bearer)],
        None,
    )
    .await
}

/// The snapshot's `client` once `decided` holds: the server verifies a
/// changed kit in the background, so its offer trails the file.
async fn settled(instance: &Instance, secret: &str, decided: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = client_get(instance, "/control/v1/client/status", secret).await;
        let client = status.json()["client"].clone();
        if decided(&client) {
            return client;
        }
        assert!(
            Instant::now() < deadline,
            "the offer never settled: {client}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether the server logged a kit refused for its signing key.
fn refused_for_its_key(instance: &Instance) -> bool {
    instance.events("client_kit").iter().any(|event| {
        event["fields"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("does not match the active key id"))
    })
}

/// The snapshot names the kit's version and each platform's payload
/// digest once the server's own key verifies it, and the kit route
/// serves its bytes; a missing kit or one signed by another key is not
/// offered at all.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_offers_only_a_kit_it_verifies() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("server-offers-verified-kit-files");
    let kit = root.join("client-kit.zip");
    let key = ReleaseKey::generate();
    let instance = serving("server-offers-verified-kit", &kit, &key).await;
    let client = enroll(&instance, "alpha", "Alpha Desk").await;

    let status = client_get(&instance, "/control/v1/client/status", &client.secret).await;
    assert_eq!(status.status, StatusCode::OK, "{status:?}");
    let offered = &status.json()["client"];
    assert!(
        offered.get("version").is_none() && offered.get("sha256").is_none(),
        "no kit, no offer: {offered}"
    );
    let download = client_get(&instance, "/control/v1/client/kit", &client.secret).await;
    assert_eq!(download.status, StatusCode::NOT_FOUND, "{download:?}");

    write_kit(&kit, &key, b"the server's client");
    let offered = settled(&instance, &client.secret, |c| c.get("version").is_some()).await;
    assert_eq!(offered["id"], "alpha", "the caller's own facts stand");
    assert_eq!(offered["version"], "0.0.0-acceptance");
    let digests = offered["sha256"]
        .as_object()
        .expect("one digest per platform");
    assert_eq!(digests.len(), 3, "{offered}");
    for (platform, member) in [
        ("macos-x86_64", "payload/macos-x86_64/jaynshare"),
        ("macos-aarch64", "payload/macos-aarch64/jaynshare"),
        ("windows-x86_64", "payload/windows-x86_64/jaynshare.exe"),
    ] {
        let bytes = if client_platform() && member == native_payload() {
            b"the server's client".to_vec()
        } else {
            kit_member_bytes(member)
        };
        assert_eq!(digests[platform], sha256_hex(&bytes), "{platform}");
    }

    let download = client_get(&instance, "/control/v1/client/kit", &client.secret).await;
    assert_eq!(download.status, StatusCode::OK, "{download:?}");
    assert_eq!(download.header("content-type"), Some("application/zip"));
    assert_eq!(
        download.body().as_ref(),
        fs::read(&kit).expect("the kit").as_slice(),
        "the kit arrives byte for byte"
    );
    let unknown = client_get(&instance, "/control/v1/client/kit", "jsc2_unknown").await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED, "{unknown:?}");
    let bearer = client.bearer();
    let posted = control(
        instance.addr,
        Method::POST,
        "/control/v1/client/kit",
        &[("authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(posted.status, StatusCode::METHOD_NOT_ALLOWED);

    // Signed by a key this server does not hold: logged with the reason,
    // and not offered.
    write_kit(&kit, &ReleaseKey::generate(), b"a foreign client");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !refused_for_its_key(&instance) {
        let _ = client_get(&instance, "/control/v1/client/status", &client.secret).await;
        assert!(
            Instant::now() < deadline,
            "{:?}",
            instance.events("client_kit")
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let status = client_get(&instance, "/control/v1/client/status", &client.secret).await;
    assert!(
        status.json()["client"].get("version").is_none(),
        "{status:?}"
    );
    let download = client_get(&instance, "/control/v1/client/kit", &client.secret).await;
    assert_eq!(download.status, StatusCode::NOT_FOUND);
}

fn install_executable(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().expect("bin directory")).expect("bin directory");
    fs::write(path, bytes).expect("the installed client");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
}

/// One run of the installed client, as the engineer's shell starts it.
fn run_installed(
    machine: &ClientHome,
    args: &[&str],
    extra: &[(&str, &str)],
    stdin: Option<&str>,
) -> (i32, String, String) {
    let mut child = Command::new(installed_binary(&machine.home))
        .args(args)
        .env_clear()
        .envs(machine.env())
        .envs(extra.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run the installed client");
    let mut input = child.stdin.take().expect("stdin");
    input
        .write_all(stdin.unwrap_or_default().as_bytes())
        .expect("write stdin");
    drop(input);
    let output = child
        .wait_with_output()
        .expect("the installed client's output");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The client the suite built, and an older one: the same executable with
/// bytes appended, so it runs but carries another digest.
fn two_clients() -> (Vec<u8>, Vec<u8>) {
    let built = fs::read(binary()).expect("the binary under test");
    let older = [built.as_slice(), b"\nacceptance: an older client\n"].concat();
    (built, older)
}

/// An installed client on another payload than its server's replaces
/// itself on `claude` and carries on with the launch; it follows a
/// rollback on `status` the same way; the status line never updates.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_follows_its_server_and_its_rollback() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: no client payload for this platform");
        return;
    }
    let root = scratch("client-follows-server-kits");
    let kit = root.join("client-kit.zip");
    let key = ReleaseKey::generate();
    let instance = serving("client-follows-server", &kit, &key).await;
    let machine = install_client(&instance).await;
    key.plant(&machine.home);
    let installed = installed_binary(&machine.home);
    let (built, older) = two_clients();
    install_executable(&installed, &older);
    let (newer_kit, older_kit) = (root.join("newer.zip"), root.join("older.zip"));
    write_kit(&newer_kit, &key, &built);
    write_kit(&older_kit, &key, &older);
    fs::copy(&newer_kit, &kit).expect("the server's kit");
    let secret = &machine.client.secret;
    settled(&instance, secret, |c| {
        c["sha256"][platform()] == sha256_hex(&built)
    })
    .await;

    // The status line only reads, whatever the server offers.
    let (code, stdout, _) = run_installed(
        &machine,
        &["statusline"],
        &[("JAYNSHARE_STATUSLINE", "1")],
        Some(&statusline_payload("follow-session")),
    );
    assert_eq!(code, 0);
    assert!(!stdout.is_empty(), "the line still renders");
    assert_eq!(fs::read(&installed).expect("installed"), older, "no update");

    let (code, _, stderr) =
        run_installed(&machine, &["claude", "--auto", "--", "-p", "hi"], &[], None);
    assert_eq!(code, 0, "the launch carries on: {stderr}");
    assert!(
        stderr.contains("updating to this server's client, 0.0.0-acceptance"),
        "{stderr}"
    );
    assert_eq!(
        fs::read(&installed).expect("installed"),
        built,
        "the server's client replaced the older one"
    );
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.argv, ["-p", "hi"], "the same arguments, once");

    let (code, _, stderr) = run_installed(&machine, &["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(!stderr.contains("updating"), "already current: {stderr}");
    machine.claude_ran().expect("Claude Code was launched");

    // The server rolls back to the older kit; `status` follows it.
    fs::copy(&older_kit, &kit).expect("the rolled-back kit");
    settled(&instance, secret, |c| {
        c["sha256"][platform()] == sha256_hex(&older)
    })
    .await;
    let (code, stdout, stderr) = run_installed(&machine, &["status", "--json"], &[], None);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains("updating to this server's client"),
        "{stderr}"
    );
    assert_eq!(fs::read(&installed).expect("installed"), older);
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("one envelope");
    assert_eq!(
        envelope["result"]["client"]["sha256"][platform()],
        sha256_hex(&older),
        "the re-run reports the client it now is"
    );
    let (_, schema, _) = run_installed(&machine, &["schema", "status", "--json"], &[], None);
    let schema: Value = serde_json::from_str(schema.trim()).expect("the schema envelope");
    validate(&schema["result"], &envelope).expect("the published status schema");
}

/// A kit the server offers but the client's pinned key did not sign is
/// refused with the reason, and the client carries on as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_kit_signed_by_another_key_is_refused() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: no client payload for this platform");
        return;
    }
    let root = scratch("unpinned-kit-refused-kits");
    let kit = root.join("client-kit.zip");
    let server_key = ReleaseKey::generate();
    let instance = serving("unpinned-kit-refused", &kit, &server_key).await;
    let machine = install_client(&instance).await;
    ReleaseKey::generate().plant(&machine.home);
    let installed = installed_binary(&machine.home);
    let (built, older) = two_clients();
    install_executable(&installed, &older);
    write_kit(&kit, &server_key, &built);
    settled(&instance, &machine.client.secret, |c| {
        c["sha256"][platform()] == sha256_hex(&built)
    })
    .await;

    let (code, _, stderr) = run_installed(&machine, &["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the launch carries on: {stderr}");
    assert!(stderr.contains("not updated"), "{stderr}");
    assert!(
        stderr.contains("does not match the active key id"),
        "{stderr}"
    );
    assert_eq!(fs::read(&installed).expect("installed"), older, "unchanged");
    machine.claude_ran().expect("Claude Code was launched");
}

fn platform() -> &'static str {
    native_payload()
        .strip_prefix("payload/")
        .and_then(|rest| rest.split('/').next())
        .expect("a payload directory")
}
