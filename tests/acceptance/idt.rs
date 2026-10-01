//! The server identity: the key generated on first start, the TLS listener
//! on it, the pin a client holds, and a client following its server from
//! plain HTTP onto it.

use std::fs;

#[allow(unused_imports)]
use crate::client_fx::*;
#[allow(unused_imports)]
use crate::harness::*;

const KEY_FILE: &str = "server-identity-key.pem";
const OTHER_PIN: &str = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn identity_tls() -> Setup {
    Setup {
        mitm: true,
        data_plane: "tls = \"identity\"\n".into(),
        ..Setup::default()
    }
}

fn operator_identity(instance: &Instance) -> serde_json::Value {
    let status = instance.cli_json(&["status"], None);
    assert_eq!(status["ok"], true, "{status}");
    status["result"]["status"]["server"]["tls_pin"].clone()
}

fn client_toml(machine: &ClientHome) -> toml::Table {
    fs::read_to_string(machine.client_dir.join("client.toml"))
        .expect("client.toml")
        .parse()
        .expect("client.toml parses")
}

fn append_toml(machine: &ClientHome, line: &str) {
    let path = machine.client_dir.join("client.toml");
    let mut text = fs::read_to_string(&path).expect("client.toml");
    text.push_str(line);
    fs::write(&path, text).expect("client.toml");
}

/// A new install's listener is TLS on a key the server generated itself,
/// private to it, and the same across a restart; the operator's own client
/// reaches it through the pin.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_install_serves_tls_on_its_own_identity() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_with("identity-new-install", identity_tls()).await;
    assert!(
        instance
            .stdout()
            .contains(&format!("listening on https://{}", instance.addr)),
        "{}",
        instance.stdout()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(instance.root.join("state").join(KEY_FILE))
            .expect("the identity key")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the identity key is the server's alone"
        );
    }
    let pin = operator_identity(&instance);
    assert!(
        pin.as_str().is_some_and(|pin| pin.starts_with("sha256/")),
        "{pin}"
    );
    instance.restart();
    assert_eq!(
        operator_identity(&instance),
        pin,
        "the identity survives a restart"
    );
}

/// A plain-HTTP configuration stays plain HTTP, but its clients already
/// learn the pin; once the operator turns the identity TLS on, they follow
/// over `https` and keep it.
#[tokio::test(flavor = "multi_thread")]
async fn an_http_client_learns_the_pin_and_follows_its_server_onto_tls() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("identity-follow").await;
    assert!(
        instance
            .stdout()
            .contains(&format!("listening on http://{}", instance.addr)),
        "{}",
        instance.stdout()
    );
    let machine = install_client(&instance).await;
    let (code, _, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    let pin = operator_identity(&instance);
    assert_eq!(
        client_toml(&machine)["server_identity"].as_str(),
        pin.as_str()
    );
    assert_eq!(
        client_toml(&machine)["base_url"].as_str(),
        Some(machine.base_url.as_str())
    );

    instance.write_setup(&identity_tls());
    instance.restart();
    let (code, _, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
    assert_eq!(code, 0, "the client follows onto TLS: {stderr}");
    let https = format!("https://{}", instance.addr);
    assert_eq!(
        client_toml(&machine)["base_url"].as_str(),
        Some(https.as_str())
    );
    let (code, _, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
    assert_eq!(code, 0, "the next run goes straight to https: {stderr}");
}

/// A client reaching its plain-HTTP server through a TLS front checks the
/// front's certificate and never takes the server's pin, which the front
/// does not present.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_behind_a_tls_front_keeps_its_anchor() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("identity-tls-front").await;
    let machine = install_client(&instance).await;
    let https = tls_front(instance.addr, &instance.root.join("tls-front")).await;
    machine.set("base_url", &format!("{https:?}"));
    fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/acceptance/fixtures/tls/test-ca.pem"),
        machine.client_dir.join("base-url-ca.pem"),
    )
    .expect("base-url-ca.pem");
    for run in ["first", "second"] {
        let (code, _, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
        assert_eq!(code, 0, "{run} run through the front: {stderr}");
    }
    assert!(client_toml(&machine).get("server_identity").is_none());
}

/// A server presenting another key than the pinned one is refused, and the
/// refused installation is left as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_whose_identity_is_not_the_pinned_one_is_refused() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("identity-wrong-pin").await;
    let machine = install_client(&instance).await;
    append_toml(&machine, &format!("server_identity = {OTHER_PIN:?}\n"));
    instance.write_setup(&identity_tls());
    instance.restart();

    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 4, "{stderr}");
    assert!(
        stderr.contains(&format!("is not the pinned {OTHER_PIN}")),
        "the refusal names the pin: {stderr}"
    );
    assert_eq!(
        client_toml(&machine)["base_url"].as_str(),
        Some(machine.base_url.as_str()),
        "a refused server never moves the base URL"
    );

    let https = format!("https://{}", instance.addr);
    machine.set("base_url", &format!("{https:?}"));
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 4, "{stderr}");
    assert!(stderr.contains("is not the pinned"), "{stderr}");
}

/// A client's own login carries a secret, so off loopback it is refused over
/// plain HTTP and goes through once its server serves the identity TLS.
#[tokio::test(flavor = "multi_thread")]
async fn a_remote_client_logs_in_over_the_identity_tls() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if non_loopback_addr().is_none() {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    }
    let plain = Setup {
        mitm: true,
        wildcard: true,
        ..Setup::default()
    };
    let mut instance = Instance::start_with("identity-remote-login", plain.clone()).await;
    let machine = install_client(&instance).await;
    let remote = non_loopback_dest(&instance).expect("checked above");
    machine.set("base_url", &format!("\"http://{remote}\""));
    let (code, _, stderr) = machine.jaynshare(&["status", "--json"], &[], None);
    assert_eq!(code, 0, "the client learns the pin: {stderr}");
    let no_browser = machine
        .root
        .join("no-browser-on-path")
        .display()
        .to_string();
    let (code, stdout, stderr) =
        machine.jaynshare(&["account", "login"], &[("PATH", &no_browser)], None);
    assert_ne!(code, 0, "{stdout}{stderr}");
    assert!(stderr.contains("insecure_channel"), "{stderr}");

    instance.write_setup(&Setup {
        data_plane: "tls = \"identity\"\n".into(),
        ..plain
    });
    instance.restart();
    let (browser, (code, stdout, stderr)) = crate::own::client_login(&machine).await;
    assert_eq!(browser, StatusCode::FOUND);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let https = format!("https://{remote}");
    assert_eq!(
        client_toml(&machine)["base_url"].as_str(),
        Some(https.as_str())
    );
    let (code, stdout, stderr) = machine.jaynshare(&["account", "list", "--json"], &[], None);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(
        envelope["result"]["accounts"][0]["health"]["state"],
        "ready"
    );
}

/// An enrollment bundle cannot carry the pin, so packaging refuses before
/// any client is issued.
#[tokio::test(flavor = "multi_thread")]
async fn an_identity_server_packages_no_enrollment_bundle() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = crate::bundle::Operator::start_with("identity-bundle", identity_tls()).await;
    let out = operator.instance.root.join("bundle-out");
    private_dir(&out);
    let (exit, stdout, stderr) = operator.cli(&[
        "client",
        "enrol",
        "alpha",
        "--name",
        "Alpha Desk",
        "--kit",
        &operator.kit_path().display().to_string(),
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(exit, 3, "{stdout}{stderr}");
    assert!(stderr.contains("data_plane.tls"), "{stderr}");
    let clients = operator.instance.cli_json(&["client", "list"], None);
    assert_eq!(clients["result"]["clients"], json!([]), "{clients}");
}

/// An operator certificate serves as before, and its server names no pin, so
/// its clients keep checking the certificate.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_certificate_names_no_pin() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/acceptance/identity-operator-certificate-certs");
    let (cert, key) = stage_tls_pair(&directory);
    let instance = Instance::start_with(
        "identity-operator-certificate",
        Setup {
            data_plane: format!(
                "tls_certificate_file = \"{}\"\ntls_private_key_file = \"{}\"\n",
                cert.display(),
                key.display()
            ),
            ..Setup::default()
        },
    )
    .await;
    let status = instance.cli_json(&["status"], None);
    assert_eq!(status["ok"], true, "{status}");
    let server = &status["result"]["status"]["server"];
    assert_eq!(server["tls"], true, "{server}");
    assert!(server["tls_pin"].is_null(), "{server}");
}
