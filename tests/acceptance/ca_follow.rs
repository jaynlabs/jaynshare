//! Clients follow their server's MITM CA: a staged CA joins `ca.pem` on the
//! next `status` or launch, a CA replaced at once is fetched before the
//! launch, and a CA never travels over plain HTTP off loopback.

use std::fs;

use crate::client_fx::{ClientHome, install_client, statusline_payload};
use crate::harness::{Instance, Setup, Value, non_loopback_dest};

/// The fingerprints of the certificates in the installation's `ca.pem`.
fn trusted(machine: &ClientHome) -> Vec<String> {
    let pem = fs::read(machine.client_dir.join("ca.pem")).expect("ca.pem");
    x509_parser::pem::Pem::iter_from_buffer(&pem)
        .map(|block| {
            let digest = ring::digest::digest(&ring::digest::SHA256, &block.expect("PEM").contents);
            let pairs: Vec<String> = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect();
            pairs.join(":")
        })
        .collect()
}

fn recorded(machine: &ClientHome) -> String {
    let toml: toml::Table = fs::read_to_string(machine.client_dir.join("client.toml"))
        .expect("client.toml")
        .parse()
        .expect("client.toml parses");
    toml["ca_fingerprint"]
        .as_str()
        .expect("ca_fingerprint")
        .to_string()
}

/// The operator's `ca rotate` with `flags`, answered as JSON.
fn rotate(instance: &Instance, flags: &[&str]) -> Value {
    let args = [&["ca", "rotate", "--yes"], flags].concat();
    let envelope = instance.cli_json(&args, None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    envelope["result"].clone()
}

/// A staged CA is trusted beside the current one from the next `status`
/// on, and a launch then hands Claude Code both; the status line never
/// fetches it.
#[tokio::test(flavor = "multi_thread")]
async fn a_staged_ca_joins_ca_pem_before_the_switch() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("ca-follow-staged").await;
    let machine = install_client(&instance).await;
    let current = recorded(&machine);

    let staged = rotate(&instance, &[]);
    let next = staged["next"]["fingerprint"]
        .as_str()
        .expect("staged")
        .to_string();
    let (code, stdout, _) = machine.jaynshare(
        &["statusline"],
        &[("JAYNSHARE_STATUSLINE", "1")],
        Some(&statusline_payload("ca-follow-session")),
    );
    assert_eq!(code, 0);
    assert!(!stdout.is_empty(), "the line still renders");
    assert_eq!(
        trusted(&machine),
        [current.as_str()],
        "the status line only reads"
    );

    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.contains(&format!("its next CA {next}")), "{stderr}");
    assert_eq!(trusted(&machine), [current.clone(), next]);
    assert_eq!(
        recorded(&machine),
        current,
        "the presented CA is still the current one"
    );

    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        !stderr.contains("now trusting"),
        "nothing more to fetch: {stderr}"
    );
    let run = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        run.env.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
        Some(
            machine
                .client_dir
                .join("ca.pem")
                .display()
                .to_string()
                .as_str()
        )
    );
}

/// A CA replaced at once fails the launch check, so the launch fetches it,
/// drops the old CA and goes ahead.
#[tokio::test(flavor = "multi_thread")]
async fn a_ca_replaced_now_is_fetched_before_the_launch() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("ca-follow-now").await;
    let machine = install_client(&instance).await;
    let rotated = rotate(&instance, &["--now"]);
    let new = rotated["fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();
    assert_ne!(rotated["previous_fingerprint"], rotated["fingerprint"]);

    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains(&format!("now trusting the server's CA {new}")),
        "{stderr}"
    );
    assert!(machine.claude_ran().is_some(), "Claude Code was launched");
    assert_eq!(trusted(&machine), [new.as_str()]);
    assert_eq!(recorded(&machine), new);
}

/// Over plain HTTP off loopback a client refuses the server's new CA and
/// says why; once the server serves its identity TLS, it takes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_ca_never_travels_over_plain_http_off_loopback() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let plain = Setup {
        mitm: true,
        wildcard: true,
        ..Setup::default()
    };
    let mut instance = Instance::start_with("ca-follow-plain-http", plain.clone()).await;
    let Some(remote) = non_loopback_dest(&instance) else {
        eprintln!("skipping: the fixture host has no non-loopback address");
        return;
    };
    let machine = install_client(&instance).await;
    machine.set("base_url", &format!("\"http://{remote}\""));
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 0, "the client learns the pin: {stderr}");
    let old = trusted(&machine);

    let new = rotate(&instance, &["--now"])["fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 12, "{stderr}");
    assert!(stderr.contains("plain HTTP"), "says why: {stderr}");
    assert_eq!(trusted(&machine), old, "nothing replaced");

    instance.write_setup(&Setup {
        data_plane: "tls = \"identity\"\n".into(),
        ..plain
    });
    instance.restart();
    let (code, _, stderr) = machine.jaynshare(&["status"], &[], None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(trusted(&machine), [new]);
}
