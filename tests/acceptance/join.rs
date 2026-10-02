//! `client invite` and `join`: a machine becomes a pool client with one
//! command, on the server the invite names and with the client the invite's
//! key signed, or not at all.

use std::path::{Path, PathBuf};

use base64::Engine as _;

use crate::enrol::{
    Operator, client_platform, config_root, decode_invite, encode_invite, identity_setup,
    join_from, kit_member_bytes, native_payload,
};
use crate::harness::{
    Setup, Value, binary, cli_raw, isolated_env, json, private_dir, scratch, validate,
};
use crate::release_fx::ReleaseKey;

const OTHER_PIN: &str = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn fresh_home(name: &str) -> PathBuf {
    let home = scratch(name).join("home");
    private_dir(&home);
    home
}

fn client_toml(home: &Path) -> toml::Table {
    std::fs::read_to_string(config_root(home).join("client/client.toml"))
        .expect("client.toml")
        .parse()
        .expect("client.toml parses")
}

/// Nothing of a client is on the machine: no installation, no executable,
/// no pinned key.
fn nothing_installed(home: &Path) -> bool {
    let root = config_root(home);
    !root.join("client").exists()
        && !root.join("bin").exists()
        && !root.join("release.pub").exists()
}

fn operator_status(operator: &Operator) -> Value {
    let envelope = operator.instance.cli_json(&["status"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    envelope["result"]["status"].clone()
}

/// A fresh machine joins with one command: the client files with the pin
/// and the `https` base URL, the pinned key, the server's own client on the
/// search path; the code lands nowhere; and `uninstall` takes the link back.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_machine_joins_with_one_command() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: join: no client payload for this platform");
        return;
    }
    let operator = Operator::start("join-fresh-machine").await;
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let fields = decode_invite(&invite);
    let home = fresh_home("join-fresh-machine-engineer");
    let (exit, transcript) = join_from(&home, &invite, &[]);
    assert_eq!(exit, 0, "{transcript}");
    let base_url = format!("https://{}", operator.instance.addr);
    for line in [
        format!("✓ connected to the pool at {base_url} (identity matches the invite)"),
        "✓ installed jaynshare 0.0.0-acceptance (this server's client)".to_string(),
        "joined the pool as alpha (Alpha Desk)".to_string(),
    ] {
        assert!(transcript.contains(&line), "{line}: {transcript}");
    }
    let code = fields["code"].as_str().expect("code");
    assert!(!transcript.contains(code), "{transcript}");

    let status = operator_status(&operator);
    let ca = operator.get("/control/v1/ca");
    let toml = client_toml(&home);
    assert_eq!(toml["client_id"].as_str(), Some("alpha"), "{toml}");
    assert_eq!(toml["base_url"].as_str(), Some(base_url.as_str()), "{toml}");
    assert_eq!(
        toml["server_identity"].as_str(),
        status["server"]["tls_pin"].as_str(),
        "{toml}"
    );
    assert_eq!(
        toml["proxy_url"].as_str().map(String::from),
        operator
            .instance
            .mitm_addr
            .map(|addr| format!("http://{addr}")),
        "{toml}"
    );
    assert_eq!(
        toml["ca_fingerprint"].as_str(),
        ca["ca"]["fingerprint"].as_str(),
        "{toml}"
    );
    let root = config_root(&home);
    assert_eq!(
        std::fs::read_to_string(root.join("client/ca.pem")).expect("ca.pem"),
        ca["ca"]["certificate_pem"].as_str().expect("the CA")
    );
    let pinned = std::fs::read_to_string(root.join("release.pub")).expect("release.pub");
    assert_eq!(
        pinned.lines().nth(1),
        fields["signing_key"].as_str(),
        "the pinned key is the invite's: {pinned}"
    );
    let executable = if cfg!(windows) {
        let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA"));
        local.join("Programs/Jaynshare/jaynshare.exe")
    } else {
        root.join("bin/jaynshare")
    };
    assert_eq!(
        std::fs::read(&executable).expect("the executable"),
        kit_member_bytes(native_payload()),
        "the server's client is installed"
    );
    #[cfg(unix)]
    {
        let link = home.join(".local/bin/jaynshare");
        assert_eq!(
            std::fs::read_link(&link).expect("the search-path link"),
            executable
        );
        assert!(
            transcript.contains(&link.display().to_string()),
            "{transcript}"
        );
    }
    for file in [root.join("client/client.toml"), root.join("release.pub")] {
        let text = std::fs::read_to_string(&file).expect("an installed file");
        assert!(!text.contains(code), "{}: the code", file.display());
    }

    let env = isolated_env(&home);
    let (exit, stdout, stderr) = cli_raw(&["status", "--json"], &env, None);
    assert_eq!(exit, 0, "{stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["role"], "client", "{envelope}");
    assert_eq!(envelope["result"]["client"]["id"], "alpha", "{envelope}");

    let (exit, stdout, stderr) = cli_raw(&["uninstall"], &env, None);
    assert_eq!(exit, 0, "{stdout}{stderr}");
    #[cfg(unix)]
    assert!(
        std::fs::symlink_metadata(home.join(".local/bin/jaynshare")).is_err(),
        "the link goes with the executable"
    );

    // `--json`: the installation's facts and the version.
    let invite = operator.invite("beta", "Beta Desk", &[]);
    let home = fresh_home("join-fresh-machine-json");
    let env = isolated_env(&home);
    let (exit, stdout, stderr) = cli_raw(&["join", &invite, "--json"], &env, None);
    assert_eq!(exit, 0, "{stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["result"]["client_id"], "beta", "{envelope}");
    assert_eq!(
        envelope["result"]["version"], "0.0.0-acceptance",
        "{envelope}"
    );
    assert_eq!(
        envelope["result"]["origins"]["base_url"], base_url,
        "{envelope}"
    );
    let schema = operator.instance.cli_json(&["schema", "join"], None);
    validate(&schema["result"], &envelope).expect("the published join schema");
}

/// An invite claims once: the second machine is refused and installs
/// nothing; one past its expiry is refused the same way.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_works_once_and_until_it_expires() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: join: no client payload for this platform");
        return;
    }
    let faults = crate::faults::Faults::new();
    let operator =
        Operator::start_with_faults("join-once-until-expiry", std::sync::Arc::clone(&faults)).await;
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let (exit, transcript) = join_from(&fresh_home("join-once-until-expiry-first"), &invite, &[]);
    assert_eq!(exit, 0, "{transcript}");
    let second = fresh_home("join-once-until-expiry-second");
    let (exit, transcript) = join_from(&second, &invite, &[]);
    assert_eq!(exit, 5, "a reused invite: {transcript}");
    assert!(
        transcript.contains("the server refused the invite"),
        "{transcript}"
    );
    assert!(nothing_installed(&second), "{transcript}");

    let invite = operator.invite("beta", "Beta Desk", &["--expires", "1m"]);
    faults.set_deadline(std::time::Instant::now(), 61);
    let (exit, transcript) = join_from(&second, &invite, &[]);
    assert_eq!(exit, 5, "an expired invite: {transcript}");
    assert!(nothing_installed(&second), "{transcript}");
}

/// A server presenting another identity than the invite's is refused
/// before the claim: nothing is installed and the invite stays good.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_with_another_identity_is_refused() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: join: no client payload for this platform");
        return;
    }
    let operator = Operator::start("join-other-identity").await;
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let mut forged = decode_invite(&invite);
    forged["identity"] = json!(OTHER_PIN);
    let home = fresh_home("join-other-identity-engineer");
    let (exit, transcript) = join_from(&home, &encode_invite(&forged), &[]);
    assert_eq!(exit, 4, "{transcript}");
    assert!(
        transcript.contains(&format!("is not the pinned {OTHER_PIN}")),
        "the refusal names the pin: {transcript}"
    );
    assert!(nothing_installed(&home), "{transcript}");

    let (exit, transcript) = join_from(&home, &invite, &[]);
    assert_eq!(exit, 0, "the invite is unspent: {transcript}");
}

/// A server whose client is not signed with the invite's key installs
/// nothing; the claim spent the invite, and the refusal says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_not_signed_with_the_invite_key_is_refused() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: join: no client payload for this platform");
        return;
    }
    let operator = Operator::start("join-unpinned-kit").await;
    let mut forged = decode_invite(&operator.invite("alpha", "Alpha Desk", &[]));
    let other = ReleaseKey::generate();
    forged["signing_key"] = json!(
        base64::engine::general_purpose::STANDARD
            .encode([b"Ed".as_slice(), &other.public[..8], &other.public].concat())
    );
    let home = fresh_home("join-unpinned-kit-engineer");
    let (exit, transcript) = join_from(&home, &encode_invite(&forged), &[]);
    assert_eq!(exit, 17, "{transcript}");
    assert!(
        transcript.contains("not signed with the invite's key")
            && transcript.contains("the invite is spent"),
        "{transcript}"
    );
    assert!(nothing_installed(&home), "{transcript}");
}

/// A server no machine could join safely issues no invite: plain HTTP
/// (exit 3, naming the identity TLS) or MITM off (exit 14), each before
/// any client exists; and an invite to a plain-HTTP origin is refused
/// before it is spent.
#[tokio::test(flavor = "multi_thread")]
async fn an_unsafe_server_issues_no_invite_and_http_is_refused() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let plain = Operator::start_with(
        "join-unsafe-plain",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let (exit, stdout, stderr) = plain.cli(&["client", "invite", "alpha"]);
    assert_eq!(exit, 3, "{stdout}{stderr}");
    assert!(stderr.contains("tls = \"identity\""), "{stderr}");
    let clients = plain.instance.cli_json(&["client", "list"], None);
    assert_eq!(clients["result"]["clients"], json!([]), "{clients}");

    let no_mitm = Operator::start_with(
        "join-unsafe-no-mitm",
        Setup {
            mitm: false,
            ..identity_setup()
        },
    )
    .await;
    let (exit, stdout, stderr) = no_mitm.cli(&["client", "invite", "alpha"]);
    assert_eq!(exit, 14, "{stdout}{stderr}");
    let clients = no_mitm.instance.cli_json(&["client", "list"], None);
    assert_eq!(clients["result"]["clients"], json!([]), "{clients}");

    if !client_platform() {
        return;
    }
    let operator = Operator::start("join-unsafe-http-invite").await;
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let mut http = decode_invite(&invite);
    http["base_url"] = json!(format!("http://{}", operator.instance.addr));
    let home = fresh_home("join-unsafe-http-invite-engineer");
    let (exit, transcript) = join_from(&home, &encode_invite(&http), &[]);
    assert_eq!(exit, 5, "{transcript}");
    assert!(transcript.contains("plain HTTP"), "{transcript}");
    assert!(nothing_installed(&home), "{transcript}");
    let (exit, transcript) = join_from(&home, &invite, &[]);
    assert_eq!(exit, 0, "the invite is unspent: {transcript}");
}

/// `--expires` sets the invite's lifetime within its bounds, `--no-account`
/// is kept on the pending entry, and `reissue` replaces the invite with its
/// own terms: the previous one stops working.
#[tokio::test(flavor = "multi_thread")]
async fn the_invite_terms_are_kept_and_reissue_replaces_them() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start("join-invite-terms").await;
    let before = time::OffsetDateTime::now_utc();
    let envelope = operator.instance.cli_json(
        &[
            "client",
            "invite",
            "alpha",
            "--expires",
            "1h",
            "--no-account",
        ],
        None,
    );
    assert_eq!(envelope["ok"], true, "{envelope}");
    let schema = operator
        .instance
        .cli_json(&["schema", "client", "invite"], None);
    validate(&schema["result"], &envelope).expect("the published invite schema");
    let first = envelope["result"]["invite"]
        .as_str()
        .expect("the invite")
        .to_string();
    crate::leaks::register_needle(
        "enrollment-code",
        decode_invite(&first)["code"].as_str().expect("code"),
    );
    let expires = time::OffsetDateTime::parse(
        envelope["result"]["expires_at"].as_str().expect("expiry"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("an RFC 3339 expiry");
    let lifetime = (expires - before).whole_seconds();
    assert!((3590..=3610).contains(&lifetime), "{lifetime}: {envelope}");
    let shown = operator
        .instance
        .cli_json(&["client", "show", "alpha"], None);
    let schema = operator
        .instance
        .cli_json(&["schema", "client", "show"], None);
    validate(&schema["result"], &shown).expect("the published show schema");
    assert_eq!(shown["result"]["client"]["no_account"], true, "{shown}");
    assert_eq!(
        shown["result"]["client"]["display_name"], "alpha",
        "{shown}"
    );

    let (exit, stdout, stderr) = operator.cli(&["client", "invite", "beta", "--expires", "30s"]);
    assert_eq!(exit, 9, "below the bounds: {stdout}{stderr}");
    let (exit, _, _) = operator.cli(&["client", "show", "beta"]);
    assert_eq!(exit, 6, "no client was issued");

    let envelope = operator
        .instance
        .cli_json(&["client", "reissue", "alpha"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let second = envelope["result"]["invite"]
        .as_str()
        .expect("the invite")
        .to_string();
    crate::leaks::register_needle(
        "enrollment-code",
        decode_invite(&second)["code"].as_str().expect("code"),
    );
    assert_ne!(first, second);
    let shown = operator
        .instance
        .cli_json(&["client", "show", "alpha"], None);
    assert_ne!(shown["result"]["client"]["no_account"], true, "{shown}");

    if !client_platform() {
        return;
    }
    let home = fresh_home("join-invite-terms-engineer");
    let (exit, transcript) = join_from(&home, &first, &[]);
    assert_eq!(exit, 5, "the replaced invite: {transcript}");
    let (exit, transcript) = join_from(&home, &second, &[]);
    assert_eq!(exit, 0, "{transcript}");
}

/// A server on an operator certificate has no pin, so its invite names
/// none: the join trusts the certificate through the system store or
/// `--tls-ca`, whose anchor the installation keeps for later commands.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_certificate_invite_trusts_the_certificate() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: join: no client payload for this platform");
        return;
    }
    let (cert, key) = crate::harness::stage_tls_pair(&scratch("join-operator-certificate-certs"));
    let operator = Operator::start_with(
        "join-operator-certificate",
        Setup {
            mitm: true,
            data_plane: format!(
                "tls_certificate_file = \"{}\"\ntls_private_key_file = \"{}\"\n",
                cert.display(),
                key.display()
            ),
            ..Setup::default()
        },
    )
    .await;
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let fields = decode_invite(&invite);
    assert!(fields["identity"].is_null(), "{fields}");
    assert_eq!(
        fields["base_url"],
        format!("https://{}", operator.instance.addr),
        "{fields}"
    );

    let home = fresh_home("join-operator-certificate-engineer");
    let (exit, transcript) = join_from(&home, &invite, &[]);
    assert_eq!(exit, 4, "an untrusted certificate: {transcript}");
    assert!(nothing_installed(&home), "{transcript}");

    let anchor =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance/fixtures/tls/test-ca.pem");
    let env = isolated_env(&home);
    let (exit, stdout, stderr) = cli_raw(
        &["--tls-ca", &anchor.display().to_string(), "join", &invite],
        &env,
        None,
    );
    assert_eq!(exit, 0, "{stdout}{stderr}");
    assert!(stderr.contains("(certificate trusted)"), "{stderr}");
    let client_dir = config_root(&home).join("client");
    assert_eq!(
        std::fs::read(client_dir.join("base-url-ca.pem")).expect("the kept anchor"),
        std::fs::read(&anchor).expect("the test CA")
    );
    assert!(client_toml(&home).get("server_identity").is_none());
    let (exit, stdout, stderr) = cli_raw(&["status", "--client"], &env, None);
    assert_eq!(
        exit, 0,
        "later commands trust the kept anchor: {stdout}{stderr}"
    );
}

/// A server offering no kit gets the joining executable itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_without_a_kit_gets_this_executable() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: join: no client payload for this platform");
        return;
    }
    let operator = Operator::start("join-no-kit").await;
    std::fs::remove_file(operator.kit_path()).expect("remove the kit");
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let home = fresh_home("join-no-kit-engineer");
    let (exit, transcript) = join_from(&home, &invite, &[]);
    assert_eq!(exit, 0, "{transcript}");
    assert!(
        transcript.contains("this server offers no client kit"),
        "{transcript}"
    );
    let executable = if cfg!(windows) {
        let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA"));
        local.join("Programs/Jaynshare/jaynshare.exe")
    } else {
        config_root(&home).join("bin/jaynshare")
    };
    assert!(
        std::fs::read(&executable).expect("the executable")
            == std::fs::read(binary()).expect("this build"),
        "the joining executable is installed"
    );
}
