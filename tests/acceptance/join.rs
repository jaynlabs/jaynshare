//! `client invite` and `join`: a machine becomes a pool client with one
//! command, on the server the invite names and with the client the invite's
//! key signed, or not at all; then the engineer's Claude account joins the
//! pool too, unless the invite says otherwise.

use std::path::{Path, PathBuf};

use base64::Engine as _;

use crate::acc::callback_target;
use crate::enrol::{
    Operator, client_platform, config_root, decode_invite, encode_invite, identity_setup,
    installed_binary, join_from, kit_member_bytes, native_payload,
};
use crate::fake_tools::FakeTools;
use crate::harness::{
    Duration, Instant, Setup, StatusCode, Value, binary, cli_pty_answers, cli_raw, isolated_env,
    json, private_dir, scratch, send, validate,
};
use crate::own::callback_request;
use crate::profile_fx::path_editor;
use crate::release_fx::ReleaseKey;

const OTHER_PIN: &str = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const QUESTION: &str = "Add your Claude account to the pool? [Y/n] ";
const ACCOUNT_LATER: &str =
    "add your Claude account to the pool later with `jaynshare account login`";

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
/// search path; with no terminal the account step is named for later; the
/// code lands nowhere; and `uninstall` takes the link back.
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
        ACCOUNT_LATER.to_string(),
    ] {
        assert!(transcript.contains(&line), "{line}: {transcript}");
    }
    assert!(!transcript.contains(QUESTION), "{transcript}");
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
    let executable = installed_binary(&home);
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
    if cfg!(windows) {
        let edits = path_editor(&home).calls("powershell");
        assert_eq!(edits.len(), 1, "{edits:?}");
        assert!(
            edits[0].iter().any(|arg| arg.contains("$p + $d")),
            "the user Path gains the folder: {edits:?}"
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
    if cfg!(windows) {
        let edits = path_editor(&home).calls("powershell");
        assert_eq!(edits.len(), 2, "{edits:?}");
        assert!(
            edits[1].iter().any(|arg| arg.contains("-ne $d")),
            "the user Path loses the folder: {edits:?}"
        );
    }

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

/// The signed macOS bootstrap downloads the official client archive, checks
/// it, and uses that binary to join a local server.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
async fn shell_bootstrap_joins_a_local_server() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start("join-shell-bootstrap").await;
    let invite = operator.invite("bootstrap", "Bootstrap client", &[]);
    let bootstrap = Bootstrap::serve("join-shell-bootstrap-release").await;
    let home = fresh_home("join-shell-bootstrap-engineer");
    let output = std::process::Command::new("sh")
        .arg(&bootstrap.script)
        .args(bootstrap.args(&invite))
        .envs(isolated_env(&home))
        .env_remove("JAYNSHARE_CONFIG")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("NO_PROXY")
        .env_remove("https_proxy")
        .env_remove("http_proxy")
        .env_remove("no_proxy")
        .output()
        .expect("run install.sh");
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{transcript}");
    assert!(
        transcript.contains("joined the pool as bootstrap (Bootstrap client)"),
        "{transcript}"
    );
    assert!(config_root(&home).join("client/client.toml").is_file());
}

/// A release carrying this build, served with its `install.sh`.
#[cfg(target_os = "macos")]
struct Bootstrap {
    script: PathBuf,
    origin: String,
    ca: PathBuf,
}

#[cfg(target_os = "macos")]
impl Bootstrap {
    async fn serve(scenario: &str) -> Self {
        use crate::release_fx::{
            FIXTURE_VERSION, ReleaseKey, host_target, serve_release, with_platform_archive,
            write_release_of,
        };

        let release = scratch(scenario).join("release");
        let executable = std::fs::read(binary()).expect("the bootstrap executable");
        write_release_of(
            &release,
            &ReleaseKey::generate(),
            FIXTURE_VERSION,
            |parts| with_platform_archive(parts, host_target(), &executable),
            |_| {},
        );
        let (origin, ca) = serve_release(&release, "localhost", FIXTURE_VERSION).await;
        Self {
            script: release.join("install.sh"),
            origin,
            ca,
        }
    }

    /// `install.sh`'s arguments for this release and `invite`.
    fn args<'a>(&'a self, invite: &'a str) -> [&'a str; 7] {
        [
            "--version",
            crate::release_fx::FIXTURE_VERSION,
            "--release-origin",
            &self.origin,
            "--tls-ca",
            self.ca.to_str().expect("CA path"),
            invite,
        ]
    }
}

/// Piped into `sh`, as the one-line install runs it, the bootstrap's join
/// still asks the account question on the terminal.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
async fn a_piped_shell_bootstrap_asks_on_the_terminal() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start("join-piped-bootstrap").await;
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let bootstrap = Bootstrap::serve("join-piped-bootstrap-release").await;
    let home = fresh_home("join-piped-bootstrap-engineer");
    let script = bootstrap.script.display().to_string();
    let argv = [
        &["/bin/sh", "-c", "cat \"$0\" | sh -s -- \"$@\"", &script][..],
        &bootstrap.args(&invite),
    ]
    .concat();
    let no_proxy = ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]
        .map(|name| (name.to_string(), String::new()));
    let (exit, transcript) = crate::harness::pty_answers(
        "join-piped-bootstrap-terminal",
        &argv,
        &[isolated_env(&home), no_proxy.to_vec()].concat(),
        &[(QUESTION, "n\n")],
    );
    assert_eq!(exit, 0, "{transcript}");
    assert!(transcript.contains(ACCOUNT_LATER), "{transcript}");
}

/// An invite claims once: the second machine is refused and installs
/// nothing; one past its expiry is refused the same way.
#[cfg(unix)]
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
                "tls_certificate_file = {}\ntls_private_key_file = {}\n",
                crate::harness::toml_path(&cert),
                crate::harness::toml_path(&key)
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
    let executable = installed_binary(&home);
    assert!(
        std::fs::read(&executable).expect("the executable")
            == std::fs::read(binary()).expect("this build"),
        "the joining executable is installed"
    );
}

/// The account step on a terminal, with `open` scripted by `answer`: the
/// fake answers for the browser. The server offers no kit, so the client
/// the join installs and re-runs is this build.
struct AccountStep {
    operator: Operator,
    home: PathBuf,
    browser: FakeTools,
}

impl AccountStep {
    async fn start(scenario: &str) -> Self {
        let operator = Operator::start(scenario).await;
        std::fs::remove_file(operator.kit_path()).expect("remove the kit");
        let home = fresh_home(&format!("{scenario}-engineer"));
        let browser = FakeTools::new(home.parent().expect("a scratch root"), &["open"]);
        Self {
            operator,
            home,
            browser,
        }
    }

    fn env(&self) -> Vec<(String, String)> {
        [isolated_env(&self.home), self.browser.env()].concat()
    }

    /// The account the step added, as the operator sees it.
    fn account(&self) -> Value {
        let accounts = self.operator.instance.status()["accounts"].clone();
        assert_eq!(accounts.as_array().map(Vec::len), Some(1), "{accounts}");
        accounts[0].clone()
    }
}

/// Whether this machine can drive the step: a client platform with a
/// `script` for the terminal.
fn account_step_platform() -> bool {
    client_platform() && cfg!(unix)
}

/// Answered yes, the step opens the browser on the login the installed
/// client started; the callback it catches is forwarded, and the account
/// is the engineer's own.
#[tokio::test(flavor = "multi_thread")]
async fn a_join_adds_the_engineer_s_account_through_the_browser_callback() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !account_step_platform() {
        eprintln!("skipping: join: the account step needs a client platform with `script`");
        return;
    }
    let step = AccountStep::start("join-account-callback").await;
    let invite = step.operator.invite("alpha", "Alpha Desk", &[]);
    let env = step.env();
    let join = std::thread::spawn(move || {
        cli_pty_answers(
            "join-account-callback-terminal",
            &["join", &invite],
            &env,
            &[(QUESTION, "\n")],
        )
    });
    let url = opened_url(&step.browser).await;
    let (callback, state) = callback_target(&url);
    let browser = send(callback, callback_request(&state)).await;
    assert_eq!(browser.status, StatusCode::FOUND, "the success page");
    let (exit, transcript) = join.join().expect("the join");
    assert_eq!(exit, 0, "{transcript}");
    assert!(transcript.contains("login succeeded"), "{transcript}");
    assert!(
        transcript.contains("joined the pool as alpha (Alpha Desk)"),
        "{transcript}"
    );
    assert!(!transcript.contains(ACCOUNT_LATER), "{transcript}");
    let account = step.account();
    assert_eq!(account["owner"], "alpha", "{account}");
    assert_eq!(account["source_class"], "browser", "{account}");
}

/// The URL the installed client asked the fake browser to open.
async fn opened_url(browser: &FakeTools) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(call) = browser.calls("open").first() {
            return call[0].clone();
        }
        assert!(Instant::now() < deadline, "the browser was never opened");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// When no browser opens, the step asks for the code instead and forwards
/// the paste.
#[tokio::test(flavor = "multi_thread")]
async fn a_join_without_a_browser_takes_the_pasted_code() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !account_step_platform() {
        eprintln!("skipping: join: the account step needs a client platform with `script`");
        return;
    }
    let step = AccountStep::start("join-account-paste").await;
    step.browser.rule("open", &[]).exit(1);
    let invite = step.operator.invite("alpha", "Alpha Desk", &[]);
    let (exit, transcript) = cli_pty_answers(
        "join-account-paste-terminal",
        &["join", &invite],
        &step.env(),
        &[
            (QUESTION, "\n"),
            ("paste the authorisation code", "oat-fixture-pasted\n"),
        ],
    );
    assert_eq!(exit, 0, "{transcript}");
    assert!(transcript.contains("login succeeded"), "{transcript}");
    assert!(!transcript.contains("oat-fixture-pasted"), "{transcript}");
    assert_eq!(step.account()["owner"], "alpha");
}

/// Answered no, nothing is added and the step is named for later.
#[tokio::test(flavor = "multi_thread")]
async fn a_join_answered_no_adds_no_account() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !account_step_platform() {
        eprintln!("skipping: join: the account step needs a client platform with `script`");
        return;
    }
    let step = AccountStep::start("join-account-declined").await;
    let invite = step.operator.invite("alpha", "Alpha Desk", &[]);
    let (exit, transcript) = cli_pty_answers(
        "join-account-declined-terminal",
        &["join", &invite],
        &step.env(),
        &[(QUESTION, "n\n")],
    );
    assert_eq!(exit, 0, "{transcript}");
    assert!(transcript.contains(ACCOUNT_LATER), "{transcript}");
    assert!(step.browser.calls("open").is_empty());
    let accounts = step.operator.instance.status()["accounts"].clone();
    assert_eq!(accounts, json!([]), "{accounts}");
}

/// A `--no-account` invite has no account step, even on a terminal, and
/// the server refuses the client a login while it owns no account.
#[tokio::test(flavor = "multi_thread")]
async fn a_no_account_invite_skips_the_account_step() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !account_step_platform() {
        eprintln!("skipping: join: the account step needs a client platform with `script`");
        return;
    }
    let step = AccountStep::start("join-no-account").await;
    let invite = step
        .operator
        .invite("alpha", "Alpha Desk", &["--no-account"]);
    let (exit, transcript) = cli_pty_answers(
        "join-no-account-terminal",
        &["join", &invite],
        &step.env(),
        &[],
    );
    assert_eq!(exit, 0, "{transcript}");
    assert!(!transcript.contains(QUESTION), "{transcript}");
    assert!(!transcript.contains("account login"), "{transcript}");

    let (exit, stdout, stderr) = cli_raw(&["account", "login"], &step.env(), None);
    assert_eq!(exit, 5, "{stdout}{stderr}");
    assert!(
        stderr.contains("adds no account of its own, and it owns none"),
        "{stderr}"
    );
    assert!(step.browser.calls("open").is_empty());
    assert_eq!(step.operator.instance.status()["accounts"], json!([]));
}

/// The step re-runs the installed client as `account login`; when that
/// fails, the step fails and not the join, and the warning names the retry.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_account_step_leaves_the_join_standing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !account_step_platform() {
        eprintln!("skipping: join: the account step needs a client platform with `script`");
        return;
    }
    let operator = Operator::start("join-account-failed").await;
    let failing = b"#!/bin/sh\necho \"the installed client ran: $*\"\nexit 3\n";
    let kit = operator.kit_with_payload(native_payload(), failing);
    std::fs::copy(kit, operator.kit_path()).expect("the server's kit");
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let home = fresh_home("join-account-failed-engineer");
    let (exit, transcript) = cli_pty_answers(
        "join-account-failed-terminal",
        &["join", &invite],
        &isolated_env(&home),
        &[(QUESTION, "\n")],
    );
    assert_eq!(exit, 0, "{transcript}");
    for line in [
        "the installed client ran: account login",
        "warning: no Claude account was added; run `jaynshare account login` to try again",
        "joined the pool as alpha (Alpha Desk)",
    ] {
        assert!(transcript.contains(line), "{line}: {transcript}");
    }
}
