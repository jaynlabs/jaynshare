//! The MITM CA scenarios: CA generation and rotation, the start-time check,
//! and the trust material the proxy serves.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData as _};
use sha2::{Digest, Sha256};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::parse_x509_pem;

use crate::harness::{
    Instant, Value, binary, json, private_dir, reserve_port, scratch, write_private,
};

/// The state directory files fixes.
const CA_CERT_FILE: &str = "mitm-ca.pem";
const LEAF_CERT_FILE: &str = "mitm-leaf.pem";
const LEAF_KEY_FILE: &str = "mitm-leaf-key.pem";

// A local instance
// `Setup` carries no `[mitm]` lines and `harness.rs` is not this sweep's to
// edit, so the scenarios here start the binary directly over their own
// configuration document.

struct MitmInstance {
    root: PathBuf,
    config: PathBuf,
    child: Option<Child>,
    faults: Option<std::sync::Arc<crate::faults::Faults>>,
}

fn spawn(scenario: &str, faults: Option<std::sync::Arc<crate::faults::Faults>>) -> MitmInstance {
    let _guard = crate::harness::PORT_HANDOFF
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let port = reserve_port();
    let mitm_port = reserve_port();
    let root = scratch(scenario);
    private_dir(&root.join("state"));
    private_dir(&root.join("log"));
    let config = root.join("config.toml");
    write_private(
        &config,
        &format!(
            "version = 1\n\n\
             [data_plane]\n\
             listen = \"127.0.0.1:{port}\"\n\n\
             [mitm]\n\
             enabled = true\n\
             listen = \"127.0.0.1:{mitm_port}\"\n\n\
             [storage]\n\
             state_file = \"{}\"\n\n\
             [logging]\n\
             directory = \"{}\"\n\
             level = \"debug\"\n",
            root.join("state/state.json").display(),
            root.join("log").display(),
        ),
    );
    let mut command = Command::new(binary());
    command
        .args(["--config", &config.display().to_string(), "serve"])
        .env("PATH", root.join("no-browser-on-path"))
        .env("HOME", root.join("home"))
        .stdout(Stdio::from(
            fs::File::create(root.join("stdout.txt")).expect("stdout file"),
        ))
        .stderr(Stdio::from(
            fs::File::create(root.join("stderr.txt")).expect("stderr file"),
        ));
    if let Some(faults) = &faults {
        faults.inject(&mut command);
    }
    let child = command.spawn().expect("start the binary under test");
    let mut instance = MitmInstance {
        root,
        config,
        child: Some(child),
        faults,
    };
    instance.await_startup();
    drop(_guard);
    instance
}

impl MitmInstance {
    fn await_startup(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if self.stdout().contains("listening on") {
                return;
            }
            if let Some(status) = self
                .child
                .as_mut()
                .expect("child")
                .try_wait()
                .expect("try_wait")
            {
                panic!(
                    "the server exited during startup with {status}: {}",
                    self.stderr()
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "the server never printed its startup line: {}",
            self.stderr()
        );
    }

    fn stdout(&self) -> String {
        fs::read_to_string(self.root.join("stdout.txt")).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        fs::read_to_string(self.root.join("stderr.txt")).unwrap_or_default()
    }

    /// Idempotent: a scenario that stopped the instance itself still restarts.
    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        #[cfg(unix)]
        assert!(
            Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .expect("send SIGTERM")
                .success(),
            "SIGTERM was accepted"
        );
        #[cfg(not(unix))]
        child.kill().expect("stop child");
        child.wait().expect("wait for stopped child");
    }

    /// Respawns on the same configuration (the CA check runs again).
    fn restart(&mut self) {
        self.stop();
        let mut command = Command::new(binary());
        command
            .args(["--config", &self.config.display().to_string(), "serve"])
            .env("PATH", self.root.join("no-browser-on-path"))
            .env("HOME", self.root.join("home"))
            .stdout(Stdio::from(
                fs::File::create(self.root.join("stdout.txt")).expect("stdout file"),
            ))
            .stderr(Stdio::from(
                fs::File::create(self.root.join("stderr.txt")).expect("stderr file"),
            ));
        if let Some(faults) = &self.faults {
            faults.inject(&mut command);
        }
        self.child = Some(command.spawn().expect("restart the binary under test"));
        self.await_startup();
    }

    fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    fn server_log(&self) -> String {
        fs::read_to_string(self.root.join("log/server.ndjson")).unwrap_or_default()
    }

    /// The server log lines carrying this `event`, oldest first.
    fn events(&self, event: &str) -> Vec<Value> {
        self.server_log()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|line| line["event"] == event)
            .collect()
    }

    fn cli_json(&self, args: &[&str]) -> Value {
        let mut command = Command::new(binary());
        command
            .args(["--config", &self.config.display().to_string()])
            .args(args)
            .arg("--json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(faults) = &self.faults {
            faults.inject(&mut command);
        }
        let output = command.output().expect("run the CLI");
        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("CLI JSON envelope ({e}): {stdout}"))
    }

    fn status(&self) -> Value {
        self.cli_json(&["status"])["result"]["status"].clone()
    }
}

impl Drop for MitmInstance {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ------------------------------------------------------------------ certificate helpers

/// SHA-256 of the DER, colon-separated upper-case hex pairs.
fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
    hex.join(":")
}

pub(crate) fn ca_fingerprint(state_dir: &Path) -> String {
    let bytes = fs::read(state_dir.join(CA_CERT_FILE)).expect("read the CA file");
    let (_, pem) = parse_x509_pem(&bytes).expect("the CA file is PEM");
    fingerprint(&pem.contents)
}

pub(crate) fn dns_names(cert: &x509_parser::certificate::X509Certificate<'_>) -> Vec<String> {
    cert.extensions()
        .iter()
        .filter_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
        .flat_map(|san| san.general_names.iter())
        .filter_map(|gn| match gn {
            GeneralName::DNSName(d) => Some((*d).to_owned()),
            _ => None,
        })
        .collect()
}

// ------------------------------------------------------------------ scenarios

/// A fresh state
/// directory yields exactly three files with the modes, the CA private
/// key is on no disk file, the leaf carries the whole intercept set and
/// verifies against the CA, and both certificates are valid for 730 days
/// from an hour before generation.
#[tokio::test(flavor = "multi_thread")]
async fn fresh_state_directory_yields_the_three_trust_files() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = spawn("fresh-state-directory", None);
    let state_dir = instance.state_dir();

    // Exactly three files, and nothing that could hold the CA key.
    // The state document itself is written only once something mutates it,
    // and this instance carries no account, so it may be absent. The server
    // identity key is the listener's own, not the CA's.
    let mut names: Vec<String> = fs::read_dir(&state_dir)
        .expect("state dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name != "state.json" && name != "server-identity-key.pem")
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["mitm-ca.pem", "mitm-leaf-key.pem", "mitm-leaf.pem"],
        "exactly the three files beside the state file: {names:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |name: &str| {
            fs::metadata(state_dir.join(name))
                .expect("meta")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(CA_CERT_FILE), 0o644, "the CA is public");
        assert_eq!(mode(LEAF_CERT_FILE), 0o644, "the leaf is public");
        assert_eq!(mode(LEAF_KEY_FILE), 0o600, "the leaf key is private");
    }

    // No file ever holds the CA private key: the only key file is
    // the leaf's, and its public key is not the CA's.
    let key_bytes = fs::read(state_dir.join(LEAF_KEY_FILE)).expect("read the leaf key");
    let key_pair = KeyPair::from_pkcs8_pem_and_sign_algo(
        &String::from_utf8(key_bytes).expect("the leaf key is text"),
        &PKCS_ECDSA_P256_SHA256,
    )
    .expect("the leaf key is a P-256 key");
    let ca_bytes = fs::read(state_dir.join(CA_CERT_FILE)).expect("read the CA file");
    let (_, ca_pem) = parse_x509_pem(&ca_bytes).expect("the CA file is PEM");
    let ca = ca_pem.parse_x509().expect("the CA parses");
    let leaf_bytes = fs::read(state_dir.join(LEAF_CERT_FILE)).expect("read the leaf file");
    let (_, leaf_pem) = parse_x509_pem(&leaf_bytes).expect("the leaf file is PEM");
    let leaf = leaf_pem.parse_x509().expect("the leaf parses");
    assert_ne!(
        key_pair.der_bytes(),
        ca.tbs_certificate.subject_pki.subject_public_key.as_ref(),
        "the leaf key cannot sign a new certificate: the CA key is gone"
    );

    assert!(ca.is_ca(), "the CA carries the basic constraint");
    assert!(!leaf.is_ca(), "the leaf does not");
    leaf.verify_signature(Some(ca.public_key()))
        .expect("the leaf verifies against the CA under a chain check");
    // A strict (RFC 5280) chain check links the leaf to its issuer by key
    // identifier: Python 3.13+'s default context refuses a leaf without an
    // Authority Key Identifier (live D11, 2026-09-22).
    let ski = ca
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
            _ => None,
        });
    let aki = leaf
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|id| id.0.to_vec())
            }
            _ => None,
        });
    assert!(ski.is_some(), "the CA carries a Subject Key Identifier");
    assert_eq!(
        aki, ski,
        "the leaf's Authority Key Identifier names the CA's key (RFC 5280)"
    );
    let sans = dns_names(&leaf);
    assert_eq!(
        sans,
        ["api.anthropic.com", "probe.jaynshare.invalid"],
        "the leaf's SANs are exactly the intercept set"
    );

    // 730 days, starting an hour before generation.
    for cert in [&ca, &leaf] {
        let validity = cert.validity();
        let span = validity.not_after.to_datetime() - validity.not_before.to_datetime();
        assert_eq!(span.whole_days(), 730, "730-day validity");
        assert!(
            validity.not_before.to_datetime()
                < time::OffsetDateTime::now_utc() - time::Duration::minutes(30),
            "valid from at least an hour before generation, so a slow client clock still accepts it"
        );
    }
    instance.stop();
}

/// With the leaf key deleted the
/// server starts, logs an error naming the file and the rotate verb, shows
/// the `unusable` state, and never regenerates. The CONNECT- and
/// tunnelled-target halves of the row ride with the proxy listener
/// scenarios of the listener sweep.
#[tokio::test(flavor = "multi_thread")]
async fn deleted_leaf_key_is_unusable_never_regenerated() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = spawn("deleted-leaf-key", None);
    let fingerprint = ca_fingerprint(&instance.state_dir());
    instance.stop();
    fs::remove_file(instance.state_dir().join(LEAF_KEY_FILE)).expect("delete the leaf key");

    instance.restart();
    let error_line = instance
        .events("ca_unusable")
        .into_iter()
        .next()
        .expect("the start logs one error line for the unusable material");
    let rendered = error_line.to_string();
    assert!(
        rendered.contains(LEAF_KEY_FILE),
        "names the file: {rendered}"
    );
    assert!(rendered.contains("ca rotate"), "names the verb: {rendered}");
    assert_eq!(
        ca_fingerprint(&instance.state_dir()),
        fingerprint,
        "the check never regenerates"
    );
    let mitm = &instance.status()["mitm"];
    assert_eq!(mitm["ca"]["state"], "unusable", "the unusable state");
}

/// With the platform clock moved
/// inside the 30-day window, start logs the expiry warning and `status`
/// shows `expiring`; outside the window nothing is warned. The once-a-day
/// repetition and the real client's reaction are checked by hand.
#[tokio::test(flavor = "multi_thread")]
async fn expiry_warning_thirty_days_out() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let mut instance = spawn("expiry-warning-thirty", Some(faults.clone()));
    let not_after = {
        let bytes = fs::read(instance.state_dir().join(CA_CERT_FILE)).expect("read the CA file");
        let (_, pem) = parse_x509_pem(&bytes).expect("the CA file is PEM");
        let ca = pem.parse_x509().expect("the CA parses");
        ca.validity().not_after.to_datetime()
    };
    assert!(
        instance.events("ca_expiring").is_empty(),
        "no warning while the CA is fresh"
    );
    instance.stop();

    faults.set_time(not_after - time::Duration::days(29));
    instance.restart();
    let warning = instance
        .events("ca_expiring")
        .into_iter()
        .next()
        .expect("the expiry warning at start");
    assert_eq!(
        instance.status()["mitm"]["ca"]["state"],
        "expiring",
        "the expiring state"
    );
    assert!(
        warning.to_string().contains("rotate"),
        "the warning names the way out: {warning}"
    );
}

/// `ca rotate` stages the next CA in its own private file beside the
/// current material, and it stays staged across a restart.
#[tokio::test(flavor = "multi_thread")]
async fn a_staged_ca_survives_a_restart() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = spawn("staged-survives-restart", None);
    let current = ca_fingerprint(&instance.state_dir());
    let envelope = instance.cli_json(&["ca", "rotate", "--yes"]);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let next = envelope["result"]["next"].clone();
    assert_eq!(
        ca_fingerprint(&instance.state_dir()),
        current,
        "the current files stay"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let staged =
            fs::metadata(instance.state_dir().join("mitm-ca-next.pem")).expect("the staged file");
        assert_eq!(staged.permissions().mode() & 0o777, 0o600, "it holds a key");
    }
    instance.restart();
    let status = instance.status();
    assert_eq!(
        status["mitm"]["ca"]["fingerprint"],
        json!(current),
        "{status}"
    );
    assert_eq!(
        status["mitm"]["ca"]["next"], next,
        "still staged, same switch: {status}"
    );
}

/// `ca rotate --now` replaces all
/// three files, logs one line carrying the old and the new fingerprint, and
/// `status` shows the new one. The open-tunnel-keeps-its-leaf and
/// new-handshake halves ride with the proxy listener scenarios.
#[tokio::test(flavor = "multi_thread")]
async fn rotate_replaces_the_material_and_logs_both_fingerprints() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = spawn("rotate-replaces-material", None);
    let old = ca_fingerprint(&instance.state_dir());
    let old_files: Vec<String> = [CA_CERT_FILE, LEAF_CERT_FILE, LEAF_KEY_FILE]
        .map(|name| fs::read_to_string(instance.state_dir().join(name)).expect("old file"))
        .to_vec();

    let envelope = instance.cli_json(&["ca", "rotate", "--now", "--yes"]);
    assert_eq!(envelope["ok"], true, "the rotation applied: {envelope}");

    let rotated = instance
        .events("ca_rotated")
        .into_iter()
        .next()
        .expect("one rotation line");
    let rendered = rotated.to_string();
    assert!(
        rendered.contains(&old),
        "carries the old fingerprint: {rendered}"
    );
    let new = ca_fingerprint(&instance.state_dir());
    assert_ne!(new, old, "the CA changed");
    assert!(
        rendered.contains(&new),
        "carries the new fingerprint: {rendered}"
    );
    for (name, old_contents) in [CA_CERT_FILE, LEAF_CERT_FILE, LEAF_KEY_FILE]
        .iter()
        .zip(old_files)
    {
        assert_ne!(
            fs::read_to_string(instance.state_dir().join(name)).expect("new file"),
            old_contents,
            "{name} was replaced"
        );
    }
    let status = instance.status();
    assert_eq!(
        status["mitm"]["ca"]["fingerprint"],
        json!(new),
        "status shows the new CA"
    );
    let file_not_after = {
        let bytes = fs::read(instance.state_dir().join(CA_CERT_FILE)).expect("read the CA file");
        let (_, pem) = parse_x509_pem(&bytes).expect("the CA file is PEM");
        pem.parse_x509()
            .expect("the CA parses")
            .validity()
            .not_after
            .to_datetime()
    };
    let reported = time::OffsetDateTime::parse(
        status["mitm"]["ca"]["not_after"]
            .as_str()
            .expect("the expiry"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("RFC 3339");
    assert_eq!(
        reported, file_not_after,
        "the expiry shown is the rotated certificate's, not the clock's"
    );
}
