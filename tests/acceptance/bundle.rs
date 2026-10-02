//! The enrollment bundle and the client installation.
//!
//! Every test here needs a client kit the product will accept, so the
//! fixture mints its own minisign key pair per run and writes `release.pub`
//! under the test's home. The kit is built here in Rust;
//! `tools/make-client-kit.py` is the independent writer the same reader has
//! to accept, and its `--self-test` is the cross-check.
//!
//! The operator CLI's enrollment verbs are exercised elsewhere, so a pending
//! entry is created over the control plane and the CLI under test is only
//! the packaging and engineer half.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::harness::{
    Answer, Instance, Setup, SocketAddr, StatusCode, Value, binary, cli_pty, cli_pty_answers,
    cli_raw, control_post, isolated_env, json, private_dir, scratch, stage_tls_pair,
};

/// what a client kit carries besides the release set.
pub(crate) const KIT_MEMBERS: [&str; 8] = [
    "README.txt",
    "install-macos.sh",
    "uninstall-macos.sh",
    "install-windows.ps1",
    "uninstall-windows.ps1",
    "payload/macos-x86_64/jaynshare",
    "payload/macos-aarch64/jaynshare",
    "payload/windows-x86_64/jaynshare.exe",
];

/// the bundle root, member for member.
const BUNDLE_MEMBERS: [&str; 13] = [
    "manifest.json",
    "ca.pem",
    "release.json",
    "release.json.minisig",
    "SHA256SUMS",
    "README.txt",
    "install-macos.sh",
    "uninstall-macos.sh",
    "install-windows.ps1",
    "uninstall-windows.ps1",
    "payload/macos-x86_64/jaynshare",
    "payload/macos-aarch64/jaynshare",
    "payload/windows-x86_64/jaynshare.exe",
];

// ------------------------------------------------------------------ the release key and the kit

use crate::release_fx::{canonical, public_key_file, release_key_pair, sha256_hex, signature_file};

/// the configuration root under a scenario's home, where `release.pub`
/// sits until the release pipeline embeds the key.
pub(crate) fn config_root(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Jaynshare")
    } else {
        home.join(".config/jaynshare")
    }
}

/// Writes `release.pub` under `home`. Every machine that verifies a kit or a
/// bundle needs it — the operator packaging and the engineer installing alike
/// (a release build embeds it in the binary).
fn write_release_key(home: &Path, public: &[u8]) {
    let root = config_root(home);
    private_dir(&root);
    std::fs::write(root.join("release.pub"), public_key_file(public)).expect("release.pub");
}

/// Writes `release.pub` under `home` and returns the key pair that matches it.
fn plant_release_key(home: &Path) -> (Vec<u8>, Vec<u8>) {
    let (pkcs8, public) = release_key_pair();
    write_release_key(home, &public);
    (pkcs8, public)
}

/// The filler bytes each kit member carries (the payload member is the one
/// `native_payload` names).
pub(crate) fn kit_member_bytes(name: &str) -> Vec<u8> {
    format!("{name} of the acceptance client kit\n").into_bytes()
}

/// The release set (the manifest, signature and sums) for exactly
/// `members`, in archive order before the members.
fn kit_release_set(
    pkcs8: &[u8],
    public: &[u8],
    members: &[(String, Vec<u8>)],
) -> Vec<(String, Vec<u8>)> {
    let member_map: Vec<Value> = members
        .iter()
        .map(|(name, bytes)| {
            json!({ "path": name, "length": bytes.len(), "sha256": sha256_hex(bytes) })
        })
        .collect();
    let sums: Vec<u8> = members
        .iter()
        .flat_map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)).into_bytes())
        .collect();
    let release = json!({
        "schema_version": 1,
        "version": "0.0.0-acceptance",
        "commit": "acceptance",
        "sha256sums_sha256": sha256_hex(&sums),
        "artifacts": [{ "purpose": "client-kit", "members": member_map }],
    });
    let release_bytes = canonical(&release);
    vec![
        ("release.json".to_string(), release_bytes.clone()),
        (
            "release.json.minisig".to_string(),
            signature_file(pkcs8, public, &release_bytes),
        ),
        ("SHA256SUMS".to_string(), sums),
    ]
}

/// Writes the ZIP file itself: one flat archive, stored, in order.
fn write_kit_archive(path: &Path, all: &[(String, Vec<u8>)]) {
    let file = std::fs::File::create(path).expect("create the kit");
    let mut archive = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in all {
        use std::io::Write as _;
        archive.start_file(name, options).expect("start member");
        archive.write_all(bytes).expect("write member");
    }
    archive.finish().expect("finish the kit");
}

/// A second valid kit whose members are given, signed as it is
/// written (the release set binds these digests, so the kit verifies).
pub(crate) fn write_kit_members(
    path: &Path,
    pkcs8: &[u8],
    public: &[u8],
    members: &[(String, Vec<u8>)],
) {
    let mut all = kit_release_set(pkcs8, public, members);
    all.extend(members.to_vec());
    write_kit_archive(path, &all);
}

/// A client kit ZIP the product accepts: the members, a `release.json`
/// binding every one of them, `SHA256SUMS` agreeing with it, and a signature
/// over the manifest bytes. `damage` is applied to the member map just before
/// the archive is written, which is how each tampered class is produced.
fn write_kit(
    path: &Path,
    pkcs8: &[u8],
    public: &[u8],
    damage: impl FnOnce(&mut Vec<(String, Vec<u8>)>),
) {
    let mut members: Vec<(String, Vec<u8>)> = KIT_MEMBERS
        .iter()
        .map(|name| ((*name).to_string(), kit_member_bytes(name)))
        .collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    let mut all = kit_release_set(pkcs8, public, &members);
    all.extend(members);
    damage(&mut all);
    write_kit_archive(path, &all);
}

/// The valid kit every happy path uses.
pub(crate) fn good_kit(dir: &Path, pkcs8: &[u8], public: &[u8]) -> PathBuf {
    let path = dir.join("client-kit.zip");
    write_kit(&path, pkcs8, public, |_| {});
    path
}

/// Reads a ZIP into (name, bytes) pairs, in archive order.
fn read_zip(path: &Path) -> Vec<(String, Vec<u8>)> {
    let file = std::fs::File::open(path).expect("open the archive");
    let mut archive = zip::ZipArchive::new(file).expect("read the archive");
    (0..archive.len())
        .map(|i| {
            use std::io::Read as _;
            let mut entry = archive.by_index(i).expect("member");
            let name = entry.name().to_string();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).expect("member bytes");
            (name, bytes)
        })
        .collect()
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

fn mitm_setup() -> Setup {
    Setup {
        mitm: true,
        ..Setup::default()
    }
}

/// An operator instance plus its own home, so the CLI under test resolves
/// `release.pub` and the client directory under the scenario's root.
pub(crate) struct Operator {
    pub(crate) instance: Instance,
    scenario: String,
    home: PathBuf,
    out: PathBuf,
    kit: PathBuf,
    pkcs8: Vec<u8>,
    public: Vec<u8>,
}

impl Operator {
    /// A scenario that needs a non-default setup (e.g. MITM on).
    pub(crate) async fn start_with(scenario: &str, setup: Setup) -> Operator {
        let instance = Instance::start_with(scenario, setup).await;
        Self::finish(scenario, instance).await
    }

    /// MITM on: every enrollment is MITM mode, so its bundle carries the
    /// proxy origin and the CA.
    pub(crate) async fn start(scenario: &str) -> Operator {
        let instance = Instance::start_with(scenario, mitm_setup()).await;
        Self::finish(scenario, instance).await
    }

    /// An instance under the write-boundary fixture.
    async fn start_with_faults(scenario: &str, faults: Arc<crate::faults::Faults>) -> Operator {
        let instance = Instance::start_with_faults(scenario, mitm_setup(), faults).await;
        Self::finish(scenario, instance).await
    }

    async fn finish(scenario: &str, instance: Instance) -> Operator {
        let root = scratch(&format!("{scenario}-operator"));
        let home = root.join("home");
        private_dir(&home);
        let out = root.join("out");
        private_dir(&out);
        let (pkcs8, public) = plant_release_key(&home);
        let kit = good_kit(&root, &pkcs8, &public);
        Operator {
            instance,
            scenario: scenario.to_string(),
            home,
            out,
            kit,
            pkcs8,
            public,
        }
    }

    fn env(&self) -> Vec<(String, String)> {
        isolated_env(&self.home)
    }

    /// One operator CLI run against this instance, with the scenario's home
    /// so `release.pub` resolves under it.
    pub(crate) fn cli(&self, args: &[&str]) -> (i32, String, String) {
        let owned = self.env();
        let pairs: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.instance.cli_env(args, None, &pairs)
    }

    /// One raw control GET on this instance (the loopback operator's).
    async fn ctl_get(&self, path: &str) -> Answer {
        let request = crate::harness::Request::builder()
            .method(crate::harness::Method::GET)
            .uri(path)
            .body(crate::harness::Full::new(crate::harness::Bytes::new()))
            .expect("control request builds");
        crate::harness::send(self.instance.addr, request).await
    }
    /// the pending entry the packaging verbs work from.
    async fn issue(&self, id: &str, name: &str) -> Value {
        let answer = control_post(
            self.instance.addr,
            "/control/v1/clients",
            &[],
            json!({ "id": id, "display_name": name }),
        )
        .await;
        assert_eq!(answer.status, StatusCode::CREATED, "issue {id}: {answer:?}");
        answer.json()
    }
}

/// The packaged bundle carries the tree and the
/// manifest, its integrity data is the kit's byte-for-byte, the archive and
/// the code file are owner-only, and a second packaging refuses rather than
/// overwriting.
#[tokio::test(flavor = "multi_thread")]
async fn the_bundle_is_inspectable_owner_only_and_never_overwritten() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start("bundle-inspectable-owner").await;
    let issued = operator.issue("alpha", "Alpha Desk").await;
    let generation = issued["client"]["generation"].as_u64().expect("generation");

    let (code, stdout, stderr) = operator.cli(&[
        "client",
        "bundle",
        "alpha",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
        "--json",
    ]);
    assert_eq!(code, 0, "packaging: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the CLI envelope");
    assert_eq!(envelope["ok"], true, "{envelope}");
    let archive = PathBuf::from(
        envelope["result"]["archive"]
            .as_str()
            .expect("the archive path"),
    );
    assert_eq!(
        archive.file_name().and_then(|n| n.to_str()),
        Some(format!("jaynshare-client-alpha-g{generation}.zip").as_str()),
        "the name"
    );

    // The bundle root holds exactly these members.
    let members = read_zip(&archive);
    let names: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, BUNDLE_MEMBERS, "the bundle tree");

    // The manifest names the client, the origin and the release.
    let manifest: Value = serde_json::from_slice(
        &members
            .iter()
            .find(|(n, _)| n == "manifest.json")
            .expect("manifest.json")
            .1,
    )
    .expect("the manifest parses");
    assert_eq!(manifest["client_id"], "alpha");
    assert_eq!(manifest["display_name"], "Alpha Desk");
    assert_eq!(manifest["generation"], json!(generation));
    assert_eq!(
        manifest["origins"]["base_url"],
        json!(format!("http://{}", operator.instance.addr))
    );
    assert!(
        manifest["pending_expires_at"].is_string(),
        "the expiry travels with the bundle: {manifest}"
    );
    // The kit this bundle was packaged from, and every payload's
    // target and digest.
    assert_eq!(
        manifest["kit"]["file"],
        json!(
            operator
                .kit
                .file_name()
                .and_then(|n| n.to_str())
                .expect("kit name")
        )
    );
    assert_eq!(
        manifest["kit"]["sha256"],
        json!(sha256_hex(
            &std::fs::read(&operator.kit).expect("kit bytes")
        ))
    );
    let targets: Vec<&str> = manifest["payloads"]
        .as_array()
        .expect("payloads")
        .iter()
        .map(|p| p["target"].as_str().expect("target"))
        .collect();
    assert_eq!(
        targets,
        ["macos-x86_64", "macos-aarch64", "windows-x86_64"],
        "one entry per supported client target"
    );
    // The bundle carries no endpoint path;: the CA facts every
    // enrollment needs (every launch is MITM mode).
    assert!(manifest["ca"]["fingerprint"].is_string(), "{manifest}");
    assert!(
        !manifest.to_string().contains("/control/v1"),
        "no endpoint path: {manifest}"
    );
    // No code and no secret is anywhere in the archive.
    for (name, bytes) in &members {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains("enrollment_code") && !text.contains("client_secret"),
            "{name} carries a disclosure"
        );
    }

    // The release set is copied from the kit byte-for-byte.
    let kit = read_zip(&operator.kit);
    for name in ["release.json", "release.json.minisig", "SHA256SUMS"] {
        let from_kit = &kit.iter().find(|(n, _)| n == name).expect(name).1;
        let in_bundle = &members.iter().find(|(n, _)| n == name).expect(name).1;
        assert_eq!(from_kit, in_bundle, "{name} is copied byte-for-byte");
    }

    // Owner-only, and the code file is separate from the archive.
    #[cfg(unix)]
    assert_eq!(mode_of(&archive), 0o600, "the archive is owner-only");
    assert!(
        envelope["result"]["code_file"].is_null(),
        "`client bundle` packages an already-issued entry, so it discloses nothing again"
    );

    //A second packaging refuses rather than overwriting.
    let (code, _, stderr) = operator.cli(&[
        "client",
        "bundle",
        "alpha",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
    ]);
    assert_eq!(code, 8, "overwrite refused: {stderr}");
    assert!(archive.is_file(), "the first bundle still stands");
}

/// The claim install leaves the files and nothing else, the
/// secret is owner-only, and a claim the server refuses leaves no partial
/// enrollment behind.
#[tokio::test(flavor = "multi_thread")]
async fn the_claim_installs_only_allowed_facts_or_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("claim-installs-allowed").await;
    let issued = operator.issue("alpha", "Alpha Desk").await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("the code is disclosed once")
        .to_string();
    let bundle_dir = package_and_extract(&operator, "alpha").await;

    // A refused claim first: the wrong code leaves no installation at all
    // ( — the code is never retried, so nothing may survive).
    let engineer = scratch("claim-installs-allowed-engineer");
    let home = engineer.join("home");
    private_dir(&home);
    write_release_key(&home, &operator.public);
    let env = isolated_env(&home);
    let (exit, transcript) = cli_pty_answers(
        "claim-installs-allowed-refused",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", "not-the-code\n"),
        ],
    );
    assert_eq!(exit, 5, "the server refuses the claim: {transcript}");
    let client_dir = config_root(&home).join("client");
    assert!(
        !client_dir.exists(),
        "a failed claim leaves no partial enrollment: {}",
        client_dir.display()
    );

    // Now the real one: confirm, then the code at the hidden prompt.
    let (exit, transcript) = cli_pty_answers(
        "claim-installs-allowed-claim",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    );
    assert_eq!(exit, 0, "the claim installs: {transcript}");
    assert!(
        client_dir.join("client.toml").is_file(),
        "the client.toml: {transcript}"
    );
    let secret = client_dir.join("client-secret");
    assert!(secret.is_file(), "the client-secret");
    #[cfg(unix)]
    assert_eq!(mode_of(&secret), 0o600, "the secret is owner-only");

    // Only allowed facts. The installation names the client and the
    // origin; it never carries the enrollment code.
    let toml = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    assert!(toml.contains("client_id = \"alpha\""), "{toml}");
    assert!(
        !toml.contains("mode ="),
        "no transport mode is recorded: {toml}"
    );
    assert!(
        !toml.contains(&code),
        "the code never lands on disk: {toml}"
    );
}

/// Packages `id`'s pending bundle and extracts it, the way an engineer's
/// machine receives it (reads an extracted directory).
async fn package_and_extract(operator: &Operator, id: &str) -> PathBuf {
    let (code, stdout, stderr) = operator.cli(&[
        "client",
        "bundle",
        id,
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
        "--json",
    ]);
    assert_eq!(code, 0, "packaging {id}: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    let archive = PathBuf::from(envelope["result"]["archive"].as_str().expect("archive"));
    let extracted = archive.with_extension("extracted");
    let _ = std::fs::remove_dir_all(&extracted);
    private_dir(&extracted);
    for (name, bytes) in read_zip(&archive) {
        let path = extracted.join(&name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("bundle subdirectory");
        }
        std::fs::write(&path, bytes).expect("extract member");
    }
    extracted
}

/// The client directory holds exactly the files with the
/// stated modes, and a rotation replaces `client-secret` in place without
/// disturbing the rest.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_directory_holds_exactly_its_files() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("client-directory-holds").await;
    let (home, _installed) = enrol_one(&operator, "alpha", "Alpha Desk").await;
    let client_dir = config_root(&home).join("client");

    // Every enrollment is MITM mode, so the installation carries
    // `ca.pem` beside the other two.
    let mut names: Vec<String> = std::fs::read_dir(&client_dir)
        .expect("client directory")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["ca.pem", "client-secret", "client.toml"],
        "the files"
    );
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&client_dir), 0o700, "the directory is private");
        assert_eq!(mode_of(&client_dir.join("client-secret")), 0o600);
    }

    //A rotation replaces the secret file and leaves the rest alone.
    let before = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    let rotated = rotate_secret(&operator, "alpha").await;
    let env = isolated_env(&home);
    let (exit, _, stderr) = cli_raw(&["secret", "set", "--stdin"], &env, Some(&rotated));
    assert_eq!(exit, 0, "the rotated secret installs: {stderr}");
    assert_eq!(
        std::fs::read_to_string(client_dir.join("client-secret"))
            .expect("client-secret")
            .trim(),
        rotated,
        "the file holds the secret alone"
    );
    #[cfg(unix)]
    assert_eq!(
        mode_of(&client_dir.join("client-secret")),
        0o600,
        "still owner-only after the replacement"
    );
    assert_eq!(
        std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml"),
        before,
        "only one file is replaced"
    );
}

/// Issues, packages and claims one client; returns the engineer's home and
/// the secret the claim disclosed.
pub(crate) async fn enrol_one(operator: &Operator, id: &str, name: &str) -> (PathBuf, String) {
    let home = scratch(&format!("{}-engineer", operator.scenario)).join("home");
    private_dir(&home);
    let secret = enrol_into(operator, id, name, &home).await;
    (home, secret)
}

/// The same into a home the scenario prepared (a `.claude/settings.json`
/// already there, the documented behaviour), asserting exit 0; returns the secret.
pub(crate) async fn enrol_into(operator: &Operator, id: &str, name: &str, home: &Path) -> String {
    let (exit, transcript) = try_enrol_into(operator, id, name, home).await;
    assert_eq!(exit, 0, "enrol {id}: {transcript}");
    std::fs::read_to_string(config_root(home).join("client/client-secret")).expect("client-secret")
}

/// One `enrol --bundle` of a freshly issued `id` into `home`, answering the
/// confirmation and the code on a pseudo-terminal: exit code and transcript.
pub(crate) async fn try_enrol_into(
    operator: &Operator,
    id: &str,
    name: &str,
    home: &Path,
) -> (i32, String) {
    let issued = operator.issue(id, name).await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let bundle_dir = package_and_extract(operator, id).await;
    write_release_key(home, &operator.public);
    let env = isolated_env(home);
    cli_pty_answers(
        &format!("{}-enrol-{id}", operator.scenario),
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    )
}

/// An `enrol --bundle` into `home` that is expected to stop after the
/// confirmation and before the code prompt (the staged checks, e.g. an
/// invalid Claude Code settings file): exit code and transcript. The
/// enrollment code stays unspent.
#[allow(dead_code)] // the enrollment-refusal scenarios use it
pub(crate) async fn enrol_refused_after_confirm(
    operator: &Operator,
    id: &str,
    name: &str,
    home: &Path,
) -> (i32, String) {
    operator.issue(id, name).await;
    let bundle_dir = package_and_extract(operator, id).await;
    write_release_key(home, &operator.public);
    let env = isolated_env(home);
    cli_pty_answers(
        &format!("{}-enrol-refused-{id}", operator.scenario),
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[("install this enrollment?", "y\n")],
    )
}

/// rotate `id` over the control plane and return the new secret.
async fn rotate_secret(operator: &Operator, id: &str) -> String {
    let answer = control_post(
        operator.instance.addr,
        &format!("/control/v1/clients/{id}/rotate"),
        &[],
        json!({}),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "rotate {id}: {answer:?}");
    answer.json()["client_secret"]
        .as_str()
        .expect("the new secret, disclosed once")
        .to_string()
}

/// `status` takes its role from the machine: a client directory
/// alone gives the client form, a configuration alone the operator form,
/// `--client` with no installation exits 11, and `--server` is always the
/// operator.
#[tokio::test(flavor = "multi_thread")]
async fn status_takes_its_role_from_the_machine() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("status-takes-role").await;

    // No installation and no configuration: `--client` names the missing
    // file and the installer to run.
    let bare = scratch("status-takes-role-bare").join("home");
    private_dir(&bare);
    let bare_env = isolated_env(&bare);
    let (exit, stdout, stderr) = cli_raw(&["status", "--client", "--json"], &bare_env, None);
    assert_eq!(exit, 11, "not enrolled: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["error"]["code"], "cli_not_enrolled", "{envelope}");

    // A client directory alone: the client form, the body.
    let (home, _) = enrol_one(&operator, "alpha", "Alpha Desk").await;
    let env = isolated_env(&home);
    let (exit, stdout, stderr) = cli_raw(&["status", "--json"], &env, None);
    assert_eq!(exit, 0, "the client form: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["result"]["client"]["id"], "alpha", "{envelope}");
    assert_eq!(envelope["role"], "client", "the role: {envelope}");
    // plus `client.origins`: the allow-list and nothing else.
    assert!(
        envelope["result"]["client"]["origins"]["base_url"].is_string(),
        "{envelope}"
    );
    assert!(
        envelope["result"]["accounts"].is_null(),
        "the client projection carries no operator facts: {envelope}"
    );

    // A configuration alone: the operator form, which carries the pool.
    let (exit, stdout, stderr) = operator.cli(&["status", "--json"]);
    assert_eq!(exit, 0, "the operator form: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert!(
        envelope["result"]["status"]["accounts"].is_array(),
        "the operator projection: {envelope}"
    );
}

/// `client enrol` refuses an unverifiable kit before it touches
/// the registry, a world-readable `--out` is refused, and `client bundle` on
/// an entry that is not pending is a conflict.
#[tokio::test(flavor = "multi_thread")]
async fn enrol_refuses_before_it_changes_the_registry() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start("enrol-refuses-changes").await;
    let registry = |addr: SocketAddr| async move {
        let answer =
            crate::harness::control(addr, http::Method::GET, "/control/v1/clients", &[], None)
                .await;
        assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
        answer.json()["clients"]
            .as_array()
            .expect("the registry")
            .len()
    };
    let before = registry(operator.instance.addr).await;

    // Each tampered class: an unsigned manifest, a changed payload and a
    // missing member. All are exit 17 and none creates a pending entry.
    let root = operator.kit.parent().expect("kit directory").to_path_buf();
    type Tamper = Box<dyn FnOnce(&mut Vec<(String, Vec<u8>)>)>;
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "signature",
            Box::new(|members: &mut Vec<(String, Vec<u8>)>| {
                let entry = members
                    .iter_mut()
                    .find(|(n, _)| n == "release.json.minisig")
                    .expect("the signature");
                entry.1 = b"untrusted comment: signature\nAAAA\n".to_vec();
            }),
        ),
        (
            "payload",
            Box::new(|members: &mut Vec<(String, Vec<u8>)>| {
                let entry = members
                    .iter_mut()
                    .find(|(n, _)| n == "payload/macos-aarch64/jaynshare")
                    .expect("a payload");
                entry.1 = b"a different executable".to_vec();
            }),
        ),
        (
            "missing",
            Box::new(|members: &mut Vec<(String, Vec<u8>)>| {
                members.retain(|(n, _)| n != "install-macos.sh");
            }),
        ),
    ];
    for (what, damage) in cases {
        let path = root.join(format!("kit-{what}.zip"));
        write_kit(&path, &operator.pkcs8, &operator.public, damage);
        let (exit, stdout, stderr) = operator.cli(&[
            "client",
            "enrol",
            &format!("bad-{what}"),
            "--name",
            "Bad Kit",
            "--kit",
            &path.display().to_string(),
            "--out",
            &operator.out.display().to_string(),
        ]);
        assert_eq!(exit, 17, "{what}: {stdout}{stderr}");
        assert!(
            stderr.to_lowercase().contains(what)
                || stderr.contains("release.json")
                || stderr.contains("install-macos.sh"),
            "{what}: the message names the failed check: {stderr}"
        );
        assert_eq!(
            registry(operator.instance.addr).await,
            before,
            "{what}: the registry is untouched"
        );
    }

    // A world-readable `--out` is refused before anything is written.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open = root.join("open-out");
        std::fs::create_dir_all(&open).expect("out dir");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let (exit, _, stderr) = operator.cli(&[
            "client",
            "enrol",
            "open",
            "--name",
            "Open Out",
            "--kit",
            &operator.kit.display().to_string(),
            "--out",
            &open.display().to_string(),
        ]);
        assert_eq!(exit, 8, "a world-readable --out: {stderr}");
        assert_eq!(registry(operator.instance.addr).await, before);
    }

    // `client bundle` only packages a pending entry: once claimed, it is a
    // conflict, not a second disclosure.
    let issued = operator.issue("alpha", "Alpha Desk").await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let claimed = control_post(
        operator.instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": "alpha", "code": code }),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK, "{claimed:?}");
    let (exit, _, stderr) = operator.cli(&[
        "client",
        "bundle",
        "alpha",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
    ]);
    assert_eq!(exit, 8, "an active entry cannot be packaged: {stderr}");
}

/// `secret set` takes the rotated secret from a hidden prompt,
/// `--stdin` or an owner-only `--file`, keeps the installed file `0600`, and
/// without an installation exits 11 having written nothing.
#[tokio::test(flavor = "multi_thread")]
async fn secret_set_takes_every_channel_and_writes_one_file() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("secret-set-takes-channel").await;

    // No installation: exit 11, and nothing is created.
    let bare = scratch("secret-set-takes-channel-bare").join("home");
    private_dir(&bare);
    let bare_env = isolated_env(&bare);
    let (exit, _, stderr) = cli_raw(&["secret", "set", "--stdin"], &bare_env, Some("jsc2_x"));
    assert_eq!(exit, 11, "not enrolled: {stderr}");
    assert!(
        !config_root(&bare).join("client").exists(),
        "nothing was written"
    );

    let (home, _) = enrol_one(&operator, "alpha", "Alpha Desk").await;
    let env = isolated_env(&home);
    let secret_file = config_root(&home).join("client/client-secret");

    // `--stdin`.
    let rotated = rotate_secret(&operator, "alpha").await;
    let (exit, _, stderr) = cli_raw(&["secret", "set", "--stdin"], &env, Some(&rotated));
    assert_eq!(exit, 0, "--stdin: {stderr}");
    assert_eq!(
        std::fs::read_to_string(&secret_file)
            .expect("secret")
            .trim(),
        rotated
    );

    // `--file`, owner-only.
    let rotated = rotate_secret(&operator, "alpha").await;
    let staged = scratch("secret-set-takes-channel-file").join("secret");
    crate::harness::write_private(&staged, &rotated);
    let (exit, _, stderr) = cli_raw(
        &["secret", "set", "--file", &staged.display().to_string()],
        &env,
        None,
    );
    assert_eq!(exit, 0, "--file: {stderr}");
    assert_eq!(
        std::fs::read_to_string(&secret_file)
            .expect("secret")
            .trim(),
        rotated
    );
    #[cfg(unix)]
    assert_eq!(mode_of(&secret_file), 0o600, "still owner-only");

    // A world-readable `--file` is refused and the installed secret stands.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open = scratch("secret-set-takes-channel-open").join("secret");
        std::fs::create_dir_all(open.parent().expect("parent")).expect("dir");
        std::fs::write(&open, "jsc2_open").expect("write");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let (exit, _, stderr) = cli_raw(
            &["secret", "set", "--file", &open.display().to_string()],
            &env,
            None,
        );
        assert_ne!(exit, 0, "a world-readable secret file is refused: {stderr}");
        assert_eq!(
            std::fs::read_to_string(&secret_file)
                .expect("secret")
                .trim(),
            rotated,
            "the installed secret is unchanged"
        );
    }

    // The hidden prompt, on a terminal.
    let rotated = rotate_secret(&operator, "alpha").await;
    let (exit, transcript) = cli_pty(
        "secret-set-takes-channel-prompt",
        &["secret", "set"],
        &env,
        Some(("new client secret", &format!("{rotated}\n"))),
    );
    assert_eq!(exit, 0, "the hidden prompt: {transcript}");
    assert!(
        !transcript.contains(&rotated),
        "the secret is never echoed: {transcript}"
    );
    assert_eq!(
        std::fs::read_to_string(&secret_file)
            .expect("secret")
            .trim(),
        rotated
    );
    let _ = binary();
}

/// With MITM on, the enrolment bundle carries the CA
/// certificate and its fingerprint, matching `GET /control/v1/ca`'s, and
/// carries no key, no secret and no leaf.
#[tokio::test(flavor = "multi_thread")]
async fn the_bundle_carries_the_ca_certificate_and_fingerprint_and_no_key() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start_with(
        "bundle-carries-ca",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    operator.issue("alpha", "Alpha Desk").await;

    let (code, stdout, stderr) = operator.cli(&[
        "client",
        "bundle",
        "alpha",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
        "--json",
    ]);
    assert_eq!(code, 0, "packaging: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the CLI envelope");
    let archive = PathBuf::from(
        envelope["result"]["archive"]
            .as_str()
            .expect("the archive path"),
    );

    // The control plane agrees on the CA in force.
    let ca_answer = operator.ctl_get("/control/v1/ca").await;
    let control_fingerprint = ca_answer.json()["ca"]["fingerprint"]
        .as_str()
        .expect("the control fingerprint")
        .to_string();

    // The manifest names the CA's SHA-256 and its fingerprint, and
    // the bundled certificate hashes to both.
    let members = read_zip(&archive);
    let manifest: Value = serde_json::from_slice(
        &members
            .iter()
            .find(|(n, _)| n == "manifest.json")
            .expect("manifest.json")
            .1,
    )
    .expect("the manifest parses");
    let (ca_name, ca_pem) = &members
        .iter()
        .find(|(n, _)| n == "ca.pem")
        .expect("ca.pem in the bundle")
        .clone();
    assert!(
        ca_pem.starts_with(b"-----BEGIN CERTIFICATE-----"),
        "{ca_name} is a PEM certificate"
    );
    let (_, pem) = x509_parser::pem::parse_x509_pem(ca_pem.as_slice()).expect("the CA PEM parses");
    let der_digest = Sha256::digest(pem.contents.as_slice());
    let colon_hex: String = der_digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    assert_eq!(
        manifest["ca"]["fingerprint"], control_fingerprint,
        "the manifest's fingerprint is the control plane's: {manifest}"
    );
    assert_eq!(manifest["ca"]["sha256"], sha256_hex(ca_pem), "{manifest}");
    assert_eq!(colon_hex, control_fingerprint, "the bundled CA's digest");

    // No key, no secret, no leaf, nothing the instance holds.
    for (name, bytes) in &members {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("PRIVATE KEY"), "{name} carries a key");
        assert!(
            !text.contains("-----BEGIN RSA") && !text.contains("-----BEGIN EC"),
            "{name} carries a key"
        );
        assert!(
            !text.contains("jse2_") && !text.contains("jsc2_") && !text.contains("jso2_"),
            "{name} carries a secret"
        );
        assert!(
            !text.contains(&operator.instance.needles.access_token),
            "{name} carries the access token"
        );
        assert!(
            !text.contains(&operator.instance.needles.refresh_token),
            "{name} carries the refresh token"
        );
    }
    let manifest_text = manifest.to_string();
    assert!(
        !manifest_text.contains("leaf") && !manifest_text.to_lowercase().contains("key"),
        "the manifest names no leaf and no key: {manifest_text}"
    );
}

/// An enrollment installs `ca.pem` alongside the
/// client files, while a bundle from a server with
/// MITM mode off refuses with what the enrollment lacks (every launch
/// is MITM mode).
#[tokio::test(flavor = "multi_thread")]
async fn a_mitm_enrollment_adds_ca_pem() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start_with(
        "client-directory-holds-mitm",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;

    // A MITM bundle: the client directory gains `ca.pem`, byte-identical to
    // the bundle's.
    let issued = operator.issue("alpha", "Alpha Desk").await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let bundle_dir = package_and_extract(&operator, "alpha").await;
    let home = scratch("client-directory-holds-mitm-engineer").join("home");
    private_dir(&home);
    write_release_key(&home, &operator.public);
    let env = isolated_env(&home);
    let (exit, transcript) = cli_pty_answers(
        "enrol-alpha-mitm",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    );
    assert_eq!(exit, 0, "enrol alpha mitm: {transcript}");
    let client_dir = config_root(&home).join("client");
    let mut members: Vec<String> = std::fs::read_dir(&client_dir)
        .expect("client directory")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    members.sort();
    assert_eq!(
        members,
        ["ca.pem", "client-secret", "client.toml"],
        "{members:?}"
    );
    let toml = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    assert!(
        !toml.contains("mode ="),
        "no transport mode is recorded: {toml}"
    );
    let proxy = toml
        .split("proxy_url = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or("");
    assert!(!proxy.is_empty(), "{toml}");
    assert_eq!(
        std::fs::read(client_dir.join("ca.pem")).expect("ca.pem"),
        std::fs::read(bundle_dir.join("ca.pem")).expect("bundle ca.pem"),
        "the installed CA is the bundle's"
    );
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&client_dir), 0o700, "the directory is private");
        assert_eq!(mode_of(&client_dir.join("client-secret")), 0o600);
    }

    //A bundle from a server with MITM mode off refuses, naming what
    // the enrollment lacks, before anything is asked or written.
    let plain = Operator::start_with("client-directory-holds-mitm-b", Setup::default()).await;
    plain.issue("beta", "Beta Desk").await;
    let bundle_dir = package_and_extract(&plain, "beta").await;
    let home = scratch("client-directory-holds-mitm-b-engineer").join("home");
    private_dir(&home);
    write_release_key(&home, &plain.public);
    let env = isolated_env(&home);
    let (exit, transcript) = cli_pty_answers(
        "enrol-beta-mitm",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[],
    );
    assert_eq!(exit, 14, "a bundle without the proxy or CA: {transcript}");
    assert!(transcript.contains(""), "{transcript}");
    assert!(
        !config_root(&home).join("client").exists(),
        "nothing was written: {transcript}"
    );
}

/// The advertised origins replace the listeners' bind addresses
/// in the packaged manifest, and a malformed advertised origin refuses to
/// start, naming the dotted key.
#[tokio::test(flavor = "multi_thread")]
async fn advertised_origins_replace_the_bind_addresses() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start_with(
        "bundle-inspectable-owner-adv",
        Setup {
            clients: "advertised_base_url = \"http://pool.example.internal:17421\"\nadvertised_proxy_url = \"http://pool.example.internal:17422/\"\n"
                .into(),
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    operator.issue("alpha", "Alpha Desk").await;
    let dir = package_and_extract(&operator, "alpha").await;
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(
        manifest["origins"]["base_url"],
        "http://pool.example.internal:17421"
    );
    assert_eq!(
        manifest["origins"]["proxy"],
        "http://pool.example.internal:17422"
    );

    // A malformed advertised origin is refused at start-up, naming the key.
    let (exit, stderr) = Instance::start_expecting_failure(
        "bundle-inspectable-owner-adv-bad",
        Setup {
            clients: "advertised_base_url = \"pool.example.internal:17421\"\n".into(),
            ..Setup::default()
        },
    )
    .await;
    assert_eq!(exit, 3, "{stderr}");
    assert!(stderr.contains("clients.advertised_base_url"), "{stderr}");
}

/// The engineer half of the TLS leg: with TLS on the
/// base URL, packaging carries the `base-url-ca.pem` and the installed
/// client trusts it without `--tls-ca`; `--tls-ca` stays
/// accepted beside it, and a caller trusting neither fails the handshake.
#[tokio::test(flavor = "multi_thread")]
async fn engineer_verbs_trust_the_tls_ca_anchor() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/acceptance/private-listener-reached-eng-certs");
    let (cert, key) = stage_tls_pair(&dir);
    let test_ca =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance/fixtures/tls/test-ca.pem");
    let operator = Operator::start_with(
        "private-listener-reached-eng",
        Setup {
            data_plane: format!(
                "tls_certificate_file = \"{}\"\ntls_private_key_file = \"{}\"\n",
                cert.display(),
                key.display()
            ),
            clients: format!("base_url_ca_certificate_file = \"{}\"\n", test_ca.display()),
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let tls_ca = cert.display().to_string();
    // The TLS listener speaks no plaintext, even on loopback, so
    // the control-plane steps go over TLS with the same anchor.
    let origin = format!("https://{}", operator.instance.addr);
    let issued = crate::harness::send_tls(
        operator.instance.addr,
        crate::harness::Request::builder()
            .method(crate::harness::Method::POST)
            .uri("/control/v1/clients")
            .header("content-type", "application/json")
            .body(crate::harness::Full::new(crate::harness::Bytes::from(
                json!({ "id": "alpha", "display_name": "Alpha Desk" }).to_string(),
            )))
            .expect("request builds"),
        false,
    )
    .await;
    assert_eq!(
        issued.status,
        crate::harness::StatusCode::CREATED,
        "{issued:?}"
    );

    // The operator CLI against `--server` always needs the operator secret;
    // provision one over TLS and hand it to the packaging run.
    let provisioned = crate::harness::send_tls(
        operator.instance.addr,
        crate::harness::Request::builder()
            .method(crate::harness::Method::POST)
            .uri("/control/v1/operator/secret")
            .header("host", operator.instance.addr.to_string())
            .header("content-type", "application/json")
            .body(crate::harness::Full::new(crate::harness::Bytes::from(
                json!({}).to_string(),
            )))
            .expect("request builds"),
        false,
    )
    .await;
    assert_eq!(
        provisioned.status,
        crate::harness::StatusCode::OK,
        "{provisioned:?}"
    );
    let operator_secret = crate::harness::secret_file(
        &operator.instance.root,
        "op-secret",
        provisioned.json()["operator_secret"]
            .as_str()
            .expect("secret"),
    );
    let operator_secret = operator_secret.display().to_string();
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();

    // Packaging: the operator CLI against the https origin, trusting the
    // same anchor.
    let (exit, stdout, stderr) = operator.cli(&[
        "--server",
        &origin,
        "--tls-ca",
        &tls_ca,
        "--operator-secret-file",
        &operator_secret,
        "client",
        "bundle",
        "alpha",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
        "--json",
    ]);
    assert_eq!(exit, 0, "packaging alpha: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    let archive = PathBuf::from(envelope["result"]["archive"].as_str().expect("archive"));
    // The https bundle carries the anchor and its facts.
    let ca_pem = std::fs::read(&test_ca).expect("the test CA");
    let manifest = &envelope["result"]["manifest"];
    assert_eq!(
        manifest["base_url_ca"]["sha256"],
        json!(sha256_hex(&ca_pem)),
        "{manifest}"
    );
    let ca_fingerprint = manifest["base_url_ca"]["fingerprint"]
        .as_str()
        .expect("the base-URL CA fingerprint")
        .to_string();
    let bundle_dir = archive.with_extension("extracted");
    let _ = std::fs::remove_dir_all(&bundle_dir);
    private_dir(&bundle_dir);
    for (name, bytes) in read_zip(&archive) {
        let path = bundle_dir.join(&name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("bundle subdirectory");
        }
        std::fs::write(&path, bytes).expect("extract member");
    }
    assert_eq!(
        std::fs::read(bundle_dir.join("base-url-ca.pem")).expect("base-url-ca.pem member"),
        ca_pem
    );

    // The claim goes over https trusting the bundle's anchor alone.
    let home = scratch("private-listener-reached-eng-engineer").join("home");
    private_dir(&home);
    write_release_key(&home, &operator.public);
    let env = isolated_env(&home);
    let (exit, transcript) = cli_pty_answers(
        "enrol-alpha-tls",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    );
    assert_eq!(exit, 0, "enrol alpha tls: {transcript}");
    assert!(
        transcript.contains(&ca_fingerprint),
        "the base-URL CA fingerprint is shown before confirmation: {transcript}"
    );
    assert!(
        config_root(&home).join("client/client-secret").exists(),
        "the claim committed"
    );
    let client_dir = config_root(&home).join("client");
    assert_eq!(
        std::fs::read(client_dir.join("base-url-ca.pem")).expect("the installed anchor"),
        ca_pem,
        "base-url-ca.pem is installed for an https base URL"
    );
    let toml = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    assert!(
        toml.contains(&format!("base_url_ca_fingerprint = {ca_fingerprint:?}")),
        "{toml}"
    );
    let mut files: Vec<String> = std::fs::read_dir(&client_dir)
        .expect("client directory")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(
        files,
        ["base-url-ca.pem", "ca.pem", "client-secret", "client.toml"],
        "an https base-URL enrollment holds exactly these files"
    );

    // With the anchor: `status --client` answers over https.
    let (exit, stdout, stderr) = cli_raw(
        &["status", "--client", "--json", "--tls-ca", &tls_ca],
        &env,
        None,
    );
    assert_eq!(exit, 0, "status with the anchor: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["result"]["client"]["id"], "alpha", "{envelope}");

    // the client form: `api` sends as the enrolled client, with the
    // secret in the header and never in argv, over the same
    // anchor. Live 12 G2 is this row on the real listener.
    let (exit, stdout, stderr) = cli_raw(
        &[
            "api",
            "GET",
            "/control/v1/client/status",
            "--json",
            "--tls-ca",
            &tls_ca,
        ],
        &env,
        None,
    );
    assert_eq!(exit, 0, "api as the client: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["role"], "client", "{envelope}");
    assert_eq!(envelope["result"]["status"], 200, "{envelope}");
    let snapshot: Value = serde_json::from_str(
        envelope["result"]["body"]
            .as_str()
            .expect("the body is UTF-8"),
    )
    .expect("client snapshot");
    assert_eq!(snapshot["client"]["id"], "alpha", "{snapshot}");

    // Without `--tls-ca` the installed anchor serves alone.
    let (exit, stdout, stderr) = cli_raw(
        &["api", "GET", "/control/v1/client/status", "--json"],
        &env,
        None,
    );
    assert_eq!(exit, 0, "api on the installed anchor: {stdout}{stderr}");
    let (exit, stdout, stderr) = cli_raw(&["status", "--client", "--json"], &env, None);
    assert_eq!(exit, 0, "status on the installed anchor: {stdout}{stderr}");

    //A caller trusting neither anchor — the operator CLI without
    // `--tls-ca` — fails the handshake, and the line names the caller as
    // the does for a tunnel. A log line can trail the handshake by a
    // tick.
    let (exit, stdout, stderr) = operator.cli(&[
        "--server",
        &origin,
        "--operator-secret-file",
        &operator_secret,
        "client",
        "list",
        "--json",
    ]);
    assert_eq!(exit, 4, "an untrusted caller: {stdout}{stderr}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let lines = loop {
        let lines = operator.instance.events("tls_handshake_failed");
        if !lines.is_empty() || std::time::Instant::now() > deadline {
            break lines;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(!lines.is_empty(), "the failed handshake left a line");
    assert!(
        lines[0]["fields"]["source_address"]
            .as_str()
            .expect("the caller's address")
            .starts_with("127.0.0.1:"),
        "the failed handshake names the caller: {lines:?}"
    );

    // With the anchor moved aside the installation is incomplete,
    // and the refusal names the file.
    std::fs::rename(
        client_dir.join("base-url-ca.pem"),
        client_dir.join("base-url-ca.pem.aside"),
    )
    .expect("move the anchor aside");
    let (exit, stdout, stderr) = cli_raw(&["status", "--client", "--json"], &env, None);
    assert_eq!(exit, 11, "status without the anchor: {stdout}{stderr}");
    assert!(stdout.contains("base-url-ca.pem"), "{stdout}{stderr}");
}

/// A refused client credential is the pre-principal
/// answer, which carries no `control_api_version`; `status --client` maps it
/// to exit 5 `cli_refused`, not exit 10 `cli_incompatible_server`.
#[tokio::test]
async fn a_refused_credential_is_exit_5() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("refused-credential-exit").await;
    let (home, _) = enrol_one(&operator, "alpha", "Alpha Desk").await;
    let env = isolated_env(&home);

    // Sanity: the enrolled client serves.
    let (exit, stdout, stderr) = cli_raw(&["status", "--client", "--json"], &env, None);
    assert_eq!(exit, 0, "sanity: {stdout}{stderr}");

    // Revoke over the control plane.
    let answer = control_post(
        operator.instance.addr,
        "/control/v1/clients/alpha/revoke",
        &[],
        json!({}),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "revoke: {answer:?}");

    // The refused credential: exit 5, the message, `cli_refused`.
    let (exit, stdout, stderr) = cli_raw(&["status", "--client", "--json"], &env, None);
    assert_eq!(exit, 5, "{stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["error"]["code"], "cli_refused", "{envelope}");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(message.contains("re-enrol"), "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");

    // The human form carries the same slug.
    let (exit, stdout, stderr) = cli_raw(&["status", "--client"], &env, None);
    assert_eq!(exit, 5, "{stdout}{stderr}");
    assert!(
        stderr.contains("cli_refused") || stdout.contains("cli_refused"),
        "{stdout}{stderr}"
    );
}

/// Advertised origins drive packaging: with the
/// keys set, every packaging verb embeds them even beside wildcard binds;
/// with a key unset beside a wildcard bind, packaging refuses naming the key
/// before anything is issued; with a key unset and a concrete loopback
/// listen, the origin is derived from the listener.
#[tokio::test(flavor = "multi_thread")]
async fn advertised_origins_drive_packaging_and_a_wildcard_needs_them() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // The advertised keys are set: they win over both wildcard binds.
    let operator = Operator::start_with(
        "advertised-origins-drive-adv",
        Setup {
            clients: "advertised_base_url = \"http://pool.example.internal:17421\"\nadvertised_proxy_url = \"http://pool.example.internal:17422\"\n".into(),
            mitm: true,
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    operator.issue("alpha", "Alpha").await;
    let dir = package_and_extract(&operator, "alpha").await;
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(
        manifest["origins"]["base_url"],
        "http://pool.example.internal:17421"
    );
    assert_eq!(
        manifest["origins"]["proxy"],
        "http://pool.example.internal:17422"
    );
    // Both keys unset beside wildcard binds: `client enrol` refuses before
    // the pending generation exists.
    let operator = Operator::start_with(
        "advertised-origins-drive-wild",
        Setup {
            mitm: true,
            wildcard: true,
            ..Setup::default()
        },
    )
    .await;
    let (code, stdout, stderr) = operator.cli(&[
        "client",
        "enrol",
        "beta",
        "--name",
        "Beta",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
    ]);
    assert_eq!(code, 3, "{stdout}{stderr}");
    let transcript = format!("{stdout}{stderr}");
    assert!(
        transcript.contains("clients.advertised_base_url"),
        "{transcript}"
    );
    assert!(
        std::fs::read_dir(&operator.out)
            .expect("out directory")
            .next()
            .is_none(),
        "the out directory is still empty"
    );
    let answer = operator.ctl_get("/control/v1/clients/beta").await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "{answer:?}");
    // A key unset with a concrete loopback listen: the origin is derived. An
    // `http` origin ignores the base-URL CA key.
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance/fixtures/tls");
    let anchor_key =
        |path: &Path| format!("base_url_ca_certificate_file = \"{}\"\n", path.display());
    let operator = Operator::start_with(
        "advertised-origins-drive-derived",
        Setup {
            mitm: true,
            clients: anchor_key(&fixtures.join("test-ca.pem")),
            ..Setup::default()
        },
    )
    .await;
    operator.issue("gamma", "Gamma").await;
    let dir = package_and_extract(&operator, "gamma").await;
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(
        manifest["origins"]["base_url"],
        format!("http://{}", operator.instance.addr)
    );
    assert!(
        !dir.join("base-url-ca.pem").exists(),
        "http carries no listener anchor"
    );
    assert!(manifest.get("base_url_ca").is_none(), "{manifest}");

    // An `https` advertised base URL needs a valid anchor file: unset, a
    // leaf that is no CA, or a file carrying a private key refuse packaging
    // naming the key; a CA certificate is packaged as `base-url-ca.pem`.
    let https = "advertised_base_url = \"https://pool.example.internal:17421\"\n";
    let operator = Operator::start_with(
        "advertised-origins-drive-https",
        Setup {
            clients: https.into(),
            ..Setup::default()
        },
    )
    .await;
    operator.issue("delta", "Delta").await;
    let bundle = |operator: &Operator| {
        operator.cli(&[
            "client",
            "bundle",
            "delta",
            "--kit",
            &operator.kit.display().to_string(),
            "--out",
            &operator.out.display().to_string(),
        ])
    };
    let (code, stdout, stderr) = bundle(&operator);
    assert_eq!(code, 3, "unset: {stdout}{stderr}");
    assert!(
        stderr.contains("clients.base_url_ca_certificate_file"),
        "{stderr}"
    );
    let keyed = operator.instance.root.join("ca-with-key.pem");
    let mut bytes = std::fs::read(fixtures.join("test-ca.pem")).expect("test CA");
    bytes.extend(std::fs::read(fixtures.join("test-leaf-key.pem")).expect("a key"));
    std::fs::write(&keyed, bytes).expect("a key-bearing anchor");
    for (file, why) in [
        (fixtures.join("test-leaf.pem"), "not a CA"),
        (keyed, "private key"),
    ] {
        operator.instance.reload_with_setup(&Setup {
            clients: format!("{https}{}", anchor_key(&file)),
            ..Setup::default()
        });
        let (code, stdout, stderr) = bundle(&operator);
        assert_eq!(code, 3, "{why}: {stdout}{stderr}");
        assert!(
            stderr.contains("clients.base_url_ca_certificate_file") && stderr.contains(why),
            "{stderr}"
        );
    }
    assert!(
        std::fs::read_dir(&operator.out)
            .expect("out")
            .next()
            .is_none(),
        "a refused packaging leaves no output"
    );
    operator.instance.reload_with_setup(&Setup {
        clients: format!("{https}{}", anchor_key(&fixtures.join("test-ca.pem"))),
        ..Setup::default()
    });
    let dir = package_and_extract(&operator, "delta").await;
    let pem = std::fs::read(fixtures.join("test-ca.pem")).expect("test CA");
    assert_eq!(
        std::fs::read(dir.join("base-url-ca.pem")).expect("the anchor member"),
        pem
    );
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(
        manifest["base_url_ca"]["sha256"],
        json!(sha256_hex(&pem)),
        "{manifest}"
    );
}

// ------------------------------------------------------------------ second-kit helpers

/// Whether this machine installs a client: the kit carries a payload for
/// macOS and Windows only, so the enrollment scenarios skip elsewhere.
pub(crate) fn client_platform() -> bool {
    matches!(
        (std::env::consts::OS, std::env::consts::ARCH),
        ("macos", "x86_64" | "aarch64") | ("windows", "x86_64")
    )
}

/// The kit member this machine runs — the acceptance mirror of the
/// product's `bundle::native_payload`.
pub(crate) fn native_payload() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "x86_64") => "payload/macos-x86_64/jaynshare",
        ("macos", "aarch64") => "payload/macos-aarch64/jaynshare",
        ("windows", "x86_64") => "payload/windows-x86_64/jaynshare.exe",
        other => panic!("no client payload on {other:?}"),
    }
}

impl Operator {
    /// The kit this operator packages from.
    pub(crate) fn kit_path(&self) -> &Path {
        &self.kit
    }

    /// A second valid kit whose native payload member carries `bytes`
    /// instead of the filler text, signed with the new payload bound (so the
    /// kit verifies). Each call replaces the previous kit file.
    pub(crate) fn kit_with_payload(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let native = native_payload();
        let mut members: Vec<(String, Vec<u8>)> = KIT_MEMBERS
            .iter()
            .map(|member| ((*member).to_string(), kit_member_bytes(member)))
            .collect();
        let entry = members
            .iter_mut()
            .find(|(member, _)| member == native)
            .expect("the kit's native payload");
        assert_eq!(entry.0, name, "the replaced member is the native payload");
        entry.1 = bytes.to_vec();
        members.sort_by(|a, b| a.0.cmp(&b.0));
        let path = self.out.join("kit-with-payload.zip");
        write_kit_members(&path, &self.pkcs8, &self.public, &members);
        path
    }
}

/// Host access is operator access: the CLI on the server host reads the
/// operator projection, an enrolled engineer's credential is refused at the
/// operator endpoints, and the deployment docs require one VM per tenant.
#[tokio::test(flavor = "multi_thread")]
async fn host_access_is_operator_access() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("host-access-operator").await;

    // One enrolled engineer on this instance, on the operator's machine.
    let home = scratch("host-access-operator-client").join("home");
    private_dir(&home);
    let client_secret = enrol_into(&operator, "eng", "Eng Desk", &home).await;

    let (exit, stdout, stderr) = operator.cli(&["status", "--json"]);
    assert_eq!(exit, 0, "the operator form: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert!(
        envelope["result"]["status"]["accounts"].is_array(),
        "host control reads the operator projection: {envelope}"
    );

    // The engineer's side: the client projection carries no operator facts.
    let (exit, stdout, stderr) = cli_raw(&["status", "--json"], &isolated_env(&home), None);
    assert_eq!(exit, 0, "the client form: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["role"], "client", "{envelope}");
    assert!(
        envelope["result"]["accounts"].is_null(),
        "the client projection carries no operator facts: {envelope}"
    );

    // The engineer's secret at the operator surface: refused.
    let bearer = format!("Bearer {client_secret}");
    let headers: Vec<(&str, &str)> = vec![("authorization", &bearer)];
    let answer = crate::harness::control(
        operator.instance.addr,
        http::Method::GET,
        "/control/v1/status",
        &headers,
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.json()["error"]["code"], "operator_required");

    // The deployment docs state the boundary: host access is operator
    // access, and an untrusted tenant needs a VM of its own.
    let doc = Path::new("deploy/README-server.md");
    let text = std::fs::read_to_string(doc).expect("deploy/README-server.md");
    assert!(
        text.contains("operator access"),
        "{}: {text}",
        doc.display()
    );
    assert!(
        text.contains("own VM") || text.contains("separate VM"),
        "{}: {text}",
        doc.display()
    );
}

/// The installed client files keep their protection: the client
/// directory is 0700 and `client-secret` 0600 through the enrol and a
/// `secret set` replacement, the bundle's extraction directory is
/// owner-only, and on Windows the ACL read back with the real
/// `icacls` grants only the installing user and `SYSTEM`.
#[tokio::test(flavor = "multi_thread")]
async fn client_files_keep_their_protection() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("client-files-keep").await;
    let (home, _) = enrol_one(&operator, "alpha", "Alpha Desk").await;
    let client_dir = config_root(&home).join("client");

    #[cfg(unix)]
    {
        assert_eq!(mode_of(&client_dir), 0o700, "the directory is private");
        assert_eq!(
            mode_of(&client_dir.join("client-secret")),
            0o600,
            "the secret is owner-only"
        );

        // `secret set` replaces the file and the mode survives.
        let rotated = rotate_secret(&operator, "alpha").await;
        let env = isolated_env(&home);
        let (exit, _, stderr) = cli_raw(&["secret", "set", "--stdin"], &env, Some(&rotated));
        assert_eq!(exit, 0, "secret set: {stderr}");
        assert_eq!(
            mode_of(&client_dir.join("client-secret")),
            0o600,
            "still 0600 after the replacement"
        );
    }

    // The extraction directory is owner-only while it exists (the
    // staging directory is gone by the time anything can be observed).
    operator.issue("beta", "Beta Desk").await;
    let extracted = package_and_extract(&operator, "beta").await;
    #[cfg(unix)]
    assert_eq!(mode_of(&extracted), 0o700, "the extraction directory");
    #[cfg(windows)]
    assert!(extracted.is_dir(), "the extraction directory");

    // On Windows the real `icacls` read-back grants only the
    // installing user and `SYSTEM`, with no inherited entry.
    if cfg!(windows) {
        let out = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .expect("whoami");
        assert!(out.status.success(), "whoami failed");
        let row = String::from_utf8_lossy(&out.stdout);
        let user = row.trim().trim_matches('"');
        for path in [client_dir.clone(), client_dir.join("client-secret")] {
            let out = std::process::Command::new("icacls")
                .arg(&path)
                .output()
                .expect("icacls");
            assert!(
                out.status.success(),
                "icacls {}: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr)
            );
            let readback = String::from_utf8_lossy(&out.stdout);
            for line in readback.lines().map(str::trim) {
                let Some(at) = line.find(":(") else {
                    continue;
                };
                let principal = line[..at].trim();
                let name_only = !user.contains('\\')
                    && principal
                        .rfind('\\')
                        .map(|i| principal[i + 1..].eq_ignore_ascii_case(user))
                        .unwrap_or(false);
                assert!(
                    principal.eq_ignore_ascii_case("NT AUTHORITY\\SYSTEM")
                        || principal == "*S-1-5-18"
                        || principal.eq_ignore_ascii_case(user)
                        || name_only,
                    "{} grants {principal}",
                    path.display()
                );
                assert!(
                    !line[at..].contains("(I)"),
                    "{} keeps an inherited entry for {principal}",
                    path.display()
                );
            }
        }
    }
}

/// A default client install trusts the CA only through the
/// per-launch `NODE_EXTRA_CA_CERTS` path and the fake OS trust store records
/// no call; with `enrol --trust-os-store` exactly the confirmed fingerprint
/// is added, `trust-ca remove` removes exactly it again, and a failing store
/// call is reported without failing the install.
#[tokio::test(flavor = "multi_thread")]
async fn the_os_trust_store_is_optional_and_exact() {
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    use crate::fake_tools::FakeTools;

    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start_with(
        "os-trust-store-optional",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let tools = FakeTools::new(
        &scratch("os-trust-store-optional-fake-tools"),
        &["security", "certutil"],
    );
    let (tool, add_head) = if cfg!(target_os = "macos") {
        ("security", "add-trusted-cert")
    } else {
        ("certutil", "-addstore")
    };
    let keychain = |home: &Path| {
        home.join("Library/Keychains/login.keychain-db")
            .display()
            .to_string()
    };

    // A default MITM enrol: the per-launch path only, no OS-store call.
    let issued = operator.issue("alpha", "Alpha Desk").await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let bundle_dir = package_and_extract(&operator, "alpha").await;
    let home_a = scratch("os-trust-store-optional-home-a").join("home");
    private_dir(&home_a);
    write_release_key(&home_a, &operator.public);
    let env_a = [isolated_env(&home_a), tools.env()].concat();
    let (exit, transcript) = cli_pty_answers(
        "os-trust-store-optional-enrol-a",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env_a,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    );
    assert_eq!(exit, 0, "the default enrol: {transcript}");
    assert!(
        tools.calls("security").is_empty() && tools.calls("certutil").is_empty(),
        "the default install makes no OS trust-store call: {:?}",
        tools.records()
    );

    // The explicit option into a second home: exactly one add, naming that
    // home's `ca.pem`, after the install.
    let issued = operator.issue("beta", "Beta Desk").await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let bundle_dir = package_and_extract(&operator, "beta").await;
    let home_b = scratch("os-trust-store-optional-home-b").join("home");
    private_dir(&home_b);
    write_release_key(&home_b, &operator.public);
    let env_b = [isolated_env(&home_b), tools.env()].concat();
    let (exit, transcript) = cli_pty_answers(
        "os-trust-store-optional-enrol-b",
        &[
            "enrol",
            "--bundle",
            &bundle_dir.display().to_string(),
            "--trust-os-store",
        ],
        &env_b,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    );
    assert_eq!(exit, 0, "the explicit enrol: {transcript}");
    let client_b = config_root(&home_b).join("client");
    let ca_b = client_b.join("ca.pem");
    let toml = std::fs::read_to_string(client_b.join("client.toml")).expect("client.toml");
    let fingerprint = toml
        .split("ca_fingerprint = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or("")
        .to_string();
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(&std::fs::read(&ca_b).expect("ca.pem")).expect("PEM");
    let sha1: String = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &pem.contents)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let colon_hex: String = Sha256::digest(pem.contents.as_slice())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    assert_eq!(fingerprint, colon_hex, "client.toml names the fingerprint");
    let ca_text = ca_b.display().to_string();
    let calls = tools.calls(tool);
    assert_eq!(calls.len(), 1, "exactly one OS-store call: {calls:?}");
    if cfg!(target_os = "macos") {
        assert_eq!(
            calls[0],
            [
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-k",
                &keychain(&home_b),
                &ca_text
            ],
            "{calls:?}"
        );
    } else {
        assert_eq!(
            calls[0],
            ["-user", "-addstore", "Root", &ca_text],
            "{calls:?}"
        );
    }

    // `trust-ca remove`: the fingerprint is shown, confirmed, and exactly the
    // certificate's SHA-1 hash is deleted.
    let (exit, transcript) = cli_pty_answers(
        "os-trust-store-optional-trust-ca-remove",
        &["trust-ca", "remove"],
        &env_b,
        &[("Remove this CA", "y\n")],
    );
    assert_eq!(exit, 0, "trust-ca remove: {transcript}");
    assert!(
        transcript.contains(&fingerprint),
        "the fingerprint is shown: {transcript}"
    );
    let calls = tools.calls(tool);
    assert_eq!(calls.len(), 2, "{calls:?}");
    if cfg!(target_os = "macos") {
        assert_eq!(
            calls[1],
            ["delete-certificate", "-Z", &sha1, &keychain(&home_b)],
            "{calls:?}"
        );
    } else {
        assert_eq!(calls[1], ["-user", "-delstore", "Root", &sha1], "{calls:?}");
    }

    // A fake whose `add` exits 1: the enrol still exits 0, the failure is on
    // stderr, and the file-based trust is unaffected.
    tools
        .rule(tool, &[add_head])
        .exit(1)
        .stderr("boom\n")
        .times(1);
    let issued = operator.issue("gamma", "Gamma Desk").await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let bundle_dir = package_and_extract(&operator, "gamma").await;
    let home_c = scratch("os-trust-store-optional-home-c").join("home");
    private_dir(&home_c);
    write_release_key(&home_c, &operator.public);
    let env_c = [isolated_env(&home_c), tools.env()].concat();
    let (exit, transcript) = cli_pty_answers(
        "os-trust-store-optional-enrol-c",
        &[
            "enrol",
            "--bundle",
            &bundle_dir.display().to_string(),
            "--trust-os-store",
        ],
        &env_c,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    );
    assert_eq!(
        exit, 0,
        "the failing store call does not fail the install: {transcript}"
    );
    assert!(
        transcript.contains("boom"),
        "the failure is named: {transcript}"
    );
}

/// The split: the server half (`operator secret set`, `client issue`)
/// runs on the server's loopback and discloses once on stdout; the remote
/// half (`client bundle` with `--server` and the disclosed secret) writes
/// the ZIP and no code file; a packaged or a claimed entry refuses to be
/// packaged again.
#[tokio::test(flavor = "multi_thread")]
async fn remote_enrolment_through_issue_and_remote_packaging() {
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start("remote-enrolment").await;

    // The server half: on the server's loopback the operator
    // CLI provisions the remote-operator secret and issues the entry; each
    // verb discloses its secret exactly once, and only on stdout.
    let (secret_exit, secret_stdout, secret_stderr) = operator.cli(&["operator", "secret", "set"]);
    assert_eq!(
        secret_exit, 0,
        "operator secret set: {secret_stdout}{secret_stderr}"
    );
    let secret = secret_stdout
        .trim_end()
        .lines()
        .last()
        .expect("the disclosure line")
        .rsplit(' ')
        .next()
        .expect("the secret")
        .to_string();
    assert!(
        secret.starts_with("jso2_"),
        "the disclosed secret: {secret_stdout}"
    );
    assert_eq!(
        secret_stdout.matches(&secret).count(),
        1,
        "disclosed once: {secret_stdout}"
    );
    assert!(
        !secret_stderr.contains(&secret),
        "stderr carries no secret: {secret_stderr}"
    );

    let (issue_exit, issue_stdout, issue_stderr) =
        operator.cli(&["client", "issue", "desk-1", "--name", "Desk One"]);
    assert_eq!(issue_exit, 0, "client issue: {issue_stdout}{issue_stderr}");
    let code = issue_stdout
        .trim_end()
        .lines()
        .last()
        .expect("the disclosure line")
        .rsplit(' ')
        .next()
        .expect("the code")
        .to_string();
    assert!(
        code.starts_with("jse2_"),
        "the disclosed code: {issue_stdout}"
    );
    assert_eq!(
        issue_stdout.matches(&code).count(),
        1,
        "disclosed once: {issue_stdout}"
    );
    assert!(
        !issue_stderr.contains(&code) && !issue_stderr.contains(&secret),
        "stderr carries neither the code nor the secret: {issue_stderr}"
    );
    assert!(
        !secret_stderr.contains(&code),
        "stderr carries no code: {secret_stderr}"
    );

    // The remote half: the binary packages the pending entry with the
    // operator secret from a 0600 file, against the instance's base URL,
    // and writes the ZIP and no code file.
    let staged = scratch("remote-enrolment-secret").join("op-secret");
    crate::harness::write_private(&staged, &secret);
    let server = format!("http://{}", operator.instance.addr);
    let bundle_args = [
        "client",
        "bundle",
        "desk-1",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
        "--server",
        &server,
        "--operator-secret-file",
        &staged.display().to_string(),
    ];
    let (bundle_exit, bundle_stdout, bundle_stderr) = operator.cli(&bundle_args);
    assert_eq!(
        bundle_exit, 0,
        "host packaging: {bundle_stdout}{bundle_stderr}"
    );
    let archive = operator.out.join("jaynshare-client-desk-1-g1.zip");
    let entries: Vec<String> = std::fs::read_dir(&operator.out)
        .expect("out directory")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entries,
        ["jaynshare-client-desk-1-g1.zip"],
        "exactly one ZIP, and no code file"
    );
    assert_eq!(
        read_zip(&archive)
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        BUNDLE_MEMBERS,
        "the bundle tree"
    );

    // The entry is still pending, but the output exists — a second
    // packaging refuses rather than overwriting.
    let (exit, _, stderr) = operator.cli(&bundle_args);
    assert_eq!(exit, 8, "overwrite refused: {stderr}");
    assert!(archive.is_file(), "the first bundle still stands");

    // A claimed entry is no longer pending: after the full install of a
    // fresh `desk-2`, packaging it refuses and discloses nothing.
    let home = scratch("remote-enrolment-engineer").join("home");
    private_dir(&home);
    enrol_into(&operator, "desk-2", "Desk Two", &home).await;
    let (exit, _, stderr) = operator.cli(&[
        "client",
        "bundle",
        "desk-2",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
        "--server",
        &server,
        "--operator-secret-file",
        &staged.display().to_string(),
    ]);
    assert_eq!(exit, 8, "a non-pending entry cannot be packaged: {stderr}");
}

/// The ids `client list` shows for this instance.
async fn listed_ids(operator: &Operator) -> Vec<String> {
    let (code, stdout, stderr) = operator.cli(&["client", "list", "--json"]);
    assert_eq!(code, 0, "client list: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the CLI envelope");
    envelope["result"]["clients"]
        .as_array()
        .expect("the registry")
        .iter()
        .map(|c| c["id"].as_str().expect("an id").to_string())
        .collect()
}

/// The manifest names no fact whose key carries a secret, a
/// code, a verifier or anything private, and no value is a control endpoint
/// path (a payload's archive `path` is a filename, not an endpoint).
fn secret_bearing_keys(value: &Value, hits: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                let name = key.to_lowercase();
                if ["secret", "code", "verifier", "private"]
                    .iter()
                    .any(|word| name.contains(word))
                {
                    hits.push(key.clone());
                }
                secret_bearing_keys(inner, hits);
            }
        }
        Value::Array(items) => {
            for inner in items {
                secret_bearing_keys(inner, hits);
            }
        }
        Value::String(text) if text.contains("/control/") || text.contains("/v1/") => {
            hits.push(text.clone());
        }
        _ => {}
    }
}

/// `client enrol` is one transaction: the ZIP carries
/// the exact tree with the byte-identical signed members and a
/// canonical manifest that names no secret-bearing fact, the code is
/// A separate owner-only file in the owner-only directory, another
/// id's delivery shares that directory while the same id's output is never
/// overwritten, and every failed half leaves the
/// registry and the directory untouched.
#[tokio::test(flavor = "multi_thread")]
async fn preparing_a_bundle_is_one_transaction() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("preparing-bundle-transaction").await;
    let out = scratch("preparing-bundle-transaction-out");
    private_dir(&out);

    // 1. The transaction: verify the kit, issue the pending generation,
    // package the ZIP and the separate code file.
    let (code, stdout, stderr) = operator.cli(&[
        "client",
        "enrol",
        "desk-1",
        "--name",
        "Desk One",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &out.display().to_string(),
        "--json",
    ]);
    assert_eq!(code, 0, "enrol desk-1: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the CLI envelope");
    assert_eq!(envelope["ok"], true, "{envelope}");
    let archive = PathBuf::from(envelope["result"]["archive"].as_str().expect("the archive"));
    assert_eq!(
        archive.file_name().and_then(|n| n.to_str()),
        Some("jaynshare-client-desk-1-g1.zip"),
        "the archive name"
    );
    let code_file = PathBuf::from(
        envelope["result"]["code_file"]
            .as_str()
            .expect("the code file"),
    );
    assert_eq!(
        code_file.file_name().and_then(|n| n.to_str()),
        Some("jaynshare-client-desk-1-g1.code"),
        "the code is a separate file"
    );

    // Owner-only outputs, and the directory holds the two
    // files and nothing else.
    let entries = || -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&out)
            .expect("the out directory")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        entries(),
        [
            "jaynshare-client-desk-1-g1.code".to_string(),
            "jaynshare-client-desk-1-g1.zip".to_string()
        ],
        "the directory holds the ZIP and the code file alone"
    );
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&out), 0o700, "the directory is owner-only");
        assert_eq!(mode_of(&archive), 0o600, "the archive is owner-only");
        assert_eq!(mode_of(&code_file), 0o600, "the code file is owner-only");
    }

    // The ZIP root is exactly BUNDLE_MEMBERS (this instance's base
    // URL is http, so the pool holds no CA and `ca.pem` travels empty).
    let members = read_zip(&archive);
    let names: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, BUNDLE_MEMBERS, "the bundle tree");

    // The release set and every kit member are byte-identical.
    let kit = read_zip(&operator.kit);
    for name in ["release.json", "release.json.minisig", "SHA256SUMS"]
        .into_iter()
        .chain(KIT_MEMBERS)
    {
        let from_kit = &kit.iter().find(|(n, _)| n == name).expect(name).1;
        let in_bundle = &members.iter().find(|(n, _)| n == name).expect(name).1;
        assert_eq!(from_kit, in_bundle, "{name} is copied byte-for-byte");
    }

    // Canonical JSON, and no secret-bearing key name anywhere.
    let manifest_bytes = &members
        .iter()
        .find(|(n, _)| n == "manifest.json")
        .expect("manifest.json")
        .1;
    let manifest: Value = serde_json::from_slice(manifest_bytes).expect("the manifest parses");
    assert_eq!(
        manifest_bytes.as_slice(),
        canonical(&manifest).as_slice(),
        "manifest.json is RFC 8785 canonical"
    );
    let mut forbidden = Vec::new();
    secret_bearing_keys(&manifest, &mut forbidden);
    assert!(
        forbidden.is_empty(),
        "secret-bearing manifest keys: {forbidden:?}"
    );

    // 2. Another id into the same --out: its own ZIP and code beside
    // the manual run's, all owner-only. The same id again is
    // refused and overwrites nothing.
    use std::os::unix::fs::PermissionsExt;
    let (code, _, stderr) = operator.cli(&[
        "client",
        "enrol",
        "desk-2",
        "--name",
        "Desk Two",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 0, "a second id shares the directory: {stderr}");
    let both = [
        "jaynshare-client-desk-1-g1.code".to_string(),
        "jaynshare-client-desk-1-g1.zip".to_string(),
        "jaynshare-client-desk-2-g1.code".to_string(),
        "jaynshare-client-desk-2-g1.zip".to_string(),
    ];
    assert_eq!(entries(), both, "one ZIP and one code file per id");
    for name in &both {
        let mode = std::fs::metadata(out.join(name))
            .expect("the output")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{name} is owner-only");
    }
    let before = std::fs::read(out.join("jaynshare-client-desk-1-g1.zip")).expect("desk-1 ZIP");
    let (code, _, stderr) = operator.cli(&[
        "client",
        "enrol",
        "desk-1",
        "--name",
        "Desk One",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 8, "the same id is refused: {stderr}");
    assert!(stderr.contains(""), "the refusal names: {stderr}");
    assert_eq!(entries(), both, "the refusal wrote nothing");
    assert_eq!(
        std::fs::read(out.join("jaynshare-client-desk-1-g1.zip")).expect("desk-1 ZIP"),
        before,
        "the manual run's ZIP is not overwritten"
    );

    // 3. A kit that fails verification: exit 17 and no pending generation.
    let tampered = scratch("preparing-bundle-transaction-tampered").join("kit.zip");
    write_kit(&tampered, &operator.pkcs8, &operator.public, |members| {
        let entry = members
            .iter_mut()
            .find(|(name, _)| name == native_payload())
            .expect("the native payload member");
        entry.1[0] ^= 0xff;
    });
    let (code, _, stderr) = operator.cli(&[
        "client",
        "enrol",
        "desk-3",
        "--name",
        "Desk Three",
        "--kit",
        &tampered.display().to_string(),
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 17, "the tampered kit is refused: {stderr}");
    let listed = listed_ids(&operator).await;
    assert!(
        !listed.iter().any(|id| id == "desk-3"),
        "no pending generation was left for desk-3: {listed:?}"
    );

    // 4. An --out under a regular file cannot take the bundle: non-zero,
    // and desk-4 is not left pending in the registry.
    let blocker = scratch("preparing-bundle-transaction-blocked").join("blocker");
    std::fs::write(&blocker, b"a regular file\n").expect("the blocker file");
    let (code, _, stderr) = operator.cli(&[
        "client",
        "enrol",
        "desk-4",
        "--name",
        "Desk Four",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &blocker.join("out").display().to_string(),
    ]);
    assert_ne!(code, 0, "the unusable --out is refused: {stderr}");
    let listed = listed_ids(&operator).await;
    assert!(
        !listed.iter().any(|id| id == "desk-4"),
        "desk-4 is neither pending nor left behind: {listed:?}"
    );

    // 5. Registry persistence fails (the crash boundary at the state
    // rename, in the fixture, never a real registry): the server dies before
    // the pending generation is durable, and neither the ZIP nor the code
    // file is published.
    let faults = crate::faults::Faults::new();
    let mut crashing =
        Operator::start_with_faults("preparing-bundle-transaction-persist", Arc::clone(&faults))
            .await;
    let before = crashing.instance.state_digest();
    let pid = crashing.instance.pid();
    faults.arm_rename_kill("state.json");
    let (code, _, stderr) = crashing.cli(&[
        "client",
        "enrol",
        "desk-5",
        "--name",
        "Desk Five",
        "--kit",
        &crashing.kit.display().to_string(),
        "--out",
        &crashing.out.display().to_string(),
    ]);
    assert_ne!(
        code, 0,
        "the unpersisted issue fails the preparation: {stderr}"
    );
    assert_eq!(
        crashing.instance.await_exit(),
        86,
        "dead at the rename boundary"
    );
    let published: Vec<String> = std::fs::read_dir(&crashing.out)
        .expect("the out directory")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        published.is_empty(),
        "neither ZIP nor code file is published: {published:?}"
    );
    assert_eq!(
        crashing.instance.state_digest(),
        before,
        "the registry kept its old bytes"
    );
    // The asserted leftover holds the state's secrets on an unlisted name.
    let temporary = crashing
        .instance
        .root
        .join(format!("state/.state.json.{pid}.tmp"));
    std::fs::remove_file(&temporary).expect("remove the asserted temporary");
    faults.clear_rename();
    crashing.instance.respawn();
    let listed = listed_ids(&crashing).await;
    assert!(
        !listed.iter().any(|id| id == "desk-5"),
        "desk-5 was never registered: {listed:?}"
    );
}

/// A clean-profile claim shows the facts before the
/// confirmation, reads the code hidden after it and never echoes it, and
/// installs exactly the two files (a base-URL enrollment carries no
/// `ca.pem`), the executable and the two settings entries; the
/// engineer's `status` answers from that home.
#[tokio::test(flavor = "multi_thread")]
async fn a_clean_profile_claim_installs_exactly_the_client() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("clean-profile-claim").await;
    let issued = operator.issue("alpha", "Alpha Desk").await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("the code is disclosed once")
        .to_string();
    let bundle_dir = package_and_extract(&operator, "alpha").await;
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(bundle_dir.join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");

    // A fresh home that has never held a client.
    let home = scratch("clean-profile-claim-engineer").join("home");
    private_dir(&home);
    write_release_key(&home, &operator.public);
    let env = isolated_env(&home);
    let (exit, transcript) = cli_pty_answers(
        "clean-profile-claim-enrol",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    );
    assert_eq!(exit, 0, "the claim installs: {transcript}");

    // The id, the display name, both origins, the expiry, the CA
    // fingerprint, the release version and the commit precede the
    // confirmation; the code prompt follows it; the code is never echoed.
    let confirm_at = transcript
        .find("install this enrollment?")
        .expect("the confirmation question");
    let code_at = transcript
        .find("enrollment code")
        .expect("the hidden code prompt");
    for label in [
        "client id:",
        "display name:",
        "base URL:",
        "proxy:",
        "pending until:",
        "CA fingerprint:",
        "release:",
    ] {
        let at = transcript
            .find(label)
            .unwrap_or_else(|| panic!("the {label} fact is missing: {transcript}"));
        assert!(
            at < confirm_at,
            "{label} is shown before the confirmation: {transcript}"
        );
    }
    assert!(
        code_at > confirm_at,
        "the code is asked only after the confirmation: {transcript}"
    );
    let base_url = manifest["origins"]["base_url"].as_str().expect("origin");
    assert!(
        transcript.contains(&format!("base URL:         {base_url}")),
        "the base-URL origin: {transcript}"
    );
    let proxy = manifest["origins"]["proxy"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| "none".to_string());
    assert!(
        transcript.contains(&format!("proxy:            {proxy}")),
        "the proxy origin: {transcript}"
    );
    let expiry = manifest["pending_expires_at"].as_str().expect("expiry");
    assert!(
        transcript.contains(&format!("pending until:    {expiry}")),
        "the pending expiry: {transcript}"
    );
    // The CA the launch will trust, by its fingerprint.
    let fingerprint = manifest["ca"]["fingerprint"]
        .as_str()
        .expect("the CA fingerprint");
    assert!(
        transcript.contains(&format!("CA fingerprint:   {fingerprint}")),
        "the CA fingerprint slot: {transcript}"
    );
    let version = manifest["release"]["version"].as_str().expect("version");
    let commit = manifest["release"]["commit"].as_str().expect("commit");
    assert!(
        transcript.contains(&format!("release:          {version} ({commit})")),
        "the release identity: {transcript}"
    );
    assert!(
        !transcript.contains("mode:"),
        "no transport mode is shown: {transcript}"
    );
    assert!(
        transcript.contains("client id:        alpha"),
        "the client id: {transcript}"
    );
    assert!(
        transcript.contains("display name:     Alpha Desk"),
        "the display name: {transcript}"
    );
    assert!(
        !transcript.contains(&code),
        "the code never appears in the transcript: {transcript}"
    );

    // Exactly the three files, at the stated modes, and the
    // executable beside them.
    #[cfg(unix)]
    {
        let client_dir = config_root(&home).join("client");
        let mut names: Vec<String> = std::fs::read_dir(&client_dir)
            .expect("client directory")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["ca.pem", "client-secret", "client.toml"],
            "the files, nothing else: {names:?}"
        );
        assert_eq!(mode_of(&client_dir), 0o700, "the directory is private");
        assert_eq!(
            mode_of(&client_dir.join("client-secret")),
            0o600,
            "the secret is owner-only"
        );
        let exe = config_root(&home).join("bin/jaynshare");
        assert!(exe.is_file(), "the executable: {}", exe.display());
        let exe_mode = mode_of(&exe);
        assert!(
            exe_mode == 0o700 || exe_mode == 0o755,
            "the executable is owner-only: {exe_mode:o}"
        );
        assert_eq!(
            mode_of(exe.parent().expect("bin")),
            0o700,
            "the bin directory is private"
        );
    }

    // The engineer's `status` from that home.
    let (exit, stdout, stderr) = cli_raw(&["status", "--json"], &env, None);
    assert_eq!(exit, 0, "the engineer's status: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["result"]["client"]["id"], "alpha", "{envelope}");

    // Exactly the two settings entries, by the absolute path.
    let settings: Value = serde_json::from_str(
        &std::fs::read_to_string(home.join(".claude/settings.json")).expect("settings.json"),
    )
    .expect("settings JSON");
    let exe_display = config_root(&home)
        .join("bin/jaynshare")
        .display()
        .to_string();
    let status = &settings["statusLine"];
    let status_command = status["command"].as_str().expect("statusLine command");
    assert!(
        status_command.contains(&exe_display) && status_command.ends_with("statusline"),
        "the status line: {status_command}"
    );
    let hook = &settings["hooks"]["UserPromptSubmit"][0]["hooks"][0];
    let hook_command = hook["command"].as_str().expect("title-hook command");
    assert!(
        hook_command.contains(&exe_display) && hook_command.ends_with("title-hook"),
        "the title hook: {hook_command}"
    );

    // The Windows half: the paths the installer must have used (this half runs on Windows only; it is written here and skipped off it).
    if cfg!(windows) {
        let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA"));
        let exe = local.join("Programs/Jaynshare/jaynshare.exe");
        assert!(exe.is_file(), "the executable: {}", exe.display());
        let appdata = PathBuf::from(std::env::var_os("APPDATA").expect("APPDATA"));
        let client_dir = appdata.join("Jaynshare/client");
        let mut names: Vec<String> = std::fs::read_dir(&client_dir)
            .expect("client directory")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["client-secret", "client.toml"], "{names:?}");
        assert!(
            !client_dir.join("ca.pem").exists(),
            "no CA file on a base-URL enrollment"
        );
    }

    // macOS: the bundle arrives as a browser download extracted in
    // Finder, so every file carries the quarantine mark. The real
    // `install-macos.sh` needs no platform signature: it removes the mark from
    // its digest-checked payload copy only and runs it, and the payload stops
    // at its own confirmation (no terminal, exit 21). The bundle keeps its
    // marks.
    if cfg!(target_os = "macos") {
        let native = native_payload();
        let script = std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/kit/install-macos.sh"),
        )
        .expect("the real installer");
        let payload_bytes = std::fs::read(binary()).expect("this build's binary");
        let mut members: Vec<(String, Vec<u8>)> = KIT_MEMBERS
            .iter()
            .map(|member| (member.to_string(), kit_member_bytes(member)))
            .collect();
        for entry in members.iter_mut() {
            if entry.0 == "install-macos.sh" {
                entry.1 = script.clone();
            }
            if entry.0 == native {
                entry.1 = payload_bytes.clone();
            }
        }
        members.sort_by(|a, b| a.0.cmp(&b.0));
        let kit = scratch("clean-profile-claim-quarantine-kit").join("client-kit.zip");
        write_kit_members(&kit, &operator.pkcs8, &operator.public, &members);
        operator.issue("gamma", "Gamma Desk").await;
        let (code, stdout, stderr) = operator.cli(&[
            "client",
            "bundle",
            "gamma",
            "--kit",
            &kit.display().to_string(),
            "--out",
            &operator.out.display().to_string(),
            "--json",
        ]);
        assert_eq!(code, 0, "packaging: {stdout}{stderr}");
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
        let archive = PathBuf::from(envelope["result"]["archive"].as_str().expect("archive"));
        let downloaded = archive.with_extension("downloaded");
        extract_archive(&archive, &downloaded);
        let mark = "0083;66f2a000;Safari;";
        let marked = std::process::Command::new("xattr")
            .args(["-r", "-w", "com.apple.quarantine", mark])
            .arg(&downloaded)
            .status()
            .expect("xattr");
        assert!(marked.success(), "the bundle is marked as downloaded");

        let root = scratch("clean-profile-claim-quarantine");
        let home = root.join("home");
        private_dir(&home);
        write_release_key(&home, &operator.public);
        let tmpdir = root.join("tmp");
        private_dir(&tmpdir);
        let output = std::process::Command::new("/bin/sh")
            .arg("./install-macos.sh")
            .current_dir(&downloaded)
            // cargo leaks the build-time triple as JAYNSHARE_TARGET into the
            // test process; a real user run selects by `uname -m`.
            .env_remove("JAYNSHARE_TARGET")
            .envs(
                isolated_env(&home)
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str())),
            )
            .env("TMPDIR", &tmpdir)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run the installer");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(21),
            "the payload ran and refused at its own confirmation: {stderr}"
        );
        assert!(
            stderr.contains("needs a terminal for its confirmation"),
            "{stderr}"
        );
        assert!(
            !config_root(&home).join("client").exists(),
            "nothing durable before the confirmation"
        );
        let kept = std::process::Command::new("xattr")
            .args(["-p", "com.apple.quarantine"])
            .arg(downloaded.join(native))
            .output()
            .expect("xattr");
        assert_eq!(
            String::from_utf8_lossy(&kept.stdout).trim(),
            mark,
            "the bundle's payload keeps its quarantine mark"
        );
        let left: Vec<_> = std::fs::read_dir(&tmpdir)
            .expect("the installer's TMPDIR")
            .collect();
        assert!(left.is_empty(), "the payload copy is removed: {left:?}");
    }
}

/// SHA-256 of every file under the home's configuration root plus the
/// Claude Code settings file, sorted by path: the byte-identical check.
fn install_snapshot(home: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("walk the configuration root") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, files);
            } else {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&config_root(home), &mut files);
    let settings = home.join(".claude/settings.json");
    if settings.is_file() {
        files.push(settings);
    }
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(home)
                .expect("under the home")
                .display()
                .to_string();
            let digest = sha256_hex(&std::fs::read(&path).expect("read"));
            (rel, digest)
        })
        .collect()
}

/// A refusal or a lost response leaves the prior install
/// byte-identical and nothing partial behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_claim_leaves_the_prior_install_byte_identical() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let mut operator = Operator::start("failed-claim-leaves-prior").await;

    // The prior install, and its hashes.
    let (home, _secret) = enrol_one(&operator, "desk-1", "Desk One").await;
    let before = install_snapshot(&home);
    assert!(before.len() >= 3, "the prior install has files: {before:?}");

    // A second bundle. On the enrolled machine the already-enrolled guard
    // refuses `enrol` before the facts, the confirmation or the code — the
    // strongest form of the refusal sentence — so the wrong code is
    // never read there. The refusal leaves every hash unchanged.
    operator.issue("desk-2", "Desk Two").await;
    let bundle_dir = package_and_extract(&operator, "desk-2").await;
    let env = isolated_env(&home);
    let (exit, transcript) = cli_pty_answers(
        "failed-claim-leaves-prior-enrol-desk-2-conflict",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &env,
        &[],
    );
    assert_eq!(
        exit, 8,
        "an enrolled machine refuses a second enrol: {transcript}"
    );
    assert!(
        transcript.contains("already enrolled"),
        "the refusal names the prior install: {transcript}"
    );
    assert_eq!(
        install_snapshot(&home),
        before,
        "the refusal leaves the prior install byte-identical"
    );

    // The same bundle into a clean home, confirmed with a wrong code: the
    // claim is refused, the code is spent as far as the server knows, and
    // nothing is installed (the claim-refusal case, re-run against this unit's
    // bundle so the two cases share one packaging).
    let second = scratch("failed-claim-leaves-prior-second").join("home");
    private_dir(&second);
    write_release_key(&second, &operator.public);
    let second_env = isolated_env(&second);
    let (exit, transcript) = cli_pty_answers(
        "failed-claim-leaves-prior-enrol-desk-2",
        &["enrol", "--bundle", &bundle_dir.display().to_string()],
        &second_env,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", "not-the-code\n"),
        ],
    );
    assert_eq!(exit, 5, "the server refuses the wrong code: {transcript}");
    assert!(
        transcript.contains("the enrollment claim was refused"),
        "{transcript}"
    );
    assert!(transcript.contains("reissue"), "{transcript}");
    assert!(
        !config_root(&second).join("client").exists(),
        "nothing was installed: {}",
        config_root(&second).join("client").display()
    );
    assert_eq!(
        install_snapshot(&home),
        before,
        "the prior install is untouched by the other machine's refusal"
    );

    // A lost response: the bundle was packaged against the live instance,
    // and the instance stops before the claim — the response never comes.
    // (The harness cannot stop an instance between the confirmation and the
    // claim; the unit's fallback is this pre-stopped origin, nothing
    // rewritten.)
    let issued = operator.issue("desk-3", "Desk Three").await;
    let code = issued["enrollment_code"]
        .as_str()
        .expect("code")
        .to_string();
    let lost_bundle = package_and_extract(&operator, "desk-3").await;
    operator.instance.stop();
    let (exit, transcript) = cli_pty_answers(
        "failed-claim-leaves-prior-enrol-desk-3",
        &["enrol", "--bundle", &lost_bundle.display().to_string()],
        &second_env,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", &format!("{code}\n")),
        ],
    );
    assert_eq!(exit, 5, "the lost response fails the claim: {transcript}");
    assert!(
        transcript.contains("the enrollment claim failed"),
        "the connectivity kind is named apart from a refusal: {transcript}"
    );
    assert!(transcript.contains("reissue"), "{transcript}");
    assert!(
        transcript.contains("never retried"),
        "the code is never retried: {transcript}"
    );
    // No staging left: the configuration root keeps the pinned key and the
    // emptied `bin/` directory the staging created, nothing more.
    let second_root = config_root(&second);
    let mut names: Vec<String> = std::fs::read_dir(&second_root)
        .expect("configuration root")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["bin", "release.pub"],
        "no staging directory is left under the configuration root: {names:?}"
    );
    assert!(
        std::fs::read_dir(second_root.join("bin"))
            .expect("bin directory")
            .next()
            .is_none(),
        "the staged executable was removed"
    );
    assert_eq!(
        install_snapshot(&home),
        before,
        "the prior install is still byte-identical"
    );

    // the second sentence — a durable secret whose post-install status
    // check fails keeps the complete installation — cannot be produced here
    // without a fault seam in `enrol`; covers the durable-secret
    // case, so this half is left out.
}

/// Extracts an archive the way the receiving machine does: every member at
/// its stored path under `destination`.
fn extract_archive(archive: &Path, destination: &Path) {
    let _ = std::fs::remove_dir_all(destination);
    private_dir(destination);
    for (name, bytes) in read_zip(archive) {
        let path = destination.join(&name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("bundle subdirectory");
        }
        std::fs::write(&path, bytes).expect("extract member");
    }
}

/// Rewrites the extracted bundle's `manifest.json` canonically after `edit`.
fn edit_manifest(bundle: &Path, edit: impl FnOnce(&mut Value)) {
    let path = bundle.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("manifest.json")).expect("manifest");
    edit(&mut manifest);
    std::fs::write(&path, canonical(&manifest)).expect("rewrite manifest.json");
}

/// One hex digit of a digest, changed.
fn flip_hex(digest: &str) -> String {
    let mut chars: Vec<char> = digest.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}

/// A tampered bundle is refused before the code prompt.
/// The installer reads the *extracted* directory, so every tamper is made
/// there: a flipped payload byte, a replaced CA, a manifest digest that no
/// longer binds its file, a member swapped for a symbolic link, and an
/// unlisted file at the root or under `payload/` each exit 17 before the
/// confirmation, with no code prompt and no client directory. A changed
/// display name is a client fact, which leaves to the human
/// comparison: it is shown, the engineer declines, exit 21, nothing
/// installed. Archive-only tampers (traversal, case collision, a symlink
/// entry) never survive into a directory the installer can see; `read_zip`'s
/// own tests hold them.
#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_bundle_is_refused_before_the_code_prompt() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start_with(
        "tampered-bundle-refused",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    operator.issue("alpha", "Alpha Desk").await;
    let (code, stdout, stderr) = operator.cli(&[
        "client",
        "bundle",
        "alpha",
        "--kit",
        &operator.kit.display().to_string(),
        "--out",
        &operator.out.display().to_string(),
        "--json",
    ]);
    assert_eq!(code, 0, "packaging: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    let archive = PathBuf::from(envelope["result"]["archive"].as_str().expect("archive"));

    // One enrol run from a fresh home. A damaged run has `n` typed ahead
    // (an empty prompt matches at once), so a tamper that slipped through
    // would end at the confirmation, exit 21, instead of waiting for input.
    let attempt = |label: &str, bundle: &Path, answers: &[(&str, &str)]| {
        let home = scratch(&format!("tampered-bundle-refused-{label}")).join("home");
        private_dir(&home);
        write_release_key(&home, &operator.public);
        let env = isolated_env(&home);
        let (exit, transcript) = cli_pty_answers(
            &format!("tampered-bundle-refused-enrol-{label}"),
            &["enrol", "--bundle", &bundle.display().to_string()],
            &env,
            answers,
        );
        (exit, transcript, config_root(&home).join("client").exists())
    };
    let typed_ahead = [("", "n\n")];

    // The tame copy first: it shows the real facts and runs to the code
    // prompt, so every refusal below is the tamper's doing.
    let tame = operator.out.join("tame");
    extract_archive(&archive, &tame);
    let (exit, transcript, installed) = attempt(
        "tame",
        &tame,
        &[
            ("install this enrollment?", "y\n"),
            ("enrollment code", "not-the-code\n"),
        ],
    );
    assert_eq!(
        exit, 5,
        "the tame bundle runs to the claim, which is refused: {transcript}"
    );
    assert!(transcript.contains("Alpha Desk"), "{transcript}");
    assert!(!installed, "a refused claim installs nothing");

    // A syntactically valid PEM certificate that is not the bundled CA.
    let another_ca = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBszCCAVmgAwIBAgIUKnXYz5u7oVGLylYq0TmUbYZZYbcwCgYIKoZIzj0EAwIw\n",
        "-----END CERTIFICATE-----\n"
    );
    let target = native_payload();
    type Damage = Box<dyn FnOnce(&Path)>;
    let cases: Vec<(&str, Damage)> = vec![
        (
            "payload-byte",
            Box::new(move |b: &Path| {
                let path = b.join(target);
                let mut bytes = std::fs::read(&path).expect("payload");
                let middle = bytes.len() / 2;
                bytes[middle] ^= 0x01;
                std::fs::write(&path, bytes).expect("flip");
            }),
        ),
        (
            "ca-replaced",
            Box::new(move |b: &Path| {
                std::fs::write(b.join("ca.pem"), another_ca).expect("replace ca.pem")
            }),
        ),
        (
            "manifest-payload-digest",
            Box::new(|b: &Path| {
                edit_manifest(b, |m| {
                    let entry = &mut m["payloads"][0]["sha256"];
                    *entry = json!(flip_hex(entry.as_str().expect("payload digest")));
                })
            }),
        ),
        (
            "manifest-ca-digest",
            Box::new(|b: &Path| {
                edit_manifest(b, |m| {
                    let entry = &mut m["ca"]["sha256"];
                    *entry = json!(flip_hex(entry.as_str().expect("ca digest")));
                })
            }),
        ),
        (
            "payload-symlink",
            Box::new(move |b: &Path| {
                // The genuine bytes, but reached through a link out of the bundle.
                let path = b.join(target);
                let outside = b.parent().expect("parent").join("genuine-payload");
                std::fs::rename(&path, &outside).expect("move the payload out");
                #[cfg(unix)]
                std::os::unix::fs::symlink(&outside, &path).expect("symlink");
            }),
        ),
        (
            "extra-root-file",
            Box::new(|b: &Path| std::fs::write(b.join("evil.sh"), b"#!/bin/sh\n").expect("extra")),
        ),
        (
            "extra-payload-file",
            Box::new(move |b: &Path| {
                let beside = b.join(target).with_file_name("evil");
                std::fs::write(beside, b"x").expect("extra")
            }),
        ),
    ];
    for (label, damage) in cases {
        if label == "payload-symlink" && !cfg!(unix) {
            continue;
        }
        let bundle = operator.out.join(format!("damaged-{label}"));
        extract_archive(&archive, &bundle);
        damage(&bundle);
        let (exit, transcript, installed) = attempt(label, &bundle, &typed_ahead);
        assert_eq!(exit, 17, "{label}: refused as unverified: {transcript}");
        assert!(
            !transcript.contains("install this enrollment?"),
            "{label}: refused before the confirmation: {transcript}"
        );
        assert!(
            !transcript.contains("enrollment code"),
            "{label}: the code prompt was reached: {transcript}"
        );
        assert!(!installed, "{label}: the client directory was created");
    }

    // A client fact: shown for the human comparison, declined, nothing done.
    let renamed = operator.out.join("damaged-display-name");
    extract_archive(&archive, &renamed);
    edit_manifest(&renamed, |m| m["display_name"] = json!("Tampered Desk"));
    let (exit, transcript, installed) = attempt("display-name", &renamed, &typed_ahead);
    assert_eq!(exit, 21, "declined at the comparison: {transcript}");
    assert!(
        transcript.contains("Tampered Desk"),
        "shown as received: {transcript}"
    );
    assert!(!transcript.contains("enrollment code"), "{transcript}");
    assert!(!installed, "nothing installed");

    // The code was never spent: the registry still holds alpha pending.
    let clients = operator.ctl_get("/control/v1/clients").await.json();
    assert_eq!(clients["clients"][0]["state"], "pending", "{clients}");
}

/// Following a CA rotation and the OS-store option change only the trust
/// material: `status` replaces only `ca.pem` and the fingerprint line in
/// `client.toml` (the secret, id, generation, release identity and the
/// settings entries stay byte-identical), and `trust-ca add`/`remove` act on
/// the exact confirmed fingerprint alone, never touching another
/// certificate in the store; without a terminal the option refuses before
/// any store call.
#[tokio::test(flavor = "multi_thread")]
async fn following_a_rotation_and_the_os_store_touch_only_the_ca() {
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    use crate::fake_tools::FakeTools;

    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start_with(
        "ca-update-os-store",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    let (home, _client_secret) = enrol_one(&operator, "alpha", "Alpha Desk").await;
    let client_dir = config_root(&home).join("client");

    // As: a base-URL enrol under a MITM operator carries the
    // fingerprint in `client.toml`; this build seeds `ca.pem` from the
    // pre-rotation CA the pool serves.
    let ca = operator.ctl_get("/control/v1/ca").await.json();
    let old_pem = ca["ca"]["certificate_pem"]
        .as_str()
        .expect("the CA's certificate")
        .to_string();
    std::fs::write(client_dir.join("ca.pem"), &old_pem).expect("seed ca.pem");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            client_dir.join("ca.pem"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("seed ca.pem mode");
    }
    let old_toml = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    let old_secret = std::fs::read(client_dir.join("client-secret")).expect("client-secret");
    let old_ca = std::fs::read(client_dir.join("ca.pem")).expect("ca.pem");
    let old_settings =
        std::fs::read_to_string(home.join(".claude/settings.json")).expect("settings.json");

    // The operator replaces the CA; the client's next status follows it.
    let (code, _, stderr) = operator.cli(&["ca", "rotate", "--now", "--yes"]);
    assert_eq!(code, 0, "rotate: {stderr}");
    let new_ca = operator.ctl_get("/control/v1/ca").await.json();
    let new_pem = new_ca["ca"]["certificate_pem"]
        .as_str()
        .expect("the rotated CA");
    let new_fingerprint = new_ca["ca"]["fingerprint"].as_str().expect("fingerprint");
    let env = isolated_env(&home);
    let (code, _, stderr) = cli_raw(&["status"], &env, None);
    assert_eq!(code, 0, "status follows the rotation: {stderr}");
    assert!(stderr.contains(new_fingerprint), "{stderr}");
    let ca_bytes = std::fs::read(client_dir.join("ca.pem")).expect("ca.pem");
    assert_eq!(ca_bytes, new_pem.as_bytes(), "ca.pem is the rotated CA");
    #[cfg(unix)]
    assert_eq!(mode_of(&client_dir.join("ca.pem")), 0o600, "mode unchanged");
    let toml = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    let mut fingerprint_lines = 0;
    for (before, after) in old_toml.lines().zip(toml.lines()) {
        if before.starts_with("ca_fingerprint") {
            assert_eq!(
                after,
                format!("ca_fingerprint = \"{new_fingerprint}\""),
                "{toml}"
            );
            fingerprint_lines += 1;
        } else {
            // So the client id, the generation and the release identity in
            // `client.toml` are byte-identical too.
            assert_eq!(before, after, "only the fingerprint line moved");
        }
    }
    assert_eq!(fingerprint_lines, 1, "{old_toml}");
    assert_eq!(
        std::fs::read(client_dir.join("client-secret")).expect("client-secret"),
        old_secret,
        "the secret file is byte-identical"
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".claude/settings.json")).expect("settings.json"),
        old_settings,
        "the settings entries are unchanged"
    );

    // over the fake OS store: `trust-ca add` explains the broader
    // effect and adds exactly the confirmed certificate, once.
    let tools = FakeTools::new(
        &scratch("ca-update-os-store-fake-tools"),
        &["security", "certutil"],
    );
    let tool = if cfg!(target_os = "macos") {
        "security"
    } else {
        "certutil"
    };
    let keychain = |home: &Path| {
        home.join("Library/Keychains/login.keychain-db")
            .display()
            .to_string()
    };
    let store_env = [isolated_env(&home), tools.env()].concat();
    let (exit, transcript) = cli_pty_answers(
        "ca-update-os-store-trust-ca-add",
        &["trust-ca", "add"],
        &store_env,
        &[("Add this CA to the OS trust store?", "y\n")],
    );
    assert_eq!(exit, 0, "trust-ca add: {transcript}");
    assert!(
        transcript.contains("trusted by every program"),
        "the broader effect is explained: {transcript}"
    );
    assert!(
        transcript.contains(new_fingerprint),
        "the confirmed fingerprint is shown: {transcript}"
    );
    let ca_text = client_dir.join("ca.pem").display().to_string();
    let calls = tools.calls(tool);
    assert_eq!(calls.len(), 1, "exactly one store call: {calls:?}");
    assert!(
        tools
            .calls(if tool == "security" {
                "certutil"
            } else {
                "security"
            })
            .is_empty(),
        "no call on the other platform's tool: {:?}",
        tools.records()
    );
    if cfg!(target_os = "macos") {
        assert_eq!(
            calls[0],
            [
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-k",
                &keychain(&home),
                &ca_text
            ],
            "{calls:?}"
        );
    } else {
        assert_eq!(
            calls[0],
            ["-user", "-addstore", "Root", &ca_text],
            "{calls:?}"
        );
    }

    // A second, unrelated certificate is planted in the store: `trust-ca
    // remove` shows `client.toml`'s fingerprint and removes only the exact
    // match; the unrelated certificate stays.
    let unrelated = tools.dir.join("planted-unrelated-ca.pem");
    std::fs::write(&unrelated, &old_ca).expect("plant the unrelated certificate");
    let (_, unrelated_der) = x509_parser::pem::parse_x509_pem(&old_ca).expect("PEM");
    let unrelated_sha1: String = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        &unrelated_der.contents,
    )
    .as_ref()
    .iter()
    .map(|b| format!("{b:02X}"))
    .collect();
    let (_, new_der) = x509_parser::pem::parse_x509_pem(&ca_bytes).expect("PEM");
    let installed_sha1: String =
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &new_der.contents)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
    let (exit, transcript) = cli_pty_answers(
        "ca-update-os-store-trust-ca-remove",
        &["trust-ca", "remove"],
        &store_env,
        &[("Remove this CA", "y\n")],
    );
    assert_eq!(exit, 0, "trust-ca remove: {transcript}");
    assert!(
        transcript.contains(new_fingerprint),
        "client.toml's fingerprint is shown: {transcript}"
    );
    let calls = tools.calls(tool);
    assert_eq!(calls.len(), 2, "{calls:?}");
    if cfg!(target_os = "macos") {
        assert_eq!(
            calls[1],
            [
                "delete-certificate",
                "-Z",
                &installed_sha1,
                &keychain(&home)
            ],
            "{calls:?}"
        );
    } else {
        assert_eq!(
            calls[1],
            ["-user", "-delstore", "Root", &installed_sha1],
            "{calls:?}"
        );
    }
    assert!(
        !transcript.contains(&unrelated_sha1),
        "the unrelated certificate's hash is never named: {transcript}"
    );
    assert!(
        tools
            .records()
            .iter()
            .all(|r| !r.to_string().contains("planted-unrelated-ca.pem")),
        "no store call touches the planted certificate: {:?}",
        tools.records()
    );
    assert_eq!(
        std::fs::read(&unrelated).expect("the planted certificate"),
        old_ca,
        "the unrelated certificate remains"
    );

    // Without a terminal the confirmation cannot be read: exit 21, and the
    // store was never called.
    let before = tools.records().len();
    let (code, _, stderr) = cli_raw(&["trust-ca", "add"], &store_env, None);
    assert_eq!(code, 21, "no terminal: {stderr}");
    assert!(stderr.contains("cli_confirmation_required"), "{stderr}");
    assert_eq!(tools.records().len(), before, "no store call: {stderr}");
}
