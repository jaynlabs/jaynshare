//! The client installation a join leaves, and the verbs that keep it.
//!
//! Every test here needs a client kit the product will accept, so the
//! fixture mints its own minisign key pair per run, plants it as the
//! server's release key and serves a kit signed with it; the joining machine
//! pins that key from the invite. The kit is built here in Rust;
//! `tools/make-client-kit.py` is the independent writer the same reader has
//! to accept, and its `--self-test` is the cross-check.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;

use crate::harness::{
    Instance, Setup, Value, cli_pty, cli_pty_answers, cli_raw, isolated_env, json, private_dir,
    scratch,
};
use crate::release_fx::{ReleaseKey, canonical, sha256_hex, signature_file};

/// what a client kit carries besides the release set.
pub(crate) const KIT_MEMBERS: [&str; 4] = [
    "README.txt",
    "payload/macos-x86_64/jaynshare",
    "payload/macos-aarch64/jaynshare",
    "payload/windows-x86_64/jaynshare.exe",
];

// ------------------------------------------------------------------ the release key and the kit

/// the configuration root under a scenario's home, where `release.pub`
/// sits once a join pinned it.
pub(crate) fn config_root(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Jaynshare")
    } else {
        home.join(".config/jaynshare")
    }
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

/// A valid kit whose members are given, signed as it is written (the
/// release set binds these digests, so the kit verifies).
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

/// The valid kit every happy path uses: the filler members, signed.
pub(crate) fn good_kit(dir: &Path, pkcs8: &[u8], public: &[u8]) -> PathBuf {
    let path = dir.join("client-kit.zip");
    let mut members: Vec<(String, Vec<u8>)> = KIT_MEMBERS
        .iter()
        .map(|name| ((*name).to_string(), kit_member_bytes(name)))
        .collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    write_kit_members(&path, pkcs8, public, &members);
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
pub(crate) fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

/// Whether this machine installs a client: the kit carries a payload for
/// macOS and Windows only, so the join scenarios skip elsewhere.
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

// ------------------------------------------------------------------ invites

const INVITE_PREFIX: &str = "jsi1_";

/// The JSON an invite carries.
pub(crate) fn decode_invite(invite: &str) -> Value {
    let body = invite.strip_prefix(INVITE_PREFIX).expect("an invite");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .expect("base64url");
    serde_json::from_slice(&bytes).expect("the invite's JSON")
}

pub(crate) fn encode_invite(value: &Value) -> String {
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string());
    format!("{INVITE_PREFIX}{body}")
}

/// Identity TLS and MITM on: the server a machine can join.
pub(crate) fn identity_setup() -> Setup {
    Setup {
        mitm: true,
        data_plane: "tls = \"identity\"\n".into(),
        ..Setup::default()
    }
}

/// An instance serving a kit signed with its own release key.
pub(crate) struct Operator {
    pub(crate) instance: Instance,
    scenario: String,
    out: PathBuf,
    kit: PathBuf,
    pub(crate) pkcs8: Vec<u8>,
    pub(crate) public: Vec<u8>,
}

impl Operator {
    /// A server a machine can join.
    pub(crate) async fn start(scenario: &str) -> Operator {
        Self::start_with(scenario, identity_setup()).await
    }

    /// `setup` plus the kit file.
    pub(crate) async fn start_with(scenario: &str, mut setup: Setup) -> Operator {
        let (root, kit) = Self::kit_file(scenario, &mut setup);
        let instance = Instance::start_with(scenario, setup).await;
        Self::finish(scenario, instance, root, kit)
    }

    /// A server a machine can join, under the write-boundary fixture.
    pub(crate) async fn start_with_faults(
        scenario: &str,
        faults: Arc<crate::faults::Faults>,
    ) -> Operator {
        let mut setup = identity_setup();
        let (root, kit) = Self::kit_file(scenario, &mut setup);
        let instance = Instance::start_with_faults(scenario, setup, faults).await;
        Self::finish(scenario, instance, root, kit)
    }

    fn kit_file(scenario: &str, setup: &mut Setup) -> (PathBuf, PathBuf) {
        let root = scratch(&format!("{scenario}-operator"));
        let kit = root.join("client-kit.zip");
        setup
            .clients
            .push_str(&format!("kit_file = {:?}\n", kit.display().to_string()));
        (root, kit)
    }

    /// The key is planted before the kit exists: the server keeps its
    /// verdict on a kit until the file changes.
    fn finish(scenario: &str, instance: Instance, root: PathBuf, kit: PathBuf) -> Operator {
        let key = ReleaseKey::generate();
        key.plant(&instance.root.join("home"));
        let written = good_kit(&root, &key.pkcs8, &key.public);
        assert_eq!(written, kit);
        let out = root.join("out");
        private_dir(&out);
        Operator {
            instance,
            scenario: scenario.to_string(),
            out,
            kit,
            pkcs8: key.pkcs8,
            public: key.public,
        }
    }

    /// One operator CLI run on the server's host.
    pub(crate) fn cli(&self, args: &[&str]) -> (i32, String, String) {
        self.instance.cli(args, None)
    }

    /// One control GET's body, through the operator CLI.
    pub(crate) fn get(&self, path: &str) -> Value {
        let envelope = self.instance.cli_json(&["api", "GET", path], None);
        assert_eq!(envelope["result"]["status"], 200, "{path}: {envelope}");
        serde_json::from_str(envelope["result"]["body"].as_str().expect("the body"))
            .expect("a JSON body")
    }

    /// `client invite <id> --name <name>` plus `extra`: the invite, whose
    /// code is a leak needle from here on.
    pub(crate) fn invite(&self, id: &str, name: &str, extra: &[&str]) -> String {
        let mut args = vec!["client", "invite", id, "--name", name, "--json"];
        args.extend_from_slice(extra);
        let (exit, stdout, stderr) = self.cli(&args);
        assert_eq!(exit, 0, "invite {id}: {stdout}{stderr}");
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
        let invite = envelope["result"]["invite"]
            .as_str()
            .expect("the invite")
            .to_string();
        let code = decode_invite(&invite)["code"]
            .as_str()
            .expect("the code")
            .to_string();
        crate::leaks::register_needle("enrollment-code", &code);
        invite
    }

    /// `client rotate <id>`: the new secret.
    pub(crate) fn rotate(&self, id: &str) -> String {
        let envelope = self.instance.cli_json(&["client", "rotate", id], None);
        assert_eq!(envelope["ok"], true, "rotate {id}: {envelope}");
        envelope["result"]["client_secret"]
            .as_str()
            .expect("the new secret, disclosed once")
            .to_string()
    }

    /// The kit this server offers.
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

/// `join <invite>` from `home`, with `env` beside the home's own: the exit
/// code and the transcript.
pub(crate) fn join_from(home: &Path, invite: &str, env: &[(String, String)]) -> (i32, String) {
    let env = [isolated_env(home), env.to_vec()].concat();
    let (exit, stdout, stderr) = cli_raw(&["join", invite], &env, None);
    (exit, format!("{stdout}{stderr}"))
}

/// Invites and joins one client from a fresh home; returns the home and
/// the secret the join installed.
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
    assert_eq!(exit, 0, "join {id}: {transcript}");
    std::fs::read_to_string(config_root(home).join("client/client-secret")).expect("client-secret")
}

/// One join of a freshly invited `id` into `home`: exit code and transcript.
pub(crate) async fn try_enrol_into(
    operator: &Operator,
    id: &str,
    name: &str,
    home: &Path,
) -> (i32, String) {
    let invite = operator.invite(id, name, &[]);
    join_from(home, &invite, &[])
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

    // A rotation replaces the secret file and leaves the rest alone.
    let before = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    let rotated = operator.rotate("alpha");
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

/// `status` takes its role from the machine: a client directory
/// alone gives the client form, a configuration alone the operator form,
/// and `--client` with no installation exits 11.
#[tokio::test(flavor = "multi_thread")]
async fn status_takes_its_role_from_the_machine() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("status-takes-role").await;

    // No installation and no configuration: `--client` names the missing
    // file and the join.
    let bare = scratch("status-takes-role-bare").join("home");
    private_dir(&bare);
    let bare_env = isolated_env(&bare);
    let (exit, stdout, stderr) = cli_raw(&["status", "--client", "--json"], &bare_env, None);
    assert_eq!(exit, 11, "not enrolled: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["error"]["code"], "cli_not_enrolled", "{envelope}");
    assert!(stdout.contains("jaynshare join"), "{envelope}");

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
    let rotated = operator.rotate("alpha");
    let (exit, _, stderr) = cli_raw(&["secret", "set", "--stdin"], &env, Some(&rotated));
    assert_eq!(exit, 0, "--stdin: {stderr}");
    assert_eq!(
        std::fs::read_to_string(&secret_file)
            .expect("secret")
            .trim(),
        rotated
    );

    // `--file`, owner-only.
    let rotated = operator.rotate("alpha");
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
    let rotated = operator.rotate("alpha");
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
}

/// A copy of the CA update ZIP with one byte of `ca.pem` changed: the same
/// members, a certificate whose digest no longer matches the manifest's.
fn write_tampered_ca_update(path: &Path, members: &[(String, Vec<u8>)]) {
    let file = std::fs::File::create(path).expect("create the tampered bundle");
    let mut archive = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in members {
        let mut bytes = bytes.clone();
        if name == "ca.pem" {
            // Flip inside the base64 body: the DER (and its digest) changes.
            let middle = bytes.len() / 2;
            bytes[middle] ^= 0x01;
        }
        use std::io::Write as _;
        archive
            .start_file(name.as_str(), options)
            .expect("start member");
        archive.write_all(&bytes).expect("write member");
    }
    archive.finish().expect("finish the tampered bundle");
}

/// The CA-update bundle replaces only the trust material: the
/// certificate and the fingerprint in `client.toml` move, the client id,
/// secret and release identity are byte-identical, the old secret still
/// authenticates, and a tampered bundle is refused with nothing replaced.
#[tokio::test(flavor = "multi_thread")]
async fn the_ca_update_bundle_replaces_trust_material_only() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("ca-update-bundle").await;
    let (home, _) = enrol_one(&operator, "alpha", "Alpha Desk").await;
    let client_dir = config_root(&home).join("client");
    let old_toml = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    let old_secret_bytes = std::fs::read(client_dir.join("client-secret")).expect("client-secret");
    let old_ca_bytes = std::fs::read(client_dir.join("ca.pem")).expect("ca.pem");

    // The operator rotates the CA and packages the update bundle.
    let (code, _, stderr) = operator.cli(&["ca", "rotate", "--yes"]);
    assert_eq!(code, 0, "rotate: {stderr}");
    let (code, stdout, stderr) = operator.cli(&[
        "ca",
        "update-bundle",
        "--out",
        &operator.out.display().to_string(),
        "--json",
    ]);
    assert_eq!(code, 0, "update-bundle: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the CLI envelope");
    let archive = PathBuf::from(envelope["result"]["archive"].as_str().expect("archive"));

    // The bundle carries the server's two origins — derived from the
    // listeners here, as no advertised key is set.
    let ca_update = read_zip(&archive)
        .into_iter()
        .find(|(name, _)| name == "ca-update.json")
        .map(|(_, bytes)| serde_json::from_slice::<Value>(&bytes).expect("ca-update.json"))
        .expect("ca-update.json");
    let mut members: Vec<&str> = ca_update
        .as_object()
        .expect("a manifest object")
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        ["ca_sha256", "fingerprint", "issued_at", "origins", "schema"],
        "{ca_update}"
    );
    assert_eq!(
        ca_update["origins"],
        json!([
            format!("https://{}", operator.instance.addr),
            format!(
                "http://{}",
                operator.instance.mitm_addr.expect("mitm address")
            ),
        ]),
        "{ca_update}"
    );

    // The engineer applies it; --yes is the skip for no terminal.
    let (code, _, stderr) = cli_raw(
        &[
            "ca-update",
            "--from",
            &archive.display().to_string(),
            "--yes",
        ],
        &isolated_env(&home),
        None,
    );
    assert_eq!(code, 0, "ca-update: {stderr}");
    assert!(
        stderr.contains("current CA fingerprint") && stderr.contains("new CA fingerprint"),
        "both fingerprints are shown: {stderr}"
    );

    // The trust material is the rotated CA, nothing else moved.
    let new_ca = operator.get("/control/v1/ca");
    let new_pem = new_ca["ca"]["certificate_pem"].as_str().expect("the CA");
    let ca_bytes = std::fs::read(client_dir.join("ca.pem")).expect("ca.pem");
    assert_ne!(ca_bytes, old_ca_bytes, "the certificate was replaced");
    assert_eq!(ca_bytes, new_pem.as_bytes(), "it is the rotated CA");
    let toml = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    let fingerprint = new_ca["ca"]["fingerprint"].as_str().expect("fingerprint");
    let mut fingerprint_lines = 0;
    for (before, after) in old_toml.lines().zip(toml.lines()) {
        if before.starts_with("ca_fingerprint") {
            assert_eq!(
                after,
                format!("ca_fingerprint = \"{fingerprint}\""),
                "{toml}"
            );
            fingerprint_lines += 1;
        } else {
            assert_eq!(before, after, "only the fingerprint line moved");
        }
    }
    assert_eq!(fingerprint_lines, 1, "{old_toml}");
    assert_eq!(
        std::fs::read(client_dir.join("client-secret")).expect("client-secret"),
        old_secret_bytes,
        "the secret file is byte-identical"
    );

    // The old secret still authenticates; the client id is unchanged.
    let (code, stdout, stderr) = cli_raw(
        &["status", "--client", "--json"],
        &isolated_env(&home),
        None,
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["result"]["client"]["id"], "alpha", "{envelope}");

    // The bundle travels trust material alone.
    let members = read_zip(&archive);
    for (name, bytes) in &members {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains("jsc2_") && !text.contains("jse2_") && !text.contains("PRIVATE KEY"),
            "{name} carries a secret or a key"
        );
    }

    // A tampered bundle is refused with nothing replaced.
    let tampered = archive.with_extension("tampered.zip");
    write_tampered_ca_update(&tampered, &members);
    let (code, _, stderr) = cli_raw(
        &[
            "ca-update",
            "--from",
            &tampered.display().to_string(),
            "--yes",
        ],
        &isolated_env(&home),
        None,
    );
    assert_eq!(code, 17, "tampered: {stderr}");
    assert!(stderr.contains("cli_bundle_invalid"), "{stderr}");
    assert_eq!(
        std::fs::read(client_dir.join("ca.pem")).expect("ca.pem"),
        ca_bytes,
        "the tampered bundle replaced nothing"
    );
    assert_eq!(
        std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml"),
        toml,
    );
}

/// The advertised origins replace the listeners' bind addresses in the
/// invite and the CA update, even beside wildcard binds; beside a wildcard
/// bind with the key unset, the invite refuses naming the key before
/// anything is issued; with a concrete listen the origin is derived from
/// it; and a malformed advertised origin refuses to start.
#[tokio::test(flavor = "multi_thread")]
async fn advertised_origins_drive_the_invite_and_a_wildcard_needs_them() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start_with(
        "advertised-origins-drive-adv",
        Setup {
            clients: "advertised_base_url = \"https://pool.example.internal:17421\"\nadvertised_proxy_url = \"http://pool.example.internal:17422/\"\n".into(),
            wildcard: true,
            ..identity_setup()
        },
    )
    .await;
    let invite = decode_invite(&operator.invite("alpha", "Alpha", &[]));
    assert_eq!(
        invite["base_url"], "https://pool.example.internal:17421",
        "{invite}"
    );
    assert!(invite["identity"].is_string(), "{invite}");
    let (code, stdout, stderr) = operator.cli(&[
        "ca",
        "update-bundle",
        "--out",
        &operator.out.display().to_string(),
        "--json",
    ]);
    assert_eq!(code, 0, "update-bundle: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the CLI envelope");
    let archive = PathBuf::from(envelope["result"]["archive"].as_str().expect("archive"));
    let ca_update = read_zip(&archive)
        .into_iter()
        .find(|(name, _)| name == "ca-update.json")
        .map(|(_, bytes)| serde_json::from_slice::<Value>(&bytes).expect("ca-update.json"))
        .expect("ca-update.json");
    assert_eq!(
        ca_update["origins"],
        json!([
            "https://pool.example.internal:17421",
            "http://pool.example.internal:17422"
        ]),
        "{ca_update}"
    );

    // Both keys unset beside wildcard binds: the invite refuses before the
    // pending generation exists.
    let operator = Operator::start_with(
        "advertised-origins-drive-wild",
        Setup {
            wildcard: true,
            ..identity_setup()
        },
    )
    .await;
    let (code, stdout, stderr) = operator.cli(&["client", "invite", "beta"]);
    assert_eq!(code, 3, "{stdout}{stderr}");
    assert!(
        stderr.contains("clients.advertised_base_url"),
        "{stdout}{stderr}"
    );
    let (code, _, _) = operator.cli(&["client", "show", "beta"]);
    assert_eq!(code, 6, "no client was issued");
    let (code, stdout, stderr) = operator.cli(&[
        "ca",
        "update-bundle",
        "--out",
        &operator.out.display().to_string(),
    ]);
    assert_eq!(code, 3, "{stdout}{stderr}");
    assert!(
        format!("{stdout}{stderr}").contains("clients.advertised_base_url"),
        "{stdout}{stderr}"
    );

    // A concrete loopback listen: the origin is derived, over TLS.
    let operator = Operator::start("advertised-origins-drive-derived").await;
    let invite = decode_invite(&operator.invite("gamma", "Gamma", &[]));
    assert_eq!(
        invite["base_url"],
        format!("https://{}", operator.instance.addr),
        "{invite}"
    );

    // A malformed advertised origin is refused at start-up, naming the key.
    let (exit, stderr) = Instance::start_expecting_failure(
        "advertised-origins-drive-bad",
        Setup {
            clients: "advertised_base_url = \"pool.example.internal:17421\"\n".into(),
            ..Setup::default()
        },
    )
    .await;
    assert_eq!(exit, 3, "{stderr}");
    assert!(stderr.contains("clients.advertised_base_url"), "{stderr}");
}

/// A refused client credential is the pre-principal
/// answer, which carries no `control_api_version`; `status --client` maps it
/// to exit 5 `cli_refused`, not exit 10 `cli_incompatible_server`.
#[tokio::test(flavor = "multi_thread")]
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

    let (exit, stdout, stderr) = operator.cli(&["client", "revoke", "alpha", "--yes"]);
    assert_eq!(exit, 0, "revoke: {stdout}{stderr}");

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
    let (home, _) = enrol_one(&operator, "eng", "Eng Desk").await;

    let (exit, stdout, stderr) = operator.cli(&["status", "--json"]);
    assert_eq!(exit, 0, "the operator form: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert!(
        envelope["result"]["status"]["accounts"].is_array(),
        "host control reads the operator projection: {envelope}"
    );

    // The engineer's side: the client projection carries no operator facts.
    let env = isolated_env(&home);
    let (exit, stdout, stderr) = cli_raw(&["status", "--json"], &env, None);
    assert_eq!(exit, 0, "the client form: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["role"], "client", "{envelope}");
    assert!(
        envelope["result"]["accounts"].is_null(),
        "the client projection carries no operator facts: {envelope}"
    );

    // The engineer's secret at the operator surface: refused.
    let (exit, stdout, stderr) =
        cli_raw(&["api", "GET", "/control/v1/status", "--json"], &env, None);
    assert_eq!(exit, 0, "the exchange itself: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["result"]["status"], 403, "{envelope}");
    let body: Value =
        serde_json::from_str(envelope["result"]["body"].as_str().expect("body")).expect("JSON");
    assert_eq!(body["error"]["code"], "operator_required", "{body}");

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
/// directory is 0700 and `client-secret` 0600 through the join and a
/// `secret set` replacement, and on Windows the ACL read back with the real
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
        let rotated = operator.rotate("alpha");
        let env = isolated_env(&home);
        let (exit, _, stderr) = cli_raw(&["secret", "set", "--stdin"], &env, Some(&rotated));
        assert_eq!(exit, 0, "secret set: {stderr}");
        assert_eq!(
            mode_of(&client_dir.join("client-secret")),
            0o600,
            "still 0600 after the replacement"
        );
    }

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

    // On the enrolled machine the guard refuses before the claim, so the
    // invite stays unspent and every hash unchanged.
    let invite = operator.invite("desk-2", "Desk Two", &[]);
    let (exit, transcript) = join_from(&home, &invite, &[]);
    assert_eq!(
        exit, 8,
        "an enrolled machine refuses a second join: {transcript}"
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

    // The same invite with a wrong code, into a clean home: the claim is
    // refused and nothing is installed.
    let second = scratch("failed-claim-leaves-prior-second").join("home");
    private_dir(&second);
    let mut wrong = decode_invite(&invite);
    wrong["code"] = json!("jse2_not-the-code");
    let (exit, transcript) = join_from(&second, &encode_invite(&wrong), &[]);
    assert_eq!(exit, 5, "the server refuses the wrong code: {transcript}");
    assert!(
        transcript.contains("the server refused the invite"),
        "{transcript}"
    );
    assert!(
        !config_root(&second).join("client").exists(),
        "nothing was installed: {transcript}"
    );
    assert_eq!(
        install_snapshot(&home),
        before,
        "the prior install is untouched by the other machine's refusal"
    );

    // A lost response: the instance stops before the claim.
    let invite = operator.invite("desk-3", "Desk Three", &[]);
    operator.instance.stop();
    let (exit, transcript) = join_from(&second, &invite, &[]);
    assert_eq!(exit, 4, "the claim never answers: {transcript}");
    assert!(transcript.contains("nothing was installed"), "{transcript}");
    let second_root = config_root(&second);
    assert!(
        !second_root.join("client").exists() && !second_root.join("bin").exists(),
        "no staging is left under the configuration root"
    );
    assert_eq!(
        install_snapshot(&home),
        before,
        "the prior install is still byte-identical"
    );
}

/// A join and a CA update change only the trust material: the join makes
/// no OS trust-store call, `ca-update` shows the installed and the new
/// fingerprint and refuses without a confirmed comparison, a yes replaces
/// only `ca.pem` and the fingerprint line in `client.toml` (the secret, id,
/// generation and the settings entries stay byte-identical), and
/// `trust-ca add`/`remove` act on the exact confirmed fingerprint alone,
/// never touching another certificate in the store; without a terminal the
/// option refuses before any store call, and a failing store call is
/// reported.
#[tokio::test(flavor = "multi_thread")]
async fn a_ca_update_and_the_os_store_touch_only_the_ca() {
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    use crate::fake_tools::FakeTools;

    let _leak_sweep = crate::leaks::LeakGuard::default();
    let operator = Operator::start("ca-update-os-store").await;
    let tools = FakeTools::new(
        &scratch("ca-update-os-store-fake-tools"),
        &["security", "certutil"],
    );
    let (tool, add_head) = if cfg!(target_os = "macos") {
        ("security", "add-trusted-cert")
    } else {
        ("certutil", "-addstore")
    };
    let home = scratch("ca-update-os-store-engineer").join("home");
    private_dir(&home);
    let invite = operator.invite("alpha", "Alpha Desk", &[]);
    let (exit, transcript) = join_from(&home, &invite, &tools.env());
    assert_eq!(exit, 0, "join: {transcript}");
    assert!(
        tools.records().is_empty(),
        "the join makes no OS trust-store call: {:?}",
        tools.records()
    );
    let client_dir = config_root(&home).join("client");
    let old_toml = std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml");
    let old_secret = std::fs::read(client_dir.join("client-secret")).expect("client-secret");
    let old_ca = std::fs::read(client_dir.join("ca.pem")).expect("ca.pem");
    let old_settings =
        std::fs::read_to_string(home.join(".claude/settings.json")).expect("settings.json");
    let installed_fingerprint = old_toml
        .split("ca_fingerprint = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("client.toml names the CA fingerprint")
        .to_string();

    // The operator rotates the CA and packages the ZIP: its name is the
    // first 12 hex of the new fingerprint and it holds exactly the three
    // members.
    let (code, _, stderr) = operator.cli(&["ca", "rotate", "--yes"]);
    assert_eq!(code, 0, "rotate: {stderr}");
    let new_ca = operator.get("/control/v1/ca");
    let new_pem = new_ca["ca"]["certificate_pem"]
        .as_str()
        .expect("the rotated CA");
    let new_fingerprint = new_ca["ca"]["fingerprint"].as_str().expect("fingerprint");
    let (code, stdout, stderr) = operator.cli(&[
        "ca",
        "update-bundle",
        "--out",
        &operator.out.display().to_string(),
        "--json",
    ]);
    assert_eq!(code, 0, "update-bundle: {stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("the CLI envelope");
    let archive = PathBuf::from(envelope["result"]["archive"].as_str().expect("archive"));
    let hex: String = new_fingerprint.chars().filter(|c| *c != ':').collect();
    assert_eq!(
        archive
            .file_name()
            .expect("the ZIP's name")
            .to_string_lossy(),
        format!("jaynshare-ca-update-{}.zip", hex[..12].to_lowercase()),
        "the ZIP name"
    );
    let members = read_zip(&archive)
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<String>>();
    let mut members = members.iter().map(String::as_str).collect::<Vec<&str>>();
    members.sort_unstable();
    assert_eq!(
        members,
        ["README.txt", "ca-update.json", "ca.pem"],
        "the members, nothing else"
    );

    // On a terminal `ca-update` shows the installed fingerprint (the
    // old one, from `client.toml`) beside the new one, and answering no
    // refuses with nothing replaced.
    let env = isolated_env(&home);
    let (exit, transcript) = cli_pty_answers(
        "ca-update-os-store-ca-update-refused",
        &["ca-update", "--from", &archive.display().to_string()],
        &env,
        &[("independent channel", "n\n")],
    );
    assert_eq!(exit, 21, "the refusal: {transcript}");
    assert!(
        transcript.contains(&installed_fingerprint),
        "the installed fingerprint is shown: {transcript}"
    );
    assert!(
        transcript.contains(new_fingerprint),
        "the new fingerprint is shown: {transcript}"
    );
    assert_eq!(
        std::fs::read_to_string(client_dir.join("client.toml")).expect("client.toml"),
        old_toml,
        "the refusal replaced nothing in client.toml"
    );
    assert_eq!(
        std::fs::read(client_dir.join("client-secret")).expect("client-secret"),
        old_secret,
        "the refusal touched no secret"
    );
    assert_eq!(
        std::fs::read(client_dir.join("ca.pem")).expect("ca.pem"),
        old_ca,
        "the refusal replaced no certificate"
    );

    // Again, with the confirmed comparison: only the trust material moves.
    let (exit, transcript) = cli_pty_answers(
        "ca-update-os-store-ca-update-confirmed",
        &["ca-update", "--from", &archive.display().to_string()],
        &env,
        &[("independent channel", "y\n")],
    );
    assert_eq!(exit, 0, "the confirmed update: {transcript}");
    let ca_bytes = std::fs::read(client_dir.join("ca.pem")).expect("ca.pem");
    assert_eq!(ca_bytes, new_pem.as_bytes(), "ca.pem is the rotated CA");
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
            // So the client id, the generation and the identity pin in
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

    // Over the fake OS store: `trust-ca add` explains the broader
    // effect and adds exactly the confirmed certificate, once.
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

    // A store whose `add` fails: the failure is named, and the file-based
    // trust the launches use is unaffected.
    tools
        .rule(tool, &[add_head])
        .exit(1)
        .stderr("boom\n")
        .times(1);
    let (exit, transcript) = cli_pty_answers(
        "ca-update-os-store-trust-ca-add-fails",
        &["trust-ca", "add"],
        &store_env,
        &[("Add this CA to the OS trust store?", "y\n")],
    );
    assert_eq!(exit, 1, "the failing store call: {transcript}");
    assert!(
        transcript.contains("boom"),
        "the failure is named: {transcript}"
    );
    assert_eq!(
        std::fs::read(client_dir.join("ca.pem")).expect("ca.pem"),
        ca_bytes,
        "ca.pem is untouched"
    );
}
