//! Release verification: each test builds its release with
//! `release_fx::write_release` and plants its own key through the
//! production `release.pub` store.

#[allow(unused_imports)]
use crate::enrol::config_root;
#[allow(unused_imports)]
use crate::harness::{Value, binary, cli_raw, isolated_env, private_dir, scratch};
#[allow(unused_imports)]
use crate::release_fx::{FIXTURE_VERSION, ReleaseKey, write_release};

use std::path::{Path, PathBuf};

/// The embedded release key's id (`deploy/release-key.pub`'s key id, the
/// eight bytes after `Ed`, as 16 uppercase hex digits), the active key when
/// no `release.pub` is planted.
fn embedded_key_id() -> String {
    use base64::Engine as _;
    let file = include_str!("../../deploy/release-key.pub");
    let line = file.lines().nth(1).expect("the key line");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(line.trim())
        .expect("the key is base64");
    decoded[2..10].iter().map(|b| format!("{b:02X}")).collect()
}

/// `release verify <dir> [--key-id <id>] --json` with exactly the isolated
/// environment: (exit, envelope, stderr).
fn verify(home: &Path, dir: &Path, key_id: Option<&str>) -> (i32, Value, String) {
    let dir_arg = dir.display().to_string();
    let mut owned: Vec<String> = vec!["release".into(), "verify".into(), dir_arg];
    if let Some(id) = key_id {
        owned.push("--key-id".into());
        owned.push(id.into());
    }
    owned.push("--json".into());
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = cli_raw(&args, &isolated_env(home), None);
    let envelope = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    (code, envelope, stderr)
}

/// The active-key store's bytes and mode.
fn store(home: &Path) -> (Vec<u8>, u32) {
    let path = config_root(home).join("release.pub");
    let bytes = std::fs::read(&path).expect("release.pub");
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(&path)
            .expect("release.pub metadata")
            .permissions()
            .mode()
    };
    #[cfg(not(unix))]
    let mode = 0;
    (bytes, mode & 0o777)
}

/// The `signature` check of a failed verify's JSON envelope.
fn signature_check(envelope: &Value) -> &Value {
    envelope["error"]["details"][0]["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "signature")
        .expect("the signature check")
}

/// The release signatures are real minisign
/// files, `release.pub` is the single active-key store and replaces
/// the embedded key, and a rotation overlap (`--key-id`) admits the next key only after the current key verified it.
#[tokio::test(flavor = "multi_thread")]
async fn the_active_key_and_the_rotation_overlap() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("active-key-rotation");
    let key_a = ReleaseKey::generate();
    let key_b = ReleaseKey::generate();
    let dir = |name: &str| -> PathBuf { root.join(name) };

    // 1. No `release.pub` planted: the embedded key is active and does not
    // match, so a release signed by a fresh key fails as `signature` (17)
    // and the message names both key ids.
    let home = root.join("home-no-store");
    private_dir(&home);
    let release = write_release(&dir("no-store"), &key_a, |_| {}, |_| {});
    let (code, envelope, stderr) = verify(&home, &release, None);
    assert_eq!(
        code, 17,
        "an untrusted signature stops the verify: {stderr}"
    );
    let check = signature_check(&envelope);
    assert_eq!(check["passed"], false, "{envelope}");
    let message = check["message"].as_str().expect("message");
    assert!(
        message.contains(&key_a.id()) && message.contains(&embedded_key_id()),
        "names both key ids: {message}"
    );

    // 2. Key A planted, release signed by A: the signature check passes and
    // the manifest checks follow. The store still holds exactly A.
    let home = root.join("home-a");
    private_dir(&home);
    key_a.plant(&home);
    let release = write_release(&dir("signed-a"), &key_a, |_| {}, |_| {});
    let (code, _, stderr) = verify(&home, &release, None);
    assert!(
        code == 0,
        "the signature and manifest checks must pass: {code} {stderr}"
    );
    assert_eq!(
        store(&home).0,
        key_a.public_file(),
        "the store is untouched"
    );

    // 3. Key A planted, release signed by B: 17, both key ids named.
    let release = write_release(&dir("signed-b"), &key_b, |_| {}, |_| {});
    let (code, envelope, stderr) = verify(&home, &release, None);
    assert_eq!(code, 17, "{stderr}");
    let message = signature_check(&envelope)["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains(&key_a.id()) && message.contains(&key_b.id()),
        "both ids named: {message}"
    );
    assert_eq!(store(&home).0, key_a.public_file(), "");

    // 4. A corrupt `release.pub` is a failed `key` check, never a fallback to
    // the embedded key.
    let home = root.join("home-corrupt");
    private_dir(&home);
    std::fs::create_dir_all(config_root(&home)).expect("config root");
    std::fs::write(
        config_root(&home).join("release.pub"),
        b"one line of garbage\n",
    )
    .expect("release.pub");
    let release = write_release(&dir("corrupt-store"), &key_a, |_| {}, |_| {});
    let (code, envelope, stderr) = verify(&home, &release, None);
    assert_eq!(code, 17, "{stderr}");
    let checks = envelope["error"]["details"][0]["checks"]
        .as_array()
        .expect("checks");
    assert_eq!(checks.len(), 1, "no signature check ran: {envelope}");
    assert_eq!(checks[0]["name"], "key", "{envelope}");
    assert_eq!(checks[0]["passed"], false, "{envelope}");

    // 5. The rotation overlap: signed by A, `next_key_id` = B, the B
    // signature and B's public file carried along. `--key-id <B>` passes
    // the signature check and admits B into the store; afterwards B alone
    // verifies and A alone fails.
    let home = root.join("home-overlap");
    private_dir(&home);
    key_a.plant(&home);
    let overlap = write_release(
        &dir("overlap"),
        &key_a,
        |parts| {
            parts.manifest["next_key_id"] = serde_json::json!(key_b.id());
        },
        |files| {
            let manifest = files
                .iter()
                .find(|(name, _)| name == "release.json")
                .expect("release.json")
                .1
                .clone();
            files.push((
                format!("release.json.{}.minisig", key_b.id()),
                key_b.sign(&manifest),
            ));
            files.push((
                format!("release-key-{}.pub", key_b.id()),
                key_b.public_file(),
            ));
        },
    );
    let (code, _, stderr) = verify(&home, &overlap, Some(&key_b.id()));
    assert!(
        code == 0 || code == 101,
        "the overlap verifies and the next key is admitted: {code} {stderr}"
    );
    let (bytes, mode) = store(&home);
    assert_eq!(bytes, key_b.public_file(), ": B is admitted");
    assert_eq!(mode, 0o644, "the admitted key's mode");

    // After the admission B alone is the active key.
    let release = write_release(&dir("after-overlap-b"), &key_b, |_| {}, |_| {});
    let (code, _, stderr) = verify(&home, &release, None);
    assert!(
        code == 0 || code == 101,
        "B signs under the admitted key: {code} {stderr}"
    );
    let release = write_release(&dir("after-overlap-a"), &key_a, |_| {}, |_| {});
    let (code, envelope, stderr) = verify(&home, &release, None);
    assert_eq!(code, 17, "A is no longer trusted: {stderr}");
    let message = signature_check(&envelope)["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains(&key_a.id()) && message.contains(&key_b.id()),
        "both ids named: {message}"
    );

    // 6. The same overlap with a bad B signature: 17, and the store still
    // holds A — the next key is admitted only after it verified.
    let home = root.join("home-bad-overlap");
    private_dir(&home);
    key_a.plant(&home);
    let overlap = write_release(
        &dir("overlap-bad"),
        &key_a,
        |parts| {
            parts.manifest["next_key_id"] = serde_json::json!(key_b.id());
        },
        |files| {
            files.push((
                format!("release.json.{}.minisig", key_b.id()),
                key_b.sign(b"not the manifest"),
            ));
            files.push((
                format!("release-key-{}.pub", key_b.id()),
                key_b.public_file(),
            ));
        },
    );
    let (code, envelope, stderr) = verify(&home, &overlap, Some(&key_b.id()));
    assert_eq!(code, 17, "a bad next-key signature fails: {stderr}");
    let check = signature_check(&envelope);
    assert_eq!(check["passed"], false, "{envelope}");
    assert!(
        check["message"]
            .as_str()
            .expect("message")
            .contains(&key_b.id()),
        "the failure names the next key: {envelope}"
    );
    assert_eq!(store(&home).0, key_a.public_file(), ": A stands");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_idle_server_makes_no_release_request() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    use crate::harness::{Instance, StatusCode, haiku_prompt, messages, send};

    let instance = Instance::start("idle-server-makes-no-release").await;
    instance.add_fsub();

    // Three exchanges, then the server is left idle: nothing in the idle
    // window may contact the release host.
    for _ in 0..3 {
        assert_eq!(
            send(instance.addr, messages(haiku_prompt())).await.status,
            StatusCode::OK
        );
    }
    instance.settle();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Every path the fake upstream saw is an exchange or one of the
    // documented endpoints — the same list asserts over.
    let seen = instance.upstream.seen();
    let allowed = [
        "/v1/messages",
        "/api/oauth/usage",
        "/api/oauth/profile",
        "/v1/oauth/token",
    ];
    for entry in &seen {
        assert!(
            allowed.contains(&entry.path.as_str()),
            "an idle server contacts only the exchange or the egress endpoints: {}",
            entry.path
        );
    }

    // The binary names the release origin only in its fetching verbs'
    // constant.
    let bytes = std::fs::read(crate::harness::binary()).expect("release binary");
    let needle = |text: &[u8], pattern: &str| {
        text.windows(pattern.len())
            .filter(|w| *w == pattern.as_bytes())
            .count()
    };
    assert_eq!(
        needle(&bytes, "github.com/jaynlabs/jaynshare/releases"),
        1,
        "the release origin is named only by the `OFFICIAL_ORIGIN` constant"
    );

    // `status --json` carries no member naming a release check, an update or
    // A latest version: the idle surface names nothing to fetch.
    let (exit, stdout, stderr) = instance.cli(&["status", "--json"], None);
    assert_eq!(exit, 0, "status --json failed: {stderr}");
    let status: serde_json::Value = serde_json::from_str(&stdout).expect("status --json is JSON");
    fn walk(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, member) in map {
                    out.push(key.clone());
                    walk(member, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, out);
                }
            }
            _ => {}
        }
    }
    let mut keys = Vec::new();
    walk(&status, &mut keys);
    for key in &keys {
        assert!(
            !key.contains("update") && !key.contains("latest"),
            "status names no release check, update or latest version: {key}"
        );
    }
}

// ------------------------------------------------------------------ scenarios

/// One release set, one version, only the allowed files:
/// `tools/release/build.py` produces the six artifacts plus
/// the three release-set files, each archive holding exactly its
/// four entries, the host archive's executable being the binary under test,
/// and `release verify` accepting the set under the minted key.
#[tokio::test(flavor = "multi_thread")]
async fn one_release_set_one_version_only_the_allowed_files() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let python_ok = std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !python_ok {
        eprintln!("skipping: python3 is absent");
        return;
    }

    let root = scratch("release-set-version");
    let home = root.join("home");
    let seed = root.join("seed.bin");
    let public = root.join("release.pub");
    let minted = std::process::Command::new("python3")
        .args([
            "tools/make-client-kit.py",
            "keygen",
            "--pub",
            &public.display().to_string(),
            "--seed",
            &seed.display().to_string(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run make-client-kit.py keygen");
    assert!(
        minted.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&minted.stderr)
    );

    let version = "0.7.0";
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let host = host_target();
    let out = root.join("out");
    let built = std::process::Command::new("python3")
        .args([
            "tools/release/build.py",
            "--version",
            version,
            "--commit",
            commit,
            "--key",
            &seed.display().to_string(),
            "--bin",
            &format!("{host}={}", binary().display()),
            "--allow-placeholder",
            "--out",
            &out.display().to_string(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run build.py");
    assert!(
        built.status.success(),
        "build.py: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let stderr = String::from_utf8_lossy(&built.stderr);
    assert!(
        stderr.matches("placeholder executable").count() == 4,
        "the four placeholder targets are announced on stderr: {stderr}"
    );

    // Exactly the six artifacts plus the three release-set files.
    let mut files: Vec<String> = std::fs::read_dir(&out)
        .expect("release directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    files.sort();
    let targets = [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ];
    let mut artifacts: Vec<String> = targets
        .iter()
        .map(|target| {
            if *target == "x86_64-pc-windows-msvc" {
                format!("jaynshare-{version}-{target}.zip")
            } else {
                format!("jaynshare-{version}-{target}.tar.gz")
            }
        })
        .chain([format!("jaynshare-{version}-client-kit.zip")])
        .collect::<Vec<_>>();
    artifacts.sort();
    let mut expected = artifacts.clone();
    expected.extend([
        "SHA256SUMS".to_owned(),
        "release.json".to_owned(),
        "release.json.minisig".to_owned(),
    ]);
    expected.sort();
    assert_eq!(files, expected, "only the allowed files");

    // Each platform archive lists exactly its four entries under
    // its root; the kits follow the kit layouts, not this shape.
    for target in &targets {
        let extension = if *target == "x86_64-pc-windows-msvc" {
            "zip"
        } else {
            "tar.gz"
        };
        let name = format!("jaynshare-{version}-{target}.{extension}");
        let path = out.join(&name);
        let root_name = format!("jaynshare-{version}-{target}");
        let names: Vec<String> = if extension == "zip" {
            let file = std::fs::File::open(&path).expect("open the archive");
            let mut archive = zip::ZipArchive::new(file).expect("read the archive");
            (0..archive.len())
                .map(|i| archive.by_index(i).expect("member").name().to_string())
                .collect()
        } else {
            let listed = std::process::Command::new("tar")
                .args(["tzf", &path.display().to_string()])
                .output()
                .expect("run tar");
            assert!(listed.status.success(), "tar tzf {name}");
            String::from_utf8_lossy(&listed.stdout)
                .lines()
                .map(str::to_owned)
                .collect()
        };
        // A tar archive opens with its root's own entry (the installer's
        // staging reads it); the members follow.
        if extension != "zip" {
            assert_eq!(
                names.first().map(String::as_str),
                Some(format!("{root_name}/").as_str()),
                "{name}: the root entry first"
            );
        }
        let members: Vec<&str> = names
            .iter()
            .filter(|n| **n != format!("{root_name}/"))
            .map(|n| n.strip_prefix(&format!("{root_name}/")).expect("rooted"))
            .collect();
        let executable = if extension == "zip" {
            "jaynshare.exe"
        } else {
            "jaynshare"
        };
        assert_eq!(
            members,
            [executable, "LICENSE", "NOTICE.md", "README.txt"].to_vec(),
            "{name}: exactly its four entries under {root_name}"
        );
    }

    // The host archive's executable is the binary under test
    // and reports the same `version`.
    let extract = root.join("extract");
    std::fs::create_dir_all(&extract).expect("extract directory");
    let host_archive = out.join(format!("jaynshare-{version}-{host}.tar.gz"));
    let extracted = std::process::Command::new("tar")
        .args([
            "xzf",
            &host_archive.display().to_string(),
            "-C",
            &extract.display().to_string(),
        ])
        .status()
        .expect("run tar");
    assert!(extracted.success(), "tar xzf the host archive");
    let extracted_bin = extract
        .join(format!("jaynshare-{version}-{host}"))
        .join("jaynshare")
        .canonicalize()
        .expect("the extracted executable");
    let shipped = std::process::Command::new(&extracted_bin)
        .arg("version")
        .output()
        .expect("run the extracted executable");
    assert!(shipped.status.success(), "the extracted executable runs");
    let under_test = std::process::Command::new(binary())
        .arg("version")
        .output()
        .expect("run the binary under test");
    assert_eq!(
        String::from_utf8_lossy(shipped.stdout.trim_ascii()),
        String::from_utf8_lossy(under_test.stdout.trim_ascii()),
        "the shipped executable reports the same version"
    );

    // Release.json parses, agrees with SHA256SUMS, and carries the
    // six artifacts.
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.join("release.json")).expect("read release.json"),
    )
    .expect("release.json parses");
    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["version"], version);
    assert_eq!(manifest["commit"], commit);
    assert_eq!(
        manifest["artifacts"].as_array().expect("artifacts").len(),
        6
    );
    let sums = std::fs::read(out.join("SHA256SUMS")).expect("read SHA256SUMS");
    assert_eq!(
        manifest["sha256sums_sha256"],
        crate::release_fx::sha256_hex(&sums),
        "release.json agrees with SHA256SUMS"
    );

    // `release verify` accepts the whole set under the minted key.
    let config = crate::enrol::config_root(&home);
    crate::harness::private_dir(&config);
    std::fs::write(
        config.join("release.pub"),
        std::fs::read(&public).expect("read the minted public key"),
    )
    .expect("plant release.pub");
    let (code, stdout, stderr) = cli_raw(
        &["release", "verify", &out.display().to_string()],
        &isolated_env(&home),
        None,
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
}

/// the target for the machine the suite runs on.
fn host_target() -> &'static str {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "linux") => "x86_64-unknown-linux-musl",
        ("aarch64", "linux") => "aarch64-unknown-linux-musl",
        _ => panic!("no release target for this machine"),
    }
}

/// `release fetch` (the explicit release-host contact): the release set,
/// the archive and the client kit come from the named mirror and nothing
/// else is requested; a redirect is followed only within the mirror's host; a
/// mirror that is not plain `https` is a usage error; a
/// tampered archive is a release failure; a stopped host is unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn release_fetch_contacts_only_the_named_origin() {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use http::Request;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    use crate::harness::{Bytes, Full, Infallible, Response, fs, stage_tls_pair};
    use crate::release_fx::{FIXTURE_VERSION, artifact_names};

    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("idle-server-makes-no-release-b");
    let home = root.join("home");
    let key = ReleaseKey::generate();
    let served = root.join("served");
    let release = write_release(&served, &key, |_| {}, |_| {});
    let env = isolated_env(&home);
    key.plant(&home);

    // The release host: TLS from the committed pair, `GET /v<version>/<name>`
    // answered from `served`, anything else 404, every request counted.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (cert, key_file) = stage_tls_pair(&root.join("tls"));
    let acceptor = release_acceptor(&cert, &key_file);
    let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let served_dir = std::sync::Arc::new(std::sync::Mutex::new(served.clone()));
    let requests = std::sync::Arc::new(AtomicUsize::new(0));
    // When set, `/v<version>/<name>` answers 302 to `https://<this>/assets/<name>`.
    let redirect_to: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
    tokio::spawn({
        let seen = seen.clone();
        let served_dir = served_dir.clone();
        let requests = requests.clone();
        let redirect_to = redirect_to.clone();
        async move {
            loop {
                let Ok((plain, _)) = listener.accept().await else {
                    return;
                };
                let Ok(stream) = acceptor.accept(plain).await else {
                    continue;
                };
                let seen = seen.clone();
                let served_dir = served_dir.clone();
                let requests = requests.clone();
                let redirect_to = redirect_to.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<_>| {
                        let seen = seen.clone();
                        let served_dir = served_dir.clone();
                        let requests = requests.clone();
                        let redirect_to = redirect_to.clone();
                        async move {
                            requests.fetch_add(1, AtomicOrdering::SeqCst);
                            let path = request.uri().path().to_string();
                            seen.lock().expect("seen").push(path.clone());
                            let name = path.split('/').nth(2).unwrap_or("");
                            let redirect = redirect_to.lock().expect("redirect").clone();
                            if let Some(authority) = redirect.filter(|_| path.starts_with("/v")) {
                                return Ok(Response::builder()
                                    .status(http::StatusCode::FOUND)
                                    .header(
                                        http::header::LOCATION,
                                        format!("https://{authority}/assets/{name}"),
                                    )
                                    .body(Full::new(Bytes::new()))
                                    .expect("redirect"));
                            }
                            let (status, bytes) =
                                match fs::read(served_dir.lock().expect("served").join(name)) {
                                    Ok(bytes) => (http::StatusCode::OK, bytes),
                                    Err(_) => (http::StatusCode::NOT_FOUND, Vec::new()),
                                };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from(bytes)))
                                    .expect("response"),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    });
    let origin = format!("https://localhost:{}", addr.port());

    // The happy leg: the release set, this host's archive and the client
    // kit, from this origin only.
    let out = root.join("out");
    let (code, stdout, stderr) = cli_raw(
        &[
            "release",
            "fetch",
            FIXTURE_VERSION,
            "--out",
            out.to_str().expect("out path"),
            "--release-origin",
            &origin,
            "--tls-ca",
            CA_PEM,
        ],
        &env,
        None,
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    let expected: Vec<String> = ["release.json", "release.json.minisig", "SHA256SUMS"]
        .iter()
        .map(|n| n.to_string())
        .chain(
            artifact_names(FIXTURE_VERSION)
                .into_iter()
                .filter(|(_, purpose, target)| {
                    *purpose == "client-kit" || *target == Some(host_target())
                })
                .map(|(name, _, _)| name),
        )
        .collect();
    let written: Vec<String> = std::fs::read_dir(&out)
        .expect("out")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(written.len(), expected.len(), "{written:?}");
    for name in &expected {
        assert!(
            written.contains(name),
            "{name} missing from {written:?}; the release set is complete"
        );
        assert_eq!(
            fs::read(out.join(name)).expect("fetched bytes"),
            fs::read(release.join(name)).expect("served bytes"),
            "{name} arrives byte-for-byte"
        );
    }
    let requested = seen.lock().expect("seen").clone();
    let mut wanted: Vec<String> = expected
        .iter()
        .map(|name| format!("/v{FIXTURE_VERSION}/{name}"))
        .collect();
    wanted.sort();
    let mut got = requested.clone();
    got.sort();
    assert_eq!(got, wanted, "only the release set was requested");

    // GitHub answers every asset with a redirect: one within the mirror's
    // host is followed; one to another host fails without contacting it.
    let fetch = |out: &std::path::Path| {
        cli_raw(
            &[
                "release",
                "fetch",
                FIXTURE_VERSION,
                "--out",
                out.to_str().expect("out path"),
                "--release-origin",
                &origin,
                "--tls-ca",
                CA_PEM,
            ],
            &env,
            None,
        )
    };
    *redirect_to.lock().expect("redirect") = Some(format!("localhost:{}", addr.port()));
    let out = root.join("out-redirected");
    let (code, stdout, stderr) = fetch(&out);
    assert_eq!(code, 0, "{stdout}{stderr}");
    for name in &expected {
        assert_eq!(
            fs::read(out.join(name)).expect("fetched bytes"),
            fs::read(release.join(name)).expect("served bytes"),
            "{name} arrives byte-for-byte through the redirect"
        );
    }
    *redirect_to.lock().expect("redirect") = Some(format!("127.0.0.1:{}", addr.port()));
    seen.lock().expect("seen").clear();
    let (code, stdout, stderr) = fetch(&root.join("out-foreign"));
    assert_eq!(code, 17, "{stdout}{stderr}");
    let requested = seen.lock().expect("seen").clone();
    assert_eq!(
        requested,
        [format!("/v{FIXTURE_VERSION}/release.json")],
        "the foreign redirect target is never contacted"
    );
    *redirect_to.lock().expect("redirect") = None;

    // A mirror that is not plain https with no user information, query or
    // fragment is a usage error, and contacts nothing.
    let requests_before = requests.load(AtomicOrdering::SeqCst);
    for bad in [
        format!("http://localhost:{}", addr.port()),
        "https://user@localhost:1".to_string(),
        "https://localhost:1/x?y".to_string(),
    ] {
        let other = root.join("out-bad");
        let (code, stdout, stderr) = cli_raw(
            &[
                "release",
                "fetch",
                FIXTURE_VERSION,
                "--out",
                other.to_str().expect("path"),
                "--release-origin",
                &bad,
                "--tls-ca",
                CA_PEM,
            ],
            &env,
            None,
        );
        assert_eq!(code, 2, "{bad}: {stdout}{stderr}");
    }
    assert_eq!(
        requests.load(AtomicOrdering::SeqCst),
        requests_before,
        "a refused origin contacts no host"
    );

    // One flipped byte in the requested archive is a release failure naming
    // the artifact and the check, caught before anything installs.
    let tampered = root.join("served-tampered");
    write_release(
        &tampered,
        &key,
        |_| {},
        |files| {
            let name = format!("jaynshare-{FIXTURE_VERSION}-x86_64-unknown-linux-musl.tar.gz");
            let entry = files
                .iter_mut()
                .find(|(n, _)| *n == name)
                .expect("the linux-musl archive");
            entry.1[0] ^= 0xff;
        },
    );
    *served_dir.lock().expect("served") = tampered;
    let out = root.join("out-tampered");
    let (code, stdout, stderr) = cli_raw(
        &[
            "release",
            "fetch",
            FIXTURE_VERSION,
            "--out",
            out.to_str().expect("path"),
            "--release-origin",
            &origin,
            "--tls-ca",
            CA_PEM,
            "--target",
            "x86_64-unknown-linux-musl",
        ],
        &env,
        None,
    );
    assert_eq!(code, 17, "{stdout}{stderr}");
    assert!(
        stderr.contains("release.artifact"),
        "the artifact check is named: {stderr}"
    );

    // A host that does not answer is unreachable (exit 4), never a download
    // lie: a port is reserved, then nothing listens on it.
    let stopped = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let stopped_port = stopped.local_addr().expect("port").port();
    drop(stopped);
    let out = root.join("out-stopped");
    let (code, stdout, stderr) = cli_raw(
        &[
            "release",
            "fetch",
            FIXTURE_VERSION,
            "--out",
            out.to_str().expect("path"),
            "--release-origin",
            &format!("https://localhost:{stopped_port}"),
            "--tls-ca",
            CA_PEM,
            "--target",
            "x86_64-unknown-linux-musl",
        ],
        &env,
        None,
    );
    assert_eq!(code, 4, "{stdout}{stderr}");
}

/// A copy of the harness's `test_acceptor` (it is harness-private): the
/// staged certificate chain and key as a TLS acceptor.
fn release_acceptor(cert: &std::path::Path, key: &std::path::Path) -> tokio_rustls::TlsAcceptor {
    use rustls_pki_types::pem::PemObject;
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key).expect("fake key parses");
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(cert)
        .expect("fake certificate")
        .collect::<Result<_, _>>()
        .expect("fake certificate parses");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("the fake pair loads");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
}

/// The committed test CA, the anchor `--tls-ca` carries.
const CA_PEM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/acceptance/fixtures/tls/test-ca.pem"
);

/// swaps the first two `SHA256SUMS` lines, keeping the rest byte for
/// byte (each line is `<64 hex> <name>\n`, so the byte positions are exact).
fn swap_first_two_sums_lines(bytes: Vec<u8>) -> Vec<u8> {
    let first = bytes.iter().position(|&b| b == b'\n').unwrap();
    let second = first + 1 + bytes[first + 1..].iter().position(|&b| b == b'\n').unwrap();
    let mut swapped = bytes[first + 1..second].to_vec();
    swapped.push(b'\n');
    swapped.extend_from_slice(&bytes[..first]);
    swapped.push(b'\n');
    swapped.extend_from_slice(&bytes[second + 1..]);
    swapped
}

/// `release verify` refuses any mismatch before
/// execution, in the order, naming the artifact and the failed check.
#[tokio::test(flavor = "multi_thread")]
async fn release_verify_refuses_any_mismatch_before_execution() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("release-verify-refuses");
    let home = root.join("home");
    let key = ReleaseKey::generate();
    key.plant(&home);
    let env = isolated_env(&home);
    let kit = format!("jaynshare-{FIXTURE_VERSION}-client-kit.zip");
    let verify = |path: &std::path::Path, extra: &[&str]| {
        let mut args = vec!["release", "verify", path.to_str().unwrap()];
        args.extend_from_slice(extra);
        cli_raw(&args, &env, None)
    };

    // The good release passes every check; --json carries the checks and the
    // version.
    let good = write_release(&root.join("good"), &key, |_| {}, |_| {});
    let (code, stdout, stderr) = verify(&good, &[]);
    assert_eq!(code, 0, "{stderr}");
    for check in [
        "release.canonical",
        "release.sums",
        "release.names",
        "release.unlisted",
        "release.artifact",
    ] {
        assert!(stdout.contains(&format!("ok     {check}:")), "{stdout}");
    }
    let (code, stdout, _) = verify(&good, &["--json"]);
    assert_eq!(code, 0, "{stdout}");
    let envelope: crate::harness::Value = stdout.trim().parse().expect("the envelope is JSON");
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["result"]["version"], FIXTURE_VERSION);
    for check in envelope["result"]["checks"].as_array().expect("checks") {
        assert_eq!(check["passed"], true, "{check}");
    }

    // Every failing case: exit 17, the failed check on standard error, and
    // `--json`'s envelope refuses with cli_release_unverified.
    let mut json_runs = 0;
    let mut fails = |dir: &std::path::Path, check: &str, needle: &str, json: bool| {
        let (code, _stdout, stderr) = verify(dir, &[]);
        assert_eq!(code, 17, "{check}: {stderr}");
        assert!(
            stderr
                .lines()
                .any(|line| line.starts_with(&format!("cli_release_unverified: {check}"))),
            "{check}: {stderr}"
        );
        assert!(stderr.contains(needle), "{check}: {stderr}");
        if json {
            let (code, stdout, _) = verify(dir, &["--json"]);
            assert_eq!(code, 17, "{stdout}");
            let envelope: crate::harness::Value =
                stdout.trim().parse().expect("the envelope is JSON");
            assert_eq!(envelope["ok"], false, "{stdout}");
            assert_eq!(
                envelope["error"]["code"], "cli_release_unverified",
                "{stdout}"
            );
            json_runs += 1;
        }
        let _ = check;
        let _ = needle;
        let _ = json;
        let _ = json_runs;
    };

    // One byte of the client kit flipped after signing: the artifact's digest.
    let flipped = write_release(
        &root.join("flipped"),
        &key,
        |_| {},
        |files| {
            let position = files.iter().position(|(name, _)| *name == kit).unwrap();
            files[position].1[0] ^= 0xff;
        },
    );
    fails(&flipped, "release.artifact", &kit, true);

    // A signed length lie in the manifest: the artifact's byte length.
    let length_lie = write_release(
        &root.join("length-lie"),
        &key,
        |parts| {
            for entry in parts.manifest["artifacts"].as_array_mut().unwrap() {
                if entry["filename"] == kit.as_str() {
                    entry["length"] = crate::harness::json!(entry["length"].as_u64().unwrap() + 1);
                }
            }
        },
        |_| {},
    );
    fails(&length_lie, "release.artifact", &kit, false);

    // A signed digest lie in the manifest: the artifact's digest.
    let digest_lie = write_release(
        &root.join("digest-lie"),
        &key,
        |parts| {
            for entry in parts.manifest["artifacts"].as_array_mut().unwrap() {
                if entry["filename"] == kit.as_str() {
                    entry["sha256"] = crate::harness::json!("0".repeat(64));
                }
            }
        },
        |_| {},
    );
    fails(&digest_lie, "release.artifact", &kit, false);

    // An artifact renamed in both the manifest and the directory: the
    // file name no longer follows the naming rule.
    let renamed = write_release(
        &root.join("renamed"),
        &key,
        |parts| {
            let old = format!("jaynshare-{FIXTURE_VERSION}-x86_64-apple-darwin.tar.gz");
            let new = format!("jaynshare-{FIXTURE_VERSION}-x86_64-apple-darwin.tgz");
            for entry in parts.manifest["artifacts"].as_array_mut().unwrap() {
                if entry["filename"] == old.as_str() {
                    entry["filename"] = crate::harness::json!(&new);
                }
            }
            for (name, _) in parts.artifacts.iter_mut() {
                if *name == old {
                    *name = new.clone();
                }
            }
            parts.manifest["sha256sums_sha256"] = crate::harness::json!(
                crate::release_fx::sha256_hex(&crate::release_fx::sha256sums(&parts.artifacts))
            );
        },
        |_| {},
    );
    let renamed_new = format!("jaynshare-{FIXTURE_VERSION}-x86_64-apple-darwin.tgz");
    fails(&renamed, "release.names", &renamed_new, false);

    // A duplicate artifact entry in the manifest.
    let duplicate = write_release(
        &root.join("duplicate"),
        &key,
        |parts| {
            let first = parts.manifest["artifacts"][0].clone();
            parts.manifest["artifacts"]
                .as_array_mut()
                .unwrap()
                .push(first);
        },
        |_| {},
    );
    let duplicated = format!("jaynshare-{FIXTURE_VERSION}-x86_64-unknown-linux-musl.tar.gz");
    fails(&duplicate, "release.names", &duplicated, false);

    // An extra file in the directory.
    let unlisted = write_release(
        &root.join("unlisted"),
        &key,
        |_| {},
        |files| {
            files.push(("notes.txt".into(), b"scratch\n".to_vec()));
        },
    );
    fails(&unlisted, "release.unlisted", "notes.txt", false);

    // Two sums lines swapped, the manifest's digest updated before signing,
    // so only the bytewise order is wrong.
    let swapped = write_release(
        &root.join("swapped"),
        &key,
        |parts| {
            let sums = crate::release_fx::sha256sums(&parts.artifacts);
            let swapped = swap_first_two_sums_lines(sums);
            parts.manifest["sha256sums_sha256"] =
                crate::harness::json!(crate::release_fx::sha256_hex(&swapped));
        },
        |files| {
            let position = files
                .iter()
                .position(|(name, _)| name == "SHA256SUMS")
                .unwrap();
            files[position].1 = swap_first_two_sums_lines(std::mem::take(&mut files[position].1));
        },
    );
    fails(&swapped, "release.sums", "SHA256SUMS", false);

    // SHA256SUMS edited after signing: its digest no longer matches the
    // signed manifest.
    let edited_sums = write_release(
        &root.join("edited-sums"),
        &key,
        |_| {},
        |files| {
            let position = files
                .iter()
                .position(|(name, _)| name == "SHA256SUMS")
                .unwrap();
            files[position].1[0] ^= 1;
        },
    );
    fails(&edited_sums, "release.sums", "SHA256SUMS", false);

    // Verifying a single file: the good release passes, the flipped release
    // still refuses at the artifact.
    let kit_path = good.join(&kit);
    let (code, stdout, stderr) = verify(&kit_path, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("ok     release.artifact:"), "{stdout}");
    let flipped_kit = flipped.join(&kit);
    let (code, _stdout, stderr) = verify(&flipped_kit, &[]);
    assert_eq!(code, 17, "{stderr}");
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("cli_release_unverified: release.artifact")),
        "{stderr}"
    );
    assert!(stderr.contains(&kit), "{stderr}");
    assert!(json_runs >= 1, "--json must have run at least once");
}

use crate::linux_fx::head_commit;

// ------------------------------------------------------------------ publish.sh

/// `publish.sh`'s call sequence with a fake `gh` on `PATH` and a
/// fake `cross.sh` (`JAYNSHARE_CROSS`): one `build.py` call carries the
/// version, the signing key and all five `--bin` lines, and `gh release
/// create` receives absolute asset paths and creates the tag at the built
/// commit. A seed inside the repository is refused before anything runs.
#[test]
fn publish_script_runs_cross_build_publish_in_order() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let python_ok = std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !python_ok {
        eprintln!("skipping: python3 is absent");
        return;
    }

    let root = scratch("release-set-version-c");
    // The signing seed must live outside the repository; the
    // scenario root is inside it, so the seed goes to the system temporary
    // directory.
    let seed = std::env::temp_dir().join("release-set-version-c-seed.bin");
    let public = root.join("release.pub");
    let minted = std::process::Command::new("python3")
        .args([
            "tools/make-client-kit.py",
            "keygen",
            "--pub",
            &public.display().to_string(),
            "--seed",
            &seed.display().to_string(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run make-client-kit.py keygen");
    assert!(
        minted.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&minted.stderr)
    );

    let tools = crate::fake_tools::FakeTools::new(&root, &["gh", "python3"]);

    // The fake cross.sh: five stand-in binaries and the `--bin` lines
    // cross.sh prints.
    let fake_cross = root.join("fake-cross.sh");
    std::fs::write(
        &fake_cross,
        "#!/bin/sh\nset -eu\nfor t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-msvc; do\n  mkdir -p \"$2/$t\"\n  echo \"executable $t\" > \"$2/$t/jaynshare\"\n  echo \"--bin $t=$2/$t/jaynshare\"\ndone\n",
    )
    .expect("write fake cross.sh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_cross, std::fs::Permissions::from_mode(0o755))
            .expect("make the fake cross.sh executable");
    }

    let fake_build = root.join("fake-build.sh");
    std::fs::write(
        &fake_build,
        "#!/bin/sh\nset -eu\nout=\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = --out ]; then out=$2; shift 2; else shift; fi\ndone\nmkdir -p \"$out\"\ntouch \"$out/release.json\" \"$out/SHA256SUMS\"\n",
    )
    .expect("write fake build.py");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_build, std::fs::Permissions::from_mode(0o755))
            .expect("make the fake build.py executable");
    }
    tools
        .rule("python3", &["tools/release/build.py"])
        .run(&fake_build, &["{argv}"]);

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let publish = manifest.join("tools/release/publish.sh");
    let run_publish = |seed: &Path| {
        let mut path = tools.bin.display().to_string();
        path.push(':');
        path.push_str(&std::env::var("PATH").unwrap_or_default());
        let output = std::process::Command::new("bash")
            .arg(&publish)
            .arg("0.7.1-rc.1+build.7")
            .arg("--key")
            .arg(seed)
            .env("JAYNSHARE_CROSS", &fake_cross)
            .env("PATH", &path)
            .env("FAKE_TOOL_DIR", &tools.dir)
            .current_dir(&manifest)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run publish.sh");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    // 1. A seed inside the repository is refused before anything runs.
    let (code, _, stderr) = run_publish(&manifest.join("Cargo.toml"));
    assert_eq!(code, 2, "the seed refusal: {stderr}");
    assert!(
        stderr.contains("outside the repository"),
        "the refusal names the rule: {stderr}"
    );
    assert!(
        tools.records().is_empty(),
        "nothing ran: {:?}",
        tools.records()
    );

    // 2. The good seed runs the whole sequence. The fake packager writes two
    //    artifacts so the `gh` call can prove their paths and tag target.
    let (code, stdout, stderr) = run_publish(&seed);
    assert_eq!(code, 0, "the release succeeds: {stdout}{stderr}");
    assert!(
        stdout.contains("==> cross.sh")
            && stdout.contains("==> build.py")
            && stdout.contains("==> gh release create"),
        "the sequence ran in order: code {code}, out {stdout:?}, err {stderr:?}"
    );
    let calls = tools.calls("gh");
    assert_eq!(calls.len(), 1, "one GitHub release call: {calls:?}");
    let gh = &calls[0];
    assert_eq!(&gh[..3], ["release", "create", "v0.7.1-rc.1+build.7"]);
    let options = gh
        .iter()
        .position(|arg| arg == "--generate-notes")
        .expect("generated notes option");
    let assets = &gh[3..options];
    assert_eq!(assets.len(), 2, "the two packaged assets: {assets:?}");
    assert!(assets.iter().all(|asset| Path::new(asset).is_absolute()));
    assert!(assets.iter().any(|asset| asset.ends_with("/release.json")));
    assert!(assets.iter().any(|asset| asset.ends_with("/SHA256SUMS")));
    let target = gh
        .iter()
        .position(|arg| arg == "--target")
        .expect("tag target");
    let commit = head_commit();
    assert_eq!(
        gh.get(target + 1).map(String::as_str),
        Some(commit.as_str())
    );
    assert!(!gh.iter().any(|arg| arg == "--verify-tag"));
}

/// `release latest`: the newest version is discovered at the origin's
/// `latest` redirect and nothing else is requested; an origin that does not
/// redirect to a release tag fails.
#[tokio::test(flavor = "multi_thread")]
async fn release_latest_reads_the_origin_redirect() {
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    use http::Request;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    use crate::harness::{Bytes, Full, Infallible, Response, stage_tls_pair};
    use crate::release_fx::FIXTURE_VERSION;

    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("idle-server-makes-no-release-c-latest");
    let home = root.join("home");
    let env = isolated_env(&home);

    // The release host: TLS from the committed pair; `GET /latest` answered
    // with the redirect to the fixture release's tag while `redirecting`
    // holds, a bare 404 after. Every request is counted.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (cert, key_file) = stage_tls_pair(&root.join("tls"));
    let acceptor = release_acceptor(&cert, &key_file);
    let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let redirecting = std::sync::Arc::new(AtomicBool::new(true));
    tokio::spawn({
        let seen = seen.clone();
        let redirecting = redirecting.clone();
        async move {
            loop {
                let Ok((plain, _)) = listener.accept().await else {
                    return;
                };
                let Ok(stream) = acceptor.accept(plain).await else {
                    continue;
                };
                let seen = seen.clone();
                let redirecting = redirecting.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<_>| {
                        let seen = seen.clone();
                        let redirecting = redirecting.clone();
                        async move {
                            let path = request.uri().path().to_string();
                            seen.lock().expect("seen").push(path.clone());
                            let (status, location) = if path == "/latest"
                                && redirecting.load(AtomicOrdering::SeqCst)
                            {
                                (
                                    http::StatusCode::FOUND,
                                    Some(format!(
                                        "https://release.example/releases/tag/v{FIXTURE_VERSION}"
                                    )),
                                )
                            } else {
                                (http::StatusCode::NOT_FOUND, None)
                            };
                            let mut builder = Response::builder().status(status);
                            if let Some(location) = location {
                                builder = builder.header(http::header::LOCATION, location);
                            }
                            Ok::<_, Infallible>(
                                builder
                                    .body(Full::new(Bytes::from(Vec::new())))
                                    .expect("response"),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    });
    let origin = format!("https://localhost:{}", addr.port());

    // The happy leg: one request, the version named.
    let (code, stdout, stderr) = cli_raw(
        &[
            "release",
            "latest",
            "--release-origin",
            &origin,
            "--tls-ca",
            CA_PEM,
        ],
        &env,
        None,
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains(FIXTURE_VERSION), "{stdout}");
    assert_eq!(
        seen.lock().expect("seen").clone(),
        vec!["/latest".to_string()],
        "only the latest redirect is requested"
    );

    // A host that does not redirect to a release: refused (4, unreachable).
    redirecting.store(false, AtomicOrdering::SeqCst);
    let (code, stdout, stderr) = cli_raw(
        &[
            "release",
            "latest",
            "--release-origin",
            &origin,
            "--tls-ca",
            CA_PEM,
        ],
        &env,
        None,
    );
    assert_eq!(code, 4, "{stdout}{stderr}");
    assert!(
        stderr.contains("release.unreachable") && stderr.contains("did not redirect"),
        "{stderr}"
    );
}
