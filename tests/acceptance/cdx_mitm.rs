//! Codex through the MITM: the fake chatgpt.com behind the upstream
//! override, a Codex login seeded in the state, and requests sent inside an
//! intercepted `chatgpt.com` tunnel the way Codex sends them.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use ruzstd::encoding::{CompressionLevel, compress_to_vec};

use crate::harness::{
    Bytes, CODEX_RESPONSES_PATH, Command, Duration, Full, Instance, Instant, Method,
    OffsetDateTime, Request, Setup, Stdio, Value, fs, haiku_prompt, json, make_private,
    private_dir,
};
use crate::proxy::{Intercepted, Offer, ca_file, intercept};

const API_HOST: &str = "chatgpt.com";
const ACCOUNTS_CHECK_PATH: &str = "/backend-api/wham/accounts/check";
/// The workspace of the pooled login, and the engineer's own.
const POOLED_ACCOUNT_ID: &str = "acct-fixture-pooled";
const ENGINEER_ACCOUNT_ID: &str = "acct-fixture-engineer";

/// MITM on, and `CDX`: a portable login turned into a Codex one in the
/// state, as a Codex login records it.
async fn start_with_codex(scenario: &str, setup: Setup) -> Instance {
    let mut instance = Instance::start_with(
        scenario,
        Setup {
            mitm: true,
            ..setup
        },
    )
    .await;
    let portable = json!({
        "access_token": instance.needles.access_token,
        "refresh_token": instance.needles.refresh_token,
        "expires_at": "2099-01-01T00:00:00Z",
    })
    .to_string();
    let envelope = instance.cli_json(
        &["account", "add", "--portable", "--stdin", "--name", "CDX"],
        Some(&portable),
    );
    assert_eq!(envelope["ok"], true, "adding CDX: {envelope}");
    instance.restart_with_state(|state| {
        let record = state["accounts"]
            .as_array_mut()
            .expect("accounts")
            .iter_mut()
            .find(|r| r["display_name"] == "CDX")
            .expect("the CDX record");
        record["provider"] = json!("codex");
        record["chatgpt_account_id"] = json!(POOLED_ACCOUNT_ID);
    });
    instance
}

/// An intercepted `chatgpt.com` tunnel on HTTP/1.1, which Codex's
/// WebSocket handshake needs, trusting `ca` alone.
async fn codex_tunnel(instance: &Instance, ca: &std::path::Path) -> Result<Intercepted, String> {
    let proxy = instance.mitm_addr.expect("MITM on");
    intercept(
        proxy,
        "chatgpt.com:443",
        None,
        ca,
        Offer::alpn(&["http/1.1"]),
    )
    .await
}

/// A request as Codex sends it, its own login's headers included.
fn codex_request(method: Method, path: &str, body: Bytes) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", API_HOST)
        .header("authorization", "Bearer engineer-own-login")
        .header("chatgpt-account-id", ENGINEER_ACCOUNT_ID)
        .header("session-id", "codex-session")
        .header("content-type", "application/json")
        .body(Full::new(body))
        .expect("the in-tunnel request builds")
}

/// A `/responses` turn, zstd-compressed as Codex sends it.
fn responses_request(compressed: &[u8]) -> Request<Full<Bytes>> {
    let mut request = codex_request(
        Method::POST,
        CODEX_RESPONSES_PATH,
        Bytes::copy_from_slice(compressed),
    );
    request
        .headers_mut()
        .insert("content-encoding", "zstd".parse().unwrap());
    request
}

fn zstd(body: &Value) -> Vec<u8> {
    compress_to_vec(
        &body.to_string().into_bytes()[..],
        CompressionLevel::Fastest,
    )
}

/// What reached the fake chatgpt.com; background reads on other paths aside.
fn codex_calls(instance: &Instance) -> usize {
    instance
        .upstream
        .seen()
        .iter()
        .filter(|seen| seen.path.starts_with("/backend-api/"))
        .count()
}

fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_codex_turn_rides_the_pooled_login_with_its_zstd_bytes_and_model() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = start_with_codex("codex-pooled-turn", Setup::default()).await;
    let mut tunnel = codex_tunnel(&instance, &ca_file(&instance))
        .await
        .expect("the handshake succeeds");
    let compressed = zstd(&json!({ "model": "gpt-5-codex", "stream": true, "input": [] }));

    let answer = tunnel.send(responses_request(&compressed)).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert!(
        answer.text().contains("hello from the fake chatgpt"),
        "the turn is relayed: {}",
        answer.text()
    );

    let turns: Vec<_> = instance
        .upstream
        .seen()
        .into_iter()
        .filter(|seen| seen.path == CODEX_RESPONSES_PATH)
        .collect();
    let [seen] = &turns[..] else {
        panic!("one turn upstream: {turns:?}");
    };
    assert_eq!(
        seen.body, compressed,
        "the client's own bytes are forwarded"
    );
    assert_eq!(seen.header("content-encoding"), Some("zstd"));
    assert_eq!(
        seen.headers_named("authorization"),
        [format!("Bearer {}", instance.needles.access_token)],
        "the pooled bearer replaces the engineer's"
    );
    assert_eq!(
        seen.headers_named("chatgpt-account-id"),
        [POOLED_ACCOUNT_ID]
    );

    let records = instance.audit_settled(1);
    let record = &records[0];
    assert_eq!(record["model"], "gpt-5-codex", "read from the decoded body");
    assert_eq!(record["serving_account"]["display_name"], "CDX");
    assert_eq!(record["session_id"], "codex-session");
    let usage = instance.account("CDX")["usage"].clone();
    assert_eq!(
        usage["input_tokens"], 11,
        "response.completed counts: {usage}"
    );
    assert_eq!(
        usage["output_tokens"], 7,
        "response.completed counts: {usage}"
    );
}

/// The upgrade, the workspace check, telemetry under `block` and an
/// account-bound path are all answered without the pool.
#[tokio::test(flavor = "multi_thread")]
async fn what_codex_sends_beside_its_turns_never_reaches_the_pool() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = start_with_codex(
        "codex-local-answers",
        Setup {
            telemetry_policy: "block",
            ..Setup::default()
        },
    )
    .await;
    let mut tunnel = codex_tunnel(&instance, &ca_file(&instance))
        .await
        .expect("the handshake succeeds");

    let mut upgrade = codex_request(Method::GET, CODEX_RESPONSES_PATH, Bytes::new());
    let headers = upgrade.headers_mut();
    headers.insert("upgrade", "websocket".parse().unwrap());
    headers.insert("connection", "upgrade".parse().unwrap());
    let answer = tunnel.send(upgrade).await;
    assert_eq!(answer.status, 426, "Codex falls back to HTTP at once");

    let check = tunnel
        .send(codex_request(
            Method::GET,
            ACCOUNTS_CHECK_PATH,
            Bytes::new(),
        ))
        .await;
    assert_eq!(check.status, 200, "{}", check.text());
    let check = check.json();
    assert_eq!(check["accounts"][0]["id"], ENGINEER_ACCOUNT_ID, "{check}");
    assert_eq!(check["default_account_id"], ENGINEER_ACCOUNT_ID);

    let telemetry = tunnel
        .send(codex_request(
            Method::POST,
            "/backend-api/codex/analytics-events/events",
            Bytes::from_static(b"{}"),
        ))
        .await;
    assert_eq!(telemetry.status, 200);
    assert_eq!(telemetry.json(), json!({}));

    let bound = tunnel
        .send(codex_request(
            Method::GET,
            "/backend-api/wham/settings/user",
            Bytes::new(),
        ))
        .await;
    assert_eq!(bound.status, 403, "{}", bound.text());
    let bound = bound.json();
    assert_eq!(bound["error"]["type"], "proxy_error", "{bound}");
    assert!(bound.get("type").is_none(), "Codex's envelope: {bound}");

    assert_eq!(codex_calls(&instance), 0, "nothing reached chatgpt.com");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_s_own_429_is_codex_s_usage_limit_with_its_reset() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = start_with_codex("codex-usage-limit", Setup::default()).await;
    let envelope = instance.cli_json(&["account", "disable", "CDX"], None);
    assert_eq!(envelope["ok"], true, "{envelope}");
    let mut tunnel = codex_tunnel(&instance, &ca_file(&instance))
        .await
        .expect("the handshake succeeds");

    let before = unix_now();
    let answer = tunnel
        .send(responses_request(&zstd(&json!({ "model": "gpt-5-codex" }))))
        .await;
    let after = unix_now();
    assert_eq!(answer.status, 429, "{}", answer.text());
    let retry_after: i64 = answer
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    let error = answer.json()["error"].clone();
    assert_eq!(error["type"], "usage_limit_reached", "{error}");
    let resets_at = error["resets_at"].as_i64().expect("resets_at");
    assert!(
        (before + retry_after..=after + retry_after).contains(&resets_at),
        "resets_at is the retry time: {resets_at}"
    );

    let check = tunnel
        .send(codex_request(
            Method::GET,
            ACCOUNTS_CHECK_PATH,
            Bytes::new(),
        ))
        .await;
    assert_eq!(check.status, 200, "answered whatever the pool's state");
    assert_eq!(codex_calls(&instance), 0, "nothing reached chatgpt.com");
}

/// The trust files of a server from before Codex: a leaf without
/// `chatgpt.com`, signed by a CA whose key is gone.
fn plant_pre_codex_ca(state: &std::path::Path) {
    let now = OffsetDateTime::now_utc();
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Jaynshare local CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let (not_before, not_after) = (
        now - time::Duration::hours(1),
        now + time::Duration::days(730),
    );
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca = ca_params.self_signed(&ca_key).expect("CA certificate");

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec![
        "api.anthropic.com".to_string(),
        "probe.jaynshare.invalid".to_string(),
    ])
    .expect("leaf parameters");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("leaf certificate");

    fs::write(state.join("mitm-ca.pem"), ca.pem()).expect("write the CA");
    fs::write(state.join("mitm-leaf.pem"), leaf.pem()).expect("write the leaf");
    let key = state.join("mitm-leaf-key.pem");
    fs::write(&key, leaf_key.serialize_pem()).expect("write the leaf key");
    make_private(&key);
}

/// The staged CA alone, as a client that fetched only it would trust.
fn staged_ca_only(state: &std::path::Path) -> std::path::PathBuf {
    let next = fs::read_to_string(state.join("mitm-ca-next.pem")).expect("a CA is staged");
    let end = "-----END CERTIFICATE-----\n";
    let first = &next[..next.find(end).expect("a certificate") + end.len()];
    let path = state.join("staged-ca-only.pem");
    fs::write(&path, first).expect("write the staged CA");
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pre_codex_ca_keeps_anthropic_and_a_staged_ca_serves_chatgpt_com() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_with(
        "codex-pre-codex-ca",
        Setup {
            mitm: true,
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance.stop();
    let state = instance.root.join("state");
    plant_pre_codex_ca(&state);
    let current = fs::read(state.join("mitm-ca.pem")).expect("the planted CA");
    instance.respawn();

    let missing = instance.events("ca_names_missing");
    assert_eq!(missing.len(), 1, "{missing:?}");
    assert_eq!(missing[0]["fields"]["names"], "chatgpt.com");
    assert_eq!(
        fs::read(state.join("mitm-ca.pem")).expect("the CA file"),
        current,
        "the current CA is untouched"
    );

    let proxy = instance.mitm_addr.expect("MITM on");
    let mut anthropic = intercept(
        proxy,
        "api.anthropic.com:443",
        None,
        &ca_file(&instance),
        Offer::default(),
    )
    .await
    .expect("Anthropic stays on the current CA");
    let answer = anthropic
        .send(anthropic.request(
            Method::POST,
            "api.anthropic.com",
            "/v1/messages",
            &haiku_prompt().to_string(),
        ))
        .await;
    assert_eq!(answer.status, 200, "{}", answer.text());

    assert!(
        codex_tunnel(&instance, &ca_file(&instance)).await.is_err(),
        "the current CA's leaf does not cover chatgpt.com"
    );
    let mut codex = codex_tunnel(&instance, &staged_ca_only(&state))
        .await
        .expect("chatgpt.com is served on the staged CA");
    let check = codex
        .send(codex_request(
            Method::GET,
            ACCOUNTS_CHECK_PATH,
            Bytes::new(),
        ))
        .await;
    assert_eq!(check.status, 200, "{}", check.text());
}

/// A real Codex CLI on `PATH`; asked with a throwaway home, so nothing reads
/// the developer's own.
fn codex_available(root: &std::path::Path) -> bool {
    let home = root.join("probe-home");
    private_dir(&home);
    Command::new("codex")
        .arg("--version")
        .env("HOME", &home)
        .env("CODEX_HOME", &home)
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A JWT-shaped fixture token, unsigned and valid nowhere.
fn fixture_jwt(claims: &Value) -> String {
    use base64::Engine as _;
    let part = |v: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    format!(
        "{}.{}.fixture-signature",
        part(&json!({ "alg": "none", "typ": "JWT" })),
        part(claims)
    )
}

/// A throwaway `CODEX_HOME` logged in as the engineer with fixture tokens.
fn codex_home(root: &std::path::Path) -> std::path::PathBuf {
    let home = root.join("codex-home");
    private_dir(&home);
    let claims = json!({
        "email": "engineer@fixture.invalid",
        "exp": 4_102_444_800_u64,
        "https://api.openai.com/auth": {
            "chatgpt_plan_type": "plus",
            "chatgpt_user_id": "user-fixture",
            "chatgpt_account_id": ENGINEER_ACCOUNT_ID,
        },
    });
    let auth = json!({
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": fixture_jwt(&claims),
            "access_token": fixture_jwt(&claims),
            "refresh_token": "fixture-refresh-token",
            "account_id": ENGINEER_ACCOUNT_ID,
        },
        "last_refresh": OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("timestamp"),
    });
    let auth_path = home.join("auth.json");
    fs::write(&auth_path, auth.to_string()).expect("write auth.json");
    make_private(&auth_path);
    fs::write(
        home.join("config.toml"),
        "cli_auth_credentials_store = \"file\"\ncheck_for_update_on_startup = false\n",
    )
    .expect("write config.toml");
    home
}

/// A real `codex exec` through the proxy to the fake chatgpt.com: its
/// WebSocket refused, the workspace check answered, the turn pooled.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_codex_exec_completes_a_turn_on_the_pooled_login() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = start_with_codex("codex-real-exec", Setup::default()).await;
    if !codex_available(&instance.root) {
        eprintln!("skipping: no codex CLI on PATH");
        return;
    }
    let work = instance.root.join("work");
    private_dir(&work);
    let proxy = format!("http://{}", instance.mitm_addr.expect("MITM on"));
    let mut child = Command::new("codex")
        .args(["exec", "--skip-git-repo-check", "say hi"])
        .current_dir(&work)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", instance.root.join("home"))
        .env("CODEX_HOME", codex_home(&instance.root))
        .env("CODEX_CA_CERTIFICATE", ca_file(&instance))
        .env("HTTPS_PROXY", &proxy)
        .env("HTTP_PROXY", &proxy)
        .env("NO_PROXY", "localhost,127.0.0.1,::1")
        .env(
            "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
            format!("http://{}/oauth/token", instance.upstream.addr),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start codex");
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().expect("poll codex").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("codex exec did not finish within 120 s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let output = child.wait_with_output().expect("codex output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("hello from the fake chatgpt"),
        "codex exec: {}\nstdout: {stdout}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let turn = instance
        .upstream
        .seen()
        .into_iter()
        .find(|seen| seen.path == CODEX_RESPONSES_PATH)
        .expect("the turn reached chatgpt.com");
    assert_eq!(
        turn.headers_named("authorization"),
        [format!("Bearer {}", instance.needles.access_token)]
    );
    assert_eq!(
        turn.headers_named("chatgpt-account-id"),
        [POOLED_ACCOUNT_ID]
    );
    let audit = instance.audit();
    let record = audit
        .iter()
        .find(|r| r["path"] == CODEX_RESPONSES_PATH)
        .expect("the turn's record");
    assert!(record["model"].is_string(), "the model was read: {record}");
}
