//! Codex upstream: a ChatGPT login through the paste or a client's forward,
//! its token refresh, and its usage read, against the staged fake.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::acc::await_operation;
use crate::harness::*;

const TOKEN: &str = "/oauth/token";
const USAGE: &str = "/backend-api/wham/usage";
const WORKSPACE: &str = "acct-fixture-workspace";
const CALLBACK: &str = "http://127.0.0.1:1455/auth/callback";

fn jwt(claims: Value) -> String {
    format!(
        "e30.{}.fixture-signature",
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

/// What auth.openai.com answers: JWT tokens, no `expires_in`.
struct Tokens {
    access: String,
    refresh: String,
    reply: Reply,
}

fn codex_tokens() -> Tokens {
    let access = jwt(json!({ "exp": 4_070_908_800_i64, "jti": Uuid::new_v4() }));
    let refresh = format!("rt-fixture-{}", Uuid::new_v4());
    let id_token = jwt(json!({
        "jti": Uuid::new_v4(),
        "https://api.openai.com/profile": { "email": "dev@codex.fixture.invalid" },
        "https://api.openai.com/auth": { "chatgpt_account_id": WORKSPACE },
    }));
    for (role, value) in [
        ("codex access token", &access),
        ("codex refresh token", &refresh),
        ("codex id token", &id_token),
    ] {
        crate::leaks::register_needle(role, value);
    }
    let reply = Reply::status(
        200,
        json!({ "id_token": id_token, "access_token": access, "refresh_token": refresh })
            .to_string(),
    );
    Tokens {
        access,
        refresh,
        reply,
    }
}

fn codex_usage(session: u64, weekly: u64) -> Reply {
    let window = |percent: u64, seconds: u64| {
        json!({
            "used_percent": percent,
            "limit_window_seconds": seconds,
            "reset_after_seconds": 3600,
            "reset_at": 4_070_908_800_i64,
        })
    };
    Reply::status(
        200,
        json!({
            "plan_type": "plus",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": window(session, 18_000),
                "secondary_window": window(weekly, 604_800),
            },
            "credits": null,
        })
        .to_string(),
    )
}

fn calls_to(instance: &Instance, path: &str) -> Vec<Seen> {
    instance
        .upstream
        .seen()
        .into_iter()
        .filter(|seen| seen.path == path)
        .collect()
}

fn state_of(url: &str) -> String {
    let uri: http::Uri = url.parse().expect("the URL parses");
    let query = uri.query().expect("a query");
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("state="))
        .expect("a state value")
        .to_string()
}

fn record(instance: &Instance, name: &str) -> Value {
    instance.state_file()["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .find(|record| record["display_name"] == name)
        .unwrap_or_else(|| panic!("no record {name}"))
        .clone()
}

/// The operator's login: no listener, the pasted callback URL completes it.
async fn operator_login(instance: &Instance, name: &str) -> Tokens {
    let started = control_post(
        instance.addr,
        "/control/v1/accounts/login",
        &[],
        json!({ "provider": "codex", "display_name": name }),
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.text());
    let started = started.json();
    assert_eq!(started["manual_code_required"], true, "{started}");
    let url = started["authorization_url"].as_str().expect("url");
    assert!(
        url.starts_with("https://auth.openai.com/oauth/authorize?"),
        "{url}"
    );
    assert!(
        url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback"),
        "{url}"
    );
    let id = started["operation_id"].as_str().expect("operation id");

    let tokens = codex_tokens();
    instance.upstream.script([tokens.reply.clone()]);
    let paste = format!(
        "{CALLBACK}?code=ac-fixture&scope=openid&state={}",
        state_of(url)
    );
    let pasted = control_post(
        instance.addr,
        &format!("/control/v1/operations/{id}/code"),
        &[],
        json!({ "code": paste }),
    )
    .await;
    assert_eq!(pasted.status, StatusCode::ACCEPTED, "{}", pasted.text());
    let operation = await_operation(instance, id);
    assert_eq!(operation["state"], "succeeded", "{operation}");
    tokens
}

#[tokio::test(flavor = "multi_thread")]
async fn cdx_operator_login_takes_the_pasted_callback_and_reads_the_id_token() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("cdx-operator-login").await;

    operator_login(&instance, "CDX").await;

    let exchange = &calls_to(&instance, TOKEN)[0];
    assert_eq!(
        exchange.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    let form: Vec<(String, String)> = String::from_utf8_lossy(&exchange.body)
        .split('&')
        .map(|pair| pair.split_once('=').expect("key=value"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let field = |name: &str| {
        form.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(field("grant_type"), Some("authorization_code"));
    assert_eq!(field("client_id"), Some("app_EMoamEEZ73f0CkXaXp7hrann"));
    assert_eq!(field("code"), Some("ac-fixture"));
    assert_eq!(
        field("redirect_uri"),
        Some("http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback")
    );
    assert_eq!(field("code_verifier").map(str::len), Some(43));
    assert_eq!(field("state"), None, "Codex's exchange sends no state");

    let saved = record(&instance, "CDX");
    assert_eq!(saved["provider"], "codex");
    assert_eq!(saved["chatgpt_account_id"], WORKSPACE);
    assert_eq!(saved["profile_email"], "dev@codex.fixture.invalid");
    assert_eq!(
        saved["expires_at"], "2099-01-01T00:00:00Z",
        "the access token's exp"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cdx_client_login_is_pinned_to_the_codex_callback_port() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("cdx-client-login").await;
    let client = enroll(&instance, "engineer-1", "Engineer").await;
    let bearer = client.bearer();
    let login = "/control/v1/client/accounts/login";

    let refused = control_post(
        instance.addr,
        login,
        &[("authorization", &bearer)],
        json!({ "provider": "codex", "redirect_port": 9 }),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{}",
        refused.text()
    );
    assert_eq!(refused.json()["error"]["target"], "redirect_port");

    let started = control_post(
        instance.addr,
        login,
        &[("authorization", &bearer)],
        json!({ "provider": "codex", "redirect_port": 1455 }),
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.text());
    let started = started.json();
    assert_eq!(started["manual_code_required"], false);
    let url = started["authorization_url"].as_str().expect("url");
    let id = started["operation_id"].as_str().expect("operation id");

    instance.upstream.script([codex_tokens().reply]);
    let forwarded = control_post(
        instance.addr,
        &format!("/control/v1/client/accounts/operations/{id}/code"),
        &[("authorization", &bearer)],
        json!({ "code": format!("code=ac-fixture&state={}", state_of(url)) }),
    )
    .await;
    assert_eq!(
        forwarded.status,
        StatusCode::ACCEPTED,
        "{}",
        forwarded.text()
    );
    let operation = await_operation(&instance, id);
    assert_eq!(operation["state"], "succeeded", "{operation}");

    let saved = record(&instance, "dev@codex.fixture.invalid");
    assert_eq!(saved["provider"], "codex");
    assert_eq!(saved["owner"], "engineer-1");
}

/// A usage 401 forces one refresh and one retry.
#[tokio::test(flavor = "multi_thread")]
async fn cdx_usage_probe_refreshes_once_after_a_401() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("cdx-usage-refresh").await;
    let login = operator_login(&instance, "CDX").await;
    let rotated = codex_tokens();
    instance.upstream.script([
        Reply::status(401, json!({ "detail": "expired" }).to_string()),
        rotated.reply.clone(),
        codex_usage(25, 40),
    ]);

    let probed = instance.cli_json(&["probe", "--wait"], None);

    assert_eq!(probed["ok"], true, "{probed}");
    let account = instance.account("CDX");
    assert_eq!(account["probe"]["outcome"], "updated", "{account}");
    let utilisation = |name: &str| {
        account["buckets"]
            .as_array()
            .expect("buckets")
            .iter()
            .find(|bucket| bucket["name"] == name)
            .map(|bucket| bucket["utilisation"].clone())
    };
    assert_eq!(utilisation("session"), Some(json!(0.25)));
    assert_eq!(utilisation("weekly"), Some(json!(0.40)));
    let usage = calls_to(&instance, USAGE);
    assert_eq!(usage.len(), 2, "one usage retry after the forced refresh");
    assert_eq!(
        usage[0].header("authorization"),
        Some(format!("Bearer {}", login.access).as_str())
    );
    assert_eq!(usage[0].header("chatgpt-account-id"), Some(WORKSPACE));
    assert_eq!(
        usage[1].header("authorization"),
        Some(format!("Bearer {}", rotated.access).as_str())
    );
    let refresh = &calls_to(&instance, TOKEN)[1];
    assert_eq!(refresh.header("content-type"), Some("application/json"));
    assert_eq!(
        refresh.json(),
        json!({
            "grant_type": "refresh_token",
            "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
            "refresh_token": login.refresh,
        })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cdx_a_rejected_refresh_names_codex_s_reason() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("cdx-refresh-rejected").await;
    operator_login(&instance, "CDX").await;
    instance.upstream.script([
        Reply::status(401, json!({ "detail": "expired" }).to_string()),
        Reply::status(
            401,
            json!({ "error": { "code": "refresh_token_reused", "message": "fixture" } })
                .to_string(),
        ),
    ]);
    let rejected = instance.cli_json(&["probe", "--wait"], None);

    assert_eq!(rejected["ok"], true, "{rejected}");
    let health = &instance.account("CDX")["health"];
    assert_eq!(health["state"], "errored", "{health}");
    assert_eq!(
        health["reason"],
        "refresh rejected by the token endpoint (HTTP 401 Unauthorized, refresh_token_reused)"
    );
}
