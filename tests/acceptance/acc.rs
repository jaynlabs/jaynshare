//! Account credentials: browser login and device login, the stored
//! state file, imports and renames.
use crate::harness::*;

/// Around every mutating operation: `remove FSUB --yes`
/// while a route names FSUB is refused naming that route; adding a second
/// identity with an email a route names is refused naming that route as
/// `ambiguous`; disable and enable of the same account under the same
/// configuration are both (recovery is never blocked); the state file is
/// byte-identical after each refusal; once the configuration drops the
/// entries, rename and remove both succeed.
#[tokio::test(flavor = "multi_thread")]
async fn reference_conflicts_block_add_remove_rename_never_enable() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "reference-conflicts-block",
        Setup {
            selection:
                "routes = [{ name = \"named\", patterns = [\"*haiku*\"], accounts = [\"FSUB\"] }, \
                 { name = \"by-email\", patterns = [\"*\"], accounts = [\"a@x.io\"] }]\n"
                    .into(),
            ..Setup::default()
        },
        |instance| {
            add_two(instance);
            // The first identity with `a@x.io` makes `route by-email`
            // resolve; the pool starts with no conflict of its own.
            instance.add_oauth("SHARED", "a@x.io", &Uuid::new_v4().to_string());
        },
    )
    .await;
    let handle = instance.handle("FSUB");

    // Remove is refused naming the route entry that would go unresolvable.
    let state_before = instance.state_digest();
    let envelope = instance.cli_json(&["account", "remove", "FSUB", "--yes"], None);
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    assert_eq!(envelope["error"]["code"], "account_reference_conflict");
    let details = envelope["error"]["details"].as_array().expect("details");
    assert_eq!(details.len(), 1, "{envelope}");
    assert_eq!(details[0]["target"], "route named");
    assert_eq!(details[0]["code"], "unresolvable");
    assert_eq!(
        instance.state_digest(),
        state_before,
        "the refusal wrote nothing"
    );

    // Add is refused naming the route whose email reference the second
    // identity would make ambiguous.
    instance.upstream.script([Reply::status(
        200,
        json!({
            "account": { "email": "a@x.io", "uuid": Uuid::new_v4().to_string() },
            "organization": { "uuid": Uuid::new_v4().to_string(), "name": "Other Org" },
        })
        .to_string(),
    )]);
    let portable = json!({
        "access_token": needle("access token", "oat-fixture"),
        "refresh_token": needle("refresh token", "ort-fixture"),
        "expires_at": "2099-01-01T00:00:00Z",
    })
    .to_string();
    let state_before = instance.state_digest();
    let envelope = instance.cli_json(
        &[
            "account",
            "add",
            "--portable",
            "--stdin",
            "--name",
            "SHARED2",
        ],
        Some(&portable),
    );
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    assert_eq!(envelope["error"]["code"], "account_reference_conflict");
    let details = envelope["error"]["details"].as_array().expect("details");
    assert_eq!(details.len(), 1, "{envelope}");
    assert_eq!(details[0]["target"], "route by-email");
    assert_eq!(details[0]["code"], "ambiguous");
    assert_eq!(
        instance.state_digest(),
        state_before,
        "the refusal wrote nothing"
    );

    // Enable and disable never affect resolution, so they are never refused.
    let envelope = instance.cli_json(&["account", "disable", "FSUB"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    let envelope = instance.cli_json(&["account", "enable", "FSUB"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");

    // The configuration drops the entries by the reload. Both
    // operations succeed now.
    instance.reload_with_setup(&Setup::default());
    let envelope = instance.cli_json(&["account", "rename", "FSUB", "Renamed"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"],
        handle.as_str(),
        "the handle is unchanged"
    );
    let envelope = instance.cli_json(&["account", "remove", "Renamed", "--yes"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
}

/// Around disable and enable: FSUB errored through the
/// 401 helper, `disable FSUB` keeps the credential, identity and expiry while
/// selection immediately stops offering it (`disabled`), the next prompt is
/// served by FSUB2 with no sleep; `enable FSUB` clears the errored state and
/// makes FSUB eligible again at once (the default the ranking chose keeps
/// serving); enabling the already-enabled, freshly errored account
/// is the operator retry path; an attempt already sent upstream finishes
/// with its 200 when disable lands.
#[tokio::test(flavor = "multi_thread")]
async fn disable_preserves_error_and_identity_enable_clears_it() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_with_accounts(
        "disable-preserves-error",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)]),
            ..Setup::default()
        },
        add_two,
    )
    .await;

    // The 401 helper errors FSUB through the no-refresh-material branch
    // (the): the family's refresh token is stripped while the server
    // is down, so the forced refresh errors the account without a token call.
    instance.restart_with_state(|state| {
        let record = state["accounts"]
            .as_array_mut()
            .expect("accounts array")
            .iter_mut()
            .find(|r| r["display_name"] == "FSUB")
            .expect("FSUB record");
        record["refresh_token"] = Value::Null;
    });
    instance.error_via_401("FSUB").await;
    let errored = instance.account("FSUB");
    assert_eq!(errored["eligibility"]["reason"], "errored");

    // Disable: enabled false, the errored state preserved, identity and the
    // expiry untouched, and selection's reason now `disabled`.
    let envelope = instance.cli_json(&["account", "disable", "FSUB"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(envelope["result"]["account"]["enabled"], false);
    assert_eq!(envelope["result"]["account"]["health"]["state"], "errored");
    let disabled = instance.account("FSUB");
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["health"]["state"], "errored");
    assert_eq!(disabled["handle"], errored["handle"], "identity preserved");
    assert_eq!(
        disabled["profile"], errored["profile"],
        "identity preserved"
    );
    assert_eq!(
        disabled["credential"]["access_token_expires_at"],
        errored["credential"]["access_token_expires_at"],
        "the expiry is preserved"
    );
    assert_eq!(disabled["eligibility"]["reason"], "disabled");

    // The next prompt is served by FSUB2 immediately — no sleep.
    let started = Instant::now();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "no sleep before FSUB2 serves: {:?}",
        started.elapsed()
    );
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");

    // Enable: the flag is set and the errored state cleared, visible to
    // selection immediately. The next prompt is not served by FSUB: the
    // ranking moved the default to FSUB2 when FSUB was disabled, and the
    // default stays — a returning higher-tier account never takes it back
    // unasked.
    let envelope = instance.cli_json(&["account", "enable", "FSUB"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(envelope["result"]["account"]["enabled"], true);
    assert_eq!(envelope["result"]["account"]["health"]["state"], "ready");
    assert_eq!(
        envelope["result"]["account"]["health"]["reason"],
        Value::Null
    );
    let enabled = instance.account("FSUB");
    assert_eq!(enabled["eligibility"]["eligible"], true);
    assert_eq!(enabled["eligibility"]["reason"], Value::Null);

    // The next prompt is served by the default the ranking chose, FSUB2.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");

    // Enable on the already-enabled, freshly errored account: the retry path.
    instance.error_via_401("FSUB").await;
    let envelope = instance.cli_json(&["account", "enable", "FSUB"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(envelope["result"]["account"]["enabled"], true);
    assert_eq!(envelope["result"]["account"]["health"]["state"], "ready");
    assert_eq!(instance.account("FSUB")["health"]["state"], "ready");

    // An attempt already sent upstream finishes with its 200 when disable
    // lands: the write never waits on the exchange, the exchange never
    // rechecks the flag.
    let gate = Arc::new(Notify::new());
    let before = instance.upstream.calls();
    instance.upstream.script([Reply::Hold(gate.clone())]);
    let addr = instance.addr;
    let prompt =
        tokio::spawn(async move { send(addr, pinned(messages(haiku_prompt()), "FSUB")).await });
    for _ in 0..500 {
        if instance.upstream.calls() > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        instance.upstream.calls() > before,
        "the attempt is in flight at the fake"
    );
    let envelope = instance.cli_json(&["account", "disable", "FSUB"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    gate.notify_one();
    let answer = prompt.await.expect("the prompt task");
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(5);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["attempts"], 1);
}

/// The re-import path. `FSUB` errored through the 401
/// helper; re-importing the same identity by `--portable --stdin` and, in the
/// browser-login twin, re-logging into it with the same profile both update
/// the account in place — one account, the original handle, `errored ==
/// false`, `health.reason == null` — and the next prompt is served by it.
#[tokio::test(flavor = "multi_thread")]
async fn reimporting_an_errored_identity_clears_it_in_place() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("reimporting-errored-identity").await;
    instance.add_fsub();
    let handle = instance.handle("FSUB");

    // Errored through the 401 helper: the forced refresh is refused
    // permanently (the branch), so the account ends errored.
    instance.upstream.script_token([reply_auth_401()]);
    instance.error_via_401("FSUB").await;

    // (a) A re-import of the same identity by `--portable --stdin` resolves
    // to the account already in the pool and clears it in place.
    let portable = json!({
        "access_token": needle("access token", "oat-fixture"),
        "refresh_token": needle("refresh token", "ort-fixture"),
        "expires_at": "2099-01-01T00:00:00Z",
    })
    .to_string();
    let envelope = instance.cli_json(
        &["account", "add", "--portable", "--stdin", "--name", "FSUB"],
        Some(&portable),
    );
    assert_eq!(envelope["ok"], true, "the re-import: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"].as_str(),
        Some(handle.as_str()),
        "the same account, in place"
    );
    let row = instance.account("FSUB");
    assert_eq!(row["health"]["state"], "ready");
    assert_eq!(row["health"]["reason"], Value::Null);
    assert_eq!(
        instance.state_file()["accounts"]
            .as_array()
            .expect("accounts")
            .iter()
            .find(|r| r["display_name"] == "FSUB")
            .expect("FSUB record")["errored"],
        false,
        "errored cleared"
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1,
        "no duplicate"
    );

    // The next prompt is served by FSUB.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(
        instance.last_record(2)["serving_account"]["display_name"],
        "FSUB"
    );

    // (b) The browser-login twin: the same fake, the same profile, so the
    // flow lands on the identity the pool already holds — errored again
    // first, cleared by the re-login.
    instance.upstream.script_token([reply_auth_401()]);
    instance.error_via_401("FSUB").await;
    let (id, url) = start_login(&instance);
    let (callback, state) = callback_target(&url);
    let code = format!("oat-fixture-{}", Uuid::new_v4());
    let answer = send(
        callback,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/callback?code={code}&state={state}"))
            .body(Full::new(Bytes::new()))
            .expect("request builds"),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::FOUND,
        "the browser is sent to the success page"
    );
    let operation = await_operation(&instance, &id);
    assert_eq!(operation["state"], "succeeded");
    assert_eq!(
        operation["account"]["handle"].as_str(),
        Some(handle.as_str()),
        "the re-login updated the errored account in place"
    );
    let row = instance.account("FSUB");
    assert_eq!(row["health"]["state"], "ready");
    assert_eq!(row["health"]["reason"], Value::Null);
    assert_eq!(
        instance.state_file()["accounts"]
            .as_array()
            .expect("accounts")
            .iter()
            .find(|r| r["display_name"] == "FSUB")
            .expect("FSUB record")["errored"],
        false,
        "errored cleared"
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1,
        "no duplicate"
    );

    // The next prompt is served by FSUB.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(
        instance.last_record(4)["serving_account"]["display_name"],
        "FSUB"
    );
}

// ------------------------------------------------------------------ the browser login

/// `account login --no-wait` and the two values the rest of a flow needs.
pub(crate) fn start_login(instance: &Instance) -> (String, String) {
    let envelope = instance.cli_json(&["account", "login", "--no-wait"], None);
    assert_eq!(envelope["ok"], true, "starting a login: {envelope}");
    (
        envelope["result"]["operation_id"]
            .as_str()
            .expect("operation_id")
            .to_string(),
        envelope["result"]["authorization_url"]
            .as_str()
            .expect("authorization_url")
            .to_string(),
    )
}

/// The redirect URI and state of a printed authorisation URL.
pub(crate) fn callback_target(url: &str) -> (SocketAddr, String) {
    let uri: http::Uri = url.parse().expect("the URL parses");
    assert!(url.starts_with("https://claude.ai/oauth/authorize?"));
    let mut port = None;
    let mut state = None;
    for pair in uri.query().expect("a query").split('&') {
        let (k, v) = pair.split_once('=').expect("every parameter has a value");
        match k {
            "redirect_uri" => {
                let redirect: http::Uri = urldecode(v).parse().expect("the redirect URI parses");
                port = redirect.port_u16();
            }
            "state" => state = Some(urldecode(v)),
            _ => {}
        }
    }
    (
        SocketAddr::from(([127, 0, 0, 1], port.expect("a callback port"))),
        state.expect("a state value"),
    )
}

fn urldecode(v: &str) -> String {
    let mut out = String::new();
    let bytes = v.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).expect("hex") as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Poll `account operation show` until the operation ends; the last state.
pub(crate) fn await_operation(instance: &Instance, id: &str) -> Value {
    for _ in 0..60 {
        let envelope = instance.cli_json(&["account", "operation", "show", id], None);
        assert_eq!(envelope["ok"], true, "operation show: {envelope}");
        let operation = envelope["result"]["operation"].clone();
        let state = operation["state"].as_str().expect("state").to_string();
        if matches!(state.as_str(), "succeeded" | "failed" | "cancelled") {
            return operation;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("the operation {id} never ended: {}", instance.stderr());
}

/// The browser is always a fake: here the
/// loopback callback is driven exactly as a real browser would drive it, and
/// the flow completes.
#[tokio::test(flavor = "multi_thread")]
async fn acc_login_callback_completes_the_flow() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("acc-login-callback").await;
    let (id, url) = start_login(&instance);

    // The OAuth parameters on the printed URL.
    assert!(url.contains("code=true"));
    assert!(url.contains("client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("scope=org%3Acreate_api_key"));
    let (callback, state) = callback_target(&url);
    let code = format!("oat-fixture-{}", Uuid::new_v4());
    let answer = send(
        callback,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/callback?code={code}&state={state}"))
            .body(Full::new(Bytes::new()))
            .expect("request builds"),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::FOUND,
        "the browser is sent to the success page"
    );

    let operation = await_operation(&instance, &id);
    assert_eq!(operation["state"], "succeeded");
    assert!(
        operation["account"].is_object(),
        "the account object arrives with success"
    );
    let account = instance.status()["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .find(|a| a["kind"] == "oauth")
        .expect("the login created an oauth account")
        .clone();
    assert_eq!(account["source_class"], "browser");
    assert_eq!(account["profile"]["email"], "fsub@fixture.invalid");
    assert_eq!(account["health"]["state"], "ready");

    // The exchange carried the code, the PKCE verifier and our identity.
    let exchange = instance
        .upstream
        .seen()
        .into_iter()
        .find(|s| s.path == "/v1/oauth/token")
        .expect("the token endpoint was called");
    let body = exchange.json();
    assert_eq!(body["grant_type"], "authorization_code");
    assert_eq!(body["code"], code);
    assert_eq!(body["client_id"], "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
    assert_eq!(
        body["redirect_uri"]
            .as_str()
            .unwrap()
            .split_once(':')
            .unwrap()
            .0,
        "http",
        "the redirect URI of the printed URL is honoured"
    );
    assert_eq!(
        body["code_verifier"].as_str().expect("verifier").len(),
        43,
        "32 random bytes, base64url without padding"
    );

    // The profile was fetched with the fresh bearer.
    let profile = instance
        .upstream
        .seen()
        .into_iter()
        .find(|s| s.path == "/api/oauth/profile")
        .expect("the profile endpoint was called");
    assert_eq!(
        profile.header("authorization"),
        Some(format!("Bearer {FIXTURE_LOGIN_ACCESS}").as_str())
    );
}

/// A real browser keeps the callback connection alive after the redirect;
/// the flow completes without waiting for it to close.
#[tokio::test(flavor = "multi_thread")]
async fn acc_login_callback_completes_on_a_kept_alive_connection() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("acc-login-keep-alive").await;
    let (id, url) = start_login(&instance);
    let (callback, state) = callback_target(&url);
    let stream = TcpStream::connect(callback).await.expect("connect");
    let (mut browser, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("handshake");
    let held = tokio::spawn(connection);
    let answer = browser
        .send_request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/callback?code=oat-keep-alive&state={state}"))
                .body(Full::new(Bytes::new()))
                .expect("request builds"),
        )
        .await
        .expect("the callback is answered");
    assert_eq!(answer.status(), StatusCode::FOUND);

    let operation = await_operation(&instance, &id);
    assert_eq!(operation["state"], "succeeded");
    drop(browser);
    held.abort();
}

/// The manual path: `account login --stdin` reads a
/// pasted code and submits it to its own operation. A bare
/// code, because the paste has to exist before the flow's state does; the
/// full-callback path is covered by the browser test above and
/// `parse_paste`'s unit tests.
#[tokio::test(flavor = "multi_thread")]
async fn acc_login_manual_paste_completes_the_flow() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("acc-login-paste").await;
    let paste = "oat-pasted";
    let envelope = instance.cli_json(&["account", "login", "--stdin"], Some(paste));
    assert_eq!(envelope["ok"], true, "the login completed: {envelope}");
    assert_eq!(envelope["result"]["operation"]["state"], "succeeded");
    let account = instance.status()["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .find(|a| a["kind"] == "oauth")
        .expect("the login created an oauth account")
        .clone();
    assert_eq!(account["profile"]["email"], "fsub@fixture.invalid");
}

/// A wrong state refuses the code and leaves the pool
/// unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn acc_login_wrong_state_leaves_the_pool_unchanged() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("acc-login-wrong-state").await;
    let (id, url) = start_login(&instance);
    let (callback, _) = callback_target(&url);
    let paste = format!(
        "http://localhost:{}/callback?code=oat-wrong&state=deliberately-wrong",
        callback.port()
    );
    let envelope = instance.cli_json(
        &["account", "operation", "code", "--stdin", &id],
        Some(&paste),
    );
    assert_eq!(
        envelope["ok"], true,
        "the submission was accepted: {envelope}"
    );
    let operation = await_operation(&instance, &id);
    assert_eq!(operation["state"], "failed");
    assert!(
        operation["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("state"),
        "a safe reason naming the mismatch: {}",
        operation["error"]
    );
    assert!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .is_empty(),
        "the pool is unchanged"
    );
}

/// A cancellation ends the flow with no account and no
/// partial state.
#[tokio::test(flavor = "multi_thread")]
async fn acc_login_cancel_leaves_the_pool_unchanged() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("acc-login-cancel").await;
    let (id, _) = start_login(&instance);
    let envelope = instance.cli_json(&["account", "operation", "cancel", &id], None);
    assert_eq!(envelope["ok"], true, "cancelling: {envelope}");
    let operation = await_operation(&instance, &id);
    assert_eq!(operation["state"], "cancelled");
    assert!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .is_empty(),
        "the pool is unchanged"
    );
}

/// The browser delivers a refusal (`error=access_denied`): the operation ends `failed` with the safe reason
/// and the retry action, the pool is unchanged, and no code, state value or
/// verifier reaches the operation object or the log. The timeout case is
/// `acc_login_times_out_past_its_ttl_with_the_retry_action`.
#[tokio::test(flavor = "multi_thread")]
async fn acc_login_refused_authorisation_ends_failed_with_the_retry_action() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("acc-login-refused").await;
    let (id, url) = start_login(&instance);
    let (callback, state) = callback_target(&url);
    let answer = send(
        callback,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/callback?error=access_denied&state={state}"))
            .body(Full::new(Bytes::new()))
            .expect("request builds"),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::BAD_REQUEST,
        "a refusal is not the success page"
    );

    let operation = await_operation(&instance, &id);
    assert_eq!(operation["state"], "failed");
    let error = &operation["error"];
    assert_eq!(error["code"], "login_failed");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("refused"),
        "a safe reason naming the refusal: {error}"
    );
    assert_eq!(
        error["details"][0]["code"], "retry",
        "the retry action: {error}"
    );
    assert_eq!(error["details"][0]["message"], "start a new login");

    assert!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .is_empty(),
        "the pool is unchanged"
    );

    // No code, state value or verifier returns in the operation object or
    // reaches the log. No code exists here (the callback carries none) and
    // the verifier never left the flow; the state value is the one secret
    // this flow held somewhere observable, so it stands for the three.
    assert!(
        !operation.to_string().contains(&state),
        "the state never returns in the operation object: {operation}"
    );
    let mut hits = Vec::new();
    sweep(&instance.root, &[], &[state.as_str()], &mut hits);
    assert!(hits.is_empty(), "the state is never logged: {hits:#?}");
}

/// The timeout case: a browser flow that sits out
/// its whole TTL ends `failed` with a safe reason and the retry action, the
/// pool is unchanged, and the callback listener is closed. The TTL is the
/// server's fixed 15-minute constant (`login.rs`), no fake input can shorten
/// it, so the deadline is moved from outside the process: the
/// the published expiry is the anchor: awaiting one tick plus the suite's
/// 2 s scheduling slack before it, failed at it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn acc_login_times_out_past_its_ttl_with_the_retry_action() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = crate::faults::Faults::new();
    let instance =
        Instance::start_with_faults("acc-login-timeout", Setup::default(), faults.clone()).await;
    let (id, url) = start_login(&instance);
    let (callback, state) = callback_target(&url);

    let operation = instance.cli_json(&["account", "operation", "show", &id], None);
    let expires_at = time::OffsetDateTime::parse(
        operation["result"]["operation"]["expires_at"]
            .as_str()
            .expect("expires_at"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("RFC 3339 expiry");

    // Awaiting one tick plus the suite's scheduling slack before the TTL.
    faults.set_time(expires_at - time::Duration::seconds(3));
    let envelope = instance.cli_json(&["account", "operation", "show", &id], None);
    assert_eq!(
        envelope["result"]["operation"]["state"],
        "awaiting_authorization"
    );

    // Failed at the TTL: the safe reason names the expiry, the retry action
    // follows, no account was added and the state value returns nowhere.
    faults.set_time(expires_at);
    let operation = await_operation(&instance, &id);
    assert_eq!(operation["state"], "failed");
    let error = &operation["error"];
    assert_eq!(error["code"], "login_failed");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("expired"),
        "a safe reason naming the expiry: {error}"
    );
    assert_eq!(error["details"][0]["code"], "retry", "{error}");
    assert_eq!(error["details"][0]["message"], "start a new login");
    assert!(
        !operation.to_string().contains(&state),
        "the state never returns in the operation object: {operation}"
    );
    assert!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .is_empty(),
        "the pool is unchanged"
    );

    // The callback listener closed with the flow.
    let answer = try_send(
        callback,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/callback?code=oat-late&state={state}"))
            .body(Full::new(Bytes::new()))
            .expect("request builds"),
    )
    .await;
    assert!(
        answer.is_err(),
        "the callback listener is closed after the expiry: {answer:?}"
    );
}

// ---- step 3, session A: the refresh engine

/// 20 concurrent prompts against an in-margin FSUB with a held token reply
/// share one refresh: exactly one token call,
/// `health.state == "refreshing"` before release, every attempt answered
/// 200 on the rotated bearer.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_prompts_share_one_refresh() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("acc-shared-refresh").await;
    let rotated = needle("access token", "oat-rotated");
    instance.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &instance.needles.access_token,
        &instance.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
    );
    let gate = Arc::new(Notify::new());
    instance.upstream.script_token([Reply::HoldThen(
        gate.clone(),
        Box::new(Reply::status(
            200,
            json!({
                "access_token": rotated,
                "refresh_token": needle("refresh token", "ort-rotated"),
                "expires_in": 3600,
            })
            .to_string(),
        )),
    )]);

    let prompts: Vec<_> = (0..20)
        .map(|_| {
            let addr = instance.addr;
            tokio::spawn(async move { send(addr, messages(haiku_prompt())).await })
        })
        .collect();
    for _ in 0..100 {
        if !instance.upstream.token_calls().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(instance.upstream.token_calls().len(), 1);
    assert_eq!(instance.account("FSUB")["health"]["state"], "refreshing");
    gate.notify_one();

    for prompt in prompts {
        assert_eq!(prompt.await.expect("prompt task").status, StatusCode::OK);
    }
    assert_eq!(instance.upstream.token_calls().len(), 1);
    let attempts: Vec<_> = instance
        .upstream
        .seen()
        .into_iter()
        .filter(|seen| seen.path == "/v1/messages")
        .collect();
    assert_eq!(attempts.len(), 20);
    let bearer = format!("Bearer {rotated}");
    assert!(
        attempts
            .iter()
            .all(|attempt| { attempt.header("authorization") == Some(bearer.as_str()) })
    );
}

/// Transient refresh failures make three calls 500 ms then 1 s
/// apart and leave an unexpired family ready; a permanent rejection makes one
/// call, errors the account safely, and ends the exchange with the proxy's 502.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_retries_transient_failures_but_not_permanent_ones() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let transient = Instance::start("refresh-retries-transient-transient").await;
    transient.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &transient.needles.access_token,
        &transient.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
    );
    transient
        .upstream
        .script_token([503, 503, 503].map(|status| Reply::status(status, "{}")));

    let answer = send(transient.addr, messages(haiku_prompt())).await;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let token_calls = transient.upstream.token_calls();
    assert_eq!(token_calls.len(), 3);
    assert!(token_calls[1].at.duration_since(token_calls[0].at) >= Duration::from_millis(500));
    assert!(token_calls[2].at.duration_since(token_calls[1].at) >= Duration::from_secs(1));
    let attempts: Vec<_> = transient
        .upstream
        .seen()
        .into_iter()
        .filter(|seen| seen.path == "/v1/messages")
        .collect();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].header("authorization"),
        Some(format!("Bearer {}", transient.needles.access_token).as_str())
    );
    let fsub = transient.account("FSUB");
    assert_eq!(fsub["health"]["state"], "ready");
    let next_refresh = crate_time(
        fsub["credential"]["next_refresh_allowed_at"]
            .as_str()
            .expect("transient floor"),
    );
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!((next_refresh - now - 30).abs() <= 3, "30-second floor");

    let permanent = Instance::start("refresh-retries-transient-permanent").await;
    permanent.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &permanent.needles.access_token,
        &permanent.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
    );
    permanent
        .upstream
        .script_token([Reply::status(400, "rejected")]);

    let answer = send(permanent.addr, messages(haiku_prompt())).await;

    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    assert!(answer.text().contains("FSUB"), "{}", answer.text());
    assert_eq!(permanent.upstream.token_calls().len(), 1);
    let fsub = permanent.account("FSUB");
    assert_eq!(fsub["health"]["state"], "errored");
    let reason = fsub["health"]["reason"].as_str().expect("safe reason");
    assert!(reason.contains("token endpoint"), "{reason}");
    for needle in permanent.needles.all() {
        assert!(!reason.contains(needle), "secret in health reason");
    }
}

/// A 401 on a future-dated token forces one refresh and the
/// retry answers 200; a second 401 inside the 10 s success floor makes no
/// second token call, and the retry carries the rotated bearer.
#[tokio::test(flavor = "multi_thread")]
async fn success_floor_suppresses_a_second_rotation() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("success-floor-suppresses").await;
    instance.add_fsub();

    let rotated = needle("access token", "oat-rotated");
    instance.upstream.script([reply_auth_401()]);
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": rotated,
            "refresh_token": needle("refresh token", "ort-rotated"),
            "expires_in": 3600,
        })
        .to_string(),
    )]);

    // First exchange: 401 on the 2099 bearer → forced refresh → retry → 200.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(instance.upstream.token_calls().len(), 1, "one token call");

    // Second exchange, inside the 10 s success floor: 401 again, but the
    // engine answers Ready without rotating and the retry reuses the newest
    // (rotated) bearer to the default 200.
    instance.upstream.script([reply_auth_401()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());

    assert_eq!(
        instance.upstream.token_calls().len(),
        1,
        "the floor suppressed the second rotation"
    );
    let attempts: Vec<_> = instance
        .upstream
        .seen()
        .into_iter()
        .filter(|seen| seen.path == "/v1/messages")
        .collect();
    assert_eq!(attempts.len(), 4, "two attempts per exchange");
    let old_bearer = format!("Bearer {}", instance.needles.access_token);
    let rotated_bearer = format!("Bearer {rotated}");
    assert_eq!(
        attempts[0].header("authorization"),
        Some(old_bearer.as_str())
    );
    assert_eq!(
        attempts[1].header("authorization"),
        Some(rotated_bearer.as_str())
    );
    assert_eq!(
        attempts[2].header("authorization"),
        Some(rotated_bearer.as_str()),
        "the floor retry carries the newest persisted token"
    );
    assert_eq!(
        attempts[3].header("authorization"),
        Some(rotated_bearer.as_str())
    );

    for record in instance.audit_settled(2) {
        assert_eq!(record["attempts"], 2, "both attempts count: {record}");
        assert_eq!(record["error_class"], Value::Null);
    }

    assert_eq!(
        instance.events("forced_refresh").len(),
        2,
        "one per 401; only the first rotates"
    );
    assert_eq!(instance.events("refresh_succeeded").len(), 1);
    let skipped = instance.events("refresh_skipped");
    assert_eq!(skipped.len(), 1, "one skip: {skipped:?}");
    assert_eq!(skipped[0]["fields"]["why"], "success_floor");
    assert_eq!(instance.account("FSUB")["health"]["state"], "ready");
}

/// The transient floor keeps a valid old token ready and an
/// expired token in refresh-wait without reopening the token endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn transient_refresh_floor() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let valid = Instance::start("transient-refresh-floor-valid").await;
    valid.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &valid.needles.access_token,
        &valid.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
    );
    valid
        .upstream
        .script_token([503, 503, 503].map(|status| Reply::status(status, "{}")));

    for _ in 0..2 {
        let answer = send(valid.addr, messages(haiku_prompt())).await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    }
    assert_eq!(valid.upstream.token_calls().len(), 3);
    let attempts: Vec<_> = valid
        .upstream
        .seen()
        .into_iter()
        .filter(|seen| seen.path == "/v1/messages")
        .collect();
    assert_eq!(attempts.len(), 2);
    let old_bearer = format!("Bearer {}", valid.needles.access_token);
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.header("authorization") == Some(&old_bearer))
    );
    assert_eq!(valid.account("FSUB")["health"]["state"], "ready");

    let expired = Instance::start("transient-refresh-floor-expired").await;
    expired.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &expired.needles.access_token,
        &expired.needles.refresh_token,
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );
    expired
        .upstream
        .script_token([503, 503, 503].map(|status| Reply::status(status, "{}")));

    for _ in 0..2 {
        let answer = send(expired.addr, messages(haiku_prompt())).await;
        assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(answer.json()["error"]["type"], "rate_limit_error");
        let retry_after = answer
            .header("retry-after")
            .expect("refresh-wait retry-after")
            .parse::<u64>()
            .expect("numeric retry-after");
        assert!((1..=30).contains(&retry_after));
    }
    assert_eq!(
        expired.upstream.token_calls().len(),
        3,
        "the second prompt inside the floor makes no token call"
    );
    assert!(
        expired
            .audit_settled(2)
            .iter()
            .all(|record| record["attempts"] == 0 && record["error_class"] == "rate_limit")
    );
    let fsub = expired.account("FSUB");
    assert_eq!(fsub["health"]["state"], "refresh_wait");
    let next_refresh = crate_time(
        fsub["credential"]["next_refresh_allowed_at"]
            .as_str()
            .expect("transient floor"),
    );
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!((next_refresh - now - 30).abs() <= 3, "30-second floor");
}

/// Rejected credentials (the 401, a permanent token-endpoint
/// rejection) persist `errored` with their safe reasons across a restart, while
/// everything refuses to error on — 403, any 429, a network failure, a
/// transient refresh — leaves a healthy account healthy, across a restart too.
#[tokio::test(flavor = "multi_thread")]
async fn errored_persists_and_transient_failures_do_not_error() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("errored-persists-transient").await;
    instance.add_fkey();
    instance.add_fsub();
    instance.add_oauth_family(
        "FSUB2",
        "fsub2@fixture.invalid",
        FSUB2_UUID,
        &needle("access token", "oat-fsub2"),
        &needle("refresh token", "ort-fsub2"),
        OffsetDateTime::now_utc() + time::Duration::seconds(3600),
    );

    // (a) FKEY: an upstream 401 errors the account.
    instance.error_via_401("FKEY").await;
    let fkey_reason = instance.account("FKEY")["health"]["reason"]
        .as_str()
        .expect("safe reason")
        .to_string();
    assert!(!fkey_reason.is_empty());

    // (b) FSUB: the 401 forces a refresh and the token endpoint answers with
    // a permanent rejection — one call, then errored.
    instance.upstream.script([reply_auth_401()]);
    instance
        .upstream
        .script_token([Reply::status(400, "rejected")]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{}", answer.text());
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    assert_eq!(instance.upstream.token_calls().len(), 1);
    instance.settle();
    let fsub = instance.account("FSUB");
    assert_eq!(fsub["health"]["state"], "errored");
    let fsub_reason = fsub["health"]["reason"]
        .as_str()
        .expect("safe reason")
        .to_string();
    assert!(fsub_reason.contains("token endpoint"), "{fsub_reason}");
    for needle in instance.needles.all() {
        assert!(!fsub_reason.contains(needle), "secret in health reason");
        assert!(!fkey_reason.contains(needle), "secret in health reason");
    }

    // The errored state and its reason survive a restart.
    instance.restart();
    assert_eq!(instance.account("FKEY")["health"]["state"], "errored");
    assert_eq!(
        instance.account("FKEY")["health"]["reason"].as_str(),
        Some(fkey_reason.as_str()),
        "the reason is persisted"
    );
    assert_eq!(instance.account("FSUB")["health"]["state"], "errored");
    assert_eq!(
        instance.account("FSUB")["health"]["reason"].as_str(),
        Some(fsub_reason.as_str()),
        "the reason is persisted"
    );

    // FSUB2 (healthy) walks every case: none may error it.

    // 403 ends the exchange with the 502 and leaves the account ready.
    instance.upstream.script([Reply::status(
        403,
        json!({
            "type": "error",
            "error": { "type": "permission_error", "message": "Request not allowed" },
            "request_id": "req_fixture_0403",
        })
        .to_string(),
    )]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{}", answer.text());
    assert_eq!(instance.account("FSUB2")["health"]["state"], "ready");

    // An exhaustion 429 is relayed byte-identical; the account stays ready.
    // The windows reset 3 s out so the hold lapses naturally instead of
    // pinning FSUB2 unavailable until 2099.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("5h-reset", &reset_in(3)),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
            ("7d-reset", &reset_in(3)),
        ],
        Some("3"),
    )]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("3"));
    assert_eq!(instance.account("FSUB2")["health"]["state"], "ready");
    std::thread::sleep(Duration::from_millis(4_000));

    // A network failure on both attempts closes the caller's connection and
    // never touches health.
    instance
        .upstream
        .script([Reply::ResetBeforeHeaders, Reply::ResetBeforeHeaders]);
    let outcome = try_send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert!(outcome.is_err(), "the caller's connection closes");
    assert_eq!(instance.account("FSUB2")["health"]["state"], "ready");

    // An in-margin expiry makes the selection wait for a refresh; three
    // transient token failures burn the retry budget, leave the still-valid
    // family ready and set the 30-second floor.
    let fsub2_access = needle("access token", "oat-fsub2");
    instance.add_oauth_family(
        "FSUB2",
        "fsub2@fixture.invalid",
        FSUB2_UUID,
        &fsub2_access,
        &needle("refresh token", "ort-fsub2"),
        OffsetDateTime::now_utc() + time::Duration::seconds(299),
    );
    instance
        .upstream
        .script_token([503, 503, 503].map(|status| Reply::status(status, "{}")));
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let fsub2 = instance.account("FSUB2");
    assert_eq!(fsub2["health"]["state"], "ready");
    let next_refresh = crate_time(
        fsub2["credential"]["next_refresh_allowed_at"]
            .as_str()
            .expect("transient floor"),
    );
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!((next_refresh - now - 30).abs() <= 3, "30-second floor");
    let attempts: Vec<_> = instance
        .upstream
        .seen()
        .into_iter()
        .filter(|seen| seen.path == "/v1/messages")
        .collect();
    let bearer = format!("Bearer {fsub2_access}");
    assert_eq!(
        attempts.last().expect("an attempt").header("authorization"),
        Some(bearer.as_str())
    );

    // A pure burst throttle is relayed verbatim; still ready. Last, because
    // its 90 s hold would otherwise gate the pinned cases above.
    instance.upstream.script([reply_throttle_429(Some(90))]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("90"));
    assert_eq!(instance.account("FSUB2")["health"]["state"], "ready");

    // holds over a restart too: FSUB2 was never errored.
    instance.restart();
    assert_eq!(instance.account("FSUB2")["health"]["state"], "ready");
    assert_eq!(instance.account("FKEY")["health"]["state"], "errored");
    assert_eq!(instance.account("FSUB")["health"]["state"], "errored");
}

/// The margin refresh blocks the selected account's attempt,
/// leaves an outside-margin account alone, and also runs at startup.
#[tokio::test(flavor = "multi_thread")]
async fn refreshes_inside_the_margin_and_at_startup() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("refreshes-inside-margin-margin").await;
    let rotated = needle("access token", "oat-rotated");
    let future_access = needle("access token", "oat-future");
    let future_refresh = needle("refresh token", "ort-future");
    let now = OffsetDateTime::now_utc();
    instance.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &instance.needles.access_token,
        &instance.needles.refresh_token,
        now + time::Duration::seconds(299),
    );
    instance.add_oauth_family(
        "FSUB2",
        "fsub2@fixture.invalid",
        FSUB2_UUID,
        &future_access,
        &future_refresh,
        now + time::Duration::minutes(20),
    );
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": rotated,
            "refresh_token": needle("refresh token", "ort-rotated"),
            "expires_in": 3600,
        })
        .to_string(),
    )]);

    let before = instance.upstream.calls();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let seen = instance.upstream.seen();
    let seen = &seen[before..];
    assert_eq!(
        seen.iter()
            .map(|call| call.path.as_str())
            .collect::<Vec<_>>(),
        ["/v1/oauth/token", "/v1/messages"]
    );
    assert_eq!(
        seen[1].header("authorization"),
        Some(format!("Bearer {rotated}").as_str())
    );
    assert!(
        instance.account("FSUB")["credential"]["last_refresh_success"].is_string(),
        "the successful refresh is persisted"
    );

    let token_calls = instance.upstream.token_calls().len();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(
        instance.upstream.token_calls().len(),
        token_calls,
        "the account outside the margin makes no token call"
    );

    let mut startup = Instance::start("refreshes-inside-margin-startup").await;
    let startup_rotated = needle("access token", "oat-startup");
    startup.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &startup.needles.access_token,
        &startup.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
    );
    let old_expiry = startup.account("FSUB")["credential"]["access_token_expires_at"].clone();
    startup.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": startup_rotated,
            "refresh_token": needle("refresh token", "ort-startup"),
            "expires_in": 3600,
        })
        .to_string(),
    )]);
    let before = startup.upstream.calls();

    startup.restart();

    let mut fsub = startup.account("FSUB");
    for _ in 0..100 {
        if fsub["credential"]["access_token_expires_at"] != old_expiry {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        fsub = startup.account("FSUB");
    }
    assert_ne!(fsub["credential"]["access_token_expires_at"], old_expiry);
    assert!(fsub["credential"]["last_refresh_success"].is_string());

    let answer = send(startup.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let seen = startup.upstream.seen();
    let seen = &seen[before..];
    assert_eq!(
        seen.iter()
            .map(|call| call.path.as_str())
            .collect::<Vec<_>>(),
        ["/v1/oauth/token", "/v1/messages"]
    );
    assert_eq!(
        seen[1].header("authorization"),
        Some(format!("Bearer {startup_rotated}").as_str())
    );
}

/// The publish order survives a crash: the refresh
/// publishes (and is durable) before the attempt goes out, so killing the
/// server while its attempt stalls leaves the rotated family in the state
/// file, the restarted server derives `ready` (nothing is restored as
/// `refreshing`), and the next prompt serves with the rotated bearer and no
/// token call.
#[tokio::test(flavor = "multi_thread")]
async fn rotated_family_is_durable_before_it_serves() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("rotated-family-durable").await;
    instance.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &instance.needles.access_token,
        &instance.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
    );
    let rotated_access = needle("access token", "oat-rotated");
    let rotated_refresh = needle("refresh token", "ort-rotated");
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": rotated_access.clone(),
            "refresh_token": rotated_refresh.clone(),
            "expires_in": 3600,
        })
        .to_string(),
    )]);
    instance.upstream.script([Reply::Stall]);

    // Fire without awaiting: the exchange refreshes, publishes, then stalls
    // mid-attempt — the crash happens while serving, not while refreshing.
    let addr = instance.addr;
    let stalled = tokio::spawn(async move { send(addr, messages(haiku_prompt())).await });
    let rotated_bearer = format!("Bearer {rotated_access}");
    let mut published = false;
    for _ in 0..500 {
        if instance.upstream.seen().iter().any(|seen| {
            seen.path == "/v1/messages"
                && seen.header("authorization") == Some(rotated_bearer.as_str())
        }) {
            published = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(published, "the attempt went out on the rotated bearer");
    assert_eq!(instance.upstream.token_calls().len(), 1);

    instance.crash_and_restart();
    stalled.abort();

    // The rotated family was durable before it served.
    let record = instance.state_file()["accounts"]
        .as_array()
        .expect("state accounts")
        .iter()
        .find(|account| account["display_name"] == "FSUB")
        .expect("FSUB persisted")
        .clone();
    assert_eq!(record["access_token"], json!(rotated_access));
    assert_eq!(record["refresh_token"], json!(rotated_refresh));
    assert_eq!(
        instance.account("FSUB")["health"]["state"],
        "ready",
        "the runtime registry is never restored as refreshing"
    );

    // The next prompt needs no token call and serves with the rotated bearer.
    let before = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let seen = instance.upstream.seen();
    let seen = &seen[before..];
    assert_eq!(
        seen.iter()
            .map(|call| call.path.as_str())
            .collect::<Vec<_>>(),
        ["/v1/messages"],
        "no token call after the restart"
    );
    assert_eq!(
        seen[0].header("authorization"),
        Some(rotated_bearer.as_str())
    );
}

/// Every mutation — add, replace, rename, disable,
/// enable, remove — is already durable in the state file when its CLI call
/// returns, with no settle. Then the fail-stop: with the state directory
/// made unwritable, `rename` is refused `503 unavailable` (CLI exit 10), the
/// process exits 23, and a restart after restoring the mode shows the old
/// name. Unix-only; skipped as root with a message, never silently.
#[tokio::test(flavor = "multi_thread")]
async fn state_is_durable_at_ack_and_an_unwritable_state_stops_the_process() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("state-durable-ack").await;
    let record = |name: &str| {
        instance.state_file()["accounts"]
            .as_array()
            .expect("accounts array")
            .iter()
            .find(|r| r["display_name"] == name)
            .cloned()
    };

    // Add: the family is pooled the moment the CLI returns (no settle).
    instance.add_fsub();
    let added = record("FSUB").expect("FSUB persisted at ack");
    assert_eq!(added["access_token"], json!(instance.needles.access_token));
    assert_eq!(
        added["refresh_token"],
        json!(instance.needles.refresh_token)
    );

    // Replace: the new key is pooled and the old one is gone at the ack.
    instance.add_fkey();
    assert!(record("FKEY").is_some(), "FKEY persisted at ack");
    let key2 = needle("API key", "fixture");
    let envelope = instance.cli_json(
        &["account", "replace", "FKEY", "--api-key", "--stdin"],
        Some(&key2),
    );
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    let state = instance.state_file().to_string();
    assert!(state.contains(&key2), "the replaced key is pooled: {state}");
    assert!(
        !state.contains(&instance.needles.api_key),
        "the replaced-out key is gone"
    );

    // Rename, disable, enable — each durable at its ack.
    let handle = instance.handle("FSUB");
    let envelope = instance.cli_json(&["account", "rename", "FSUB", "Renamed"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    let renamed = record("Renamed").expect("the rename is durable at ack");
    assert_eq!(renamed["handle"], json!(handle), "the handle is unchanged");

    let envelope = instance.cli_json(&["account", "disable", "Renamed"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        record("Renamed").expect("the disable is durable at ack")["enabled"],
        json!(false)
    );

    let envelope = instance.cli_json(&["account", "enable", "Renamed"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        record("Renamed").expect("the enable is durable at ack")["enabled"],
        json!(true)
    );

    // Remove: the record is gone at the ack.
    instance.add_oauth("TMP", "tmp@fixture.invalid", &Uuid::new_v4().to_string());
    assert!(record("TMP").is_some(), "TMP persisted at ack");
    let envelope = instance.cli_json(&["account", "remove", "TMP", "--yes"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert!(record("TMP").is_none(), "the removal is durable at ack");

    #[cfg(not(unix))]
    {
        eprintln!("skipping the unwritable-stop rows: the scenario is Unix-only");
        eprintln!("skipping: the scenario is Unix-only");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = instance.root.join("state");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500))
            .expect("chmod the state directory");
        // As root the mode cannot make the directory unwritable: skip with a
        // message, never silently.
        if fs::write(dir.join(".probe"), b"probe").is_ok() {
            let _ = fs::remove_file(dir.join(".probe"));
            eprintln!(
                "skipping the unwritable-stop rows: running as root, chmod 0500 cannot make the state directory unwritable"
            );
            eprintln!(
                "skipping: running as root, chmod 0500 cannot make the state directory unwritable"
            );
            return;
        }
        let envelope = instance.cli_json(&["account", "rename", "Renamed", "X"], None);
        assert_eq!(envelope["exit_code"], 10, "{envelope}");
        assert_eq!(envelope["error"]["code"], "unavailable", "{envelope}");
        assert_eq!(
            instance.await_exit(),
            23,
            "the process exits 23 on the failed state write"
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("restore the mode");
        instance.respawn();
        assert_eq!(
            instance.account("Renamed")["display_name"],
            "Renamed",
            "the failed rename wrote nothing and the restart restores the old name"
        );
    }
}

// ---- step 4, session A: identity and credential

/// A Claude-managed import copies the family, names only safe
/// causes on every failure, and never touches the source.
/// The Keychain half is checked by hand on macOS: every row here pins the
/// hint to the file so a developer Mac's real store is never read.
#[tokio::test(flavor = "multi_thread")]
async fn managed_import_copies_the_family_and_never_touches_the_source() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    use time::macros::datetime;

    let instance = Instance::start("managed-import-copies").await;
    let expires = datetime!(2099-01-01 00:00 UTC);
    let managed_path = instance.managed_path();
    let mtime = || {
        fs::metadata(&managed_path)
            .expect("managed file")
            .modified()
            .expect("mtime")
    };
    let add_managed = || {
        let envelope = instance.cli_json(
            &[
                "account",
                "add",
                "--claude-managed",
                "--platform-hint",
                "file",
            ],
            None,
        );
        (
            envelope,
            mtime(),
            fs::read(&managed_path).expect("managed file"),
        )
    };

    // (a) Nested placement: one account, the fake profile's identity, the
    // copied family in the state file, the source unchanged.
    let managed = [
        instance.needles.access_token.clone(),
        instance.needles.refresh_token.clone(),
    ];
    instance.plant_managed_file(Placement::Nested, &managed[0], &managed[1], expires);
    let (source_bytes, source_mtime) = (fs::read(&managed_path).expect("managed file"), mtime());
    let (envelope, after_mtime, after_bytes) = add_managed();
    assert_eq!(envelope["ok"], true, "the managed add: {envelope}");
    let account = envelope["result"]["account"].clone();
    assert_eq!(account["source_class"], "managed-store");
    assert_eq!(account["profile"]["email"], "fsub@fixture.invalid");
    assert_eq!(account["profile"]["account_uuid"], FIXTURE_ACCOUNT_UUID);
    let state = instance.state_file().to_string();
    assert!(state.contains(&managed[0]), "the access token was copied");
    assert!(state.contains(&managed[1]), "the refresh token was copied");
    assert_eq!(after_mtime, source_mtime, "the source mtime");
    assert_eq!(after_bytes, source_bytes, "the source bytes");
    let handle = account["handle"].as_str().expect("handle").to_string();

    // (b) Top-level placement: the same account's family is replaced in place;
    // no duplicate appears.
    let second = [
        needle("access token", "oat"),
        needle("refresh token", "ort"),
    ];
    instance.plant_managed_file(Placement::TopLevel, &second[0], &second[1], expires);
    let (source_bytes, source_mtime) = (fs::read(&managed_path).expect("managed file"), mtime());
    let (envelope, after_mtime, after_bytes) = add_managed();
    assert_eq!(envelope["ok"], true, "the managed re-add: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"].as_str(),
        Some(handle.as_str()),
        "the same account is updated in place"
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1,
        "no duplicate was created"
    );
    let state = instance.state_file().to_string();
    assert!(
        state.contains(&second[0]),
        "the new access token was copied"
    );
    assert!(!state.contains(&managed[0]), "the old family went");
    assert_eq!(after_mtime, source_mtime, "the source mtime");
    assert_eq!(after_bytes, source_bytes, "the source bytes");

    // (c)–(f): every cause is a safe `import_failed` naming the class,
    // with the pool byte-identical.
    let refused = |digest: String, args: &[&str], message: &str| {
        let (code, stdout, stderr) = instance.cli(args, None);
        assert_eq!(code, 9, "the refused add: {stdout}{stderr}");
        assert!(
            stderr.contains(message),
            "the cause names `{message}`: {stdout}{stderr}"
        );
        assert_eq!(instance.state_digest(), digest, "the pool is unchanged");
    };
    let args = [
        "account",
        "add",
        "--claude-managed",
        "--platform-hint",
        "file",
    ];

    // (c) The source is gone.
    instance.remove_managed_file();
    let digest = instance.state_digest();
    refused(digest.clone(), &args, "credentials file: missing");

    // (d) Malformed bytes.
    instance.plant_managed_bytes(b"not json");
    refused(digest.clone(), &args, "credentials file: wrong shape");

    // (e) A family missing its refresh token.
    instance.plant_managed_bytes(
        json!({ "accessToken": "a", "expiresAt": 1_767_225_600_000i64 })
            .to_string()
            .as_bytes(),
    );
    refused(digest.clone(), &args, "credentials file: incomplete family");

    // (f) A keychain hint is unsupported off macOS; on macOS the row is
    // checked by hand, never by touching a real store here.
    #[cfg(not(target_os = "macos"))]
    {
        let args = [
            "account",
            "add",
            "--claude-managed",
            "--platform-hint",
            "keychain",
        ];
        refused(digest.clone(), &args, "keychain");
    }

    // (g) No token byte reaches stdout, stderr, the logs or the audit.
    instance.settle();
    let mut needles = instance.needles.all().to_vec();
    needles.extend(managed.iter().map(String::as_str));
    needles.extend(second.iter().map(String::as_str));
    // the allow-list: the state file holds pooled credentials, and the
    // planted file is the source we must not have modified.
    let allowed = [instance.root.join("state/state.json"), managed_path];
    let mut hits = Vec::new();
    sweep(&instance.root, &allowed, &needles, &mut hits);
    for surface in [instance.stdout(), instance.stderr()] {
        for needle in &needles {
            if encodings(needle).iter().any(|form| surface.contains(form)) {
                hits.push("a standard stream".to_string());
            }
        }
    }
    assert!(hits.is_empty(), "needle hits: {hits:#?}");
}

/// `account replace KEY --api-key --stdin` puts a new key on the
/// same account (handle unchanged, errored from the 401 helper cleared) and
/// the next prompt's attempt carries it; a replace across kinds is refused
/// with `kind_mismatch` in `details` and the pool byte-identical, in both
/// directions.
#[tokio::test(flavor = "multi_thread")]
async fn replace_key_clears_errored_and_refuses_kind_mismatches() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("replace-key-clears").await;
    instance.add_fsub();
    let key1 = needle("API key", "fixture");
    let envelope = instance.cli_json(
        &["account", "add", "--api-key", "--stdin", "--name", "KEY"],
        Some(&key1),
    );
    assert_eq!(envelope["ok"], true, "adding KEY: {envelope}");
    let handle = instance.handle("KEY");

    // The replace is also the errored-recovery path.
    instance.error_via_401("KEY").await;
    let key2 = needle("API key", "fixture");
    let envelope = instance.cli_json(
        &["account", "replace", "KEY", "--api-key", "--stdin"],
        Some(&key2),
    );
    assert_eq!(envelope["ok"], true, "replacing KEY: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"].as_str(),
        Some(handle.as_str()),
        "the handle never changes"
    );
    let row = instance.account("KEY");
    assert_eq!(row["health"]["state"], "ready");
    assert_eq!(row["health"]["reason"], Value::Null, "errored cleared");
    let state = instance.state_file().to_string();
    assert!(state.contains(&key2), "the new key is pooled");
    assert!(!state.contains(&key1), "the old key went");

    // The next prompt's attempt carries the new key (pinned: FSUB is the default).
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "KEY")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(
        instance.upstream.last().header("x-api-key"),
        Some(key2.as_str())
    );

    //A replacement never crosses kinds; the pool is untouched.
    let digest = instance.state_digest();
    let envelope = instance.cli_json(
        &["account", "replace", "FSUB", "--api-key", "--stdin"],
        Some(&key1),
    );
    assert_eq!(
        envelope["exit_code"], 8,
        "OAuth target, API-key credential: {envelope}"
    );
    assert_eq!(
        envelope["error"]["details"][0]["code"], "kind_mismatch",
        "the detail names the kind rule: {envelope}"
    );
    assert_eq!(instance.state_digest(), digest, "the pool is unchanged");

    let portable = json!({
        "access_token": instance.needles.access_token,
        "refresh_token": instance.needles.refresh_token,
        "expires_at": "2099-01-01T00:00:00Z",
    })
    .to_string();
    let envelope = instance.cli_json(
        &["account", "replace", "KEY", "--portable", "--stdin"],
        Some(&portable),
    );
    assert_eq!(
        envelope["exit_code"], 8,
        "API-key target, OAuth credential: {envelope}"
    );
    assert_eq!(
        envelope["error"]["details"][0]["code"], "kind_mismatch",
        "the detail names the kind rule: {envelope}"
    );
    assert_eq!(instance.state_digest(), digest, "the pool is unchanged");
}

/// While a proactive refresh is stalled on
/// the token endpoint, a replace (then a remove) of the account lands at once
/// and wins: the operation's result is discarded (`family_replaced`, then
/// `account_removed`), the state file keeps the operator's family, the attempt
/// carries the operator's bearer, and a removed account is never resurrected
/// (/32/34/35, the operator precedence).
#[tokio::test(flavor = "multi_thread")]
async fn operator_writes_win_over_an_in_flight_refresh() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // (a) A replace during the stalled refresh.
    let instance = Instance::start("replace-key-clears-replace-under").await;
    instance.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &instance.needles.access_token,
        &instance.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
    );
    let rotated_access = needle("access token", "oat-rotated");
    let rotated_refresh = needle("refresh token", "ort-rotated");
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": rotated_access.clone(),
            "refresh_token": rotated_refresh.clone(),
            "expires_in": 3600,
        })
        .to_string(),
    )]);
    instance.upstream.delay_token(Duration::from_secs(2));

    let addr = instance.addr;
    let prompt = tokio::spawn(async move { send(addr, messages(haiku_prompt())).await });
    for _ in 0..500 {
        if instance.upstream.token_calls().len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        instance.upstream.token_calls().len(),
        1,
        "the refresh is in flight"
    );

    let new_access = needle("access token", "oat-new");
    let new_refresh = needle("refresh token", "ort-new");
    let portable = json!({
        "access_token": new_access,
        "refresh_token": new_refresh,
        "expires_at": "2099-01-01T00:00:00Z",
    })
    .to_string();
    let started = Instant::now();
    let (code, stdout, stderr) = instance.cli(
        &["account", "replace", "FSUB", "--portable", "--stdin"],
        Some(&portable),
    );
    assert_eq!(code, 0, "the replace: {stdout}{stderr}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the replace is not blocked by the in-flight refresh"
    );
    let state = instance.state_file().to_string();
    assert!(state.contains(&new_access), "family N is pooled at once");

    let answer = prompt.await.expect("the prompt finishes");
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let bearer = format!("Bearer {new_access}");
    assert_eq!(
        instance
            .upstream
            .seen()
            .into_iter()
            .rev()
            .find(|seen| seen.path == "/v1/messages")
            .expect("one attempt")
            .header("authorization"),
        Some(bearer.as_str()),
        "the attempt carries the operator's family"
    );
    let discarded = instance.events("refresh_discarded");
    assert_eq!(
        discarded.len(),
        1,
        "{}",
        serde_json::to_string(&discarded).unwrap()
    );
    assert_eq!(discarded[0]["fields"]["why"], "family_replaced");
    assert_eq!(
        instance.upstream.token_calls().len(),
        1,
        "the discarded refresh triggered no second call"
    );
    let state = instance.state_file().to_string();
    assert!(state.contains(&new_access), "N survives the discard");
    assert!(!state.contains(&rotated_access), "R was never published");
    assert_eq!(instance.account("FSUB")["health"]["state"], "ready");
    drop(instance);

    // (b) The same shape with a removal instead.
    let instance = Instance::start("replace-key-clears-remove-under").await;
    instance.add_oauth_family(
        "FSUB",
        "fsub@fixture.invalid",
        FIXTURE_ACCOUNT_UUID,
        &instance.needles.access_token,
        &instance.needles.refresh_token,
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
    );
    let rotated_access = needle("access token", "oat-rotated");
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": rotated_access.clone(),
            "refresh_token": needle("refresh token", "ort-rotated"),
            "expires_in": 3600,
        })
        .to_string(),
    )]);
    instance.upstream.delay_token(Duration::from_secs(2));

    let addr = instance.addr;
    let prompt = tokio::spawn(async move { send(addr, messages(haiku_prompt())).await });
    for _ in 0..500 {
        if instance.upstream.token_calls().len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        instance.upstream.token_calls().len(),
        1,
        "the refresh is in flight"
    );

    let started = Instant::now();
    let (code, stdout, stderr) = instance.cli(&["account", "remove", "FSUB", "--yes"], None);
    assert_eq!(code, 0, "the remove: {stdout}{stderr}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the remove is not blocked by the in-flight refresh"
    );
    assert!(
        instance.state_file()["accounts"]
            .as_array()
            .expect("accounts")
            .is_empty(),
        "the record is gone at once"
    );

    let answer = prompt.await.expect("the prompt finishes");
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the sessionless prompt ends on the exclusion-set path"
    );
    assert_eq!(
        instance
            .upstream
            .seen()
            .iter()
            .filter(|seen| seen.path == "/v1/messages")
            .count(),
        0,
        "the removed account was never attempted"
    );
    let discarded = instance.events("refresh_discarded");
    assert_eq!(
        discarded.len(),
        1,
        "{}",
        serde_json::to_string(&discarded).unwrap()
    );
    assert_eq!(discarded[0]["fields"]["why"], "account_removed");
    assert!(
        instance.state_file()["accounts"]
            .as_array()
            .expect("accounts")
            .is_empty(),
        "no record was resurrected"
    );
}

/// The same portable object through `--portable
/// --stdin`, through `--portable --file <0600 path>` and through `--server-file
/// <0600 path>` stays one account with one handle; `source` reads
/// `portable-json`, `portable-json`, `explicit-file` in turn, the last import
/// wins in `status`. A `0644` server file is refused naming the mode, with the
/// state file unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn one_portable_object_three_channels_last_source_wins() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("portable-object-three").await;
    let portable = json!({
        "access_token": needle("access token", "oat-fixture"),
        "refresh_token": needle("refresh token", "ort-fixture"),
        "expires_at": "2099-01-01T00:00:00Z",
    })
    .to_string();
    let profile = json!({
        "account": { "email": "portable@fixture.invalid", "uuid": Uuid::new_v4() },
        "organization": { "uuid": FIXTURE_ORG_UUID, "name": "Fixture Org" },
    })
    .to_string();

    // (a) `--portable --stdin`: the account is created with its source.
    instance
        .upstream
        .script([Reply::status(200, profile.clone())]);
    let envelope = instance.cli_json(
        &["account", "add", "--portable", "--stdin"],
        Some(&portable),
    );
    assert_eq!(envelope["ok"], true, "the stdin add: {envelope}");
    let account = envelope["result"]["account"].clone();
    assert_eq!(account["source_class"], "portable-json");
    let handle = account["handle"].as_str().expect("handle").to_string();
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1,
        "one account after the first import"
    );

    // (b) `--portable --file` (0600): the same identity is updated in place.
    let file = instance.root.join("portable.json");
    write_private(&file, &portable);
    instance
        .upstream
        .script([Reply::status(200, profile.clone())]);
    let envelope = instance.cli_json(
        &[
            "account",
            "add",
            "--portable",
            "--file",
            file.to_str().expect("utf-8 path"),
        ],
        None,
    );
    assert_eq!(envelope["ok"], true, "the file add: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"].as_str(),
        Some(handle.as_str()),
        "the same account is updated in place"
    );
    assert_eq!(
        envelope["result"]["account"]["source_class"],
        "portable-json"
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1,
        "still one account"
    );

    // (c) `--server-file` (0600): the server reads the same protected path and
    // names the account `explicit-file` — the source the status then shows.
    instance.upstream.script([Reply::status(200, profile)]);
    let envelope = instance.cli_json(
        &[
            "account",
            "add",
            "--server-file",
            file.to_str().expect("utf-8 path"),
        ],
        None,
    );
    assert_eq!(envelope["ok"], true, "the server-file add: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"].as_str(),
        Some(handle.as_str()),
        "still the same account"
    );
    assert_eq!(
        instance.account("portable@fixture.invalid")["source_class"],
        "explicit-file",
        "the last import wins in status"
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1,
        "one account throughout"
    );

    // (d) A 0644 server file is refused naming the mode; the pool is unchanged.
    // Only Unix refuses a file by its mode.
    if cfg!(windows) {
        return;
    }
    let open = instance.root.join("open.json");
    fs::write(&open, &portable).expect("write the open file");
    crate::leaks::register_planted(&open);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&open, fs::Permissions::from_mode(0o644)).expect("chmod the open file");
    }
    let digest = instance.state_digest();
    let envelope = instance.cli_json(
        &[
            "account",
            "add",
            "--server-file",
            open.to_str().expect("utf-8 path"),
        ],
        None,
    );
    assert_eq!(envelope["exit_code"], 9, "{envelope}");
    assert_eq!(envelope["error"]["code"], "import_failed");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("mode 644"),
        "the refusal names the mode: {message}"
    );
    assert_eq!(instance.state_digest(), digest, "the refusal wrote nothing");

    // (e) The same 0644 file through the CLI's own `--file` channel is refused
    // by the CLI before any request (as in (c)); the pool is unchanged. The
    // channel rule is a usage error, exit 2, not the server's
    // rejection of a value.
    let envelope = instance.cli_json(
        &[
            "account",
            "add",
            "--portable",
            "--file",
            open.to_str().expect("utf-8 path"),
        ],
        None,
    );
    assert_eq!(envelope["exit_code"], 2, "{envelope}");
    assert_eq!(envelope["error"]["code"], "cli_usage");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("mode 644"),
        "the CLI refusal names the mode: {message}"
    );
    assert_eq!(instance.state_digest(), digest, "nothing written");
}

/// A `--server-file` import is copied once. The file
/// is deleted, the server restarted → the account is still there with its
/// copied family, `ready`, and a prompt goes out with its access token. The
/// path is then overwritten with another family before a second restart →
/// the account's family is unchanged: no live link to the source.
#[tokio::test(flavor = "multi_thread")]
async fn server_file_import_survives_without_its_source() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("server-file-import").await;
    let family = [
        format!("sk-ant-oat-famA-{}", Uuid::new_v4()),
        format!("sk-ant-ort-famA-{}", Uuid::new_v4()),
    ];
    let other = [
        format!("sk-ant-oat-famB-{}", Uuid::new_v4()),
        format!("sk-ant-ort-famB-{}", Uuid::new_v4()),
    ];
    let portable = |family: &[String; 2]| {
        json!({
            "access_token": family[0],
            "refresh_token": family[1],
            "expires_at": "2099-01-01T00:00:00Z",
        })
        .to_string()
    };
    let file = instance.root.join("server-cred.json");
    write_private(&file, &portable(&family));

    // The import: one account, `explicit-file`, the family copied.
    instance.upstream.script([Reply::status(
        200,
        json!({
            "account": {
                "email": "portable@fixture.invalid",
                "uuid": Uuid::new_v4().to_string(),
            },
            "organization": { "uuid": FIXTURE_ORG_UUID, "name": "Fixture Org" },
        })
        .to_string(),
    )]);
    let envelope = instance.cli_json(
        &[
            "account",
            "add",
            "--server-file",
            file.to_str().expect("utf-8 path"),
        ],
        None,
    );
    assert_eq!(envelope["ok"], true, "the import: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["source_class"],
        "explicit-file"
    );

    // The source is gone and the server restarted: the copied family stands.
    fs::remove_file(&file).expect("delete the source");
    instance.restart();
    let account = instance.account("portable@fixture.invalid");
    assert_eq!(account["health"]["state"], "ready");
    let record = instance.state_file()["accounts"]
        .as_array()
        .expect("state accounts")
        .iter()
        .find(|account| account["display_name"] == "portable@fixture.invalid")
        .expect("the account persisted")
        .clone();
    assert_eq!(record["access_token"], json!(family[0]));
    assert_eq!(record["refresh_token"], json!(family[1]));

    // A prompt goes out with the copied access token.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let seen = instance.upstream.seen();
    let messages_call = seen
        .iter()
        .find(|seen| seen.path == "/v1/messages")
        .expect("the attempt went out");
    assert_eq!(
        messages_call.header("authorization"),
        Some(format!("Bearer {}", family[0]).as_str())
    );

    // The path is overwritten with another family: no live link, the second
    // restart leaves the account's family untouched.
    write_private(&file, &portable(&other));
    instance.restart();
    let record = instance.state_file()["accounts"]
        .as_array()
        .expect("state accounts")
        .iter()
        .find(|account| account["display_name"] == "portable@fixture.invalid")
        .expect("the account persisted")
        .clone();
    assert_eq!(record["access_token"], json!(family[0]), "family unchanged");
    assert_eq!(
        record["refresh_token"],
        json!(family[1]),
        "family unchanged"
    );
    let state = instance.state_file().to_string();
    assert!(
        !state.contains(&other[0]) && !state.contains(&other[1]),
        "the overwrite never reached the pool"
    );
}

/// Identity discrimination: the same account UUID in
/// the same organisation imports twice as one account — the second add is the
/// in-place update (same handle, new family in the state file); the
/// same UUID in another organisation is a second account, two handles; with
/// no organisation UUID the exact profile name discriminates, so the same
/// name twice is still one account.
#[tokio::test(flavor = "multi_thread")]
async fn identity_is_account_uuid_plus_organisation_discriminator() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("identity-account-uuid").await;
    let account_uuid = Uuid::new_v4();
    let email = "dup@fixture.invalid";
    let profile = |org: Value| {
        json!({
            "account": { "email": email, "uuid": account_uuid },
            "organization": org,
        })
        .to_string()
    };
    let family = || {
        json!({
            "access_token": needle("access token", "oat-fixture"),
            "refresh_token": needle("refresh token", "ort-fixture"),
            "expires_at": "2099-01-01T00:00:00Z",
        })
    };
    let add = |instance: &Instance, answer: &str, family: Value| {
        instance.upstream.script([Reply::status(200, answer)]);
        instance.cli_json(
            &["api", "POST", "/control/v1/accounts", "--body-stdin"],
            Some(
                &json!({ "credential": { "source": "portable_json", "credential": family } })
                    .to_string(),
            ),
        )
    };
    let body_of = |envelope: &Value| -> Value {
        serde_json::from_str(envelope["result"]["body"].as_str().expect("body text"))
            .expect("response body")
    };

    // (a) `(A, org X)` twice: the first add creates, the second is the
    // in-place update: the same handle, the new family in the state.
    let first = family();
    let org_x = json!({ "uuid": Uuid::new_v4(), "name": "Org X" }).to_string();
    let envelope = add(&instance, &profile(org_x.clone().into()), first.clone());
    assert_eq!(envelope["result"]["status"], 201, "{envelope}");
    let handle = body_of(&envelope)["account"]["handle"]
        .as_str()
        .expect("handle")
        .to_string();

    let second = family();
    let envelope = add(&instance, &profile(org_x.into()), second.clone());
    assert_eq!(envelope["result"]["status"], 201, "{envelope}");
    assert_eq!(
        body_of(&envelope)["account"]["handle"].as_str(),
        Some(handle.as_str()),
        "the second add is the in-place update"
    );
    let state = instance.state_file().to_string();
    assert!(
        state.contains(second["access_token"].as_str().expect("token")),
        "the new family was copied"
    );
    assert!(
        !state.contains(first["access_token"].as_str().expect("token")),
        "the old family went"
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        1,
        "no duplicate was created"
    );

    // (b) `(A, org Y)`: a second account, two handles.
    let org_y = Uuid::new_v4();
    let envelope = add(
        &instance,
        &profile(json!({ "uuid": org_y, "name": "Org Y" })),
        family(),
    );
    assert_eq!(envelope["result"]["status"], 201, "{envelope}");
    let other = body_of(&envelope)["account"]["handle"]
        .as_str()
        .expect("handle")
        .to_string();
    assert_ne!(other, handle, "another organisation is another account");
    let status = instance.status();
    let accounts = status["accounts"].as_array().expect("accounts");
    assert_eq!(accounts.len(), 2);
    let handles: Vec<_> = accounts
        .iter()
        .map(|a| a["handle"].as_str().expect("handle"))
        .collect();
    assert!(handles.contains(&handle.as_str()) && handles.contains(&other.as_str()));

    // (c) `(A, no organisation UUID, name "X")` twice: the exact profile name
    // discriminates, so both answers land on one account.
    let unnamed = profile(json!({ "name": "X" }));
    let envelope = add(&instance, &unnamed, family());
    assert_eq!(envelope["result"]["status"], 201, "{envelope}");
    let named = body_of(&envelope)["account"]["handle"]
        .as_str()
        .expect("handle")
        .to_string();
    let envelope = add(&instance, &unnamed, family());
    assert_eq!(envelope["result"]["status"], 201, "{envelope}");
    assert_eq!(
        body_of(&envelope)["account"]["handle"].as_str(),
        Some(named.as_str()),
        "the profile name discriminates when no organisation UUID exists"
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        3,
        "one account per organisation discriminator"
    );
}

/// A profile the fake answers, a without an
/// `account.uuid`, and a profile stalled past the data-plane first-byte
/// deadline each refuse a new account `422 credential_rejected` with the state
/// digest unchanged. The named replacement is the other half: with the profile
/// the identity is unknown and does not contradict `FSUB`, so the
/// replace succeeds, keeps FSUB's stored identity facts and swaps the family;
/// with the profile answering a different `(uuid, org)` the replace is
/// and the pool stays put.
#[tokio::test(flavor = "multi_thread")]
async fn profile_unavailable_or_incomplete_refuses_new_accounts() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "profile-unavailable-incomplete",
        Setup {
            data_plane: "first_byte_timeout_seconds = 3\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let facts = instance.account("FSUB")["profile"].clone();
    let digest = instance.state_digest();
    let family = || {
        json!({
            "access_token": needle("access token", "oat-fixture"),
            "refresh_token": needle("refresh token", "ort-fixture"),
            "expires_at": "2099-01-01T00:00:00Z",
        })
    };
    let send = |family: &str| {
        instance.cli_json(
            &["account", "add", "--portable", "--stdin", "--name", "NEW"],
            Some(family),
        )
    };

    // A profile that answers 500 refuses the new account.
    instance.upstream.script([Reply::status(500, "down")]);
    let envelope = send(&family().to_string());
    assert_eq!(envelope["exit_code"], 9, "{envelope}");
    assert_eq!(envelope["error"]["code"], "credential_rejected");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .expect("message")
            .contains("profile lookup failed"),
        "{envelope}"
    );
    assert_eq!(instance.state_digest(), digest, "500 wrote nothing");

    // A 200 profile without an account UUID refuses the new account too.
    instance.upstream.script([Reply::status(
        200,
        json!({
            "account": { "email": "half@fixture.invalid" },
            "organization": { "uuid": Uuid::new_v4(), "name": "Org X" },
        })
        .to_string(),
    )]);
    let envelope = send(&family().to_string());
    assert_eq!(envelope["exit_code"], 9, "{envelope}");
    assert_eq!(envelope["error"]["code"], "credential_rejected");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .expect("message")
            .contains("no account UUID"),
        "{envelope}"
    );
    assert_eq!(instance.state_digest(), digest, "the 200 wrote nothing");

    // A stalled profile is bounded by the first-byte deadline and refuses.
    instance.upstream.script([Reply::Stall]);
    let started = Instant::now();
    let envelope = send(&family().to_string());
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "the stall is bounded by the profile deadline"
    );
    assert_eq!(envelope["exit_code"], 9, "{envelope}");
    assert_eq!(envelope["error"]["code"], "credential_rejected");
    assert_eq!(instance.state_digest(), digest, "the stall wrote nothing");

    // the second half: the operator names FSUB, the profile is still
    // — an identity that cannot contradict the named account — so the
    // family is replaced in place and the stored identity facts stay.
    let replaced = family();
    instance.upstream.script([Reply::status(500, "down")]);
    let envelope = instance.cli_json(
        &["account", "replace", "FSUB", "--portable", "--stdin"],
        Some(&replaced.to_string()),
    );
    assert_eq!(envelope["exit_code"], 0, "the replace: {envelope}");
    let row = instance.account("FSUB");
    assert_eq!(row["profile"], facts, "the identity facts are unchanged");
    assert_eq!(
        row["credential"]["access_token_expires_at"],
        "2099-01-01T00:00:00Z"
    );
    let state = instance.state_file().to_string();
    assert!(
        state.contains(replaced["access_token"].as_str().expect("token")),
        "the new family is pooled"
    );

    // A profile that contradicts the named account is a 409, pool unchanged.
    let contradicting = json!({
        "account": { "email": "other@fixture.invalid", "uuid": Uuid::new_v4() },
        "organization": { "uuid": Uuid::new_v4(), "name": "Org X" },
    })
    .to_string();
    instance
        .upstream
        .script([Reply::status(200, contradicting)]);
    let after_replace = instance.state_digest();
    let envelope = instance.cli_json(
        &["account", "replace", "FSUB", "--portable", "--stdin"],
        Some(&family().to_string()),
    );
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    assert_eq!(envelope["error"]["code"], "conflict");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .expect("message")
            .contains(""),
        "{envelope}"
    );
    assert_eq!(instance.state_digest(), after_replace, "409 wrote nothing");
    assert_eq!(instance.account("FSUB")["profile"], facts);
}

/// Naming. A second identity sharing the first's email
/// suffixes both names with their organisation names, the first renamed in
/// place at the second add; a third sharing one organisation name moves the
/// colliding pair to `email (organisation UUID)`. An operator-supplied name
/// survives a re-import whose profile email changed, and the
/// branch: re-importing that identity under another name is a conflict naming
/// the operator's name, the pool unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn shared_emails_take_suffixes_and_explicit_names_survive() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("shared-emails-take").await;
    let email = "twin@fixture.invalid";
    let family = || {
        json!({
            "access_token": needle("access token", "oat-fixture"),
            "refresh_token": needle("refresh token", "ort-fixture"),
            "expires_at": "2099-01-01T00:00:00Z",
        })
    };
    let add = |instance: &Instance, answer: Value, name: Option<&str>| {
        instance
            .upstream
            .script([Reply::status(200, answer.to_string())]);
        let mut args = vec!["account", "add", "--portable", "--stdin"];
        if let Some(name) = name {
            args.extend(["--name", name]);
        }
        instance.cli_json(&args, Some(&family().to_string()))
    };
    let profile = |account_uuid: Uuid, org_name: &str| {
        json!({
            "account": { "email": email, "uuid": account_uuid },
            "organization": { "uuid": Uuid::new_v4(), "name": org_name },
        })
    };

    // The first identity keeps the bare email; the second one sharing it
    // suffixes both names with their organisation names.
    let envelope = add(&instance, profile(Uuid::new_v4(), "Org X"), None);
    assert_eq!(envelope["ok"], true, "first add: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["display_name"], email,
        "the bare email while it is unique"
    );
    let envelope = add(&instance, profile(Uuid::new_v4(), "Org Y"), None);
    assert_eq!(envelope["ok"], true, "second add: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["display_name"],
        format!("{email} (Org Y)")
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .iter()
            .map(|a| a["display_name"].as_str().expect("name"))
            .collect::<Vec<_>>(),
        vec![format!("{email} (Org X)"), format!("{email} (Org Y)")],
        "the first one was renamed in place at the second add"
    );

    // A third with the same organisation name: the colliding pair falls back
    // to the full organisation UUID, the first keeps its unique name.
    let org_y_uuid = instance.account(&format!("{email} (Org Y)"))["profile"]["organization_uuid"]
        .as_str()
        .expect("org uuid")
        .to_string();
    let third = profile(Uuid::new_v4(), "Org Y");
    let envelope = add(&instance, third, None);
    assert_eq!(envelope["ok"], true, "third add: {envelope}");
    let third_org_uuid = envelope["result"]["account"]["profile"]["organization_uuid"]
        .as_str()
        .expect("org uuid")
        .to_string();
    assert_eq!(
        envelope["result"]["account"]["display_name"],
        format!("{email} ({third_org_uuid})")
    );
    let names: Vec<String> = instance.status()["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .map(|a| a["display_name"].as_str().expect("name").to_string())
        .collect();
    assert!(
        names.contains(&format!("{email} ({org_y_uuid})")),
        "the second moved to the organisation UUID with the third: {names:?}"
    );
    assert!(
        names.contains(&format!("{email} (Org X)")),
        "the unique organisation name stands: {names:?}"
    );

    // An operator name survives a re-import whose profile email changed
    // The display name stays, the profile facts update.
    let named_uuid = Uuid::new_v4();
    let named_org = Uuid::new_v4();
    let named = json!({
        "account": { "email": email, "uuid": named_uuid },
        "organization": { "uuid": named_org, "name": "Org W" },
    });
    let envelope = add(&instance, named, Some("Explicit"));
    assert_eq!(envelope["ok"], true, "named add: {envelope}");
    let renamed = json!({
        "account": { "email": "moved@fixture.invalid", "uuid": named_uuid },
        "organization": { "uuid": named_org, "name": "Org W" },
    });
    let envelope = add(&instance, renamed.clone(), None);
    assert_eq!(
        envelope["ok"], true,
        "re-import with a new email: {envelope}"
    );
    assert_eq!(envelope["result"]["account"]["display_name"], "Explicit");
    assert_eq!(
        envelope["result"]["account"]["profile"]["email"], "moved@fixture.invalid",
        "the profile facts followed the refresh"
    );
    assert_eq!(
        instance.status()["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        4,
        "the re-import replaced in place"
    );

    // The same identity under a different name is a 409 naming the
    // operator's name, the pool untouched.
    let before = instance.state_digest();
    let envelope = add(&instance, renamed, Some("Other"));
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    assert_eq!(envelope["error"]["code"], "conflict");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(message.contains("Explicit"), "{message}");
    assert_eq!(instance.state_digest(), before, "409 wrote nothing");
    assert_eq!(instance.account("Explicit")["display_name"], "Explicit");
}

/// Allows exactly two account kinds, refuses
/// without mutation: `credential.source: "third"` is refused naming the
/// member; a portable object carrying an extra `kind` member is a
/// naming the three members; `account add --kind x` is clap's exit 2, with
/// stdin an open pipe the test never writes to (a read of stdin would block).
#[tokio::test(flavor = "multi_thread")]
async fn unknown_kind_and_extra_field_refused_without_mutation() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("unknown-kind-extra").await;

    // `source: "third"` — a 400 before the pool or the profile is touched.
    let before = instance.state_digest();
    let envelope = instance.cli_json(
        &["api", "POST", "/control/v1/accounts", "--body-stdin"],
        Some("{\"credential\": {\"source\": \"third\", \"api_key\": \"sk-ant-api-fixture\"}}"),
    );
    assert_eq!(envelope["result"]["status"], 400, "{envelope}");
    let body: Value = serde_json::from_str(envelope["result"]["body"].as_str().expect("body text"))
        .expect("refusal envelope");
    assert_eq!(body["error"]["target"], "credential.source", "{body}");
    assert_eq!(instance.state_digest(), before, "the refusal wrote nothing");

    // A portable object with an extra `kind` member — the extra field is a 422.
    let portable = json!({
        "access_token": needle("access token", "oat-fixture"),
        "refresh_token": needle("refresh token", "ort-fixture"),
        "expires_at": "2099-01-01T00:00:00Z",
        "kind": "subscription",
    });
    let envelope = instance.cli_json(
        &["api", "POST", "/control/v1/accounts", "--body-stdin"],
        Some(
            &json!({ "credential": { "source": "portable_json", "credential": portable } })
                .to_string(),
        ),
    );
    assert_eq!(envelope["result"]["status"], 422, "{envelope}");
    let body: Value = serde_json::from_str(envelope["result"]["body"].as_str().expect("body text"))
        .expect("refusal envelope");
    assert_eq!(body["error"]["code"], "credential_rejected", "{body}");
    assert_eq!(instance.state_digest(), before, "the refusal wrote nothing");

    // `--kind` is not a flag `account add` offers: clap exits 2 before any
    // read of stdin, though stdin is an open pipe nobody writes to.
    let (code, stderr) = instance.cli_usage(&["account", "add", "--kind", "x"]);
    assert_eq!(code, 2, "clap usage exit: {stderr}");
    assert!(stderr.contains("unexpected argument"), "{stderr}");
    assert_eq!(
        instance.state_digest(),
        before,
        "the usage exit touched nothing"
    );
}

/// A malformed JSON file, a missing field, an empty
/// `access_token`, an extra field, a non-RFC 3339 `expires_at` and a JSON
/// array are each refused naming the cause, the digest and the
/// `account list` count unchanged after every one. The server-file channel
/// is the one where all six reach the server intact: `--portable --stdin`
/// pre-parses client-side and the API's `credential` member must already be
/// an object.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_portable_objects_refused_without_mutation() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("malformed-portable-objects").await;

    let list_count = || {
        let envelope = instance.cli_json(&["account", "list"], None);
        envelope["result"]["accounts"]
            .as_array()
            .expect("accounts array")
            .len()
    };
    let token = needle("access token", "oat-fixture");
    let cases: &[(&str, &str, &str, &str)] = &[
        // (label, file bytes, error code, cause the refusal names)
        (
            "malformed JSON",
            "{\"access_token\": \"oops",
            "import_failed",
            "not a JSON object",
        ),
        (
            "missing field",
            &json!({ "access_token": token, "refresh_token": "r" }).to_string(),
            "credential_rejected",
            "exactly access_token, refresh_token and expires_at",
        ),
        (
            "empty access_token",
            &json!({
                "access_token": "",
                "refresh_token": "r",
                "expires_at": "2099-01-01T00:00:00Z",
            })
            .to_string(),
            "credential_rejected",
            "access_token is not a non-empty string",
        ),
        (
            "extra field",
            &json!({
                "access_token": token,
                "refresh_token": "r",
                "expires_at": "2099-01-01T00:00:00Z",
                "kind": "subscription",
            })
            .to_string(),
            "credential_rejected",
            "exactly access_token, refresh_token and expires_at",
        ),
        (
            "expires_at not RFC 3339",
            &json!({
                "access_token": token,
                "refresh_token": "r",
                "expires_at": "tomorrow",
            })
            .to_string(),
            "credential_rejected",
            "expires_at is not an RFC 3339 timestamp",
        ),
        (
            "JSON array",
            "[1, 2]",
            "credential_rejected",
            "not a JSON object",
        ),
    ];

    for (label, bytes, code, cause) in cases {
        let file = instance
            .root
            .join(format!("portable-{}.json", label.replace(' ', "-")));
        write_private(&file, bytes);
        let body = json!({
            "display_name": "P",
            "credential": {
                "source": "file",
                "path": file.to_str().expect("utf-8 path"),
            },
        })
        .to_string();
        let before = instance.state_digest();
        let count = list_count();

        let envelope = instance.cli_json(
            &["api", "POST", "/control/v1/accounts", "--body-stdin"],
            Some(&body),
        );
        assert_eq!(envelope["result"]["status"], 422, "{label}: {envelope}");
        let refusal: Value =
            serde_json::from_str(envelope["result"]["body"].as_str().expect("body text"))
                .expect("refusal envelope");
        assert_eq!(refusal["error"]["code"], *code, "{label}: {refusal}");
        let message = refusal["error"]["message"].as_str().expect("message");
        assert!(message.contains(*cause), "{label}: {message}");

        assert_eq!(
            instance.state_digest(),
            before,
            "{label}: the refusal wrote nothing"
        );
        assert_eq!(list_count(), count, "{label}: the pool is unchanged");
    }
}

/// `account add --api-key --stdin --name KEY`
/// persists one enabled, ready `api_key` account; the key byte is nowhere in
/// the CLI's argv, standard streams, the server log or the audit record, but
/// the state file holds it (the sweep is over outputs, not the fixture's
/// state).
#[tokio::test(flavor = "multi_thread")]
async fn api_key_add_via_stdin_leaks_no_key_byte() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("api-key-add-via-stdin").await;

    let (code, stdout, stderr) = instance.cli(
        &["account", "add", "--api-key", "--stdin", "--name", "KEY"],
        Some(&instance.needles.api_key),
    );
    assert_eq!(code, 0, "adding KEY: {stdout}{stderr}");

    // One enabled, ready API-key account, key never echoed.
    let row = instance.account("KEY");
    assert_eq!(row["enabled"], true, "{row}");
    assert_eq!(row["health"]["state"], "ready", "{row}");
    assert_eq!(row["kind"], "api_key", "{row}");

    // Argv (the harness built it), stdout, stderr, log and audit
    // carry no key byte; the state file may and does.
    let argv = "--config ".to_string()
        + instance.config.display().to_string().as_str()
        + " account add --api-key --stdin --name KEY";
    let mut hits = Vec::new();
    sweep(
        &instance.root,
        &[instance.root.join("state/state.json")],
        &[&instance.needles.api_key],
        &mut hits,
    );
    for surface in [argv, stdout, stderr, instance.stdout(), instance.stderr()] {
        for form in encodings(&instance.needles.api_key) {
            if surface.contains(&form) {
                hits.push(surface.clone());
            }
        }
    }
    assert!(hits.is_empty(), "needle hits: {hits:#?}");

    let state = instance.state_file();
    let persisted = state["accounts"]
        .as_array()
        .expect("state accounts")
        .iter()
        .find(|a| a["display_name"] == "KEY")
        .expect("KEY persisted");
    assert_eq!(persisted["api_key"], instance.needles.api_key);
}

// ---- step 4, session B: lifecycle and references

/// Each reference form resolves uniquely to the same
/// account; UUID prefixes match nothing; a shared email is ambiguous
/// with the organisation named as the qualifier; a decimal position is never a
/// reference while a display name made of digits resolves as a name.
#[tokio::test(flavor = "multi_thread")]
async fn reference_forms_ambiguity_and_positions() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("acc-references").await;
    instance.add_fsub();
    instance.add_fkey();

    // Every form of FSUB resolves to the same handle. The account UUID
    // compares case-insensitively in full.
    let handle = instance.handle("FSUB");
    for reference in [
        "FSUB".to_string(),
        "fsub".to_string(),
        "fsub@fixture.invalid".to_string(),
        FIXTURE_ACCOUNT_UUID.to_string(),
        FIXTURE_ACCOUNT_UUID.to_uppercase(),
        FIXTURE_ORG_UUID.to_string(),
        handle.clone(),
    ] {
        let envelope = instance.cli_json(&["account", "show", &reference], None);
        assert_eq!(envelope["ok"], true, "show {reference}: {envelope}");
        assert_eq!(
            envelope["result"]["account"]["handle"],
            handle.as_str(),
            "show {reference} resolved elsewhere"
        );
    }

    // No prefix matching — an 8-character UUID prefix matches nothing,
    // exit 6 with the display names the CLI could see.
    let prefix = &FIXTURE_ACCOUNT_UUID[..8];
    let envelope = instance.cli_json(&["account", "show", prefix], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    assert_eq!(envelope["error"]["code"], "account_not_found");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("FSUB") && message.contains("FKEY"),
        "exit 6 lists the display names: {message}"
    );

    // Two accounts sharing one email are ambiguous; the message names
    // the organisation name or full organisation UUID as the qualifier.
    instance.add_other_org(
        "FSUB2",
        "fsub@fixture.invalid",
        &Uuid::new_v4().to_string(),
        &Uuid::new_v4().to_string(),
    );
    let envelope = instance.cli_json(&["account", "show", "fsub@fixture.invalid"], None);
    assert_eq!(envelope["exit_code"], 7, "{envelope}");
    assert_eq!(envelope["error"]["code"], "ambiguous_account_reference");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("FSUB") && message.contains("FSUB2"),
        "exit 7 lists both display names: {message}"
    );
    assert!(
        message.contains("organisation"),
        "the message names the organisation as the qualifier: {message}"
    );
    assert_eq!(
        envelope["error"]["details"].as_array().map(|d| d.len()),
        Some(2),
        "the matching display names travel in details"
    );

    // Is no account yet → exit 6 with the position sentence.
    let envelope = instance.cli_json(&["account", "show", "0"], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("positions are not references"),
        "the position sentence: {message}"
    );

    //A display name made only of decimal digits is valid; it
    // resolves as a name and removal goes through it too.
    let envelope = instance.cli_json(
        &["account", "add", "--api-key", "--stdin", "--name", "0"],
        Some(&instance.needles.api_key),
    );
    assert_eq!(
        envelope["ok"], true,
        "adding the account named 0: {envelope}"
    );
    let envelope = instance.cli_json(&["account", "show", "0"], None);
    assert_eq!(envelope["ok"], true, "show 0 now resolves: {envelope}");
    let (code, _, _) = instance.cli(&["account", "remove", "0", "--yes"], None);
    assert_eq!(code, 0, "remove 0 --yes");
    let envelope = instance.cli_json(&["account", "show", "0"], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    let message = envelope["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("positions are not references"),
        "after removal the position sentence is back: {message}"
    );
}

/// Every account carries a UUID handle, the API-key one
/// included although it has no profile UUID; rename, key replacement and a
/// restart leave every handle unchanged; a removed account's handle never
/// returns — a fresh account with the same display name gets a new handle,
/// `show` on the old handle misses with exit 6, and `show <handle>` for every
/// remaining account resolves.
#[tokio::test(flavor = "multi_thread")]
async fn handles_survive_rename_replacement_restart_and_removal() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("handles-survive-rename").await;
    instance.add_fsub();
    let key1 = needle("API key", "fixture");
    for name in ["KEY", "TMP"] {
        let envelope = instance.cli_json(
            &["account", "add", "--api-key", "--stdin", "--name", name],
            Some(&key1),
        );
        assert_eq!(envelope["ok"], true, "adding {name}: {envelope}");
    }

    // Every handle from `status --json` is a UUID — the API-key accounts,
    // which have no profile UUID, carry one like the OAuth account does.
    let before: Vec<String> = instance.status()["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .map(|a| {
            let handle = a["handle"].as_str().expect("handle string");
            Uuid::parse_str(handle).expect("the handle is a UUID");
            handle.to_string()
        })
        .collect();
    let key_row = instance.account("KEY");
    assert_eq!(key_row["account_uuid"], Value::Null, "no profile UUID");
    let key_handle = instance.handle("KEY");

    // Rename and key replacement leave the handle unchanged.
    let envelope = instance.cli_json(&["account", "rename", "KEY", "KEY2"], None);
    assert_eq!(envelope["ok"], true, "renaming KEY: {envelope}");
    assert_eq!(envelope["result"]["account"]["handle"], key_handle.as_str());
    let key2 = needle("API key", "fixture");
    let envelope = instance.cli_json(
        &["account", "replace", "KEY2", "--api-key", "--stdin"],
        Some(&key2),
    );
    assert_eq!(envelope["ok"], true, "replacing KEY2's key: {envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"],
        key_handle.as_str(),
        "the replacement never moves the handle"
    );

    // The restart stands in for D5's refresh read: every handle is the same.
    instance.restart();
    let after: Vec<String> = instance.status()["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .map(|a| a["handle"].as_str().expect("handle string").to_string())
        .collect();
    assert_eq!(
        after, before,
        "rename, replacement and restart moved nothing"
    );

    // A removed handle is never reused: the fresh account with the same
    // display name gets a new handle, and `show` on the old one misses.
    let tmp_handle = instance.handle("TMP");
    let envelope = instance.cli_json(&["account", "remove", "TMP", "--yes"], None);
    assert_eq!(envelope["ok"], true, "removing TMP: {envelope}");
    let envelope = instance.cli_json(
        &["account", "add", "--api-key", "--stdin", "--name", "TMP"],
        Some(&key1),
    );
    assert_eq!(envelope["ok"], true, "adding the fresh TMP: {envelope}");
    assert_ne!(
        instance.handle("TMP"),
        tmp_handle,
        "the handle is never reused"
    );
    let envelope = instance.cli_json(&["account", "show", &tmp_handle], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    assert_eq!(envelope["error"]["code"], "account_not_found");

    // Every surviving handle still resolves as an reference.
    for handle in [
        &key_handle,
        instance.handle("FSUB").as_str(),
        instance.handle("TMP").as_str(),
    ] {
        let envelope = instance.cli_json(&["account", "show", handle], None);
        assert_eq!(envelope["ok"], true, "show {handle}: {envelope}");
        assert_eq!(
            envelope["result"]["account"]["handle"], *handle,
            "show resolved elsewhere"
        );
    }
}

/// The default removed while a prompt is in flight
/// on it → that prompt finishes with its 200, the next prompt is served by
/// the other account and `status.default` has moved; removing the final
/// account →, the next prompt is the nobody ending, `account
/// list` empty; a restart restores no record; the fake saw no revocation
/// call — no path but `/v1/messages`, `/v1/oauth/token` and the profile.
#[tokio::test(flavor = "multi_thread")]
async fn remove_default_in_flight_then_the_final_account() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("remove-default-flight").await;
    add_two(&instance);
    assert_eq!(instance.default_account(), instance.handle("FSUB"));

    // The default's attempt is in flight at the fake, held there.
    let gate = Arc::new(Notify::new());
    let before = instance.upstream.calls();
    instance.upstream.script([Reply::Hold(gate.clone())]);
    let addr = instance.addr;
    let prompt =
        tokio::spawn(async move { send(addr, pinned(messages(haiku_prompt()), "FSUB")).await });
    for _ in 0..500 {
        if instance.upstream.calls() > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        instance.upstream.calls() > before,
        "the attempt is in flight at the fake"
    );

    // The remove lands at once; the in-flight attempt still finishes 200.
    let envelope = instance.cli_json(&["account", "remove", "FSUB", "--yes"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    gate.notify_one();
    let answer = prompt.await.expect("the prompt task");
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");

    // The default is gone from `status` at once (the write is durable
    // when the remove returned) and the next prompt is served by FSUB2.
    assert_eq!(
        instance.default_account(),
        instance.handle("FSUB2"),
        "status.default moved off the removed account"
    );
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");

    // The final account: removal succeeds, and the next prompt ends on
    // the nobody with no attempt at all.
    let envelope = instance.cli_json(&["account", "remove", "FSUB2", "--yes"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls, "nobody made no attempt");
    let record = instance.last_record(3);
    assert_eq!(record["no_service_reason"], "no_account_configured");

    let envelope = instance.cli_json(&["account", "list"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert!(
        envelope["result"]["accounts"]
            .as_array()
            .expect("accounts array")
            .is_empty(),
        "{envelope}"
    );

    // The removal is durable; the restarted server restores nothing.
    instance.restart();
    let envelope = instance.cli_json(&["account", "list"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert!(
        envelope["result"]["accounts"]
            .as_array()
            .expect("accounts array")
            .is_empty(),
        "no record was restored: {envelope}"
    );
    assert!(
        instance.state_file()["accounts"]
            .as_array()
            .expect("accounts")
            .is_empty(),
        "the state file keeps no account record"
    );

    // Removal never calls Anthropic's revocation; the only
    // paths the fake ever saw are the attempt, the token endpoint and the
    // profile.
    let allowed = ["/v1/messages", "/v1/oauth/token", "/api/oauth/profile"];
    for seen in instance.upstream.seen() {
        assert!(
            allowed.contains(&seen.path.as_str()),
            "unexpected upstream path {}",
            seen.path
        );
    }
}

/// The member set: the account's top-level members and the members of
/// its three nested objects, asserted present (not merely non-null) everywhere.
fn assert_every_account_member(account: &Value, label: &str) {
    for member in [
        "handle",
        "display_name",
        "kind",
        "source_class",
        "enabled",
        "owner",
        "health",
        "profile",
        "credential",
    ] {
        assert!(account.get(member).is_some(), "{label} lacks {member}");
    }
    for member in ["state", "reason", "since"] {
        assert!(
            account["health"].get(member).is_some(),
            "{label} health lacks {member}"
        );
    }
    for member in [
        "email",
        "account_uuid",
        "organization_uuid",
        "organization_name",
    ] {
        assert!(
            account["profile"].get(member).is_some(),
            "{label} profile lacks {member}"
        );
    }
    for member in [
        "access_token_expires_at",
        "refresh_material_present",
        "last_refresh_attempt",
        "last_refresh_success",
        "next_refresh_allowed_at",
    ] {
        assert!(
            account["credential"].get(member).is_some(),
            "{label} credential lacks {member}"
        );
    }
}

/// One instance carrying an API-key account, an OAuth
/// account that refreshed (rotated), one in refresh-wait, one errored and one
/// disabled; `status --json` has every member on every account with
/// `null` where the fact does not apply and never a missing key; the needle
/// sweep over `status`, `account list/show`, the log, the audit and every CLI
/// output of the run finds no key, token, code, state or verifier byte.
#[tokio::test(flavor = "multi_thread")]
async fn status_has_every_fact_and_leaks_no_secret() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("status-has-fact-leaks").await;

    // The five states. FKEY is the API-key account (no profile identity, no
    // refresh times); FROT will refresh and rotate; FWAIT will end in the
    // transient floor; FERR will end errored; FDIS is disabled.
    instance.add_fkey();
    instance.add_oauth_family(
        "FROT",
        "frot@fixture.invalid",
        &Uuid::new_v4().to_string(),
        &instance.needles.access_token,
        &instance.needles.refresh_token,
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );
    instance.add_oauth_family(
        "FWAIT",
        "fwait@fixture.invalid",
        &Uuid::new_v4().to_string(),
        &needle("access token", "oat-fwait"),
        &needle("refresh token", "ort-fwait"),
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );
    instance.add_oauth_family(
        "FERR",
        "ferr@fixture.invalid",
        &Uuid::new_v4().to_string(),
        &needle("access token", "oat-ferr"),
        &needle("refresh token", "ort-ferr"),
        OffsetDateTime::now_utc() + time::Duration::seconds(3600),
    );
    instance.add_oauth("FDIS", "fdis@fixture.invalid", &Uuid::new_v4().to_string());

    // The token endpoint answers in the order the prompts consume it: FROT's
    // rotation, FWAIT's three transient 503s, FERR's permanent rejection.
    let rotated_access = needle("access token", "oat-rotated");
    let rotated_refresh = needle("refresh token", "ort-rotated");
    instance.upstream.script_token([
        Reply::status(
            200,
            json!({
                "access_token": rotated_access,
                "refresh_token": rotated_refresh,
                "expires_in": 3600,
            })
            .to_string(),
        ),
        Reply::status(503, "{}"),
        Reply::status(503, "{}"),
        Reply::status(503, "{}"),
        Reply::status(400, "rejected"),
    ]);

    // FROT: an expired token makes the first prompt refresh (blocking), and
    // the attempt answers 200 on the rotated bearer.
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FROT")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());

    // FWAIT: the transient floor ends the exchange as the 429.
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FWAIT")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    // FERR: the 401 forces a refresh, the token endpoint rejects it
    // permanently, the account ends errored.
    instance.upstream.script([reply_auth_401()]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FERR")).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{}", answer.text());

    // FDIS: disabled through the operator surface.
    let envelope = instance.cli_json(&["account", "disable", "FDIS"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    instance.settle();

    // Every member present on every account, with the right health
    // states behind them.
    let fkey = instance.account("FKEY");
    let frot = instance.account("FROT");
    let fwait = instance.account("FWAIT");
    let ferr = instance.account("FERR");
    let fdis = instance.account("FDIS");
    for (account, label) in [
        (&fkey, "FKEY"),
        (&frot, "FROT"),
        (&fwait, "FWAIT"),
        (&ferr, "FERR"),
        (&fdis, "FDIS"),
    ] {
        assert_every_account_member(account, label);
    }
    assert_eq!(fkey["health"]["state"], "ready");
    assert_eq!(frot["health"]["state"], "ready");
    assert_eq!(fwait["health"]["state"], "refresh_wait");
    assert_eq!(ferr["health"]["state"], "errored");
    assert_eq!(fdis["health"]["state"], "ready");
    assert_eq!(fdis["enabled"], false);
    assert_eq!(fdis["eligibility"]["reason"], "disabled");

    // The facts that do not apply are explicit nulls, never omitted.
    // FKEY: no profile identity (the profile members exist and are null) and
    // no refresh times of any kind.
    for member in [
        "email",
        "account_uuid",
        "organization_uuid",
        "organization_name",
    ] {
        assert!(fkey["profile"][member].is_null(), "FKEY profile.{member}");
    }
    for member in [
        "access_token_expires_at",
        "last_refresh_attempt",
        "last_refresh_success",
        "next_refresh_allowed_at",
    ] {
        assert!(
            fkey["credential"][member].is_null(),
            "FKEY credential.{member}"
        );
    }
    assert_eq!(fkey["credential"]["refresh_material_present"], false);

    // FROT: the rotation made both refresh times facts.
    assert_eq!(frot["credential"]["refresh_material_present"], true);
    assert!(frot["credential"]["last_refresh_attempt"].is_string());
    assert!(frot["credential"]["last_refresh_success"].is_string());

    // FWAIT: one attempt, no success, and the floor is the next permitted
    // refresh time.
    assert!(fwait["credential"]["last_refresh_attempt"].is_string());
    assert!(fwait["credential"]["last_refresh_success"].is_null());
    assert!(fwait["credential"]["next_refresh_allowed_at"].is_string());

    // FERR: the errored state carries its safe reason and its since.
    assert!(
        ferr["health"]["reason"]
            .as_str()
            .is_some_and(|r| !r.is_empty())
    );
    assert!(ferr["health"]["since"].is_string());

    // No secret byte on any surface the run produced. The needle set
    // is every credential the run used plus the fixture OAuth family a
    // default token reply could leak; code, state and verifier bytes belong
    // to the browser login, which this run never opens.
    let mut needles: Vec<String> = instance
        .needles
        .all()
        .iter()
        .map(|s| s.to_string())
        .collect();
    needles.push(rotated_access);
    needles.push(rotated_refresh);
    needles.push(FIXTURE_LOGIN_ACCESS.to_string());
    needles.push(FIXTURE_LOGIN_REFRESH.to_string());
    let needle_refs: Vec<&str> = needles.iter().map(String::as_str).collect();

    // The read surfaces, run through the CLI and kept for the sweep. The add
    // envelopes carry the same projected account objects `account show` does.
    let mut cli_outputs: Vec<String> = Vec::new();
    let mut cli_call = |args: &[&str], stdin: Option<&str>| {
        let (code, stdout, stderr) = instance.cli(args, stdin);
        assert_eq!(code, 0, "CLI {args:?}: {stdout}{stderr}");
        cli_outputs.push(stdout);
        cli_outputs.push(stderr);
    };
    cli_call(&["status"], None);
    cli_call(&["status", "--json"], None);
    cli_call(&["account", "list"], None);
    for name in ["FKEY", "FROT", "FWAIT", "FERR", "FDIS"] {
        cli_call(&["account", "show", name], None);
    }

    // the allow-list: the state file holds the pooled credentials.
    let allowed = [instance.root.join("state")];
    let mut hits = Vec::new();
    sweep(&instance.root, &allowed, &needle_refs, &mut hits);
    for surface in cli_outputs
        .iter()
        .chain(std::iter::once(&instance.stdout()))
        .chain(std::iter::once(&instance.stderr()))
    {
        for needle in &needle_refs {
            if encodings(needle).iter().any(|form| surface.contains(form)) {
                hits.push(format!("a CLI or server stream: {needle}"));
            }
        }
    }
    assert!(hits.is_empty(), "needle hits: {hits:#?}");
}
