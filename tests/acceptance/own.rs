//! Account owners: a client logs in a Claude account of its own through the
//! callback it catches and forwards, logs it in again, and reaches no other
//! owner's account or login.

use std::io::BufRead as _;

use crate::acc::callback_target;
use crate::client_fx::{ClientHome, install_client};
use crate::harness::*;

const LOGIN: &str = "/control/v1/client/accounts/login";

/// `account login` as the client, its browser driven as a real one would
/// drive it: the printed URL's callback answered on the client's own port.
/// The browser's answer, then the exit code, standard output and standard
/// error.
pub(crate) async fn client_login(home: &ClientHome) -> (StatusCode, (i32, String, String)) {
    let no_browser = home.root.join("no-browser-on-path").display().to_string();
    let mut child = home
        .command(&[("PATH", &no_browser)])
        .args(["account", "login"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run jaynshare");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
    let mut url = String::new();
    tokio::task::block_in_place(|| stdout.read_line(&mut url)).expect("the URL line");
    if url.trim().is_empty() {
        let output = child.wait_with_output().expect("jaynshare output");
        panic!(
            "the client printed no URL: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let (callback, state) = callback_target(url.trim());
    let browser = send(callback, callback_request(&state)).await;
    let outcome = tokio::task::block_in_place(|| {
        let mut rest = String::new();
        stdout.read_to_string(&mut rest).expect("stdout");
        let output = child.wait_with_output().expect("jaynshare output");
        (
            output.status.code().unwrap_or(-1),
            format!("{url}{rest}"),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    });
    (browser.status, outcome)
}

pub(crate) fn callback_request(state: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/callback?code=oat-fixture-{}&state={state}",
            Uuid::new_v4()
        ))
        .body(Full::new(Bytes::new()))
        .expect("request builds")
}

/// A login started as `bearer` whose callback is forwarded through the
/// control API, read until it ends.
async fn forwarded_login(instance: &Instance, bearer: &str) -> Value {
    let started = control_post(
        instance.addr,
        LOGIN,
        &[("authorization", bearer)],
        json!({ "redirect_port": 9 }),
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.text());
    let started = started.json();
    let id = started["operation_id"].as_str().expect("operation id");
    let (_, state) = callback_target(started["authorization_url"].as_str().expect("url"));
    let forwarded = control_post(
        instance.addr,
        &format!("/control/v1/client/accounts/operations/{id}/code"),
        &[("authorization", bearer)],
        json!({ "code": format!("code=oat-fixture-{}&state={state}", Uuid::new_v4()) }),
    )
    .await;
    assert_eq!(
        forwarded.status,
        StatusCode::ACCEPTED,
        "{}",
        forwarded.text()
    );
    await_client_operation(instance, bearer, id).await
}

/// The client's operator call at `path` (an issue or a reissue) with
/// `body`, claimed: the client's bearer.
async fn claimed_bearer(instance: &Instance, id: &str, path: &str, body: Value) -> String {
    let issued = control_post(instance.addr, path, &[], body).await;
    assert_eq!(issued.status, StatusCode::CREATED, "{}", issued.text());
    let code = issued.json()["enrollment_code"]
        .as_str()
        .expect("the code")
        .to_string();
    crate::leaks::register_needle("enrollment-code", &code);
    let claimed = control_post(
        instance.addr,
        "/control/v1/enrollment/claim",
        &[],
        json!({ "id": id, "code": code }),
    )
    .await;
    assert_eq!(claimed.status, StatusCode::OK, "{}", claimed.text());
    let claimed = claimed.json();
    assert_eq!(claimed["no_account"], true, "{claimed}");
    let secret = claimed["client_secret"].as_str().expect("the secret");
    crate::leaks::register_needle("client-secret", secret);
    format!("Bearer {secret}")
}

/// A client's own operation, read until it ends.
async fn await_client_operation(instance: &Instance, bearer: &str, id: &str) -> Value {
    let path = format!("/control/v1/client/accounts/operations/{id}");
    for _ in 0..60 {
        let answer = control(
            instance.addr,
            Method::GET,
            &path,
            &[("authorization", bearer)],
            None,
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
        let operation = answer.json()["operation"].clone();
        if matches!(
            operation["state"].as_str(),
            Some("succeeded" | "failed" | "cancelled")
        ) {
            return operation;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("the operation {id} never ended: {}", instance.stderr());
}

/// The accounts a client's own listing names.
async fn owned(instance: &Instance, bearer: &str) -> Vec<Value> {
    let answer = control(
        instance.addr,
        Method::GET,
        "/control/v1/client/accounts/owned",
        &[("authorization", bearer)],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    answer.json()["accounts"]
        .as_array()
        .expect("accounts")
        .clone()
}

/// The login lands as the client's own account, the client lists it, and
/// once its token dies the same login brings the same account back.
#[tokio::test(flavor = "multi_thread")]
async fn own_a_client_logs_in_its_own_account_and_logs_it_in_again() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("own-login").await;
    let home = install_client(&instance).await;

    let (browser, (code, stdout, stderr)) = client_login(&home).await;
    assert_eq!(
        browser,
        StatusCode::FOUND,
        "the browser is sent to the success page"
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("fsub@fixture.invalid"), "{stdout}");
    let account = instance.status()["accounts"][0].clone();
    assert_eq!(account["owner"], "engineer-1");
    assert_eq!(account["source_class"], "browser");
    assert_eq!(
        instance.state_file()["accounts"][0]["owner"],
        "engineer-1",
        "the owner is durable"
    );

    let (code, stdout, stderr) = home.jaynshare(&["account", "list", "--json"], &[], None);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("envelope");
    assert_eq!(envelope["role"], "client");
    let listed = envelope["result"]["accounts"].as_array().expect("accounts");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["handle"], account["handle"]);
    assert_eq!(listed[0]["health"]["state"], "ready");

    let name = account["display_name"].as_str().expect("display name");
    instance.upstream.script_token([reply_auth_401()]);
    instance.error_via_401(name).await;
    let (_, (code, stdout, stderr)) = client_login(&home).await;
    assert_eq!(code, 0, "{stdout}{stderr}");
    let accounts = instance.status()["accounts"].clone();
    assert_eq!(
        accounts.as_array().expect("accounts").len(),
        1,
        "logged in again, not added twice"
    );
    assert_eq!(accounts[0]["handle"], account["handle"]);
    assert_eq!(accounts[0]["health"]["state"], "ready");
    assert_eq!(accounts[0]["owner"], "engineer-1");
}

/// A second client's login onto the first client's account fails and
/// moves nothing.
#[tokio::test(flavor = "multi_thread")]
async fn own_a_client_is_refused_another_client_s_account() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("own-another-client").await;
    let home = install_client(&instance).await;
    let (_, (code, stdout, stderr)) = client_login(&home).await;
    assert_eq!(code, 0, "{stdout}{stderr}");
    let account = instance.status()["accounts"][0].clone();

    let beta = enroll(&instance, "beta", "Beta Desk").await.bearer();
    let operation = forwarded_login(&instance, &beta).await;
    assert_eq!(operation["state"], "failed");
    assert_eq!(
        operation["error"]["message"],
        "this identity is another owner's account; the pool is unchanged"
    );
    let accounts = instance.status()["accounts"].clone();
    assert_eq!(accounts.as_array().expect("accounts").len(), 1);
    assert_eq!(accounts[0]["handle"], account["handle"]);
    assert_eq!(accounts[0]["owner"], "engineer-1");
    assert!(owned(&instance, &beta).await.is_empty());
    assert_eq!(owned(&instance, &home.client.bearer()).await.len(), 1);
}

/// The client's CLI is refused on the operator's account; a client reaches
/// only its own operations, the operator reaches them through its own
/// routes and is kept out of the client's.
#[tokio::test(flavor = "multi_thread")]
async fn own_a_client_reaches_only_its_own_logins() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("own-reach").await;
    let home = install_client(&instance).await;
    instance.add_fsub();

    let (browser, (code, stdout, stderr)) = client_login(&home).await;
    assert_eq!(browser, StatusCode::FOUND);
    assert_eq!(code, 9, "{stdout}{stderr}");
    assert!(stderr.contains("another owner's account"), "{stderr}");
    assert_eq!(instance.account("FSUB")["owner"], Value::Null);

    let (code, _, stderr) = home.jaynshare(&["account", "login", "--no-wait"], &[], None);
    assert_eq!(code, 2, "{stderr}");

    let alpha = home.client.bearer();
    let started = control_post(
        instance.addr,
        LOGIN,
        &[("authorization", &alpha)],
        json!({ "redirect_port": 9 }),
    )
    .await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.text());
    let id = started.json()["operation_id"]
        .as_str()
        .expect("operation id")
        .to_string();
    let path = format!("/control/v1/client/accounts/operations/{id}");

    let beta = enroll(&instance, "beta", "Beta Desk").await.bearer();
    let as_beta = [("authorization", beta.as_str())];
    let read = control(instance.addr, Method::GET, &path, &as_beta, None).await;
    assert_eq!(read.status, StatusCode::NOT_FOUND, "{}", read.text());
    for (action, body) in [
        ("code", json!({ "code": "oat-fixture-beta" })),
        ("cancel", json!({})),
    ] {
        let answer = control_post(instance.addr, &format!("{path}/{action}"), &as_beta, body).await;
        assert_eq!(
            answer.status,
            StatusCode::NOT_FOUND,
            "{action}: {}",
            answer.text()
        );
    }

    let read = control(
        instance.addr,
        Method::GET,
        &path,
        &[("authorization", &alpha)],
        None,
    )
    .await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.text());
    assert_eq!(read.json()["operation"]["state"], "awaiting_authorization");

    let operator = control(
        instance.addr,
        Method::GET,
        &format!("/control/v1/operations/{id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(operator.status, StatusCode::OK, "{}", operator.text());
    let refused = control_post(instance.addr, LOGIN, &[], json!({ "redirect_port": 9 })).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json()["error"]["code"], "client_required");

    let invalid = control_post(
        instance.addr,
        LOGIN,
        &[("authorization", &alpha)],
        json!({ "redirect_port": 70000 }),
    )
    .await;
    assert_eq!(
        invalid.status,
        StatusCode::BAD_REQUEST,
        "{}",
        invalid.text()
    );
}

/// A client whose invite adds no account logs its own account in again,
/// is refused a new identity, and owning none, is refused at the start.
#[tokio::test(flavor = "multi_thread")]
async fn own_a_no_account_client_logs_in_only_its_own_accounts_again() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("own-no-account").await;
    let home = install_client(&instance).await;
    let (_, (code, stdout, stderr)) = client_login(&home).await;
    assert_eq!(code, 0, "{stdout}{stderr}");
    let account = instance.status()["accounts"][0].clone();
    let alpha = claimed_bearer(
        &instance,
        "engineer-1",
        "/control/v1/clients/engineer-1/reissue",
        json!({ "no_account": true }),
    )
    .await;

    let operation = forwarded_login(&instance, &alpha).await;
    assert_eq!(operation["state"], "succeeded", "{operation}");
    assert_eq!(operation["account"]["handle"], account["handle"]);

    instance.upstream.script([Reply::status(
        200,
        json!({
            "account": { "email": "new@fixture.invalid", "uuid": Uuid::new_v4() },
            "organization": { "uuid": Uuid::new_v4(), "name": "New Org" },
        })
        .to_string(),
    )]);
    let operation = forwarded_login(&instance, &alpha).await;
    assert_eq!(operation["state"], "failed", "{operation}");
    assert_eq!(
        operation["error"]["message"],
        "this client's invite adds no new account, and this identity is none of its own; the pool is unchanged"
    );
    let accounts = instance.status()["accounts"].clone();
    assert_eq!(
        accounts.as_array().expect("accounts").len(),
        1,
        "{accounts}"
    );

    let beta = claimed_bearer(
        &instance,
        "beta",
        "/control/v1/clients",
        json!({ "id": "beta", "display_name": "Beta Desk", "no_account": true }),
    )
    .await;
    let refused = control_post(
        instance.addr,
        LOGIN,
        &[("authorization", &beta)],
        json!({ "redirect_port": 9 }),
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text());
    assert_eq!(refused.json()["error"]["code"], "new_account_refused");
}
