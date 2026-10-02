//! Selection: preferences, routes, priorities, tiers, sessions and the
//! ranking that picks the serving account.
use crate::faults::Faults;
use crate::harness::*;
use crate::leaks::negative_control;
/// The audit record carries the cause: pin, preference, route,
/// session, default, ranking, revalidation.
#[tokio::test(flavor = "multi_thread")]
async fn audit_record_carries_the_cause() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "audit-record-carries",
        Setup {
            // Short cadence so the revalidation halves run in seconds.
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            selection: routes(&[("h", &["*haiku*"], None, None)]),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);

    send(instance.addr, messages(haiku_prompt())).await;
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    send(instance.addr, preferred(messages(haiku_prompt()), "FSUB2")).await;
    send(instance.addr, in_session(messages(haiku_prompt()), "alpha")).await;
    send(instance.addr, in_session(messages(haiku_prompt()), "alpha")).await;
    // The operator's route preference is the `route` cause.
    assert_eq!(
        instance.cli(&["switch", "--route", "h", "FSUB2"], None).0,
        0
    );
    send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(
        instance.cli(&["switch", "--route", "h", "--clear"], None).0,
        0
    );
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, messages(haiku_prompt())).await;
    send(instance.addr, messages(haiku_prompt())).await;

    let records = instance.audit_settled(8);
    let causes: Vec<(&str, &str)> = records
        .iter()
        .map(|r| {
            (
                r["selection_cause"].as_str().expect("cause"),
                r["serving_account"]["display_name"]
                    .as_str()
                    .expect("account"),
            )
        })
        .collect();
    assert_eq!(
        causes,
        vec![
            ("default", "FSUB"),
            ("pin", "FSUB2"),
            ("preference", "FSUB2"),
            ("default", "FSUB"),
            ("session", "FSUB"),
            ("route", "FSUB2"),
            ("default", "FSUB"),
            ("ranking", "FSUB2"),
        ]
    );
    assert_eq!(instance.events("default_moved").len(), 1, "the one line");

    // The revalidation cause: both accounts over the threshold now, the quota
    // model offers one candidate per cadence (floor and interval 2 s).
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    instance
        .upstream
        .script([reply_headerless_200(), reply_headerless_200()]);
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(10);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "revalidation");
    assert_eq!(
        instance.default_account(),
        instance.handle("FSUB2"),
        "the candidate never becomes the default"
    );
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "gate closed");
    assert_eq!(instance.upstream.calls(), calls);
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    instance.upstream.script([reply_headerless_200()]);
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(12);
    assert_eq!(record["selection_cause"], "revalidation");
    assert_eq!(instance.events("default_moved").len(), 1);
    assert_eq!(instance.events("revalidation_started").len(), 2);
}
/// Request with no model → served by the default; a family
/// bucket at 0.99 is ignored.
#[tokio::test(flavor = "multi_thread")]
async fn model_less_request_is_served_by_the_default() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("model-less-request").await;
    add_two(&instance);
    let model_less = json!({
        "max_tokens": 32,
        "messages": [{ "role": "user", "content": "say hi" }],
    });
    //A family weekly window at 0.99 on the default.
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    headers.extend(ratelimit_headers("0.12", "0.03", "2099-01-01T00:00:00Z"));
    headers.push((
        "anthropic-ratelimit-unified-7d_oi-utilization".into(),
        "0.99".into(),
    ));
    headers.push((
        "anthropic-ratelimit-unified-7d_oi-status".into(),
        "allowed".into(),
    ));
    instance.upstream.script([Reply::Raw {
        status: 200,
        headers,
        body: message_body().to_string(),
    }]);
    let answer = send(instance.addr, messages(model_less.clone())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let answer = send(instance.addr, messages(model_less)).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(2);
    assert_eq!(record["model"], Value::Null);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "default");
}
/// Pin to an eligible account of a lower tier → served, default
/// unchanged; pin to an account the route excludes → nobody; pin to an
/// account over the threshold → nobody. The held half is
/// re-asserted once the quota model's holds exist.
#[tokio::test(flavor = "multi_thread")]
async fn pin_serves_or_nobody_and_never_moves_the_default() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "pin-serves-nobody",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)])
                + "routes = [{ name = \"haiku\", patterns = [\"*haiku*\"], accounts = [\"FSUB\"] }]\n",
            ..Setup::default()
        },
        add_two,
    )
    .await;
    let default = instance.default_account();
    assert_eq!(default, instance.handle("FSUB"));

    // The route lists FSUB only: a pin cannot bypass it.
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("5"));
    assert_eq!(instance.upstream.calls(), calls);

    // Off the route, the lower tier serves the pin and the default stays.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(
        instance.addr,
        pinned(messages(prompt_for("claude-sonnet-5")), "FSUB2"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "pin");
    assert_eq!(instance.default_account(), default);

    // Now over the threshold: nobody, and FSUB never stands in.
    let calls = instance.upstream.calls();
    let answer = send(
        instance.addr,
        pinned(messages(prompt_for("claude-sonnet-5")), "FSUB2"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls);
    assert_eq!(instance.default_account(), default);
    assert!(instance.events("default_moved").is_empty());

    // Pin to a held account → nobody as well: a 429 first holds FSUB (the
    // route's only haiku account, reached by an unpinned request), then the
    // pin is refused without an attempt (the held half).
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("90"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "real 429");
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("5"));
    assert_eq!(instance.upstream.calls(), calls, "no attempt on a hold");
    let record = instance.last_record(5);
    assert_eq!(record["no_service_reason"], "pinned_unavailable");
    assert_eq!(record["attempts"], 0);
}
/// Preference eligible → served, default unchanged, no switch
/// log; preference ineligible → ordinary rules, audit shows the real account.
#[tokio::test(flavor = "multi_thread")]
async fn preference_serves_while_eligible_then_ordinary_rules() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("preference-serves-while-eligible").await;
    add_two(&instance);
    let default = instance.default_account();

    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, preferred(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "preference");
    assert_eq!(instance.default_account(), default);
    assert!(instance.events("default_moved").is_empty());
    assert!(instance.events("operator_switch").is_empty());

    let answer = send(instance.addr, preferred(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "default");
}
/// Unknown preference / pin → refused, never served by another
/// account.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_preference_or_pin_is_refused() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("unknown-preference-pin").await;
    add_two(&instance);
    let calls = instance.upstream.calls();
    for request in [
        preferred(messages(haiku_prompt()), "FSUB9"),
        pinned(messages(haiku_prompt()), "FSUB9"),
    ] {
        let answer = send(instance.addr, request).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND);
        assert_eq!(answer.json()["error"]["type"], "not_found_error");
    }
    assert_eq!(instance.upstream.calls(), calls);
    for record in instance.audit_settled(2) {
        assert_eq!(record["serving_account"], Value::Null);
        assert_eq!(record["attempts"], 0);
    }
}
/// `A0` default at 0.50, `B0` at 0.10 → stays on `A0`.
#[tokio::test(flavor = "multi_thread")]
async fn the_default_sticks_over_a_less_used_sibling() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("default-sticks-over").await;
    add_two(&instance);
    instance
        .upstream
        .script([reply_teaching_weekly("0.50", "2099-01-01T00:00:00Z")]);
    send(instance.addr, messages(haiku_prompt())).await;
    instance
        .upstream
        .script([reply_teaching_weekly("0.10", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "default");
    assert_eq!(instance.default_account(), instance.handle("FSUB"));
    assert!(instance.events("default_moved").is_empty());
}
/// `C1` default, `A0` becomes eligible → `C1` still serves and
/// stays the default; nothing preempts, no move line.
#[tokio::test(flavor = "multi_thread")]
async fn a_returning_higher_tier_never_preempts_the_default() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "returning-higher-tier-never-preempts",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    exhaust_fsub_until(&instance, 2).await;

    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "ranking");
    assert_eq!(instance.default_account(), instance.handle("FSUB2"));
    assert_eq!(instance.events("default_moved").len(), 1);

    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], true);
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "default");
    assert_eq!(instance.default_account(), instance.handle("FSUB2"));
    assert_eq!(instance.events("default_moved").len(), 1, "no move line");
}
/// Distribution off: two sessions both on the default although
/// `B0` is idle.
#[tokio::test(flavor = "multi_thread")]
async fn distribution_off_binds_every_session_to_the_default() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("distribution-off-binds").await;
    add_two(&instance);
    for id in ["foxtrot-1", "foxtrot-2"] {
        let answer = send(instance.addr, in_session(messages(haiku_prompt()), id)).await;
        assert_eq!(answer.status, StatusCode::OK);
    }
    for record in instance.audit_settled(2) {
        assert_eq!(record["serving_account"]["display_name"], "FSUB");
        assert_eq!(record["selection_cause"], "default");
    }
    let status = instance.status();
    assert_eq!(status["sessions"]["known"], 2);
    assert_eq!(status["sessions"]["active"], 2);
    assert_eq!(status["sessions"]["distribution_enabled"], false);
    assert_eq!(instance.account("FSUB")["sessions_active"], 2);
    assert_eq!(instance.account("FSUB2")["sessions_active"], 0);
}
/// Distribution on: session 1 → A, session 2 → B, session 3 → C;
/// session 1 stays on A for its lifetime; `A0` idle and `C1` loaded → a new
/// session still lands on A.
#[tokio::test(flavor = "multi_thread")]
async fn distribution_spreads_new_sessions_by_load_within_a_tier() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "distribution-spreads-new",
        Setup {
            selection: "distribute_sessions = true\n".into(),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    instance.add_oauth("FSUB3", "fsub3@fixture.invalid", FSUB3_UUID);
    for (i, (id, expected)) in [
        ("golf-1", "FSUB"),
        ("golf-2", "FSUB2"),
        ("golf-3", "FSUB3"),
        ("golf-1", "FSUB"),
    ]
    .into_iter()
    .enumerate()
    {
        let answer = send(instance.addr, in_session(messages(haiku_prompt()), id)).await;
        assert_eq!(answer.status, StatusCode::OK);
        let record = instance.last_record(i + 1);
        assert_eq!(record["serving_account"]["display_name"], expected, "{id}");
        assert_eq!(record["selection_cause"], "session");
    }
    assert_eq!(instance.status()["sessions"]["distribution_enabled"], true);
    for name in ["FSUB", "FSUB2", "FSUB3"] {
        assert_eq!(instance.account(name)["sessions_active"], 1, "{name}");
    }
    assert_eq!(instance.default_account(), instance.handle("FSUB"));

    // Priority still wins: a loaded C1 never draws a session from an idle A0.
    let instance = Instance::start_with_accounts(
        "distribution-spreads-new-sessions",
        Setup {
            selection: "distribute_sessions = true\n".to_string()
                + &priorities(&[("FSUB", 0), ("FSUB2", 1)]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    for id in ["golf-4", "golf-5"] {
        send(
            instance.addr,
            pinned(in_session(messages(haiku_prompt()), id), "FSUB2"),
        )
        .await;
    }
    assert_eq!(instance.account("FSUB2")["sessions_active"], 2);
    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "golf-6"),
    )
    .await;
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "session");
}
/// Bound session's account exhausted → its real 429 relayed with
/// one attempt, no other account tried, no move line. The
/// expiry half — after the session's 1 h window the next attempt binds anew
/// runs against the harness-moved clock: the anchor is the last
/// exchange that saw the session, forgotten at the deadline exactly, and the
/// fresh binding follows the default the operator moved in between.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_session_gets_its_accounts_real_429() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = Faults::new();
    let instance = Instance::start_with_faults(
        "bound-session-gets-accounts",
        Setup::default(),
        faults.clone(),
    )
    .await;
    add_two(&instance);
    send(instance.addr, in_session(messages(haiku_prompt()), "india")).await;

    instance.upstream.script([reply_exhausted_429(30)]);
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "india")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("30"));
    assert_eq!(answer.json()["error"]["type"], "rate_limit_error");
    assert_eq!(answer.header("request-id"), Some("req_fixture_0429"));
    assert_eq!(
        instance.upstream.calls(),
        calls + 1,
        "one attempt, nobody else"
    );
    let record = instance.last_record(2);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "session");
    assert_eq!(record["error_class"], "rate_limit");
    assert!(instance.events("default_moved").is_empty(), "no move line");

    // The expiry half. The operator moves the default first (no move
    // re-binds a live session); the bound attempt above still showed FSUB. The
    // anchor is the last exchange that saw the session; at the 1 h window the
    // session is forgotten, and the next attempt binds anew — to the new
    // default, and the fresh binding sticks.
    instance.cli_json(&["switch", "FSUB2", "--yes"], None);
    let anchor = Instant::now();
    faults.set_deadline(anchor, 3600);
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "india")).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(3);
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB2",
        "the expired session binds anew, to the default it now finds"
    );
    assert_eq!(record["selection_cause"], "default");
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "india")).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        instance.last_record(4)["serving_account"]["display_name"],
        "FSUB2",
        "the fresh binding sticks"
    );
}

/// A held account is never chosen while a healthy sibling is;
/// an errored account is dropped likewise; the disabled half arrives with
/// `account disable` (step 4).
#[tokio::test(flavor = "multi_thread")]
async fn disabled_errored_held_never_chosen() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "disabled-errored-held",
        Setup {
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    instance.add_fkey();

    // FSUB2 at 0.99 and FKEY at 0.98; then a real 429 holds the default FSUB.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    instance.upstream.script([reply_teaching_apikey(&[
        ("tokens-limit", "100"),
        ("tokens-remaining", "2"),
        ("requests-limit", "100"),
        ("requests-remaining", "50"),
    ])]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FKEY")).await;
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("90"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "FSUB held");

    // Every ordinary choice is barred (held or over threshold): the
    // revalidation candidate is FKEY, the lowest utilisation (0.98 under
    // FSUB2's 0.99); it serves once and binds nothing.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(4);
    assert_eq!(record["serving_account"]["display_name"], "FKEY");
    assert_eq!(record["selection_cause"], "revalidation");

    // The held pin is refused without an attempt.
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("5"));
    assert_eq!(instance.upstream.calls(), calls);

    // Errored: a 401 on the API key errors the account; it is never chosen.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    instance.upstream.script([reply_auth_401()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert!(answer.text().contains("FKEY"), "{}", answer.text());
    instance.settle();
    let fkey = instance.account("FKEY");
    assert_eq!(fkey["health"]["state"], "errored");
    assert_eq!(fkey["eligibility"]["eligible"], false);
    assert_eq!(fkey["eligibility"]["reason"], "errored");

    // With FKEY errored, the revalidation candidate is FSUB2.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(7);
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB2",
        "the errored account is out"
    );
    assert_eq!(record["selection_cause"], "revalidation");
}

/// The switch threshold on the shared windows bars every model;
/// A family weekly at threshold bars only that family; an unlearned family
/// bucket leaves the account eligible; an API key at `remaining/limit = 0.02`
/// is ineligible.
#[tokio::test(flavor = "multi_thread")]
async fn threshold_family_and_apikey_thresholds() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "threshold-family-apikey",
        Setup {
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);

    // 0.98 on the shared weekly: ineligible for every model.
    instance
        .upstream
        .script([reply_teaching_weekly("0.98", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "ranking");
    // The ranking moved the default: the sonnet attempt is served by
    // it without another ranking pass.
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "default");

    // The family weekly at threshold bars FSUB2 for the learned family's
    // models only (teaches the mapping here).
    instance
        .upstream
        .script([reply_teaching_family("0.98", "allowed")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;

    // Both accounts barred for haiku: the revalidation candidate is FSUB
    // (the older observation at the equal utilisation), and its headroom
    // restores it.
    instance
        .upstream
        .script([reply_teaching_weekly("0.10", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "the headroom reached FSUB");
    let record = instance.last_record(5);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "revalidation");

    // The family-barred account is skipped; the headroom account serves.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(6);
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB",
        "the unlearned account stays eligible; the family-barred one is skipped"
    );
    let fsub2 = instance.account("FSUB2");
    assert_eq!(
        fsub2["buckets"]
            .as_array()
            .expect("buckets")
            .iter()
            .find(|b| b["name"] == "weekly:fable")
            .expect("the family bucket")["utilisation"],
        0.98
    );

    // API key at 0.02 remaining: ineligible (the fraction).
    instance.add_fkey();
    instance.upstream.script([reply_teaching_apikey(&[
        ("tokens-limit", "100"),
        ("tokens-remaining", "2"),
        ("requests-limit", "100"),
        ("requests-remaining", "50"),
    ])]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FKEY")).await;
    assert_eq!(answer.status, StatusCode::OK);
    instance.settle();
    assert_eq!(
        instance.account("FKEY")["eligibility"]["reason"],
        "over_threshold"
    );
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FKEY")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls);
}

/// The revalidation candidate serves once per revalidation cadence,
/// never becomes the default, and the log line names it; between candidates
/// the caller gets nobody.
#[tokio::test(flavor = "multi_thread")]
async fn revalidation_once_per_cadence_never_the_default() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "revalidation-per-cadence",
        Setup {
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, messages(haiku_prompt())).await;
    let default = instance.default_account();
    assert_eq!(default, instance.handle("FSUB"));

    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(3);
    assert_eq!(record["selection_cause"], "revalidation");
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(instance.default_account(), default, "never the default");
    assert!(instance.events("default_moved").is_empty());
    assert_eq!(instance.events("revalidation_started").len(), 1);

    // Inside the interval: nobody.
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls);

    tokio::time::sleep(Duration::from_millis(2_300)).await;
    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(5);
    assert_eq!(record["selection_cause"], "revalidation");
    assert_eq!(instance.default_account(), default);
    assert!(instance.events("default_moved").is_empty());
    assert_eq!(instance.events("revalidation_started").len(), 2);
}

/// Every "nobody" reason appears in the audit record and the log;
/// `all_tried` is asserted in the second record.
#[tokio::test(flavor = "multi_thread")]
async fn every_selection_reason_lands_in_audit_and_log() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("selection-reason-lands").await;

    // no_account_configured.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let reason = |records: Vec<Value>, i: usize| {
        records[i]["no_service_reason"]
            .as_str()
            .expect("reason")
            .to_string()
    };
    assert_eq!(reason(instance.audit(), 0), "no_account_configured");

    instance.add_fsub();
    // The exclusive route names FSUB, which now exists.
    instance.reload_with_setup(&Setup {
        selection:
            "routes = [{ name = \"sonnet\", patterns = [\"*sonnet*\"], accounts = [\"FSUB\"] }]\n"
                .into(),
        ..Setup::default()
    });
    // Hold FSUB: the next unbound request is all_held_or_over_threshold.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("90"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    // pinned_unavailable.
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("5"));

    // route_exhausted: the route's only account is held.
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    let records = instance.audit_settled(5);
    assert_eq!(reason(records.clone(), 0), "no_account_configured");
    assert_eq!(records[1]["attempts"], 1, "the real 429");
    assert_eq!(reason(records.clone(), 2), "all_held_or_over_threshold");
    assert_eq!(reason(records.clone(), 3), "pinned_unavailable");
    assert_eq!(reason(records, 4), "route_exhausted");
    let logged: Vec<String> = instance
        .events("no_account")
        .iter()
        .filter_map(|e| e["fields"]["reason"].as_str().map(String::from))
        .collect();
    for expected in [
        "no_account_configured",
        "all_held_or_over_threshold",
        "pinned_unavailable",
        "route_exhausted",
    ] {
        assert!(
            logged.contains(&expected.to_string()),
            "{expected} missing from the log: {logged:?}"
        );
    }

    // all_disabled_or_errored: an errored-only pool (the OAuth half of the
    // reason needs the refresh work of step 3).
    let errored_only = Instance::start("selection-reason-lands-errored").await;
    errored_only.add_fkey();
    errored_only.upstream.script([reply_auth_401()]);
    let answer = send(errored_only.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    let answer = send(errored_only.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let record = errored_only.audit().pop().expect("a record");
    assert_eq!(record["no_service_reason"], "all_disabled_or_errored");
}

/// Under distribution a session whose account becomes held keeps
/// it: the next attempt ends with the synthetic 429 and no attempt; a request
/// without a session follows the ordinary rules and binds nothing.
#[tokio::test(flavor = "multi_thread")]
async fn held_assignment_keeps_the_session_and_binds_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "held-assignment-keeps-session",
        Setup {
            selection: "distribute_sessions = true\n".into(),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);

    // The session binds FSUB2 (a pin is a first-attempt answer).
    let answer = send(
        instance.addr,
        pinned(in_session(messages(haiku_prompt()), "hotel"), "FSUB2"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    send(instance.addr, in_session(messages(haiku_prompt()), "hotel")).await;

    // Hold FSUB2; the session keeps it and the next attempt is synthetic.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("5h-reset", &reset_in(30)),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("30"),
    )]);
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "hotel")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "real 429");
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "hotel")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = answer
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    assert!((26..=31).contains(&retry_after), "{retry_after}");
    assert!(answer.text().contains("FSUB2"), "{}", answer.text());
    assert_eq!(instance.upstream.calls(), calls, "no attempt");
    assert_eq!(instance.account("FSUB2")["sessions_active"], 1, "stays");

    // A sessionless request follows rules 5–6 and binds nothing.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(5);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "default");
    assert_eq!(instance.status()["sessions"]["known"], 1);
}

/// A bound session whose account is under an
/// exhaustion hold gets the synthetic 429 computed for that account, with no
/// attempt.
#[tokio::test(flavor = "multi_thread")]
async fn bound_and_held_gets_the_synthetic_429() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("bound-held-gets-synthetic").await;
    add_two(&instance);
    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "juliet"),
    )
    .await;

    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("5h-reset", &reset_in(90)),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("90"),
    )]);
    let answer = send(
        instance.addr,
        in_session(messages(haiku_prompt()), "juliet"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "the real 429");

    let calls = instance.upstream.calls();
    let answer = send(
        instance.addr,
        in_session(messages(haiku_prompt()), "juliet"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = answer
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    assert!((85..=91).contains(&retry_after), "{retry_after}");
    assert!(answer.text().contains("FSUB"), "{}", answer.text());
    assert_eq!(answer.json()["error"]["type"], "rate_limit_error");
    assert_eq!(instance.upstream.calls(), calls);
    let record = instance.last_record(3);
    assert_eq!(record["attempts"], 0);
    assert_eq!(record["selection_cause"], "session");
    assert_eq!(record["error_class"], "rate_limit");
    assert!(instance.events("default_moved").is_empty());
}

// ---- step 5: the operator's steer, the route view and the advisor

/// A haiku prompt whose advisor tool names opus.
fn haiku_with_opus_advisor() -> Value {
    json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 32,
        "tools": [{ "type": "advisor_20260301", "model": "claude-opus-5" }],
        "messages": [{ "role": "user", "content": "hi" }],
    })
}

/// Teaches opus to the fable family on `name` with its `weekly:fable` at
/// `utilization`, through a pinned attempt.
async fn teach_fable(instance: &Instance, name: &str, utilization: &str) {
    instance
        .upstream
        .script([reply_teaching_family(utilization, "allowed")]);
    let answer = send(
        instance.addr,
        pinned(messages(prompt_for("claude-opus-5")), name),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "teaching {name}");
}

/// `switch B`: default = B, answer eligible; `switch` to a
/// disabled, errored, held or over-threshold account → exit 0, the default
/// moved, `will_serve: false` naming the reason as a warning;
/// `switch --route r` to an account r's list lacks → refused.
#[tokio::test(flavor = "multi_thread")]
async fn switch_reports_will_serve_and_the_reason() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "switch-reports-will",
        Setup {
            // The exclusive route is on sonnet so the haiku probes below pin freely.
            selection: routes(&[("s", &["*sonnet*"], Some(&["FSUB"]), None)]),
            ..Setup::default()
        },
        |instance| {
            add_two(instance);
            instance.add_oauth("FSUB3", "fsub3@fixture.invalid", FSUB3_UUID);
        },
    )
    .await;

    let (code, stdout, stderr) = instance.cli(&["switch", "FSUB2"], None);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("FSUB2"), "{stdout}");
    assert!(
        stderr.is_empty(),
        "no warning for an eligible target: {stderr}"
    );
    let status = instance.status();
    assert_eq!(
        status["default_account"]["handle"],
        json!(instance.handle("FSUB2"))
    );
    assert_eq!(status["default_account"]["operator_chosen"], true);
    let since = status["default_account"]["since"].as_str().expect("since");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!(
        (now - crate_time(since)).abs() <= 5,
        "since is now: {since}"
    );
    let switched = instance.events("default_switched");
    assert_eq!(switched.len(), 1);
    assert_eq!(switched[0]["fields"]["will_serve"], true);

    // Disabled.
    assert_eq!(instance.cli(&["account", "disable", "FSUB2"], None).0, 0);
    let (code, _, stderr) = instance.cli(&["switch", "FSUB2"], None);
    assert_eq!(code, 0, "an ineligible target is not an error");
    assert!(
        stderr.contains("warning") && stderr.contains("disabled"),
        "{stderr}"
    );
    let envelope = instance.cli_json(&["switch", "FSUB2"], None);
    assert_eq!(envelope["result"]["will_serve"], false);
    assert_eq!(envelope["result"]["reason"], "disabled");
    assert_eq!(
        instance.default_account(),
        instance.handle("FSUB2"),
        "the default moved anyway"
    );
    assert_eq!(instance.cli(&["account", "enable", "FSUB2"], None).0, 0);

    // Errored (an API key's 401 errors it at once).
    instance.add_fkey();
    instance.error_via_401("FKEY").await;
    let envelope = instance.cli_json(&["switch", "FKEY"], None);
    assert_eq!(envelope["result"]["will_serve"], false);
    assert_eq!(envelope["result"]["reason"], "errored");

    // Held (an exhaustion 429 on FSUB's bucket).
    instance.upstream.script([reply_exhausted_429(120)]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    let envelope = instance.cli_json(&["switch", "FSUB"], None);
    assert_eq!(envelope["result"]["will_serve"], false);
    assert_eq!(envelope["result"]["reason"], "held");
    assert!(
        envelope["result"]["reason_detail"]
            .as_str()
            .is_some_and(|d| d.contains('T')),
        "the hold end: {envelope}"
    );

    // Over the threshold.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB3")).await;
    let envelope = instance.cli_json(&["switch", "FSUB3"], None);
    assert_eq!(envelope["result"]["will_serve"], false);
    assert_eq!(envelope["result"]["reason"], "over_threshold");
    assert_eq!(instance.default_account(), instance.handle("FSUB3"));
    assert_eq!(instance.events("default_switched").len(), 6);

    // The route's list lacks the account ( → 409, exit 8).
    let (code, _, stderr) = instance.cli(&["switch", "--route", "s", "FSUB2"], None);
    assert_eq!(code, 8, "{stderr}");
    assert!(stderr.contains("conflict"), "{stderr}");
    // No such route ( → 404, exit 6).
    let (code, _, stderr) = instance.cli(&["switch", "--route", "nosuch", "FSUB"], None);
    assert_eq!(code, 6, "{stderr}");
    assert!(stderr.contains("route_not_found"), "{stderr}");
    // A position is never a reference.
    let (code, _, stderr) = instance.cli(&["switch", "1"], None);
    assert_eq!(code, 6, "{stderr}");
    assert!(stderr.contains("positions are not references"), "{stderr}");
    // `--clear` without `--route` is a usage error.
    assert_eq!(instance.cli_usage(&["switch", "--clear"]).0, 2);
    assert_eq!(instance.route_view("s")["preference"], Value::Null);

    // The listing marks the default.
    let (code, stdout, _) = instance.cli(&["switch"], None);
    assert_eq!(code, 0);
    let marked: Vec<&str> = stdout.lines().filter(|l| l.starts_with("* ")).collect();
    assert_eq!(marked.len(), 1, "{stdout}");
    assert!(marked[0].contains("FSUB3"), "{stdout}");
}

/// `switch C1` with `A0` eligible → C1 serves until it becomes
/// ineligible, then A0; the operator's choice is then forgotten.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_chosen_default_stands_until_ineligible() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "operator-chosen-default",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    assert_eq!(instance.cli(&["switch", "FSUB2"], None).0, 0);

    for i in 1..=2 {
        send(instance.addr, messages(haiku_prompt())).await;
        let record = instance.last_record(i);
        assert_eq!(record["serving_account"]["display_name"], "FSUB2");
        assert_eq!(record["selection_cause"], "default");
    }
    assert!(instance.events("default_moved").is_empty());
    assert_eq!(
        instance.status()["default_account"]["operator_chosen"],
        true
    );

    assert_eq!(instance.cli(&["account", "disable", "FSUB2"], None).0, 0);
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "ranking");
    let moved = instance.events("default_moved");
    assert_eq!(moved.len(), 1);
    assert_eq!(
        moved[0]["fields"]["cause"], "disabled",
        "the cause: {}",
        moved[0]
    );
    let status = instance.status();
    assert_eq!(
        status["default_account"]["handle"],
        json!(instance.handle("FSUB"))
    );
    assert_eq!(status["default_account"]["operator_chosen"], false);

    // Ordinary rules from here: FSUB2 back does not take the default.
    assert_eq!(instance.cli(&["account", "enable", "FSUB2"], None).0, 0);
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(4);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "default");
    assert_eq!(instance.events("default_moved").len(), 1);
}

/// `switch B` while a session is bound to A → the session keeps
/// A; attempts without a session move to B; a new session binds to B.
#[tokio::test(flavor = "multi_thread")]
async fn a_switch_never_moves_a_bound_session() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("switch-never-moves").await;
    add_two(&instance);
    send(instance.addr, in_session(messages(haiku_prompt()), "kilo")).await;
    assert_eq!(
        instance.last_record(1)["serving_account"]["display_name"],
        "FSUB"
    );

    assert_eq!(instance.cli(&["switch", "FSUB2"], None).0, 0);
    send(instance.addr, in_session(messages(haiku_prompt()), "kilo")).await;
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "session");
    assert!(instance.events("default_moved").is_empty());

    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "default");

    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "kilo-new"),
    )
    .await;
    assert_eq!(
        instance.last_record(4)["serving_account"]["display_name"],
        "FSUB2"
    );
    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "kilo-new"),
    )
    .await;
    let record = instance.last_record(5);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "session");
}

/// Advisor model's family spent on the default → another account
/// serving both; no account serves both → request model only, fallback logged
/// once per minute.
#[tokio::test(flavor = "multi_thread")]
async fn advisor_two_pass_and_the_fallback_line() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("advisor-two-pass").await;
    add_two(&instance);
    // FSUB2 has the fable family spent, FSUB does not; FSUB2 is the default.
    teach_fable(&instance, "FSUB", "0.10").await;
    teach_fable(&instance, "FSUB2", "0.98").await;
    assert_eq!(instance.cli(&["switch", "FSUB2"], None).0, 0);

    send(instance.addr, messages(haiku_with_opus_advisor())).await;
    let record = instance.last_record(3);
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB",
        "serves both models"
    );
    assert_eq!(record["selection_cause"], "ranking");
    assert!(instance.events("advisor_fallback").is_empty());

    // Now nobody serves both: the request model alone, once logged.
    teach_fable(&instance, "FSUB", "0.98").await;
    send(instance.addr, messages(haiku_with_opus_advisor())).await;
    let record = instance.last_record(5);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    let lines = instance.events("advisor_fallback");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["fields"]["advisor_model"], "claude-opus-5");
    send(instance.addr, messages(haiku_with_opus_advisor())).await;
    assert_eq!(
        instance.last_record(6)["serving_account"]["display_name"],
        "FSUB"
    );
    assert_eq!(
        instance.events("advisor_fallback").len(),
        1,
        "once per minute"
    );
}

/// Preference eligible for the request model only, advisor
/// present → the second pass serves the preferred account.
#[tokio::test(flavor = "multi_thread")]
async fn a_preference_is_kept_in_the_second_pass() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("preference-kept-second").await;
    add_two(&instance);
    teach_fable(&instance, "FSUB", "0.98").await;
    teach_fable(&instance, "FSUB2", "0.98").await;

    send(
        instance.addr,
        preferred(messages(haiku_with_opus_advisor()), "FSUB2"),
    )
    .await;
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "preference");
    assert_eq!(instance.events("advisor_fallback").len(), 1);
}

/// A route preference on the request model's route wins over
/// the advisor model's route; the advisor's route is consulted only when the
/// request model's has none.
#[tokio::test(flavor = "multi_thread")]
async fn the_request_models_route_preference_wins() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "request-models-route",
        Setup {
            selection: routes(&[
                ("o", &["*opus*"], Some(&["FSUB", "FSUB2"]), None),
                ("h", &["*haiku*"], Some(&["FSUB", "FSUB2"]), None),
            ]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    assert_eq!(instance.cli(&["switch", "--route", "h", "FSUB"], None).0, 0);
    assert_eq!(
        instance.cli(&["switch", "--route", "o", "FSUB2"], None).0,
        0
    );

    send(instance.addr, messages(haiku_with_opus_advisor())).await;
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "route");

    assert_eq!(
        instance.cli(&["switch", "--route", "h", "--clear"], None).0,
        0
    );
    send(instance.addr, messages(haiku_with_opus_advisor())).await;
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "route");
    assert_eq!(instance.events("route_preference_cleared").len(), 1);
}

/// A route with a bucket override and no list restricts
/// nothing; eligibility for its models is judged on the named bucket.
#[tokio::test(flavor = "multi_thread")]
async fn a_bucket_override_governs_without_restricting() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "bucket-override-governs",
        Setup {
            selection: routes(&[("b", &["*haiku*"], None, Some("weekly:fable"))]),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    // FSUB's fable bucket is spent; its shared weekly is not.
    teach_fable(&instance, "FSUB", "0.99").await;

    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(2);
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB2",
        "haiku is judged on weekly:fable through the override"
    );
    let view = instance.route_view("b");
    assert_eq!(view["bucket"], "weekly:fable");
    let accounts = view["accounts"].as_array().expect("accounts");
    assert_eq!(accounts.len(), 2, "no list restricts nothing");
    let eligible = |name: &str| {
        accounts
            .iter()
            .find(|a| a["display_name"] == name)
            .expect("listed")["eligible"]
            .clone()
    };
    assert_eq!(eligible("FSUB"), false);
    assert_eq!(eligible("FSUB2"), true);
    // A model outside the route is judged on the shared weekly: FSUB serves it.
    send(
        instance.addr,
        pinned(messages(prompt_for("claude-sonnet-5")), "FSUB"),
    )
    .await;
    assert_eq!(
        instance.last_record(3)["serving_account"]["display_name"],
        "FSUB"
    );
}

/// The `status` route view: listed accounts with eligibility,
/// the preference, the predicted target, `null` when nobody.
#[tokio::test(flavor = "multi_thread")]
async fn the_route_view() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "route-view",
        Setup {
            selection: routes(&[
                ("h", &["*haiku*"], Some(&["FSUB", "FSUB2"]), None),
                ("open", &["*sonnet*"], None, None),
            ]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    let view = instance.route_view("h");
    assert_eq!(view["patterns"], json!(["*haiku*"]));
    assert_eq!(view["preference"], Value::Null);
    assert_eq!(view["predicted_target"], json!(instance.handle("FSUB")));
    let accounts = view["accounts"].as_array().expect("accounts");
    assert_eq!(accounts.len(), 2);
    assert!(accounts.iter().all(|a| a["eligible"] == true));
    assert_eq!(
        instance.route_view("open")["accounts"]
            .as_array()
            .expect("accounts")
            .len(),
        2
    );

    assert_eq!(
        instance.cli(&["switch", "--route", "h", "FSUB2"], None).0,
        0
    );
    let view = instance.route_view("h");
    assert_eq!(view["preference"], json!(instance.handle("FSUB2")));
    assert_eq!(view["predicted_target"], json!(instance.handle("FSUB2")));

    for name in ["FSUB", "FSUB2"] {
        instance
            .upstream
            .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
        send(instance.addr, pinned(messages(haiku_prompt()), name)).await;
    }
    let view = instance.route_view("h");
    assert!(
        view["accounts"]
            .as_array()
            .expect("accounts")
            .iter()
            .all(|a| a["eligible"] == false)
    );
    assert_eq!(view["predicted_target"], Value::Null);
}

/// Route prediction in `status` equals the account the next
/// request gets, for each route, before and after a forced move; the read
/// moves nothing.
#[tokio::test(flavor = "multi_thread")]
async fn prediction_equals_the_next_exchange() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "prediction-equals-next",
        Setup {
            selection: routes(&[
                ("h", &["*haiku*"], Some(&["FSUB", "FSUB2"]), None),
                ("s", &["*sonnet*"], None, None),
            ]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    let mut count = 0;
    for round in 0..2 {
        if round == 1 {
            let predicted = instance.route_view("h")["predicted_target"].clone();
            assert_eq!(predicted, json!(instance.handle("FSUB")));
            assert_eq!(instance.cli(&["account", "disable", "FSUB"], None).0, 0);
        }
        for (route, model) in [("h", "claude-haiku-4-5-20251001"), ("s", "claude-sonnet-5")] {
            let default_before = instance.default_account();
            let predicted = instance.route_view(route)["predicted_target"].clone();
            assert_eq!(
                instance.default_account(),
                default_before,
                "the read moves nothing"
            );
            let predicted_name = instance.status()["accounts"]
                .as_array()
                .expect("accounts")
                .iter()
                .find(|a| a["handle"] == predicted)
                .expect("the prediction names an account")["display_name"]
                .clone();
            send(instance.addr, messages(prompt_for(model))).await;
            count += 1;
            let record = instance.last_record(count);
            assert_eq!(
                record["serving_account"]["display_name"], predicted_name,
                "route {route}, round {round}"
            );
        }
    }
}

/// Distribution on, a route preference on r → sessions on r's
/// models all land on the preferred account; other models still spread.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_preference_skips_distribution() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "route-preference-skips",
        Setup {
            selection: "distribute_sessions = true\n".to_string()
                + &routes(&[("h", &["*haiku*"], None, None)]),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    assert_eq!(
        instance.cli(&["switch", "--route", "h", "FSUB2"], None).0,
        0
    );

    for (i, id) in ["bravo-a", "bravo-b", "bravo-c"].into_iter().enumerate() {
        send(instance.addr, in_session(messages(haiku_prompt()), id)).await;
        let record = instance.last_record(i + 1);
        assert_eq!(record["serving_account"]["display_name"], "FSUB2");
        assert_eq!(record["selection_cause"], "route");
    }
    // A model with no route spreads: the least-loaded account is FSUB.
    send(
        instance.addr,
        in_session(messages(prompt_for("claude-sonnet-5")), "bravo-d"),
    )
    .await;
    let record = instance.last_record(4);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "session");
}

/// `switch --route h FSUB2`: FSUB2 serves h's models while
/// eligible, then the ordinary rules with the preference still shown; refused
/// when the route's list lacks the account; `--clear` restores; `route rm h`
/// (a file edit and the reload) drops the route and its preference, and
/// the route added back carries none.
#[tokio::test(flavor = "multi_thread")]
async fn route_preference_lifecycle_and_the_reload_that_drops_it() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "route-preference-lifecycle-reload",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)])
                + &routes(&[
                    ("h", &["*haiku*"], Some(&["FSUB", "FSUB2"]), None),
                    ("s", &["*sonnet*"], Some(&["FSUB"]), None),
                ]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    let fsub2 = instance.handle("FSUB2");
    let bytes_before = fs::read(&instance.config).expect("configuration bytes");

    // The preference serves while eligible.
    let envelope = instance.cli_json(&["switch", "--route", "h", "FSUB2"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(envelope["result"]["will_serve"], true);
    for i in 1..=2 {
        send(instance.addr, messages(haiku_prompt())).await;
        let record = instance.last_record(i);
        assert_eq!(record["serving_account"]["display_name"], "FSUB2");
        assert_eq!(record["selection_cause"], "route");
    }
    assert_eq!(instance.route_view("h")["preference"], json!(fsub2));

    // Refused when the route's list lacks the account.
    let envelope = instance.cli_json(&["switch", "--route", "s", "FSUB2"], None);
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    assert_eq!(envelope["error"]["code"], "conflict");
    assert_eq!(instance.route_view("s")["preference"], Value::Null);

    // Ineligible: the ordinary rules, the preference still shown.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", &reset_in(3_600))]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(instance.account("FSUB2")["eligibility"]["eligible"], false);
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(4);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "default");
    assert_eq!(instance.route_view("h")["preference"], json!(fsub2));

    // `--clear` restores; setting it again on the ineligible account is
    // accepted (merely ineligible now).
    assert_eq!(
        instance.cli(&["switch", "--route", "h", "--clear"], None).0,
        0
    );
    assert_eq!(instance.route_view("h")["preference"], Value::Null);
    let envelope = instance.cli_json(&["switch", "--route", "h", "FSUB2"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(envelope["result"]["will_serve"], false);
    assert_eq!(instance.route_view("h")["preference"], json!(fsub2));

    // `route rm h`: the file edited, the reload applied, the route and its
    // preference gone; the process is the same.
    let pid = instance.pid();
    let envelope = instance.cli_json(&["route", "rm", "h"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(envelope["result"]["reload"]["applied"], true);
    assert_eq!(
        envelope["result"]["reload"]["changed_keys"],
        json!(["selection.routes"])
    );
    let routes_now = instance.status()["routes"].clone();
    assert!(
        routes_now
            .as_array()
            .expect("routes")
            .iter()
            .all(|r| r["name"] != "h"),
        "{routes_now}"
    );
    let dropped = instance.events("route_preference_dropped");
    assert_eq!(dropped.len(), 1, "{dropped:?}");
    assert_eq!(dropped[0]["fields"]["route"], "h");
    assert_eq!(instance.pid(), pid);
    let file = fs::read_to_string(&instance.config).expect("configuration");
    assert!(!file.contains("\"h\""), "the route left the file: {file}");

    // A preference exists only for a configured route.
    let envelope = instance.cli_json(&["switch", "--route", "h", "FSUB2"], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    assert_eq!(envelope["error"]["code"], "route_not_found");

    // The route added back — appended last — carries no preference.
    let envelope = instance.cli_json(
        &[
            "route",
            "add",
            "h",
            "--pattern",
            "*haiku*",
            "--account",
            "FSUB",
            "--account",
            "FSUB2",
        ],
        None,
    );
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    let names: Vec<String> = instance.status()["routes"]
        .as_array()
        .expect("routes")
        .iter()
        .map(|r| r["name"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(names, ["s", "h"]);
    let view = instance.route_view("h");
    assert_eq!(view["preference"], Value::Null);
    assert_eq!(view["patterns"], json!(["*haiku*"]));
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(5);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "default");

    // The file round-tripped through two edits: the same bytes but for the
    // route's place in the table.
    let file = fs::read_to_string(&instance.config).expect("configuration");
    assert_ne!(file.into_bytes(), bytes_before);
    let config_digest = instance.status()["configuration"]["digest"].clone();
    assert_eq!(config_digest, envelope["result"]["digest_after"]);
}

/// A route naming an unknown account: `route add` is refused at
/// before any write; the same route written by hand makes `config
/// reload` and `SIGHUP` reject the candidate naming the route and the
/// reference, the old table kept and the digests telling the two files
/// apart; a restart on that file refuses to start.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_account_in_a_route_is_refused_at_start_and_at_reload() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let good = Setup {
        selection: routes(&[("h", &["*haiku*"], Some(&["FSUB", "FSUB2"]), None)]),
        ..Setup::default()
    };
    let bad = Setup {
        selection: routes(&[
            ("h", &["*haiku*"], Some(&["FSUB", "FSUB2"]), None),
            ("g", &["*opus*"], Some(&["ghost"]), None),
        ]),
        ..Setup::default()
    };
    let mut instance =
        Instance::start_with_accounts("unknown-account-route", good.clone(), add_two).await;
    let digest_before = instance.status()["configuration"]["digest"].clone();
    let file_before = fs::read(&instance.config).expect("configuration bytes");

    // first: exit 6, nothing written.
    let envelope = instance.cli_json(
        &[
            "route",
            "add",
            "g",
            "--pattern",
            "*opus*",
            "--account",
            "ghost",
        ],
        None,
    );
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    assert_eq!(envelope["error"]["code"], "account_not_found");
    assert_eq!(
        fs::read(&instance.config).expect("configuration bytes"),
        file_before
    );

    // By hand, then `config reload`: rejected naming the route and the reference.
    instance.write_setup(&bad);
    let bad_bytes = fs::read(&instance.config).expect("configuration bytes");
    let bad_digest = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(&bad_bytes))
    };
    let envelope = instance.cli_json(&["config", "reload"], None);
    assert_eq!(envelope["exit_code"], 3, "{envelope}");
    assert_eq!(envelope["error"]["code"], "configuration_invalid");
    let details = envelope["error"]["details"].as_array().expect("details");
    assert_eq!(details.len(), 1, "{envelope}");
    assert_eq!(details[0]["target"], "selection.routes[1].accounts[0]");
    let message = details[0]["message"].as_str().expect("message");
    assert!(
        message.contains("route g") && message.contains("ghost"),
        "{message}"
    );

    // The old table stays, the digests tell the files apart.
    let status = instance.status();
    let names: Vec<&str> = status["routes"]
        .as_array()
        .expect("routes")
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert_eq!(names, ["h"]);
    assert_eq!(status["configuration"]["digest"], digest_before);
    let last = &status["configuration"]["last_reload"];
    assert_eq!(last["applied"], false);
    assert_eq!(last["digest"], json!(bad_digest));
    assert_eq!(last["rejected_restart_keys"], json!([]));
    assert_eq!(
        last["errors"][0]["target"],
        "selection.routes[1].accounts[0]"
    );
    assert_eq!(
        fs::read(&instance.config).expect("configuration bytes"),
        bad_bytes,
        "a reload never touches the file"
    );
    send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(instance.last_record(1)["selection_cause"], "default");

    // SIGHUP shares the path: a second rejected result, logged as
    // would return it.
    #[cfg(unix)]
    {
        let reload_count = instance.events("reload").len();
        instance.sighup();
        let deadline = Instant::now() + Duration::from_secs(5);
        while instance.events("reload").len() <= reload_count && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let reloads = instance.events("reload");
        assert_eq!(reloads.len(), reload_count + 1, "{reloads:?}");
        let reload = reloads.last().expect("SIGHUP reload");
        assert_eq!(reload["level"], "warn");
        let result = reload["fields"]["result"].as_str().expect("result");
        assert!(result.contains(&bad_digest), "{result}");
        assert!(result.contains("\"applied\":false"), "{result}");
        assert_eq!(instance.status()["configuration"]["digest"], digest_before);
    }

    // The same file at start: refused before the bind.
    instance.stop();
    let (code, stderr) = instance.spawn_expecting_failure();
    assert_eq!(code, 3, "{stderr}");
    assert!(
        stderr.contains("selection.routes[1].accounts[0]")
            && stderr.contains("route g")
            && stderr.contains("ghost"),
        "{stderr}"
    );

    // The corrected file starts, and a reload of it applies with no change.
    instance.write_setup(&good);
    instance.respawn();
    let envelope = instance.cli_json(&["config", "reload"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(envelope["result"]["applied"], true);
    assert_eq!(envelope["result"]["changed_keys"], json!([]));
    assert_eq!(envelope["result"]["digest"], digest_before);
}
// ------------------------------------------------------------------ storm control

/// the `[selection.ramp]` table: 1 + 1 per step, the step and window
/// long enough that the counts below are ordering, not timing.
fn ramp(enabled: bool, step_interval_ms: u64, window_seconds: u64) -> String {
    format!(
        "\n[selection.ramp]\nenabled = {enabled}\ninitial_concurrency = 1\n\
         concurrency_step = 1\nstep_interval_ms = {step_interval_ms}\n\
         window_seconds = {window_seconds}\n"
    )
}

/// One gate per held reply, so every waiter can be released whether or not it
/// has reached the gate yet (`Notify` stores one permit).
fn gates(n: usize) -> Vec<Arc<Notify>> {
    (0..n).map(|_| Arc::new(Notify::new())).collect()
}

fn release(gates: &[Arc<Notify>]) {
    for gate in gates {
        gate.notify_one();
    }
}

/// N ` prompts on their own connections, all in flight together.
fn burst(
    addr: SocketAddr,
    n: usize,
    request: impl Fn() -> Request<Full<Bytes>> + Send + Sync + 'static,
) -> Vec<tokio::task::JoinHandle<Answer>> {
    let request = Arc::new(request);
    (0..n)
        .map(|_| {
            let request = Arc::clone(&request);
            tokio::spawn(async move { send(addr, request()).await })
        })
        .collect()
}

async fn join_all(handles: Vec<tokio::task::JoinHandle<Answer>>) -> Vec<Answer> {
    let mut answers = Vec::with_capacity(handles.len());
    for handle in handles {
        answers.push(handle.await.expect("the prompt task"));
    }
    answers
}

/// attempts the fake has seen beyond `before`, polled until `expected`
/// of them or the deadline; the caller asserts the count.
async fn attempts_since(fake: &Fake, before: usize, expected: usize, within: Duration) -> usize {
    let deadline = Instant::now() + within;
    loop {
        let seen = fake.calls() - before;
        if seen >= expected || Instant::now() > deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const FSUB4_UUID: &str = "3c1f5a7e-0000-4000-8000-0000000000a4";

/// Default over threshold → the ranking: lowest priority, unknown
/// reset first, then soonest reset; the move line with its cause; a ramp
/// started on the new default.
#[tokio::test(flavor = "multi_thread")]
async fn the_ranking_moves_the_default_and_starts_a_ramp() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "ranking-moves-default",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 0), ("FSUB3", 0), ("FKEY", 1)])
                + &ramp(true, 250, 30),
            ..Setup::default()
        },
        |instance| {
            add_two(instance);
            instance.add_oauth("FSUB3", "fsub3@fixture.invalid", FSUB3_UUID);
            instance.add_oauth("FSUB4", "fsub4@fixture.invalid", FSUB4_UUID);
            instance.add_fkey();
        },
    )
    .await;
    // FSUB2 and FSUB3 learn their weekly resets, FSUB3's the sooner; FSUB4's
    // stays unknown; FKEY is the lower tier.
    instance
        .upstream
        .script([reply_teaching_weekly("0.10", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    instance
        .upstream
        .script([reply_teaching_weekly("0.10", "2098-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB3")).await;
    exhaust_fsub_until(&instance, 3_600).await;

    // Unknown reset first.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(4);
    assert_eq!(record["serving_account"]["display_name"], "FSUB4");
    assert_eq!(record["selection_cause"], "ranking");
    assert_eq!(instance.default_account(), instance.handle("FSUB4"));
    let moved = instance.events("default_moved");
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0]["fields"]["cause"], "over_threshold");
    assert_eq!(moved[0]["fields"]["from"], instance.handle("FSUB"));
    assert_eq!(moved[0]["fields"]["to"], instance.handle("FSUB4"));
    let ramps = instance.events("ramp_started");
    assert_eq!(ramps.len(), 1, "{ramps:?}");
    assert_eq!(ramps[0]["fields"]["acct"], "FSUB4");
    assert_eq!(ramps[0]["fields"]["cause"], "default_moved");
    let view = instance.account("FSUB4")["ramp"].clone();
    assert_eq!(view["active"], true, "{view}");
    assert!(view["started_at"].is_string(), "{view}");
    assert!(view["limit"].as_u64().is_some_and(|l| l >= 1), "{view}");
    assert_eq!(instance.account("FSUB")["ramp"]["active"], false);

    // Then the soonest known reset: FSUB3 (2098) over FSUB2 (2099); FKEY's
    // tier never competes while a priority-0 account is eligible.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, messages(haiku_prompt())).await;
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(6);
    assert_eq!(record["serving_account"]["display_name"], "FSUB3");
    assert_eq!(record["selection_cause"], "ranking");
    assert_eq!(instance.default_account(), instance.handle("FSUB3"));
    assert_eq!(instance.events("default_moved").len(), 2);
    let ramps = instance.events("ramp_started");
    assert_eq!(ramps.len(), 2, "{ramps:?}");
    assert_eq!(ramps[1]["fields"]["acct"], "FSUB3");
    assert_eq!(instance.account("FSUB3")["ramp"]["active"], true);
    assert!(
        instance
            .audit()
            .iter()
            .all(|r| r["serving_account"]["display_name"] != "FKEY"),
        "the lower tier never served"
    );
}

/// After a forced move, 20 concurrent requests: attempts on the
/// new account start ≤ 1 at t=0, ≤ 2 after one step …; none waits past the
/// window; slots free at response headers, not at stream end; ramp disabled →
/// all at once. Counts at the fake under a 6 s step and a
/// 10 s window.
#[tokio::test(flavor = "multi_thread")]
async fn a_forced_move_ramps_attempts_on_the_new_default() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "forced-move-ramps",
        Setup {
            selection: ramp(true, 6_000, 10),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    exhaust_fsub_until(&instance, 3_600).await;

    // The first attempt's headers arrive at once and its body waits; the
    // other nineteen replies wait whole.
    let body_gate = Arc::new(Notify::new());
    let held = gates(19);
    let before = instance.upstream.calls();
    instance.upstream.script(
        std::iter::once(Reply::HoldBody(Arc::clone(&body_gate)))
            .chain(held.iter().map(|g| Reply::Hold(Arc::clone(g)))),
    );
    let started = Instant::now();
    let prompts = burst(instance.addr, 20, || messages(haiku_prompt()));

    // Cap 1: the first attempt's headers free its slot while its body is
    // still open, so exactly one more is admitted — and no third.
    assert_eq!(
        attempts_since(&instance.upstream, before, 2, Duration::from_secs(3)).await,
        2
    );
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        instance.upstream.calls() - before,
        2,
        "cap 1 until the first step"
    );
    let view = instance.account("FSUB2")["ramp"].clone();
    assert_eq!(view["active"], true, "{view}");
    assert_eq!(view["limit"], 1, "{view}");

    // The step lifts the cap to 2: one more attempt, no more.
    assert_eq!(
        attempts_since(&instance.upstream, before, 3, Duration::from_secs(8)).await,
        3
    );
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "not before the step"
    );
    assert_eq!(instance.upstream.calls() - before, 3);

    // The window lifts the ramp: every remaining attempt is admitted.
    assert_eq!(
        attempts_since(&instance.upstream, before, 20, Duration::from_secs(12)).await,
        20
    );
    assert!(
        started.elapsed() <= Duration::from_secs(13),
        "everyone admitted by the window's end plus the slack"
    );
    assert_eq!(instance.account("FSUB2")["ramp"]["active"], false);

    body_gate.notify_one();
    release(&held);
    let answers = join_all(prompts).await;
    assert!(answers.iter().all(|a| a.status == StatusCode::OK));
    let records = instance.audit_settled(21);
    assert!(
        records[1..]
            .iter()
            .all(|r| r["serving_account"]["display_name"] == "FSUB2"),
        "all twenty on the new default"
    );
    assert_eq!(instance.events("default_moved").len(), 1);
    assert_eq!(instance.events("ramp_started").len(), 1);
    drop(instance);

    // Ramp disabled: the same move admits all twenty together.
    let instance = Instance::start_with(
        "forced-move-ramps-attempts",
        Setup {
            selection: ramp(false, 6_000, 10),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    exhaust_fsub_until(&instance, 3_600).await;
    let held = gates(20);
    let before = instance.upstream.calls();
    instance
        .upstream
        .script(held.iter().map(|g| Reply::Hold(Arc::clone(g))));
    let prompts = burst(instance.addr, 20, || messages(haiku_prompt()));
    assert_eq!(
        attempts_since(&instance.upstream, before, 20, Duration::from_secs(3)).await,
        20,
        "all at once"
    );
    assert_eq!(instance.account("FSUB2")["ramp"]["active"], false);
    release(&held);
    let answers = join_all(prompts).await;
    assert!(answers.iter().all(|a| a.status == StatusCode::OK));
    assert_eq!(instance.events("default_moved").len(), 1);
    assert!(instance.events("ramp_started").is_empty());
}

/// A client that disconnects while waiting for a ramp slot ends
/// with no attempt, and the slot it waited for is not consumed.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_leaving_the_ramp_queue_makes_no_attempt() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "client-leaving-ramp",
        Setup {
            selection: ramp(true, 30_000, 30),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    exhaust_fsub_until(&instance, 3_600).await;

    // One attempt holds the only slot.
    let gate = Arc::new(Notify::new());
    let before = instance.upstream.calls();
    instance.upstream.script([Reply::Hold(Arc::clone(&gate))]);
    let addr = instance.addr;
    let first = tokio::spawn(async move { send(addr, messages(haiku_prompt())).await });
    assert_eq!(
        attempts_since(&instance.upstream, before, 1, Duration::from_secs(3)).await,
        1
    );

    // The second connects, delivers its request, waits, and leaves.
    let body = haiku_prompt().to_string();
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\n\
         anthropic-version: 2023-06-01\r\ncontent-length: {}\r\n\r\n",
        instance.addr,
        body.len()
    );
    let mut stream = StdTcpStream::connect(instance.addr).expect("connect");
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .and_then(|_| stream.flush())
        .expect("send the request");
    std::thread::sleep(Duration::from_millis(500));
    drop(stream);

    let records = instance.audit_settled(2);
    assert_eq!(
        instance.upstream.calls() - before,
        1,
        "no attempt for the leaver"
    );
    assert_eq!(records[1]["status"], Value::Null);
    assert_eq!(records[1]["attempts"], 0);
    assert_eq!(records[1]["serving_account"]["display_name"], "FSUB2");

    // The slot the leaver waited for goes to the next caller once the first
    // attempt's headers arrive.
    gate.notify_one();
    let answer = first.await.expect("the first prompt");
    assert_eq!(answer.status, StatusCode::OK);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.upstream.calls() - before, 2);
    assert_eq!(instance.last_record(4)["attempts"], 1);
}

/// Throttle 429 `retry-after: 3` → the account is paused 3 s: new
/// requests on it wait, none rotates, the default is unchanged; a second
/// throttle during the pause extends it; the pause's end releases the waiters
/// staggered under a fresh ramp. Counts at the fake under a 5 s
/// step.
#[tokio::test(flavor = "multi_thread")]
async fn a_throttle_pauses_the_account_and_its_end_releases_staggered() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "throttle-pauses-account",
        Setup {
            data_plane: "throttle_absorb_seconds = 1\n".into(),
            // One waiter may go as the revalidation request after 2 s; the
            // gate then stays shut for the rest of the scenario. 2 s (not 1)
            // leaves the "paused attempts wait" read 1.5 s of slack under a
            // loaded suite.
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 60\n".into(),
            selection: ramp(true, 5_000, 30),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);

    instance.upstream.script([reply_throttle_429(Some(5))]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let paused_at = Instant::now();
    let account = instance.account("FSUB");
    let first_end = crate_time(
        account["quota_holds"]["throttle_hold_end"]
            .as_str()
            .expect("the pause end"),
    );
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!(
        (first_end - now - 5).abs() <= 2,
        "paused ≈ 5 s: {first_end}"
    );
    assert_eq!(
        account["eligibility"]["eligible"], true,
        "paused, not ineligible"
    );
    assert_eq!(instance.default_account(), instance.handle("FSUB"));
    assert_eq!(instance.events("account_paused").len(), 1);

    // Four callers during the pause: none reaches the fake, until the floor
    // releases one as the revalidation request — which is throttled again
    // and extends the pause. The three others keep waiting.
    let held = gates(3);
    let before = instance.upstream.calls();
    instance.upstream.script(
        std::iter::once(reply_throttle_429(Some(5)))
            .chain(held.iter().map(|g| Reply::Hold(Arc::clone(g)))),
    );
    let prompts = burst(instance.addr, 4, || messages(haiku_prompt()));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        instance.upstream.calls() - before,
        0,
        "paused attempts wait"
    );
    assert_eq!(
        attempts_since(&instance.upstream, before, 1, Duration::from_secs(3)).await,
        1,
        "one revalidation release"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second_end = crate_time(
        instance.account("FSUB")["quota_holds"]["throttle_hold_end"]
            .as_str()
            .expect("still paused"),
    );
    assert!(
        second_end > first_end,
        "the second throttle extended the pause"
    );
    assert_eq!(instance.events("account_paused").len(), 2);
    assert_eq!(instance.upstream.calls() - before, 1, "the rest still wait");

    // The pause ends → a fresh ramp: one waiter at the end, one more per step.
    assert_eq!(
        attempts_since(&instance.upstream, before, 2, Duration::from_secs(8)).await,
        2
    );
    // The revalidation at ≈2 s was throttled for 5 s more: the pause ends
    // at ≈7 s (the hold end is whole seconds, so allow one).
    assert!(
        paused_at.elapsed() >= Duration::from_secs(6),
        "not before the extended pause end"
    );
    let ramps = instance.events("ramp_started");
    assert_eq!(ramps.len(), 1, "{ramps:?}");
    assert_eq!(ramps[0]["fields"]["cause"], "pause_end");
    assert_eq!(instance.account("FSUB")["ramp"]["active"], true);
    // The pause's end is logged beside its start, naming the account.
    let ended = instance.events("account_pause_ended");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["fields"]["acct"], "FSUB");
    assert_eq!(ended[0]["fields"]["cause"], "hold_elapsed");
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        instance.upstream.calls() - before,
        2,
        "cap 1 until the step"
    );
    assert_eq!(
        attempts_since(&instance.upstream, before, 3, Duration::from_secs(8)).await,
        3
    );
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        instance.upstream.calls() - before,
        3,
        "cap 2 until the next step"
    );
    assert_eq!(
        attempts_since(&instance.upstream, before, 4, Duration::from_secs(8)).await,
        4
    );

    release(&held);
    let statuses: Vec<u16> = join_all(prompts)
        .await
        .iter()
        .map(|a| a.status.as_u16())
        .collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        3,
        "{statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|s| **s == 429).count(),
        1,
        "{statuses:?}"
    );
    // Nobody rotated: every record names FSUB, the default never moved.
    let records = instance.audit_settled(5);
    assert!(
        records
            .iter()
            .all(|r| r["serving_account"]["display_name"] == "FSUB"),
        "{records:?}"
    );
    assert!(instance.events("default_moved").is_empty());
    assert_eq!(instance.default_account(), instance.handle("FSUB"));
    assert!(
        instance.account("FSUB")["quota_holds"]["throttle_hold_end"].is_null(),
        "the pause is over"
    );
}

/// An account added at runtime serves at once: no ramp, no pause,
/// even beside a sibling mid-ramp.
#[tokio::test(flavor = "multi_thread")]
async fn a_runtime_add_serves_at_once_without_a_ramp() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "runtime-add-serves",
        Setup {
            selection: ramp(true, 30_000, 30),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    exhaust_fsub_until(&instance, 3_600).await;
    send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(instance.default_account(), instance.handle("FSUB2"));
    assert_eq!(
        instance.account("FSUB2")["ramp"]["active"],
        true,
        "FSUB2 mid-ramp"
    );

    instance.add_oauth("FSUB3", "fsub3@fixture.invalid", FSUB3_UUID);
    let added = instance.account("FSUB3");
    assert_eq!(
        added["ramp"],
        json!({ "active": false, "started_at": null, "limit": null })
    );
    assert_eq!(added["quota_holds"]["throttle_hold_end"], Value::Null);

    // Four attempts on the new account start together; the sibling mid-ramp
    // still admits one at a time.
    let on_new = gates(4);
    let on_ramped = gates(2);
    let before = instance.upstream.calls();
    instance
        .upstream
        .script(on_new.iter().map(|g| Reply::Hold(Arc::clone(g))));
    let pinned_prompts = burst(instance.addr, 4, || {
        pinned(messages(haiku_prompt()), "FSUB3")
    });
    assert_eq!(
        attempts_since(&instance.upstream, before, 4, Duration::from_secs(3)).await,
        4,
        "all four at once"
    );
    instance
        .upstream
        .script(on_ramped.iter().map(|g| Reply::Hold(Arc::clone(g))));
    let ramped_prompts = burst(instance.addr, 2, || messages(haiku_prompt()));
    assert_eq!(
        attempts_since(&instance.upstream, before, 5, Duration::from_secs(3)).await,
        5
    );
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert_eq!(
        instance.upstream.calls() - before,
        5,
        "the sibling's cap is 1"
    );

    release(&on_new);
    release(&on_ramped);
    let answers = join_all(pinned_prompts).await;
    assert!(answers.iter().all(|a| a.status == StatusCode::OK));
    let answers = join_all(ramped_prompts).await;
    assert!(answers.iter().all(|a| a.status == StatusCode::OK));
    let records = instance.audit_settled(8);
    assert_eq!(
        records
            .iter()
            .filter(|r| r["serving_account"]["display_name"] == "FSUB3")
            .count(),
        4
    );
    assert_eq!(instance.account("FSUB3")["ramp"]["active"], false);
}

// ------------------------------------------------------------------ step 10: the rows no step named

/// `FSUB`, `FSUB2`, `FSUB3` at one tier, `FSUB` the initial default.
fn add_three(instance: &Instance) {
    add_two(instance);
    instance.add_oauth("FSUB3", "fsub3@fixture.invalid", FSUB3_UUID);
}

/// An account outside an exclusive route never serves a matching
/// model, even with capacity and even when the route's accounts are gone;
/// within one exchange an account already tried is never chosen again.
#[tokio::test(flavor = "multi_thread")]
async fn route_boundary_and_the_exclusion_set() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "route-boundary-exclusion",
        Setup {
            selection: routes(&[("sonnet", &["*sonnet*"], Some(&["FSUB2", "FSUB3"]), None)]),
            ..Setup::default()
        },
        add_three,
    )
    .await;
    assert_eq!(instance.default_account(), instance.handle("FSUB"));

    // The default is not listed: the route's models bypass it and
    // the ranking among the listed accounts serves — moving nothing.
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(1);
    assert_ne!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "ranking");
    assert_eq!(instance.default_account(), instance.handle("FSUB"));

    // FSUB2 and FSUB3 each fail once; neither is tried again and
    // FSUB, idle and eligible, is never a candidate for the route's model.
    instance
        .upstream
        .script([reply_unparseable(), reply_unparseable()]);
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        instance.upstream.calls(),
        calls + 2,
        "each listed account once"
    );
    let record = instance.last_record(2);
    assert_eq!(record["attempts"], 2);
    assert_eq!(record["no_service_reason"], "all_tried");
    for seen in instance.upstream.seen().iter().skip(calls) {
        assert_ne!(
            seen.header("authorization"),
            Some(format!("Bearer {}", instance.needles.access_token).as_str()),
            "FSUB's credential never left for the route's model"
        );
    }

    // Both listed accounts held: nobody, although FSUB has capacity.
    for name in ["FSUB2", "FSUB3"] {
        instance.upstream.script([reply_exhausted_429(90)]);
        let answer = send(instance.addr, pinned(messages(haiku_prompt()), name)).await;
        assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls, "no attempt on FSUB");
    assert_eq!(
        instance.last_record(5)["no_service_reason"],
        "route_exhausted"
    );
    // A model the route does not match is FSUB's as before.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        instance.last_record(6)["serving_account"]["display_name"],
        "FSUB"
    );
}

/// The model-less projection: a family-only exhaustion leaves
/// the account eligible (no family bucket takes part), a shared hold makes
/// it ineligible with the reason and the hold end.
#[tokio::test(flavor = "multi_thread")]
async fn model_less_eligibility_ignores_family_facts_but_not_shared_holds() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("model-less-eligibility").await;
    instance.add_fsub();

    instance
        .upstream
        .script([reply_teaching_family("0.12", "allowed")]);
    let answer = send(instance.addr, messages(prompt_for("claude-fable-5-1"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "0.10"),
            ("7d-status", "allowed"),
            ("7d_oi-utilization", "1.0"),
            ("7d_oi-status", "rejected"),
        ],
        Some("90"),
    )]);
    let answer = send(instance.addr, messages(prompt_for("claude-fable-5-1"))).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    let fsub = instance.account("FSUB");
    let family = fsub["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly:fable")
        .expect("the family bucket")
        .clone();
    assert_eq!(family["state"], "exhausted");
    assert_eq!(
        fsub["eligibility"],
        json!({ "eligible": true, "reason": null, "reason_detail": null }),
        "a family-only hold is not the whole account"
    );
    // The fable model itself is refused, so the projection is not merely
    // repeating the family's answer.
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(prompt_for("claude-fable-5-1"))).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls);

    // A shared-window hold bars every model: ineligible, with the end.
    instance.upstream.script([reply_exhausted_429(90)]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let fsub = instance.account("FSUB");
    let weekly = fsub["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["state"], "exhausted");
    assert_eq!(fsub["eligibility"]["eligible"], false);
    assert_eq!(fsub["eligibility"]["reason"], "held");
    assert_eq!(
        fsub["eligibility"]["reason_detail"], weekly["hold_end"],
        "the detail is the hold end"
    );
}

/// At startup the ranking over the restored quota picks the
/// default and a log line names it; when nothing is eligible the first
/// configured account is the default.
#[tokio::test(flavor = "multi_thread")]
async fn the_startup_default_is_the_ranking_winner_else_the_first() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("startup-default-ranking").await;
    add_two(&instance);
    let chosen = instance.events("default_chosen");
    assert!(chosen.is_empty(), "an empty pool at start picks nobody");

    // FSUB over the threshold, learned on a pinned attempt: still the
    // default until something ranks.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.default_account(), instance.handle("FSUB"));
    instance.settle();

    instance.restart();
    let default = instance.status()["default_account"].clone();
    assert_eq!(default["handle"], json!(instance.handle("FSUB2")));
    assert_eq!(default["operator_chosen"], false);
    let line = instance.events("default_chosen").pop().expect("the line");
    assert_eq!(line["fields"]["acct"], "FSUB2");
    assert_eq!(line["fields"]["cause"], "ranking");

    // Nothing eligible: the first configured account.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::OK);
    instance.settle();
    instance.restart();
    assert_eq!(instance.default_account(), instance.handle("FSUB"));
    let line = instance.events("default_chosen").pop().expect("the line");
    assert_eq!(line["fields"]["acct"], "FSUB");
    assert_eq!(line["fields"]["cause"], "first_configured");
}

/// `*Opus*` matches `claude-opus-5` and `CLAUDE-OPUS-4`; the
/// bare pattern `opus` matches neither (the whole id, not a substring);
/// `.` and `?` are literal.
#[tokio::test(flavor = "multi_thread")]
async fn patterns_match_the_whole_id_case_insensitively_with_star_only() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "patterns-match-whole",
        Setup {
            selection: routes(&[
                // First in order: a bare `opus` would claim the opus models
                // if it were a substring match.
                ("bare", &["opus"], Some(&["FSUB3"]), None),
                ("opus", &["*Opus*"], Some(&["FSUB2"]), None),
                ("literal", &["claude.sonnet?5"], Some(&["FSUB3"]), None),
            ]),
            ..Setup::default()
        },
        add_three,
    )
    .await;
    let served_by = |n: usize| instance.last_record(n)["serving_account"]["display_name"].clone();

    let answer = send(instance.addr, messages(prompt_for("claude-opus-5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(served_by(1), "FSUB2", "`*Opus*`, not the bare `opus`");
    let answer = send(instance.addr, messages(prompt_for("CLAUDE-OPUS-4"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(served_by(2), "FSUB2", "case-insensitive");
    // The bare pattern matches exactly its own id.
    let answer = send(instance.addr, messages(prompt_for("opus"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(served_by(3), "FSUB3");
    // `.` and `?` match themselves only.
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(served_by(4), "FSUB", "`.` and `?` are not wildcards");
    assert_eq!(instance.last_record(4)["selection_cause"], "default");
    let answer = send(instance.addr, messages(prompt_for("claude.sonnet?5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        served_by(5),
        "FSUB3",
        "the literal characters match themselves"
    );
}

/// Two routes matching one model: the first in configuration
/// order is the route.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_matching_route_wins() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "first-matching-route",
        Setup {
            selection: routes(&[
                ("narrow", &["*haiku*"], Some(&["FSUB2"]), None),
                ("wide", &["claude-*"], Some(&["FSUB3"]), None),
            ]),
            ..Setup::default()
        },
        add_three,
    )
    .await;

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(
        record["selection_cause"], "ranking",
        "the route's own ranking"
    );
    // The later route still governs what the first does not match.
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        instance.last_record(2)["serving_account"]["display_name"],
        "FSUB3"
    );
    // The route view predicts the same.
    assert_eq!(
        instance.route_view("narrow")["predicted_target"],
        json!(instance.handle("FSUB2"))
    );
}

/// An exclusive route whose listed accounts are both over the
/// threshold answers nobody with reason route exhausted while a third,
/// unlisted account sits idle.
#[tokio::test(flavor = "multi_thread")]
async fn an_exhausted_exclusive_route_yields_nobody_despite_idle_capacity() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "exhausted-exclusive-route",
        Setup {
            selection: routes(&[("sonnet", &["*sonnet*"], Some(&["FSUB", "FSUB2"]), None)]),
            ..Setup::default()
        },
        add_three,
    )
    .await;

    for name in ["FSUB", "FSUB2"] {
        instance
            .upstream
            .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
        let answer = send(instance.addr, pinned(messages(haiku_prompt()), name)).await;
        assert_eq!(answer.status, StatusCode::OK);
    }
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls, "FSUB3 is not a candidate");
    let record = instance.last_record(3);
    assert_eq!(record["no_service_reason"], "route_exhausted");
    assert_eq!(record["serving_account"], Value::Null);
    let logged = instance.events("no_account");
    assert_eq!(
        logged.last().expect("the line")["fields"]["reason"],
        "route_exhausted"
    );
    assert_eq!(
        instance.route_view("sonnet")["predicted_target"],
        Value::Null
    );

    // FSUB3's capacity serves everything the route does not claim.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        instance.last_record(4)["serving_account"]["display_name"],
        "FSUB3"
    );
}

/// A blocked pattern matching the advisor model alone ends the
/// exchange with 400 and no attempt; an empty list blocks nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_advisor_model_refuses_and_an_empty_list_blocks_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "blocked-advisor-model",
        Setup {
            blocked_models: vec!["*opus*".into()],
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let advised = || {
        messages(json!({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 32,
            "tools": [{ "type": "advisor_20260301", "model": "claude-opus-5" }],
            "messages": [{ "role": "user", "content": "hi" }],
        }))
    };

    let calls = instance.upstream.calls();
    let answer = send(instance.addr, advised()).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.json()["error"]["type"], "invalid_request_error");
    assert_eq!(instance.upstream.calls(), calls, "no attempt");
    let record = instance.last_record(1);
    assert_eq!(record["blocked_pattern"], "*opus*");
    assert_eq!(record["attempts"], 0);
    assert_eq!(record["serving_account"], Value::Null);
    assert_eq!(record["status"], 400);

    // The request model alone is fine.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);

    // An empty list blocks nothing: the same request is served.
    instance.reload_with_setup(&Setup::default());
    let answer = send(instance.addr, advised()).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(3);
    assert_eq!(record["blocked_pattern"], Value::Null);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
}

/// A session's binding is set at its first
/// attempt and never moved, not even by the ranking's move of the default,
/// and the account that last served it follows the binding.
/// The binding and last-served halves run against real time; the 2 min / 1 h
/// windows run under the harness-moved clock, the deadlines asserted
/// exactly: no effect one tick before them, the effect at them. The
/// release binary is started unchanged and reads the platform clock as it
/// always does; the scenario tags and its report record are
/// the runner's own.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_binding_is_set_once_and_the_last_served_follows_it() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    session_binding_body("binding-set-last").await;
}

/// The suite's own test of itself: the same body as the session-binding
/// test, run with the behaviour it asserts removed (the requests carry no
/// session id, so nothing can bind), must fail.
#[tokio::test(flavor = "multi_thread")]
async fn negative_control_catches_a_sabotaged_session_binding() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    negative_control(sabotaged_session_binding_body()).await;
}

/// The sabotage: the same body's opening, but the request carries no session
/// id — the behaviour the scenario asserts (a bound session, its cause, its
/// counts) cannot happen. The body must fail on the first session assertion.
async fn sabotaged_session_binding_body() {
    let instance = Instance::start("other-failures-skip-control").await;
    add_two(&instance);

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(
        record["selection_cause"], "default",
        "the first attempt binds to the default"
    );
    assert_eq!(instance.account("FSUB")["sessions_active"], 1);
}

/// The body that the binding test and its negative control both run.
async fn session_binding_body(root: &'static str) {
    let faults = Faults::new();
    let instance = Instance::start_with_faults(root, Setup::default(), faults.clone()).await;
    add_two(&instance);

    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "delta")).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(
        record["selection_cause"], "default",
        "the first attempt binds to the default"
    );
    assert_eq!(instance.account("FSUB")["sessions_active"], 1);
    assert_eq!(instance.account("FSUB2")["sessions_active"], 0);

    // FSUB over the threshold; an unbound attempt moves the default.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.default_account(), instance.handle("FSUB2"));
    assert_eq!(instance.events("default_moved").len(), 1);

    // The bound session stays with FSUB (the threshold bars no bound
    // attempt), served by it, its record naming the session as the cause.
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "delta")).await;
    // The anchor is this exchange, the last to see the session: taken before
    // the reads below, so their time under a loaded suite does not move it.
    let anchor = Instant::now();
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(4);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "session");
    assert_eq!(record["session_id"], "delta");
    let served: Vec<Value> = instance
        .audit()
        .into_iter()
        .filter(|r| r["session_id"] == "delta")
        .map(|r| r["serving_account"]["display_name"].clone())
        .collect();
    assert_eq!(
        served,
        vec![json!("FSUB"), json!("FSUB")],
        "last-served follows the binding"
    );
    assert_eq!(instance.account("FSUB")["sessions_active"], 1);
    assert_eq!(instance.account("FSUB2")["sessions_active"], 0);

    // The 2 min / 1 h windows, under the harness-moved clock: the anchor is
    // the exchange that last saw the session. The product saw it at
    // or before the anchor, so it is active two ticks (2 s) before the 2 min
    // window, inactive at it; known at the 1 h window, forgotten.
    faults.set_deadline(anchor, 118);
    assert_eq!(
        instance.status()["sessions"],
        json!({ "known": 1, "active": 1, "distribution_enabled": false }),
        "active two ticks before the 2 min window"
    );
    faults.set_deadline(anchor, 120);
    assert_eq!(
        instance.status()["sessions"],
        json!({ "known": 1, "active": 0, "distribution_enabled": false }),
        "inactive at the 2 min deadline, still known"
    );
    faults.set_deadline(anchor, 3600);
    assert_eq!(
        instance.status()["sessions"],
        json!({ "known": 0, "active": 0, "distribution_enabled": false }),
        "forgotten at the 1 h deadline"
    );
}

/// `status` counts known and active sessions, the active count per
/// account, and the distribution flag.
#[tokio::test(flavor = "multi_thread")]
async fn status_counts_sessions_per_account_and_the_distribution_flag() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "status-counts-sessions",
        Setup {
            selection: "distribute_sessions = true\n".into(),
            ..Setup::default()
        },
    )
    .await;
    add_two(&instance);
    let status = instance.status();
    assert_eq!(
        status["sessions"],
        json!({ "known": 0, "active": 0, "distribution_enabled": true })
    );

    // Three sessions spread A, B, A; a request without a session
    // counts as none.
    for id in ["echo-1", "echo-2", "echo-3"] {
        let answer = send(instance.addr, in_session(messages(haiku_prompt()), id)).await;
        assert_eq!(answer.status, StatusCode::OK);
    }
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let status = instance.status();
    assert_eq!(
        status["sessions"],
        json!({ "known": 3, "active": 3, "distribution_enabled": true })
    );
    let active = |name: &str| {
        status["accounts"]
            .as_array()
            .expect("accounts")
            .iter()
            .find(|a| a["display_name"] == name)
            .expect(name)["sessions_active"]
            .clone()
    };
    assert_eq!(active("FSUB"), 2);
    assert_eq!(active("FSUB2"), 1);
    // The human rendering carries the same counts.
    let (code, human, _) = instance.cli(&["status", "--verbose"], None);
    assert_eq!(code, 0);
    assert!(human.contains("known 3 active 3 · distributing"), "{human}");
    assert!(human.contains("2 sess"), "{human}");

    // The flag follows the configuration; the counts are untouched.
    instance.reload_with_setup(&Setup::default());
    let status = instance.status();
    assert_eq!(
        status["sessions"],
        json!({ "known": 3, "active": 3, "distribution_enabled": false })
    );
}
