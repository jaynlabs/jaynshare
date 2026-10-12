//! Account state between CLI mutations and reloads: what the running
//! instance picks up without a restart, and what it holds on to.
use crate::faults::Faults;
use crate::harness::*;

/// Rename under and: an empty name is refused
/// (400 → exit 9); a name differing only by Unicode case from another
/// account is a conflict (exit 8); a name a route or priority entry uses is
/// the conflict naming both entries; then, with the entries dropped
/// from the configuration, the rename succeeds with the handle unchanged,
/// the next exchange selected under the new name without a
/// restart or reload: the reloads are the configuration
/// changes around it, and the process id is unchanged throughout.
#[tokio::test(flavor = "multi_thread")]
async fn rename_refusals_then_success_keeps_the_handle() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "rename-refusals-success",
        Setup {
            selection: "priorities = [{ account = \"FSUB\", value = 0 }]\n\
                        routes = [{ name = \"haiku\", patterns = [\"*haiku*\"], accounts = [\"FSUB\"] }]\n"
                .into(),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    let handle = instance.handle("FSUB");

    // An empty name is not a name: 400, exit 9.
    let envelope = instance.cli_json(&["account", "rename", "FSUB", ""], None);
    assert_eq!(envelope["exit_code"], 9, "{envelope}");
    assert_eq!(envelope["error"]["code"], "invalid_request");
    assert_eq!(envelope["error"]["target"], "display_name");

    // `fsub2` differs from `FSUB2` only by Unicode case: 409, exit 8.
    let envelope = instance.cli_json(&["account", "rename", "FSUB", "fsub2"], None);
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    assert_eq!(envelope["error"]["code"], "conflict");
    assert_eq!(envelope["error"]["target"], "fsub2");

    // A route and a priority entry both name FSUB: the refusal names
    // each entry and leaves the state file untouched.
    let state_before = instance.state_digest();
    let envelope = instance.cli_json(&["account", "rename", "FSUB", "Renamed"], None);
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    assert_eq!(envelope["error"]["code"], "account_reference_conflict");
    let details = envelope["error"]["details"].as_array().expect("details");
    assert!(
        details.iter().any(|d| d["target"] == "route haiku"),
        "the route entry named: {envelope}"
    );
    assert!(
        details.iter().any(|d| d["target"] == "priority 0"),
        "the priority entry named: {envelope}"
    );
    assert_eq!(
        instance.state_digest(),
        state_before,
        "the refusal wrote nothing"
    );

    // The configuration drops the entries by the reload.
    instance.reload_with_setup(&Setup::default());
    let pid = instance.pid();
    let envelope = instance.cli_json(&["account", "rename", "FSUB", "Renamed"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"],
        handle.as_str(),
        "the handle is unchanged"
    );
    assert_eq!(instance.pid(), pid, "the rename restarts nothing");
    assert_eq!(
        instance.events("reload").len(),
        2,
        "the setup's and the drop's"
    );

    // The next exchange is selected under the new configuration, which
    // answers with the new name.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "Renamed");
}
/// An injected failure that is neither a network failure nor an
/// upstream status skips that account and tries the next; with no account
/// left the caller gets 502 `proxy_error` carrying the failure's description
/// and no needle. Sessionless: a session's exchange
/// has its one bound candidate.
#[tokio::test(flavor = "multi_thread")]
async fn other_failures_skip_the_account_then_502() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("other-failures-skip").await;
    add_two(&instance);
    let default = instance.default_account();

    instance.upstream.script([reply_unparseable()]);
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.upstream.calls(), calls + 2);
    let seen = instance.upstream.seen();
    let identities: Vec<Value> = seen[seen.len() - 2..]
        .iter()
        .map(|attempt| {
            serde_json::from_str(attempt.json()["metadata"]["user_id"].as_str().unwrap()).unwrap()
        })
        .collect();
    assert_ne!(
        identities[0]["device_id"], identities[1]["device_id"],
        "failover normalizes for the newly selected account"
    );
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["failed_over"], true);
    assert_eq!(record["attempts"], 2);
    assert_eq!(instance.default_account(), default, "no failover move");
    assert!(instance.events("default_moved").is_empty());

    instance
        .upstream
        .script([reply_unparseable(), reply_unparseable()]);
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert_eq!(instance.upstream.calls(), calls + 2);
    let body = answer.json();
    assert_eq!(body["error"]["type"], "proxy_error");
    let message = body["error"]["message"].as_str().expect("message");
    assert!(message.contains("every attempt failed"), "{message}");
    assert!(
        message.len() > "every attempt failed: ".len(),
        "carries the description"
    );
    for needle in instance.needles.all() {
        assert!(!message.contains(needle), "needle in the description");
    }
    let record = instance.last_record(2);
    assert_eq!(record["attempts"], 2);
    assert_eq!(record["error_class"], "upstream");
    assert_eq!(
        record["no_service_reason"], "all_tried",
        "the exclusion reason in the audit record"
    );

    // A session's exchange has one candidate: the failure ends it with the 502.
    instance.upstream.script([reply_unparseable()]);
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "lima")).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert_eq!(instance.upstream.calls(), calls + 1);
    assert!(answer.text().contains("FSUB"), "{}", answer.text());
}
/// A higher-tier account becoming eligible never preempts: every
/// bound session keeps its account, with no move line, and an operator-chosen
/// default likewise.
#[tokio::test(flavor = "multi_thread")]
async fn a_returning_higher_tier_never_takes_a_bound_session() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with_accounts(
        "returning-higher-tier",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    exhaust_fsub_until(&instance, 2).await;

    send(instance.addr, in_session(messages(haiku_prompt()), "mike")).await;
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "ranking");
    assert_eq!(instance.events("default_moved").len(), 1);

    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], true);
    send(instance.addr, in_session(messages(haiku_prompt()), "mike")).await;
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "session");
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(4);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "default");
    assert_eq!(instance.events("default_moved").len(), 1, "no move line");

    // The operator's choice of the lower tier stands while FSUB (tier
    // 0) is eligible; nothing outranks it and no move line is written.
    assert_eq!(instance.cli(&["switch", "FSUB2"], None).0, 0);
    send(instance.addr, messages(haiku_prompt())).await;
    let record = instance.last_record(5);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "default");
    assert_eq!(
        instance.status()["default_account"]["operator_chosen"],
        true
    );
    assert_eq!(instance.events("default_moved").len(), 1, "no move line");
}

/// The default's weekly reset is learned mid-connection: no
/// re-ranking line and no move; a sooner-resetting sibling wins only at the
/// next bind (dropped).
#[tokio::test(flavor = "multi_thread")]
async fn a_learned_weekly_reset_moves_nothing_until_the_next_bind() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("learned-weekly-reset").await;
    add_two(&instance);
    // FSUB2 resets in an hour; FSUB's reset is unknown, then learned at ten hours.
    instance
        .upstream
        .script([reply_teaching_weekly("0.10", &reset_in(3_600))]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "november"),
    )
    .await;
    instance
        .upstream
        .script([reply_teaching_weekly("0.20", &reset_in(36_000))]);
    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "november"),
    )
    .await;
    instance.settle();
    assert!(
        instance.account("FSUB")["buckets"]
            .as_array()
            .expect("buckets")
            .iter()
            .any(|b| b["name"] == "weekly" && b["reset"] != Value::Null),
        "the reset was learned"
    );
    assert_eq!(instance.default_account(), instance.handle("FSUB"));
    assert!(
        instance.events("default_moved").is_empty(),
        "no re-ranking line"
    );

    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "november"),
    )
    .await;
    send(instance.addr, messages(haiku_prompt())).await;
    let records = instance.audit_settled(5);
    assert_eq!(records[3]["serving_account"]["display_name"], "FSUB");
    assert_eq!(records[3]["selection_cause"], "session");
    assert_eq!(records[4]["serving_account"]["display_name"], "FSUB");
    assert_eq!(records[4]["selection_cause"], "default");

    // The sibling wins at the next bind, once the default is barred.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", &reset_in(36_000))]);
    send(instance.addr, messages(haiku_prompt())).await;
    send(
        instance.addr,
        in_session(messages(haiku_prompt()), "november-next"),
    )
    .await;
    let record = instance.last_record(7);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    assert_eq!(record["selection_cause"], "ranking");
    assert_eq!(instance.events("default_moved").len(), 1);
}

/// The exchange's single candidate refused on 401 after a failed
/// refresh, and on 403, ends the exchange with the 502 naming it; another
/// healthy account in the pool is never attempted, whatever its tier
/// The tail: a session bound before the failure
/// keeps its binding and gets the 429 naming its errored account.
#[tokio::test(flavor = "multi_thread")]
async fn the_refused_candidate_ends_502_and_the_sibling_is_never_tried() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // (a) a 401 whose forced refresh the token endpoint rejects (HTTP 400).
    let instance = Instance::start_with_accounts(
        "refused-candidate-ends",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    send(instance.addr, in_session(messages(haiku_prompt()), "oscar")).await;

    instance.upstream.script([reply_auth_401()]);
    instance.upstream.script_token([Reply::status(
        400,
        json!({"error": "invalid_grant", "error_description": "token revoked"}).to_string(),
    )]);
    let before = instance.upstream.seen().len();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{}", answer.text());
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    assert!(answer.text().contains("FSUB"), "{}", answer.text());

    // One attempt, one token call — the refresh failed, so no retry, and
    // FSUB2 (the lower tier) is never touched.
    let seen = &instance.upstream.seen()[before..];
    assert_eq!(seen.len(), 2, "one attempt, one token call, nothing else");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {}", instance.needles.access_token).as_str()),
        "the attempt carried FSUB's bearer"
    );
    let record = instance.last_record(2);
    assert_eq!(record["attempts"], 1);
    assert_eq!(record["error_class"], "authentication");
    assert_eq!(record["serving_account"]["display_name"], "FSUB");

    instance.settle();
    assert_eq!(instance.account("FSUB")["health"]["state"], "errored");
    assert_eq!(
        instance.account("FSUB2")["health"]["state"],
        "ready",
        "FSUB2 untouched"
    );

    // The session bound before the failure keeps its binding: it
    // gets the synthetic 429 naming its errored account, no attempt made.
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, in_session(messages(haiku_prompt()), "oscar")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(answer.text().contains("FSUB"), "{}", answer.text());
    assert_eq!(instance.upstream.calls(), calls, "no attempt for the 429");

    // (b) a bare 403: the 502 ends the exchange, the account not errored.
    let instance = Instance::start_with_accounts(
        "refused-candidate-ends-403",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    instance.upstream.script([Reply::status(
        403,
        json!({
            "type": "error",
            "error": { "type": "permission_error", "message": "Request not allowed" },
            "request_id": "req_fixture_0403",
        })
        .to_string(),
    )]);

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{}", answer.text());
    assert_eq!(answer.json()["error"]["type"], "proxy_error");
    assert!(answer.text().contains("FSUB"), "{}", answer.text());
    let record = instance.last_record(1);
    assert_eq!(record["attempts"], 1, "no second attempt");

    instance.settle();
    assert_eq!(
        instance.account("FSUB")["health"]["state"],
        "ready",
        "403 does not error the account"
    );
    assert_eq!(instance.account("FSUB2")["health"]["state"], "ready");
}

/// A classified 429 updates the serving account's quota while the
/// body and headers the caller receives are byte-identical to the fake's.
#[tokio::test(flavor = "multi_thread")]
async fn classified_429_updates_quota_and_relays_bytes() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("classified-429-updates").await;
    instance.add_fsub();
    let body = json!({
        "type": "error",
        "error": { "type": "rate_limit_error", "message": "You have hit your weekly limit" },
        "request_id": "req_fixture_0453",
    })
    .to_string();
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.40"),
            ("5h-status", "allowed"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
            ("7d-reset", "2099-01-01T00:00:00Z"),
        ],
        Some("45"),
    )
    .with_body(body.clone())]);

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        answer.body(),
        Bytes::from(body),
        "the body is byte-identical"
    );
    assert_eq!(answer.header("retry-after"), Some("45"));
    assert_eq!(answer.header("request-id"), Some("req_fixture_0429"));
    assert_eq!(
        answer.header("anthropic-ratelimit-unified-7d-utilization"),
        Some("1.0"),
        "the rate-limit headers reach the caller unchanged"
    );
    assert_eq!(answer.header("x-should-retry"), None);

    instance.settle();
    let weekly = instance.account("FSUB")["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["state"], "exhausted", "the classification landed");
    assert_eq!(weekly["utilisation"], 1.0);
    assert_eq!(weekly["observed_source"], "response-headers");
    assert_eq!(
        instance.events("quota_classified")[0]["fields"]["classification"],
        "exhaustion"
    );
}

/// Every mutation answers only after the
/// next exchange is already selected under the new pool. For each of add (a
/// higher-tier account — unlisted in the priorities, so tier 0 above FKEY's
/// 1 and FSUB2's 2), replace (a key the fake distinguishes by bearer),
/// rename, disable, enable and remove: the operation reports success, then
/// immediately one prompt — its audit record and the bearer the fake saw
/// carry the new pool. The add and rename prompts pin by the account's new
/// name, which misses with 404 before the operation and resolves after, so
/// the contrast is the old pool against the new one. No restart, no reload
/// (`events("reload")` empty) and one process id throughout.
#[tokio::test(flavor = "multi_thread")]
async fn every_mutation_serves_the_next_exchange_from_the_new_pool() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let fsub2_access = needle("family access token", "oat-fixture");
    let instance = Instance::start_with_accounts(
        "mutation-serves-next",
        Setup {
            selection: priorities(&[("FSUB2", 2), ("FKEY", 1)]),
            ..Setup::default()
        },
        |instance| {
            instance.add_fsub();
            instance.add_oauth_family(
                "FSUB2",
                "fsub2@fixture.invalid",
                FSUB2_UUID,
                &fsub2_access,
                &needle("family refresh token", "ort-fixture"),
                OffsetDateTime::now_utc() + time::Duration::hours(1),
            );
            let envelope = instance.cli_json(
                &["account", "add", "--api-key", "--stdin", "--name", "FKEY"],
                Some(&instance.needles.api_key),
            );
            assert_eq!(envelope["ok"], true, "adding FKEY: {envelope}");
        },
    )
    .await;
    let key1 = instance.needles.api_key.clone();
    let pid = instance.pid();
    let reloads = instance.events("reload").len();

    // The starting pool: the default FSUB serves with its bearer.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(
        instance.upstream.last().header("authorization"),
        Some(format!("Bearer {}", instance.needles.access_token).as_str()),
    );

    // ---- add: before it the pin by the new name misses (the old pool);
    // after it the same pin serves with the new account's bearer.
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB3")).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", answer.text());
    let fsub3_access = needle("family access token", "oat-fixture");
    instance.add_oauth_family(
        "FSUB3",
        "fsub3@fixture.invalid",
        FSUB3_UUID,
        &fsub3_access,
        &needle("family refresh token", "ort-fixture"),
        OffsetDateTime::now_utc() + time::Duration::hours(1),
    );
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB3")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB3");
    assert_eq!(
        instance.upstream.last().header("authorization"),
        Some(format!("Bearer {fsub3_access}").as_str()),
    );
    assert_eq!(instance.pid(), pid, "the add restarts nothing");

    // ---- replace: the fake sees key1 before and key2 after, so the bearer
    // is what distinguishes the replaced credential.
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FKEY")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(
        instance.upstream.last().header("x-api-key"),
        Some(key1.as_str()),
    );
    let key2 = needle("pooled API key", "fixture");
    let envelope = instance.cli_json(
        &["account", "replace", "FKEY", "--api-key", "--stdin"],
        Some(&key2),
    );
    assert_eq!(envelope["exit_code"], 0, "replacing FKEY: {envelope}");
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FKEY")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(
        instance.upstream.last().header("x-api-key"),
        Some(key2.as_str()),
    );
    assert_eq!(instance.pid(), pid);

    // ---- rename: the pin by the new name misses before the rename and
    // serves with the renamed account's bearer after (the handle unchanged).
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "RENAMED")).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", answer.text());
    let handle = instance.handle("FSUB");
    let envelope = instance.cli_json(&["account", "rename", "FSUB", "RENAMED"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        envelope["result"]["account"]["handle"],
        handle.as_str(),
        "the handle is unchanged"
    );
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "RENAMED")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(7);
    assert_eq!(record["serving_account"]["display_name"], "RENAMED");
    assert_eq!(
        instance.upstream.last().header("authorization"),
        Some(format!("Bearer {}", instance.needles.access_token).as_str()),
    );
    assert_eq!(instance.pid(), pid);

    // ---- disable: the disabled default leaves new selection at
    // once; the ranking picks FSUB3 and the default moves with it.
    let envelope = instance.cli_json(&["account", "disable", "RENAMED"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        instance.account("RENAMED")["eligibility"]["reason"],
        "disabled"
    );
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(8);
    assert_eq!(record["serving_account"]["display_name"], "FSUB3");
    assert_eq!(
        instance.upstream.last().header("authorization"),
        Some(format!("Bearer {fsub3_access}").as_str()),
    );
    assert_eq!(instance.pid(), pid);

    // ---- enable: eligible again at once. The default the ranking
    // chose keeps serving unpinned, so the pin shows the return.
    let envelope = instance.cli_json(&["account", "enable", "RENAMED"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "RENAMED")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(9);
    assert_eq!(record["serving_account"]["display_name"], "RENAMED");
    assert_eq!(
        instance.upstream.last().header("authorization"),
        Some(format!("Bearer {}", instance.needles.access_token).as_str()),
    );
    assert_eq!(instance.pid(), pid);

    // ---- remove: the default goes; the very next exchange is
    // served by the pool that remains, and FSUB3 is nowhere in status.
    assert_eq!(instance.default_account(), instance.handle("FSUB3"));
    let envelope = instance.cli_json(&["account", "remove", "FSUB3", "--yes"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(10);
    assert_eq!(record["serving_account"]["display_name"], "RENAMED");
    assert_eq!(
        instance.upstream.last().header("authorization"),
        Some(format!("Bearer {}", instance.needles.access_token).as_str()),
    );
    assert!(
        !instance.status()["accounts"]
            .as_array()
            .expect("accounts array")
            .iter()
            .any(|a| a["display_name"] == "FSUB3"),
    );

    // The whole run never reloaded and never changed process.
    assert_eq!(instance.events("reload").len(), reloads);
    assert_eq!(instance.pid(), pid);
}

/// A run that sets every field
/// kind (both variants), handle, display name, profile email and identity,
/// source class, `enabled: false`, errored with a safe reason and a time, an
/// API key and an OAuth family, both refresh times and a
/// `refresh_not_before` — and a restart restores each one equal in `status`
/// and in `state_file`; each record's key set is exactly the field
/// list of the documented behaviour, so an undocumented field is absent.
#[tokio::test(flavor = "multi_thread")]
async fn every_account_field_survives_a_restart() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("account-field-survives").await;

    // Between them the five accounts set every fact: FKEY the API-key
    // kind (`api-key-entry`, a key, no identity, no refresh times); FROT an
    // OAuth family that refreshed and rotated (both refresh times); FWAIT an
    // attempt with no success and a `refresh_not_before` (the transient
    // floor); FERR errored with a safe reason and a time; FDIS disabled.
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
        &needle("waiting family access token", "oat-fwait"),
        &needle("waiting family refresh token", "ort-fwait"),
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );
    instance.add_oauth_family(
        "FERR",
        "ferr@fixture.invalid",
        &Uuid::new_v4().to_string(),
        &needle("errored family access token", "oat-ferr"),
        &needle("errored family refresh token", "ort-ferr"),
        OffsetDateTime::now_utc() + time::Duration::seconds(3600),
    );
    instance.add_oauth("FDIS", "fdis@fixture.invalid", &Uuid::new_v4().to_string());

    // The token endpoint answers in the order the prompts consume it: FROT's
    // rotation, FWAIT's three transient 503s, FERR's permanent rejection.
    instance.upstream.script_token([
        Reply::status(
            200,
            json!({
                "access_token": needle("rotated access token", "oat-rotated"),
                "refresh_token": needle("rotated refresh token", "ort-rotated"),
                "expires_in": 3600,
            })
            .to_string(),
        ),
        Reply::status(503, "{}"),
        Reply::status(503, "{}"),
        Reply::status(503, "{}"),
        Reply::status(400, "rejected"),
    ]);

    // FROT refreshes and rotates; FWAIT ends in the transient floor; FERR's
    // 401 forces a refresh the token endpoint rejects permanently.
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FROT")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FWAIT")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    instance.upstream.script([reply_auth_401()]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FERR")).await;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{}", answer.text());

    // FDIS: the enabled flag goes false through the operator surface.
    let envelope = instance.cli_json(&["account", "disable", "FDIS"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    instance.settle();

    let persisted_status = |a: &Value| {
        json!({
            "handle": a["handle"],
            "display_name": a["display_name"],
            "kind": a["kind"],
            "source_class": a["source_class"],
            "enabled": a["enabled"],
            "health_state": a["health"]["state"],
            "health_reason": a["health"]["reason"],
            "health_since": a["health"]["since"],
            "email": a["profile"]["email"],
            "account_uuid": a["profile"]["account_uuid"],
            "organization_uuid": a["profile"]["organization_uuid"],
            "organization_name": a["profile"]["organization_name"],
            "access_token_expires_at": a["credential"]["access_token_expires_at"],
            "refresh_material_present": a["credential"]["refresh_material_present"],
            "last_refresh_attempt": a["credential"]["last_refresh_attempt"],
            "last_refresh_success": a["credential"]["last_refresh_success"],
            "next_refresh_allowed_at": a["credential"]["next_refresh_allowed_at"],
        })
    };
    let before_status: std::collections::BTreeMap<String, Value> = instance.status()["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .map(|a| {
            (
                a["display_name"].as_str().expect("name").to_string(),
                persisted_status(a),
            )
        })
        .collect();
    // Every fact as the state file persists it (the documented behaviour).
    let records = |instance: &Instance| -> std::collections::BTreeMap<String, Value> {
        instance.state_file()["accounts"]
            .as_array()
            .expect("state accounts")
            .iter()
            .map(|r| {
                (
                    r["display_name"].as_str().expect("name").to_string(),
                    r.clone(),
                )
            })
            .collect()
    };
    let before_records = records(&instance);

    instance.restart();

    // Each field is equal in `status` after the restart.
    let after_status: std::collections::BTreeMap<String, Value> = instance.status()["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .map(|a| {
            (
                a["display_name"].as_str().expect("name").to_string(),
                persisted_status(a),
            )
        })
        .collect();
    assert_eq!(after_status, before_status, "every status field equal");

    // Each field is equal in `state_file`, and the record carries exactly
    // the field list — an undocumented field is absent.
    let after_records = records(&instance);
    assert_eq!(after_records, before_records, "every record equal");
    for (name, record) in &after_records {
        let mut expected = vec![
            "kind",
            "handle",
            "display_name",
            "profile_email",
            "account_uuid",
            "organization_uuid",
            "organization_name",
            "source",
            "enabled",
            "errored",
            "error_reason",
            "error_at",
            "quota",
        ];
        if record["kind"] == "oauth" {
            expected.extend([
                "access_token",
                "refresh_token",
                "expires_at",
                "last_refresh_attempt_at",
                "last_refresh_success_at",
                "refresh_not_before",
            ]);
        } else {
            expected.extend(["api_key"]);
        }
        let mut keys: Vec<&str> = record
            .as_object()
            .expect("record object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        expected.sort_unstable();
        assert_eq!(keys, expected, "{name}: the field set, exactly");
    }

    // The values behind the set: the run's operations are what the file pins.
    let fkey = &after_records["FKEY"];
    assert_eq!(fkey["kind"], "api_key");
    assert_eq!(fkey["source"], "api-key-entry");
    assert_eq!(fkey["api_key"], json!(instance.needles.api_key));
    assert_eq!(fkey["profile_email"], Value::Null, "no identity");
    let frot = &after_records["FROT"];
    assert!(frot["last_refresh_attempt_at"].is_string());
    assert!(frot["last_refresh_success_at"].is_string());
    assert_eq!(frot["refresh_not_before"], Value::Null);
    assert_ne!(
        frot["refresh_token"], frot["access_token"],
        "the rotated family"
    );
    let fwait = &after_records["FWAIT"];
    assert!(fwait["last_refresh_attempt_at"].is_string());
    assert!(fwait["last_refresh_success_at"].is_null());
    assert!(fwait["refresh_not_before"].is_string());
    let ferr = &after_records["FERR"];
    assert_eq!(ferr["errored"], true);
    assert!(ferr["error_reason"].as_str().is_some_and(|r| !r.is_empty()));
    assert!(ferr["error_at"].is_string());
    let fdis = &after_records["FDIS"];
    assert_eq!(fdis["enabled"], false);
}

// ---- step 4

/// The model the caller asked for arrives upstream unchanged
/// under a route that selects a different account; a configuration
/// key claiming models for an account is unknown, refused by `config set`
/// before any write and by `config validate`. The
/// live keys beside it — a probe interval set and unset, a pattern blocked
/// and unblocked — apply through the same file edit and reload.
#[tokio::test(flavor = "multi_thread")]
async fn the_model_passes_through_and_a_model_claim_is_unknown() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_with_accounts(
        "model-passes-through",
        Setup {
            selection: priorities(&[("FSUB", 0), ("FSUB2", 1)])
                + &routes(&[("s", &["*sonnet*"], Some(&["FSUB2"]), None)]),
            ..Setup::default()
        },
        add_two,
    )
    .await;
    assert_eq!(instance.default_account(), instance.handle("FSUB"));
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(1);
    assert_eq!(record["serving_account"]["display_name"], "FSUB2");
    // The exclusive route passed the default over: the ranking served.
    assert_eq!(record["selection_cause"], "ranking");
    assert_eq!(instance.upstream.last().json()["model"], "claude-sonnet-5");

    // A per-account model claim has no configuration key: unknown, so
    // `config set` exits 3 before writing and `config validate` names it.
    let file_before = fs::read(&instance.config).expect("configuration bytes");
    let envelope = instance.cli_json(
        &[
            "config",
            "set",
            "selection.account_models",
            "{ FSUB = [\"*opus*\"] }",
        ],
        None,
    );
    assert_eq!(envelope["exit_code"], 3, "{envelope}");
    assert_eq!(envelope["error"]["code"], "cli_configuration_invalid");
    assert_eq!(
        envelope["error"]["details"][0]["target"],
        "selection.account_models"
    );
    assert_eq!(
        fs::read(&instance.config).expect("configuration bytes"),
        file_before
    );
    let claimed = instance.root.join("claimed.toml");
    write_private(
        &claimed,
        &format!(
            "{}[accounts]\nmodels = {{ FSUB = [\"*opus*\"] }}\n",
            String::from_utf8_lossy(&file_before)
        ),
    );
    let (code, stdout, stderr) = instance.cli(
        &["config", "validate", &claimed.display().to_string()],
        None,
    );
    assert_eq!(code, 3, "{stdout}{stderr}");
    assert!(stderr.contains("accounts.models"), "{stderr}");
    let (code, stdout, stderr) = instance.cli(&["config", "validate"], None);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stdout.contains(
            instance.status()["configuration"]["digest"]
                .as_str()
                .unwrap_or("?")
        ),
        "{stdout}"
    );
    assert!(stderr.contains("not checked"), "the note: {stderr}");

    // A live key set and unset.
    let envelope = instance.cli_json(
        &["config", "set", "quota.probe_interval_seconds", "300"],
        None,
    );
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        envelope["result"]["reload"]["changed_keys"],
        json!([]),
        "300 is the default"
    );
    let envelope = instance.cli_json(
        &["config", "set", "quota.probe_interval_seconds", "45"],
        None,
    );
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        envelope["result"]["reload"]["changed_keys"],
        json!(["quota.probe_interval_seconds"])
    );
    assert_eq!(
        instance.status()["configuration"]["effective"]["quota"]["probe_interval_seconds"],
        45
    );
    let envelope = instance.cli_json(
        &["config", "set", "quota.probe_interval_seconds", "10"],
        None,
    );
    assert_eq!(
        envelope["exit_code"], 3,
        "below the floor, refused locally: {envelope}"
    );
    assert_eq!(
        instance.status()["configuration"]["effective"]["quota"]["probe_interval_seconds"],
        45
    );
    let envelope = instance.cli_json(&["config", "unset", "quota.probe_interval_seconds"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        instance.status()["configuration"]["effective"]["quota"]["probe_interval_seconds"],
        300
    );
    assert!(
        !fs::read_to_string(&instance.config)
            .expect("configuration")
            .contains("probe_interval_seconds"),
        "no default written into the file"
    );

    // The block list edited the same way.
    let envelope = instance.cli_json(&["block", "add", "*sonnet*"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        envelope["result"]["reload"]["changed_keys"],
        json!(["selection.blocked_models"])
    );
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(instance.last_record(2)["blocked_pattern"], "*sonnet*");
    let envelope = instance.cli_json(&["block", "add", "*sonnet*"], None);
    assert_eq!(envelope["exit_code"], 8, "{envelope}");
    let envelope = instance.cli_json(&["block", "rm", "*sonnet*"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(instance.status()["blocked_models"], json!([]));
    let envelope = instance.cli_json(&["block", "rm", "*sonnet*"], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.upstream.last().json()["model"], "claude-sonnet-5");

    // An unreachable server: exit 4, nothing written, the offline hint.
    let file_before = fs::read(&instance.config).expect("configuration bytes");
    instance.stop();
    let envelope = instance.cli_json(&["block", "add", "*opus*"], None);
    assert_eq!(envelope["exit_code"], 4, "{envelope}");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("config edit --offline"),
        "{envelope}"
    );
    assert_eq!(
        fs::read(&instance.config).expect("configuration bytes"),
        file_before
    );
}

/// A route carries a name, several patterns, an account list in
/// each reference form and a governing-bucket override naming a known
/// bucket, written by `route add` and shown in the route view; a list
/// entry given as an index is rejected by `route add` and, written by hand,
/// at reload; `priority set` and `clear` resolve the same forms.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_in_every_reference_form_and_no_index() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("route-reference-form").await;
    add_two(&instance);
    let other_org = Uuid::new_v4().to_string();
    instance.add_other_org(
        "OTHER",
        "other@fixture.invalid",
        &Uuid::new_v4().to_string(),
        &other_org,
    );
    let fsub = instance.handle("FSUB");

    // Display name, email, account UUID, organisation UUID, handle.
    let envelope = instance.cli_json(
        &[
            "route",
            "add",
            "all",
            "--pattern",
            "*haiku*",
            "--pattern",
            "*sonnet*",
            "--account",
            "FSUB",
            "--account",
            "fsub2@fixture.invalid",
            "--account",
            FSUB2_UUID,
            "--account",
            &other_org,
            "--account",
            &fsub,
            "--bucket",
            "weekly:fable",
        ],
        None,
    );
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        envelope["result"]["reload"]["changed_keys"],
        json!(["selection.routes"])
    );
    let view = instance.route_view("all");
    assert_eq!(view["patterns"], json!(["*haiku*", "*sonnet*"]));
    assert_eq!(view["bucket"], "weekly:fable");
    let listed: Vec<&str> = view["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .filter_map(|a| a["display_name"].as_str())
        .collect();
    assert_eq!(listed, ["FSUB", "FSUB2", "OTHER"]);
    let file = fs::read_to_string(&instance.config).expect("configuration");
    for typed in [
        "\"FSUB\"",
        "\"fsub2@fixture.invalid\"",
        &format!("\"{FSUB2_UUID}\""),
        &format!("\"{other_org}\""),
        &format!("\"{fsub}\""),
    ] {
        assert!(file.contains(typed), "stored as typed: {file}");
    }
    let (code, stdout, _) = instance.cli(&["route", "list", "--local"], None);
    assert_eq!(code, 0);
    assert!(stdout.contains("weekly:fable"), "{stdout}");

    // An index is not a reference: exit 6 at, nothing written.
    let before = fs::read(&instance.config).expect("configuration bytes");
    let envelope = instance.cli_json(
        &[
            "route",
            "add",
            "first",
            "--pattern",
            "*opus*",
            "--account",
            "1",
        ],
        None,
    );
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("positions are not references"),
        "{envelope}"
    );
    assert_eq!(
        fs::read(&instance.config).expect("configuration bytes"),
        before
    );
    // Written by hand, the reload rejects it the same way.
    let file = String::from_utf8_lossy(&before).to_string();
    write_private(
        &instance.config,
        &format!(
            "{file}\n[[selection.routes]]\nname = \"first\"\npatterns = [\"*opus*\"]\naccounts = [\"1\"]\n"
        ),
    );
    let envelope = instance.cli_json(&["config", "reload"], None);
    assert_eq!(envelope["exit_code"], 3, "{envelope}");
    assert_eq!(
        envelope["error"]["details"][0]["target"],
        "selection.routes[1].accounts[0]"
    );
    write_private(&instance.config, &file);

    // The same forms on `priority set`; one entry per account.
    let envelope = instance.cli_json(&["priority", "set", "fsub2@fixture.invalid", "2"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(
        envelope["result"]["reload"]["changed_keys"],
        json!(["selection.priorities"])
    );
    assert_eq!(instance.account("FSUB2")["priority"], 2);
    let envelope = instance.cli_json(&["priority", "set", FSUB2_UUID, "-1"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(instance.account("FSUB2")["priority"], -1);
    let file = fs::read_to_string(&instance.config).expect("configuration");
    assert_eq!(
        file.matches("fsub2@fixture.invalid").count(),
        2,
        "the route's and the one priority entry, under the reference first typed: {file}"
    );
    assert!(
        !file.contains(&format!("account = \"{FSUB2_UUID}\"")),
        "{file}"
    );
    let (code, stdout, _) = instance.cli(&["priority", "list"], None);
    assert_eq!(code, 0);
    assert!(stdout.contains("priority -1"), "{stdout}");
    let envelope = instance.cli_json(&["priority", "set", "2", "5"], None);
    assert_eq!(envelope["exit_code"], 6, "{envelope}");
    let envelope = instance.cli_json(&["priority", "clear", &fsub], None);
    assert_eq!(envelope["exit_code"], 6, "no entry to clear: {envelope}");
    let envelope = instance.cli_json(&["priority", "clear", "FSUB2"], None);
    assert_eq!(envelope["exit_code"], 0, "{envelope}");
    assert_eq!(instance.account("FSUB2")["priority"], 0);
    assert!(
        !fs::read_to_string(&instance.config)
            .expect("configuration")
            .contains("value = "),
        "the entry left the file"
    );

    // The route's models keep flowing under the override's judgement.
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.last_record(1)["selection_cause"], "default");
}

/// The write-boundary fixture, proven on the real writers: armed
/// between the temporary write and its rename (the boundary), the
/// process dies with the temporary file left behind and the state file
/// unchanged; the filled destination (RLIMIT_FSIZE, injected by the shim) is
/// the boundary at which the already-open audit and log appends fail. The
/// release binary is started unchanged and its fault is outside its bytes
/// The audit destination made unwritable while the
/// instance runs is plain filesystem work does from the harness
/// (chmod on the log directory, rotation's rename failing at it).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_write_boundary_fixture_fails_a_write_at_its_boundaries() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let faults = Faults::new();
    let mut instance =
        Instance::start_with_faults("t-acp-66", Setup::default(), faults.clone()).await;
    instance.add_fsub();

    // The crash boundary: armed, the next state rename — the coalesced
    // quota write of the teaching exchange — kills the process after the
    // temporary write, before the rename. The temporary file stays; the
    // state file keeps its old bytes (the promise, crashed for).
    let before = instance.state_digest();
    let pid = instance.pid();
    faults.arm_rename_kill("state.json");
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.await_exit(), 86, "dead at the rename boundary");
    assert_eq!(
        instance.state_digest(),
        before,
        "the state file kept its old bytes across the crash"
    );
    let temporary = instance
        .root
        .join("state/.state.json.".to_owned() + &pid.to_string() + ".tmp");
    assert!(temporary.exists(), "the temporary write stayed behind");
    // The leftover held the pooled credentials on a name the allow-list does
    // not know; the evidence is asserted, so it goes before the sweep sees it.
    fs::remove_file(&temporary).expect("remove the asserted temporary");

    // Unchanged state means unchanged accounts: the respawn serves with the
    // pool it had, and the next write lands whole.
    faults.clear_rename();
    instance.respawn();
    assert_eq!(instance.account("FSUB")["sessions_active"], 0);
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    instance.settle();
    assert_ne!(
        instance.state_digest(),
        before,
        "the next write lands whole once the fault is cleared"
    );

    // The filled destination: from the next injected process on, every
    // append past the limit fails, and the platform's SIGXFSZ kills the
    // process at its first crossing write (SIGXFSZ = 25 on both fixtures).
    let server_log = instance.root.join("log/server.ndjson");
    let audit_log = instance.root.join("log/exchanges.ndjson");
    let biggest = server_log
        .metadata()
        .expect("server log")
        .len()
        .max(audit_log.metadata().expect("audit log").len());
    faults.fill_destination_at(biggest);
    use std::os::unix::process::ExitStatusExt;
    let status = instance.respawn_expecting_exit_status();
    assert_eq!(
        status.signal(),
        Some(25),
        "the filled destination killed the process: {status}"
    );

    // The fixture is reversible: un-filled, the instance starts and serves.
    faults.clear_fill();
    instance.respawn();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
}
