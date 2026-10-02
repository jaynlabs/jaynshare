//! Quota accounting: the subscription and API-key buckets, throttling,
//! revalidation, and what the status projections report.
use crate::harness::*;
/// Seconds between a log event's `timestamp` and one of its rfc3339 fields
/// the hold length the classification line computed. Fields live in
/// the `fields` object.
fn event_span(event: &Value, field: &str) -> i64 {
    use time::format_description::well_known::Rfc3339;
    let parse = |v: &Value| {
        time::OffsetDateTime::parse(v.as_str().expect("rfc3339 string"), &Rfc3339)
            .expect("parsable timestamp")
            .unix_timestamp()
    };
    parse(&event["fields"][field]) - parse(&event["timestamp"])
}

async fn wait_for_usage_calls(instance: &Instance, count: usize, timeout: Duration) -> Vec<Seen> {
    let deadline = Instant::now() + timeout;
    loop {
        let calls = instance.upstream.usage_calls();
        if calls.len() >= count {
            return calls;
        }
        assert!(Instant::now() < deadline, "usage calls: {calls:?}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn bucket<'a>(account: &'a Value, name: &str) -> &'a Value {
    account["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|bucket| bucket["name"] == name)
        .unwrap_or_else(|| panic!("no bucket {name}: {account}"))
}

// ------------------------------------------------------------------ step 8: usage probe

/// Enabling usage probing starts a sweep immediately and the
/// configured 30 s cadence starts the next one.
#[tokio::test(flavor = "multi_thread")]
async fn usage_scheduler_starts_immediately_and_repeats() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("usage-scheduler-starts").await;
    instance.add_fsub();
    instance.add_fkey();
    instance.reload_with_setup(&Setup {
        quota: "probe_enabled = true\nprobe_interval_seconds = 30\n".into(),
        ..Setup::default()
    });

    let first = wait_for_usage_calls(&instance, 1, Duration::from_secs(3)).await;
    assert_eq!(first[0].method, "GET");
    let status = instance.status();
    assert_eq!(status["usage_probe"]["enabled"], true);
    assert_eq!(status["usage_probe"]["interval_seconds"], 30);
    assert!(status["usage_probe"]["last_started"].is_string());
    assert!(status["usage_probe"]["next_run"].is_string());

    let calls = wait_for_usage_calls(&instance, 2, Duration::from_secs(33)).await;
    assert!(
        calls[1].at.duration_since(calls[0].at) >= Duration::from_secs(29),
        "the repeat follows the configured cadence"
    );
}

/// An operator starts exactly one ordinary sweep; an overlapping
/// trigger is refused without another usage request.
#[tokio::test(flavor = "multi_thread")]
async fn operator_probe_refuses_an_overlapping_sweep() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("operator-probe-refuses").await;
    instance.add_fsub();
    instance.upstream.delay_usage(Duration::from_secs(2));

    let first = instance.cli_json(&["probe"], None);
    assert_eq!(first["ok"], true, "{first}");
    assert!(first["result"]["started_at"].is_string());
    let overlapping = instance.cli_json(&["probe"], None);
    assert_eq!(overlapping["ok"], false, "{overlapping}");
    assert_eq!(overlapping["exit_code"], 8);
    assert_eq!(overlapping["error"]["code"], "sweep_in_progress");

    wait_for_usage_calls(&instance, 1, Duration::from_secs(3)).await;
    tokio::time::sleep(Duration::from_millis(2_200)).await;
    assert_eq!(instance.upstream.usage_calls().len(), 1);
}

/// Usage percent values update an OAuth account without touching
/// traffic totals; API-key accounts are not applicable.
#[tokio::test(flavor = "multi_thread")]
async fn usage_updates_oauth_only_and_probe_wait_prints_outcomes() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("usage-updates-oauth").await;
    instance.add_fsub();
    instance.add_fkey();
    let before = instance.account("FSUB")["usage"].clone();

    let envelope = instance.cli_json(&["probe", "--wait"], None);

    assert_eq!(envelope["ok"], true, "{envelope}");
    let accounts = envelope["result"]["status"]["accounts"]
        .as_array()
        .expect("accounts");
    let fsub = accounts
        .iter()
        .find(|account| account["display_name"] == "FSUB")
        .expect("FSUB");
    let fkey = accounts
        .iter()
        .find(|account| account["display_name"] == "FKEY")
        .expect("FKEY");
    assert_eq!(fsub["probe"]["outcome"], "updated");
    assert_eq!(fkey["probe"]["outcome"], "not_applicable");
    assert_eq!(bucket(fsub, "session")["utilisation"], 0.25);
    assert_eq!(bucket(fsub, "weekly")["utilisation"], 0.40);
    assert_eq!(bucket(fsub, "weekly:sonnet")["utilisation"], 0.10);
    assert_eq!(bucket(fsub, "weekly:fable")["utilisation"], 0.15);
    assert_eq!(fsub["usage"], before, "a usage read is not model traffic");
    assert_eq!(fkey["buckets"].as_array().expect("buckets").len(), 4);

    let calls = instance.upstream.usage_calls();
    assert_eq!(calls.len(), 1, "API-key accounts are never probed");
    assert_eq!(calls[0].path, "/api/oauth/usage");
    assert_eq!(calls[0].header("anthropic-beta"), Some("oauth-2025-04-20"));
    assert_eq!(
        calls[0].header("authorization"),
        Some(format!("Bearer {}", instance.needles.access_token).as_str())
    );
    assert!(calls[0].body.is_empty());

    let (code, stdout, stderr) = instance.cli(&["probe", "--wait"], None);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stdout.lines().any(|line| line.contains("FSUB  updated")),
        "{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("FKEY  not_applicable")),
        "{stdout}"
    );
}

/// A usage 401 forces one refresh and one retry; a later timeout
/// reports `timed_out` and retains the last quota observation.
#[tokio::test(flavor = "multi_thread")]
async fn usage_401_refreshes_once_and_timeout_retains_quota() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "usage-401-refreshes",
        Setup {
            quota: "probe_deadline_seconds = 1\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance.upstream.script_usage([
        Reply::status(401, json!({ "type": "error" }).to_string()),
        reply_usage("60", "70"),
    ]);
    instance.upstream.script_token([Reply::status(
        200,
        json!({
            "access_token": "sk-ant-oat-fixture-probe-rotated",
            "refresh_token": "sk-ant-ort-fixture-probe-rotated",
            "expires_in": 3600,
        })
        .to_string(),
    )]);

    let refreshed = instance.cli_json(&["probe", "--wait"], None);

    assert_eq!(refreshed["ok"], true, "{refreshed}");
    assert_eq!(instance.upstream.token_calls().len(), 1);
    let usage = instance.upstream.usage_calls();
    assert_eq!(usage.len(), 2, "one usage retry after the forced refresh");
    assert_eq!(
        usage[1].header("authorization"),
        Some("Bearer sk-ant-oat-fixture-probe-rotated")
    );
    assert_eq!(
        bucket(&instance.account("FSUB"), "weekly")["utilisation"],
        0.70
    );

    instance.upstream.script_usage([Reply::Stall]);
    let timed_out = instance.cli_json(&["probe", "--wait"], None);

    assert_eq!(timed_out["ok"], true, "{timed_out}");
    let fsub = timed_out["result"]["status"]["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .find(|account| account["display_name"] == "FSUB")
        .expect("FSUB");
    assert_eq!(fsub["probe"]["outcome"], "timed_out");
    assert_eq!(fsub["probe"]["error"], "usage probe deadline elapsed");
    assert_eq!(bucket(fsub, "weekly")["utilisation"], 0.70);
    assert_eq!(instance.upstream.token_calls().len(), 1);
}
// ------------------------------------------------------------------ step 2: 429 classification, holds, freshness, revalidation

/// A spend-cap 429 on A holds A and same-organisation B; an
/// account in another organisation is unaffected.
#[tokio::test(flavor = "multi_thread")]
async fn spend_cap_holds_the_organisation_and_not_others() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("spend-cap-holds-organisation").await;
    add_two(&instance);
    instance.add_other_org(
        "FOTHER",
        "fother@fixture.invalid",
        "3c1f5a7e-0000-4000-8000-0000000000a4",
        "3c1f5a7e-0000-4000-8000-0000000000c3",
    );

    instance.upstream.script([reply_spend_cap_429()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        answer.header("retry-after").is_none(),
        "no retry-after on the spend cap"
    );
    let classification = &instance.events("quota_classified")[0];
    assert_eq!(classification["fields"]["acct"], "FSUB");
    assert_eq!(classification["fields"]["classification"], "exhaustion");
    assert_eq!(classification["fields"]["buckets"], "spend-cap");

    for name in ["FSUB", "FSUB2"] {
        let account = instance.account(name);
        assert_eq!(account["eligibility"]["eligible"], false, "{name}");
        assert_eq!(account["eligibility"]["reason"], "held");
    }
    assert_eq!(
        instance.account("FOTHER")["eligibility"]["eligible"],
        true,
        "the other organisation is unaffected"
    );

    // Same organisation: the pin to FSUB2 is refused, nobody attempts.
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls);

    // Another organisation serves (ranking past the held default).
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FOTHER");
    assert_eq!(record["selection_cause"], "ranking");
}

/// Utilisation ≥ 1 proves exhaustion of the named bucket; the
/// `rejected` status word proves it at any utilisation; an unknown status
/// word never counts.
#[tokio::test(flavor = "multi_thread")]
async fn status_or_utilisation_proves_exhaustion_naming_buckets() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("status-utilisation-proves").await;
    instance.add_fsub();

    // Utilisation 1.0 on the session window: only that bucket is named.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "0.90"),
            ("7d-status", "allowed"),
        ],
        Some("0"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let line = &instance.events("quota_classified")[0];
    assert_eq!(line["fields"]["classification"], "exhaustion");
    assert_eq!(line["fields"]["buckets"], "session");
    tokio::time::sleep(Duration::from_millis(1_400)).await;

    // The rejected status word proves the weekly bucket below 1.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "0.90"),
            ("7d-status", "rejected"),
        ],
        Some("0"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let line = &instance.events("quota_classified")[1];
    assert_eq!(line["fields"]["classification"], "exhaustion");
    assert_eq!(line["fields"]["buckets"], "weekly");
    tokio::time::sleep(Duration::from_millis(1_400)).await;

    // An unknown status word never counts: 0.99 is throttle.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "0.99"),
            ("7d-status", "wednesday"),
        ],
        Some("90"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        instance.events("quota_classified")[2]["fields"]["classification"],
        "throttle"
    );
    assert!(
        instance.account("FSUB")["quota_holds"]["throttle_hold_end"].is_string(),
        "the throttle hold is set"
    );
}

/// API-key `tokens.remaining = 0` on a 429 → token exhaustion;
/// positive counters → throttle.
#[tokio::test(flavor = "multi_thread")]
async fn api_key_remaining_zero_is_exhaustion_positive_is_throttle() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "api-key-remaining",
        Setup {
            data_plane: "throttle_absorb_seconds = 1\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fkey();

    instance.upstream.script([reply_429_apikey(
        &[
            ("tokens-limit", "100"),
            ("tokens-remaining", "0"),
            ("requests-limit", "50"),
            ("requests-remaining", "40"),
        ],
        Some("0"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let line = &instance.events("quota_classified")[0];
    assert_eq!(line["fields"]["classification"], "exhaustion");
    assert_eq!(line["fields"]["buckets"], "tokens");
    tokio::time::sleep(Duration::from_millis(1_400)).await;

    instance.upstream.script([reply_429_apikey(
        &[
            ("tokens-limit", "100"),
            ("tokens-remaining", "30"),
            ("requests-limit", "50"),
            ("requests-remaining", "40"),
        ],
        Some("20"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let line = &instance.events("quota_classified")[1];
    assert_eq!(line["fields"]["classification"], "throttle");
    assert!(instance.account("FKEY")["quota_holds"]["throttle_hold_end"].is_string(),);
}

/// A 429 with only `retry-after` is throttle whatever the value;
/// it never classifies exhaustion.
#[tokio::test(flavor = "multi_thread")]
async fn retry_after_alone_is_throttle_whatever_its_value() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("retry-alone-throttle").await;
    instance.add_fsub();

    // No rate-limit facts at all, retry-after 90.
    instance
        .upstream
        .script([reply_429_unified(&[], Some("90"))]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.header("retry-after"), Some("90"));
    let line = &instance.events("quota_classified")[0];
    assert_eq!(line["fields"]["classification"], "throttle");
    assert!(
        (event_span(line, "hold_end") - 90).abs() <= 3,
        "the hold follows the retry-after: {line}"
    );
    // The hold is account-wide admission only: eligibility unchanged.
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], true);
}

/// The classification log line names account, class, buckets and
/// hold end, and copies neither the body text nor a credential.
#[tokio::test(flavor = "multi_thread")]
async fn classification_log_is_credential_free_and_body_free() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "classification-log-credential",
        Setup {
            data_plane: "throttle_absorb_seconds = 1\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    let marker = format!("would exceed the unique marker {}", Uuid::new_v4());
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("30"),
    )
    .with_body(
        json!({
            "type": "error",
            "error": { "type": "rate_limit_error", "message": marker },
            "request_id": "req_fixture_0429",
        })
        .to_string(),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    let lines: Vec<String> = instance
        .events("quota_classified")
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert!(line.contains("FSUB"));
    assert!(line.contains("exhaustion"));
    assert!(line.contains("weekly"));
    assert!(line.contains("hold_end"));
    assert!(
        !line.contains(&marker),
        "no upstream body text in the log: {line}"
    );
    assert!(
        !line.contains(&instance.needles.access_token),
        "no credential in the log"
    );
}

/// Reset-backed exhaustion holds to the exact reset; the
/// reset-less fallback takes `retry-after` with the 60 s fallback and the
/// 1…3600 s clamps. Each sub-case re-attempts after the configured
/// revalidation floor, since the hold bars any ordinary attempt.
#[tokio::test(flavor = "multi_thread")]
async fn exhaustion_hold_exact_reset_fallback_and_clamps() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "exhaustion-hold-exact",
        Setup {
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fkey();

    // Minimum clamp: retry-after 0 → 1 s (the 1…3600).
    instance.upstream.script([reply_429_apikey(
        &[
            ("tokens-limit", "100"),
            ("tokens-remaining", "0"),
            ("requests-remaining", "40"),
        ],
        Some("0"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let line = &instance.events("quota_classified")[0];
    assert_eq!(line["fields"]["buckets"], "tokens");
    assert!((event_span(line, "hold_end") - 1).abs() <= 2, "{line}");
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    // Malformed retry-after → the 60 s fallback.
    instance.upstream.script([reply_429_apikey(
        &[
            ("requests-limit", "50"),
            ("requests-remaining", "0"),
            ("tokens-remaining", "40"),
        ],
        Some("soon"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let line = &instance.events("quota_classified")[1];
    assert_eq!(line["fields"]["buckets"], "requests");
    assert!((event_span(line, "hold_end") - 60).abs() <= 2, "{line}");
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    // A plausible value stands.
    instance.upstream.script([reply_429_apikey(
        &[
            ("output-tokens-limit", "100"),
            ("output-tokens-remaining", "0"),
            ("requests-remaining", "40"),
            ("tokens-remaining", "40"),
        ],
        Some("25"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let line = &instance.events("quota_classified")[2];
    assert_eq!(line["fields"]["buckets"], "output-tokens");
    assert!((event_span(line, "hold_end") - 25).abs() <= 2, "{line}");
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    // Maximum clamp: retry-after 5000 → 3600 s.
    instance.upstream.script([reply_429_apikey(
        &[
            ("input-tokens-limit", "100"),
            ("input-tokens-remaining", "0"),
            ("requests-remaining", "40"),
            ("tokens-remaining", "40"),
        ],
        Some("5000"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let line = &instance.events("quota_classified")[3];
    assert!((event_span(line, "hold_end") - 3600).abs() <= 2, "{line}");
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    // A future reset holds to the reset exactly, ignoring the retry-after.
    // The earlier sub-cases' counters ride along with capacity, so only
    // `tokens` proves exhaustion here (the capacity rule).
    instance.upstream.script([reply_429_apikey(
        &[
            ("tokens-limit", "100"),
            ("tokens-remaining", "0"),
            ("tokens-reset", &reset_in(120)),
            ("requests-remaining", "40"),
            ("output-tokens-remaining", "40"),
            ("input-tokens-remaining", "40"),
        ],
        Some("30"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let line = &instance.events("quota_classified")[4];
    assert!((event_span(line, "hold_end") - 120).abs() <= 2, "{line}");
}

/// A family-only exhaustion bars only that family's models;
/// another model on the same account keeps working.
#[tokio::test(flavor = "multi_thread")]
async fn family_only_exhaustion_leaves_other_families_usable() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("family-exhaustion-leaves-other").await;
    instance.add_fsub();

    // Teach the fable family for the haiku model.
    instance
        .upstream
        .script([reply_teaching_family("0.12", "allowed")]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);

    // The family bucket rejects; the shared windows stay healthy.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "0.10"),
            ("7d-status", "allowed"),
            ("7d_oi-utilization", "1.0"),
            ("7d_oi-status", "rejected"),
        ],
        Some("2"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let line = &instance.events("quota_classified")[0];
    assert_eq!(line["fields"]["buckets"], "weekly:fable");
    assert_eq!(
        instance.account("FSUB")["buckets"]
            .as_array()
            .expect("buckets")
            .iter()
            .find(|b| b["name"] == "weekly:fable")
            .expect("the family bucket")["state"],
        "exhausted"
    );

    // The held family refuses the model without an attempt.
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls);

    // Another model is governed by the shared windows only: usable.
    let answer = send(instance.addr, messages(prompt_for("claude-sonnet-5"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(4);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
}

/// A newer reset replaces a reset-backed hold; a reset-less
/// rejection only extends the fallback hold. Every later 429 rides
/// A revalidation attempt (floor 2 s).
#[tokio::test(flavor = "multi_thread")]
async fn newer_reset_replaces_and_reset_less_only_extends() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "newer-reset-replaces",
        Setup {
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fkey();

    instance.upstream.script([reply_429_apikey(
        &[
            ("tokens-limit", "100"),
            ("tokens-remaining", "0"),
            ("tokens-reset", &reset_in(100)),
            ("requests-remaining", "40"),
        ],
        Some("45"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let line = &instance.events("quota_classified")[0];
    assert!(
        (event_span(line, "hold_end") - 100).abs() <= 2,
        "the reset wins over the retry-after: {line}"
    );
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    instance.upstream.script([reply_429_apikey(
        &[
            ("tokens-limit", "100"),
            ("tokens-remaining", "0"),
            ("tokens-reset", &reset_in(200)),
            ("requests-remaining", "40"),
        ],
        Some("45"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let line = &instance.events("quota_classified")[1];
    assert!(
        (event_span(line, "hold_end") - 198).abs() <= 3,
        "the newer reset replaces the hold: {line}"
    );
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    // Reset-less: a later rejection only extends, never shortens.
    instance.upstream.script([reply_429_apikey(
        &[
            ("requests-limit", "50"),
            ("requests-remaining", "0"),
            ("tokens-remaining", "40"),
        ],
        Some("30"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let first = &instance.events("quota_classified")[2];
    assert!((event_span(first, "hold_end") - 30).abs() <= 2, "{first}");
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    instance.upstream.script([reply_429_apikey(
        &[
            ("requests-limit", "50"),
            ("requests-remaining", "0"),
            ("tokens-remaining", "40"),
        ],
        Some("15"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let second = &instance.events("quota_classified")[3];
    let shortened = event_span(second, "hold_end");
    assert!(
        shortened > 25 && shortened < 31,
        "the 15 s rejection did not shorten the running hold: {second}"
    );
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    instance.upstream.script([reply_429_apikey(
        &[
            ("requests-limit", "50"),
            ("requests-remaining", "0"),
            ("tokens-remaining", "40"),
        ],
        Some("90"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    let third = &instance.events("quota_classified")[4];
    assert!(
        (event_span(third, "hold_end") - 88).abs() <= 3,
        "a later end extends the hold: {third}"
    );
}

/// A throttle leaves the bucket observations unchanged, holds
/// the account's admission account-wide, exercises the 1…300 s clamp and
/// extends only.
#[tokio::test(flavor = "multi_thread")]
async fn throttle_leaves_buckets_unchanged_and_extends_only() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "throttle-leaves-buckets",
        Setup {
            data_plane: "throttle_absorb_seconds = 1\n".into(),
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance
        .upstream
        .script([reply_teaching_weekly("0.50", "2099-01-01T00:00:00Z")]);
    send(instance.addr, messages(haiku_prompt())).await;

    // Minimum clamp: retry-after 0 → a 1 s hold; with the absorb bound at 1 s
    // the exchange absorbs it and retries, then it clears naturally
    // at its end.
    instance
        .upstream
        .script([reply_throttle_429(Some(0)), reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "absorbed and retried");
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(
        instance.account("FSUB")["quota_holds"]["throttle_hold_end"].is_null(),
        "the hold ended naturally"
    );

    instance.upstream.script([reply_throttle_429(Some(120))]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let hold = instance.account("FSUB")["quota_holds"]["throttle_hold_end"]
        .as_str()
        .expect("hold end")
        .to_string();
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let end = crate_time(&hold);
    assert!((end - started - 119).abs() <= 3, "hold ≈ 120 s: {hold}");

    // A later throttle received during the hold never shortens it.
    // The throttle hold does not exclude from selection, so the send
    // waits at admission; after the floor the pool releases one
    // waiting attempt as the revalidation request, and its
    // throttle 60 must not shorten the running 120 s hold.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    instance.upstream.script([reply_throttle_429(Some(60))]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "relayed");
    assert_eq!(instance.events("revalidation_started").len(), 1);
    let end = crate_time(
        instance.account("FSUB")["quota_holds"]["throttle_hold_end"]
            .as_str()
            .expect("still held"),
    );
    assert!((end - started - 119).abs() <= 4, "not shortened: {end}");

    // A longer one extends, clamped to 300 s (the 1…300) — again through
    // the released revalidation attempt, 2 s after the last one.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    instance.upstream.script([reply_throttle_429(Some(600))]);
    send(instance.addr, messages(haiku_prompt())).await;
    let end = crate_time(
        instance.account("FSUB")["quota_holds"]["throttle_hold_end"]
            .as_str()
            .expect("still held"),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    assert!((end - now - 300).abs() <= 4, "clamped extension: {end}");

    // The released revalidation's 200 ends the pause at
    // once, and the log carries the end as it carried the start — the
    // natural end of the first, absorbed hold before it.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "the revalidation's 200");
    assert!(instance.account("FSUB")["quota_holds"]["throttle_hold_end"].is_null());
    let ended = instance.events("account_pause_ended");
    assert_eq!(ended.len(), 2, "{ended:?}");
    assert_eq!(ended[0]["fields"]["cause"], "hold_elapsed");
    assert_eq!(ended[1]["fields"]["cause"], "revalidation");
    assert_eq!(ended[1]["fields"]["acct"], "FSUB");
    assert_eq!(
        instance.events("account_paused").len(),
        3,
        "0, 120 and the 600 extension; the 60 that did not extend logs no start"
    );

    // Buckets untouched by classification, account still eligible.
    let weekly = instance.account("FSUB")["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["utilisation"], 0.50);
    assert_eq!(weekly["state"], "available");
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], true);
}

/// At the reset the bucket is unknown again, before the next
/// status snapshot and the next selection.
#[tokio::test(flavor = "multi_thread")]
async fn reset_expiry_leaves_the_bucket_unknown() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("reset-expiry-leaves-bucket").await;
    instance.add_fsub();
    exhaust_fsub_until(&instance, 2).await;

    tokio::time::sleep(Duration::from_millis(2_600)).await;
    let weekly = instance.account("FSUB")["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["state"], "unknown");
    assert_eq!(weekly["utilisation"], Value::Null);
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], true);

    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(2);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
    assert_eq!(record["selection_cause"], "default");
}

/// A newer observation with headroom clears an exhaustion hold
/// early; a successful headerless revalidation also clears it and leaves the
/// bucket unknown.
#[tokio::test(flavor = "multi_thread")]
async fn headroom_clears_hold_and_headerless_revalidation_leaves_unknown() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "headroom-clears-hold",
        Setup {
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    exhaust_fsub_until(&instance, 3_600).await;
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("3000"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "held now");
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], false);

    // Headroom clears the hold before its prior end.
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    instance
        .upstream
        .script([reply_teaching_weekly("0.10", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "revalidated with headroom");
    let weekly = instance.account("FSUB")["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["state"], "available");
    assert_eq!(weekly["utilisation"], 0.10);
    assert_eq!(weekly["hold_end"], Value::Null);

    // Exhaust again, then a headerless revalidation: hold cleared, bucket unknown.
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "0.12"),
            ("5h-status", "allowed"),
            ("7d-utilization", "1.0"),
            ("7d-status", "rejected"),
        ],
        Some("3000"),
    )]);
    send(instance.addr, messages(haiku_prompt())).await;
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "the revalidation served");
    let record = instance.last_record(5);
    assert_eq!(record["selection_cause"], "revalidation");
    let weekly = instance.account("FSUB")["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["state"], "unknown", "no observation, no hold");
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], true);
}

/// A threshold-only exclusion yields a revalidation candidate at
/// once; a held account waits out the configured floor first.
#[tokio::test(flavor = "multi_thread")]
async fn threshold_only_candidate_is_immediate_held_waits_the_floor() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "threshold-candidate-immediate",
        Setup {
            quota: "revalidation_floor_seconds = 6\nrevalidation_interval_seconds = 2\n".into(),
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
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "threshold-only → candidate now"
    );
    let record = instance.last_record(3);
    assert_eq!(record["selection_cause"], "revalidation");

    // Held: the floor after the last 429 must pass before a candidate. Both
    // holds arrive through revalidation attempts (pins to over-threshold
    // accounts are refused before any attempt), 2 s apart — the gate's own
    // cadence. FSUB first (its observation is the older), then FSUB2.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "0.99"),
            ("7d-status", "allowed"),
        ],
        Some("90"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "FSUB held");
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    instance.upstream.script([reply_429_unified(
        &[
            ("5h-utilization", "1.0"),
            ("5h-status", "rejected"),
            ("7d-utilization", "0.99"),
            ("7d-status", "allowed"),
        ],
        Some("90"),
    )]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "FSUB2 held");

    // With the floor at 6 s both anchors are still inside it when the gate
    // reopens: nobody, and no candidate.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "both held and inside the floor: nobody"
    );
    assert_eq!(instance.upstream.calls(), calls, "no candidate yet");

    // Past the floor the older-observed account is challenged and serves.
    tokio::time::sleep(Duration::from_millis(3_000)).await;
    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(7);
    assert_eq!(record["selection_cause"], "revalidation");
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
}

/// The candidate ranking: lowest utilisation first, then the
/// oldest observation, without regard to pool order. The
/// stable-reference tie break is unit-tested beside `candidate_rank`.
#[tokio::test(flavor = "multi_thread")]
async fn revalidation_ranking_by_utilisation_then_age() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("revalidation-ranking-utilisation").await;
    add_two(&instance);
    instance.add_oauth("FSUB3", "fsub3@fixture.invalid", FSUB3_UUID);

    // FSUB2 observed first, FSUB3 last; FSUB has the lowest utilisation.
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    instance
        .upstream
        .script([reply_teaching_weekly("0.98", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    instance
        .upstream
        .script([reply_teaching_weekly("0.98", "2099-01-01T00:00:00Z")]);
    send(instance.addr, pinned(messages(haiku_prompt()), "FSUB3")).await;

    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let record = instance.last_record(4);
    assert_eq!(record["selection_cause"], "revalidation");
    assert_eq!(
        record["serving_account"]["display_name"], "FSUB",
        "lowest utilisation, then the older observation"
    );
    assert_eq!(instance.events("revalidation_started").len(), 1);
}

/// Twenty concurrent callers share one revalidation gate: one
/// attempt, one log line, the rest refused; the next candidate after the
/// interval.
#[tokio::test(flavor = "multi_thread")]
async fn twenty_concurrent_callers_share_one_gate() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "twenty-concurrent-callers",
        Setup {
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 3\n".into(),
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

    // The candidate's answer keeps the accounts over the threshold, so the
    // remaining callers cannot be served either.
    let before = instance.upstream.calls();
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answers = tokio::time::timeout(
        Duration::from_secs(20),
        futures_join((0..20).map(|_| {
            let addr = instance.addr;
            async move { send(addr, messages(haiku_prompt())).await }
        })),
    )
    .await
    .expect("the burst finishes");
    let statuses: Vec<u16> = answers.iter().map(|a| a.status.as_u16()).collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        1,
        "exactly one revalidation attempt served a caller: {statuses:?}"
    );
    assert_eq!(statuses.iter().filter(|s| **s == 429).count(), 19);
    let burst = instance.upstream.calls();
    assert_eq!(burst - before, 1, "one attempt");
    assert_eq!(instance.events("revalidation_started").len(), 1);

    tokio::time::sleep(Duration::from_millis(3_300)).await;
    instance
        .upstream
        .script([reply_teaching_weekly("0.99", "2099-01-01T00:00:00Z")]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.events("revalidation_started").len(), 2);
}

/// Run several futures to completion together.
async fn futures_join(
    futures: impl IntoIterator<Item = impl std::future::Future<Output = Answer> + Send + 'static>,
) -> Vec<Answer> {
    let futures: Vec<_> = futures.into_iter().collect();
    let mut handles = Vec::with_capacity(futures.len());
    for future in futures {
        handles.push(tokio::spawn(future));
    }
    let mut answers = Vec::with_capacity(handles.len());
    for handle in handles {
        answers.push(handle.await.expect("joined"));
    }
    answers
}

/// A revalidation's 200 clears the hold; another 429 re-arms it
/// and restarts the floor; a network failure preserves every quota fact and
/// still consumes the gate interval.
#[tokio::test(flavor = "multi_thread")]
async fn revalidation_200_clears_429_rearms_network_preserves() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "revalidation-200-clears",
        Setup {
            quota: "revalidation_floor_seconds = 2\nrevalidation_interval_seconds = 2\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();

    // Hold FSUB with a real 429, then a revalidation's 200 clears
    // it and the account returns to ordinary consideration.
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
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "held");

    // 200 clears.
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    instance.upstream.script([reply_headerless_200()]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.account("FSUB")["eligibility"]["eligible"], true);

    // Re-exhaust, then a revalidation 429 re-arms the hold.
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
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "held again");
    tokio::time::sleep(Duration::from_millis(2_300)).await;
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
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "re-armed");
    let lines = instance.events("quota_classified");
    assert_eq!(lines.len(), 3, "the revalidation was reclassified");
    tokio::time::sleep(Duration::from_millis(2_300)).await;

    // A network failure preserves the facts and consumes the gate.
    instance
        .upstream
        .script([Reply::ResetBeforeHeaders, Reply::ResetBeforeHeaders]);
    let outcome = try_send(instance.addr, messages(haiku_prompt())).await;
    assert!(outcome.is_err(), "the closed connection is the answer");
    let lines = instance.events("quota_classified");
    assert_eq!(lines.len(), 3, "no classification for a network failure");
    let weekly = instance.account("FSUB")["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "weekly")
        .expect("weekly")
        .clone();
    assert_eq!(weekly["state"], "exhausted", "facts preserved");
    assert_eq!(weekly["utilisation"], 1.0);

    // The interval was spent: the immediate next caller gets nobody.
    let calls = instance.upstream.calls();
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls);
}

// ------------------------------------------------------------------ step 9: quota persistence and status

/// Persisted quota stays with the stable account identity when
/// account order is reversed; quota records contain no credential material.
#[tokio::test(flavor = "multi_thread")]
async fn persisted_quota_follows_identity_not_array_order() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("persisted-quota-follows").await;
    instance.add_fsub();
    instance.add_fkey();

    instance
        .upstream
        .script([reply_teaching_weekly("0.22", "2099-01-01T00:00:00Z")]);
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FSUB"))
            .await
            .status,
        StatusCode::OK
    );
    instance.upstream.script([reply_teaching_apikey(&[
        ("requests-limit", "100"),
        ("requests-remaining", "25"),
        ("requests-reset", "2099-01-01T00:00:00Z"),
    ])]);
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FKEY"))
            .await
            .status,
        StatusCode::OK
    );
    instance.settle();

    let state = instance.state_file();
    let quota_only = json!({
        "accounts": state["accounts"]
            .as_array()
            .expect("accounts")
            .iter()
            .map(|account| account["quota"].clone())
            .collect::<Vec<_>>(),
        "organizations": state["organization_quota"],
    })
    .to_string();
    for secret in instance.needles.all() {
        assert!(!quota_only.contains(secret), "quota persisted a credential");
    }

    instance.restart_with_state(|state| {
        state["accounts"]
            .as_array_mut()
            .expect("accounts")
            .reverse();
    });

    assert_eq!(
        bucket(&instance.account("FSUB"), "weekly")["utilisation"],
        0.22
    );
    assert_eq!(
        bucket(&instance.account("FKEY"), "requests")["utilisation"],
        0.75
    );
}

/// A clean stop flushes a fresh header observation, while a
/// request and token-count update by itself schedules no state write.
// The clean stop is SIGTERM; the harness can only kill a Windows server.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn clean_stop_flushes_quota_but_counters_do_not_write() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("clean-stop-flushes").await;
    instance.add_fsub();
    instance.settle();

    instance
        .upstream
        .script([reply_teaching_weekly("0.64", "2099-01-01T00:00:00Z")]);
    assert_eq!(
        send(instance.addr, messages(haiku_prompt())).await.status,
        StatusCode::OK
    );
    instance.stop();
    instance.respawn();
    assert_eq!(
        bucket(&instance.account("FSUB"), "weekly")["utilisation"],
        0.64,
        "the final flush survived restart"
    );

    let before = instance.state_digest();
    instance.upstream.script([reply_headerless_200()]);
    assert_eq!(
        send(instance.addr, messages(haiku_prompt())).await.status,
        StatusCode::OK
    );
    instance.settle();
    assert_eq!(
        instance.state_digest(),
        before,
        "traffic counters alone do not dirty state"
    );
    assert_eq!(instance.account("FSUB")["usage"]["requests"], 1);
}

/// A restored bucket whose reset is already past is unknown in
/// the first snapshot and the expired form is scheduled back to state.
#[tokio::test(flavor = "multi_thread")]
async fn restored_past_reset_is_unknown_immediately() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("restored-past-reset").await;
    instance.add_fsub();
    instance.restart_with_state(|state| {
        let account = &mut state["accounts"][0];
        let weekly = account["quota"]
            .as_array_mut()
            .expect("quota")
            .iter_mut()
            .find(|bucket| bucket["name"] == "weekly")
            .expect("weekly");
        weekly["utilization"] = json!(1.0);
        weekly["status"] = json!("rejected");
        weekly["reset_at"] = json!("2000-01-01T00:00:00Z");
        weekly["observed_at"] = json!("1999-12-31T23:59:59Z");
        weekly["source"] = json!("response-headers");
        weekly["exhaustion_hold_until"] = json!("2099-01-01T00:00:00Z");
    });

    let account = instance.account("FSUB");
    let weekly = bucket(&account, "weekly");
    assert_eq!(weekly["state"], "unknown");
    assert!(weekly["utilisation"].is_null());
    assert!(weekly["reset_at"].is_null());

    instance.settle();
    let state = instance.state_file();
    let persisted = state["accounts"][0]["quota"]
        .as_array()
        .expect("quota")
        .iter()
        .find(|bucket| bucket["name"] == "weekly")
        .expect("weekly");
    assert!(persisted["reset_at"].is_null());
    assert!(persisted["observed_at"].is_null());
}

/// Restart retains reset-backed exhaustion but clears throttle
/// admission, probe outcomes, and scheduler timestamps.
#[tokio::test(flavor = "multi_thread")]
async fn restart_keeps_durable_quota_and_clears_runtime_state() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start("restart-keeps-durable").await;
    instance.add_fsub();
    instance.add_fkey();

    instance.upstream.script([reply_exhausted_429(90)]);
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FSUB"))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    instance.upstream.script([reply_throttle_429(Some(300))]);
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FKEY"))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    instance
        .upstream
        .script_usage([Reply::status(500, "probe failed")]);
    let probe = instance.cli_json(&["probe", "--wait"], None);
    assert_eq!(probe["ok"], true, "{probe}");
    assert_eq!(instance.account("FSUB")["probe"]["outcome"], "failed");
    assert!(instance.account("FKEY")["quota_holds"]["throttle_hold_end"].is_string());

    // Windows stops the server with a kill, which skips the shutdown flush.
    #[cfg(not(unix))]
    await_persisted_hold(&instance, "FSUB", "weekly");
    instance.restart();

    assert_eq!(
        bucket(&instance.account("FSUB"), "weekly")["state"],
        "exhausted"
    );
    assert_eq!(instance.account("FKEY")["eligibility"]["eligible"], true);
    assert!(instance.account("FKEY")["quota_holds"]["throttle_hold_end"].is_null());
    assert!(instance.account("FSUB")["probe"]["outcome"].is_null());
    let status = instance.status();
    let probe = &status["usage_probe"];
    assert!(probe["last_started"].is_null());
    assert!(probe["last_finished"].is_null());
    assert!(probe["next_run"].is_null());
}

/// Waits for the quota flusher to write the bucket's exhaustion hold.
#[cfg(not(unix))]
fn await_persisted_hold(instance: &Instance, account: &str, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state = instance.state_file();
        let held = state["accounts"]
            .as_array()
            .expect("state accounts")
            .iter()
            .filter(|a| a["display_name"] == account)
            .flat_map(|a| a["quota"].as_array().expect("quota"))
            .any(|b| b["name"] == name && b["exhaustion_hold_until"].is_string());
        if held {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{account}'s {name} hold was never persisted: {state}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One snapshot distinguishes unknown, available, exhausted,
/// throttle-held, and a failed probe.
#[tokio::test(flavor = "multi_thread")]
async fn status_distinguishes_every_quota_state() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_with(
        "status-distinguishes-quota",
        Setup {
            quota: "revalidation_floor_seconds = 60\n".into(),
            ..Setup::default()
        },
    )
    .await;
    instance.add_fsub();
    instance.add_oauth(
        "FSUB2",
        "second@fixture.invalid",
        "3c1f5a7e-0000-4000-8000-0000000000b2",
    );
    instance.add_fkey();
    instance
        .upstream
        .script_usage([reply_usage("25", "40"), Reply::status(500, "probe failed")]);
    let probe = instance.cli_json(&["probe", "--wait"], None);
    assert_eq!(probe["ok"], true, "{probe}");

    instance.upstream.script([reply_exhausted_429(90)]);
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2"))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    instance.upstream.script([reply_throttle_429(Some(300))]);
    assert_eq!(
        send(instance.addr, pinned(messages(haiku_prompt()), "FKEY"))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    instance.add_oauth(
        "FSUB3",
        "third@fixture.invalid",
        "3c1f5a7e-0000-4000-8000-0000000000b3",
    );

    let available = instance.account("FSUB");
    let exhausted = instance.account("FSUB2");
    let throttled = instance.account("FKEY");
    let unknown = instance.account("FSUB3");
    assert_eq!(bucket(&available, "session")["state"], "available");
    assert_eq!(
        available["quota_holds"],
        json!({ "throttle_hold_end": null, "revalidation_allowed": true }),
        "nothing to challenge: revalidation is not withheld"
    );
    assert_eq!(bucket(&exhausted, "weekly")["state"], "exhausted");
    assert_eq!(exhausted["eligibility"]["reason"], "held");
    assert_eq!(exhausted["probe"]["outcome"], "failed");
    assert!(exhausted["probe"]["error"].is_string());
    // The throttle hold shows as such; the account stays
    // eligible, and inside the floor since its 429 no revalidation may go.
    assert!(throttled["quota_holds"]["throttle_hold_end"].is_string());
    assert_eq!(throttled["quota_holds"]["revalidation_allowed"], false);
    assert_eq!(throttled["eligibility"]["eligible"], true);
    assert_eq!(throttled["eligibility"]["reason"], Value::Null);
    assert_eq!(bucket(&unknown, "session")["state"], "unknown");
    assert_eq!(bucket(&unknown, "session")["utilisation"], Value::Null);
}

// ------------------------------------------------------------------ step 10: the bucket model in status

/// Every member of one bucket, so an absent fact is an explicit null.
fn assert_bucket_unknown(bucket: &Value, scope: &str) {
    assert_eq!(bucket["scope"], scope, "{bucket}");
    assert_eq!(bucket["state"], "unknown", "{bucket}");
    for field in [
        "utilisation",
        "limit",
        "remaining",
        "reset",
        "hold_end",
        "observed_at",
        "observed_source",
    ] {
        assert_eq!(bucket[field], Value::Null, "{field} of {bucket}");
    }
}

/// Fresh subscription and API-key accounts expose exactly the
/// fixed expected buckets, every one `unknown` with null facts, and the
/// unknowns make nobody exhausted.
#[tokio::test(flavor = "multi_thread")]
async fn fresh_accounts_expose_the_expected_buckets_as_unknown() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("fresh-accounts-expose").await;
    instance.add_fsub();
    instance.add_fkey();

    let fsub = instance.account("FSUB");
    let names: Vec<&str> = fsub["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .map(|b| b["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["session", "weekly"], "the subscription set");
    for name in names {
        assert_bucket_unknown(bucket(&fsub, name), "account");
    }
    assert_eq!(fsub["eligibility"]["eligible"], true, "");

    let fkey = instance.account("FKEY");
    let names: Vec<&str> = fkey["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .map(|b| b["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        ["requests", "tokens", "input-tokens", "output-tokens"],
        "the API-key set"
    );
    for name in names {
        assert_bucket_unknown(bucket(&fkey, name), "account");
    }
    assert_eq!(fkey["eligibility"]["eligible"], true, "");

    // The human rendering says unknown, never 0%.
    let (code, human, _) = instance.cli(&["status", "--accounts"], None);
    assert_eq!(code, 0);
    for name in [
        "session",
        "weekly",
        "requests",
        "tokens",
        "input-tokens",
        "output-tokens",
    ] {
        let line = human
            .lines()
            .find(|line| line.split_whitespace().next() == Some(name))
            .unwrap_or_else(|| panic!("no {name} bar: {human}"));
        assert!(line.ends_with("unknown"), "{name}: {line}");
    }
    assert!(!human.contains('%'), "{human}");
}

/// Once a family bucket is present, a model of that family is
/// governed by it while another model keeps the shared weekly window.
#[tokio::test(flavor = "multi_thread")]
async fn a_family_bucket_governs_its_models_only() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("family-bucket-governs").await;
    instance.add_fsub();

    // teaches the mapping on the fable response: `weekly:fable` at the
    // threshold, the shared weekly at 0.03.
    instance
        .upstream
        .script([reply_teaching_family("0.98", "allowed")]);
    let answer = send(instance.addr, messages(prompt_for("claude-fable-5-1"))).await;
    assert_eq!(answer.status, StatusCode::OK);
    let fsub = instance.account("FSUB");
    let family = bucket(&fsub, "weekly:fable");
    assert_eq!(family["scope"], "family");
    assert_eq!(family["utilisation"], 0.98);
    assert_eq!(bucket(&fsub, "weekly")["utilisation"], 0.03);

    // The family's model is barred by its bucket: no attempt.
    let calls = instance.upstream.calls();
    let answer = send(
        instance.addr,
        pinned(messages(prompt_for("claude-fable-5-1")), "FSUB"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(instance.upstream.calls(), calls, "governed by weekly:fable");

    // Another model is governed by `weekly` instead: served.
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(instance.upstream.calls(), calls + 1);
    let record = instance.last_record(3);
    assert_eq!(record["serving_account"]["display_name"], "FSUB");
}

/// An API-key response supplying four different resets keeps
/// all four independently; a later response touching one counter leaves the
/// other three resets alone.
#[tokio::test(flavor = "multi_thread")]
async fn four_api_key_resets_survive_independently() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("four-api-key-resets").await;
    instance.add_fkey();

    let resets = [
        ("requests", "2098-01-01T00:00:00Z"),
        ("tokens", "2098-02-01T00:00:00Z"),
        ("input-tokens", "2098-03-01T00:00:00Z"),
        ("output-tokens", "2098-04-01T00:00:00Z"),
    ];
    let mut fields = Vec::new();
    for (name, reset) in resets {
        fields.push((format!("{name}-limit"), "1000".to_string()));
        fields.push((format!("{name}-remaining"), "900".to_string()));
        fields.push((format!("{name}-reset"), reset.to_string()));
    }
    let borrowed: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    instance.upstream.script([reply_teaching_apikey(&borrowed)]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let fkey = instance.account("FKEY");
    for (name, reset) in resets {
        let b = bucket(&fkey, name);
        assert_eq!(b["reset"], reset, "{name}");
        assert_eq!(b["limit"], 1000.0);
        assert_eq!(b["remaining"], 900.0);
        assert_eq!(b["state"], "available");
        assert!((b["utilisation"].as_f64().expect("utilisation") - 0.1).abs() < 1e-9);
    }

    // One counter moves; the other three windows keep their own resets.
    instance.upstream.script([reply_teaching_apikey(&[
        ("tokens-limit", "1000"),
        ("tokens-remaining", "500"),
        ("tokens-reset", "2098-02-02T00:00:00Z"),
    ])]);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK);
    let fkey = instance.account("FKEY");
    assert_eq!(bucket(&fkey, "tokens")["reset"], "2098-02-02T00:00:00Z");
    assert_eq!(bucket(&fkey, "tokens")["remaining"], 500.0);
    assert_eq!(bucket(&fkey, "requests")["reset"], "2098-01-01T00:00:00Z");
    assert_eq!(
        bucket(&fkey, "input-tokens")["reset"],
        "2098-03-01T00:00:00Z"
    );
    assert_eq!(
        bucket(&fkey, "output-tokens")["reset"],
        "2098-04-01T00:00:00Z"
    );
}

/// A success on A followed by a 429 on B: each observation
/// lands on its own serving account and nowhere else.
#[tokio::test(flavor = "multi_thread")]
async fn observations_land_only_on_the_serving_account() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("observations-land-serving").await;
    add_two(&instance);

    instance
        .upstream
        .script([reply_teaching_weekly("0.30", "2098-01-01T00:00:00Z")]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::OK);
    instance.upstream.script([reply_exhausted_429(90)]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB2")).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);

    let fsub = instance.account("FSUB");
    let weekly = bucket(&fsub, "weekly");
    assert_eq!(weekly["utilisation"], 0.30);
    assert_eq!(weekly["reset"], "2098-01-01T00:00:00Z");
    assert_eq!(weekly["state"], "available");
    assert_eq!(weekly["hold_end"], Value::Null, "B's 429 never reached A");
    assert_eq!(fsub["eligibility"]["eligible"], true);

    let fsub2 = instance.account("FSUB2");
    let weekly = bucket(&fsub2, "weekly");
    assert_eq!(weekly["state"], "exhausted");
    assert_eq!(weekly["utilisation"], 1.0);
    assert!(weekly["hold_end"].is_string());
    assert_eq!(
        bucket(&fsub2, "session")["utilisation"],
        0.40,
        "the 429's own headers taught B alone"
    );
    assert_eq!(fsub2["eligibility"]["reason"], "held");
}

/// Two concurrent attempts whose responses finish out of order:
/// the observation processed last is the newer and wins field by field, and
/// A malformed field in it erases nothing the earlier one supplied.
#[tokio::test(flavor = "multi_thread")]
async fn newer_observation_wins_and_malformed_fields_erase_nothing() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("newer-observation-wins").await;
    instance.add_fsub();

    // A is sent first and answered last: session 0.55, weekly utilisation
    // malformed, weekly reset R_A. B is sent second and answered first:
    // session 0.12, weekly 0.40, reset R_B.
    let gate = Arc::new(Notify::new());
    let mut late = Reply::Raw {
        status: 200,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            (
                "anthropic-ratelimit-unified-5h-utilization".into(),
                "0.55".into(),
            ),
            (
                "anthropic-ratelimit-unified-5h-status".into(),
                "allowed".into(),
            ),
            (
                "anthropic-ratelimit-unified-5h-reset".into(),
                "2098-01-01T00:00:00Z".into(),
            ),
            (
                "anthropic-ratelimit-unified-7d-utilization".into(),
                "not-a-number".into(),
            ),
            (
                "anthropic-ratelimit-unified-7d-status".into(),
                "allowed".into(),
            ),
            (
                "anthropic-ratelimit-unified-7d-reset".into(),
                "2098-06-01T00:00:00Z".into(),
            ),
        ],
        body: message_body().to_string(),
    };
    if let Reply::Raw { headers, .. } = &mut late {
        headers.retain(|(n, _)| n != "request-id");
    }
    instance.upstream.script([
        Reply::HoldThen(Arc::clone(&gate), Box::new(late)),
        reply_teaching_weekly("0.40", "2098-03-01T00:00:00Z"),
    ]);
    let addr = instance.addr;
    let first = tokio::spawn(async move { send(addr, messages(haiku_prompt())).await });
    // A must hold the first scripted reply before B is sent: the fake's call
    // count includes the profile lookup of the add, so the attempts are what
    // this waits on.
    let deadline = Instant::now() + Duration::from_secs(3);
    while instance
        .upstream
        .seen()
        .iter()
        .filter(|call| call.path == "/v1/messages")
        .count()
        < 1
    {
        assert!(
            Instant::now() < deadline,
            "the first attempt reached the fake"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = send(addr, messages(haiku_prompt())).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(
        bucket(&instance.account("FSUB"), "weekly")["utilisation"],
        0.40
    );
    gate.notify_one();
    let first = first.await.expect("join");
    assert_eq!(first.status, StatusCode::OK);

    let fsub = instance.account("FSUB");
    let session = bucket(&fsub, "session");
    let weekly = bucket(&fsub, "weekly");
    assert_eq!(session["utilisation"], 0.55, "the later observation wins");
    assert_eq!(
        weekly["reset"], "2098-06-01T00:00:00Z",
        "its valid reset replaces the older"
    );
    assert_eq!(
        weekly["utilisation"], 0.40,
        "its malformed utilisation leaves the older value"
    );
    assert_eq!(weekly["state"], "available");
}

/// A subscription utilisation of 1.01 is stored as 1.01; API-key
/// counters that are incomplete or inconsistent yield no utilisation and
/// make nothing exhausted.
#[tokio::test(flavor = "multi_thread")]
async fn over_one_is_kept_and_incomplete_counters_stay_unknown() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start("over-kept-incomplete").await;
    instance.add_fsub();
    instance.add_fkey();

    instance
        .upstream
        .script([reply_teaching_weekly("1.01", "2098-01-01T00:00:00Z")]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FSUB")).await;
    assert_eq!(answer.status, StatusCode::OK);
    let fsub = instance.account("FSUB");
    assert_eq!(bucket(&fsub, "weekly")["utilisation"], 1.01, "not clamped");
    assert_eq!(fsub["eligibility"]["reason"], "over_threshold");

    // A limit without a remaining, then a remaining above its limit: neither
    // manufactures a utilisation.
    instance.upstream.script([reply_teaching_apikey(&[
        ("tokens-limit", "100"),
        ("requests-limit", "50"),
        ("requests-remaining", "80"),
    ])]);
    let answer = send(instance.addr, pinned(messages(haiku_prompt()), "FKEY")).await;
    assert_eq!(answer.status, StatusCode::OK);
    let fkey = instance.account("FKEY");
    let tokens = bucket(&fkey, "tokens");
    assert_eq!(tokens["limit"], 100.0);
    assert_eq!(tokens["remaining"], Value::Null);
    assert_eq!(tokens["utilisation"], Value::Null);
    let requests = bucket(&fkey, "requests");
    assert_eq!(requests["remaining"], 80.0);
    assert_eq!(
        requests["utilisation"],
        Value::Null,
        "remaining above limit"
    );
    assert_eq!(fkey["eligibility"]["eligible"], true, "");
    assert_eq!(bucket(&fkey, "input-tokens")["state"], "unknown");
}
