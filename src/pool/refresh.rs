//! OAuth token-family refreshes shared by every trigger for one account.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::watch;
use uuid::Uuid;

use crate::data_plane::upstream::RefreshFailure;
use crate::pool::{Account, Credential, OAuthCredential, Secret, Stale};
use crate::server::{MutateError, Server, Stop};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Startup,
    Proactive,
    Forced,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Proactive => "proactive",
            Self::Forced => "forced",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ready,
    Errored,
    Wait { until: OffsetDateTime },
}

struct InFlight {
    started_at: OffsetDateTime,
    outcome: watch::Sender<Option<Outcome>>,
}

pub struct Operation {
    handle: Uuid,
    outcome: watch::Sender<Option<Outcome>>,
}

pub enum Join {
    Wait(watch::Receiver<Option<Outcome>>),
    Run(Operation),
}

/// The runtime registry of in-flight operations (never persisted).
#[derive(Default)]
pub struct Refreshes {
    operations: Mutex<HashMap<Uuid, InFlight>>,
}

impl Refreshes {
    pub fn join_or_start(&self, handle: Uuid, now: OffsetDateTime) -> Join {
        let mut operations = self.operations.lock().expect("refresh lock");
        if let Some(operation) = operations.get(&handle) {
            return Join::Wait(operation.outcome.subscribe());
        }
        let (outcome, _) = watch::channel(None);
        operations.insert(
            handle,
            InFlight {
                started_at: now,
                outcome: outcome.clone(),
            },
        );
        Join::Run(Operation { handle, outcome })
    }

    pub fn in_flight(&self, handle: Uuid) -> Option<OffsetDateTime> {
        self.operations
            .lock()
            .expect("refresh lock")
            .get(&handle)
            .map(|operation| operation.started_at)
    }

    fn finish(&self, operation: Operation, outcome: Outcome) {
        operation.outcome.send_replace(Some(outcome));
        self.operations
            .lock()
            .expect("refresh lock")
            .remove(&operation.handle);
    }
}

/// The OAuth refresh rules for one account. No pool lock is held across I/O.
pub async fn ensure_fresh(server: &Arc<Server>, handle: Uuid, trigger: Trigger) -> Outcome {
    let now = OffsetDateTime::now_utc();
    if let Some(outcome) = without_refresh_for(server, handle, trigger, now) {
        return outcome;
    }
    match server.refreshes.join_or_start(handle, now) {
        Join::Wait(receiver) => await_outcome(receiver).await,
        Join::Run(operation) => {
            let receiver = operation.outcome.subscribe();
            let runner = Arc::clone(server);
            tokio::spawn(async move {
                let outcome = run(&runner, handle, trigger).await;
                runner.refreshes.finish(operation, outcome);
            });
            await_outcome(receiver).await
        }
    }
}

fn without_refresh_for(
    server: &Server,
    handle: Uuid,
    trigger: Trigger,
    now: OffsetDateTime,
) -> Option<Outcome> {
    let pool = server.pool.lock().expect("pool lock");
    without_refresh(
        pool.get(handle),
        trigger,
        server.refresh_settings().refresh_margin_seconds,
        now,
    )
}

fn without_refresh(
    account: Option<&Account>,
    trigger: Trigger,
    margin_seconds: u64,
    now: OffsetDateTime,
) -> Option<Outcome> {
    let Some(account) = account else {
        return Some(Outcome::Ready);
    };
    if account.errored.is_some() {
        return Some(Outcome::Errored);
    }
    if trigger == Trigger::Startup && !account.enabled {
        return Some(Outcome::Ready);
    }
    let Credential::OAuth(family) = &account.credential else {
        return Some(Outcome::Ready);
    };
    if !needs_refresh(family, trigger, margin_seconds, now) {
        if trigger == Trigger::Forced {
            tracing::info!(event = "refresh_skipped", account = %account.display_name, why = "success_floor", "refresh skipped");
        }
        return Some(Outcome::Ready);
    }
    if family.in_transient_floor(now) {
        let until = family
            .refresh_not_before
            .expect("a transient floor has an end");
        tracing::info!(event = "refresh_skipped", account = %account.display_name, why = "transient_floor", "refresh skipped");
        return Some(if trigger == Trigger::Forced || family.is_expired(now) {
            Outcome::Wait { until }
        } else {
            Outcome::Ready
        });
    }
    None
}

fn needs_refresh(
    family: &OAuthCredential,
    trigger: Trigger,
    margin_seconds: u64,
    now: OffsetDateTime,
) -> bool {
    match trigger {
        Trigger::Forced => !family.in_success_floor(now),
        Trigger::Startup | Trigger::Proactive => family.expires_within(margin_seconds, now),
    }
}

async fn await_outcome(mut receiver: watch::Receiver<Option<Outcome>>) -> Outcome {
    loop {
        if let Some(outcome) = receiver.borrow().clone() {
            return outcome;
        }
        receiver
            .changed()
            .await
            .expect("a refresh runner publishes before it leaves");
    }
}

async fn run(server: &Arc<Server>, handle: Uuid, trigger: Trigger) -> Outcome {
    let now = OffsetDateTime::now_utc();
    if let Some(outcome) = without_refresh_for(server, handle, trigger, now) {
        return outcome;
    }
    let (provider, display_name, family) = {
        let pool = server.pool.lock().expect("pool lock");
        let Some(account) = pool.get(handle) else {
            return Outcome::Ready;
        };
        let Credential::OAuth(family) = &account.credential else {
            return Outcome::Ready;
        };
        (
            account.provider,
            account.display_name.clone(),
            family.clone(),
        )
    };
    let sent = family.refresh_token.clone();
    let Some(refresh_token) = sent.as_ref() else {
        return if trigger == Trigger::Forced || family.is_expired(now) {
            persist_errored(
                server,
                handle,
                None,
                if trigger == Trigger::Forced {
                    "upstream 401 on oauth credential".into()
                } else {
                    "access token expired and no refresh token is held".into()
                },
                now,
            )
        } else {
            Outcome::Ready
        };
    };

    tracing::info!(event = "refresh_started", account = %display_name, trigger = trigger.as_str(), "OAuth refresh started");
    let deadline = Duration::from_secs(server.refresh_settings().refresh_deadline_seconds);
    let mut call = 1;
    let result = loop {
        match server
            .upstream
            .refresh_family(provider, refresh_token, deadline)
            .await
        {
            Err(RefreshFailure::Transient(error)) => {
                let Some(delay) = retry_delay(call) else {
                    break Err(RefreshFailure::Transient(error));
                };
                tracing::warn!(event = "refresh_failed", account = %display_name, class = "transient", error, call, retry_in_ms = delay.as_millis(), "OAuth refresh failed transiently; retrying");
                tokio::time::sleep(delay).await;
                call += 1;
            }
            result => break result,
        }
    };
    match result {
        Ok(fresh) => publish_family(server, handle, &display_name, sent.as_ref(), family, fresh),
        Err(RefreshFailure::Permanent { status, code }) => {
            tracing::warn!(event = "refresh_failed", account = %display_name, class = "permanent", status = status.as_u16(), code = code.unwrap_or(""), call, "OAuth refresh rejected");
            let code = code.map(|code| format!(", {code}")).unwrap_or_default();
            persist_errored(
                server,
                handle,
                sent.as_ref(),
                format!("refresh rejected by the token endpoint (HTTP {status}{code})"),
                OffsetDateTime::now_utc(),
            )
        }
        Err(RefreshFailure::Transient(error)) => {
            let now = OffsetDateTime::now_utc();
            let until = now + TimeDuration::seconds(30);
            tracing::warn!(event = "refresh_failed", account = %display_name, class = "transient", error, call, next_allowed_at = %until, "OAuth refresh failed transiently");
            match server.mutate_pool(|pool| {
                pool.note_refresh_attempt(handle, sent.as_ref(), now)?;
                pool.set_refresh_not_before(handle, sent.as_ref(), until)
            }) {
                Ok(()) if family.is_expired(now) => Outcome::Wait { until },
                Ok(()) => Outcome::Ready,
                Err(MutateError::Refused(stale)) => {
                    discarded(&display_name, stale);
                    Outcome::Ready
                }
                Err(error @ MutateError::Persist(_)) => {
                    state_write_failed(server, error);
                    Outcome::Wait { until }
                }
            }
        }
    }
}

fn retry_delay(failed_call: usize) -> Option<Duration> {
    match failed_call {
        1 => Some(Duration::from_millis(500)),
        2 => Some(Duration::from_secs(1)),
        _ => None,
    }
}

fn publish_family(
    server: &Server,
    handle: Uuid,
    display_name: &str,
    sent: Option<&Secret>,
    old: OAuthCredential,
    fresh: OAuthCredential,
) -> Outcome {
    let now = OffsetDateTime::now_utc();
    let family = old.replaced_by(fresh, now);
    let rotated =
        old.access_token != family.access_token || old.refresh_token != family.refresh_token;
    let expires_at = family.expires_at;
    match server.mutate_pool(|pool| pool.replace_family(handle, sent, family)) {
        Ok(()) => {
            tracing::info!(event = "refresh_succeeded", account = %display_name, rotated, expires_at = %expires_at, "OAuth refresh succeeded");
            Outcome::Ready
        }
        Err(MutateError::Refused(stale)) => {
            discarded(display_name, stale);
            Outcome::Ready
        }
        Err(error @ MutateError::Persist(_)) => {
            state_write_failed(server, error);
            Outcome::Wait {
                until: now + TimeDuration::seconds(30),
            }
        }
    }
}

fn persist_errored(
    server: &Server,
    handle: Uuid,
    sent: Option<&Secret>,
    reason: String,
    now: OffsetDateTime,
) -> Outcome {
    match server.mutate_pool(|pool| pool.mark_refresh_errored(handle, sent, reason, now)) {
        Ok(()) => Outcome::Errored,
        Err(MutateError::Refused(stale)) => {
            let display_name = server
                .pool
                .lock()
                .expect("pool lock")
                .get(handle)
                .map_or_else(
                    || handle.to_string(),
                    |account| account.display_name.clone(),
                );
            discarded(&display_name, stale);
            Outcome::Ready
        }
        Err(error @ MutateError::Persist(_)) => {
            state_write_failed(server, error);
            Outcome::Wait {
                until: now + TimeDuration::seconds(30),
            }
        }
    }
}

fn discarded(display_name: &str, stale: Stale) {
    let why = match stale {
        Stale::AccountRemoved => "account_removed",
        Stale::FamilyReplaced => "family_replaced",
    };
    tracing::info!(event = "refresh_discarded", account = %display_name, why, "discarded refresh result because the account changed");
}

fn state_write_failed<E: std::fmt::Debug>(server: &Server, error: MutateError<E>) {
    tracing::error!(event = "state_write_failed", error = ?error, "could not persist OAuth refresh state; stopping");
    server.request_stop(Stop::Unwritable);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use serde_json::json;
    use time::macros::datetime;
    use tokio::sync::Notify;

    use super::*;

    fn family(now: OffsetDateTime) -> OAuthCredential {
        OAuthCredential {
            access_token: Secret::new("access".into()),
            refresh_token: Some(Secret::new("refresh".into())),
            expires_at: now + TimeDuration::hours(1),
            last_refresh_attempt_at: None,
            last_refresh_success_at: None,
            refresh_not_before: None,
        }
    }

    fn account(now: OffsetDateTime) -> Account {
        Account::new(
            crate::provider::Provider::Anthropic,
            "FSUB".into(),
            crate::pool::Profile::default(),
            crate::pool::Source::PortableJson,
            Credential::OAuth(family(now)),
        )
    }

    /// One token endpoint that announces the call, then answers after `delay`,
    /// so the test can mutate the pool while the operation is in flight.
    async fn token_responder(delay: std::time::Duration) -> (std::net::SocketAddr, Arc<Notify>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("responder bind");
        let addr = listener.local_addr().expect("responder address");
        let hit = Arc::new(Notify::new());
        let handler_hit = Arc::clone(&hit);
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let service = service_fn(move |_request| {
                let hit = Arc::clone(&handler_hit);
                async move {
                    hit.notify_one();
                    tokio::time::sleep(delay).await;
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(
                        json!({
                            "access_token": "rotated-access",
                            "refresh_token": "rotated-refresh",
                            "expires_in": 3600,
                        })
                        .to_string(),
                    ))))
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        (addr, hit)
    }

    /// A server whose one OAuth account's token call is answered by a local
    /// responder after a delay; `hit` fires when the call reached it.
    async fn stale_run_fixture() -> (Arc<Server>, Uuid, Arc<Notify>) {
        let (addr, hit) = token_responder(std::time::Duration::from_millis(300)).await;
        let server = Arc::new(Server::for_tests(addr));
        let handle = {
            let mut pool = server.pool.lock().expect("pool lock");
            pool.add(account(OffsetDateTime::now_utc()), None)
                .expect("the fixture account is new")
        };
        (server, handle, hit)
    }

    /// The operator wins; the operation reports Ready
    /// after one `refresh_discarded` line and writes nothing.
    #[tokio::test]
    async fn run_discards_the_result_when_the_family_was_replaced_under_it() {
        let (server, handle, hit) = stale_run_fixture().await;
        let sent = Secret::new("refresh".into());
        let runner = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { run(&server, handle, Trigger::Forced).await })
        };

        hit.notified().await;
        let mut installed = family(OffsetDateTime::now_utc());
        installed.access_token = Secret::new("operator-access".into());
        installed.refresh_token = Some(Secret::new("operator-refresh".into()));
        server
            .pool
            .lock()
            .expect("pool lock")
            .replace_family(handle, Some(&sent), installed.clone())
            .expect("the operator replacement applies");

        assert_eq!(runner.await.expect("the run finishes"), Outcome::Ready);
        let pool = server.pool.lock().expect("pool lock");
        assert_eq!(
            pool.get(handle).expect("still there").credential,
            Credential::OAuth(installed),
            "the rotated family never overwrote the operator's"
        );
    }

    #[tokio::test]
    async fn run_discards_the_result_when_the_account_was_removed_under_it() {
        let (server, handle, hit) = stale_run_fixture().await;
        let runner = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { run(&server, handle, Trigger::Forced).await })
        };

        hit.notified().await;
        server.pool.lock().expect("pool lock").remove(handle);

        assert_eq!(runner.await.expect("the run finishes"), Outcome::Ready);
        assert!(
            server.pool.lock().expect("pool lock").accounts().is_empty(),
            "removal is never resurrected"
        );
    }

    #[test]
    fn startup_refresh_gate_covers_enabled_disabled_and_errored_accounts() {
        let now = datetime!(2026-09-17 00:00 UTC);
        let mut account = account(now);
        let Credential::OAuth(family) = &mut account.credential else {
            panic!("OAuth fixture")
        };
        family.expires_at = now + TimeDuration::seconds(300);

        assert_eq!(
            without_refresh(Some(&account), Trigger::Startup, 300, now),
            None
        );

        account.enabled = false;
        assert_eq!(
            without_refresh(Some(&account), Trigger::Startup, 300, now),
            Some(Outcome::Ready)
        );

        account.enabled = true;
        account.errored = Some(crate::pool::Errored {
            reason: "operator action required".into(),
            at: now,
        });
        assert_eq!(
            without_refresh(Some(&account), Trigger::Startup, 300, now),
            Some(Outcome::Errored)
        );
    }

    #[test]
    fn refresh_need_obeys_margin_and_forced_success_floor() {
        let now = datetime!(2026-09-17 00:00 UTC);
        let mut family = family(now);

        assert!(!needs_refresh(&family, Trigger::Proactive, 300, now));
        family.expires_at = now + TimeDuration::seconds(300);
        assert!(needs_refresh(&family, Trigger::Proactive, 300, now));
        assert!(needs_refresh(&family, Trigger::Forced, 300, now));

        family.last_refresh_success_at = Some(now);
        assert!(!needs_refresh(&family, Trigger::Forced, 300, now));
        family.last_refresh_success_at = Some(now - TimeDuration::seconds(10));
        assert!(needs_refresh(&family, Trigger::Forced, 300, now));
    }

    #[test]
    fn transient_retry_schedule_has_two_delays() {
        assert_eq!(retry_delay(1), Some(Duration::from_millis(500)));
        assert_eq!(retry_delay(2), Some(Duration::from_secs(1)));
        assert_eq!(retry_delay(3), None);
    }

    #[tokio::test]
    async fn concurrent_joiners_share_one_run_and_leave_no_entry() {
        let refreshes = Arc::new(Refreshes::default());
        let handle = Uuid::new_v4();
        let runs = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let now = datetime!(2026-09-17 00:00 UTC);

        let runner = {
            let refreshes = Arc::clone(&refreshes);
            let runs = Arc::clone(&runs);
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            tokio::spawn(async move {
                let Join::Run(operation) = refreshes.join_or_start(handle, now) else {
                    panic!("first task runs")
                };
                let receiver = operation.outcome.subscribe();
                runs.fetch_add(1, Ordering::Relaxed);
                started.notify_one();
                release.notified().await;
                refreshes.finish(operation, Outcome::Ready);
                await_outcome(receiver).await
            })
        };
        started.notified().await;
        let joiner = {
            let refreshes = Arc::clone(&refreshes);
            tokio::spawn(async move {
                let Join::Wait(receiver) = refreshes.join_or_start(handle, now) else {
                    panic!("second task waits")
                };
                await_outcome(receiver).await
            })
        };
        release.notify_one();

        assert_eq!(runner.await.expect("runner"), Outcome::Ready);
        assert_eq!(joiner.await.expect("joiner"), Outcome::Ready);
        assert_eq!(runs.load(Ordering::Relaxed), 1);
        assert_eq!(refreshes.in_flight(handle), None);
    }
}
