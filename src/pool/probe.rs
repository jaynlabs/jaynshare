//! Scheduled and operator-triggered OAuth usage sweeps.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::watch;
use uuid::Uuid;

use crate::config::QuotaSettings;
use crate::data_plane::upstream::UsageFailure;
use crate::provider::Provider;
use crate::server::Server;

use super::refresh::{self, Outcome as RefreshOutcome, Trigger as RefreshTrigger};
use super::{Account, Credential, Kind};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Updated,
    NotApplicable,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountOutcome {
    pub outcome: Outcome,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub last_started: Option<OffsetDateTime>,
    pub last_finished: Option<OffsetDateTime>,
    pub next_run: Option<OffsetDateTime>,
    pub outcomes: HashMap<Uuid, AccountOutcome>,
}

#[derive(Default)]
struct State {
    running: bool,
    last_started: Option<OffsetDateTime>,
    last_finished: Option<OffsetDateTime>,
    next_run: Option<OffsetDateTime>,
    outcomes: HashMap<Uuid, AccountOutcome>,
}

pub struct Probes {
    state: Mutex<State>,
    schedule: watch::Sender<Schedule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Schedule {
    enabled: bool,
    interval_seconds: u64,
}

impl From<&QuotaSettings> for Schedule {
    fn from(settings: &QuotaSettings) -> Self {
        Self {
            enabled: settings.probe_enabled,
            interval_seconds: settings.probe_interval_seconds,
        }
    }
}

impl Probes {
    pub fn new(settings: QuotaSettings) -> Self {
        let (schedule, _) = watch::channel(Schedule::from(&settings));
        Self {
            state: Mutex::new(State::default()),
            schedule,
        }
    }

    pub fn reconfigure(&self, settings: QuotaSettings) {
        let next = Schedule::from(&settings);
        self.schedule.send_if_modified(|current| {
            if *current == next {
                false
            } else {
                *current = next;
                true
            }
        });
    }

    fn subscribe(&self) -> watch::Receiver<Schedule> {
        self.schedule.subscribe()
    }

    fn begin(&self, started_at: OffsetDateTime) -> Result<(), StartError> {
        let mut state = self.state.lock().expect("probe lock");
        if state.running {
            return Err(StartError::InProgress);
        }
        state.running = true;
        state.last_started = Some(started_at);
        Ok(())
    }

    fn account_finished(&self, handle: Uuid, outcome: AccountOutcome) {
        self.state
            .lock()
            .expect("probe lock")
            .outcomes
            .insert(handle, outcome);
    }

    fn sweep_finished(&self, finished_at: OffsetDateTime) {
        let mut state = self.state.lock().expect("probe lock");
        state.running = false;
        state.last_finished = Some(finished_at);
    }

    fn set_next_run(&self, next_run: Option<OffsetDateTime>) {
        self.state.lock().expect("probe lock").next_run = next_run;
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().expect("probe lock");
        Snapshot {
            last_started: state.last_started,
            last_finished: state.last_finished,
            next_run: state.next_run,
            outcomes: state.outcomes.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    InProgress,
}

#[derive(Debug, Clone, Copy)]
pub enum Trigger {
    Scheduled,
    Operator,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Operator => "operator",
        }
    }
}

/// Claim the server-wide sweep slot and return immediately. The
/// spawned sweep owns one configuration snapshot for all of its accounts.
pub fn trigger(server: &Arc<Server>, trigger: Trigger) -> Result<OffsetDateTime, StartError> {
    let loaded = server.config();
    let settings = loaded.config.quota.clone();
    let started_at = OffsetDateTime::now_utc();
    server.probes.begin(started_at)?;
    tracing::info!(
        event = "usage_probe_started",
        trigger = trigger.as_str(),
        "usage probe sweep started"
    );
    let runner = Arc::clone(server);
    tokio::spawn(async move { sweep(runner, settings, started_at).await });
    Ok(started_at)
}

/// Off by default, immediate on start or off→on reload,
/// periodic thereafter, and a running sweep makes a tick a no-op.
pub async fn scheduler(server: Arc<Server>) {
    let mut changes = server.probes.subscribe();
    let initial = *changes.borrow();
    let mut enabled = initial.enabled;
    let mut deadline = enabled.then(tokio::time::Instant::now);
    server
        .probes
        .set_next_run(enabled.then(OffsetDateTime::now_utc));
    let mut stop = server.stop_signal();
    loop {
        match deadline {
            Some(due) => tokio::select! {
                _ = tokio::time::sleep_until(due) => {
                    if trigger(&server, Trigger::Scheduled) == Err(StartError::InProgress) {
                        tracing::debug!(event = "usage_probe_skipped", why = "sweep_in_progress", "scheduled usage probe skipped");
                    }
                    let current = *changes.borrow();
                    enabled = current.enabled;
                    let (next_deadline, next_run) = schedule_after(current.interval_seconds);
                    deadline = enabled.then_some(next_deadline).flatten();
                    server.probes.set_next_run(enabled.then_some(next_run).flatten());
                }
                changed = changes.changed() => {
                    if changed.is_err() { return; }
                    let current = *changes.borrow();
                    let newly_enabled = !enabled && current.enabled;
                    enabled = current.enabled;
                    let (next_deadline, next_run) = schedule_after(current.interval_seconds);
                    deadline = if newly_enabled {
                        Some(tokio::time::Instant::now())
                    } else if enabled {
                        next_deadline
                    } else {
                        None
                    };
                    let next = if newly_enabled {
                        Some(OffsetDateTime::now_utc())
                    } else {
                        enabled.then_some(next_run).flatten()
                    };
                    server.probes.set_next_run(next);
                }
                changed = stop.changed() => {
                    if changed.is_err() || stop.borrow().is_some() { return; }
                }
            },
            None => tokio::select! {
                changed = changes.changed() => {
                    if changed.is_err() { return; }
                    let current = *changes.borrow();
                    enabled = current.enabled;
                    deadline = enabled.then(tokio::time::Instant::now);
                    server.probes.set_next_run(enabled.then(OffsetDateTime::now_utc));
                }
                changed = stop.changed() => {
                    if changed.is_err() || stop.borrow().is_some() { return; }
                }
            },
        }
    }
}

fn schedule_after(seconds: u64) -> (Option<tokio::time::Instant>, Option<OffsetDateTime>) {
    let duration = Duration::from_secs(seconds);
    let monotonic = tokio::time::Instant::now().checked_add(duration);
    let wall = i64::try_from(seconds).ok().and_then(|seconds| {
        OffsetDateTime::now_utc().checked_add(time::Duration::seconds(seconds))
    });
    (monotonic, wall)
}

async fn sweep(server: Arc<Server>, settings: QuotaSettings, started_at: OffsetDateTime) {
    let accounts: Vec<(Uuid, Kind)> = server
        .pool
        .lock()
        .expect("pool lock")
        .accounts()
        .iter()
        .map(|account| (account.handle, account.kind()))
        .collect();
    for (handle, kind) in accounts {
        let outcome = if kind == Kind::ApiKey {
            AccountOutcome {
                outcome: Outcome::NotApplicable,
                finished_at: OffsetDateTime::now_utc(),
                error: None,
            }
        } else {
            probe_oauth(&server, handle, &settings).await
        };
        server.probes.account_finished(handle, outcome);
    }
    let finished_at = OffsetDateTime::now_utc();
    server.probes.sweep_finished(finished_at);
    tracing::info!(event = "usage_probe_finished", started_at = %started_at, finished_at = %finished_at, "usage probe sweep finished");
}

async fn probe_oauth(
    server: &Arc<Server>,
    handle: Uuid,
    settings: &QuotaSettings,
) -> AccountOutcome {
    let result = match tokio::time::Instant::now()
        .checked_add(Duration::from_secs(settings.probe_deadline_seconds))
    {
        Some(deadline) => {
            tokio::time::timeout_at(deadline, probe_oauth_inner(server, handle)).await
        }
        None => Ok(probe_oauth_inner(server, handle).await),
    };
    match result {
        Err(_) => AccountOutcome {
            outcome: Outcome::TimedOut,
            finished_at: OffsetDateTime::now_utc(),
            error: Some("usage probe deadline elapsed".into()),
        },
        Ok(Ok(())) => AccountOutcome {
            outcome: Outcome::Updated,
            finished_at: OffsetDateTime::now_utc(),
            error: None,
        },
        Ok(Err(error)) => AccountOutcome {
            outcome: Outcome::Failed,
            finished_at: OffsetDateTime::now_utc(),
            error: Some(error),
        },
    }
}

async fn probe_oauth_inner(server: &Arc<Server>, handle: Uuid) -> Result<(), String> {
    ready_to_probe(server, handle, RefreshTrigger::Proactive).await?;
    let first = fetch_usage(server, handle).await;
    let (provider, usage) = match first {
        Err(UsageFailure::Unauthorized) => {
            ready_to_probe(server, handle, RefreshTrigger::Forced).await?;
            fetch_usage(server, handle).await.map_err(usage_error)?
        }
        result => result.map_err(usage_error)?,
    };
    let observations = provider.observe_usage(&usage)?;
    let applied = server.pool.lock().expect("pool lock").observe_usage(
        handle,
        observations,
        OffsetDateTime::now_utc(),
    );
    if !applied {
        return Err("account left the pool before its usage result was applied".into());
    }
    server.mark_quota_dirty();
    Ok(())
}

async fn ready_to_probe(
    server: &Arc<Server>,
    handle: Uuid,
    trigger: RefreshTrigger,
) -> Result<(), String> {
    match refresh::ensure_fresh(server, handle, trigger).await {
        RefreshOutcome::Ready => Ok(()),
        RefreshOutcome::Errored => Err("credential refresh was permanently rejected".into()),
        RefreshOutcome::Wait { until } => Err(format!(
            "credential refresh is waiting until {}",
            crate::timestamp::rfc3339(until)
        )),
    }
}

async fn fetch_usage(
    server: &Server,
    handle: Uuid,
) -> Result<(Provider, serde_json::Value), UsageFailure> {
    let account = oauth_account(server, handle).map_err(UsageFailure::Failed)?;
    let usage = server.upstream.fetch_usage(&account).await?;
    Ok((account.provider, usage))
}

fn oauth_account(server: &Server, handle: Uuid) -> Result<Account, String> {
    let pool = server.pool.lock().expect("pool lock");
    let account = pool
        .get(handle)
        .ok_or_else(|| "account left the pool before probing".to_string())?;
    match &account.credential {
        Credential::OAuth(_) => Ok(account.clone()),
        Credential::ApiKey(_) => Err("usage probing does not apply to API-key accounts".into()),
    }
}

fn usage_error(error: UsageFailure) -> String {
    match error {
        UsageFailure::Unauthorized => "usage endpoint rejected the refreshed credential".into(),
        UsageFailure::Failed(error) => error,
    }
}
