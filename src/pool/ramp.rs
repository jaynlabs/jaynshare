//! Admission pacing. A ranking move starts a **ramp** on the new
//! default — a concurrency cap that grows by a step every interval until the
//! window passes; a throttle hold **pauses** admission on the account and a
//! fresh ramp starts at its end; every attempt holds a **slot** from its start
//! until upstream response headers arrive. All of it runtime only.

use std::sync::Arc;

use time::OffsetDateTime;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::config::RampSettings;

use super::{Admission, Pool};

/// One ramp on an account, with the policy in force when it began — a
/// running ramp keeps its values across a reload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ramp {
    pub started_at: OffsetDateTime,
    initial: u64,
    step: u64,
    step_interval_ms: u64,
    window_seconds: u64,
}

impl Ramp {
    /// `None` when the policy disables the ramp (the ramp can be disabled).
    pub fn start(settings: &RampSettings, at: OffsetDateTime) -> Option<Self> {
        settings.enabled.then_some(Self {
            started_at: at,
            initial: settings.initial_concurrency,
            step: settings.concurrency_step,
            step_interval_ms: settings.step_interval_ms,
            window_seconds: settings.window_seconds,
        })
    }

    fn elapsed_ms(&self, now: OffsetDateTime) -> u64 {
        (now - self.started_at)
            .whole_milliseconds()
            .clamp(0, u64::MAX as i128) as u64
    }

    /// The cap on attempts in flight at `now`, or `None` once the window has
    /// passed and the ramp has lifted.
    pub fn limit(&self, now: OffsetDateTime) -> Option<u64> {
        let elapsed = self.elapsed_ms(now);
        if elapsed >= self.window_seconds.saturating_mul(1_000) {
            return None;
        }
        let steps = elapsed / self.step_interval_ms.max(1);
        Some(self.initial.saturating_add(self.step.saturating_mul(steps)))
    }
}

/// Why a ramp began, for the log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RampCause {
    /// The ranking made the account the default.
    DefaultMoved,
    /// The account's throttle hold ended.
    PauseEnd,
}

impl std::fmt::Display for RampCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DefaultMoved => "default_moved",
            Self::PauseEnd => "pause_end",
        })
    }
}

/// Why a pause ended — its hold ran out, or a revalidation's non-429
/// cleared it early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseEndCause {
    HoldElapsed,
    Revalidation,
}

impl std::fmt::Display for PauseEndCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::HoldElapsed => "hold_elapsed",
            Self::Revalidation => "revalidation",
        })
    }
}

/// What `settle` found: a pause that ended at `pause_ended`, and the ramp that
/// began in its place, if the policy starts one.
#[derive(Debug, Clone, Copy, Default)]
struct Settled {
    pause_ended: Option<OffsetDateTime>,
    ramp_began: Option<RampCause>,
}

/// What admission says to one attempt.
#[derive(Debug)]
pub enum Admit {
    /// Proceed; the caller holds a slot until it releases it (`release_slot`).
    Now,
    /// The account is paused until `until`; wake on `notify`.
    Paused {
        until: OffsetDateTime,
        notify: Arc<Notify>,
    },
    /// Every slot under the ramp's current cap is held; wake on `notify`.
    Ramping { limit: u64, notify: Arc<Notify> },
}

impl Admission {
    /// The transition: a hold that has ended becomes a fresh ramp that
    /// began at the hold's end; a ramp whose window has passed is gone.
    fn settle(&mut self, settings: &RampSettings, now: OffsetDateTime) -> Settled {
        let mut settled = Settled::default();
        if let Some(end) = self.throttle_hold_until
            && end <= now
        {
            self.throttle_hold_until = None;
            self.ramp = Ramp::start(settings, end);
            settled.pause_ended = Some(end);
            settled.ramp_began = self.ramp.as_ref().map(|_| RampCause::PauseEnd);
        }
        if self.ramp.as_ref().is_some_and(|r| r.limit(now).is_none()) {
            self.ramp = None;
            settled.ramp_began = None;
        }
        settled
    }

    /// The ramp that would be in force at `now` without settling — the same
    /// answer `settle` arrives at, for read-only views.
    fn ramp_at(&self, settings: &RampSettings, now: OffsetDateTime) -> Option<Ramp> {
        let ramp = match self.throttle_hold_until {
            Some(end) if end <= now => Ramp::start(settings, end),
            Some(_) => None,
            None => self.ramp.clone(),
        };
        ramp.filter(|r| r.limit(now).is_some())
    }
}

impl Pool {
    /// The ranking made `handle` the default; its ramp begins now
    /// (unless disabled). An operator switch, a distribution bind and a
    /// runtime add never call this.
    pub fn start_ramp(&mut self, handle: Uuid, settings: &RampSettings, now: OffsetDateTime) {
        let Some(ramp) = Ramp::start(settings, now) else {
            return;
        };
        let name = display_name(self, handle);
        let admission = self.admission.entry(handle).or_default();
        admission.ramp = Some(ramp);
        log_ramp_started(&name, settings, RampCause::DefaultMoved, now);
    }

    /// One attempt asks to proceed on `handle`. `Now` takes a
    /// slot the caller must release when upstream response headers arrive or
    /// the attempt fails.
    pub fn admit(&mut self, handle: Uuid, settings: &RampSettings, now: OffsetDateTime) -> Admit {
        let name = display_name(self, handle);
        let admission = self.admission.entry(handle).or_default();
        let settled = admission.settle(settings, now);
        if let Some(ended) = settled.pause_ended {
            log_pause_ended(&name, ended, PauseEndCause::HoldElapsed);
        }
        if let Some(cause) = settled.ramp_began {
            log_ramp_started(&name, settings, cause, now);
        }
        if let Some(until) = admission.throttle_hold_until.filter(|t| *t > now) {
            return Admit::Paused {
                until,
                notify: Arc::clone(&admission.notify),
            };
        }
        if let Some(limit) = admission.ramp.as_ref().and_then(|r| r.limit(now))
            && admission.slots_held >= limit
        {
            return Admit::Ramping {
                limit,
                notify: Arc::clone(&admission.notify),
            };
        }
        admission.slots_held += 1;
        Admit::Now
    }

    /// A revalidation request's non-429 ends the pause now
    /// rather than at its scheduled end; the fresh ramp starts at the
    /// clearing, and the waiters wake into it.
    pub fn clear_throttle_hold(
        &mut self,
        handle: Uuid,
        settings: &RampSettings,
        now: OffsetDateTime,
    ) {
        let name = display_name(self, handle);
        if let Some(admission) = self.admission.get_mut(&handle)
            && admission.throttle_hold_until.is_some_and(|t| t > now)
        {
            admission.throttle_hold_until = Some(now);
            let settled = admission.settle(settings, now);
            log_pause_ended(&name, now, PauseEndCause::Revalidation);
            if let Some(cause) = settled.ramp_began {
                log_ramp_started(&name, settings, cause, now);
            }
            admission.notify.notify_waiters();
        }
    }

    /// One paused attempt released as the revalidation request also
    /// counts against the ramp that follows — it is an attempt in flight.
    pub fn take_slot(&mut self, handle: Uuid) {
        self.admission.entry(handle).or_default().slots_held += 1;
    }

    /// Upstream response headers arrived (or the attempt failed): the
    /// slot is free and a waiter may take it.
    pub fn release_slot(&mut self, handle: Uuid) {
        if let Some(admission) = self.admission.get_mut(&handle) {
            admission.slots_held = admission.slots_held.saturating_sub(1);
            admission.notify.notify_waiters();
        }
    }

    /// The ramp on `handle` as `status` shows it — when it began and
    /// the cap in force now — or `None` when no ramp runs.
    pub fn ramp_view(
        &self,
        handle: Uuid,
        settings: &RampSettings,
        now: OffsetDateTime,
    ) -> Option<(OffsetDateTime, u64)> {
        let ramp = self.admission.get(&handle)?.ramp_at(settings, now)?;
        Some((ramp.started_at, ramp.limit(now)?))
    }

    #[cfg(test)]
    fn slots_held(&self, handle: Uuid) -> u64 {
        self.admission.get(&handle).map_or(0, |a| a.slots_held)
    }
}

fn display_name(pool: &Pool, handle: Uuid) -> String {
    pool.get(handle)
        .map_or_else(|| handle.to_string(), |a| a.display_name.clone())
}

/// The pause's end, the twin of `account_paused`.
fn log_pause_ended(name: &str, ended_at: OffsetDateTime, cause: PauseEndCause) {
    tracing::info!(
        event = "account_pause_ended",
        acct = %name,
        cause = %cause,
        ended_at = %crate::timestamp::rfc3339(ended_at),
        "throttle hold over; attempts on the account are admitted again"
    );
}

fn log_ramp_started(name: &str, settings: &RampSettings, cause: RampCause, now: OffsetDateTime) {
    tracing::info!(
        event = "ramp_started",
        acct = %name,
        cause = %cause,
        initial = settings.initial_concurrency,
        step = settings.concurrency_step,
        step_interval_ms = settings.step_interval_ms,
        window_seconds = settings.window_seconds,
        started_at = %crate::timestamp::rfc3339(now),
        "attempts on the account are admitted under a growing concurrency cap"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::account::{Account, Credential, Profile, Secret, Source};
    use time::Duration;
    use time::macros::datetime;

    const T0: OffsetDateTime = datetime!(2026-01-01 00:00 UTC);

    fn settings() -> RampSettings {
        RampSettings {
            enabled: true,
            initial_concurrency: 1,
            concurrency_step: 1,
            step_interval_ms: 250,
            window_seconds: 30,
        }
    }

    fn pool() -> (Pool, Uuid) {
        let account = Account::new(
            crate::provider::Provider::Anthropic,
            "A".into(),
            Profile::default(),
            Source::ApiKeyEntry,
            Credential::ApiKey(Secret::new("k".into())),
        );
        let pool = Pool::from_accounts(vec![account], T0);
        let handle = pool.accounts()[0].handle;
        (pool, handle)
    }

    fn is_now(verdict: &Admit) -> bool {
        matches!(verdict, Admit::Now)
    }

    /// The arithmetic: 1 at t=0, 2 from 250 ms, 3 from 500 ms …, lifted
    /// at 30 s; the ramp is gone when disabled.
    #[test]
    fn the_cap_grows_by_a_step_every_interval_and_lifts_at_the_window() {
        let ramp = Ramp::start(&settings(), T0).expect("enabled");
        assert_eq!(ramp.limit(T0), Some(1));
        assert_eq!(ramp.limit(T0 + Duration::milliseconds(249)), Some(1));
        assert_eq!(ramp.limit(T0 + Duration::milliseconds(250)), Some(2));
        assert_eq!(ramp.limit(T0 + Duration::milliseconds(1_000)), Some(5));
        assert_eq!(ramp.limit(T0 + Duration::milliseconds(29_999)), Some(120));
        assert_eq!(ramp.limit(T0 + Duration::seconds(30)), None);
        // A clock behind the start reads as t=0, never as a lifted ramp.
        assert_eq!(ramp.limit(T0 - Duration::seconds(1)), Some(1));
        assert_eq!(
            Ramp::start(
                &RampSettings {
                    enabled: false,
                    ..settings()
                },
                T0
            ),
            None
        );
    }

    /// Under a ramp only `limit` attempts hold slots at once; a
    /// released slot admits the next; the lift admits everyone.
    #[test]
    fn admission_caps_slots_under_the_ramp_and_frees_them_on_release() {
        let (mut pool, a) = pool();
        pool.start_ramp(a, &settings(), T0);
        assert!(is_now(&pool.admit(a, &settings(), T0)));
        assert!(matches!(
            pool.admit(a, &settings(), T0),
            Admit::Ramping { limit: 1, .. }
        ));
        pool.release_slot(a);
        assert!(is_now(&pool.admit(a, &settings(), T0)));
        assert_eq!(pool.slots_held(a), 1);
        // The next step opens one more slot.
        let t1 = T0 + Duration::milliseconds(250);
        assert!(is_now(&pool.admit(a, &settings(), t1)));
        assert!(matches!(
            pool.admit(a, &settings(), t1),
            Admit::Ramping { limit: 2, .. }
        ));
        assert_eq!(pool.ramp_view(a, &settings(), t1), Some((T0, 2)));
        // Past the window the cap is gone.
        let t2 = T0 + Duration::seconds(30);
        assert!(is_now(&pool.admit(a, &settings(), t2)));
        assert!(is_now(&pool.admit(a, &settings(), t2)));
        assert_eq!(pool.ramp_view(a, &settings(), t2), None);
        assert_eq!(pool.slots_held(a), 4);
    }

    /// A throttle hold pauses every attempt; at its end a fresh ramp
    /// begins at the hold's end, so the paused attempts release staggered.
    #[test]
    fn a_pause_holds_every_attempt_and_ends_in_a_fresh_ramp() {
        let (mut pool, a) = pool();
        let end = T0 + Duration::seconds(3);
        pool.hold_throttle(a, end);
        assert!(matches!(
            pool.admit(a, &settings(), T0),
            Admit::Paused { until, .. } if until == end
        ));
        assert_eq!(pool.ramp_view(a, &settings(), T0), None);
        // Read-only, the view already predicts the ramp past the end.
        assert_eq!(
            pool.ramp_view(a, &settings(), end + Duration::milliseconds(300)),
            Some((end, 2))
        );
        assert!(is_now(&pool.admit(a, &settings(), end)));
        assert!(matches!(
            pool.admit(a, &settings(), end),
            Admit::Ramping { limit: 1, .. }
        ));
        assert_eq!(pool.throttle_hold_end(a, end), None);
        // A pause set while a ramp runs replaces it: the fresh one starts at
        // the new end, not the old ramp's clock.
        let later = end + Duration::seconds(5);
        pool.hold_throttle(a, later);
        assert!(matches!(
            pool.admit(a, &settings(), end + Duration::seconds(1)),
            Admit::Paused { .. }
        ));
        assert_eq!(pool.ramp_view(a, &settings(), later), Some((later, 1)));
    }

    /// A hold cleared early by a revalidation ends now, and
    /// the fresh ramp starts from the clearing, not from the scheduled end.
    #[test]
    fn a_cleared_pause_starts_its_ramp_at_the_clearing() {
        let (mut pool, a) = pool();
        pool.hold_throttle(a, T0 + Duration::seconds(60));
        let cleared = T0 + Duration::seconds(10);
        pool.clear_throttle_hold(a, &settings(), cleared);
        assert_eq!(pool.throttle_hold_end(a, cleared), None);
        assert_eq!(pool.ramp_view(a, &settings(), cleared), Some((cleared, 1)));
        assert!(is_now(&pool.admit(a, &settings(), cleared)));
        assert!(matches!(
            pool.admit(a, &settings(), cleared),
            Admit::Ramping { .. }
        ));
    }

    /// An account with no ramp and no pause admits everything at
    /// once, whatever its siblings are doing; a disabled policy ramps nobody.
    #[test]
    fn no_ramp_admits_at_once() {
        let (mut pool, a) = pool();
        for _ in 0..4 {
            assert!(is_now(&pool.admit(a, &settings(), T0)));
        }
        let off = RampSettings {
            enabled: false,
            ..settings()
        };
        pool.start_ramp(a, &off, T0);
        assert_eq!(pool.ramp_view(a, &off, T0), None);
        assert!(is_now(&pool.admit(a, &off, T0)));
    }
}
