//! Sessions and their bindings.
//!
//! A session is the pair (principal, `x-claude-code-session-id`). The pool
//! remembers, per session, the account it is bound to — set at its first
//! attempt, moved only by failover — the account that served it last, when it
//! was last seen and how many of its exchanges are in flight. Every
//! time-dependent decision takes `now` from the caller so the windows are
//! provable without a clock seam.

use std::collections::HashMap;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Active while an exchange is in flight or seen within this window.
pub const ACTIVE_WINDOW: Duration = Duration::minutes(2);
/// Known until idle this long, then forgotten — and the binding with it.
pub const KNOWN_WINDOW: Duration = Duration::hours(1);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// The principal as the audit record names it: kind and stable id.
    pub principal: String,
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Set at the first attempt, moved only by failover.
    pub bound: Option<Uuid>,
    pub last_served: Option<Uuid>,
    pub last_seen: OffsetDateTime,
    pub in_flight: u32,
}

impl SessionRecord {
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.in_flight > 0 || now - self.last_seen < ACTIVE_WINDOW
    }

    fn is_forgotten(&self, now: OffsetDateTime) -> bool {
        self.in_flight == 0 && now - self.last_seen >= KNOWN_WINDOW
    }
}

#[derive(Debug, Default, Clone)]
pub struct Sessions {
    records: HashMap<SessionKey, SessionRecord>,
}

/// What `status` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub known: usize,
    pub active: usize,
}

impl Sessions {
    /// Forget sessions idle for an hour; an in-flight exchange keeps its own.
    pub fn reap(&mut self, now: OffsetDateTime) {
        self.records.retain(|_, r| !r.is_forgotten(now));
    }

    pub fn binding(&self, key: &SessionKey) -> Option<Uuid> {
        self.records.get(key).and_then(|r| r.bound)
    }

    /// One session's record, for the client surface's own lookup keyed
    /// by principal and session id. Read-only: a client read moves nothing.
    pub fn record(&self, key: &SessionKey) -> Option<&SessionRecord> {
        self.records.get(key)
    }

    /// An exchange for the session has started: known from now, active while it runs.
    pub fn begin(&mut self, key: SessionKey, now: OffsetDateTime) {
        let record = self.records.entry(key).or_insert(SessionRecord {
            bound: None,
            last_served: None,
            last_seen: now,
            in_flight: 0,
        });
        record.in_flight += 1;
        record.last_seen = now;
    }

    /// Bind the session to `handle`; the other account it was bound to, if any.
    pub fn bind(&mut self, key: &SessionKey, handle: Uuid) -> Option<Uuid> {
        let record = self.records.get_mut(key)?;
        record.bound.replace(handle).filter(|old| *old != handle)
    }

    /// The exchange ended; `served` is the account that made its last attempt, if any.
    pub fn end(&mut self, key: &SessionKey, served: Option<Uuid>, now: OffsetDateTime) {
        if let Some(record) = self.records.get_mut(key) {
            record.in_flight = record.in_flight.saturating_sub(1);
            record.last_seen = now;
            if served.is_some() {
                record.last_served = served;
            }
        }
    }

    /// A removed account can bind nothing: its sessions bind afresh at their next
    /// attempt.
    pub fn unbind_account(&mut self, handle: Uuid) {
        for record in self.records.values_mut() {
            if record.bound == Some(handle) {
                record.bound = None;
            }
        }
    }

    pub fn counts(&self, now: OffsetDateTime) -> Counts {
        Counts {
            known: self.records.len(),
            active: self.records.values().filter(|r| r.is_active(now)).count(),
        }
    }

    /// Active sessions per bound account.
    pub fn active_per_account(&self, now: OffsetDateTime) -> HashMap<Uuid, usize> {
        let mut out = HashMap::new();
        for record in self.records.values().filter(|r| r.is_active(now)) {
            if let Some(handle) = record.bound {
                *out.entry(handle).or_insert(0) += 1;
            }
        }
        out
    }

    /// Exchanges in flight per bound account.
    pub fn in_flight_per_account(&self) -> HashMap<Uuid, usize> {
        let mut out = HashMap::new();
        for record in self.records.values().filter(|r| r.in_flight > 0) {
            if let Some(handle) = record.bound {
                *out.entry(handle).or_insert(0) += record.in_flight as usize;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const T0: OffsetDateTime = datetime!(2026-09-16 12:00 UTC);

    fn key(id: &str) -> SessionKey {
        SessionKey {
            principal: "loopback".into(),
            session_id: id.into(),
        }
    }

    #[test]
    fn a_bind_names_the_binding_it_moves() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut s = Sessions::default();
        s.begin(key("s1"), T0);
        assert_eq!(s.binding(&key("s1")), None);
        assert_eq!(s.bind(&key("s1"), a), None);
        assert_eq!(s.bind(&key("s1"), a), None);
        assert_eq!(s.bind(&key("s1"), b), Some(a));
        assert_eq!(s.binding(&key("s1")), Some(b));
        s.end(&key("s1"), Some(b), T0);
        assert_eq!(s.records.get(&key("s1")).unwrap().last_served, Some(b));
    }

    #[test]
    fn active_two_minutes_known_one_hour_in_flight_keeps_both() {
        let mut s = Sessions::default();
        s.begin(key("s1"), T0);
        s.end(&key("s1"), None, T0);
        s.begin(key("s2"), T0);
        let t = T0 + Duration::minutes(2);
        s.reap(t);
        assert_eq!(
            s.counts(t),
            Counts {
                known: 2,
                active: 1
            }
        );
        let t = T0 + Duration::hours(1);
        s.reap(t);
        assert_eq!(
            s.counts(t),
            Counts {
                known: 1,
                active: 1
            }
        );
        assert!(s.records.contains_key(&key("s2")));
        s.end(&key("s2"), None, t);
        s.reap(t + Duration::hours(1));
        assert_eq!(s.counts(t + Duration::hours(1)), Counts::default());
    }

    #[test]
    fn per_account_counts_follow_bindings() {
        let a = Uuid::new_v4();
        let mut s = Sessions::default();
        s.begin(key("s1"), T0);
        s.bind(&key("s1"), a);
        s.begin(key("s2"), T0);
        s.bind(&key("s2"), a);
        s.end(&key("s2"), Some(a), T0);
        assert_eq!(s.active_per_account(T0).get(&a), Some(&2));
        assert_eq!(s.in_flight_per_account().get(&a), Some(&1));
        s.unbind_account(a);
        assert!(s.active_per_account(T0).is_empty());
    }
}
