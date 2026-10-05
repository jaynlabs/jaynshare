//! The 429 and hold bookkeeping: classification, the holds it sets
//! and clears, the admission slot waiting attempts poll, and the revalidation
//! bookkeeping.

use http::HeaderMap;
use time::OffsetDateTime;
use uuid::Uuid;

use super::quota;
use super::{Account, Kind, Pool};

impl Pool {
    /// Classify one upstream 429, set the hold it earns and log one
    /// credential-free line. `collected` is the 429 body, read only for
    /// the error classification fields and never logged or stored.
    pub fn record_429(
        &mut self,
        handle: Uuid,
        model: Option<&str>,
        headers: &HeaderMap,
        collected: Option<&[u8]>,
        now: OffsetDateTime,
    ) -> quota::Classification {
        self.learn_family(model, headers);
        let Some(account) = self.get(handle) else {
            return quota::Classification::Throttle;
        };
        let spend_cap = account.provider.is_spend_cap_429(collected);
        let kind = account.kind();
        let name = account.display_name.clone();
        let org = account.profile.organization_uuid;
        let fresh = account.provider.observe_headers(kind, headers);
        let classification = if spend_cap {
            // An organisation cap is exhaustion of the shared spend-cap
            // bucket; without a verified organisation the hold is account-alone.
            quota::Classification::Exhaustion {
                buckets: vec![quota::SPEND_CAP.to_string()],
            }
        } else {
            let family = self.family_for(model);
            quota::classify(kind, family, &fresh, &account.quota)
        };
        let hold_end = match &classification {
            quota::Classification::Exhaustion { buckets } => {
                let retry_after = header_retry_after(headers);
                if spend_cap {
                    match org {
                        Some(uuid) => {
                            let bucket = self.organisation_quota.entry(uuid).or_insert_with(|| {
                                quota::Bucket::unknown(quota::SPEND_CAP, quota::Scope::Organisation)
                            });
                            hold_fallback(bucket, retry_after, now)
                        }
                        None => {
                            let account = self.get_mut(handle).expect("checked above");
                            let bucket = match account
                                .quota
                                .iter_mut()
                                .find(|b| b.name == quota::SPEND_CAP)
                            {
                                Some(b) => b,
                                None => {
                                    account.quota.push(quota::Bucket::unknown(
                                        quota::SPEND_CAP,
                                        quota::Scope::Organisation,
                                    ));
                                    account.quota.last_mut().expect("just pushed")
                                }
                            };
                            hold_fallback(bucket, retry_after, now)
                        }
                    }
                } else {
                    let account = self.get_mut(handle).expect("checked above");
                    quota::apply(
                        &mut account.quota,
                        fresh,
                        quota::Source::ResponseHeaders,
                        now,
                    );
                    let mut end = None;
                    for name in buckets {
                        if let Some(bucket) = account.quota.iter_mut().find(|b| &b.name == name) {
                            quota::hold_exhausted(bucket, retry_after, now);
                            end = end.max(bucket.exhaustion_hold_until);
                        }
                    }
                    end
                }
            }
            quota::Classification::Throttle => {
                // The bucket observations and their states remain unchanged.
                let end = now
                    + time::Duration::seconds(quota::throttle_hold_seconds(header_retry_after(
                        headers,
                    )) as i64);
                self.hold_throttle(handle, end);
                Some(end)
            }
        };
        let admission = self.admission.entry(handle).or_default();
        admission.last_429 = Some(now);
        let (class, names) = match &classification {
            quota::Classification::Exhaustion { buckets } => ("exhaustion", buckets.join(", ")),
            quota::Classification::Throttle => ("throttle", String::new()),
        };
        let hold_text = hold_end.map(crate::timestamp::rfc3339).unwrap_or_default();
        tracing::info!(
            event = "quota_classified",
            acct = %name,
            classification = class,
            buckets = %names,
            hold_end = %hold_text,
            "429 classified; the affected hold is set"
        );
        classification
    }

    /// The account-wide admission hold, extended only, waking
    /// waiters. New attempts pause at admission; the ramp that was
    /// running gives way to the fresh one that starts at the hold's end.
    pub fn hold_throttle(&mut self, handle: Uuid, until: OffsetDateTime) {
        let name = self
            .get(handle)
            .map_or_else(|| handle.to_string(), |a| a.display_name.clone());
        let admission = self.admission.entry(handle).or_default();
        let extended = admission.throttle_hold_until.is_none_or(|t| until > t);
        if extended {
            admission.throttle_hold_until = Some(until);
            admission.ramp = None;
            admission.notify.notify_waiters();
            tracing::info!(
                event = "account_paused",
                acct = %name,
                until = %crate::timestamp::rfc3339(until),
                "throttled; new attempts on the account wait at admission until the hold ends"
            );
        }
    }

    /// The running throttle hold, if any.
    pub fn throttle_hold_end(&self, handle: Uuid, now: OffsetDateTime) -> Option<OffsetDateTime> {
        self.admission
            .get(&handle)
            .and_then(|a| a.throttle_hold_until)
            .filter(|t| *t > now)
    }

    /// The soonest running hold end on the account, its organisation
    /// spend-cap hold included — the hold the exchange's log line names.
    pub fn quota_hold_end(&self, handle: Uuid, now: OffsetDateTime) -> Option<OffsetDateTime> {
        let account_hold = self
            .get(handle)
            .and_then(|a| {
                a.quota
                    .iter()
                    .filter_map(|b| b.exhaustion_hold_until)
                    .filter(|t| *t > now)
                    .min()
            })
            .max(self.organisation_hold(self.get(handle)?, now));
        account_hold.max(self.throttle_hold_end(handle, now))
    }

    /// Release one attempt waiting at admission as the
    /// revalidation request — the floor since the account's most recent 429 has
    /// passed even though its throttle hold runs on, and the server-wide gate
    /// is open. Consumes the gate (spent in every case).
    pub fn release_waiting_revalidation(
        &mut self,
        handle: Uuid,
        model: Option<&str>,
        quota_settings: &crate::config::QuotaSettings,
        now: OffsetDateTime,
    ) -> bool {
        if self.next_revalidation.is_some_and(|t| t > now)
            || self.throttle_hold_end(handle, now).is_none()
        {
            return false;
        }
        let within_floor = self
            .admission
            .get(&handle)
            .and_then(|a| a.last_429)
            .is_some_and(|t| {
                now - t < time::Duration::seconds(quota_settings.revalidation_floor_seconds as i64)
            });
        if within_floor {
            return false;
        }
        self.next_revalidation = Some(
            now + time::Duration::seconds(quota_settings.revalidation_interval_seconds as i64),
        );
        let name = self
            .get(handle)
            .map(|a| a.display_name.clone())
            .unwrap_or_else(|| handle.to_string());
        let what = model.unwrap_or("any model");
        let fact = self
            .throttle_hold_end(handle, now)
            .map(|t| {
                format!(
                    "{what} against the throttle hold until {}",
                    crate::timestamp::rfc3339(t)
                )
            })
            .unwrap_or_else(|| format!("{what} against the throttle hold"));
        tracing::info!(
            event = "revalidation_started",
            acct = %name,
            fact = %fact,
            next_at = ?self.next_revalidation,
            "a waiting attempt is released to challenge the throttle hold"
        );
        true
    }

    /// Whether a revalidation request could be released for this
    /// account now — the server-wide gate is open and the account is
    /// past the floor since its last 429, or has no hold to challenge.
    pub fn revalidation_allowed(
        &self,
        handle: Uuid,
        quota_settings: &crate::config::QuotaSettings,
        now: OffsetDateTime,
    ) -> bool {
        self.next_revalidation.is_none_or(|t| t <= now)
            && self
                .get(handle)
                .is_some_and(|a| self.revalidation_ready(a, quota_settings, now))
    }

    /// A revalidation's non-429 clears the holds it challenged; a
    /// successful revalidation with no usable quota fields leaves the buckets
    /// unknown.
    pub fn clear_holds_after_revalidation(
        &mut self,
        handle: Uuid,
        ramp: &crate::config::RampSettings,
        now: OffsetDateTime,
    ) {
        let org = self.get(handle).and_then(|a| a.profile.organization_uuid);
        if let Some(account) = self.get_mut(handle) {
            for bucket in &mut account.quota {
                if bucket.exhaustion_hold_until.is_some_and(|t| t > now) {
                    let (name, scope) = (bucket.name.clone(), bucket.scope);
                    *bucket = quota::Bucket::unknown(&name, scope);
                }
            }
        }
        if let Some(uuid) = org
            && let Some(bucket) = self.organisation_quota.get_mut(&uuid)
            && bucket.exhaustion_hold_until.is_some_and(|t| t > now)
        {
            *bucket = quota::Bucket::unknown(quota::SPEND_CAP, quota::Scope::Organisation);
        }
        self.clear_throttle_hold(handle, ramp, now);
    }
}

/// A spend-cap hold has no reset of its own; the fallback, extended only.
fn hold_fallback(
    bucket: &mut quota::Bucket,
    retry_after: Option<u64>,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    let fallback =
        now + time::Duration::seconds(quota::exhaustion_fallback_seconds(retry_after) as i64);
    let end = match bucket.exhaustion_hold_until.filter(|t| *t > now) {
        Some(existing) => existing.max(fallback),
        None => fallback,
    };
    bucket.exhaustion_hold_until = Some(end);
    Some(end)
}

/// The raw `retry-after` header, integer seconds, or none when absent or
/// unparseable (the fallbacks live in the hold arithmetic).
fn header_retry_after(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// The candidate order — lowest maximum utilisation across the account's
/// governing buckets, then the oldest observation, then the lexically smallest
/// stable reference. Ascending. `family` is the model's governing weekly bucket;
/// when one is verified the shared `weekly` does not participate.
pub(super) fn candidate_rank(
    account: &Account,
    family: Option<&str>,
) -> (f64, (bool, Option<OffsetDateTime>), String) {
    // A verified family names its weekly bucket `weekly:<family>`.
    let weekly = family
        .map(|f| format!("{}:{f}", quota::WEEKLY))
        .unwrap_or_else(|| quota::WEEKLY.to_string());
    let governed: Vec<&quota::Bucket> = account
        .quota
        .iter()
        .filter(|b| match account.kind() {
            Kind::OAuth => b.name == quota::SESSION || b.name == weekly,
            Kind::ApiKey => b.limit.is_some(),
        })
        .collect();
    let max_util = governed
        .iter()
        .filter_map(|b| b.effective_utilization())
        .fold(f64::NEG_INFINITY, f64::max);
    let age = governed
        .iter()
        .map(|b| (b.observed_at.is_none(), b.observed_at))
        .max()
        .unwrap_or((true, None));
    (
        max_util,
        age,
        account
            .profile
            .account_uuid
            .unwrap_or(account.handle)
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::super::{Credential, OAuthCredential, Profile, Secret, Source};
    use super::*;
    use time::Duration;
    use time::macros::datetime;

    fn oauth(email: &str, org: Option<&str>, account_uuid: Uuid) -> Account {
        Account::new(
            crate::provider::Provider::Anthropic,
            String::new(),
            Profile {
                email: Some(email.into()),
                account_uuid: Some(account_uuid),
                organization_uuid: None,
                organization_name: org.map(String::from),
                chatgpt_account_id: None,
            },
            Source::PortableJson,
            Credential::OAuth(OAuthCredential {
                access_token: Secret::new("t".into()),
                refresh_token: None,
                expires_at: datetime!(2027-01-01 00:00 UTC),
                last_refresh_attempt_at: None,
                last_refresh_success_at: None,
                refresh_not_before: None,
            }),
        )
    }

    #[test]
    fn candidate_rank_tie_breaks_on_the_stable_reference() {
        // Same utilisation, same observation age: the lexically smaller stable
        // account reference ranks first, whatever the pool order.
        let older_ref = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_000a);
        let newer_ref = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_000b);
        let mut first = oauth("z@x.io", Some("One"), newer_ref);
        let mut second = oauth("a@x.io", Some("One"), older_ref);
        for account in [&mut first, &mut second] {
            account.quota = vec![quota::Bucket {
                utilization: Some(0.9),
                observed_at: Some(datetime!(2026-09-16 00:00 UTC)),
                ..quota::Bucket::unknown(quota::WEEKLY, quota::Scope::Account)
            }];
        }
        assert!(
            candidate_rank(&second, None) < candidate_rank(&first, None),
            "the lexically smaller stable reference ranks first"
        );
        // Only the reference decides: same account data, opposite order.
        let (a, b) = (candidate_rank(&first, None), candidate_rank(&second, None));
        assert!(a > b);
    }

    fn quota_settings(floor: u64, interval: u64) -> crate::config::QuotaSettings {
        crate::config::QuotaSettings {
            probe_enabled: false,
            probe_interval_seconds: 300,
            probe_deadline_seconds: 30,
            revalidation_floor_seconds: floor,
            revalidation_interval_seconds: interval,
        }
    }

    /// `revalidation_allowed` is the projection of the revalidation readiness
    /// and the server-wide gate — withheld inside the floor and while the gate is
    /// closed, allowed when nothing is held.
    #[test]
    fn revalidation_allowed_tracks_the_floor_and_the_gate() {
        let now = datetime!(2026-09-17 12:00 UTC);
        let settings = quota_settings(60, 120);
        let mut pool = Pool::default();
        let handle = pool
            .add(oauth("a@x.io", Some("One"), Uuid::new_v4()), None)
            .expect("added");

        // No hold to challenge: allowed.
        assert!(pool.revalidation_allowed(handle, &settings, now));

        // A throttle hold with a fresh 429: inside the floor, withheld.
        pool.hold_throttle(handle, now + Duration::seconds(300));
        pool.admission.entry(handle).or_default().last_429 = Some(now);
        assert!(!pool.revalidation_allowed(handle, &settings, now));

        // Past the floor: allowed again, until the gate closes.
        let later = now + Duration::seconds(61);
        assert!(pool.revalidation_allowed(handle, &settings, later));
        pool.next_revalidation = Some(later + Duration::seconds(120));
        assert!(!pool.revalidation_allowed(handle, &settings, later));
    }
}
