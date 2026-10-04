//! The pool: accounts, their quota, the default account and per-account usage.
//! Persistence of the durable part is `state.rs`'s.

pub mod account;
pub(crate) mod holds;
pub mod managed;
pub mod operations;
pub mod operator;
pub mod probe;
pub mod quota;
pub mod ramp;
pub mod refresh;
pub mod selection;
pub mod sessions;

use std::collections::HashMap;

use http::HeaderMap;
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::config::SelectionSettings;
use crate::provider::anthropic;

use holds::candidate_rank;

pub use account::{Account, Credential, Errored, Kind, OAuthCredential, Profile, Secret, Source};
pub use operations::{OperationError, ReferenceConflict, Why};
pub use sessions::{SessionKey, Sessions};

/// Usage since start; runtime only.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub requests: u64,
}

/// Per-account runtime admission state — the throttle hold, when the account
/// last saw a 429 (the revalidation floor's anchor), the ramp in progress, the
/// attempts holding a slot, and the notify that wakes waiting attempts. Never
/// persisted.
#[derive(Debug, Default, Clone)]
struct Admission {
    throttle_hold_until: Option<OffsetDateTime>,
    last_429: Option<OffsetDateTime>,
    /// The ramp in progress, once a ranking move or a pause end began one.
    ramp: Option<ramp::Ramp>,
    /// Attempts between admission and their upstream response headers.
    slots_held: u64,
    notify: std::sync::Arc<Notify>,
}

#[derive(Debug, Default, Clone)]
pub struct Pool {
    accounts: Vec<Account>,
    usage: HashMap<Uuid, Usage>,
    /// Sessions and their bindings; runtime only.
    sessions: Sessions,
    /// The default's ownership and the route preferences; runtime
    /// only, they survive a reload and not a restart.
    operator: operator::Operator,
    /// Verified organisation → its shared `spend-cap` bucket.
    /// Persisted in `state.organization_quota` keyed by the
    /// organisation UUID; matched by identity on restore, never by position.
    organisation_quota: HashMap<Uuid, quota::Bucket>,
    /// Verified family → the models seen governed by it. Runtime only.
    families: HashMap<String, Vec<String>>,
    /// Runtime-only admission state per account.
    admission: HashMap<Uuid, Admission>,
    /// The server-wide revalidation gate.
    next_revalidation: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolve {
    NotFound,
    /// The matching display names, for the caller to qualify.
    Ambiguous(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    AccountRemoved,
    FamilyReplaced,
}

/// Unicode case folding — the one comparison display
/// names, emails, route names and references share.
pub fn fold(s: &str) -> String {
    unicase::UniCase::new(s).to_folded_case()
}

/// A reference may be the display name, profile email, account UUID, organisation UUID or handle.
pub fn references(account: &Account, reference: &str) -> bool {
    let folded = fold(reference);
    if fold(&account.display_name) == folded {
        return true;
    }
    if account
        .profile
        .email
        .as_ref()
        .is_some_and(|e| fold(e) == folded)
    {
        return true;
    }
    match reference.parse::<Uuid>() {
        Ok(uuid) => {
            account.handle == uuid
                || account.profile.account_uuid == Some(uuid)
                || account.profile.organization_uuid == Some(uuid)
        }
        Err(_) => false,
    }
}

impl Pool {
    pub fn from_accounts(mut accounts: Vec<Account>, now: OffsetDateTime) -> Self {
        for a in &mut accounts {
            a.ensure_expected_buckets();
            quota::expire(&mut a.quota, now);
        }
        Self {
            accounts,
            usage: HashMap::new(),
            sessions: Sessions::default(),
            operator: operator::Operator::default(),
            organisation_quota: HashMap::new(),
            families: HashMap::new(),
            admission: HashMap::new(),
            next_revalidation: None,
        }
    }

    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    pub fn default_account(&self) -> Option<Uuid> {
        self.operator.default
    }

    pub fn get(&self, handle: Uuid) -> Option<&Account> {
        self.accounts.iter().find(|a| a.handle == handle)
    }

    fn get_mut(&mut self, handle: Uuid) -> Option<&mut Account> {
        self.accounts.iter_mut().find(|a| a.handle == handle)
    }

    pub fn usage(&self, handle: Uuid) -> Usage {
        self.usage.get(&handle).copied().unwrap_or_default()
    }

    /// Buckets past their reset are unknown again; run before
    /// any selection or snapshot. Returns whether any bucket changed — the
    /// reset expiry is a durable fact and its caller schedules the write.
    pub fn expire_quota(&mut self, now: OffsetDateTime) -> bool {
        let mut changed = false;
        for a in &mut self.accounts {
            changed |= quota::expire(&mut a.quota, now);
        }
        for bucket in self.organisation_quota.values_mut() {
            changed |= quota::expire(std::slice::from_mut(bucket), now);
        }
        changed
    }

    /// The organisation spend-cap buckets as persisted records, each
    /// carrying its organisation UUID. Key order is stable; order carries no
    /// identity.
    pub fn organisation_quota_records(&self) -> Vec<serde_json::Value> {
        let mut orgs: Vec<_> = self.organisation_quota.iter().collect();
        orgs.sort_by_key(|(uuid, _)| **uuid);
        orgs.into_iter()
            .map(|(uuid, bucket)| {
                let mut value = serde_json::to_value(bucket).expect("bucket serialises");
                value["organization_uuid"] = serde_json::json!(uuid);
                value
            })
            .collect()
    }

    /// Install restored organisation entries and expire them against
    /// the current clock before anything is served. Malformed entries are no
    /// observations.
    pub fn restore_organisation_quota(
        &mut self,
        entries: &[serde_json::Value],
        now: OffsetDateTime,
    ) {
        for entry in entries {
            let Some(uuid) = entry
                .get("organization_uuid")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| s.parse().ok())
            else {
                continue;
            };
            let Ok(bucket) = serde_json::from_value::<quota::Bucket>(entry.clone()) else {
                continue;
            };
            self.organisation_quota.insert(uuid, bucket);
        }
        for bucket in self.organisation_quota.values_mut() {
            quota::expire(std::slice::from_mut(bucket), now);
        }
    }

    /// The account's shared organisation spend-cap hold, while it runs.
    pub fn organisation_hold(
        &self,
        account: &Account,
        now: OffsetDateTime,
    ) -> Option<OffsetDateTime> {
        account
            .profile
            .organization_uuid
            .and_then(|org| self.organisation_quota.get(&org))
            .and_then(|b| b.exhaustion_hold_until)
            .filter(|t| *t > now)
    }

    fn organisation_holds(&self, now: OffsetDateTime) -> HashMap<Uuid, OffsetDateTime> {
        self.organisation_quota
            .iter()
            .filter_map(|(org, b)| {
                b.exhaustion_hold_until
                    .filter(|t| *t > now)
                    .map(|t| (*org, t))
            })
            .collect()
    }

    /// The family whose weekly bucket governs this model, from the
    /// pool's verified mapping.
    fn family_for(&self, model: Option<&str>) -> Option<&str> {
        let model = model?;
        self.families
            .iter()
            .find(|(_, models)| models.iter().any(|m| m == model))
            .map(|(f, _)| f.as_str())
    }

    /// The sessions as they stand at `now` (forgotten ones reaped first).
    pub fn sessions(&mut self, now: OffsetDateTime) -> &Sessions {
        self.sessions.reap(now);
        &self.sessions
    }

    pub fn session_begin(&mut self, key: SessionKey, now: OffsetDateTime) {
        self.sessions.reap(now);
        self.sessions.begin(key, now);
    }

    pub fn session_end(&mut self, key: &SessionKey, served: Option<Uuid>, now: OffsetDateTime) {
        self.sessions.end(key, served, now);
    }

    pub fn route_preferences(&self) -> &HashMap<String, Uuid> {
        &self.operator.route_preferences
    }

    /// The verified family → models mapping, as learned so far.
    pub fn families(&self) -> &HashMap<String, Vec<String>> {
        &self.families
    }

    /// The choice an attempt would get now, moving nothing.
    pub fn predict(
        &mut self,
        facts: &selection::RequestFacts<'_>,
        settings: &SelectionSettings,
        now: OffsetDateTime,
    ) -> Result<selection::Choice, selection::Nobody> {
        self.expire_quota(now);
        self.sessions.reap(now);
        let active = self.sessions.active_per_account(now);
        let in_flight = self.sessions.in_flight_per_account();
        let org_holds = self.organisation_holds(now);
        let snapshot = selection::Snapshot {
            accounts: &self.accounts,
            default: self.operator.default,
            route_preferences: &self.operator.route_preferences,
            active_sessions: &active,
            in_flight: &in_flight,
            families: &self.families,
            organisation_holds: &org_holds,
            now,
        };
        selection::select(facts, &snapshot, settings)
    }

    pub fn resolve(&self, reference: &str) -> Result<&Account, Resolve> {
        let matches: Vec<&Account> = self
            .accounts
            .iter()
            .filter(|a| references(a, reference))
            .collect();
        match matches.as_slice() {
            [] => Err(Resolve::NotFound),
            [one] => Ok(one),
            many => Err(Resolve::Ambiguous(
                many.iter().map(|a| a.display_name.clone()).collect(),
            )),
        }
    }

    /// At startup the ranking picks the default; nothing eligible → the first account.
    pub fn choose_initial_default(
        &mut self,
        settings: &SelectionSettings,
        now: OffsetDateTime,
    ) -> Option<Uuid> {
        let (no_preferences, no_load) = (HashMap::new(), HashMap::new());
        let (no_families, no_orgs) = (HashMap::new(), HashMap::new());
        let snapshot = selection::Snapshot {
            accounts: &self.accounts,
            default: None,
            route_preferences: &no_preferences,
            active_sessions: &no_load,
            in_flight: &no_load,
            families: &no_families,
            organisation_holds: &no_orgs,
            now,
        };
        let ranked = selection::select(&selection::RequestFacts::default(), &snapshot, settings)
            .map(|c| c.handle)
            .ok();
        let chosen = ranked.or_else(|| self.accounts.first().map(|a| a.handle));
        self.move_default(chosen, now);
        if let Some(account) = chosen.and_then(|h| self.get(h)) {
            tracing::info!(
                event = "default_chosen",
                acct = %account.display_name,
                cause = if ranked.is_some() { "ranking" } else { "first_configured" },
                "the startup default"
            );
        }
        chosen
    }

    /// The choice for one attempt, with the default moved as the ranking
    /// requires and the session bound as the binding rules require. `facts.binding` is
    /// filled in here from the session store.
    pub fn select(
        &mut self,
        facts: &selection::RequestFacts<'_>,
        session: Option<&SessionKey>,
        quota: &crate::config::QuotaSettings,
        settings: &SelectionSettings,
        now: OffsetDateTime,
    ) -> Result<selection::Choice, selection::Nobody> {
        let facts = selection::RequestFacts {
            session: session.is_some(),
            binding: session.and_then(|k| self.sessions.binding(k)),
            ..facts.clone()
        };
        match self.predict(&facts, settings, now) {
            Ok(choice) => {
                // The ranking's winner becomes the default when the default
                // was barred for a cause of its own (or there was none); a ranking run
                // because this attempt's route or exclusion set passed the default over
                // moves nothing.
                if choice.cause == selection::Cause::Ranking
                    && (self.operator.default.is_none() || choice.default_moved_from.is_some())
                {
                    self.move_default(Some(choice.handle), now);
                    // The ranking's move starts the ramp on the new
                    // default; a switch and a bind do not come through here.
                    self.start_ramp(choice.handle, &settings.ramp, now);
                }
                if choice.binds
                    && let Some(key) = session
                {
                    self.sessions.bind(key, choice.handle);
                }
                Ok(choice)
            }
            Err(nobody) => {
                // When the ordinary rules yield nothing quota-wise, the
                // quota model may offer one revalidation candidate. A pin and a
                // binding are hard choices: they never revalidate.
                if nobody.reason == selection::NoService::AllHeldOrOverThreshold
                    && facts.pin.is_none()
                    && facts.binding.is_none()
                    && let Some(handle) = self.offer_revalidation(&nobody, facts.model, quota, now)
                {
                    return Ok(selection::Choice {
                        handle,
                        cause: selection::Cause::Revalidation,
                        default_moved_from: None,
                        default_moved_cause: None,
                        binds: false,
                        advisor_fallback: false,
                    });
                }
                Err(nobody)
            }
        }
    }

    /// Whether this account may be challenged now. Held accounts wait
    /// out the floor after their most recent 429; threshold-only exclusion
    /// qualifies at once.
    fn revalidation_ready(
        &self,
        account: &Account,
        quota: &crate::config::QuotaSettings,
        now: OffsetDateTime,
    ) -> bool {
        let held = self.throttle_hold_end(account.handle, now).is_some()
            || account
                .quota
                .iter()
                .any(|b| b.state(now) == quota::State::Exhausted)
            || account
                .profile
                .organization_uuid
                .and_then(|o| self.organisation_quota.get(&o))
                .is_some_and(|b| b.state(now) == quota::State::Exhausted);
        !held
            || self
                .admission
                .get(&account.handle)
                .and_then(|a| a.last_429)
                .is_some_and(|t| {
                    now - t >= time::Duration::seconds(quota.revalidation_floor_seconds as i64)
                })
    }

    /// The quota model's one revalidation candidate, or none.
    /// Consumes the server-wide gate when it offers one: the interval is
    /// spent in every case.
    fn offer_revalidation(
        &mut self,
        nobody: &selection::Nobody,
        model: Option<&str>,
        quota_settings: &crate::config::QuotaSettings,
        now: OffsetDateTime,
    ) -> Option<Uuid> {
        if self.next_revalidation.is_some_and(|t| t > now) {
            tracing::debug!(event = "revalidation_gate_closed", next = ?self.next_revalidation, "a revalidation already ran in this interval");
            return None;
        }
        let family = self.family_for(model);
        let ready: Vec<&Account> = nobody
            .revalidation_pool
            .iter()
            .filter_map(|h| self.get(*h))
            .filter(|a| self.revalidation_ready(a, quota_settings, now))
            .collect();
        let candidate = ready.iter().copied().min_by(|a, b| {
            let (util_a, age_a, ref_a) = candidate_rank(a, family);
            let (util_b, age_b, ref_b) = candidate_rank(b, family);
            util_a
                .total_cmp(&util_b)
                .then(age_a.cmp(&age_b))
                .then(ref_a.cmp(&ref_b))
        })?;
        let (name, handle, log) = (
            candidate.display_name.clone(),
            candidate.handle,
            challenge(nobody, model, candidate, now),
        );
        self.next_revalidation = Some(
            now + time::Duration::seconds(quota_settings.revalidation_interval_seconds as i64),
        );
        tracing::info!(
            event = "revalidation_started",
            acct = %name,
            fact = %log,
            next_at = ?self.next_revalidation,
            "one stale or held quota fact is challenged"
        );
        Some(handle)
    }

    /// Dropped from rotation until the operator acts.
    pub fn mark_errored(&mut self, handle: Uuid, reason: String, now: OffsetDateTime) {
        if let Some(a) = self.get_mut(handle) {
            a.errored = Some(Errored { reason, at: now });
        }
    }

    fn family_if_unchanged(
        &mut self,
        handle: Uuid,
        sent: Option<&Secret>,
    ) -> Result<&mut OAuthCredential, Stale> {
        let account = self.get_mut(handle).ok_or(Stale::AccountRemoved)?;
        let Credential::OAuth(family) = &mut account.credential else {
            return Err(Stale::FamilyReplaced);
        };
        if family.refresh_token.as_ref() != sent {
            return Err(Stale::FamilyReplaced);
        }
        Ok(family)
    }

    pub fn replace_family(
        &mut self,
        handle: Uuid,
        sent: Option<&Secret>,
        family: OAuthCredential,
    ) -> Result<(), Stale> {
        *self.family_if_unchanged(handle, sent)? = family;
        Ok(())
    }

    pub fn note_refresh_attempt(
        &mut self,
        handle: Uuid,
        sent: Option<&Secret>,
        now: OffsetDateTime,
    ) -> Result<(), Stale> {
        self.family_if_unchanged(handle, sent)?
            .last_refresh_attempt_at = Some(now);
        Ok(())
    }

    pub fn set_refresh_not_before(
        &mut self,
        handle: Uuid,
        sent: Option<&Secret>,
        until: OffsetDateTime,
    ) -> Result<(), Stale> {
        self.family_if_unchanged(handle, sent)?.refresh_not_before = Some(until);
        Ok(())
    }

    pub fn mark_refresh_errored(
        &mut self,
        handle: Uuid,
        sent: Option<&Secret>,
        reason: String,
        now: OffsetDateTime,
    ) -> Result<(), Stale> {
        self.family_if_unchanged(handle, sent)?
            .last_refresh_attempt_at = Some(now);
        self.get_mut(handle).expect("family exists").errored = Some(Errored { reason, at: now });
        Ok(())
    }

    /// Headers teach only the serving account. Returns whether quota changed.
    pub fn observe_response_headers(
        &mut self,
        handle: Uuid,
        model: Option<&str>,
        headers: &HeaderMap,
        now: OffsetDateTime,
    ) -> bool {
        self.learn_family(model, headers);
        let Some(a) = self.get_mut(handle) else {
            return false;
        };
        let observations = a.provider.observe_headers(a.kind(), headers);
        if observations.is_empty() {
            return false;
        }
        quota::apply(
            &mut a.quota,
            observations,
            quota::Source::ResponseHeaders,
            now,
        );
        true
    }

    /// A usage response updates only an OAuth account and never
    /// increments its traffic counters.
    pub fn observe_usage(
        &mut self,
        handle: Uuid,
        observations: Vec<quota::Observation>,
        now: OffsetDateTime,
    ) -> bool {
        let Some(account) = self.get_mut(handle) else {
            return false;
        };
        if account.kind() != Kind::OAuth || observations.is_empty() {
            return false;
        }
        quota::apply(&mut account.quota, observations, quota::Source::Usage, now);
        true
    }

    /// Token usage attributed to the serving account.
    pub fn add_usage(&mut self, handle: Uuid, input_tokens: u64, output_tokens: u64) {
        let u = self.usage.entry(handle).or_default();
        u.input_tokens += input_tokens;
        u.output_tokens += output_tokens;
    }

    pub fn count_request(&mut self, handle: Uuid) {
        self.usage.entry(handle).or_default().requests += 1;
    }

    /// The model→family header mapping is the only source of the family mapping. `7d_oi-*`
    /// headers on an attempt for a model make that model governed by
    /// `weekly:fable` (runtime only; the mapping is verified again on every
    /// response that carries it).
    fn learn_family(&mut self, model: Option<&str>, headers: &HeaderMap) {
        let Some(model) = model else { return };
        let fable = headers.iter().any(|(name, _)| {
            name.as_str()
                .strip_prefix(anthropic::RATELIMIT_UNIFIED_PREFIX)
                .is_some_and(|rest| rest.starts_with(anthropic::FAMILY_FABLE_HEADER))
        });
        if fable {
            let models = self.families.entry(quota::FAMILY_FABLE.into()).or_default();
            if !models.iter().any(|m| m == model) {
                models.push(model.to_string());
            }
        }
    }
}

/// The revalidation log line names the fact being challenged.
fn challenge(
    nobody: &selection::Nobody,
    model: Option<&str>,
    candidate: &Account,
    now: OffsetDateTime,
) -> String {
    let what = model.unwrap_or("any model");
    let held = candidate
        .quota
        .iter()
        .find(|b| b.state(now) == quota::State::Exhausted)
        .map(|b| format!("the hold on {}", b.name));
    let fact = held.unwrap_or_else(|| {
        nobody
            .retry_at
            .map(|t| format!("the threshold until {}", crate::timestamp::rfc3339(t)))
            .unwrap_or_else(|| "the switch threshold".into())
    });
    format!("{what} against {fact}")
}

#[cfg(test)]
mod tests {
    use super::*;
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
            Credential::OAuth(account::OAuthCredential {
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
    fn refresh_publish_does_not_overwrite_a_replaced_family() {
        let mut account = oauth("a@x.io", Some("One"), Uuid::new_v4());
        let Credential::OAuth(family) = &mut account.credential else {
            unreachable!()
        };
        let sent = Secret::new("old-refresh".into());
        family.refresh_token = Some(sent.clone());
        let mut pool = Pool::from_accounts(vec![account], datetime!(2026-09-17 00:00 UTC));
        let handle = pool.accounts()[0].handle;
        let replacement = Secret::new("operator-refresh".into());
        let mut installed = match &pool.get(handle).unwrap().credential {
            Credential::OAuth(family) => family.clone(),
            Credential::ApiKey(_) => unreachable!(),
        };
        installed.refresh_token = Some(replacement.clone());
        pool.replace_family(handle, Some(&sent), installed.clone())
            .unwrap();

        let mut stale_result = installed.clone();
        stale_result.access_token = Secret::new("stale-rotation".into());
        assert_eq!(
            pool.replace_family(handle, Some(&sent), stale_result),
            Err(Stale::FamilyReplaced)
        );
        assert_eq!(
            pool.get(handle).unwrap().credential,
            Credential::OAuth(installed)
        );
    }

    /// One OAuth account holding refresh token `refresh`, with its family for
    /// byte-equal comparisons.
    fn guarded_pool() -> (Pool, Uuid, OAuthCredential, Secret) {
        let mut account = oauth("a@x.io", Some("One"), Uuid::new_v4());
        let Credential::OAuth(family) = &mut account.credential else {
            unreachable!()
        };
        family.access_token = Secret::new("access".into());
        family.refresh_token = Some(Secret::new("refresh".into()));
        let held = match &account.credential {
            Credential::OAuth(family) => family.clone(),
            _ => unreachable!(),
        };
        let pool = Pool::from_accounts(vec![account], datetime!(2026-09-17 00:00 UTC));
        let handle = pool.accounts()[0].handle;
        (pool, handle, held, Secret::new("refresh".into()))
    }

    #[test]
    fn guarded_writes_refuse_an_account_removed_under_the_operation() {
        let (mut pool, handle, held, sent) = guarded_pool();
        pool.remove(handle);
        let now = datetime!(2026-09-17 00:00 UTC);
        let mut rotated = held.clone();
        rotated.access_token = Secret::new("rotated".into());

        assert_eq!(
            pool.replace_family(handle, Some(&sent), rotated),
            Err(Stale::AccountRemoved)
        );
        assert_eq!(
            pool.note_refresh_attempt(handle, Some(&sent), now),
            Err(Stale::AccountRemoved)
        );
        assert_eq!(
            pool.set_refresh_not_before(handle, Some(&sent), now + time::Duration::seconds(30)),
            Err(Stale::AccountRemoved)
        );
        assert_eq!(
            pool.mark_refresh_errored(handle, Some(&sent), "reason".into(), now),
            Err(Stale::AccountRemoved)
        );
        assert!(pool.accounts().is_empty(), "removal is never resurrected");
    }

    #[test]
    fn guarded_writes_apply_inside_the_same_lineage() {
        let (mut pool, handle, held, sent) = guarded_pool();
        let mut rotated = held;
        rotated.access_token = Secret::new("rotated".into());

        pool.replace_family(handle, Some(&sent), rotated.clone())
            .expect("the same refresh token is the same lineage");
        assert_eq!(
            pool.get(handle).unwrap().credential,
            Credential::OAuth(rotated)
        );
    }

    #[test]
    fn sent_none_matches_only_a_family_that_still_has_no_refresh_token() {
        let (mut pool, handle, held, _) = guarded_pool();
        let mut replacement = held.clone();
        replacement.access_token = Secret::new("rotated".into());

        assert_eq!(
            pool.replace_family(handle, None, replacement),
            Err(Stale::FamilyReplaced),
            "a family that gained a refresh token is a replaced lineage"
        );

        // The no-refresh-material branch matches only a family with none.
        pool.get_mut(handle)
            .expect("the guarded account")
            .credential = Credential::OAuth(OAuthCredential {
            access_token: Secret::new("access".into()),
            refresh_token: None,
            ..held
        });
        let mut without = match pool.accounts()[0].credential.clone() {
            Credential::OAuth(family) => family,
            _ => unreachable!(),
        };
        without.access_token = Secret::new("rotated".into());
        pool.replace_family(handle, None, without)
            .expect("the no-refresh-material branch matches a family with none");
    }

    #[test]
    fn references_resolve_every_form_and_report_ambiguity() {
        let mut pool = Pool::default();
        let id = Uuid::new_v4();
        let h1 = pool.add(oauth("a@x.io", Some("One"), id), None).unwrap();
        let h2 = pool
            .add(oauth("a@x.io", Some("Two"), Uuid::new_v4()), None)
            .unwrap();
        assert_eq!(pool.resolve("A@X.IO (two)").unwrap().handle, h2);
        assert_eq!(
            pool.resolve(&h1.to_string().to_uppercase()).unwrap().handle,
            h1
        );
        assert_eq!(pool.resolve(&id.to_string()).unwrap().handle, h1);
        assert_eq!(pool.resolve("nobody"), Err(Resolve::NotFound));
        assert_eq!(
            pool.resolve("a@x.io"),
            Err(Resolve::Ambiguous(vec![
                "a@x.io (One)".into(),
                "a@x.io (Two)".into()
            ]))
        );
        // The first holder's derived name collides under folding.
        assert_eq!(
            pool.add(
                oauth("b@x.io", None, Uuid::new_v4()),
                Some("A@X.IO (ONE)".into())
            ),
            Err(OperationError::NameConflict("A@X.IO (ONE)".into()))
        );
    }
}
