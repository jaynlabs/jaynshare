//! Which account serves an attempt: a pure function of request facts, a snapshot
//! and configuration. Precedence is: pin,
//! preference, operator route preference, the session's binding, the default,
//! the ranking, and the revalidation offer the caller makes.

use std::collections::HashMap;

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::{Route, SelectionSettings};
use crate::provider::Provider;

use super::account::{Account, Kind};
use super::quota::{Bucket, SESSION, State, WEEKLY};

/// The request facts, as their consumers read them.
#[derive(Debug, Default, Clone)]
pub struct RequestFacts<'a> {
    /// Selection sees only this provider's accounts.
    pub provider: Provider,
    pub model: Option<&'a str>,
    pub advisor_model: Option<&'a str>,
    pub exclusion: &'a [Uuid],
    /// The pinned account, already resolved.
    pub pin: Option<Uuid>,
    /// `pref.`: the preferred account, already resolved.
    pub preference: Option<Uuid>,
    /// The attempt belongs to a session, so its first answer binds.
    pub session: bool,
    /// The session's binding, when it has one.
    pub binding: Option<Uuid>,
}

/// The rule that produced an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cause {
    Pin,
    Preference,
    #[serde(rename = "route")]
    RoutePreference,
    Session,
    Default,
    Ranking,
    Revalidation,
}

/// Why nobody serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoService {
    NoAccountConfigured,
    AllDisabledOrErrored,
    AllHeldOrOverThreshold,
    PinnedUnavailable,
    RouteExhausted,
    AllTried,
}

/// Why one account is ineligible now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ineligible {
    Disabled,
    Errored,
    Held,
    OverThreshold,
}

/// Why the default moved — the old default's own reason, or gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MoveCause {
    Disabled,
    Errored,
    Held,
    OverThreshold,
    Removed,
}

impl std::fmt::Display for MoveCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disabled => "disabled",
            Self::Errored => "errored",
            Self::Held => "held",
            Self::OverThreshold => "over_threshold",
            Self::Removed => "removed",
        })
    }
}

impl From<Ineligible> for MoveCause {
    fn from(why: Ineligible) -> Self {
        match why {
            Ineligible::Disabled => Self::Disabled,
            Ineligible::Errored => Self::Errored,
            Ineligible::Held => Self::Held,
            Ineligible::OverThreshold => Self::OverThreshold,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Choice {
    pub handle: Uuid,
    pub cause: Cause,
    /// Set when the ranking moved the default.
    pub default_moved_from: Option<Uuid>,
    /// The old default's reason, beside `default_moved_from`.
    pub default_moved_cause: Option<MoveCause>,
    /// The attempt is a session's first, so this answer binds it.
    pub binds: bool,
    /// The answer came from the request-model-only pass.
    pub advisor_fallback: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Nobody {
    pub reason: NoService,
    /// Soonest hold end or reset among the candidates.
    pub retry_at: Option<OffsetDateTime>,
    /// The bound (or pinned) account the reason names.
    pub named: Option<Uuid>,
    /// The accounts the quota model may pick a revalidation candidate from — those
    /// enabled, route-listed and eligible, restricted to their highest tier.
    pub revalidation_pool: Vec<Uuid>,
    /// The state is a quota bar, which clears without
    /// operator action, so the exchange may wait for it; every other reason
    /// answers at once.
    pub clears: bool,
}

pub struct Snapshot<'a> {
    /// One provider's accounts, with its default.
    pub accounts: Vec<&'a Account>,
    pub default: Option<Uuid>,
    /// Route name → the account the operator prefers for it.
    pub route_preferences: &'a HashMap<String, Uuid>,
    /// Active sessions and in-flight exchanges per bound account.
    pub active_sessions: &'a HashMap<Uuid, usize>,
    pub in_flight: &'a HashMap<Uuid, usize>,
    /// Verified family → the models seen governed by it. Runtime only.
    pub families: &'a HashMap<String, Vec<String>>,
    /// Organisation UUID → its spend-cap hold end, shared by its accounts.
    pub organisation_holds: &'a HashMap<Uuid, OffsetDateTime>,
    pub now: OffsetDateTime,
}

/// `*` matches any run; everything else literal; whole id, case-insensitive.
pub fn glob_matches(pattern: &str, model: &str) -> bool {
    fn go(p: &[u8], m: &[u8]) -> bool {
        match (p.first(), m.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], m) || (!m.is_empty() && go(p, &m[1..])),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => go(&p[1..], &m[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), model.as_bytes())
}

/// The first route whose pattern matches the model.
pub fn route_for<'c>(routes: &'c [Route], model: &str) -> Option<&'c Route> {
    routes
        .iter()
        .find(|r| r.patterns.iter().any(|p| glob_matches(p, model)))
}

/// The first blocked pattern matching either model.
pub fn blocked_by<'c>(
    settings: &'c SelectionSettings,
    facts: &RequestFacts<'_>,
) -> Option<&'c str> {
    settings
        .blocked_models
        .iter()
        .find(|p| {
            [facts.model, facts.advisor_model]
                .into_iter()
                .flatten()
                .any(|m| glob_matches(p, m))
        })
        .map(String::as_str)
}

/// Eligibility with no model, pin, preference, session or exclusion.
/// `org_hold` is the account's shared organisation spend-cap hold, when one runs.
pub fn eligibility(
    account: &Account,
    settings: &SelectionSettings,
    now: OffsetDateTime,
    org_hold: Option<OffsetDateTime>,
) -> Result<(), Ineligible> {
    quota_bar(account, settings, now, false, None, None, org_hold).map_err(Ineligible::from)
}

/// Eligibility for a model matching the route's first pattern, with
/// the route's bucket override in force. The pattern stands in for
/// the model verbatim, so a family bucket takes part only when the pattern is
/// a literal model id the pool has learned.
pub fn eligibility_for_route(
    account: &Account,
    route: &Route,
    settings: &SelectionSettings,
    families: &HashMap<String, Vec<String>>,
    now: OffsetDateTime,
    org_hold: Option<OffsetDateTime>,
) -> Result<(), Ineligible> {
    let model = route.patterns.first().map(String::as_str);
    let family = family_for(model, families, account, now);
    quota_bar(
        account,
        settings,
        now,
        false,
        family,
        route.bucket.as_deref(),
        org_hold,
    )
    .map_err(Ineligible::from)
}

/// Selectable now for the client catalogue — enabled and not errored, and some
/// model the data plane may serve (a learned model id the block list does not
/// match) passes the quota filters. No route, pin, preference,
/// session or exclusion set takes part, and nothing moves.
pub fn selectable(
    account: &Account,
    settings: &SelectionSettings,
    families: &HashMap<String, Vec<String>>,
    now: OffsetDateTime,
    org_hold: Option<OffsetDateTime>,
) -> bool {
    if !account.enabled || account.errored.is_some() {
        return false;
    }
    // The witness is "one model the data plane may serve". The pool has
    // no model catalogue — `families` holds only the fable mapping,
    // learned from `7d_oi-*` headers — so the witnesses are its models plus
    // one standing for every model in no learned family, which is what a
    // client asks for on a pool that has never served a fable model. Only a
    // block list matching every model takes that last witness away; a
    // pattern does that exactly when it is all `*`.
    let blocks_every_model = settings
        .blocked_models
        .iter()
        .any(|p| !p.is_empty() && p.bytes().all(|b| b == b'*'));
    if !blocks_every_model && quota_bar(account, settings, now, false, None, None, org_hold).is_ok()
    {
        return true;
    }
    families.values().flatten().any(|model| {
        let facts = RequestFacts {
            model: Some(model),
            ..RequestFacts::default()
        };
        if blocked_by(settings, &facts).is_some() {
            return false;
        }
        let family = family_for(Some(model), families, account, now);
        quota_bar(account, settings, now, false, family, None, org_hold).is_ok()
    })
}

impl From<Bar> for Ineligible {
    fn from(bar: Bar) -> Self {
        match bar {
            Bar::Disabled => Self::Disabled,
            Bar::Errored => Self::Errored,
            Bar::Held(_) => Self::Held,
            Bar::OverThreshold(_) => Self::OverThreshold,
        }
    }
}

/// The bars on one account; the time is the hold end or reset behind the bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bar {
    Disabled,
    Errored,
    Held(Option<OffsetDateTime>),
    OverThreshold(Option<OffsetDateTime>),
}

fn quota_bar(
    account: &Account,
    settings: &SelectionSettings,
    now: OffsetDateTime,
    bound: bool,
    family: Option<&str>,
    override_bucket: Option<&str>,
    org_hold: Option<OffsetDateTime>,
) -> Result<(), Bar> {
    if !account.enabled {
        return Err(Bar::Disabled);
    }
    if account.errored.is_some() {
        return Err(Bar::Errored);
    }
    // The organisation spend-cap hold affects every request its accounts make.
    if let Some(end) = org_hold {
        return Err(Bar::Held(Some(end)));
    }
    for bucket in governing_buckets(account, family, override_bucket) {
        // An exhaustion hold bars the account for that bucket's models.
        if bucket.state(now) == State::Exhausted {
            return Err(Bar::Held(bucket.exhaustion_hold_until));
        }
        // At or over the switch threshold; unknown counts as under.
        // The threshold does not bar a bound attempt.
        if !bound
            && bucket
                .effective_utilization()
                .is_some_and(|u| u >= settings.switch_threshold)
        {
            return Err(Bar::OverThreshold(bucket.reset_at));
        }
    }
    Ok(())
}

/// Session and one weekly window for a subscription — the route's
/// override when one names it, else the verified family's bucket
/// when the model is known for it, else the shared one — and every counter
/// with a limit for an API key, whose governing set has no weekly slot to
/// replace.
fn governing_buckets<'a>(
    account: &'a Account,
    family: Option<&str>,
    override_bucket: Option<&str>,
) -> impl Iterator<Item = &'a Bucket> {
    // A verified family names its weekly bucket `weekly:<family>`.
    let weekly = override_bucket.map(str::to_string).unwrap_or_else(|| {
        family
            .map(|f| format!("{WEEKLY}:{f}"))
            .unwrap_or_else(|| WEEKLY.to_string())
    });
    account.quota.iter().filter(move |b| match account.kind() {
        Kind::OAuth => b.name == SESSION || b.name == weekly,
        Kind::ApiKey => b.limit.is_some(),
    })
}

pub fn priority_of(account: &Account, settings: &SelectionSettings) -> i64 {
    settings
        .priorities
        .iter()
        .find(|p| super::references(account, &p.account))
        .map_or(0, |p| p.value)
}

/// The verified family whose weekly bucket governs this model, when
/// the account has a current observation for that bucket.
fn family_for<'a>(
    model: Option<&str>,
    families: &'a HashMap<String, Vec<String>>,
    account: &Account,
    now: OffsetDateTime,
) -> Option<&'a str> {
    let model = model?;
    families
        .iter()
        .find(|(_, models)| models.iter().any(|m| m == model))
        .map(|(family, _)| family.as_str())
        .filter(|f| {
            let name = format!("{WEEKLY}:{f}");
            account
                .quota
                .iter()
                .find(|b| b.name == name)
                .is_some_and(|b| b.observed_at.is_some_and(|t| t <= now))
        })
}

/// The tie order within a tier: unknown weekly reset first, then soonest.
fn weekly_reset_rank(account: &Account) -> (bool, Option<OffsetDateTime>) {
    let reset = governing_buckets(account, None, None)
        .filter(|b| b.name == WEEKLY)
        .find_map(|b| b.reset_at);
    (reset.is_some(), reset)
}

/// One pass of the precedence rules for one model set. Everything here is read-only.
struct Pass<'a> {
    facts: &'a RequestFacts<'a>,
    snapshot: &'a Snapshot<'a>,
    settings: &'a SelectionSettings,
    models: Vec<&'a str>,
}

impl<'a> Pass<'a> {
    fn account(&self, handle: Uuid) -> Option<&'a Account> {
        self.snapshot
            .accounts
            .iter()
            .copied()
            .find(|a| a.handle == handle)
    }

    fn priority(&self, account: &Account) -> i64 {
        priority_of(account, self.settings)
    }

    /// The account is one the model's route lists (or the route lists none).
    fn route_allows(&self, account: &Account) -> bool {
        self.models.iter().all(|m| {
            match route_for(&self.settings.routes, m).and_then(|r| r.accounts.as_deref()) {
                Some(list) => list.iter().any(|r| super::references(account, r)),
                None => true,
            }
        })
    }

    fn excluded(&self, account: &Account) -> bool {
        self.facts.exclusion.contains(&account.handle)
    }

    fn org_hold(&self, account: &Account) -> Option<OffsetDateTime> {
        account
            .profile
            .organization_uuid
            .and_then(|o| self.snapshot.organisation_holds.get(&o).copied())
            .filter(|t| *t > self.snapshot.now)
    }

    fn eligible(&self, account: &Account, bound: bool) -> bool {
        self.route_allows(account)
            && !self.excluded(account)
            && self.quota_bar(account, bound).is_ok()
    }

    /// The quota state for one account, on every model of the pass: each
    /// model's family and its route's bucket override decide the
    /// governing weekly bucket; the first bar wins.
    fn quota_bar(&self, account: &'a Account, bound: bool) -> Result<(), Bar> {
        let models: Vec<Option<&str>> = if self.models.is_empty() {
            vec![None]
        } else {
            self.models.iter().map(|m| Some(*m)).collect()
        };
        for model in models {
            let family = family_for(model, self.snapshot.families, account, self.snapshot.now);
            let override_bucket = model
                .and_then(|m| route_for(&self.settings.routes, m))
                .and_then(|r| r.bucket.as_deref());
            quota_bar(
                account,
                self.settings,
                self.snapshot.now,
                bound,
                family,
                override_bucket,
                self.org_hold(account),
            )?;
        }
        Ok(())
    }

    /// A bound account is served or names the reason it cannot be.
    fn bound(&self, handle: Uuid) -> Option<Result<Choice, Nobody>> {
        let account = self.account(handle)?;
        let nobody = |reason, retry_at| Nobody {
            reason,
            retry_at,
            named: Some(handle),
            revalidation_pool: Vec::new(),
            clears: reason == NoService::AllHeldOrOverThreshold,
        };
        Some(if !self.route_allows(account) {
            Err(nobody(NoService::RouteExhausted, None))
        } else if self.excluded(account) {
            Err(nobody(NoService::AllTried, None))
        } else {
            match self.quota_bar(account, true) {
                Ok(()) => Ok(Choice {
                    handle,
                    cause: Cause::Session,
                    default_moved_from: None,
                    default_moved_cause: None,
                    binds: false,
                    advisor_fallback: false,
                }),
                Err(Bar::Disabled | Bar::Errored) => {
                    Err(nobody(NoService::AllDisabledOrErrored, None))
                }
                Err(Bar::Held(at) | Bar::OverThreshold(at)) => {
                    Err(nobody(NoService::AllHeldOrOverThreshold, at))
                }
            }
        })
    }

    /// The request model's route preference, else the advisor model's.
    fn route_preference(&self) -> Option<Uuid> {
        self.models.iter().find_map(|m| {
            let route = route_for(&self.settings.routes, m)?;
            self.snapshot.route_preferences.get(&route.name).copied()
        })
    }

    fn run(&self) -> Result<Choice, Nobody> {
        let binds = self.facts.session && self.facts.binding.is_none();
        let choice = |handle, cause| Choice {
            handle,
            cause,
            default_moved_from: None,
            default_moved_cause: None,
            binds,
            advisor_fallback: false,
        };
        // Rule 1: a pin is served by that account or nobody.
        if let Some(pin) = self.facts.pin {
            let account = self.account(pin);
            return match account {
                Some(a) if self.eligible(a, false) => Ok(choice(pin, Cause::Pin)),
                _ => Err(Nobody {
                    reason: NoService::PinnedUnavailable,
                    retry_at: None,
                    named: Some(pin),
                    revalidation_pool: Vec::new(),
                    clears: false,
                }),
            };
        }
        // Rule 2: an eligible preference serves regardless of tier, default or session.
        if let Some(preferred) = self.facts.preference
            && let Some(a) = self.account(preferred)
            && self.eligible(a, false)
        {
            return Ok(choice(preferred, Cause::Preference));
        }
        // Rule 3: the operator's route preference while it is eligible.
        if let Some(preferred) = self.route_preference()
            && let Some(a) = self.account(preferred)
            && self.eligible(a, false)
        {
            return Ok(choice(preferred, Cause::RoutePreference));
        }
        // Rule 4: a bound session is served by its binding and nothing else runs.
        if let Some(bound) = self.facts.binding
            && let Some(answer) = self.bound(bound)
        {
            return answer;
        }
        let allowed: Vec<&Account> = self
            .snapshot
            .accounts
            .iter()
            .copied()
            .filter(|a| self.route_allows(a))
            .collect();
        let routed = self
            .models
            .iter()
            .any(|m| route_for(&self.settings.routes, m).is_some_and(|r| r.accounts.is_some()));
        let nobody = |reason, retry_at, pool| Nobody {
            reason,
            retry_at,
            named: None,
            revalidation_pool: pool,
            clears: false,
        };
        if allowed.is_empty() {
            return Err(nobody(NoService::RouteExhausted, None, Vec::new()));
        }
        let not_tried: Vec<&Account> = allowed
            .iter()
            .copied()
            .filter(|a| !self.excluded(a))
            .collect();
        if not_tried.is_empty() {
            return Err(nobody(NoService::AllTried, None, Vec::new()));
        }
        let usable: Vec<&Account> = not_tried
            .iter()
            .copied()
            .filter(|a| a.is_usable())
            .collect();
        if usable.is_empty() {
            return Err(nobody(NoService::AllDisabledOrErrored, None, Vec::new()));
        }
        let eligible: Vec<&Account> = usable
            .iter()
            .copied()
            .filter(|a| self.quota_bar(a, false).is_ok())
            .collect();
        if eligible.is_empty() {
            // The soonest hold end or reset across the candidates, the
            // organisation spend-cap hold included; the revalidation pool
            // is the highest tier among those usable.
            let retry_at = usable
                .iter()
                .filter_map(|a| {
                    let per_account = governing_buckets(a, None, None)
                        .filter_map(|b| b.exhaustion_hold_until.max(b.reset_at))
                        .chain(self.org_hold(a));
                    per_account.filter(|t| *t > self.snapshot.now).min()
                })
                .min();
            let top = usable
                .iter()
                .map(|a| self.priority(a))
                .min()
                .expect("non-empty");
            let pool = usable
                .iter()
                .filter(|a| self.priority(a) == top)
                .map(|a| a.handle)
                .collect();
            // An exclusive route whose usable candidates are all
            // quota-barred clears on its own, like the whole pool's.
            return Err(Nobody {
                clears: true,
                ..nobody(
                    if routed {
                        NoService::RouteExhausted
                    } else {
                        NoService::AllHeldOrOverThreshold
                    },
                    retry_at,
                    pool,
                )
            });
        }
        // With distribution on, a session's first attempt lands on the
        // least-loaded eligible account; the default does not move.
        if self.settings.distribute_sessions && binds {
            let winner = eligible
                .iter()
                .copied()
                .min_by_key(|a| {
                    (
                        self.priority(a),
                        self.snapshot
                            .active_sessions
                            .get(&a.handle)
                            .copied()
                            .unwrap_or(0),
                        self.snapshot.in_flight.get(&a.handle).copied().unwrap_or(0),
                        weekly_reset_rank(a),
                    )
                })
                .expect("non-empty");
            return Ok(choice(winner.handle, Cause::Session));
        }
        // Rule 5: the default serves every attempt it is eligible for; nothing preempts it.
        if let Some(default) = self.snapshot.default
            && eligible.iter().any(|a| a.handle == default)
        {
            return Ok(choice(default, Cause::Default));
        }
        // Rule 6: lowest priority, unknown weekly reset first, then soonest.
        let winner = eligible
            .iter()
            .copied()
            .min_by_key(|a| (self.priority(a), weekly_reset_rank(a)))
            .expect("non-empty");
        // The default moves for a cause of its own — hold, errored,
        // disabled, threshold, or gone from the pool — never because this
        // attempt's route or exclusion set passed it over.
        let default_moved_cause = self.snapshot.default.and_then(|d| match self.account(d) {
            None => Some(MoveCause::Removed),
            Some(a) => self
                .quota_bar(a, false)
                .err()
                .map(|bar| MoveCause::from(Ineligible::from(bar))),
        });
        Ok(Choice {
            handle: winner.handle,
            cause: Cause::Ranking,
            default_moved_from: self
                .snapshot
                .default
                .filter(|_| default_moved_cause.is_some()),
            default_moved_cause,
            binds,
            advisor_fallback: false,
        })
    }
}

/// One answer and its
/// cause, or nobody and the reason. With an advisor model the rules run with both
/// models first and with the request model alone if that yields nobody.
pub fn select(
    facts: &RequestFacts<'_>,
    snapshot: &Snapshot<'_>,
    settings: &SelectionSettings,
) -> Result<Choice, Nobody> {
    if snapshot.accounts.is_empty() {
        return Err(Nobody {
            reason: NoService::NoAccountConfigured,
            retry_at: None,
            named: None,
            revalidation_pool: Vec::new(),
            clears: false,
        });
    }
    let request_only: Vec<&str> = facts.model.into_iter().collect();
    let both: Vec<&str> = facts.model.into_iter().chain(facts.advisor_model).collect();
    let first = Pass {
        facts,
        snapshot,
        settings,
        models: both,
    }
    .run();
    match (first, facts.advisor_model) {
        (Ok(choice), _) => Ok(choice),
        (Err(nobody), None) => Err(nobody),
        (Err(_), Some(_)) => Pass {
            facts,
            snapshot,
            settings,
            models: request_only,
        }
        .run()
        .map(|c| Choice {
            advisor_fallback: true,
            ..c
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::pool::account::{Credential, Profile, Secret, Source};
    use crate::pool::quota::{Bucket, Scope};
    use time::macros::datetime;

    fn settings() -> SelectionSettings {
        config::parse(b"version = 1\n", std::path::Path::new("/"))
            .unwrap()
            .selection
    }

    fn account(name: &str) -> Account {
        Account::new(
            crate::provider::Provider::Anthropic,
            name.into(),
            Profile::default(),
            Source::ApiKeyEntry,
            Credential::ApiKey(Secret::new("k".into())),
        )
    }

    fn oauth(name: &str, weekly_utilization: f64) -> Account {
        let mut a = Account::new(
            crate::provider::Provider::Anthropic,
            name.into(),
            Profile::default(),
            Source::PortableJson,
            Credential::OAuth(crate::pool::account::OAuthCredential {
                access_token: Secret::new("t".into()),
                refresh_token: None,
                expires_at: datetime!(2027-01-01 00:00 UTC),
                last_refresh_attempt_at: None,
                last_refresh_success_at: None,
                refresh_not_before: None,
            }),
        );
        a.quota = vec![
            Bucket::unknown(SESSION, Scope::Account),
            Bucket {
                utilization: Some(weekly_utilization),
                observed_at: Some(NOW),
                ..Bucket::unknown(WEEKLY, Scope::Account)
            },
        ];
        a
    }

    const NOW: OffsetDateTime = datetime!(2026-09-16 00:00 UTC);

    struct Fixture {
        accounts: Vec<Account>,
        default: Option<Uuid>,
        route_preferences: HashMap<String, Uuid>,
        active: HashMap<Uuid, usize>,
        in_flight: HashMap<Uuid, usize>,
    }

    impl Fixture {
        fn new(accounts: Vec<Account>, default: Option<Uuid>) -> Self {
            Self {
                accounts,
                default,
                route_preferences: HashMap::new(),
                active: HashMap::new(),
                in_flight: HashMap::new(),
            }
        }

        fn snapshot(&self) -> Snapshot<'_> {
            static EMPTY: std::sync::LazyLock<HashMap<String, Vec<String>>> =
                std::sync::LazyLock::new(HashMap::new);
            static ORGS: std::sync::LazyLock<HashMap<Uuid, OffsetDateTime>> =
                std::sync::LazyLock::new(HashMap::new);
            Snapshot {
                accounts: self.accounts.iter().collect(),
                default: self.default,
                route_preferences: &self.route_preferences,
                active_sessions: &self.active,
                in_flight: &self.in_flight,
                families: &EMPTY,
                organisation_holds: &ORGS,
                now: NOW,
            }
        }
    }

    /// An OAuth account with a learned `weekly:fable` beside the shared weekly.
    fn oauth_with_fable(name: &str, weekly: f64, fable: f64) -> Account {
        let mut a = oauth(name, weekly);
        a.quota.push(Bucket {
            utilization: Some(fable),
            observed_at: Some(NOW),
            ..Bucket::unknown(&format!("{WEEKLY}:fable"), Scope::Account)
        });
        a
    }

    fn fable_families() -> HashMap<String, Vec<String>> {
        HashMap::from([("fable".to_string(), vec!["claude-opus-5".to_string()])])
    }

    #[test]
    fn the_advisor_pass_bars_on_any_model_of_the_set() {
        // An account whose advisor family is spent fails the both-models
        // pass and serves the request-only pass.
        let s = settings();
        let a = oauth_with_fable("a", 0.1, 0.99);
        let f = Fixture::new(vec![a.clone()], Some(a.handle));
        let families = fable_families();
        let snapshot = Snapshot {
            families: &families,
            ..f.snapshot()
        };
        let facts = RequestFacts {
            model: Some("claude-haiku-4-5"),
            advisor_model: Some("claude-opus-5"),
            ..RequestFacts::default()
        };
        let choice = select(&facts, &snapshot, &s).unwrap();
        assert_eq!(choice.handle, a.handle);
        assert!(choice.advisor_fallback, "the second pass served");

        // The shared weekly at threshold bars both passes.
        let a = oauth_with_fable("a", 0.99, 0.1);
        let f = Fixture::new(vec![a.clone()], Some(a.handle));
        let snapshot = Snapshot {
            families: &families,
            ..f.snapshot()
        };
        assert_eq!(
            select(&facts, &snapshot, &s).unwrap_err().reason,
            NoService::AllHeldOrOverThreshold
        );
    }

    #[test]
    fn a_route_bucket_override_replaces_the_weekly_slot() {
        // The override governs the route's models on a
        // subscription account; an API key has no weekly slot to replace.
        let mut s = settings();
        s.routes.push(Route {
            name: "b".into(),
            patterns: vec!["*haiku*".into()],
            accounts: None,
            bucket: Some("weekly:fable".into()),
        });
        let a = oauth_with_fable("a", 0.1, 0.99);
        let f = Fixture::new(vec![a.clone()], Some(a.handle));
        let haiku = RequestFacts {
            model: Some("claude-haiku-4-5"),
            ..RequestFacts::default()
        };
        assert_eq!(
            select(&haiku, &f.snapshot(), &s).unwrap_err().reason,
            NoService::AllHeldOrOverThreshold
        );
        let sonnet = RequestFacts {
            model: Some("claude-sonnet-5"),
            ..RequestFacts::default()
        };
        assert_eq!(select(&sonnet, &f.snapshot(), &s).unwrap().handle, a.handle);
        // The route-scoped projection agrees with the pass.
        assert_eq!(
            eligibility_for_route(&a, &s.routes[0], &s, &HashMap::new(), NOW, None),
            Err(Ineligible::OverThreshold)
        );
        assert_eq!(eligibility(&a, &s, NOW, None), Ok(()));
        let key = account("k");
        assert_eq!(
            eligibility_for_route(&key, &s.routes[0], &s, &HashMap::new(), NOW, None),
            Ok(())
        );
    }

    #[test]
    fn the_move_cause_is_the_old_defaults_reason() {
        // Held, errored, disabled, over the threshold, or gone.
        let s = settings();
        let b = oauth("b", 0.1);
        let facts = RequestFacts::default();
        let cause = |old: Account| {
            let f = Fixture::new(vec![old.clone(), b.clone()], Some(old.handle));
            let choice = select(&facts, &f.snapshot(), &s).unwrap();
            assert_eq!(choice.default_moved_from, Some(old.handle));
            choice.default_moved_cause
        };
        let mut over = oauth("a", 0.99);
        assert_eq!(cause(over.clone()), Some(MoveCause::OverThreshold));
        over.quota[1].exhaustion_hold_until = Some(NOW + time::Duration::minutes(5));
        assert_eq!(cause(over), Some(MoveCause::Held));
        let mut disabled = oauth("a", 0.1);
        disabled.enabled = false;
        assert_eq!(cause(disabled), Some(MoveCause::Disabled));
        let mut errored = oauth("a", 0.1);
        errored.errored = Some(crate::pool::Errored {
            reason: "x".into(),
            at: NOW,
        });
        assert_eq!(cause(errored), Some(MoveCause::Errored));
        let gone = Uuid::new_v4();
        let f = Fixture::new(vec![b.clone()], Some(gone));
        let choice = select(&facts, &f.snapshot(), &s).unwrap();
        assert_eq!(choice.default_moved_cause, Some(MoveCause::Removed));
        // No cause when the default was merely passed over by this attempt.
        let a = oauth("a", 0.1);
        let excl = [a.handle];
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let choice = select(
            &RequestFacts {
                exclusion: &excl,
                ..RequestFacts::default()
            },
            &f.snapshot(),
            &s,
        )
        .unwrap();
        assert_eq!(choice.default_moved_cause, None);
        assert_eq!(choice.default_moved_from, None);
    }

    #[test]
    fn glob_is_whole_id_case_insensitive_with_star_only() {
        assert!(glob_matches("*haiku*", "claude-haiku-4-5"));
        assert!(glob_matches("CLAUDE-*", "claude-opus-5"));
        assert!(!glob_matches("haiku", "claude-haiku"));
        assert!(!glob_matches("claude-?", "claude-x"));
        assert!(glob_matches("*", ""));
    }

    #[test]
    fn empty_pool_and_all_tried_have_their_reasons() {
        let s = settings();
        let f = Fixture::new(vec![], None);
        assert_eq!(
            select(&RequestFacts::default(), &f.snapshot(), &s)
                .unwrap_err()
                .reason,
            NoService::NoAccountConfigured
        );
        let a = account("a");
        let excl = [a.handle];
        let f = Fixture::new(vec![a], None);
        let facts = RequestFacts {
            exclusion: &excl,
            ..RequestFacts::default()
        };
        assert_eq!(
            select(&facts, &f.snapshot(), &s).unwrap_err().reason,
            NoService::AllTried
        );
    }

    #[test]
    fn default_sticks_and_ranking_moves_it_when_over_threshold() {
        let s = settings();
        let (a, b) = (oauth("a", 0.5), oauth("b", 0.1));
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let choice = select(&RequestFacts::default(), &f.snapshot(), &s).unwrap();
        assert_eq!((choice.handle, choice.cause), (a.handle, Cause::Default));
        assert!(!choice.binds);

        let mut a = a;
        a.quota[1].utilization = Some(0.99);
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let choice = select(&RequestFacts::default(), &f.snapshot(), &s).unwrap();
        assert_eq!((choice.handle, choice.cause), (b.handle, Cause::Ranking));
        assert_eq!(choice.default_moved_from, Some(a.handle));
        assert_eq!(
            eligibility(&f.accounts[0], &s, NOW, None),
            Err(Ineligible::OverThreshold)
        );
    }

    #[test]
    fn everyone_over_threshold_names_the_soonest_reset_and_the_revalidation_pool() {
        let s = settings();
        let mut a = oauth("a", 1.0);
        a.quota[1].reset_at = Some(NOW + time::Duration::hours(2));
        let f = Fixture::new(vec![a.clone()], None);
        let nobody = select(&RequestFacts::default(), &f.snapshot(), &s).unwrap_err();
        assert_eq!(nobody.reason, NoService::AllHeldOrOverThreshold);
        assert_eq!(nobody.retry_at, Some(NOW + time::Duration::hours(2)));
        assert_eq!(nobody.revalidation_pool, vec![a.handle]);
    }

    #[test]
    fn exclusive_route_restricts_candidates() {
        let mut s = settings();
        let (a, b) = (account("a"), account("b"));
        s.routes.push(Route {
            name: "only-b".into(),
            patterns: vec!["*haiku*".into()],
            accounts: Some(vec!["b".into()]),
            bucket: None,
        });
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let facts = RequestFacts {
            model: Some("claude-haiku"),
            ..RequestFacts::default()
        };
        assert_eq!(select(&facts, &f.snapshot(), &s).unwrap().handle, b.handle);
        let facts = RequestFacts {
            model: Some("claude-opus"),
            ..RequestFacts::default()
        };
        assert_eq!(select(&facts, &f.snapshot(), &s).unwrap().handle, a.handle);
    }

    #[test]
    fn only_a_quota_barred_route_clears_on_its_own() {
        // The exclusive route's one account is over threshold
        // while another serves elsewhere — the state clears at the reset.
        let mut s = settings();
        let (a, b) = (oauth("a", 0.1), oauth("b", 0.99));
        s.routes.push(Route {
            name: "only-b".into(),
            patterns: vec!["*haiku*".into()],
            accounts: Some(vec!["b".into()]),
            bucket: None,
        });
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let haiku = RequestFacts {
            model: Some("claude-haiku"),
            ..RequestFacts::default()
        };
        let nobody = select(&haiku, &f.snapshot(), &s).unwrap_err();
        assert_eq!(nobody.reason, NoService::RouteExhausted);
        assert!(nobody.clears);
        // A route naming no configured account never clears on its own.
        s.routes[0].accounts = Some(vec!["gone".into()]);
        let nobody = select(&haiku, &f.snapshot(), &s).unwrap_err();
        assert_eq!(nobody.reason, NoService::RouteExhausted);
        assert!(!nobody.clears);
        // Neither does a pool with every candidate disabled.
        let mut disabled = a.clone();
        disabled.enabled = false;
        let f = Fixture::new(vec![disabled], None);
        let nobody = select(&RequestFacts::default(), &f.snapshot(), &s).unwrap_err();
        assert_eq!(nobody.reason, NoService::AllDisabledOrErrored);
        assert!(!nobody.clears);
    }

    #[test]
    fn a_higher_tier_never_preempts_the_default() {
        let mut s = settings();
        let (a, b) = (account("a"), account("b"));
        s.priorities.push(config::Priority {
            account: "b".into(),
            value: -1,
        });
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let choice = select(&RequestFacts::default(), &f.snapshot(), &s).unwrap();
        assert_eq!((choice.handle, choice.cause), (a.handle, Cause::Default));
    }

    #[test]
    fn a_session_s_first_attempt_binds_and_its_binding_is_served_past_the_threshold() {
        let s = settings();
        let (a, b) = (oauth("a", 0.5), oauth("b", 0.1));
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let facts = RequestFacts {
            session: true,
            ..RequestFacts::default()
        };
        let choice = select(&facts, &f.snapshot(), &s).unwrap();
        assert!(choice.binds);
        assert_eq!(choice.handle, a.handle);

        // Over the threshold, the bound account is still attempted.
        let f = Fixture::new(
            vec![oauth("a", 0.99), b.clone()],
            Some(f.accounts[0].handle),
        );
        let bound = f.accounts[0].handle;
        let facts = RequestFacts {
            session: true,
            binding: Some(bound),
            ..RequestFacts::default()
        };
        let choice = select(&facts, &f.snapshot(), &s).unwrap();
        assert_eq!(
            (choice.handle, choice.cause, choice.binds),
            (bound, Cause::Session, false)
        );

        // Under a hold, or disabled, the bound account ends the exchange naming itself.
        let mut held = oauth("a", 0.5);
        held.quota[0].exhaustion_hold_until = Some(NOW + time::Duration::minutes(5));
        let f = Fixture::new(vec![held.clone(), b.clone()], Some(b.handle));
        let facts = RequestFacts {
            session: true,
            binding: Some(held.handle),
            ..RequestFacts::default()
        };
        let nobody = select(&facts, &f.snapshot(), &s).unwrap_err();
        assert_eq!(nobody.reason, NoService::AllHeldOrOverThreshold);
        assert_eq!(nobody.named, Some(held.handle));
        assert_eq!(nobody.retry_at, Some(NOW + time::Duration::minutes(5)));
        let mut off = oauth("a", 0.5);
        off.enabled = false;
        let f = Fixture::new(vec![off.clone(), b.clone()], Some(b.handle));
        let facts = RequestFacts {
            session: true,
            binding: Some(off.handle),
            ..RequestFacts::default()
        };
        assert_eq!(
            select(&facts, &f.snapshot(), &s).unwrap_err().reason,
            NoService::AllDisabledOrErrored
        );
    }

    #[test]
    fn pin_and_preference_precede_everything_and_a_pin_never_falls_over() {
        let s = settings();
        let (a, b) = (oauth("a", 0.5), oauth("b", 0.99));
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let facts = RequestFacts {
            pin: Some(b.handle),
            ..RequestFacts::default()
        };
        let nobody = select(&facts, &f.snapshot(), &s).unwrap_err();
        assert_eq!(nobody.reason, NoService::PinnedUnavailable);
        assert_eq!(nobody.named, Some(b.handle));
        let facts = RequestFacts {
            preference: Some(b.handle),
            session: true,
            binding: Some(a.handle),
            ..RequestFacts::default()
        };
        // An ineligible preference falls through to the binding.
        let choice = select(&facts, &f.snapshot(), &s).unwrap();
        assert_eq!((choice.handle, choice.cause), (a.handle, Cause::Session));
        let f = Fixture::new(vec![a.clone(), oauth("b", 0.2)], Some(a.handle));
        let pref = f.accounts[1].handle;
        let facts = RequestFacts {
            preference: Some(pref),
            session: true,
            binding: Some(a.handle),
            ..RequestFacts::default()
        };
        let choice = select(&facts, &f.snapshot(), &s).unwrap();
        assert_eq!(
            (choice.handle, choice.cause, choice.binds),
            (pref, Cause::Preference, false)
        );
    }

    #[test]
    fn distribution_spreads_first_attempts_by_load_and_keeps_the_default() {
        let mut s = settings();
        s.distribute_sessions = true;
        let (a, b) = (oauth("a", 0.1), oauth("b", 0.1));
        let mut f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        f.active.insert(a.handle, 1);
        let facts = RequestFacts {
            session: true,
            ..RequestFacts::default()
        };
        let choice = select(&facts, &f.snapshot(), &s).unwrap();
        assert_eq!(
            (choice.handle, choice.cause, choice.binds),
            (b.handle, Cause::Session, true)
        );
        assert_eq!(choice.default_moved_from, None);
        // Without a session nothing spreads: the default serves.
        let choice = select(&RequestFacts::default(), &f.snapshot(), &s).unwrap();
        assert_eq!(
            (choice.handle, choice.cause, choice.binds),
            (a.handle, Cause::Default, false)
        );
    }

    #[test]
    fn advisor_pass_prefers_an_account_serving_both_models() {
        let mut s = settings();
        let (a, b) = (account("a"), account("b"));
        s.routes.push(Route {
            name: "opus".into(),
            patterns: vec!["*opus*".into()],
            accounts: Some(vec!["b".into()]),
            bucket: None,
        });
        let f = Fixture::new(vec![a.clone(), b.clone()], Some(a.handle));
        let facts = RequestFacts {
            model: Some("claude-haiku"),
            advisor_model: Some("claude-opus"),
            ..RequestFacts::default()
        };
        let choice = select(&facts, &f.snapshot(), &s).unwrap();
        assert_eq!((choice.handle, choice.advisor_fallback), (b.handle, false));
        // Nobody serves both: the request model alone decides.
        s.routes.push(Route {
            name: "haiku".into(),
            patterns: vec!["*haiku*".into()],
            accounts: Some(vec!["a".into()]),
            bucket: None,
        });
        let choice = select(&facts, &f.snapshot(), &s).unwrap();
        assert_eq!((choice.handle, choice.advisor_fallback), (a.handle, true));
    }

    #[test]
    fn selectable_now_takes_state_and_quota_but_no_route() {
        let s = settings();
        let mut families = HashMap::new();
        families.insert(
            "fable".into(),
            vec!["fable-1".to_string(), "fable-2".to_string()],
        );
        // Enabled with unknown buckets: under the threshold.
        let a = account("a");
        assert!(selectable(&a, &s, &families, NOW, None));
        // Disabled and errored accounts are not selectable.
        let mut d = account("d");
        d.enabled = false;
        assert!(!selectable(&d, &s, &families, NOW, None));
        let mut e = account("e");
        e.errored = Some(crate::pool::account::Errored {
            reason: "x".into(),
            at: NOW,
        });
        assert!(!selectable(&e, &s, &families, NOW, None));
        // Over the threshold on the governing weekly bucket.
        let over = oauth("over", 1.0);
        assert!(!selectable(&over, &s, &families, NOW, None));
        // The witness set is not the learned families. A pool that has
        // learned none still serves every model outside the block list, so an
        // account under the threshold is selectable.
        assert!(selectable(&a, &s, &HashMap::new(), NOW, None));
        // A partial block list leaves that witness; only one matching
        // every model takes it away.
        let mut s2 = s.clone();
        s2.blocked_models = vec!["fable-*".into()];
        assert!(selectable(&a, &s2, &families, NOW, None));
        s2.blocked_models = vec!["*opus*".into(), "*sonnet*".into()];
        assert!(selectable(&a, &s2, &families, NOW, None));
        s2.blocked_models = vec!["*".into()];
        assert!(!selectable(&a, &s2, &families, NOW, None));
        assert!(!selectable(&a, &s2, &HashMap::new(), NOW, None));
        // The state and quota bars still apply with no family learned.
        assert!(!selectable(&d, &s, &HashMap::new(), NOW, None));
        assert!(!selectable(&over, &s, &HashMap::new(), NOW, None));
    }
}
