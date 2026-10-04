//! The operator's runtime steer — who owns each provider's default and
//! the per-route preferences. Never persisted: a restart returns the
//! defaults to the pool's own ranking and drops every preference.

use std::collections::HashMap;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::Route;
use crate::provider::Provider;

use super::{Pool, fold, references};

#[derive(Debug, Default, Clone)]
pub struct Operator {
    pub defaults: HashMap<Provider, DefaultAccount>,
    /// Configured route name → the preferred account.
    pub route_preferences: HashMap<String, Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultAccount {
    pub handle: Uuid,
    /// The default came from `switch`, not from the ranking.
    pub chosen: bool,
    /// When the current default was last set, by either.
    pub since: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRefusal {
    /// The route's account list does not contain the account.
    NotListed,
}

impl Pool {
    pub fn operator(&self) -> &Operator {
        &self.operator
    }

    /// The account's provider's default moves whether or not the account is
    /// eligible; an account removed since it was resolved moves nothing.
    /// Returns the previous default.
    pub fn switch_default(&mut self, handle: Uuid, now: OffsetDateTime) -> Option<Uuid> {
        let provider = self.get(handle)?.provider;
        self.set_default(provider, handle, true, now)
    }

    /// The ranking, an automatic move or a removal: the pool's own move, which forgets the
    /// operator's choice.
    pub(super) fn move_default(
        &mut self,
        provider: Provider,
        handle: Option<Uuid>,
        now: OffsetDateTime,
    ) {
        match handle {
            Some(handle) => {
                self.set_default(provider, handle, false, now);
            }
            None => {
                self.operator.defaults.remove(&provider);
            }
        }
    }

    fn set_default(
        &mut self,
        provider: Provider,
        handle: Uuid,
        chosen: bool,
        now: OffsetDateTime,
    ) -> Option<Uuid> {
        let previous = self.operator.defaults.get(&provider).copied();
        let since = previous
            .filter(|d| d.handle == handle)
            .map_or(now, |d| d.since);
        let default = DefaultAccount {
            handle,
            chosen,
            since,
        };
        self.operator.defaults.insert(provider, default);
        previous.map(|d| d.handle)
    }

    /// Refused when the route's list lacks the account; an
    /// ineligible account is accepted.
    pub fn set_route_preference(
        &mut self,
        route: &Route,
        handle: Uuid,
    ) -> Result<(), RouteRefusal> {
        let listed = match (&route.accounts, self.get(handle)) {
            (None, _) => true,
            (Some(list), Some(account)) => list.iter().any(|r| references(account, r)),
            (Some(_), None) => false,
        };
        if !listed {
            return Err(RouteRefusal::NotListed);
        }
        self.operator
            .route_preferences
            .insert(route.name.clone(), handle);
        Ok(())
    }

    /// The preference dropped, if the route had one.
    pub fn clear_route_preference(&mut self, route: &str) -> Option<Uuid> {
        self.operator.route_preferences.remove(route)
    }

    /// A reload keeps only the preferences of routes the new
    /// table still configures; returns what was dropped.
    pub fn retain_route_preferences(&mut self, routes: &[Route]) -> Vec<(String, Uuid)> {
        let kept: Vec<String> = routes.iter().map(|r| fold(&r.name)).collect();
        let mut dropped = Vec::new();
        self.operator.route_preferences.retain(|name, account| {
            let keep = kept.contains(&fold(name));
            if !keep {
                dropped.push((name.clone(), *account));
            }
            keep
        });
        dropped.sort();
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::account::{Account, Credential, Profile, Secret, Source};
    use time::macros::datetime;

    fn key(name: &str) -> Account {
        Account::new(
            Provider::Anthropic,
            name.into(),
            Profile::default(),
            Source::ApiKeyEntry,
            Credential::ApiKey(Secret::new("k".into())),
        )
    }

    const T0: OffsetDateTime = datetime!(2026-01-01 00:00 UTC);
    const T1: OffsetDateTime = datetime!(2026-01-01 00:01 UTC);
    const T2: OffsetDateTime = datetime!(2026-01-01 00:02 UTC);

    #[test]
    fn switch_marks_chosen_and_a_pool_move_forgets_it() {
        let mut pool = Pool::from_accounts(vec![key("A"), key("B")], T0);
        let (a, b) = (pool.accounts()[0].handle, pool.accounts()[1].handle);
        let default = |pool: &Pool| pool.operator().defaults[&Provider::Anthropic];
        pool.move_default(Provider::Anthropic, Some(a), T0);
        assert_eq!(default(&pool).since, T0);
        assert!(!default(&pool).chosen);

        assert_eq!(pool.switch_default(b, T1), Some(a));
        assert_eq!(default(&pool).handle, b);
        assert!(default(&pool).chosen);
        assert_eq!(default(&pool).since, T1);

        // The same account switched to again: `since` stays.
        pool.switch_default(b, T2);
        assert_eq!(default(&pool).since, T1);

        pool.move_default(Provider::Anthropic, Some(a), T2);
        assert!(!default(&pool).chosen);
        assert_eq!(default(&pool).since, T2);
    }

    #[test]
    fn each_provider_keeps_its_own_default() {
        let mut codex = key("C");
        codex.provider = Provider::Codex;
        let mut pool = Pool::from_accounts(vec![key("A"), codex], T0);
        let (a, c) = (pool.accounts()[0].handle, pool.accounts()[1].handle);
        pool.move_default(Provider::Anthropic, Some(a), T0);
        assert_eq!(pool.switch_default(c, T1), None);
        assert_eq!(pool.default_account(Provider::Codex), Some(c));
        assert_eq!(pool.default_account(Provider::Anthropic), Some(a));
        // Removing a provider's default moves it within that provider only.
        pool.remove(c);
        assert_eq!(pool.default_account(Provider::Codex), None);
        assert_eq!(pool.default_account(Provider::Anthropic), Some(a));
        assert_eq!(pool.switch_default(c, T2), None, "a removed account");
    }

    #[test]
    fn a_route_preference_needs_the_route_to_list_the_account() {
        let mut pool = Pool::from_accounts(vec![key("A"), key("B")], T0);
        let b = pool.accounts()[1].handle;
        let exclusive = Route {
            name: "h".into(),
            patterns: vec!["*haiku*".into()],
            accounts: Some(vec!["A".into()]),
            bucket: None,
        };
        assert_eq!(
            pool.set_route_preference(&exclusive, b),
            Err(RouteRefusal::NotListed)
        );
        let empty = Route {
            accounts: Some(vec![]),
            ..exclusive.clone()
        };
        assert_eq!(
            pool.set_route_preference(&empty, b),
            Err(RouteRefusal::NotListed)
        );
        let open = Route {
            accounts: None,
            ..exclusive.clone()
        };
        assert_eq!(pool.set_route_preference(&open, b), Ok(()));
        assert_eq!(pool.route_preferences().get("h"), Some(&b));
        assert_eq!(pool.clear_route_preference("h"), Some(b));
        assert_eq!(pool.clear_route_preference("h"), None);
    }

    /// The reload keeps a preference whose route survives — under
    /// case folding — and drops the rest.
    #[test]
    fn a_reload_drops_the_preferences_of_vanished_routes() {
        let mut pool = Pool::from_accounts(vec![key("A"), key("B")], T0);
        let b = pool.accounts()[1].handle;
        let open = |name: &str| Route {
            name: name.into(),
            patterns: vec!["*".into()],
            accounts: None,
            bucket: None,
        };
        pool.set_route_preference(&open("h"), b).unwrap();
        pool.set_route_preference(&open("s"), b).unwrap();
        assert_eq!(
            pool.retain_route_preferences(&[open("H")]),
            vec![("s".to_string(), b)]
        );
        assert_eq!(pool.route_preferences().get("h"), Some(&b));
        assert_eq!(
            pool.retain_route_preferences(&[]),
            vec![("h".to_string(), b)]
        );
        assert!(pool.route_preferences().is_empty());
    }
}
