//! The operator's runtime steer — who owns the default and the
//! per-route preferences. Never persisted: a restart returns the
//! default to the pool's own ranking and drops every preference.

use std::collections::HashMap;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::Route;

use super::{Pool, fold, references};

#[derive(Debug, Default, Clone)]
pub struct Operator {
    pub default: Option<Uuid>,
    /// The default came from `switch`, not from the ranking.
    pub chosen: bool,
    /// When the current default was last set, by either.
    pub since: Option<OffsetDateTime>,
    /// Configured route name → the preferred account.
    pub route_preferences: HashMap<String, Uuid>,
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

    /// The default moves whether or not the account is eligible.
    /// Returns the previous default.
    pub fn switch_default(&mut self, handle: Uuid, now: OffsetDateTime) -> Option<Uuid> {
        let previous = self.operator.default;
        if previous != Some(handle) {
            self.operator.since = Some(now);
        }
        self.operator.default = Some(handle);
        self.operator.chosen = true;
        previous
    }

    /// The ranking, an automatic move or a removal: the pool's own move, which forgets the
    /// operator's choice.
    pub(super) fn move_default(&mut self, handle: Option<Uuid>, now: OffsetDateTime) {
        if self.operator.default != handle {
            self.operator.since = handle.map(|_| now);
        }
        self.operator.default = handle;
        self.operator.chosen = false;
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
            crate::provider::Provider::Anthropic,
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
        pool.move_default(Some(a), T0);
        assert_eq!(pool.operator().since, Some(T0));
        assert!(!pool.operator().chosen);

        assert_eq!(pool.switch_default(b, T1), Some(a));
        assert_eq!(pool.operator().default, Some(b));
        assert!(pool.operator().chosen);
        assert_eq!(pool.operator().since, Some(T1));

        // The same account switched to again: `since` stays.
        pool.switch_default(b, T2);
        assert_eq!(pool.operator().since, Some(T1));

        pool.move_default(Some(a), T2);
        assert!(!pool.operator().chosen);
        assert_eq!(pool.operator().since, Some(T2));
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
