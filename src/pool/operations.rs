//! The operator's account operations: add, replace, rename, enable/disable
//! and remove, and the refusals they share. The reference check needs the
//! configuration and lives in `config::references`; the handlers run it
//! around these inside the same `mutate_pool` closure.

use time::OffsetDateTime;
use uuid::Uuid;

use super::{Account, Credential, Kind, Pool, Profile, Source, fold};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationError {
    NotFound,
    /// A name is non-empty.
    NameEmpty,
    /// The display name is taken under case folding.
    NameConflict(String),
    /// An add landing on an existing identity named it differently;
    /// `rename` is the only way a name changes.
    NameMismatch {
        existing: String,
    },
    /// A replacement never changes the account's kind.
    KindMismatch {
        account: Kind,
        credential: Kind,
    },
    /// The credential's identity contradicts the named account.
    IdentityMismatch,
    /// A client's add landed on an identity it does not own.
    NotOwner,
    /// A re-login landed on an identity the pool does not hold.
    NewAccount,
    /// The entries the operation would leave unresolvable or ambiguous.
    ReferenceConflict(Vec<ReferenceConflict>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    Unresolvable,
    Ambiguous,
}

impl Why {
    pub fn as_str(self) -> &'static str {
        match self {
            Why::Unresolvable => "unresolvable",
            Why::Ambiguous => "ambiguous",
        }
    }
}

/// One configuration entry the operation would leave unresolvable or ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceConflict {
    /// `route <name>` or `priority <n>`, `n` the entry's index in
    /// `selection.priorities` as the configuration errors key it.
    pub entry: String,
    pub reference: String,
    pub why: Why,
}

/// The same account UUID under the same organisation discriminator.
fn same_identity(a: &Profile, b: &Profile) -> bool {
    let (Some(x), Some(y)) = (a.account_uuid, b.account_uuid) else {
        return false;
    };
    x == y
        && match (a.organization_uuid, b.organization_uuid) {
            (Some(x), Some(y)) => x == y,
            (None, None) => a.organization_name == b.organization_name,
            _ => false,
        }
}

/// A credential installed over an existing account starts
/// with no refresh history and clears the errored state.
fn install(account: &mut Account, mut credential: Credential, source: Source) {
    if let Credential::OAuth(family) = &mut credential {
        family.last_refresh_attempt_at = None;
        family.last_refresh_success_at = None;
        family.refresh_not_before = None;
    }
    account.credential = credential;
    account.source = source;
    account.errored = None;
}

impl Pool {
    /// Same identity replaces the credential in place, unless a client adds
    /// one it does not own; otherwise a different name refuses the add and a
    /// taken name conflicts.
    pub fn add(
        &mut self,
        mut account: Account,
        operator_name: Option<String>,
    ) -> Result<Uuid, OperationError> {
        if let Some(existing) = self.same_identity_of(&account) {
            let handle = existing.handle;
            if account.owner.is_some() && account.owner != existing.owner {
                return Err(OperationError::NotOwner);
            }
            if let Some(name) = &operator_name
                && fold(name) != fold(&existing.display_name)
            {
                return Err(OperationError::NameMismatch {
                    existing: existing.display_name.clone(),
                });
            }
            let existing = self.get_mut(handle).expect("found above");
            existing.profile = account.profile;
            install(existing, account.credential, account.source);
            return Ok(handle);
        }
        account.display_name = match operator_name {
            Some(name) => {
                if self.name_taken(&name, None) {
                    return Err(OperationError::NameConflict(name));
                }
                name
            }
            None => self.derive_name(&mut account)?,
        };
        let handle = account.handle;
        self.accounts.push(account);
        if self.operator.default.is_none() {
            // The pool's own move, so `since` records when this
            // account became the default and `operator_chosen` stays false.
            self.move_default(Some(handle), OffsetDateTime::now_utc());
        }
        Ok(handle)
    }

    /// [`Pool::add`] that never adds: only an identity the pool holds
    /// takes the new credential.
    pub fn relogin(
        &mut self,
        account: Account,
        operator_name: Option<String>,
    ) -> Result<Uuid, OperationError> {
        if self.same_identity_of(&account).is_none() {
            return Err(OperationError::NewAccount);
        }
        self.add(account, operator_name)
    }

    fn same_identity_of(&self, candidate: &Account) -> Option<&Account> {
        self.accounts
            .iter()
            .find(|a| a.kind() == Kind::OAuth && same_identity(&a.profile, &candidate.profile))
    }

    pub(super) fn name_taken(&self, name: &str, except: Option<Uuid>) -> bool {
        let folded = fold(name);
        self.accounts
            .iter()
            .any(|a| Some(a.handle) != except && fold(&a.display_name) == folded)
    }

    /// The profile email; when accounts share it, every derived-named
    /// holder moves to `email (organisation name)` — the earlier ones renamed
    /// in place at the colliding add — falling back to the full organisation
    /// UUID when a name is absent or the organisation names would still
    /// collide, and to the handle as the last resort. Operator-supplied names
    /// are out of the suffix's reach; one equal to a derived form
    /// refuses the add rather than duplicating it.
    fn derive_name(&mut self, account: &mut Account) -> Result<String, OperationError> {
        let email = account
            .profile
            .email
            .clone()
            .unwrap_or_else(|| account.handle.to_string());
        let folded = fold(&email);
        // The accounts sharing the profile email, the newcomer included,
        // decide together whether an organisation name is unique among them.
        let mut holders: Vec<(Option<String>, Option<Uuid>)> = self
            .accounts
            .iter()
            .filter(|a| {
                a.profile
                    .email
                    .as_deref()
                    .is_some_and(|e| fold(e) == folded)
            })
            .map(|a| {
                (
                    a.profile.organization_name.clone(),
                    a.profile.organization_uuid,
                )
            })
            .collect();
        holders.push((
            account.profile.organization_name.clone(),
            account.profile.organization_uuid,
        ));
        if holders.len() == 1 && !self.name_taken(&email, None) {
            return Ok(email);
        }
        let labels: Vec<String> = holders
            .iter()
            .map(|(name, uuid)| {
                let unique = name.as_deref().is_some_and(|n| {
                    holders
                        .iter()
                        .filter(|(m, _)| m.as_deref().is_some_and(|m| fold(m) == fold(n)))
                        .count()
                        == 1
                });
                match (unique, name.as_deref(), uuid) {
                    (true, Some(n), _) => n.to_string(),
                    _ => uuid
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| account.handle.to_string()),
                }
            })
            .collect();
        let labelled: Vec<String> = labels
            .iter()
            .map(|label| format!("{email} ({label})"))
            .collect();
        for name in &labelled {
            if self
                .accounts
                .iter()
                .filter(|a| a.profile.email.as_deref().is_none_or(|e| fold(e) != folded))
                .any(|a| fold(&a.display_name) == fold(name))
            {
                return Err(OperationError::NameConflict(name.clone()));
            }
        }
        // The suffix is part of the derived name, not a rename outside
        // `rename`; a later refresh never touches it again. A holder is
        // renamed only when its name is the bare email or the derived form
        // of its own organisation — never an operator-supplied name.
        let mut i = 0;
        for existing in self.accounts.iter_mut().filter(|a| {
            a.profile
                .email
                .as_deref()
                .is_some_and(|e| fold(e) == folded)
        }) {
            let (org, uuid) = &holders[i];
            let derived = match (org, uuid) {
                (Some(n), _) => format!("{email} ({n})"),
                (None, Some(u)) => format!("{email} ({u})"),
                (None, None) => continue,
            };
            if fold(&existing.display_name) == folded || existing.display_name == derived {
                existing.display_name = format!(
                    "{} ({})",
                    existing.profile.email.as_deref().unwrap_or(&email),
                    labels[i]
                );
            }
            i += 1;
        }
        Ok(labelled[labelled.len() - 1].clone())
    }

    /// The credential replaced in place, never across kinds.
    /// An identity the profile supplied must be the account's; one it
    /// could not supply (`None`, or no account UUID) does not contradict, and
    /// the stored identity facts stay. Errored clears.
    pub fn replace_credential(
        &mut self,
        handle: Uuid,
        credential: Credential,
        profile: Option<Profile>,
        source: Source,
    ) -> Result<(), OperationError> {
        let account = self.get_mut(handle).ok_or(OperationError::NotFound)?;
        if credential.kind() != account.kind() {
            return Err(OperationError::KindMismatch {
                account: account.kind(),
                credential: credential.kind(),
            });
        }
        if let Some(profile) = profile.filter(|p| p.account_uuid.is_some()) {
            if !same_identity(&account.profile, &profile) {
                return Err(OperationError::IdentityMismatch);
            }
            account.profile = profile;
        }
        install(account, credential, source);
        Ok(())
    }

    /// A non-empty name, unique under case folding; the
    /// handle never changes.
    pub fn rename(&mut self, handle: Uuid, name: &str) -> Result<(), OperationError> {
        if name.is_empty() {
            return Err(OperationError::NameEmpty);
        }
        if self.get(handle).is_none() {
            return Err(OperationError::NotFound);
        }
        if self.name_taken(name, Some(handle)) {
            return Err(OperationError::NameConflict(name.to_string()));
        }
        self.get_mut(handle).expect("found above").display_name = name.to_string();
        Ok(())
    }

    /// Disable keeps everything but new selection; enable
    /// clears errored even when already enabled — the retry path.
    pub fn set_enabled(&mut self, handle: Uuid, enabled: bool) -> Result<(), OperationError> {
        let account = self.get_mut(handle).ok_or(OperationError::NotFound)?;
        account.enabled = enabled;
        if enabled {
            account.errored = None;
        }
        Ok(())
    }

    /// Durable removal is the caller's; here the account leaves selection at once.
    pub fn remove(&mut self, handle: Uuid) -> Option<Account> {
        let i = self.accounts.iter().position(|a| a.handle == handle)?;
        let removed = self.accounts.remove(i);
        self.usage.remove(&handle);
        self.admission.remove(&handle);
        self.sessions.unbind_account(handle);
        self.operator.route_preferences.retain(|_, h| *h != handle);
        if self.operator.default == Some(handle) {
            let next = self.accounts.first().map(|a| a.handle);
            self.move_default(next, OffsetDateTime::now_utc());
        }
        Some(removed)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::pool::{OAuthCredential, Secret};

    fn family(access: &str, refresh: Option<&str>) -> OAuthCredential {
        OAuthCredential {
            access_token: Secret::new(access.into()),
            refresh_token: refresh.map(|r| Secret::new(r.into())),
            expires_at: datetime!(2027-01-01 00:00 UTC),
            last_refresh_attempt_at: None,
            last_refresh_success_at: None,
            refresh_not_before: None,
        }
    }

    fn oauth(email: &str, org: Option<&str>, account_uuid: Uuid) -> Account {
        Account::new(
            String::new(),
            Profile {
                email: Some(email.into()),
                account_uuid: Some(account_uuid),
                organization_uuid: None,
                organization_name: org.map(String::from),
            },
            Source::PortableJson,
            Credential::OAuth(family("t", None)),
        )
    }

    fn api_key(name: &str) -> Account {
        Account::new(
            name.into(),
            Profile::default(),
            Source::ApiKeyEntry,
            Credential::ApiKey(Secret::new("sk-ant-key".into())),
        )
    }

    fn errored(pool: &mut Pool, handle: Uuid) {
        pool.mark_errored(handle, "401".into(), datetime!(2026-09-16 00:00 UTC));
    }

    #[test]
    fn derived_names_use_email_then_organisation_suffix() {
        let mut pool = Pool::default();
        let first = pool
            .add(oauth("a@x.io", Some("One"), Uuid::new_v4()), None)
            .unwrap();
        let second = pool
            .add(oauth("A@x.io", Some("Two"), Uuid::new_v4()), None)
            .unwrap();
        assert_eq!(pool.get(first).unwrap().display_name, "a@x.io (One)");
        assert_eq!(pool.get(second).unwrap().display_name, "A@x.io (Two)");
        assert_eq!(pool.default_account(), Some(first));
    }

    /// On add: the earlier holder is renamed in place at the colliding add;
    /// a third sharing one organisation name moves the colliding pair to the
    /// full organisation UUID; an operator name never takes the suffix.
    #[test]
    fn shared_emails_suffix_both_holders_and_fall_back_to_the_uuid() {
        let mut pool = Pool::default();
        let mut first = oauth("a@x.io", Some("One"), Uuid::new_v4());
        let first_org = Uuid::new_v4();
        first.profile.organization_uuid = Some(first_org);
        let first = pool.add(first, None).unwrap();
        let mut second = oauth("A@x.io", Some("Two"), Uuid::new_v4());
        let second_org = Uuid::new_v4();
        second.profile.organization_uuid = Some(second_org);
        let second = pool.add(second, None).unwrap();

        // Same organisation name as the second: the colliding pair falls back
        // to the organisation UUID, the first keeps its unique name.
        let mut third = oauth("A@x.io", Some("Two"), Uuid::new_v4());
        let third_org = Uuid::new_v4();
        third.profile.organization_uuid = Some(third_org);
        let third = pool.add(third, None).unwrap();
        assert_eq!(
            pool.get(second).unwrap().display_name,
            format!("A@x.io ({second_org})")
        );
        assert_eq!(
            pool.get(third).unwrap().display_name,
            format!("A@x.io ({third_org})")
        );
        assert_eq!(pool.get(first).unwrap().display_name, "a@x.io (One)");

        // An operator name is out of the suffix's reach.
        let named = pool
            .add(
                oauth("a@x.io", Some("Three"), Uuid::new_v4()),
                Some("Explicit".into()),
            )
            .unwrap();
        assert_eq!(pool.get(named).unwrap().display_name, "Explicit");
    }

    #[test]
    fn same_identity_replaces_in_place_and_clears_errored() {
        let mut pool = Pool::default();
        let id = Uuid::new_v4();
        let handle = pool
            .add(oauth("a@x.io", Some("One"), id), Some("named".into()))
            .unwrap();
        errored(&mut pool, handle);
        let again = pool.add(oauth("a@x.io", Some("One"), id), None).unwrap();
        assert_eq!(again, handle);
        assert_eq!(pool.accounts().len(), 1);
        assert_eq!(pool.get(handle).unwrap().display_name, "named");
        assert!(pool.get(handle).unwrap().errored.is_none());
    }

    /// On add: the same identity under another name is a conflict, not a rename;
    /// the same name under folding proceeds.
    #[test]
    fn add_on_an_existing_identity_refuses_a_different_name() {
        let mut pool = Pool::default();
        let id = Uuid::new_v4();
        let handle = pool
            .add(oauth("a@x.io", Some("One"), id), Some("Explicit".into()))
            .unwrap();
        assert_eq!(
            pool.add(oauth("a@x.io", Some("One"), id), Some("Other".into())),
            Err(OperationError::NameMismatch {
                existing: "Explicit".into()
            })
        );
        assert_eq!(
            pool.add(oauth("a@x.io", Some("One"), id), Some("EXPLICIT".into())),
            Ok(handle)
        );
        assert_eq!(pool.get(handle).unwrap().display_name, "Explicit");
    }

    #[test]
    fn a_client_re_adds_only_an_identity_it_owns() {
        let mut pool = Pool::default();
        let (mine, theirs) = (Uuid::new_v4(), Uuid::new_v4());
        let owned_by = |owner: &str, id| Account {
            owner: Some(owner.into()),
            ..oauth("a@x.io", Some("One"), id)
        };
        let handle = pool.add(owned_by("mac-1", mine), None).unwrap();
        pool.add(oauth("b@x.io", Some("One"), theirs), None)
            .unwrap();

        assert_eq!(pool.add(owned_by("mac-1", mine), None), Ok(handle));
        assert_eq!(
            pool.add(owned_by("mac-2", mine), None),
            Err(OperationError::NotOwner)
        );
        assert_eq!(
            pool.add(owned_by("mac-1", theirs), None),
            Err(OperationError::NotOwner)
        );
        // The operator re-adds any identity, and the owner stays.
        assert_eq!(
            pool.add(oauth("a@x.io", Some("One"), mine), None),
            Ok(handle)
        );
        assert_eq!(pool.get(handle).unwrap().owner.as_deref(), Some("mac-1"));
    }

    #[test]
    fn a_relogin_never_adds_an_account() {
        let mut pool = Pool::default();
        let (mine, new) = (Uuid::new_v4(), Uuid::new_v4());
        let owned_by = |owner: &str, id| Account {
            owner: Some(owner.into()),
            ..oauth("a@x.io", Some("One"), id)
        };
        let handle = pool.add(owned_by("mac-1", mine), None).unwrap();

        assert_eq!(pool.relogin(owned_by("mac-1", mine), None), Ok(handle));
        assert_eq!(
            pool.relogin(owned_by("mac-2", mine), None),
            Err(OperationError::NotOwner)
        );
        assert_eq!(
            pool.relogin(owned_by("mac-1", new), None),
            Err(OperationError::NewAccount)
        );
        assert_eq!(pool.accounts().len(), 1);
    }

    #[test]
    fn replace_keeps_the_kind_and_the_handle() {
        let mut pool = Pool::default();
        let key = pool.add(api_key("KEY"), Some("KEY".into())).unwrap();
        let sub = pool
            .add(oauth("a@x.io", Some("One"), Uuid::new_v4()), None)
            .unwrap();
        assert_eq!(
            pool.replace_credential(
                key,
                Credential::OAuth(family("new", Some("r"))),
                None,
                Source::PortableJson
            ),
            Err(OperationError::KindMismatch {
                account: Kind::ApiKey,
                credential: Kind::OAuth
            })
        );
        assert_eq!(
            pool.replace_credential(
                sub,
                Credential::ApiKey(Secret::new("k".into())),
                None,
                Source::ApiKeyEntry
            ),
            Err(OperationError::KindMismatch {
                account: Kind::OAuth,
                credential: Kind::ApiKey
            })
        );
        assert_eq!(
            pool.replace_credential(
                Uuid::new_v4(),
                Credential::ApiKey(Secret::new("k".into())),
                None,
                Source::ApiKeyEntry
            ),
            Err(OperationError::NotFound)
        );
        errored(&mut pool, key);
        pool.replace_credential(
            key,
            Credential::ApiKey(Secret::new("k2".into())),
            None,
            Source::ApiKeyEntry,
        )
        .unwrap();
        let account = pool.get(key).unwrap();
        assert_eq!(
            account.credential,
            Credential::ApiKey(Secret::new("k2".into()))
        );
        assert!(account.errored.is_none());
        assert_eq!(pool.accounts().len(), 2);
    }

    /// On replace: a supplied identity must match; an absent one does
    /// not contradict and leaves the stored facts alone. The new
    /// family has no refresh history.
    #[test]
    fn replace_checks_a_supplied_identity_and_resets_refresh_timing() {
        let mut pool = Pool::default();
        let id = Uuid::new_v4();
        let sub = pool.add(oauth("a@x.io", Some("One"), id), None).unwrap();
        let mut stale = family("rotated", Some("r"));
        stale.last_refresh_attempt_at = Some(datetime!(2026-09-16 00:00 UTC));
        stale.last_refresh_success_at = Some(datetime!(2026-09-16 00:00 UTC));
        stale.refresh_not_before = Some(datetime!(2026-09-16 00:01 UTC));

        let other = Profile {
            email: Some("b@x.io".into()),
            account_uuid: Some(Uuid::new_v4()),
            organization_uuid: None,
            organization_name: Some("One".into()),
        };
        assert_eq!(
            pool.replace_credential(
                sub,
                Credential::OAuth(stale.clone()),
                Some(other),
                Source::PortableJson
            ),
            Err(OperationError::IdentityMismatch)
        );
        assert_eq!(
            pool.get(sub).unwrap().credential,
            Credential::OAuth(family("t", None))
        );

        let no_uuid = Profile {
            email: Some("b@x.io".into()),
            ..Profile::default()
        };
        errored(&mut pool, sub);
        pool.replace_credential(
            sub,
            Credential::OAuth(stale.clone()),
            Some(no_uuid),
            Source::ExplicitFile,
        )
        .unwrap();
        let account = pool.get(sub).unwrap();
        assert_eq!(account.profile.email.as_deref(), Some("a@x.io"));
        assert_eq!(account.source, Source::ExplicitFile);
        assert!(account.errored.is_none());
        assert_eq!(
            account.credential,
            Credential::OAuth(family("rotated", Some("r")))
        );

        let renamed = Profile {
            email: Some("renamed@x.io".into()),
            account_uuid: Some(id),
            organization_uuid: None,
            organization_name: Some("One".into()),
        };
        pool.replace_credential(
            sub,
            Credential::OAuth(stale),
            Some(renamed),
            Source::PortableJson,
        )
        .unwrap();
        assert_eq!(
            pool.get(sub).unwrap().profile.email.as_deref(),
            Some("renamed@x.io")
        );
        assert_eq!(pool.get(sub).unwrap().handle, sub);
    }

    #[test]
    fn rename_is_non_empty_unique_under_folding_and_keeps_the_handle() {
        let mut pool = Pool::default();
        let a = pool.add(api_key("A"), Some("A".into())).unwrap();
        let _b = pool.add(api_key("Straße"), Some("Straße".into())).unwrap();
        assert_eq!(pool.rename(a, ""), Err(OperationError::NameEmpty));
        assert_eq!(
            pool.rename(Uuid::new_v4(), "X"),
            Err(OperationError::NotFound)
        );
        assert_eq!(
            pool.rename(a, "STRASSE"),
            Err(OperationError::NameConflict("STRASSE".into()))
        );
        pool.rename(a, "a").unwrap();
        pool.rename(a, "Renamed").unwrap();
        assert_eq!(pool.get(a).unwrap().display_name, "Renamed");
        assert_eq!(pool.get(a).unwrap().handle, a);
    }

    #[test]
    fn enable_clears_errored_and_disable_keeps_it() {
        let mut pool = Pool::default();
        let a = pool.add(api_key("A"), Some("A".into())).unwrap();
        errored(&mut pool, a);
        pool.set_enabled(a, false).unwrap();
        assert!(!pool.get(a).unwrap().enabled);
        assert!(pool.get(a).unwrap().errored.is_some());
        pool.set_enabled(a, true).unwrap();
        assert!(pool.get(a).unwrap().enabled);
        assert!(pool.get(a).unwrap().errored.is_none());
        errored(&mut pool, a);
        pool.set_enabled(a, true).unwrap();
        assert!(pool.get(a).unwrap().errored.is_none(), "the retry path");
        assert_eq!(
            pool.set_enabled(Uuid::new_v4(), true),
            Err(OperationError::NotFound)
        );
    }
}
