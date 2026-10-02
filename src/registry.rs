//! The client registry and the remote-operator slot: one entry per client id, monotonically
//! increasing generations, verifiers only. Every operation is pure over the
//! entry list; the caller owns persistence and disclosure.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::secret::{Role, Secret, Verifier};

/// The three states, and nothing between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryState {
    Pending,
    Active,
    Revoked,
}

impl EntryState {
    pub fn name(self) -> &'static str {
        match self {
            EntryState::Pending => "pending",
            EntryState::Active => "active",
            EntryState::Revoked => "revoked",
        }
    }
}

/// The registry entry, exactly these fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub id: String,
    pub display_name: String,
    pub state: EntryState,
    pub generation: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub activated_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub verifier: Option<Verifier>,
    /// The invite opted out of the account step: this client adds no Claude
    /// account of its own. Left out of `state.json` when false, so a 2.0.x
    /// rollback still reads the entry.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_account: bool,
}

/// A verifier object with the operator domain plus `rotated_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorEntry {
    pub algorithm: String,
    pub domain: String,
    pub digest: String,
    #[serde(with = "time::serde::rfc3339")]
    pub rotated_at: OffsetDateTime,
}

impl OperatorEntry {
    pub fn as_verifier(&self) -> Verifier {
        Verifier {
            algorithm: "sha256".to_string(),
            domain: Role::OperatorSecret.domain().to_string(),
            digest: self.digest.clone(),
        }
    }
}

/// The registry as state carries it: the `clients` array and the `operator` slot.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Registry {
    pub clients: Vec<RegistryEntry>,
    pub operator: Option<OperatorEntry>,
}

impl Registry {
    /// The bootstrap exception: no entry in any state and no operator secret.
    pub fn is_bootstrap(&self) -> bool {
        self.clients.is_empty() && self.operator.is_none()
    }

    pub fn entry(&self, id: &str) -> Option<&RegistryEntry> {
        self.clients.iter().find(|e| e.id == id)
    }

    /// Whether the client's invite lets it add accounts of its own.
    pub fn adds_accounts(&self, id: &str) -> bool {
        self.entry(id).is_some_and(|entry| !entry.no_account)
    }

    /// The active client whose secret verifier matches, for principal resolution.
    pub fn client_by_secret(&self, secret: &str) -> Option<String> {
        self.clients
            .iter()
            .find(|e| {
                e.state == EntryState::Active
                    && e.verifier
                        .as_ref()
                        .is_some_and(|v| v.matches(Role::ClientSecret, secret))
            })
            .map(|e| e.id.clone())
    }

    pub fn operator_by_secret(&self, secret: &str) -> bool {
        self.operator
            .as_ref()
            .is_some_and(|o| o.as_verifier().matches(Role::OperatorSecret, secret))
    }

    /// 1–63 ASCII lowercase letters, digits, `_` or `-`, beginning
    /// with a letter or digit.
    pub fn validate_id(id: &str) -> Result<(), String> {
        let ok = !id.is_empty()
            && id.len() <= 63
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
            && id
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        if ok {
            Ok(())
        } else {
            Err("a client id is 1–63 ASCII lowercase letters, digits, `_` or `-`, beginning with a letter or digit".into())
        }
    }

    /// 1–128 UTF-8 bytes after surrounding whitespace is removed, no
    /// control character. Returns the trimmed name.
    pub fn validate_display_name(name: &str) -> Result<String, String> {
        let trimmed = name.trim();
        let ok =
            !trimmed.is_empty() && trimmed.len() <= 128 && !trimmed.chars().any(char::is_control);
        if ok {
            Ok(trimmed.to_string())
        } else {
            Err("a display name is 1–128 UTF-8 bytes after surrounding whitespace is removed and carries no control character".into())
        }
    }

    /// Create a pending enrollment; the code is returned once and its
    /// verifier alone retained. `Err` is `None` for a duplicate id.
    pub fn issue(
        &mut self,
        id: &str,
        display_name: &str,
        now: OffsetDateTime,
        lifetime_seconds: u64,
    ) -> Result<(String, OffsetDateTime), Option<String>> {
        Self::validate_id(id).map_err(Some)?;
        let display_name = Self::validate_display_name(display_name).map_err(Some)?;
        if self.entry(id).is_some() {
            return Err(None);
        }
        let code = Secret::generate(Role::EnrollmentCode);
        let entry = RegistryEntry {
            id: id.to_string(),
            display_name,
            state: EntryState::Pending,
            generation: 1,
            issued_at: now,
            expires_at: Some(now + duration_seconds(lifetime_seconds)),
            activated_at: None,
            revoked_at: None,
            verifier: Some(Verifier::new(Role::EnrollmentCode, code.as_str())),
            no_account: false,
        };
        self.clients.push(entry);
        Ok((code.into_string(), now + duration_seconds(lifetime_seconds)))
    }

    /// Invalidate any outstanding code, create the next generation
    /// as pending. Accepted for a pending, active or revoked id.
    pub fn reissue(
        &mut self,
        id: &str,
        now: OffsetDateTime,
        lifetime_seconds: u64,
    ) -> Result<(String, OffsetDateTime), ReissueError> {
        let entry = self
            .clients
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(ReissueError::Unknown)?;
        let code = Secret::generate(Role::EnrollmentCode);
        entry.state = EntryState::Pending;
        entry.generation += 1;
        entry.issued_at = now;
        entry.expires_at = Some(now + duration_seconds(lifetime_seconds));
        entry.activated_at = None;
        entry.revoked_at = None;
        entry.verifier = Some(Verifier::new(Role::EnrollmentCode, code.as_str()));
        Ok((code.into_string(), now + duration_seconds(lifetime_seconds)))
    }

    /// Consume the code atomically, activate and return the persistent
    /// secret once. Every failure is one indistinguishable refusal;
    /// the cause is only for the operator's log line.
    pub fn claim(
        &mut self,
        id: &str,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<(RegistryEntry, String), ClaimCause> {
        let Some(entry) = self.clients.iter_mut().find(|e| e.id == id) else {
            return Err(ClaimCause::UnknownId);
        };
        let verified = entry
            .verifier
            .as_ref()
            .is_some_and(|v| v.matches(Role::EnrollmentCode, code));
        if !verified {
            return Err(ClaimCause::WrongCode);
        }
        if entry.state != EntryState::Pending {
            // Active or revoked: the verifier is no longer an enrollment code's.
            return Err(ClaimCause::WrongCode);
        }
        if entry.expires_at.is_some_and(|at| now > at) {
            return Err(ClaimCause::Expired);
        }
        let secret = Secret::generate(Role::ClientSecret);
        entry.state = EntryState::Active;
        entry.activated_at = Some(now);
        entry.expires_at = None;
        entry.verifier = Some(Verifier::new(Role::ClientSecret, secret.as_str()));
        Ok((entry.clone(), secret.into_string()))
    }

    /// Whether the generation just issued may add accounts; each invite sets it.
    pub fn set_no_account(&mut self, id: &str, no_account: bool) {
        if let Some(entry) = self.clients.iter_mut().find(|e| e.id == id) {
            entry.no_account = no_account;
        }
    }

    /// Rotate an active client; the old secret dies on the next request.
    pub fn rotate(&mut self, id: &str) -> Result<String, ()> {
        let entry = self
            .clients
            .iter_mut()
            .find(|e| e.id == id && e.state == EntryState::Active)
            .ok_or(())?;
        let secret = Secret::generate(Role::ClientSecret);
        entry.generation += 1;
        entry.verifier = Some(Verifier::new(Role::ClientSecret, secret.as_str()));
        Ok(secret.into_string())
    }

    /// Every code and secret for the id dies at once; the entry stays
    /// visible. Revoking an already-revoked id changes nothing.
    pub fn revoke(&mut self, id: &str, now: OffsetDateTime) -> Result<(), ()> {
        let entry = self.clients.iter_mut().find(|e| e.id == id).ok_or(())?;
        if entry.state == EntryState::Revoked {
            return Ok(());
        }
        entry.state = EntryState::Revoked;
        entry.revoked_at = Some(now);
        entry.expires_at = None;
        entry.verifier = None;
        Ok(())
    }

    /// The display name only; identity and generation unchanged.
    pub fn rename(&mut self, id: &str, display_name: &str) -> Result<(), String> {
        let display_name = Self::validate_display_name(display_name)?;
        let entry = self
            .clients
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "no client has this id".to_string())?;
        entry.display_name = display_name;
        Ok(())
    }

    /// Provision or rotate the remote-operator secret; discloses once.
    pub fn provision_operator_secret(&mut self, now: OffsetDateTime) -> String {
        let secret = Secret::generate(Role::OperatorSecret);
        let verifier = Verifier::new(Role::OperatorSecret, secret.as_str());
        self.operator = Some(OperatorEntry {
            algorithm: verifier.algorithm.to_string(),
            domain: verifier.domain.to_string(),
            digest: verifier.digest,
            rotated_at: now,
        });
        secret.into_string()
    }

    /// Remove the secret; only loopback callers are operators again.
    pub fn remove_operator_secret(&mut self) {
        self.operator = None;
    }
}

fn duration_seconds(seconds: u64) -> time::Duration {
    time::Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX))
}

/// Why a claim failed; the response withholds it, the log names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimCause {
    UnknownId,
    WrongCode,
    Expired,
}

impl fmt::Display for ClaimCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ClaimCause::UnknownId => "no client has this id",
            ClaimCause::WrongCode => "the code is wrong or already consumed",
            ClaimCause::Expired => "the code has expired",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReissueError {
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn issued(lifetime: u64) -> (Registry, String) {
        let mut registry = Registry::default();
        let (code, _) = registry
            .issue("mac-build", "Mac Build", now(), lifetime)
            .expect("issue");
        (registry, code)
    }

    #[test]
    fn client_id_and_display_name_rules() {
        assert!(Registry::validate_id("mac-build").is_ok());
        assert!(Registry::validate_id("a").is_ok());
        assert!(Registry::validate_id("a_1-9").is_ok());
        assert!(Registry::validate_id("").is_err());
        assert!(Registry::validate_id("-lead").is_err());
        assert!(Registry::validate_id("Upper").is_err());
        assert!(Registry::validate_id("a".repeat(64).as_str()).is_err());
        assert!(Registry::validate_id("a".repeat(63).as_str()).is_ok());
        assert!(Registry::validate_display_name("  desk one  ").is_ok());
        assert!(Registry::validate_display_name("").is_err());
        assert!(Registry::validate_display_name(" ").is_err());
        assert!(Registry::validate_display_name("\u{7}x").is_err());
        assert!(Registry::validate_display_name("é".repeat(64).as_str()).is_ok());
        assert!(Registry::validate_display_name("é".repeat(65).as_str()).is_err());
    }

    #[test]
    fn issue_creates_a_pending_entry_with_the_verifier_only() {
        let (mut registry, code) = issued(86_400);
        assert!(code.starts_with("jse2_"));
        let entry = registry.entry("mac-build").expect("entry");
        assert_eq!(entry.state, EntryState::Pending);
        assert_eq!(entry.generation, 1);
        assert_eq!(entry.display_name, "Mac Build");
        assert_eq!(
            entry.expires_at,
            Some(now() + time::Duration::seconds(86_400))
        );
        let verifier = entry.verifier.as_ref().expect("code verifier");
        assert_eq!(verifier.domain, "jaynshare/enrollment");
        assert!(verifier.matches(Role::EnrollmentCode, &code));
        // A duplicate id is refused, a duplicate display name is not.
        assert_eq!(registry.issue("mac-build", "Again", now(), 60), Err(None));
        assert!(registry.issue("other", "Mac Build", now(), 60).is_ok());
    }

    #[test]
    fn claim_activates_once_and_every_replay_fails() {
        let (mut registry, code) = issued(86_400);
        let (entry, secret) = registry.claim("mac-build", &code, now()).expect("claim");
        assert!(secret.starts_with("jsc2_"));
        assert_eq!(entry.state, EntryState::Active);
        assert_eq!(entry.activated_at, Some(now()));
        assert_eq!(entry.expires_at, None);
        assert!(
            entry
                .verifier
                .as_ref()
                .expect("secret verifier")
                .matches(Role::ClientSecret, &secret)
        );
        assert!(registry.client_by_secret(&secret).as_deref() == Some("mac-build"));
        // A second claim — a replay, a wrong code, an unknown id — is refused
        // without returning or replacing a secret.
        assert_eq!(
            registry.claim("mac-build", &code, now()),
            Err(ClaimCause::WrongCode)
        );
        assert_eq!(
            registry.claim("mac-build", "jse2_nope", now()),
            Err(ClaimCause::WrongCode)
        );
        assert_eq!(
            registry.claim("ghost", &code, now()),
            Err(ClaimCause::UnknownId)
        );
        assert_eq!(
            registry.client_by_secret(&secret).as_deref(),
            Some("mac-build")
        );
    }

    #[test]
    fn expired_codes_are_refused_and_reissue_advances_the_generation() {
        let (mut registry, code) = issued(60);
        let later = now() + time::Duration::seconds(61);
        assert_eq!(
            registry.claim("mac-build", &code, later),
            Err(ClaimCause::Expired)
        );
        let (code2, expires) = registry
            .reissue("mac-build", later, 86_400)
            .expect("reissue");
        assert_ne!(code, code2);
        let entry = registry.entry("mac-build").expect("entry");
        assert_eq!(entry.generation, 2);
        assert_eq!(entry.state, EntryState::Pending);
        assert_eq!(entry.expires_at, Some(expires));
        assert!(
            registry.claim("mac-build", &code, later).is_err(),
            "the old code is dead"
        );
        assert!(registry.claim("mac-build", &code2, later).is_ok());
    }

    #[test]
    fn the_no_account_flag_is_written_only_when_set() {
        let (mut registry, _) = issued(60);
        let plain = serde_json::to_value(registry.entry("mac-build")).expect("serialises");
        assert!(plain.get("no_account").is_none(), "{plain}");
        let read: RegistryEntry = serde_json::from_value(plain).expect("reads back");
        assert!(!read.no_account);
        assert!(registry.adds_accounts("mac-build"));
        registry.set_no_account("mac-build", true);
        let flagged = serde_json::to_value(registry.entry("mac-build")).expect("serialises");
        assert_eq!(flagged["no_account"], true);
        assert!(!registry.adds_accounts("mac-build"));
        assert!(!registry.adds_accounts("unknown"));
    }

    #[test]
    fn rotate_replaces_the_secret_and_kills_the_old_one() {
        let (mut registry, code) = issued(86_400);
        let (entry, first) = registry.claim("mac-build", &code, now()).expect("claim");
        let generation = entry.generation;
        let second = registry.rotate("mac-build").expect("rotate");
        assert_ne!(first, second);
        assert_eq!(
            registry.entry("mac-build").expect("entry").generation,
            generation + 1
        );
        assert!(registry.client_by_secret(&first).is_none());
        assert!(registry.client_by_secret(&second).is_some());
        // Rotation is for an active client only.
        assert_eq!(registry.rotate("ghost"), Err(()));
    }

    #[test]
    fn revoke_kills_every_generation_and_reissue_reenrolls() {
        let (mut registry, code) = issued(86_400);
        let (_, secret) = registry.claim("mac-build", &code, now()).expect("claim");
        registry.revoke("mac-build", now()).expect("revoke");
        let entry = registry.entry("mac-build").expect("entry");
        assert_eq!(entry.state, EntryState::Revoked);
        assert_eq!(entry.revoked_at, Some(now()));
        assert_eq!(entry.verifier, None, "a revoked entry holds no verifier");
        assert!(registry.client_by_secret(&secret).is_none());
        assert_eq!(
            registry.claim("mac-build", &code, now()),
            Err(ClaimCause::WrongCode)
        );
        // Revoking twice is a no-op; re-enrolment is a higher pending generation.
        registry.revoke("mac-build", now()).expect("revoke twice");
        let (code2, _) = registry.reissue("mac-build", now(), 60).expect("reissue");
        let entry = registry.entry("mac-build").expect("entry");
        assert_eq!(entry.state, EntryState::Pending);
        assert_eq!(entry.generation, 2);
        assert!(registry.claim("mac-build", &code, now()).is_err());
        assert!(registry.claim("mac-build", &code2, now()).is_ok());
    }

    #[test]
    fn the_operator_slot_is_domain_separate() {
        let mut registry = Registry::default();
        let operator = registry.provision_operator_secret(now());
        assert!(operator.starts_with("jso2_"));
        assert!(registry.operator_by_secret(&operator));
        let (mut registry, code) = issued(86_400);
        let (_, client) = registry.claim("mac-build", &code, now()).expect("claim");
        // A client secret never authenticates the operator slot and vice versa
        // The domains differ.
        assert!(!registry.operator_by_secret(&client));
        registry.provision_operator_secret(now());
        assert!(registry.client_by_secret(&operator).is_none());
        registry.remove_operator_secret();
        assert!(!registry.operator_by_secret(&operator));
    }
}
