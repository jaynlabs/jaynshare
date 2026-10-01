//! One pooled account and its persisted record.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::quota::{self, Bucket};

/// A credential value that never prints itself.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    #[serde(rename = "oauth")]
    OAuth,
    #[serde(rename = "api_key")]
    ApiKey,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::OAuth => "oauth",
            Kind::ApiKey => "api_key",
        }
    }
}

/// Source class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    ApiKeyEntry,
    PortableJson,
    ExplicitFile,
    ManagedStore,
    Browser,
}

impl Source {
    /// The source class named in the snapshot and the log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::ApiKeyEntry => "api-key-entry",
            Source::PortableJson => "portable-json",
            Source::ExplicitFile => "explicit-file",
            Source::ManagedStore => "managed-store",
            Source::Browser => "browser",
        }
    }
}

/// Identity facts retained with the credential.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub email: Option<String>,
    pub account_uuid: Option<Uuid>,
    pub organization_uuid: Option<Uuid>,
    pub organization_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthCredential {
    pub access_token: Secret,
    pub refresh_token: Option<Secret>,
    pub expires_at: OffsetDateTime,
    pub last_refresh_attempt_at: Option<OffsetDateTime>,
    pub last_refresh_success_at: Option<OffsetDateTime>,
    pub refresh_not_before: Option<OffsetDateTime>,
}

impl OAuthCredential {
    pub fn expires_within(&self, margin_seconds: u64, now: OffsetDateTime) -> bool {
        self.expires_at <= now + Duration::seconds(margin_seconds as i64)
    }

    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn in_success_floor(&self, now: OffsetDateTime) -> bool {
        self.last_refresh_success_at
            .is_some_and(|at| at <= now && at + Duration::seconds(10) > now)
    }

    pub fn in_transient_floor(&self, now: OffsetDateTime) -> bool {
        self.refresh_not_before.is_some_and(|at| at > now)
    }

    pub fn replaced_by(&self, mut fresh: Self, now: OffsetDateTime) -> Self {
        if fresh.refresh_token.is_none() {
            fresh.refresh_token = self.refresh_token.clone();
        }
        fresh.last_refresh_attempt_at = Some(now);
        fresh.last_refresh_success_at = Some(now);
        fresh.refresh_not_before = None;
        fresh
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    OAuth(OAuthCredential),
    ApiKey(Secret),
}

impl Credential {
    pub fn kind(&self) -> Kind {
        match self {
            Credential::OAuth(_) => Kind::OAuth,
            Credential::ApiKey(_) => Kind::ApiKey,
        }
    }
}

/// Operator action is required; persisted with its safe reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Errored {
    pub reason: String,
    pub at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    pub handle: Uuid,
    pub display_name: String,
    pub profile: Profile,
    pub source: Source,
    pub enabled: bool,
    pub errored: Option<Errored>,
    pub credential: Credential,
    pub quota: Vec<Bucket>,
    /// The client that added the account; `None` for the operator's.
    pub owner: Option<String>,
}

impl Account {
    pub fn new(
        display_name: String,
        profile: Profile,
        source: Source,
        credential: Credential,
    ) -> Self {
        let quota = quota::expected_buckets(credential.kind());
        Self {
            handle: Uuid::new_v4(),
            display_name,
            profile,
            source,
            enabled: true,
            errored: None,
            credential,
            quota,
            owner: None,
        }
    }

    pub fn kind(&self) -> Kind {
        self.credential.kind()
    }

    /// Enabled and not errored.
    pub fn is_usable(&self) -> bool {
        self.enabled && self.errored.is_none()
    }

    /// The expected buckets are always present, in a stable order.
    pub fn ensure_expected_buckets(&mut self) {
        for expected in quota::expected_buckets(self.kind()) {
            if !self.quota.iter().any(|b| b.name == expected.name) {
                self.quota.push(expected);
            }
        }
    }

    /// Every nullable field present, variant fields only for the kind.
    pub fn to_record(&self) -> Value {
        serde_json::to_value(Record::from(self)).expect("record serializes")
    }

    /// An invalid record fails startup; a malformed quota array is no observations.
    pub fn from_record(value: &Value) -> Result<Self, String> {
        let record: Record = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        let credential = match record.kind {
            Kind::ApiKey => {
                if record.access_token.is_some()
                    || record.refresh_token.is_some()
                    || record.expires_at.is_some()
                    || record.last_refresh_attempt_at.is_some()
                    || record.last_refresh_success_at.is_some()
                    || record.refresh_not_before.is_some()
                {
                    return Err("api_key record carries OAuth fields".into());
                }
                Credential::ApiKey(record.api_key.ok_or("api_key record without api_key")?)
            }
            Kind::OAuth => {
                if record.api_key.is_some() {
                    return Err("oauth record carries api_key".into());
                }
                Credential::OAuth(OAuthCredential {
                    access_token: record
                        .access_token
                        .ok_or("oauth record without access_token")?,
                    refresh_token: record.refresh_token.flatten(),
                    expires_at: record.expires_at.ok_or("oauth record without expires_at")?,
                    last_refresh_attempt_at: record.last_refresh_attempt_at.flatten(),
                    last_refresh_success_at: record.last_refresh_success_at.flatten(),
                    refresh_not_before: record.refresh_not_before.flatten(),
                })
            }
        };
        let errored = record.errored.then(|| Errored {
            reason: record.error_reason.unwrap_or_else(|| "unrecorded".into()),
            at: record.error_at.unwrap_or(OffsetDateTime::UNIX_EPOCH),
        });
        let quota: Vec<Bucket> = record
            .quota
            .and_then(|q| serde_json::from_value(q).ok())
            .unwrap_or_default();
        if record.display_name.is_empty() {
            return Err("display_name is empty".into());
        }
        let mut account = Self {
            handle: record.handle,
            display_name: record.display_name,
            profile: Profile {
                email: record.profile_email,
                account_uuid: record.account_uuid,
                organization_uuid: record.organization_uuid,
                organization_name: record.organization_name,
            },
            source: record.source,
            enabled: record.enabled,
            errored,
            credential,
            quota,
            owner: record.owner,
        };
        account.ensure_expected_buckets();
        Ok(account)
    }
}

/// The loose shape of a persisted record; serialization and the per-kind
/// rules checked by `from_record` share it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    kind: Kind,
    handle: Uuid,
    display_name: String,
    profile_email: Option<String>,
    account_uuid: Option<Uuid>,
    organization_uuid: Option<Uuid>,
    organization_name: Option<String>,
    source: Source,
    enabled: bool,
    errored: bool,
    error_reason: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    error_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_key: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_token: Option<Secret>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "double_option"
    )]
    refresh_token: Option<Option<Secret>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    expires_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "double_time")]
    last_refresh_attempt_at: Option<Option<OffsetDateTime>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "double_time")]
    last_refresh_success_at: Option<Option<OffsetDateTime>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "double_time")]
    refresh_not_before: Option<Option<OffsetDateTime>>,
    #[serde(default)]
    quota: Option<Value>,
    // Absent when null, so a 2.0.x rollback still reads the state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
}

impl From<&Account> for Record {
    fn from(a: &Account) -> Self {
        let (errored, error_reason, error_at) = match &a.errored {
            Some(e) => (true, Some(e.reason.clone()), Some(e.at)),
            None => (false, None, None),
        };
        let (
            api_key,
            access_token,
            refresh_token,
            expires_at,
            last_refresh_attempt_at,
            last_refresh_success_at,
            refresh_not_before,
        ) = match &a.credential {
            Credential::ApiKey(key) => (Some(key.clone()), None, None, None, None, None, None),
            Credential::OAuth(c) => (
                None,
                Some(c.access_token.clone()),
                Some(c.refresh_token.clone()),
                Some(c.expires_at),
                Some(c.last_refresh_attempt_at),
                Some(c.last_refresh_success_at),
                Some(c.refresh_not_before),
            ),
        };
        Self {
            kind: a.kind(),
            handle: a.handle,
            display_name: a.display_name.clone(),
            profile_email: a.profile.email.clone(),
            account_uuid: a.profile.account_uuid,
            organization_uuid: a.profile.organization_uuid,
            organization_name: a.profile.organization_name.clone(),
            source: a.source,
            enabled: a.enabled,
            errored,
            error_reason,
            error_at,
            api_key,
            access_token,
            refresh_token,
            expires_at,
            last_refresh_attempt_at,
            last_refresh_success_at,
            refresh_not_before,
            quota: Some(serde_json::to_value(&a.quota).expect("buckets serialize")),
            owner: a.owner.clone(),
        }
    }
}

/// Distinguishes an absent member (`None`) from an explicit `null` (`Some(None)`).
mod double_option {
    use super::Secret;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Option<Secret>>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_some(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Option<Secret>>, D::Error> {
        Option::<Secret>::deserialize(d).map(Some)
    }
}

/// The same for instants: absent and explicit `null` both stay `null`, an
/// instant renders as RFC 3339.
mod double_time {
    use super::Rfc3339;
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(
        v: &Option<Option<OffsetDateTime>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v.as_ref().and_then(Option::as_ref) {
            None => s.serialize_none(),
            Some(t) => s.serialize_str(&crate::timestamp::rfc3339(*t)),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Option<OffsetDateTime>>, D::Error> {
        let raw = Option::<String>::deserialize(d)?;
        match raw {
            None => Ok(Some(None)),
            Some(s) => OffsetDateTime::parse(s.as_str(), &Rfc3339)
                .map(|t| Some(Some(t)))
                .map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::macros::datetime;

    fn oauth() -> Account {
        Account::new(
            "alice@example.com".into(),
            Profile {
                email: Some("alice@example.com".into()),
                account_uuid: Some(Uuid::nil()),
                organization_uuid: None,
                organization_name: Some("Acme".into()),
            },
            Source::PortableJson,
            Credential::OAuth(OAuthCredential {
                access_token: Secret::new("jso2_access".into()),
                refresh_token: None,
                expires_at: datetime!(2026-09-17 00:00 UTC),
                last_refresh_attempt_at: None,
                last_refresh_success_at: None,
                refresh_not_before: None,
            }),
        )
    }

    #[test]
    fn record_round_trips_and_carries_only_the_kind_s_fields() {
        let a = oauth();
        let v = a.to_record();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert!(keys.contains(&"refresh_token"));
        assert!(!keys.contains(&"api_key"));
        assert_eq!(v["refresh_token"], Value::Null);
        assert_eq!(v["error_at"], Value::Null);
        assert_eq!(Account::from_record(&v).unwrap(), a);

        let k = Account::new(
            "k".into(),
            Profile::default(),
            Source::ApiKeyEntry,
            Credential::ApiKey(Secret::new("sk".into())),
        );
        let v = k.to_record();
        assert!(v.get("access_token").is_none());
        assert_eq!(Account::from_record(&v).unwrap(), k);
    }

    #[test]
    fn a_field_of_the_wrong_kind_is_an_invalid_record() {
        let mut v = oauth().to_record();
        v["api_key"] = json!("sk");
        assert!(Account::from_record(&v).unwrap_err().contains("api_key"));
        let mut v = oauth().to_record();
        v.as_object_mut().unwrap().remove("refresh_token");
        assert_eq!(
            Account::from_record(&v).unwrap().credential,
            oauth().credential
        );
    }

    #[test]
    fn a_record_without_an_owner_is_the_operator_s() {
        let v = oauth().to_record();
        assert!(v.get("owner").is_none());
        assert_eq!(Account::from_record(&v).unwrap().owner, None);
    }

    #[test]
    fn an_owned_record_round_trips() {
        let owned = Account {
            owner: Some("mac-1".into()),
            ..oauth()
        };
        let v = owned.to_record();
        assert_eq!(v["owner"], "mac-1");
        assert_eq!(Account::from_record(&v).unwrap(), owned);
    }

    #[test]
    fn malformed_quota_loads_as_no_observations() {
        let mut v = oauth().to_record();
        v["quota"] = json!("garbage");
        let a = Account::from_record(&v).unwrap();
        assert_eq!(a.quota, quota::expected_buckets(Kind::OAuth));
    }

    #[test]
    fn secrets_never_debug_print() {
        assert_eq!(
            format!("{:?}", Secret::new("jso2_x".into())),
            "Secret(<redacted>)"
        );
    }

    #[test]
    fn refresh_floors_have_exact_boundaries() {
        let now = datetime!(2026-09-17 00:00 UTC);
        let Credential::OAuth(mut family) = oauth().credential else {
            panic!("OAuth fixture")
        };

        family.expires_at = now + Duration::seconds(301);
        assert!(!family.expires_within(300, now));
        family.expires_at = now + Duration::seconds(300);
        assert!(family.expires_within(300, now));

        family.last_refresh_success_at = Some(now);
        assert!(family.in_success_floor(now));
        assert!(family.in_success_floor(now + Duration::seconds(9)));
        assert!(!family.in_success_floor(now + Duration::seconds(10)));
        assert!(!family.in_success_floor(now - Duration::seconds(1)));

        family.refresh_not_before = Some(now + Duration::seconds(30));
        assert!(family.in_transient_floor(now));
        assert!(family.in_transient_floor(now + Duration::seconds(29)));
        assert!(!family.in_transient_floor(now + Duration::seconds(30)));
    }

    fn refresh_family(refresh: Option<&str>, now: OffsetDateTime) -> OAuthCredential {
        OAuthCredential {
            access_token: Secret::new("access".into()),
            refresh_token: refresh.map(|t| Secret::new(t.into())),
            expires_at: now + Duration::hours(1),
            last_refresh_attempt_at: None,
            last_refresh_success_at: None,
            refresh_not_before: None,
        }
    }

    /// The token endpoint may answer without a new refresh token.
    #[test]
    fn replaced_by_keeps_the_old_refresh_token_when_the_response_omits_it() {
        let now = datetime!(2026-09-17 00:00 UTC);
        let old = refresh_family(Some("old-refresh"), now);
        let mut fresh = refresh_family(None, now);
        fresh.expires_at = now + Duration::hours(2);

        let rotated = old.replaced_by(fresh, now);

        assert_eq!(
            rotated.refresh_token.as_ref().map(Secret::expose),
            Some("old-refresh"),
            "the lineage's refresh token survives"
        );
        assert_eq!(rotated.last_refresh_attempt_at, Some(now));
        assert_eq!(rotated.last_refresh_success_at, Some(now));
        assert_eq!(rotated.refresh_not_before, None);
    }

    #[test]
    fn replaced_by_takes_the_fresh_refresh_token_when_the_response_carries_one() {
        let now = datetime!(2026-09-17 00:00 UTC);
        let rotated = refresh_family(Some("old-refresh"), now)
            .replaced_by(refresh_family(Some("fresh-refresh"), now), now);

        assert_eq!(
            rotated.refresh_token.as_ref().map(Secret::expose),
            Some("fresh-refresh")
        );
    }
}
