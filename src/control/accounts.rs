//! The account operations and the account object the reads and every
//! mutation answer with. The pool-side rules are `pool::operations`; the
//! reference check is `config::references`, run inside the same
//! `mutate_pool` closure so a refusal leaves the state file untouched.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{HeaderMap, Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::Principal;
use crate::config::references;
use crate::data_plane::relay::ResponseBody;
use crate::pool::managed::{self, ImportFailed};
use crate::pool::selection;
use crate::pool::{
    Account, Credential, OAuthCredential, OperationError, Pool, Profile, ReferenceConflict,
    Resolve, Secret, Source,
};
use crate::provider::Provider;
use crate::server::{MutateError, Server};
use crate::state;
use crate::timestamp::rfc3339;

use super::{
    base, error, insecure_channel, insecure_channel_refusal, member_errors, mutation_body,
    mutation_line, percent_decode, persist_failed, read, time_or_null,
};

/// The four credential sources, shared by add and replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialSource {
    ApiKey,
    PortableJson,
    File,
    ClaudeManaged,
}

fn credential_source(name: &str) -> Option<CredentialSource> {
    match name {
        "api_key" => Some(CredentialSource::ApiKey),
        "portable_json" => Some(CredentialSource::PortableJson),
        "file" => Some(CredentialSource::File),
        "claude_managed" => Some(CredentialSource::ClaudeManaged),
        _ => None,
    }
}

/// One validated `credential` object: what the pool stores, and the identity
/// the profile endpoint supplied for it.
struct Imported {
    credential: Credential,
    /// `Err` with its safe reason when the lookup failed or carried no account
    /// UUID: `add` refuses on it, `replace` proceeds on the
    /// operator's explicit naming.
    identity: Result<Profile, String>,
    source: Source,
}

/// The `credential` object, validated and resolved: the member check per
/// source, the channel rule, the managed read and the profile
/// lookup. `Err` is the refusal, already shaped.
async fn import_credential(
    server: &Server,
    peer: SocketAddr,
    principal: Option<&Principal>,
    credential: &Value,
) -> Result<Imported, Response<ResponseBody>> {
    let source = match credential_source(credential["source"].as_str().unwrap_or("")) {
        Some(source) => source,
        None => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "credential.source is one of api_key, portable_json, file, claude_managed",
                Some("credential.source".into()),
                vec![],
            ));
        }
    };
    let allowed: &[(&str, &str, bool)] = match source {
        CredentialSource::ApiKey => &[("source", "string", true), ("api_key", "string", true)],
        CredentialSource::PortableJson => {
            &[("source", "string", true), ("credential", "object", true)]
        }
        CredentialSource::File => &[("source", "string", true), ("path", "string", true)],
        CredentialSource::ClaudeManaged => &[
            ("source", "string", true),
            ("platform_hint", "string", false),
        ],
    };
    let details = member_errors(credential, allowed);
    if !details.is_empty() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the credential object has invalid members",
            Some("credential".into()),
            details,
        ));
    }
    // A pooled credential crosses the wire only on loopback or under TLS.
    let carries_secret = matches!(
        source,
        CredentialSource::ApiKey | CredentialSource::PortableJson
    );
    if carries_secret && insecure_channel(server, peer) {
        return Err(insecure_channel_refusal(server, peer, principal));
    }
    if source == CredentialSource::ApiKey {
        let key = credential["api_key"].as_str().unwrap_or("").trim();
        // The key is opaque, so the only validation is the one a
        // key must pass to be sent at all — non-empty and a legal header
        // value (it is sent as `x-api-key`); anything else is a 422.
        let rejected = if key.is_empty() {
            Some("api_key is empty")
        } else if !key.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            Some("api_key is not a header value: it must be visible ASCII without spaces")
        } else {
            None
        };
        if let Some(why) = rejected {
            return Err(error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "credential_rejected",
                why,
                Some("credential.api_key".into()),
                vec![],
            ));
        }
        // No live probe on add (the key is opaque); a bad key surfaces as a refused credential on first use.
        return Ok(Imported {
            credential: Credential::ApiKey(Secret::new(key.to_string())),
            identity: Ok(Profile::default()),
            source: Source::ApiKeyEntry,
        });
    }
    let (family, account_source) = match source {
        CredentialSource::PortableJson => (
            parse_portable(&credential["credential"]).map_err(|message| {
                error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "credential_rejected",
                    &message,
                    Some("credential.credential".into()),
                    vec![],
                )
            })?,
            Source::PortableJson,
        ),
        CredentialSource::File => {
            let path = std::path::PathBuf::from(credential["path"].as_str().unwrap_or(""));
            let object = read_protected_file(&path).map_err(|message| {
                error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "import_failed",
                    &format!("explicit file: {message}"),
                    Some("credential.path".into()),
                    vec![],
                )
            })?;
            (
                parse_portable(&object).map_err(|message| {
                    error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "credential_rejected",
                        &message,
                        Some("credential.path".into()),
                        vec![],
                    )
                })?,
                Source::ExplicitFile,
            )
        }
        CredentialSource::ClaudeManaged => (
            managed_family(credential).await.map_err(managed_refusal)?,
            Source::ManagedStore,
        ),
        CredentialSource::ApiKey => unreachable!("answered above"),
    };
    // Identity first; nothing is saved without it.
    let identity = match server
        .upstream
        .fetch_profile(family.access_token.expose())
        .await
    {
        Ok(profile) if profile.account_uuid.is_some() => Ok(profile),
        Ok(_) => Err("the profile carries no account UUID; the account was not saved".to_string()),
        Err(message) => Err(format!("profile lookup failed: {message}")),
    };
    Ok(Imported {
        credential: Credential::OAuth(family),
        identity,
        source: account_source,
    })
}

/// What a managed import can refuse before the pool sees it.
enum ManagedRefusal {
    /// `platform_hint` is `keychain` or `file`.
    Hint,
    /// The class and cause, never the contents.
    Failed(ImportFailed),
}

/// The managed store this host holds, read once and copied.
async fn managed_family(credential: &Value) -> Result<OAuthCredential, ManagedRefusal> {
    let hint = match credential["platform_hint"].as_str() {
        None => None,
        Some(name) => Some(managed::Hint::parse(name).ok_or(ManagedRefusal::Hint)?),
    };
    managed::read(hint, &crate::config::platform::home())
        .await
        .map_err(ManagedRefusal::Failed)
}

fn managed_refusal(refusal: ManagedRefusal) -> Response<ResponseBody> {
    let failed = match refusal {
        ManagedRefusal::Hint => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "credential.platform_hint is keychain or file",
                Some("credential.platform_hint".into()),
                vec![],
            );
        }
        ManagedRefusal::Failed(failed) => failed,
    };
    tracing::info!(event = "managed_import", class = %failed.class, outcome = %failed.cause, "a Claude-managed import failed");
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "import_failed",
        &failed.to_string(),
        Some("credential.platform_hint".into()),
        vec![],
    )
}

/// The operation runs on the candidate pool, then every route and
/// priority reference is resolved against it; an entry the operation newly
/// breaks refuses it, and `mutate_pool` discards the candidate unwritten
/// Enable and disable never call this.
fn guarded<T>(
    config: &crate::config::Config,
    pool: &mut Pool,
    apply: impl FnOnce(&mut Pool) -> Result<T, OperationError>,
) -> Result<T, OperationError> {
    let before = references::conflicts(config, pool);
    let out = apply(pool)?;
    let introduced = references::introduced(&before, &references::conflicts(config, pool));
    if introduced.is_empty() {
        return Ok(out);
    }
    Err(OperationError::ReferenceConflict(introduced))
}

/// One refused operation, as its envelope and its log line.
fn refused(
    operation: &str,
    account: Option<Uuid>,
    error_value: OperationError,
) -> Response<ResponseBody> {
    let (why, response) = match error_value {
        OperationError::NotFound => (
            "not_found",
            error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "no account has this handle",
                account.map(|h| h.to_string()),
                vec![],
            ),
        ),
        OperationError::NameEmpty => (
            "name_empty",
            error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "a display name is not empty",
                Some("display_name".into()),
                vec![],
            ),
        ),
        OperationError::NameConflict(name) => (
            "name_conflict",
            error(
                StatusCode::CONFLICT,
                "conflict",
                "an account already has this display name",
                Some(name),
                vec![],
            ),
        ),
        OperationError::NameMismatch { existing } => (
            "name_mismatch",
            error(
                StatusCode::CONFLICT,
                "conflict",
                &format!(
                    "this credential belongs to the account {existing:?}; rename it with the name operation"
                ),
                Some(existing),
                vec![],
            ),
        ),
        OperationError::KindMismatch {
            account: held,
            credential,
        } => (
            "kind_mismatch",
            error(
                StatusCode::CONFLICT,
                "conflict",
                "a replacement credential has the account's kind",
                account.map(|h| h.to_string()),
                vec![json!({
                    "target": "credential",
                    "code": "kind_mismatch",
                    "message": format!("the account is {}, the credential {}", held.as_str(), credential.as_str()),
                })],
            ),
        ),
        OperationError::IdentityMismatch => (
            "identity_mismatch",
            error(
                StatusCode::CONFLICT,
                "conflict",
                "the credential's identity is not this account's",
                account.map(|h| h.to_string()),
                vec![],
            ),
        ),
        OperationError::NotOwner => (
            "not_owner",
            error(
                StatusCode::CONFLICT,
                "conflict",
                "this identity is another owner's account",
                account.map(|h| h.to_string()),
                vec![],
            ),
        ),
        OperationError::NewAccount => (
            "new_account",
            error(
                StatusCode::CONFLICT,
                "conflict",
                "this identity is not an account of the pool",
                account.map(|h| h.to_string()),
                vec![],
            ),
        ),
        OperationError::ReferenceConflict(entries) => {
            let listed: Vec<String> = entries.iter().map(|c| c.entry.clone()).collect();
            tracing::info!(
                event = "account_operation_refused",
                operation,
                account = named(account),
                why = "reference_conflict",
                entries = %json!(listed),
                "the operation would leave a configured reference unusable"
            );
            return error(
                StatusCode::CONFLICT,
                "account_reference_conflict",
                "the configuration's routes or priorities would no longer resolve; change it first and repeat",
                account.map(|h| h.to_string()),
                entries.iter().map(reference_detail).collect(),
            );
        }
    };
    tracing::info!(
        event = "account_operation_refused",
        operation,
        account = named(account),
        why,
        "an account operation was refused"
    );
    response
}

/// The log line's `account` field: the handle when the operation named one.
fn named(handle: Option<Uuid>) -> String {
    handle.map(|h| h.to_string()).unwrap_or_default()
}

fn reference_detail(conflict: &ReferenceConflict) -> Value {
    json!({
        "target": conflict.entry,
        "code": conflict.why.as_str(),
        "message": format!("{:?} would be {} in {}", conflict.reference, conflict.why.as_str(), conflict.entry),
    })
}

/// Add an account; the credential shape depends on its `source`.
pub(super) async fn add_account(
    server: &Server,
    peer: SocketAddr,
    principal: &Principal,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let body = match mutation_body(server, peer, Some(principal), request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    let details = member_errors(
        &body,
        &[
            ("display_name", "string", false),
            ("credential", "object", true),
        ],
    );
    if !details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            details,
        );
    }
    let display_name = body["display_name"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let imported = match import_credential(server, peer, Some(principal), &body["credential"]).await
    {
        Ok(imported) => imported,
        Err(refusal) => return refusal,
    };
    if imported.credential.kind() == crate::pool::Kind::ApiKey && display_name.is_none() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "an API-key account needs a non-empty display_name",
            Some("display_name".into()),
            vec![],
        );
    }
    // An OAuth source without a resolved identity saves nothing.
    let profile = match imported.identity {
        Ok(profile) => profile,
        Err(message) => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "credential_rejected",
                &message,
                None,
                vec![],
            );
        }
    };
    let name = display_name
        .clone()
        .or_else(|| profile.email.clone())
        .unwrap_or_else(|| format!("account {}", profile.account_uuid.unwrap_or_default()));
    let account = Account::new(
        Provider::Anthropic,
        name,
        profile,
        imported.source,
        imported.credential,
    );
    let added = server.mutate_pool(|pool| {
        guarded(&server.config().config, pool, |pool| {
            let known: Vec<Uuid> = pool.accounts().iter().map(|a| a.handle).collect();
            pool.add(account, display_name)
                .map(|handle| (handle, known.contains(&handle)))
        })
    });
    match added {
        Ok((handle, updated)) => {
            let account = account_object(server, handle).unwrap_or(Value::Null);
            tracing::info!(event = "account_added", handle = %handle, source = imported.source.as_str(), updated, "account added");
            mutation_line(
                server,
                peer,
                principal,
                "account_add",
                &handle.to_string(),
                "added",
            );
            base(StatusCode::CREATED, json!({ "account": account }))
        }
        Err(MutateError::Refused(why)) => refused("add", None, why),
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

/// The credential replaced in place, the errored state cleared.
pub(super) async fn replace_account(
    server: &Server,
    peer: SocketAddr,
    principal: &Principal,
    handle: Uuid,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let body = match mutation_body(server, peer, Some(principal), request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    let details = member_errors(&body, &[("credential", "object", true)]);
    if !details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            details,
        );
    }
    if server.pool.lock().expect("pool lock").get(handle).is_none() {
        return refused("replace", Some(handle), OperationError::NotFound);
    }
    let imported = match import_credential(server, peer, Some(principal), &body["credential"]).await
    {
        Ok(imported) => imported,
        Err(refusal) => return refusal,
    };
    // An identity the profile could not supply does not contradict the
    // account the operator named; the stored facts stay and the family lands.
    let profile = imported.identity.ok();
    let (credential, source) = (imported.credential, imported.source);
    let cleared = server
        .pool
        .lock()
        .expect("pool lock")
        .get(handle)
        .is_some_and(|a| a.errored.is_some());
    let replaced = server.mutate_pool(|pool| {
        guarded(&server.config().config, pool, |pool| {
            pool.replace_credential(handle, credential, profile, source)
        })
    });
    match replaced {
        Ok(()) => {
            tracing::info!(event = "account_replaced", account = %handle, source = source.as_str(), errored_cleared = cleared, "an account credential was replaced");
            mutation_line(
                server,
                peer,
                principal,
                "account_credential",
                &handle.to_string(),
                "replaced",
            );
            base(
                StatusCode::OK,
                json!({ "account": account_object(server, handle).unwrap_or(Value::Null) }),
            )
        }
        Err(MutateError::Refused(why)) => refused("replace", Some(handle), why),
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

/// Rename; the handle never changes.
pub(super) async fn rename_account(
    server: &Server,
    peer: SocketAddr,
    principal: &Principal,
    handle: Uuid,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let body = match mutation_body(server, peer, Some(principal), request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    let details = member_errors(&body, &[("display_name", "string", true)]);
    if !details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            details,
        );
    }
    let name = body["display_name"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_string();
    let from = server
        .pool
        .lock()
        .expect("pool lock")
        .get(handle)
        .map(|a| a.display_name.clone());
    let renamed = server.mutate_pool(|pool| {
        guarded(&server.config().config, pool, |pool| {
            pool.rename(handle, &name)
        })
    });
    match renamed {
        Ok(()) => {
            tracing::info!(event = "account_renamed", account = %handle, from = from.unwrap_or_default(), to = name, "an account was renamed");
            mutation_line(
                server,
                peer,
                principal,
                "account_rename",
                &handle.to_string(),
                "renamed",
            );
            base(
                StatusCode::OK,
                json!({ "account": account_object(server, handle).unwrap_or(Value::Null) }),
            )
        }
        Err(MutateError::Refused(why)) => refused("rename", Some(handle), why),
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

/// Enable sets the flag and clears errored — the operator retry path
/// — and disable removes the account from new selection. Neither is refused
/// by the reference check.
async fn set_enabled(
    server: &Server,
    peer: SocketAddr,
    principal: &Principal,
    handle: Uuid,
    enabled: bool,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    if let Some(refusal) = mutation_body(server, peer, Some(principal), request)
        .await
        .err()
    {
        return refusal;
    }
    let cleared = enabled
        && server
            .pool
            .lock()
            .expect("pool lock")
            .get(handle)
            .is_some_and(|a| a.errored.is_some());
    match server.mutate_pool(|pool| pool.set_enabled(handle, enabled)) {
        Ok(()) => {
            if enabled {
                tracing::info!(event = "account_enabled", account = %handle, errored_cleared = cleared, "an account was enabled");
            } else {
                tracing::info!(event = "account_disabled", account = %handle, "an account was disabled");
            }
            mutation_line(
                server,
                peer,
                principal,
                if enabled {
                    "account_enable"
                } else {
                    "account_disable"
                },
                &handle.to_string(),
                if enabled { "enabled" } else { "disabled" },
            );
            base(
                StatusCode::OK,
                json!({ "account": account_object(server, handle).unwrap_or(Value::Null) }),
            )
        }
        Err(MutateError::Refused(why)) => refused(
            if enabled { "enable" } else { "disable" },
            Some(handle),
            why,
        ),
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

pub(super) async fn enable_account(
    server: &Server,
    peer: SocketAddr,
    principal: &Principal,
    handle: Uuid,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    set_enabled(server, peer, principal, handle, true, request).await
}

pub(super) async fn disable_account(
    server: &Server,
    peer: SocketAddr,
    principal: &Principal,
    handle: Uuid,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    set_enabled(server, peer, principal, handle, false, request).await
}

/// Durable removal, live at once; the reference check may refuse it.
pub(super) fn remove_account(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    handle: Uuid,
    headers: &HeaderMap,
) -> Response<ResponseBody> {
    // The guard runs on a body-less mutation too.
    if let Some(refusal) = super::csrf_refusal(server, peer, Some(principal), headers) {
        return refusal;
    }
    let was_default = server.pool.lock().expect("pool lock").default_account() == Some(handle);
    let removed = server.mutate_pool(|pool| {
        guarded(&server.config().config, pool, |pool| {
            pool.remove(handle)
                .map(|_| ())
                .ok_or(OperationError::NotFound)
        })
    });
    match removed {
        Ok(()) => {
            tracing::info!(event = "account_removed", handle = %handle, was_default, "account removed");
            mutation_line(
                server,
                peer,
                principal,
                "account_remove",
                &handle.to_string(),
                "removed",
            );
            base(StatusCode::OK, json!({}))
        }
        Err(MutateError::Refused(why)) => refused("remove", Some(handle), why),
        Err(MutateError::Persist(e)) => persist_failed(server, e),
    }
}

pub(super) fn resolve(server: &Arc<Server>, query: Option<&str>) -> Response<ResponseBody> {
    let reference = query
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("reference=")))
        .map(percent_decode)
        .filter(|r| !r.is_empty() && r.len() <= 1024 && !r.chars().any(char::is_control));
    let Some(reference) = reference else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "reference is required: one display name, email, UUID or handle",
            Some("reference".into()),
            vec![],
        );
    };
    let found = server
        .pool
        .lock()
        .expect("pool lock")
        .resolve(&reference)
        .map(|a| a.handle);
    match found {
        Ok(handle) => read(json!({ "account": account_object(server, handle) })),
        Err(Resolve::NotFound) => error(StatusCode::NOT_FOUND, "account_not_found", "no account matches the reference", Some(reference), vec![]),
        Err(Resolve::Ambiguous(names)) => error(
            StatusCode::BAD_REQUEST,
            "ambiguous_account_reference",
            // The qualifier (organisation name or full organisation UUID)
            // is what disambiguates, so the message names it.
            &format!(
                "the reference matches several accounts: {}; an organisation name or full organisation UUID is the qualifier",
                names.join(", ")
            ),
            Some(reference),
            names.into_iter().map(|n| json!({ "target": n, "code": "matches", "message": "this account matches the reference" })).collect(),
        ),
    }
}

/// A regular file, owner-readable only, read once.
fn read_protected_file(path: &std::path::Path) -> Result<Value, String> {
    state::check_private(path)?;
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|_| "the file is not a JSON object".to_string())
}

/// A portable credential: exactly `access_token`, `refresh_token`, `expires_at`.
fn parse_portable(object: &Value) -> Result<OAuthCredential, String> {
    let map = object
        .as_object()
        .ok_or("the portable credential is not a JSON object")?;
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["access_token", "expires_at", "refresh_token"] {
        return Err(
            "the portable credential has exactly access_token, refresh_token and expires_at".into(),
        );
    }
    let string = |k: &str| {
        map[k]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .ok_or(format!("{k} is not a non-empty string"))
    };
    let access_token = string("access_token")?;
    let refresh_token = string("refresh_token")?;
    let expires_at = OffsetDateTime::parse(
        &string("expires_at")?,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| "expires_at is not an RFC 3339 timestamp".to_string())?;
    Ok(OAuthCredential {
        access_token: Secret::new(access_token),
        refresh_token: Some(Secret::new(refresh_token)),
        expires_at,
        last_refresh_attempt_at: None,
        last_refresh_success_at: None,
        refresh_not_before: None,
    })
}

pub(crate) fn account_object(server: &Server, handle: Uuid) -> Option<Value> {
    let now = OffsetDateTime::now_utc();
    let loaded = server.config();
    let probe = server.probes.snapshot();
    let mut pool = server.pool.lock().expect("pool lock");
    if pool.expire_quota(now) {
        server.mark_quota_dirty();
    }
    let runtime = Runtime {
        config: &loaded.config,
        probe: &probe,
        active_per_account: &pool.sessions(now).active_per_account(now),
        refreshes: &server.refreshes,
        now,
    };
    let account = pool.get(handle)?;
    Some(project_pool_account(&pool, account, &runtime))
}

/// What the pool's runtime adds to one account object, shared by the snapshot
/// and `account show` so both say the same thing.
pub(crate) struct Runtime<'a> {
    pub(crate) config: &'a crate::config::Config,
    pub(crate) probe: &'a crate::pool::probe::Snapshot,
    pub(crate) active_per_account: &'a std::collections::HashMap<Uuid, usize>,
    pub(crate) refreshes: &'a crate::pool::refresh::Refreshes,
    pub(crate) now: OffsetDateTime,
}

/// One account with every runtime fact filled —
/// the throttle hold and whether revalidation is allowed, the active
/// sessions, the ramp in force and the last probe outcome.
pub(crate) fn project_pool_account(pool: &Pool, account: &Account, runtime: &Runtime<'_>) -> Value {
    let (handle, now) = (account.handle, runtime.now);
    let config = runtime.config;
    let mut object = project_account(
        account,
        pool.usage(handle),
        &config.selection,
        pool.organisation_hold(account, now),
        runtime.refreshes.in_flight(handle),
        now,
    );
    object["sessions_active"] = json!(
        runtime
            .active_per_account
            .get(&handle)
            .copied()
            .unwrap_or(0)
    );
    object["quota_holds"] = json!({
        "throttle_hold_end": time_or_null(pool.throttle_hold_end(handle, now)),
        "revalidation_allowed": pool.revalidation_allowed(handle, &config.quota, now),
    });
    // The ramp in force, read-only.
    if let Some((started_at, limit)) = pool.ramp_view(handle, &config.selection.ramp, now) {
        object["ramp"] =
            json!({ "active": true, "started_at": rfc3339(started_at), "limit": limit });
    }
    if let Some(outcome) = runtime.probe.outcomes.get(&handle) {
        object["probe"] = json!(outcome);
    }
    object
}

pub(super) fn health_of(
    account: &Account,
    refreshing_since: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> (&'static str, Option<String>, Option<OffsetDateTime>) {
    match (&account.errored, refreshing_since) {
        (Some(error), _) => ("errored", Some(error.reason.clone()), Some(error.at)),
        (None, Some(started)) => ("refreshing", None, Some(started)),
        (None, None) => match &account.credential {
            Credential::OAuth(family)
                if family.in_transient_floor(now) && family.is_expired(now) =>
            {
                (
                    "refresh_wait",
                    Some("credential refresh failed transiently".into()),
                    family.last_refresh_attempt_at,
                )
            }
            _ => ("ready", None, None),
        },
    }
}

/// One account, every member present; the runtime facts
/// `project_pool_account` fills start `null`, `0` or inactive here.
pub(super) fn project_account(
    account: &Account,
    usage: crate::pool::Usage,
    settings: &crate::config::SelectionSettings,
    org_hold: Option<OffsetDateTime>,
    refreshing_since: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Value {
    let (health_state, reason, since) = health_of(account, refreshing_since, now);
    let credential = match &account.credential {
        Credential::OAuth(c) => json!({
            "access_token_expires_at": rfc3339(c.expires_at),
            "refresh_material_present": c.refresh_token.is_some(),
            "last_refresh_attempt": time_or_null(c.last_refresh_attempt_at),
            "last_refresh_success": time_or_null(c.last_refresh_success_at),
            "next_refresh_allowed_at": time_or_null(c.refresh_not_before),
        }),
        Credential::ApiKey(_) => json!({
            "access_token_expires_at": null,
            "refresh_material_present": false,
            "last_refresh_attempt": null,
            "last_refresh_success": null,
            "next_refresh_allowed_at": null,
        }),
    };
    let (eligible, ineligible) = match selection::eligibility(account, settings, now, org_hold) {
        Ok(()) => (true, None),
        Err(why) => (false, Some(why)),
    };
    let buckets: Vec<Value> = account
        .quota
        .iter()
        .map(|b| {
            json!({
                "name": b.name,
                "scope": b.scope,
                "state": b.state(now),
                "utilisation": b.effective_utilization(),
                "limit": b.limit,
                "remaining": b.remaining,
                "reset": time_or_null(b.reset_at),
                "hold_end": time_or_null(b.exhaustion_hold_until),
                "observed_at": time_or_null(b.observed_at),
                "observed_source": b.source,
            })
        })
        .collect();
    let hold_end = account
        .quota
        .iter()
        .filter_map(|b| b.exhaustion_hold_until)
        .filter(|t| *t > now)
        .min();
    // Over-threshold detail is the reset of the bucket that produced
    // the bar — the wait until the account is eligible again.
    let over_reset = account
        .quota
        .iter()
        .filter(|b| {
            b.effective_utilization()
                .is_some_and(|u| u >= settings.switch_threshold)
        })
        .filter_map(|b| b.reset_at)
        .min();
    json!({
        "handle": account.handle,
        "display_name": account.display_name,
        "kind": account.kind().as_str(),
        "source_class": account.source,
        "enabled": account.enabled,
        "owner": account.owner,
        "health": { "state": health_state, "reason": reason, "since": time_or_null(since) },
        "profile": account.profile,
        "credential": credential,
        "priority": selection::priority_of(account.handle, std::slice::from_ref(account), settings),
        "eligibility": {
            "eligible": eligible,
            "reason": ineligible,
            "reason_detail": ineligible.map(|why| match why {
                selection::Ineligible::Held => {
                    hold_end.map(rfc3339).unwrap_or_else(|| "held".into())
                }
                selection::Ineligible::OverThreshold => over_reset
                    .map(rfc3339)
                    .unwrap_or_else(|| "over_threshold".into()),
                selection::Ineligible::Errored => reason.clone().unwrap_or_default(),
                selection::Ineligible::Disabled => "disabled".into(),
            }),
        },
        "buckets": buckets,
        "quota_holds": { "throttle_hold_end": Value::Null, "revalidation_allowed": null },
        "usage": usage,
        "sessions_active": 0,
        "ramp": { "active": false, "started_at": null, "limit": null },
        "probe": { "outcome": null, "finished_at": null, "error": null },
    })
}

#[cfg(test)]
mod tests {
    use time::Duration;
    use time::macros::datetime;

    use super::*;
    use crate::config;
    use crate::pool::Errored;
    use crate::pool::refresh::{Join, Refreshes};

    #[test]
    fn health_is_derived_over_all_four_states() {
        let now = datetime!(2026-09-17 00:00 UTC);
        let attempted = now - Duration::seconds(1);
        let started = now - Duration::seconds(2);
        let mut account = Account::new(
            crate::provider::Provider::Anthropic,
            "FSUB".into(),
            Profile::default(),
            Source::PortableJson,
            Credential::OAuth(OAuthCredential {
                access_token: Secret::new("access".into()),
                refresh_token: Some(Secret::new("refresh".into())),
                expires_at: now + Duration::hours(1),
                last_refresh_attempt_at: None,
                last_refresh_success_at: None,
                refresh_not_before: None,
            }),
        );

        assert_eq!(health_of(&account, None, now), ("ready", None, None));

        let Credential::OAuth(family) = &mut account.credential else {
            panic!("OAuth fixture")
        };
        family.expires_at = now;
        family.last_refresh_attempt_at = Some(attempted);
        family.refresh_not_before = Some(now + Duration::seconds(30));
        assert_eq!(
            health_of(&account, None, now),
            (
                "refresh_wait",
                Some("credential refresh failed transiently".into()),
                Some(attempted),
            )
        );
        assert_eq!(
            health_of(&account, Some(started), now),
            ("refreshing", None, Some(started))
        );

        account.errored = Some(Errored {
            reason: "operator action required".into(),
            at: now,
        });
        assert_eq!(
            health_of(&account, Some(started), now),
            (
                "errored",
                Some("operator action required".into()),
                Some(now),
            )
        );
    }

    /// The snapshot's `health` member carries `state`, `reason` and
    /// `since` for every state; `since` is the error time, the operation's
    /// start, the last attempt or null. Fake registry = one `join_or_start`
    /// entry that no runner ever finishes.
    #[test]
    fn project_account_carries_health_since_for_every_state() {
        let now = datetime!(2026-09-17 00:00 UTC);
        let attempted = now - Duration::seconds(1);
        let started = now - Duration::seconds(2);
        let settings = config::parse(b"version = 1\n", std::path::Path::new("/"))
            .expect("default settings")
            .selection;
        let mut account = Account::new(
            crate::provider::Provider::Anthropic,
            "FSUB".into(),
            Profile::default(),
            Source::PortableJson,
            Credential::OAuth(OAuthCredential {
                access_token: Secret::new("access".into()),
                refresh_token: Some(Secret::new("refresh".into())),
                expires_at: now + Duration::hours(1),
                last_refresh_attempt_at: None,
                last_refresh_success_at: None,
                refresh_not_before: None,
            }),
        );
        let health = |account: &Account, refreshing_since: Option<OffsetDateTime>| {
            project_account(
                account,
                crate::pool::Usage::default(),
                &settings,
                None,
                refreshing_since,
                now,
            )["health"]
                .clone()
        };

        assert_eq!(
            health(&account, None),
            json!({ "state": "ready", "reason": null, "since": null })
        );

        let refreshes = Refreshes::default();
        assert!(matches!(
            refreshes.join_or_start(account.handle, started),
            Join::Run(_)
        ));
        assert_eq!(
            health(&account, refreshes.in_flight(account.handle)),
            json!({ "state": "refreshing", "reason": null, "since": rfc3339(started) })
        );

        let Credential::OAuth(family) = &mut account.credential else {
            panic!("OAuth fixture")
        };
        family.expires_at = now;
        family.last_refresh_attempt_at = Some(attempted);
        family.refresh_not_before = Some(now + Duration::seconds(30));
        assert_eq!(
            health(&account, None),
            json!({
                "state": "refresh_wait",
                "reason": "credential refresh failed transiently",
                "since": rfc3339(attempted),
            })
        );

        account.errored = Some(Errored {
            reason: "operator action required".into(),
            at: now,
        });
        assert_eq!(
            health(&account, Some(started)),
            json!({
                "state": "errored",
                "reason": "operator action required",
                "since": rfc3339(now),
            })
        );
    }
}
