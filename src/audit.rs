//! One record per exchange, unconditional.

use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::AuditSettings;
use crate::logfile::RotatingFile;
use crate::pool::selection::Cause;

pub const AUDIT_LOG: &str = "exchanges.ndjson";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    Loopback,
    /// An enrolled client, its id the stable identity.
    Client,
    /// A caller presenting the remote-operator secret.
    Operator,
}

#[derive(Debug, Clone, Serialize)]
pub struct Principal {
    pub kind: PrincipalKind,
    pub id: Option<String>,
}

impl Principal {
    /// The principal half of a session key, stable across exchanges.
    pub fn key(&self) -> String {
        match self.kind {
            PrincipalKind::Loopback => format!("loopback:{}", self.id.as_deref().unwrap_or("")),
            PrincipalKind::Client => format!("client:{}", self.id.as_deref().unwrap_or("")),
            PrincipalKind::Operator => "operator".to_string(),
        }
    }

    /// The role's name for log lines.
    pub fn role(&self) -> &'static str {
        match self.kind {
            PrincipalKind::Loopback => "loopback-operator",
            PrincipalKind::Client => "client",
            PrincipalKind::Operator => "remote-operator",
        }
    }

    pub fn is_operator(&self) -> bool {
        matches!(self.kind, PrincipalKind::Loopback | PrincipalKind::Operator)
    }

    /// The enrolled client's id; `None` for an operator.
    pub fn client_id(&self) -> Option<&str> {
        match self.kind {
            PrincipalKind::Client => self.id.as_deref(),
            PrincipalKind::Loopback | PrincipalKind::Operator => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServingAccount {
    pub display_name: String,
    pub account_uuid: Option<Uuid>,
    pub organization_uuid: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Authentication,
    RateLimit,
    Upstream,
    Request,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    BaseUrl,
    /// The exchange was decoded from an intercepted tunnel.
    Mitm,
}

/// Every record field, always present; unavailable values are `null`.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub duration_ms: u64,
    /// `null` for the one exchange with no principal: the pre-auth refusal,
    /// which is still traced through its record.
    pub principal: Option<Principal>,
    pub source_address: String,
    pub session_id: Option<String>,
    pub method: String,
    pub path: String,
    pub model: Option<String>,
    pub serving_account: Option<ServingAccount>,
    /// An upstream reason such as `refresh_wait`, or null when one served.
    pub no_service_reason: Option<String>,
    pub selection_cause: Option<Cause>,
    pub status: Option<u16>,
    pub attempts: u32,
    pub failed_over: bool,
    pub error_class: Option<ErrorClass>,
    pub pinned: bool,
    pub mode: Mode,
    pub blocked_pattern: Option<String>,
}

pub struct AuditLog {
    inner: Mutex<Inner>,
}

struct Inner {
    file: RotatingFile,
    /// The time of the last successful append, kept under the same
    /// lock as the file so a projection never reads it ahead of the bytes;
    /// a failed append never advances it.
    last_record: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditHealth {
    pub path: String,
    pub last_record: Option<OffsetDateTime>,
    pub active_file_bytes: u64,
    pub retained_files: u64,
}

impl AuditLog {
    pub fn open(path: &Path, settings: &AuditSettings) -> std::io::Result<Self> {
        Ok(Self {
            inner: Mutex::new(Inner {
                file: RotatingFile::open(path, settings.max_bytes, settings.retained_files)?,
                last_record: None,
            }),
        })
    }

    /// If this fails, the caller stops admitting exchanges.
    pub fn append(&self, record: &Record) -> std::io::Result<()> {
        let line = serde_json::to_vec(record)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("audit lock poisoned"))?;
        inner.file.append_line(&line)?;
        inner.last_record = Some(OffsetDateTime::now_utc());
        Ok(())
    }

    pub fn health(&self) -> AuditHealth {
        let inner = self.inner.lock().expect("audit lock");
        AuditHealth {
            path: inner.file.path().display().to_string(),
            last_record: inner.last_record,
            active_file_bytes: inner.file.size(),
            retained_files: inner.file.retained_count(),
        }
    }
}
