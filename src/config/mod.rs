//! Configuration document: schema, validation and platform paths.
//!
//! The file is parsed to a [`toml::Table`] and then walked by a validator that
//! records every independently detectable error with its dotted key
//! instead of stopping at the first one.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use toml::Table;

pub mod platform;
pub mod references;
pub mod reload;
pub(crate) mod validate;

use validate::Validator;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:17421";
pub const DEFAULT_MITM_PORT: u16 = 17422;

/// `[mitm] listen` when absent: the data plane's address on
/// [`DEFAULT_MITM_PORT`], so moving the data plane moves the proxy with it.
pub fn default_mitm_listen(data_plane: &str) -> String {
    let ip = data_plane
        .parse::<SocketAddr>()
        .map_or(IpAddr::from([127, 0, 0, 1]), |addr| addr.ip());
    SocketAddr::new(ip, DEFAULT_MITM_PORT).to_string()
}
/// A byte limit below this would rotate routine startup bursts away.
const MIN_LOG_BYTES: i64 = 65_536;

#[derive(Debug, Clone, Serialize)]
pub struct Config {
    pub accounts: AccountSettings,
    pub quota: QuotaSettings,
    pub selection: SelectionSettings,
    pub data_plane: DataPlaneSettings,
    pub diagnostics: Diagnostics,
    pub mitm: MitmSettings,
    pub clients: ClientSettings,
    pub storage: StorageSettings,
    pub logging: LoggingSettings,
    pub audit: AuditSettings,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSettings {
    pub refresh_margin_seconds: u64,
    pub refresh_deadline_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuotaSettings {
    pub probe_enabled: bool,
    pub probe_interval_seconds: u64,
    pub probe_deadline_seconds: u64,
    pub revalidation_floor_seconds: u64,
    pub revalidation_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SelectionSettings {
    pub switch_threshold: f64,
    pub distribute_sessions: bool,
    pub blocked_models: Vec<String>,
    pub priorities: Vec<Priority>,
    pub routes: Vec<Route>,
    pub ramp: RampSettings,
}

#[derive(Debug, Clone, Serialize)]
pub struct Priority {
    pub account: String,
    pub value: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub name: String,
    pub patterns: Vec<String>,
    /// `None` is unrestricted; `Some(vec![])` is exclusive and empty.
    pub accounts: Option<Vec<String>>,
    pub bucket: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RampSettings {
    pub enabled: bool,
    pub initial_concurrency: u64,
    pub concurrency_step: u64,
    pub step_interval_ms: u64,
    pub window_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataPlaneSettings {
    pub listen: SocketAddr,
    pub tls: Option<TlsFiles>,
    /// Present only for a loopback harness origin.
    #[serde(serialize_with = "uri_option")]
    pub upstream_origin: Option<http::Uri>,
    pub max_connections: usize,
    pub first_byte_timeout_seconds: u64,
    pub body_idle_timeout_seconds: u64,
    pub throttle_absorb_seconds: u64,
    pub hold_budget_seconds: u64,
    pub telemetry_policy: TelemetryPolicy,
    /// Never serialised; it may carry user information.
    #[serde(skip)]
    pub corporate_proxy_url: Option<http::Uri>,
    pub no_proxy: Vec<String>,
    pub egress: EgressSettings,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsFiles {
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryPolicy {
    Forward,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EgressSettings {
    pub mode: EgressMode,
    pub addresses: Vec<IpAddr>,
    #[serde(serialize_with = "uri")]
    pub check_url: http::Uri,
    pub cache_seconds: u64,
    pub hold_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EgressMode {
    Off,
    Auto,
    AllowList,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostics {
    pub wire_capture_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MitmSettings {
    pub enabled: bool,
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientSettings {
    pub enrollment_lifetime_seconds: u64,
    /// The origins a client reaches when they differ from the listeners'
    /// own addresses, as behind a forwarded port.
    pub advertised_base_url: Option<String>,
    pub advertised_proxy_url: Option<String>,
    /// The base-URL listener's PEM trust anchor, packaged as
    /// `base-url-ca.pem` when the advertised base URL is `https`.
    pub base_url_ca_certificate_file: Option<PathBuf>,
    /// The client kit the server offers its clients to follow.
    pub kit_file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageSettings {
    pub state_file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoggingSettings {
    pub directory: PathBuf,
    pub level: LogLevel,
    pub max_bytes: u64,
    pub retained_files: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditSettings {
    pub max_bytes: u64,
    pub retained_files: u64,
}

fn uri<S: serde::Serializer>(u: &http::Uri, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&u.to_string())
}

fn uri_option<S: serde::Serializer>(u: &Option<http::Uri>, s: S) -> Result<S::Ok, S::Error> {
    match u {
        Some(u) => s.serialize_some(&u.to_string()),
        None => s.serialize_none(),
    }
}

/// One validation error, keyed by the dotted key that caused it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigError {
    pub target: String,
    pub message: String,
}

/// Where the document names an account: the exact dotted
/// key of the literal, kept even when the entry around it is broken, so the
/// state cross-references are reported in the same result as the local
/// errors, under the key the operator wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceSite {
    pub target: String,
    pub literal: String,
    pub site: Site,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Site {
    Route(String),
    Priority,
}

/// A parsed document: the configuration as far as it validated, every local
/// error, and the account references only a pool can judge.
#[derive(Debug)]
pub struct Parsed {
    pub config: Config,
    pub errors: Vec<ConfigError>,
    pub references: Vec<ReferenceSite>,
}

#[derive(Debug)]
pub struct ConfigErrors(pub Vec<ConfigError>);

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{}: {}", e.target, e.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

/// The configuration in force, with the bytes it was read from.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub path: PathBuf,
    pub digest: String,
    pub config: Config,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// How the configuration path was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Selected {
    Flag,
    Variable,
    PlatformDefault,
}

/// `--config` wins over `JAYNSHARE_CONFIG`, which wins over the platform default.
pub fn config_path(flag: Option<&Path>) -> PathBuf {
    config_selection(flag).0
}

/// The path and how it was selected. A relative flag or variable value is
/// resolved from the process's initial working directory once, here, so
/// the paths inside the file and every message name one place.
pub fn config_selection(flag: Option<&Path>) -> (PathBuf, Selected) {
    if let Some(p) = flag {
        return (absolute(p), Selected::Flag);
    }
    if let Some(p) = std::env::var_os("JAYNSHARE_CONFIG").filter(|v| !v.is_empty()) {
        return (absolute(Path::new(&p)), Selected::Variable);
    }
    (platform::config_file(), Selected::PlatformDefault)
}

/// A relative configuration path is resolved from the process's
/// initial working directory. Every file argument a verb takes goes through
/// here before `base_dir` derives the directory its inner paths resolve
/// from, so a bare file name never yields an empty base directory.
pub fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| p.to_path_buf(), |cwd| cwd.join(p))
    }
}

/// Loading's first operation: the bytes, or the path and the failure.
pub fn read(path: &Path) -> Result<Vec<u8>, ConfigErrors> {
    std::fs::read(path).map_err(|e| {
        single(
            "configuration",
            format!("cannot read {}: {e}", path.display()),
        )
    })
}

pub fn load(path: &Path) -> Result<LoadedConfig, ConfigErrors> {
    let bytes = read(path)?;
    let config = parse(&bytes, base_dir(path))?;
    Ok(LoadedConfig {
        path: path.to_path_buf(),
        digest: sha256_hex(&bytes),
        config,
    })
}

/// The directory a document's relative paths resolve from.
pub fn base_dir(path: &Path) -> &Path {
    path.parent().unwrap_or(Path::new("."))
}

/// Parse and validate a document; relative paths resolve against `base_dir`.
pub fn parse(bytes: &[u8], base_dir: &Path) -> Result<Config, ConfigErrors> {
    let parsed = parse_document(bytes, base_dir)?;
    if parsed.errors.is_empty() {
        Ok(parsed.config)
    } else {
        Err(ConfigErrors(parsed.errors))
    }
}

/// The lenient form: a document that is UTF-8 TOML with keys is walked to
/// the end so every local error is reported at once, and the
/// reference sites come back for the caller holding a pool. `Err` is the
/// document itself being unreadable as TOML.
pub fn parse_document(bytes: &[u8], base_dir: &Path) -> Result<Parsed, ConfigErrors> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| single("configuration", format!("not UTF-8: {e}")))?;
    if text.trim().is_empty() {
        return Err(single("configuration", "empty document".into()));
    }
    let table: Table = text
        .parse()
        .map_err(|e: toml::de::Error| single("configuration", syntax_message(text, &e)))?;
    // A bare file name has an empty parent; resolving inner paths
    // from it would leave them relative, and the containment check then
    // sees an empty state directory that every path sits inside.
    let base_dir = &absolute(base_dir);
    let mut v = Validator {
        errors: Vec::new(),
        references: Vec::new(),
        base_dir,
    };
    let config = v.document(&table);
    Ok(Parsed {
        config,
        errors: v.errors,
        references: v.references,
    })
}

/// The document with every default applied under its
/// own key names, the two secret-bearing keys reduced to presence (and the
/// path for the private key), never the proxy URL's user information.
pub fn effective_view(config: &Config) -> serde_json::Value {
    use serde_json::json;
    let path = |p: &Path| p.display().to_string();
    let d = &config.data_plane;
    json!({
        "version": 1,
        "accounts": config.accounts,
        "quota": config.quota,
        "selection": config.selection,
        "data_plane": {
            "listen": d.listen.to_string(),
            "tls_certificate_file": d.tls.as_ref().map(|t| path(&t.certificate_file)),
            "tls_private_key_file": { "set": d.tls.is_some(), "path": d.tls.as_ref().map(|t| path(&t.private_key_file)) },
            "upstream_origin": d.upstream_origin.as_ref().map(ToString::to_string),
            "max_connections": d.max_connections,
            "first_byte_timeout_seconds": d.first_byte_timeout_seconds,
            "body_idle_timeout_seconds": d.body_idle_timeout_seconds,
            "throttle_absorb_seconds": d.throttle_absorb_seconds,
            "hold_budget_seconds": d.hold_budget_seconds,
            "telemetry_policy": d.telemetry_policy,
            "corporate_proxy_url": { "set": d.corporate_proxy_url.is_some(), "path": null },
            "no_proxy": d.no_proxy,
            "egress": d.egress,
        },
        "diagnostics": { "wire_capture_directory": config.diagnostics.wire_capture_directory.as_deref().map(path) },
        "mitm": config.mitm,
        "clients": config.clients,
        "storage": { "state_file": path(&config.storage.state_file) },
        "logging": {
            "directory": path(&config.logging.directory),
            "level": config.logging.level,
            "max_bytes": config.logging.max_bytes,
            "retained_files": config.logging.retained_files,
        },
        "audit": config.audit,
    })
}

/// A syntax error names its line and column and, when the span is
/// a bare key or table header, the key itself — never a value, which could
/// be a proxy password.
fn syntax_message(text: &str, e: &toml::de::Error) -> String {
    let Some(span) = e.span() else {
        return e.message().to_string();
    };
    let start = span.start.min(text.len());
    let line = text[..start].matches('\n').count() + 1;
    let column = start - text[..start].rfind('\n').map_or(0, |i| i + 1) + 1;
    let excerpt = text.get(span.start..span.end.min(text.len())).unwrap_or("");
    let key_like = !excerpt.is_empty()
        && excerpt.len() <= 64
        && excerpt
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '[' | ']' | '"'));
    if key_like {
        format!("{} at line {line}, column {column}: {excerpt}", e.message())
    } else {
        format!("{} at line {line}, column {column}", e.message())
    }
}

fn single(target: &str, message: String) -> ConfigErrors {
    ConfigErrors(vec![ConfigError {
        target: target.into(),
        message,
    }])
}

#[cfg(test)]
mod tests {
    use super::validate::is_no_proxy_entry;
    use super::*;

    fn parse_str(s: &str) -> Result<Config, ConfigErrors> {
        parse(s.as_bytes(), Path::new("/etc/jaynshare"))
    }

    /// `config validate candidate.toml` — a bare file name — once left every
    /// inner path relative, so the state directory normalised to nothing and
    /// the containment check refused any capture directory.
    #[test]
    fn a_bare_file_name_resolves_inner_paths_from_the_working_directory() {
        let doc = "version = 1\n[storage]\nstate_file = \"./state-custom.json\"\n[diagnostics]\nwire_capture_directory = \"../capture-custom\"\n";
        let c = parse(doc.as_bytes(), Path::new("")).expect("a sibling capture directory is valid");
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(c.storage.state_file, cwd.join("./state-custom.json"));
        assert_eq!(
            c.diagnostics.wire_capture_directory.as_deref(),
            Some(cwd.join("../capture-custom").as_path())
        );
        assert_eq!(
            absolute(Path::new("/etc/jaynshare")),
            PathBuf::from("/etc/jaynshare")
        );
        assert_eq!(absolute(Path::new("x.toml")), cwd.join("x.toml"));
    }

    #[test]
    fn minimal_document_takes_every_default() {
        let c = parse_str("version = 1\n").unwrap();
        assert_eq!(c.data_plane.listen.to_string(), DEFAULT_LISTEN);
        assert_eq!(c.data_plane.first_byte_timeout_seconds, 120);
        assert_eq!(c.selection.switch_threshold, 0.98);
        assert_eq!(c.data_plane.telemetry_policy, TelemetryPolicy::Forward);
        assert!(c.data_plane.upstream_origin.is_none());
        assert_eq!(c.audit.retained_files, 7);
        assert!(c.mitm.enabled);
        assert_eq!(c.mitm.listen.to_string(), "127.0.0.1:17422");
    }

    #[test]
    fn the_proxy_listener_defaults_to_the_data_plane_address() {
        let c = parse_str("version = 1\n[data_plane]\nlisten = \"100.64.0.7:9000\"\n").unwrap();
        assert_eq!(c.mitm.listen.to_string(), "100.64.0.7:17422");
    }

    #[test]
    fn an_explicit_proxy_listener_wins_over_the_data_plane_address() {
        let doc = "version = 1\n[data_plane]\nlisten = \"100.64.0.7:9000\"\n[mitm]\nlisten = \"127.0.0.1:9001\"\n";
        assert_eq!(
            parse_str(doc).unwrap().mitm.listen.to_string(),
            "127.0.0.1:9001"
        );
    }

    #[test]
    fn every_error_is_reported_at_once_with_its_dotted_key() {
        let doc = r#"
version = 1
[bogus]
x = 1
[data_plane]
listen = "localhost:17421"
first_byte_timeout_seconds = "120"
upstream_origin = "https://api.example.com"
[selection]
switch_threshold = inf
[logging]
max_bytes = 1024
"#;
        let errs = parse_str(doc).unwrap_err().0;
        let targets: Vec<&str> = errs.iter().map(|e| e.target.as_str()).collect();
        assert_eq!(
            targets,
            [
                "bogus",
                "selection.switch_threshold",
                "data_plane.listen",
                "data_plane.upstream_origin",
                "data_plane.first_byte_timeout_seconds",
                "logging.max_bytes",
            ]
        );
    }

    #[test]
    fn version_must_be_one_and_document_must_not_be_empty() {
        assert_eq!(parse_str("").unwrap_err().0[0].target, "configuration");
        assert_eq!(
            parse_str("version = 2\n").unwrap_err().0[0].target,
            "version"
        );
        assert_eq!(
            parse_str("[data_plane]\n").unwrap_err().0[0].target,
            "version"
        );
    }

    #[test]
    fn duplicate_keys_are_a_syntax_error_naming_the_key() {
        let e = parse_str("version = 1\nversion = 1\n").unwrap_err();
        assert!(
            e.0[0].message.contains("duplicate key"),
            "{}",
            e.0[0].message
        );
        assert!(e.0[0].message.contains("line 2"), "{}", e.0[0].message);
        let e = parse_str("version = 1\n[logging]\n[logging]\n").unwrap_err();
        assert!(e.0[0].message.contains("logging"), "{}", e.0[0].message);
        // A broken value is located, never quoted.
        let e = parse_str("version = 1\n[data_plane]\nproxy_url = \"http://u:secretpw@h\n")
            .unwrap_err();
        assert!(!e.0[0].message.contains("secretpw"), "{}", e.0[0].message);
    }

    #[test]
    fn loopback_upstream_override_is_accepted_and_announced() {
        for origin in ["http://127.0.0.1:9", "http://127.0.0.1:9/"] {
            let document = format!("version = 1\n[data_plane]\nupstream_origin = \"{origin}\"\n");
            let config = parse_str(&document).unwrap();
            assert_eq!(
                config.data_plane.upstream_origin.unwrap().to_string(),
                "http://127.0.0.1:9/"
            );
        }
        let e =
            parse_str("version = 1\n[data_plane]\nupstream_origin = \"http://127.0.0.1:9/v1\"\n")
                .unwrap_err();
        assert_eq!(e.0[0].target, "data_plane.upstream_origin");
    }

    #[test]
    fn relative_paths_resolve_against_the_config_directory_without_expansion() {
        let c = parse_str("version = 1\n[storage]\nstate_file = \"~/state.json\"\n").unwrap();
        assert_eq!(
            c.storage.state_file,
            PathBuf::from("/etc/jaynshare/~/state.json")
        );
    }

    #[test]
    fn capture_directory_may_not_contain_the_log_directory() {
        let doc = "version = 1\n[logging]\ndirectory = \"cap/log\"\n[diagnostics]\nwire_capture_directory = \"cap\"\n";
        let e = parse_str(doc).unwrap_err();
        assert_eq!(e.0[0].target, "diagnostics.wire_capture_directory");
    }

    #[test]
    fn tls_needs_both_files() {
        let e =
            parse_str("version = 1\n[data_plane]\ntls_certificate_file = \"c.pem\"\n").unwrap_err();
        assert_eq!(e.0[0].target, "data_plane.tls_private_key_file");
    }

    #[test]
    fn routes_and_priorities_validate_shape_and_duplicates() {
        let doc = r#"
version = 1
[[selection.routes]]
name = "a"
patterns = ["*haiku*"]
[[selection.routes]]
name = "A"
patterns = []
bucket = "nope"
[[selection.priorities]]
account = "x"
value = 1
[[selection.priorities]]
account = "x"
value = "2"
"#;
        let errs = parse_str(doc).unwrap_err().0;
        let targets: Vec<&str> = errs.iter().map(|e| e.target.as_str()).collect();
        assert_eq!(
            targets,
            [
                "selection.priorities[1].value",
                "selection.routes[1].patterns",
                "selection.routes[1].bucket",
                "selection.routes[1].name",
            ]
        );
    }

    /// `…@127.0.0.1:70000` once passed validation and
    /// would have tunnelled through port 80; the user information never
    /// reaches the message.
    #[test]
    fn a_proxy_url_needs_a_port_a_u16_can_hold() {
        for url in [
            "http://user:password@127.0.0.1:70000",
            "http://proxy.example:0x50",
            "ftp://proxy.example:3128",
            "http:///nohost",
        ] {
            let doc = format!("version = 1\n[data_plane]\ncorporate_proxy_url = \"{url}\"\n");
            let e = parse_str(&doc).unwrap_err();
            assert_eq!(e.0.len(), 1, "{url}");
            assert_eq!(e.0[0].target, "data_plane.corporate_proxy_url", "{url}");
            assert!(!e.0[0].message.contains("password"), "{url}");
        }
        for url in [
            "http://user:password@127.0.0.1:3128",
            "https://proxy.example",
            "http://[::1]:8080",
        ] {
            let doc = format!("version = 1\n[data_plane]\ncorporate_proxy_url = \"{url}\"\n");
            assert!(parse_str(&doc).is_ok(), "{url}");
        }
        // The same text-versus-u16 gap for the two other URL keys.
        let e =
            parse_str("version = 1\n[data_plane]\nupstream_origin = \"http://127.0.0.1:70000\"\n")
                .unwrap_err();
        assert_eq!(e.0[0].target, "data_plane.upstream_origin");
        let e = parse_str(
            "version = 1\n[data_plane.egress]\ncheck_url = \"http://127.0.0.1:70000/ip\"\n",
        )
        .unwrap_err();
        assert_eq!(e.0[0].target, "data_plane.egress.check_url");
        assert!(
            parse_str("version = 1\n[data_plane]\nupstream_origin = \"http://[::1]:18500\"\n")
                .is_ok()
        );
    }

    #[test]
    fn no_proxy_entries_are_names_or_suffixes() {
        assert!(is_no_proxy_entry("example.com"));
        assert!(is_no_proxy_entry(".corp.example."));
        assert!(!is_no_proxy_entry("10.0.0.1"));
        assert!(!is_no_proxy_entry("*"));
        assert!(!is_no_proxy_entry(""));
    }
}
