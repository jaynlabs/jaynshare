//! The validator: every independently detectable error with its
//! dotted key.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use toml::{Table, Value};

use super::platform;
use super::{
    AccountSettings, AuditSettings, ClientSettings, Config, ConfigError, DEFAULT_LISTEN,
    DataPlaneSettings, Diagnostics, EgressMode, EgressSettings, ListenerTls, LogLevel,
    LoggingSettings, MIN_LOG_BYTES, MitmSettings, Priority, QuotaSettings, RampSettings,
    ReferenceSite, Route, SelectionSettings, Site, StorageSettings, TelemetryPolicy, TlsFiles,
};

pub(crate) struct Validator<'a> {
    pub(crate) errors: Vec<ConfigError>,
    /// Every account literal under its exact dotted key (`ReferenceSite`).
    pub(crate) references: Vec<ReferenceSite>,
    pub(crate) base_dir: &'a Path,
}

/// A table under validation: the value and its dotted prefix.
struct Node<'t> {
    table: &'t Table,
    prefix: String,
}

impl Node<'_> {
    fn key(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}.{name}", self.prefix)
        }
    }
}

static EMPTY: std::sync::LazyLock<Table> = std::sync::LazyLock::new(Table::new);

impl Validator<'_> {
    fn error(&mut self, target: impl Into<String>, message: impl Into<String>) {
        self.errors.push(ConfigError {
            target: target.into(),
            message: message.into(),
        });
    }

    pub(crate) fn document(&mut self, root: &Table) -> Config {
        let root_node = Node {
            table: root,
            prefix: String::new(),
        };
        self.known_keys(
            &root_node,
            &[
                "version",
                "accounts",
                "quota",
                "selection",
                "data_plane",
                "diagnostics",
                "mitm",
                "clients",
                "storage",
                "logging",
                "audit",
            ],
        );
        match root.get("version") {
            Some(Value::Integer(1)) => {}
            Some(_) => self.error("version", "must be the integer 1"),
            None => self.error("version", "required; must be the integer 1"),
        }
        let accounts_node = self.table(&root_node, "accounts");
        let accounts = self.accounts(&accounts_node);
        let quota_node = self.table(&root_node, "quota");
        let quota = self.quota(&quota_node);
        let selection_node = self.table(&root_node, "selection");
        let selection = self.selection(&selection_node);
        let data_plane_node = self.table(&root_node, "data_plane");
        let data_plane = self.data_plane(&data_plane_node);
        let diagnostics_node = self.table(&root_node, "diagnostics");
        let diagnostics = self.diagnostics(&diagnostics_node);
        let mitm_node = self.table(&root_node, "mitm");
        let mitm = self.mitm(&mitm_node, data_plane.listen);
        let clients_node = self.table(&root_node, "clients");
        let clients = self.clients(&clients_node);
        let storage_node = self.table(&root_node, "storage");
        let storage = self.storage(&storage_node);
        let logging_node = self.table(&root_node, "logging");
        let logging = self.logging(&logging_node);
        let audit_node = self.table(&root_node, "audit");
        let audit = self.audit(&audit_node);
        self.cross_checks(&storage, &logging, &diagnostics);
        Config {
            accounts,
            quota,
            selection,
            data_plane,
            diagnostics,
            mitm,
            clients,
            storage,
            logging,
            audit,
        }
    }

    fn known_keys(&mut self, node: &Node<'_>, known: &[&str]) {
        for key in node.table.keys() {
            if !known.contains(&key.as_str()) {
                self.error(node.key(key), "unknown key");
            }
        }
    }

    fn table<'t>(&mut self, parent: &Node<'t>, name: &str) -> Node<'t> {
        let key = parent.key(name);
        let table = match parent.table.get(name) {
            None => &EMPTY,
            Some(Value::Table(t)) => t,
            Some(_) => {
                self.error(&key, "must be a table");
                &EMPTY
            }
        };
        Node { table, prefix: key }
    }

    fn integer(&mut self, node: &Node<'_>, name: &str, default: i64, min: i64, max: i64) -> i64 {
        let key = node.key(name);
        match node.table.get(name) {
            None => default,
            Some(Value::Integer(n)) if (min..=max).contains(n) => *n,
            Some(Value::Integer(_)) => {
                self.error(key, format!("must be between {min} and {max}"));
                default
            }
            Some(_) => {
                self.error(key, "must be an integer");
                default
            }
        }
    }

    fn unsigned(&mut self, node: &Node<'_>, name: &str, default: u64, min: u64, max: u64) -> u64 {
        let n = self.integer(
            node,
            name,
            i64::try_from(default).unwrap_or(i64::MAX),
            i64::try_from(min).unwrap_or(i64::MAX),
            i64::try_from(max).unwrap_or(i64::MAX),
        );
        u64::try_from(n).unwrap_or(default)
    }

    fn boolean(&mut self, node: &Node<'_>, name: &str, default: bool) -> bool {
        match node.table.get(name) {
            None => default,
            Some(Value::Boolean(b)) => *b,
            Some(_) => {
                self.error(node.key(name), "must be a boolean");
                default
            }
        }
    }

    fn string(&mut self, node: &Node<'_>, name: &str) -> Option<String> {
        match node.table.get(name) {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                self.error(node.key(name), "must be a string");
                None
            }
        }
    }

    fn string_array(&mut self, node: &Node<'_>, name: &str) -> Option<Vec<String>> {
        let key = node.key(name);
        let items = match node.table.get(name) {
            None => return None,
            Some(Value::Array(items)) => items,
            Some(_) => {
                self.error(key, "must be an array of strings");
                return None;
            }
        };
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            match item {
                Value::String(s) if !s.is_empty() => out.push(s.clone()),
                Value::String(_) => self.error(format!("{key}[{i}]"), "must not be empty"),
                _ => self.error(format!("{key}[{i}]"), "must be a string"),
            }
        }
        Some(out)
    }

    fn enum_string<'k>(
        &mut self,
        node: &Node<'_>,
        name: &str,
        allowed: &[&'k str],
    ) -> Option<&'k str> {
        let value = self.string(node, name)?;
        match allowed.iter().find(|a| **a == value) {
            Some(a) => Some(a),
            None => {
                self.error(
                    node.key(name),
                    format!("must be one of {}", allowed.join(", ")),
                );
                None
            }
        }
    }

    /// Relative to the configuration directory, no expansion of any kind.
    fn path(&mut self, node: &Node<'_>, name: &str) -> Option<PathBuf> {
        let s = self.string(node, name)?;
        if s.is_empty() {
            self.error(node.key(name), "must not be empty");
            return None;
        }
        Some(self.base_dir.join(s))
    }

    /// One numeric IP address plus a non-zero port.
    fn listen(&mut self, node: &Node<'_>, name: &str, default: &str) -> SocketAddr {
        let fallback: SocketAddr = default.parse().expect("default listener is valid");
        let Some(s) = self.string(node, name) else {
            return fallback;
        };
        match s.parse::<SocketAddr>() {
            Ok(addr) if addr.port() != 0 => addr,
            _ => {
                self.error(
                    node.key(name),
                    "must be a numeric IP address and a port in 1…65535 (IPv6 in brackets)",
                );
                fallback
            }
        }
    }

    fn accounts(&mut self, node: &Node<'_>) -> AccountSettings {
        self.known_keys(
            node,
            &["refresh_margin_seconds", "refresh_deadline_seconds"],
        );
        AccountSettings {
            refresh_margin_seconds: self.unsigned(node, "refresh_margin_seconds", 300, 60, 1800),
            refresh_deadline_seconds: self.unsigned(node, "refresh_deadline_seconds", 30, 5, 120),
        }
    }

    fn quota(&mut self, node: &Node<'_>) -> QuotaSettings {
        self.known_keys(
            node,
            &[
                "probe_enabled",
                "probe_interval_seconds",
                "probe_deadline_seconds",
                "revalidation_floor_seconds",
                "revalidation_interval_seconds",
            ],
        );
        QuotaSettings {
            probe_enabled: self.boolean(node, "probe_enabled", false),
            probe_interval_seconds: self.unsigned(
                node,
                "probe_interval_seconds",
                300,
                30,
                u64::MAX,
            ),
            probe_deadline_seconds: self.unsigned(node, "probe_deadline_seconds", 10, 1, u64::MAX),
            revalidation_floor_seconds: self.unsigned(
                node,
                "revalidation_floor_seconds",
                60,
                1,
                u64::MAX,
            ),
            revalidation_interval_seconds: self.unsigned(
                node,
                "revalidation_interval_seconds",
                60,
                1,
                u64::MAX,
            ),
        }
    }

    fn selection(&mut self, node: &Node<'_>) -> SelectionSettings {
        self.known_keys(
            node,
            &[
                "switch_threshold",
                "distribute_sessions",
                "blocked_models",
                "priorities",
                "routes",
                "ramp",
            ],
        );
        let switch_threshold = match node.table.get("switch_threshold") {
            None => 0.98,
            Some(Value::Float(f)) if f.is_finite() && *f > 0.0 && *f <= 1.0 => *f,
            Some(_) => {
                self.error(
                    node.key("switch_threshold"),
                    "must be a finite number with 0 < value <= 1",
                );
                0.98
            }
        };
        let priorities = self.priorities(node);
        let routes = self.routes(node);
        let ramp_node = self.table(node, "ramp");
        self.known_keys(
            &ramp_node,
            &[
                "enabled",
                "initial_concurrency",
                "concurrency_step",
                "step_interval_ms",
                "window_seconds",
            ],
        );
        let ramp = RampSettings {
            enabled: self.boolean(&ramp_node, "enabled", true),
            initial_concurrency: self.unsigned(&ramp_node, "initial_concurrency", 1, 1, u64::MAX),
            concurrency_step: self.unsigned(&ramp_node, "concurrency_step", 1, 1, u64::MAX),
            step_interval_ms: self.unsigned(&ramp_node, "step_interval_ms", 250, 1, u64::MAX),
            window_seconds: self.unsigned(&ramp_node, "window_seconds", 30, 1, u64::MAX),
        };
        SelectionSettings {
            switch_threshold,
            distribute_sessions: self.boolean(node, "distribute_sessions", false),
            blocked_models: self
                .string_array(node, "blocked_models")
                .unwrap_or_default(),
            priorities,
            routes,
            ramp,
        }
    }

    fn table_array<'t>(&mut self, node: &Node<'t>, name: &str) -> Vec<Node<'t>> {
        let key = node.key(name);
        let items = match node.table.get(name) {
            None => return Vec::new(),
            Some(Value::Array(items)) => items,
            Some(_) => {
                self.error(key, "must be an array of tables");
                return Vec::new();
            }
        };
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            match item {
                Value::Table(t) => out.push(Node {
                    table: t,
                    prefix: format!("{key}[{i}]"),
                }),
                _ => self.error(format!("{key}[{i}]"), "must be a table"),
            }
        }
        out
    }

    /// Exactly `account` and `value`; duplicates are rejected here by
    /// literal reference, and by resolved account at start against state.
    fn priorities(&mut self, node: &Node<'_>) -> Vec<Priority> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for entry in self.table_array(node, "priorities") {
            self.known_keys(&entry, &["account", "value"]);
            let account = self.required_string(&entry, "account");
            if let Some(literal) = &account {
                self.references.push(ReferenceSite {
                    target: entry.key("account"),
                    literal: literal.clone(),
                    site: Site::Priority,
                });
            }
            let value = match entry.table.get("value") {
                Some(Value::Integer(n)) => Some(*n),
                Some(_) => {
                    self.error(entry.key("value"), "must be an integer");
                    None
                }
                None => {
                    self.error(entry.key("value"), "required");
                    None
                }
            };
            if let (Some(account), Some(value)) = (account, value) {
                if !seen.insert(account.clone()) {
                    self.error(entry.key("account"), "duplicate priority entry");
                }
                out.push(Priority { account, value });
            }
        }
        out
    }

    fn required_string(&mut self, node: &Node<'_>, name: &str) -> Option<String> {
        match self.string(node, name) {
            Some(s) if s.is_empty() => {
                self.error(node.key(name), "must not be empty");
                None
            }
            Some(s) => Some(s),
            None => {
                if !node.table.contains_key(name) {
                    self.error(node.key(name), "required");
                }
                None
            }
        }
    }

    /// `name` and non-empty `patterns` required; `accounts` and `bucket` optional.
    fn routes(&mut self, node: &Node<'_>) -> Vec<Route> {
        let mut folded_names = BTreeSet::new();
        let mut out = Vec::new();
        for entry in self.table_array(node, "routes") {
            self.known_keys(&entry, &["name", "patterns", "accounts", "bucket"]);
            let name = self.required_string(&entry, "name");
            let patterns = self.string_array(&entry, "patterns");
            match &patterns {
                None if !entry.table.contains_key("patterns") => {
                    self.error(entry.key("patterns"), "required")
                }
                Some(p) if p.is_empty() => self.error(entry.key("patterns"), "must not be empty"),
                _ => {}
            }
            let accounts = self.string_array(&entry, "accounts");
            // The sites keep the file's own indexes: a broken sibling entry
            // is reported under its key, not by shifting this one.
            if let Some(Value::Array(items)) = entry.table.get("accounts") {
                let route = name.clone().unwrap_or_else(|| entry.prefix.clone());
                for (j, item) in items.iter().enumerate() {
                    if let Value::String(literal) = item
                        && !literal.is_empty()
                    {
                        self.references.push(ReferenceSite {
                            target: format!("{}[{j}]", entry.key("accounts")),
                            literal: literal.clone(),
                            site: Site::Route(route.clone()),
                        });
                    }
                }
            }
            let bucket = self.string(&entry, "bucket");
            if let Some(b) = &bucket
                && !crate::pool::quota::is_bucket_name(b)
            {
                self.error(entry.key("bucket"), "not a known bucket name");
            }
            if let (Some(name), Some(patterns)) = (name, patterns) {
                if !folded_names.insert(name.to_lowercase()) {
                    self.error(entry.key("name"), "duplicate route name");
                }
                out.push(Route {
                    name,
                    patterns,
                    accounts,
                    bucket,
                });
            }
        }
        out
    }

    fn data_plane(&mut self, node: &Node<'_>) -> DataPlaneSettings {
        self.known_keys(
            node,
            &[
                "listen",
                "tls",
                "tls_certificate_file",
                "tls_private_key_file",
                "upstream_origin",
                "max_connections",
                "first_byte_timeout_seconds",
                "body_idle_timeout_seconds",
                "throttle_absorb_seconds",
                "hold_budget_seconds",
                "telemetry_policy",
                "corporate_proxy_url",
                "no_proxy",
                "egress",
            ],
        );
        let listen = self.listen(node, "listen", DEFAULT_LISTEN);
        let tls = self.listener_tls(node);
        let upstream_origin = self.upstream_origin(node);
        let corporate_proxy_url = self.proxy_url(node);
        let no_proxy = self.string_array(node, "no_proxy").unwrap_or_default();
        for (i, entry) in no_proxy.iter().enumerate() {
            if !is_no_proxy_entry(entry) {
                self.error(
                    format!("{}[{i}]", node.key("no_proxy")),
                    "must be an exact DNS name or a leading-dot suffix; IP literals and * are rejected",
                );
            }
        }
        let telemetry_policy =
            match self.enum_string(node, "telemetry_policy", &["forward", "block"]) {
                Some("block") => TelemetryPolicy::Block,
                _ => TelemetryPolicy::Forward,
            };
        let egress_node = self.table(node, "egress");
        let egress = self.egress(&egress_node);
        DataPlaneSettings {
            listen,
            tls,
            upstream_origin,
            max_connections: usize::try_from(self.unsigned(
                node,
                "max_connections",
                256,
                1,
                u64::MAX,
            ))
            .unwrap_or(256),
            first_byte_timeout_seconds: self.unsigned(
                node,
                "first_byte_timeout_seconds",
                120,
                1,
                u64::MAX,
            ),
            body_idle_timeout_seconds: self.unsigned(
                node,
                "body_idle_timeout_seconds",
                120,
                1,
                u64::MAX,
            ),
            throttle_absorb_seconds: self.unsigned(node, "throttle_absorb_seconds", 60, 0, 300),
            hold_budget_seconds: self.unsigned(node, "hold_budget_seconds", 0, 0, u64::MAX),
            telemetry_policy,
            corporate_proxy_url,
            no_proxy,
            egress,
        }
    }

    /// `tls` and the certificate pair; absent, the mode follows the pair.
    fn listener_tls(&mut self, node: &Node<'_>) -> ListenerTls {
        let mode = self.enum_string(node, "tls", &["off", "identity", "certificate"]);
        let cert = self.path(node, "tls_certificate_file");
        let key = self.path(node, "tls_private_key_file");
        let pair_named = cert.is_some() || key.is_some();
        let files = match (cert, key) {
            (Some(certificate_file), Some(private_key_file)) => Some(TlsFiles {
                certificate_file,
                private_key_file,
            }),
            (None, None) => None,
            (Some(_), None) => {
                self.error(
                    node.key("tls_private_key_file"),
                    "required when tls_certificate_file is set",
                );
                None
            }
            (None, Some(_)) => {
                self.error(
                    node.key("tls_certificate_file"),
                    "required when tls_private_key_file is set",
                );
                None
            }
        };
        match mode {
            Some("off" | "identity") if pair_named => {
                self.error(
                    node.key("tls"),
                    "must be \"certificate\" when tls_certificate_file or tls_private_key_file is set",
                );
                ListenerTls::Off
            }
            Some("identity") => ListenerTls::Identity,
            Some("certificate") if !pair_named => {
                self.error(
                    node.key("tls"),
                    "\"certificate\" needs tls_certificate_file and tls_private_key_file",
                );
                ListenerTls::Off
            }
            _ => files.map_or(ListenerTls::Off, ListenerTls::Certificate),
        }
    }

    /// An `http` or `https` origin whose host is loopback, nothing else.
    fn upstream_origin(&mut self, node: &Node<'_>) -> Option<http::Uri> {
        let key = node.key("upstream_origin");
        let s = self.string(node, "upstream_origin")?;
        let Ok(uri) = s.parse::<http::Uri>() else {
            self.error(key, "must be an http or https origin");
            return None;
        };
        let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
        let bare = uri.path() == "/" && uri.query().is_none();
        let host_ok = uri.host().is_some_and(is_loopback_host);
        let no_userinfo = uri.authority().is_none_or(|a| !a.as_str().contains('@'));
        let port_ok =
            uri.port_u16().is_some() || !declares_port(uri.authority().map_or("", |a| a.as_str()));
        if !(scheme_ok && bare && no_userinfo && port_ok) {
            self.error(
                key,
                "must be an http or https origin with a valid port and no user information, path, query or fragment",
            );
            return None;
        }
        if !host_ok {
            self.error(
                key,
                "only a loopback origin may override the Anthropic API origin",
            );
            return None;
        }
        Some(uri)
    }

    /// The origin a forwarded listener advertises —
    /// host and port required, unlike `upstream_origin`'s loopback rule.
    fn advertised_origin(&mut self, node: &Node<'_>, name: &str) -> Option<String> {
        let s = self.string(node, name)?;
        let Ok(uri) = s.parse::<http::Uri>() else {
            self.error(node.key(name), "must be an http or https origin with a host, a port and no user information, path, query or fragment");
            return None;
        };
        let ok = matches!(uri.scheme_str(), Some("http" | "https"))
            && uri.host().is_some()
            && uri.port_u16().is_some()
            && (uri.path() == "/" || uri.path().is_empty())
            && uri.query().is_none()
            && uri.authority().is_none_or(|a| !a.as_str().contains('@'));
        if !ok {
            self.error(node.key(name), "must be an http or https origin with a host, a port and no user information, path, query or fragment");
            return None;
        }
        Some(format!(
            "{}://{}",
            uri.scheme_str().unwrap_or_default(),
            uri.authority()
                .map_or(String::new(), |a| a.as_str().to_string())
        ))
    }

    /// `http` or `https` with host and valid port; user information allowed.
    fn proxy_url(&mut self, node: &Node<'_>) -> Option<http::Uri> {
        let key = node.key("corporate_proxy_url");
        let s = self.string(node, "corporate_proxy_url")?;
        match s.parse::<http::Uri>() {
            // `http::Uri` parses `:70000` but answers `port == None` for it,
            // as for no port at all; the connector would then fall back to 80
            // or 443. The authority text tells the two apart.
            Ok(uri)
                if matches!(uri.scheme_str(), Some("http" | "https"))
                    && uri.host().is_some()
                    && (uri.port_u16().is_some()
                        || !declares_port(uri.authority().map_or("", |a| a.as_str()))) =>
            {
                Some(uri)
            }
            _ => {
                self.error(
                    key,
                    "must be an http or https URL with a host and valid port",
                );
                None
            }
        }
    }

    /// The three egress pin forms.
    fn egress(&mut self, node: &Node<'_>) -> EgressSettings {
        self.known_keys(
            node,
            &[
                "mode",
                "addresses",
                "check_url",
                "cache_seconds",
                "hold_seconds",
            ],
        );
        let mode = match self.enum_string(node, "mode", &["off", "auto", "allow-list"]) {
            Some("auto") => EgressMode::Auto,
            Some("allow-list") => EgressMode::AllowList,
            _ => EgressMode::Off,
        };
        let raw = self.string_array(node, "addresses").unwrap_or_default();
        let mut addresses = Vec::with_capacity(raw.len());
        for (i, a) in raw.iter().enumerate() {
            match a.parse::<IpAddr>() {
                Ok(ip) if !addresses.contains(&ip) => addresses.push(ip),
                Ok(_) => self.error(
                    format!("{}[{i}]", node.key("addresses")),
                    "duplicate address",
                ),
                Err(_) => self.error(
                    format!("{}[{i}]", node.key("addresses")),
                    "must be an IPv4 or IPv6 address",
                ),
            }
        }
        match mode {
            EgressMode::AllowList if addresses.is_empty() => self.error(
                node.key("addresses"),
                "must be non-empty for mode allow-list",
            ),
            EgressMode::Off | EgressMode::Auto if !addresses.is_empty() => self.error(
                node.key("addresses"),
                "must be empty unless mode is allow-list",
            ),
            _ => {}
        }
        let default_check: http::Uri = "https://api.ipify.org".parse().expect("valid default");
        let check_url = match self.string(node, "check_url") {
            None => default_check,
            Some(s) => match s.parse::<http::Uri>() {
                Ok(uri)
                    if matches!(uri.scheme_str(), Some("http" | "https"))
                        && uri.authority().is_some_and(|a| {
                            !a.as_str().contains('@')
                                && (uri.port_u16().is_some() || !declares_port(a.as_str()))
                        }) =>
                {
                    uri
                }
                _ => {
                    self.error(
                        node.key("check_url"),
                        "must be an absolute http or https URL with a valid port and without user information",
                    );
                    default_check
                }
            },
        };
        EgressSettings {
            mode,
            addresses,
            check_url,
            cache_seconds: self.unsigned(node, "cache_seconds", 30, 1, u64::MAX),
            hold_seconds: self.unsigned(node, "hold_seconds", 120, 0, u64::MAX),
        }
    }

    fn diagnostics(&mut self, node: &Node<'_>) -> Diagnostics {
        self.known_keys(node, &["wire_capture_directory"]);
        Diagnostics {
            wire_capture_directory: self.path(node, "wire_capture_directory"),
        }
    }

    fn mitm(&mut self, node: &Node<'_>, data_plane: SocketAddr) -> MitmSettings {
        self.known_keys(node, &["enabled", "listen"]);
        MitmSettings {
            enabled: self.boolean(node, "enabled", true),
            listen: self.listen(
                node,
                "listen",
                &super::default_mitm_listen(&data_plane.to_string()),
            ),
        }
    }

    fn clients(&mut self, node: &Node<'_>) -> ClientSettings {
        self.known_keys(
            node,
            &[
                "enrollment_lifetime_seconds",
                "advertised_base_url",
                "advertised_proxy_url",
                "base_url_ca_certificate_file",
            ],
        );
        ClientSettings {
            enrollment_lifetime_seconds: self.unsigned(
                node,
                "enrollment_lifetime_seconds",
                86_400,
                60,
                604_800,
            ),
            advertised_base_url: self.advertised_origin(node, "advertised_base_url"),
            advertised_proxy_url: self.advertised_origin(node, "advertised_proxy_url"),
            base_url_ca_certificate_file: self.path(node, "base_url_ca_certificate_file"),
        }
    }

    fn storage(&mut self, node: &Node<'_>) -> StorageSettings {
        self.known_keys(node, &["state_file"]);
        StorageSettings {
            state_file: self
                .path(node, "state_file")
                .unwrap_or_else(platform::state_file),
        }
    }

    fn logging(&mut self, node: &Node<'_>) -> LoggingSettings {
        self.known_keys(node, &["directory", "level", "max_bytes", "retained_files"]);
        let level = match self.enum_string(node, "level", &["error", "warn", "info", "debug"]) {
            Some("error") => LogLevel::Error,
            Some("warn") => LogLevel::Warn,
            Some("debug") => LogLevel::Debug,
            _ => LogLevel::Info,
        };
        LoggingSettings {
            directory: self
                .path(node, "directory")
                .unwrap_or_else(platform::log_directory),
            level,
            max_bytes: self.unsigned(
                node,
                "max_bytes",
                10_485_760,
                MIN_LOG_BYTES as u64,
                u64::MAX,
            ),
            retained_files: self.unsigned(node, "retained_files", 5, 1, u64::MAX),
        }
    }

    fn audit(&mut self, node: &Node<'_>) -> AuditSettings {
        self.known_keys(node, &["max_bytes", "retained_files"]);
        AuditSettings {
            max_bytes: self.unsigned(
                node,
                "max_bytes",
                10_485_760,
                MIN_LOG_BYTES as u64,
                u64::MAX,
            ),
            retained_files: self.unsigned(node, "retained_files", 7, 1, u64::MAX),
        }
    }

    /// The capture directory is never the state or log directory nor contains either.
    fn cross_checks(
        &mut self,
        storage: &StorageSettings,
        logging: &LoggingSettings,
        diag: &Diagnostics,
    ) {
        let Some(capture) = &diag.wire_capture_directory else {
            return;
        };
        let state_dir = storage.state_file.parent().unwrap_or(Path::new("/"));
        let capture = normalize(capture);
        for protected in [normalize(state_dir), normalize(&logging.directory)] {
            // Reject either containment direction, and equality: the capture
            // is an ancestor of, a descendant of, or the same as the state or
            // log directory (it must be an explicit isolated directory).
            if protected.starts_with(&capture) || capture.starts_with(&protected) {
                self.error(
                    "diagnostics.wire_capture_directory",
                    "must not be, contain, or sit inside the state or log directory",
                );
                return;
            }
        }
    }
}

/// Whether an authority carries a `:port` after its host (IPv6 literals are
/// bracketed, so a colon inside `[…]` is not a port separator).
fn declares_port(authority: &str) -> bool {
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    match host_port.rsplit_once(':') {
        Some((head, _)) => !head.contains('[') || head.ends_with(']'),
        None => false,
    }
}

pub fn is_loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => bare.eq_ignore_ascii_case("localhost"),
    }
}

/// Exact DNS name or leading-dot suffix; no IP literal, no `*`.
/// Exact DNS name or leading-dot suffix; no IP literal, no `*`.
pub(crate) fn is_no_proxy_entry(entry: &str) -> bool {
    let name = entry.strip_prefix('.').unwrap_or(entry);
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Lexical normalisation only: `.` and `..` components, no filesystem access.
fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}
