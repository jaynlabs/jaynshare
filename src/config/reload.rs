//! What a candidate changes against the configuration in force —
//! the restart keys that reject it whole and the live keys a successful
//! reload names. Pure; `control::reload` applies the verdict.

use serde_json::Value;

use super::{Config, ListenerTls};

/// Every restart key whose
/// value the candidate changes, in table order.
pub fn changed_restart_keys(current: &Config, candidate: &Config) -> Vec<&'static str> {
    let (c, n) = (current, candidate);
    let certificate = |config: &Config| {
        config
            .data_plane
            .tls
            .files()
            .map(|t| t.certificate_file.clone())
    };
    let private_key = |config: &Config| {
        config
            .data_plane
            .tls
            .files()
            .map(|t| t.private_key_file.clone())
    };
    let rows: [(&'static str, bool); 17] = [
        (
            "data_plane.listen",
            c.data_plane.listen != n.data_plane.listen,
        ),
        // The certificate pair's rows name a change to or from it.
        (
            "data_plane.tls",
            (c.data_plane.tls == ListenerTls::Identity)
                != (n.data_plane.tls == ListenerTls::Identity),
        ),
        (
            "data_plane.tls_certificate_file",
            certificate(c) != certificate(n),
        ),
        (
            "data_plane.tls_private_key_file",
            private_key(c) != private_key(n),
        ),
        (
            "data_plane.upstream_origin",
            c.data_plane.upstream_origin != n.data_plane.upstream_origin,
        ),
        (
            "data_plane.max_connections",
            c.data_plane.max_connections != n.data_plane.max_connections,
        ),
        (
            "data_plane.corporate_proxy_url",
            c.data_plane.corporate_proxy_url != n.data_plane.corporate_proxy_url,
        ),
        (
            "data_plane.no_proxy",
            c.data_plane.no_proxy != n.data_plane.no_proxy,
        ),
        (
            "diagnostics.wire_capture_directory",
            c.diagnostics.wire_capture_directory != n.diagnostics.wire_capture_directory,
        ),
        ("mitm.enabled", c.mitm.enabled != n.mitm.enabled),
        ("mitm.listen", c.mitm.listen != n.mitm.listen),
        (
            "storage.state_file",
            c.storage.state_file != n.storage.state_file,
        ),
        (
            "logging.directory",
            c.logging.directory != n.logging.directory,
        ),
        (
            "logging.max_bytes",
            c.logging.max_bytes != n.logging.max_bytes,
        ),
        (
            "logging.retained_files",
            c.logging.retained_files != n.logging.retained_files,
        ),
        ("audit.max_bytes", c.audit.max_bytes != n.audit.max_bytes),
        (
            "audit.retained_files",
            c.audit.retained_files != n.audit.retained_files,
        ),
    ];
    rows.into_iter()
        .filter_map(|(key, changed)| changed.then_some(key))
        .collect()
}

/// The dotted keys whose effective value the candidate changes, in
/// table order. An array key (`selection.routes`, `data_plane.no_proxy`) is
/// one key. Meaningful once the restart keys are
/// known equal: the secret-bearing proxy URL is presence alone in the
/// effective view.
pub fn changed_keys(current: &Config, candidate: &Config) -> Vec<String> {
    let (current, candidate) = (
        super::effective_view(current),
        super::effective_view(candidate),
    );
    let mut out = Vec::new();
    diff("", &current, &candidate, &mut out);
    out
}

fn diff(prefix: &str, current: &Value, candidate: &Value, out: &mut Vec<String>) {
    match (current, candidate) {
        (Value::Object(current), Value::Object(candidate)) => {
            for (key, value) in current {
                let dotted = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                diff(&dotted, value, &candidate[key], out);
            }
        }
        _ if current != candidate => out.push(prefix.to_string()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn config(extra: &str) -> Config {
        super::super::parse(
            format!("version = 1\n{extra}").as_bytes(),
            Path::new("/etc/jaynshare"),
        )
        .expect("test document")
    }

    #[test]
    fn every_restart_row_is_named_and_live_keys_are_not() {
        let current = config("");
        let candidate = config(
            "[data_plane]\nlisten = \"127.0.0.1:1\"\nmax_connections = 1\nno_proxy = [\"a.example\"]\n\
             corporate_proxy_url = \"http://user:pw@proxy.example:3128\"\n\
             tls_certificate_file = \"c.pem\"\ntls_private_key_file = \"k.pem\"\n\
             upstream_origin = \"http://127.0.0.1:9\"\nfirst_byte_timeout_seconds = 1\n\
             [diagnostics]\nwire_capture_directory = \"cap\"\n\
             [mitm]\nenabled = false\nlisten = \"127.0.0.1:2\"\n\
             [storage]\nstate_file = \"state/s.json\"\n\
             [logging]\ndirectory = \"l\"\nmax_bytes = 65536\nretained_files = 1\nlevel = \"debug\"\n\
             [audit]\nmax_bytes = 65536\nretained_files = 1\n",
        );
        assert_eq!(
            changed_restart_keys(&current, &candidate),
            [
                "data_plane.listen",
                "data_plane.tls_certificate_file",
                "data_plane.tls_private_key_file",
                "data_plane.upstream_origin",
                "data_plane.max_connections",
                "data_plane.corporate_proxy_url",
                "data_plane.no_proxy",
                "diagnostics.wire_capture_directory",
                "mitm.enabled",
                "mitm.listen",
                "storage.state_file",
                "logging.directory",
                "logging.max_bytes",
                "logging.retained_files",
                "audit.max_bytes",
                "audit.retained_files",
            ]
        );
        assert!(changed_restart_keys(&current, &current).is_empty());
        let identity = config("[data_plane]\ntls = \"identity\"\n");
        assert_eq!(
            changed_restart_keys(&current, &identity),
            ["data_plane.tls"]
        );
        assert_eq!(
            changed_restart_keys(&identity, &candidate)[..4],
            [
                "data_plane.listen",
                "data_plane.tls",
                "data_plane.tls_certificate_file",
                "data_plane.tls_private_key_file",
            ]
        );
        let live_only =
            config("[data_plane]\nfirst_byte_timeout_seconds = 1\n[logging]\nlevel = \"debug\"\n");
        assert!(changed_restart_keys(&current, &live_only).is_empty());
    }

    #[test]
    fn changed_keys_are_dotted_leaves_with_arrays_whole() {
        let current = config("[selection]\nblocked_models = [\"*opus*\"]\n");
        let candidate = config(
            "[accounts]\nrefresh_margin_seconds = 120\n\
             [quota]\nprobe_interval_seconds = 30\n\
             [selection]\nswitch_threshold = 0.5\nblocked_models = []\n\
             routes = [{ name = \"h\", patterns = [\"*haiku*\"] }]\n\
             [selection.ramp]\nenabled = false\n\
             [data_plane.egress]\nmode = \"auto\"\n\
             [logging]\nlevel = \"warn\"\n",
        );
        assert_eq!(
            changed_keys(&current, &candidate),
            [
                "accounts.refresh_margin_seconds",
                "quota.probe_interval_seconds",
                "selection.switch_threshold",
                "selection.blocked_models",
                "selection.routes",
                "selection.ramp.enabled",
                "data_plane.egress.mode",
                "logging.level",
            ]
        );
        assert!(changed_keys(&current, &current).is_empty());
        // The same value written differently changes nothing.
        let restated =
            config("[selection]\nblocked_models = [\"*opus*\"]\nswitch_threshold = 0.98\n");
        assert!(changed_keys(&current, &restated).is_empty());
    }
}
