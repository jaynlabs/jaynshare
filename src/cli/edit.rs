//! The file-editing pipeline of `config edit` and the file-backed `config`
//! verbs (`paths`, `show --local`, `validate`, `edit --offline`): read the
//! selected file, build the candidate on the operator's own document
//! (comments and order kept), validate it locally against the configuration
//! schema, write it atomically beside the original with mode `0600`, ask the
//! server to reload, and put the previous bytes back when the reload does
//! not apply. `config paths`, `config show --local`, `config validate` and
//! `config edit --offline` never contact a server.

use std::path::{Path, PathBuf};

use http::Method;
use serde_json::{Value, json};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table};

use crate::audit::AUDIT_LOG;
#[cfg(test)]
use crate::config::TelemetryPolicy;
use crate::config::{self, ConfigErrors, Selected};
use crate::pool::fold;
use crate::state;

use super::Failure;
use super::Outcome;
use super::args::{BlockVerb, Cli, ConfigVerb, PriorityVerb, RouteAddArgs, RouteVerb};
use super::control::Control;

/// The file-editing pipeline: `edit` builds the candidate on the
/// operator's document; the result is the server's answer object with the
/// reload's outcome under `reload`.
async fn edit_and_reload(
    control: &Control,
    edit: impl FnOnce(&mut DocumentMut) -> Result<(), Failure>,
) -> Result<Value, Failure> {
    let path = control.config_path()?;
    let (previous, mut document) = read_document(path)?;
    edit(&mut document)?;
    let candidate = document.to_string().into_bytes();
    validate_bytes(&candidate, path)?;
    control.reachable().await?;
    write(path, &candidate)?;
    match control.reload().await {
        Ok(reload) => Ok(json!({
            "path": path.display().to_string(),
            "digest_before": config::sha256_hex(&previous),
            "digest_after": config::sha256_hex(&candidate),
            "reload": reload,
        })),
        Err(failure) => {
            // The file never says what the server refused.
            write(path, &previous)?;
            Err(failure)
        }
    }
}

fn read_document(path: &Path) -> Result<(Vec<u8>, DocumentMut), Failure> {
    let bytes = std::fs::read(path).map_err(|e| {
        Failure::local(
            3,
            "cli_configuration_invalid",
            format!("configuration {}: cannot read: {e}", path.display()),
        )
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|e| {
        Failure::local(
            3,
            "cli_configuration_invalid",
            format!("configuration {}: not UTF-8: {e}", path.display()),
        )
    })?;
    let document = text.parse::<DocumentMut>().map_err(|e| {
        Failure::local(
            3,
            "cli_configuration_invalid",
            format!("configuration {}: {}", path.display(), e.message()),
        )
    })?;
    Ok((bytes, document))
}

/// What `config new` scaffolds — the minimal document, one
/// loopback listener, no pools, every other key left commented at its
/// documented default. The tests below parse it with the same parser,
/// so it cannot drift from the schema.
pub(super) const TEMPLATE: &str = r#"# Jaynshare configuration (version 1).
# `version = 1` alone is already valid; every omitted key takes its
# documented default. Validate any edit with `jaynshare config validate <path>`.

version = 1

[data_plane]
# Loopback until you set the server's private address (a tailnet IP, say),
# with ingress filtered to that network. The client proxy listens on the
# same address, port 17422.
listen = "127.0.0.1:17421"
# TLS on the server's own identity key, which clients pin: no certificate
# to manage, and moving the address never breaks them.
tls = "identity"

# Optional keys with their defaults; uncomment to override.
# [data_plane]
# max_connections = 256
# telemetry_policy = "forward"
# first_byte_timeout_seconds = 120
# [selection]
# switch_threshold = 0.98
# [quota]
# probe_enabled = false
# [logging]
# level = "info"
# max_bytes = 10485760
# [audit]
# retained_files = 7
"#;

/// `config new --out <path>` writes [`TEMPLATE`] as an atomic
/// `0600` file; an existing file is never overwritten. Installation
/// itself still synthesizes nothing — this is the operator's starting point.
pub(super) fn new(out: &Path) -> Outcome {
    if out.exists() {
        return Err(Failure::local(
            8,
            "cli_conflict",
            format!("{}: refusing to overwrite an existing file", out.display()),
        ));
    }
    write(out, TEMPLATE.as_bytes())?;
    let digest = config::sha256_hex(TEMPLATE.as_bytes());
    Ok((
        json!({ "path": out.display().to_string(), "digest": digest }),
        format!(
            "{} written; edit it, then `jaynshare server install --config {}`",
            out.display(),
            out.display()
        ),
    ))
}

/// Validated locally — syntax, types, ranges, duplicates — never the
/// state cross-references only the server can check.
fn validate_bytes(bytes: &[u8], path: &Path) -> Result<config::Config, Failure> {
    config::parse(bytes, path.parent().unwrap_or(Path::new(".")))
        .map_err(|errors| invalid(path, errors))
}

fn invalid(path: &Path, errors: ConfigErrors) -> Failure {
    Failure {
        code: 3,
        error: json!({
            "code": "cli_configuration_invalid",
            "message": format!("configuration {}: {} error(s); nothing was written", path.display(), errors.0.len()),
            "target": null,
            "details": errors.0.iter().map(|e| json!({ "target": e.target, "code": "configuration_invalid", "message": e.message })).collect::<Vec<_>>(),
        }),
    }
}

/// Atomic, same directory, mode `0600`.
fn write(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    state::write_private_atomic(path, bytes).map_err(|e| {
        Failure::local(
            1,
            "cli_internal",
            format!("configuration {}: cannot write: {e}", path.display()),
        )
    })
}

fn config_path(cli: &Cli) -> PathBuf {
    config::config_path(cli.config.as_deref())
}

// ---------------------------------------------------------------- config

/// The control-backed `config` verbs; `config validate` is [`validate`].
pub(super) async fn config(control: &Control, verb: &ConfigVerb) -> Outcome {
    match verb {
        ConfigVerb::Validate { .. } => unreachable!("file-backed, dispatched before connecting"),
        ConfigVerb::Reload => {
            let result = control.reload().await?;
            Ok((result.clone(), reload_line(&result)))
        }
        ConfigVerb::Set { key, value } => {
            let result = edit_and_reload(control, |document| set_key(document, key, value)).await?;
            Ok((
                result.clone(),
                format!("{key} set; {}", reload_line(&result["reload"])),
            ))
        }
        ConfigVerb::Unset { key } => {
            let result = edit_and_reload(control, |document| unset_key(document, key)).await?;
            Ok((
                result.clone(),
                format!("{key} unset; {}", reload_line(&result["reload"])),
            ))
        }
        ConfigVerb::Show { local: false } => {
            // The server's object; the body verbatim.
            let body = control
                .expect(Method::GET, "/control/v1/configuration", None)
                .await?;
            let c = &body["configuration"];
            let mut lines = vec![
                format!(
                    "{} digest {} loaded {}",
                    c["path"].as_str().unwrap_or(""),
                    c["digest"].as_str().unwrap_or(""),
                    c["loaded_at"].as_str().unwrap_or("")
                ),
                format!("last reload {}", c["last_reload"]),
            ];
            lines.extend(dotted_lines(&c["effective"]));
            Ok((body, lines.join("\n")))
        }
        ConfigVerb::Edit { offline: false } => {
            let path = control.config_path()?.to_path_buf();
            let (previous, candidate) = edited_candidate(&path)?;
            let digest_before = config::sha256_hex(&previous);
            if candidate == previous {
                return Ok((
                    json!({ "path": path.display().to_string(), "digest_before": digest_before, "digest_after": digest_before, "reload": null }),
                    format!("{}: unchanged; nothing was written", path.display()),
                ));
            }
            control.reachable().await?;
            write(&path, &candidate)?;
            match control.reload().await {
                Ok(reload) => {
                    let result = json!({
                        "path": path.display().to_string(),
                        "digest_before": digest_before,
                        "digest_after": config::sha256_hex(&candidate),
                        "reload": reload,
                    });
                    Ok((
                        result.clone(),
                        format!(
                            "{} replaced; {}",
                            path.display(),
                            reload_line(&result["reload"])
                        ),
                    ))
                }
                Err(failure) => {
                    // The file never says what the server refused.
                    write(&path, &previous)?;
                    Err(failure)
                }
            }
        }
        ConfigVerb::Paths
        | ConfigVerb::New { .. }
        | ConfigVerb::Show { local: true }
        | ConfigVerb::Edit { offline: true } => {
            unreachable!("file-backed, dispatched before connecting")
        }
    }
}

/// `config paths` — every owned location of the configuration
/// selected on this machine, whether it exists and its mode; nothing is
/// created and a missing or invalid file still answers with the defaults.
pub(super) fn paths(cli: &Cli) -> Outcome {
    let (path, selected) = config::config_selection(cli.config.as_deref());
    let parsed = config::read(&path)
        .and_then(|bytes| config::parse_document(&bytes, config::base_dir(&path)))
        .ok();
    let from_file = parsed.as_ref().map(|p| &p.config);
    if from_file.is_none() && !cli.quiet {
        eprintln!(
            "note: {} is missing or unreadable; the state and log paths shown are the platform defaults",
            path.display()
        );
    }
    let platform_state = config::platform::state_file();
    let platform_logs = config::platform::log_directory();
    let state = from_file.map_or(platform_state.clone(), |c| c.storage.state_file.clone());
    let logs = from_file.map_or(platform_logs.clone(), |c| c.logging.directory.clone());
    let derived = |p: &Path, platform: &Path| {
        if from_file.is_some() && p != platform {
            "configuration"
        } else {
            "platform-default"
        }
    };
    let selected = match selected {
        Selected::Flag => "flag",
        Selected::Variable => "variable",
        Selected::PlatformDefault => "platform-default",
    };
    let entries: [(&str, &str, PathBuf, Option<&str>); 5] = [
        (
            "configuration",
            "configuration",
            path.clone(),
            Some(selected),
        ),
        (
            "state",
            "state",
            state.clone(),
            Some(derived(&state, &platform_state)),
        ),
        (
            "log_directory",
            "log directory",
            logs.clone(),
            Some(derived(&logs, &platform_logs)),
        ),
        ("audit", "audit", logs.join(AUDIT_LOG), None),
        (
            "client_directory",
            "client directory",
            config::platform::client_directory(),
            Some("platform-default"),
        ),
    ];
    let mut result = serde_json::Map::new();
    let mut lines = Vec::new();
    for (member, label, p, selected_by) in entries {
        let mode = state::mode_summary(&p);
        let exists = p.exists();
        lines.push(format!(
            "{label:<16} {}  {}  {}",
            p.display(),
            selected_by.map_or(String::new(), |s| format!("({s})")),
            match &mode {
                Some(mode) => format!("exists, mode {mode}"),
                None if exists => "exists".to_string(),
                None => "missing".to_string(),
            }
        ));
        result.insert(
            member.to_string(),
            json!({ "path": p.display().to_string(), "selected_by": selected_by, "exists": exists, "mode": mode }),
        );
    }
    Ok((Value::Object(result), lines.join("\n")))
}

/// `config show --local` — the file parsed on this machine with every
/// default applied and the secret-bearing keys reduced to presence and path.
pub(super) fn show_local(cli: &Cli) -> Outcome {
    let path = config_path(cli);
    let bytes = read_bytes(&path)?;
    let config = validate_bytes(&bytes, &path)?;
    let view = config::effective_view(&config);
    Ok((view.clone(), dotted_lines(&view).join("\n")))
}

/// `config edit --offline` — the editor, local validation and the
/// atomic replacement, with the cross-reference note; no server.
pub(super) fn edit_offline(cli: &Cli) -> Outcome {
    let path = config_path(cli);
    let (previous, candidate) = edited_candidate(&path)?;
    let digest_before = config::sha256_hex(&previous);
    if candidate != previous {
        write(&path, &candidate)?;
    }
    if !cli.quiet {
        eprintln!(
            "note: account references and route cross-references were not checked; the server checks them at the next start or reload"
        );
    }
    let digest_after = config::sha256_hex(&candidate);
    Ok((
        json!({ "path": path.display().to_string(), "digest_before": digest_before, "digest_after": digest_after, "reload": null }),
        if candidate == previous {
            format!("{}: unchanged; nothing was written", path.display())
        } else {
            format!(
                "{} replaced, digest {digest_after}; not reloaded (--offline)",
                path.display()
            )
        },
    ))
}

/// `config edit`'s common half: the previous bytes and the candidate the
/// editor left, validated locally. The editor works on a
/// temporary copy beside the file, mode `0600`, so an interrupted edit
/// never leaves the configuration half-written.
fn edited_candidate(path: &Path) -> Result<(Vec<u8>, Vec<u8>), Failure> {
    let previous = read_bytes(path)?;
    let editor = std::env::var("VISUAL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .ok_or_else(|| {
            Failure::local(
                1,
                "cli_internal",
                "no editor: set VISUAL or EDITOR to the command to run",
            )
        })?;
    let directory = config::base_dir(path);
    let temporary = directory.join(format!(
        ".{}.edit.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config.toml"),
        std::process::id()
    ));
    state::write_private_atomic(&temporary, &previous).map_err(|e| {
        Failure::local(
            1,
            "cli_internal",
            format!(
                "{}: cannot write the editing copy: {e}",
                temporary.display()
            ),
        )
    })?;
    let mut words = editor.split_whitespace();
    let program = words.next().expect("non-empty editor");
    let status = std::process::Command::new(program)
        .args(words)
        .arg(&temporary)
        .status();
    let outcome = match status {
        Ok(status) if status.success() => std::fs::read(&temporary).map_err(|e| {
            Failure::local(
                1,
                "cli_internal",
                format!("{}: cannot read back the edit: {e}", temporary.display()),
            )
        }),
        Ok(status) => Err(Failure::local(
            1,
            "cli_internal",
            format!("the editor ({program}) exited with {status}; nothing was written"),
        )),
        Err(e) => Err(Failure::local(
            1,
            "cli_internal",
            format!("cannot run the editor ({program}): {e}"),
        )),
    };
    let _ = std::fs::remove_file(&temporary);
    let candidate = outcome?;
    if candidate != previous {
        validate_bytes(&candidate, path)?;
    }
    Ok((previous, candidate))
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|e| {
        Failure::local(
            3,
            "cli_configuration_invalid",
            format!("configuration {}: cannot read: {e}", path.display()),
        )
    })
}

/// The effective view as `dotted.key = value` lines, one per leaf; arrays
/// and the presence objects stay JSON on their line.
fn dotted_lines(view: &Value) -> Vec<String> {
    fn walk(prefix: &str, value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(members)
                if !members.contains_key("set") || !members.contains_key("path") =>
            {
                for (key, value) in members {
                    let dotted = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk(&dotted, value, out);
                }
            }
            other => out.push(format!("{prefix} = {other}")),
        }
    }
    let mut out = Vec::new();
    walk("", view, &mut out);
    out
}

fn reload_line(result: &Value) -> String {
    let keys = result["changed_keys"]
        .as_array()
        .map(|k| {
            k.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    format!(
        "reload applied, digest {}, changed keys [{keys}]",
        result["digest"].as_str().unwrap_or("")
    )
}

/// File-backed validation; every configuration error at once, the digest when clean.
pub(super) fn validate(cli: &Cli, path: Option<&Path>) -> Outcome {
    let path = path.map_or_else(|| config_path(cli), config::absolute);
    let bytes = std::fs::read(&path).map_err(|e| {
        Failure::local(
            3,
            "cli_configuration_invalid",
            format!("configuration {}: cannot read: {e}", path.display()),
        )
    })?;
    validate_bytes(&bytes, &path)?;
    if !cli.quiet {
        eprintln!(
            "note: account references and route cross-references were not checked; the server checks them at the next start or reload"
        );
    }
    let digest = config::sha256_hex(&bytes);
    Ok((
        json!({ "path": path.display().to_string(), "digest": digest, "errors": [] }),
        format!("{}: valid, digest {digest}", path.display()),
    ))
}

/// `<toml-value>` parsed as TOML; a bare word that is not one is a string.
fn set_key(document: &mut DocumentMut, key: &str, value: &str) -> Result<(), Failure> {
    if let Some(verb) = table_array_verb(key) {
        return Err(Failure::local(
            2,
            "cli_usage",
            format!("{key} is a table-array key; use `jaynshare {verb}` to edit it"),
        ));
    }
    let value = value
        .parse::<toml_edit::Value>()
        .unwrap_or_else(|_| toml_edit::Value::from(value));
    let (parent, last) = parent_table(document, key, true)?;
    parent.insert(&last, Item::Value(value));
    Ok(())
}

fn unset_key(document: &mut DocumentMut, key: &str) -> Result<(), Failure> {
    if let Some(verb) = table_array_verb(key) {
        return Err(Failure::local(
            2,
            "cli_usage",
            format!("{key} is a table-array key; use `jaynshare {verb}` to edit it"),
        ));
    }
    let (parent, last) = parent_table(document, key, false)?;
    if parent.remove(&last).is_none() {
        return Err(Failure::local(
            6,
            "cli_not_found",
            format!("{key} is not set in the file; its default already applies"),
        ));
    }
    let path: Vec<&str> = key.split('.').collect();
    prune_empty(document, &path[..path.len() - 1]);
    Ok(())
}

/// A verb that empties what its counterpart created leaves nothing behind:
/// `unset` drops a table it emptied, `rm`/`clear` the array they emptied,
/// then `[selection]` itself — so the file reads as before the first edit
/// rather than carrying `[]` and empty tables that only restate the defaults.
/// defaults. Walks from the deepest segment up, stopping at the first
/// non-empty container.
fn prune_empty(document: &mut DocumentMut, path: &[&str]) {
    for depth in (1..=path.len()).rev() {
        let (last, parents) = path[..depth].split_last().expect("depth >= 1");
        let Some(parent) = table_at(document, parents) else {
            return;
        };
        let empty = parent.get(last).is_some_and(|item| match item {
            Item::None => true,
            Item::Table(table) => table.is_empty(),
            Item::ArrayOfTables(tables) => tables.is_empty(),
            Item::Value(value) => {
                value.as_array().is_some_and(Array::is_empty)
                    || value.as_inline_table().is_some_and(InlineTable::is_empty)
            }
        });
        if !empty {
            return;
        }
        parent.remove(last);
    }
}

/// The table `path` names, the root for an empty path; `None` when a
/// segment is missing or not a table.
fn table_at<'d>(
    document: &'d mut DocumentMut,
    path: &[&str],
) -> Option<&'d mut dyn toml_edit::TableLike> {
    let mut table: &mut dyn toml_edit::TableLike = document.as_table_mut();
    for segment in path {
        table = table.get_mut(segment)?.as_table_like_mut()?;
    }
    Some(table)
}

/// `selection.routes` and `selection.priorities` have their own verbs.
fn table_array_verb(key: &str) -> Option<&'static str> {
    if key == "selection.routes" || key.starts_with("selection.routes.") {
        Some("route")
    } else if key == "selection.priorities" || key.starts_with("selection.priorities.") {
        Some("priority")
    } else {
        None
    }
}

/// The table holding the last segment of a dotted key, created on the way
/// when `create`; a segment that is a value, not a table, is exit 3.
fn parent_table<'d>(
    document: &'d mut DocumentMut,
    key: &str,
    create: bool,
) -> Result<(&'d mut dyn toml_edit::TableLike, String), Failure> {
    let segments: Vec<&str> = key.split('.').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(Failure::local(
            2,
            "cli_usage",
            format!("{key:?} is not a dotted key"),
        ));
    }
    let (last, path) = segments.split_last().expect("at least one segment");
    let mut table: &mut dyn toml_edit::TableLike = document.as_table_mut();
    let mut walked = String::new();
    for segment in path {
        walked = if walked.is_empty() {
            (*segment).to_string()
        } else {
            format!("{walked}.{segment}")
        };
        if !table.contains_key(segment) {
            if !create {
                return Err(Failure::local(
                    6,
                    "cli_not_found",
                    format!("{key} is not set in the file; its default already applies"),
                ));
            }
            let mut fresh = Table::new();
            fresh.set_implicit(true);
            table.insert(segment, Item::Table(fresh));
        }
        table = table
            .get_mut(segment)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| {
                Failure::local(
                    3,
                    "cli_configuration_invalid",
                    format!("{walked} is not a table in the file"),
                )
            })?;
    }
    Ok((table, (*last).to_string()))
}

// ---------------------------------------------------------------- route

pub(super) async fn route(control: &Control, cli: &Cli, verb: &RouteVerb) -> Outcome {
    match verb {
        RouteVerb::List { local: false } => {
            let body = control
                .expect(Method::GET, "/control/v1/status", None)
                .await?;
            let rows = body["status"]["routes"]
                .as_array()
                .map(|r| r.iter().map(route_row).collect::<Vec<_>>())
                .unwrap_or_default();
            // The snapshot body verbatim; the table is the rendering.
            Ok((
                body,
                if rows.is_empty() {
                    "(no routes)".into()
                } else {
                    rows.join("\n")
                },
            ))
        }
        RouteVerb::List { local: true } => {
            let path = config_path(cli);
            let bytes = std::fs::read(&path).map_err(|e| {
                Failure::local(
                    3,
                    "cli_configuration_invalid",
                    format!("configuration {}: cannot read: {e}", path.display()),
                )
            })?;
            let config = validate_bytes(&bytes, &path)?;
            let routes = serde_json::to_value(&config.selection.routes).expect("routes serialise");
            let rows: Vec<String> = config
                .selection
                .routes
                .iter()
                .map(|r| {
                    format!(
                        "{} patterns {:?} accounts {} bucket {}",
                        r.name,
                        r.patterns,
                        r.accounts
                            .as_ref()
                            .map_or("(unrestricted)".to_string(), |a| format!("{a:?}")),
                        r.bucket.as_deref().unwrap_or("none")
                    )
                })
                .collect();
            Ok((
                json!({ "routes": routes }),
                if rows.is_empty() {
                    "(no routes)".into()
                } else {
                    rows.join("\n")
                },
            ))
        }
        RouteVerb::Add(args) => {
            // Every reference resolves before the write; the file
            // keeps it as typed (so it stays resolvable).
            for reference in &args.accounts {
                control.resolve(reference).await?;
            }
            let result = edit_and_reload(control, |document| add_route(document, args)).await?;
            Ok((
                result.clone(),
                format!(
                    "route {} added; {}",
                    args.name,
                    reload_line(&result["reload"])
                ),
            ))
        }
        RouteVerb::Rm { name } => {
            let result = edit_and_reload(control, |document| remove_route(document, name)).await?;
            Ok((
                result.clone(),
                format!("route {name} removed; {}", reload_line(&result["reload"])),
            ))
        }
    }
}

fn route_row(r: &Value) -> String {
    let accounts = r["accounts"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|x| {
                    format!(
                        "{}{}",
                        x["display_name"].as_str().unwrap_or(""),
                        if x["eligible"].as_bool().unwrap_or(false) {
                            ""
                        } else {
                            "!"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    format!(
        "{} patterns {} bucket {} preference {} predicted {} accounts [{accounts}]",
        r["name"].as_str().unwrap_or(""),
        r["patterns"],
        r["bucket"],
        r["preference"],
        r["predicted_target"]
    )
}

/// A table-array entry of the operator's document in either TOML spelling:
/// an inline array of inline tables, or `[[selection.routes]]` tables.
enum TableArray<'d> {
    Inline(&'d mut Array),
    Tables(&'d mut ArrayOfTables),
}

impl TableArray<'_> {
    /// The string member `key` of every entry, in order; missing → empty.
    fn strings(&self, key: &str) -> Vec<String> {
        let of = |s: Option<&str>| s.unwrap_or_default().to_string();
        match self {
            TableArray::Inline(array) => array
                .iter()
                .map(|v| {
                    of(v.as_inline_table()
                        .and_then(|t| t.get(key))
                        .and_then(|n| n.as_str()))
                })
                .collect(),
            TableArray::Tables(tables) => tables
                .iter()
                .map(|t| of(t.get(key).and_then(Item::as_str)))
                .collect(),
        }
    }

    fn remove(&mut self, index: usize) {
        match self {
            TableArray::Inline(array) => {
                array.remove(index);
            }
            TableArray::Tables(tables) => {
                tables.remove(index);
            }
        }
    }

    fn insert_route(&mut self, index: usize, args: &RouteAddArgs) {
        let strings = |items: &[String]| items.iter().map(String::as_str).collect::<Array>();
        match self {
            TableArray::Inline(array) => {
                let mut entry = InlineTable::new();
                entry.insert("name", args.name.as_str().into());
                entry.insert("patterns", strings(&args.patterns).into());
                if !args.accounts.is_empty() {
                    entry.insert("accounts", strings(&args.accounts).into());
                }
                if let Some(bucket) = &args.bucket {
                    entry.insert("bucket", bucket.as_str().into());
                }
                array.insert(index, entry);
            }
            TableArray::Tables(tables) => {
                let mut entry = Table::new();
                entry.insert("name", toml_edit::value(args.name.as_str()));
                entry.insert("patterns", toml_edit::value(strings(&args.patterns)));
                if !args.accounts.is_empty() {
                    entry.insert("accounts", toml_edit::value(strings(&args.accounts)));
                }
                if let Some(bucket) = &args.bucket {
                    entry.insert("bucket", toml_edit::value(bucket.as_str()));
                }
                tables.insert(index, entry);
            }
        }
    }

    /// `priority set`: the entries whose literal `account` is in `existing`
    /// take the value; none → one appended under `reference`.
    fn set_priority(&mut self, reference: &str, value: i64, existing: &[String]) {
        let is_target =
            |literal: Option<&str>| existing.iter().any(|e| Some(e.as_str()) == literal);
        let mut updated = false;
        match self {
            TableArray::Inline(array) => {
                for entry in array.iter_mut().filter_map(|v| v.as_inline_table_mut()) {
                    if is_target(entry.get("account").and_then(|a| a.as_str())) {
                        entry.insert("value", value.into());
                        updated = true;
                    }
                }
                if !updated {
                    let mut entry = InlineTable::new();
                    entry.insert("account", reference.into());
                    entry.insert("value", value.into());
                    array.push(entry);
                }
            }
            TableArray::Tables(tables) => {
                for entry in tables.iter_mut() {
                    if is_target(entry.get("account").and_then(Item::as_str)) {
                        entry.insert("value", toml_edit::value(value));
                        updated = true;
                    }
                }
                if !updated {
                    let mut entry = Table::new();
                    entry.insert("account", toml_edit::value(reference));
                    entry.insert("value", toml_edit::value(value));
                    tables.push(entry);
                }
            }
        }
    }

    fn retain_priorities(&mut self, drop: &[String]) {
        let is_target = |literal: Option<&str>| drop.iter().any(|e| Some(e.as_str()) == literal);
        match self {
            TableArray::Inline(array) => array.retain(|v| {
                !is_target(
                    v.as_inline_table()
                        .and_then(|t| t.get("account"))
                        .and_then(|a| a.as_str()),
                )
            }),
            TableArray::Tables(tables) => {
                tables.retain(|t| !is_target(t.get("account").and_then(Item::as_str)));
            }
        }
    }
}

/// One `selection.<key>` item of the document: created from `default` when
/// absent and `create`, `None` when absent otherwise.
fn selection_entry<'d>(
    document: &'d mut DocumentMut,
    key: &str,
    create: bool,
    default: impl FnOnce() -> Item,
) -> Result<Option<&'d mut Item>, Failure> {
    if !document.contains_key("selection") {
        if !create {
            return Ok(None);
        }
        let mut fresh = Table::new();
        fresh.set_implicit(true);
        document.insert("selection", Item::Table(fresh));
    }
    let selection = document.get_mut("selection").expect("present");
    let selection = selection.as_table_like_mut().ok_or_else(|| {
        Failure::local(
            3,
            "cli_configuration_invalid",
            "selection is not a table in the file",
        )
    })?;
    if !selection.contains_key(key) {
        if !create {
            return Ok(None);
        }
        selection.insert(key, default());
    }
    Ok(selection.get_mut(key))
}

/// A table-array key in either TOML spelling; anything else is exit 3.
fn table_array<'d>(item: &'d mut Item, key: &str) -> Result<TableArray<'d>, Failure> {
    match item {
        Item::ArrayOfTables(tables) => Ok(TableArray::Tables(tables)),
        Item::Value(value) if value.is_array() => {
            Ok(TableArray::Inline(value.as_array_mut().expect("array")))
        }
        _ => Err(Failure::local(
            3,
            "cli_configuration_invalid",
            format!("selection.{key} is not an array of tables in the file"),
        )),
    }
}

fn routes_of(document: &mut DocumentMut, create: bool) -> Result<Option<TableArray<'_>>, Failure> {
    selection_entry(document, "routes", create, || {
        Item::ArrayOfTables(ArrayOfTables::new())
    })?
    .map(|item| table_array(item, "routes"))
    .transpose()
}

/// `route add`: appended last unless `--before`/`--after` places it.
fn add_route(document: &mut DocumentMut, args: &RouteAddArgs) -> Result<(), Failure> {
    let mut routes = routes_of(document, true)?.expect("created");
    let names = routes.strings("name");
    let position = |name: &str| names.iter().position(|n| fold(n) == fold(name));
    if position(&args.name).is_some() {
        return Err(Failure::local(
            8,
            "cli_conflict",
            format!("route {} already exists", args.name),
        ));
    }
    let index = match (&args.before, &args.after) {
        (Some(anchor), _) => position(anchor).ok_or_else(|| route_missing(anchor))?,
        (None, Some(anchor)) => position(anchor).ok_or_else(|| route_missing(anchor))? + 1,
        (None, None) => names.len(),
    };
    routes.insert_route(index, args);
    Ok(())
}

fn remove_route(document: &mut DocumentMut, name: &str) -> Result<(), Failure> {
    let Some(mut routes) = routes_of(document, false)? else {
        return Err(route_missing(name));
    };
    let index = routes
        .strings("name")
        .iter()
        .position(|n| fold(n) == fold(name))
        .ok_or_else(|| route_missing(name))?;
    routes.remove(index);
    prune_empty(document, &["selection", "routes"]);
    Ok(())
}

fn route_missing(name: &str) -> Failure {
    Failure {
        code: 6,
        error: json!({ "code": "route_not_found", "message": format!("no configured route is named {name:?}"), "target": name, "details": [] }),
    }
}

// ---------------------------------------------------------------- priority

pub(super) async fn priority(control: &Control, verb: &PriorityVerb) -> Outcome {
    match verb {
        PriorityVerb::List => {
            let body = control
                .expect(Method::GET, "/control/v1/status", None)
                .await?;
            let accounts = body["status"]["accounts"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let rows: Vec<String> = accounts
                .iter()
                .map(|a| {
                    format!(
                        "{} {} priority {}",
                        a["display_name"].as_str().unwrap_or(""),
                        a["handle"].as_str().unwrap_or(""),
                        a["priority"]
                    )
                })
                .collect();
            // The snapshot body verbatim; the table is the rendering.
            Ok((
                body,
                if rows.is_empty() {
                    "(no accounts)".into()
                } else {
                    rows.join("\n")
                },
            ))
        }
        PriorityVerb::Set { reference, value } => {
            let handle = resolved_handle(control, reference).await?;
            let existing = entries_for(control, &handle).await?;
            let result = edit_and_reload(control, |document| {
                set_priority(document, reference, *value, &existing)
            })
            .await?;
            Ok((
                result.clone(),
                format!(
                    "priority of {reference} set to {value}; {}",
                    reload_line(&result["reload"])
                ),
            ))
        }
        PriorityVerb::Clear { reference } => {
            let handle = resolved_handle(control, reference).await?;
            let existing = entries_for(control, &handle).await?;
            if existing.is_empty() {
                return Err(Failure::local(
                    6,
                    "cli_not_found",
                    format!("{reference} has no priority entry; its priority is already 0"),
                ));
            }
            let result =
                edit_and_reload(control, |document| clear_priority(document, &existing)).await?;
            Ok((
                result.clone(),
                format!(
                    "priority of {reference} cleared; {}",
                    reload_line(&result["reload"])
                ),
            ))
        }
    }
}

async fn resolved_handle(control: &Control, reference: &str) -> Result<String, Failure> {
    Ok(control.resolve(reference).await?["account"]["handle"]
        .as_str()
        .unwrap_or_default()
        .to_string())
}

/// The priority entries of the file that resolve to `handle`, by
/// their literal `account` strings — the server resolves each, the CLI cannot.
async fn entries_for(control: &Control, handle: &str) -> Result<Vec<String>, Failure> {
    let (_, mut document) = read_document(control.config_path()?)?;
    let literals = priorities_of(&mut document, false)?
        .map(|p| p.strings("account"))
        .unwrap_or_default();
    let mut matching = Vec::new();
    for literal in literals {
        let resolves = match control.resolve(&literal).await {
            Ok(body) => body["account"]["handle"] == handle,
            Err(f) if f.code == 6 || f.code == 7 => false,
            Err(f) => return Err(f),
        };
        if resolves {
            matching.push(literal);
        }
    }
    Ok(matching)
}

fn priorities_of(
    document: &mut DocumentMut,
    create: bool,
) -> Result<Option<TableArray<'_>>, Failure> {
    selection_entry(document, "priorities", create, || {
        Item::Value(Array::new().into())
    })?
    .map(|item| table_array(item, "priorities"))
    .transpose()
}

fn set_priority(
    document: &mut DocumentMut,
    reference: &str,
    value: i64,
    existing: &[String],
) -> Result<(), Failure> {
    priorities_of(document, true)?
        .expect("created")
        .set_priority(reference, value, existing);
    Ok(())
}

fn clear_priority(document: &mut DocumentMut, existing: &[String]) -> Result<(), Failure> {
    if let Some(mut priorities) = priorities_of(document, false)? {
        priorities.retain_priorities(existing);
    }
    prune_empty(document, &["selection", "priorities"]);
    Ok(())
}

// ---------------------------------------------------------------- block

pub(super) async fn block(control: &Control, verb: &BlockVerb) -> Outcome {
    match verb {
        BlockVerb::List => {
            let body = control
                .expect(Method::GET, "/control/v1/status", None)
                .await?;
            let rows: Vec<String> = body["status"]["blocked_models"]
                .as_array()
                .map(|b| {
                    b.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            // The snapshot body verbatim; the table is the rendering.
            Ok((
                body,
                if rows.is_empty() {
                    "(nothing blocked)".into()
                } else {
                    rows.join("\n")
                },
            ))
        }
        BlockVerb::Add { pattern } => {
            let result = edit_and_reload(control, |document| {
                let list = blocked_models(document, true)?.expect("created");
                if list.iter().any(|v| v.as_str() == Some(pattern.as_str())) {
                    return Err(Failure::local(
                        8,
                        "cli_conflict",
                        format!("{pattern:?} is already in selection.blocked_models"),
                    ));
                }
                list.push(pattern.as_str());
                Ok(())
            })
            .await?;
            Ok((
                result.clone(),
                format!("{pattern} blocked; {}", reload_line(&result["reload"])),
            ))
        }
        BlockVerb::Rm { pattern } => {
            let result =
                edit_and_reload(control, |document| remove_blocked(document, pattern)).await?;
            Ok((
                result.clone(),
                format!("{pattern} unblocked; {}", reload_line(&result["reload"])),
            ))
        }
    }
}

fn remove_blocked(document: &mut DocumentMut, pattern: &str) -> Result<(), Failure> {
    let index = blocked_models(document, false)?
        .and_then(|list| list.iter().position(|v| v.as_str() == Some(pattern)));
    let Some(index) = index else {
        return Err(Failure::local(
            6,
            "cli_not_found",
            format!("{pattern:?} is not in selection.blocked_models"),
        ));
    };
    blocked_models(document, false)?
        .expect("present")
        .remove(index);
    prune_empty(document, &["selection", "blocked_models"]);
    Ok(())
}

fn blocked_models(document: &mut DocumentMut, create: bool) -> Result<Option<&mut Array>, Failure> {
    selection_entry(document, "blocked_models", create, || {
        Item::Value(Array::new().into())
    })?
    .map(|item| {
        item.as_array_mut().ok_or_else(|| {
            Failure::local(
                3,
                "cli_configuration_invalid",
                "selection.blocked_models is not an array in the file",
            )
        })
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "version = 1\n\n[data_plane]\nlisten = \"127.0.0.1:1\"\n";

    fn parsed(extra: &str) -> DocumentMut {
        format!("{BASE}{extra}").parse().expect("toml")
    }

    #[test]
    fn the_template_parses_and_is_the_minimal_document() {
        let config = config::parse(TEMPLATE.as_bytes(), Path::new(".")).expect("template parses");
        assert_eq!(config.data_plane.listen.to_string(), "127.0.0.1:17421");
        assert!(config.mitm.enabled, "clients enrol only with MITM on");
        assert_eq!(config.data_plane.tls, config::ListenerTls::Identity);
        assert_eq!(config.data_plane.telemetry_policy, TelemetryPolicy::Forward);
        assert!(config.selection.priorities.is_empty());
        assert!(config.selection.routes.is_empty());
    }

    #[test]
    fn new_writes_the_template_once_at_0600_and_refuses_overwrite() {
        let dir = std::env::temp_dir().join(format!("config-new-test-{}", std::process::id(),));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let out = dir.join("cfg.toml");

        let (result, line) = new(&out).map_err(|f| f.error).expect("first write");
        assert_eq!(result["path"], out.display().to_string());
        assert!(line.contains("server install"));
        assert_eq!(std::fs::read(&out).expect("bytes"), TEMPLATE.as_bytes());
        #[cfg(unix)]
        assert_eq!(state::mode_summary(&out), Some("0600".into()));

        let refusal = new(&out).unwrap_err().error;
        assert_eq!(refusal["code"], "cli_conflict");
        assert!(
            refusal["message"]
                .as_str()
                .expect("message")
                .contains("refusing to overwrite")
        );
        assert_eq!(std::fs::read(&out).expect("bytes"), TEMPLATE.as_bytes());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_the_last_entry_leaves_no_empty_container_behind() {
        let mut document = parsed("\n[selection]\nblocked_models = [\"*opus*\"]\n");
        remove_blocked(&mut document, "*opus*")
            .map_err(|f| f.error)
            .unwrap();
        assert_eq!(document.to_string(), BASE);

        let mut document =
            parsed("\n[selection]\npriorities = [{ account = \"SUB\", value = 1 }]\n");
        clear_priority(&mut document, &["SUB".into()])
            .map_err(|f| f.error)
            .unwrap();
        assert_eq!(document.to_string(), BASE);

        let mut document =
            parsed("\n[[selection.routes]]\nname = \"h\"\npatterns = [\"*haiku*\"]\n");
        remove_route(&mut document, "h")
            .map_err(|f| f.error)
            .unwrap();
        assert_eq!(document.to_string(), BASE);

        let mut document = parsed("\n[quota]\nprobe_enabled = true\n");
        unset_key(&mut document, "quota.probe_enabled")
            .map_err(|f| f.error)
            .unwrap();
        assert_eq!(document.to_string(), BASE);
    }

    #[test]
    fn a_container_that_still_holds_something_stays() {
        let mut document = parsed("\n[selection]\nblocked_models = [\"*opus*\", \"*sonnet*\"]\n");
        remove_blocked(&mut document, "*opus*")
            .map_err(|f| f.error)
            .unwrap();
        let kept = document["selection"]["blocked_models"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>());
        assert_eq!(kept, Some(vec!["*sonnet*"]));

        let mut document = parsed("\n[quota]\nprobe_enabled = true\nprobe_interval_seconds = 60\n");
        unset_key(&mut document, "quota.probe_enabled")
            .map_err(|f| f.error)
            .unwrap();
        assert!(
            document
                .to_string()
                .contains("[quota]\nprobe_interval_seconds = 60")
        );
    }
}
