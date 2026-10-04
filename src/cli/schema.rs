//! The JSON Schema (draft 2020-12) of each verb's `--json` document —
//! the envelope with `result` bound to the verb's object. Control-backed
//! verbs bind the control response body as the server produces it;
//! file-backed verbs bind their own result object. A verb whose behaviour
//! lands later binds its result shape where one is fixed, and an open object
//! where its body is a control body not yet served by this build.

use serde_json::{Value, json};

use super::help::DOCS;
use crate::provider::Provider;

/// Verbs with no `--json` document at all.
pub(super) const NO_JSON: &[&str] = &["claude", "codex", "env", "statusline", "title-hook"];

/// Verbs whose `--json` is one raw object per line and no envelope.
const PER_LINE: &[&str] = &["log tail", "audit tail"];

fn string() -> Value {
    json!({ "type": "string" })
}

fn nullable(schema: Value) -> Value {
    json!({ "oneOf": [schema, { "type": "null" }] })
}

fn nullable_string() -> Value {
    json!({ "type": ["string", "null"] })
}

fn nullable_number() -> Value {
    json!({ "type": ["number", "null"] })
}

fn array(items: Value) -> Value {
    json!({ "type": "array", "items": items })
}

/// A closed object: every listed member required, no other allowed.
fn object(members: &[(&str, Value)]) -> Value {
    let required: Vec<&str> = members.iter().map(|(name, _)| *name).collect();
    let properties: serde_json::Map<String, Value> = members
        .iter()
        .map(|(name, schema)| ((*name).to_string(), schema.clone()))
        .collect();
    json!({ "type": "object", "required": required, "additionalProperties": false, "properties": properties })
}

/// What every deploy verb answers.
fn deploy_members() -> Vec<(&'static str, Value)> {
    vec![
        ("operation", string()),
        ("version", nullable_string()),
        ("commit", nullable_string()),
        ("paths", array(string())),
        ("project", nullable_string()),
        ("rolled_back", json!({ "type": "boolean" })),
        (
            "checks",
            array(object(&[
                ("name", string()),
                ("passed", json!({ "type": "boolean" })),
                ("message", string()),
            ])),
        ),
    ]
}

fn open_object() -> Value {
    json!({ "type": "object" })
}

fn reference(name: &str) -> Value {
    json!({ "$ref": format!("#/$defs/{name}") })
}

/// The operator's account object, or a client's view of its own.
fn any_account() -> Value {
    json!({ "oneOf": [reference("account"), reference("owned_account")] })
}

/// A read carries `control_api_version`, `captured_at` and its payload.
fn read(member: &str, payload: Value) -> Value {
    object(&[
        ("control_api_version", json!({ "type": "integer" })),
        ("captured_at", string()),
        (member, payload),
    ])
}

/// A mutation carries `control_api_version` and the resulting object.
fn mutation(members: &[(&str, Value)]) -> Value {
    let mut all = vec![("control_api_version", json!({ "type": "integer" }))];
    all.extend(members.iter().cloned());
    object(&all)
}

fn defs() -> Value {
    let time = string();
    let bucket = object(&[
        ("name", string()),
        (
            "scope",
            json!({ "enum": ["account", "organisation", "family"] }),
        ),
        (
            "state",
            json!({ "enum": ["available", "exhausted", "unknown"] }),
        ),
        ("utilisation", nullable_number()),
        ("limit", nullable_number()),
        ("remaining", nullable_number()),
        ("reset", nullable_string()),
        ("hold_end", nullable_string()),
        ("observed_at", nullable_string()),
        ("observed_source", nullable_string()),
    ]);
    let health = object(&[
        (
            "state",
            json!({ "enum": ["ready", "refreshing", "refresh_wait", "errored"] }),
        ),
        ("reason", nullable_string()),
        ("since", nullable_string()),
    ]);
    let profile = object(&[
        ("email", nullable_string()),
        ("account_uuid", nullable_string()),
        ("organization_uuid", nullable_string()),
        ("organization_name", nullable_string()),
        ("chatgpt_account_id", nullable_string()),
    ]);
    // A client's view of an account it owns.
    let provider = json!({ "enum": Provider::ALL.map(Provider::as_str) });
    let owned_account = object(&[
        ("handle", string()),
        ("display_name", string()),
        ("provider", provider.clone()),
        ("selectable", json!({ "type": "boolean" })),
        (
            "rate_limits",
            object(&[
                ("five_hour", nullable_number()),
                ("weekly", nullable_number()),
            ]),
        ),
        ("profile", profile.clone()),
        ("health", health.clone()),
    ]);
    let account = object(&[
        ("handle", string()),
        ("display_name", string()),
        ("provider", provider),
        ("kind", json!({ "enum": ["oauth", "api_key"] })),
        (
            "source_class",
            json!({ "enum": ["api-key-entry", "portable-json", "explicit-file", "managed-store", "browser"] }),
        ),
        ("enabled", json!({ "type": "boolean" })),
        ("owner", nullable_string()),
        ("health", health.clone()),
        ("profile", profile.clone()),
        (
            "credential",
            object(&[
                ("access_token_expires_at", nullable_string()),
                ("refresh_material_present", json!({ "type": "boolean" })),
                ("last_refresh_attempt", nullable_string()),
                ("last_refresh_success", nullable_string()),
                ("next_refresh_allowed_at", nullable_string()),
            ]),
        ),
        ("priority", json!({ "type": "integer" })),
        (
            "eligibility",
            object(&[
                ("eligible", json!({ "type": "boolean" })),
                ("reason", nullable_string()),
                ("reason_detail", nullable_string()),
            ]),
        ),
        ("buckets", array(bucket)),
        (
            "quota_holds",
            object(&[
                ("throttle_hold_end", nullable_string()),
                (
                    "revalidation_allowed",
                    json!({ "type": ["boolean", "null"] }),
                ),
            ]),
        ),
        (
            "usage",
            object(&[
                ("input_tokens", json!({ "type": "integer" })),
                ("output_tokens", json!({ "type": "integer" })),
                ("requests", json!({ "type": "integer" })),
            ]),
        ),
        ("sessions_active", json!({ "type": "integer" })),
        (
            "ramp",
            object(&[
                ("active", json!({ "type": "boolean" })),
                ("started_at", nullable_string()),
                ("limit", json!({ "type": ["integer", "null"] })),
            ]),
        ),
        (
            "probe",
            object(&[
                (
                    "outcome",
                    json!({ "enum": ["updated", "not_applicable", "timed_out", "failed", null] }),
                ),
                ("finished_at", nullable_string()),
                ("error", nullable_string()),
            ]),
        ),
    ]);
    let route = object(&[
        ("name", string()),
        ("patterns", array(string())),
        ("bucket", nullable_string()),
        ("preference", nullable_string()),
        (
            "accounts",
            array(object(&[
                ("handle", string()),
                ("display_name", string()),
                ("eligible", json!({ "type": "boolean" })),
            ])),
        ),
        ("predicted_target", nullable_string()),
    ]);
    // The reload body, passed through unreshaped wherever it appears,
    // so it carries the `control_api_version` of every control response.
    let reload = mutation(&[
        ("digest", nullable_string()),
        ("applied", json!({ "type": "boolean" })),
        ("changed_keys", array(string())),
        ("rejected_restart_keys", array(string())),
    ]);
    // One provider's default.
    let default = nullable(object(&[
        ("handle", string()),
        ("operator_chosen", json!({ "type": "boolean" })),
        ("since", nullable_string()),
    ]));
    let snapshot = object(&[
        (
            "server",
            object(&[
                ("version", string()),
                (
                    "build",
                    object(&[("commit", string()), ("target", string())]),
                ),
                ("started_at", time.clone()),
                ("listen", string()),
                ("tls", json!({ "type": "boolean" })),
                ("tls_pin", nullable_string()),
                ("signing_key", nullable_string()),
                ("control_api_versions", array(json!({ "type": "integer" }))),
                ("telemetry_policy", string()),
                ("upstream_origin_override", nullable_string()),
                (
                    "egress",
                    object(&[
                        ("mode", string()),
                        ("pinned_addresses", array(string())),
                        ("observed_address", nullable_string()),
                        ("observed_at", nullable_string()),
                        ("held_now", json!({ "type": "integer" })),
                    ]),
                ),
            ]),
        ),
        (
            "capture",
            object(&[
                ("enabled", json!({ "type": "boolean" })),
                ("directory", nullable_string()),
            ]),
        ),
        (
            "mitm",
            object(&[
                ("enabled", json!({ "type": "boolean" })),
                ("listen", string()),
                (
                    "ca",
                    object(&[
                        ("fingerprint", nullable_string()),
                        ("not_after", nullable_string()),
                        ("state", nullable_string()),
                        (
                            "next",
                            nullable(object(&[
                                ("fingerprint", string()),
                                ("not_after", string()),
                                ("switch_at", string()),
                            ])),
                        ),
                    ]),
                ),
                (
                    "tunnels",
                    object(&[
                        ("intercepted", json!({ "type": "integer" })),
                        ("tunnelled", json!({ "type": "integer" })),
                    ]),
                ),
                (
                    "counters",
                    json!({ "type": "object", "additionalProperties": { "type": "integer" } }),
                ),
            ]),
        ),
        ("accounts", array(reference("account"))),
        ("default_account", default.clone()),
        (
            "default_accounts",
            object(&Provider::ALL.map(|p| (p.as_str(), default.clone()))),
        ),
        ("routes", array(reference("route"))),
        ("blocked_models", array(string())),
        (
            "sessions",
            object(&[
                ("known", json!({ "type": "integer" })),
                ("active", json!({ "type": "integer" })),
                ("distribution_enabled", json!({ "type": "boolean" })),
            ]),
        ),
        (
            "usage_probe",
            object(&[
                ("enabled", json!({ "type": "boolean" })),
                ("interval_seconds", json!({ "type": "integer" })),
                ("last_started", nullable_string()),
                ("last_finished", nullable_string()),
                ("next_run", nullable_string()),
                ("pending_reason", nullable_string()),
            ]),
        ),
        ("configuration", reference("configuration")),
        (
            "storage",
            object(&[
                (
                    "state",
                    object(&[("path", string()), ("last_write", nullable_string())]),
                ),
                (
                    "audit",
                    object(&[
                        ("path", string()),
                        ("last_record", nullable_string()),
                        ("active_file_bytes", json!({ "type": "integer" })),
                        ("retained_files", json!({ "type": "integer" })),
                    ]),
                ),
                ("log", object(&[("path", string()), ("level", string())])),
                ("unwritable", json!({ "type": "boolean" })),
            ]),
        ),
        ("clients", array(open_object())),
    ]);
    let operation = object(&[
        ("operation_id", string()),
        (
            "state",
            json!({ "enum": ["awaiting_authorization", "exchanging", "succeeded", "failed", "cancelled"] }),
        ),
        ("expires_at", time.clone()),
        ("account", nullable(any_account())),
        ("error", nullable(reference("error"))),
    ]);
    let error = object(&[
        ("code", string()),
        ("message", string()),
        ("target", nullable_string()),
        (
            "details",
            array(
                json!({ "type": "object", "properties": { "target": nullable_string(), "code": string(), "message": string() } }),
            ),
        ),
    ]);
    // The effective view — every configuration table.
    let effective_view = object(&[
        ("version", json!({ "const": 1 })),
        ("accounts", open_object()),
        ("quota", open_object()),
        ("selection", open_object()),
        ("data_plane", open_object()),
        ("diagnostics", open_object()),
        ("mitm", open_object()),
        ("clients", open_object()),
        ("storage", open_object()),
        ("logging", open_object()),
        ("audit", open_object()),
    ]);
    // The configuration in force, in the snapshot and alone.
    let configuration = object(&[
        ("path", string()),
        ("digest", string()),
        ("loaded_at", time.clone()),
        ("effective", reference("effective_view")),
        (
            "secrets",
            json!({ "type": "object", "additionalProperties": object(&[("set", json!({ "type": "boolean" })), ("readable", json!({ "type": ["boolean", "null"] }))]) }),
        ),
        ("last_reload", nullable(open_object())),
    ]);
    // One operational or crash log object.
    let log_object = object(&[
        ("timestamp", string()),
        (
            "level",
            json!({ "enum": ["error", "warn", "info", "debug"] }),
        ),
        ("event", string()),
        ("message", string()),
        ("fields", open_object()),
    ]);
    // One audit record, every field present.
    let audit_record = object(&[
        ("timestamp", string()),
        ("duration_ms", json!({ "type": "integer", "minimum": 0 })),
        (
            "principal",
            object(&[
                (
                    "kind",
                    json!({ "enum": ["loopback", "client", "operator"] }),
                ),
                ("id", nullable_string()),
            ]),
        ),
        ("source_address", string()),
        ("session_id", nullable_string()),
        ("method", string()),
        ("path", string()),
        ("model", nullable_string()),
        (
            "serving_account",
            nullable(object(&[
                ("display_name", string()),
                ("account_uuid", nullable_string()),
                ("organization_uuid", nullable_string()),
            ])),
        ),
        ("no_service_reason", nullable_string()),
        ("selection_cause", nullable_string()),
        ("status", json!({ "type": ["integer", "null"] })),
        ("attempts", json!({ "type": "integer", "minimum": 0 })),
        ("failed_over", json!({ "type": "boolean" })),
        (
            "error_class",
            json!({ "enum": ["authentication", "rate_limit", "upstream", "request", null] }),
        ),
        ("pinned", json!({ "type": "boolean" })),
        ("mode", json!({ "enum": ["base-url", "mitm"] })),
        ("blocked_pattern", nullable_string()),
    ]);
    json!({
        "error": error,
        "account": account,
        "route": route,
        "reload": reload,
        "configuration": configuration,
        "effective_view": effective_view,
        "log_object": log_object,
        "audit_record": audit_record,
        "status_snapshot": snapshot,
        "operation": operation,
        "owned_account": owned_account,
        "edit_result": object(&[
            ("path", string()),
            ("digest_before", string()),
            ("digest_after", string()),
            ("reload", nullable(reference("reload"))),
        ]),
        "ca_export_result": object(&[
            ("path", nullable_string()),
            ("certificate_pem", string()),
            ("fingerprint", nullable_string()),
            ("not_after", nullable_string()),
        ]),
        "deploy_result": object(&deploy_members()),
        "install_result": object(
            &[deploy_members(), vec![("invite", nullable(reference("invite_result")))]].concat(),
        ),
        "invite_result": object(&[
            ("client", reference("registry_entry")),
            ("expires_at", string()),
            ("invite", string()),
        ]),
        "client_result": object(&[
            ("client_id", string()),
            ("display_name", string()),
            ("origins", object(&[("base_url", string()), ("proxy", nullable_string())])),
            ("ca_fingerprint", nullable_string()),
            ("files", array(string())),
        ]),
        "path_entry": object(&[
            ("path", string()),
            ("selected_by", json!({ "enum": ["flag", "variable", "configuration", "platform-default", null] })),
            ("exists", json!({ "type": "boolean" })),
            ("mode", nullable_string()),
        ]),
        "registry_entry": object(&[
            ("id", string()),
            ("display_name", string()),
            ("state", json!({ "enum": ["pending", "active", "revoked"] })),
            ("generation", json!({ "type": "integer" })),
            ("issued_at", string()),
            ("expires_at", nullable_string()),
            ("activated_at", nullable_string()),
            ("revoked_at", nullable_string()),
            ("hash_algorithm", string()),
            ("no_account", json!({ "type": "boolean" })),
        ]),
    })
}

/// The `result` schema of one verb, or `None` when the verb has no `--json` document.
fn result_of(path: &str) -> Option<Value> {
    let status_read = read("status", reference("status_snapshot"));
    // The client form of `status`: the client status body plus the origins the
    // installation holds. Disjoint from the operator snapshot: only
    // the client body carries `client` at the top level. `session` is absent
    // unless --session was given.
    let client_status = json!({
        "type": "object",
        "required": ["control_api_version", "captured_at", "client"],
        "additionalProperties": false,
        "properties": {
            "control_api_version": json!({ "type": "integer" }),
            "captured_at": string(),
            "client": {
                "type": "object",
                "required": ["id", "display_name", "origins"],
                "additionalProperties": false,
                "properties": {
                    "id": string(),
                    "display_name": string(),
                    "origins": object(&[
                        ("base_url", string()),
                        ("proxy", nullable_string()),
                    ]),
                    // The client kit the server offers, when it offers one:
                    // its version and each platform's payload digest.
                    "version": string(),
                    "sha256": { "type": "object", "additionalProperties": string() },
                },
            },
            "server": object(&[
                ("version", string()),
                ("available", json!({ "type": "boolean" })),
                ("control_api_version", json!({ "type": "integer" })),
                ("tls_pin", nullable_string()),
            ]),
            "capabilities": array(string()),
            "ca_fingerprint": nullable_string(),
            "ca_next_fingerprint": nullable_string(),
            "pool": object(&[
                ("accounts_configured", json!({ "type": "integer" })),
                ("accounts_selectable", json!({ "type": "integer" })),
            ]),
            "sessions": object(&[
                ("known", json!({ "type": "integer" })),
                ("active", json!({ "type": "integer" })),
            ]),
            "wire_capture_enabled": json!({ "type": "boolean" }),
            "hold_hint_seconds": json!({ "type": "integer" }),
            // `null` when this principal has no such session.
            "session": json!({ "oneOf": [
                object(&[
                    ("serving_account_display_name", string()),
                    ("last_routed_at", string()),
                ]),
                { "type": "null" },
            ] }),
            // MITM mode only: the two probe answers as
            // received (`null` for a form that did not answer 200) and the
            // outcome; `fingerprint_matches` is `null` unless both answered.
            "probe": {
                "type": "object",
                "required": ["outcome", "tunnel", "absolute", "fingerprint_matches"],
                "additionalProperties": false,
                "properties": {
                    "outcome": { "enum": ["unreachable", "credential_refused", "ca_not_trusted", "healthy"] },
                    "tunnel": { "type": ["object", "null"] },
                    "absolute": { "type": ["object", "null"] },
                    "fingerprint_matches": { "type": ["boolean", "null"] },
                },
            },
        },
    });
    let account_mutation = mutation(&[("account", reference("account"))]);
    let edit = reference("edit_result");
    let will_serve = mutation(&[
        (
            "account",
            object(&[("handle", string()), ("display_name", string())]),
        ),
        ("will_serve", json!({ "type": "boolean" })),
        ("reason", nullable_string()),
        ("reason_detail", nullable_string()),
    ]);
    let schema = match path {
        p if NO_JSON.contains(&p) => return None,
        "help" => object(&[("help", string())]),
        "version" => object(&[
            ("version", string()),
            ("commit", string()),
            ("target", string()),
        ]),
        "schema" => open_object(),
        "serve" => json!({ "type": "null" }),
        "status" => json!({ "oneOf": [status_read, client_status] }),
        "account list" => read("accounts", array(any_account())),
        "account show" => read("account", reference("account")),
        "account add" | "account replace" | "account rename" | "account enable"
        | "account disable" => account_mutation,
        "account remove" => mutation(&[]),
        "account login" => json!({ "oneOf": [
            mutation(&[
                ("operation_id", string()),
                ("state", string()),
                ("authorization_url", string()),
                ("expires_at", string()),
                ("manual_code_required", json!({ "type": "boolean" })),
            ]),
            read("operation", reference("operation")),
        ] }),
        "account operation show" => read("operation", reference("operation")),
        "account operation code" => mutation(&[("submitted", json!({ "const": true }))]),
        "account operation cancel" => mutation(&[("cancelled", json!({ "const": true }))]),
        "switch" => json!({ "oneOf": [
            status_read,
            will_serve,
            mutation(&[
                ("route", string()),
                ("account", object(&[("handle", string()), ("display_name", string())])),
                ("will_serve", json!({ "type": "boolean" })),
                ("reason", nullable_string()),
                ("reason_detail", nullable_string()),
            ]),
            mutation(&[("route", string()), ("account", nullable_string())]),
        ] }),
        // Two documents under one verb path: the snapshot body and,
        // with `--local`, the file's own route table.
        "route list" => json!({ "oneOf": [
            status_read,
            object(&[(
                "routes",
                array(object(&[
                    ("name", string()),
                    ("patterns", array(string())),
                    ("accounts", nullable(array(string()))),
                    ("bucket", nullable_string()),
                ])),
            )]),
        ] }),
        "priority list" | "block list" => status_read,
        "route add" | "route rm" | "priority set" | "priority clear" | "block add" | "block rm"
        | "config set" | "config unset" | "config edit" => edit,
        "probe" => json!({ "oneOf": [mutation(&[("started_at", string())]), status_read] }),
        "config reload" => reference("reload"),
        "config new" => object(&[("path", string()), ("digest", string())]),
        "config validate" => object(&[
            ("path", string()),
            ("digest", nullable_string()),
            (
                "errors",
                array(object(&[
                    ("target", nullable_string()),
                    ("code", string()),
                    ("message", string()),
                ])),
            ),
        ]),
        "config paths" => object(&[
            ("configuration", reference("path_entry")),
            ("state", reference("path_entry")),
            ("log_directory", reference("path_entry")),
            ("audit", reference("path_entry")),
            ("client_directory", reference("path_entry")),
        ]),
        // Two documents under one verb path: the configuration read and, with
        // `--local`, the effective view of the file alone.
        "config show" => json!({ "oneOf": [
            read("configuration", reference("configuration")),
            reference("effective_view"),
        ] }),
        "log tail" => reference("log_object"),
        "audit tail" => reference("audit_record"),
        "api" => object(&[
            ("status", json!({ "type": "integer" })),
            (
                "headers",
                json!({ "type": "object", "additionalProperties": string() }),
            ),
            (
                "body",
                json!({ "oneOf": [string(), object(&[("base64", string())])] }),
            ),
        ]),
        // The invite travels inside `result` with `--json`, or into
        // `--disclose-to`'s file, named by `disclosure_file`.
        "client invite" | "client reissue" => json!({ "oneOf": [
            reference("invite_result"),
            object(&[
                ("client", reference("registry_entry")),
                ("expires_at", string()),
                ("disclosure_file", string()),
            ]),
        ] }),
        "client rotate" => json!({ "oneOf": [
            mutation(&[
                ("client", reference("registry_entry")),
                ("client_secret", string()),
            ]),
            mutation(&[
                ("client", reference("registry_entry")),
                ("disclosure_file", string()),
            ]),
        ] }),
        "client revoke" | "client rename" => mutation(&[("client", reference("registry_entry"))]),
        "operator secret set" => json!({ "oneOf": [
            mutation(&[
                ("operator_secret", string()),
                ("rotated_at", nullable_string()),
            ]),
            mutation(&[
                ("rotated_at", nullable_string()),
                ("disclosure_file", string()),
            ]),
        ] }),
        "client list" => read("clients", array(reference("registry_entry"))),
        "client show" => read("client", reference("registry_entry")),
        "ca export" => reference("ca_export_result"),
        p if p.starts_with("client ") || p.starts_with("operator ") || p.starts_with("ca ") => {
            open_object()
        }
        "server install" => reference("install_result"),
        p if p.starts_with("release ") || p.starts_with("server ") || p.starts_with("service ") => {
            reference("deploy_result")
        }
        "join" => object(&[
            ("client_id", string()),
            ("display_name", string()),
            (
                "origins",
                object(&[("base_url", string()), ("proxy", nullable_string())]),
            ),
            ("ca_fingerprint", nullable_string()),
            ("files", array(string())),
            ("version", string()),
        ]),
        "update" | "trust-ca add" | "trust-ca remove" | "uninstall" | "secret set" => {
            reference("client_result")
        }
        _ => open_object(),
    };
    Some(schema)
}

/// The whole document of one verb, or `None` for a verb with no `--json`.
pub(super) fn of_verb(path: &str) -> Option<Value> {
    let result = result_of(path)?;
    if PER_LINE.contains(&path) {
        let mut document = result;
        document["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
        document["title"] = json!(format!(
            "jaynshare {path} --json: one object per line, no envelope"
        ));
        document["$defs"] = defs();
        return Some(document);
    }
    let mut properties = json!({
        "cli_version": string(),
        "command": { "const": path },
        "ok": { "type": "boolean" },
        "exit_code": { "type": "integer", "minimum": 0, "maximum": 23 },
        "result": nullable(result),
        "error": nullable(reference("error")),
    });
    let mut required = vec![
        "cli_version",
        "command",
        "ok",
        "exit_code",
        "result",
        "error",
    ];
    if matches!(path, "status" | "api" | "account list" | "account login") {
        properties["role"] = json!({ "enum": ["operator", "client"] });
        required.push("role");
    }
    Some(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("jaynshare {path} --json"),
        "type": "object",
        "required": required,
        "additionalProperties": false,
        "properties": properties,
        "$defs": defs(),
    }))
}

/// Every verb with a `--json` document, mapped to its schema.
pub(super) fn all() -> Value {
    let mut map = serde_json::Map::new();
    for doc in DOCS {
        if map.contains_key(doc.path) {
            continue;
        }
        if let Some(schema) = of_verb(doc.path) {
            map.insert(doc.path.to_string(), schema);
        }
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_verb_has_a_schema_or_refuses_json() {
        for doc in DOCS {
            let schema = of_verb(doc.path);
            assert_eq!(
                schema.is_none(),
                NO_JSON.contains(&doc.path),
                "{}",
                doc.path
            );
        }
        let every = all();
        assert!(every.get("status").is_some());
        assert!(every.get("claude").is_none());
        assert_eq!(
            of_verb("status").unwrap()["properties"]["role"]["enum"],
            json!(["operator", "client"])
        );
        assert!(
            of_verb("account add").unwrap()["properties"]
                .get("role")
                .is_none()
        );
    }
}
