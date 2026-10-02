//! The two Claude Code settings entries the client owns: the status-line
//! command (10 s refresh) and the `UserPromptSubmit` title hook (2 s
//! timeout), both invoking the installed executable by absolute path. Every
//! other key is the engineer's: preserved, in order, and never the theme.
//!
//! An install is planned first (so an invalid file stops it before a claim)
//! and committed later; the one backup of the original file is written once
//! and never overwritten.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// A computed change to the settings file, not yet written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub path: PathBuf,
    /// The new file contents.
    pub bytes: Vec<u8>,
    /// The original file, when no backup exists yet.
    pub backup: Option<Vec<u8>>,
}

/// Claude Code's user settings file: `~/.claude/settings.json`
/// (`%USERPROFILE%\.claude\settings.json` on Windows).
pub fn path() -> PathBuf {
    crate::config::platform::home()
        .join(".claude")
        .join("settings.json")
}

/// The one backup, beside the file it holds.
fn backup_path(path: &Path) -> PathBuf {
    path.with_file_name("settings.json.jaynshare-backup")
}

/// How Claude Code runs the installed client — a quoted absolute
/// path and the subcommand verb.
fn command(executable: &Path, verb: &str) -> String {
    let path = executable.display().to_string();
    if cfg!(target_os = "windows") {
        format!("\"{path}\" {verb}")
    } else {
        format!("'{}' {verb}", path.replace('\'', r"'\''"))
    }
}

/// A `UserPromptSubmit` group is ours when it has hooks and every one of
/// them invokes this executable (the group form).
fn group_is_ours(group: &Value, executable: &str) -> bool {
    matches!(
        group.get("hooks").and_then(Value::as_array),
        Some(list) if !list.is_empty() && list.iter().all(|hook| is_ours(hook, executable))
    )
}

/// An entry is ours when its command invokes this executable.
fn is_ours(entry: &Value, executable: &str) -> bool {
    entry
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.contains(executable))
}

/// The plan that adds (or refreshes) the two
/// entries for `executable`; `Ok(None)` when the file already holds exactly
/// them; `Err` naming the file when it is not valid JSON. Until the unit
/// lands, nothing is planned.
pub fn plan_install(executable: &Path) -> Result<Option<Plan>, String> {
    let path = path();
    let backup = backup_path(&path);
    plan_install_at(&path, &backup, executable)
}

/// Takes the target paths explicitly, so the tests run in a temp directory.
fn plan_install_at(path: &Path, backup: &Path, executable: &Path) -> Result<Option<Plan>, String> {
    let invalid = |why: String| {
        format!(
            "{} is not valid JSON ({why}); fix or move it, then run the installer again",
            path.display()
        )
    };
    let (old, original) = match std::fs::read(path) {
        Ok(bytes) => {
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|why| invalid(why.to_string()))?;
            if !value.is_object() {
                return Err(invalid("expected an object".into()));
            }
            (value, Some(bytes))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => (json!({}), None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };

    let mut new = old.clone();
    let obj = new.as_object_mut().expect("checked above");
    let exe = executable.display().to_string();

    // The status line: ours is added, or its command refreshed while
    // the engineer's `padding` and `refreshInterval` stand; a foreign entry
    // stays as it is.
    let status_command = command(executable, "statusline");
    match obj.get("statusLine").map(|entry| is_ours(entry, &exe)) {
        None => {
            obj.insert(
                "statusLine".into(),
                json!({
                    "type": "command",
                    "command": status_command,
                    "padding": 0,
                    "refreshInterval": 10
                }),
            );
        }
        Some(true) => {
            let entry = obj
                .get_mut("statusLine")
                .and_then(Value::as_object_mut)
                .expect("checked by is_ours");
            entry.insert("command".into(), json!(status_command));
        }
        Some(false) => {}
    }

    // The title hook: one group with no matcher, pushed after every
    // group the engineer keeps.
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        return Err(invalid("\"hooks\" is not an object".into()));
    }
    let hook_object = hooks.as_object_mut().expect("checked above");
    let groups = match hook_object.remove("UserPromptSubmit") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(groups)) => groups,
        Some(Value::Object(group)) => vec![Value::Object(group)],
        Some(other) => {
            return Err(invalid(format!(
                "\"hooks.UserPromptSubmit\" is neither an object nor an array: {other}"
            )));
        }
    };
    let mut groups: Vec<Value> = groups
        .into_iter()
        .filter(|group| match group.get("hooks").and_then(Value::as_array) {
            Some(list) if !list.is_empty() && list.iter().all(|hook| is_ours(hook, &exe)) => {
                false // ours alone: the previous install's group
            }
            _ => true,
        })
        .collect();
    groups.push(json!({
        "hooks": [{
            "type": "command",
            "command": command(executable, "title-hook"),
            "timeout": 2
        }]
    }));
    hook_object.insert("UserPromptSubmit".into(), Value::Array(groups));

    if new == old {
        return Ok(None);
    }
    let mut bytes = serde_json::to_vec_pretty(&new).map_err(|why| why.to_string())?;
    bytes.push(b'\n');
    let backup = match &original {
        Some(bytes) if !backup.exists() => Some(bytes.clone()),
        _ => None,
    };
    Ok(Some(Plan {
        path: path.to_path_buf(),
        bytes,
        backup,
    }))
}

/// The foreign status-line command when `path`'s
/// file holds a `statusLine` that is not ours; `None` when the file is
/// missing, invalid, or the entry is ours (so ours is never displaced).
pub fn foreign_status_line(executable: &Path) -> Option<String> {
    foreign_status_line_at(&path(), executable)
}

fn foreign_status_line_at(path: &Path, executable: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    let entry = value.get("statusLine")?;
    if is_ours(entry, &executable.display().to_string()) {
        return None;
    }
    entry
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The plan that removes only the two entries for
/// `executable`; `Ok(None)` when the file is missing or holds nothing of
/// ours; `Err` naming the file when it is not valid JSON (install's shape).
pub fn plan_uninstall(executable: &Path) -> Result<Option<Plan>, String> {
    let path = path();
    let backup = backup_path(&path);
    plan_uninstall_at(&path, &backup, executable)
}

/// Takes the target paths explicitly, so the tests run in a temp
/// directory. The plan's `backup` is always `None`: an uninstall restores,
/// it never re-backs-up.
fn plan_uninstall_at(
    path: &Path,
    backup: &Path,
    executable: &Path,
) -> Result<Option<Plan>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let invalid = |why: String| {
        format!(
            "{} is not valid JSON ({why}); fix or move it, then run the installer again",
            path.display()
        )
    };
    let old: Value = serde_json::from_slice(&bytes).map_err(|why| invalid(why.to_string()))?;
    if !old.is_object() {
        return Err(invalid("expected an object".into()));
    }
    let exe = executable.display().to_string();

    let mut new = old.clone();
    let obj = new.as_object_mut().expect("checked above");

    // The status line: gone when it is ours, a foreign one stays.
    if obj
        .get("statusLine")
        .is_some_and(|entry| is_ours(entry, &exe))
    {
        obj.remove("statusLine");
    }

    // The title hook: every `UserPromptSubmit` group whose hooks are all
    // ours goes; a group with any foreign hook stays; an event left empty
    // goes with its last group, and an empty `hooks` with it.
    if let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) {
        let decision = match hooks.get("UserPromptSubmit") {
            None => None,
            Some(Value::Array(groups)) => {
                let kept: Vec<Value> = groups
                    .iter()
                    .filter(|group| !group_is_ours(group, &exe))
                    .cloned()
                    .collect();
                if kept.len() == groups.len() {
                    None // nothing of ours: untouched
                } else if kept.is_empty() {
                    Some(None) // the event is empty: gone with it
                } else {
                    Some(Some(Value::Array(kept)))
                }
            }
            Some(entry) if entry.is_object() || entry.is_null() => {
                group_is_ours(entry, &exe).then_some(None)
            }
            Some(other) => {
                return Err(invalid(format!(
                    "\"hooks.UserPromptSubmit\" is neither an object nor an array: {other}"
                )));
            }
        };
        match decision {
            Some(Some(value)) => {
                hooks.insert("UserPromptSubmit".into(), value);
            }
            Some(None) => {
                hooks.remove("UserPromptSubmit");
            }
            None => {}
        }
    }
    if obj
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|hooks| hooks.is_empty())
    {
        obj.remove("hooks");
    }

    if new == old {
        return Ok(None);
    }

    // The backup is restored (its own bytes written back) only when
    // doing so cannot overwrite later edits — that is, only when it equals
    // the result. Any other backup stays; a later uninstall tries again.
    if let Ok(backup_bytes) = std::fs::read(backup)
        && let Ok(backup_value) = serde_json::from_slice::<Value>(&backup_bytes)
        && backup_value == new
    {
        return Ok(Some(Plan {
            path: path.to_path_buf(),
            bytes: backup_bytes,
            backup: None,
        }));
    }
    let mut bytes = serde_json::to_vec_pretty(&new).map_err(|why| why.to_string())?;
    bytes.push(b'\n');
    Ok(Some(Plan {
        path: path.to_path_buf(),
        bytes,
        backup: None,
    }))
}

/// After a commit, drop the backup beside `path` when
/// the file now equals it byte for byte (a byte-exact restore left nothing
/// to restore). Any other backup stays for a later uninstall.
pub fn remove_backup(path: &Path) {
    let backup = backup_path(path);
    let same = match (std::fs::read(&backup), std::fs::read(path)) {
        (Ok(restored), Ok(current)) => restored == current,
        _ => false,
    };
    if same {
        let _ = std::fs::remove_file(&backup);
    }
}

/// Write the backup (when the plan carries one and none
/// exists) and then the file, atomically.
pub fn commit(plan: &Plan) -> Result<(), String> {
    if let Some(original) = &plan.backup {
        let backup = backup_path(&plan.path);
        if !backup.exists() {
            crate::state::write_private_atomic(&backup, original)
                .map_err(|why| format!("{}: {why}", backup.display()))?;
        }
    }
    crate::state::write_private_atomic(&plan.path, &plan.bytes)
        .map_err(|why| format!("{}: {why}", plan.path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A fresh temp directory no other test shares.
    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("jaynshare-settings-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// A settings file holding our two entries and nothing else.
    fn ours_only(executable: &Path) -> Value {
        json!({
            "statusLine": {"type": "command", "command": command(executable, "statusline")},
            "hooks": {"UserPromptSubmit": [
                {"hooks": [{"type": "command", "command": command(executable, "title-hook")}]}
            ]}
        })
    }

    #[test]
    fn a_fresh_file_gets_both_entries_and_no_backup() {
        let dir = temp("fresh");
        let path = dir.join("settings.json");
        let backup = backup_path(&path);
        let executable = dir.join("bin/jaynshare");
        let plan = plan_install_at(&path, &backup, &executable)
            .unwrap()
            .expect("a fresh file always changes");
        assert_eq!(plan.backup, None, "nothing to back up");
        let new: Value = serde_json::from_slice(&plan.bytes).expect("pretty JSON");
        let status = &new["statusLine"];
        assert_eq!(status["type"], "command");
        assert_eq!(status["padding"], 0);
        assert_eq!(status["refreshInterval"], 10);
        assert_eq!(status["command"], command(&executable, "statusline"));
        let groups = new["hooks"]["UserPromptSubmit"].as_array().expect("array");
        assert_eq!(groups.len(), 1);
        let hook = &groups[0]["hooks"][0];
        assert_eq!(hook["command"], command(&executable, "title-hook"));
        assert_eq!(hook["timeout"], 2);
        assert!(hook.get("matcher").is_none(), "no matcher");
        commit(&plan).expect("commit");
        assert_eq!(fs::read(&path).expect("file"), plan.bytes);
    }

    #[test]
    fn unrelated_keys_keep_their_order() {
        let dir = temp("order");
        let path = dir.join("settings.json");
        fs::write(
            &path,
            r##"{"theme": "dark", "model": "opus", "hooks": {"PreToolUse": []}, "other": 1}"##,
        )
        .unwrap();
        let plan = plan_install_at(&path, &backup_path(&path), &dir.join("bin/jaynshare"))
            .unwrap()
            .unwrap();
        let new: Value = serde_json::from_slice(&plan.bytes).unwrap();
        let keys: Vec<_> = new.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["theme", "model", "hooks", "other", "statusLine"]);
        assert_eq!(
            new["hooks"]["PreToolUse"],
            json!([]),
            "no other hook event is touched"
        );
    }

    #[test]
    fn a_second_install_changes_nothing_and_the_backup_is_written_once() {
        let dir = temp("idempotent");
        let path = dir.join("settings.json");
        let backup = backup_path(&path);
        let executable = dir.join("bin/jaynshare");
        fs::write(&path, r#"{"theme": "dark"}"#).unwrap();
        let plan = plan_install_at(&path, &backup, &executable)
            .unwrap()
            .unwrap();
        assert_eq!(plan.backup.as_deref(), Some(&br#"{"theme": "dark"}"#[..]));
        commit(&plan).unwrap();
        let original = fs::read(&backup).unwrap();

        assert_eq!(
            plan_install_at(&path, &backup, &executable).unwrap(),
            None,
            "idempotent"
        );

        // A second, different install: the engineer's file changed again.
        fs::write(&path, r#"{"extra": 1, "theme": "dark"}"#).unwrap();
        let plan = plan_install_at(&path, &backup, &executable)
            .unwrap()
            .unwrap();
        assert_eq!(plan.backup, None, "an existing backup is never replaced");
        commit(&plan).unwrap();
        assert_eq!(fs::read(&backup).unwrap(), original);
    }

    #[test]
    fn invalid_json_stops_with_the_path() {
        let dir = temp("invalid");
        let path = dir.join("settings.json");
        let executable = dir.join("bin/jaynshare");
        for body in ["{\"theme\": ", "[1]"] {
            fs::write(&path, body).unwrap();
            let err = plan_install_at(&path, &backup_path(&path), &executable).unwrap_err();
            assert!(
                err.contains("settings.json") && err.contains("not valid JSON"),
                "{err}"
            );
            assert_eq!(fs::read(&path).unwrap(), body.as_bytes(), "never rewritten");
        }
    }

    #[test]
    fn a_foreign_user_prompt_submit_group_stays_and_ours_is_added_once() {
        let dir = temp("foreign");
        let path = dir.join("settings.json");
        let executable = dir.join("bin/jaynshare");
        let ours = json!({"hooks": {"UserPromptSubmit": [
            {"hooks": [{"type": "command", "command": "echo hi"}]},
            {"hooks": [{"type": "command", "command": command(&executable, "title-hook"), "timeout": 2}]}
        ]}});
        fs::write(&path, ours.to_string()).unwrap();
        let plan = plan_install_at(&path, &backup_path(&path), &executable)
            .unwrap()
            .unwrap();
        let groups =
            serde_json::from_slice::<Value>(&plan.bytes).unwrap()["hooks"]["UserPromptSubmit"]
                .as_array()
                .expect("array")
                .clone();
        assert_eq!(groups.len(), 2, "ours replaced by ours, the foreign kept");
        assert_eq!(groups[0]["hooks"][0]["command"], "echo hi");
        assert_eq!(
            groups[1]["hooks"][0]["command"],
            command(&executable, "title-hook")
        );
        commit(&plan).unwrap();
        assert_eq!(
            plan_install_at(&path, &backup_path(&path), &executable).unwrap(),
            None,
            "the added group is recognized as ours"
        );
    }

    #[test]
    fn the_engineers_refresh_interval_and_padding_survive() {
        let dir = temp("interval");
        let path = dir.join("settings.json");
        let executable = dir.join("bin/jaynshare");
        let unquoted = format!("{} statusline", executable.display());
        let existing = json!({"statusLine": {
            "type": "command", "command": unquoted, "padding": 7, "refreshInterval": 99
        }});
        fs::write(&path, existing.to_string()).unwrap();
        let plan = plan_install_at(&path, &backup_path(&path), &executable)
            .unwrap()
            .unwrap();
        let status = serde_json::from_slice::<Value>(&plan.bytes).unwrap()["statusLine"].clone();
        assert_eq!(status["refreshInterval"], 99);
        assert_eq!(status["padding"], 7);
        assert_eq!(status["command"], command(&executable, "statusline"));
    }

    #[test]
    fn uninstall_removes_ours_and_keeps_every_foreign_entry() {
        let dir = temp("uninstall-foreign");
        let path = dir.join("settings.json");
        let executable = dir.join("bin/jaynshare");
        let existing = json!({
            "theme": "dark",
            "statusLine": {"type": "command", "command": "other-tool line"},
            "hooks": {
                "UserPromptSubmit": [
                    {"hooks": [{"type": "command", "command": "other-tool title"}]},
                    {"hooks": [{"type": "command", "command": command(&executable, "title-hook"), "timeout": 2}]}
                ],
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]
            }
        });
        fs::write(&path, existing.to_string()).unwrap();
        let plan = plan_uninstall_at(&path, &backup_path(&path), &executable)
            .unwrap()
            .expect("our two entries are there");
        assert_eq!(plan.backup, None, "an uninstall never carries a backup");
        let new: Value = serde_json::from_slice(&plan.bytes).unwrap();
        assert_eq!(
            new["statusLine"]["command"], "other-tool line",
            "the foreign status line stays"
        );
        let groups = new["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "only our group went");
        assert_eq!(groups[0]["hooks"][0]["command"], "other-tool title");
        assert_eq!(
            new["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "echo hi",
            "no other hook event is touched"
        );
        assert_eq!(new["theme"], "dark");
    }

    #[test]
    fn uninstall_removes_hooks_when_it_held_only_ours() {
        let dir = temp("uninstall-hooks");
        let path = dir.join("settings.json");
        let executable = dir.join("bin/jaynshare");
        fs::write(&path, ours_only(&executable).to_string()).unwrap();
        let plan = plan_uninstall_at(&path, &backup_path(&path), &executable)
            .unwrap()
            .unwrap();
        let new: Value = serde_json::from_slice(&plan.bytes).unwrap();
        assert_eq!(
            new.as_object().unwrap().len(),
            0,
            "both entries were everything: the file is empty"
        );
        assert!(new.get("hooks").is_none(), "`hooks` is gone with its group");
    }

    #[test]
    fn uninstall_restores_the_backup_byte_for_byte_when_nothing_else_changed() {
        let dir = temp("uninstall-restore");
        let path = dir.join("settings.json");
        let backup = backup_path(&path);
        let executable = dir.join("bin/jaynshare");
        fs::write(&path, br#"{"theme": "dark"}"#).unwrap();
        let plan = plan_install_at(&path, &backup, &executable)
            .unwrap()
            .unwrap();
        commit(&plan).unwrap();
        let original = fs::read(&backup).unwrap();

        let plan = plan_uninstall_at(&path, &backup, &executable)
            .unwrap()
            .expect("our entries are there");
        assert_eq!(plan.bytes, original, "the backup's own bytes");
        assert_eq!(plan.backup, None);
        commit(&plan).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original, "a byte-exact restore");
    }

    #[test]
    fn uninstall_after_an_unrelated_edit_writes_the_result_and_keeps_the_backup() {
        let dir = temp("uninstall-edit");
        let path = dir.join("settings.json");
        let backup = backup_path(&path);
        let executable = dir.join("bin/jaynshare");
        fs::write(&backup, br#"{"theme": "dark"}"#).unwrap();
        let plan = plan_install_at(&path, &backup, &executable)
            .unwrap()
            .unwrap();
        commit(&plan).unwrap();
        // The engineer's unrelated edit after the install.
        let mut edited = ours_only(&executable);
        edited["model"] = json!("opus");
        fs::write(&path, edited.to_string()).unwrap();

        let plan = plan_uninstall_at(&path, &backup, &executable)
            .unwrap()
            .expect("our entries are there");
        let new: Value = serde_json::from_slice(&plan.bytes).unwrap();
        assert_eq!(
            new,
            json!({"model": "opus"}),
            "our entries gone, the edit kept"
        );
        assert_eq!(
            fs::read(&backup).unwrap(),
            br#"{"theme": "dark"}"#,
            "the backup stays: restoring it would overwrite the edit"
        );
    }

    #[test]
    fn uninstall_of_a_missing_file_is_nothing() {
        let dir = temp("uninstall-missing");
        let path = dir.join("settings.json");
        assert_eq!(
            plan_uninstall_at(&path, &backup_path(&path), &dir.join("bin/jaynshare")).unwrap(),
            None
        );
    }

    #[test]
    fn foreign_status_line_is_the_command_of_an_entry_that_is_not_ours() {
        let dir = temp("foreign-status");
        let path = dir.join("settings.json");
        let executable = dir.join("bin/jaynshare");

        fs::write(
            &path,
            r#"{"statusLine": {"type": "command", "command": "other-tool line", "padding": 1}}"#,
        )
        .unwrap();
        assert_eq!(
            foreign_status_line_at(&path, &executable).as_deref(),
            Some("other-tool line"),
            "a foreign status line is reported"
        );

        let own = json!({"statusLine": {"type": "command", "command": command(&executable, "statusline")}});
        fs::write(&path, own.to_string()).unwrap();
        assert_eq!(
            foreign_status_line_at(&path, &executable),
            None,
            "our own status line is not foreign"
        );

        let _ = fs::remove_file(&path);
        assert_eq!(
            foreign_status_line_at(&path, &executable),
            None,
            "a missing file has no foreign status line"
        );

        fs::write(&path, "{\"theme\": ").unwrap();
        assert_eq!(
            foreign_status_line_at(&path, &executable),
            None,
            "an invalid file has no foreign status line"
        );
    }
}
