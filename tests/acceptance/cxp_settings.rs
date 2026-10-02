//! The Claude Code settings entries — install, update, uninstall, foreign
//! entries, the theme — and the client documentation. The settings file is
//! `<home>/.claude/settings.json`.

#[allow(unused_imports)]
use crate::client_fx::*;
#[allow(unused_imports)]
use crate::harness::*;

/// The kit's README documents what the pool records: every
/// field name the product's audit record actually carries appears in
/// the documentation, wire capture is stated as the only way bodies are
/// recorded, and the account-bound-feature statements are present.
#[tokio::test(flavor = "multi_thread")]
async fn the_kit_documentation_states_what_is_recorded() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let readme = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/kit/README.txt"),
    )
    .expect("the kit's README is in the repository");

    // The product's own audit field names are all documented: start a pool,
    // route one prompt, and check the README against the record it wrote.
    let instance = Instance::start("kit-documentation-states").await;
    add_two(&instance);
    let answer = send(instance.addr, messages(haiku_prompt())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let record = instance.last_record(1);
    for field in record.as_object().expect("an audit record object") {
        assert!(
            readme.contains(field.0.as_str()),
            "the README does not document audit field `{}` (the record: {record})",
            field.0
        );
    }

    assert!(readme.contains("source address"), "{readme}");
    assert!(readme.contains("wire capture"), "{readme}");
    assert!(readme.contains("bodies"), "{readme}");
    assert!(readme.contains("jaynshare status"), "{readme}");
    assert!(
        readme
            .lines()
            .any(|line| line.contains("only") && line.contains("capture")),
        "a line states bodies are recorded only while capture is on: {readme}"
    );

    // Remote Control does not work, the connector warning is
    // expected, and the engineer's own login is never used.
    assert!(readme.contains("Remote Control"), "{readme}");
    assert!(readme.contains("connector"), "{readme}");
    assert!(readme.contains("never used"), "{readme}");

    // Plain ASCII, every line within an 80-column terminal.
    for (number, line) in readme.lines().enumerate() {
        assert!(line.is_ascii(), "line {} is not ASCII: {line}", number + 1);
        assert!(
            line.chars().count() <= 80,
            "line {} is {} columns: {line}",
            number + 1,
            line.chars().count()
        );
    }
}

use crate::enrol::{
    Operator, client_platform, config_root, enrol_into, installed_binary, native_payload,
    try_enrol_into,
};

/// An enrollment
/// installs exactly the two entries into an existing settings file: every
/// key keeps its place, the original bytes are backed up once, and an
/// invalid file stops the install before the code is spent.
#[tokio::test(flavor = "multi_thread")]
async fn settings_install_keeps_keys_is_idempotent_and_backed_up() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("settings-install-keeps-keys").await;
    let home = scratch("settings-install-keeps-keys-engineer").join("home");
    private_dir(&home);
    let settings = home.join(".claude/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = r#"{
  "theme": "dark",
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "echo hi"
          }
        ]
      }
    ]
  }
}"#;
    std::fs::write(&settings, original).unwrap();

    enrol_into(&operator, "alpha", "Alpha Desk", &home).await;

    let installed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let keys: Vec<&String> = installed.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["theme", "model", "hooks", "statusLine"], "");
    assert_eq!(installed["theme"], "dark");
    assert_eq!(installed["model"], "opus");
    assert_eq!(
        installed["hooks"]["PreToolUse"],
        serde_json::json!([{
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "echo hi"}]
        }]),
        "the PreToolUse group is untouched"
    );
    let binary = installed_binary(&home);
    let status = &installed["statusLine"];
    let status_command = status["command"].as_str().unwrap();
    assert!(
        status_command.contains(binary.display().to_string().as_str()),
        "the installed client by absolute path: {status_command}"
    );
    assert!(status_command.ends_with("statusline"), "{status_command}");
    assert_eq!(status["type"], "command");
    assert_eq!(status["padding"], 0);
    assert_eq!(status["refreshInterval"], 10, "/");
    let groups = installed["hooks"]["UserPromptSubmit"]
        .as_array()
        .expect("the hook groups");
    assert_eq!(groups.len(), 1, "exactly one UserPromptSubmit group");
    let hook = &groups[0]["hooks"][0];
    let hook_command = hook["command"].as_str().unwrap();
    assert!(hook_command.ends_with("title-hook"), "{hook_command}");
    assert!(
        hook_command.contains(binary.display().to_string().as_str()),
        "{hook_command}"
    );
    assert_eq!(hook["timeout"], 2, "");
    assert!(hook.get("matcher").is_none(), "no matcher");

    assert_eq!(
        std::fs::read(settings.with_file_name("settings.json.jaynshare-backup")).unwrap(),
        original.as_bytes(),
        "the backup holds the bytes as they were before the install"
    );

    // An invalid file stops the join before the claim.
    let home2 = scratch("settings-install-keeps-keys-invalid").join("home");
    private_dir(&home2);
    let settings2 = home2.join(".claude/settings.json");
    std::fs::create_dir_all(settings2.parent().unwrap()).unwrap();
    std::fs::write(&settings2, "{\"theme\": ").unwrap();
    let (exit, transcript) = try_enrol_into(&operator, "beta", "Beta Desk", &home2).await;
    assert_ne!(exit, 0, "the install stops: {transcript}");
    assert!(transcript.contains("settings.json"), "{transcript}");
    assert!(transcript.contains("not valid JSON"), "{transcript}");
    assert_eq!(
        std::fs::read(&settings2).unwrap(),
        b"{\"theme\": ",
        "an invalid file is never rewritten"
    );
    assert!(
        !config_root(&home2).join("client/client.toml").exists(),
        "the code is unspent: nothing was installed"
    );
}

/// The
/// installed entries carry the 10 s refresh interval, an engineer's own
/// changed interval and their keys survive a second install, and the two
/// entries are still exactly one group of ours.
#[tokio::test(flavor = "multi_thread")]
async fn an_engineers_refresh_interval_survives_a_second_install() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("engineers-refresh-interval").await;
    let home = scratch("engineers-refresh-interval-engineer").join("home");
    private_dir(&home);
    enrol_into(&operator, "alpha", "Alpha Desk", &home).await;

    let settings = home.join(".claude/settings.json");
    let installed: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap())
        .expect("the install wrote valid JSON");
    assert_eq!(
        installed["statusLine"]["refreshInterval"], 10,
        "the installed refresh interval is 10 s"
    );

    // The engineer's own changes: their interval and one key of their own.
    let mut edited = installed;
    edited["statusLine"]["refreshInterval"] = json!(30);
    edited["model"] = json!("opus");
    std::fs::write(&settings, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();

    let (exit, stdout, stderr) = cli_raw(
        &[
            "update",
            "--from",
            &operator.kit_path().display().to_string(),
        ],
        &isolated_env(&home),
        None,
    );
    assert_eq!(exit, 0, "the update installs: {stdout}{stderr}");

    let after: Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).expect("JSON");
    assert_eq!(
        after["statusLine"]["refreshInterval"], 30,
        "the engineer's interval survives the second install"
    );
    assert_eq!(after["model"], "opus", "the engineer's key stands");
    let binary = installed_binary(&home);
    let groups = after["hooks"]["UserPromptSubmit"]
        .as_array()
        .expect("the hook groups");
    assert_eq!(groups.len(), 1, "exactly one UserPromptSubmit group");
    assert!(
        groups[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains(binary.display().to_string().as_str()),
        "the one group is ours"
    );
    assert_eq!(after, edited, "no other key changed");
}

/// An update asks for no code and
/// replaces only the executable; a failed post-update check rolls the
/// executable and the settings entries back; a tampered kit changes
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn update_keeps_the_client_files_and_rolls_back_on_failure() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let mut operator = Operator::start("update-keeps-client").await;
    let home = scratch("update-keeps-client-engineer").join("home");
    private_dir(&home);
    enrol_into(&operator, "alpha", "Alpha Desk", &home).await;

    let client_dir = config_root(&home).join("client");
    let toml_path = client_dir.join("client.toml");
    let secret_path = client_dir.join("client-secret");
    let ca_path = client_dir.join("ca.pem");
    let binary = installed_binary(&home);
    let settings = home.join(".claude/settings.json");
    let toml_before = std::fs::read(&toml_path).expect("client.toml");
    let secret_before = std::fs::read(&secret_path).expect("client-secret");
    let settings_before = std::fs::read(&settings).expect("settings.json");
    let ca_before = std::fs::read(&ca_path).expect("every enrollment installs ca.pem");

    // The happy update: only the executable changes, and no code is asked.
    let native = native_payload();
    let kit = operator.kit_with_payload(native, b"new executable");
    let (exit, stdout, stderr) = cli_raw(
        &["update", "--from", &kit.display().to_string()],
        &isolated_env(&home),
        None,
    );
    assert_eq!(exit, 0, "the update installs: {stdout}{stderr}");
    assert!(
        !stdout.contains("enrollment code") && !stderr.contains("enrollment code"),
        "no enrollment code is asked: {stdout}{stderr}"
    );
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        b"new executable",
        "the kit's executable is installed"
    );
    assert_eq!(
        std::fs::read(&toml_path).unwrap(),
        toml_before,
        "client.toml stands"
    );
    assert_eq!(
        std::fs::read(&secret_path).unwrap(),
        secret_before,
        "client-secret stands"
    );
    assert_eq!(
        std::fs::read(&settings).unwrap(),
        settings_before,
        "the entries are already exact: nothing rewritten"
    );
    assert_eq!(std::fs::read(&ca_path).unwrap(), ca_before, "ca.pem stands");

    // A failed post-update check rolls the replacements back.
    operator.instance.stop();
    let third = operator.kit_with_payload(native, b"newer executable");
    let (exit, _, stderr) = cli_raw(
        &["update", "--from", &third.display().to_string()],
        &isolated_env(&home),
        None,
    );
    assert_eq!(exit, 4, "the check fails with the server gone: {stderr}");
    assert!(
        stderr.contains("rolled back"),
        "the engineer is told of the rollback: {stderr}"
    );
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        b"new executable",
        "the previous executable is back"
    );
    assert_eq!(
        std::fs::read(&settings).unwrap(),
        settings_before,
        "the settings entries rolled back"
    );
    assert_eq!(
        std::fs::read(&toml_path).unwrap(),
        toml_before,
        "client.toml stands"
    );
    assert_eq!(
        std::fs::read(&secret_path).unwrap(),
        secret_before,
        "client-secret stands"
    );

    // A tampered kit is refused before anything is written.
    let tampered = operator.kit_with_payload(native, b"tampered executable");
    let mut raw = std::fs::read(&tampered).expect("the kit bytes");
    let at = raw
        .windows(b"tampered executable".len())
        .position(|w| w == b"tampered executable")
        .expect("the payload member's bytes in the archive");
    raw[at] ^= 0x01;
    std::fs::write(&tampered, raw).unwrap();
    let (exit, _, stderr) = cli_raw(
        &["update", "--from", &tampered.display().to_string()],
        &isolated_env(&home),
        None,
    );
    assert_eq!(exit, 17, "the tampered kit is refused: {stderr}");
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        b"new executable",
        "the executable stands"
    );
    assert_eq!(
        std::fs::read(&toml_path).unwrap(),
        toml_before,
        "client.toml stands"
    );
    assert_eq!(
        std::fs::read(&secret_path).unwrap(),
        secret_before,
        "client-secret stands"
    );
    assert_eq!(
        std::fs::read(&settings).unwrap(),
        settings_before,
        "the settings entries stand"
    );
}

/// Uninstalling removes only the two
/// entries this product installed: the foreign status line, the foreign
/// `UserPromptSubmit` group, `PreToolUse` and `theme` all stay, and the
/// executable and the files are gone.
#[tokio::test(flavor = "multi_thread")]
async fn uninstall_removes_the_two_entries_and_nothing_else() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("uninstall-removes-two").await;
    let home = scratch("uninstall-removes-two-engineer").join("home");
    private_dir(&home);
    let settings = home.join(".claude/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = r#"{
  "theme": "dark",
  "statusLine": {
    "type": "command",
    "command": "other-tool line"
  },
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "other-tool title"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "echo hi"
          }
        ]
      }
    ]
  }
}"#;
    std::fs::write(&settings, original).unwrap();

    enrol_into(&operator, "alpha", "Alpha Desk", &home).await;

    let (exit, stdout, stderr) = cli_raw(&["uninstall"], &isolated_env(&home), None);
    assert_eq!(exit, 0, "uninstall: {stdout}{stderr}");

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap())
            .expect("the settings file is still JSON");
    let expected: serde_json::Value = serde_json::from_str(original).unwrap();
    assert_eq!(
        after, expected,
        "the pre-seeded value, byte-exact restored over our entries"
    );
    let text = std::fs::read_to_string(&settings).unwrap();
    assert!(
        !text.contains("bin/jaynshare"),
        "no command of ours anywhere: {text}"
    );
    assert!(
        !config_root(&home).join("client").exists(),
        "the client files are gone"
    );
    assert!(
        !installed_binary(&home).exists(),
        "the installed executable is gone"
    );
}

/// Uninstalling after an
/// unrelated Claude settings edit keeps the edit (the backup is not
/// restored), leaves the credentials and transcripts byte-identical, and
/// removes the executable and the client files; without the edit, the
/// backup is restored byte for byte and then removed.
#[tokio::test(flavor = "multi_thread")]
async fn uninstall_after_an_unrelated_edit_keeps_it() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("uninstall-unrelated-edit").await;
    let home = scratch("uninstall-unrelated-edit-engineer").join("home");
    private_dir(&home);
    enrol_into(&operator, "alpha", "Alpha Desk", &home).await;

    // The engineer's unrelated edit after the install.
    let settings = home.join(".claude/settings.json");
    let mut edited: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap())
            .expect("the installed settings file is JSON");
    edited["model"] = serde_json::json!("opus");
    std::fs::write(
        &settings,
        serde_json::to_string_pretty(&edited).unwrap() + "\n",
    )
    .unwrap();
    // Claude Code's own data, which the uninstall must never touch.
    let claude = home.join(".claude");
    std::fs::write(claude.join(".credentials.json"), br#"{"token": "keep-me"}"#).unwrap();
    std::fs::create_dir_all(claude.join("projects/p")).unwrap();
    std::fs::write(claude.join("projects/p/s.jsonl"), b"transcript\n").unwrap();

    let (exit, stdout, stderr) = cli_raw(&["uninstall", "--json"], &isolated_env(&home), None);
    assert_eq!(exit, 0, "uninstall: {stdout}{stderr}");
    let envelope: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("the CLI envelope");
    let result = &envelope["result"];
    let files = result["files"].as_array().expect("the removed paths");
    let listed = |path: &str| {
        files
            .iter()
            .any(|entry| entry.as_str().is_some_and(|f| f.ends_with(path)))
    };
    assert!(listed("client.toml"), "files: {:?}", files);
    assert!(listed("client-secret"), "files: {:?}", files);

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap())
            .expect("the settings file is still JSON");
    assert_eq!(
        after,
        serde_json::json!({"model": "opus"}),
        "our entries gone, the edit kept"
    );
    assert_eq!(
        std::fs::read(claude.join(".credentials.json")).unwrap(),
        br#"{"token": "keep-me"}"#,
        "the credentials are byte-identical"
    );
    assert_eq!(
        std::fs::read(claude.join("projects/p/s.jsonl")).unwrap(),
        b"transcript\n",
        "the transcript is byte-identical"
    );
    assert!(
        !installed_binary(&home).exists(),
        "the installed executable is gone"
    );
    assert!(
        !config_root(&home).join("client").exists(),
        "the client files are gone"
    );

    // Without an edit after the install, the backup is restored byte for
    // byte and then gone with it.
    let home2 = scratch("uninstall-unrelated-edit-light").join("home");
    private_dir(&home2);
    let settings2 = home2.join(".claude/settings.json");
    std::fs::create_dir_all(settings2.parent().unwrap()).unwrap();
    std::fs::write(&settings2, br#"{"theme": "light"}"#).unwrap();
    enrol_into(&operator, "beta", "Beta Desk", &home2).await;

    let (exit, stdout, stderr) = cli_raw(&["uninstall", "--json"], &isolated_env(&home2), None);
    assert_eq!(exit, 0, "uninstall: {stdout}{stderr}");
    assert_eq!(
        std::fs::read(&settings2).unwrap(),
        br#"{"theme": "light"}"#,
        "the backup restored byte for byte"
    );
    assert!(
        !settings2
            .with_file_name("settings.json.jaynshare-backup")
            .exists(),
        "the restored backup is removed"
    );
}

/// A settings file already carrying a foreign status-line
/// command and a foreign `UserPromptSubmit` hook: the install adds its own
/// hook without displacing either, a second install is idempotent, and
/// uninstall removes only its own.
#[tokio::test(flavor = "multi_thread")]
async fn settings_foreign_entries_survive_install_update_and_uninstall() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("learned-weekly-reset-settings").await;
    let home = scratch("learned-weekly-reset-settings-engineer").join("home");
    private_dir(&home);
    let settings = home.join(".claude/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = r#"{
  "statusLine": {
    "type": "command",
    "command": "other-tool line",
    "padding": 1
  },
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "other-tool title"
          }
        ]
      }
    ]
  }
}"#;
    std::fs::write(&settings, original).unwrap();

    let (exit, transcript) = try_enrol_into(&operator, "alpha", "Alpha Desk", &home).await;
    assert_eq!(exit, 0, "enrol alpha: {transcript}");
    assert!(
        transcript.contains("notice:") && transcript.contains("other-tool line"),
        "the engineer is told the status line was left in place: {transcript}"
    );

    let after_enrol: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap())
            .expect("the install wrote valid JSON");
    assert_eq!(
        after_enrol["statusLine"],
        serde_json::json!({
            "type": "command",
            "command": "other-tool line",
            "padding": 1
        }),
        "/: the foreign status line is unchanged and ours was not written"
    );
    let binary = installed_binary(&home);
    let groups = after_enrol["hooks"]["UserPromptSubmit"]
        .as_array()
        .expect("the hook groups");
    assert_eq!(groups.len(), 2, "the foreign group first, then ours");
    assert_eq!(
        groups[0]["hooks"][0]["command"], "other-tool title",
        "the foreign group is unchanged and first"
    );
    let ours = &groups[1]["hooks"][0];
    assert!(
        ours["command"].as_str().unwrap().ends_with("title-hook"),
        "our group is second: {}",
        ours["command"]
    );
    assert!(
        ours["command"]
            .as_str()
            .unwrap()
            .contains(binary.display().to_string().as_str()),
        "ours points at the installed client"
    );
    assert_eq!(ours["timeout"], 2, "");
    let after_enrol_bytes = std::fs::read(&settings).unwrap();

    // A second install (an update) changes nothing: idempotent.
    let (exit, stdout, stderr) = cli_raw(
        &[
            "update",
            "--from",
            &operator.kit_path().display().to_string(),
        ],
        &isolated_env(&home),
        None,
    );
    assert_eq!(exit, 0, "the update installs: {stdout}{stderr}");
    assert_eq!(
        std::fs::read(&settings).unwrap(),
        after_enrol_bytes,
        "the second install is idempotent"
    );

    // Uninstall removes only our entries; the foreign ones stay.
    let (exit, stdout, stderr) = cli_raw(&["uninstall"], &isolated_env(&home), None);
    assert_eq!(exit, 0, "uninstall: {stdout}{stderr}");
    let after_uninstall: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap())
            .expect("the settings file is still JSON");
    let expected: serde_json::Value = serde_json::from_str(original).unwrap();
    assert_eq!(after_uninstall, expected, "only the foreign entries remain");
}

/// The client never writes or changes the
/// engineer's theme or colours: an existing `theme` survives install and
/// update, and a home without a settings file never gains one.
#[tokio::test(flavor = "multi_thread")]
async fn no_theme_key_is_written_or_changed() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    let operator = Operator::start("no-theme-key-written").await;

    // A home with the engineer's own theme: it survives everything.
    let home = scratch("no-theme-key-written-theme").join("home");
    private_dir(&home);
    let settings = home.join(".claude/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(&settings, br#"{"theme": "light-daltonized"}"#).unwrap();

    enrol_into(&operator, "alpha", "Alpha Desk", &home).await;
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap())
            .expect("the install wrote valid JSON");
    assert_eq!(
        after["theme"], "light-daltonized",
        "the engineer's theme survives the install"
    );

    let (exit, stdout, stderr) = cli_raw(
        &[
            "update",
            "--from",
            &operator.kit_path().display().to_string(),
        ],
        &isolated_env(&home),
        None,
    );
    assert_eq!(exit, 0, "the update installs: {stdout}{stderr}");
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).expect("JSON");
    assert_eq!(
        after["theme"], "light-daltonized",
        "the engineer's theme survives the update"
    );

    // A home without a settings file: no theme or colour key is written.
    let home2 = scratch("no-theme-key-written-fresh").join("home");
    private_dir(&home2);
    let settings2 = home2.join(".claude/settings.json");

    enrol_into(&operator, "beta", "Beta Desk", &home2).await;
    let (exit, stdout, stderr) = cli_raw(
        &[
            "update",
            "--from",
            &operator.kit_path().display().to_string(),
        ],
        &isolated_env(&home2),
        None,
    );
    assert_eq!(exit, 0, "the update installs: {stdout}{stderr}");
    let fresh: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings2).unwrap())
            .expect("the install wrote valid JSON");
    assert!(fresh.get("theme").is_none(), "no theme key: {fresh}");
    for key in fresh.as_object().unwrap().keys() {
        assert!(
            !key.to_lowercase().contains("color") && !key.to_lowercase().contains("colour"),
            "no colour key is written: {key}"
        );
    }
}

/// `client update` with no `--from`: the newest version's client kit is
/// fetched from a verified HTTPS mirror, verified before installation, and
/// the temporary kit file is gone afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn update_without_from_fetches_the_latest_kit() {
    if !client_platform() {
        eprintln!("skipping: enrollment: no client payload for this platform");
        return;
    }
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use http::Request;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut operator = Operator::start("update-keeps-client-b").await;
    let home = scratch("update-keeps-client-b-engineer").join("home");
    crate::harness::private_dir(&home);
    enrol_into(&operator, "alpha", "Alpha Desk", &home).await;

    let binary = installed_binary(&home);
    let native = native_payload();

    // The kit the origin will serve: the native payload carries bytes this
    // test can recognize.
    let kit = operator.kit_with_payload(native, b"fetched executable");
    let kit_bytes = std::fs::read(&kit).expect("the kit bytes");

    // The release host: TLS from the committed pair; `GET /latest` redirects
    // to the kit's release tag, `GET /v<version>/jaynshare-<version>-client-kit.zip`
    // serves the kit; anything else 404, every request counted.
    let version = "0.0.0-acceptance";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (cert, key_file) = crate::harness::stage_tls_pair(&home.join("tls"));
    let acceptor = {
        use rustls_pki_types::pem::PemObject;
        let key = rustls_pki_types::PrivateKeyDer::from_pem_file(&key_file).expect("fake key");
        let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(&cert)
            .expect("fake certificate")
            .collect::<Result<_, _>>()
            .expect("fake certificate parses");
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("the fake pair loads");
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
    };
    let kit_served = std::sync::Arc::new(kit_bytes);
    let requests = std::sync::Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let kit_served = kit_served.clone();
        let requests = requests.clone();
        async move {
            loop {
                let Ok((plain, _)) = listener.accept().await else {
                    return;
                };
                let Ok(stream) = acceptor.accept(plain).await else {
                    continue;
                };
                let kit_served = kit_served.clone();
                let requests = requests.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<_>| {
                        let kit_served = kit_served.clone();
                        let requests = requests.clone();
                        async move {
                            requests.fetch_add(1, AtomicOrdering::SeqCst);
                            let path = request.uri().path().to_string();
                            let (status, bytes) = if path == "/latest" {
                                (
                                    http::StatusCode::FOUND,
                                    format!("https://release.example/releases/tag/v{version}")
                                        .into_bytes(),
                                )
                            } else if path
                                == format!("/v{version}/jaynshare-{version}-client-kit.zip")
                            {
                                (http::StatusCode::OK, kit_served.as_ref().to_vec())
                            } else {
                                (http::StatusCode::NOT_FOUND, Vec::new())
                            };
                            let mut builder = Response::builder().status(status);
                            if status == http::StatusCode::FOUND {
                                builder = builder.header(
                                    http::header::LOCATION,
                                    format!("https://release.example/releases/tag/v{version}"),
                                );
                            }
                            Ok::<_, Infallible>(
                                builder
                                    .body(Full::new(Bytes::from(bytes)))
                                    .expect("response"),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    });
    let origin = format!("https://localhost:{}", addr.port());
    let ca = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/acceptance/fixtures/tls/test-ca.pem"
    )
    .to_string();

    // The no-argument update: latest is discovered, the kit is fetched and
    // applied; the temporary kit directory does not survive.
    let (exit, stdout, stderr) = cli_raw(
        &["update", "--release-origin", &origin, "--tls-ca", &ca],
        &isolated_env(&home),
        None,
    );
    assert_eq!(exit, 0, "the fetched kit installs: {stdout}{stderr}");
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        b"fetched executable",
        "the kit's executable is installed"
    );
    assert_eq!(
        requests.load(AtomicOrdering::SeqCst),
        2,
        "one latest read, one kit download"
    );
    let leftover: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .expect("temp dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("jaynshare-kit-"))
        .collect();
    assert!(leftover.is_empty(), "no kit file survives: {leftover:?}");

    operator.instance.stop();
}
