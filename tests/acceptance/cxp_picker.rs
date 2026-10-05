//! The account picker — keyboard and numbered, its rows, cancel, terminal
//! restoration and the no-terminal refusal. Picker tests run on a
//! pseudo-terminal: `machine.pty(...)` and `machine.pty_shell(...)` with the
//! `KEY_*` constants (`client_fx`).

#[allow(unused_imports)]
use crate::client_fx::*;
#[allow(unused_imports)]
use crate::harness::*;
#[allow(unused_imports)]
use crate::proxy::claude_request;

/// An unselectable row is drawn dim and marked, without a number.
#[tokio::test(flavor = "multi_thread")]
async fn an_unselectable_row_has_no_number_in_the_numbered_picker() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("numbered-unselectable-number-a").await;
    add_two(&instance);
    instance.cli(&["account", "disable", "FSUB2"], None);
    let machine = install_client(&instance).await;

    // Answer 3 (out of range: FSUB2 has no number), then 2 (FSUB).
    let (code, transcript) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[("NO_COLOR", "1")],
        &[
            ("or q to cancel", "3\r"),
            ("Enter a number from 1 to 2", "2\r"),
        ],
    );
    assert_eq!(code, 0, "the fake exits 0");
    let line = |name: &str| {
        transcript
            .lines()
            .find(|line| line.contains(name))
            .unwrap_or_else(|| panic!("{name:?} missing: {transcript}"))
            .trim_end()
            .to_owned()
    };
    let header = line("5h used");
    assert!(
        header.trim_start().starts_with("5h used") && header.ends_with("Weekly used"),
        "the bars' titles, and no other: {transcript}"
    );
    assert!(
        line("Automatic").starts_with("  1) Automatic (server decides)"),
        "the automatic row first: {transcript}"
    );
    assert!(
        line("FSUB ").starts_with("  2) FSUB "),
        "the selectable account row: {transcript}"
    );
    let fsub2 = line("FSUB2");
    assert!(
        fsub2.starts_with("     FSUB2") && fsub2.ends_with("unavailable"),
        "the unselectable row is marked, without a number: {transcript}"
    );
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        seen.pin(),
        Some(token(true, &instance.handle("FSUB"))),
        "the chosen account's pin token"
    );

    // Answer 1: the automatic row sends no token.
    let (code, _) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0);
    let seen = machine
        .claude_ran()
        .expect("Claude Code was launched again");
    assert!(seen.pin().is_none(), "the automatic row sends no token");
}

#[tokio::test(flavor = "multi_thread")]
async fn pick_mode_without_a_terminal_refuses_naming_the_flags() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("pick-mode-without-terminal").await;
    add_two(&instance);
    let machine = install_client(&instance).await;

    // No terminal at all: pick mode refuses before any environment is built.
    let (code, _, stderr) = machine.jaynshare(&["claude"], &[], None);
    assert_eq!(code, 16, "no terminal, exit 16: {stderr}");
    assert!(
        stderr.starts_with("cli_no_terminal:"),
        "the refusal names the launcher: {stderr}"
    );
    assert!(
        stderr.contains("--account") && stderr.contains("--auto"),
        "the refusal names both flags: {stderr}"
    );
    assert!(
        machine.claude_ran().is_none(),
        ": Claude Code never started"
    );

    // An override does not conjure a terminal either.
    let (code, _, _) = machine.jaynshare(&["claude", "--picker", "numbered"], &[], None);
    assert_eq!(code, 16, "the forced numbered picker still needs one");
    let (code, _, _) = machine.jaynshare(&["claude"], &[("JAYNSHARE_PICKER", "keyboard")], None);
    assert_eq!(code, 16, "the overridden keyboard picker still needs one");

    // --auto needs no picker, so no terminal either.
    let (code, _, _) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "--auto runs without a picker");

    // A JAYNSHARE_PICKER outside the closed set refuses with exit 2,
    // before the terminal is even asked about — here with no terminal,
    let (code, _, stderr) =
        machine.jaynshare(&["claude"], &[("JAYNSHARE_PICKER", "sideways")], None);
    assert_eq!(code, 2, "a bad variable value refuses: {stderr}");
    assert!(stderr.starts_with("cli_usage:"), "the usage row: {stderr}");
    assert!(
        stderr.contains("JAYNSHARE_PICKER")
            && stderr.contains("keyboard")
            && stderr.contains("numbered"),
        "the message names the variable and both values: {stderr}"
    );
    // …and on one.
    let (code, _) = machine.pty(&["claude"], &[("JAYNSHARE_PICKER", "sideways")], &[]);
    assert_eq!(code, 2, "holds on a terminal too");

    // On a terminal the variable forces the numbered picker.
    let (code, _) = machine.pty(
        &["claude"],
        &[("JAYNSHARE_PICKER", "numbered")],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "the forced numbered picker ran and chose");
}

/// The picker draws with the characters the
/// console is known to render: UTF-8 names render as UTF-8 with `…`, a name
/// longer than its column is cut, control characters are stripped; on a
/// console with no UTF-8 locale the same rows draw as ASCII (`?`, `...`).
#[tokio::test(flavor = "multi_thread")]
async fn the_picker_draws_ascii_where_utf8_is_not_known() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // The catalogue comes from a fake control server, so it can carry names
    // the real server would refuse.
    let catalogue = json!({ "accounts": [
        { "handle": "h-zoe", "display_name": "Zoë Café", "selectable": true },
        { "handle": "h-long", "display_name": "A".repeat(200), "selectable": true },
        { "handle": "h-ctl", "display_name": "evil\u{1b}[31mred\u{7}name", "selectable": true },
    ] });
    let fake = FakeControl::start(move |request: &str| {
        let mut body = if request.starts_with("GET /control/v1/client/accounts") {
            catalogue.clone()
        } else {
            snapshot_body(None)
        };
        body["control_api_version"] = json!(1);
        http_reply(200, "application/json", &body.to_string())
    });
    let instance = Instance::start_client("picker-draws-ascii").await;
    let machine = install_client(&instance).await;
    machine.set("base_url", &format!("{:?}", fake.origin()));

    // 1. The machine's default locale names UTF-8: the preferred set.
    let (code, transcript) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "the fake exits 0");
    assert!(
        transcript.contains("Zoë Café"),
        "the UTF-8 name as sent: {transcript}"
    );
    assert!(transcript.contains('…'), "the long name cut to its column");
    assert!(
        !transcript.contains(&"A".repeat(100)),
        "the long name is truncated"
    );
    assert!(
        transcript.contains("evil[31mredname"),
        "control characters removed from the name"
    );
    assert!(
        !transcript.contains('\u{7}') && !transcript.contains("\u{1b}[31m"),
        "neither BEL nor an escape sequence survived"
    );

    // 2. A console with no UTF-8 locale: the ASCII set.
    let (code, transcript) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[("LANG", "C")],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "the fake exits 0");
    assert!(
        transcript.contains("Zo? Caf?"),
        "non-ASCII drawn as `?`: {transcript}"
    );
    assert!(
        transcript.contains("..."),
        "the long name cut with an ASCII ellipsis"
    );
    assert!(
        !transcript.contains('…') && !transcript.contains('ë'),
        "nothing outside the ASCII set was drawn"
    );
}

/// The keyboard marker skips an unselectable row: up from the automatic
/// row wraps past FSUB2 to FSUB.
#[tokio::test(flavor = "multi_thread")]
async fn the_keyboard_marker_skips_an_unselectable_row() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("numbered-unselectable-number-b").await;
    add_two(&instance);
    instance.cli(&["account", "disable", "FSUB2"], None);
    let machine = install_client(&instance).await;

    let keys = format!("{KEY_UP}{KEY_ENTER}");
    let (code, transcript) = machine.pty(
        &["claude", "--picker", "keyboard"],
        &[("NO_COLOR", "1")],
        &[("esc cancel", &keys)],
    );
    assert_eq!(code, 0, "the fake exits 0: {transcript}");
    assert!(
        transcript.contains("❯ Automatic (server decides)"),
        "the marker starts on the automatic row: {transcript}"
    );
    assert!(
        transcript.contains("❯ FSUB ") && !transcript.contains("❯ FSUB2"),
        "the marker went from the automatic row to FSUB: {transcript}"
    );
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        seen.pin(),
        Some(token(true, &instance.handle("FSUB"))),
        "FSUB was chosen"
    );
}

/// After every outcome
/// selection, Esc and Ctrl-C (a byte in raw mode) — raw mode is off and
/// echo back on (the `stty -a` leg), the cursor shown again (the `?25l`/
/// `?25h` leg). The "error while drawing" leg cannot be caused from
/// outside; the guard's `Drop` is the same code path as these exits.
#[tokio::test(flavor = "multi_thread")]
async fn the_terminal_is_restored_after_every_outcome() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("terminal-restored-outcome").await;
    add_two(&instance);
    instance.cli(&["account", "disable", "FSUB2"], None);
    let machine = install_client(&instance).await;

    let shell = |prompt: &str, keys: &str| {
        machine.pty_shell(
            "$JAYNSHARE claude --picker keyboard; echo \"exit=$?\"; stty -a",
            &[],
            &[(prompt, keys)],
        )
    };
    for (keys, want, why) in [
        (KEY_ENTER, "exit=0", "selection: the automatic row"),
        (KEY_ESC, "exit=15", ": Esc cancels"),
        (KEY_CTRL_C, "exit=15", ": Ctrl-C is a key in raw mode"),
    ] {
        let (code, transcript) = shell("esc cancel", keys);
        assert_eq!(code, 0, "the shell exits 0 ({why}): {transcript}");
        let after = transcript
            .rsplit("exit=")
            .next()
            .expect("text after the last exit=");
        let tokens: Vec<&str> = after.split_whitespace().collect();
        assert!(
            tokens.contains(&"icanon") && tokens.contains(&"echo"),
            " ({why}): canonical mode with echo restored: {after}"
        );
        assert!(
            !tokens.contains(&"-icanon") && !tokens.contains(&"-echo"),
            " ({why}): raw mode is off: {after}"
        );
        assert!(
            transcript.contains(want),
            "({why}): expected {want} in the transcript: {transcript}"
        );
        let hide = transcript
            .rmatch_indices("\u{1b}[?25l")
            .next()
            .map(|(i, _)| i)
            .expect("the cursor was hidden");
        let show = transcript[hide..]
            .find("\u{1b}[?25h")
            .expect(" ({why}): the cursor was shown again");
        let _ = show;
    }
}

/// The three intents and their tokens: an
/// `--account` reference pins, a picker selection pins, `--auto` and the
/// automatic row send no token at all.
#[tokio::test(flavor = "multi_thread")]
async fn account_and_picker_pin_auto_sends_none() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("account-picker-pin").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let pin = |name: &str| Some(token(true, &instance.handle(name)));

    // 1. `--account FSUB2` is a strict pin.
    let (code, _, stderr) = machine.jaynshare(&["claude", "--account", "FSUB2"], &[], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.pin(), pin("FSUB2"), "the pin token");
    assert_eq!(
        claude_request(&seen.env).await.status,
        StatusCode::OK,
        "the request was answered"
    );
    let record = instance.last_record(1);
    assert_eq!(record["pinned"], json!(true), "pinned");
    assert_eq!(
        record["serving_account"]["display_name"],
        json!("FSUB2"),
        "served by the pinned account"
    );

    // 2. A numbered-picker selection is the same strict pin;
    // is FSUB2.
    let (code, _) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[],
        &[("or q to cancel", "3\r")],
    );
    assert_eq!(code, 0, "the fake exits 0");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(
        seen.pin(),
        pin("FSUB2"),
        "a picker choice is a pin token too"
    );
    assert_eq!(
        claude_request(&seen.env).await.status,
        StatusCode::OK,
        "the request was answered"
    );
    let record = instance.last_record(2);
    assert_eq!(record["pinned"], json!(true), "pinned");
    assert_eq!(
        record["serving_account"]["display_name"],
        json!("FSUB2"),
        "served by the chosen account"
    );

    // 3. Keyboard selection: down once from the automatic row lands on FSUB.
    let (code, _) = machine.pty(
        &["claude", "--picker", "keyboard"],
        &[],
        &[("esc cancel", &format!("{KEY_DOWN}{KEY_ENTER}"))],
    );
    assert_eq!(code, 0, "the fake exits 0");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert_eq!(seen.pin(), pin("FSUB"), "the keyboard choice pins too");

    // 4. `--auto` sends no account-intent token.
    let (code, _, stderr) = machine.jaynshare(&["claude", "--auto"], &[], None);
    assert_eq!(code, 0, "the fake exits 0: {stderr}");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert!(seen.pin().is_none(), "no token");
    assert_eq!(
        claude_request(&seen.env).await.status,
        StatusCode::OK,
        "the request was answered"
    );
    let record = instance.last_record(3);
    assert_eq!(record["pinned"], json!(false), "not pinned");

    // 5. The automatic row: numbered picker answering 1 sends no token
    // either.
    let (code, _) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "the fake exits 0");
    let seen = machine.claude_ran().expect("Claude Code was launched");
    assert!(seen.pin().is_none(), "the automatic row sends no token");

    instance.stop();
}

/// The picker only appears in pick
/// mode; its rows are automatic first, then the catalogue in the server's
/// order, and every row shows the shared five-hour and weekly windows but no
/// unrelated quota, token or health detail; Claude Code starts only after a
/// selection.
#[tokio::test(flavor = "multi_thread")]
async fn the_picker_only_in_pick_mode_with_account_rate_limits() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("picker-pick-mode").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let taught = send(
        instance.addr,
        with(
            messages(haiku_prompt()),
            &[("authorization", &machine.client.bearer())],
        ),
    )
    .await;
    assert_eq!(taught.status, StatusCode::OK, "teach FSUB's limits");

    // No picker in any other launch mode, on a terminal or not.
    for (args, extra) in [
        (vec!["claude", "--account", "FSUB"], vec![]),
        (vec!["claude", "--auto"], vec![]),
        (vec!["claude", "--direct"], vec![]),
        (vec!["claude"], vec![("JAYNSHARE_ACCOUNT", "FSUB")]),
    ] {
        let (code, transcript) = machine.pty(&args, &extra, &[]);
        assert_eq!(code, 0, "the launch {args:?} exits 0");
        assert!(
            !transcript.contains("Choose an account"),
            "{args:?} never shows the picker: {transcript}"
        );
    }

    // Pick mode, numbered: the rows in the server's order, automatic first.
    let (code, transcript) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[("NO_COLOR", "1")],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "answering the automatic row exits 0");
    let automatic = transcript
        .find("1) Automatic (server decides)")
        .expect("the automatic row first");
    let fsub = transcript.find("2) FSUB").expect("the first account row");
    let fsub2 = transcript.find("3) FSUB2").expect("the second account row");
    assert!(
        automatic < fsub && fsub < fsub2,
        "server's order: {transcript}"
    );
    // A row's percentages, each after its bar.
    let windows = |at: usize| -> Vec<&str> {
        let row = transcript[at..].lines().next().unwrap_or_default();
        row.split_whitespace()
            .filter(|word| word.ends_with('%'))
            .collect()
    };
    assert_eq!(
        windows(fsub),
        ["12%", "3%"],
        "the learned windows: {transcript}"
    );
    assert_eq!(
        windows(fsub2),
        ["0%", "0%"],
        "unknown windows read as reset: {transcript}"
    );
    for word in ["token", "health", "quota", "@"] {
        assert!(
            !transcript.to_lowercase().contains(&word.to_lowercase()),
            "unrequested detail {word:?} in the rows: {transcript}"
        );
    }

    // Claude Code only after a selection — cancelling never starts it.
    // The record is cleared first: only the cancel leg's absence may show.
    let _ = machine.claude_ran();
    let (code, _) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[],
        &[("or q to cancel", "q\r")],
    );
    assert_eq!(code, 15, "the cancel key's refusal: ");
    assert!(
        machine.claude_ran().is_none(),
        ": Claude Code never started on cancel"
    );
}

/// The descriptor chooses: raw mode means the
/// keyboard picker, and the override forces either, `--picker` winning over
/// `JAYNSHARE_PICKER`. The no-raw-mode leg of the descriptor cannot be made
/// on a Unix pseudo-terminal; the unit tests of `decide` carry it.
#[tokio::test(flavor = "multi_thread")]
async fn the_descriptor_chooses_and_an_override_forces_either() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("descriptor-chooses-override").await;
    add_two(&instance);
    let machine = install_client(&instance).await;

    // A terminal that can go raw, no override: the keyboard picker.
    let (code, _) = machine.pty(&["claude"], &[], &[("esc cancel", KEY_ENTER)]);
    assert_eq!(code, 0, "the keyboard picker's header appeared and chose");

    // The variable forces the numbered prompt.
    let (code, _) = machine.pty(
        &["claude"],
        &[("JAYNSHARE_PICKER", "numbered")],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "the variable's numbered picker chose");

    // The variable says keyboard, `--picker` says numbered: `--picker` wins.
    let (code, transcript) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[("JAYNSHARE_PICKER", "keyboard")],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0);
    assert!(
        transcript.contains("Enter a number"),
        "the numbered prompt, not the keyboard header: {transcript}"
    );

    // The other way round: `--picker keyboard` wins again.
    let (code, _) = machine.pty(
        &["claude", "--picker", "keyboard"],
        &[("JAYNSHARE_PICKER", "numbered")],
        &[("esc cancel", KEY_ENTER)],
    );
    assert_eq!(code, 0, "the keyboard header appeared and chose");
}

/// The picker draws on the terminal, never on
/// standard output, and reads the controlling terminal, so a launch with
/// redirected streams still gets a picker.
#[tokio::test(flavor = "multi_thread")]
async fn picker_output_stays_on_the_terminal() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("picker-output-stays").await;
    add_two(&instance);
    let machine = install_client(&instance).await;
    let out = machine.root.join("picker-output-stays-stdout.txt");

    // Numbered: the picker is on the terminal, the redirect keeps nothing.
    let (code, transcript) = machine.pty_shell(
        &format!(
            "$JAYNSHARE claude --picker numbered > '{}'; echo \"exit=$?\"",
            out.display()
        ),
        &[],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "the shell line exits 0: {transcript}");
    assert!(
        transcript.contains("Choose an account") && transcript.contains("exit=0"),
        "the picker drew on the terminal: {transcript}"
    );
    let redirected = fs::read_to_string(&out).expect("the redirect file");
    for word in ["Choose an account", "Automatic", "Enter a number"] {
        assert!(
            !redirected.contains(word),
            "{word:?} went to standard output: {redirected}"
        );
    }
    let _ = fs::remove_file(&out);

    // The same for the keyboard picker.
    let (code, transcript) = machine.pty_shell(
        &format!(
            "$JAYNSHARE claude --picker keyboard > '{}'; echo \"exit=$?\"",
            out.display()
        ),
        &[],
        &[("esc cancel", KEY_ENTER)],
    );
    assert_eq!(code, 0, "the shell line exits 0: {transcript}");
    assert!(
        transcript.contains("esc cancel") && transcript.contains("exit=0"),
        "the keyboard picker drew on the terminal: {transcript}"
    );
    let redirected = fs::read_to_string(&out).expect("the redirect file");
    assert!(
        !redirected.contains("Choose an account"),
        "the header went to standard output: {redirected}"
    );
    let _ = fs::remove_file(&out);

    // Standard input redirected: the picker still reads the terminal.
    let (code, transcript) = machine.pty_shell(
        "$JAYNSHARE claude --picker numbered < /dev/null; echo \"exit=$?\"",
        &[],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "the shell line exits 0: {transcript}");
    assert!(
        transcript.contains("Choose an account") && transcript.contains("exit=0"),
        "the picker drew despite the redirected input: {transcript}"
    );
}

/// Every way of cancelling ends the
/// launch with exit 15 (`cli_picker_cancelled`), a message naming the
/// non-interactive flags on standard error, and no Claude Code. Each leg is
/// `(what cancels, where to stop waiting, the keys)`: eight legs of Esc,
/// Ctrl-C, Ctrl-D and `q`, in both pickers, plus the empty line in the
/// numbered picker, which re-prompts and selects nothing; then Ctrl-C on a
/// running instance proves the interrupt watcher is armed before the prompt
/// is drawn and disarmed after a selection.
#[tokio::test(flavor = "multi_thread")]
async fn cancel_interrupt_and_end_of_input_each_end_with_15() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let instance = Instance::start_client("cancel-interrupt-end").await;
    add_two(&instance);
    let machine = install_client(&instance).await;

    let message = "cli_picker_cancelled: the account picker was cancelled; nothing was launched. Launch without the picker with --account <reference> or --auto";
    let legs: &[(&str, &str, &str)] = &[
        ("keyboard, Esc", "esc cancel", KEY_ESC),
        ("keyboard, Ctrl-C", "esc cancel", KEY_CTRL_C),
        ("keyboard, Ctrl-D", "esc cancel", "\u{4}"),
        ("keyboard, q", "esc cancel", "q"),
        ("numbered, q", "or q to cancel", "q\r"),
        (
            "numbered, Ctrl-C (the interrupt)",
            "or q to cancel",
            KEY_CTRL_C,
        ),
        ("numbered, end of input", "or q to cancel", "\u{4}"),
    ];
    for (why, prompt, keys) in legs {
        let (code, transcript) = machine.pty(
            &["claude", "--picker", where_picker(why)],
            &[],
            &[(*prompt, *keys)],
        );
        assert_eq!(code, 15, " ({why}): {transcript}");
        assert!(
            transcript.contains(message),
            " ({why}): the message names the flags: {transcript}"
        );
        assert!(
            machine.claude_ran().is_none(),
            " ({why}): nothing was launched"
        );
    }

    // An empty line is not a choice: it re-prompts, and `q` there cancels.
    let (code, transcript) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[],
        &[("or q to cancel", "\r"), ("Enter a number from 1", "q\r")],
    );
    assert_eq!(code, 15, " (the re-prompt): {transcript}");
    assert!(
        transcript.contains(message),
        " (the re-prompt): {transcript}"
    );

    // A selection disarms the interrupt watcher: Ctrl-C after Claude Code
    // exits must not end this launch with 15.
    let (code, transcript) = machine.pty(
        &["claude", "--picker", "numbered"],
        &[("FAKE_CLAUDE_EXIT", "0")],
        &[("or q to cancel", "1\r")],
    );
    assert_eq!(code, 0, "the fake exits 0: {transcript}");
    assert!(
        machine.claude_ran().is_some(),
        "a selection launches Claude Code even though the watcher watched"
    );
}

/// Bare `jaynshare` offers every provider's accounts, each provider's
/// indented under its own automatic row named after its tool, and launches
/// the tool of the row picked; `JAYNSHARE_ACCOUNT` does not skip it. Without a terminal it
/// refuses like any pick, and without an installation it is the help.
#[tokio::test(flavor = "multi_thread")]
async fn bare_jaynshare_picks_across_providers_and_launches_the_picked_tool() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let mut instance = Instance::start_client("bare-picks-across-providers").await;
    add_two(&instance);
    instance.restart_with_state(|state| {
        let record = state["accounts"]
            .as_array_mut()
            .expect("accounts")
            .iter_mut()
            .find(|r| r["display_name"] == "FSUB2")
            .expect("the FSUB2 record");
        record["provider"] = json!("codex");
        record["chatgpt_account_id"] = json!("ws-fsub2");
    });
    let machine = install_client(&instance).await;
    let pin = |name: &str| Some(token(true, &instance.handle(name)));
    // The fake answers as either tool; its CA variable tells which ran.
    let ran = |why: &str| {
        let seen = machine.claude_ran().expect(why);
        let tool = if seen.env.contains_key("CODEX_CA_CERTIFICATE") {
            "codex"
        } else {
            assert!(seen.env.contains_key("NODE_EXTRA_CA_CERTS"), "{why}");
            "claude"
        };
        (tool, seen.pin())
    };

    let numbered = [("JAYNSHARE_PICKER", "numbered"), ("NO_COLOR", "1")];
    let (code, transcript) = machine.pty(&[], &numbered, &[("or q to cancel", "4\r")]);
    assert_eq!(code, 0, "the fake exits 0: {transcript}");
    let lines = [
        "\n  1) Claude Code (server decides)\r",
        "\n    2) FSUB ",
        "\r\n\r\n  3) Codex (server decides)\r",
        "\n    4) FSUB2 ",
        "\r\n\r\nEnter a number (1-4)",
    ];
    let at: Vec<usize> = lines
        .iter()
        .map(|line| {
            transcript
                .find(line)
                .unwrap_or_else(|| panic!("{line:?} missing: {transcript}"))
        })
        .collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "in order: {transcript}");
    assert_eq!(ran("4: FSUB2"), ("codex", pin("FSUB2")));

    let (code, _) = machine.pty(&[], &numbered, &[("or q to cancel", "1\r")]);
    assert_eq!(code, 0);
    assert_eq!(ran("1: Claude Code's automatic row"), ("claude", None));

    // The marker starts on Claude Code's line and follows an account's
    // indent: up wraps to FSUB2, and down twice lands on Codex's line.
    let keyboard = [("JAYNSHARE_PICKER", "keyboard"), ("NO_COLOR", "1")];
    for (keys, drawn, want) in [
        (
            format!("{KEY_UP}{KEY_ENTER}"),
            "  ❯ FSUB2 ",
            ("codex", pin("FSUB2")),
        ),
        (
            format!("{KEY_DOWN}{KEY_DOWN}{KEY_ENTER}"),
            "❯ Codex (server decides)",
            ("codex", None),
        ),
    ] {
        let (code, transcript) = machine.pty(&[], &keyboard, &[("esc cancel", &keys)]);
        assert_eq!(code, 0, "{keys:?}: {transcript}");
        for text in ["❯ Claude Code (server decides)", drawn] {
            assert!(transcript.contains(text), "{text:?}: {transcript}");
        }
        assert_eq!(ran(&format!("{keys:?}")), want, "{keys:?}");
    }

    let (code, transcript) = machine.pty(
        &[],
        &[
            ("JAYNSHARE_PICKER", "numbered"),
            ("JAYNSHARE_ACCOUNT", "FSUB"),
        ],
        &[("or q to cancel", "3\r")],
    );
    assert_eq!(code, 0, "{transcript}");
    let seen = machine.claude_ran().expect("Codex was launched");
    assert!(!seen.env.contains_key("JAYNSHARE_ACCOUNT"));
    assert_eq!(seen.pin(), None, "the picker, not the variable, chose");

    let (code, _, stderr) = machine.jaynshare(&[], &[], None);
    assert_eq!(code, 16, "{stderr}");
    assert!(stderr.starts_with("cli_no_terminal:"), "{stderr}");

    fs::remove_file(machine.client_dir.join("client.toml")).expect("remove client.toml");
    let (code, _, stderr) = machine.jaynshare(&[], &[], None);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("Usage: jaynshare"), "{stderr}");
    instance.stop();
}

/// `--picker` matches the leg's name.
fn where_picker(why: &&str) -> &'static str {
    if why.starts_with("keyboard") {
        "keyboard"
    } else {
        "numbered"
    }
}
