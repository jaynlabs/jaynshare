//! The help: one table naming every verb with its role,
//! intent, the exit rows it can produce beyond 0/1/2 and its examples. The
//! top-level help is rendered from the table, grouped by role in the order
//! engineer, operator, deploy, server; each verb's help is clap's usage and
//! options followed by the table's exit rows and examples. Help never reads a
//! file or contacts a server.

use clap::{ColorChoice, Command, CommandFactory};

use super::args::Cli;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Role {
    Engineer,
    Operator,
    Deploy,
    Server,
    /// `help`, `version`, `schema`: no role, they run anywhere.
    Any,
}

pub(super) struct VerbDoc {
    /// The verb as one or two words (`account add`).
    pub(super) path: &'static str,
    pub(super) role: Role,
    /// The release in which the verb gains its behaviour; `None` when it
    /// already has it. A later verb parses, has help and a schema
    /// and refuses to run (`cli_internal`).
    pub(super) lands: Option<&'static str>,
    pub(super) intent: &'static str,
    /// Exit rows beyond 0/1/2.
    pub(super) exits: &'static [i32],
    pub(super) examples: &'static [&'static str],
}

macro_rules! verb {
    ($path:literal, $role:ident, $lands:expr, $intent:literal, [$($exit:expr),*], [$($example:literal),*]) => {
        VerbDoc {
            path: $path,
            role: Role::$role,
            lands: $lands,
            intent: $intent,
            exits: &[$($exit),*],
            examples: &[$($example),*],
        }
    };
}

/// Every verb once, in the order help lists them within a role.
pub(super) static DOCS: &[VerbDoc] = &[
    // ---- engineer
    verb!(
        "claude",
        Engineer,
        None,
        "Launch Claude Code through the pool; after the launch the exit code is Claude Code's",
        [4, 6, 7, 11, 13, 14, 15, 16],
        [
            "jaynshare claude --auto -- -p \"<prompt>\"",
            "jaynshare claude --account <reference>"
        ]
    ),
    verb!(
        "codex",
        Engineer,
        None,
        "Launch Codex through the pool (it still needs your own `codex login`); after the launch the exit code is Codex's",
        [4, 6, 7, 11, 13, 14, 15, 16],
        [
            "jaynshare codex --auto -- exec \"<prompt>\"",
            "jaynshare codex --account <reference>"
        ]
    ),
    verb!(
        "env",
        Engineer,
        None,
        "Print the launch environment, quoted for the shell to evaluate",
        [4, 6, 7, 11, 14],
        [
            "eval \"$(jaynshare env)\"",
            "eval \"$(jaynshare env --provider codex)\"",
            "jaynshare env --shell fish --show"
        ]
    ),
    verb!(
        "alias",
        Engineer,
        None,
        "Print the one shell line that makes `claude` run `jaynshare claude`",
        [],
        ["jaynshare alias", "jaynshare alias --shell powershell"]
    ),
    verb!(
        "join",
        Engineer,
        None,
        "Join a pool with the operator's invite, install its client and add your Claude and ChatGPT accounts",
        [4, 5, 8, 10, 14, 17, 18],
        ["jaynshare join <invite>"]
    ),
    verb!(
        "update",
        Engineer,
        None,
        "Apply a client kit to this installation",
        [11, 17, 20],
        [
            "jaynshare update --from <client-kit.zip>",
            "jaynshare update"
        ]
    ),
    verb!(
        "trust-ca add",
        Engineer,
        None,
        "Add the pool's CA to the OS trust store (optional, always confirmed)",
        [11, 21],
        ["jaynshare trust-ca add"]
    ),
    verb!(
        "trust-ca remove",
        Engineer,
        None,
        "Remove the pool's CA from the OS trust store",
        [11, 21],
        ["jaynshare trust-ca remove"]
    ),
    verb!(
        "uninstall",
        Engineer,
        None,
        "Remove this client installation",
        [11],
        ["jaynshare uninstall"]
    ),
    verb!(
        "secret set",
        Engineer,
        None,
        "Install a rotated client secret, read by hidden prompt, --stdin or --file",
        [5, 11],
        ["jaynshare secret set", "jaynshare secret set --file <path>"]
    ),
    verb!(
        "status",
        Engineer,
        None,
        "As the enrolled client: this client's view of the pool (--client, --line, --session)",
        [4, 5, 11, 12],
        ["jaynshare status --client", "jaynshare status --line"]
    ),
    verb!(
        "api",
        Engineer,
        None,
        "As the enrolled client: send one request through the proxy (--client)",
        [4, 11],
        ["jaynshare api GET /v1/models --client"]
    ),
    verb!(
        "account login",
        Engineer,
        None,
        "As the enrolled client: log in a Claude or ChatGPT account of your own, or log it in again",
        [4, 5, 8, 9, 10, 11],
        [
            "jaynshare account login",
            "jaynshare account login --provider codex"
        ]
    ),
    verb!(
        "account list",
        Engineer,
        None,
        "As the enrolled client: list the accounts this client added",
        [4, 5, 10, 11],
        ["jaynshare account list"]
    ),
    verb!(
        "statusline",
        Engineer,
        None,
        "Claude Code's status-line command: reads its payload, prints one line",
        [],
        ["jaynshare statusline < <payload.json>"]
    ),
    verb!(
        "title-hook",
        Engineer,
        None,
        "Claude Code's title hook: reads its payload, prints the hook's JSON",
        [],
        ["jaynshare title-hook < <payload.json>"]
    ),
    // ---- operator
    verb!(
        "status",
        Operator,
        None,
        "Read the pool table with utilisation bars; --verbose adds the diagnostics; --check prints nothing",
        [3, 4, 5, 10],
        ["jaynshare status", "jaynshare status --verbose"]
    ),
    verb!(
        "account list",
        Operator,
        None,
        "List the pool's accounts",
        [3, 4, 5, 10],
        ["jaynshare account list"]
    ),
    verb!(
        "account show",
        Operator,
        None,
        "Show one account by reference",
        [3, 4, 5, 6, 7, 10],
        ["jaynshare account show <reference>"]
    ),
    verb!(
        "account add",
        Operator,
        None,
        "Add an account from an API key, a portable object, a server-side file or Claude Code's store",
        [3, 4, 5, 8, 9, 10],
        [
            "jaynshare account add --api-key --name <name>",
            "jaynshare account add --portable --file <path>"
        ]
    ),
    verb!(
        "account login",
        Operator,
        None,
        "Start a browser login, Claude's or (--provider codex) ChatGPT's; prints the authorisation URL first",
        [3, 4, 5, 8, 9, 10],
        [
            "jaynshare account login --name <name>",
            "jaynshare account login --provider codex",
            "jaynshare account login --no-wait"
        ]
    ),
    verb!(
        "account operation show",
        Operator,
        None,
        "Report one login operation, and its account on success",
        [3, 4, 5, 6, 10],
        ["jaynshare account operation show <operation-id>"]
    ),
    verb!(
        "account operation code",
        Operator,
        None,
        "Submit a pasted authorisation code to a login operation",
        [3, 4, 5, 6, 8, 10],
        ["jaynshare account operation code <operation-id>"]
    ),
    verb!(
        "account operation cancel",
        Operator,
        None,
        "Cancel a login operation",
        [3, 4, 5, 6, 8, 10],
        ["jaynshare account operation cancel <operation-id>"]
    ),
    verb!(
        "account replace",
        Operator,
        None,
        "Replace an account's credential, keeping its name and handle",
        [3, 4, 5, 6, 7, 8, 9, 10],
        ["jaynshare account replace <reference> --api-key --stdin"]
    ),
    verb!(
        "account remove",
        Operator,
        None,
        "Remove an account (asks; --yes skips)",
        [3, 4, 5, 6, 7, 8, 10, 21],
        [
            "jaynshare account remove <reference>",
            "jaynshare account remove <reference> --yes"
        ]
    ),
    verb!(
        "account rename",
        Operator,
        None,
        "Rename an account",
        [3, 4, 5, 6, 7, 8, 10],
        ["jaynshare account rename <reference> <new-name>"]
    ),
    verb!(
        "account enable",
        Operator,
        None,
        "Enable an account; also the retry path out of the errored state",
        [3, 4, 5, 6, 7, 10],
        ["jaynshare account enable <reference>"]
    ),
    verb!(
        "account disable",
        Operator,
        None,
        "Disable an account: it keeps everything but new selection",
        [3, 4, 5, 6, 7, 10],
        ["jaynshare account disable <reference>"]
    ),
    verb!(
        "switch",
        Operator,
        None,
        "Move the default account, steer one route, or list accounts with the default marked",
        [3, 4, 5, 6, 7, 8, 10],
        [
            "jaynshare switch",
            "jaynshare switch <reference>",
            "jaynshare switch --route <name> --clear"
        ]
    ),
    verb!(
        "route list",
        Operator,
        None,
        "The route view with predicted targets, or with --local what the file says",
        [3, 4, 5, 10],
        ["jaynshare route list", "jaynshare route list --local"]
    ),
    verb!(
        "route add",
        Operator,
        None,
        "Add a route to the configuration file and reload",
        [3, 4, 5, 6, 7, 8, 10],
        ["jaynshare route add <name> --pattern <glob> --account <reference>"]
    ),
    verb!(
        "route rm",
        Operator,
        None,
        "Remove a route from the configuration file and reload",
        [3, 4, 5, 6, 8, 10],
        ["jaynshare route rm <name>"]
    ),
    verb!(
        "priority list",
        Operator,
        None,
        "Each account's priority",
        [3, 4, 5, 10],
        ["jaynshare priority list"]
    ),
    verb!(
        "priority set",
        Operator,
        None,
        "Write an account's priority to the file and reload; lower wins",
        [3, 4, 5, 6, 7, 8, 10],
        ["jaynshare priority set <reference> <integer>"]
    ),
    verb!(
        "priority clear",
        Operator,
        None,
        "Remove an account's priority entry: back to 0",
        [3, 4, 5, 6, 7, 8, 10],
        ["jaynshare priority clear <reference>"]
    ),
    verb!(
        "block list",
        Operator,
        None,
        "The blocked model patterns in force",
        [3, 4, 5, 10],
        ["jaynshare block list"]
    ),
    verb!(
        "block add",
        Operator,
        None,
        "Block a model pattern in the file and reload",
        [3, 4, 5, 8, 10],
        ["jaynshare block add <glob>"]
    ),
    verb!(
        "block rm",
        Operator,
        None,
        "Unblock a model pattern in the file and reload",
        [3, 4, 5, 6, 8, 10],
        ["jaynshare block rm <glob>"]
    ),
    verb!(
        "probe",
        Operator,
        None,
        "Start a usage probe sweep; --wait prints each account's outcome",
        [3, 4, 5, 8, 10],
        ["jaynshare probe", "jaynshare probe --wait"]
    ),
    verb!(
        "client list",
        Operator,
        None,
        "List the client registry",
        [3, 4, 5, 10],
        ["jaynshare client list"]
    ),
    verb!(
        "client show",
        Operator,
        None,
        "Show one registry entry; never its code or secret",
        [3, 4, 5, 6, 10],
        ["jaynshare client show <id>"]
    ),
    verb!(
        "client invite",
        Operator,
        None,
        "Invite a machine: a client id and its single-use invite, disclosed once",
        [3, 4, 5, 8, 9, 10, 14, 17],
        [
            "jaynshare client invite <id>",
            "jaynshare client invite <id> --name <display-name> --expires 1h --no-account"
        ]
    ),
    verb!(
        "client reissue",
        Operator,
        None,
        "Replace a lost or expired invite; the previous one stops working",
        [3, 4, 5, 6, 8, 10, 14, 17],
        ["jaynshare client reissue <id>"]
    ),
    verb!(
        "client rotate",
        Operator,
        None,
        "Rotate a client's secret and disclose the new one once",
        [3, 4, 5, 6, 8, 10],
        ["jaynshare client rotate <id>"]
    ),
    verb!(
        "client revoke",
        Operator,
        None,
        "Revoke a client (asks; --yes skips); revoking twice is exit 0",
        [3, 4, 5, 6, 10, 21],
        ["jaynshare client revoke <id> --yes"]
    ),
    verb!(
        "client rename",
        Operator,
        None,
        "Rename a client",
        [3, 4, 5, 6, 9, 10],
        ["jaynshare client rename <id> <display-name>"]
    ),
    verb!(
        "operator secret set",
        Operator,
        None,
        "Create the remote-operator secret — the pool's master key, never stored by the CLI — and disclose it once",
        [3, 4, 5, 8, 10, 21],
        [
            "jaynshare operator secret set",
            "jaynshare operator secret set --disclose-to <path>"
        ]
    ),
    verb!(
        "operator secret remove",
        Operator,
        None,
        "Delete the remote-operator secret",
        [3, 4, 5, 10],
        ["jaynshare operator secret remove"]
    ),
    verb!(
        "ca show",
        Operator,
        None,
        "The MITM CA's fingerprint, expiry and state",
        [3, 4, 5, 10],
        ["jaynshare ca show"]
    ),
    verb!(
        "ca export",
        Operator,
        None,
        "The CA certificate as PEM, on standard output or into a fresh file",
        [3, 4, 5, 8, 10],
        ["jaynshare ca export", "jaynshare ca export --out <path>"]
    ),
    verb!(
        "ca rotate",
        Operator,
        None,
        "Stage the next CA, presented after a week; --now replaces it at once (asks; --yes skips)",
        [3, 4, 5, 8, 10, 21],
        ["jaynshare ca rotate", "jaynshare ca rotate --now"]
    ),
    verb!(
        "config paths",
        Operator,
        None,
        "Every owned path in force, how it was selected, whether it exists and its mode",
        [],
        ["jaynshare config paths"]
    ),
    verb!(
        "config new",
        Operator,
        None,
        "Write a minimal, valid scaffold configuration; never overwrites",
        [8],
        ["jaynshare config new --out <path>"]
    ),
    verb!(
        "config show",
        Operator,
        None,
        "The effective configuration from the server, or with --local from the file",
        [3, 4, 5, 10],
        ["jaynshare config show", "jaynshare config show --local"]
    ),
    verb!(
        "config validate",
        Operator,
        None,
        "Check a file without a server: every error at once, the digest when clean",
        [3],
        [
            "jaynshare config validate",
            "jaynshare config validate <path>"
        ]
    ),
    verb!(
        "config reload",
        Operator,
        None,
        "Reload the file the server started with",
        [3, 4, 5, 8, 10],
        ["jaynshare config reload"]
    ),
    verb!(
        "config set",
        Operator,
        None,
        "Set one scalar or array key in the file and reload",
        [3, 4, 5, 8, 10],
        ["jaynshare config set quota.probe_interval_seconds <n>"]
    ),
    verb!(
        "config unset",
        Operator,
        None,
        "Remove one key from the file so its default applies, and reload",
        [3, 4, 5, 6, 8, 10],
        ["jaynshare config unset logging.level"]
    ),
    verb!(
        "config edit",
        Operator,
        None,
        "Edit the file in $VISUAL or $EDITOR, validate, replace atomically and reload",
        [3, 4, 5, 8, 10],
        ["jaynshare config edit", "jaynshare config edit --offline"]
    ),
    verb!(
        "log tail",
        Operator,
        None,
        "The operational log, last lines first-to-last, optionally followed across rotation",
        [3],
        [
            "jaynshare log tail -n 20",
            "jaynshare log tail --follow --event <name>"
        ]
    ),
    verb!(
        "audit tail",
        Operator,
        None,
        "The audit log, filtered; never a body or a credential",
        [3],
        ["jaynshare audit tail --account <display-name> --status 429"]
    ),
    verb!(
        "api",
        Operator,
        None,
        "Send one request through the proxy as the operator; status and headers on standard error, body on standard output",
        [3, 4, 5, 10],
        [
            "jaynshare api GET /v1/models",
            "jaynshare api POST /v1/messages --body-file <path> --account <reference>"
        ]
    ),
    // ---- deploy
    verb!(
        "release verify",
        Deploy,
        None,
        "Verify a release directory or file against the release key",
        [17],
        ["jaynshare release verify <dir>"]
    ),
    verb!(
        "release fetch",
        Deploy,
        None,
        "Download and verify a release from the release host — the one verb that contacts it",
        [4, 17],
        ["jaynshare release fetch <version> --out <dir>"]
    ),
    verb!(
        "release latest",
        Deploy,
        None,
        "Name the newest published release version from the release host",
        [4, 17],
        ["jaynshare release latest"]
    ),
    verb!(
        "server preflight",
        Deploy,
        None,
        "Check this host for a native install and report what each check found",
        [3, 18, 21],
        ["jaynshare server preflight --from <release-dir>"]
    ),
    verb!(
        "server install",
        Deploy,
        None,
        "Install the newest verified release, or a clone's build, as the native service, writing a configuration when there is none and ending with an invite for you; run again, it updates",
        [3, 4, 8, 17, 18, 19, 20, 21],
        [
            "jaynshare server install",
            "jaynshare server install --version <semver>",
            "jaynshare server install --binary target/release/jaynshare"
        ]
    ),
    verb!(
        "server update",
        Deploy,
        None,
        "Update the native install to its origin's newest release, a version or a release directory (asks; --yes skips)",
        [4, 8, 17, 18, 19, 20, 21],
        [
            "jaynshare server update",
            "jaynshare server update --version <semver>",
            "jaynshare server update --from <release-dir>"
        ]
    ),
    verb!(
        "server uninstall",
        Deploy,
        None,
        "Remove the native install, preserving state unless --purge (interactive only)",
        [19, 21],
        [
            "jaynshare server uninstall",
            "jaynshare server uninstall --purge"
        ]
    ),
    verb!(
        "server prune",
        Deploy,
        None,
        "Remove old releases, keeping the last --keep",
        [],
        ["jaynshare server prune --keep 2"]
    ),
    verb!(
        "server auto-update",
        Deploy,
        None,
        "Update the native install from its release origin every night; clients follow on their next launch",
        [8, 18, 19],
        [
            "jaynshare server auto-update on",
            "jaynshare server auto-update off"
        ]
    ),
    verb!(
        "service install",
        Deploy,
        None,
        "Register the service with the platform's manager",
        [18, 19],
        ["jaynshare service install"]
    ),
    verb!(
        "service remove",
        Deploy,
        None,
        "Unregister the service",
        [18, 19],
        ["jaynshare service remove"]
    ),
    verb!(
        "service start",
        Deploy,
        None,
        "Start the service",
        [18, 19],
        ["jaynshare service start"]
    ),
    verb!(
        "service stop",
        Deploy,
        None,
        "Stop the service",
        [18, 19],
        ["jaynshare service stop"]
    ),
    verb!(
        "service restart",
        Deploy,
        None,
        "Restart the service",
        [18, 19],
        ["jaynshare service restart"]
    ),
    verb!(
        "service status",
        Deploy,
        None,
        "One of absent, stopped, starting, running, failed, manager-unavailable",
        [19],
        ["jaynshare service status"]
    ),
    // ---- server
    verb!(
        "serve",
        Server,
        None,
        "Run the server in the foreground until stopped; SIGHUP reloads",
        [3, 22, 23],
        ["jaynshare serve", "JAYNSHARE_CONFIG=<path> jaynshare serve"]
    ),
    // ---- any machine
    verb!(
        "help",
        Any,
        None,
        "Print help for the executable or one verb",
        [],
        ["jaynshare help", "jaynshare help account add"]
    ),
    verb!(
        "version",
        Any,
        None,
        "Print the version and build identity",
        [],
        ["jaynshare version", "jaynshare version --json"]
    ),
    verb!(
        "schema",
        Any,
        None,
        "Print the JSON Schema of a verb's --json document, or of every verb",
        [],
        ["jaynshare schema status", "jaynshare schema"]
    ),
];

/// The table row for a verb path; `status` and `api` have two rows (one per
/// role) and the operator's is the one returned.
pub(super) fn doc(path: &str) -> Option<&'static VerbDoc> {
    DOCS.iter()
        .filter(|d| d.path == path)
        .max_by_key(|d| d.role == Role::Operator)
}

/// The top-level help, verbs grouped by role.
pub(super) fn top_level() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "jaynshare {} — the pooled proxy for Claude Code and Codex\n\n",
        crate::server::VERSION
    ));
    out.push_str(
        "Usage: jaynshare [global options] <verb> [options] [arguments] [-- passthrough]\n",
    );
    out.push_str(
        "On an enrolled machine, `jaynshare` alone picks any pooled account and launches its tool.\n\n",
    );
    let width = DOCS.iter().map(|d| d.path.len()).max().unwrap_or(0);
    let groups: [(Role, &str); 5] = [
        (
            Role::Engineer,
            "Engineer verbs (the enrolled client machine)",
        ),
        (
            Role::Operator,
            "Operator verbs (pool administration, on the host or with --server)",
        ),
        (
            Role::Deploy,
            "Deploy verbs (installation and release work on a host)",
        ),
        (Role::Server, "Server verb"),
        (Role::Any, "On any machine"),
    ];
    for (role, heading) in groups {
        out.push_str(heading);
        out.push_str(":\n");
        for doc in DOCS.iter().filter(|d| d.role == role) {
            if role == Role::Engineer && matches!(doc.path, "statusline" | "title-hook") {
                continue;
            }
            out.push_str(&format!("  {:width$}  {}\n", doc.path, doc.intent));
        }
        if role == Role::Engineer {
            out.push_str("  Run by Claude Code, not by hand:\n");
            for doc in DOCS
                .iter()
                .filter(|d| matches!(d.path, "statusline" | "title-hook"))
            {
                out.push_str(&format!("  {:width$}  {}\n", doc.path, doc.intent));
            }
        }
        out.push('\n');
    }
    out.push_str("Global options (before or after the verb):\n");
    for (flag, meaning) in [
        ("--json", "one JSON document on standard output"),
        (
            "--quiet, -q",
            "suppress progress and hints on standard error; errors still print",
        ),
        (
            "--no-color",
            "never emit colour (NO_COLOR has the same effect)",
        ),
        (
            "--config <path>",
            "the configuration file; wins over JAYNSHARE_CONFIG",
        ),
        (
            "--server <origin>",
            "address a running instance by its base-URL origin as a remote operator",
        ),
        (
            "--operator-secret-file <path>",
            "protected file holding the remote-operator secret for --server",
        ),
        (
            "--tls-ca <path>",
            "extra trust anchor for an https --server origin",
        ),
        (
            "--timeout <seconds>",
            "deadline for one control request (default 10)",
        ),
        ("--yes", "answer every skippable confirmation"),
        ("--help, -h", "help for the executable or the verb"),
        ("--version, -V", "version and build identity"),
    ] {
        out.push_str(&format!("  {flag:30}  {meaning}\n"));
    }
    out.push_str("\nExit codes: 0 success, 1 unexpected failure, 2 usage error; `jaynshare help <verb>` lists a verb's other rows.\n");
    out
}

/// A verb's exit rows and examples, appended to clap's usage and options.
fn after_help(doc: &VerbDoc) -> String {
    let mut out = String::new();
    if let Some(milestone) = doc.lands {
        out.push_str(&format!(
            "This verb's behaviour lands in {milestone}; this build parses it and refuses to run it.\n\n"
        ));
    }
    if doc.exits.is_empty() {
        out.push_str("Exit codes: 0, 1 (unexpected failure), 2 (usage error).\n");
    } else {
        out.push_str("Exit codes beyond 0/1/2:\n");
        for code in doc.exits {
            out.push_str(&format!("  {code:>2}  {}\n", exit_meaning(*code)));
        }
    }
    out.push_str("\nExamples:\n");
    for example in doc.examples {
        out.push_str(&format!("  {example}\n"));
    }
    out
}

/// The exit-code table, one line each.
pub(super) fn exit_meaning(code: i32) -> &'static str {
    match code {
        0 => "success",
        1 => "unexpected failure: I/O error, internal error, an outcome no other row names",
        2 => "usage error",
        3 => "configuration invalid or unreadable, or a reload rejected as invalid",
        4 => "server unreachable",
        5 => "refused: no principal, wrong role or wrong channel",
        6 => "not found: account, client, route, operation, version or endpoint",
        7 => "ambiguous account reference",
        8 => "conflict: the state does not admit the operation",
        9 => "rejected on the owner's rule for the values given",
        10 => "server failed or answered incompatibly",
        11 => "not enrolled or installation incomplete",
        12 => "CA not trusted or fingerprint mismatch",
        13 => "Claude Code or Codex not found",
        14 => "MITM mode impossible for this enrollment",
        15 => "picker cancelled",
        16 => "pick mode with no usable terminal",
        17 => "release verification failed",
        18 => "preflight failed or platform refused",
        19 => "service manager reported failure",
        20 => "rolled back after a failed post-operation check",
        21 => "confirmation required and not given, or an interactive-only verb without a terminal",
        22 => "serve: a listener could not be bound",
        23 => {
            "serve: pre-bind preflight failed, or the server stopped on an unwritable audit or state file"
        }
        _ => "not a CLI exit code",
    }
}

/// The clap command with the table's intent lines and after-help attached,
/// the top-level help replaced by [`top_level`], and colour decided once.
pub(super) fn command(color: ColorChoice) -> Command {
    let mut command = Cli::command()
        .color(color)
        .override_help(top_level())
        .override_usage("jaynshare [global options] <verb> [options] [arguments] [-- passthrough]");
    for doc in DOCS {
        let words: Vec<&str> = doc.path.split(' ').collect();
        command = attach(command, &words, doc);
    }
    command
}

fn attach(command: Command, words: &[&str], doc: &VerbDoc) -> Command {
    let (first, rest) = words.split_first().expect("a verb has at least one word");
    command.mut_subcommand(*first, |sub| {
        if rest.is_empty() {
            sub.about(doc.intent).after_help(after_help(doc))
        } else {
            attach(sub, rest, doc)
        }
    })
}

/// The usage line of the verb the arguments name, for the clap errors
/// that omit it (an invalid value). Global options that take a value are
/// skipped with their value; the walk stops at the first unknown word.
pub(super) fn usage_for(argv: &[std::ffi::OsString], color: ColorChoice) -> String {
    const VALUED: [&str; 5] = [
        "--config",
        "--server",
        "--operator-secret-file",
        "--tls-ca",
        "--timeout",
    ];
    let mut words = Vec::new();
    let mut skip_value = false;
    for token in argv.iter().skip(1) {
        let Some(word) = token.to_str() else { break };
        if skip_value {
            skip_value = false;
            continue;
        }
        if word.starts_with('-') {
            skip_value = VALUED.contains(&word);
            continue;
        }
        words.push(word.to_string());
    }
    fn descend<'c>(command: &'c mut Command, words: &[String]) -> &'c mut Command {
        if let Some((first, rest)) = words.split_first()
            && command.find_subcommand(first).is_some()
        {
            return descend(command.find_subcommand_mut(first).expect("found"), rest);
        }
        command
    }
    let mut command = command(color);
    command.build();
    descend(&mut command, &words).render_usage().to_string()
}

/// Every leaf verb the grammar knows, as its path words; a unit test holds
/// this and the table to one set.
#[cfg(test)]
fn grammar_paths() -> Vec<String> {
    fn walk(command: &Command, prefix: &str, out: &mut Vec<String>) {
        for sub in command.get_subcommands() {
            let path = if prefix.is_empty() {
                sub.get_name().to_string()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            if sub.has_subcommands() {
                walk(sub, &path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&Cli::command(), "", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_and_the_grammar_name_one_verb_set() {
        let mut grammar = grammar_paths();
        grammar.sort();
        let mut table: Vec<String> = DOCS.iter().map(|d| d.path.to_string()).collect();
        table.sort();
        table.dedup();
        assert_eq!(grammar, table);
        command(ColorChoice::Never).debug_assert();
    }

    #[test]
    fn help_lists_every_verb_by_role_and_keeps_the_vocabulary() {
        let help = top_level();
        for doc in DOCS {
            assert!(help.contains(doc.path), "{} missing from help", doc.path);
        }
        // The kept product words.
        for word in [
            "status", "switch", "claude", "codex", "env", "probe", "route", "client", "service",
            "api", "alias",
        ] {
            assert!(help.contains(&format!("  {word}")), "{word} missing");
        }
        let engineer = help.find("Engineer verbs").unwrap();
        let operator = help.find("Operator verbs").unwrap();
        let deploy = help.find("Deploy verbs").unwrap();
        let server = help.find("Server verb").unwrap();
        assert!(engineer < operator && operator < deploy && deploy < server);
        for doc in DOCS {
            for example in doc.examples {
                assert!(
                    !example.contains("sk-ant") && !example.contains("jse2_"),
                    "{example}"
                );
            }
        }
    }

    #[test]
    fn every_documented_exit_code_is_a_verb_specific_one() {
        for doc in DOCS {
            for code in doc.exits {
                assert!((3..=23).contains(code), "{}: {code}", doc.path);
            }
        }
    }
}
