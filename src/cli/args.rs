//! The clap structs for the whole grammar, every verb of every role
//! registered once. Intent lines, exit rows and examples live in `help`'s
//! table, not here; a verb whose behaviour belongs to a later
//! release parses, has help and a schema, and does nothing else.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::provider::Provider;

#[derive(Parser)]
#[command(
    name = "jaynshare",
    disable_version_flag = true,
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
pub(super) struct Cli {
    /// One JSON document on standard output.
    #[arg(long, global = true)]
    pub(super) json: bool,
    /// Suppress progress and hints on standard error; errors still print.
    #[arg(long, short = 'q', global = true)]
    pub(super) quiet: bool,
    /// Never emit colour; NO_COLOR in the environment has the same effect.
    #[arg(long, global = true)]
    pub(super) no_color: bool,
    /// The configuration file; same meaning as JAYNSHARE_CONFIG and wins over it.
    #[arg(long, global = true, value_name = "path")]
    pub(super) config: Option<PathBuf>,
    /// Address a running instance by its base-URL origin as a remote operator.
    #[arg(long, global = true, value_name = "origin")]
    pub(super) server: Option<String>,
    /// Protected file holding the remote-operator secret for --server.
    #[arg(long, global = true, value_name = "path")]
    pub(super) operator_secret_file: Option<PathBuf>,
    /// Extra trust anchor (PEM) for an https --server origin.
    #[arg(long, global = true, value_name = "path")]
    pub(super) tls_ca: Option<PathBuf>,
    /// Deadline in seconds for one control request.
    #[arg(long, global = true, default_value_t = 10, value_name = "seconds")]
    pub(super) timeout: u64,
    /// Answer every skippable confirmation.
    #[arg(long, global = true)]
    pub(super) yes: bool,
    /// Version and build identity.
    #[arg(long, short = 'V')]
    pub(super) version: bool,
    #[command(subcommand)]
    pub(super) verb: Option<Verb>,
}

#[derive(Subcommand)]
pub(super) enum Verb {
    // ---- any machine
    Help {
        /// The verb, as one or two words.
        verb: Vec<String>,
    },
    Version,
    Schema {
        /// The verb, as one or two words; none prints every verb's schema.
        verb: Vec<String>,
    },
    // ---- server
    Serve,
    // ---- operator (and the two dual-role verbs)
    Status(StatusArgs),
    Account {
        #[command(subcommand)]
        verb: AccountVerb,
    },
    Switch(SwitchArgs),
    Route {
        #[command(subcommand)]
        verb: RouteVerb,
    },
    Priority {
        #[command(subcommand)]
        verb: PriorityVerb,
    },
    Block {
        #[command(subcommand)]
        verb: BlockVerb,
    },
    Probe(ProbeArgs),
    Client {
        #[command(subcommand)]
        verb: ClientVerb,
    },
    Operator {
        #[command(subcommand)]
        verb: OperatorVerb,
    },
    Ca {
        #[command(subcommand)]
        verb: CaVerb,
    },
    Config {
        #[command(subcommand)]
        verb: ConfigVerb,
    },
    Log {
        #[command(subcommand)]
        verb: LogVerb,
    },
    Audit {
        #[command(subcommand)]
        verb: AuditVerb,
    },
    Api(ApiArgs),
    // ---- deploy
    Release {
        #[command(subcommand)]
        verb: ReleaseVerb,
    },
    Server {
        #[command(subcommand)]
        verb: ServerVerb,
    },
    Service {
        #[command(subcommand)]
        verb: ServiceVerb,
    },
    // ---- engineer
    Claude(ToolArgs),
    Codex(ToolArgs),
    Env(EnvArgs),
    Alias {
        #[arg(long, value_enum, value_name = "shell")]
        shell: Option<Shell>,
    },
    Join {
        /// The invite the operator's `client invite` printed (jsi1_…).
        invite: String,
    },
    Update {
        /// A client kit archive; without it, the newest release's
        /// client kit is fetched from the origin (`--version` names one).
        #[arg(long, value_name = "zip")]
        from: Option<PathBuf>,
        #[arg(long, value_name = "semver")]
        version: Option<String>,
        /// A verified `https` mirror in place of the official origin
        /// (with `--version`, or for the latest kit).
        #[arg(long, value_name = "https-origin")]
        release_origin: Option<String>,
    },
    TrustCa {
        #[command(subcommand)]
        verb: TrustCaVerb,
    },
    Uninstall,
    Secret {
        #[command(subcommand)]
        verb: SecretVerb,
    },
    Statusline,
    TitleHook,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum Shell {
    Sh,
    Fish,
    Powershell,
    Cmd,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum Picker {
    Keyboard,
    Numbered,
}

#[derive(Args)]
pub(super) struct StatusArgs {
    /// Read the snapshot and print nothing; the exit code is the answer.
    #[arg(long, conflicts_with_all = ["accounts", "routes", "clients", "config_section", "line", "session"])]
    pub(super) check: bool,
    /// Print the accounts section alone.
    #[arg(long, conflicts_with_all = ["routes", "clients", "config_section"])]
    pub(super) accounts: bool,
    /// Print the routes section alone.
    #[arg(long, conflicts_with_all = ["clients", "config_section"])]
    pub(super) routes: bool,
    /// Print the clients section alone.
    #[arg(long, conflicts_with = "config_section")]
    pub(super) clients: bool,
    /// Print the configuration section alone.
    #[arg(long = "config-section")]
    pub(super) config_section: bool,
    /// Add the diagnostics the default table leaves out: server, egress,
    /// capture, mitm, sessions, probe, clients, storage, config, and
    /// per-account usage, holds and ramps.
    #[arg(long, conflicts_with = "check")]
    pub(super) verbose: bool,
    /// Force the operator role.
    #[arg(long, conflicts_with = "client")]
    pub(super) operator: bool,
    /// Force the engineer role: the enrolled client's status.
    #[arg(long)]
    pub(super) client: bool,
    /// As the client: include one session's facts.
    #[arg(long, value_name = "id")]
    pub(super) session: Option<String>,
    /// As the client: print exactly the status-line text.
    #[arg(long)]
    pub(super) line: bool,
}

#[derive(Args)]
pub(super) struct ProbeArgs {
    /// Wait for this sweep and print its per-account outcomes.
    #[arg(long)]
    pub(super) wait: bool,
}

#[derive(Subcommand)]
pub(super) enum RouteVerb {
    List {
        /// What the configuration file says, with no prediction.
        #[arg(long)]
        local: bool,
    },
    Add(RouteAddArgs),
    Rm {
        name: String,
    },
}

#[derive(Args)]
pub(super) struct RouteAddArgs {
    pub(super) name: String,
    /// A model pattern; repeatable.
    #[arg(long = "pattern", value_name = "glob", required = true)]
    pub(super) patterns: Vec<String>,
    /// An account reference; repeatable. None: the route restricts nothing.
    #[arg(long = "account", value_name = "reference")]
    pub(super) accounts: Vec<String>,
    /// The governing-bucket override.
    #[arg(long, value_name = "name")]
    pub(super) bucket: Option<String>,
    /// Place the route before this one.
    #[arg(long, value_name = "route", conflicts_with = "after")]
    pub(super) before: Option<String>,
    /// Place the route after this one.
    #[arg(long, value_name = "route")]
    pub(super) after: Option<String>,
}

#[derive(Subcommand)]
pub(super) enum PriorityVerb {
    List,
    Set {
        reference: String,
        /// Lower wins; negative allowed.
        #[arg(allow_negative_numbers = true)]
        value: i64,
    },
    Clear {
        reference: String,
    },
}

#[derive(Subcommand)]
pub(super) enum BlockVerb {
    List,
    Add { pattern: String },
    Rm { pattern: String },
}

#[derive(Subcommand)]
pub(super) enum ConfigVerb {
    Paths,
    /// Write a minimal, valid scaffold at `--out`; never overwrites.
    New {
        /// Where to write the scaffold configuration file.
        #[arg(long, value_name = "path")]
        out: PathBuf,
    },
    Show {
        /// Parse the file on this machine instead of reading the server.
        #[arg(long)]
        local: bool,
    },
    Validate {
        path: Option<PathBuf>,
    },
    Reload,
    Set {
        key: String,
        /// A TOML value; a bare word that is not one is a string.
        value: String,
    },
    Unset {
        key: String,
    },
    Edit {
        /// Validate and replace without a reload; references are not checked.
        #[arg(long)]
        offline: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum LogVerb {
    Tail(LogTailArgs),
}

#[derive(Args)]
pub(super) struct LogTailArgs {
    /// Lines to print (default 50).
    #[arg(
        short = 'n',
        long = "lines",
        default_value_t = 50,
        value_name = "count"
    )]
    pub(super) count: usize,
    /// Keep printing new objects; survives a rotation.
    #[arg(long)]
    pub(super) follow: bool,
    /// Objects at this severity or above: error, warn, info or debug.
    #[arg(long, value_name = "level")]
    pub(super) level: Option<String>,
    /// Objects with one of these event names (repeatable).
    #[arg(long = "event", value_name = "name")]
    pub(super) events: Vec<String>,
    /// Objects at or after this RFC 3339 time.
    #[arg(long, value_name = "rfc3339")]
    pub(super) since: Option<String>,
    /// Read crash.ndjson instead of server.ndjson.
    #[arg(long)]
    pub(super) crash: bool,
}

#[derive(Subcommand)]
pub(super) enum AuditVerb {
    Tail(AuditTailArgs),
}

#[derive(Args)]
pub(super) struct AuditTailArgs {
    /// Records to print (default 50).
    #[arg(
        short = 'n',
        long = "lines",
        default_value_t = 50,
        value_name = "count"
    )]
    pub(super) count: usize,
    /// Keep printing new records; survives a rotation.
    #[arg(long)]
    pub(super) follow: bool,
    /// Records served by this account (display name).
    #[arg(long, value_name = "display-name")]
    pub(super) account: Option<String>,
    /// Records of this client principal.
    #[arg(long, value_name = "id")]
    pub(super) client: Option<String>,
    /// Records of this session.
    #[arg(long, value_name = "id")]
    pub(super) session: Option<String>,
    /// Records with this final status.
    #[arg(long, value_name = "code")]
    pub(super) status: Option<u16>,
    /// Records where the serving account differs from the first attempted.
    #[arg(long)]
    pub(super) failed_over: bool,
    /// Records at or after this RFC 3339 time. Filters combine with AND.
    #[arg(long, value_name = "rfc3339")]
    pub(super) since: Option<String>,
}

#[derive(Args)]
pub(super) struct SwitchArgs {
    /// The account; omitted with no --clear, the listing with the default marked.
    pub(super) reference: Option<String>,
    /// Steer this configured route instead of the default.
    #[arg(long, value_name = "name")]
    pub(super) route: Option<String>,
    /// Remove the route's preference.
    #[arg(long, requires = "route", conflicts_with = "reference")]
    pub(super) clear: bool,
}

#[derive(Subcommand)]
pub(super) enum AccountVerb {
    List,
    Show {
        reference: String,
    },
    Add(AddArgs),
    Login(LoginArgs),
    Operation {
        #[command(subcommand)]
        verb: OperationVerb,
    },
    Replace {
        reference: String,
        #[command(flatten)]
        args: ReplaceArgs,
    },
    Remove {
        reference: String,
    },
    Rename {
        reference: String,
        new_name: String,
    },
    Enable {
        reference: String,
    },
    Disable {
        reference: String,
    },
}

#[derive(Args)]
pub(super) struct LoginArgs {
    /// Display name for the new account; the profile derives one without it.
    #[arg(long)]
    pub(super) name: Option<String>,
    /// Whose login: a Claude account (the default) or a ChatGPT one for Codex.
    #[arg(long, value_enum, value_name = "provider", default_value_t)]
    pub(super) provider: Provider,
    /// Print the URL and the operation id and exit at once.
    #[arg(long)]
    pub(super) no_wait: bool,
    #[command(flatten)]
    pub(super) channel: SecretChannel,
}

#[derive(Subcommand)]
pub(super) enum OperationVerb {
    Show {
        operation_id: String,
    },
    Code {
        operation_id: String,
        #[command(flatten)]
        channel: SecretChannel,
    },
    Cancel {
        operation_id: String,
    },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub(super) struct SourceFlags {
    /// An Anthropic API key, by hidden prompt, --stdin or --file.
    #[arg(long)]
    pub(super) api_key: bool,
    /// A portable credential object, by hidden prompt, --stdin or --file.
    #[arg(long)]
    pub(super) portable: bool,
    /// A protected file on the server host that the server reads.
    #[arg(long, value_name = "path")]
    pub(super) server_file: Option<PathBuf>,
    /// The credential Claude Code holds on the server host.
    #[arg(long)]
    pub(super) claude_managed: bool,
}

#[derive(Args)]
pub(super) struct AddArgs {
    #[command(flatten)]
    pub(super) source: SourceFlags,
    /// Display name; required for --api-key, derived otherwise.
    #[arg(long)]
    pub(super) name: Option<String>,
    #[command(flatten)]
    pub(super) channel: SecretChannel,
    /// Which managed source to read; only beside --claude-managed.
    #[arg(long, value_name = "keychain|file", requires = "claude_managed")]
    pub(super) platform_hint: Option<String>,
}

/// The two explicit channels for a secret, shared by every verb that reads one.
#[derive(Args, Default)]
pub(super) struct SecretChannel {
    /// Read the secret from standard input, up to 64 KiB.
    #[arg(long, conflicts_with = "file")]
    pub(super) stdin: bool,
    /// Read the secret from an owner-only file on this machine.
    #[arg(long, value_name = "path")]
    pub(super) file: Option<PathBuf>,
}

#[derive(Args)]
pub(super) struct ReplaceArgs {
    #[command(flatten)]
    pub(super) source: SourceFlags,
    #[command(flatten)]
    pub(super) channel: SecretChannel,
    /// Which managed source to read; only beside --claude-managed.
    #[arg(long, value_name = "keychain|file", requires = "claude_managed")]
    pub(super) platform_hint: Option<String>,
}

#[derive(Args)]
pub(super) struct ApiArgs {
    /// The HTTP method.
    pub(super) method: String,
    /// The path on the base-URL origin, starting with /.
    pub(super) path: String,
    #[arg(long, value_name = "path", conflicts_with = "body_stdin")]
    pub(super) body_file: Option<PathBuf>,
    #[arg(long)]
    pub(super) body_stdin: bool,
    #[arg(long = "header", value_name = "name:value")]
    pub(super) headers: Vec<String>,
    /// Pin the exchange to this account (`pin.`).
    #[arg(long, value_name = "reference", conflicts_with = "prefer")]
    pub(super) account: Option<String>,
    /// Prefer this account (`pref.`).
    #[arg(long, value_name = "reference")]
    pub(super) prefer: Option<String>,
    /// Force the engineer role: send as the enrolled client.
    #[arg(long, conflicts_with = "operator")]
    pub(super) client: bool,
    /// Force the operator role.
    #[arg(long)]
    pub(super) operator: bool,
}

#[derive(Subcommand)]
pub(super) enum ClientVerb {
    List,
    Show {
        id: String,
    },
    Invite(InviteArgs),
    Reissue {
        id: String,
        #[command(flatten)]
        terms: InviteTerms,
    },
    Rotate {
        id: String,
        #[arg(long, value_name = "path")]
        disclose_to: Option<PathBuf>,
    },
    Revoke {
        id: String,
    },
    Rename {
        id: String,
        display_name: String,
    },
}

#[derive(Args)]
pub(super) struct InviteArgs {
    pub(super) id: String,
    /// The display name; the id when omitted.
    #[arg(long, value_name = "display-name")]
    pub(super) name: Option<String>,
    #[command(flatten)]
    pub(super) terms: InviteTerms,
}

#[derive(Args)]
pub(super) struct InviteTerms {
    /// How long the invite works: seconds, or a number and s, m, h or d.
    #[arg(long, value_name = "duration", value_parser = super::invite::expiry_seconds)]
    pub(super) expires: Option<u64>,
    /// The joining machine adds no Claude account of its own.
    #[arg(long)]
    pub(super) no_account: bool,
    #[arg(long, value_name = "path")]
    pub(super) disclose_to: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(super) enum OperatorVerb {
    Secret {
        #[command(subcommand)]
        verb: OperatorSecretVerb,
    },
}

#[derive(Subcommand)]
pub(super) enum OperatorSecretVerb {
    Set {
        #[arg(long, value_name = "path")]
        disclose_to: Option<PathBuf>,
    },
    Remove,
}

#[derive(Subcommand)]
pub(super) enum CaVerb {
    Show,
    Export {
        #[arg(long, value_name = "path")]
        out: Option<PathBuf>,
    },
    Rotate {
        /// Replace the CA at once instead of staging the next one.
        #[arg(long)]
        now: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum ReleaseVerb {
    /// The newest published version, discovered at the origin's `latest`
    /// redirect of the release origin.
    Latest {
        /// A verified `https` mirror in place of the official origin.
        #[arg(long, value_name = "https-origin")]
        release_origin: Option<String>,
    },
    Verify {
        target: PathBuf,
        /// A signing key id during a rotation overlap.
        #[arg(long, value_name = "id")]
        key_id: Option<String>,
    },
    Fetch {
        version: String,
        #[arg(long, value_name = "dir")]
        out: PathBuf,
        /// A Rust target triple; default: this machine's.
        #[arg(long, value_name = "rust-target")]
        target: Option<String>,
        /// A verified `https` mirror in place of the official origin.
        #[arg(long, value_name = "https-origin")]
        release_origin: Option<String>,
    },
}

#[derive(Subcommand)]
pub(super) enum ServerVerb {
    Preflight {
        #[arg(long, value_name = "release-dir")]
        from: Option<PathBuf>,
    },
    Install {
        /// A release directory on this host instead of a download.
        #[arg(long, value_name = "release-dir", conflicts_with_all = ["version", "binary", "release_origin"])]
        from: Option<PathBuf>,
        /// The published version to fetch; default: the newest.
        #[arg(long, value_name = "semver", conflicts_with = "binary")]
        version: Option<String>,
        /// A clone's own build, installed with the official client kit of its version.
        #[arg(long, value_name = "path")]
        binary: Option<PathBuf>,
        /// The client kit for --binary instead of the official one.
        #[arg(long, value_name = "zip", requires = "binary")]
        kit: Option<PathBuf>,
        /// The data-plane address when install writes the configuration;
        /// default: Tailscale's, else this host's only private one.
        #[arg(long, value_name = "ip")]
        listen: Option<std::net::IpAddr>,
        /// A verified `https` mirror in place of the official origin; later
        /// updates follow it.
        #[arg(long, value_name = "https-origin")]
        release_origin: Option<String>,
    },
    Update {
        #[arg(long, value_name = "release-dir", conflicts_with = "version")]
        from: Option<PathBuf>,
        /// Default: the newest release of the origin the server was
        /// installed from, or its clone build again.
        #[arg(long, value_name = "semver")]
        version: Option<String>,
        /// The explicit downgrade form.
        #[arg(long)]
        allow_downgrade: bool,
        /// A verified `https` mirror in place of the recorded or official
        /// origin; later updates follow it.
        #[arg(long, value_name = "https-origin", conflicts_with = "from")]
        release_origin: Option<String>,
    },
    Uninstall {
        /// Remove state and logs too; interactive-only.
        #[arg(long)]
        purge: bool,
    },
    Prune {
        /// Prior releases to keep (default 1).
        #[arg(long, default_value_t = 1, value_name = "n")]
        keep: usize,
    },
    AutoUpdate {
        #[arg(value_enum)]
        switch: Switch,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum Switch {
    On,
    Off,
}

#[derive(Subcommand)]
pub(super) enum ServiceVerb {
    Install,
    Remove,
    Start,
    Stop,
    Restart,
    Status,
}

/// `claude`'s, `codex`'s and `env`'s launch intent: at most one of the three.
#[derive(Args)]
pub(super) struct LaunchArgs {
    /// Pin the session to this account.
    #[arg(long, value_name = "reference", conflicts_with_all = ["auto", "direct"])]
    pub(super) account: Option<String>,
    /// Let the pool choose.
    #[arg(long, conflicts_with = "direct")]
    pub(super) auto: bool,
    /// Bypass the pool.
    #[arg(long)]
    pub(super) direct: bool,
}

/// `claude` and `codex`.
#[derive(Args)]
pub(super) struct ToolArgs {
    #[command(flatten)]
    pub(super) launch: LaunchArgs,
    /// The picker; wins over JAYNSHARE_PICKER.
    #[arg(long, value_enum, value_name = "picker")]
    pub(super) picker: Option<Picker>,
    /// Passed to the tool unchanged and in order: everything
    /// after the launcher's own options, and everything after `--`,
    /// including a later literal `--` and words that look like options.
    #[arg(
        trailing_var_arg = true,
        value_name = "tool arguments",
        allow_hyphen_values = true
    )]
    pub(super) args: Vec<std::ffi::OsString>,
}

#[derive(Args)]
pub(super) struct EnvArgs {
    #[command(flatten)]
    pub(super) launch: LaunchArgs,
    /// The shell to quote for; detected from the parent when omitted.
    #[arg(long, value_enum, value_name = "shell")]
    pub(super) shell: Option<Shell>,
    /// Print even when standard output is a terminal.
    #[arg(long)]
    pub(super) show: bool,
}

#[derive(Subcommand)]
pub(super) enum TrustCaVerb {
    Add,
    Remove,
}

#[derive(Subcommand)]
pub(super) enum SecretVerb {
    Set {
        #[command(flatten)]
        channel: SecretChannel,
    },
}
