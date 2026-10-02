//! The launcher: resolve the launch's account
//! intent, build Claude Code's environment, and replace this process with
//! Claude Code. `run` is the spine: every check runs in a fixed order, and
//! each leaf — an environment rule, the picker, the shell quoting of `env` —
//! lives in its own file.
//!
//! Nothing here reads a secret from anywhere but the client installation,
//! and nothing puts one in an argument vector: the child receives it through
//! its environment only.

pub mod env;
mod exec;
mod intent;
pub mod shell;

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use crate::client::{self, ClientInstallation};
use crate::picker;

pub use env::EnvPlan;

/// The deadline of the launch's authenticated check.
const REACHABLE_WITHIN: Duration = Duration::from_millis(1_500);
/// The snapshot and catalogue reads made before the launch.
const READ_TIMEOUT: Duration = Duration::from_millis(1_500);

/// The launch mode the flags chose (clap already refused two).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentFlag {
    /// No flag: the picker decides, unless `JAYNSHARE_ACCOUNT` names an
    /// account.
    Pick,
    Account(String),
    Auto,
    Direct,
}

/// One `claude` or `env` invocation, stripped of clap's types.
pub struct Request {
    pub intent: IntentFlag,
    pub picker: Option<picker::Kind>,
    /// Passed to Claude Code unchanged and in order.
    pub claude_args: Vec<OsString>,
}

/// A refusal before the replacement: the exit code and slug, and the
/// message for standard error.
#[derive(Debug)]
pub struct Refusal {
    pub code: i32,
    pub slug: &'static str,
    pub message: String,
}

impl Refusal {
    fn new(code: i32, slug: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            slug,
            message: message.into(),
        }
    }
}

/// A launch ready to happen: the child's environment, and for `claude` the
/// Claude Code executable found on the search path.
pub struct Prepared {
    pub plan: EnvPlan,
    pub claude: Option<PathBuf>,
    /// Lines for standard error before the launch: the unselectable-account
    /// warning, the "the pool is not in use" notice.
    pub notices: Vec<String>,
}

/// `run`: prepare, then replace this process with Claude Code. Returns only
/// on a refusal, or — where the platform cannot replace a process — with
/// Claude Code's own exit code.
pub fn run(request: Request) -> Result<i32, Refusal> {
    let args = request.claude_args.clone();
    let prepared = prepare(request, true)?;
    for notice in &prepared.notices {
        eprintln!("{notice}");
    }
    let claude = prepared.claude.expect("run looks Claude Code up");
    exec::exec(&claude, &args, &prepared.plan)
}

/// The shared half of `claude` and `env`: every check and the plan.
/// `launch` is false for `env`, which needs no Claude Code executable.
pub fn prepare(request: Request, launch: bool) -> Result<Prepared, Refusal> {
    let mut notices = Vec::new();
    // The environment's pin is consumed whatever the flags say; an
    // explicit flag wins over it (the flag is the more
    // deliberate input).
    let ambient = std::env::var("JAYNSHARE_ACCOUNT")
        .ok()
        .filter(|v| !v.is_empty());
    let intent = match (request.intent, ambient) {
        (IntentFlag::Pick, Some(reference)) => IntentFlag::Account(reference),
        (flag, _) => flag,
    };

    if intent == IntentFlag::Direct {
        // A direct launch needs nothing from the pool — but `claude` is
        // an engineer verb, so the client installation must exist.
        client::read_installation().map_err(installation_refusal)?;
        let mut plan = EnvPlan::default();
        env::direct::apply(&mut plan);
        plan.unset("JAYNSHARE_ACCOUNT");
        plan.unset(crate::statusline::ACTIVE_ENV);
        notices.push(
            "jaynshare: --direct: the pool is not in use; Claude Code runs under your own login"
                .to_string(),
        );
        let claude = if launch {
            Some(exec::find_claude().map_err(claude_missing)?)
        } else {
            None
        };
        return Ok(Prepared {
            plan,
            claude,
            notices,
        });
    }

    // Pick mode needs a terminal, and says so before anything else.
    let picker_kind = if intent == IntentFlag::Pick {
        // A `JAYNSHARE_PICKER` outside its closed set refuses before launch.
        let chosen = picker::choose(request.picker)
            .map_err(|message| Refusal::new(2, "cli_usage", message))?;
        Some(chosen.ok_or_else(|| {
            Refusal::new(
                16,
                "cli_no_terminal",
                "there is no terminal for the account picker; launch with --account <reference> or --auto",
            )
        })?)
    } else {
        None
    };

    // The installation is the client installation's files, and only those.
    let mut installation = client::read_installation().map_err(installation_refusal)?;
    let secret = client::read_secret(&installation).map_err(installation_refusal)?;
    require_proxy(&installation)?;

    // No pooled environment is ever built without Claude Code.
    let claude = if launch {
        Some(exec::find_claude().map_err(claude_missing)?)
    } else {
        None
    };

    // One intercepted probe gives an authenticated answer within 1.5 s, or
    // nothing launches; the snapshot stays best-effort.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(reachable(&mut installation, &secret))?;
    let snapshot = runtime
        .block_on(client::snapshot(&installation, &secret, None, READ_TIMEOUT))
        .ok();
    if let Some(snapshot) = &snapshot {
        runtime.block_on(crate::client_ca::follow(
            &mut installation,
            &secret,
            snapshot,
        ));
        if launch {
            runtime.block_on(crate::cli::follow(&installation, &secret, snapshot));
        }
    }
    // The hold hint; an unreadable snapshot leaves the deadline alone.
    let hold_hint = snapshot.and_then(|snapshot| snapshot["hold_hint_seconds"].as_u64());

    let token = runtime.block_on(async {
        match &intent {
            IntentFlag::Account(reference) => {
                intent::resolve(&installation, &secret, reference, &mut notices).await
            }
            IntentFlag::Pick => {
                intent::pick(&installation, &secret, picker_kind.expect("pick mode")).await
            }
            IntentFlag::Auto => Ok(None),
            IntentFlag::Direct => unreachable!("handled above"),
        }
    })?;

    let mut plan = env::build(&env::Inputs {
        installation: &installation,
        secret: &secret,
        token: token.as_deref(),
        hold_hint,
        inherited_timeout: std::env::var("API_TIMEOUT_MS").ok(),
    });
    if launch {
        plan.set(crate::statusline::ACTIVE_ENV, "1");
    } else {
        plan.unset(crate::statusline::ACTIVE_ENV);
    }
    Ok(Prepared {
        plan,
        claude,
        notices,
    })
}

/// Every launch is MITM mode, so the enrollment must name a proxy origin.
fn require_proxy(installation: &ClientInstallation) -> Result<(), Refusal> {
    if installation.proxy.as_deref().is_none_or(str::is_empty) {
        return Err(Refusal::new(
            14,
            "cli_transport_unavailable",
            "this enrollment has no proxy origin; the server must enable MITM mode and the machine be enrolled again",
        ));
    }
    Ok(())
}

/// The launch check. A missing `ca.pem`, or one the proxy's handshake fails,
/// is fetched from the server first, once.
async fn reachable(installation: &mut ClientInstallation, secret: &str) -> Result<(), Refusal> {
    let origin = installation.proxy.clone().unwrap_or_default();
    let ca = installation.directory.join("ca.pem");
    if !ca.is_file() {
        crate::client_ca::refresh(installation, secret)
            .await
            .map_err(|why| {
                Refusal::new(
                    14,
                    "cli_transport_unavailable",
                    format!(
                        "this enrollment has no CA certificate ({} is missing), and the server's could not be fetched: {why}",
                        ca.display()
                    ),
                )
            })?;
    }
    let checked = match crate::probe_client::launch_check(installation, secret, REACHABLE_WITHIN)
        .await
    {
        Err(12) => match crate::client_ca::refresh(installation, secret).await {
            Ok(true) => crate::probe_client::launch_check(installation, secret, REACHABLE_WITHIN)
                .await
                .map_err(|code| (code, String::new())),
            Ok(false) => Err((12, String::new())),
            Err(why) => Err((12, why)),
        },
        other => other.map_err(|code| (code, String::new())),
    };
    checked.map_err(|(code, why)| check_refusal(&origin, code, &why))
}

/// A failed check names the origin and the `--direct` way out, and keeps
/// the failure's class — 4 no answer, 5 the credential refused, 6 no
/// snapshot under that origin, 10 a failed or incompatible server, 12 the CA
/// failed.
fn check_refusal(origin: &str, code: i32, why: &str) -> Refusal {
    let (code, slug, what) = match code {
        4 => (
            4,
            "cli_unreachable",
            "gave no answer within 1.5 s; the pool is unreachable",
        ),
        5 => (5, "cli_refused", "refused this machine's credential"),
        6 => (6, "cli_not_found", "has no client snapshot"),
        10 => (
            10,
            "cli_incompatible_server",
            "failed, or answered as no server this build speaks to",
        ),
        12 => (
            12,
            "cli_ca_untrusted",
            "failed the TLS handshake against this installation's CA",
        ),
        _ => (1, "cli_internal", "could not be checked"),
    };
    let why = if why.is_empty() {
        String::new()
    } else {
        format!(" ({why})")
    };
    Refusal::new(
        code,
        slug,
        format!(
            "{origin} {what}{why}. `jaynshare claude --direct` launches Claude Code outside the pool, under your own login"
        ),
    )
}

fn installation_refusal((code, message): (i32, String)) -> Refusal {
    let slug = match code {
        11 => "cli_not_enrolled",
        5 => "cli_refused",
        3 => "cli_configuration_invalid",
        _ => "cli_internal",
    };
    Refusal::new(code, slug, message)
}

fn claude_missing(why: String) -> Refusal {
    Refusal::new(
        13,
        "cli_claude_missing",
        format!(
            "Claude Code is not installed or not on the search path ({why}); install Claude Code (https://code.claude.com) and launch again"
        ),
    )
}
