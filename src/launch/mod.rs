//! The launcher: resolve the launch's account
//! intent, build the tool's environment, and replace this process with
//! Claude Code or Codex. `run` is the spine: every check runs in a fixed
//! order, and each leaf — an environment rule, the picker, the shell quoting
//! of `env` — lives in its own file.
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
use crate::provider::{Provider, Tool};

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

/// One `claude`, `codex`, bare `jaynshare` or `env` invocation, stripped of
/// clap's types.
pub struct Request {
    /// Whose tool launches, on whose accounts; `None` offers every
    /// provider's in the picker, and the account picked decides.
    pub provider: Option<Provider>,
    pub intent: IntentFlag,
    pub picker: Option<picker::Kind>,
    /// Passed to the tool unchanged and in order.
    pub args: Vec<OsString>,
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

/// A launch ready to happen: the child's environment and arguments, and for
/// a launch the tool's executable found on the search path.
pub struct Prepared {
    pub plan: EnvPlan,
    pub executable: Option<PathBuf>,
    pub args: Vec<OsString>,
    /// Lines for standard error before the launch: the unselectable-account
    /// warning, the "the pool is not in use" notice.
    pub notices: Vec<String>,
}

/// `run`: prepare, then replace this process with the tool. Returns only
/// on a refusal, or — where the platform cannot replace a process — with
/// the tool's own exit code.
pub fn run(request: Request) -> Result<i32, Refusal> {
    let prepared = prepare(request, true)?;
    for notice in &prepared.notices {
        eprintln!("{notice}");
    }
    let executable = prepared.executable.expect("run looks the tool up");
    exec::exec(&executable, &prepared.args, &prepared.plan)
}

/// The shared half of `claude`, `codex`, bare `jaynshare` and `env`: every
/// check and the plan. `launch` is false for `env`, which needs no executable.
pub fn prepare(request: Request, launch: bool) -> Result<Prepared, Refusal> {
    let mut notices = Vec::new();
    // The environment's pin is consumed whatever the flags say; an
    // explicit flag wins over it (the flag is the more
    // deliberate input). Bare `jaynshare` always picks.
    let ambient = std::env::var("JAYNSHARE_ACCOUNT")
        .ok()
        .filter(|v| !v.is_empty() && request.provider.is_some());
    let intent = match (request.intent, ambient) {
        (IntentFlag::Pick, Some(reference)) => IntentFlag::Account(reference),
        (flag, _) => flag,
    };

    if intent == IntentFlag::Direct {
        let tool = request.provider.expect("--direct names its tool").tool();
        // A direct launch needs nothing from the pool — but `claude` is
        // an engineer verb, so the client installation must exist.
        client::read_installation().map_err(installation_refusal)?;
        let mut plan = EnvPlan::default();
        env::direct::apply(&mut plan, tool);
        plan.unset("JAYNSHARE_ACCOUNT");
        plan.unset(crate::statusline::ACTIVE_ENV);
        notices.push(format!(
            "jaynshare: --direct: the pool is not in use; {} runs under your own login",
            tool.name
        ));
        return Ok(Prepared {
            plan,
            executable: executable(tool, launch)?,
            args: request.args,
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

    // No pooled environment is ever built without the tool; when the
    // account picked decides it, it is looked up once picked.
    let found = match request.provider {
        Some(provider) => executable(provider.tool(), launch)?,
        None => None,
    };

    // One intercepted probe gives an authenticated answer within 1.5 s, or
    // nothing launches; the snapshot stays best-effort.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(reachable(&mut installation, &secret, request.provider))?;
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

    let (provider, token) = runtime.block_on(select(
        &installation,
        &secret,
        request.provider,
        intent,
        picker_kind,
        &mut notices,
    ))?;
    let tool = provider.tool();
    let executable = if found.is_some() {
        found
    } else {
        executable(tool, launch)?
    };

    let mut plan = env::build(&env::Inputs {
        tool,
        installation: &installation,
        secret: &secret,
        token: token.as_deref(),
        hold_hint,
        inherited_timeout: tool
            .deadline
            .as_ref()
            .and_then(|deadline| std::env::var(deadline.variable).ok()),
    });
    if launch {
        plan.set(crate::statusline::ACTIVE_ENV, "1");
    } else {
        plan.unset(crate::statusline::ACTIVE_ENV);
    }
    let args = tool
        .pooled_args
        .iter()
        .map(OsString::from)
        .chain(request.args)
        .collect();
    Ok(Prepared {
        plan,
        executable,
        args,
        notices,
    })
}

/// Provider selection shared by the MITM launcher and Desktop's native Gateway.
pub async fn select(
    installation: &ClientInstallation,
    secret: &str,
    provider: Option<Provider>,
    flag: IntentFlag,
    kind: Option<picker::Kind>,
    notices: &mut Vec<String>,
) -> Result<(Provider, Option<String>), Refusal> {
    let flag = match (flag, std::env::var("JAYNSHARE_ACCOUNT").ok()) {
        (IntentFlag::Pick, Some(reference)) if !reference.is_empty() && provider.is_some() => {
            IntentFlag::Account(reference)
        }
        (flag, _) => flag,
    };
    match (flag, provider) {
        (IntentFlag::Account(reference), Some(provider)) => {
            let token =
                intent::resolve(installation, secret, &reference, provider, notices).await?;
            Ok((provider, token))
        }
        (IntentFlag::Pick, provider) => {
            let kind = picker::choose(kind)
                .map_err(|message| Refusal::new(2, "cli_usage", message))?
                .ok_or_else(|| Refusal::new(16, "cli_no_terminal",
                    "there is no terminal for the account picker; launch with --account <reference> or --auto"))?;
            intent::pick(installation, secret, provider, kind).await
        }
        (IntentFlag::Auto, Some(provider)) => Ok((provider, None)),
        _ => Err(Refusal::new(
            2,
            "cli_usage",
            "this selection requires a provider and a pooled account",
        )),
    }
}

/// The tool's executable for a launch; `env` looks nothing up.
fn executable(tool: &Tool, launch: bool) -> Result<Option<PathBuf>, Refusal> {
    if !launch {
        return Ok(None);
    }
    exec::find(tool.executable)
        .map(Some)
        .map_err(|why| missing(tool, why))
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
async fn reachable(
    installation: &mut ClientInstallation,
    secret: &str,
    provider: Option<Provider>,
) -> Result<(), Refusal> {
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
    checked.map_err(|(code, why)| check_refusal(&origin, code, &why, provider))
}

/// A failed check names the origin and the `--direct` way out (every
/// tool's when no provider was named), and keeps the failure's class — 4 no
/// answer, 5 the credential refused, 6 no snapshot under that origin, 10 a
/// failed or incompatible server, 12 the CA failed.
fn check_refusal(origin: &str, code: i32, why: &str, provider: Option<Provider>) -> Refusal {
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
    let providers = match provider {
        Some(provider) => vec![provider],
        None => Provider::ALL.to_vec(),
    };
    let direct = providers
        .into_iter()
        .map(|provider| {
            let tool = provider.tool();
            format!(
                "`jaynshare {} --direct` launches {}",
                tool.executable, tool.name
            )
        })
        .collect::<Vec<_>>()
        .join(" and ");
    Refusal::new(
        code,
        slug,
        format!("{origin} {what}{why}. {direct} outside the pool, under your own login"),
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

fn missing(tool: &Tool, why: String) -> Refusal {
    let Tool { name, home, .. } = tool;
    Refusal::new(
        13,
        tool.missing,
        format!(
            "{name} is not installed or not on the search path ({why}); install {name} ({home}) and launch again"
        ),
    )
}
