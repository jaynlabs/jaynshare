//! `env`: the launch environment of `claude` or `codex` — the same
//! `launch::prepare` plan — printed for the shell to evaluate, every value
//! quoted for that shell. Refused on a terminal without `--show`; `--json`
//! is refused before this runs (`schema::NO_JSON`).

use std::io::IsTerminal;

use super::args::{EnvArgs, Shell};
use super::tool::intent;
use super::{Failure, Outcome};
use crate::launch;

/// `env`: the launch environment as shell assignments.
pub(super) fn env(args: &EnvArgs) -> Outcome {
    if std::io::stdout().is_terminal() && !args.show {
        return Err(Failure::local(
            2,
            "cli_usage",
            "env prints the client secret for a shell to evaluate; run it as eval \"$(jaynshare env …)\", or add --show to print it on this terminal",
        ));
    }
    let request = launch::Request {
        provider: args.provider,
        intent: intent(&args.launch),
        picker: None,
        args: Vec::new(),
    };
    let prepared = launch::prepare(request, false)
        .map_err(|refusal| Failure::local(refusal.code, refusal.slug, refusal.message))?;
    for notice in &prepared.notices {
        eprintln!("{notice}");
    }
    let shell = match args.shell {
        Some(Shell::Sh) => launch::shell::Shell::Sh,
        Some(Shell::Fish) => launch::shell::Shell::Fish,
        Some(Shell::Powershell) => launch::shell::Shell::Powershell,
        Some(Shell::Cmd) => launch::shell::Shell::Cmd,
        None => launch::shell::detect(),
    };
    let mut lines: Vec<String> = prepared
        .plan
        .set
        .iter()
        .map(|(name, value)| launch::shell::set_line(shell, name, value))
        .collect();
    lines.extend(
        prepared
            .plan
            .unset
            .iter()
            .map(|name| launch::shell::unset_line(shell, name)),
    );
    Ok((serde_json::Value::Null, lines.join("\n")))
}
