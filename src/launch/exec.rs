//! Finding the tool and the replacement itself.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{EnvPlan, Refusal};

/// The first `program` on the search path that is an executable file.
pub(super) fn find(program: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").ok_or_else(|| "PATH is not set".to_string())?;
    let names: Vec<String> = if cfg!(windows) {
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT".into());
        exts.split(';')
            .filter(|e| !e.is_empty())
            .map(|e| format!("{program}{}", e.to_ascii_lowercase()))
            .collect()
    } else {
        vec![program.to_string()]
    };
    for dir in std::env::split_paths(&path) {
        for name in &names {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    Err(format!("no `{program}` on PATH"))
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn command(program: &Path, args: &[OsString], plan: &EnvPlan) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    for name in &plan.unset {
        command.env_remove(name);
    }
    for (name, value) in &plan.set {
        command.env(name, value);
    }
    command
}

/// On Unix the launcher's process *becomes* the tool, so its
/// exit code and signals are the tool's; `exec` returns only on failure.
#[cfg(unix)]
pub(super) fn exec(program: &Path, args: &[OsString], plan: &EnvPlan) -> Result<i32, Refusal> {
    use std::os::unix::process::CommandExt;
    let error = command(program, args, plan).exec();
    Err(Refusal::new(
        1,
        "cli_internal",
        format!("could not start {}: {error}", program.display()),
    ))
}

/// Where no `exec` exists: wait for the tool and exit with its
/// status. (Console interrupts reach every process of the console group, so
/// the tool receives them directly.)
#[cfg(not(unix))]
pub(super) fn exec(program: &Path, args: &[OsString], plan: &EnvPlan) -> Result<i32, Refusal> {
    let status = command(program, args, plan).status().map_err(|error| {
        Refusal::new(
            1,
            "cli_internal",
            format!("could not start {}: {error}", program.display()),
        )
    })?;
    Ok(status.code().unwrap_or(1))
}
