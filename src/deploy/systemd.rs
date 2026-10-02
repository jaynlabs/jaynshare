//! The system unit and its manager: the unit text, the one
//! `systemctl` wrapper, `service install|remove|start|stop|restart|status`
//! and its six states. `systemctl` is reached by name from `PATH`; inside
//! the acceptance suite's `LinuxBox` that is a recording fake that runs the
//! real `jaynshare serve` as the service user.

use std::path::Path;
use std::process::Output;

use super::result::{Check, DeployResult};

/// The one system unit.
pub const UNIT_NAME: &str = "jaynshare.service";
/// Where the unit file is written.
pub const UNIT_PATH: &str = "/etc/systemd/system/jaynshare.service";

/// The one `systemctl` wrapper: `systemctl <args>`, standard input closed.
pub fn systemctl(args: &[&str]) -> Result<Output, String> {
    std::process::Command::new("systemctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("systemctl: {e}"))
}

/// The unit file's exact text. `config_override` is the
/// operator-chosen configuration path, the only `JAYNSHARE_*` variable the unit may
/// set. `Restart=on-failure` restarts after a failure, never after a clean
/// stop; stdout and stderr go to the journal, not an owned log.
pub fn unit_text(config_override: Option<&Path>) -> String {
    let environment = match config_override {
        // systemd's quoting: the whole assignment in double quotes, with
        // `\`, `"` escaped and `%` doubled (its specifier character).
        Some(path) => {
            let value = path
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('%', "%%");
            format!("Environment=\"JAYNSHARE_CONFIG={value}\"\n")
        }
        None => String::new(),
    };
    format!(
        "# The Jaynshare pool server. Installed by `jaynshare server install`.\n\
         [Unit]\n\
         Description=Jaynshare pool server\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         WorkingDirectory={home}\n\
         UMask=0077\n\
         ExecStart={current}/jaynshare serve\n\
         {environment}\
         Restart=on-failure\n\
         RestartSec=5\n\
         TimeoutStopSec=30\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        user = super::native::SERVICE_USER,
        home = super::native::SERVICE_HOME,
        current = super::native::CURRENT,
    )
}

/// The six states, as `service status` prints them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Absent,
    Stopped,
    Starting,
    Running,
    Failed,
    ManagerUnavailable,
}

impl ServiceState {
    /// The word `service status` prints.
    pub fn name(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Failed => "failed",
            Self::ManagerUnavailable => "manager-unavailable",
        }
    }
}

/// The unit's state from the manager. A manager that cannot answer
/// (systemctl failed, or systemd is not PID 1) is `ManagerUnavailable`; the
/// output's judgement is [`judge_state`]'s.
pub fn state() -> ServiceState {
    if !Path::new("/run/systemd/system").exists() {
        return ServiceState::ManagerUnavailable;
    }
    let output =
        systemctl(&["show", UNIT_NAME, "-p", "LoadState,ActiveState,SubState"]).map(|output| {
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).into_owned())
            } else {
                // Including "System has not been booted with systemd as init
                // system": the manager is there but cannot tell the state.
                Err(String::from_utf8_lossy(&output.stderr).into_owned())
            }
        });
    judge_state(output.and_then(|inner| inner))
}

/// The pure half of [`state`]: the `systemctl show` output, or why the
/// manager could not give it, as one of the six service states.
fn judge_state(output: Result<String, String>) -> ServiceState {
    let Ok(text) = output else {
        return ServiceState::ManagerUnavailable;
    };
    let property = |key: &str| {
        let prefix = format!("{key}=");
        text.lines().find_map(|line| line.strip_prefix(&prefix))
    };
    if property("LoadState") == Some("not-found") {
        return ServiceState::Absent;
    }
    match property("ActiveState").unwrap_or("") {
        "active" => ServiceState::Running,
        "activating" | "reloading" => ServiceState::Starting,
        "failed" => ServiceState::Failed,
        "inactive" | "deactivating" => ServiceState::Stopped,
        _ => ServiceState::ManagerUnavailable,
    }
}

/// `service <verb>`: which one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOp {
    Install,
    Remove,
    Start,
    Stop,
    Restart,
    Status,
}

/// One `service` verb. A manager failure is a `manager.*` check
/// (19); a written but unloaded unit is not success; on macOS and Windows
/// `service install` refuses before writing (`preflight.platform`, 18).
pub fn service(op: ServiceOp) -> DeployResult {
    let operation = match op {
        ServiceOp::Install => "service install",
        ServiceOp::Remove => "service remove",
        ServiceOp::Start => "service start",
        ServiceOp::Stop => "service stop",
        ServiceOp::Restart => "service restart",
        ServiceOp::Status => "service status",
    };
    let mut result = DeployResult::new(operation);
    if !cfg!(target_os = "linux") {
        // No launchd agent, Windows service or task; nothing is
        // written. `service status` reports the manager it cannot find.
        result.checks.push(if op == ServiceOp::Status {
            Check::fail(
                "manager.state",
                format!(
                    "{}: {} has no systemd",
                    ServiceState::ManagerUnavailable.name(),
                    std::env::consts::OS
                ),
            )
        } else {
            Check::fail(
                "preflight.platform",
                format!(
                    "{operation} is refused on {}: the server service is Linux with systemd only, and nothing was written",
                    std::env::consts::OS
                ),
            )
        });
        return result;
    }
    if op == ServiceOp::Install && !Path::new("/run/systemd/system").exists() {
        // Systemd is not PID 1; refuse before anything is written.
        result.checks.push(Check::fail(
            "preflight.platform",
            "systemd is not PID 1 on this machine; jaynshare.service was not written",
        ));
        return result;
    }
    match op {
        ServiceOp::Install => {
            if let Err(why) = write_unit_file(Path::new(UNIT_PATH), unit_text(None).as_bytes()) {
                result.checks.push(Check::fail(
                    "manager.install",
                    format!("{UNIT_PATH}: {why}"),
                ));
                return result;
            }
            if systemctl_step(&mut result, "manager.install", &["daemon-reload"])
                && systemctl_step(&mut result, "manager.install", &["enable", UNIT_NAME])
            {
                // A written but unloaded unit is not success.
                let state = state();
                if state == ServiceState::Absent {
                    result.checks.push(Check::fail(
                        "manager.install",
                        "the unit was written but the manager has not loaded it",
                    ));
                } else {
                    result.checks.push(Check::pass(
                        "manager.install",
                        format!("the unit is {}", state.name()),
                    ));
                }
            }
            result
        }
        ServiceOp::Remove => {
            if !Path::new(UNIT_PATH).exists() {
                result.checks.push(Check::pass(
                    "manager.remove",
                    "the unit was absent; nothing to remove",
                ));
                return result;
            }
            if systemctl_step(&mut result, "manager.remove", &["stop", UNIT_NAME])
                && systemctl_step(&mut result, "manager.remove", &["disable", UNIT_NAME])
            {
                match std::fs::remove_file(UNIT_PATH) {
                    Ok(()) => result.checks.push(Check::pass(
                        "manager.remove",
                        format!("removed {UNIT_PATH}"),
                    )),
                    Err(why) => {
                        result
                            .checks
                            .push(Check::fail("manager.remove", format!("{UNIT_PATH}: {why}")));
                        return result;
                    }
                }
                systemctl_step(&mut result, "manager.remove", &["daemon-reload"]);
            }
            result
        }
        ServiceOp::Start | ServiceOp::Stop | ServiceOp::Restart => {
            let verb = match op {
                ServiceOp::Start => "start",
                ServiceOp::Stop => "stop",
                _ => "restart",
            };
            let name = format!("manager.{verb}");
            if systemctl_step(&mut result, &name, &[verb, UNIT_NAME]) {
                let state = state();
                let settled = match op {
                    ServiceOp::Stop => state == ServiceState::Stopped,
                    _ => matches!(state, ServiceState::Running | ServiceState::Starting),
                };
                result.checks.push(if settled {
                    Check::pass(&name, format!("the unit is {}", state.name()))
                } else {
                    Check::fail(
                        &name,
                        format!("the unit is {} after systemctl {verb}", state.name()),
                    )
                });
            }
            result
        }
        ServiceOp::Status => {
            // Exactly one check whose message is the state word; it
            // fails only for a manager the state cannot be read from.
            let state = state();
            result
                .checks
                .push(if state == ServiceState::ManagerUnavailable {
                    Check::fail("manager.state", state.name())
                } else {
                    Check::pass("manager.state", state.name())
                });
            result
        }
    }
}

/// One systemctl step: pass, or a failed `name` check naming the command and
/// stderr's first line (a manager failure is a failure).
pub(super) fn systemctl_step(result: &mut DeployResult, name: &str, args: &[&str]) -> bool {
    let stderr = match systemctl(args) {
        Ok(output) if output.status.success() => {
            result
                .checks
                .push(Check::pass(name, format!("systemctl {}", args.join(" "))));
            return true;
        }
        Ok(output) => String::from_utf8_lossy(&output.stderr).into_owned(),
        Err(why) => why,
    };
    let first = stderr.lines().next().unwrap_or("no error output");
    result.checks.push(Check::fail(
        name,
        format!("systemctl {}: {first}", args.join(" ")),
    ));
    false
}

/// Writes the unit file, mode 0644.
pub(super) fn write_unit_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_is_exact_and_sets_no_variable_by_default() {
        let text = unit_text(None);
        for line in [
            "Wants=network-online.target",
            "After=network-online.target",
            "User=jaynshare",
            "Group=jaynshare",
            "WorkingDirectory=/var/lib/jaynshare",
            "UMask=0077",
            "ExecStart=/opt/jaynshare/current/jaynshare serve",
            "Restart=on-failure",
            "RestartSec=5",
            "StandardOutput=journal",
            "StandardError=journal",
            "WantedBy=multi-user.target",
        ] {
            assert!(text.lines().any(|l| l == line), "{line}:\n{text}");
        }
        assert!(!text.contains("Environment"), "{text}");
        assert!(!text.contains("JAYNSHARE_"), "{text}");
    }

    #[test]
    fn an_override_is_the_only_variable_and_is_quoted() {
        let text = unit_text(Some(Path::new("/etc/jaynshare conf/50%\"x.toml")));
        let set: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("Environment"))
            .collect();
        assert_eq!(
            set,
            ["Environment=\"JAYNSHARE_CONFIG=/etc/jaynshare conf/50%%\\\"x.toml\""],
            "{text}"
        );
        assert_eq!(text.matches("JAYNSHARE_").count(), 1, "{text}");
    }

    /// `systemctl show`'s three lines, as the fixture and real systemd print
    /// them.
    fn show(load: &str, active: &str) -> String {
        format!("LoadState={load}\nActiveState={active}\nSubState=dead\n")
    }

    #[test]
    fn judge_state_names_the_six_states() {
        let not_booted = "System has not been booted with systemd as init system (PID 1). \
                         Can't operate.";
        assert_eq!(
            judge_state(Err(not_booted.to_owned())),
            ServiceState::ManagerUnavailable
        );
        assert_eq!(
            judge_state(Ok(show("not-found", "inactive"))),
            ServiceState::Absent
        );
        assert_eq!(
            judge_state(Ok(show("loaded", "active"))),
            ServiceState::Running
        );
        assert_eq!(
            judge_state(Ok(show("loaded", "activating"))),
            ServiceState::Starting
        );
        assert_eq!(
            judge_state(Ok(show("loaded", "reloading"))),
            ServiceState::Starting
        );
        assert_eq!(
            judge_state(Ok(show("loaded", "failed"))),
            ServiceState::Failed
        );
        assert_eq!(
            judge_state(Ok(show("loaded", "inactive"))),
            ServiceState::Stopped
        );
        assert_eq!(
            judge_state(Ok(show("loaded", "deactivating"))),
            ServiceState::Stopped
        );
    }
}
