//! `server auto-update on|off`: a nightly systemd timer that runs
//! `server update --yes`, whose rollback covers a bad release; clients follow
//! the server on their next launch. Release installs only: a clone's build
//! is updated by rebuilding it.

use std::path::Path;

use super::native::{self, Origin};
use super::result::{Check, DeployResult};
use super::systemd;

pub const TIMER_NAME: &str = "jaynshare-update.timer";
pub const TIMER_PATH: &str = "/etc/systemd/system/jaynshare-update.timer";
/// The oneshot the timer starts, named after it as systemd expects.
pub const SERVICE_PATH: &str = "/etc/systemd/system/jaynshare-update.service";
const CHECK: &str = "manager.auto_update";

/// Between 03:00 and 04:00 server time; a night the host was off runs at boot.
pub const TIMER_TEXT: &str = "\
# Starts jaynshare-update.service nightly. Installed by `jaynshare server auto-update on`.
[Unit]
Description=Nightly Jaynshare server update

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
";

pub fn service_text() -> String {
    format!(
        "# Updates the Jaynshare server from its release origin. Installed by `jaynshare server auto-update on`.\n\
         [Unit]\n\
         Description=Jaynshare server update\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={current}/jaynshare server update --yes\n",
        current = native::CURRENT,
    )
}

pub fn is_on() -> bool {
    [TIMER_PATH, SERVICE_PATH]
        .iter()
        .any(|path| Path::new(path).exists())
}

/// Refused before anything is written when nothing is installed or the
/// install follows a clone's build.
pub fn on() -> DeployResult {
    let mut result = DeployResult::new("server auto-update on");
    if !native::gated(&mut result, native::platform_gate("server auto-update on")) {
        return result;
    }
    if std::fs::read_link(native::CURRENT).is_err() {
        result.checks.push(Check::fail(
            "conflict.install",
            "nothing is installed; use server install",
        ));
        return result;
    }
    let origin = native::recorded_origin().unwrap_or(Origin::Official);
    if let Origin::Build(binary) = &origin {
        result.checks.push(Check::fail(
            "conflict.origin",
            format!(
                "the server runs the build at {}; auto-update follows releases only, so rebuild and run tools/install-server.sh again",
                binary.display()
            ),
        ));
        return result;
    }
    for (path, text) in [(TIMER_PATH, TIMER_TEXT), (SERVICE_PATH, &service_text())] {
        if let Err(why) = systemd::write_unit_file(Path::new(path), text.as_bytes()) {
            result
                .checks
                .push(Check::fail(CHECK, format!("{path}: {why}")));
            return result;
        }
    }
    let started = systemd::systemctl_step(&mut result, CHECK, &["daemon-reload"])
        && systemd::systemctl_step(&mut result, CHECK, &["enable", TIMER_NAME])
        && systemd::systemctl_step(&mut result, CHECK, &["start", TIMER_NAME]);
    if started {
        result.checks.push(Check::pass(
            CHECK,
            format!(
                "the server updates nightly to {}; clients follow on their next launch",
                origin.followed()
            ),
        ));
    }
    result
}

pub fn off() -> DeployResult {
    let mut result = DeployResult::new("server auto-update off");
    if !native::gated(&mut result, native::platform_gate("server auto-update off")) {
        return result;
    }
    if !is_on() {
        result
            .checks
            .push(Check::pass(CHECK, "auto-update was already off"));
        return result;
    }
    if remove(&mut result) && systemd::systemctl_step(&mut result, CHECK, &["daemon-reload"]) {
        result.checks.push(Check::pass(
            CHECK,
            "the server no longer updates itself; server update still does",
        ));
    }
    result
}

/// Stops and disables the timer and removes both units, leaving the
/// manager's reload to the caller; `true` when every step passed. A running
/// update is left to finish.
pub(super) fn remove(result: &mut DeployResult) -> bool {
    if !is_on() {
        return true;
    }
    let disabled = systemd::systemctl_step(result, CHECK, &["stop", TIMER_NAME])
        && systemd::systemctl_step(result, CHECK, &["disable", TIMER_NAME]);
    if !disabled {
        return false;
    }
    for path in [TIMER_PATH, SERVICE_PATH] {
        match std::fs::remove_file(path) {
            Ok(()) => result
                .checks
                .push(Check::pass(CHECK, format!("removed {path}"))),
            Err(why) if why.kind() == std::io::ErrorKind::NotFound => {}
            Err(why) => {
                result
                    .checks
                    .push(Check::fail(CHECK, format!("{path}: {why}")));
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<&str> {
        text.lines().filter(|line| !line.starts_with('#')).collect()
    }

    #[test]
    fn the_service_runs_the_installed_update_unattended() {
        assert_eq!(
            lines(&service_text()),
            [
                "[Unit]",
                "Description=Jaynshare server update",
                "Wants=network-online.target",
                "After=network-online.target",
                "",
                "[Service]",
                "Type=oneshot",
                "ExecStart=/opt/jaynshare/current/jaynshare server update --yes",
            ]
        );
    }

    #[test]
    fn the_timer_fires_nightly_with_jitter_and_catches_up_at_boot() {
        assert_eq!(
            lines(TIMER_TEXT),
            [
                "[Unit]",
                "Description=Nightly Jaynshare server update",
                "",
                "[Timer]",
                "OnCalendar=*-*-* 03:00:00",
                "RandomizedDelaySec=1h",
                "Persistent=true",
                "",
                "[Install]",
                "WantedBy=timers.target",
            ]
        );
        assert_eq!(
            Path::new(TIMER_PATH).file_stem(),
            Path::new(SERVICE_PATH).file_stem()
        );
    }
}
