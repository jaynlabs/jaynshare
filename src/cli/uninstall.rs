//! `uninstall`: remove the executable, its place on the search path, the
//! installation's files and only the two Claude Code settings entries; leave Claude Code, its credentials,
//! transcripts and every unrelated setting; report anything that could not be
//! removed. The server's registry is not touched.

use std::io::ErrorKind;

use serde_json::{Value, json};

use super::args::Cli;
use super::{Failure, Outcome};

/// One `uninstall`, no server call, no confirmation. A settings file
/// that is not valid JSON is reported and skipped — everything else still
/// goes; any file that cannot be removed is reported and the exit is 1.
pub(super) async fn uninstall(cli: &Cli) -> Outcome {
    let _ = cli;
    let installation = crate::client::read_installation().map_err(|(code, message)| {
        if code == 11 {
            Failure::local(11, "cli_not_enrolled", message)
        } else {
            Failure::local(code, "cli_internal", message)
        }
    })?;

    crate::desktop::restore_if_present(&installation.directory)
        .await
        .map_err(|why| Failure::local(1, "cli_internal", format!("Desktop integration could not be restored: {why}; the client installation is kept so restore can be retried")))?;

    let executable = crate::config::platform::client_binary();
    match crate::settings::plan_uninstall(&executable) {
        Ok(Some(plan)) => {
            if let Err(why) = crate::settings::commit(&plan) {
                report_skipped_settings(&why);
            } else {
                // A byte-exact restore also drops the now-redundant
                // backup; any other backup stays.
                crate::settings::remove_backup(&plan.path);
            }
        }
        Ok(None) => {}
        Err(why) => report_skipped_settings(&why),
    }

    let directory = installation.directory.clone();
    let mut paths = vec![
        directory.join("client-secret"),
        directory.join("client.toml"),
        directory.join("desktop.lock"),
    ];
    for ca in [
        directory.join("ca.pem"),
        directory.join(crate::client::BASE_URL_CA_FILE),
    ] {
        if ca.exists() {
            paths.push(ca);
        }
    }
    paths.push(executable.clone());

    let mut removed: Vec<String> = super::search_path::unlink(&executable)
        .map(|link| link.display().to_string())
        .into_iter()
        .collect();
    let mut failures: Vec<(String, String)> = Vec::new();
    for path in paths {
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path.display().to_string()),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => failures.push((path.display().to_string(), e.to_string())),
        }
    }
    // Each directory goes when the removal left it empty; a leftover file
    // keeps it (we own every file it should hold, so empty is the norm). The
    // executable's own directory is ours too.
    for dir in [Some(directory.as_path()), executable.parent()]
        .into_iter()
        .flatten()
    {
        if std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none()) {
            match std::fs::remove_dir(dir) {
                Ok(()) => removed.push(dir.display().to_string()),
                Err(e) => failures.push((dir.display().to_string(), e.to_string())),
            }
        }
    }

    // The client facts and the removed paths, never the secret.
    let mut result = crate::client::client_result(&installation);
    result["files"] = json!(removed);
    result["not_removed"] = json!(
        failures
            .iter()
            .map(|(path, error)| json!({ "path": path, "error": error }))
            .collect::<Vec<Value>>()
    );

    let human = removed
        .iter()
        .map(|path| format!("removed {path}"))
        .collect::<Vec<_>>()
        .join("\n");
    if !failures.is_empty() {
        // One line per removed path, then one per failure; the exit names
        // every path it could not remove, after doing all it can.
        if !human.is_empty() {
            eprintln!("{human}");
        }
        let named = failures
            .iter()
            .map(|(path, error)| format!("{path} ({error})"))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Failure::local(
            1,
            "cli_internal",
            format!("could not remove: {named}"),
        ));
    }
    Ok((result, human))
}

fn report_skipped_settings(why: &str) {
    eprintln!(
        "warning: the Claude Code settings entries were not removed ({why}); everything else is removed"
    );
}
