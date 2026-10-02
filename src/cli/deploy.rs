//! The deploy verbs: file-backed on the machine that runs them, no
//! control connection, the behaviour in `crate::deploy`. Each prints what it
//! is about to do on standard error first, and its `--json` result is the
//! deploy object.

use serde_json::json;

use super::args::{ReleaseVerb, ServerVerb, ServiceVerb, Verb};
use super::{Cli, Failure, Outcome};
use crate::deploy::native;
use crate::deploy::result::DeployResult;
use crate::deploy::systemd::{self, ServiceOp};

/// The deploy verbs this build carries; `None` for one whose behaviour has
/// not landed (its help still names the milestone, so the caller refused it
/// before reaching here).
pub(super) fn dispatch(cli: &Cli, verb: &Verb) -> Option<Outcome> {
    let release_row = (17, "cli_release_unverified");
    let fetch_row = (4, "cli_unreachable");
    let preflight_row = (18, "cli_preflight_failed");
    let manager_row = (19, "cli_manager_failed");
    match verb {
        Verb::Release {
            verb: ReleaseVerb::Verify { target, key_id },
        } => {
            eprintln!("verifying the release at {}", target.display());
            let result = crate::deploy::release::verify(target, key_id.as_deref());
            Some(finish(result, release_row))
        }
        Verb::Release {
            verb: ReleaseVerb::Latest { release_origin },
        } => {
            eprintln!("asking the release host for its newest release");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let mut result = DeployResult::new("release latest");
            match runtime.block_on(crate::deploy::release::newest_version(
                release_origin.as_deref(),
                cli.tls_ca.as_deref(),
            )) {
                Ok(version) => result.version = Some(version),
                Err(why) => result.checks.push(crate::deploy::result::Check::fail(
                    "release.unreachable",
                    why,
                )),
            }
            Some(finish(result, fetch_row))
        }
        Verb::Release {
            verb:
                ReleaseVerb::Fetch {
                    version,
                    out,
                    target,
                    release_origin,
                },
        } => {
            eprintln!(
                "fetching release {version} for {} into {}",
                target
                    .as_deref()
                    .unwrap_or(crate::deploy::release::native_target()),
                out.display()
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let result = runtime.block_on(crate::deploy::release::fetch(
                version,
                out,
                target.as_deref(),
                release_origin.as_deref(),
                cli.tls_ca.as_deref(),
            ));
            if let Some(check) = result
                .failed()
                .filter(|check| check.name == "release.origin")
            {
                return Some(Err(Failure::local(
                    2,
                    "cli_usage",
                    format!("{}: {}", check.name, check.message),
                )));
            }
            Some(finish(result, fetch_row))
        }
        Verb::Server {
            verb: ServerVerb::Preflight { from },
        } => {
            eprintln!("running the server preflight");
            let record = firewall_record(cli.config.as_deref());
            let result = crate::deploy::preflight::run(&crate::deploy::preflight::Inputs {
                from: from.as_deref(),
                config: cli.config.as_deref(),
                firewall_record: record.as_deref(),
            });
            Some(finish(result, preflight_row))
        }
        Verb::Server {
            verb: ServerVerb::Install { from },
        } => {
            eprintln!(
                "{}",
                server_plan(
                    &format!("installing the native server from {}", from.display()),
                    from,
                    cli.config.as_deref(),
                )
            );
            let record = firewall_record(cli.config.as_deref());
            let result = native::install(&native::InstallInputs {
                from,
                config: cli.config.as_deref(),
                firewall_record: record.as_deref(),
            });
            Some(finish(result, manager_row))
        }
        Verb::Server {
            verb:
                ServerVerb::Update {
                    from,
                    version,
                    allow_downgrade,
                    release_origin,
                },
        } => {
            match (from, version) {
                (Some(from), _) => eprintln!(
                    "{}",
                    server_plan(
                        &format!("updating the native server from {}", from.display()),
                        from,
                        cli.config.as_deref(),
                    )
                ),
                (None, Some(version)) => eprintln!("updating the native server to {version}"),
                (None, None) => {}
            }
            let record = firewall_record(Some(&native::service_config_path()));
            let result = native::update(&native::UpdateInputs {
                from: from.as_deref(),
                version: version.as_deref(),
                release_origin: release_origin.as_deref(),
                tls_ca: cli.tls_ca.as_deref(),
                allow_downgrade: *allow_downgrade,
                yes: cli.yes,
                confirm: &interactive_confirm,
                firewall_record: record.as_deref(),
            });
            Some(finish(result, manager_row))
        }
        Verb::Server {
            verb: ServerVerb::Uninstall { purge },
        } => {
            eprintln!(
                "uninstalling the native server{}",
                if *purge { " and purging its data" } else { "" }
            );
            Some(finish(
                native::uninstall(*purge, &interactive_confirm),
                manager_row,
            ))
        }
        Verb::Server {
            verb: ServerVerb::Prune { keep },
        } => {
            eprintln!("pruning native releases, keeping the newest {keep}");
            Some(finish(native::prune(*keep), manager_row))
        }
        Verb::Service { verb } => {
            let op = match verb {
                ServiceVerb::Install => ServiceOp::Install,
                ServiceVerb::Remove => ServiceOp::Remove,
                ServiceVerb::Start => ServiceOp::Start,
                ServiceVerb::Stop => ServiceOp::Stop,
                ServiceVerb::Restart => ServiceOp::Restart,
                ServiceVerb::Status => ServiceOp::Status,
            };
            let result = systemd::service(op);
            if matches!(verb, ServiceVerb::Status) {
                // The human form is exactly the state word on
                // one line; the DeployResult stays the `--json` answer and
                // the exit row is unchanged.
                let word = result
                    .checks
                    .iter()
                    .find(|check| check.name == "manager.state")
                    .and_then(|check| check.message.split(':').next())
                    .unwrap_or_default()
                    .to_string();
                let outcome = finish_with(result, manager_row, word.clone());
                return Some(match outcome {
                    // The word is the human answer even when the
                    // manager is unavailable; the exit code stays 19.
                    Ok(ok) => Ok(ok),
                    Err(failure) => {
                        if !cli.json {
                            println!("{word}");
                        }
                        Err(failure)
                    }
                });
            }
            Some(finish(result, manager_row))
        }
        _ => None,
    }
}

/// Where the host firewall cannot be inspected, an operator on a
/// terminal may continue only after recording the interface and rule they
/// checked; unattended, nothing is asked and preflight refuses. Asked only
/// when a configured listener is not loopback (the firewall check does not apply there).
fn firewall_record(config: Option<&std::path::Path>) -> Option<String> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let (path, _) = crate::config::config_selection(config);
    let loaded = crate::config::load(&path).ok()?;
    let mut listeners = vec![loaded.config.data_plane.listen];
    if loaded.config.mitm.enabled {
        listeners.push(loaded.config.mitm.listen);
    }
    listeners.retain(|listener| !listener.ip().is_loopback());
    if listeners.is_empty() {
        return None;
    }
    let why = uninspectable(&listeners)?;
    eprintln!(
        "\nThe host firewall cannot be inspected ({why}). Check by hand that every listener is \
admitted only from the private interface or source range."
    );
    interactive_confirm("record the interface and rule you checked (empty to stop): ")
        .ok()
        .filter(|line| !line.is_empty())
}

/// Why the firewall cannot be inspected for one of the non-loopback
/// `listeners` — `nft` itself, or a ruleset whose expressions the judgement
/// does not read, as iptables' own chain jumps and matches are — or `None`
/// when every one of them has a verdict. The interface is the assignment check's, so the
/// reason given is the one preflight's own check would report.
fn uninspectable(listeners: &[std::net::SocketAddr]) -> Option<String> {
    let ruleset = match crate::deploy::firewall::nft_ruleset() {
        Err(why) => return Some(why),
        Ok(ruleset) => ruleset,
    };
    unreadable_ruleset(&ruleset, listeners, &|ip| {
        crate::deploy::address::assigned(ip).ok().flatten()
    })
}

/// [`uninspectable`]'s judgement over an already-read ruleset, with the
/// interface lookup passed in so every case is testable. A listener on no
/// interface is an assignment failure and never a firewall one.
fn unreadable_ruleset(
    ruleset: &str,
    listeners: &[std::net::SocketAddr],
    interface_of: &dyn Fn(std::net::IpAddr) -> Option<String>,
) -> Option<String> {
    listeners.iter().find_map(|listener| {
        match crate::deploy::firewall::judge(ruleset, *listener, &interface_of(listener.ip())?) {
            crate::deploy::firewall::Verdict::Unknown(why) => Some(why),
            _ => None,
        }
    })
}

fn interactive_confirm(prompt: &str) -> Result<String, String> {
    super::verbs::typed_line(prompt).map_err(|failure| {
        failure.error["message"]
            .as_str()
            .unwrap_or("confirmation required")
            .to_string()
    })
}

/// The exit row of a result: 20 when it rolled back, else the class its
/// first failed check names (`<class>.<check>`), else the verb's default.
fn exit_row(result: &DeployResult, default: (i32, &'static str)) -> (i32, &'static str) {
    if result.rolled_back {
        return (20, "cli_rolled_back");
    }
    let class = result
        .failed()
        .and_then(|check| check.name.split('.').next())
        .unwrap_or("");
    match class {
        "release"
            if result
                .failed()
                .is_some_and(|check| check.name == "release.unreachable") =>
        {
            (4, "cli_unreachable")
        }
        // The signature and key checks carry no class prefix (their names are
        // `release verify`'s); they are release verification wherever run.
        "release" | "signature" | "key" => (17, "cli_release_unverified"),
        "preflight" => (18, "cli_preflight_failed"),
        "manager" => (19, "cli_manager_failed"),
        "confirmation" => (21, "cli_confirmation_required"),
        "conflict" => (8, "cli_conflict"),
        "configuration" => (3, "cli_configuration_invalid"),
        _ => default,
    }
}

/// A result whose checks all passed is the verb's answer; otherwise its exit
/// row with the first failed check named, and the whole result in the
/// error's details (the artifact and the failed check, nothing
/// manifest-adjacent). A rolled-back result's message says whether the
/// rollback itself succeeded, from the `manager.rollback`
/// check.
fn finish(result: DeployResult, default: (i32, &'static str)) -> Outcome {
    let text = result.to_text();
    finish_with(result, default, text)
}

/// The same, with the human form overridden (`service status` prints exactly
/// the state word); the `--json` object and the exit row are the
/// result's.
fn finish_with(result: DeployResult, default: (i32, &'static str), text: String) -> Outcome {
    if result.failed().is_none() && !result.rolled_back {
        return Ok((result.to_json(), text));
    }
    let (code, slug) = exit_row(&result, default);
    let mut message = match result.failed() {
        Some(check) => format!("{}: {}", check.name, check.message),
        None => "rolled back".to_string(),
    };
    if result.rolled_back {
        message.push_str(&match result
            .checks
            .iter()
            .find(|check| check.name == "manager.rollback")
        {
            Some(check) if check.passed => "; rollback succeeded".to_string(),
            Some(check) => format!("; rollback FAILED: {}", check.message),
            None => "; rollback outcome unknown".to_string(),
        });
    }
    let mut failure = Failure::local(code, slug, message);
    failure.error["details"] = json!([result.to_json()]);
    Err(failure)
}

/// The version `release.json` claims (the plan line reads it but never
/// trusts it: verification is the verb's own work); `None` when the file or
/// the field cannot be read.
fn claimed_version(release_json: &std::path::Path) -> Option<String> {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(release_json).ok()?).ok()?;
    value["version"].as_str().map(str::to_string)
}

/// The plan line for `server install` / `server update --from`: what it
/// touches — the claimed version and release directory, the unit and the
/// service configuration paths, and the configured listeners' addresses when
/// `--config` names a readable file. Only addresses are named, never another
/// configuration value.
fn server_plan(intro: &str, from: &std::path::Path, config: Option<&std::path::Path>) -> String {
    let claimed = claimed_version(&from.join("release.json")).unwrap_or_else(|| "unknown".into());
    let mut plan = format!(
        "{intro}: claims version {claimed}, release directory {}/{claimed}, unit {}, service configuration {}",
        native::RELEASES,
        systemd::UNIT_PATH,
        native::service_config_path().display(),
    );
    if let Some(listeners) = config_listeners(config) {
        plan.push_str(&format!(", listeners {listeners}"));
    }
    plan
}

/// The configured listeners' addresses (the control namespace rides
/// the data-plane listener; the proxy listener unless the proxy mode is
/// off). `None` when the configuration cannot be read and parsed.
fn config_listeners(config: Option<&std::path::Path>) -> Option<String> {
    let table = toml::from_str::<toml::Table>(&std::fs::read_to_string(config?).ok()?).ok()?;
    let listen = |key: &str, default: &str| {
        table
            .get(key)
            .and_then(|t| t.get("listen"))
            .map(|v| v.as_str().map_or(v.to_string(), str::to_owned))
            .unwrap_or_else(|| default.to_string())
    };
    let data_plane = listen("data_plane", crate::config::DEFAULT_LISTEN);
    let mut listeners = vec![data_plane.clone()];
    if table
        .get("mitm")
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
    {
        listeners.push(listen(
            "mitm",
            &crate::config::default_mitm_listen(&data_plane),
        ));
    }
    Some(listeners.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::result::Check;
    use std::path::PathBuf;

    /// A scratch directory for one unit test's files.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "native-plan-first-l1-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    #[test]
    fn the_server_plan_names_the_claim_and_the_paths_and_only_listener_addresses() {
        let dir = scratch("plan");
        std::fs::write(
            dir.join("release.json"),
            "{\"schema_version\": 1, \"version\": \"0.7.0-test\"}",
        )
        .expect("release.json");
        let config = dir.join("cfg.toml");
        std::fs::write(
            &config,
            "version = 1\nsecret = \"hush\"\n\n[data_plane]\nlisten = \"127.0.0.1:17421\"\n",
        )
        .expect("config");
        let plan = server_plan(
            "installing the native server from here",
            &dir,
            Some(&config),
        );
        assert!(plan.starts_with("installing the native server from here: "));
        assert!(plan.contains("claims version 0.7.0-test"));
        assert!(plan.contains("/opt/jaynshare/releases/0.7.0-test"));
        assert!(plan.contains(systemd::UNIT_PATH));
        assert!(plan.contains(native::service_config_path().to_str().expect("utf-8 path")));
        assert!(plan.contains("listeners 127.0.0.1:17421"));
        // No configuration value but the listener address.
        assert!(!plan.contains("hush"));
        assert!(!plan.contains("version = 1"));

        // An unreadable release still plans, with the claim unknown.
        let plan = server_plan(
            "updating the native server from gone",
            &dir.join("gone"),
            None,
        );
        assert!(plan.starts_with("updating the native server from gone: "));
        assert!(plan.contains("claims version unknown"));
        assert!(!plan.contains("listeners"));
    }

    /// The exit-20 message says whether the rollback itself
    /// succeeded; the JSON details stay the whole result.
    fn rolled_back(rollback: Option<Check>) -> DeployResult {
        let mut result = DeployResult::new("server install");
        result.rolled_back = true;
        result
            .checks
            .push(Check::fail("manager.health", "the status read timed out"));
        if let Some(check) = rollback {
            result.checks.push(check);
        }
        result
    }

    #[test]
    fn the_failure_message_says_whether_the_rollback_succeeded() {
        let failure = finish_with(
            rolled_back(Some(Check::pass(
                "manager.rollback",
                "the previous version is restored",
            ))),
            (19, "cli_manager_failed"),
            String::new(),
        )
        .expect_err("a rollback is a failure");
        assert_eq!(failure.code, 20);
        assert_eq!(failure.error["code"], "cli_rolled_back");
        assert!(
            failure.error["message"]
                .as_str()
                .expect("message")
                .ends_with("; rollback succeeded")
        );
        assert_eq!(failure.error["details"][0]["rolled_back"], true);

        let failure = finish_with(
            rolled_back(Some(Check::fail(
                "manager.rollback",
                "the unit would not start again",
            ))),
            (19, "cli_manager_failed"),
            String::new(),
        )
        .expect_err("a rollback is a failure");
        assert!(
            failure.error["message"]
                .as_str()
                .expect("message")
                .ends_with("; rollback FAILED: the unit would not start again")
        );

        let failure = finish_with(rolled_back(None), (19, "cli_manager_failed"), String::new())
            .expect_err("a rollback is a failure");
        assert!(
            failure.error["message"]
                .as_str()
                .expect("message")
                .ends_with("; rollback outcome unknown")
        );
    }

    #[test]
    fn a_ruleset_the_judgement_cannot_read_leaves_the_firewall_uninspectable() {
        let listener: std::net::SocketAddr = "100.101.102.103:17421".parse().expect("listener");
        let tailscale0 = |_| Some("tailscale0".to_owned());
        // iptables-nft writes a chain jump, and its conntrack match, as
        // expressions the firewall judgement does not read: a real host running
        // tailscaled or a rootful Docker has them in its input chain.
        let jump = r#"{"nftables":[
            {"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter",
              "hook":"input","prio":0,"policy":"accept"}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":3,
              "expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"ts-input"}}]}}]}"#;
        let why = unreadable_ruleset(jump, &[listener], &tailscale0).expect("uninspectable");
        assert!(why.contains("jump") && why.contains("INPUT"), "{why}");
        // A ruleset with a verdict is inspected, so nothing is asked.
        let dropped = r#"{"nftables":[
            {"chain":{"family":"ip","table":"filter","name":"input","type":"filter",
              "hook":"input","prio":0,"policy":"drop"}}]}"#;
        assert!(unreadable_ruleset(dropped, &[listener], &tailscale0).is_none());
        // An unassigned address is an assignment failure; the firewall check asks nothing.
        assert!(unreadable_ruleset(jump, &[listener], &|_| None).is_none());
    }
}
