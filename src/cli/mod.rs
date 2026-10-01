//! The `jaynshare` executable: one grammar for every role
//! (`args`), help from one table (`help`), the `--json` schemas (`schema`),
//! the control client (`control`), the control verbs and their rendering
//! (`verbs`) and the file-editing verbs of `edit`. This module is
//! the dispatch: parsing, the roles, the two streams and the
//! envelope, exit codes and the refusals of verbs whose
//! behaviour a later release owns.

mod alias;
mod args;
mod bundle;
mod claude;
mod client_accounts;
mod control;
mod deploy;
mod edit;
mod engineer;
mod env;
mod help;
mod schema;
mod tail;
mod trust_ca;
mod uninstall;
mod update;
mod verbs;

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use clap::{ColorChoice, FromArgMatches};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::audit::{AUDIT_LOG, AuditLog};
use crate::capture::Capture;
use crate::config;
use crate::data_plane::upstream::Upstream;
use crate::pool::refresh::{self, Trigger};
use crate::pool::{Credential, Errored, Pool, probe};
use crate::server::{COMMIT, Server, Stop, TARGET, VERSION};
use crate::{data_plane, logging, mitm, state};

use args::{
    AccountVerb, AuditVerb, CaVerb, Cli, ClientVerb, ConfigVerb, LogVerb, OperationVerb,
    OperatorSecretVerb, OperatorVerb, SecretVerb, ServerVerb, Verb,
};
use control::Control;
pub(crate) use control::{error_chain, http_client, http_client_anchors, http_client_plain};
use help::Role;
use verbs::{
    account_add, account_availability, account_list, account_login, account_remove, account_rename,
    account_replace, account_show, api, ca_export, ca_rotate, ca_show, client_issue, client_list,
    client_reissue, client_rename, client_revoke, client_rotate, client_show, operation_cancel,
    operation_code, operation_show, operator_secret_remove, operator_secret_set, probe, status,
    switch,
};

/// A failure the envelope reports: the exit code and the error object.
pub(super) struct Failure {
    pub(super) code: i32,
    pub(super) error: Value,
}

impl Failure {
    pub(super) fn local(code: i32, slug: &str, message: impl Into<String>) -> Self {
        Self {
            code,
            error: json!({ "code": slug, "message": message.into(), "target": null, "details": [] }),
        }
    }

    /// A verb whose behaviour lands in a later release: it parses, has help
    /// and a schema, and does nothing.
    pub(super) fn not_in_this_build(path: &str) -> Self {
        let milestone = help::doc(path)
            .and_then(|d| d.lands)
            .unwrap_or("a later release");
        Self::local(
            1,
            "cli_internal",
            format!(
                "`jaynshare {path}` is not available in this build; its behaviour lands in {milestone}"
            ),
        )
    }
}

pub(super) type Outcome = Result<(Value, String), Failure>;

/// Colour only on a terminal, and never under `--no-color` or `NO_COLOR`.
fn colour_wanted(cli: &Cli) -> bool {
    !cli.no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// The role an invocation's context supplies: an engineer's
/// machine has a `client.toml`, a host has a configuration file.
fn client_installation() -> (std::path::PathBuf, bool) {
    let file = config::platform::client_directory().join("client.toml");
    let exists = file.is_file();
    (file, exists)
}

/// An engineer verb without an installation exits 11 naming the
/// missing file and the installer to run.
fn engineer_context() -> Result<(), Failure> {
    let (file, exists) = client_installation();
    if exists {
        return Ok(());
    }
    let installer = if cfg!(target_os = "windows") {
        "install-windows.ps1"
    } else {
        "install-macos.sh"
    };
    Err(Failure::local(
        11,
        "cli_not_enrolled",
        format!(
            "this machine is not enrolled: {} is missing; run the enrollment bundle's {installer}",
            file.display()
        ),
    ))
}

/// Which role `status` and `api` serve this time.
fn dual_role(cli: &Cli, operator_flag: bool, client_flag: bool) -> Role {
    if client_flag {
        Role::Engineer
    } else if operator_flag || cli.server.is_some() || cli.config.is_some() {
        Role::Operator
    } else if config::platform::client_directory().is_dir() {
        Role::Engineer
    } else {
        Role::Operator
    }
}

pub fn main() -> i32 {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let json_asked = argv.iter().any(|a| a == "--json");
    let color = if argv.iter().any(|a| a == "--no-color") || std::env::var_os("NO_COLOR").is_some()
    {
        ColorChoice::Never
    } else {
        ColorChoice::Auto
    };
    let matches = match help::command(color).try_get_matches_from(&argv) {
        Ok(matches) => matches,
        Err(e) => {
            if e.use_stderr() {
                // One line naming what is wrong and the usage line; the
                // envelope too when --json was on the line.
                let rendered = e.to_string();
                eprint!("{rendered}");
                if !rendered.contains("Usage:") {
                    eprintln!("\n{}", help::usage_for(&argv, color));
                }
                if json_asked {
                    print_envelope(
                        "",
                        None,
                        Err(Failure::local(
                            2,
                            "cli_usage",
                            e.to_string().lines().next().unwrap_or("usage error"),
                        )),
                    );
                }
                return 2;
            }
            // --help on standard output, exit 0.
            print!("{e}");
            return 0;
        }
    };
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => {
            eprint!("{e}");
            return 2;
        }
    };
    if cli.version {
        return finish(&cli, "version", None, version());
    }
    let Some(verb) = &cli.verb else {
        eprint!("{}", help::top_level());
        return 2;
    };
    let path = verb_path(verb);
    // The verbs and forms that refuse --json. A global option before
    // the verb escapes clap's conflict rules, so the check is here.
    let refuses_json = schema::NO_JSON.contains(&path)
        || matches!(verb, Verb::Status(args) if args.check || args.line);
    if cli.json && refuses_json {
        eprintln!(
            "error: `jaynshare {path}` does not accept --json here\n\n{}",
            help::usage_for(&argv, color)
        );
        if json_asked {
            print_envelope(
                path,
                None,
                Err(Failure::local(
                    2,
                    "cli_usage",
                    format!("`jaynshare {path}` does not accept --json here"),
                )),
            );
        }
        return 2;
    }
    match verb {
        Verb::Help { verb } => return finish(&cli, path, None, help_verb(verb, color)),
        Verb::Version => return finish(&cli, path, None, version()),
        Verb::Schema { verb } => return finish(&cli, path, None, schema_verb(verb)),
        Verb::Serve => return serve(&cli),
        // `config validate` is file-backed, no server; before `Control::connect`,
        // which would refuse the very file the verb is asked to judge.
        Verb::Config {
            verb: ConfigVerb::Validate { path: file },
        } => {
            return finish(&cli, path, None, edit::validate(&cli, file.as_deref()));
        }
        Verb::Config {
            verb: ConfigVerb::Paths,
        } => return finish(&cli, path, None, edit::paths(&cli)),
        Verb::Config {
            verb: ConfigVerb::New { out },
        } => return finish(&cli, path, None, edit::new(out)),
        Verb::Config {
            verb: ConfigVerb::Show { local: true },
        } => return finish(&cli, path, None, edit::show_local(&cli)),
        Verb::Config {
            verb: ConfigVerb::Edit { offline: true },
        } => return finish(&cli, path, None, edit::edit_offline(&cli)),
        // File-backed and line-oriented; with --json one raw
        // object per line and never an envelope.
        Verb::Log {
            verb: LogVerb::Tail(args),
        } => return finish_lines(tail::log_tail(&cli, args)),
        Verb::Audit {
            verb: AuditVerb::Tail(args),
        } => return finish_lines(tail::audit_tail(&cli, args)),
        // Claude Code runs these two itself: they never write to standard
        // error and always exit 0.
        Verb::Statusline => return crate::statusline::main(),
        Verb::TitleHook => return crate::title_hook::main(),
        // `claude` exits with its own codes only before it replaces itself.
        Verb::Claude(args) => return claude::claude(args),
        Verb::Env(args) => return finish(&cli, path, None, env::env(args)),
        // Print-only, but still an engineer verb.
        Verb::Alias { shell } => {
            let outcome = engineer_context().and_then(|()| alias::alias(*shell));
            return finish(&cli, path, None, outcome);
        }
        _ => {}
    }
    let role = help::doc(path).map(|d| d.role).unwrap_or(Role::Operator);
    let dual = match verb {
        Verb::Status(args) => Some(dual_role(&cli, args.operator, args.client)),
        Verb::Api(args) => Some(dual_role(&cli, args.operator, args.client)),
        Verb::Account {
            verb: AccountVerb::Login(_) | AccountVerb::List,
        } => Some(dual_role(&cli, false, false)),
        _ => None,
    };
    // The deploy verbs are file-backed, with no control connection.
    if matches!(role, Role::Deploy) {
        if let Some(refusal) = later_verb_refusal(&cli, verb, path, role, dual) {
            return finish(&cli, path, dual, Err(refusal));
        }
        let outcome =
            deploy::dispatch(&cli, verb).unwrap_or_else(|| Err(Failure::not_in_this_build(path)));
        return finish(&cli, path, dual, outcome);
    }
    // The engineer verbs that create or replace the installation: no operator
    // configuration is read, the installation (or the bundle) is the context.
    let engineer_direct = matches!(
        verb,
        Verb::Enrol { .. }
            | Verb::Secret { .. }
            | Verb::CaUpdate { .. }
            | Verb::Update { .. }
            | Verb::Uninstall
            | Verb::TrustCa { .. }
    ) || matches!(verb, Verb::Status(_) | Verb::Api(_) | Verb::Account { .. } if dual == Some(Role::Engineer));
    if engineer_direct {
        if let Some(refusal) = later_verb_refusal(&cli, verb, path, role, dual) {
            if matches!(verb, Verb::Status(args) if args.check) {
                return refusal.code;
            }
            return finish(&cli, path, dual, Err(refusal));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let outcome = runtime.block_on(async {
            match verb {
                Verb::Status(args) => engineer::status(&cli, args).await,
                Verb::Api(args) => engineer::api(&cli, args).await,
                Verb::Enrol {
                    bundle,
                    trust_os_store,
                } => engineer::enrol(&cli, bundle, *trust_os_store).await,
                Verb::Secret {
                    verb: SecretVerb::Set { channel },
                } => engineer::secret_set(&cli, channel).await,
                Verb::CaUpdate { from } => engineer::ca_update(&cli, from).await,
                Verb::Update {
                    from,
                    version,
                    release_origin,
                } => {
                    update::update(
                        &cli,
                        from.as_deref(),
                        version.as_deref(),
                        release_origin.as_deref(),
                    )
                    .await
                }
                Verb::Uninstall => uninstall::uninstall(&cli).await,
                Verb::TrustCa { verb } => {
                    trust_ca::trust_ca(&cli, matches!(verb, args::TrustCaVerb::Add)).await
                }
                Verb::Account {
                    verb: AccountVerb::Login(args),
                } => client_accounts::account_login(&cli, args).await,
                Verb::Account {
                    verb: AccountVerb::List,
                } => client_accounts::account_list(&cli).await,
                _ => unreachable!("engineer_direct"),
            }
        });
        if matches!(verb, Verb::Status(args) if args.check) {
            return match outcome {
                Ok(_) => 0,
                Err(f) => f.code,
            };
        }
        return finish(&cli, path, dual, outcome);
    }
    if let Some(refusal) = later_verb_refusal(&cli, verb, path, role, dual) {
        if matches!(verb, Verb::Status(args) if args.check) {
            return refusal.code;
        }
        return finish(&cli, path, dual, Err(refusal));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let outcome = runtime.block_on(async {
        let control = match Control::connect(&cli) {
            Ok(control) => control,
            Err(failure) => return Err(failure),
        };
        match verb {
            Verb::Status(args) => status(&control, &cli, args).await,
            Verb::Probe(args) => probe(&control, args).await,
            Verb::Account { verb } => match verb {
                AccountVerb::List => account_list(&control).await,
                AccountVerb::Show { reference } => account_show(&control, reference).await,
                AccountVerb::Add(args) => account_add(&control, args).await,
                AccountVerb::Login(args) => account_login(&control, &cli, args).await,
                AccountVerb::Operation { verb } => match verb {
                    OperationVerb::Show { operation_id } => {
                        operation_show(&control, operation_id).await
                    }
                    OperationVerb::Code {
                        operation_id,
                        channel,
                    } => operation_code(&control, operation_id, channel).await,
                    OperationVerb::Cancel { operation_id } => {
                        operation_cancel(&control, operation_id).await
                    }
                },
                AccountVerb::Remove { reference } => {
                    account_remove(&control, &cli, reference).await
                }
                AccountVerb::Replace { reference, args } => {
                    account_replace(&control, reference, args).await
                }
                AccountVerb::Rename {
                    reference,
                    new_name,
                } => account_rename(&control, reference, new_name).await,
                AccountVerb::Enable { reference } => {
                    account_availability(&control, reference, true).await
                }
                AccountVerb::Disable { reference } => {
                    account_availability(&control, reference, false).await
                }
            },
            Verb::Api(args) => api(&control, args, &cli).await,
            Verb::Switch(args) => switch(&control, &cli, args).await,
            Verb::Client { verb } => match verb {
                ClientVerb::List => client_list(&control).await,
                ClientVerb::Show { id } => client_show(&control, id).await,
                ClientVerb::Issue {
                    id,
                    name,
                    disclose_to,
                } => client_issue(&control, &cli, id, name, disclose_to.as_deref()).await,
                ClientVerb::Bundle { id, kit, out } => {
                    bundle::validate_client_id(id)?;
                    bundle::client_bundle(&control, id, kit, out).await
                }
                ClientVerb::Enrol { id, name, kit, out } => {
                    bundle::client_enrol(&control, id, name, kit, out).await
                }
                ClientVerb::Reissue {
                    id,
                    kit,
                    out,
                    disclose_to,
                } => match (kit, out) {
                    // The packaging half repacks for the new
                    // generation; the bare form is the registry call alone.
                    (Some(kit), Some(out)) => {
                        bundle::client_reissue(&control, &cli, id, kit, out, disclose_to.as_deref())
                            .await
                    }
                    (None, None) => {
                        client_reissue(&control, &cli, id, disclose_to.as_deref()).await
                    }
                    _ => unreachable!("clap requires --kit and --out together"),
                },
                ClientVerb::Rotate { id, disclose_to } => {
                    client_rotate(&control, &cli, id, disclose_to.as_deref()).await
                }
                ClientVerb::Revoke { id } => client_revoke(&control, &cli, id).await,
                ClientVerb::Rename { id, display_name } => {
                    client_rename(&control, id, display_name).await
                }
            },
            Verb::Operator {
                verb: OperatorVerb::Secret { verb },
            } => match verb {
                OperatorSecretVerb::Set { disclose_to } => {
                    operator_secret_set(&control, &cli, disclose_to.as_deref()).await
                }
                OperatorSecretVerb::Remove => operator_secret_remove(&control).await,
            },
            Verb::Ca {
                verb: CaVerb::Rotate,
            } => ca_rotate(&control, &cli).await,
            Verb::Ca { verb: CaVerb::Show } => ca_show(&control).await,
            Verb::Ca {
                verb: CaVerb::Export { out },
            } => ca_export(&control, out.as_deref()).await,
            Verb::Ca {
                verb: CaVerb::UpdateBundle { out },
            } => bundle::ca_update_bundle(&control, out).await,
            Verb::Route { verb } => edit::route(&control, &cli, verb).await,
            Verb::Priority { verb } => edit::priority(&control, verb).await,
            Verb::Block { verb } => edit::block(&control, verb).await,
            Verb::Config { verb } => edit::config(&control, verb).await,
            _ => Err(Failure::not_in_this_build(path)),
        }
    });
    if matches!(verb, Verb::Status(args) if args.check) {
        // Nothing on either stream; the exit code is the answer.
        return match outcome {
            Ok(_) => 0,
            Err(f) => f.code,
        };
    }
    finish(&cli, path, dual, outcome)
}

/// The refusals that precede any request: the `--json` rule is above;
/// here the role contexts, the interactive-only confirmations, and
/// the verbs this build parses but does not run.
fn later_verb_refusal(
    cli: &Cli,
    verb: &Verb,
    path: &str,
    role: Role,
    dual: Option<Role>,
) -> Option<Failure> {
    // The verbs whose owner requires an interactive confirmation
    // never accept --yes and exit 21 without a terminal.
    let interactive_only = matches!(
        verb,
        Verb::Server {
            verb: ServerVerb::Uninstall { purge: true }
        } | Verb::Enrol { .. }
    );
    if interactive_only {
        if cli.yes {
            return Some(Failure::local(
                21,
                "cli_confirmation_required",
                format!(
                    "`jaynshare {path}` reads its confirmation on the terminal and does not accept --yes"
                ),
            ));
        }
        if !std::io::stdin().is_terminal() {
            return Some(Failure::local(
                21,
                "cli_confirmation_required",
                format!("`jaynshare {path}` needs a terminal for its confirmation"),
            ));
        }
    }
    match dual.unwrap_or(role) {
        // `secret set` and `ca-update` replace installation files, so they
        // need one; `enrol` creates one and gates itself (its interactive
        // check ran above); the engineer `status` form needs its files
        // too.
        Role::Engineer
            if matches!(
                verb,
                Verb::Secret { .. }
                    | Verb::CaUpdate { .. }
                    | Verb::Update { .. }
                    | Verb::Uninstall
                    | Verb::TrustCa { .. }
            ) =>
        {
            engineer_context().err()
        }
        Role::Engineer if matches!(verb, Verb::Enrol { .. }) => None,
        Role::Engineer
            if matches!(verb, Verb::Status(_) | Verb::Api(_) | Verb::Account { .. })
                && dual == Some(Role::Engineer) =>
        {
            engineer_context().err()
        }
        Role::Engineer => Some(
            engineer_context()
                .err()
                .unwrap_or_else(|| Failure::not_in_this_build(path)),
        ),
        Role::Deploy | Role::Operator => {
            let lands = help::doc(path).and_then(|d| d.lands).is_some();
            lands.then(|| Failure::not_in_this_build(path))
        }
        Role::Server | Role::Any => None,
    }
}

/// `jaynshare help [<verb>]`.
fn help_verb(words: &[String], color: ColorChoice) -> Outcome {
    let text = if words.is_empty() {
        help::top_level()
    } else {
        let mut command = help::command(color);
        command.build();
        let mut current = &mut command;
        for word in words {
            current = current.find_subcommand_mut(word).ok_or_else(|| {
                Failure::local(
                    2,
                    "cli_usage",
                    format!(
                        "no verb is spelt {:?}; see `jaynshare --help`",
                        words.join(" ")
                    ),
                )
            })?;
        }
        current.render_help().to_string()
    };
    Ok((json!({ "help": text }), text.trim_end().to_string()))
}

/// `jaynshare schema [<verb>]`.
fn schema_verb(words: &[String]) -> Outcome {
    if words.is_empty() {
        let all = schema::all();
        let text = serde_json::to_string_pretty(&all).expect("schema serialises");
        return Ok((all, text));
    }
    let path = words.join(" ");
    if help::doc(&path).is_none() {
        return Err(Failure::local(
            2,
            "cli_usage",
            format!("no verb is spelt {path:?}; see `jaynshare --help`"),
        ));
    }
    match schema::of_verb(&path) {
        Some(document) => {
            let text = serde_json::to_string_pretty(&document).expect("schema serialises");
            Ok((document, text))
        }
        None => Err(Failure::local(
            2,
            "cli_usage",
            format!("`jaynshare {path}` has no --json document"),
        )),
    }
}

/// The verb's command path: the envelope's `command` and the help table's key.
fn verb_path(verb: &Verb) -> &'static str {
    use args::*;
    match verb {
        Verb::Help { .. } => "help",
        Verb::Version => "version",
        Verb::Schema { .. } => "schema",
        Verb::Serve => "serve",
        Verb::Status(_) => "status",
        Verb::Account { verb } => match verb {
            AccountVerb::List => "account list",
            AccountVerb::Show { .. } => "account show",
            AccountVerb::Add(_) => "account add",
            AccountVerb::Login(_) => "account login",
            AccountVerb::Operation { verb } => match verb {
                OperationVerb::Show { .. } => "account operation show",
                OperationVerb::Code { .. } => "account operation code",
                OperationVerb::Cancel { .. } => "account operation cancel",
            },
            AccountVerb::Replace { .. } => "account replace",
            AccountVerb::Remove { .. } => "account remove",
            AccountVerb::Rename { .. } => "account rename",
            AccountVerb::Enable { .. } => "account enable",
            AccountVerb::Disable { .. } => "account disable",
        },
        Verb::Switch(_) => "switch",
        Verb::Route { verb } => match verb {
            RouteVerb::List { .. } => "route list",
            RouteVerb::Add(_) => "route add",
            RouteVerb::Rm { .. } => "route rm",
        },
        Verb::Priority { verb } => match verb {
            PriorityVerb::List => "priority list",
            PriorityVerb::Set { .. } => "priority set",
            PriorityVerb::Clear { .. } => "priority clear",
        },
        Verb::Block { verb } => match verb {
            BlockVerb::List => "block list",
            BlockVerb::Add { .. } => "block add",
            BlockVerb::Rm { .. } => "block rm",
        },
        Verb::Probe(_) => "probe",
        Verb::Client { verb } => match verb {
            ClientVerb::List => "client list",
            ClientVerb::Show { .. } => "client show",
            ClientVerb::Issue { .. } => "client issue",
            ClientVerb::Bundle { .. } => "client bundle",
            ClientVerb::Enrol { .. } => "client enrol",
            ClientVerb::Reissue { .. } => "client reissue",
            ClientVerb::Rotate { .. } => "client rotate",
            ClientVerb::Revoke { .. } => "client revoke",
            ClientVerb::Rename { .. } => "client rename",
        },
        Verb::Operator { verb } => match verb {
            OperatorVerb::Secret { verb } => match verb {
                OperatorSecretVerb::Set { .. } => "operator secret set",
                OperatorSecretVerb::Remove => "operator secret remove",
            },
        },
        Verb::Ca { verb } => match verb {
            CaVerb::Show => "ca show",
            CaVerb::Export { .. } => "ca export",
            CaVerb::Rotate => "ca rotate",
            CaVerb::UpdateBundle { .. } => "ca update-bundle",
        },
        Verb::Config { verb } => match verb {
            ConfigVerb::Paths => "config paths",
            ConfigVerb::New { .. } => "config new",
            ConfigVerb::Show { .. } => "config show",
            ConfigVerb::Validate { .. } => "config validate",
            ConfigVerb::Reload => "config reload",
            ConfigVerb::Set { .. } => "config set",
            ConfigVerb::Unset { .. } => "config unset",
            ConfigVerb::Edit { .. } => "config edit",
        },
        Verb::Log { verb } => match verb {
            LogVerb::Tail(_) => "log tail",
        },
        Verb::Audit { verb } => match verb {
            AuditVerb::Tail(_) => "audit tail",
        },
        Verb::Api(_) => "api",
        Verb::Release { verb } => match verb {
            ReleaseVerb::Verify { .. } => "release verify",
            ReleaseVerb::Latest { .. } => "release latest",
            ReleaseVerb::Fetch { .. } => "release fetch",
        },
        Verb::Server { verb } => match verb {
            ServerVerb::Preflight { .. } => "server preflight",
            ServerVerb::Install { .. } => "server install",
            ServerVerb::Update { .. } => "server update",
            ServerVerb::Uninstall { .. } => "server uninstall",
            ServerVerb::Prune { .. } => "server prune",
        },
        Verb::Service { verb } => match verb {
            ServiceVerb::Install => "service install",
            ServiceVerb::Remove => "service remove",
            ServiceVerb::Start => "service start",
            ServiceVerb::Stop => "service stop",
            ServiceVerb::Restart => "service restart",
            ServiceVerb::Status => "service status",
        },
        Verb::Claude(_) => "claude",
        Verb::Env(_) => "env",
        Verb::Alias { .. } => "alias",
        Verb::Enrol { .. } => "enrol",
        Verb::Update { .. } => "update",
        Verb::CaUpdate { .. } => "ca-update",
        Verb::TrustCa { verb } => match verb {
            TrustCaVerb::Add => "trust-ca add",
            TrustCaVerb::Remove => "trust-ca remove",
        },
        Verb::Uninstall => "uninstall",
        Verb::Secret { verb } => match verb {
            SecretVerb::Set { .. } => "secret set",
        },
        Verb::Statusline => "statusline",
        Verb::TitleHook => "title-hook",
    }
}

/// The lines were written as they matched; a failure is one
/// line on standard error and the code, envelope or not.
fn finish_lines(outcome: Result<(), Failure>) -> i32 {
    match outcome {
        Ok(()) => 0,
        Err(f) => {
            eprintln!(
                "{}: {}",
                f.error["code"].as_str().unwrap_or("error"),
                f.error["message"].as_str().unwrap_or("")
            );
            f.code
        }
    }
}

/// The answer on standard output — human, or the one envelope —
/// and a failure on standard error; the exit code is the outcome's.
fn finish(cli: &Cli, command: &str, role: Option<Role>, outcome: Outcome) -> i32 {
    let code = match &outcome {
        Ok(_) => 0,
        Err(f) => f.code,
    };
    if let Err(f) = &outcome
        && f.code == 130
    {
        // Ended by a signal, not a CLI exit code; no envelope.
        eprintln!("{}", f.error["message"].as_str().unwrap_or("interrupted"));
        return code;
    }
    if cli.json {
        print_envelope(command, role, outcome.map(|(result, _)| result));
    } else {
        match outcome {
            Ok((_, human)) => {
                if !human.is_empty() {
                    println!("{human}");
                }
            }
            Err(f) => {
                eprintln!(
                    "{}: {}",
                    f.error["code"].as_str().unwrap_or("error"),
                    f.error["message"].as_str().unwrap_or("")
                );
                // The failure's detail entries, one per line under the message.
                for detail in f.error["details"].as_array().into_iter().flatten() {
                    // A deployment verb's detail is its whole result: every
                    // failed check, so a preflight names each one.
                    if let Some(checks) = detail["checks"].as_array() {
                        // The first failed check is the message above.
                        for check in checks.iter().filter(|c| c["passed"] == false).skip(1) {
                            eprintln!(
                                "  {}: {}",
                                check["name"].as_str().unwrap_or(""),
                                check["message"].as_str().unwrap_or("")
                            );
                        }
                        continue;
                    }
                    eprintln!(
                        "  {}: {}",
                        detail["target"].as_str().unwrap_or(""),
                        detail["message"].as_str().unwrap_or("")
                    );
                }
            }
        }
    }
    code
}

/// The one shape for success and failure; `role` on the two
/// dual-role verbs and on no other.
fn print_envelope(command: &str, role: Option<Role>, outcome: Result<Value, Failure>) {
    let (ok, code, result, error) = match outcome {
        Ok(result) => (true, 0, result, Value::Null),
        Err(f) => (false, f.code, Value::Null, f.error),
    };
    let mut envelope = json!({
        "cli_version": VERSION,
        "command": command,
        "ok": ok,
        "exit_code": code,
        "result": result,
        "error": error,
    });
    if let Some(role) = role {
        envelope["role"] = json!(match role {
            Role::Engineer => "client",
            _ => "operator",
        });
    }
    println!("{envelope}");
}

fn version() -> Outcome {
    Ok((
        json!({ "version": VERSION, "commit": COMMIT, "target": TARGET }),
        format!("jaynshare {VERSION} ({COMMIT}, {TARGET})"),
    ))
}

// ---------------------------------------------------------------- serve

fn serve(cli: &Cli) -> i32 {
    match serve_inner(cli) {
        Ok(code) => code,
        Err((code, message)) => {
            eprintln!("{message}");
            code
        }
    }
}

/// In order: the configuration is read and parsed, every
/// protected path's mode is checked, the state is read, the cross-
/// references are judged beside the local errors, the server and
/// audit logs are opened — all at their final locations, before either
/// listener binds and before any existing file changes. A failure names
/// the path and the operation; the configuration's own failures exit 3,
/// the rest 23.
fn serve_inner(cli: &Cli) -> Result<i32, (i32, String)> {
    let path = config::config_path(cli.config.as_deref());
    let bytes = config::read(&path).map_err(|e| (3, e.to_string()))?;
    let parsed = config::parse_document(&bytes, config::base_dir(&path))
        .map_err(|e| (3, format!("configuration {}: {e}", path.display())))?;
    let digest = config::sha256_hex(&bytes);
    let cfg = &parsed.config;
    let state_path = cfg.storage.state_file.clone();
    let log_dir = cfg.logging.directory.clone();
    let audit_path = log_dir.join(AUDIT_LOG);
    // No secret-bearing existing file or directory broader than
    // owner-only; the directories the server owns are created private.
    let preflight =
        |what: &str, p: &std::path::Path, m: String| (23, format!("{what} {}: {m}", p.display()));
    if let Some(dir) = state_path.parent() {
        state::ensure_private_dir(dir)
            .map_err(|e| preflight("state directory", dir, format!("cannot create: {e}")))?;
    }
    state::ensure_private_dir(&log_dir)
        .map_err(|e| preflight("log directory", &log_dir, format!("cannot create: {e}")))?;
    let mut protected: Vec<(&str, std::path::PathBuf)> = vec![
        ("configuration", path.clone()),
        (
            "configuration directory",
            config::base_dir(&path).to_path_buf(),
        ),
        ("state", state_path.clone()),
        ("log directory", log_dir.clone()),
        ("server log", log_dir.join(logging::SERVER_LOG)),
        ("crash log", log_dir.join(logging::CRASH_LOG)),
        ("audit log", audit_path.clone()),
    ];
    if let Some(dir) = state_path.parent() {
        protected.push(("state directory", dir.to_path_buf()));
    }
    if let Some(tls) = &cfg.data_plane.tls {
        protected.push(("TLS private key", tls.private_key_file.clone()));
    }
    for (what, p) in &protected {
        state::check_private(p).map_err(|m| preflight(what, p, m))?;
    }
    // The state read; then the cross-references beside the local
    // errors, in one result.
    let state_read = state::load(&state_path);
    let mut errors = parsed.errors;
    if let Ok(durable) = &state_read
        && !parsed.references.is_empty()
    {
        let pool = Pool::from_accounts(durable.accounts.clone(), OffsetDateTime::now_utc());
        errors.extend(config::references::errors(&parsed.references, &pool));
    }
    if !errors.is_empty() {
        return Err((
            3,
            format!(
                "configuration {}: {}",
                path.display(),
                config::ConfigErrors(errors)
            ),
        ));
    }
    let mut durable = state_read.map_err(|m| (23, format!("state: {m}")))?;
    logging::init(&cfg.logging).map_err(|m| (23, format!("server log: {m}")))?;
    let audit = AuditLog::open(&audit_path, &cfg.audit).map_err(|e| {
        preflight(
            "audit log",
            &audit_path,
            format!("cannot open for append: {e}"),
        )
    })?;
    let loaded = config::LoadedConfig {
        path: path.clone(),
        digest,
        config: parsed.config.clone(),
    };
    let cfg = &loaded.config;
    let capture = match &cfg.diagnostics.wire_capture_directory {
        Some(dir) => Some(
            Capture::open(dir).map_err(|e| (23, format!("wire capture {}: {e}", dir.display())))?,
        ),
        None => None,
    };
    let upstream =
        Upstream::new(&cfg.data_plane).map_err(|m| (23, format!("upstream client: {m}")))?;
    // The TLS pair, if both files are set, is loaded and matched before the bind.
    let tls = match &cfg.data_plane.tls {
        Some(files) => {
            Some(data_plane::tls::prepare(files).map_err(|m| (23, format!("TLS listener: {m}")))?)
        }
        None => None,
    };
    let now = OffsetDateTime::now_utc();
    // Every preflight open succeeded: the one pre-bind state change (an
    // expired family with nothing to refresh it) may be written now.
    let mut state_changed = false;
    for account in &mut durable.accounts {
        let Credential::OAuth(family) = &mut account.credential else {
            continue;
        };
        if account.enabled
            && account.errored.is_none()
            && family.is_expired(now)
            && family.refresh_token.is_none()
        {
            family.last_refresh_attempt_at = Some(now);
            account.errored = Some(Errored {
                reason: "access token expired and no refresh token is held".into(),
                at: now,
            });
            state_changed = true;
        }
    }
    if state_changed {
        state::write(&state_path, &durable).map_err(|e| {
            (
                23,
                format!("state {}: cannot write: {e}", state_path.display()),
            )
        })?;
    }
    let mut pool = Pool::from_accounts(durable.accounts.clone(), now);
    // Restored organisation quota, installed and expired before the listener binds.
    pool.restore_organisation_quota(&durable.organization_quota, now);
    let restored_quota_changed = pool.accounts() != durable.accounts
        || pool.organisation_quota_records() != durable.organization_quota;
    pool.choose_initial_default(&cfg.selection, now);
    let startup_handles = pool
        .accounts()
        .iter()
        .map(|account| account.handle)
        .collect::<Vec<_>>();

    let listen_addr = cfg.data_plane.listen;
    let mitm = cfg.mitm.clone();
    let ca_state_dir = state_path.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    );
    let runtime = tokio::runtime::Runtime::new().map_err(|e| (1, format!("runtime: {e}")))?;
    runtime.block_on(async move {
        // Before the first write the logs can fail: a file-size limit is an
        // I/O error (a failed state write stops the server), a fatal signal a
        // crash object.
        let signal_set = Signals::install().map_err(|e| (1, format!("signal handlers: {e}")))?;
        let listener = data_plane::bind(listen_addr).await.map_err(|m| (data_plane::EXIT_BIND_FAILED, m))?;
        let bound = listener.local_addr().map_err(|e| (1, e.to_string()))?;
        let loopback = match data_plane::implicit_loopback(bound) {
            Some(addr) => Some(data_plane::bind(addr).await.map_err(|m| {
                (data_plane::EXIT_BIND_FAILED, format!("{m} (the loopback bind beside {bound})"))
            })?),
            None => None,
        };
        // The proxy listener binds beside the base-URL listener,
        // still before the startup line, so a failed bind leaves no partially
        // bound instance. It binds with the mode off too, serving
        // only the 405: a port turned off fails diagnosably.
        let proxy_listener = mitm::listener::bind(mitm.listen)
            .await
            .map_err(|m| (data_plane::EXIT_BIND_FAILED, m))?;
        // The start-time check over the three CA files runs before
        // the startup line, so a server that says it is listening has already
        // generated or judged its trust material. Unusable material never
        // stops the start: base-URL mode and tunnelled targets keep serving
        // and intercepted targets answer 503.
        let started = OffsetDateTime::now_utc();
        let ca = match mitm.enabled {
            true => match crate::mitm::ca::Ca::load_or_generate(&ca_state_dir, started) {
                Ok(ca) => {
                    ca.warn_expiry(started);
                    Some(Arc::new(ca))
                }
                Err(e) => {
                    tracing::error!(event = "ca_unusable", error = %e, "the CA trust material is unusable; intercepted targets answer 503");
                    None
                }
            },
            false => None,
        };
        let listen = listener.local_addr().map_err(|e| (1, e.to_string()))?;
        let (path, digest) = (loaded.path.clone(), loaded.digest.clone());
        let server = Arc::new(Server::new(loaded, durable, pool, audit, capture, upstream));
        server.set_mitm_ca(ca);
        if restored_quota_changed {
            server.mark_quota_dirty();
        }
        for handle in startup_handles {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                refresh::ensure_fresh(&server, handle, Trigger::Startup).await;
            });
        }
        // The startup line always names the upstream it will use.
        let upstream_note = if server.upstream.override_active() {
            format!(" upstream override {}", server.upstream.origin())
        } else {
            format!(" upstream {} verified against the system trust store", server.upstream.origin())
        };
        // The one startup line; the scheme names the transport.
        let scheme = if server.config().config.data_plane.tls.is_some() { "https" } else { "http" };
        println!("jaynshare {VERSION} listening on {scheme}://{listen} configuration {} digest {digest}{upstream_note}", path.display());
        tracing::info!(event = "server_started", listen = %listen, configuration = %path.display(), digest = %digest, upstream = %server.upstream.origin(), upstream_override = server.upstream.override_active(), "server started");
        // The bootstrap exception says so, once, until it ends.
        if server.bootstrap() {
            tracing::warn!(event = "bootstrap_authorisation", "no client is enrolled and no operator secret exists: every loopback caller is the loopback operator whatever it presents; the first issue or operator secret ends this");
        }
        if let Some(c) = &server.capture {
            tracing::warn!(event = "wire_capture_enabled", directory = %c.directory().display(), "wire capture is on; the directory holds request and response bytes");
        }

        tokio::spawn(quota_flusher(Arc::clone(&server)));
        tokio::spawn(probe::scheduler(Arc::clone(&server)));
        tokio::spawn(signals(Arc::clone(&server), signal_set));
        tokio::spawn(mitm::listener::serve(
            Arc::clone(&server),
            proxy_listener,
            mitm.enabled,
        ));
        if let Some(loopback) = loopback {
            tokio::spawn(data_plane::serve(Arc::clone(&server), loopback, tls.clone()));
        }
        data_plane::serve(Arc::clone(&server), listener, tls).await;
        let why = *server.stop_signal().borrow();
        if let Err(e) = server.flush_quota() {
            tracing::error!(event = "state_write_failed", error = %e, "final quota flush failed");
        }
        let reason = match why {
            Some(Stop::Signal) => "signal",
            Some(Stop::Unwritable) => "unwritable",
            None => "listener_closed",
        };
        tracing::info!(event = "server_stopped", reason, "server stopped");
        Ok(match why {
            Some(Stop::Unwritable) => 23,
            _ => 0,
        })
    })
}

/// Dirty quota reaches the state file within a second.
async fn quota_flusher(server: Arc<Server>) {
    let mut stop = server.stop_signal();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = stop.changed() => return,
        }
        if let Err(e) = server.flush_quota() {
            tracing::error!(event = "state_write_failed", error = %e, "quota flush failed; stopping");
            server.request_stop(Stop::Unwritable);
            return;
        }
    }
}

/// The signals the server listens to, installed before the first log write.
struct Signals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
    #[cfg(unix)]
    hup: tokio::signal::unix::Signal,
    /// The catchable fatal signals, each with its name.
    #[cfg(unix)]
    fatal: Vec<(tokio::signal::unix::Signal, &'static str, i32)>,
}

impl Signals {
    fn install() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut fatal = Vec::new();
            for (number, name) in [
                (libc::SIGABRT, "SIGABRT"),
                (libc::SIGQUIT, "SIGQUIT"),
                (libc::SIGTRAP, "SIGTRAP"),
                (libc::SIGSYS, "SIGSYS"),
                (libc::SIGXCPU, "SIGXCPU"),
            ] {
                fatal.push((signal(SignalKind::from_raw(number))?, name, number));
            }
            Ok(Self {
                term: signal(SignalKind::terminate())?,
                int: signal(SignalKind::interrupt())?,
                hup: signal(SignalKind::hangup())?,
                fatal,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }
}

/// SIGTERM and SIGINT stop cleanly; SIGHUP reloads the
/// configuration, its result logged. A fatal signal
/// appends one crash object and exits non-zero.
async fn signals(server: Arc<Server>, mut set: Signals) {
    #[cfg(unix)]
    {
        use std::future::poll_fn;
        use std::task::Poll;
        loop {
            let fatal = poll_fn(|cx| {
                for (signal, name, number) in &mut set.fatal {
                    if signal.poll_recv(cx).is_ready() {
                        return Poll::Ready((*name, *number));
                    }
                }
                Poll::Pending
            });
            tokio::select! {
                _ = set.term.recv() => break,
                _ = set.int.recv() => break,
                _ = set.hup.recv() => {
                    tracing::info!(event = "sighup", "SIGHUP received; reloading the configuration");
                    let server = Arc::clone(&server);
                    let _ = tokio::task::spawn_blocking(move || crate::control::reload::reload(&server)).await;
                }
                (name, number) = fatal => {
                    let message = format!("fatal signal {name} ({number}) received");
                    tracing::error!(event = "fatal_signal", signal = name, "{message}; exiting");
                    logging::crash("signal", &message, None);
                    std::process::exit(128 + number);
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = &mut set;
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!(event = "stop_requested", "stop signal received");
    server.request_stop(Stop::Signal);
}
