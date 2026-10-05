//! `join <invite>`: the one step that makes a machine a pool client. It
//! checks the server against the invite's identity, claims with the
//! invite's code, installs the server's own client once it verifies against
//! the invite's signing key, puts it on the search path, and offers to add
//! the engineer's Claude account. Everything that can refuse without
//! spending the code refuses before the claim.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use http::Method;
use serde_json::json;

use super::args::Cli;
use super::{Failure, Outcome};
use crate::bundle::{self, PinnedKey};
use crate::client::{self, ClientInstallation, ClientRequest};
use crate::config::platform;
use crate::invite::Invite;
use crate::provider::Provider;
use crate::server::VERSION;

fn local(code: i32, slug: &str, message: impl Into<String>) -> Failure {
    Failure::local(code, slug, message)
}

/// After the claim the code is spent, so every refusal says so.
fn spent(code: i32, slug: &str, why: impl std::fmt::Display) -> Failure {
    client::remove_staged();
    local(
        code,
        slug,
        format!(
            "{why}; nothing was installed, and the invite is spent: ask the operator for a new one"
        ),
    )
}

fn progress(cli: &Cli, line: &str) {
    if !cli.quiet {
        eprintln!("{line}");
    }
}

pub(super) async fn join(cli: &Cli, text: &str) -> Outcome {
    let invite = Invite::decode(text).map_err(|why| local(2, "cli_usage", why))?;
    let key = invite
        .signing_key()
        .map_err(|why| local(2, "cli_usage", why))?;
    let payload_member = preflight(&invite)?;
    // A settings file that is not JSON stops the join while the code is
    // still unspent.
    let binary = platform::client_binary();
    let settings_plan = crate::settings::plan_install(&binary).map_err(|why| {
        local(
            1,
            "cli_internal",
            format!("{why}; nothing was installed and the invite is unspent"),
        )
    })?;
    if let Some(command) = crate::settings::foreign_status_line(&binary) {
        eprintln!(
            "notice: Claude Code's status line is another tool's ({command}); it was left in place and the jaynshare status line was not installed. Remove it and run `jaynshare update --from <kit>` to install ours."
        );
    }
    let Claimed {
        installation,
        secret,
        ca_pem,
        adds_account,
    } = claim(cli, &invite).await?;
    progress(
        cli,
        &format!(
            "✓ connected to the pool at {} ({})",
            invite.base_url,
            match invite.identity {
                Some(_) => "identity matches the invite",
                None => "certificate trusted",
            }
        ),
    );
    let (payload, version) =
        server_client(cli, &installation, &secret, &key, payload_member).await?;
    install(&installation, &secret, &ca_pem, &payload, &key)
        .map_err(|why| spent(1, "cli_internal", format!("installing failed: {why}")))?;
    progress(
        cli,
        &format!("✓ installed jaynshare {version} (this server's client)"),
    );
    if let Some(plan) = &settings_plan
        && let Err(why) = crate::settings::commit(plan)
    {
        eprintln!(
            "warning: the Claude Code settings entries were not written ({why}); run `jaynshare update` to add them"
        );
    }
    link(cli, &binary);
    check(cli, &installation, &secret).await?;
    let providers = served(&binary).await;
    if adds_account {
        account_step(cli, &binary, &providers).await;
    }
    let mut result = client::client_result(&installation);
    result["version"] = json!(version);
    let launches: Vec<String> = providers
        .iter()
        .map(|provider| format!("`jaynshare {}`", provider.tool().executable))
        .collect();
    let human = format!(
        "joined the pool as {} ({}); launch through it with {}",
        installation.client_id,
        installation.display_name,
        launches.join(" or ")
    );
    Ok((result, human))
}

/// The refusals that leave the invite unspent: a plain-HTTP server, an
/// installation already here, a platform the kit has no client for. Returns
/// this platform's payload member.
fn preflight(invite: &Invite) -> Result<&'static str, Failure> {
    if invite.base_url.starts_with("http://") {
        return Err(local(
            5,
            "cli_refused",
            format!(
                "{} is plain HTTP, which would carry this machine's secret in clear; ask the operator to turn on the server's identity TLS (`tls = \"identity\"` under [data_plane]) and send a new invite",
                invite.base_url
            ),
        ));
    }
    let toml = platform::client_directory().join("client.toml");
    if toml.is_file() {
        return Err(local(
            8,
            "cli_conflict",
            format!(
                "{}: this machine is already enrolled; run `jaynshare uninstall` first to join again",
                toml.display()
            ),
        ));
    }
    bundle::native_payload().ok_or_else(|| {
        local(
            18,
            "cli_preflight_failed",
            format!(
                "this platform ({}/{}) has no jaynshare client",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        )
    })
}

/// What the claim over the invite's pinned channel answers.
struct Claimed {
    installation: ClientInstallation,
    secret: String,
    ca_pem: String,
    /// The invite lets this client add a Claude account of its own.
    adds_account: bool,
}

async fn claim(cli: &Cli, invite: &Invite) -> Result<Claimed, Failure> {
    let mut installation = ClientInstallation {
        directory: platform::client_directory(),
        client_id: invite.client_id.clone(),
        display_name: String::new(),
        base_url: invite.base_url.trim_end_matches('/').to_string(),
        proxy: None,
        ca_fingerprint: None,
        server_identity: invite.identity.clone(),
        no_proxy: vec![],
    };
    let request = ClientRequest::for_installation(
        &installation,
        Duration::from_secs(cli.timeout),
        cli.tls_ca.as_deref(),
    )
    .map_err(|e| local(1, "cli_internal", e))?;
    let body = json!({ "id": invite.client_id, "code": invite.code });
    let claimed = match request
        .call(
            Method::POST,
            "/control/v1/enrollment/claim",
            None,
            Some(&body),
        )
        .await
    {
        Ok((status, value)) if status.is_success() => value,
        Ok((status, value)) => {
            let (_, message) = client::client_failure(status, &value);
            return Err(local(
                5,
                "cli_refused",
                format!(
                    "the server refused the invite ({message}); an invite works once and expires, so ask the operator for a new one"
                ),
            ));
        }
        Err((code, why)) => {
            return Err(local(
                code,
                "cli_unreachable",
                format!("{why}; nothing was installed"),
            ));
        }
    };
    let Some(secret) = claimed["client_secret"].as_str() else {
        return Err(spent(
            10,
            "cli_incompatible_server",
            "the claim answer carries no client_secret",
        ));
    };
    let ca = &claimed["ca"];
    let (Some(proxy), Some(ca_pem), Some(fingerprint)) = (
        claimed["proxy_url"].as_str(),
        ca["certificate_pem"].as_str(),
        ca["fingerprint"].as_str(),
    ) else {
        return Err(spent(
            14,
            "cli_transport_unavailable",
            "the server named no proxy origin or CA, and every launch goes through the proxy; the server must turn MITM mode on",
        ));
    };
    installation.display_name = claimed["display_name"]
        .as_str()
        .unwrap_or(&invite.client_id)
        .to_string();
    installation.proxy = Some(proxy.to_string());
    installation.ca_fingerprint = Some(fingerprint.to_string());
    Ok(Claimed {
        installation,
        secret: secret.to_string(),
        ca_pem: ca_pem.to_string(),
        adds_account: claimed["no_account"] != true,
    })
}

/// The client this server offers, verified against the invite's key, and
/// its version. A server offering none gets this executable.
async fn server_client(
    cli: &Cli,
    installation: &ClientInstallation,
    secret: &str,
    key: &PinnedKey,
    payload_member: &str,
) -> Result<(Vec<u8>, String), Failure> {
    crate::state::ensure_private_dir(&installation.directory).map_err(|e| {
        spent(
            1,
            "cli_internal",
            format!("{}: {e}", installation.directory.display()),
        )
    })?;
    // A server with no pin is trusted from here on through `--tls-ca`'s
    // anchor, kept beside the installation.
    if installation.server_identity.is_none()
        && let Some(anchor) = &cli.tls_ca
    {
        let kept = installation.directory.join(client::BASE_URL_CA_FILE);
        std::fs::copy(anchor, &kept)
            .map_err(|e| spent(1, "cli_internal", format!("{}: {e}", kept.display())))?;
    }
    let staged = installation.directory.join("client-kit.zip.partial");
    let downloaded = client::download_kit(installation, secret, &staged).await;
    let verified = match downloaded {
        Ok(()) => bundle::verify_kit_zip(&staged, key),
        Err((6, _)) => {
            progress(
                cli,
                &format!(
                    "this server offers no client kit, so this jaynshare ({VERSION}) is installed"
                ),
            );
            let own = std::env::current_exe()
                .and_then(std::fs::read)
                .map_err(|e| spent(1, "cli_internal", format!("reading this executable: {e}")))?;
            return Ok((own, VERSION.to_string()));
        }
        Err((code, why)) => return Err(spent(code, "cli_unreachable", why)),
    };
    let _ = std::fs::remove_file(&staged);
    let kit = verified.map_err(|why| {
        spent(
            17,
            "cli_release_unverified",
            format!("the server's client is not signed with the invite's key: {why}"),
        )
    })?;
    Ok((kit.members[payload_member].clone(), kit.version))
}

/// The executable, the client files, the secret and the pinned key; the
/// caller removes them all when one fails.
fn install(
    installation: &ClientInstallation,
    secret: &str,
    ca_pem: &str,
    payload: &[u8],
    key: &PinnedKey,
) -> Result<(), String> {
    let binary = platform::client_binary();
    let folder = binary.parent().expect("the executable has a folder");
    crate::state::ensure_private_dir(folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    super::update::replace_atomically(&binary, payload)?;
    client::stage(installation, ca_pem.as_bytes())?;
    client::commit_secret(&installation.directory, secret)?;
    let pinned = platform::release_key_file();
    crate::state::write_private_atomic(&pinned, key.file_text().as_bytes())
        .map_err(|e| format!("{}: {e}", pinned.display()))
}

/// The installed command onto the search path; a failure is reported, the
/// installation stands.
fn link(cli: &Cli, binary: &Path) {
    match super::search_path::link(binary) {
        Ok(linked) if linked.on_path => {
            progress(
                cli,
                &format!("✓ `jaynshare` runs {}", linked.path.display()),
            );
        }
        Ok(linked) => {
            let directory = linked.path.parent().unwrap_or(&linked.path);
            progress(
                cli,
                &format!(
                    "✓ linked {}; add {} to your PATH (or open a new terminal) to run `jaynshare`",
                    linked.path.display(),
                    directory.display()
                ),
            );
        }
        Err(why) => eprintln!("warning: `jaynshare` was not put on your PATH: {why}"),
    }
}

/// The installation answers the server: kept whatever this says, but the
/// engineer learns of a failure.
async fn check(cli: &Cli, installation: &ClientInstallation, secret: &str) -> Result<(), Failure> {
    let timeout = Duration::from_secs(cli.timeout);
    match client::snapshot(installation, secret, None, timeout).await {
        Ok(_) => Ok(()),
        Err((code, why)) => Err(local(
            code,
            "cli_unreachable",
            format!("the installation is in place but its status check failed: {why}"),
        )),
    }
}

/// The providers the installed client logs in: the default needs no
/// option, and a client from an older server refuses `--provider`.
async fn served(binary: &Path) -> Vec<Provider> {
    let mut served = Vec::new();
    for provider in Provider::ALL {
        let accepted = provider.is_default()
            || tokio::process::Command::new(binary)
                .args(login_args(provider))
                .arg("--help")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .is_ok_and(|status| status.success());
        if accepted {
            served.push(provider);
        }
    }
    served
}

/// `account login`, naming the provider unless it is the default.
fn login_args(provider: Provider) -> Vec<&'static str> {
    let mut args = vec!["account", "login"];
    if !provider.is_default() {
        args.extend(["--provider", provider.as_str()]);
    }
    args
}

/// The invite's account step, run by the installed client so it speaks its
/// server's API: one question per provider. Without a terminal to ask on,
/// or under `--json`, each is left for later.
async fn account_step(cli: &Cli, binary: &Path, providers: &[Provider]) {
    let asks = !cli.json && std::io::stdin().is_terminal();
    for &provider in providers {
        let account = provider.tool().account;
        let args = login_args(provider);
        let command = format!("jaynshare {}", args.join(" "));
        if !(asks && (cli.yes || agrees(&format!("Add your {account} to the pool? [Y/n] ")))) {
            progress(
                cli,
                &format!("add your {account} to the pool later with `{command}`"),
            );
            continue;
        }
        match run_in_terminal(binary, &args).await {
            Ok(status) if status.success() => {}
            Ok(_) => eprintln!("warning: no {account} was added; run `{command}` to try again"),
            Err(why) => eprintln!(
                "warning: {}: {why}; run `{command}` to add your {account}",
                binary.display()
            ),
        }
    }
}

/// A `[Y/n]` question: any answer but a no is a yes; closed input is a no.
fn agrees(prompt: &str) -> bool {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok_and(|read| {
        read > 0 && !matches!(line.trim().to_ascii_lowercase().as_str(), "n" | "no")
    })
}

/// Runs `binary` on this terminal until it ends; an interrupt is its own
/// to handle.
async fn run_in_terminal(binary: &Path, args: &[&str]) -> std::io::Result<ExitStatus> {
    let mut child = tokio::process::Command::new(binary).args(args).spawn()?;
    loop {
        tokio::select! {
            status = child.wait() => return status,
            _ = tokio::signal::ctrl_c() => {}
        }
    }
}
