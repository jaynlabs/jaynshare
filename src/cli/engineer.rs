//! The engineer's own verbs: `secret set` and the `--json` form of
//! `status --client`. These run without an operator configuration — the
//! installation itself is their context, and `api` in its client form.

use http::Method;
use serde_json::{Value, json};

use super::args::{ApiArgs, Cli, DesktopArgs, SecretChannel, StatusArgs};
use super::verbs::{api_request, api_response, read_input};
use super::{Failure, Outcome};
use crate::client::{self, ClientInstallation, ClientRequest};

fn local(code: i32, slug: &str, message: impl Into<String>) -> Failure {
    Failure::local(code, slug, message)
}

pub(super) async fn desktop(cli: &Cli, args: &DesktopArgs) -> Outcome {
    if !cfg!(target_os = "macos") {
        return Err(local(
            2,
            "cli_usage",
            "Claude Desktop integration supports macOS only",
        ));
    }
    if args.restore {
        crate::desktop::restore()
            .await
            .map_err(|why| local(1, "cli_internal", why))?;
        return Ok((
            Value::Null,
            "removed the Jaynshare Gateway integration; conversations are preserved".into(),
        ));
    }
    let installation = installation()?;
    let secret_value = secret(&installation)?;
    let intent = if let Some(reference) = &args.account {
        crate::launch::IntentFlag::Account(reference.clone())
    } else if args.auto {
        crate::launch::IntentFlag::Auto
    } else {
        crate::launch::IntentFlag::Pick
    };
    let mut notices = Vec::new();
    let (_, selector) = crate::launch::select(
        &installation,
        &secret_value,
        Some(crate::provider::Provider::Anthropic),
        intent,
        None,
        &mut notices,
    )
    .await
    .map_err(|refusal| local(refusal.code, refusal.slug, refusal.message))?;
    for notice in notices {
        eprintln!("{notice}");
    }
    crate::desktop::run(installation, selector, cli.quiet)
        .await
        .map_err(|why| local(1, "cli_internal", why))?;
    Ok((Value::Null, String::new()))
}

/// A `(exit code, message)` from the client's HTTP layer as a `Failure`.
pub(super) fn client_failure_pair((code, message): (i32, String)) -> Failure {
    let slug = match code {
        4 => "cli_unreachable",
        5 => "cli_refused",
        // Exit code 11: not enrolled or installation incomplete.
        11 => "cli_not_enrolled",
        6 => "cli_not_found",
        10 => "cli_incompatible_server",
        _ => "cli_internal",
    };
    local(code, slug, message)
}

pub(super) fn installation() -> Result<ClientInstallation, Failure> {
    client::read_installation().map_err(client_failure_pair)
}

pub(super) fn secret(installation: &ClientInstallation) -> Result<String, Failure> {
    client::read_secret(installation).map_err(client_failure_pair)
}

/// The colour rule; the human and one-line forms share it.
fn colour_wanted(cli: &Cli) -> bool {
    super::colour_wanted(cli)
}

/// The installation's pin, or its `base-url-ca.pem` without `--tls-ca`;
/// a global `--tls-ca` is added beside the anchor.
pub(super) fn request(
    installation: &ClientInstallation,
    cli: &Cli,
) -> Result<ClientRequest, Failure> {
    ClientRequest::for_installation(
        installation,
        std::time::Duration::from_secs(cli.timeout),
        cli.tls_ca.as_deref(),
    )
    .map_err(|e| local(1, "cli_internal", e))
}

// ------------------------------------------------------------------ secret set

/// `secret set`: replace the client secret, then prove it works with
/// one status check; a refused check leaves the new file in place
/// (the old secret is already dead).
pub(super) async fn secret_set(cli: &Cli, channel: &SecretChannel) -> Outcome {
    let installation = installation()?;
    secret(&installation)?;
    let new = read_input(
        channel.file.as_ref(),
        channel.stdin,
        "new client secret (hidden): ",
    )?;
    if let Err(why) = client::commit_secret(&installation.directory, &new) {
        return Err(local(1, "cli_internal", why));
    }
    let check = request(&installation, cli)?
        .call(Method::GET, "/control/v1/client/status", Some(&new), None)
        .await;
    match check {
        Ok((status, _)) if status.is_success() => {
            let result = client::client_result(&installation);
            Ok((
                result,
                format!(
                    "the client secret is replaced and serves ({})",
                    installation.client_id
                ),
            ))
        }
        Ok((status, value)) => {
            let (code, message) = client::client_failure(status, &value);
            if code == 5 {
                return Err(local(
                    5,
                    "cli_refused",
                    format!(
                        "the server refuses the new secret: {message}; the operator's disclosure and this file disagree — the old secret is already dead. The new file is kept; install the operator's value with `secret set` again"
                    ),
                ));
            }
            Err(local(code, "cli_refused", message))
        }
        Err((code, why)) => Err(local(
            code,
            "cli_unreachable",
            format!("the new secret is in place but the status check failed: {why}"),
        )),
    }
}

// ------------------------------------------------------------------ status

/// The client read plus the origins the installation
/// holds; the human form is a rate-limit table with diagnostics under
/// `--verbose`, `--line` is exactly the
/// status-line text, `--json` is the envelope result.
pub(super) async fn status(cli: &Cli, args: &StatusArgs) -> Outcome {
    if args.check {
        // The exit code is the answer; the verb refuses --json with --check.
        return Ok((Value::Null, String::new()));
    }
    let mut installation = installation()?;
    let secret_value = secret(&installation)?;
    let mut path = "/control/v1/client/status".to_string();
    if let Some(session) = &args.session {
        path.push_str(&format!("?session_id={session}"));
    }
    path.push_str(if args.session.is_some() { "&" } else { "?" });
    path.push_str("rate_limits=true");
    let (status, body) = match request(&installation, cli)?
        .call(Method::GET, &path, Some(&secret_value), None)
        .await
    {
        Ok(pair) => pair,
        Err((code, why)) => {
            let slug = if code == 4 {
                "cli_unreachable"
            } else {
                "cli_incompatible_server"
            };
            return Err(local(code, slug, why));
        }
    };
    if !status.is_success() {
        let (code, message) = client::client_failure(status, &body);
        let slug = match code {
            5 => "cli_refused",
            6 => "cli_not_found",
            10 => "cli_incompatible_server",
            _ => "cli_internal",
        };
        return Err(local(code, slug, message));
    }
    client::keep_identity(&installation, &body);
    if !args.line {
        crate::client_ca::follow(&mut installation, &secret_value, &body).await;
        super::follow(&installation, &secret_value, &body).await;
    }
    let mut result = body;
    result["client"]["origins"] = json!({
        "base_url": installation.base_url,
        "proxy": installation.proxy,
    });
    // The probe host, asked twice.
    let probe = crate::probe_client::probe(&installation, &secret_value).await;
    result["probe"] = crate::probe_client::member(&probe);
    let failure = crate::probe_client::failure(&probe);
    let human = status_human(&result, cli, args);
    match failure {
        // The probe's failure class is the exit code. The facts still
        // read on standard output; the failure is its one line on stderr.
        Some((code, slug, message)) => {
            if !cli.json && !args.line {
                println!("{human}");
            }
            let message = if slug == "cli_ca_untrusted" {
                format!(
                    "{message} (the server's CA is {}; client.toml records {})",
                    result["ca_fingerprint"].as_str().unwrap_or("unknown"),
                    installation.ca_fingerprint.as_deref().unwrap_or("none")
                )
            } else {
                message
            };
            Err(local(code, slug, message))
        }
        None => {
            if args.line {
                // Exactly the status-line text, colour as the colour rule says.
                let colour = colour_wanted(cli);
                let line = crate::statusline::render(
                    &crate::statusline::Snapshot::Answer(result.clone()),
                    colour,
                );
                return Ok((Value::Null, line));
            }
            Ok((result, human))
        }
    }
}

/// Rate limits, followed by client diagnostics under `--verbose`.
fn status_human(result: &Value, cli: &Cli, args: &StatusArgs) -> String {
    let table = result["accounts"]
        .as_array()
        .map(|accounts| super::verbs::rate_limits_table(accounts, colour_wanted(cli)))
        .unwrap_or_else(|| "accounts  (rate limits unavailable)".to_owned());
    if !args.verbose {
        return table;
    }
    let client = &result["client"];
    let origins = &client["origins"];
    let proxy = origins["proxy"]
        .as_str()
        .filter(|p| !p.is_empty())
        .unwrap_or("none");
    let mut lines = vec![
        table,
        format!(
            "client:   {} ({}) · base URL {}, proxy {}",
            client["id"].as_str().unwrap_or(""),
            client["display_name"].as_str().unwrap_or(""),
            origins["base_url"].as_str().unwrap_or(""),
            proxy
        ),
    ];
    let server = &result["server"];
    lines.push(format!(
        "server:   {}, {}, control API {}",
        server["version"].as_str().unwrap_or(""),
        if server["available"].as_bool().unwrap_or(false) {
            "available"
        } else {
            "unavailable"
        },
        server["control_api_version"]
    ));
    let pool = &result["pool"];
    let sessions = &result["sessions"];
    lines.push(format!(
        "pool:     {} of {} accounts selectable, {} active sessions ({} known)",
        pool["accounts_selectable"],
        pool["accounts_configured"],
        sessions["active"],
        sessions["known"]
    ));
    // The named session's row only when the caller asked for one.
    if let Some(session) = result.get("session") {
        match session.as_object() {
            Some(session) => lines.push(format!(
                "session:  served by {}, last routed {}",
                session["serving_account_display_name"]
                    .as_str()
                    .unwrap_or(""),
                session["last_routed_at"].as_str().unwrap_or("")
            )),
            None => lines.push("session:  no routed request yet".to_owned()),
        }
    }
    lines.push(format!(
        "capture:  {}",
        if result["wire_capture_enabled"].as_bool().unwrap_or(false) {
            "ON: request and response bodies are being recorded"
        } else {
            "off"
        }
    ));
    lines.push(format!(
        "hold:     {}",
        match result["hold_hint_seconds"].as_u64() {
            Some(0) | None => "none".to_owned(),
            Some(seconds) => format!("up to {seconds} s before an answer"),
        }
    ));
    if let Some(probe) = result.get("probe").filter(|p| p.is_object()) {
        let fingerprint = match probe["fingerprint_matches"].as_bool() {
            Some(true) => ", the CA fingerprint matches",
            Some(false) => ", the CA fingerprint differs",
            None => "",
        };
        lines.push(format!(
            "probe:    {}{}",
            probe["outcome"].as_str().unwrap_or(""),
            fingerprint
        ));
    }
    lines.join("\n")
}

// --------------------------------------------------------------------- api

/// `api` as the enrolled client: the installation's secret goes into the
/// intent header, never argv, and the exchange leaves its audit record like
/// any other request from this machine.
pub(super) async fn api(cli: &Cli, args: &ApiArgs) -> Outcome {
    let installation = installation()?;
    let secret_value = secret(&installation)?;
    let (method, body, headers) = api_request(args)?;
    let origin = installation.base_url.clone();
    let response = request(&installation, cli)?
        .send(method, &args.path, Some(&secret_value), body, &headers)
        .await
        .map_err(client_failure_pair)?;
    api_response(response, cli, &|why| {
        local(4, "cli_unreachable", format!("{origin}: {why}"))
    })
    .await
}
