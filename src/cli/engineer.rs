//! The engineer's own verbs: `enrol --bundle`, `secret set` and the
//! `--json` form of `status --client`. These run without an operator
//! configuration — the installation itself is their context, and `api`
//! in its client form.

use std::path::Path;

use http::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::args::{ApiArgs, Cli, SecretChannel, StatusArgs};
use super::verbs::{api_request, api_response, confirm, read_input};
use super::{Failure, Outcome};
use crate::bundle::{self, PinnedKey};
use crate::client::{self, ClientInstallation, ClientRequest};

fn local(code: i32, slug: &str, message: impl Into<String>) -> Failure {
    Failure::local(code, slug, message)
}

/// A `(exit code, message)` from the client's HTTP layer as a `Failure`.
fn client_failure_pair((code, message): (i32, String)) -> Failure {
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

fn installation() -> Result<ClientInstallation, Failure> {
    client::read_installation().map_err(client_failure_pair)
}

fn secret(installation: &ClientInstallation) -> Result<String, Failure> {
    client::read_secret(installation).map_err(client_failure_pair)
}

/// The colour rule; the human and one-line forms share it.
fn colour_wanted(cli: &Cli) -> bool {
    super::colour_wanted(cli)
}

/// The installation's `base-url-ca.pem` is trusted without
/// `--tls-ca`; a global `--tls-ca` is added beside it.
fn request(installation: &ClientInstallation, cli: &Cli) -> Result<ClientRequest, Failure> {
    let anchor = installation.base_url_ca();
    let anchors: Vec<&Path> = anchor
        .as_deref()
        .into_iter()
        .chain(cli.tls_ca.as_deref())
        .collect();
    ClientRequest::new(
        &installation.base_url,
        std::time::Duration::from_secs(cli.timeout),
        &anchors,
    )
    .map_err(|e| local(1, "cli_internal", e))
}

// ------------------------------------------------------------------ enrol

/// `enrol --bundle <extracted-dir>`: verify the bundle,
/// show its facts, confirm, stage, claim, commit — removing everything staged
/// when the claim does not answer (a code is never retried).
pub(super) async fn enrol(cli: &Cli, bundle_dir: &Path, trust_os_store: bool) -> Outcome {
    let toml = crate::config::platform::client_directory().join("client.toml");
    if toml.is_file() {
        return Err(local(
            8,
            "cli_conflict",
            format!(
                "{}: this machine is already enrolled; rotate the client's secret instead",
                toml.display()
            ),
        ));
    }
    let key = PinnedKey::load().map_err(|why| {
        local(
            17,
            "cli_release_unverified",
            format!("the enrollment bundle cannot be verified: {why}"),
        )
    })?;
    let facts = bundle::verify_bundle_dir(bundle_dir, &key).map_err(|why| {
        local(
            17,
            "cli_release_unverified",
            format!("{}: {why}", bundle_dir.display()),
        )
    })?;
    // Every launch is MITM mode, so refuse a bundle without the proxy origin
    // or its CA before showing facts or writing anything.
    if facts.proxy.is_none() {
        return Err(local(
            14,
            "cli_transport_unavailable",
            "this enrollment has no proxy origin; the server must enable MITM mode",
        ));
    }
    if facts.ca_sha256.is_none() {
        return Err(local(
            14,
            "cli_transport_unavailable",
            "this enrollment has no CA certificate; the server must enable MITM mode",
        ));
    }
    let ca_pem = std::fs::read(bundle_dir.join("ca.pem"))
        .map_err(|e| local(17, "cli_release_unverified", format!("ca.pem: {e}")))?;
    let Some(payload_member) = bundle::native_payload() else {
        return Err(local(
            18,
            "cli_preflight_failed",
            format!(
                "this platform ({}/{}) has no client payload in the bundle",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        ));
    };
    let payload = std::fs::read(bundle_dir.join(payload_member)).map_err(|e| {
        local(
            17,
            "cli_release_unverified",
            format!("{payload_member}: {e}"),
        )
    })?;
    // An `https` base URL brings its listener's trust anchor, which the
    // bundle verification already bound to the manifest.
    let base_url_ca_pem = match facts.base_url_ca_sha256 {
        Some(_) => Some(
            std::fs::read(bundle_dir.join(bundle::BASE_URL_CA_MEMBER)).map_err(|e| {
                local(
                    17,
                    "cli_release_unverified",
                    format!("{}: {e}", bundle::BASE_URL_CA_MEMBER),
                )
            })?,
        ),
        None => None,
    };
    // The facts, before anything is asked or written.
    eprintln!("client id:        {}", facts.client_id);
    eprintln!("display name:     {}", facts.display_name);
    eprintln!("base URL:         {}", facts.base_url);
    eprintln!(
        "proxy:            {}",
        facts.proxy.as_deref().unwrap_or("none")
    );
    eprintln!(
        "pending until:    {}",
        facts.pending_expires_at.as_deref().unwrap_or("unknown")
    );
    eprintln!(
        "CA fingerprint:   {}",
        facts.ca_fingerprint.as_deref().unwrap_or("none")
    );
    eprintln!(
        "base-URL CA:      {}",
        facts.base_url_ca_fingerprint.as_deref().unwrap_or("none")
    );
    eprintln!(
        "release:          {} ({})",
        facts.release_version, facts.release_commit
    );
    if !confirm("install this enrollment? [y/N] ")? {
        return Err(local(
            21,
            "cli_confirmation_required",
            "the enrollment was refused; nothing was installed",
        ));
    }
    // The two settings entries are planned before the code is
    // read, so a settings file that is not JSON stops the install while the
    // code is still unspent and nothing has been written.
    let settings_plan = crate::settings::plan_install(&crate::config::platform::client_binary())
        .map_err(|why| {
            local(
                1,
                "cli_internal",
                format!("{why}; nothing was installed and the enrollment code is unspent"),
            )
        })?;
    if let Some(command) =
        crate::settings::foreign_status_line(&crate::config::platform::client_binary())
    {
        eprintln!(
            "notice: Claude Code's status line is another tool's ({command}); it was left in place and the jaynshare status line was not installed. Remove it and run `jaynshare update --from <kit>` to install ours."
        );
    }
    // The code enters by hidden prompt only — never argv, an
    // environment variable, a file or standard output.
    eprint!("enrollment code (hidden): ");
    use std::io::Write as _;
    std::io::stderr().flush().ok();
    let code = rpassword::read_password().map_err(|e| {
        if e.kind() == std::io::ErrorKind::Interrupted {
            local(130, "cli_interrupted", "interrupted at the hidden prompt")
        } else {
            local(1, "cli_internal", format!("hidden prompt: {e}"))
        }
    })?;
    // Stage everything but the secret before the claim, so the claim
    // is the last step that can fail.
    let toml_document = client::client_toml(
        &facts.client_id,
        &facts.display_name,
        &facts.base_url,
        facts.proxy.as_deref(),
        facts.ca_fingerprint.as_deref(),
        facts.base_url_ca_fingerprint.as_deref(),
        &[],
    );
    let staged = client::stage(
        &toml_document,
        &payload,
        Some(&ca_pem),
        base_url_ca_pem.as_deref(),
    )
    .map_err(|why| {
        local(
            1,
            "cli_internal",
            format!("staging the installation failed: {why}"),
        )
    })?;
    let staged_anchor = base_url_ca_pem
        .as_ref()
        .map(|_| staged.join(client::BASE_URL_CA_FILE));
    let claim_request = request_from_base_url(&facts, staged_anchor.as_deref(), cli)?;
    let claim = async {
        let body = json!({ "id": facts.client_id, "code": code.trim() });
        claim_request
            .call(
                Method::POST,
                "/control/v1/enrollment/claim",
                None,
                Some(&body),
            )
            .await
    }
    .await;
    let claimed = match claim {
        Ok((status, value)) if status.is_success() => value,
        Ok((_, value)) => {
            // The claim was refused, or answered anything but success: the
            // code may be spent — it is never retried.
            client::remove_staged();
            let why = value["error"]["message"]
                .as_str()
                .unwrap_or("the server refused the claim")
                .to_string();
            return Err(local(
                5,
                "cli_refused",
                format!(
                    "the enrollment claim was refused ({why}); the installation was removed and the operator must reissue the generation"
                ),
            ));
        }
        Err((_, why)) => {
            client::remove_staged();
            return Err(local(
                5,
                "cli_refused",
                format!(
                    "the enrollment claim failed ({why}); the installation was removed and the operator must reissue the generation — the code is never retried"
                ),
            ));
        }
    };
    let Some(secret_value) = claimed["client_secret"].as_str() else {
        client::remove_staged();
        return Err(local(
            10,
            "cli_incompatible_server",
            "the claim response carries no client_secret; the installation was removed and the operator must reissue the generation",
        ));
    };
    let directory = crate::config::platform::client_directory();
    if let Err(why) = client::commit_secret(&directory, secret_value) {
        client::remove_staged();
        return Err(local(
            1,
            "cli_internal",
            format!(
                "writing the client secret failed: {why}; the operator must reissue the generation"
            ),
        ));
    }
    // The settings entries commit with the installation. The secret
    // is already durable, so a failure here is reported, never rolled back:
    // `update --from` writes the entries again.
    if let Some(plan) = &settings_plan
        && let Err(why) = crate::settings::commit(plan)
    {
        eprintln!(
            "warning: the Claude Code settings entries were not written ({why}); run `jaynshare update --from <kit>` to add them"
        );
    }
    // Last check: the installation is kept whatever this answers,
    // but the engineer learns of it.
    let installation = match installation() {
        Ok(installation) => installation,
        Err(failure) => return Err(failure),
    };
    let check = request(&installation, cli)?
        .call(
            Method::GET,
            "/control/v1/client/status",
            Some(&secret(&installation)?),
            None,
        )
        .await;
    match check {
        Ok((status, _)) if status.is_success() => {}
        Ok((status, value)) => {
            let (code, message) = client::client_failure(status, &value);
            return Err(local(
                code,
                "cli_refused",
                format!("the installation is in place but its status check was refused: {message}"),
            ));
        }
        Err((code, why)) => {
            return Err(local(
                code,
                "cli_unreachable",
                format!("the installation is in place but the control plane is unreachable: {why}"),
            ));
        }
    }
    // The OS-store trust is this flag alone, never the default.
    // Its failure does not invalidate the file-based trust, so it is
    // reported and the install still succeeds.
    if trust_os_store {
        let ca = installation.directory.join("ca.pem");
        let fingerprint = installation.ca_fingerprint.clone().unwrap_or_default();
        eprintln!("CA fingerprint: {fingerprint}");
        eprintln!(
            "the CA will be trusted by every program of this user, not only the launched Claude Code"
        );
        if let Err(why) = crate::deploy::trust_store::add(&ca, &fingerprint) {
            eprintln!(
                "warning: the CA was not added to the OS trust store ({why}); the per-launch trust of `NODE_EXTRA_CA_CERTS` is unaffected"
            );
        }
    }
    let result = client::client_result(&installation);
    let human = format!(
        "enrolled {} ({}); installation in {}",
        installation.client_id,
        installation.display_name,
        installation.directory.display()
    );
    Ok((result, human))
}

/// A request to the manifest's base URL, before the installation exists:
/// an `https` origin is trusted through the staged `base-url-ca.pem`.
fn request_from_base_url(
    facts: &bundle::BundleManifest,
    staged_anchor: Option<&Path>,
    cli: &Cli,
) -> Result<ClientRequest, Failure> {
    let anchors: Vec<&Path> = staged_anchor
        .into_iter()
        .chain(cli.tls_ca.as_deref())
        .collect();
    ClientRequest::new(
        &facts.base_url,
        std::time::Duration::from_secs(cli.timeout),
        &anchors,
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

// ------------------------------------------------------------------ ca update

/// The CA update ZIP carries exactly these members, no more, no fewer.
const CA_UPDATE_MEMBERS: [&str; 3] = ["ca-update.json", "ca.pem", "README.txt"];

/// `ca-update --from <zip>`: verify the bundle's certificate
/// and digests, show both fingerprints, require the independent comparison,
/// then atomically replace only `ca.pem` and the fingerprint in `client.toml`
/// — the client id, generation, secret and release identity are untouched.
pub(super) async fn ca_update(cli: &Cli, from: &Path) -> Outcome {
    let invalid = |why: String| {
        local(
            17,
            "cli_bundle_invalid",
            format!("{}: {why}", from.display()),
        )
    };
    let members = bundle::read_zip(from).map_err(invalid)?;
    for required in CA_UPDATE_MEMBERS {
        if !members.contains_key(required) {
            return Err(invalid(format!(
                "the CA update bundle is missing {required:?}"
            )));
        }
    }
    if let Some(extra) = members
        .keys()
        .find(|name| !CA_UPDATE_MEMBERS.contains(&name.as_str()))
    {
        return Err(invalid(format!(
            "the CA update bundle carries an unexpected member {extra:?}"
        )));
    }
    let manifest: Value = serde_json::from_slice(&members["ca-update.json"])
        .map_err(|e| invalid(format!("ca-update.json: {e}")))?;
    let manifest_fingerprint = manifest["fingerprint"]
        .as_str()
        .ok_or_else(|| invalid("ca-update.json: fingerprint missing".to_string()))?;
    let manifest_sha256 = manifest["ca_sha256"]
        .as_str()
        .ok_or_else(|| invalid("ca-update.json: ca_sha256 missing".to_string()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&members["ca.pem"])
        .map_err(|e| invalid(format!("ca.pem: {e}")))?;
    pem.parse_x509()
        .map_err(|e| invalid(format!("ca.pem: {e}")))?;
    let digest = Sha256::digest(&pem.contents);
    let bare: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let colon = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    if colon != manifest_fingerprint || bare != manifest_sha256 {
        return Err(invalid(
            "ca.pem: its digest does not match the manifest's".to_string(),
        ));
    }
    let installation = installation()?;
    eprintln!(
        "current CA fingerprint: {}",
        installation.ca_fingerprint.as_deref().unwrap_or("none")
    );
    eprintln!("new CA fingerprint:     {manifest_fingerprint}");
    if !cli.yes
        && !confirm(
            "compare the new fingerprint with the operator's `ca show` through an independent channel; matches? [y/N] ",
        )?
    {
        return Err(local(
            21,
            "cli_confirmation_required",
            "the update was refused; nothing was replaced",
        ));
    }
    let new_fingerprint = manifest_fingerprint.to_string();
    crate::state::write_private_atomic(&installation.directory.join("ca.pem"), &members["ca.pem"])
        .map_err(|why| local(1, "cli_internal", format!("replacing ca.pem failed: {why}")))?;
    let document = client::client_toml(
        &installation.client_id,
        &installation.display_name,
        &installation.base_url,
        installation.proxy.as_deref(),
        Some(&new_fingerprint),
        installation.base_url_ca_fingerprint.as_deref(),
        &installation.no_proxy,
    );
    crate::state::write_private_atomic(
        &installation.directory.join("client.toml"),
        document.as_bytes(),
    )
    .map_err(|why| {
        local(
            1,
            "cli_internal",
            format!("rewriting client.toml failed: {why}"),
        )
    })?;
    let result = json!({
        "previous_fingerprint": installation.ca_fingerprint,
        "fingerprint": new_fingerprint,
        "directory": installation.directory.display().to_string(),
    });
    Ok((result, format!("updated the CA: {new_fingerprint}")))
}

// ------------------------------------------------------------------ status

/// The client read plus the origins the installation
/// holds; the human form is labelled lines, `--line` is exactly the
/// status-line text, `--json` is the envelope result.
pub(super) async fn status(cli: &Cli, args: &StatusArgs) -> Outcome {
    if args.check {
        // The exit code is the answer; the verb refuses --json with --check.
        return Ok((Value::Null, String::new()));
    }
    let installation = installation()?;
    let secret_value = secret(&installation)?;
    let mut path = "/control/v1/client/status".to_string();
    if let Some(session) = &args.session {
        path.push_str(&format!("?session_id={session}"));
    }
    if args.line {
        path.push_str(if args.session.is_some() { "&" } else { "?" });
        path.push_str("rate_limits=true");
    }
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
    if !args.line {
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
    let human = status_human(&result);
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

/// The human form, labelled lines built
/// from `result` (the status body plus `client.origins` and
/// `probe`) and nothing else.
fn status_human(result: &Value) -> String {
    let client = &result["client"];
    let origins = &client["origins"];
    let proxy = origins["proxy"]
        .as_str()
        .filter(|p| !p.is_empty())
        .unwrap_or("none");
    let mut lines = vec![format!(
        "client:   {} ({}) · base URL {}, proxy {}",
        client["id"].as_str().unwrap_or(""),
        client["display_name"].as_str().unwrap_or(""),
        origins["base_url"].as_str().unwrap_or(""),
        proxy
    )];
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
