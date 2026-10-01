//! `update --from <client-kit.zip>`: replace only the executable,
//! the two Claude Code settings entries (merged) and release identity;
//! reuse `client.toml`, `client-secret` and `ca.pem`; ask for no code; roll
//! the replacements back when the authenticated post-update status check
//! fails. [`follow`] runs the same steps on the kit the server offers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use super::args::Cli;
use super::{Failure, Outcome};
use crate::bundle::{self, PinnedKey};
use crate::client::{self, ClientInstallation};
use crate::config::platform;
use crate::server::VERSION;

fn installation_refusal((code, message): (i32, String)) -> Failure {
    let slug = match code {
        11 => "cli_not_enrolled",
        5 => "cli_refused",
        3 => "cli_configuration_invalid",
        _ => "cli_internal",
    };
    local(code, slug, message)
}

fn local(code: i32, slug: &str, message: impl Into<String>) -> Failure {
    Failure::local(code, slug, message)
}

/// `path` with `.<suffix>` appended to its file name.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// Writes `bytes` to `<path>.new` (mode 0700 on Unix) and renames over
/// `path`, so the old file stands until the replacement is complete. A
/// running Windows executable cannot be replaced, only renamed, so it moves
/// to `<path>.old` first.
fn replace_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let staged = sibling(path, "new");
    std::fs::write(&staged, bytes).map_err(|e| format!("{}: {e}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", staged.display()))?;
    }
    let aside = sibling(path, "old");
    let set_aside = cfg!(windows) && path.exists();
    if set_aside {
        let _ = std::fs::remove_file(&aside);
        std::fs::rename(path, &aside).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    std::fs::rename(&staged, path).map_err(|e| {
        if set_aside {
            let _ = std::fs::rename(&aside, path);
        }
        format!("{}: {e}", path.display())
    })
}

/// Puts the previous executable back: the set-aside file on Windows, its
/// bytes elsewhere, and none when there was none.
fn restore(path: &Path, previous: Option<&[u8]>) -> Result<(), String> {
    let aside = sibling(path, "old");
    if cfg!(windows) && aside.is_file() {
        return std::fs::rename(&aside, path).map_err(|e| format!("{}: {e}", path.display()));
    }
    match previous {
        Some(bytes) => replace_atomically(path, bytes),
        None => std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display())),
    }
}

/// `update [--from <kit>] [--version <semver>]
/// [--release-origin <https-origin>]`. With `--from` the given archive is
/// applied; without it, `--version`'s client kit — or the newest published
/// one (the origin's latest redirect) — is fetched from the origin first,
/// verified by [`bundle::verify_kit_zip`], then the same pipeline runs. The
/// fetched kit is a private temporary file, deleted afterwards.
pub(super) async fn update(
    cli: &Cli,
    from: Option<&Path>,
    version: Option<&str>,
    release_origin: Option<&str>,
) -> Outcome {
    let staged = match from {
        Some(_) => None,
        None => {
            let requested = match version {
                Some(version) => version.to_string(),
                None => {
                    eprintln!("asking the release host for its newest release");
                    crate::deploy::release::newest_version(release_origin, cli.tls_ca.as_deref())
                        .await
                        .map_err(|why| local(4, "cli_unreachable", why))?
                }
            };
            eprintln!("fetching the client kit for {requested}");
            Some(
                crate::deploy::release::fetch_client_kit(
                    &requested,
                    release_origin,
                    cli.tls_ca.as_deref(),
                )
                .await
                .map_err(|why| local(17, "cli_release_unverified", why))?,
            )
        }
    };
    let outcome = update_from(from.unwrap_or_else(|| {
        staged
            .as_deref()
            .expect("the fetched kit stands in for --from")
    }))
    .await;
    if let Some(dir) = staged.and_then(|p| p.parent().map(Path::to_path_buf)) {
        let _ = std::fs::remove_dir_all(dir);
    }
    outcome
}

/// The `--from` pipeline.
async fn update_from(from: &Path) -> Outcome {
    let installation = client::read_installation().map_err(installation_refusal)?;
    let secret = client::read_secret(&installation).map_err(installation_refusal)?;
    let version = install(&installation, &secret, from).await?;
    let mut result = client::client_result(&installation);
    result["version"] = json!(version);
    let human = format!(
        "updated the client to {version} ({})",
        installation.client_id
    );
    Ok((result, human))
}

/// Verify the kit at `from`, replace the executable and the settings
/// entries, check the server still answers, and roll back if it does not.
/// Returns the installed version.
async fn install(
    installation: &ClientInstallation,
    secret: &str,
    from: &Path,
) -> Result<String, Failure> {
    let key = PinnedKey::load().map_err(|why| {
        local(
            17,
            "cli_release_unverified",
            format!("the client kit cannot be verified: {why}"),
        )
    })?;
    let kit = bundle::verify_kit_zip(from, &key).map_err(|why| {
        local(
            17,
            "cli_release_unverified",
            format!("{}: {why}", from.display()),
        )
    })?;
    let Some(payload_member) = bundle::native_payload() else {
        return Err(local(
            18,
            "cli_preflight_failed",
            format!(
                "this platform ({}/{}) has no client payload in the kit",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        ));
    };
    let executable = kit.members[payload_member].clone();

    let binary = platform::client_binary();
    let old_executable = std::fs::read(&binary).ok();
    let settings_path = crate::settings::path();
    let old_settings = std::fs::read(&settings_path).ok();

    // The settings error already names the file.
    let plan = crate::settings::plan_install(&binary)
        .map_err(|why| local(1, "cli_internal", format!("{why}; nothing was changed")))?;
    if let Some(command) = crate::settings::foreign_status_line(&binary) {
        eprintln!(
            "notice: Claude Code's status line is another tool's ({command}); it was left in place and the jaynshare status line was not installed. Remove it and run `jaynshare update --from <kit>` to install ours."
        );
    }

    if let Err(why) = replace_atomically(&binary, &executable) {
        return Err(local(1, "cli_internal", why));
    }
    if let Some(plan) = &plan
        && let Err(why) = crate::settings::commit(plan)
    {
        return Err(local(1, "cli_internal", why));
    }

    match client::snapshot(installation, secret, None, Duration::from_secs(5)).await {
        Ok(_) => Ok(kit.version),
        Err((code, why)) => {
            // The replacements roll back; the three client files
            // never were touched.
            let _ = restore(&binary, old_executable.as_deref());
            match &old_settings {
                Some(bytes) => {
                    let _ = crate::state::write_private_atomic(&settings_path, bytes)
                        .map_err(|e| e.to_string());
                }
                None => {
                    let _ = std::fs::remove_file(&settings_path);
                }
            }
            let slug = match code {
                4 => "cli_unreachable",
                5 => "cli_refused",
                _ => "cli_incompatible_server",
            };
            Err(local(
                code,
                slug,
                format!(
                    "the post-update status check failed ({why}); the executable and the Claude Code settings entries were rolled back"
                ),
            ))
        }
    }
}

// ------------------------------------------------------------------ following the server

/// `claude` and `status` follow their server: when the snapshot names
/// another client payload than this process runs, the server's kit is
/// fetched, verified against the pinned key and installed by [`install`],
/// then this process re-runs as the new client with the same arguments. A
/// failure says why and returns, so the caller carries on as this version.
pub(crate) async fn follow(installation: &ClientInstallation, secret: &str, snapshot: &Value) {
    if cfg!(windows) {
        let _ = std::fs::remove_file(sibling(&platform::client_binary(), "old"));
    }
    let Some((binary, wanted)) = behind(snapshot) else {
        return;
    };
    let offered = snapshot["client"]["version"].as_str().unwrap_or("unknown");
    eprintln!("jaynshare: updating to this server's client, {offered}");
    let staged = installation.directory.join("client-kit.zip.partial");
    let installed = fetch_and_install(installation, secret, &staged).await;
    let _ = std::fs::remove_file(&staged);
    let why = match installed {
        // Re-running only once the installed file is the announced one
        // means a server whose kit disagrees with its snapshot cannot loop us.
        Ok(_) if digest(&binary).as_deref() == Some(wanted.as_str()) => rerun(&binary),
        Ok(version) => {
            format!("the server's kit holds another client than it announced ({version})")
        }
        Err(why) => format!("not updated: {why}"),
    };
    eprintln!("jaynshare: {why}; carrying on with {VERSION}");
}

/// The installed executable and the server's payload digest, when this
/// process runs that executable and the server offers another one. A build
/// run from anywhere else never follows.
fn behind(snapshot: &Value) -> Option<(PathBuf, String)> {
    let wanted = snapshot["client"]["sha256"][bundle::native_platform()?].as_str()?;
    let binary = platform::client_binary().canonicalize().ok()?;
    let running = std::env::current_exe().ok()?.canonicalize().ok()?;
    (running == binary && digest(&binary)? != wanted).then(|| (binary, wanted.to_string()))
}

fn digest(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|bytes| bundle::sha256_hex(&bytes))
}

async fn fetch_and_install(
    installation: &ClientInstallation,
    secret: &str,
    staged: &Path,
) -> Result<String, String> {
    client::download_kit(installation, secret, staged)
        .await
        .map_err(|(_, why)| why)?;
    install(installation, secret, staged)
        .await
        .map_err(|failure| {
            failure.error["message"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
}

/// Becomes `binary` with this process's arguments; returns only on failure.
#[cfg(unix)]
fn rerun(binary: &Path) -> String {
    use std::os::unix::process::CommandExt;
    let mut args = std::env::args_os();
    let error = std::process::Command::new(binary)
        .arg0(args.next().unwrap_or_default())
        .args(args)
        .exec();
    format!("could not run {}: {error}", binary.display())
}

/// Where no `exec` exists: run `binary` and exit with its status.
#[cfg(not(unix))]
fn rerun(binary: &Path) -> String {
    match std::process::Command::new(binary)
        .args(std::env::args_os().skip(1))
        .status()
    {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => format!("could not run {}: {error}", binary.display()),
    }
}
