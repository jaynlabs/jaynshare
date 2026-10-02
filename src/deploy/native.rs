//! The native Linux server — `server install|update|
//! uninstall|prune`. The paths are the fixed ones below, real on the host;
//! the acceptance suite runs these verbs as root inside `LinuxBox`, never
//! through a path seam. Platform tools are reached by name from `PATH`, one
//! wrapper each:
//! `systemctl` through `systemd::systemctl`, account tools through
//! [`account_tool`].
//!
//! Check names start with their exit class (`cli/deploy.rs::exit_row`);
//! `rolled_back` is 20.

#![allow(dead_code)] // some helpers are exercised only by the acceptance suite

use std::io::Read as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Output;

use serde::{Deserialize, Serialize};

use super::address::Detected;
use super::result::{Check, DeployResult};
use unix::{MetadataExt as _, PermissionsExt as _};

/// The Unix calls the native install makes: modes, ownership, links and the
/// effective uid. The install is Linux-only and `platform_gate` refuses
/// everywhere else before any of them runs; off Unix they exist so
/// the one executable builds for every target.
#[cfg(unix)]
mod unix {
    pub(super) use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    pub(super) fn is_root() -> bool {
        // SAFETY: geteuid(2) takes no argument and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    pub(super) fn chown(path: &std::path::Path, uid: u32, gid: u32) -> std::io::Result<()> {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
    }
}

#[cfg(not(unix))]
mod unix {
    const OFF_UNIX: &str = "the native install runs only on Linux; platform_gate refuses first";

    pub(super) trait PermissionsExt {
        fn from_mode(mode: u32) -> Self;
    }

    impl PermissionsExt for std::fs::Permissions {
        fn from_mode(_: u32) -> Self {
            unreachable!("{OFF_UNIX}")
        }
    }

    pub(super) trait MetadataExt {
        fn mode(&self) -> u32;
        fn uid(&self) -> u32;
        fn gid(&self) -> u32;
    }

    impl MetadataExt for std::fs::Metadata {
        fn mode(&self) -> u32 {
            unreachable!("{OFF_UNIX}")
        }
        fn uid(&self) -> u32 {
            unreachable!("{OFF_UNIX}")
        }
        fn gid(&self) -> u32 {
            unreachable!("{OFF_UNIX}")
        }
    }

    pub(super) fn symlink(
        _: impl AsRef<std::path::Path>,
        _: impl AsRef<std::path::Path>,
    ) -> std::io::Result<()> {
        unreachable!("{OFF_UNIX}")
    }

    pub(super) fn is_root() -> bool {
        false
    }

    pub(super) fn chown(_: &std::path::Path, _: u32, _: u32) -> std::io::Result<()> {
        unreachable!("{OFF_UNIX}")
    }
}

/// Every versioned release lives below this root, owned by root.
pub const RELEASES: &str = "/opt/jaynshare/releases";
/// The atomically replaced link to one complete release.
pub const CURRENT: &str = "/opt/jaynshare/current";
/// The command link on the search path.
pub const COMMAND_LINK: &str = "/usr/local/bin/jaynshare";
/// The dedicated non-login user and group.
pub const SERVICE_USER: &str = "jaynshare";
/// The service home, which fixes the Linux default paths.
pub const SERVICE_HOME: &str = "/var/lib/jaynshare";
/// The client kit's name inside a version directory, so the server's kit is
/// `CURRENT/client-kit.zip` (contract K1).
pub const KIT_FILE: &str = "client-kit.zip";
/// Where the installed release came from, which `server update` with no
/// version follows.
pub const ORIGIN_RECORD: &str = "/opt/jaynshare/origin.json";

/// The one wrapper for the account tools the service account needs (`getent`, `id`,
/// `useradd`, `groupadd`): `<tool> <args>`, standard input closed.
pub fn account_tool(tool: &str, args: &[&str]) -> Result<Output, String> {
    std::process::Command::new(tool)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{tool}: {e}"))
}

/// `server install`'s inputs.
pub struct InstallInputs<'a> {
    pub source: Source<'a>,
    /// The global `--config`: the operator's configuration, copied to the
    /// service's path. Without it the installed one stays, or one is written.
    pub config: Option<&'a Path>,
    /// The data-plane address of a written configuration; detected when absent.
    pub listen: Option<IpAddr>,
    /// A mirror in place of the recorded or official origin.
    pub release_origin: Option<&'a str>,
    /// The global `--tls-ca`: the extra trust anchor for a download.
    pub tls_ca: Option<&'a Path>,
    /// Reads one typed line on a terminal; `Err(why)` when there is none.
    pub ask: &'a dyn Fn(&str) -> Result<String, String>,
    /// The manual firewall record for the configuration at a path
    /// (preflight's `UnknownFirewall::Recorded`).
    pub firewall_record: &'a dyn Fn(&Path) -> Option<String>,
}

/// Where `server install` and `server update` take a release from.
pub enum Source<'a> {
    /// A release directory on this host (`--from`).
    Directory(&'a Path),
    /// A published version, fetched from the origin; the newest when `None`.
    Published(Option<&'a str>),
    /// A clone's own build (`--binary`) with a client kit: `--kit`, else the
    /// official kit of the build's version.
    Build {
        binary: &'a Path,
        kit: Option<&'a Path>,
    },
}

/// Where the installed release came from, as [`ORIGIN_RECORD`] holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Origin {
    Official,
    /// An `https` mirror of the release origin.
    Mirror(String),
    /// A clone build's executable, installed again as it is rebuilt.
    Build(PathBuf),
}

impl Origin {
    /// What `server update` installs from this origin.
    pub(super) fn followed(&self) -> String {
        match self {
            Self::Official => "the newest official release".to_owned(),
            Self::Mirror(mirror) => format!("the newest release at {mirror}"),
            Self::Build(binary) => format!("the build at {}", binary.display()),
        }
    }
}

/// What the transaction stages below `RELEASES/<version>/`.
enum Payload {
    /// A verified release directory: its platform archive, and its client kit
    /// when the set carries one.
    Release(PathBuf),
    /// A clone build's executable and its verified client kit.
    Build { binary: PathBuf, kit: PathBuf },
}

/// A verified release, ready for the transaction.
struct Prepared {
    payload: Payload,
    /// The version directory's name.
    version: String,
    /// What `server update` follows next; `None` keeps the recorded origin.
    origin: Option<Origin>,
    /// The download, removed when the operation ends.
    _scratch: Option<Scratch>,
}

/// A temporary directory, removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Where a release or a client kit is downloaded from.
struct Fetch<'a> {
    /// A mirror; `None` is the official origin.
    origin: Option<&'a str>,
    tls_ca: Option<&'a Path>,
}

/// A server install runs only on Linux x86-64 or arm64 with
/// systemd as PID 1 (`/run/systemd/system` present, sd_booted's test), and
/// refuses on macOS and Windows before writing anything. `preflight.platform`.
pub fn platform_gate(operation: &str) -> Vec<Check> {
    judge_platform(
        std::env::consts::OS,
        std::env::consts::ARCH,
        Path::new("/run/systemd/system").is_dir(),
        operation,
    )
}

/// The pure part of [`platform_gate`].
pub fn judge_platform(os: &str, arch: &str, systemd_booted: bool, operation: &str) -> Vec<Check> {
    if os != "linux" || !matches!(arch, "x86_64" | "aarch64") {
        return vec![Check::fail(
            "preflight.platform",
            format!(
                "{operation} is refused on {os}/{arch}: a production server is Linux x86-64 or arm64, and nothing was written. macOS and Windows are client platforms"
            ),
        )];
    }
    let mut checks = vec![Check::pass("preflight.platform", format!("linux/{arch}"))];
    checks.push(if systemd_booted {
        Check::pass("preflight.systemd", "systemd is PID 1")
    } else {
        Check::fail(
            "preflight.systemd",
            "systemd is not PID 1 here (/run/systemd/system is absent), so the install is refused and nothing was written: the server runs only under systemd",
        )
    });
    checks
}

/// Create or reuse `jaynshare:jaynshare`, refusing root, an
/// interactive shell, another home or a supplementary group
/// (`preflight.service_account`). An existing account is judged by
/// [`judge_account`]; a missing one is created as a system user with
/// `/usr/sbin/nologin` and a `0700` [`SERVICE_HOME`].
pub fn service_account() -> Vec<Check> {
    if !unix::is_root() {
        return vec![Check::fail(
            "preflight.administrator",
            "run as an administrator able to create system users",
        )];
    }
    match getent_line("passwd", SERVICE_USER) {
        Err(check) => vec![check],
        Ok(None) => create_account(),
        Ok(Some(passwd)) => reuse_account(&passwd),
    }
}

/// `getent <database> <key>`'s trimmed line, `Ok(None)` when the key is
/// absent (getent's exit 2); anything else is a failed
/// `preflight.service_account` naming the call.
fn getent_line(database: &str, key: &str) -> Result<Option<String>, Check> {
    match account_tool("getent", &[database, key]) {
        Err(why) => Err(tool_check("getent", &[database, key], &why)),
        Ok(out) if out.status.success() => {
            Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_owned()))
        }
        Ok(out) if out.status.code() == Some(2) => Ok(None),
        Ok(out) => Err(tool_check(
            "getent",
            &[database, key],
            &format!("exit {}", out.status.code().unwrap_or(-1)),
        )),
    }
}

/// An account tool that could not run or exited non-zero: a failed
/// `preflight.service_account` naming it.
fn tool_check(tool: &str, args: &[&str], why: &str) -> Check {
    Check::fail(
        "preflight.service_account",
        format!("{tool} {} failed: {why}", args.join(" ")),
    )
}

/// Runs an account tool, turning a spawn failure or a non-zero exit into a
/// failed `preflight.service_account` naming it.
fn run_tool(tool: &str, args: &[&str]) -> Result<Output, Check> {
    let out = account_tool(tool, args).map_err(|why| tool_check(tool, args, &why))?;
    if out.status.success() {
        Ok(out)
    } else {
        Err(tool_check(
            tool,
            args,
            &format!("exit {}", out.status.code().unwrap_or(-1)),
        ))
    }
}

/// No account yet — the group (when absent), then the system user,
/// then [`SERVICE_HOME`] as `0700` owned `jaynshare:jaynshare`.
fn create_account() -> Vec<Check> {
    match getent_line("group", SERVICE_USER) {
        Err(check) => return vec![check],
        Ok(None) => {
            if let Err(check) = run_tool("groupadd", &["--system", SERVICE_USER]) {
                return vec![check];
            }
        }
        Ok(Some(_)) => {}
    }
    if let Err(check) = run_tool(
        "useradd",
        &[
            "--system",
            "--gid",
            SERVICE_USER,
            "--home-dir",
            SERVICE_HOME,
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            SERVICE_USER,
        ],
    ) {
        return vec![check];
    }
    match getent_line("passwd", SERVICE_USER) {
        Err(check) => vec![check],
        Ok(None) => vec![Check::fail(
            "preflight.service_account",
            format!("the created account {SERVICE_USER} is absent again"),
        )],
        Ok(Some(passwd)) => match passwd_fields(&passwd) {
            Some((uid, gid, _, _)) => match make_home(uid, gid) {
                Ok(()) => vec![Check::pass(
                    "preflight.service_account",
                    format!("created the service account {SERVICE_USER}"),
                )],
                Err(check) => vec![check],
            },
            None => vec![Check::fail(
                "preflight.service_account",
                format!("cannot read the created account's passwd entry: {passwd}"),
            )],
        },
    }
}

/// [`SERVICE_HOME`], mode `0700`, owned `jaynshare:jaynshare`.
fn make_home(uid: u32, gid: u32) -> Result<(), Check> {
    std::fs::create_dir_all(SERVICE_HOME)
        .and_then(|()| {
            std::fs::set_permissions(SERVICE_HOME, std::fs::Permissions::from_mode(0o700))
        })
        .map_err(|why| {
            Check::fail(
                "preflight.service_account",
                format!("{SERVICE_HOME}: {why}"),
            )
        })?;
    unix::chown(Path::new(SERVICE_HOME), uid, gid).map_err(|why| {
        Check::fail(
            "preflight.service_account",
            format!("{SERVICE_HOME}: chown {uid}:{gid}: {why}"),
        )
    })
}

/// An existing account is reused only when the judgement holds; the
/// checks come from [`judge_account`], and a reusable account is announced.
fn reuse_account(passwd: &str) -> Vec<Check> {
    let group_ids = match run_tool("id", &["-G", SERVICE_USER]) {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        Err(check) => return vec![check],
    };
    let primary_gid = match getent_line("group", SERVICE_USER) {
        Err(check) => return vec![check],
        Ok(None) => {
            return vec![Check::fail(
                "preflight.service_account",
                format!(
                    "the account's primary group is not the {SERVICE_USER} group, which is absent"
                ),
            )];
        }
        Ok(Some(line)) => match line.split(':').nth(2).and_then(|g| g.parse::<u32>().ok()) {
            Some(gid) => gid,
            None => {
                return vec![Check::fail(
                    "preflight.service_account",
                    format!("cannot read the {SERVICE_USER} group's gid: {line}"),
                )];
            }
        },
    };
    let mut checks = judge_account(passwd, &group_ids, primary_gid);
    if checks.iter().all(|check| check.passed) {
        checks.push(Check::pass(
            "preflight.service_account",
            format!("reusing the service account {SERVICE_USER}"),
        ));
    }
    checks
}

/// The uid, gid, home and shell of a `getent passwd` line.
fn passwd_fields(passwd: &str) -> Option<(u32, u32, &str, &str)> {
    let fields: Vec<&str> = passwd.trim_end().split(':').collect();
    if fields.len() < 7 {
        return None;
    }
    Some((
        fields[2].parse().ok()?,
        fields[3].parse().ok()?,
        fields[5],
        fields[6],
    ))
}

/// The pure account judgement: `passwd` is `getent passwd jaynshare`'s
/// line, `group_ids` the output of `id -G jaynshare`, `primary_gid` the
/// `jaynshare` group's gid. An empty result means the account is
/// reusable; every refusal is its own failed `preflight.service_account`
/// naming the rule: root, an interactive shell, a home other than
/// [`SERVICE_HOME`], a primary group other than `jaynshare`'s, or any
/// supplementary group.
fn judge_account(passwd: &str, group_ids: &str, primary_gid: u32) -> Vec<Check> {
    let Some((uid, gid, home, shell)) = passwd_fields(passwd) else {
        return vec![Check::fail(
            "preflight.service_account",
            format!("cannot read the account's passwd entry: {passwd}"),
        )];
    };
    let mut checks = Vec::new();
    if uid == 0 {
        checks.push(Check::fail(
            "preflight.service_account",
            "the service account must not be root: uid 0",
        ));
    }
    if !matches!(
        shell,
        "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false" | "/usr/bin/false"
    ) {
        checks.push(Check::fail(
            "preflight.service_account",
            format!("an interactive shell {shell} is refused: the service account must not be able to log in"),
        ));
    }
    if home != SERVICE_HOME {
        checks.push(Check::fail(
            "preflight.service_account",
            format!("a home other than {SERVICE_HOME}: {home}"),
        ));
    }
    if gid != primary_gid {
        checks.push(Check::fail(
            "preflight.service_account",
            format!(
                "a primary group other than the {SERVICE_USER} group (gid {primary_gid}): gid {gid}"
            ),
        ));
    }
    if group_ids.split_whitespace().count() > 1 {
        checks.push(Check::fail(
            "preflight.service_account",
            format!(
                "membership in a supplementary group is refused (id -G lists {group_ids}, more than the primary gid {gid})"
            ),
        ));
    }
    checks
}

/// `server install`, in this order; each step's checks go
/// into the result and the first failing step ends it:
/// 1. [`platform_gate`], and no build while auto-update is on;
/// 2. [`prepare`] — nothing of the release runs before it verifies;
/// 3. on an installed server, no downgrade: running install again updates;
/// 4. [`service_account`] — create or reuse `jaynshare`;
/// 5. the configuration: `--config`, else the installed one, else
///    [`generate_configuration`];
/// 6. `preflight::run` against it — binds nothing;
/// 7. [`transaction`] — stage, select, reload, start, check, and roll back
///    after selection;
/// 8. the origin `server update` follows next.
pub fn install(inputs: &InstallInputs<'_>) -> DeployResult {
    let mut result = DeployResult::new("server install");
    if !gated(&mut result, platform_gate("server install")) {
        return result;
    }
    if matches!(inputs.source, Source::Build { .. }) && super::auto_update::is_on() {
        result.checks.push(Check::fail(
            "conflict.auto_update",
            "auto-update follows releases only; run server auto-update off before installing a build",
        ));
        return result;
    }
    let recorded = recorded_origin();
    let fetch = Fetch {
        origin: fetch_origin(inputs.release_origin, recorded.as_ref()),
        tls_ca: inputs.tls_ca,
    };
    let Some(prepared) = prepare(&inputs.source, &fetch, &mut result) else {
        return result;
    };
    if let Some(check) = downgrade(&prepared.version) {
        result.checks.push(check);
        return result;
    }
    if !gated(&mut result, service_account()) {
        return result;
    }
    let service_config = service_config_path();
    let generated = match (inputs.config, service_config.exists(), inputs.listen) {
        (None, false, listen) => match generate_configuration(listen, inputs.ask) {
            Ok((scratch, check)) => {
                result.checks.push(check);
                Some(scratch)
            }
            Err(check) => {
                result.checks.push(check);
                return result;
            }
        },
        (_, _, Some(_)) => {
            result.checks.push(Check::fail(
                "configuration.listen",
                "--listen applies only when install writes the configuration, and one is already given or installed",
            ));
            return result;
        }
        _ => None,
    };
    let supplied = inputs.config.map(Path::to_path_buf).or_else(|| {
        generated
            .as_ref()
            .map(|scratch| scratch.0.join("config.toml"))
    });
    let checked = supplied.clone().unwrap_or(service_config);
    let record = (inputs.firewall_record)(&checked);
    let preflight = super::preflight::run(&super::preflight::Inputs {
        from: None,
        config: Some(&checked),
        unknown_firewall: super::preflight::UnknownFirewall::recorded(record.as_deref()),
    });
    if !gated(&mut result, preflight.checks) {
        return result;
    }
    transaction(&prepared.payload, supplied.as_deref(), &mut result);
    record_origin(&prepared, &mut result);
    result
}

/// Reads, fetches or builds `source` and verifies it; a failure lands in
/// `result` and the answer is `None`. Nothing is written but a scratch
/// directory.
fn prepare(source: &Source<'_>, fetch: &Fetch<'_>, result: &mut DeployResult) -> Option<Prepared> {
    if !matches!(source, Source::Directory(_)) && !unix::is_root() {
        result.checks.push(Check::fail(
            "preflight.administrator",
            format!("run as an administrator able to stage a release below {RELEASES}"),
        ));
        return None;
    }
    match source {
        Source::Directory(dir) => verified_release(dir.to_path_buf(), None, None, result),
        Source::Published(version) => {
            let (dir, scratch) = fetch_release(*version, fetch, result)?;
            let origin = fetch
                .origin
                .map_or(Origin::Official, |mirror| Origin::Mirror(mirror.to_owned()));
            verified_release(dir, Some(scratch), Some(origin), result)
        }
        Source::Build { binary, kit } => prepare_build(binary, *kit, fetch, result),
    }
}

/// The release at `dir` once `release::verify` passes.
fn verified_release(
    dir: PathBuf,
    scratch: Option<Scratch>,
    origin: Option<Origin>,
    result: &mut DeployResult,
) -> Option<Prepared> {
    let verified = super::release::verify(&dir, None);
    result.version = verified.version.clone();
    result.commit = verified.commit.clone();
    if !gated(result, verified.checks) {
        return None;
    }
    Some(Prepared {
        payload: Payload::Release(dir),
        version: verified
            .version
            .expect("a verified release names a version"),
        origin,
        _scratch: scratch,
    })
}

/// `version`, the origin's newest when `None`, fetched into a root-owned
/// scratch directory below [`RELEASES`].
fn fetch_release(
    version: Option<&str>,
    fetch: &Fetch<'_>,
    result: &mut DeployResult,
) -> Option<(PathBuf, Scratch)> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let version = match version {
        Some(version) => version.to_owned(),
        None => {
            match runtime.block_on(super::release::newest_version(fetch.origin, fetch.tls_ca)) {
                Ok(version) => version,
                Err(why) => {
                    result.checks.push(Check::fail("release.unreachable", why));
                    return None;
                }
            }
        }
    };
    // Created as the stage creates it, so the fetch's private directory
    // below it is the only one narrowed to 0700.
    if let Err(why) = std::fs::create_dir_all(RELEASES) {
        result
            .checks
            .push(Check::fail("release.out", format!("{RELEASES}: {why}")));
        return None;
    }
    let out = Path::new(RELEASES).join(format!(".fetch-{version}-{}", std::process::id()));
    let scratch = Scratch(out.clone());
    let fetched = runtime.block_on(super::release::fetch(
        &version,
        &out,
        None,
        fetch.origin,
        fetch.tls_ca,
    ));
    if fetched.failed().is_some() {
        result.checks.extend(fetched.checks);
        return None;
    }
    Some((out, scratch))
}

/// A clone's build: its version and digest name the version directory
/// (`<version>+local.<digest>`), and its client kit — `kit`, else the
/// official kit of that version — verifies under the active release key.
fn prepare_build(
    binary: &Path,
    kit: Option<&Path>,
    fetch: &Fetch<'_>,
    result: &mut DeployResult,
) -> Option<Prepared> {
    let identity = std::fs::canonicalize(binary)
        .map_err(|why| format!("{}: {why}", binary.display()))
        .and_then(|binary| {
            let (version, commit) = build_identity(&binary)?;
            let bytes =
                std::fs::read(&binary).map_err(|why| format!("{}: {why}", binary.display()))?;
            Ok((binary, version, commit, crate::bundle::sha256_hex(&bytes)))
        });
    let (binary, version, commit, digest) = match identity {
        Ok(identity) => identity,
        Err(why) => {
            result.checks.push(Check::fail("release.binary", why));
            return None;
        }
    };
    let name = format!("{version}+local.{}", &digest[..12]);
    result.version = Some(name.clone());
    result.commit = Some(commit);
    result.checks.push(Check::pass(
        "release.binary",
        format!("{} is jaynshare {version}", binary.display()),
    ));
    let (kit, scratch, kit_version) = match verified_kit(kit, &version, fetch) {
        Ok(verified) => verified,
        Err(why) => {
            result.checks.push(Check::fail("release.kit", why));
            return None;
        }
    };
    result.checks.push(Check::pass(
        "release.kit",
        format!("the client kit {kit_version} verifies under the active release key"),
    ));
    Some(Prepared {
        payload: Payload::Build {
            binary: binary.clone(),
            kit,
        },
        version: name,
        origin: Some(Origin::Build(binary)),
        _scratch: scratch,
    })
}

/// A build's client kit — `kit`, else the official kit of `version`,
/// downloaded to a scratch directory — once it verifies under the active
/// release key; with the kit's own version.
fn verified_kit(
    kit: Option<&Path>,
    version: &str,
    fetch: &Fetch<'_>,
) -> Result<(PathBuf, Option<Scratch>, String), String> {
    let (kit, scratch) = match kit {
        Some(kit) => (kit.to_path_buf(), None),
        None => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let path = runtime
                .block_on(super::release::fetch_client_kit(
                    version,
                    fetch.origin,
                    fetch.tls_ca,
                ))
                .map_err(|why| {
                    format!("the official client kit of {version}: {why}; pass --kit <zip>")
                })?;
            let scratch = path.parent().map(|dir| Scratch(dir.to_path_buf()));
            (path, scratch)
        }
    };
    let verified = super::release::active_key()
        .and_then(|key| crate::bundle::verify_kit_zip(&kit, &key))
        .map_err(|why| format!("{}: {why}", kit.display()))?;
    Ok((kit, scratch, verified.version))
}

/// `<binary> --version --json`'s version and commit; the version must be
/// a plain one, as it names a directory.
fn build_identity(binary: &Path) -> Result<(String, String), String> {
    let unanswered = || format!("{} --version answered no version", binary.display());
    let output = std::process::Command::new(binary)
        .args(["--version", "--json"])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|why| format!("{}: {why}", binary.display()))?;
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|_| unanswered())?;
    let field = |key: &str| envelope["result"][key].as_str().map(str::to_owned);
    match (field("version"), field("commit")) {
        (Some(version), Some(commit)) if output.status.success() && plain_version(&version) => {
            Ok((version, commit))
        }
        _ => Err(unanswered()),
    }
}

/// A version that is safe as a directory name: SemVer's characters only.
fn plain_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// The origin to fetch from: `explicit`, else the recorded mirror, else the
/// official one (`None`).
fn fetch_origin<'a>(explicit: Option<&'a str>, recorded: Option<&'a Origin>) -> Option<&'a str> {
    explicit.or(match recorded {
        Some(Origin::Mirror(mirror)) => Some(mirror.as_str()),
        _ => None,
    })
}

/// The recorded origin; `None` when there is no record or it does not parse.
pub(super) fn recorded_origin() -> Option<Origin> {
    serde_json::from_slice(&std::fs::read(ORIGIN_RECORD).ok()?).ok()
}

/// After a successful transaction, the origin `server update` follows next.
fn record_origin(prepared: &Prepared, result: &mut DeployResult) {
    let Some(origin) = &prepared.origin else {
        return;
    };
    if result.failed().is_some() || result.rolled_back {
        return;
    }
    let bytes = serde_json::to_vec(origin).expect("an origin serializes");
    result.checks.push(
        match write_private_bytes(Path::new(ORIGIN_RECORD), &bytes, 0o644) {
            Ok(()) => Check::pass(
                "manager.origin",
                format!("server update follows {}", origin.followed()),
            ),
            Err(why) => Check::fail("manager.origin", format!("{ORIGIN_RECORD}: {why}")),
        },
    );
}

/// The refusal of `version` when it is lower than the installed release.
fn downgrade(version: &str) -> Option<Check> {
    let current = file_name(&std::fs::read_link(CURRENT).ok()?);
    (semver_precedence(version, &current) == std::cmp::Ordering::Less).then(|| {
        Check::fail(
            "conflict.downgrade",
            format!(
                "{version} is lower than the installed {current}; a downgrade needs server update --allow-downgrade"
            ),
        )
    })
}

/// A configuration for this host when there is none: the data plane on
/// `listen`, else on the detected address, else on the one the operator
/// types; every other key takes its default, the proxy listener included.
/// It is written to a private scratch file, which the transaction copies.
fn generate_configuration(
    listen: Option<IpAddr>,
    ask: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(Scratch, Check), Check> {
    let (ip, how) = match listen {
        Some(ip) => (ip, "given by --listen".to_owned()),
        None => match super::address::detect_listen() {
            Detected::One(ip, how) => (ip, how),
            Detected::Choose(candidates) => ask_listen(&candidates, ask)?,
        },
    };
    let port = crate::config::DEFAULT_LISTEN
        .parse::<SocketAddr>()
        .expect("the default listener parses")
        .port();
    let listen = SocketAddr::new(ip, port);
    let dir = std::env::temp_dir().join(format!("jaynshare-install-{}", std::process::id()));
    let scratch = Scratch(dir.clone());
    let path = dir.join("config.toml");
    crate::state::ensure_private_dir(&dir)
        .and_then(|()| crate::state::open_private(&path))
        .and_then(|mut file| {
            use std::io::Write as _;
            file.write_all(configuration_text(listen, &how).as_bytes())
        })
        .map_err(|why| {
            Check::fail(
                "configuration.generated",
                format!("{}: {why}", path.display()),
            )
        })?;
    Ok((
        scratch,
        Check::pass(
            "configuration.generated",
            format!("the data plane listens on {listen} ({how})"),
        ),
    ))
}

/// The address the operator types when detection found no single one;
/// refused without a terminal.
fn ask_listen(
    candidates: &[(String, IpAddr)],
    ask: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(IpAddr, String), Check> {
    let found = match candidates {
        [] => "none".to_owned(),
        _ => candidates
            .iter()
            .map(|(interface, ip)| format!("{ip} on {interface}"))
            .collect::<Vec<_>>()
            .join(", "),
    };
    let refused = |why: String| {
        Check::fail(
            "configuration.listen",
            format!(
                "no single private address to listen on (found: {found}){why}; pass --listen <ip> or --config <path>"
            ),
        )
    };
    let line = ask(&format!(
        "No single private IPv4 address to listen on (found: {found}).\nListen on: "
    ))
    .map_err(|_| refused(String::new()))?;
    line.parse()
        .map(|ip| (ip, "typed at install".to_owned()))
        .map_err(|_| refused(format!(", and {line:?} is not an address")))
}

/// The generated document: the data-plane address, its TLS on the server
/// identity, and the service's state file named outright, so root reading
/// this configuration finds the identity key the service wrote.
fn configuration_text(listen: SocketAddr, how: &str) -> String {
    let state_file = state_root().join("state.json").display().to_string();
    format!(
        "# Written by `jaynshare server install`. Listener address: {how}.\n\
         version = 1\n\n[data_plane]\nlisten = \"{listen}\"\ntls = \"identity\"\n\n\
         [storage]\nstate_file = {state_file:?}\n"
    )
}

/// Appends `checks` to `result`; `true` when every one passed.
pub(super) fn gated(result: &mut DeployResult, checks: Vec<Check>) -> bool {
    let passed = checks.iter().all(|check| check.passed);
    result.checks.extend(checks);
    passed
}

/// After the release verified and preflight passed: stage the
/// payload's files below `RELEASES/<version>/` (root-owned, not
/// writable by the service user; the executable at
/// `RELEASES/<version>/jaynshare`), copy a supplied configuration atomically
/// as `0600` owned by the service user without overwriting one,
/// write the unit (`systemd::unit_text`), atomically replace [`CURRENT`] and
/// [`COMMAND_LINK`], `daemon-reload`, enable and start or restart the unit,
/// and complete the loopback status read within 30 s. A failure after
/// selection calls [`rollback`].
fn transaction(payload: &Payload, supplied_config: Option<&Path>, result: &mut DeployResult) {
    let Some(version) = result.version.clone() else {
        result.checks.push(Check::fail(
            "release.version",
            "no verified version reached the transaction",
        ));
        return;
    };
    let target = super::release::native_target();

    // 1. Stage: the payload's files below RELEASES/<version>/.
    let staged = stage(payload, &version, target, result);
    if !staged {
        return;
    }
    let version_dir = format!("{RELEASES}/{version}");

    // 2. Configuration: a supplied file (the operator's or the generated
    //    one) is copied atomically as 0600 owned by the service user; an
    //    existing one must be identical.
    let service_config = service_config_path();

    // Everything the transaction may have to undo, recorded before
    // anything changes: the previous selection, command link and unit-file
    // bytes, the running state, and whether the service's configuration
    // predates this transaction (a supplied `--config` may be copied below).
    let mut prior = Prior {
        current: std::fs::read_link(CURRENT).ok(),
        command: std::fs::read_link(COMMAND_LINK).ok(),
        unit: std::fs::read(super::systemd::UNIT_PATH).ok(),
        was_active: super::systemd::state() == super::systemd::ServiceState::Running,
        config_existed: service_config.exists(),
        state_dir: None,
        snapshot: None,
    };
    let supplied = match supplied_config {
        Some(config) => match std::fs::read(config) {
            Ok(bytes) => Some(bytes),
            Err(why) => {
                result.checks.push(Check::fail(
                    "configuration.copied",
                    format!("{}: {why}", config.display()),
                ));
                return;
            }
        },
        None => None,
    };
    // An update supplies no configuration: the installed one stays exactly
    // as it is, byte-for-byte. An install still needs one.
    if supplied.is_none() && service_config.exists() {
        result.checks.push(Check::pass(
            "configuration.present",
            format!(
                "{} stays as it is; an update never rewrites the configuration",
                service_config.display()
            ),
        ));
    } else {
        let config_step = select_configuration(
            supplied.as_deref(),
            std::fs::read(&service_config).ok().as_deref(),
        );
        result.checks.push(match config_step {
        ConfigDecision::Copy => copy_configuration(
            supplied_config.expect("a Copy decision has a source"),
            &service_config,
        ),
        ConfigDecision::Keep => Check::pass(
            "configuration.present",
            format!(
                "{} already holds identical bytes; not overwritten",
                service_config.display()
            ),
        ),
        ConfigDecision::Conflict => Check::fail(
            "conflict.configuration",
            format!(
                "{} differs from the supplied {}; the existing configuration is never overwritten",
                service_config.display(),
                supplied_config.expect("a Conflict decision has a source").display()
            ),
        ),
        ConfigDecision::Missing => Check::fail(
            "configuration.missing",
            "the service has no configuration: server install writes one, or supply --config <path>",
        ),
    });
        if !result.checks.iter().all(|check| check.passed) {
            return;
        }
    }

    // 3. Unit: the unit text; the previous file's bytes and the running
    //    state are already in `prior`. A supplied `--config` was copied to
    //    the service's own path above, so the
    //    unit names no override: pointing at the operator's source would
    //    hand the service a file it may not read and bypass the copy.
    let unit_text = super::systemd::unit_text(None);
    if let Err(why) = write_private_bytes(
        Path::new(super::systemd::UNIT_PATH),
        unit_text.as_bytes(),
        0o644,
    ) {
        result.checks.push(Check::fail(
            "manager.unit",
            format!("{}: {why}", super::systemd::UNIT_PATH),
        ));
        return;
    }
    result.checks.push(Check::pass(
        "manager.unit",
        format!("wrote {}", super::systemd::UNIT_PATH),
    ));

    // 4. Select: both links replaced atomically, root first.
    for (link, target_path) in [
        (CURRENT, format!("{RELEASES}/{version}")),
        (COMMAND_LINK, format!("{CURRENT}/jaynshare")),
    ] {
        if let Err(why) = atomically_replace_link(link, &target_path) {
            result.checks.push(Check::fail(
                "manager.select",
                format!("{link} -> {target_path}: {why}"),
            ));
            rollback(result, &prior);
            return;
        }
        result.paths.push(link.to_owned());
    }
    result
        .checks
        .push(Check::pass("manager.select", format!("selected {version}")));

    // 5. Snapshot: the service's state root, each file's mode and
    //    owner preserved, before the new release may run; the snapshot is
    //    removed after a successful transaction. A failure here cannot be
    //    undone safely, so the selection rolls back and the transaction ends.
    match snapshot_state() {
        Ok((snapshot, state_dir)) => {
            prior.snapshot = Some(snapshot);
            prior.state_dir = state_dir;
        }
        Err(why) => {
            result.checks.push(Check::fail(
                "manager.snapshot",
                format!("the state root cannot be snapshotted: {why}"),
            ));
            rollback(result, &prior);
            return;
        }
    }

    // 6. Manager: reload, enable, then restart or start.
    for step in [
        vec!["daemon-reload"],
        vec!["enable", super::systemd::UNIT_NAME],
        if prior.was_active {
            vec!["restart", super::systemd::UNIT_NAME]
        } else {
            vec!["start", super::systemd::UNIT_NAME]
        },
    ] {
        let name = format!("manager.{}", step[0]);
        match super::systemd::systemctl(&step) {
            Ok(output) if output.status.success() => result
                .checks
                .push(Check::pass(&name, format!("systemctl {}", step.join(" ")))),
            Ok(output) => {
                let first = String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .next()
                    .unwrap_or("no error output")
                    .to_owned();
                result.checks.push(Check::fail(
                    &name,
                    format!("systemctl {}: {first}", step.join(" ")),
                ));
                rollback(result, &prior);
                return;
            }
            Err(why) => {
                result.checks.push(Check::fail(
                    &name,
                    format!("systemctl {}: {why}", step.join(" ")),
                ));
                rollback(result, &prior);
                return;
            }
        }
    }

    // 7. Status: the loopback operator status read within
    //    30 s, through the newly linked executable.
    match status_check(&service_config) {
        Ok(elapsed) => result.checks.push(Check::pass(
            "manager.status",
            format!("the installed server answers status within {elapsed:.1} s"),
        )),
        Err((elapsed, code)) => {
            result.checks.push(Check::fail(
                "manager.status",
                format!(
                    "status --check exited {code} after {elapsed:.1} s, within the 30 s deadline"
                ),
            ));
            rollback(result, &prior);
            return;
        }
    }

    // 8. Record the installed paths; the snapshot is no longer needed.
    if let Some(snapshot) = prior.snapshot.take() {
        let _ = std::fs::remove_dir_all(&snapshot);
    }
    result.paths.push(version_dir);
    result.paths.push(service_config.display().to_string());
    result.paths.push(super::systemd::UNIT_PATH.to_owned());
}

/// The service's own configuration file: the Linux default path with
/// `HOME` fixed to [`SERVICE_HOME`].
pub fn service_config_path() -> std::path::PathBuf {
    std::path::PathBuf::from(SERVICE_HOME)
        .join(".config")
        .join("jaynshare")
        .join("config.toml")
}

/// The pure half of staging: `entry` is the archive member's path; the root
/// directory, the four regular files, everything else is refused.
fn judge_archive_entry(entry: &str, root: &str) -> ArchiveEntry {
    if entry == format!("{root}/") || entry == root {
        return ArchiveEntry::Root;
    }
    let Some(rest) = entry.strip_prefix(&format!("{root}/")) else {
        return ArchiveEntry::Refuse;
    };
    match rest {
        "jaynshare" | "LICENSE" | "NOTICE.md" | "README.txt" => ArchiveEntry::File,
        _ => ArchiveEntry::Refuse,
    }
}

/// The archive members [`judge_archive_entry`] admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveEntry {
    Root,
    File,
    Refuse,
}

/// The stage: [`fill_staging`] into `.staging-<version>-<pid>`, set root's
/// modes, then reuse, refuse or install the version directory. `false` when
/// the result now holds the failure.
fn stage(payload: &Payload, version: &str, target: &str, result: &mut DeployResult) -> bool {
    let staging_root = Path::new("/opt/jaynshare");
    let staging = staging_root.join(format!(
        "releases/.staging-{version}-{}",
        std::process::id()
    ));
    let cleanup = || {
        let _ = std::fs::remove_dir_all(&staging);
    };
    let with_kit = match fill_staging(payload, version, target, &staging) {
        Ok(with_kit) => with_kit,
        Err(why) => {
            cleanup();
            result.checks.push(why);
            return false;
        }
    };
    // Root owns the tree, the executable 0755, everything else 0644.
    for (name, _) in tree_files(&staging).unwrap_or_default() {
        let path = staging.join(&name);
        let mode = if name == "jaynshare" { 0o755 } else { 0o644 };
        if let Err(why) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .map_err(|why| format!("{}: {why}", path.display()))
            .and_then(|()| {
                unix::chown(&path, 0, 0)
                    .map_err(|why| format!("{}: chown root: {why}", path.display()))
            })
        {
            cleanup();
            result.checks.push(Check::fail("release.archive", why));
            return false;
        }
    }
    // The version directory: identical bytes are reused, different bytes are
    // a conflict, absence installs the staging.
    let version_dir = staging_root.join(format!("releases/{version}"));
    match std::fs::read_dir(&version_dir) {
        Ok(_) => {
            let same = tree_files(&staging) == tree_files(&version_dir);
            cleanup();
            if !same {
                result.checks.push(Check::fail(
                    "conflict.release",
                    format!(
                        "{} already holds different bytes for {version}; remove it or choose another",
                        version_dir.display()
                    ),
                ));
                return false;
            }
            result.checks.push(Check::pass(
                "release.archive",
                format!(
                    "{} already holds identical bytes for {version}; reused",
                    version_dir.display()
                ),
            ));
            return true;
        }
        Err(_) if !version_dir.exists() => {}
        Err(why) => {
            cleanup();
            result.checks.push(Check::fail(
                "conflict.release",
                format!("{}: {why}", version_dir.display()),
            ));
            return false;
        }
    }
    if let Err(why) = std::fs::rename(&staging, &version_dir) {
        cleanup();
        result.checks.push(Check::fail(
            "release.archive",
            format!("{}: {why}", version_dir.display()),
        ));
        return false;
    }
    result.checks.push(Check::pass(
        "release.archive",
        if with_kit {
            format!("staged {version} below {RELEASES} root-owned, with its client kit")
        } else {
            format!(
                "staged {version} below {RELEASES} root-owned; the release set carries no client kit, so clients cannot follow this server"
            )
        },
    ));
    true
}

/// The version directory's files into `staging`: the platform archive's
/// four or the build's executable, then the client kit as [`KIT_FILE`] when
/// there is one. `Ok(whether the kit is there)`.
fn fill_staging(
    payload: &Payload,
    version: &str,
    target: &str,
    staging: &Path,
) -> Result<bool, Check> {
    let copy = |from: &Path, name: &str| {
        std::fs::create_dir_all(staging)
            .and_then(|()| std::fs::copy(from, staging.join(name)))
            .map(|_| ())
            .map_err(|why| Check::fail("release.archive", format!("{}: {why}", from.display())))
    };
    let kit = match payload {
        Payload::Release(from) => {
            let archive_path = from.join(format!("jaynshare-{version}-{target}.tar.gz"));
            let bytes = std::fs::read(&archive_path).map_err(|why| {
                Check::fail(
                    "release.archive",
                    format!("{}: {why}", archive_path.display()),
                )
            })?;
            extract_archive(&bytes, &format!("jaynshare-{version}-{target}"), staging)?;
            Some(from.join(format!("jaynshare-{version}-client-kit.zip")))
                .filter(|kit| kit.is_file())
        }
        Payload::Build { binary, kit } => {
            copy(binary, "jaynshare")?;
            Some(kit.clone())
        }
    };
    match kit {
        Some(kit) => copy(&kit, KIT_FILE).map(|()| true),
        None => Ok(false),
    }
}

/// A directory's regular files as `(name, bytes)`, sorted by name; `None`
/// when one cannot be read.
fn tree_files(dir: &Path) -> Option<Vec<(String, Vec<u8>)>> {
    let mut files = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            std::fs::read(entry.path()).map(|bytes| (name, bytes))
        })
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    files.sort();
    Some(files)
}

/// The platform archive's members into `staging`: only the root directory
/// and the four regular files; everything else is a failed
/// `release.archive` naming the entry.
fn extract_archive(bytes: &[u8], root: &str, staging: &Path) -> Result<(), Check> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(false);
    let mut entries = archive.entries().map_err(|why| {
        Check::fail(
            "release.archive",
            format!("the archive cannot be read: {why}"),
        )
    })?;
    let mut saw_root = false;
    for entry in entries.by_ref() {
        let mut entry = entry.map_err(|why| {
            Check::fail("release.archive", format!("an entry cannot be read: {why}"))
        })?;
        let path = entry
            .path()
            .map_err(|why| {
                Check::fail(
                    "release.archive",
                    format!("an entry name cannot be read: {why}"),
                )
            })?
            .into_owned();
        let name = path.to_string_lossy().into_owned();
        match judge_archive_entry(&name, root) {
            ArchiveEntry::Root => saw_root = true,
            ArchiveEntry::File => {
                // A member under the root roots the archive; the directory
                // entry itself is optional: only the members are named.
                saw_root = true;
                let bytes = read_entry_bytes(&mut entry)
                    .map_err(|e| Check::fail("release.archive", format!("{name}: {e}")))?;
                let out = staging.join(path.strip_prefix(root).unwrap_or(&path));
                std::fs::create_dir_all(out.parent().unwrap_or(staging)).map_err(|why| {
                    Check::fail("release.archive", format!("{}: {why}", out.display()))
                })?;
                std::fs::write(&out, &bytes).map_err(|why| {
                    Check::fail("release.archive", format!("{}: {why}", out.display()))
                })?;
            }
            ArchiveEntry::Refuse => {
                return Err(Check::fail(
                    "release.archive",
                    format!(
                        "the archive holds an unexpected entry {name:?}: only {root}/ with jaynshare, LICENSE, NOTICE.md and README.txt is accepted"
                    ),
                ));
            }
        }
    }
    if !saw_root {
        return Err(Check::fail(
            "release.archive",
            format!("the archive is not rooted at {root}/"),
        ));
    }
    Ok(())
}

/// One tar entry's whole content.
fn read_entry_bytes<R: std::io::Read>(entry: &mut tar::Entry<'_, R>) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The configuration decision: copy a
/// new supplied file, keep identical bytes, refuse different ones, and
/// refuse to synthesize. `supplied` is the `--config` file's bytes, `there`
/// the service path's.
fn select_configuration(supplied: Option<&[u8]>, there: Option<&[u8]>) -> ConfigDecision {
    match (supplied, there) {
        (Some(supplied), Some(there)) if supplied == there => ConfigDecision::Keep,
        (Some(_), Some(_)) => ConfigDecision::Conflict,
        (Some(_), None) => ConfigDecision::Copy,
        (None, _) => ConfigDecision::Missing,
    }
}

/// The configuration decision, as [`select_configuration`] returns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigDecision {
    Copy,
    Keep,
    Conflict,
    Missing,
}

/// The atomic copy: a 0600 temporary in the target's directory, chowned
/// to the service user, fsynced, hard-linked onto the target (which fails if
/// it exists), the temporary removed, the directories 0700 and owned.
fn copy_configuration(source: &Path, target: &Path) -> Check {
    let ids = service_uid_gid();
    let pass = |what: &str| {
        Check::pass(
            "configuration.copied",
            format!(
                "{what} {} as 0600 owned by {SERVICE_USER}",
                target.display()
            ),
        )
    };
    let fail = |why: String| {
        Check::fail(
            "configuration.copied",
            format!("{}: {why}", target.display()),
        )
    };
    let dir = match target.parent() {
        Some(dir) => dir.to_path_buf(),
        None => return fail("no parent directory".into()),
    };
    // The directories 0700, owned by the service user.
    for d in [dir.parent().map(|p| p.to_path_buf()), Some(dir.clone())]
        .into_iter()
        .flatten()
    {
        if let Err(why) = std::fs::create_dir_all(&d)
            .and_then(|()| std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)))
        {
            return fail(format!("{}: {why}", d.display()));
        }
        if let Some(ids) = ids.as_ref() {
            let _ = chown_path(&d, ids.0, ids.1);
        }
    }
    let bytes = match std::fs::read(source) {
        Ok(bytes) => bytes,
        Err(why) => return fail(format!("{}: {why}", source.display())),
    };
    let temporary = dir.join(format!(".config.toml.new-{}", std::process::id()));
    let done = (|| -> Result<(), String> {
        use std::io::Write;
        let mut file = std::fs::File::create(&temporary)
            .map_err(|why| format!("{}: {why}", temporary.display()))?;
        file.write_all(&bytes)
            .map_err(|why| format!("{}: {why}", temporary.display()))?;
        file.sync_all()
            .map_err(|why| format!("{}: fsync {why}", temporary.display()))?;
        drop(file);
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|why| format!("{}: chmod {why}", temporary.display()))?;
        if let Some((uid, gid)) = ids {
            chown_path(&temporary, uid, gid)
                .map_err(|why| format!("{}: chown {why}", temporary.display()))?;
        }
        // Fails when the target exists, so nothing is overwritten.
        std::fs::hard_link(&temporary, target)
            .map_err(|why| format!("{}: link {why}", target.display()))?;
        let _ = std::fs::remove_file(&temporary);
        Ok(())
    })();
    let _ = std::fs::remove_file(&temporary);
    match done {
        Ok(()) => pass("copied"),
        Err(why) => fail(why),
    }
}

/// The service user's uid and gid (`getent passwd` through [`account_tool`]).
pub(super) fn service_uid_gid() -> Option<(u32, u32)> {
    let passwd = getent_line("passwd", SERVICE_USER).ok()??;
    passwd_fields(&passwd).map(|(uid, gid, _, _)| (uid, gid))
}

/// `chown(2)` by path; the error as text.
fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    unix::chown(path, uid, gid).map_err(|why| why.to_string())
}

/// Atomically: `path`'s bytes by temporary file in the same directory, then
/// rename over it (the unit, 0644 root).
fn write_private_bytes(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = dir.join(format!(".{}.new-{}", file_name(path), std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    };
    let outcome = write();
    let _ = std::fs::remove_file(&temporary);
    outcome
}

/// A path's final component as text ("" when it has none).
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Atomically: the link `path` -> `target` as `.new-<pid>`, then rename over
/// `path` (symlink is created fresh, rename is atomic).
fn atomically_replace_link(path: &str, target: &str) -> Result<(), String> {
    let parent = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(
        ".{}.new-{}",
        file_name(Path::new(path)),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&temporary);
    unix::symlink(target, &temporary).map_err(|why| format!("link {why}"))?;
    std::fs::rename(&temporary, path).map_err(|why| format!("rename {why}"))
}

/// The loopback status read: the newly linked executable with the
/// service's own configuration, every 500 ms up to 30 s; `Ok(the elapsed
/// seconds)` on exit 0, `Err((seconds, last exit code))` otherwise.
fn status_check(config: &Path) -> Result<f64, (f64, i32)> {
    use std::time::Instant;
    let started = Instant::now();
    let mut last_code;
    loop {
        let executable = format!("{CURRENT}/jaynshare");
        let output = std::process::Command::new(&executable)
            .args([
                "--config",
                &config.display().to_string(),
                "status",
                "--check",
            ])
            .stdin(std::process::Stdio::null())
            .output();
        let elapsed = started.elapsed().as_secs_f64();
        match output {
            Ok(output) if output.status.success() => return Ok(elapsed),
            Ok(output) => last_code = output.status.code().unwrap_or(-1),
            Err(_) => last_code = -1,
        }
        if elapsed >= 30.0 {
            return Err((elapsed, last_code));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// What [`transaction`] records before it changes anything, for [`rollback`].
pub struct Prior {
    /// [`CURRENT`]'s target before selection (`None`: no previous install).
    pub current: Option<std::path::PathBuf>,
    /// [`COMMAND_LINK`]'s target before selection.
    pub command: Option<std::path::PathBuf>,
    /// The unit file's previous bytes (`None`: no unit file yet).
    pub unit: Option<Vec<u8>>,
    /// Whether the unit was running before the transaction.
    pub was_active: bool,
    /// Whether the service's configuration predates the transaction: one
    /// copied by this transaction is removed on rollback, one that existed
    /// before is never touched.
    pub config_existed: bool,
    /// The state root's own [`StateDir`] before the transaction.
    pub state_dir: StateDir,
    /// The state-root snapshot's path, when it was taken.
    pub snapshot: Option<std::path::PathBuf>,
}

/// The state root's own `(mode, uid, gid)`.
type StateDir = Option<(u32, u32, u32)>;

/// The service's own state directory: the Linux default path with HOME
/// fixed to [`SERVICE_HOME`].
fn state_root() -> std::path::PathBuf {
    std::path::PathBuf::from(SERVICE_HOME)
        .join(".local")
        .join("state")
        .join("jaynshare")
}

/// The rollback step plan, pure: every step is tried, in this order, and one
/// failed step never stops the rest. A configuration copied by the
/// transaction is removed; one that existed before is never touched. A
/// stopped unit stays stopped: no `start`, no status check.
fn rollback_steps(was_active: bool, config_copied: bool) -> Vec<&'static str> {
    let mut steps = vec!["stop", "links", "unit", "state"];
    if config_copied {
        steps.push("configuration");
    }
    if was_active {
        steps.push("start");
        steps.push("status");
    }
    steps
}

/// After a failed step past selection, the previous release and
/// service state back, configuration and state byte-for-byte; the result's
/// `rolled_back` and one `manager.rollback` check say whether it worked,
/// and a failed rollback keeps the snapshot for the operator.
pub fn rollback(result: &mut DeployResult, prior: &Prior) {
    result.rolled_back = true;
    let mut failed: Vec<String> = Vec::new();
    for step in rollback_steps(prior.was_active, !prior.config_existed) {
        let outcome = match step {
            "stop" => systemctl_ok(&["stop", super::systemd::UNIT_NAME]),
            "links" => restore_links(prior),
            "unit" => restore_unit(prior),
            "state" => restore_state(prior),
            "configuration" => restore_configuration(),
            "start" => systemctl_ok(&["start", super::systemd::UNIT_NAME]),
            "status" => {
                status_check(&service_config_path())
                    .map(|_| ())
                    .map_err(|(elapsed, code)| {
                        format!("status --check exited {code} after {elapsed:.1} s")
                    })
            }
            other => unreachable!("the plan names its own steps, not {other}"),
        };
        if let Err(why) = outcome {
            failed.push(format!("{step}: {why}"));
        }
    }
    match failed.is_empty() {
        true => {
            if let Some(snapshot) = &prior.snapshot {
                let _ = std::fs::remove_dir_all(snapshot);
            }
            result.checks.push(Check::pass(
                "manager.rollback",
                match &prior.current {
                    Some(previous) => {
                        format!("restored {} and its service state", previous.display())
                    }
                    None => "restored the state before the first install: the selection, unit and copied configuration are gone, and the service state is as it was".to_owned(),
                },
            ));
        }
        false => {
            let why = failed.join("; ");
            if let Some(snapshot) = &prior.snapshot {
                result.paths.push(snapshot.display().to_string());
                result.checks.push(Check::fail(
                    "manager.rollback",
                    format!(
                        "the rollback failed: {why}; the snapshot is kept at {}",
                        snapshot.display()
                    ),
                ));
            } else {
                result.checks.push(Check::fail(
                    "manager.rollback",
                    format!("the rollback failed: {why}"),
                ));
            }
        }
    }
}

/// `systemctl <args>`: `Ok` on exit 0, the first stderr line or the exit
/// code as the error.
fn systemctl_ok(args: &[&str]) -> Result<(), String> {
    match super::systemd::systemctl(args) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let first = String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned();
            Err(if first.is_empty() {
                format!(
                    "systemctl {}: exit {}",
                    args.join(" "),
                    output.status.code().unwrap_or(-1)
                )
            } else {
                format!("systemctl {}: {first}", args.join(" "))
            })
        }
        Err(why) => Err(format!("systemctl {}: {why}", args.join(" "))),
    }
}

/// Both links back: [`CURRENT`] to its previous target, [`COMMAND_LINK`] to
/// its previous target; a link with no previous is removed.
fn restore_links(prior: &Prior) -> Result<(), String> {
    for (link, previous) in [(CURRENT, &prior.current), (COMMAND_LINK, &prior.command)] {
        match previous {
            Some(target) => {
                atomically_replace_link(link, &target.display().to_string())
                    .map_err(|why| format!("{link}: {why}"))?;
            }
            None => remove_ignoring_not_found(Path::new(link))?,
        }
    }
    Ok(())
}

/// The unit file back to its previous bytes, or removed when there was
/// none; then the manager learns the restored file (`daemon-reload`).
fn restore_unit(prior: &Prior) -> Result<(), String> {
    match &prior.unit {
        Some(bytes) => write_private_bytes(Path::new(super::systemd::UNIT_PATH), bytes, 0o644)
            .map_err(|why| format!("{}: {why}", super::systemd::UNIT_PATH))?,
        None => remove_ignoring_not_found(Path::new(super::systemd::UNIT_PATH))?,
    }
    systemctl_ok(&["daemon-reload"])
}

/// The state root replaced by the snapshot's bytes (`None`: nothing was
/// snapshotted, so the state was never touched). The snapshot goes with it.
fn restore_state(prior: &Prior) -> Result<(), String> {
    let Some(snapshot) = &prior.snapshot else {
        return Ok(());
    };
    let root = state_root();
    let _ = std::fs::remove_dir_all(&root);
    if let Some((mode, uid, gid)) = prior.state_dir {
        std::fs::create_dir_all(&root).map_err(|why| format!("{}: {why}", root.display()))?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode))
            .map_err(|why| format!("{}: {why}", root.display()))?;
        chown_path(&root, uid, gid)?;
        copy_tree_preserving(snapshot, &root)?;
    }
    std::fs::remove_dir_all(snapshot).map_err(|why| format!("{}: {why}", snapshot.display()))
}

/// A configuration copied by this transaction removed, with the private
/// directories the copy created; one that existed before is never touched.
fn restore_configuration() -> Result<(), String> {
    let config = service_config_path();
    remove_ignoring_not_found(&config)?;
    for dir in [
        config.parent().map(|d| d.to_path_buf()),
        config
            .parent()
            .and_then(|d| d.parent().map(|p| p.to_path_buf())),
    ]
    .into_iter()
    .flatten()
    {
        // Fails on a non-empty directory, which stays: only what the copy
        // made empty is removed.
        let _ = std::fs::remove_dir(&dir);
    }
    Ok(())
}

/// Removes `path`; a missing path is already gone.
fn remove_ignoring_not_found(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(why) => Err(format!("{}: {why}", path.display())),
    }
}

/// The snapshot: the service's state root copied under
/// `SERVICE_HOME/.rollback-<pid>/` (0700, owned by the service user, each
/// file's mode and owner preserved), with the state root's own `(mode,
/// uid, gid)`, or `None` when there was no state root yet.
fn snapshot_state() -> Result<(std::path::PathBuf, StateDir), String> {
    let snapshot = Path::new(SERVICE_HOME).join(format!(".rollback-{}", std::process::id()));
    std::fs::create_dir_all(&snapshot)
        .and_then(|()| std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o700)))
        .map_err(|why| format!("{}: {why}", snapshot.display()))?;
    if let Some((uid, gid)) = service_uid_gid() {
        chown_path(&snapshot, uid, gid)?;
    }
    let root = state_root();
    let dir = match std::fs::symlink_metadata(&root) {
        Ok(meta) => Some((meta.mode() & 0o7777, meta.uid(), meta.gid())),
        Err(_) => None,
    };
    if dir.is_some() {
        copy_tree_preserving(&root, &snapshot)?;
    }
    Ok((snapshot, dir))
}

/// Recursively copies `from`'s files and directories below `to`, preserving
/// each file's mode and owner (the snapshot and its restore).
fn copy_tree_preserving(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|why| format!("{}: {why}", to.display()))?;
    // Every directory, `from` itself included, keeps its mode and owner
    // (the log directory must stay 0700 or narrower).
    let meta =
        std::fs::symlink_metadata(from).map_err(|why| format!("{}: {why}", from.display()))?;
    if meta.is_dir() {
        apply_meta(to, &meta)?;
    }
    for entry in std::fs::read_dir(from).map_err(|why| format!("{}: {why}", from.display()))? {
        let entry = entry.map_err(|why| format!("{}: {why}", from.display()))?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        let kind = entry
            .file_type()
            .map_err(|why| format!("{}: {why}", source.display()))?;
        if kind.is_dir() {
            copy_tree_preserving(&source, &target)?;
        } else if kind.is_symlink() {
            let link = std::fs::read_link(&source)
                .map_err(|why| format!("{}: {why}", source.display()))?;
            let _ = std::fs::remove_file(&target);
            unix::symlink(&link, &target).map_err(|why| format!("{}: {why}", target.display()))?;
        } else {
            // `copy` carries the mode; the owner does not follow.
            std::fs::copy(&source, &target)
                .map_err(|why| format!("{}: {why}", source.display()))?;
            if let Ok(meta) = std::fs::symlink_metadata(&source) {
                chown_path(&target, meta.uid(), meta.gid())?;
            }
        }
    }
    Ok(())
}

/// Mode and owner of `meta` onto `path` (chown first, chmod after, as
/// chown clears the set-id bits).
fn apply_meta(path: &Path, meta: &std::fs::Metadata) -> Result<(), String> {
    chown_path(path, meta.uid(), meta.gid())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(meta.mode() & 0o7777))
        .map_err(|why| format!("{}: {why}", path.display()))
}

/// Stop and disable the unit, remove it, the auto-update timer and the command link, keep
/// everything else. `--purge`: name every path, read a typed
/// confirmation — `confirm(prompt)` is `Ok(the typed line)`, or `Err(why)`
/// when there is no terminal, and then the purge refuses with a
/// `confirmation.*` check — and remove only the release files and the
/// paths under the service home.
pub fn uninstall(purge: bool, confirm: &dyn Fn(&str) -> Result<String, String>) -> DeployResult {
    let mut result = DeployResult::new("server uninstall");
    if !gated(&mut result, platform_gate("server uninstall")) {
        return result;
    }
    if !unix::is_root() {
        result.checks.push(Check::fail(
            "preflight.administrator",
            "run as an administrator able to stop the unit and remove system files",
        ));
        return result;
    }
    if purge {
        do_purge(&mut result, confirm);
    } else {
        preserve(&mut result);
    }
    result
}

/// The five purge paths: the release files and the paths under the
/// dedicated service home — and nothing else.
fn purge_paths() -> Vec<&'static str> {
    vec![
        "/opt/jaynshare",
        COMMAND_LINK,
        super::systemd::UNIT_PATH,
        "/var/lib/jaynshare/.config/jaynshare",
        "/var/lib/jaynshare/.local/state/jaynshare",
    ]
}

/// The escape judge, pure over a resolved path: `true` when it lies
/// outside every fixed root — `/opt/jaynshare`, `/usr/local/bin`,
/// `/etc/systemd/system` and [`SERVICE_HOME`]. Judged for each purge path
/// and for every symlink found inside a purged tree. `Path::starts_with` is
/// component-aware, so `/opt/jaynshare-x` is not inside `/opt/jaynshare`.
fn judge_escape(resolved: &Path) -> bool {
    const ROOTS: [&str; 4] = [
        "/opt/jaynshare",
        "/usr/local/bin",
        "/etc/systemd/system",
        SERVICE_HOME,
    ];
    !ROOTS.iter().any(|root| resolved.starts_with(root))
}

/// The symlinks strictly below `dir`, depth first.
fn symlinks_below(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|why| format!("{}: {why}", dir.display()))? {
        let entry = entry.map_err(|why| format!("{}: {why}", dir.display()))?;
        let path = entry.path();
        match entry
            .file_type()
            .map_err(|why| format!("{}: {why}", path.display()))?
        {
            t if t.is_symlink() => out.push(path),
            t if t.is_dir() => symlinks_below(&path, out)?,
            _ => {}
        }
    }
    Ok(())
}

/// Every purge path that must be refused: a path that resolves outside the
/// fixed roots, or a symlink inside a purged tree pointing out.
fn escape_offenders() -> Vec<String> {
    let mut offenders = Vec::new();
    for path in purge_paths() {
        let path = Path::new(path);
        if !path.exists() {
            continue;
        }
        let resolved = match std::fs::canonicalize(path) {
            Ok(resolved) => resolved,
            Err(why) => {
                offenders.push(format!("{} cannot be resolved: {why}", path.display()));
                continue;
            }
        };
        if judge_escape(&resolved) {
            offenders.push(format!(
                "{} resolves to {}, outside the fixed roots",
                path.display(),
                resolved.display()
            ));
        } else if resolved.is_dir() {
            let mut links = Vec::new();
            if let Err(why) = symlinks_below(&resolved, &mut links) {
                offenders.push(format!("{} cannot be walked: {why}", path.display()));
                continue;
            }
            for link in links {
                match std::fs::canonicalize(&link) {
                    Ok(target) if !judge_escape(&target) => {}
                    Ok(target) => offenders.push(format!(
                        "{} points to {}, outside the fixed roots",
                        link.display(),
                        target.display()
                    )),
                    Err(why) => {
                        offenders.push(format!("{} cannot be resolved: {why}", link.display()))
                    }
                }
            }
        }
    }
    offenders
}

/// The purge: name every path, warn, read the typed confirmation, then
/// stop and disable the unit, remove the auto-update timer and the five paths and reload — keeping the
/// service account and [`SERVICE_HOME`] itself. Nothing is removed before
/// the confirmation or on any refusal.
fn do_purge(result: &mut DeployResult, confirm: &dyn Fn(&str) -> Result<String, String>) {
    let offenders = escape_offenders();
    if !offenders.is_empty() {
        result.checks.push(Check::fail(
            "conflict.path",
            format!(
                "the purge is refused and nothing was removed: {}",
                offenders.join("; ")
            ),
        ));
        return;
    }
    let paths = purge_paths()
        .into_iter()
        .filter(|path| Path::new(path).exists())
        .collect::<Vec<&str>>();
    eprintln!("purge removes:");
    for path in &paths {
        eprintln!("  {path}");
    }
    eprintln!(
        "pooled credentials, audit history and trust material become irrecoverable; \
         this purge revokes no upstream credential and removes no client-side CA; \
         the operator revokes upstream credentials and removes client-side CAs separately"
    );
    match confirm("type purge to remove these paths: ") {
        Err(why) => {
            result.checks.push(Check::fail(
                "confirmation.required",
                format!("the purge was not confirmed ({why}); nothing was removed"),
            ));
            return;
        }
        Ok(line) if line != "purge" => {
            result.checks.push(Check::fail(
                "confirmation.mismatch",
                "type `purge` exactly to confirm; nothing was removed",
            ));
            return;
        }
        Ok(_) => {}
    }
    stop_and_disable(result);
    if !result.checks.iter().all(|check| check.passed) || !super::auto_update::remove(result) {
        return;
    }
    for path in paths {
        let path = Path::new(path);
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        };
        match removed {
            Ok(()) => result.checks.push(Check::pass(
                "manager.removed",
                format!("removed {}", path.display()),
            )),
            Err(why) => result.checks.push(Check::fail(
                "manager.removed",
                format!("{}: {why}", path.display()),
            )),
        }
    }
    if !result.checks.iter().all(|check| check.passed) {
        return;
    }
    daemon_reload(result);
    result.paths = purge_paths().into_iter().map(str::to_owned).collect();
}

/// The preserve uninstall: stop and disable the unit, remove it, the auto-update timer
/// and the command link, reload, and keep every release, the selection, the
/// configuration, the state, the logs and the service account.
fn preserve(result: &mut DeployResult) {
    stop_and_disable(result);
    if !result.checks.iter().all(|check| check.passed) || !super::auto_update::remove(result) {
        return;
    }
    for (path, name) in [
        (super::systemd::UNIT_PATH, "manager.unit"),
        (COMMAND_LINK, "manager.link"),
    ] {
        match std::fs::remove_file(path) {
            Ok(()) => result
                .checks
                .push(Check::pass(name, format!("removed {path}"))),
            Err(why) if why.kind() == std::io::ErrorKind::NotFound => result
                .checks
                .push(Check::pass(name, format!("{path} was already absent"))),
            Err(why) => result
                .checks
                .push(Check::fail(name, format!("{path}: {why}"))),
        }
    }
    if !result.checks.iter().all(|check| check.passed) {
        return;
    }
    daemon_reload(result);
    result.paths = vec![
        RELEASES.to_owned(),
        CURRENT.to_owned(),
        SERVICE_HOME.to_owned(),
        "/var/lib/jaynshare/.config/jaynshare".to_owned(),
        "/var/lib/jaynshare/.local/state/jaynshare".to_owned(),
    ];
    result.checks.push(Check::pass(
        "uninstall.kept",
        "kept every release, the selection, the configuration, the state and the service account; reinstalling reuses them",
    ));
}

/// `systemctl stop` then `disable`. A unit whose file is gone is
/// already down: nothing to stop, and that is success. A manager failure
/// leaves everything in place.
fn stop_and_disable(result: &mut DeployResult) {
    if !Path::new(super::systemd::UNIT_PATH).is_file() {
        result.checks.push(Check::pass(
            "manager.stop",
            "the unit file is already absent, so nothing runs or is enabled",
        ));
        return;
    }
    for step in [
        ["stop", super::systemd::UNIT_NAME],
        ["disable", super::systemd::UNIT_NAME],
    ] {
        let name = format!("manager.{}", step[0]);
        match super::systemd::systemctl(&step) {
            Ok(output) if output.status.success() => result
                .checks
                .push(Check::pass(&name, format!("systemctl {}", step.join(" ")))),
            Ok(output) => {
                let first = String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .next()
                    .unwrap_or("no error output")
                    .to_owned();
                result.checks.push(Check::fail(
                    &name,
                    format!("systemctl {}: {first}", step.join(" ")),
                ));
                return;
            }
            Err(why) => {
                result.checks.push(Check::fail(
                    &name,
                    format!("systemctl {}: {why}", step.join(" ")),
                ));
                return;
            }
        }
    }
}

/// The manager must forget the removed unit.
fn daemon_reload(result: &mut DeployResult) {
    match super::systemd::systemctl(&["daemon-reload"]) {
        Ok(output) if output.status.success() => result
            .checks
            .push(Check::pass("manager.reload", "systemctl daemon-reload")),
        Ok(output) => {
            let first = String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("no error output")
                .to_owned();
            result.checks.push(Check::fail(
                "manager.reload",
                format!("systemctl daemon-reload: {first}"),
            ));
        }
        Err(why) => result.checks.push(Check::fail(
            "manager.reload",
            format!("systemctl daemon-reload: {why}"),
        )),
    }
}

/// `server update`'s inputs: a release directory, a version fetched from
/// the origin first, or neither, for what the recorded origin offers.
pub struct UpdateInputs<'a> {
    pub from: Option<&'a Path>,
    pub version: Option<&'a str>,
    pub release_origin: Option<&'a str>,
    /// The global `--tls-ca`: the extra trust anchor for the fetch.
    pub tls_ca: Option<&'a Path>,
    pub config: Option<&'a Path>,
    pub allow_downgrade: bool,
    /// The global `--yes`: skips the update's confirmation.
    pub yes: bool,
    /// Reads one typed line on a terminal; `Err(why)` when there is none.
    pub confirm: &'a dyn Fn(&str) -> Result<String, String>,
}

/// Verify, then install, refusing a lower version unless
/// `allow_downgrade`; never rewrites configuration or state. With neither
/// `--from` nor `--version` it follows the recorded origin: the newest
/// release there, or the clone build at its recorded path; already on that
/// is success with nothing done.
pub fn update(inputs: &UpdateInputs<'_>) -> DeployResult {
    let mut result = DeployResult::new("server update");
    if !gated(&mut result, platform_gate("server update")) {
        return result;
    }
    let recorded = recorded_origin();
    let fetch = Fetch {
        origin: fetch_origin(inputs.release_origin, recorded.as_ref()),
        tls_ca: inputs.tls_ca,
    };
    let source = match (inputs.from, inputs.version, &recorded) {
        (Some(from), _, _) => Source::Directory(from),
        (None, Some(version), _) => Source::Published(Some(version)),
        (None, None, Some(Origin::Build(binary))) if inputs.release_origin.is_none() => {
            Source::Build { binary, kit: None }
        }
        (None, None, _) => Source::Published(None),
    };
    if let Some(prepared) = prepare(&source, &fetch, &mut result) {
        let explicit = inputs.from.is_some() || inputs.version.is_some();
        update_prepared(inputs, &prepared, explicit, &mut result);
    }
    result
}

/// `update` once the release is verified: the installed-release and version
/// gates, the confirmation, then the install steps with no `--config`
/// (configuration, state and the prior release are kept). `explicit` is a
/// release the operator named, for which being on it already is a conflict.
fn update_prepared(
    inputs: &UpdateInputs<'_>,
    prepared: &Prepared,
    explicit: bool,
    result: &mut DeployResult,
) {
    let version = &prepared.version;

    // An update updates an installation: CURRENT must resolve.
    let current = match std::fs::read_link(CURRENT) {
        Ok(link) => file_name(&link),
        Err(_) => {
            result.checks.push(Check::fail(
                "conflict.install",
                "nothing is installed; use server install",
            ));
            return;
        }
    };

    // SemVer precedence against the current release's version (read
    // from CURRENT's directory name).
    if !inputs.allow_downgrade
        && let Some(check) = downgrade(version)
    {
        result.checks.push(check);
        return;
    }
    if *version == current {
        result.checks.push(if explicit {
            Check::fail("conflict.same_version", format!("already on {version}"))
        } else {
            Check::pass(
                "release.current",
                format!("already on {version}; nothing to do"),
            )
        });
        return;
    }

    // The update restarts the service; `--yes` stands in for the
    // typed confirmation.
    if !inputs.yes {
        match (inputs.confirm)(&format!("restart jaynshare on {version}? [y/N] ")) {
            Ok(line) => {
                let typed = line.trim();
                if !typed.eq_ignore_ascii_case("y") && !typed.eq_ignore_ascii_case("yes") {
                    result.checks.push(Check::fail(
                        "confirmation.declined",
                        "the answer was not yes; nothing was changed",
                    ));
                    return;
                }
            }
            Err(why) => {
                result
                    .checks
                    .push(Check::fail("confirmation.required", why));
                return;
            }
        }
    }

    // Then the install steps (the update never rewrites
    // configuration or state): preflight validates the service's installed
    // configuration at its fixed service path.
    let service_config = service_config_path();
    if !gated(result, service_account()) {
        return;
    }
    let preflight = super::preflight::run(&super::preflight::Inputs {
        from: None,
        config: Some(&service_config),
        unknown_firewall: super::preflight::UnknownFirewall::Update,
    });
    if !gated(result, preflight.checks) {
        return;
    }
    transaction(&prepared.payload, None, result);
    record_origin(prepared, result);
}

/// Remove releases older than the newest `keep`, never `current`'s
/// target.
pub fn prune(keep: usize) -> DeployResult {
    let mut result = DeployResult::new("server prune");
    let current = std::fs::read_link(CURRENT)
        .ok()
        .map(|target| file_name(&target));
    let names: Vec<String> = match std::fs::read_dir(RELEASES) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(why) => {
            result
                .checks
                .push(Check::fail("release.prune", format!("{RELEASES}: {why}")));
            return result;
        }
    };
    let removed = prune_selection(&names, current.as_deref(), keep);
    for name in &removed {
        let dir = format!("{RELEASES}/{name}");
        if let Err(why) = std::fs::remove_dir_all(&dir) {
            result
                .checks
                .push(Check::fail("release.prune", format!("{dir}: {why}")));
            return result;
        }
        result.paths.push(dir);
    }
    result.checks.push(Check::pass(
        "release.prune",
        format!(
            "kept the current release and the newest {keep} other(s); removed {}",
            removed.len()
        ),
    ));
    result
}

/// The pure half of pruning: of `entries` (release-directory names), only
/// the ones that parse as SemVer count as releases, `current`'s target is
/// never removed, and everything past the newest `keep` is
/// (`keep == 0` still keeps `current`).
fn prune_selection(entries: &[String], current: Option<&str>, keep: usize) -> Vec<String> {
    let mut releases: Vec<&String> = entries
        .iter()
        .filter(|name| Some(name.as_str()) != current)
        .filter(|name| split_version(name).0.is_some())
        .collect();
    releases.sort_by(|a, b| semver_precedence(b, a).then(a.cmp(b)));
    releases.into_iter().skip(keep).cloned().collect()
}

/// `version`'s SemVer core numbers and pre-release identifiers: `None` core
/// when it does not parse as SemVer, `None` pre-release for a release.
fn split_version(version: &str) -> (Option<Vec<u64>>, Option<Vec<String>>) {
    let no_build = version.split('+').next().unwrap_or(version);
    let (core, pre) = match no_build.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (no_build, None),
    };
    let numbers: Option<Vec<u64>> = core
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect();
    let pre = pre.map(|pre| pre.split('.').map(str::to_owned).collect());
    (numbers, pre)
}

/// SemVer precedence (semver.org): the core numbers, then the pre-release
/// identifiers — a release outranks any pre-release of the same core, numeric
/// identifiers compare numerically and below alphanumeric ones, and more
/// pre-release identifiers outrank fewer when the shared prefix is equal.
/// Build metadata is ignored. Versions that do not parse as SemVer compare
/// lexicographically, so an odd directory name still gives a stable answer.
fn semver_precedence(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (a_core, a_pre) = split_version(a);
    let (b_core, b_pre) = split_version(b);
    let (Some(a_core), Some(b_core)) = (a_core, b_core) else {
        return a.cmp(b);
    };
    let core = a_core.cmp(&b_core);
    if core != Ordering::Equal {
        return core;
    }
    match (a_pre, b_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a_pre), Some(b_pre)) => {
            for (a_id, b_id) in a_pre.iter().zip(&b_pre) {
                let ord = match (a_id.parse::<u64>(), b_id.parse::<u64>()) {
                    (Ok(a), Ok(b)) => a.cmp(&b),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => a_id.cmp(b_id),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            a_pre.len().cmp(&b_pre.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_linux_with_systemd_passes_the_gate() {
        let ok = judge_platform("linux", "aarch64", true, "server install");
        assert!(ok.iter().all(|c| c.passed), "{ok:?}");
        for (os, arch) in [
            ("macos", "aarch64"),
            ("windows", "x86_64"),
            ("linux", "riscv64"),
        ] {
            let refused = judge_platform(os, arch, true, "server install");
            assert_eq!(refused.len(), 1, "{refused:?}");
            assert_eq!(refused[0].name, "preflight.platform");
            assert!(!refused[0].passed && refused[0].message.contains("nothing was written"));
        }
        let no_systemd = judge_platform("linux", "x86_64", false, "server install");
        let failed: Vec<&str> = no_systemd
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(failed, ["preflight.systemd"]);
        assert!(no_systemd[1].message.contains("nothing was written"));
    }

    const GOOD_PASSWD: &str =
        "jaynshare:x:990:990:Jaynshare service:/var/lib/jaynshare:/usr/sbin/nologin";

    fn one_refusal(passwd: &str, group_ids: &str, primary_gid: u32, rule: &str) {
        let checks = judge_account(passwd, group_ids, primary_gid);
        assert_eq!(checks.len(), 1, "{checks:?}");
        assert_eq!(checks[0].name, "preflight.service_account");
        assert!(!checks[0].passed, "{checks:?}");
        assert!(checks[0].message.contains(rule), "{checks:?}");
    }

    #[test]
    fn judge_account_passes_a_dedicated_non_login_account() {
        assert!(judge_account(GOOD_PASSWD, "990", 990).is_empty());
    }

    #[test]
    fn judge_account_refuses_root() {
        one_refusal(
            "jaynshare:x:0:990:Jaynshare service:/var/lib/jaynshare:/usr/sbin/nologin",
            "990",
            990,
            "root",
        );
    }

    #[test]
    fn judge_account_refuses_an_interactive_shell() {
        one_refusal(
            "jaynshare:x:990:990:Jaynshare service:/var/lib/jaynshare:/bin/bash",
            "990",
            990,
            "/bin/bash",
        );
    }

    #[test]
    fn judge_account_refuses_another_home() {
        one_refusal(
            "jaynshare:x:990:990:Jaynshare service:/home/jaynshare:/usr/sbin/nologin",
            "990",
            990,
            "/home/jaynshare",
        );
    }

    #[test]
    fn judge_account_refuses_another_primary_group() {
        one_refusal(
            "jaynshare:x:990:100:Jaynshare service:/var/lib/jaynshare:/usr/sbin/nologin",
            "100",
            990,
            "primary group",
        );
    }

    #[test]
    fn judge_account_refuses_a_supplementary_group() {
        one_refusal(GOOD_PASSWD, "990 100", 990, "supplementary");
    }

    const ROOT: &str = "jaynshare-1.2.3-x86_64-unknown-linux-musl";

    #[test]
    fn the_archive_judge_admits_its_root_and_four_files() {
        assert_eq!(
            judge_archive_entry(&format!("{ROOT}/"), ROOT),
            ArchiveEntry::Root
        );
        assert_eq!(judge_archive_entry(ROOT, ROOT), ArchiveEntry::Root);
        for name in ["jaynshare", "LICENSE", "NOTICE.md", "README.txt"] {
            assert_eq!(
                judge_archive_entry(&format!("{ROOT}/{name}"), ROOT),
                ArchiveEntry::File,
                "{name}"
            );
        }
    }

    /// The release process's archives name only the four
    /// members under the root, with no directory entry of their own.
    #[test]
    fn an_archive_without_a_root_directory_entry_extracts() {
        let root = "jaynshare-1.2.3-aarch64-unknown-linux-musl";
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for name in ["jaynshare", "LICENSE", "NOTICE.md", "README.txt"] {
            let mut header = tar::Header::new_gnu();
            header.set_size(name.len() as u64);
            header.set_mode(0o644);
            archive
                .append_data(&mut header, format!("{root}/{name}"), name.as_bytes())
                .unwrap();
        }
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let staging =
            std::env::temp_dir().join(format!("jaynshare-extract-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&staging);
        extract_archive(&bytes, root, &staging).expect("extracted");
        assert_eq!(
            std::fs::read(staging.join("NOTICE.md")).unwrap(),
            b"NOTICE.md"
        );
        std::fs::remove_dir_all(&staging).unwrap();
        // An archive with no member under the root is still not rooted.
        let empty = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ))
        .into_inner()
        .unwrap()
        .finish()
        .unwrap();
        assert!(extract_archive(&empty, root, &staging).is_err());
    }

    #[test]
    fn the_archive_judge_refuses_everything_else() {
        // An extra file, a subdirectory, a link, an escape and a wrong root.
        for bad in [
            format!("{ROOT}/extra.txt"),
            format!("{ROOT}/sub/file"),
            format!("{ROOT}/link"),
            format!("{ROOT}/../escape"),
            "jaynshare-9.9.9-x86_64-unknown-linux-musl/jaynshare".to_owned(),
            "jaynshare".to_owned(),
            "/etc/passwd".to_owned(),
        ] {
            assert_eq!(
                judge_archive_entry(&bad, ROOT),
                ArchiveEntry::Refuse,
                "{bad}"
            );
        }
        // `..` inside the accepted prefix is a refusal too.
        assert_eq!(
            judge_archive_entry(&format!("{ROOT}/../{ROOT}/jaynshare"), ROOT),
            ArchiveEntry::Refuse
        );
    }

    #[test]
    fn the_configuration_decision_covers_the_four_cases() {
        let new = Some(b"version = 1\n".as_slice());
        let other = Some(b"version = 1\nchanged = true\n".as_slice());
        assert_eq!(select_configuration(new, None), ConfigDecision::Copy);
        assert_eq!(select_configuration(new, new), ConfigDecision::Keep);
        assert_eq!(select_configuration(new, other), ConfigDecision::Conflict);
        assert_eq!(select_configuration(other, new), ConfigDecision::Conflict);
        assert_eq!(select_configuration(None, None), ConfigDecision::Missing);
        assert_eq!(select_configuration(None, new), ConfigDecision::Missing);
    }

    #[test]
    fn the_service_configuration_path_is_under_the_service_home() {
        assert_eq!(
            service_config_path(),
            std::path::PathBuf::from("/var/lib/jaynshare/.config/jaynshare/config.toml")
        );
    }

    #[test]
    fn semver_precedence_orders_the_release_line() {
        use std::cmp::Ordering::*;
        assert_eq!(
            semver_precedence("0.6.0-acceptance", "0.7.0-acceptance"),
            Less
        );
        assert_eq!(
            semver_precedence("0.7.1-acceptance", "0.7.0-acceptance"),
            Greater
        );
        assert_eq!(semver_precedence("1.2.3", "1.2.3"), Equal);
        // Build metadata is ignored.
        assert_eq!(semver_precedence("1.2.3+build.1", "1.2.3"), Equal);
        // A release outranks every pre-release of the same core.
        assert_eq!(semver_precedence("1.2.3-rc.1", "1.2.3"), Less);
        // Numeric identifiers compare numerically and below alphanumeric ones.
        assert_eq!(semver_precedence("1.2.3-2", "1.2.3-10"), Less);
        assert_eq!(semver_precedence("1.2.3-10", "1.2.3-alpha"), Less);
        // More pre-release identifiers outrank fewer, shared prefix equal.
        assert_eq!(semver_precedence("1.2.3-alpha", "1.2.3-alpha.1"), Less);
        // Not SemVer on both sides: a stable lexicographic answer.
        assert_eq!(semver_precedence(".staging-1", ".staging-2"), Less);
    }

    #[test]
    fn prune_selection_keeps_current_and_the_newest() {
        let entries: Vec<String> = [
            "0.7.0-acceptance",
            "0.7.1-acceptance",
            "0.6.0-acceptance",
            ".staging-0.9.0-1",
        ]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
        let current = "0.6.0-acceptance";
        // The current release and the newest `keep` others stay.
        assert_eq!(
            prune_selection(&entries, Some(current), 1),
            ["0.7.0-acceptance"]
        );
        // `keep == 0` still never names current's target.
        assert_eq!(
            prune_selection(&entries, Some(current), 0),
            ["0.7.1-acceptance", "0.7.0-acceptance"]
        );
        // Everything fits: nothing is removed.
        assert!(prune_selection(&entries, Some(current), 2).is_empty());
        // Non-SemVer names are not releases and are never removed.
        assert!(prune_selection(&entries, Some(current), 99).is_empty());
        // No current: keep=1 keeps only the newest.
        assert_eq!(
            prune_selection(&entries, None, 1),
            ["0.7.0-acceptance", "0.6.0-acceptance"]
        );
    }

    /// The purge's five exact paths (the release files and the
    /// paths under the service home), and the escape judge over
    /// (path, resolved) pairs — kept inside the fixed roots, refused
    /// outside them, with the normal command link's target still inside.
    #[test]
    fn the_purge_paths_are_five_and_the_escape_judge_keeps_only_the_fixed_roots() {
        assert_eq!(
            purge_paths(),
            vec![
                "/opt/jaynshare",
                "/usr/local/bin/jaynshare",
                "/etc/systemd/system/jaynshare.service",
                "/var/lib/jaynshare/.config/jaynshare",
                "/var/lib/jaynshare/.local/state/jaynshare",
            ]
        );
        for (path, resolved, escaped) in [
            ("/opt/jaynshare", "/opt/jaynshare", false),
            ("/opt/jaynshare", "/opt/jaynshare/releases/1.2.3", false),
            ("/opt/jaynshare", "/etc", true),
            ("/opt/jaynshare", "/opt/jaynshare-neighbour", true),
            (
                "/usr/local/bin/jaynshare",
                "/opt/jaynshare/current/jaynshare",
                false,
            ),
            ("/usr/local/bin/jaynshare", "/usr/bin/jaynshare", true),
            (
                "/etc/systemd/system/jaynshare.service",
                "/etc/systemd/system/jaynshare.service",
                false,
            ),
            (
                "/var/lib/jaynshare/.config/jaynshare",
                "/var/lib/jaynshare/.config/jaynshare",
                false,
            ),
            ("/var/lib/jaynshare/.config/jaynshare", "/etc", true),
            (
                "/var/lib/jaynshare/.local/state/jaynshare",
                "/var/lib/jaynshare/.local/state/jaynshare",
                false,
            ),
            (
                "/var/lib/jaynshare/.local/state/jaynshare",
                "/var/log/jaynshare",
                true,
            ),
            (
                "/var/lib/jaynshare/.config/jaynshare",
                "/var/lib/jaynshare/escape",
                false,
            ),
        ] {
            assert_eq!(
                judge_escape(Path::new(resolved)),
                escaped,
                "{path} -> {resolved}"
            );
        }
    }

    #[test]
    fn the_state_root_is_under_the_service_home() {
        assert_eq!(
            state_root(),
            std::path::PathBuf::from("/var/lib/jaynshare/.local/state/jaynshare")
        );
    }

    #[test]
    fn the_generated_configuration_moves_the_listeners_onto_identity_tls() {
        let listen: SocketAddr = "100.101.102.103:17421".parse().unwrap();
        let text = configuration_text(listen, "this host's Tailscale address");
        let config = crate::config::parse(text.as_bytes(), Path::new("/var/lib/jaynshare"))
            .expect("the generated configuration is valid");
        assert_eq!(config.data_plane.listen, listen);
        assert_eq!(config.data_plane.tls, crate::config::ListenerTls::Identity);
        assert_eq!(
            config.storage.state_file,
            crate::config::absolute(&state_root().join("state.json"))
        );
        assert!(config.mitm.enabled);
        assert_eq!(config.mitm.listen.to_string(), "100.101.102.103:17422");
        let ipv6: SocketAddr = "[fd00::5]:17421".parse().unwrap();
        let text = configuration_text(ipv6, "typed at install");
        let config = crate::config::parse(text.as_bytes(), Path::new("/")).expect("valid");
        assert_eq!(config.data_plane.listen, ipv6);
    }

    #[test]
    fn the_listen_question_takes_an_address_and_refuses_without_one() {
        let candidates = [
            ("eth0".to_owned(), "192.168.1.5".parse().unwrap()),
            ("docker0".to_owned(), "172.17.0.1".parse().unwrap()),
        ];
        let typed = |line: &'static str| move |_: &str| Ok::<_, String>(line.to_owned());
        assert_eq!(
            ask_listen(&candidates, &typed("192.168.1.5")).expect("an address"),
            (candidates[0].1, "typed at install".to_owned())
        );
        let refused = ask_listen(&candidates, &typed("eth0")).expect_err("not an address");
        assert_eq!(refused.name, "configuration.listen");
        let no_terminal = |_: &str| Err("no terminal".to_owned());
        let refused = ask_listen(&candidates, &no_terminal).expect_err("no terminal");
        assert!(
            refused
                .message
                .contains("192.168.1.5 on eth0, 172.17.0.1 on docker0")
                && refused.message.contains("--listen <ip>"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_fetch_takes_the_named_origin_then_the_recorded_mirror() {
        let mirror = Origin::Mirror("https://mirror.example/r".into());
        let build = Origin::Build("/home/op/jaynshare/target/release/jaynshare".into());
        let named = Some("https://other.example/r");
        assert_eq!(fetch_origin(named, Some(&mirror)), named);
        assert_eq!(
            fetch_origin(None, Some(&mirror)),
            Some("https://mirror.example/r")
        );
        for recorded in [None, Some(&Origin::Official), Some(&build)] {
            assert_eq!(fetch_origin(None, recorded), None, "{recorded:?}");
        }
    }

    #[test]
    fn the_origin_record_names_its_kind() {
        let record =
            serde_json::to_string(&Origin::Build("/src/target/release/jaynshare".into())).unwrap();
        assert_eq!(record, r#"{"build":"/src/target/release/jaynshare"}"#);
        assert_eq!(
            serde_json::to_string(&Origin::Official).unwrap(),
            r#""official""#
        );
        let parsed: Origin =
            serde_json::from_str(r#"{"mirror":"https://mirror.example/r"}"#).expect("a mirror");
        assert_eq!(parsed, Origin::Mirror("https://mirror.example/r".into()));
    }

    #[test]
    fn only_a_plain_version_names_a_directory() {
        for good in ["2.1.0", "0.7.0-acceptance", "2.1.0-rc.1+build.5"] {
            assert!(plain_version(good), "{good}");
        }
        for bad in ["", "../2.1.0", "2.1.0/x", "2.1 .0"] {
            assert!(!plain_version(bad), "{bad}");
        }
    }

    #[test]
    fn the_rollback_plan_runs_every_step_and_stops_nothing() {
        // A running previous install with a configuration that predates the
        // transaction: stop, links, unit, state, then start and the status
        // check against the previous release.
        assert_eq!(
            rollback_steps(true, false),
            ["stop", "links", "unit", "state", "start", "status"]
        );
        // A stopped unit stays stopped; a configuration copied by the
        // transaction is removed (one that existed before is never touched).
        assert_eq!(
            rollback_steps(false, true),
            ["stop", "links", "unit", "state", "configuration"]
        );
        assert_eq!(
            rollback_steps(false, false),
            ["stop", "links", "unit", "state"]
        );
    }
}
