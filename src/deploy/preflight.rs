//! `server preflight [--from <release-dir>]`.
//! Every failed gating check makes the operation non-zero, and no listener
//! is ever bound (a port is tested by the unit's own means, not by binding
//! the configured listener's socket and keeping it).

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

use super::address::{self, AddressClass};
use super::firewall::{self, Verdict};
use super::native;
use super::release;
use super::result::{Check, DeployResult};
use crate::config;

/// What `server preflight` was given.
pub struct Inputs<'a> {
    /// `--from <release-dir>`: release integrity is checked when present.
    pub from: Option<&'a Path>,
    /// The global `--config <path>`, else the default configuration.
    pub config: Option<&'a Path>,
    pub unknown_firewall: UnknownFirewall<'a>,
}

/// What a host firewall that cannot be inspected means.
#[derive(Clone, Copy)]
pub enum UnknownFirewall<'a> {
    Refused,
    /// The interface and rule an operator on a terminal recorded checking by hand.
    Recorded(&'a str),
    /// Passes: an update keeps the installed configuration.
    Update,
}

impl<'a> UnknownFirewall<'a> {
    pub fn recorded(record: Option<&'a str>) -> Self {
        record.map_or(Self::Refused, Self::Recorded)
    }
}

/// In order: OS and architecture; release integrity (with `from`); systemd
/// and the dedicated user; the configuration's validity, permissions and
/// paths; both listener addresses (closed list, assignment, firewall);
/// port availability; 256 MiB free in the service home; the kernel's clock
/// synchronized within five minutes. Check names carry their exit class
/// (`result.rs`): `configuration.*` (3), `release.*` (17), every other
/// `preflight.*` (18).
/// Nothing is written anywhere; every check runs and is reported, except a
/// check whose input an earlier failure removed — that one is reported as
/// failed `not checked: <why>`.
pub fn run(inputs: &Inputs<'_>) -> DeployResult {
    let mut result = DeployResult::new("server preflight");
    let mut checks = Vec::new();

    // Linux x86-64/arm64 with systemd as PID 1, before anything
    // is read or written.
    checks.extend(native::platform_gate("server preflight"));

    // Release integrity, when a release was named.
    if let Some(from) = inputs.from {
        let verified = release::verify(from, None);
        result.version = verified.version.clone();
        result.commit = verified.commit.clone();
        result.paths.extend(verified.paths.iter().cloned());
        checks.extend(verified.checks);
    }

    // The dedicated user, when it already exists.
    checks.push(service_account());

    // The selected configuration through the product's own
    // loader and validator; every dotted error in one check.
    let (config_path, _) = config::config_selection(inputs.config);
    let loaded = match config::load(&config_path) {
        Ok(loaded) => {
            checks.push(Check::pass(
                "configuration.valid",
                format!("{} is valid", config_path.display()),
            ));
            Some(loaded)
        }
        Err(errors) => {
            checks.push(Check::fail("configuration.valid", errors.to_string()));
            None
        }
    };
    let configuration_failed = loaded.is_none();

    // The configuration file and the state directory are private.
    if let Some(loaded) = &loaded {
        let mut problems = Vec::new();
        let state_dir = loaded
            .config
            .storage
            .state_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        for (what, path) in [
            ("the configuration file", config_path.clone()),
            ("the state directory", state_dir),
        ] {
            if let Err(why) = crate::state::check_private(&path) {
                problems.push(format!("{what}: {why}"));
            }
        }
        checks.push(if problems.is_empty() {
            Check::pass(
                "preflight.paths",
                "the configuration file and the state directory are private",
            )
        } else {
            Check::fail("preflight.paths", problems.join("; "))
        });
    } else {
        checks.push(not_checked(
            "preflight.paths",
            "the configuration did not load",
        ));
    }

    // Listener checks + port availability for each configured listener. The
    // control namespace rides the data-plane listener; the
    // proxy listener exists only when the proxy mode is on. When the
    // configuration did not load the addresses are unknown, so every
    // listener check is reported as not checked.
    let addresses: Vec<Option<SocketAddr>> = match &loaded {
        Some(loaded) => {
            let data_plane = loaded.config.data_plane.listen;
            vec![
                Some(data_plane),
                Some(data_plane),
                loaded
                    .config
                    .mitm
                    .enabled
                    .then_some(loaded.config.mitm.listen),
            ]
        }
        None => vec![None; 3],
    };
    for (name, address) in ["data_plane", "control", "proxy"]
        .into_iter()
        .zip(addresses)
    {
        let full = |kind: &str| format!("preflight.{kind}.{name}");
        let Some(address) = address else {
            if configuration_failed {
                for kind in ["listener", "assigned", "firewall", "port"] {
                    checks.push(not_checked(full(kind), "the configuration did not load"));
                }
            }
            continue;
        };
        let listener = address::check_listener(&full("listener"), address);
        let listener_passed = listener.passed;
        checks.push(listener);
        // Only an address that passed the closed-list and assignment checks is ever test-bound below.
        let bindable = match (
            listener_passed,
            address::classify(address.ip()) != AddressClass::Loopback,
        ) {
            // Assignment and firewall apply to a non-loopback listener that passed the closed list.
            (true, false) => true,
            (false, _) => {
                checks.push(not_checked(
                    full("assigned"),
                    "the address is not on the closed list",
                ));
                checks.push(not_checked(
                    full("firewall"),
                    "the address is not on the closed list",
                ));
                false
            }
            (true, true) => match address::assigned(address.ip()) {
                Ok(Some(interface)) => {
                    checks.push(Check::pass(
                        full("assigned"),
                        format!("{address} is on {interface}"),
                    ));
                    checks.push(firewall_check(
                        full("firewall"),
                        address,
                        &interface,
                        inputs.unknown_firewall,
                    ));
                    true
                }
                Ok(None) => {
                    checks.push(Check::fail(
                        full("assigned"),
                        format!("{address} is not assigned to any interface on this host"),
                    ));
                    checks.push(not_checked(
                        full("firewall"),
                        "no interface carries the listener address",
                    ));
                    false
                }
                Err(why) => {
                    checks.push(Check::fail(full("assigned"), why));
                    checks.push(not_checked(
                        full("firewall"),
                        "the interfaces could not be listed",
                    ));
                    false
                }
            },
        };
        // A refused address is never bound, not even to test it.
        checks.push(if bindable {
            port_free(full("port"), address)
        } else {
            not_checked(
                full("port"),
                "the address failed the listener checks and is never bound",
            )
        });
    }

    // 256 MiB free in the service home.
    checks.push(service_home_disk());

    // The kernel reports its clock synchronized within five
    // minutes; the host's time daemon is what disciplines it.
    checks.push(kernel_clock());

    result.checks = checks;
    result
}

/// The firewall verdict for one listener on `interface`; an uninspectable
/// firewall is judged by `unknown`.
fn firewall_check(
    name: String,
    listener: SocketAddr,
    interface: &str,
    unknown: UnknownFirewall<'_>,
) -> Check {
    match (firewall::inspect(listener, interface), unknown) {
        (Verdict::Private, _) => Check::pass(
            name,
            format!("{listener} is admitted from the private interface only"),
        ),
        (Verdict::PublicAdmitted(rule), _) => Check::fail(
            name,
            format!(
                "the firewall admits {listener} from a public interface or source range: {rule}"
            ),
        ),
        (Verdict::Unknown(why), UnknownFirewall::Recorded(record)) => Check::pass(
            name,
            format!(
                "manual check recorded by the operator: {record} (the firewall could not be inspected: {why})"
            ),
        ),
        (Verdict::Unknown(why), UnknownFirewall::Update) => Check::pass(
            name,
            format!(
                "the firewall could not be inspected ({why}); an update keeps the installed configuration"
            ),
        ),
        (Verdict::Unknown(why), UnknownFirewall::Refused) => Check::fail(
            name,
            format!(
                "unresolved manual check: {why}; record the interface and rule checked to continue"
            ),
        ),
    }
}

/// When `jaynshare` exists, its shell must be non-interactive and
/// its home must be the service home; when it does not, install creates it.
fn service_account() -> Check {
    let Ok(output) = native::account_tool("getent", &["passwd", native::SERVICE_USER]) else {
        // No getent (or it cannot run) reads as absent; the
        // supported host is Linux and `install` reuses the account.
        return Check::pass("preflight.service_account", "will be created by install");
    };
    if !output.status.success() {
        return Check::pass("preflight.service_account", "will be created by install");
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = line.lines().next().unwrap_or("").split(':').collect();
    let home = fields.get(5).copied().unwrap_or("");
    let shell = fields.get(6).copied().unwrap_or("");
    let mut problems = Vec::new();
    if home != native::SERVICE_HOME {
        problems.push(format!(
            "its home is {home:?}, not {}",
            native::SERVICE_HOME
        ));
    }
    if !non_login(shell) {
        problems.push(format!("its shell is {shell:?}, not a non-login shell"));
    }
    if problems.is_empty() {
        Check::pass(
            "preflight.service_account",
            format!(
                "{} exists with a non-login shell and home {}",
                native::SERVICE_USER,
                native::SERVICE_HOME
            ),
        )
    } else {
        Check::fail("preflight.service_account", problems.join("; "))
    }
}

/// A non-login shell (`nologin`, `false` or any no-arguments shell
/// of that shape).
fn non_login(shell: &str) -> bool {
    shell.ends_with("/nologin") || shell.ends_with("/false")
}

/// The port test: bind the exact address and drop the socket at once.
/// A port the installed service itself listens on is not a conflict: a
/// second install or an update restarts that service.
fn port_free(name: String, address: SocketAddr) -> Check {
    match TcpListener::bind(address) {
        Ok(listener) => {
            drop(listener);
            Check::pass(name, format!("{address} is free"))
        }
        Err(why) => match held_by_service(address) {
            Some(pid) => Check::pass(
                name,
                format!(
                    "{address} is held by the running {} (pid {pid}), which the install restarts",
                    super::systemd::UNIT_NAME
                ),
            ),
            None if why.kind() == std::io::ErrorKind::AddrInUse => {
                Check::fail(name, format!("{address} is in use: {why}"))
            }
            None => Check::fail(name, format!("{address} cannot be bound: {why}")),
        },
    }
}

/// The unit's main process, when the unit runs and a socket listening on
/// `address` belongs to the dedicated service account (nothing else
/// runs as it). `/proc/net/tcp{,6}` carries each socket's owner uid; the
/// sockets themselves (`/proc/<pid>/fd`) are unreadable without
/// `CAP_SYS_PTRACE`, which a container's root lacks.
#[cfg(target_os = "linux")]
fn held_by_service(address: SocketAddr) -> Option<u32> {
    let output = super::systemd::systemctl(&[
        "show",
        super::systemd::UNIT_NAME,
        "-p",
        "MainPID",
        "--value",
    ])
    .ok()?;
    let pid: u32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()?;
    if pid == 0 {
        return None;
    }
    let (uid, _) = native::service_uid_gid()?;
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|table| std::fs::read_to_string(table).ok())
        .any(|table| {
            table
                .lines()
                .skip(1)
                .filter_map(listen_row)
                .any(|(local, owner)| local == address && owner == uid)
        })
        .then_some(pid)
}

#[cfg(not(target_os = "linux"))]
fn held_by_service(_address: SocketAddr) -> Option<u32> {
    None
}

/// One `/proc/net/tcp{,6}` row in the LISTEN state (`0A`): its local
/// address and owner uid. The kernel prints each 32-bit address word in
/// host byte order and the port big-endian.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn listen_row(line: &str) -> Option<(SocketAddr, u32)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.get(3) != Some(&"0A") {
        return None;
    }
    let (ip, port) = fields.get(1)?.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let words = (0..ip.len() / 8)
        .map(|i| u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16).ok())
        .collect::<Option<Vec<u32>>>()?;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let ip = match bytes.len() {
        4 => std::net::IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
        16 => std::net::IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
        _ => return None,
    };
    Some((SocketAddr::new(ip, port), fields.get(7)?.parse().ok()?))
}

/// At least 256 MiB free where the service home lives (or its
/// nearest existing parent, when the home is not created yet).
fn service_home_disk() -> Check {
    let name = "preflight.disk";
    let mut home = PathBuf::from(native::SERVICE_HOME);
    while !home.exists() {
        match home.parent() {
            Some(parent) => home = parent.to_path_buf(),
            None => break,
        }
    }
    match free_bytes(&home) {
        Ok(free) if disk_ok(free) => Check::pass(
            name,
            format!(
                "{} has {free} bytes free ({} MiB or more required)",
                home.display(),
                MIN_FREE / 1024 / 1024
            ),
        ),
        Ok(free) => Check::fail(
            name,
            format!(
                "{} has {free} bytes free; at least {MIN_FREE} are required",
                home.display()
            ),
        ),
        Err(why) => Check::fail(name, why),
    }
}

/// The free-space threshold.
const MIN_FREE: u64 = 256 * 1024 * 1024;

/// The disk arithmetic behind [`service_home_disk`].
fn disk_ok(free_bytes: u64) -> bool {
    free_bytes >= MIN_FREE
}

#[cfg(unix)]
fn free_bytes(directory: &Path) -> Result<u64, String> {
    let text = std::ffi::CString::new(directory.to_string_lossy().into_owned())
        .map_err(|_| format!("{}: not a plain path", directory.display()))?;
    let mut fs: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(text.as_ptr(), &mut fs) };
    if rc != 0 {
        return Err(format!(
            "statvfs {}: {}",
            directory.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(fs.f_bavail as u64 * fs.f_frsize as u64)
}

#[cfg(not(unix))]
fn free_bytes(directory: &Path) -> Result<u64, String> {
    Err(format!(
        "{}: free space is checked with statvfs, which this platform does not have",
        directory.display()
    ))
}

/// The clock tolerance, in `adjtimex`'s unit (microseconds).
const MAX_CLOCK_ERROR_US: i64 = 5 * 60 * 1_000_000;

/// What one read-only `adjtimex` query reported.
struct KernelClock {
    /// The call's return value, the kernel's clock state (`TIME_*`).
    state: i32,
    /// `STA_UNSYNC` is set in the status word.
    unsynchronized: bool,
    max_error_us: i64,
}

/// The clock check: one read-only `adjtimex` query, no packet.
fn kernel_clock() -> Check {
    match read_kernel_clock() {
        Ok(clock) => clock_verdict(&clock),
        Err(why) => Check::fail("preflight.clock", why),
    }
}

/// The clock arithmetic behind [`kernel_clock`].
fn clock_verdict(clock: &KernelClock) -> Check {
    let name = "preflight.clock";
    let seconds = clock.max_error_us as f64 / 1e6;
    if clock.state == TIME_ERROR || clock.unsynchronized {
        Check::fail(
            name,
            "the kernel reports the clock unsynchronized (adjtimex: TIME_ERROR or STA_UNSYNC); \
             let the host's time daemon synchronize it",
        )
    } else if clock.max_error_us > MAX_CLOCK_ERROR_US {
        Check::fail(
            name,
            format!(
                "the kernel's maximum clock error is {seconds:.3} s; at most {} s is allowed",
                MAX_CLOCK_ERROR_US / 1_000_000
            ),
        )
    } else {
        Check::pass(
            name,
            format!("the kernel reports the clock synchronized, maximum error {seconds:.3} s"),
        )
    }
}

/// `TIME_ERROR` (Linux `<sys/timex.h>`), named here so the verdict is
/// testable on every host.
const TIME_ERROR: i32 = 5;

#[cfg(target_os = "linux")]
// `maxerror` is a `c_long`: already `i64` on 64-bit targets only.
#[allow(clippy::useless_conversion)]
fn read_kernel_clock() -> Result<KernelClock, String> {
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    // `modes` is zero: a query that changes nothing.
    let state = unsafe { libc::adjtimex(&mut timex) };
    if state == -1 {
        return Err(format!("adjtimex: {}", std::io::Error::last_os_error()));
    }
    Ok(KernelClock {
        state,
        unsynchronized: timex.status & libc::STA_UNSYNC != 0,
        max_error_us: i64::from(timex.maxerror),
    })
}

#[cfg(not(target_os = "linux"))]
fn read_kernel_clock() -> Result<KernelClock, String> {
    Err("not checked: the kernel clock state is read with adjtimex, which only Linux has".into())
}

/// A check whose input an earlier failure removed: reported as failed, with
/// the reason it could not run.
fn not_checked(name: impl Into<String>, why: &str) -> Check {
    Check::fail(name, format!("not checked: {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_endian = "little")]
    fn a_listen_row_reads_the_local_address_and_owner() {
        let v4 = "   0: 0100007F:442D 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 41234 1 0000000000000000 100 0 0 10 0";
        assert_eq!(
            listen_row(v4),
            Some(("127.0.0.1:17453".parse().unwrap(), 999))
        );
        let v6 = "   1: 00000000000000000000000001000000:442D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 41235 1 0000000000000000 100 0 0 10 0";
        assert_eq!(listen_row(v6), Some(("[::1]:17453".parse().unwrap(), 999)));
        // ESTABLISHED (01), not a listener.
        assert_eq!(listen_row(&v4.replace(" 0A ", " 01 ")), None);
    }

    #[test]
    fn the_disk_threshold_is_256_mib() {
        assert!(disk_ok(MIN_FREE));
        assert!(disk_ok(MIN_FREE + 1));
        assert!(!disk_ok(MIN_FREE - 1));
    }

    #[test]
    fn the_clock_passes_only_synchronized_within_five_minutes() {
        let clock = |state, unsynchronized, max_error_us| {
            clock_verdict(&KernelClock {
                state,
                unsynchronized,
                max_error_us,
            })
        };
        assert!(clock(0, false, 512_000).passed);
        assert!(clock(0, false, MAX_CLOCK_ERROR_US).passed);
        let over = clock(0, false, MAX_CLOCK_ERROR_US + 1);
        assert!(
            !over.passed && over.message.contains("300 s"),
            "{}",
            over.message
        );
        assert!(!clock(TIME_ERROR, false, 0).passed);
        let unsync = clock(0, true, 0);
        assert!(!unsync.passed && unsync.message.contains("unsynchronized"));
        assert_eq!(unsync.name, "preflight.clock");
    }

    #[test]
    fn not_checked_fails_and_carries_its_exit_class_and_reason() {
        let check = not_checked(
            "preflight.listener.data_plane",
            "the configuration did not load",
        );
        assert!(!check.passed);
        assert!(check.name.starts_with("preflight."));
        assert!(
            check
                .message
                .starts_with("not checked: the configuration did not load"),
            "{}",
            check.message
        );
    }
}
