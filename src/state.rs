//! The state file: one JSON object with five top-level keys, written atomically
//! and read once at start.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::pool::Account;
use crate::registry::{OperatorEntry, RegistryEntry};

pub const STATE_VERSION: u64 = 1;
const KEYS: [&str; 5] = [
    "version",
    "accounts",
    "organization_quota",
    "clients",
    "operator",
];

/// The durable set. Members other than accounts are carried through
/// unchanged, owned by their later work.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {
    pub accounts: Vec<Account>,
    pub organization_quota: Vec<Value>,
    pub clients: Vec<RegistryEntry>,
    pub operator: Option<OperatorEntry>,
}

impl State {
    pub fn to_json(&self) -> Value {
        json!({
            "version": STATE_VERSION,
            "accounts": self.accounts.iter().map(Account::to_record).collect::<Vec<_>>(),
            "organization_quota": self.organization_quota,
            "clients": self.clients,
            "operator": self.operator,
        })
    }

    /// Invalid JSON, another version or an invalid record is an error; the file is never touched.
    pub fn from_json(value: Value) -> Result<Self, String> {
        let Value::Object(mut map) = value else {
            return Err("state is not a JSON object".into());
        };
        let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = KEYS.to_vec();
        expected.sort_unstable();
        if keys != expected {
            return Err(format!(
                "state must have exactly the keys {KEYS:?}, found {keys:?}"
            ));
        }
        if map.get("version") != Some(&json!(STATE_VERSION)) {
            return Err(format!(
                "unsupported state version (expected {STATE_VERSION})"
            ));
        }
        let accounts = match map.remove("accounts") {
            Some(Value::Array(records)) => records
                .iter()
                .enumerate()
                .map(|(i, r)| Account::from_record(r).map_err(|e| format!("accounts[{i}]: {e}")))
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("accounts must be an array".into()),
        };
        let array = |v: Option<Value>, name: &str| match v {
            Some(Value::Array(a)) => Ok(a),
            _ => Err(format!("{name} must be an array")),
        };
        let organization_quota = array(map.remove("organization_quota"), "organization_quota")?;
        let clients = array(map.remove("clients"), "clients")?
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                serde_json::from_value::<RegistryEntry>(v).map_err(|e| format!("clients[{i}]: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let operator = match map.remove("operator") {
            Some(Value::Null) | None => None,
            Some(value @ Value::Object(_)) => Some(
                serde_json::from_value::<OperatorEntry>(value)
                    .map_err(|e| format!("operator: {e}"))?,
            ),
            Some(_) => return Err("operator must be an object or null".into()),
        };
        Ok(Self {
            accounts,
            organization_quota,
            clients,
            operator,
        })
    }
}

/// A missing file is an empty pool.
pub fn load(path: &Path) -> Result<State, String> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("cannot parse {}: invalid JSON: {e}", path.display()))?;
    State::from_json(value).map_err(|e| format!("cannot load {}: {e}", path.display()))
}

/// The state file's mtime stands in for its last successful write.
pub fn last_write(path: &Path) -> Option<OffsetDateTime> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()
        .map(OffsetDateTime::from)
}

pub fn write(path: &Path, state: &State) -> io::Result<()> {
    write_private_atomic(path, &serde_json::to_vec_pretty(&state.to_json())?)
}

/// Temporary file in the same directory, mode 0600, fsync, rename, directory fsync.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    if !dir.exists() {
        ensure_private_dir(dir)?;
    }
    // An existing directory keeps the operator's mode: a deliberately
    // unwritable directory must fail the write, not be chmod'ed back.
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state.json");
    let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
    {
        let mut f = open_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    // The replaced file keeps its private ACL on Windows (the
    // renamed file inherits its parent's grant otherwise).
    #[cfg(windows)]
    crate::state::protect_windows(path).map_err(io::Error::other)?;
    Ok(())
}

pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    // Only the components we create are tightened to 0700; an existing
    // directory keeps its mode so a broad one is caught by check_private
    // and refused, not silently healed.
    if dir.exists() {
        return Ok(());
    }
    let mut built = std::path::PathBuf::new();
    for component in dir.components() {
        built.push(component);
        if built.exists() {
            continue;
        }
        fs::create_dir(&built)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&built, fs::Permissions::from_mode(0o700))?;
        }
        // The Windows ACL replaces the inherited one on every
        // component we create.
        #[cfg(windows)]
        crate::state::protect_windows(&built).map_err(io::Error::other)?;
    }
    Ok(())
}

/// Creates or truncates `path` with mode 0600.
pub fn open_private(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let f = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

/// Opens `path` for appending with mode 0600, creating it if absent.
pub fn open_private_append(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// An existing path's mode as `0600`-style text; `None` when it
/// does not exist or the platform has no mode (Windows ACL summaries land
/// on Windows).
pub fn mode_summary(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).ok()?;
        return Some(format!("{:04o}", meta.permissions().mode() & 0o777));
    }
    #[allow(unreachable_code)]
    {
        let _ = path;
        None
    }
}

/// Refuse a secret-bearing existing file or directory broader than owner-only.
/// On Windows: reduces `path`'s ACL to the installing
/// user's SID and `SYSTEM` (inheritance removed), then verifies that no
/// other access entry remains; fails closed when protection cannot be
#[cfg(windows)]
pub fn protect_windows(path: &Path) -> Result<(), String> {
    let (user_name, user_sid) = windows_user()?;
    let flags = if path.is_dir() { ":(OI)(CI)F" } else { ":F" };
    let user_flags = format!("*{user_sid}{flags}");
    let system_flags = format!("*S-1-5-18{flags}");
    let out = icacls(&[
        path.as_os_str(),
        std::ffi::OsStr::new("/inheritance:r"),
        std::ffi::OsStr::new("/grant:r"),
        std::ffi::OsStr::new(&user_flags),
        std::ffi::OsStr::new(&system_flags),
    ])?;
    if !out.status.success() {
        return Err(format!(
            "icacls could not restrict {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // Read the result back and fail closed unless only the user and
    // `SYSTEM` remain (inherited entries included).
    let read = icacls(&[path.as_os_str()])?;
    if !read.status.success() {
        return Err(format!(
            "icacls could not read {}: {}",
            path.display(),
            String::from_utf8_lossy(&read.stderr).trim()
        ));
    }
    judge_acl(
        &String::from_utf8_lossy(&read.stdout),
        &user_sid,
        &user_name,
    )
    .map_err(|e| format!("{}: {e}", path.display()))
}

/// The one `icacls` wrapper (the test suite's fake answers it).
#[cfg(windows)]
pub fn icacls(args: &[&std::ffi::OsStr]) -> Result<std::process::Output, String> {
    std::process::Command::new("icacls")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("icacls: {e}"))
}

/// The current user's name and SID (the ACL grant targets), through
/// `whoami /user /fo csv /nh` (`"host\\user","S-1-…"`).
#[cfg(windows)]
fn windows_user() -> Result<(String, String), String> {
    let out = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("whoami: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "whoami /user failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let row = String::from_utf8_lossy(&out.stdout);
    let row = row.trim().trim_matches('"');
    let mut fields = row.split("\",\"");
    let name = fields
        .next()
        .ok_or_else(|| format!("whoami /user gave no user: {row}"))?
        .trim()
        .to_owned();
    let sid = fields
        .next()
        .ok_or_else(|| format!("whoami /user gave no SID: {row}"))?
        .trim()
        .to_owned();
    Ok((name, sid))
}

/// The read-back judge: every access entry must be the user (by SID or
/// name, case-insensitive, host prefix optional) or `NT AUTHORITY\SYSTEM`
/// (`*S-1-5-18`); an inherited `(I)` entry means the inheritance removal did
/// not happen. Any other entry fails, naming it. Pure so unit tests run it on
/// every OS.
#[cfg(any(test, windows))]
fn judge_acl(readback: &str, user_sid: &str, user_name: &str) -> Result<(), String> {
    fn tail(s: &str) -> &str {
        s.rfind('\\').map(|i| &s[i + 1..]).unwrap_or(s)
    }
    let user_allowed = |principal: &str| {
        principal.eq_ignore_ascii_case(user_sid)
            || principal.eq_ignore_ascii_case(user_name)
            || tail(principal).eq_ignore_ascii_case(tail(user_name))
    };
    let system_allowed = |principal: &str| {
        principal.eq_ignore_ascii_case("NT AUTHORITY\\SYSTEM") || principal == "*S-1-5-18"
    };
    for line in readback.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("Successfully processed") {
            break;
        }
        // ACE lines end the principal with `:(`; the first line is the path.
        let Some(at) = line.find(":(") else {
            continue;
        };
        let principal = line[..at].trim();
        if line[at..].contains("(I)") {
            return Err(format!("an inherited access entry for {principal} remains"));
        }
        if !user_allowed(principal) && !system_allowed(principal) {
            return Err(format!("the ACL grants access to {principal}"));
        }
    }
    Ok(())
}

pub fn check_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = fs::metadata(path) else {
            return Ok(());
        };
        let mode = meta.permissions().mode() & 0o777;
        let limit = if meta.is_dir() { 0o700 } else { 0o600 };
        if mode & !limit != 0 {
            return Err(format!(
                "{} is mode {mode:o}; must be {limit:o} or narrower",
                path.display()
            ));
        }
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{Credential, Profile, Secret, Source};

    #[test]
    fn round_trip_keeps_exactly_five_keys() {
        let state = State {
            accounts: vec![Account::new(
                "k".into(),
                Profile::default(),
                Source::ApiKeyEntry,
                Credential::ApiKey(Secret::new("sk".into())),
            )],
            ..State::default()
        };
        let json = state.to_json();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "accounts",
                "clients",
                "operator",
                "organization_quota",
                "version"
            ]
        );
        assert_eq!(State::from_json(json).unwrap(), state);
    }

    #[test]
    fn extra_key_or_wrong_version_fails() {
        let mut json = State::default().to_json();
        json["sessions"] = json!([]);
        assert!(State::from_json(json).is_err());
        let mut json = State::default().to_json();
        json["version"] = json!(2);
        assert!(State::from_json(json).is_err());
    }

    #[test]
    fn registry_entries_round_trip_and_bad_ones_fail_startup() {
        let mut registry = crate::registry::Registry::default();
        let (code, _) = registry
            .issue("mac", "Mac", OffsetDateTime::UNIX_EPOCH, 60)
            .unwrap();
        registry
            .claim("mac", &code, OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        registry.revoke("mac", OffsetDateTime::UNIX_EPOCH).unwrap();
        let state = State {
            clients: registry.clients,
            ..State::default()
        };
        let json = state.to_json();
        assert_eq!(State::from_json(json.clone()).unwrap(), state);
        // An extra field or a wrong state fails startup.
        let mut broken = json.clone();
        broken["clients"][0]["disabled"] = json!(false);
        assert!(State::from_json(broken).is_err());
        let mut broken = json;
        broken["clients"][0]["state"] = json!("disabled");
        assert!(State::from_json(broken).is_err());
    }

    #[test]
    fn missing_file_is_empty_and_write_is_private() {
        let dir = std::env::temp_dir().join(format!("jaynshare-state-{}", uuid::Uuid::new_v4()));
        let path = dir.join("state.json");
        assert_eq!(load(&path).unwrap(), State::default());
        write(&path, &State::default()).unwrap();
        assert_eq!(load(&path).unwrap(), State::default());
        check_private(&path).unwrap();
        check_private(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(check_private(&path).is_err());
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    // unix-runnable: the `icacls` read-back judge accepts
    // exactly the user and `NT AUTHORITY\SYSTEM`, and names anything else.
    const PRIVATE_READBACK: &str = concat!(
        "C:\\Users\\max\\AppData\\Jaynshare\\client\\client-secret\n",
        "DESKTOP-ABC\\max:(F)\n",
        "NT AUTHORITY\\SYSTEM:(F)\n",
        "\n",
        "Successfully processed 1 files; Failed processing 0 files\n",
    );

    #[test]
    fn judge_acl_accepts_exactly_the_user_and_system() {
        judge_acl(PRIVATE_READBACK, "S-1-5-21-1-2-3-1001", "DESKTOP-ABC\\max")
            .expect("the user and SYSTEM alone are private");
        // The bare user name (no host prefix) is the same principal.
        judge_acl(PRIVATE_READBACK, "S-1-5-21-1-2-3-1001", "max")
            .expect("the user is the same principal without the host");
    }

    #[test]
    fn judge_acl_names_an_extra_entry() {
        let open = "BUILTIN\\Users:(RX)";
        let readback =
            PRIVATE_READBACK.replace("\nSuccessfully", &format!("\n{open}\nSuccessfully"));
        let err = judge_acl(&readback, "S-1-5-21-1-2-3-1001", "DESKTOP-ABC\\max")
            .expect_err("BUILTIN\\Users is an extra principal");
        assert!(err.contains("BUILTIN\\Users"), "{err}");
    }

    #[test]
    fn judge_acl_refuses_an_inherited_entry() {
        let inherited = PRIVATE_READBACK
            .replace("DESKTOP-ABC\\max:(F)", "DESKTOP-ABC\\max:(I)(F)")
            .replace("NT AUTHORITY\\SYSTEM:(F)", "NT AUTHORITY\\SYSTEM:(I)(F)");
        let err = judge_acl(&inherited, "S-1-5-21-1-2-3-1001", "DESKTOP-ABC\\max")
            .expect_err("inherited entries mean the inheritance removal failed");
        assert!(err.contains("inherited access entry"), "{err}");
    }
}
