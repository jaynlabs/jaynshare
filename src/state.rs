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

/// Replaces `path`'s ACL with a protected one granting full control to the
/// current user and `SYSTEM` alone, then reads it back and fails closed
/// unless exactly those entries remain. Principals are compared as SIDs,
/// so neither the display language nor an elevated token's default
/// `Administrators` entry changes the outcome.
#[cfg(windows)]
pub fn protect_windows(path: &Path) -> Result<(), String> {
    windows_acl::restrict(path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(windows)]
mod windows_acl {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{addr_of, null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
        CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetLengthSid, GetTokenInformation, INHERITED_ACE, InitializeAcl, OBJECT_INHERIT_ACE,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// A SID copied into a buffer aligned for the API to read in place.
    struct Sid(Vec<u32>);

    impl Sid {
        fn copied(sid: PSID) -> Self {
            // SAFETY: `sid` is a valid SID, so its length covers its bytes.
            let length = unsafe { GetLengthSid(sid) } as usize;
            let mut buffer = vec![0u32; length.div_ceil(4)];
            // SAFETY: both regions hold `length` bytes and do not overlap.
            unsafe {
                std::ptr::copy_nonoverlapping(sid.cast::<u8>(), buffer.as_mut_ptr().cast(), length)
            };
            Sid(buffer)
        }

        fn psid(&self) -> PSID {
            self.0.as_ptr().cast_mut().cast()
        }

        fn len(&self) -> usize {
            // SAFETY: the buffer holds a valid SID.
            unsafe { GetLengthSid(self.psid()) as usize }
        }
    }

    pub(super) fn restrict(path: &Path) -> Result<(), String> {
        let user = current_user()?;
        let system = local_system()?;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut acl = private_acl(&user, &system, path.is_dir())?;
        // SAFETY: `wide` is NUL-terminated and `acl` is an initialized ACL.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl.as_mut_ptr().cast(),
                null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "cannot restrict its ACL: {}",
                io::Error::from_raw_os_error(status as i32)
            ));
        }
        read_back(&wide, &user, &system)
    }

    fn current_user() -> Result<Sid, String> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the pseudo handle of this process needs no closing.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(format!(
                "cannot open the process token: {}",
                io::Error::last_os_error()
            ));
        }
        let mut size = 0u32;
        // SAFETY: a null buffer of size 0 only asks for the size.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size) };
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buffer` holds `size` bytes, aligned for `TOKEN_USER`.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        };
        let failure = io::Error::last_os_error();
        // SAFETY: `token` was opened above.
        unsafe { CloseHandle(token) };
        if read == 0 {
            return Err(format!("cannot read the process user: {failure}"));
        }
        // SAFETY: the call filled `buffer` with a `TOKEN_USER`.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        Ok(Sid::copied(user.User.Sid))
    }

    fn local_system() -> Result<Sid, String> {
        let mut buffer = vec![0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
        let mut size = SECURITY_MAX_SID_SIZE;
        // SAFETY: `buffer` holds `size` bytes.
        let made = unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if made == 0 {
            return Err(format!(
                "cannot name SYSTEM: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(Sid(buffer))
    }

    /// An ACL of two full-control entries; a directory's entries also
    /// apply to what is created inside it.
    fn private_acl(user: &Sid, system: &Sid, directory: bool) -> Result<Vec<u32>, String> {
        let flags = if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        // Each entry's SID replaces the `SidStart` placeholder in place.
        let entry = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
        let size = size_of::<ACL>() + 2 * entry + user.len() + system.len();
        let mut acl = vec![0u32; size.div_ceil(4)];
        let pointer = acl.as_mut_ptr().cast::<ACL>();
        // SAFETY: `acl` holds `size` bytes, aligned for `ACL`.
        if unsafe { InitializeAcl(pointer, (acl.len() * 4) as u32, ACL_REVISION) } == 0 {
            return Err(format!(
                "cannot build an ACL: {}",
                io::Error::last_os_error()
            ));
        }
        for sid in [user, system] {
            // SAFETY: `pointer` is an initialized ACL with room for the entry.
            let added = unsafe {
                AddAccessAllowedAceEx(pointer, ACL_REVISION, flags, FILE_ALL_ACCESS, sid.psid())
            };
            if added == 0 {
                return Err(format!(
                    "cannot build an ACL: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        Ok(acl)
    }

    fn read_back(wide: &[u16], user: &Sid, system: &Sid) -> Result<(), String> {
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is NUL-terminated; the outputs are written on success.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "cannot read its ACL back: {}",
                io::Error::from_raw_os_error(status as i32)
            ));
        }
        let verdict = judge(dacl, user, system);
        // SAFETY: the descriptor was allocated by the call above.
        unsafe { LocalFree(descriptor) };
        verdict
    }

    /// Every entry must allow the user or `SYSTEM` and none be inherited.
    fn judge(dacl: *const ACL, user: &Sid, system: &Sid) -> Result<(), String> {
        if dacl.is_null() {
            return Err("it has no ACL, which grants everyone access".into());
        }
        // SAFETY: a non-null DACL from the descriptor is valid while it lives.
        let count = unsafe { (*dacl).AceCount };
        for index in 0..u32::from(count) {
            let mut entry: *mut c_void = null_mut();
            // SAFETY: `index` is below the entry count.
            if unsafe { GetAce(dacl, index, &mut entry) } == 0 {
                return Err(format!(
                    "cannot read its ACL: {}",
                    io::Error::last_os_error()
                ));
            }
            // SAFETY: every entry starts with an `ACE_HEADER`.
            let header = unsafe { &*entry.cast::<ACE_HEADER>() };
            if u32::from(header.AceFlags) & INHERITED_ACE != 0 {
                return Err("an inherited access entry remains".into());
            }
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                return Err(format!(
                    "an access entry of type {} remains",
                    header.AceType
                ));
            }
            // SAFETY: an access-allowed entry carries its SID at `SidStart`.
            let sid: PSID = unsafe { addr_of!((*entry.cast::<ACCESS_ALLOWED_ACE>()).SidStart) }
                .cast_mut()
                .cast();
            // SAFETY: all three are valid SIDs.
            let known =
                unsafe { EqualSid(sid, user.psid()) != 0 || EqualSid(sid, system.psid()) != 0 };
            if !known {
                return Err(format!("the ACL grants access to {}", sid_text(sid)));
            }
        }
        Ok(())
    }

    fn sid_text(sid: PSID) -> String {
        let mut text: *mut u16 = null_mut();
        // SAFETY: `sid` is valid; the string is allocated on success.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return "an unreadable SID".into();
        }
        // SAFETY: the string is NUL-terminated.
        let length = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        // SAFETY: `length` units precede the NUL.
        let owned = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        // SAFETY: allocated by `ConvertSidToStringSidW`.
        unsafe { LocalFree(text.cast()) };
        owned
    }
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
}
