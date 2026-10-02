//! A scratch home stands in for the whole user profile. On Windows the
//! product finds the profile's folders through `USERPROFILE`, `APPDATA` and
//! `LOCALAPPDATA`, but edits the user `Path` in the registry through
//! `powershell.exe`, which no variable redirects. So an isolated child gets
//! a fake `powershell` first on a search path that misses the real one: it
//! lives below `System32`, and Windows looks for a bare program name only in
//! the executable's folder, `System32` and the Windows folder before `PATH`.

use std::path::{Path, PathBuf};

use crate::fake_tools::FakeTools;

/// The fake `powershell` of the profile under `home`, recording every call.
pub(crate) fn path_editor(home: &Path) -> FakeTools {
    FakeTools::new(home, &["powershell"])
}

/// The Windows variables that move the profile under `home`.
pub(crate) fn windows_profile(home: &Path) -> Vec<(String, String)> {
    vec![
        ("USERPROFILE".into(), home.display().to_string()),
        (
            "APPDATA".into(),
            crate::client_fx::roaming(home).display().to_string(),
        ),
        (
            "LOCALAPPDATA".into(),
            local_app_data(home).display().to_string(),
        ),
    ]
}

/// The profile's local folder (`LOCALAPPDATA`).
pub(crate) fn local_app_data(home: &Path) -> PathBuf {
    home.join("AppData").join("Local")
}
