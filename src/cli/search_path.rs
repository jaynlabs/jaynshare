//! The installed client on the user's search path: a link in `~/.local/bin`
//! on macOS, the executable's folder in the user `PATH` on Windows. `join`
//! puts it there and `uninstall` takes it off.

use std::path::{Path, PathBuf};

/// What `join` reports: where the command is found, and whether this
/// shell's `PATH` already reaches it.
pub(super) struct Linked {
    pub(super) path: PathBuf,
    pub(super) on_path: bool,
}

fn on_path(directory: &Path) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|entry| entry == directory))
}

#[cfg(unix)]
fn link_path() -> PathBuf {
    crate::config::platform::home().join(".local/bin/jaynshare")
}

/// Links `binary` as `~/.local/bin/jaynshare`. A file or a link to anything
/// else already there is another `jaynshare`, left in place.
#[cfg(unix)]
pub(super) fn link(binary: &Path) -> Result<Linked, String> {
    let link = link_path();
    let directory = link.parent().expect("the link has a directory");
    std::fs::create_dir_all(directory).map_err(|e| format!("{}: {e}", directory.display()))?;
    match std::fs::read_link(&link) {
        Ok(target) if target == binary => {}
        Ok(target) if target.exists() => {
            return Err(format!(
                "{} already runs {}; left in place",
                link.display(),
                target.display()
            ));
        }
        Ok(_) => {
            std::fs::remove_file(&link).map_err(|e| format!("{}: {e}", link.display()))?;
            std::os::unix::fs::symlink(binary, &link)
                .map_err(|e| format!("{}: {e}", link.display()))?;
        }
        Err(_) if link.symlink_metadata().is_ok() => {
            return Err(format!("{} is another file; left in place", link.display()));
        }
        Err(_) => std::os::unix::fs::symlink(binary, &link)
            .map_err(|e| format!("{}: {e}", link.display()))?,
    }
    Ok(Linked {
        on_path: on_path(directory),
        path: link,
    })
}

/// Removes the link when it is `binary`'s.
#[cfg(unix)]
pub(super) fn unlink(binary: &Path) -> Option<PathBuf> {
    let link = link_path();
    let ours = std::fs::read_link(&link).is_ok_and(|target| target == binary);
    (ours && std::fs::remove_file(&link).is_ok()).then_some(link)
}

/// Runs a PowerShell script with the executable's folder in
/// `JAYNSHARE_DIRECTORY`, so no path is ever quoted into the script.
#[cfg(windows)]
fn user_path(script: &str, directory: &Path) -> Result<(), String> {
    let status = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("JAYNSHARE_DIRECTORY", directory)
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("powershell.exe: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("powershell.exe exited with {status}"))
    }
}

#[cfg(windows)]
const ADD: &str = "$d = $env:JAYNSHARE_DIRECTORY; \
    $p = @([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ }); \
    if ($p -notcontains $d) { [Environment]::SetEnvironmentVariable('Path', (($p + $d) -join ';'), 'User') }";

#[cfg(windows)]
const REMOVE: &str = "$d = $env:JAYNSHARE_DIRECTORY; \
    $p = @([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ }); \
    if ($p -contains $d) { [Environment]::SetEnvironmentVariable('Path', (($p | Where-Object { $_ -ne $d }) -join ';'), 'User') }";

/// Adds `binary`'s folder to the user `PATH`, which new terminals read.
#[cfg(windows)]
pub(super) fn link(binary: &Path) -> Result<Linked, String> {
    let directory = binary.parent().expect("the executable has a folder");
    user_path(ADD, directory)?;
    Ok(Linked {
        on_path: on_path(directory),
        path: binary.to_path_buf(),
    })
}

/// Takes `binary`'s folder off the user `PATH`; `uninstall` reports the
/// folder itself.
#[cfg(windows)]
pub(super) fn unlink(binary: &Path) -> Option<PathBuf> {
    let _ = user_path(REMOVE, binary.parent()?);
    None
}
