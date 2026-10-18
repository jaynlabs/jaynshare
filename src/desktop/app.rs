//! Compatibility checks against the installed app and its verified managed CLI.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tokio::process::Command;
use tokio::sync::OnceCell;

use super::{bundle, compatibility, config};

/// Generous: the first run of a freshly installed binary waits for macOS's
/// security scan.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

type Stamp = (u64, SystemTime);

pub struct App {
    pub bundle: PathBuf,
    runtime: OnceCell<(PathBuf, Vec<(PathBuf, Stamp)>)>,
    version: String,
    expected_runtime: bundle::Runtime,
    stamps: Vec<(PathBuf, Stamp)>,
}

pub fn bundle() -> Result<PathBuf, String> {
    [
        crate::config::platform::home().join("Applications/Claude.app"),
        PathBuf::from("/Applications/Claude.app"),
    ]
    .into_iter()
    .find(|path| path.is_dir())
    .ok_or_else(|| "install Claude Desktop in /Applications or ~/Applications first".into())
}

impl App {
    pub async fn resolve() -> Result<Self, String> {
        if std::env::var_os("CLAUDE_USER_DATA_DIR").is_some() {
            return Err(
                "custom Claude Desktop profile paths are unsupported; unset CLAUDE_USER_DATA_DIR"
                    .into(),
            );
        }
        policy().await?;
        let bundle = bundle()?;
        let plist = bundle.join("Contents/Info.plist");
        let version = output(
            Command::new("/usr/bin/plutil")
                .args(["-extract", "CFBundleShortVersionString", "raw", "-o", "-"])
                .arg(&plist),
        )
        .await?;
        let archive = bundle.join("Contents/Resources/app.asar");
        let stamps = [plist, archive.clone()]
            .into_iter()
            .map(|path| stamp(&path).map(|stamp| (path, stamp)))
            .collect::<Result<_, _>>()?;
        let expected_runtime = bundle::runtime(&archive)?;
        let app = Self {
            bundle,
            runtime: OnceCell::new(),
            version,
            expected_runtime,
            stamps,
        };
        app.unchanged()?;
        if app.find_runtime()?.is_some() {
            app.runtime().await?;
        }
        Ok(app)
    }

    pub async fn runtime(&self) -> Result<&Path, String> {
        self.runtime.get_or_try_init(|| async {
            let runtime = self.find_runtime()?.ok_or("Desktop's managed runtime is still provisioning through the proxy; retry after its download finishes")?;
            let marker = runtime
                .ancestors()
                .nth(4)
                .expect("managed bundle")
                .join(".verified");
            let stamps: Vec<_> = [runtime.clone(), marker]
                .into_iter()
                .map(|path| stamp(&path).map(|stamp| (path, stamp)))
                .collect::<Result<_, _>>()?;
            let actual = output(
                Command::new(&runtime)
                    .arg("--version")
                    .env_clear()
                    .env("HOME", crate::config::platform::home())
                    .env("PATH", "/usr/bin:/bin"),
            )
            .await?;
            if actual.split_whitespace().next() != Some(self.expected_runtime.version.as_str()) {
                return Err(format!(
                    "the managed Claude Code runtime is incompatible; expected {}",
                    self.expected_runtime.version
                ));
            }
            compatibility::check(&runtime).await?;
            if stamps
                .iter()
                .any(|(path, before)| stamp(path).as_ref() != Ok(before))
            {
                return Err(
                    "Desktop's managed runtime changed during its compatibility check".into(),
                );
            }
            Ok::<_, String>((runtime, stamps))
        }).await?;
        self.unchanged()?;
        Ok(&self.runtime.get().expect("verified runtime").0)
    }

    pub fn unchanged(&self) -> Result<(), String> {
        if self
            .stamps
            .iter()
            .any(|(path, before)| stamp(path).as_ref() != Ok(before))
            || self.runtime.get().is_some_and(|(path, stamps)| {
                stamps
                    .iter()
                    .any(|(file, before)| stamp(file).as_ref() != Ok(before))
                    || self.find_runtime().as_ref() != Ok(&Some(path.clone()))
            })
        {
            return Err(format!(
                "Claude Desktop {} or its runtime changed; quit Desktop fully and restart `jaynshare desktop` for a compatibility check",
                self.version
            ));
        }
        Ok(())
    }

    fn find_runtime(&self) -> Result<Option<PathBuf>, String> {
        let expected = &self.expected_runtime;
        let directory = config::profile()
            .join("claude-code")
            .join(&expected.version);
        let managed = directory.join(&expected.checksum[..12]);
        let binary = managed.join("claude.app/Contents/MacOS/claude");
        let marker = managed.join(".verified");
        if !binary.is_file() || !marker.is_file() {
            return Ok(None);
        }
        if std::fs::metadata(&marker).map_err(|e| e.to_string())?.len() > 128 {
            return Err("Desktop's managed runtime verification marker is invalid".into());
        }
        if std::fs::read_to_string(marker)
            .map_err(|e| e.to_string())?
            .trim()
            != expected.checksum
        {
            return Err(
                "Desktop's managed runtime verification does not match its bundled manifest".into(),
            );
        }
        Ok(Some(binary))
    }

    pub async fn open(&self, ca: &Path) -> Result<(), String> {
        output(
            Command::new("open")
                .arg("--env")
                .arg(format!("NODE_EXTRA_CA_CERTS={}", ca.display()))
                .arg(&self.bundle),
        )
        .await
        .map(|_| ())
    }
}

fn stamp(path: &Path) -> Result<Stamp, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((
        metadata.len(),
        metadata.modified().map_err(|e| e.to_string())?,
    ))
}

pub async fn running(bundle: &Path) -> Result<bool, String> {
    let path = bundle.join("Contents/MacOS/Claude");
    let result = tokio::time::timeout(
        COMMAND_TIMEOUT,
        Command::new("pgrep")
            .args(["-f", "-l"])
            .arg(path)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "checking the running Desktop app timed out")?
    .map_err(|e| e.to_string())?;
    match result.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err("could not check whether Desktop is running".into()),
    }
}

async fn policy() -> Result<(), String> {
    let user = output(Command::new("/usr/bin/id").arg("-un")).await?;
    let policies = [
        PathBuf::from("/Library/Managed Preferences/com.anthropic.claudefordesktop.plist"),
        PathBuf::from(format!(
            "/Library/Managed Preferences/{user}/com.anthropic.claudefordesktop.plist"
        )),
        PathBuf::from("/Library/Managed Preferences/com.anthropic.claudecode.plist"),
        PathBuf::from(format!(
            "/Library/Managed Preferences/{user}/com.anthropic.claudecode.plist"
        )),
        PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json"),
        PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.d"),
    ];
    if policies.iter().any(|p| p.exists()) || std::env::var_os("CLAUDE_E2E_MANAGED_PLIST").is_some()
    {
        return Err("Claude has managed policy on this Mac; ask its administrator to configure Gateway access".into());
    }
    Ok(())
}

async fn output(command: &mut Command) -> Result<String, String> {
    let result = tokio::time::timeout(COMMAND_TIMEOUT, command.kill_on_drop(true).output())
        .await
        .map_err(|_| "Desktop compatibility command timed out")?
        .map_err(|e| e.to_string())?;
    if !result.status.success() || result.stdout.len() > 4096 {
        return Err("Desktop compatibility command failed".into());
    }
    String::from_utf8(result.stdout)
        .map(|s| s.trim().to_string())
        .map_err(|_| "invalid Desktop version output".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "uses the installed macOS Desktop bundle and managed runtime"]
    async fn installed_runtime_passes_local_streaming_check() {
        let app = App::resolve()
            .await
            .expect("installed Desktop compatibility");
        app.runtime()
            .await
            .expect("managed runtime streaming check");
    }
}
