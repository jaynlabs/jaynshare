//! Compatibility checks against the installed app and its verified managed CLI.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tokio::process::Command;

use super::config;

type Stamp = (u64, SystemTime);

pub struct App {
    pub bundle: PathBuf,
    pub runtime: PathBuf,
    version: String,
    runtime_version: &'static str,
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
        // shortcut: this private profile format is checked only on these versions; recheck the native app before adding versions.
        let runtime_version = match version.as_str() {
            "2.26454.0" => "2.1.289",
            "2.26454.2" | "2.31226.0" => "2.1.293",
            _ => {
                return Err(format!(
                    "Claude Desktop {version} has not been checked; supported versions: 2.26454.0, 2.26454.2 and 2.31226.0"
                ));
            }
        };
        let runtime = runtime(runtime_version)?;
        let actual = output(
            Command::new(&runtime)
                .arg("--version")
                .env_clear()
                .env("HOME", crate::config::platform::home())
                .env("PATH", "/usr/bin:/bin"),
        )
        .await?;
        if actual.split_whitespace().next() != Some(runtime_version) {
            return Err(format!(
                "the managed Claude Code runtime is incompatible; expected {runtime_version}"
            ));
        }
        let marker = runtime
            .ancestors()
            .nth(4)
            .expect("managed bundle")
            .join(".verified");
        let stamps = [
            plist,
            bundle.join("Contents/Resources/app.asar"),
            runtime.clone(),
            marker,
        ]
        .into_iter()
        .map(|path| stamp(&path).map(|stamp| (path, stamp)))
        .collect::<Result<_, _>>()?;
        Ok(Self {
            bundle,
            runtime,
            version,
            runtime_version,
            stamps,
        })
    }

    pub fn unchanged(&self) -> Result<(), String> {
        if self
            .stamps
            .iter()
            .any(|(path, before)| stamp(path).as_ref() != Ok(before))
            || runtime(self.runtime_version).as_ref() != Ok(&self.runtime)
        {
            return Err(format!(
                "Claude Desktop {} or its runtime changed; quit Desktop fully and restart `jaynshare desktop` for a compatibility check",
                self.version
            ));
        }
        Ok(())
    }

    pub async fn open(&self) -> Result<(), String> {
        output(Command::new("open").arg(&self.bundle))
            .await
            .map(|_| ())
    }
}

fn runtime(version: &str) -> Result<PathBuf, String> {
    let directory = config::profile().join("claude-code").join(version);
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(&directory).map_err(|_| "Desktop's managed Claude Code runtime is missing; open Desktop once to finish its installation, then quit it fully")? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let binary = path.join("claude.app/Contents/MacOS/claude");
        if path.join(".verified").is_file() && binary.is_file() {
            candidates.push(binary);
        }
    }
    if candidates.len() != 1 {
        return Err("Desktop's active verified runtime is missing or ambiguous; finish its installation before Gateway setup".into());
    }
    Ok(candidates.remove(0))
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
        Duration::from_secs(2),
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
    let result = tokio::time::timeout(Duration::from_secs(3), command.kill_on_drop(true).output())
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
