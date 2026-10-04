//! The binary reports its full source commit and Rust target.

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg_attr(test, allow(dead_code))]
fn main() {
    let commit = std::env::var("JAYNSHARE_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "0000000000000000000000000000000000000000".into());
    println!("cargo:rustc-env=JAYNSHARE_COMMIT={commit}");
    println!(
        "cargo:rustc-env=JAYNSHARE_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    println!("cargo:rerun-if-env-changed=JAYNSHARE_COMMIT");
    println!("cargo:rerun-if-changed=build.rs");
    if let Ok(directories) = Command::new("git")
        .args(["rev-parse", "--git-dir", "--git-common-dir"])
        .output()
        && directories.status.success()
    {
        let directories = String::from_utf8_lossy(&directories.stdout);
        let mut directories = directories.lines();
        if let (Some(git_dir), Some(common_dir)) = (directories.next(), directories.next()) {
            for path in git_inputs(Path::new(git_dir), Path::new(common_dir)) {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

fn git_inputs(git_dir: &Path, common_dir: &Path) -> Vec<PathBuf> {
    let head = git_dir.join("HEAD");
    let mut paths = vec![head.clone(), common_dir.join("packed-refs")];
    if let Ok(head) = std::fs::read_to_string(head)
        && let Some(reference) = head.trim().strip_prefix("ref: ")
    {
        let reference = common_dir.join(reference);
        // A packed or unborn branch can acquire its first loose ref.
        paths.push(if reference.is_file() {
            reference
        } else {
            common_dir.join("refs")
        });
    }
    // Cargo treats a missing watched file as changed on every invocation.
    paths.retain(|path| path.exists());
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_watches_cover_worktrees_without_missing_files() {
        let root = std::env::temp_dir().join(format!(
            "jaynshare-git-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let git_dir = root.join("worktree");
        let common_dir = root.join("common");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::create_dir_all(common_dir.join("refs/heads")).unwrap();
        let head = git_dir.join("HEAD");
        std::fs::write(&head, "detached-commit\n").unwrap();
        assert_eq!(
            git_inputs(&git_dir, &common_dir),
            std::slice::from_ref(&head)
        );

        std::fs::write(&head, "ref: refs/heads/main\n").unwrap();
        assert_eq!(
            git_inputs(&git_dir, &common_dir),
            [head.clone(), common_dir.join("refs")]
        );
        let reference = common_dir.join("refs/heads/main");
        std::fs::write(&reference, "first-commit\n").unwrap();
        assert_eq!(
            git_inputs(&git_dir, &common_dir),
            [head.clone(), reference.clone()]
        );
        let packed_refs = common_dir.join("packed-refs");
        std::fs::write(&packed_refs, "packed-commit refs/heads/main\n").unwrap();
        std::fs::remove_file(&reference).unwrap();
        assert_eq!(
            git_inputs(&git_dir, &common_dir),
            [head, packed_refs, common_dir.join("refs")]
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
