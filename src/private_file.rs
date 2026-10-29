//! Atomic, owner-only writes for files that hold secret material.

use anyhow::{Context, Result};
use std::path::Path;

/// Publish `bytes` at `path` atomically: write a private temporary file beside
/// it, sync it, check that it is owner-only, rename it into place, then sync
/// the directory. An existing file at `path` is replaced. On failure neither
/// the temporary file nor a partial `path` is left behind. The temporary file
/// has a random name, so no existing file beside `path` is touched.
#[cfg(unix)]
pub(crate) async fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::AsyncWriteExt;

    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix)
        .map_err(|e| anyhow::anyhow!("OS random number generator failed: {e}"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(
        path.file_name()
            .with_context(|| format!("{} has no file name", path.display()))?,
    );
    tmp_name.push(format!(".{:016x}.tmp", u64::from_ne_bytes(suffix)));
    let tmp_path = path.with_file_name(tmp_name);

    let published = async {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .await
            .with_context(|| format!("Failed to create {}", tmp_path.display()))?;
        f.write_all(bytes)
            .await
            .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
        f.sync_all()
            .await
            .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
        let mode = f.metadata().await?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} has permissions {mode:o}, expected owner-only",
                tmp_path.display()
            );
        }
        tokio::fs::rename(&tmp_path, path)
            .await
            .with_context(|| format!("Failed to rename {} into place", tmp_path.display()))
    }
    .await;
    if published.is_err() {
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }
    published?;

    // Make the rename itself durable.
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let sync_error = || format!("Failed to sync directory {}", dir.display());
    tokio::fs::File::open(dir)
        .await
        .with_context(sync_error)?
        .sync_all()
        .await
        .with_context(sync_error)
}

/// Owner-only permissions cannot be set and checked here, so refuse to write.
#[cfg(not(unix))]
pub(crate) async fn write_private_file(path: &Path, _bytes: &[u8]) -> Result<()> {
    anyhow::bail!(
        "Refusing to write {}: secret files are written only on Unix, where owner-only permissions can be checked",
        path.display()
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("axiom-private-file-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn replaces_the_target_privately_and_leaves_other_files_alone() {
        let dir = test_dir("replace");
        let target = dir.join("secret");
        std::fs::write(&target, b"old").unwrap();
        // A file of the user's that only looks like a temporary file.
        std::fs::write(dir.join("secret.tmp"), b"user data").unwrap();

        write_private_file(&target, b"new").await.unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read(dir.join("secret.tmp")).unwrap(), b"user data");
        assert_eq!(entries(&dir), ["secret", "secret.tmp"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn failed_rename_leaves_no_temp_file() {
        let dir = test_dir("rename");
        // A non-empty directory at the target makes the final rename fail
        // after the temporary file has been written and synced.
        let target = dir.join("secret");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), b"keep").unwrap();

        let err = write_private_file(&target, b"new").await.unwrap_err();

        assert!(format!("{err:#}").contains("rename"), "{err:#}");
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"keep");
        assert_eq!(entries(&dir), ["secret"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn failed_create_leaves_nothing_behind() {
        let dir = test_dir("create");
        let target = dir.join("missing").join("secret");

        let err = write_private_file(&target, b"new").await.unwrap_err();

        assert!(format!("{err:#}").contains("Failed to create"), "{err:#}");
        assert!(entries(&dir).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
