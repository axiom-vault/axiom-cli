#![allow(unused_imports)]
use crate::cli::{ConflictStrategyArg, KdfStrength, RaidModeArg, SyncModeArg};
use crate::conversions::{conflict_strategy_from, sync_mode_from};
use crate::password::{
    check_recovery_out, display_recovery_words, kdf_params_from, may_print_recovery_words,
    prompt_password, validate_password_strength, vault_password, write_recovery_words,
};
use anyhow::{Context, Result};
use axiomvault_common::{VaultId, VaultPath};
use axiomvault_crypto::recovery::RecoveryKey;
use axiomvault_crypto::KdfParams;
use axiomvault_storage::gdrive::{AuthConfig, AuthManager, GDriveConfig, Tokens};
use axiomvault_storage::{
    create_default_registry, CompositeConfig, CompositeStorageProvider, HealthStatus, RaidMode,
    RaidRebuilder, RebuildConfig, RebuildResult,
};
use axiomvault_sync::{ConflictStrategy, SyncConfig, SyncEngine, SyncMode, SyncState};
use axiomvault_vault::{
    check_migration_needed, check_vault_health, check_vault_structure, MigrationRegistry,
    MigrationStatus, VaultConfig, VaultManager, VaultOperations, VaultVersion,
};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub(crate) async fn cmd_create(
    name: &str,
    path: &Path,
    strength: KdfStrength,
    recovery_out: Option<&Path>,
) -> Result<()> {
    info!("Creating new vault");

    // Know where the recovery key can go before asking for a password.
    match recovery_out {
        Some(out) => check_recovery_out(out)?,
        None => may_print_recovery_words(std::io::stdout().is_terminal()).context(
            "Cannot show the recovery key here; pass --recovery-out <FILE> to write it to a file instead",
        )?,
    }

    let kdf_params = kdf_params_from(strength);

    let password = prompt_password("Enter password: ")?;
    let confirm = prompt_password("Confirm password: ")?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    validate_password_strength(&password)?;

    let vault_id = VaultId::unique(name).context("Invalid vault name")?;
    let vault_path = path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": vault_path
    });

    let creation = manager
        .create_vault(vault_id, &password, "local", provider_config, kdf_params)
        .await
        .context("Failed to create vault")?;

    if let Some(out) = recovery_out {
        write_recovery_words(out, &creation.recovery_words)
            .await
            .with_context(|| {
                format!(
                    "The vault was created, but saving its recovery key to {} did not complete. \
                     Show it with `axiom recovery show-key --path {}`",
                    out.display(),
                    path.display()
                )
            })?;
    }

    println!("Vault created successfully!");
    println!("  ID: {}", creation.session.vault_id());
    println!("  Location: {}", path.display());
    println!("  Provider: {}", creation.session.config().provider_type);
    match recovery_out {
        Some(out) => println!("  Recovery key: written to {}", out.display()),
        None => display_recovery_words(&creation.recovery_words),
    }

    Ok(())
}

/// Open vault for interactive session.
pub(crate) async fn cmd_open(path: &Path) -> Result<()> {
    info!("Opening vault");

    let password = vault_password("Enter password: ")?;
    let vault_path = path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": vault_path
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    println!("Vault opened successfully!");
    println!("  ID: {}", session.vault_id());
    println!("  Session: {}", session.handle().as_str());

    // Interactive session would go here
    // For now, just show that vault is accessible
    println!("\nVault is ready for operations.");

    Ok(())
}

/// List directory contents.
pub(crate) async fn cmd_list(vault_path: &Path, dir: &str) -> Result<()> {
    let password = vault_password("Enter password: ")?;
    let path_str = vault_path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let ops = VaultOperations::new(&session).context("Failed to create operations handler")?;
    let vault_dir = VaultPath::parse(dir).context("Invalid directory path")?;

    let contents = ops
        .list_directory(&vault_dir)
        .await
        .context("Failed to list directory")?;

    if contents.is_empty() {
        println!("Directory is empty.");
    } else {
        println!("Contents of {}:", dir);
        for (name, is_dir, size) in contents {
            if is_dir {
                println!("  [DIR]  {}/", name);
            } else {
                let size_str = size.map(|s| format!("{} bytes", s)).unwrap_or_default();
                println!("  [FILE] {} ({})", name, size_str);
            }
        }
    }

    Ok(())
}

/// Add a file or directory tree to the vault.
pub(crate) async fn cmd_add(vault_path: &Path, source: &Path, dest: &str) -> Result<()> {
    info!("Adding to vault");

    let password = vault_password("Enter password: ")?;
    let path_str = vault_path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let ops = VaultOperations::new(&session)?;
    let dest_path = VaultPath::parse(dest).context("Invalid destination path")?;

    // Use metadata (follows symlinks) to preserve legacy single-file symlink
    // behavior: a symlink to a regular file is still imported as that file.
    // When the source is a directory we switch to directory mode and use
    // symlink_metadata on every entry so symlinks and special files are
    // rejected rather than traversed.
    let source_meta = tokio::fs::metadata(source)
        .await
        .with_context(|| format!("Failed to inspect source {}", source.display()))?;

    if source_meta.is_dir() {
        add_directory_tree(&ops, source, &dest_path)
            .await
            .with_context(|| {
                format!(
                    "Failed to add directory {} to {}",
                    source.display(),
                    dest_path
                )
            })?;
        println!(
            "Directory added successfully: {} -> {}",
            source.display(),
            dest_path
        );
    } else {
        add_file_checked(&ops, &dest_path, source)
            .await
            .with_context(|| format!("Failed to add file {}", source.display()))?;
        let (_, _, size) = ops.metadata(&dest_path).await?;

        println!(
            "File added successfully: {} ({} bytes)",
            dest,
            size.unwrap_or_default()
        );
    }

    Ok(())
}

/// Import a single file after preflighting that the destination does not
/// already exist and is not a directory. Core's own no-overwrite guard still
/// applies when the snapshot is written.
async fn add_file_checked(
    ops: &VaultOperations<'_>,
    vault_path: &VaultPath,
    source: &Path,
) -> Result<()> {
    match ops.metadata(vault_path).await {
        Ok((_, true, _)) => {
            anyhow::bail!(
                "Cannot add file {}: a directory already exists there",
                vault_path
            )
        }
        Ok((_, false, _)) => {
            anyhow::bail!("Cannot add file {}: already exists in vault", vault_path)
        }
        Err(axiomvault_common::Error::NotFound(_)) => {
            ops.create_file_from_path(vault_path, source).await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Recursively import a local directory tree into a vault destination
/// directory. Empty directories are created, entries are processed in
/// deterministic (sorted) order, and symlinks or special files are refused.
async fn add_directory_tree(
    ops: &VaultOperations<'_>,
    source: &Path,
    dest: &VaultPath,
) -> Result<()> {
    // Reject a symlink-to-directory at the top level; metadata() above would
    // have reported it as a directory, but we must not traverse symlinks.
    let source_meta = tokio::fs::symlink_metadata(source)
        .await
        .with_context(|| format!("Failed to inspect source {}", source.display()))?;
    if source_meta.is_symlink() {
        anyhow::bail!(
            "Source {} is a symlink; refusing to traverse it",
            source.display()
        );
    }

    ensure_vault_directory(ops, dest).await?;

    let entries = collect_directory_entries(source).await?;
    for (src_path, rel_path, is_dir) in entries {
        let vault_path = vault_path_for_relative(dest, &rel_path)
            .with_context(|| format!("Invalid relative path {}", rel_path.display()))?;
        if is_dir {
            ensure_vault_directory(ops, &vault_path).await?;
        } else {
            add_file_checked(ops, &vault_path, &src_path).await?;
        }
    }

    Ok(())
}

/// Ensure `path` exists as a directory in the vault, creating it when missing
/// and failing if it already exists as a file.
async fn ensure_vault_directory(ops: &VaultOperations<'_>, path: &VaultPath) -> Result<()> {
    match ops.metadata(path).await {
        Ok((_, true, _)) => Ok(()),
        Ok((_, false, _)) => {
            anyhow::bail!("Destination path {} already exists as a file", path)
        }
        Err(axiomvault_common::Error::NotFound(_)) => {
            ops.create_directory(path).await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Walk a local directory tree and return every entry as
/// (absolute source path, path relative to source root, is_directory).
/// Entries are sorted by file name within each directory and the returned
/// vector is sorted by relative path for deterministic processing order.
async fn collect_directory_entries(root: &Path) -> Result<Vec<(PathBuf, PathBuf, bool)>> {
    let mut result = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = Vec::new();
        let mut reader = tokio::fs::read_dir(&dir)
            .await
            .with_context(|| format!("Failed to read directory {}", dir.display()))?;
        while let Some(entry) = reader
            .next_entry()
            .await
            .with_context(|| format!("Failed to read directory {}", dir.display()))?
        {
            entries.push(entry);
        }
        entries.sort_by_key(|a| a.file_name());

        for entry in entries {
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .with_context(|| {
                    format!(
                        "Path {} is not under source root {}",
                        path.display(),
                        root.display()
                    )
                })?
                .to_path_buf();
            let file_type = entry
                .file_type()
                .await
                .with_context(|| format!("Failed to inspect {}", path.display()))?;

            if file_type.is_symlink() {
                anyhow::bail!("Refusing to add symlink: {}", path.display());
            } else if file_type.is_dir() {
                result.push((path.clone(), rel, true));
                stack.push(path);
            } else if file_type.is_file() {
                result.push((path, rel, false));
            } else {
                anyhow::bail!("Refusing to add special file: {}", path.display());
            }
        }
    }

    result.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(result)
}

/// Build a vault path by appending the UTF-8 components of a local relative
/// path to a destination directory. Rejects unsafe or non-representable
/// components such as `.`, `..`, separators, and non-UTF-8 names.
fn vault_path_for_relative(dest: &VaultPath, rel: &Path) -> Result<VaultPath> {
    let mut path = dest.clone();
    for component in rel.components() {
        match component {
            std::path::Component::Normal(os) => {
                let name = os.to_str().with_context(|| {
                    format!("Non-UTF-8 path component: {}", os.to_string_lossy())
                })?;
                path = path
                    .join(name)
                    .with_context(|| format!("Invalid vault path component: {name}"))?;
            }
            other => {
                anyhow::bail!("Relative path contains unsafe component: {other:?}")
            }
        }
    }
    Ok(path)
}

/// Extract a file from the vault.
pub(crate) async fn cmd_extract(vault_path: &Path, source: &str, dest: &Path) -> Result<()> {
    info!("Extracting file from vault");

    ensure_destination_free(dest)?;

    let password = vault_password("Enter password: ")?;
    let path_str = vault_path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let ops = VaultOperations::new(&session)?;
    let source_path = VaultPath::parse(source).context("Invalid source path")?;

    // Streams the decrypted content to disk; refuses to overwrite an existing file.
    ops.export_file_to_path(&source_path, dest)
        .await
        .context("Failed to extract file from vault")?;
    let size = tokio::fs::metadata(dest)
        .await
        .context("Failed to inspect output file")?
        .len();

    println!(
        "File extracted successfully: {} ({} bytes)",
        dest.display(),
        size
    );

    Ok(())
}

/// Refuse an extract destination that already exists, including a symlink.
///
/// The core export writes the plaintext with mode 0600 and will not replace an
/// existing path; this early check, which does not follow symlinks, only gives
/// a clear error before the vault is opened.
fn ensure_destination_free(dest: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dest).is_ok() {
        anyhow::bail!(
            "Destination {} already exists; refusing to overwrite it or follow a symlink. \
             Choose a path that does not exist.",
            dest.display()
        );
    }
    Ok(())
}

/// Create a directory in the vault.
pub(crate) async fn cmd_mkdir(vault_path: &Path, dir: &str) -> Result<()> {
    info!("Creating directory");

    let password = vault_password("Enter password: ")?;
    let path_str = vault_path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let ops = VaultOperations::new(&session)?;
    let dir_path = VaultPath::parse(dir).context("Invalid directory path")?;

    ops.create_directory(&dir_path)
        .await
        .context("Failed to create directory")?;

    println!("Directory created: {}", dir);

    Ok(())
}

/// Remove a file from the vault.
pub(crate) async fn cmd_remove(vault_path: &Path, file: &str) -> Result<()> {
    info!("Removing file from vault");

    let password = vault_password("Enter password: ")?;
    let path_str = vault_path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let ops = VaultOperations::new(&session)?;
    let file_path = VaultPath::parse(file).context("Invalid file path")?;

    ops.delete_file(&file_path)
        .await
        .context("Failed to remove file")?;

    println!("File removed: {}", file);

    Ok(())
}

/// Show vault information.
pub(crate) async fn cmd_info(path: &Path) -> Result<()> {
    info!("Getting vault info");

    let password = vault_password("Enter password: ")?;
    let path_str = path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let config = session.config();

    println!("Vault Information:");
    println!("  ID: {}", config.id);
    println!(
        "  Version: {}.{}",
        config.version.major, config.version.minor
    );
    println!("  Provider: {}", config.provider_type);
    println!("  Created: {}", config.created_at);
    println!("  Modified: {}", config.modified_at);
    println!("  KDF Parameters:");
    println!("    Memory: {} KiB", config.kdf_params.memory_cost);
    println!("    Time: {} iterations", config.kdf_params.time_cost);
    println!("    Parallelism: {}", config.kdf_params.parallelism);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_destination_must_not_exist() {
        let dir = std::env::temp_dir().join(format!("axiom-extract-dest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let fresh = dir.join("fresh.txt");
        assert!(ensure_destination_free(&fresh).is_ok());

        let existing = dir.join("existing.txt");
        std::fs::write(&existing, b"keep").unwrap();
        let err = ensure_destination_free(&existing).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");

        #[cfg(unix)]
        {
            let dangling = dir.join("dangling-link");
            std::os::unix::fs::symlink(dir.join("missing-target"), &dangling).unwrap();
            assert!(ensure_destination_free(&dangling).is_err());
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
