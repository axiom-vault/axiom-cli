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
#[cfg(unix)]
use rustix::fs::Mode;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Escape ASCII control characters so untrusted names cannot restyle the
/// terminal or forge extra output lines.
fn escape_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Display a path with control characters escaped.
fn escape_path(path: &Path) -> String {
    escape_controls(&path.to_string_lossy())
}

/// Escape a `VaultPath` for display in error messages.
fn escape_vault_path(path: &VaultPath) -> String {
    escape_controls(&path.to_string())
}

/// Escape a source-derived name before it appears in an error message.
fn escape_name(name: &str) -> String {
    escape_controls(name)
}

/// Escape the text of a core error so that any untrusted vault path it
/// contains cannot restyle the terminal. The original error type is
/// discarded because the CLI only needs a printable, escaped message.
fn escape_core_error(error: axiomvault_common::Error) -> anyhow::Error {
    anyhow::anyhow!("{}", escape_controls(&error.to_string()))
}

/// One entry collected from the source tree. The collector records the
/// type, size, and identity (device/inode) of every entry but does not
/// keep directory or file descriptors open, so large trees do not exhaust
/// `RLIMIT_NOFILE`.
/// Files are reopened by path relative to a root directory handle at import
/// time and their identity is verified against the collected value, which
/// catches symlink swaps and directory renames.
#[derive(Debug)]
struct CollectedEntry {
    abs_path: PathBuf,
    rel_path: PathBuf,
    is_dir: bool,
    /// Plaintext size recorded during collection. Only meaningful for files.
    size: u64,
    /// Device and inode recorded during collection. Only meaningful for files
    /// and directories that must be re-identified during import.
    dev: u64,
    ino: u64,
}

impl CollectedEntry {
    fn dir(abs_path: PathBuf, rel_path: PathBuf, dev: u64, ino: u64) -> Self {
        Self {
            abs_path,
            rel_path,
            is_dir: true,
            size: 0,
            dev,
            ino,
        }
    }

    fn file(abs_path: PathBuf, rel_path: PathBuf, size: u64, dev: u64, ino: u64) -> Self {
        Self {
            abs_path,
            rel_path,
            is_dir: false,
            size,
            dev,
            ino,
        }
    }
}

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
        println!("Contents of {}:", escape_controls(dir));
        for (name, is_dir, size) in contents {
            let name = escape_controls(&name);
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
        // Reject a symlink-to-directory even when the user spells it with a
        // trailing slash or dot: metadata() follows the link, but
        // symlink_metadata on the normalized path reveals the final component.
        let normalized = normalize_path(source);
        let normalized_meta = tokio::fs::symlink_metadata(&normalized)
            .await
            .with_context(|| format!("Failed to inspect source {}", escape_path(source)))?;
        if normalized_meta.is_symlink() {
            anyhow::bail!(
                "Source {} is a symlink; refusing to traverse it",
                escape_path(source)
            );
        }
        add_directory_tree(&ops, source, &dest_path)
            .await
            .with_context(|| {
                format!(
                    "Failed to add directory {} to {}",
                    escape_path(source),
                    escape_vault_path(&dest_path)
                )
            })?;
        println!(
            "Directory added successfully: {} -> {}",
            escape_path(source),
            escape_vault_path(&dest_path)
        );
    } else {
        add_file_checked(&ops, &dest_path, source)
            .await
            .with_context(|| format!("Failed to add file {}", escape_path(source)))?;
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
/// already exist and is not a directory. Symlinks in `source` are followed,
/// preserving the original direct single-file behavior. Core's own
/// no-overwrite guard still applies when the snapshot is written.
async fn add_file_checked(
    ops: &VaultOperations<'_>,
    vault_path: &VaultPath,
    source: &Path,
) -> Result<()> {
    match ops.metadata(vault_path).await {
        Ok((_, true, _)) => {
            anyhow::bail!(
                "Cannot add file {}: a directory already exists there",
                escape_vault_path(vault_path)
            )
        }
        Ok((_, false, _)) => {
            anyhow::bail!(
                "Cannot add file {}: already exists in vault",
                escape_vault_path(vault_path)
            )
        }
        Err(axiomvault_common::Error::NotFound(_)) => {
            ops.create_file_from_path(vault_path, source)
                .await
                .map_err(escape_core_error)?;
            Ok(())
        }
        Err(error) => Err(escape_core_error(error)),
    }
}

/// Report why a vault path cannot be imported, escaping any untrusted name.
fn vault_conflict_error(vault_path: &VaultPath, wanted_dir: bool) -> String {
    let path = escape_vault_path(vault_path);
    if wanted_dir {
        format!("Cannot create directory {path}: already exists as a file")
    } else {
        format!("Cannot add file {path}: already exists as a directory")
    }
}

/// Recursively import a local directory tree into a vault destination
/// directory. Empty directories are created, entries are processed in
/// deterministic (sorted) order, and symlinks or special files are refused.
/// The whole tree is preflighted for representability and vault conflicts
/// before any write, so a validation failure leaves no partial import.
async fn add_directory_tree(
    ops: &VaultOperations<'_>,
    source: &Path,
    dest: &VaultPath,
) -> Result<()> {
    // Collect the source tree first. On Unix this walks the tree with
    // directory file descriptors and records type, size, and identity
    // (device/inode) for every entry, but does not keep descriptors open.
    // Files are reopened by path relative to a root handle during import,
    // with their identity verified against the collected value.
    let entries = collect_directory_entries(source).await?;

    // Build and validate the vault destination for every entry.
    let mut plans = Vec::with_capacity(entries.len());
    for entry in &entries {
        let vault_path = vault_path_for_relative(dest, &entry.rel_path).with_context(|| {
            format!(
                "Invalid relative path {} under {}",
                escape_path(&entry.rel_path),
                escape_path(source)
            )
        })?;
        plans.push((entry, vault_path));
    }

    // Preflight vault conflicts: fail before creating the destination or
    // importing any file, so the tree is never left half-written by a
    // representability or conflict error.
    for (entry, vault_path) in &plans {
        match ops.metadata(vault_path).await {
            Ok((_, true, _)) if entry.is_dir => {}
            Ok((_, false, _)) if !entry.is_dir => {
                anyhow::bail!(
                    "Cannot add file {}: already exists in vault",
                    escape_vault_path(vault_path)
                )
            }
            Ok((_, true, _)) => {
                anyhow::bail!("{}", vault_conflict_error(vault_path, false))
            }
            Ok((_, false, _)) => {
                anyhow::bail!("{}", vault_conflict_error(vault_path, true))
            }
            Err(axiomvault_common::Error::NotFound(_)) => {}
            Err(error) => return Err(escape_core_error(error)),
        }
    }

    // Only after preflight succeeds do we touch the vault.
    ensure_vault_directory(ops, dest).await?;

    // On Unix open the source root once for the import phase. Every file is
    // reopened relative to this handle, one component at a time, so large
    // trees do not exhaust the process file-descriptor limit. On non-Unix
    // platforms the fallback reopens by absolute path.
    #[cfg(unix)]
    let root_dir = open_dir_nofollow(&normalize_path(source))?;
    #[cfg(unix)]
    let root_ref = Some(&root_dir);
    #[cfg(not(unix))]
    let root_ref: Option<&std::fs::File> = None;
    let dirs: std::collections::HashMap<PathBuf, (u64, u64)> = entries
        .iter()
        .filter(|e| e.is_dir)
        .map(|e| (e.rel_path.clone(), (e.dev, e.ino)))
        .collect();

    for (entry, vault_path) in plans {
        if entry.is_dir {
            ensure_vault_directory(ops, &vault_path).await?;
        } else {
            add_directory_file_checked(ops, root_ref, &vault_path, entry, &dirs).await?;
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
            anyhow::bail!(
                "Destination path {} already exists as a file",
                escape_vault_path(path)
            )
        }
        Err(axiomvault_common::Error::NotFound(_)) => {
            ops.create_directory(path)
                .await
                .map_err(escape_core_error)?;
            Ok(())
        }
        Err(error) => Err(escape_core_error(error)),
    }
}

/// Import one file from a directory tree. The source file is reopened by
/// walking from the root directory handle and verifying the collected
/// device/inode, so a symlink swap or directory rename between collection
/// and import is caught before any vault write.
async fn add_directory_file_checked(
    ops: &VaultOperations<'_>,
    root_dir: Option<&std::fs::File>,
    vault_path: &VaultPath,
    entry: &CollectedEntry,
    dirs: &std::collections::HashMap<PathBuf, (u64, u64)>,
) -> Result<()> {
    match ops.metadata(vault_path).await {
        Ok((_, true, _)) => {
            anyhow::bail!(
                "Cannot add file {}: a directory already exists there",
                escape_vault_path(vault_path)
            )
        }
        Ok((_, false, _)) => {
            anyhow::bail!(
                "Cannot add file {}: already exists in vault",
                escape_vault_path(vault_path)
            )
        }
        Err(axiomvault_common::Error::NotFound(_)) => {
            #[cfg(unix)]
            let (file, size) = reopen_file_from_root(root_dir.unwrap(), entry, dirs)
                .with_context(|| format!("Failed to open {}", escape_path(&entry.abs_path)))?;
            #[cfg(not(unix))]
            let (file, size) = reopen_file_from_path(entry)
                .with_context(|| format!("Failed to open {}", escape_path(&entry.abs_path)))?;
            ops.create_file_from_reader(vault_path, file, Some(size))
                .await
                .map_err(escape_core_error)?;
            Ok(())
        }
        Err(error) => Err(escape_core_error(error)),
    }
}

/// Walk a local directory tree and return every entry. On Unix this uses
/// directory file descriptors so the traversal is not fooled by a directory
/// swap, but it does not keep regular-file descriptors open, so trees with
/// many files do not exhaust `RLIMIT_NOFILE`. Entries are sorted by file name
/// within each directory and the returned vector is sorted by relative path
/// for deterministic processing.
async fn collect_directory_entries(root: &Path) -> Result<Vec<CollectedEntry>> {
    #[cfg(unix)]
    {
        collect_directory_entries_unix(root).await
    }
    #[cfg(not(unix))]
    {
        collect_directory_entries_path(root).await
    }
}

#[cfg(unix)]
async fn collect_directory_entries_unix(root: &Path) -> Result<Vec<CollectedEntry>> {
    use rustix::fs::{AtFlags, Dir, FileType};
    use std::collections::HashMap;
    use std::os::unix::ffi::OsStrExt;

    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let root_dir = open_dir_nofollow(&root)?;
        let root_stat = rustix::fs::fstat(&root_dir)?;
        let mut result = Vec::new();
        let mut dirs: HashMap<PathBuf, (u64, u64)> = HashMap::new();
        let root_entry = CollectedEntry::dir(
            root.clone(),
            PathBuf::new(),
            root_stat.st_dev as u64,
            root_stat.st_ino as u64,
        );
        dirs.insert(PathBuf::new(), (root_entry.dev, root_entry.ino));
        result.push(root_entry);

        // Stack of directory work items described by relative path and
        // collected identity. Directories are reopened from the root handle
        // one at a time, so descriptor use is bounded by tree depth rather
        // than directory breadth.
        let mut stack: Vec<(PathBuf, u64, u64)> = vec![(
            PathBuf::new(),
            root_stat.st_dev as u64,
            root_stat.st_ino as u64,
        )];

        while let Some((rel, expected_dev, expected_ino)) = stack.pop() {
            let dir = reopen_dir_from_root(&root_dir, &rel, expected_dev, expected_ino, &dirs)
                .with_context(|| {
                    format!(
                        "Failed to reopen directory {}",
                        escape_path(&root.join(&rel))
                    )
                })?;
            let mut names: Vec<std::ffi::OsString> = Vec::new();
            let mut read_dir = Dir::read_from(&dir).with_context(|| {
                format!("Failed to read directory {}", escape_path(&root.join(&rel)))
            })?;
            while let Some(entry) = read_dir.read() {
                let entry = entry.with_context(|| {
                    format!("Failed to read directory {}", escape_path(&root.join(&rel)))
                })?;
                let name_bytes = entry.file_name().to_bytes();
                if name_bytes == b"." || name_bytes == b".." {
                    continue;
                }
                names.push(std::ffi::OsStr::from_bytes(name_bytes).to_os_string());
            }
            names.sort();

            for name in names {
                let entry_rel = rel.join(&name);
                let abs = root.join(&entry_rel);

                // fstatat relative to the directory fd does not follow
                // symlinks and is not fooled by intermediate symlink
                // components because we are already inside the directory.
                let stat = rustix::fs::statat(&dir, &name, AtFlags::SYMLINK_NOFOLLOW)
                    .with_context(|| format!("Failed to inspect {}", escape_path(&abs)))?;
                let file_type = FileType::from_raw_mode(stat.st_mode);
                let dev = stat.st_dev as u64;
                let ino = stat.st_ino as u64;

                match file_type {
                    FileType::Symlink => {
                        anyhow::bail!("Refusing to add symlink: {}", escape_path(&abs));
                    }
                    FileType::Directory => {
                        let entry = CollectedEntry::dir(abs, entry_rel.clone(), dev, ino);
                        dirs.insert(entry_rel.clone(), (dev, ino));
                        result.push(entry);
                        stack.push((entry_rel, dev, ino));
                    }
                    FileType::RegularFile => {
                        let size = stat.st_size as u64;
                        result.push(CollectedEntry::file(abs, entry_rel, size, dev, ino));
                    }
                    _ => {
                        anyhow::bail!("Refusing to add special file: {}", escape_path(&abs));
                    }
                }
            }
        }

        result.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        Ok(result)
    })
    .await
    .map_err(|error| anyhow::anyhow!("directory walk task failed: {error}"))?
}

#[cfg(unix)]
fn open_dir_nofollow(path: &Path) -> Result<std::fs::File> {
    use rustix::fs::OFlags;

    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("Failed to open directory {}", escape_path(path)))?;
    Ok(std::fs::File::from(fd))
}

/// Reopen a directory by walking from the root directory handle and
/// verifying every directory component against the collected `dev`/`ino`.
/// This is used by the collector so it never holds more than one directory
/// descriptor open at a time, keeping descriptor use bounded by tree depth.
#[cfg(unix)]
fn reopen_dir_from_root(
    root_dir: &std::fs::File,
    rel: &Path,
    expected_dev: u64,
    expected_ino: u64,
    dirs: &std::collections::HashMap<PathBuf, (u64, u64)>,
) -> Result<std::fs::File> {
    use rustix::fs::{FileType, OFlags};

    let mut current_dir = root_dir
        .try_clone()
        .context("Failed to duplicate root directory handle")?;
    let mut current: &std::fs::File = &current_dir;
    let mut current_path = PathBuf::new();

    let components: Vec<_> = rel.components().collect();
    if components.is_empty() {
        let stat = rustix::fs::fstat(current)?;
        if stat.st_dev as u64 != expected_dev || stat.st_ino as u64 != expected_ino {
            anyhow::bail!("Source root changed between collection and import");
        }
        return Ok(current_dir);
    }

    for (i, component) in components.iter().enumerate() {
        let name = component.as_os_str();
        current_path.push(name);

        let is_last = i + 1 == components.len();
        let (expected_dev, expected_ino) = dirs.get(&current_path).with_context(|| {
            format!(
                "Directory component {} disappeared between collection and import",
                escape_path(&current_path)
            )
        })?;
        let fd = rustix::fs::openat(
            current,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| {
            format!(
                "Failed to open directory component {}",
                escape_path(&current_path)
            )
        })?;
        let next = std::fs::File::from(fd);
        let stat = rustix::fs::fstat(&next)?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if !file_type.is_dir() {
            anyhow::bail!(
                "Directory component {} is not a directory",
                escape_path(&current_path)
            );
        }
        let dev = stat.st_dev as u64;
        let ino = stat.st_ino as u64;
        if dev != *expected_dev || ino != *expected_ino {
            anyhow::bail!(
                "Directory component {} changed between collection and import",
                escape_path(&current_path)
            );
        }
        if is_last {
            return Ok(next);
        }
        current_dir = next;
        current = &current_dir;
    }

    unreachable!("last component is always handled above");
}

/// Reopen a regular file for import by walking from the root directory
/// handle and verifying the identity of every directory component and the
/// file itself against the collected `dev`/`ino`. This catches symlink
/// swaps, directory renames, and file replacements between collection and
/// import while keeping only one file descriptor open at a time.
#[cfg(unix)]
fn reopen_file_from_root(
    root_dir: &std::fs::File,
    entry: &CollectedEntry,
    dirs: &std::collections::HashMap<PathBuf, (u64, u64)>,
) -> Result<(std::fs::File, u64)> {
    use rustix::fs::{FileType, OFlags};

    let mut current_dir = root_dir
        .try_clone()
        .context("Failed to duplicate root directory handle")?;
    let mut current: &std::fs::File = &current_dir;
    let mut current_path = PathBuf::new();

    let components: Vec<_> = entry.rel_path.components().collect();
    if components.is_empty() {
        anyhow::bail!("Cannot import the source root as a file");
    }

    for (i, component) in components.iter().enumerate() {
        let name = component.as_os_str();
        current_path.push(name);

        let is_last = i + 1 == components.len();
        if is_last {
            let fd = rustix::fs::openat(
                current,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("Failed to open {}", escape_path(&entry.abs_path)))?;
            let file = std::fs::File::from(fd);
            let metadata = file
                .metadata()
                .with_context(|| format!("Failed to inspect {}", escape_path(&entry.abs_path)))?;
            if !metadata.is_file() {
                anyhow::bail!("{} is not a regular file", escape_path(&entry.abs_path));
            }
            let dev = metadata.dev();
            let ino = metadata.ino();
            if dev != entry.dev || ino != entry.ino {
                anyhow::bail!(
                    "{} changed between collection and import",
                    escape_path(&entry.abs_path)
                );
            }
            return Ok((file, entry.size));
        }

        let (expected_dev, expected_ino) = dirs.get(&current_path).with_context(|| {
            format!(
                "Directory component {} disappeared between collection and import",
                escape_path(&entry.abs_path)
            )
        })?;
        let fd = rustix::fs::openat(
            current,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| {
            format!(
                "Failed to open directory component {}",
                escape_path(&entry.abs_path)
            )
        })?;
        let next = std::fs::File::from(fd);
        let stat = rustix::fs::fstat(&next)?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if !file_type.is_dir() {
            anyhow::bail!(
                "Directory component {} is not a directory",
                escape_path(&entry.abs_path)
            );
        }
        let dev = stat.st_dev as u64;
        let ino = stat.st_ino as u64;
        if dev != *expected_dev || ino != *expected_ino {
            anyhow::bail!(
                "Directory component {} changed between collection and import",
                escape_path(&entry.abs_path)
            );
        }
        current_dir = next;
        current = &current_dir;
    }

    unreachable!("last component is always handled above");
}

#[cfg(not(unix))]
async fn collect_directory_entries_path(root: &Path) -> Result<Vec<CollectedEntry>> {
    let mut result = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = Vec::new();
        let mut reader = tokio::fs::read_dir(&dir)
            .await
            .with_context(|| format!("Failed to read directory {}", escape_path(&dir)))?;
        while let Some(entry) = reader
            .next_entry()
            .await
            .with_context(|| format!("Failed to read directory {}", escape_path(&dir)))?
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
                        escape_path(&path),
                        escape_path(root)
                    )
                })?
                .to_path_buf();
            let metadata = entry
                .metadata()
                .await
                .with_context(|| format!("Failed to inspect {}", escape_path(&path)))?;

            if metadata.is_symlink() {
                anyhow::bail!("Refusing to add symlink: {}", escape_path(&path));
            } else if metadata.is_dir() {
                result.push(CollectedEntry::dir(path.clone(), rel, 0, 0));
                stack.push(path);
            } else if metadata.is_file() {
                let size = metadata.len();
                result.push(CollectedEntry::file(path, rel, size, 0, 0));
            } else {
                anyhow::bail!("Refusing to add special file: {}", escape_path(&path));
            }
        }
    }

    result.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(result)
}

#[cfg(not(unix))]
fn reopen_file_from_path(entry: &CollectedEntry) -> Result<(std::fs::File, u64)> {
    let file = std::fs::File::open(&entry.abs_path)
        .with_context(|| format!("Failed to open {}", escape_path(&entry.abs_path)))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect {}", escape_path(&entry.abs_path)))?;
    if !metadata.is_file() {
        anyhow::bail!("{} is not a regular file", escape_path(&entry.abs_path));
    }
    Ok((file, entry.size))
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
                    format!(
                        "Non-UTF-8 path component: {}",
                        escape_controls(&os.to_string_lossy())
                    )
                })?;
                path = path.join(name).with_context(|| {
                    format!("Invalid vault path component: {}", escape_name(name))
                })?;
            }
            other => {
                anyhow::bail!("Relative path contains unsafe component: {other:?}")
            }
        }
    }
    Ok(path)
}

/// Reconstruct a path from its components so trailing slashes, trailing `/./`
/// and other no-op spellings are removed. This lets `symlink_metadata`
/// detect a symlink at the final component even when the caller spells the
/// path as `link/` or `link/.`.
fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        result.push(component.as_os_str());
    }
    result
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

    #[cfg(unix)]
    mod file_add_walk {
        use std::collections::HashMap;
        use std::os::unix::fs::MetadataExt;

        use super::*;

        fn temp_root(name: &str) -> PathBuf {
            let root = std::env::temp_dir().join(format!(
                "axiom-vault-rs-test-{}-{}",
                name,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            root
        }

        fn make_entry(root: &Path, rel: &str, is_dir: bool) -> CollectedEntry {
            let abs = root.join(rel);
            let rel_path = PathBuf::from(rel);
            let metadata = std::fs::symlink_metadata(&abs).unwrap();
            let dev = metadata.dev();
            let ino = metadata.ino();
            if is_dir {
                CollectedEntry::dir(abs, rel_path, dev, ino)
            } else {
                CollectedEntry::file(abs, rel_path, metadata.len(), dev, ino)
            }
        }

        fn dir_map(entries: &[CollectedEntry]) -> HashMap<PathBuf, (u64, u64)> {
            entries
                .iter()
                .filter(|e| e.is_dir)
                .map(|e| (e.rel_path.clone(), (e.dev, e.ino)))
                .collect()
        }

        #[test]
        fn reopen_file_from_root_accepts_regular_file() {
            let root = temp_root("reopen-ok");
            std::fs::write(root.join("file.txt"), b"hello").unwrap();

            let entry = make_entry(&root, "file.txt", false);
            let root_dir = open_dir_nofollow(&root).unwrap();
            let dirs = dir_map(&[]);

            let (mut file, size) = reopen_file_from_root(&root_dir, &entry, &dirs).unwrap();
            let mut contents = String::new();
            std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
            assert_eq!(contents, "hello");
            assert_eq!(size, 5);
        }

        #[test]
        fn reopen_file_from_root_rejects_symlink_final_component() {
            let root = temp_root("reopen-symlink-file");
            std::fs::write(root.join("real.txt"), b"x").unwrap();
            std::os::unix::fs::symlink(root.join("real.txt"), root.join("link.txt")).unwrap();

            // Pretend the collector saw a regular file at link.txt (impossible in
            // the real collector, but it lets us test the reopen path directly).
            let metadata = std::fs::symlink_metadata(root.join("link.txt")).unwrap();
            let entry = CollectedEntry::file(
                root.join("link.txt"),
                PathBuf::from("link.txt"),
                1,
                metadata.dev(),
                metadata.ino(),
            );
            let root_dir = open_dir_nofollow(&root).unwrap();
            let dirs = dir_map(&[]);

            let err = reopen_file_from_root(&root_dir, &entry, &dirs).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("not a regular file") || msg.contains("Failed to open"),
                "{msg}"
            );
        }

        #[test]
        fn reopen_file_from_root_rejects_symlink_intermediate_component() {
            let root = temp_root("reopen-symlink-dir");
            let sub = root.join("sub");
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join("file.txt"), b"x").unwrap();

            let entries = vec![
                make_entry(&root, "sub", true),
                make_entry(&root, "sub/file.txt", false),
            ];
            let dirs = dir_map(&entries);
            let root_dir = open_dir_nofollow(&root).unwrap();

            // Replace the intermediate directory with a symlink to another directory.
            let other = root.join("other");
            std::fs::create_dir_all(&other).unwrap();
            std::fs::write(other.join("secret.txt"), b"stolen").unwrap();
            std::fs::remove_dir_all(&sub).unwrap();
            std::os::unix::fs::symlink(&other, &sub).unwrap();

            let err = reopen_file_from_root(&root_dir, &entries[1], &dirs).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("changed between collection and import")
                    || msg.contains("not a directory")
                    || msg.contains("Failed to open directory component"),
                "{msg}"
            );
        }

        #[test]
        fn reopen_file_from_root_rejects_file_replacement() {
            let root = temp_root("reopen-replace-file");
            let path = root.join("file.txt");
            std::fs::write(&path, b"original").unwrap();

            let entry = make_entry(&root, "file.txt", false);

            // Replace the file with a different file (same name, different inode).
            std::fs::remove_file(&path).unwrap();
            std::fs::write(&path, b"replacement").unwrap();

            let root_dir = open_dir_nofollow(&root).unwrap();
            let dirs = dir_map(&[]);

            let err = reopen_file_from_root(&root_dir, &entry, &dirs).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("changed between collection and import"),
                "{msg}"
            );
        }

        #[test]
        fn reopen_file_from_root_rejects_directory_replacement() {
            let root = temp_root("reopen-replace-dir");
            let sub = root.join("sub");
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join("file.txt"), b"x").unwrap();

            let entries = vec![
                make_entry(&root, "sub", true),
                make_entry(&root, "sub/file.txt", false),
            ];
            let dirs = dir_map(&entries);
            let root_dir = open_dir_nofollow(&root).unwrap();

            // Replace the directory with a different directory (same name, different inode).
            std::fs::remove_dir_all(&sub).unwrap();
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join("other.txt"), b"y").unwrap();

            let err = reopen_file_from_root(&root_dir, &entries[1], &dirs).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("changed between collection and import"),
                "{msg}"
            );
        }

        #[test]
        fn collect_directory_entries_rejects_symlink_directory() {
            let root = temp_root("collect-symlink-dir");
            let target = root.join("target");
            std::fs::create_dir_all(&target).unwrap();
            std::os::unix::fs::symlink(&target, root.join("link")).unwrap();

            let runtime = tokio::runtime::Runtime::new().unwrap();
            let err = runtime
                .block_on(collect_directory_entries_unix(&root.join("link")))
                .unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("symlink"), "{msg}");
        }

        #[test]
        fn add_directory_file_checked_rejects_stale_size() {
            let root = temp_root("stale-size");
            let file_path = root.join("file.txt");
            std::fs::write(&file_path, b"1234567890").unwrap();

            let vault_root = temp_root("stale-size-vault");
            let vault_file = vault_root.join("vault");

            let runtime = tokio::runtime::Runtime::new().unwrap();
            let session = runtime.block_on(async {
                let manager = VaultManager::new();
                let provider_config =
                    serde_json::json!({"root": vault_file.to_string_lossy().to_string()});
                manager
                    .create_vault(
                        VaultId::unique("StaleSize").unwrap(),
                        b"synthetic-password",
                        "local",
                        provider_config,
                        KdfParams::interactive(),
                    )
                    .await
                    .unwrap()
                    .session
            });
            let ops = VaultOperations::new(&session).unwrap();

            // Record the original size, then change the source before import.
            let entry = make_entry(&root, "file.txt", false);
            std::fs::write(&file_path, b"12345").unwrap();

            let root_dir = open_dir_nofollow(&root).unwrap();
            let dirs = dir_map(&[]);
            let dest = VaultPath::parse("/file.txt").unwrap();

            let err = runtime
                .block_on(add_directory_file_checked(
                    &ops,
                    Some(&root_dir),
                    &dest,
                    &entry,
                    &dirs,
                ))
                .unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("source changed") || msg.contains("size") || msg.contains("Size"),
                "unexpected error: {msg}"
            );

            // Core must not have written anything to the vault.
            let metadata = runtime.block_on(ops.metadata(&dest));
            assert!(matches!(
                metadata,
                Err(axiomvault_common::Error::NotFound(_))
            ));
        }
    }
}
