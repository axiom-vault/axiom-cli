#![allow(unused_imports)]
use crate::cli::{ConflictStrategyArg, KdfStrength, RaidModeArg, SyncModeArg};
use crate::conversions::{conflict_strategy_from, sync_mode_from};
use crate::password::{
    display_recovery_words, kdf_params_from, prompt_password, validate_password_strength,
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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub(crate) async fn cmd_sync(vault_path: &Path, strategy: ConflictStrategyArg) -> Result<()> {
    info!("Starting vault sync");

    let conflict_strategy = conflict_strategy_from(strategy);
    let password = prompt_password("Enter password: ")?;
    let path_str = vault_path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let sync_config = SyncConfig {
        conflict_strategy,
        auto_resolve_conflicts: true,
        ..Default::default()
    };

    let staging_dir = vault_path.join(".axiom_sync");
    let sync_engine: SyncEngine<dyn axiomvault_storage::StorageProvider> =
        SyncEngine::from_arc(session.provider(), &staging_dir, sync_config)
            .await
            .context("Failed to create sync engine")?;

    println!("Starting sync...");
    let result = sync_engine.sync_full().await.context("Sync failed")?;

    println!("Sync completed!");
    println!("  Files synced: {}", result.files_synced);
    println!("  Files failed: {}", result.files_failed);
    println!("  Conflicts found: {}", result.conflicts_found);
    println!("  Duration: {:?}", result.duration);

    Ok(())
}

/// Show sync status for the vault.
pub(crate) async fn cmd_sync_status(vault_path: &Path) -> Result<()> {
    info!("Getting sync status");

    let staging_dir = vault_path.join(".axiom_sync");
    let state_file = staging_dir.join("sync_state.json");

    if !state_file.exists() {
        println!("No sync state found. Vault has not been synced yet.");
        return Ok(());
    }

    let state_json = tokio::fs::read_to_string(&state_file)
        .await
        .context("Failed to read sync state")?;

    let state: SyncState =
        serde_json::from_str(&state_json).context("Failed to parse sync state")?;

    println!("Sync Status:");
    if let Some(last_sync) = state.last_full_sync {
        println!("  Last full sync: {}", last_sync);
    } else {
        println!("  Last full sync: Never");
    }

    let counts = state.count_by_status();
    println!("  Files tracked: {}", state.entries().count());

    for (status, count) in counts {
        let status_str = match status {
            axiomvault_sync::SyncStatus::Synced => "Synced",
            axiomvault_sync::SyncStatus::LocalModified => "Local modified",
            axiomvault_sync::SyncStatus::RemoteModified => "Remote modified",
            axiomvault_sync::SyncStatus::Conflicted => "Conflicted",
            axiomvault_sync::SyncStatus::Syncing => "Syncing",
            axiomvault_sync::SyncStatus::Failed => "Failed",
        };
        println!("    {}: {}", status_str, count);
    }

    if state.has_pending_changes() {
        println!("\n  Status: Has pending changes");
    } else {
        println!("\n  Status: All synced");
    }

    Ok(())
}

/// List sync conflicts.
pub(crate) async fn cmd_sync_conflicts(vault_path: &Path) -> Result<()> {
    info!("Listing sync conflicts");

    let staging_dir = vault_path.join(".axiom_sync");
    let state_file = staging_dir.join("sync_state.json");

    if !state_file.exists() {
        println!("No sync state found. Vault has not been synced yet.");
        return Ok(());
    }

    let state_json = tokio::fs::read_to_string(&state_file)
        .await
        .context("Failed to read sync state")?;

    let state: SyncState =
        serde_json::from_str(&state_json).context("Failed to parse sync state")?;

    let conflicts = state.entries_with_status(axiomvault_sync::SyncStatus::Conflicted);

    if conflicts.is_empty() {
        println!("No conflicts found.");
    } else {
        println!("Sync Conflicts:");
        for entry in conflicts {
            println!("\n  Path: {}", entry.path);
            println!("    Local etag: {:?}", entry.local_etag);
            println!("    Remote etag: {:?}", entry.remote_etag);
            println!("    Local modified: {}", entry.local_modified);
            if let Some(remote_mod) = entry.remote_modified {
                println!("    Remote modified: {}", remote_mod);
            }
        }
        println!("\nUse 'axiomvault sync resolve' to resolve conflicts.");
    }

    Ok(())
}

/// Resolve a sync conflict for a specific file.
pub(crate) async fn cmd_sync_resolve(
    vault_path: &Path,
    file: &str,
    strategy: ConflictStrategyArg,
) -> Result<()> {
    info!("Resolving sync conflict for {}", file);

    let conflict_strategy = conflict_strategy_from(strategy);
    let password = prompt_password("Enter password: ")?;
    let path_str = vault_path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let sync_config = SyncConfig {
        conflict_strategy,
        ..Default::default()
    };

    let staging_dir = vault_path.join(".axiom_sync");
    let sync_engine: SyncEngine<dyn axiomvault_storage::StorageProvider> =
        SyncEngine::from_arc(session.provider(), &staging_dir, sync_config)
            .await
            .context("Failed to create sync engine")?;

    let file_path = VaultPath::parse(file).context("Invalid file path")?;

    // Read local file content for resolution
    let ops = VaultOperations::new(&session)?;
    let local_data = ops
        .read_file(&file_path)
        .await
        .context("Failed to read local file")?;

    sync_engine
        .resolve_conflict(&file_path, local_data, conflict_strategy)
        .await
        .context("Failed to resolve conflict")?;

    println!(
        "Conflict resolved for {} using strategy: {:?}",
        file, strategy
    );

    Ok(())
}

/// Configure sync mode for the vault.
pub(crate) async fn cmd_sync_configure(
    vault_path: &Path,
    mode: SyncModeArg,
    interval: Option<u64>,
) -> Result<()> {
    info!("Configuring sync mode: {:?}", mode);

    let sync_mode = sync_mode_from(mode, interval)?;

    let staging_dir = vault_path.join(".axiom_sync");
    tokio::fs::create_dir_all(&staging_dir)
        .await
        .context("Failed to create sync directory")?;

    let config_file = staging_dir.join("sync_config.json");

    let config = SyncConfig {
        sync_mode: sync_mode.clone(),
        ..Default::default()
    };

    let config_json =
        serde_json::to_string_pretty(&config).context("Failed to serialize config")?;

    tokio::fs::write(&config_file, config_json)
        .await
        .context("Failed to write config")?;

    let mode_str = match sync_mode {
        SyncMode::Manual => "Manual".to_string(),
        SyncMode::OnDemand => "On-demand".to_string(),
        SyncMode::Periodic { interval } => format!("Periodic (every {:?})", interval),
        SyncMode::Hybrid { interval } => format!("Hybrid (every {:?})", interval),
    };

    println!("Sync configuration updated!");
    println!("  Mode: {}", mode_str);
    println!("  Config saved to: {}", config_file.display());

    Ok(())
}
