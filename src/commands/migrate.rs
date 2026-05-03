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

pub(crate) async fn cmd_migrate(path: &Path, dry_run: bool) -> Result<()> {
    info!("Checking vault migration status: {}", path.display());

    let config_path = path.join("vault.config");
    if !config_path.exists() {
        anyhow::bail!("No vault found at {}", path.display());
    }

    let config_bytes = tokio::fs::read(&config_path)
        .await
        .context("Failed to read vault config")?;
    let mut config = VaultConfig::from_bytes(&config_bytes).context("Failed to parse config")?;

    let status = check_migration_needed(&config);

    match &status {
        MigrationStatus::UpToDate => {
            println!("Vault is up to date (version {}).", config.version);
            return Ok(());
        }
        MigrationStatus::Incompatible { version } => {
            anyhow::bail!(
                "Vault version {} is incompatible with this software (current: {})",
                version,
                VaultVersion::CURRENT
            );
        }
        MigrationStatus::NeedsMigration { from, to } => {
            println!("Migration needed: {} -> {}", from, to);
        }
    }

    let registry = MigrationRegistry::default();
    let target = VaultVersion::CURRENT;

    if let Some(steps) = registry.find_path(&config.version, &target) {
        println!("Migration plan ({} step(s)):", steps.len());
        for (i, step) in steps.iter().enumerate() {
            println!(
                "  {}. {} -> {}: {}",
                i + 1,
                step.source_version(),
                step.target_version(),
                step.description()
            );
        }
    } else {
        anyhow::bail!(
            "No migration path found from {} to {}",
            config.version,
            target
        );
    }

    if dry_run {
        println!("\nDry run complete. No changes were made.");
        return Ok(());
    }

    println!("\nRunning migrations...");
    registry
        .migrate(path, &mut config, &target)
        .context("Migration failed")?;

    println!(
        "Migration completed successfully! Vault is now at version {}.",
        config.version
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// RAID helpers
// ---------------------------------------------------------------------------
