#![allow(unused_imports)]
use crate::cli::{ConflictStrategyArg, KdfStrength, RaidModeArg, SyncModeArg};
use crate::conversions::{conflict_strategy_from, sync_mode_from};
use crate::password::{
    display_recovery_words, kdf_params_from, may_print_recovery_words, prompt_password,
    validate_password_strength,
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

pub(crate) async fn cmd_change_password(path: &Path) -> Result<()> {
    info!("Changing vault password");

    let old_password = prompt_password("Enter current password: ")?;
    let new_password = prompt_password("Enter new password: ")?;
    let confirm = prompt_password("Confirm new password: ")?;

    if new_password != confirm {
        anyhow::bail!("New passwords do not match");
    }

    validate_password_strength(&new_password)?;

    let path_str = path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let mut session = manager
        .open_vault("local", provider_config, &old_password)
        .await
        .context("Failed to open vault")?;

    session
        .change_password(&old_password, &new_password)
        .context("Failed to change password")?;

    // Save updated config
    manager.save_config(&mut session).await?;

    println!("Password changed successfully!");

    Ok(())
}

/// Show recovery key for a vault.
pub(crate) async fn cmd_show_recovery_key(path: &Path) -> Result<()> {
    info!("Showing recovery key");

    may_print_recovery_words(std::io::stdout().is_terminal())?;

    let password = prompt_password("Enter password: ")?;
    let path_str = path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let master_key = session.master_key().context("Session not active")?;
    let recovery_key = session
        .config()
        .decrypt_recovery_key(master_key)
        .context("Failed to decrypt recovery key. Vault may not have a recovery key.")?;

    let words = recovery_key
        .to_mnemonic()
        .context("Failed to encode recovery key")?;

    display_recovery_words(&words);

    Ok(())
}

/// Reset vault password using recovery key.
pub(crate) async fn cmd_reset_password(path: &Path) -> Result<()> {
    info!("Resetting vault password using recovery key");

    // Read without echo; Zeroizing wipes the words when they go out of scope.
    let recovery_input = Zeroizing::new(
        rpassword::prompt_password("Enter your 24-word recovery key (space-separated): ")
            .context("Failed to read recovery key")?,
    );
    let recovery_words = recovery_input.trim();

    // Validate the recovery key format first.
    RecoveryKey::from_mnemonic(recovery_words)
        .context("Invalid recovery key. Please check your words and try again.")?;

    let new_password = prompt_password("Enter new password: ")?;
    let confirm = prompt_password("Confirm new password: ")?;

    if new_password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    validate_password_strength(&new_password)?;

    let path_str = path.to_string_lossy().to_string();

    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": path_str
    });

    let _session = manager
        .recover_vault("local", provider_config, recovery_words, &new_password)
        .await
        .context("Failed to reset password. Recovery key may be incorrect.")?;

    println!("Password reset successfully!");

    Ok(())
}

/// Migrate a legacy vault to support recovery keys.
///
/// Only a 1.0 vault is changed, through the registry migration to 1.1. A 1.1
/// or newer vault already has a recovery key; the 1.1 -> 2.0 upgrade belongs
/// to `axiom vault migrate`.
pub(crate) async fn cmd_migrate_vault(path: &Path) -> Result<()> {
    info!("Migrating vault to v1.1 format");

    let config_path = path.join("vault.config");
    if !config_path.exists() {
        anyhow::bail!("No vault found at {}", path.display());
    }
    let config_bytes = tokio::fs::read(&config_path)
        .await
        .context("Failed to read vault config")?;
    let config = VaultConfig::from_bytes(&config_bytes).context("Failed to parse config")?;

    match check_migration_needed(&config) {
        MigrationStatus::UpToDate => {
            println!(
                "Vault is at version {} with recovery key support.",
                config.version
            );
            return Ok(());
        }
        MigrationStatus::NeedsMigration { from, .. } if from == VaultVersion::V1_1 => {
            println!(
                "Vault is at version {} and already has recovery key support. \
                 Run `axiom vault migrate` to upgrade it to {}.",
                from,
                VaultVersion::CURRENT
            );
            return Ok(());
        }
        MigrationStatus::NeedsMigration { from, .. } if from < VaultVersion::V1_1 => {}
        status => anyhow::bail!("Cannot enable recovery keys: {}", status),
    }

    let password = prompt_password("Enter password: ")?;
    let provider = VaultManager::new()
        .registry()
        .resolve(
            "local",
            serde_json::json!({ "root": path.to_string_lossy() }),
        )
        .context("Failed to open vault storage")?;

    let outcome = MigrationRegistry::default()
        .migrate(provider.as_ref(), &password, &VaultVersion::V1_1)
        .await
        .context("Failed to migrate vault")?;

    println!(
        "Vault migrated successfully to v{} format!",
        outcome.config.version
    );
    if let Some(words) = &outcome.recovery_words {
        display_recovery_words(words);
    }
    println!(
        "Run `axiom vault migrate` to upgrade it to {}.",
        VaultVersion::CURRENT
    );

    Ok(())
}
