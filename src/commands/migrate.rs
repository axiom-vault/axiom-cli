#![allow(unused_imports)]
use crate::cli::{ConflictStrategyArg, KdfStrength, RaidModeArg, SyncModeArg};
use crate::conversions::{conflict_strategy_from, sync_mode_from};
use crate::password::{
    display_recovery_words, kdf_params_from, prompt_password, validate_password_strength,
    vault_password,
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
    let config = VaultConfig::from_bytes(&config_bytes).context("Failed to parse config")?;

    let action = plan_migration(&check_migration_needed(&config))?;
    if action == MigrationAction::UpToDate {
        println!("Vault is up to date (version {}).", config.version);
        return Ok(());
    }

    let registry = MigrationRegistry::default();
    let target = VaultVersion::CURRENT;
    println!("Migration needed: {} -> {}", config.version, target);

    // Registry migrations stop at 1.1; the 1.1 -> CURRENT step is a separate,
    // explicit core upgrade that publishes a new manifest generation.
    let mut steps = Vec::new();
    if action == MigrationAction::RegistryThenUpgrade {
        let registry_steps = registry
            .find_path(&config.version, &VaultVersion::V1_1)
            .with_context(|| {
                format!(
                    "No migration path found from {} to {}",
                    config.version,
                    VaultVersion::V1_1
                )
            })?;
        for step in registry_steps {
            steps.push(format!(
                "{} -> {}: {}",
                step.source_version(),
                step.target_version(),
                step.description()
            ));
        }
    }
    steps.push(format!(
        "{} -> {}: explicit core upgrade (publishes a new manifest generation)",
        VaultVersion::V1_1,
        target
    ));
    println!("Migration plan ({} step(s)):", steps.len());
    for (i, step) in steps.iter().enumerate() {
        println!("  {}. {}", i + 1, step);
    }

    if dry_run {
        println!("\nDry run complete. No changes were made.");
        return Ok(());
    }

    let password = vault_password("Enter password: ")?;
    let manager = VaultManager::new();
    let provider_config = serde_json::json!({ "root": path.to_string_lossy() });

    if action == MigrationAction::RegistryThenUpgrade {
        let provider = manager
            .registry()
            .resolve("local", provider_config.clone())
            .context("Failed to open vault storage")?;

        println!("\nRunning migrations to {}...", VaultVersion::V1_1);
        let outcome = registry
            .migrate(provider.as_ref(), &password, &VaultVersion::V1_1)
            .await
            .context("Migration failed")?;
        println!("Vault migrated to version {}.", outcome.config.version);
        // Shown before the upgrade so the words survive a failed upgrade.
        if let Some(words) = &outcome.recovery_words {
            display_recovery_words(words);
        }
    }

    println!("\nUpgrading vault to version {}...", target);
    // Explicit upgrade, not `open_vault`: a 2.0 open refuses 1.1 vaults. On
    // failure the core leaves the 1.1 snapshot current.
    let session = manager
        .upgrade_to_current("local", provider_config, &password)
        .await
        .with_context(|| {
            format!(
                "Upgrade to {} failed; the vault was left at version {}",
                target,
                VaultVersion::V1_1
            )
        })?;
    let version = session.config().version;
    if version != VaultVersion::CURRENT {
        anyhow::bail!("Upgrade reported version {} instead of {}", version, target);
    }

    println!(
        "Migration completed successfully! Vault is now at version {}.",
        version
    );

    Ok(())
}

/// What `cmd_migrate` does for a vault, decided from its config alone.
#[derive(Debug, PartialEq, Eq)]
enum MigrationAction {
    /// Already at `VaultVersion::CURRENT`.
    UpToDate,
    /// Pre-1.1 vault: registry migration to 1.1, then the explicit upgrade.
    RegistryThenUpgrade,
    /// 1.1 vault: only the explicit core upgrade to `VaultVersion::CURRENT`.
    UpgradeOnly,
}

fn plan_migration(status: &MigrationStatus) -> Result<MigrationAction> {
    match status {
        MigrationStatus::UpToDate => Ok(MigrationAction::UpToDate),
        MigrationStatus::NeedsMigration { from, .. } if *from == VaultVersion::V1_1 => {
            Ok(MigrationAction::UpgradeOnly)
        }
        MigrationStatus::NeedsMigration { from, .. } if *from < VaultVersion::V1_1 => {
            Ok(MigrationAction::RegistryThenUpgrade)
        }
        MigrationStatus::NeedsMigration { from, to } => {
            anyhow::bail!("No migration path found from {} to {}", from, to)
        }
        MigrationStatus::Incompatible { version } => anyhow::bail!(
            "Vault version {} is incompatible with this software (current: {})",
            version,
            VaultVersion::CURRENT
        ),
    }
}

// ---------------------------------------------------------------------------
// RAID helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const V1_0: VaultVersion = VaultVersion { major: 1, minor: 0 };

    fn needs(from: VaultVersion) -> MigrationStatus {
        MigrationStatus::NeedsMigration {
            from,
            to: VaultVersion::CURRENT,
        }
    }

    #[test]
    fn up_to_date_vault_needs_no_action() {
        assert_eq!(
            plan_migration(&MigrationStatus::UpToDate).unwrap(),
            MigrationAction::UpToDate
        );
    }

    #[test]
    fn v1_0_vault_runs_registry_then_upgrade() {
        assert_eq!(
            plan_migration(&needs(V1_0)).unwrap(),
            MigrationAction::RegistryThenUpgrade
        );
    }

    #[test]
    fn v1_1_vault_needs_only_the_upgrade() {
        assert_eq!(
            plan_migration(&needs(VaultVersion::V1_1)).unwrap(),
            MigrationAction::UpgradeOnly
        );
    }

    #[test]
    fn incompatible_vault_is_refused() {
        let status = MigrationStatus::Incompatible {
            version: VaultVersion { major: 3, minor: 0 },
        };
        let err = plan_migration(&status).unwrap_err().to_string();
        assert!(err.contains("incompatible"), "{err}");
    }

    #[test]
    fn unknown_source_version_is_refused() {
        let err = plan_migration(&needs(VaultVersion { major: 1, minor: 2 }))
            .unwrap_err()
            .to_string();
        assert!(err.contains("No migration path"), "{err}");
    }
}
