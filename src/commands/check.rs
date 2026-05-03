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

pub(crate) async fn cmd_check(path: &Path, shallow: bool) -> Result<()> {
    let path_str = path.to_string_lossy().to_string();

    let provider_config = serde_json::json!({
        "root": path_str
    });

    let manager = VaultManager::new();
    let provider = manager
        .registry()
        .resolve("local", provider_config.clone())
        .context("Failed to create storage provider")?;

    if shallow {
        info!("Running shallow vault check (no password required)");
        let report = check_vault_structure(provider.as_ref(), &path_str)
            .await
            .context("Failed to run shallow health check")?;

        print_health_report(&report);
        return Ok(());
    }

    info!("Running full vault health check");
    let password = prompt_password("Enter password: ")?;

    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let master_key = session.master_key().context("Session not active")?;

    let report = check_vault_health(provider.as_ref(), session.config(), master_key, &path_str)
        .await
        .context("Failed to run health check")?;

    print_health_report(&report);

    Ok(())
}

/// Print a health report to stdout.
fn print_health_report(report: &axiomvault_vault::HealthReport) {
    println!("Vault Health Report: {}", report.component);
    println!("{}", "=".repeat(50));

    for result in &report.results {
        let icon = match result.severity {
            axiomvault_vault::Severity::Info => "[OK]  ",
            axiomvault_vault::Severity::Warning => "[WARN]",
            axiomvault_vault::Severity::Error => "[ERR] ",
        };
        println!("  {} {}: {}", icon, result.check_name, result.message);
        if result.auto_fixable {
            println!("         (auto-fixable)");
        }
    }

    println!();
    println!("Result: {}", report.status);
}
