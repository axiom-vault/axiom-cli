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
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RaidConfig {
    mode: RaidModeConfig,
    backends: Vec<BackendEntry>,
}

/// Serialised RAID mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RaidModeConfig {
    /// `"mirror"` or `"erasure"`.
    #[serde(rename = "type")]
    mode_type: String,
    /// Number of data shards (erasure only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_shards: Option<usize>,
    /// Number of parity shards (erasure only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parity_shards: Option<usize>,
}

/// A single backend entry in the RAID config.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackendEntry {
    /// Provider type name (e.g. `"local"`, `"gdrive"`).
    provider_type: String,
    /// Provider-specific configuration (passed to `ProviderRegistry::resolve`).
    config: serde_json::Value,
}

fn raid_config_path(vault_path: &Path) -> PathBuf {
    vault_path.join(".axiomvault").join("raid.json")
}

/// Load the RAID configuration from disk.  Returns `None` if not found.
async fn load_raid_config(vault_path: &Path) -> Result<Option<RaidConfig>> {
    let path = raid_config_path(vault_path);
    if !path.exists() {
        return Ok(None);
    }
    let data = tokio::fs::read_to_string(&path)
        .await
        .context("Failed to read RAID config")?;
    let cfg: RaidConfig = serde_json::from_str(&data).context("Failed to parse RAID config")?;
    Ok(Some(cfg))
}

/// Save the RAID configuration atomically (write-then-rename).
async fn save_raid_config(vault_path: &Path, config: &RaidConfig) -> Result<()> {
    let dir = vault_path.join(".axiomvault");
    tokio::fs::create_dir_all(&dir)
        .await
        .context("Failed to create .axiomvault directory")?;

    let tmp_path = dir.join("raid.json.tmp");
    let final_path = dir.join("raid.json");

    let json = serde_json::to_string_pretty(config).context("Failed to serialize RAID config")?;
    tokio::fs::write(&tmp_path, &json)
        .await
        .context("Failed to write RAID config tmp")?;
    tokio::fs::rename(&tmp_path, &final_path)
        .await
        .context("Failed to rename RAID config")?;
    Ok(())
}

/// Convert a `RaidConfig` into a `RaidMode`.
fn raid_mode_from_config(cfg: &RaidModeConfig) -> Result<RaidMode> {
    match cfg.mode_type.as_str() {
        "mirror" => Ok(RaidMode::Mirror),
        "erasure" => {
            let data_shards = cfg
                .data_shards
                .ok_or_else(|| anyhow::anyhow!("erasure mode requires data_shards"))?;
            let parity_shards = cfg
                .parity_shards
                .ok_or_else(|| anyhow::anyhow!("erasure mode requires parity_shards"))?;
            Ok(RaidMode::Erasure {
                data_shards,
                parity_shards,
            })
        }
        other => anyhow::bail!("Unknown RAID mode type: {}", other),
    }
}

/// Build a `CompositeStorageProvider` from a persisted `RaidConfig`.
fn build_composite(config: &RaidConfig) -> Result<CompositeStorageProvider> {
    let registry = create_default_registry();
    let mut backends: Vec<Arc<dyn axiomvault_storage::StorageProvider>> = Vec::new();

    for (i, entry) in config.backends.iter().enumerate() {
        let provider = registry
            .resolve(&entry.provider_type, entry.config.clone())
            .with_context(|| format!("Failed to create backend {} ({})", i, entry.provider_type))?;
        backends.push(provider);
    }

    let mode = raid_mode_from_config(&config.mode)?;
    let composite_config = CompositeConfig {
        mode,
        health: Default::default(),
    };

    let composite = CompositeStorageProvider::new(backends, composite_config)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(composite)
}

// ---------------------------------------------------------------------------
// RAID commands
// ---------------------------------------------------------------------------

/// Add a storage backend to the RAID pool.
pub(crate) async fn cmd_raid_add_backend(
    vault_path: &Path,
    provider: &str,
    config_json: &str,
) -> Result<()> {
    info!("Adding backend to RAID pool: {}", provider);

    // Validate provider type and config by trying to resolve it.
    let provider_config: serde_json::Value =
        serde_json::from_str(config_json).context("Invalid JSON config")?;
    let registry = create_default_registry();
    registry
        .resolve(provider, provider_config.clone())
        .with_context(|| format!("Failed to create provider '{}'", provider))?;

    let entry = BackendEntry {
        provider_type: provider.to_string(),
        config: provider_config,
    };

    let mut raid_cfg = load_raid_config(vault_path)
        .await?
        .unwrap_or_else(|| RaidConfig {
            mode: RaidModeConfig {
                mode_type: "mirror".to_string(),
                data_shards: None,
                parity_shards: None,
            },
            backends: Vec::new(),
        });

    raid_cfg.backends.push(entry);

    // If we now have >=2 backends and a composite can be formed, sync the shard map.
    if raid_cfg.backends.len() >= 2 {
        match build_composite(&raid_cfg) {
            Ok(composite) => {
                if let Err(e) = composite.load_shard_map().await {
                    eprintln!("Warning: could not load shard map: {}", e);
                } else if let Err(e) = composite.save_shard_map().await {
                    eprintln!("Warning: could not sync shard map to new backend: {}", e);
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: cannot form composite yet ({}). \
                     You may need to run raid-configure after adding enough backends.",
                    e
                );
            }
        }
    }

    save_raid_config(vault_path, &raid_cfg).await?;

    println!("Backend added successfully!");
    println!("  Index: {}", raid_cfg.backends.len() - 1);
    println!("  Provider: {}", provider);
    println!("  Total backends: {}", raid_cfg.backends.len());

    Ok(())
}

/// Remove a storage backend from the RAID pool.
///
/// In erasure mode, shards on the removed backend are rebuilt onto remaining
/// backends before removal. In mirror mode, data exists on all other backends
/// so no migration is needed.
pub(crate) async fn cmd_raid_remove_backend(vault_path: &Path, index: usize) -> Result<()> {
    info!("Removing backend {} from RAID pool", index);

    let mut raid_cfg = load_raid_config(vault_path).await?.ok_or_else(|| {
        anyhow::anyhow!("No RAID configuration found. Run raid-add-backend first.")
    })?;

    if index >= raid_cfg.backends.len() {
        anyhow::bail!(
            "Backend index {} out of range (have {} backends)",
            index,
            raid_cfg.backends.len()
        );
    }

    // Check minimum redundancy.
    let remaining = raid_cfg.backends.len() - 1;
    let min_required = match raid_cfg.mode.mode_type.as_str() {
        "mirror" => 2,
        "erasure" => {
            let ds = raid_cfg.mode.data_shards.unwrap_or(0);
            let ps = raid_cfg.mode.parity_shards.unwrap_or(0);
            ds + ps
        }
        _ => 2,
    };

    if remaining < min_required {
        anyhow::bail!(
            "Cannot remove backend: {} mode requires at least {} backends, \
             but only {} would remain",
            raid_cfg.mode.mode_type,
            min_required,
            remaining
        );
    }

    if raid_cfg.mode.mode_type == "erasure" && remaining == min_required {
        eprintln!(
            "Warning: After removal, the array will have zero fault tolerance. \
             Any backend failure will result in data loss."
        );
    }

    // Migrate shards before removal if the backend holds any data.
    if raid_cfg.backends.len() >= 2 {
        let composite = build_composite(&raid_cfg)?;
        composite.load_shard_map().await?;

        let shard_map = composite.get_shard_map().await;
        let has_shards = shard_map
            .entries
            .values()
            .any(|entry| entry.shards.contains_key(&index));

        if has_shards {
            match raid_cfg.mode.mode_type.as_str() {
                "mirror" => {
                    // Mirror mode: data exists on all other backends,
                    // no migration needed. Just clean up the shard map.
                    eprintln!(
                        "Mirror mode: data is replicated on other backends, \
                         no migration needed."
                    );
                }
                "erasure" => {
                    // Erasure mode: rebuild shards onto another backend
                    // before removing this one.
                    eprintln!(
                        "Erasure mode: rebuilding shards from backend {} \
                         before removal...",
                        index
                    );

                    // Pick a rebuild target: first healthy backend that isn't
                    // the one being removed.
                    let mut rebuild_target = None;
                    for i in 0..composite.backend_count() {
                        if i == index {
                            continue;
                        }
                        if let Some(h) = composite.backend_health(i).await {
                            if h.status == HealthStatus::Healthy {
                                rebuild_target = Some(i);
                                break;
                            }
                        }
                    }

                    let target = rebuild_target.ok_or_else(|| {
                        anyhow::anyhow!(
                            "No healthy backend available to receive \
                             redistributed shards. Aborting removal."
                        )
                    })?;

                    let rebuilder =
                        RaidRebuilder::new(&composite, target, RebuildConfig::default())
                            .map_err(|e| anyhow::anyhow!("{}", e))?;

                    let result = rebuilder.rebuild().await.map_err(|e| {
                        anyhow::anyhow!("Shard migration failed, aborting removal: {}", e)
                    })?;

                    eprintln!(
                        "Migration complete: {} rebuilt, {} skipped, {} failed",
                        result.rebuilt, result.skipped, result.failed
                    );

                    if result.failed > 0 {
                        anyhow::bail!(
                            "Shard migration had {} failures. \
                             Aborting removal to prevent data loss.",
                            result.failed
                        );
                    }
                }
                _ => {}
            }
        }

        // Clone the current shard map before mutating so we can roll back.
        let shard_map_backup = composite.get_shard_map().await;

        // Compute the updated shard map: remove all references to the removed
        // backend and re-index higher backend indices.
        {
            let mut map = composite.shard_map_ref().write().await;
            for entry in map.entries.values_mut() {
                entry.shards.remove(&index);
                // Re-index: shift down any shard indices above the removed one.
                let shifted: std::collections::HashMap<usize, _> = entry
                    .shards
                    .drain()
                    .map(|(k, mut loc)| {
                        let new_idx = if k > index { k - 1 } else { k };
                        loc.shard_index = new_idx;
                        (new_idx, loc)
                    })
                    .collect();
                entry.shards = shifted;
            }
            map.version += 1;
            map.updated_at = chrono::Utc::now();
        }

        // Persist updated shard map first (step 1 of atomic commit).
        composite.save_shard_map().await?;

        // Remove the backend from config and persist (step 2 of atomic commit).
        let removed = raid_cfg.backends.remove(index);
        if let Err(e) = save_raid_config(vault_path, &raid_cfg).await {
            // Roll back the shard map to the pre-removal state.
            eprintln!("Failed to save RAID config, rolling back shard map...");
            {
                let mut map = composite.shard_map_ref().write().await;
                *map = shard_map_backup;
            }
            composite.save_shard_map().await.map_err(|rollback_err| {
                anyhow::anyhow!(
                    "CRITICAL: config save failed ({}) and shard map rollback \
                         also failed ({}). Manual recovery may be needed.",
                    e,
                    rollback_err
                )
            })?;
            // Re-insert the backend so the in-memory state is consistent.
            raid_cfg.backends.insert(index, removed);
            return Err(e);
        }

        println!("Backend removed successfully!");
        println!("  Removed: {} (index {})", removed.provider_type, index);
        println!("  Remaining backends: {}", raid_cfg.backends.len());
        return Ok(());
    }

    let removed = raid_cfg.backends.remove(index);
    save_raid_config(vault_path, &raid_cfg).await?;

    println!("Backend removed successfully!");
    println!("  Removed: {} (index {})", removed.provider_type, index);
    println!("  Remaining backends: {}", raid_cfg.backends.len());

    Ok(())
}

/// Show RAID status: mode, backends, health, and shard distribution.
pub(crate) async fn cmd_raid_status(vault_path: &Path) -> Result<()> {
    let raid_cfg = load_raid_config(vault_path).await?.ok_or_else(|| {
        anyhow::anyhow!("No RAID configuration found. Run raid-add-backend first.")
    })?;

    // Print RAID mode.
    println!("RAID Configuration");
    println!("{}", "=".repeat(60));
    match raid_cfg.mode.mode_type.as_str() {
        "mirror" => println!("  Mode: Mirror (RAID 1)"),
        "erasure" => println!(
            "  Mode: Erasure (RAID 5/6) — k={}, m={}",
            raid_cfg.mode.data_shards.unwrap_or(0),
            raid_cfg.mode.parity_shards.unwrap_or(0),
        ),
        other => println!("  Mode: {}", other),
    }
    println!("  Backends: {}", raid_cfg.backends.len());
    println!();

    if raid_cfg.backends.len() < 2 {
        println!("Backends:");
        for (i, entry) in raid_cfg.backends.iter().enumerate() {
            println!(
                "  [{}] {} — not enough backends for RAID",
                i, entry.provider_type
            );
        }
        return Ok(());
    }

    // Build the composite and show live health.
    let composite = build_composite(&raid_cfg)?;
    if let Err(e) = composite.load_shard_map().await {
        eprintln!("Warning: could not load shard map: {}", e);
    }

    let shard_map = composite.get_shard_map().await;

    // Count shards per backend.
    let backend_count = composite.backend_count();
    let mut shard_counts = vec![0usize; backend_count];
    for entry in shard_map.entries.values() {
        for shard in entry.shards.values() {
            if shard.shard_index < backend_count {
                shard_counts[shard.shard_index] += 1;
            }
        }
    }

    println!(
        "  {:<6} {:<12} {:<10} {:<8} Last Success",
        "Index", "Provider", "Health", "Shards"
    );
    println!("  {}", "-".repeat(54));

    for (i, shard_count) in shard_counts.iter().enumerate() {
        let health = composite.backend_health(i).await;
        let (status_str, last_success) = match &health {
            Some(h) => {
                let status = match h.status {
                    HealthStatus::Healthy => "Healthy",
                    HealthStatus::Degraded => "Degraded",
                    HealthStatus::Unhealthy => "Unhealthy",
                };
                let last = h
                    .last_success
                    .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "never".to_string());
                (status, last)
            }
            None => ("Unknown", "n/a".to_string()),
        };

        println!(
            "  {:<6} {:<12} {:<10} {:<8} {}",
            i, raid_cfg.backends[i].provider_type, status_str, shard_count, last_success
        );
    }

    println!();
    println!(
        "Shard Map: {} entries, version {}",
        shard_map.entries.len(),
        shard_map.version
    );

    // Redundancy summary.
    let healthy = composite.healthy_backend_count().await;
    println!("Redundancy: {}/{} backends healthy", healthy, backend_count);

    Ok(())
}

/// Rebuild missing shards on a target backend.
pub(crate) async fn cmd_raid_rebuild(vault_path: &Path, target: Option<usize>) -> Result<()> {
    let raid_cfg = load_raid_config(vault_path).await?.ok_or_else(|| {
        anyhow::anyhow!("No RAID configuration found. Run raid-add-backend first.")
    })?;

    if raid_cfg.backends.len() < 2 {
        anyhow::bail!("Need at least 2 backends for RAID rebuild");
    }

    let composite = build_composite(&raid_cfg)?;

    // Load the shard map so the rebuilder knows which shards need reconstruction.
    composite
        .load_shard_map()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load shard map: {}", e))?;

    // Determine target: explicit index or first non-healthy backend.
    let target_index = match target {
        Some(idx) => {
            if idx >= composite.backend_count() {
                anyhow::bail!(
                    "Target index {} out of range (have {} backends)",
                    idx,
                    composite.backend_count()
                );
            }
            idx
        }
        None => {
            // Find first degraded/offline backend.
            let mut found = None;
            for i in 0..composite.backend_count() {
                if let Some(h) = composite.backend_health(i).await {
                    if h.status != HealthStatus::Healthy {
                        found = Some(i);
                        break;
                    }
                }
            }
            found.ok_or_else(|| {
                anyhow::anyhow!(
                    "All backends are healthy. Use --target to force rebuild on a specific backend."
                )
            })?
        }
    };

    println!(
        "Rebuilding backend {} ({})...",
        target_index, raid_cfg.backends[target_index].provider_type
    );

    let rebuilder = RaidRebuilder::new(&composite, target_index, RebuildConfig::default())
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Run the rebuild with a progress bar by polling progress every 500ms.
    let result = rebuild_with_progress(&rebuilder).await?;

    println!("\nRebuild completed!");
    println!("  Rebuilt:  {}", result.rebuilt);
    println!("  Skipped:  {}", result.skipped);
    println!("  Failed:   {}", result.failed);
    println!("  Elapsed:  {:.1?}", result.elapsed);

    Ok(())
}

/// Run a rebuild while displaying a text progress bar on stderr.
///
/// Uses `tokio::select!` to poll `rebuilder.progress()` every 500ms while the
/// rebuild future runs concurrently on the same task.
async fn rebuild_with_progress(rebuilder: &RaidRebuilder<'_>) -> Result<RebuildResult> {
    use tokio::pin;

    let rebuild_fut = rebuilder.rebuild();
    pin!(rebuild_fut);

    let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
    // First tick fires immediately; consume it so the first real tick is at 500ms.
    interval.tick().await;

    loop {
        tokio::select! {
            result = &mut rebuild_fut => {
                // Print final progress state before returning.
                let progress = rebuilder.progress().await;
                print_progress_bar(&progress);
                return result.map_err(|e| anyhow::anyhow!("{}", e));
            }
            _ = interval.tick() => {
                let progress = rebuilder.progress().await;
                print_progress_bar(&progress);
            }
        }
    }
}

/// Print a single-line progress bar to stderr, overwriting the previous line.
///
/// Format: `[=====>    ] 55% (12/22 chunks, ETA: 3s)`
fn print_progress_bar(progress: &axiomvault_storage::rebuild::RebuildProgress) {
    use std::io::Write;

    let pct = progress.percentage();
    let done = progress.completed + progress.skipped + progress.failed;
    let total = progress.total;

    // Build bar: 30 characters wide.
    let bar_width = 30;
    let filled = ((pct / 100.0) * bar_width as f64) as usize;
    let filled = filled.min(bar_width);
    let empty = bar_width - filled;

    let arrow = if filled > 0 && filled < bar_width {
        format!("{}>{}", "=".repeat(filled - 1), " ".repeat(empty))
    } else if filled == bar_width {
        "=".repeat(bar_width)
    } else {
        " ".repeat(bar_width)
    };

    let eta_str = match progress.eta() {
        Some(d) => format!(", ETA: {}s", d.as_secs()),
        None => String::new(),
    };

    eprint!(
        "\r[{}] {:>3.0}% ({}/{} chunks{})",
        arrow, pct, done, total, eta_str,
    );
    let _ = std::io::stderr().flush();
}

/// Configure or change the RAID mode.
pub(crate) async fn cmd_raid_configure(
    vault_path: &Path,
    mode: RaidModeArg,
    data_shards: Option<usize>,
    parity_shards: Option<usize>,
) -> Result<()> {
    info!("Configuring RAID mode");

    let mut raid_cfg = load_raid_config(vault_path).await?.ok_or_else(|| {
        anyhow::anyhow!("No RAID configuration found. Run raid-add-backend first.")
    })?;

    let mode_config = match mode {
        RaidModeArg::Mirror => RaidModeConfig {
            mode_type: "mirror".to_string(),
            data_shards: None,
            parity_shards: None,
        },
        RaidModeArg::Erasure => {
            let k = data_shards
                .ok_or_else(|| anyhow::anyhow!("Erasure mode requires --data-shards (-k)"))?;
            let m = parity_shards
                .ok_or_else(|| anyhow::anyhow!("Erasure mode requires --parity-shards (-m)"))?;

            if k == 0 {
                anyhow::bail!("data-shards must be at least 1");
            }
            if m == 0 {
                anyhow::bail!("parity-shards must be at least 1");
            }
            if k + m != raid_cfg.backends.len() {
                anyhow::bail!(
                    "data-shards ({}) + parity-shards ({}) must equal backend count ({})",
                    k,
                    m,
                    raid_cfg.backends.len()
                );
            }

            RaidModeConfig {
                mode_type: "erasure".to_string(),
                data_shards: Some(k),
                parity_shards: Some(m),
            }
        }
    };

    raid_cfg.mode = mode_config;
    save_raid_config(vault_path, &raid_cfg).await?;

    match mode {
        RaidModeArg::Mirror => println!("RAID mode set to Mirror (RAID 1)."),
        RaidModeArg::Erasure => {
            let k = data_shards.expect("validated above");
            let m = parity_shards.expect("validated above");
            println!("RAID mode set to Erasure (k={k}, m={m}).");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{print_progress_bar, rebuild_with_progress};

    use axiomvault_storage::{
        rebuild::{RebuildConfig, RebuildProgress},
        CompositeConfig, CompositeStorageProvider, MemoryProvider, RaidMode, RaidRebuilder,
        StorageProvider,
    };
    use std::sync::Arc;
    use std::time::Instant;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_mirror_composite(n: usize) -> CompositeStorageProvider {
        let backends: Vec<Arc<dyn axiomvault_storage::StorageProvider>> = (0..n)
            .map(|_| Arc::new(MemoryProvider::new()) as _)
            .collect();
        let config = CompositeConfig {
            mode: RaidMode::Mirror,
            health: Default::default(),
        };
        CompositeStorageProvider::new(backends, config).expect("mirror composite")
    }

    fn progress_with(
        total: usize,
        completed: usize,
        skipped: usize,
        failed: usize,
    ) -> RebuildProgress {
        RebuildProgress {
            total,
            completed,
            skipped,
            failed,
            started_at: Instant::now(),
        }
    }

    // -----------------------------------------------------------------------
    // print_progress_bar – smoke tests covering all three arrow branches
    // -----------------------------------------------------------------------

    /// filled == 0: all spaces branch (pct is 0 and total > 0)
    #[test]
    fn test_print_progress_bar_zero_percent() {
        let progress = progress_with(100, 0, 0, 0);
        // Must not panic; ETA is None because done == 0.
        print_progress_bar(&progress);
    }

    /// filled == bar_width (30): equals-only branch (100%)
    #[test]
    fn test_print_progress_bar_full_progress() {
        let progress = progress_with(10, 10, 0, 0);
        // All items completed => 100% => filled == 30 => "=" * 30 branch.
        print_progress_bar(&progress);
    }

    /// filled in (0, bar_width): arrow branch with "===>   " format
    #[test]
    fn test_print_progress_bar_mid_progress_arrow() {
        // 5/10 completed = 50% => filled = 15 => arrow branch
        let progress = progress_with(10, 5, 0, 0);
        print_progress_bar(&progress);
    }

    /// filled == 1: degenerate arrow (0 '=' chars before '>') must not panic.
    /// filled = floor((pct/100) * 30). With 4/100 done => pct=4.0 =>
    /// floor(0.04 * 30) = floor(1.2) = 1. Arrow becomes ">" + 29 spaces.
    #[test]
    fn test_print_progress_bar_one_unit_filled() {
        // 4 out of 100 done => pct=4.0% => filled=1 => degenerate arrow branch
        let progress = progress_with(100, 4, 0, 0);
        print_progress_bar(&progress);
    }

    /// ETA branch: Some(d) when done > 0 and remaining > 0
    #[test]
    fn test_print_progress_bar_eta_displayed() {
        // 5 completed with 5 remaining => ETA should be Some
        let progress = progress_with(10, 5, 0, 0);
        // Verify eta() returns Some before calling print.
        assert!(progress.eta().is_some());
        print_progress_bar(&progress);
    }

    /// No ETA when done == 0 (rate is unknown)
    #[test]
    fn test_print_progress_bar_no_eta_when_nothing_done() {
        let progress = progress_with(10, 0, 0, 0);
        assert!(progress.eta().is_none());
        print_progress_bar(&progress);
    }

    /// total == 0: percentage() returns 100.0, filled == 30, equals-only branch
    #[test]
    fn test_print_progress_bar_empty_total() {
        let progress = progress_with(0, 0, 0, 0);
        assert_eq!(progress.percentage(), 100.0);
        print_progress_bar(&progress);
    }

    /// Mixed completed/skipped/failed contributes to 'done' counter
    #[test]
    fn test_print_progress_bar_counts_all_outcomes() {
        let progress = progress_with(30, 5, 3, 2);
        // done = 10/30 = 33% => filled = 10 => arrow branch
        let pct = progress.percentage();
        assert!((pct - 33.33).abs() < 0.5);
        print_progress_bar(&progress);
    }

    // -----------------------------------------------------------------------
    // rebuild_with_progress – integration tests using MemoryProvider backends
    // -----------------------------------------------------------------------

    /// Empty shard map: rebuild completes immediately with zero counts.
    #[tokio::test]
    async fn test_rebuild_with_progress_empty_shard_map() {
        let composite = make_mirror_composite(3);
        let rebuilder =
            RaidRebuilder::new(&composite, 0, RebuildConfig::default()).expect("rebuilder");

        let result = rebuild_with_progress(&rebuilder)
            .await
            .expect("rebuild_with_progress");

        assert_eq!(result.rebuilt, 0);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.failed, 0);
    }

    /// File present on all backends: rebuild skips everything (already present).
    #[tokio::test]
    async fn test_rebuild_with_progress_skips_existing_chunks() {
        let composite = make_mirror_composite(3);

        // Upload a file so it exists on all backends via the composite.
        let vp = axiomvault_common::VaultPath::parse("/test.enc").unwrap();
        composite
            .upload(&vp, b"test data".to_vec())
            .await
            .expect("upload");

        // Target is backend 2, which already has the file.
        let rebuilder =
            RaidRebuilder::new(&composite, 2, RebuildConfig::default()).expect("rebuilder");

        let result = rebuild_with_progress(&rebuilder)
            .await
            .expect("rebuild_with_progress");

        assert_eq!(result.rebuilt, 0);
        assert_eq!(result.skipped, 1);
        assert_eq!(result.failed, 0);
    }

    /// File missing from target backend: rebuild restores it.
    #[tokio::test]
    async fn test_rebuild_with_progress_restores_missing_chunk() {
        let composite = make_mirror_composite(3);

        let vp = axiomvault_common::VaultPath::parse("/restore.enc").unwrap();
        composite
            .upload(&vp, b"restore me".to_vec())
            .await
            .expect("upload");

        // Manually delete the file from backend 2 via direct backend access.
        composite.backends()[2]
            .delete(&vp)
            .await
            .expect("delete from backend 2");

        assert!(
            !composite.backends()[2]
                .exists(&vp)
                .await
                .expect("exists check"),
            "backend 2 should be missing the file"
        );

        // Rebuild targeting backend 2.
        let rebuilder =
            RaidRebuilder::new(&composite, 2, RebuildConfig::default()).expect("rebuilder");

        let result = rebuild_with_progress(&rebuilder)
            .await
            .expect("rebuild_with_progress");

        assert_eq!(result.rebuilt, 1);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.failed, 0);

        // Verify the file is restored on backend 2.
        assert!(
            composite.backends()[2]
                .exists(&vp)
                .await
                .expect("exists after rebuild"),
            "backend 2 should have the file after rebuild"
        );
        let data = composite.backends()[2]
            .download(&vp)
            .await
            .expect("download after rebuild");
        assert_eq!(data, b"restore me");
    }

    /// Multiple files, some missing: counts rebuilt vs skipped correctly.
    #[tokio::test]
    async fn test_rebuild_with_progress_multiple_files_partial_miss() {
        let composite = make_mirror_composite(3);

        let vp_a = axiomvault_common::VaultPath::parse("/a.enc").unwrap();
        let vp_b = axiomvault_common::VaultPath::parse("/b.enc").unwrap();
        let vp_c = axiomvault_common::VaultPath::parse("/c.enc").unwrap();

        composite
            .upload(&vp_a, b"aaa".to_vec())
            .await
            .expect("upload a");
        composite
            .upload(&vp_b, b"bbb".to_vec())
            .await
            .expect("upload b");
        composite
            .upload(&vp_c, b"ccc".to_vec())
            .await
            .expect("upload c");

        // Delete a and c from backend 1.
        composite.backends()[1].delete(&vp_a).await.expect("del a");
        composite.backends()[1].delete(&vp_c).await.expect("del c");

        let rebuilder =
            RaidRebuilder::new(&composite, 1, RebuildConfig::default()).expect("rebuilder");

        let result = rebuild_with_progress(&rebuilder)
            .await
            .expect("rebuild_with_progress");

        assert_eq!(result.rebuilt, 2);
        assert_eq!(result.skipped, 1);
        assert_eq!(result.failed, 0);
    }

    /// rebuild_with_progress returns Ok even when the RebuildResult has all zeros.
    /// This verifies the function's return type and that it doesn't error on no-op.
    #[tokio::test]
    async fn test_rebuild_with_progress_returns_ok_on_noop() {
        let composite = make_mirror_composite(2);
        let rebuilder =
            RaidRebuilder::new(&composite, 0, RebuildConfig::default()).expect("rebuilder");

        let result = rebuild_with_progress(&rebuilder).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }
}
