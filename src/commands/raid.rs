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
    create_default_registry, CompositeConfig, CompositeKey, CompositeStorageProvider, HealthStatus,
    RaidMode, RaidRebuilder, RebuildConfig, RebuildResult,
};
use axiomvault_sync::{ConflictStrategy, SyncConfig, SyncEngine, SyncMode, SyncState};
use axiomvault_vault::{
    check_migration_needed, check_vault_health, check_vault_structure, MigrationRegistry,
    MigrationStatus, VaultConfig, VaultManager, VaultOperations, VaultVersion,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::info;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RaidConfig {
    mode: RaidModeConfig,
    backends: Vec<BackendEntry>,
    /// Secret key that authenticates the shard map and every shard (M-16).
    /// Generated when the set is created; it stays in this local file and is
    /// never written to a backend. `None` only for a config that predates it.
    #[serde(default)]
    composite_key: Option<StoredKey>,
}

impl RaidConfig {
    /// The set's composite key.
    fn key(&self) -> Result<CompositeKey> {
        self.composite_key
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "it has no composite key, so it was written before the shard map was \
                     authenticated and cannot be used. Recreate the RAID set: move raid.json \
                     aside and run 'axiom raid add-backend' again for each backend, using \
                     empty backend locations."
                )
            })?
            .to_key()
    }
}

/// A composite key stored as 64 hex digits. `Debug` never shows it and the
/// string is wiped on drop.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct StoredKey(String);

impl StoredKey {
    /// 32 fresh bytes from the OS random number generator.
    fn generate() -> Result<Self> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut_slice())
            .map_err(|e| anyhow::anyhow!("OS random number generator failed: {e}"))?;
        // Sized up front so the string never reallocates and leaves a copy behind.
        let mut hex = String::with_capacity(64);
        for byte in bytes.iter() {
            hex.push(HEX[usize::from(byte >> 4)] as char);
            hex.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        Ok(Self(hex))
    }

    /// Decode the key. Errors never include the stored digits.
    fn to_key(&self) -> Result<CompositeKey> {
        let digits = self.0.as_bytes();
        if digits.len() != 64 {
            anyhow::bail!("its composite key is not 64 hex digits");
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        for (byte, pair) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
            let (Some(hi), Some(lo)) = (
                char::from(pair[0]).to_digit(16),
                char::from(pair[1]).to_digit(16),
            ) else {
                anyhow::bail!("its composite key contains a non-hex digit");
            };
            *byte = ((hi << 4) | lo) as u8;
        }
        Ok(CompositeKey::from_bytes(*bytes))
    }
}

impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredKey([REDACTED])")
    }
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
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
    let data = Zeroizing::new(data);
    let cfg: RaidConfig = serde_json::from_str(&data).context("Failed to parse RAID config")?;
    // Refuse a config without a usable key here, so every raid command does.
    cfg.key()
        .with_context(|| format!("Cannot use RAID config {}", path.display()))?;
    Ok(Some(cfg))
}

/// Save the RAID configuration atomically (write-then-rename). The file holds
/// the composite key, so it is created with mode 0600, synced before and after
/// the rename, and refused on non-Unix, where that mode cannot be checked.
async fn save_raid_config(vault_path: &Path, config: &RaidConfig) -> Result<()> {
    let dir = vault_path.join(".axiomvault");

    let json = Zeroizing::new(
        serde_json::to_string_pretty(config).context("Failed to serialize RAID config")?,
    );

    let mut dir_builder = tokio::fs::DirBuilder::new();
    dir_builder.recursive(true);
    #[cfg(unix)]
    dir_builder.mode(0o700);
    dir_builder
        .create(&dir)
        .await
        .context("Failed to create .axiomvault directory")?;

    crate::private_file::write_private_file(&raid_config_path(vault_path), json.as_bytes())
        .await
        .context("Failed to save RAID config")
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

    let composite = CompositeStorageProvider::new(backends, composite_config, config.key()?)
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

    // The first backend creates the RAID set, and with it the set's key.
    let existing = load_raid_config(vault_path).await?;
    let created = existing.is_none();
    let mut raid_cfg = match existing {
        Some(cfg) => cfg,
        None => RaidConfig {
            mode: RaidModeConfig {
                mode_type: "mirror".to_string(),
                data_shards: None,
                parity_shards: None,
            },
            backends: Vec::new(),
            composite_key: Some(StoredKey::generate()?),
        },
    };

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
                     You may need to run 'axiom raid configure' after adding enough backends.",
                    e
                );
            }
        }
    }

    save_raid_config(vault_path, &raid_cfg).await?;

    if created {
        eprintln!(
            "Warning: created a new RAID set. Its composite key is stored only in {}. \
             Back up that file and keep it private: if it is lost, the RAID set cannot be read.",
            raid_config_path(vault_path).display()
        );
    }

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
        anyhow::anyhow!("No RAID configuration found. Run 'axiom raid add-backend' first.")
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
        anyhow::anyhow!("No RAID configuration found. Run 'axiom raid add-backend' first.")
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
        anyhow::anyhow!("No RAID configuration found. Run 'axiom raid add-backend' first.")
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
        anyhow::anyhow!("No RAID configuration found. Run 'axiom raid add-backend' first.")
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
    use super::{
        build_composite, cmd_raid_add_backend, load_raid_config, print_progress_bar,
        raid_config_path, rebuild_with_progress,
    };

    use axiomvault_storage::{
        rebuild::{RebuildConfig, RebuildProgress},
        CompositeConfig, CompositeKey, CompositeStorageProvider, MemoryProvider, RaidMode,
        RaidRebuilder, StorageProvider,
    };
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
        CompositeStorageProvider::new(backends, config, CompositeKey::from_bytes([0x42; 32]))
            .expect("mirror composite")
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

    // -----------------------------------------------------------------------
    // RAID config – per-set composite key
    // -----------------------------------------------------------------------

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "axiom-cli-raid-{prefix}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn local_backend_config(root: &Path, index: usize) -> String {
        let backend = root.join(format!("backend-{index}"));
        std::fs::create_dir_all(&backend).unwrap();
        serde_json::json!({ "root": backend }).to_string()
    }

    /// Create a RAID set at `root/vault` from `n` local backends.
    async fn create_local_set(root: &Path, n: usize) -> PathBuf {
        let vault = root.join("vault");
        for i in 0..n {
            cmd_raid_add_backend(&vault, "local", &local_backend_config(root, i))
                .await
                .expect("add backend");
        }
        vault
    }

    fn stored_key_hex(vault: &Path) -> Option<String> {
        let data = std::fs::read_to_string(raid_config_path(vault)).unwrap();
        let json: serde_json::Value = serde_json::from_str(&data).unwrap();
        json["composite_key"].as_str().map(str::to_string)
    }

    #[tokio::test]
    async fn test_create_writes_private_config_with_32_byte_key() {
        let dir = TempDir::new("create");
        let vault = create_local_set(dir.path(), 1).await;

        let hex = stored_key_hex(&vault).expect("composite_key");
        assert_eq!(hex.len(), 64, "32 bytes as hex");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let cfg = load_raid_config(&vault).await.unwrap().expect("config");
        cfg.key().expect("key decodes");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(raid_config_path(&vault))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn test_config_without_key_is_refused() {
        let dir = TempDir::new("nokey");
        let vault = dir.path().join("vault");
        std::fs::create_dir_all(vault.join(".axiomvault")).unwrap();
        let legacy = r#"{"mode":{"type":"mirror"},"backends":[]}"#;
        std::fs::write(raid_config_path(&vault), legacy).unwrap();

        let msg = format!("{:#}", load_raid_config(&vault).await.unwrap_err());
        assert!(msg.contains("no composite key"), "{msg}");
        assert!(msg.contains("Recreate the RAID set"), "{msg}");

        // Adding a backend must not quietly give the old set a new key.
        let err = cmd_raid_add_backend(&vault, "local", &local_backend_config(dir.path(), 0))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("no composite key"));
        assert_eq!(
            std::fs::read_to_string(raid_config_path(&vault)).unwrap(),
            legacy
        );
    }

    #[tokio::test]
    async fn test_two_creates_use_different_keys() {
        let (a, b) = (TempDir::new("key-a"), TempDir::new("key-b"));
        let key_a = stored_key_hex(&create_local_set(a.path(), 1).await);
        let key_b = stored_key_hex(&create_local_set(b.path(), 1).await);
        assert!(key_a.is_some());
        assert_ne!(key_a, key_b);
    }

    #[tokio::test]
    async fn test_composite_from_config_reads_back_what_it_wrote() {
        let dir = TempDir::new("readback");
        let vault = create_local_set(dir.path(), 2).await;
        let path = axiomvault_common::VaultPath::parse("/data.enc").unwrap();

        let cfg = load_raid_config(&vault).await.unwrap().expect("config");
        build_composite(&cfg)
            .unwrap()
            .upload(&path, b"raid payload".to_vec())
            .await
            .expect("upload");

        // A fresh composite from the reloaded config verifies the set's tags.
        let cfg = load_raid_config(&vault).await.unwrap().expect("config");
        let reader = build_composite(&cfg).unwrap();
        assert_eq!(reader.download(&path).await.unwrap(), b"raid payload");

        // Under another key the same backends do not verify.
        let mut other = cfg.clone();
        other.composite_key = Some(super::StoredKey::generate().unwrap());
        assert!(build_composite(&other)
            .unwrap()
            .download(&path)
            .await
            .is_err());
    }
}
