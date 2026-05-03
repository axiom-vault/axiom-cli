use crate::cli::{ConflictStrategyArg, SyncModeArg};
use anyhow::Result;
use axiomvault_sync::{ConflictStrategy, SyncMode};

/// Convert conflict strategy enum to sync type.
pub(crate) fn conflict_strategy_from(arg: ConflictStrategyArg) -> ConflictStrategy {
    match arg {
        ConflictStrategyArg::KeepBoth => ConflictStrategy::KeepBoth,
        ConflictStrategyArg::PreferLocal => ConflictStrategy::PreferLocal,
        ConflictStrategyArg::PreferRemote => ConflictStrategy::PreferRemote,
    }
}

/// Convert sync mode enum to sync type.
pub(crate) fn sync_mode_from(arg: SyncModeArg, interval: Option<u64>) -> Result<SyncMode> {
    match arg {
        SyncModeArg::Manual => Ok(SyncMode::Manual),
        SyncModeArg::OnDemand => Ok(SyncMode::OnDemand),
        SyncModeArg::Periodic => {
            let secs =
                interval.ok_or_else(|| anyhow::anyhow!("Interval required for periodic mode"))?;
            Ok(SyncMode::Periodic {
                interval: std::time::Duration::from_secs(secs),
            })
        }
        SyncModeArg::Hybrid => {
            let secs =
                interval.ok_or_else(|| anyhow::anyhow!("Interval required for hybrid mode"))?;
            Ok(SyncMode::Hybrid {
                interval: std::time::Duration::from_secs(secs),
            })
        }
    }
}
