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
            let secs = require_positive_interval(interval, "periodic")?;
            Ok(SyncMode::Periodic {
                interval: std::time::Duration::from_secs(secs),
            })
        }
        SyncModeArg::Hybrid => {
            let secs = require_positive_interval(interval, "hybrid")?;
            Ok(SyncMode::Hybrid {
                interval: std::time::Duration::from_secs(secs),
            })
        }
    }
}

fn require_positive_interval(interval: Option<u64>, mode: &str) -> Result<u64> {
    let secs = interval.ok_or_else(|| anyhow::anyhow!("Interval required for {mode} mode"))?;
    if secs == 0 {
        anyhow::bail!("Interval must be greater than 0 seconds for {mode} mode");
    }
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn periodic_mode_requires_non_zero_interval() {
        let err = sync_mode_from(SyncModeArg::Periodic, Some(0)).unwrap_err();
        assert!(err
            .to_string()
            .contains("Interval must be greater than 0 seconds for periodic mode"));
    }

    #[test]
    fn hybrid_mode_requires_non_zero_interval() {
        let err = sync_mode_from(SyncModeArg::Hybrid, Some(0)).unwrap_err();
        assert!(err
            .to_string()
            .contains("Interval must be greater than 0 seconds for hybrid mode"));
    }

    #[test]
    fn periodic_mode_accepts_positive_interval() {
        let mode = sync_mode_from(SyncModeArg::Periodic, Some(30)).unwrap();
        match mode {
            SyncMode::Periodic { interval } => assert_eq!(interval, Duration::from_secs(30)),
            other => panic!("expected periodic mode, got {other:?}"),
        }
    }
}
