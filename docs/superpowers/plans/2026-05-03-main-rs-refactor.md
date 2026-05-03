# main.rs Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the 2710-line `src/main.rs` into focused Rust modules without changing CLI behavior.

**Architecture:** Keep `src/main.rs` as a thin async entrypoint. Move CLI declarations to `cli.rs`, command dispatch to `dispatch.rs`, shared helpers to focused modules, and command implementations under `src/commands/`. This is a mechanical refactor: preserve function bodies where possible and validate with existing tests.

**Tech Stack:** Rust 2021, Clap derive, Tokio, anyhow, existing axiomvault crates.

---

## File Structure

- Modify: `src/main.rs` — keep module declarations and `#[tokio::main] async fn main()` only.
- Create: `src/cli.rs` — `KdfStrength`, `ConflictStrategyArg`, `SyncModeArg`, `RaidModeArg`, `Cli`, and `Commands`.
- Create: `src/dispatch.rs` — one `dispatch(cli: Cli) -> Result<()>` match that calls command handlers.
- Create: `src/password.rs` — `validate_password_strength`, `prompt_password`, `display_recovery_words`, `kdf_params_from`.
- Create: `src/conversions.rs` — `conflict_strategy_from`, `sync_mode_from`, `raid_mode_from_config`.
- Create: `src/completions.rs` — `install_completions`.
- Create: `src/commands/mod.rs` — command module declarations.
- Create: `src/commands/vault.rs` — create/open/list/add/extract/mkdir/remove/info.
- Create: `src/commands/recovery.rs` — change-password, show-recovery-key, reset-password, migrate-vault.
- Create: `src/commands/check.rs` — check command and health report printing.
- Create: `src/commands/gdrive.rs` — Google Drive auth/create/open.
- Create: `src/commands/sync.rs` — sync, sync-status, sync-conflicts, sync-resolve, sync-configure.
- Create: `src/commands/migrate.rs` — format migration command.
- Create: `src/commands/raid.rs` — RAID config structs, RAID command handlers, rebuild progress helpers, and RAID/progress tests.
- Create: `src/commands/webdav.rs` — WebDAV server command.

## Task 1: Establish Baseline

**Files:** none

- [ ] Run baseline compile:

```bash
cargo check
```

Expected: `Finished dev profile` with exit code 0.

- [ ] Run baseline tests:

```bash
cargo test
```

Expected: 13 tests pass, 0 fail.

## Task 2: Move CLI Types

**Files:**
- Create: `src/cli.rs`
- Modify: `src/main.rs`

- [ ] Move `KdfStrength`, `ConflictStrategyArg`, `SyncModeArg`, `RaidModeArg`, `Cli`, and `Commands` from `main.rs` into `cli.rs`.
- [ ] Mark types and fields used by other modules as `pub` or `pub(crate)`.
- [ ] Add needed imports in `cli.rs`: `clap::{Parser, Subcommand, ValueEnum}`, `std::path::PathBuf`, and `axiomvault_storage::raid::RaidMode` if still required by enum docs/types.
- [ ] In `main.rs`, add `mod cli;` and `use clap::Parser; use cli::Cli;`.
- [ ] Run:

```bash
cargo check
```

Expected: compiles.

- [ ] Commit:

```bash
git add src/main.rs src/cli.rs
git commit -m "refactor: move cli definitions into module"
```

## Task 3: Move Shared Helpers

**Files:**
- Create: `src/password.rs`
- Create: `src/conversions.rs`
- Create: `src/completions.rs`
- Modify: `src/main.rs`

- [ ] Move password and KDF helpers into `password.rs`: `validate_password_strength`, `prompt_password`, `display_recovery_words`, `kdf_params_from`.
- [ ] Move conversion helpers into `conversions.rs`: `conflict_strategy_from`, `sync_mode_from`, `raid_mode_from_config`.
- [ ] Move `install_completions` into `completions.rs`.
- [ ] Make functions `pub(crate)` where called from command modules or dispatch.
- [ ] Add module declarations in `main.rs`: `mod password; mod conversions; mod completions;`.
- [ ] Run:

```bash
cargo check
```

Expected: compiles.

- [ ] Commit:

```bash
git add src/main.rs src/password.rs src/conversions.rs src/completions.rs
git commit -m "refactor: move shared cli helpers"
```

## Task 4: Move Local Vault and Recovery Commands

**Files:**
- Create: `src/commands/mod.rs`
- Create: `src/commands/vault.rs`
- Create: `src/commands/recovery.rs`
- Create: `src/commands/check.rs`
- Modify: `src/main.rs`

- [ ] Create `src/commands/mod.rs` with:

```rust
pub(crate) mod check;
pub(crate) mod gdrive;
pub(crate) mod migrate;
pub(crate) mod raid;
pub(crate) mod recovery;
pub(crate) mod sync;
pub(crate) mod vault;
pub(crate) mod webdav;
```

- [ ] Move vault commands into `vault.rs`: `cmd_create`, `cmd_open`, `cmd_list`, `cmd_add`, `cmd_extract`, `cmd_mkdir`, `cmd_remove`, `cmd_info`.
- [ ] Move recovery commands into `recovery.rs`: `cmd_change_password`, `cmd_show_recovery_key`, `cmd_reset_password`, `cmd_migrate_vault`.
- [ ] Move check command and report printer into `check.rs`: `cmd_check`, `print_health_report`.
- [ ] Make command functions `pub(crate)`.
- [ ] Add `mod commands;` to `main.rs`.
- [ ] Run:

```bash
cargo check
```

Expected: compiles.

- [ ] Commit:

```bash
git add src/main.rs src/commands/mod.rs src/commands/vault.rs src/commands/recovery.rs src/commands/check.rs
git commit -m "refactor: move vault and recovery commands"
```

## Task 5: Move Cloud, Sync, Migration, RAID, and WebDAV Commands

**Files:**
- Create: `src/commands/gdrive.rs`
- Create: `src/commands/sync.rs`
- Create: `src/commands/migrate.rs`
- Create: `src/commands/raid.rs`
- Create: `src/commands/webdav.rs`
- Modify: `src/main.rs`

- [ ] Move Google Drive commands into `gdrive.rs`: `cmd_gdrive_auth`, `cmd_gdrive_create`, `cmd_gdrive_open`.
- [ ] Move sync commands into `sync.rs`: `cmd_sync`, `cmd_sync_status`, `cmd_sync_conflicts`, `cmd_sync_resolve`, `cmd_sync_configure`.
- [ ] Move migration command into `migrate.rs`: `cmd_migrate`.
- [ ] Move RAID structs/helpers/commands/tests into `raid.rs`: `RaidConfig`, `RaidModeConfig`, `BackendEntry`, `raid_config_path`, `load_raid_config`, `save_raid_config`, `build_composite`, `cmd_raid_add_backend`, `cmd_raid_remove_backend`, `cmd_raid_status`, `cmd_raid_rebuild`, `rebuild_with_progress`, `print_progress_bar`, `cmd_raid_configure`, and existing `#[cfg(test)] mod tests`.
- [ ] Move WebDAV command into `webdav.rs`: `cmd_webdav`.
- [ ] Make command functions `pub(crate)`.
- [ ] Run:

```bash
cargo check
```

Expected: compiles.

- [ ] Commit:

```bash
git add src/main.rs src/commands/gdrive.rs src/commands/sync.rs src/commands/migrate.rs src/commands/raid.rs src/commands/webdav.rs
git commit -m "refactor: move remaining command modules"
```

## Task 6: Move Dispatch and Thin main.rs

**Files:**
- Create: `src/dispatch.rs`
- Modify: `src/main.rs`

- [ ] Move the `match cli.command` body from `main.rs` into `dispatch.rs` as:

```rust
pub(crate) async fn dispatch(cli: crate::cli::Cli) -> anyhow::Result<()> {
    // existing match body
    Ok(())
}
```

- [ ] Keep `main.rs` as:

```rust
mod cli;
mod commands;
mod completions;
mod conversions;
mod dispatch;
mod password;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    dispatch::dispatch(cli).await
}
```

- [ ] Run:

```bash
cargo check
```

Expected: compiles.

- [ ] Commit:

```bash
git add src/main.rs src/dispatch.rs
git commit -m "refactor: isolate command dispatch"
```

## Task 7: Final Verification

**Files:** all modified source files

- [ ] Format:

```bash
cargo fmt --all -- --check
```

Expected: exit code 0.

- [ ] Lint:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: exit code 0.

- [ ] Test:

```bash
cargo test --verbose
```

Expected: all tests pass.

- [ ] Confirm `main.rs` is small:

```bash
wc -l src/main.rs
```

Expected: under 100 lines.

- [ ] Commit any formatting-only changes:

```bash
git add -A
git commit -m "refactor: format split cli modules"
```

If there are no changes, do not create an empty commit.

---

## Self-Review

- Spec coverage: The plan covers the requested one-PR refactor of `src/main.rs` into focused modules while preserving behavior.
- Placeholder scan: No TBD/TODO placeholders remain.
- Type consistency: Module names and moved function names match the current `src/main.rs` function list.
