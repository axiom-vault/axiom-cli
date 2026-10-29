use crate::password::vault_password;
use anyhow::{Context, Result};
use axiomvault_fuse::mount::{self, MountOptions};
use axiomvault_vault::VaultManager;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;

fn auto_unmount_enabled(allow_other: bool) -> bool {
    allow_other
}

pub(crate) async fn cmd_mount(
    vault_path: &Path,
    mount_point: &Path,
    allow_other: bool,
    read_only: bool,
    no_default_permissions: bool,
) -> Result<()> {
    info!(
        "Mounting vault at {} to {}",
        vault_path.display(),
        mount_point.display()
    );

    if !mount::is_fuse_available() {
        anyhow::bail!(mount::fuse_info());
    }

    let password = vault_password("Enter password: ")?;
    let manager = VaultManager::new();
    let provider_config = serde_json::json!({
        "root": vault_path.to_string_lossy(),
    });
    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let options = MountOptions {
        allow_other,
        // fuser rejects AutoUnmount with owner-only ACLs; only enable it when
        // the mount is shared via allow_other.
        auto_unmount: auto_unmount_enabled(allow_other),
        read_only,
        default_permissions: !no_default_permissions,
    };

    let handle = mount::mount(Arc::new(session), mount_point, options, Handle::current())
        .context("Failed to mount vault")?;

    println!("Vault mounted at {}", handle.mount_point().display());
    println!("Press Ctrl+C to unmount.");

    let mut sigterm =
        signal(SignalKind::terminate()).context("Failed to install SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("Failed to install SIGHUP handler")?;
    // fuser offers no async notification when the session ends, so poll for an
    // external unmount (`fusermount3 -u`).
    let mut poll = tokio::time::interval(Duration::from_millis(200));
    loop {
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.context("Failed to wait for Ctrl+C")?;
                break;
            }
            _ = sigterm.recv() => break,
            _ = sighup.recv() => break,
            _ = poll.tick() => {
                if handle.is_finished() {
                    break;
                }
            }
        }
    }

    if handle.is_finished() {
        println!("{} was unmounted", handle.mount_point().display());
    } else {
        println!("Unmounting {}", handle.mount_point().display());
    }
    // Unmounting joins the FUSE thread, which drops the vault session; keep
    // that blocking work off the async workers.
    tokio::task::spawn_blocking(move || handle.unmount())
        .await
        .context("Failed to unmount vault")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::auto_unmount_enabled;

    #[test]
    fn enables_auto_unmount_for_shared_mounts() {
        assert!(auto_unmount_enabled(true));
    }

    #[test]
    fn disables_auto_unmount_for_owner_only_mounts() {
        assert!(!auto_unmount_enabled(false));
    }
}
