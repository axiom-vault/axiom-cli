use crate::password::prompt_password;
use anyhow::{Context, Result};
use axiomvault_fuse::mount::{self, MountOptions};
use axiomvault_vault::VaultManager;
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Handle;
use tracing::info;

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

    let password = prompt_password("Enter password: ")?;
    let manager = VaultManager::new();
    let provider_config = serde_json::json!({ "root": vault_path.to_string_lossy() });
    let session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let options = MountOptions {
        allow_other,
        auto_unmount: true,
        read_only,
        default_permissions: !no_default_permissions,
    };

    let handle = mount::mount(Arc::new(session), mount_point, options, Handle::current())
        .context("Failed to mount vault")?;

    println!("Vault mounted at {}", handle.mount_point().display());
    println!("Press Ctrl+C to unmount.");

    tokio::signal::ctrl_c()
        .await
        .context("Failed to wait for Ctrl+C")?;

    println!("Unmounting {}", handle.mount_point().display());
    handle.unmount();
    Ok(())
}
