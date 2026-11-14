use crate::cli::FuseSource;
use crate::password::vault_password;
use anyhow::{Context, Result};
use axiomvault_fuse::mount::{self, MountOptions};
use axiomvault_vault::VaultManager;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::signal::unix::{signal, SignalKind};
use zeroize::Zeroizing;

#[derive(Debug)]
pub(crate) struct GuiPasswordCancelled;

impl std::fmt::Display for GuiPasswordCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Unlock cancelled; start the desktop service to try again")
    }
}

impl std::error::Error for GuiPasswordCancelled {}

fn gui_password_result(
    success: bool,
    cancelled: bool,
    output: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut password = Zeroizing::new(output);
    if cancelled {
        return Err(GuiPasswordCancelled.into());
    }
    if !success {
        anyhow::bail!("The desktop password dialog failed");
    }
    // kdialog appends exactly one newline. Never trim password whitespace.
    if password.last() == Some(&b'\n') {
        password.pop();
    }
    if password.is_empty() {
        return Err(GuiPasswordCancelled.into());
    }
    Ok(password)
}

async fn gui_password() -> Result<Zeroizing<Vec<u8>>> {
    let output = tokio::process::Command::new("/usr/bin/kdialog")
        .args([
            "--title",
            "AxiomVault unlock",
            "--password",
            "Unlock AxiomVault (password is not saved)",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .context("Cannot open the KDE password dialog; kdialog is required")?;
    gui_password_result(
        output.status.success(),
        output.status.code() == Some(1),
        output.stdout,
    )
}

fn retry_connection(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<axiomvault_common::Error>(),
        Some(axiomvault_common::Error::Network(_))
    )
}

async fn open_source(
    source: &FuseSource,
    password: &[u8],
) -> Result<Arc<axiomvault_vault::VaultSession>> {
    if let Some(path) = &source.path {
        VaultManager::new()
            .open_vault(
                "local",
                serde_json::json!({ "root": path.to_string_lossy() }),
                password,
            )
            .await
            .map(Arc::new)
            .context("Failed to open local vault")
    } else {
        super::gdrive::open_gdrive_from_token_file(
            source
                .folder_id
                .as_deref()
                .context("A local path or Drive folder ID is required")?,
            source.tokens.as_deref(),
            source.client_id.clone(),
            password,
        )
        .await
    }
}

pub(crate) async fn cmd_mount(
    source: &FuseSource,
    mount_point: &Path,
    options: MountOptions,
    use_gui_password: bool,
) -> Result<()> {
    if !mount::is_fuse_available() {
        anyhow::bail!(mount::fuse_info());
    }

    let password = if use_gui_password {
        gui_password().await?
    } else {
        vault_password("Enter password: ")?
    };
    let session = loop {
        match open_source(source, &password).await {
            Ok(session) => break session,
            Err(error) if use_gui_password && retry_connection(&error) => {
                // Keep the entered password in this process during an outage.
                // Never replay an already mounted filesystem operation.
                eprintln!("Waiting for storage connection; retrying in 15 seconds");
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Err(error) => return Err(error),
        }
    };
    drop(password);

    let handle = mount::mount(session, mount_point, options, Handle::current())
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
    #[test]
    fn only_transient_connection_failures_retry_without_prompting_again() {
        assert!(super::retry_connection(
            &axiomvault_common::Error::Network("synthetic outage".into()).into()
        ));
        assert!(!super::retry_connection(
            &axiomvault_common::Error::NotPermitted("Invalid password".into()).into()
        ));
        assert!(!super::retry_connection(
            &axiomvault_common::Error::Authentication("revoked token".into()).into()
        ));
        assert!(!super::retry_connection(
            &axiomvault_common::Error::AuthenticationExpired(
                "server rejected a timestamp-valid token".into()
            )
            .into()
        ));
    }

    #[test]
    fn gui_password_output_is_private_and_cancellation_is_distinct() {
        assert_eq!(
            super::gui_password_result(true, false, b"synthetic password\n".to_vec())
                .unwrap()
                .as_slice(),
            b"synthetic password"
        );
        let cancelled =
            super::gui_password_result(false, true, b"synthetic password".to_vec()).unwrap_err();
        assert!(cancelled.is::<super::GuiPasswordCancelled>());
        assert!(!cancelled.to_string().contains("synthetic password"));
        assert!(super::gui_password_result(false, false, b"synthetic password".to_vec()).is_err());
        assert!(super::gui_password_result(true, false, b"\n".to_vec())
            .unwrap_err()
            .is::<super::GuiPasswordCancelled>());
    }
}
