use crate::cli::KdfStrength;
use crate::password::{
    display_recovery_words, kdf_params_from, prompt_password, validate_password_strength,
};
use anyhow::{Context, Result};
use axiomvault_common::VaultId;
use axiomvault_storage::icloud::ICloudConfig;
use axiomvault_vault::{VaultCreation, VaultManager, VaultSession};
use std::path::Path;
use tracing::info;

fn build_icloud_config(root_path: Option<&Path>, subfolder: Option<&str>) -> ICloudConfig {
    ICloudConfig {
        root_path: root_path.map(|path| path.to_string_lossy().into_owned()),
        subfolder: normalize_subfolder(subfolder),
    }
}

fn normalize_subfolder(subfolder: Option<&str>) -> Option<String> {
    subfolder
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn serialize_icloud_config(
    root_path: Option<&Path>,
    subfolder: Option<&str>,
) -> Result<serde_json::Value> {
    serde_json::to_value(build_icloud_config(root_path, subfolder))
        .context("Failed to serialize iCloud config")
}

async fn create_icloud_vault(
    name: &str,
    root_path: Option<&Path>,
    subfolder: Option<&str>,
    password: &[u8],
    strength: KdfStrength,
) -> Result<VaultCreation> {
    let vault_id = VaultId::new(name).context("Invalid vault name")?;
    let provider_config = serialize_icloud_config(root_path, subfolder)?;

    VaultManager::new()
        .create_vault(
            vault_id,
            password,
            "icloud",
            provider_config,
            kdf_params_from(strength),
        )
        .await
        .context("Failed to create vault on iCloud")
}

async fn open_icloud_vault(
    root_path: Option<&Path>,
    subfolder: Option<&str>,
    password: &[u8],
) -> Result<VaultSession> {
    let provider_config = serialize_icloud_config(root_path, subfolder)?;

    VaultManager::new()
        .open_vault("icloud", provider_config, password)
        .await
        .context("Failed to open vault on iCloud")
}

pub(crate) async fn cmd_icloud_create(
    name: &str,
    root_path: Option<&Path>,
    subfolder: Option<&str>,
    strength: KdfStrength,
) -> Result<()> {
    info!("Creating new vault on iCloud: {}", name);

    let password = prompt_password("Enter password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    validate_password_strength(&password)?;

    let normalized_subfolder = normalize_subfolder(subfolder);
    let creation = create_icloud_vault(
        name,
        root_path,
        normalized_subfolder.as_deref(),
        &password,
        strength,
    )
    .await?;

    println!("Vault created successfully on iCloud!");
    println!(" ID: {}", creation.session.vault_id());
    println!(" Provider: {}", creation.session.config().provider_type);
    match root_path {
        Some(root_path) => println!(" Root path: {}", root_path.display()),
        None => println!(" Root path: auto-detected iCloud Drive"),
    }
    if let Some(subfolder) = normalized_subfolder.as_deref() {
        println!(" Subfolder: {}", subfolder);
    }

    display_recovery_words(&creation.recovery_words);
    Ok(())
}

pub(crate) async fn cmd_icloud_open(
    root_path: Option<&Path>,
    subfolder: Option<&str>,
) -> Result<()> {
    info!("Opening vault on iCloud");

    let password = prompt_password("Enter password: ")?;
    let session = open_icloud_vault(root_path, subfolder, &password).await?;

    println!("Vault opened successfully from iCloud!");
    println!(" ID: {}", session.vault_id());
    println!(" Session: {}", session.handle().as_str());
    println!("\nVault is ready for operations.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn assert_error_contains(error: &anyhow::Error, expected: &str) {
        assert!(
            format!("{error:#}").contains(expected),
            "expected error to contain {expected:?}: {error:#}",
        );
    }

    fn unwrap_icloud_error<T>(result: Result<T>, message: &str) -> anyhow::Error {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    async fn cleanup_temp_root(root: &Path) {
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    fn temp_test_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "axiom-icloud-test-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn build_icloud_config_trims_empty_subfolder() {
        let config = build_icloud_config(Some(Path::new("/tmp/icloud")), Some(" "));
        assert_eq!(config.root_path.as_deref(), Some("/tmp/icloud"));
        assert_eq!(config.subfolder, None);
    }

    #[tokio::test]
    async fn create_icloud_vault_rejects_absolute_subfolder() {
        let root = temp_test_path("reject-absolute");
        let error = unwrap_icloud_error(
            create_icloud_vault(
                "CloudVault",
                Some(root.as_path()),
                Some("/escape"),
                b"correct-horse-battery-staple",
                KdfStrength::Interactive,
            )
            .await,
            "absolute subfolder should fail",
        );

        assert_error_contains(&error, "Failed to create vault on iCloud");
        assert_error_contains(&error, "relative path");
        assert!(!root.join("escape").exists());
    }

    #[tokio::test]
    async fn open_icloud_vault_rejects_parent_traversal_subfolder() {
        let root = temp_test_path("reject-traversal");
        tokio::fs::create_dir_all(&root).await.unwrap();

        let error = unwrap_icloud_error(
            open_icloud_vault(
                Some(root.as_path()),
                Some("safe/../escape"),
                b"correct-horse-battery-staple",
            )
            .await,
            "parent traversal subfolder should fail",
        );

        assert_error_contains(&error, "Failed to open vault on iCloud");
        assert_error_contains(&error, "'.' or '..'");
        cleanup_temp_root(&root).await;
    }

    #[tokio::test]
    async fn create_and_open_icloud_vault_with_temp_root_and_subfolder() {
        let root = temp_test_path("create-open");
        let password = b"correct-horse-battery-staple";

        let creation = create_icloud_vault(
            "CloudVault",
            Some(root.as_path()),
            Some("AxiomVault"),
            password,
            KdfStrength::Interactive,
        )
        .await
        .unwrap();

        assert_eq!(creation.session.config().provider_type, "icloud");
        assert_eq!(creation.recovery_words.split_whitespace().count(), 24);
        assert!(root.join("AxiomVault").exists());

        let session = open_icloud_vault(Some(root.as_path()), Some("AxiomVault"), password)
            .await
            .unwrap();
        assert_eq!(session.config().provider_type, "icloud");
        assert_eq!(session.vault_id().to_string(), "CloudVault");

        cleanup_temp_root(&root).await;
    }
}
