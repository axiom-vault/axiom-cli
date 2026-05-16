use crate::cli::KdfStrength;
use crate::commands::remote_oauth::{
    complete_local_oauth_flow, resolve_optional_oauth_value, resolve_required_oauth_value,
    write_secret_file,
};
use crate::password::{
    display_recovery_words, kdf_params_from, prompt_password, validate_password_strength,
};
use anyhow::{Context, Result};
use axiomvault_common::VaultId;
use axiomvault_storage::dropbox::{
    DropboxAuthConfig, DropboxAuthManager, DropboxConfig, DropboxTokens,
};
use axiomvault_storage::CloudAuthorization;
use axiomvault_vault::VaultManager;
use std::path::Path;
use tracing::info;

const DROPBOX_REDIRECT_URL: &str = "http://localhost:8080/callback";
const AXIOM_DROPBOX_APP_KEY_ENV: &str = "AXIOM_DROPBOX_APP_KEY";
const AXIOMVAULT_DROPBOX_APP_KEY_ENV: &str = "AXIOMVAULT_DROPBOX_APP_KEY";
const AXIOM_DROPBOX_APP_SECRET_ENV: &str = "AXIOM_DROPBOX_APP_SECRET";
const AXIOMVAULT_DROPBOX_APP_SECRET_ENV: &str = "AXIOMVAULT_DROPBOX_APP_SECRET";

fn resolve_dropbox_app_key(app_key: Option<String>) -> Result<String> {
    resolve_required_oauth_value(
        app_key,
        std::env::var(AXIOM_DROPBOX_APP_KEY_ENV).ok(),
        std::env::var(AXIOMVAULT_DROPBOX_APP_KEY_ENV).ok(),
        "Dropbox app key not provided. Use --app-key or set AXIOM_DROPBOX_APP_KEY (legacy: AXIOMVAULT_DROPBOX_APP_KEY)",
    )
}

fn resolve_dropbox_app_secret(app_secret: Option<String>) -> Option<String> {
    resolve_optional_oauth_value(
        app_secret,
        std::env::var(AXIOM_DROPBOX_APP_SECRET_ENV).ok(),
        std::env::var(AXIOMVAULT_DROPBOX_APP_SECRET_ENV).ok(),
    )
}

pub(crate) async fn cmd_dropbox_auth(
    app_key: Option<String>,
    app_secret: Option<String>,
    output: &Path,
) -> Result<()> {
    info!("Starting Dropbox authentication");

    let auth_config = DropboxAuthConfig {
        app_key: resolve_dropbox_app_key(app_key)?,
        app_secret: resolve_dropbox_app_secret(app_secret),
        redirect_url: DROPBOX_REDIRECT_URL.to_string(),
    };
    let auth_manager =
        DropboxAuthManager::new(auth_config).context("Failed to create Dropbox auth manager")?;

    let CloudAuthorization {
        url: auth_url,
        csrf_token,
        pkce_verifier,
    } = auth_manager.authorization_url();

    let tokens =
        complete_local_oauth_flow("Dropbox", &auth_url, &csrf_token, |auth_code| async move {
            auth_manager
                .exchange_code(&auth_code, pkce_verifier)
                .await
                .context("Failed to exchange authorization code")
        })
        .await?;

    let tokens_json =
        serde_json::to_string_pretty(&tokens).context("Failed to serialize Dropbox tokens")?;
    write_secret_file(output, &tokens_json).await?;

    println!();
    println!("Authentication successful!");
    println!("  Tokens saved to: {}", output.display());
    println!("  Expires at: {}", tokens.expires_at);
    println!();
    println!("You can now use 'axiom remote dropbox create' or 'axiom remote dropbox open'");

    Ok(())
}

pub(crate) async fn cmd_dropbox_create(
    name: &str,
    root_path: &str,
    tokens_path: &Path,
    strength: KdfStrength,
) -> Result<()> {
    info!("Creating new vault on Dropbox: {}", name);

    let kdf_params = kdf_params_from(strength);
    let password = prompt_password("Enter password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }
    validate_password_strength(&password)?;

    let tokens_json = tokio::fs::read_to_string(tokens_path)
        .await
        .context("Failed to read tokens file")?;
    let tokens: DropboxTokens =
        serde_json::from_str(&tokens_json).context("Failed to parse tokens file")?;

    let vault_id = VaultId::new(name).context("Invalid vault name")?;
    let manager = VaultManager::new();
    let dropbox_config = DropboxConfig {
        root_path: root_path.to_string(),
        tokens,
        auth_config: None,
    };
    let provider_config =
        serde_json::to_value(dropbox_config).context("Failed to serialize Dropbox config")?;

    let creation = manager
        .create_vault(vault_id, &password, "dropbox", provider_config, kdf_params)
        .await
        .context("Failed to create vault on Dropbox")?;

    println!("Vault created successfully on Dropbox!");
    println!("  ID: {}", creation.session.vault_id());
    println!("  Root path: {}", root_path);
    println!("  Provider: {}", creation.session.config().provider_type);
    display_recovery_words(&creation.recovery_words);

    Ok(())
}

pub(crate) async fn cmd_dropbox_open(root_path: &str, tokens_path: &Path) -> Result<()> {
    info!("Opening vault on Dropbox");

    let password = prompt_password("Enter password: ")?;

    let tokens_json = tokio::fs::read_to_string(tokens_path)
        .await
        .context("Failed to read tokens file")?;
    let tokens: DropboxTokens =
        serde_json::from_str(&tokens_json).context("Failed to parse tokens file")?;

    let dropbox_config = DropboxConfig {
        root_path: root_path.to_string(),
        tokens,
        auth_config: None,
    };
    let provider_config =
        serde_json::to_value(dropbox_config).context("Failed to serialize Dropbox config")?;

    let manager = VaultManager::new();
    let session = manager
        .open_vault("dropbox", provider_config, &password)
        .await
        .context("Failed to open vault on Dropbox")?;

    println!("Vault opened successfully from Dropbox!");
    println!("  ID: {}", session.vault_id());
    println!("  Session: {}", session.handle().as_str());
    println!("\nVault is ready for operations.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_dropbox_app_key_prefers_primary_env_name() {
        assert_eq!(
            resolve_required_oauth_value(
                None,
                Some("primary-app-key".into()),
                Some("legacy-app-key".into()),
                "missing"
            )
            .unwrap(),
            "primary-app-key"
        );
    }

    #[test]
    fn resolve_dropbox_app_secret_falls_back_to_legacy_value() {
        assert_eq!(
            resolve_optional_oauth_value(None, None, Some("legacy-secret".into())),
            Some("legacy-secret".into())
        );
    }
}
