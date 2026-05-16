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
use axiomvault_storage::gdrive::{AuthConfig, AuthManager, GDriveConfig, Tokens};
use axiomvault_storage::CloudAuthorization;
use axiomvault_vault::VaultManager;
use std::path::Path;
use tracing::info;

const GDRIVE_REDIRECT_URL: &str = "http://localhost:8080/callback";
const AXIOM_GOOGLE_CLIENT_ID_ENV: &str = "AXIOM_GOOGLE_CLIENT_ID";
const AXIOMVAULT_GOOGLE_CLIENT_ID_ENV: &str = "AXIOMVAULT_GOOGLE_CLIENT_ID";
const AXIOM_GOOGLE_CLIENT_SECRET_ENV: &str = "AXIOM_GOOGLE_CLIENT_SECRET";
const AXIOMVAULT_GOOGLE_CLIENT_SECRET_ENV: &str = "AXIOMVAULT_GOOGLE_CLIENT_SECRET";

fn resolve_gdrive_client_id(client_id: Option<String>) -> Result<String> {
    resolve_required_oauth_value(
        client_id,
        std::env::var(AXIOM_GOOGLE_CLIENT_ID_ENV).ok(),
        std::env::var(AXIOMVAULT_GOOGLE_CLIENT_ID_ENV).ok(),
        "Google OAuth2 client ID not provided. Use --client-id or set AXIOM_GOOGLE_CLIENT_ID (legacy: AXIOMVAULT_GOOGLE_CLIENT_ID)",
    )
}

fn resolve_gdrive_client_secret(client_secret: Option<String>) -> Option<String> {
    resolve_optional_oauth_value(
        client_secret,
        std::env::var(AXIOM_GOOGLE_CLIENT_SECRET_ENV).ok(),
        std::env::var(AXIOMVAULT_GOOGLE_CLIENT_SECRET_ENV).ok(),
    )
}

pub(crate) async fn cmd_gdrive_auth(
    client_id: Option<String>,
    client_secret: Option<String>,
    output: &Path,
) -> Result<()> {
    info!("Starting Google Drive authentication");

    let auth_config = AuthConfig {
        client_id: resolve_gdrive_client_id(client_id)?,
        client_secret: resolve_gdrive_client_secret(client_secret),
        redirect_url: GDRIVE_REDIRECT_URL.to_string(),
    };
    let auth_manager = AuthManager::new(auth_config).context("Failed to create auth manager")?;

    let CloudAuthorization {
        url: auth_url,
        csrf_token,
        pkce_verifier,
    } = auth_manager.authorization_url();

    let tokens = complete_local_oauth_flow(
        "Google Drive",
        &auth_url,
        &csrf_token,
        |auth_code| async move {
            auth_manager
                .exchange_code(&auth_code, pkce_verifier)
                .await
                .context("Failed to exchange authorization code")
        },
    )
    .await?;

    let tokens_json =
        serde_json::to_string_pretty(&tokens).context("Failed to serialize tokens")?;
    write_secret_file(output, &tokens_json).await?;

    println!();
    println!("Authentication successful!");
    println!("  Tokens saved to: {}", output.display());
    println!("  Expires at: {}", tokens.expires_at);
    println!();
    println!("You can now use 'axiom remote gdrive create' or 'axiom remote gdrive open'");

    Ok(())
}

pub(crate) async fn cmd_gdrive_create(
    name: &str,
    folder_id: &str,
    tokens_path: &Path,
    strength: KdfStrength,
) -> Result<()> {
    info!("Creating new vault on Google Drive: {}", name);

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
    let tokens: Tokens =
        serde_json::from_str(&tokens_json).context("Failed to parse tokens file")?;

    let vault_id = VaultId::new(name).context("Invalid vault name")?;
    let manager = VaultManager::new();
    let gdrive_config = GDriveConfig {
        folder_id: folder_id.to_string(),
        tokens,
        auth_config: None,
    };
    let provider_config =
        serde_json::to_value(gdrive_config).context("Failed to serialize GDrive config")?;

    let creation = manager
        .create_vault(vault_id, &password, "gdrive", provider_config, kdf_params)
        .await
        .context("Failed to create vault on Google Drive")?;

    println!("Vault created successfully on Google Drive!");
    println!("  ID: {}", creation.session.vault_id());
    println!("  Folder ID: {}", folder_id);
    println!("  Provider: {}", creation.session.config().provider_type);
    display_recovery_words(&creation.recovery_words);

    Ok(())
}

pub(crate) async fn cmd_gdrive_open(folder_id: &str, tokens_path: &Path) -> Result<()> {
    info!("Opening vault on Google Drive");

    let password = prompt_password("Enter password: ")?;

    let tokens_json = tokio::fs::read_to_string(tokens_path)
        .await
        .context("Failed to read tokens file")?;
    let tokens: Tokens =
        serde_json::from_str(&tokens_json).context("Failed to parse tokens file")?;

    let gdrive_config = GDriveConfig {
        folder_id: folder_id.to_string(),
        tokens,
        auth_config: None,
    };
    let provider_config =
        serde_json::to_value(gdrive_config).context("Failed to serialize GDrive config")?;

    let manager = VaultManager::new();
    let session = manager
        .open_vault("gdrive", provider_config, &password)
        .await
        .context("Failed to open vault on Google Drive")?;

    println!("Vault opened successfully from Google Drive!");
    println!("  ID: {}", session.vault_id());
    println!("  Session: {}", session.handle().as_str());
    println!("\nVault is ready for operations.");

    Ok(())
}
