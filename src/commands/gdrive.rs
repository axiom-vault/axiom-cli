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
    create_default_registry, CloudAuthorization, CompositeConfig, CompositeStorageProvider,
    HealthStatus, RaidMode, RaidRebuilder, RebuildConfig, RebuildResult,
};
use axiomvault_sync::{ConflictStrategy, SyncConfig, SyncEngine, SyncMode, SyncState};
use axiomvault_vault::{
    check_migration_needed, check_vault_health, check_vault_structure, MigrationRegistry,
    MigrationStatus, VaultConfig, VaultManager, VaultOperations, VaultVersion,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub(crate) async fn cmd_gdrive_auth(
    client_id: Option<String>,
    client_secret: Option<String>,
    output: &PathBuf,
) -> Result<()> {
    info!("Starting Google Drive authentication");

    // Build auth config: CLI flags take precedence over environment variables.
    let client_id = client_id
        .or_else(|| std::env::var("AXIOM_GOOGLE_CLIENT_ID").ok())
        .or_else(|| std::env::var("AXIOMVAULT_GOOGLE_CLIENT_ID").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Google OAuth2 client ID not provided. \
                 Use --client-id or set AXIOM_GOOGLE_CLIENT_ID (legacy: AXIOMVAULT_GOOGLE_CLIENT_ID)"
            )
        })?;

    // PKCE makes client_secret optional for public clients.
    let client_secret = client_secret
        .or_else(|| std::env::var("AXIOM_GOOGLE_CLIENT_SECRET").ok())
        .or_else(|| std::env::var("AXIOMVAULT_GOOGLE_CLIENT_SECRET").ok());

    let auth_config = AuthConfig {
        client_id,
        client_secret,
        redirect_url: "http://localhost:8080/callback".to_string(),
    };

    let auth_manager = AuthManager::new(auth_config).context("Failed to create auth manager")?;

    let CloudAuthorization {
        url: auth_url,
        csrf_token,
        pkce_verifier,
    } = auth_manager.authorization_url();

    // Start local HTTP server to capture the OAuth callback
    let listener = TcpListener::bind("127.0.0.1:8080").await.context(
        "Failed to start local server on port 8080. Is another process using this port?",
    )?;

    println!("Starting Google Drive authentication...");
    println!();
    println!("Opening your browser to authorize AxiomVault...");

    // Try to open the browser automatically
    let browser_opened = open::that(&auth_url).is_ok();

    if browser_opened {
        println!("Browser opened successfully!");
    } else {
        println!("Could not open browser automatically.");
        println!("Please visit this URL to authorize:");
        println!();
        println!("  {}", auth_url);
    }

    println!();
    println!("Waiting for authorization... (Press Ctrl+C to cancel)");

    // Wait for the OAuth callback with a 5-minute timeout
    let (mut socket, _) =
        tokio::time::timeout(std::time::Duration::from_secs(300), listener.accept())
            .await
            .context("OAuth callback timed out after 5 minutes")?
            .context("Failed to accept connection")?;

    // Read the HTTP request
    let mut buffer = vec![0u8; 4096];
    let n = socket
        .read(&mut buffer)
        .await
        .context("Failed to read request")?;
    let request = String::from_utf8_lossy(&buffer[..n]);

    // Parse the request to extract the authorization code
    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    // Extract code and state from the callback URL
    let callback_url = format!("http://localhost:8080{}", path);
    let parsed_url = Url::parse(&callback_url).context("Failed to parse callback URL")?;

    let mut code = None;
    let mut state = None;

    for (key, value) in parsed_url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            _ => {}
        }
    }

    let auth_code = code.ok_or_else(|| anyhow::anyhow!("No authorization code received"))?;
    let received_state = state.ok_or_else(|| anyhow::anyhow!("No state parameter received"))?;

    // Verify CSRF token
    if received_state != csrf_token {
        // Send error response
        let error_html = r#"<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1 style="color: #d32f2f;">Authentication Failed</h1>
<p>Security validation failed. Please try again.</p>
</body>
</html>"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            error_html.len(),
            error_html
        );
        socket.write_all(response.as_bytes()).await.ok();
        anyhow::bail!("CSRF token mismatch - possible security issue");
    }

    // Send success response to browser
    let success_html = r#"<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1 style="color: #4caf50;">Authentication Successful!</h1>
<p>You have successfully authorized AxiomVault to access your Google Drive.</p>
<p>You can close this window and return to the terminal.</p>
</body>
</html>"#;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        success_html.len(),
        success_html
    );
    socket.write_all(response.as_bytes()).await.ok();

    info!("Authorization code received, exchanging for tokens");
    println!();
    println!("Authorization received! Exchanging for access tokens...");

    let tokens = auth_manager
        .exchange_code(&auth_code, pkce_verifier)
        .await
        .context("Failed to exchange authorization code")?;

    // Save tokens to file with restricted permissions
    let tokens_json =
        serde_json::to_string_pretty(&tokens).context("Failed to serialize tokens")?;

    // Remove any stale file so the new one is created fresh with 0o600.
    // The mode flag in OpenOptions only applies on creation.
    let _ = tokio::fs::remove_file(output).await;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)
            .await
            .context("Failed to create token file")?;
        f.write_all(tokens_json.as_bytes())
            .await
            .context("Failed to write tokens file")?;
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(output, &tokens_json)
            .await
            .context("Failed to write tokens file")?;
    }

    println!();
    println!("Authentication successful!");
    println!("  Tokens saved to: {}", output.display());
    println!("  Expires at: {}", tokens.expires_at);
    println!();
    println!("You can now use 'axiom remote gdrive create' or 'axiom remote gdrive open'");

    Ok(())
}

/// Create a vault on Google Drive.
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

    // Load tokens
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

/// Open a vault on Google Drive.
pub(crate) async fn cmd_gdrive_open(folder_id: &str, tokens_path: &Path) -> Result<()> {
    info!("Opening vault on Google Drive");

    let password = prompt_password("Enter password: ")?;

    // Load tokens
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
