#![allow(unused_imports)]
use crate::cli::{ConflictStrategyArg, KdfStrength, RaidModeArg, SyncModeArg};
use crate::commands::remote_oauth::{
    complete_local_oauth_flow, read_tokens, resolve_optional_oauth_value,
    resolve_required_oauth_value, save_tokens,
};
use crate::conversions::{conflict_strategy_from, sync_mode_from};
use crate::password::{
    display_recovery_words, kdf_params_from, may_print_recovery_words, prompt_password,
    validate_password_strength, vault_password,
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
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const GDRIVE_REDIRECT_URL: &str = "http://localhost:8080/callback";
const AXIOM_GOOGLE_CLIENT_ID_ENV: &str = "AXIOM_GOOGLE_CLIENT_ID";
const AXIOMVAULT_GOOGLE_CLIENT_ID_ENV: &str = "AXIOMVAULT_GOOGLE_CLIENT_ID";
const AXIOM_GOOGLE_CLIENT_SECRET_ENV: &str = "AXIOM_GOOGLE_CLIENT_SECRET";
const AXIOMVAULT_GOOGLE_CLIENT_SECRET_ENV: &str = "AXIOMVAULT_GOOGLE_CLIENT_SECRET";

/// CLI flags take precedence over environment variables.
fn resolve_gdrive_client_id(client_id: Option<String>) -> Result<String> {
    resolve_required_oauth_value(
        client_id,
        std::env::var(AXIOM_GOOGLE_CLIENT_ID_ENV).ok(),
        std::env::var(AXIOMVAULT_GOOGLE_CLIENT_ID_ENV).ok(),
        "Google OAuth2 client ID not provided. Use --client-id or set AXIOM_GOOGLE_CLIENT_ID (legacy: AXIOMVAULT_GOOGLE_CLIENT_ID)",
    )
}

/// PKCE makes client_secret optional for public clients.
fn resolve_gdrive_client_secret(client_secret: Option<String>) -> Option<String> {
    resolve_optional_oauth_value(
        client_secret,
        std::env::var(AXIOM_GOOGLE_CLIENT_SECRET_ENV).ok(),
        std::env::var(AXIOMVAULT_GOOGLE_CLIENT_SECRET_ENV).ok(),
    )
}

/// Opaque, non-secret reference persisted in `vault.config` instead of tokens.
const GDRIVE_CREDENTIAL_REF: &str = "local:gdrive:cli-tokens";

/// Resolves `GDRIVE_CREDENTIAL_REF` to the tokens read from the local `--tokens` file.
struct TokensFileResolver(Tokens);

impl axiomvault_vault::manager::LocalCredentialResolver for TokensFileResolver {
    fn resolve(
        &self,
        provider_type: &str,
        credential_ref: &str,
    ) -> axiomvault_common::Result<serde_json::Value> {
        if provider_type != "gdrive" || credential_ref != GDRIVE_CREDENTIAL_REF {
            return Err(axiomvault_common::Error::NotFound(format!(
                "Unknown credential reference '{credential_ref}'"
            )));
        }
        let tokens = serde_json::to_value(&self.0)
            .map_err(|error| axiomvault_common::Error::Serialization(error.to_string()))?;
        Ok(serde_json::json!({ "tokens": tokens }))
    }
}

/// Build a manager whose provider config carries only `folder_id` and `credential_ref`.
fn gdrive_manager(tokens: Tokens, folder_id: &str) -> (VaultManager, serde_json::Value) {
    let manager = VaultManager::with_registry_and_credential_resolver(
        create_default_registry(),
        Arc::new(TokensFileResolver(tokens)),
    );
    let provider_config = serde_json::json!({
        "folder_id": folder_id,
        "credential_ref": GDRIVE_CREDENTIAL_REF,
    });
    (manager, provider_config)
}

/// Token file path: the explicit `path`, or `<config dir>/axiomvault/gdrive-tokens.json`.
fn tokens_path_or_default(path: Option<&Path>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(dirs::config_dir()
            .context("No config directory found; pass the tokens path explicitly")?
            .join("axiomvault")
            .join("gdrive-tokens.json")),
    }
}

pub(crate) async fn cmd_gdrive_auth(
    client_id: Option<String>,
    client_secret: Option<String>,
    output: Option<&Path>,
) -> Result<()> {
    let explicit_output = output.is_some();
    let output = &tokens_path_or_default(output)?;
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

    // The default location may not exist yet; create it private to the user.
    let default_dir = output.parent().filter(|_| !explicit_output);

    let tokens = complete_local_oauth_flow(
        "Google Drive",
        &auth_url,
        &csrf_token,
        |auth_code| async move {
            let tokens = auth_manager
                .exchange_code(&auth_code, pkce_verifier)
                .await
                .context("Failed to exchange authorization code")?;
            let tokens_json =
                serde_json::to_string_pretty(&tokens).context("Failed to serialize tokens")?;
            save_tokens::<Tokens>(output, default_dir, tokens_json.as_bytes()).await?;
            Ok(tokens)
        },
    )
    .await?;

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
    tokens_path: Option<&Path>,
    strength: KdfStrength,
) -> Result<()> {
    let tokens_path = tokens_path_or_default(tokens_path)?;
    info!("Creating new vault on Google Drive: {}", name);

    // Know the recovery key can be shown before asking for a password.
    may_print_recovery_words(std::io::stdout().is_terminal())?;

    let kdf_params = kdf_params_from(strength);

    let password = prompt_password("Enter password: ")?;
    let confirm = prompt_password("Confirm password: ")?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    validate_password_strength(&password)?;

    // Load tokens
    let tokens = read_tokens(&tokens_path).await?;

    let vault_id = VaultId::unique(name).context("Invalid vault name")?;

    let (manager, provider_config) = gdrive_manager(tokens, folder_id);

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
pub(crate) async fn cmd_gdrive_open(folder_id: &str, tokens_path: Option<&Path>) -> Result<()> {
    let tokens_path = tokens_path_or_default(tokens_path)?;
    info!("Opening vault on Google Drive");

    let password = vault_password("Enter password: ")?;

    // Load tokens
    let tokens = read_tokens(&tokens_path).await?;

    let (manager, provider_config) = gdrive_manager(tokens, folder_id);

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

#[cfg(test)]
mod tests {
    use super::*;
    use axiomvault_storage::{MemoryProvider, ProviderRegistry, StorageProvider};
    use axiomvault_vault::manager::LocalCredentialResolver;
    use axiomvault_vault::InMemoryFreshnessAnchor;

    fn test_tokens() -> Tokens {
        Tokens {
            access_token: "access-secret".to_string(),
            refresh_token: "refresh-secret".to_string(),
            expires_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn gdrive_create_persists_reference_not_tokens() {
        let storage = Arc::new(MemoryProvider::new());
        let factory_storage = storage.clone();
        let mut registry = ProviderRegistry::new();
        registry
            .register(
                "gdrive",
                Box::new(move |config| {
                    assert_eq!(config["tokens"]["access_token"], "access-secret");
                    Ok(factory_storage.clone() as Arc<dyn StorageProvider>)
                }),
            )
            .unwrap();
        let manager = VaultManager::with_registry_credential_resolver_and_anchor(
            registry,
            Arc::new(TokensFileResolver(test_tokens())),
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let (_, provider_config) = gdrive_manager(test_tokens(), "folder-1");

        manager
            .create_vault(
                VaultId::new("gdrive-test").unwrap(),
                b"correct horse battery staple",
                "gdrive",
                provider_config,
                KdfParams::interactive(),
            )
            .await
            .unwrap();

        let config_bytes = storage
            .download(&VaultPath::parse("vault.config").unwrap())
            .await
            .unwrap();
        let config = VaultConfig::from_bytes(&config_bytes).unwrap();
        assert_eq!(
            config.provider_config,
            serde_json::json!({
                "folder_id": "folder-1",
                "credential_ref": GDRIVE_CREDENTIAL_REF,
                // Not set by the CLI: core adds it in `persisted_provider_config` (core/vault/src/manager.rs:18-47 @ 5804c81).
                "credential_schema": 1,
            })
        );
        let raw = String::from_utf8_lossy(&config_bytes);
        assert!(!raw.contains("access-secret") && !raw.contains("refresh-secret"));
    }

    #[test]
    fn tokens_path_defaults_to_config_dir_unless_overridden() {
        let explicit = Path::new("custom/tokens.json");
        assert_eq!(tokens_path_or_default(Some(explicit)).unwrap(), explicit);
        if let Some(config_dir) = dirs::config_dir() {
            assert_eq!(
                tokens_path_or_default(None).unwrap(),
                config_dir.join("axiomvault").join("gdrive-tokens.json")
            );
        }
    }

    #[test]
    fn resolver_rejects_unknown_references() {
        let resolver = TokensFileResolver(test_tokens());
        assert!(resolver.resolve("gdrive", "local:gdrive:other").is_err());
        assert!(resolver.resolve("dropbox", GDRIVE_CREDENTIAL_REF).is_err());
    }

    #[test]
    fn resolve_gdrive_client_id_prefers_primary_env_name() {
        assert_eq!(
            resolve_required_oauth_value(
                None,
                Some("primary-client-id".into()),
                Some("legacy-client-id".into()),
                "missing",
            )
            .unwrap(),
            "primary-client-id"
        );
    }

    #[test]
    fn resolve_gdrive_client_secret_falls_back_to_legacy_value() {
        assert_eq!(
            resolve_optional_oauth_value(None, None, Some("legacy-secret".into())),
            Some("legacy-secret".into())
        );
    }
}
