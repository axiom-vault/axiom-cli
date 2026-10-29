use crate::cli::KdfStrength;
use crate::commands::remote_oauth::{
    complete_local_oauth_flow, read_tokens, resolve_optional_oauth_value,
    resolve_required_oauth_value, save_tokens,
};
use crate::password::{
    display_recovery_words, kdf_params_from, may_print_recovery_words, prompt_password,
    validate_password_strength, vault_password,
};
use anyhow::{Context, Result};
use axiomvault_common::VaultId;
use axiomvault_storage::dropbox::{DropboxAuthConfig, DropboxAuthManager, DropboxTokens};
use axiomvault_storage::{create_default_registry, CloudAuthorization};
use axiomvault_vault::VaultManager;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
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

/// Opaque, non-secret reference persisted in `vault.config` instead of tokens.
const DROPBOX_CREDENTIAL_REF: &str = "local:dropbox:cli-tokens";

/// Resolves `DROPBOX_CREDENTIAL_REF` to the tokens read from the local `--tokens` file.
struct TokensFileResolver(DropboxTokens);

impl axiomvault_vault::manager::LocalCredentialResolver for TokensFileResolver {
    fn resolve(
        &self,
        provider_type: &str,
        credential_ref: &str,
    ) -> axiomvault_common::Result<serde_json::Value> {
        if provider_type != "dropbox" || credential_ref != DROPBOX_CREDENTIAL_REF {
            return Err(axiomvault_common::Error::NotFound(format!(
                "Unknown credential reference '{credential_ref}'"
            )));
        }
        let tokens = serde_json::to_value(&self.0)
            .map_err(|error| axiomvault_common::Error::Serialization(error.to_string()))?;
        Ok(serde_json::json!({ "tokens": tokens }))
    }
}

/// Build a manager whose provider config carries only `root_path` and `credential_ref`.
fn dropbox_manager(tokens: DropboxTokens, root_path: &str) -> (VaultManager, serde_json::Value) {
    let manager = VaultManager::with_registry_and_credential_resolver(
        create_default_registry(),
        Arc::new(TokensFileResolver(tokens)),
    );
    let provider_config = serde_json::json!({
        "root_path": root_path,
        "credential_ref": DROPBOX_CREDENTIAL_REF,
    });
    (manager, provider_config)
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
            let tokens = auth_manager
                .exchange_code(&auth_code, pkce_verifier)
                .await
                .context("Failed to exchange authorization code")?;
            let tokens_json = serde_json::to_string_pretty(&tokens)
                .context("Failed to serialize Dropbox tokens")?;
            save_tokens::<DropboxTokens>(output, None, tokens_json.as_bytes()).await?;
            Ok(tokens)
        })
        .await?;

    println!();
    println!("Authentication successful!");
    println!(" Tokens saved to: {}", output.display());
    println!(" Expires at: {}", tokens.expires_at);
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

    // Know the recovery key can be shown before asking for a password.
    may_print_recovery_words(std::io::stdout().is_terminal())?;

    let kdf_params = kdf_params_from(strength);
    let password = prompt_password("Enter password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }
    validate_password_strength(&password)?;

    let tokens: DropboxTokens = read_tokens(tokens_path).await?;

    let vault_id = VaultId::unique(name).context("Invalid vault name")?;
    let (manager, provider_config) = dropbox_manager(tokens, root_path);

    let creation = manager
        .create_vault(vault_id, &password, "dropbox", provider_config, kdf_params)
        .await
        .context("Failed to create vault on Dropbox")?;

    println!("Vault created successfully on Dropbox!");
    println!(" ID: {}", creation.session.vault_id());
    println!(" Root path: {}", root_path);
    println!(" Provider: {}", creation.session.config().provider_type);
    display_recovery_words(&creation.recovery_words);
    Ok(())
}

pub(crate) async fn cmd_dropbox_open(root_path: &str, tokens_path: &Path) -> Result<()> {
    info!("Opening vault on Dropbox");

    let password = vault_password("Enter password: ")?;
    let tokens: DropboxTokens = read_tokens(tokens_path).await?;
    let (manager, provider_config) = dropbox_manager(tokens, root_path);

    let session = manager
        .open_vault("dropbox", provider_config, &password)
        .await
        .context("Failed to open vault on Dropbox")?;

    println!("Vault opened successfully from Dropbox!");
    println!(" ID: {}", session.vault_id());
    println!(" Session: {}", session.handle().as_str());
    println!("\nVault is ready for operations.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiomvault_common::VaultPath;
    use axiomvault_crypto::KdfParams;
    use axiomvault_storage::{MemoryProvider, ProviderRegistry, StorageProvider};
    use axiomvault_vault::manager::LocalCredentialResolver;
    use axiomvault_vault::{InMemoryFreshnessAnchor, VaultConfig};

    fn test_tokens() -> DropboxTokens {
        DropboxTokens {
            access_token: "access-secret".to_string(),
            refresh_token: "refresh-secret".to_string(),
            expires_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn dropbox_create_persists_reference_not_tokens() {
        let storage = Arc::new(MemoryProvider::new());
        let factory_storage = storage.clone();
        let mut registry = ProviderRegistry::new();
        registry
            .register(
                "dropbox",
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
        let (_, provider_config) = dropbox_manager(test_tokens(), "/AxiomVault");

        manager
            .create_vault(
                VaultId::new("dropbox-test").unwrap(),
                b"correct horse battery staple",
                "dropbox",
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
                "root_path": "/AxiomVault",
                "credential_ref": DROPBOX_CREDENTIAL_REF,
                "credential_schema": 1,
            })
        );
        let raw = String::from_utf8_lossy(&config_bytes);
        assert!(!raw.contains("access-secret") && !raw.contains("refresh-secret"));
    }

    #[test]
    fn resolver_rejects_unknown_references() {
        let resolver = TokensFileResolver(test_tokens());
        assert!(resolver.resolve("dropbox", "local:dropbox:other").is_err());
        assert!(resolver.resolve("gdrive", DROPBOX_CREDENTIAL_REF).is_err());
    }

    #[test]
    fn resolve_dropbox_app_key_prefers_primary_env_name() {
        assert_eq!(
            resolve_required_oauth_value(
                None,
                Some("primary-app-key".into()),
                Some("legacy-app-key".into()),
                "missing",
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
