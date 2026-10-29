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
use serde::{Deserialize, Serialize};
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

/// The `--tokens` file: the OAuth tokens and the client they were issued to,
/// which refreshing them needs. Google does not treat installed-app client
/// secrets as confidential, so the secret may sit in this owner-only file.
#[derive(Serialize, Deserialize)]
struct GdriveTokenFile {
    /// Missing in token files written by 2.0.0-rc.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    #[serde(flatten)]
    tokens: Tokens,
}

/// Resolves `GDRIVE_CREDENTIAL_REF` to the tokens read from the local `--tokens`
/// file and the client that refreshes them.
struct TokensFileResolver {
    tokens: Tokens,
    auth_config: AuthConfig,
}

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
        let to_value = |value: serde_json::Result<serde_json::Value>| {
            value.map_err(|error| axiomvault_common::Error::Serialization(error.to_string()))
        };
        Ok(serde_json::json!({
            "tokens": to_value(serde_json::to_value(&self.tokens))?,
            "auth_config": to_value(serde_json::to_value(&self.auth_config))?,
        }))
    }
}

/// Build a manager whose provider config carries only `folder_id` and `credential_ref`.
fn gdrive_manager(
    credentials: TokensFileResolver,
    folder_id: &str,
) -> (VaultManager, serde_json::Value) {
    let manager = VaultManager::with_registry_and_credential_resolver(
        create_default_registry(),
        Arc::new(credentials),
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

/// The `auth` command that writes the token file at `path`.
fn gdrive_auth_command(path: &Path) -> String {
    if tokens_path_or_default(None).ok().as_deref() == Some(path) {
        "axiom remote gdrive auth".to_string()
    } else {
        format!("axiom remote gdrive auth --output {}", path.display())
    }
}

/// The client that refreshes the tokens: the one `auth` saved, or for an older
/// token file without one, `--client-id` or the environment.
fn refresh_auth_config(
    file: &GdriveTokenFile,
    client_id: Option<String>,
    auth_command: &str,
) -> Result<AuthConfig> {
    let (client_id, client_secret) = match &file.client_id {
        Some(saved) => (saved.clone(), file.client_secret.clone()),
        None => (
            resolve_gdrive_client_id(client_id).with_context(|| {
                format!("The tokens file has no client ID to refresh its tokens with; run `{auth_command}` again")
            })?,
            resolve_gdrive_client_secret(None),
        ),
    };
    Ok(AuthConfig {
        client_id,
        client_secret,
        redirect_url: GDRIVE_REDIRECT_URL.to_string(),
    })
}

/// Read the Google Drive token file and the client that refreshes its tokens.
async fn load_gdrive_credentials(
    path: &Path,
    client_id: Option<String>,
) -> Result<TokensFileResolver> {
    let auth = gdrive_auth_command(path);
    let file: GdriveTokenFile = read_tokens(path, &auth).await?;
    let auth_config = refresh_auth_config(&file, client_id, &auth)?;
    Ok(TokensFileResolver {
        tokens: file.tokens,
        auth_config,
    })
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
    let (client_id, client_secret) = (
        auth_config.client_id.clone(),
        auth_config.client_secret.clone(),
    );
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
            let token_file = GdriveTokenFile {
                client_id: Some(client_id),
                client_secret,
                tokens,
            };
            let tokens_json =
                serde_json::to_string_pretty(&token_file).context("Failed to serialize tokens")?;
            save_tokens::<GdriveTokenFile>(output, default_dir, tokens_json.as_bytes()).await?;
            Ok(token_file.tokens)
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
    client_id: Option<String>,
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
    let credentials = load_gdrive_credentials(&tokens_path, client_id).await?;

    let vault_id = VaultId::unique(name).context("Invalid vault name")?;

    let (manager, provider_config) = gdrive_manager(credentials, folder_id);

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
pub(crate) async fn cmd_gdrive_open(
    folder_id: &str,
    tokens_path: Option<&Path>,
    client_id: Option<String>,
) -> Result<()> {
    let tokens_path = tokens_path_or_default(tokens_path)?;
    info!("Opening vault on Google Drive");

    let password = vault_password("Enter password: ")?;

    // Load tokens
    let credentials = load_gdrive_credentials(&tokens_path, client_id).await?;

    let (manager, provider_config) = gdrive_manager(credentials, folder_id);

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

    fn test_credentials() -> TokensFileResolver {
        TokensFileResolver {
            tokens: test_tokens(),
            auth_config: AuthConfig {
                client_id: "test-client-id".to_string(),
                client_secret: Some("test-client-secret".to_string()),
                redirect_url: GDRIVE_REDIRECT_URL.to_string(),
            },
        }
    }

    fn token_file(client_id: Option<&str>) -> GdriveTokenFile {
        GdriveTokenFile {
            client_id: client_id.map(str::to_string),
            client_secret: client_id.map(|_| "saved-secret".to_string()),
            tokens: test_tokens(),
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
                    // The provider refreshes expired tokens with this client.
                    assert_eq!(config["auth_config"]["client_id"], "test-client-id");
                    Ok(factory_storage.clone() as Arc<dyn StorageProvider>)
                }),
            )
            .unwrap();
        let manager = VaultManager::with_registry_credential_resolver_and_anchor(
            registry,
            Arc::new(test_credentials()),
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let (_, provider_config) = gdrive_manager(test_credentials(), "folder-1");

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
        assert!(!raw.contains("test-client-secret"));
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

    fn token_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("axiom-gdrive-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn read_tokens_hints_at_auth_when_the_file_is_missing() {
        let dir = token_test_dir("missing");
        let path = dir.join("tokens.json");

        let Err(err) = load_gdrive_credentials(&path, None).await else {
            panic!("a missing token file should fail");
        };
        let err = err.to_string();
        assert!(
            err.contains(&format!(
                "run `axiom remote gdrive auth --output {}`",
                path.display()
            )),
            "{err}"
        );

        if let Ok(default) = tokens_path_or_default(None) {
            if !default.exists() {
                let Err(err) = load_gdrive_credentials(&default, None).await else {
                    panic!("a missing token file should fail");
                };
                let err = err.to_string();
                assert!(err.contains("run `axiom remote gdrive auth` to"), "{err}");
            }
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_rejects_unknown_references() {
        let resolver = test_credentials();
        assert!(resolver.resolve("gdrive", "local:gdrive:other").is_err());
        assert!(resolver.resolve("dropbox", GDRIVE_CREDENTIAL_REF).is_err());
    }

    #[test]
    fn resolved_credentials_give_core_the_client() {
        let mut runtime = test_credentials()
            .resolve("gdrive", GDRIVE_CREDENTIAL_REF)
            .unwrap();
        runtime["folder_id"] = "folder-1".into();
        let config: GDriveConfig = serde_json::from_value(runtime).unwrap();
        let auth_config = config.auth_config.expect("auth_config is passed to core");
        assert_eq!(auth_config.client_id, "test-client-id");
        assert_eq!(
            auth_config.client_secret.as_deref(),
            Some("test-client-secret")
        );
    }

    #[test]
    fn refresh_uses_the_saved_client_before_flag_or_env() {
        let config = refresh_auth_config(
            &token_file(Some("saved-id")),
            Some("flag-id".into()),
            "auth",
        )
        .unwrap();
        assert_eq!(config.client_id, "saved-id");
        assert_eq!(config.client_secret.as_deref(), Some("saved-secret"));
    }

    #[test]
    fn rc3_token_file_parses_and_falls_back_to_the_flag() {
        // An rc.3 token file holds the tokens only.
        let rc3 = serde_json::to_value(test_tokens()).unwrap();
        let file: GdriveTokenFile = serde_json::from_value(rc3).unwrap();
        assert!(file.client_id.is_none());

        let config = refresh_auth_config(&file, Some("flag-id".into()), "auth").unwrap();
        assert_eq!(config.client_id, "flag-id");

        let env_set = [AXIOM_GOOGLE_CLIENT_ID_ENV, AXIOMVAULT_GOOGLE_CLIENT_ID_ENV]
            .iter()
            .any(|name| std::env::var(name).is_ok_and(|value| !value.is_empty()));
        if !env_set {
            let err = refresh_auth_config(&file, None, "axiom remote gdrive auth").unwrap_err();
            let err = format!("{err:#}");
            assert!(
                err.contains("run `axiom remote gdrive auth` again") && err.contains("--client-id"),
                "{err}"
            );
        }
    }

    #[test]
    fn token_file_keeps_tokens_flat_and_omits_a_missing_secret() {
        let mut file = token_file(Some("saved-id"));
        file.client_secret = None;
        let json = serde_json::to_value(&file).unwrap();
        assert_eq!(json["client_id"], "saved-id");
        assert_eq!(json["refresh_token"], "refresh-secret");
        assert!(json.get("client_secret").is_none());
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
