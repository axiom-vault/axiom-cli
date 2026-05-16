use crate::password::prompt_password;
use anyhow::{anyhow, bail, Context, Result};
use axiomvault_storage::StorageProvider;
use axiomvault_vault::{
    config::{HardwareKeyKind, HardwareKeyMetadata, CONFIG_FILENAME},
    VaultConfig, VaultManager, VaultSession,
};
use std::path::Path;

const HARDWARE_SECRET_ENV_VARS: [&str; 2] =
    ["AXIOM_YUBIKEY_RESPONSE", "AXIOM_HARDWARE_KEY_RESPONSE"];

pub(crate) async fn cmd_enroll(
    path: &Path,
    label: Option<&str>,
    key_id: Option<&str>,
) -> Result<()> {
    let password = prompt_password("Enter password: ")?;
    let secret = load_hardware_secret_from_env()?;
    let manager = VaultManager::new();
    let provider_config = local_provider_config(path);
    let mut session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    let metadata = HardwareKeyMetadata::new(
        HardwareKeyKind::YubiKeyHmacSha1,
        label.map(str::to_owned),
        key_id.map(str::to_owned),
    );
    let master_key = session.master_key().context("Session not active")?.clone();
    session
        .config_mut()
        .enroll_hardware_key(&master_key, secret.as_slice(), metadata)
        .context("Failed to enroll hardware key")?;
    manager
        .save_config(&session)
        .await
        .context("Failed to save hardware-key enrollment")?;

    println!("Hardware key enrolled successfully.");
    println!(" Secret source: AXIOM_YUBIKEY_RESPONSE");
    println!(" Kind: YubiKey challenge-response bytes");
    Ok(())
}

pub(crate) async fn cmd_status(path: &Path) -> Result<()> {
    let (config, _) = load_local_config_and_provider(path).await?;
    let status = config.hardware_key_status();

    println!(
        "Hardware key enrolled: {}",
        if status.enrolled { "yes" } else { "no" }
    );
    if let Some(metadata) = status.metadata {
        println!(" Kind: {:?}", metadata.kind);
        if let Some(label) = metadata.label {
            println!(" Label: {label}");
        }
        if let Some(key_id) = metadata.key_id {
            println!(" Key ID: {key_id}");
        }
        println!(" Enrolled at: {}", metadata.enrolled_at);
    }

    Ok(())
}

pub(crate) async fn cmd_remove(path: &Path) -> Result<()> {
    let password = prompt_password("Enter password: ")?;
    let manager = VaultManager::new();
    let provider_config = local_provider_config(path);
    let mut session = manager
        .open_vault("local", provider_config, &password)
        .await
        .context("Failed to open vault")?;

    if !session.config().hardware_key_status().is_enrolled() {
        println!("No hardware key is enrolled for this vault.");
        return Ok(());
    }

    session.config_mut().remove_hardware_key();
    manager
        .save_config(&session)
        .await
        .context("Failed to save hardware-key removal")?;

    println!("Hardware key removed successfully.");
    Ok(())
}

pub(crate) async fn cmd_test(path: &Path) -> Result<()> {
    let (config, _) = load_local_config_and_provider(path).await?;
    let secret = load_hardware_secret_from_env()?;
    let verified = config
        .verify_hardware_key(secret.as_slice())
        .context("Failed to verify hardware key")?
        .is_some();

    if !verified {
        bail!("Hardware-key response did not verify for this vault");
    }

    println!("Hardware-key response verified successfully.");
    Ok(())
}

pub(crate) async fn cmd_open(path: &Path) -> Result<()> {
    let (config, provider) = load_local_config_and_provider(path).await?;
    let secret = load_hardware_secret_from_env()?;
    let master_key = config
        .verify_hardware_key(secret.as_slice())
        .context("Failed to verify hardware key")?
        .ok_or_else(|| anyhow!("Hardware-key response did not verify for this vault"))?;
    let tree = VaultSession::load_and_decrypt_tree(&provider, &master_key)
        .await
        .context("Failed to load vault tree")?;
    let session = VaultSession::from_master_key(config, master_key, provider, tree)
        .context("Failed to open vault with hardware key")?;

    println!("Vault opened successfully with hardware key!");
    println!(" ID: {}", session.vault_id());
    println!(" Session: {}", session.handle().as_str());
    println!("\nVault is ready for operations.");
    Ok(())
}

fn load_hardware_secret_from_env() -> Result<Vec<u8>> {
    for env_var in HARDWARE_SECRET_ENV_VARS {
        if let Ok(value) = std::env::var(env_var) {
            if value.trim().is_empty() {
                continue;
            }

            return decode_hardware_secret(&value)
                .with_context(|| format!("Failed to decode {env_var}"));
        }
    }

    bail!(
        "Set AXIOM_YUBIKEY_RESPONSE to the YubiKey challenge-response bytes (plain UTF-8 or hex:...)"
    )
}

fn decode_hardware_secret(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("Hardware-key response cannot be empty");
    }

    if let Some(hex_value) = trimmed.strip_prefix("hex:") {
        return decode_hex_secret(hex_value);
    }

    Ok(trimmed.as_bytes().to_vec())
}

fn decode_hex_secret(value: &str) -> Result<Vec<u8>> {
    let cleaned: String = value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '_')
        .collect();

    if cleaned.is_empty() {
        bail!("hex hardware-key response cannot be empty");
    }
    if cleaned.len() % 2 != 0 {
        bail!("hex hardware-key response must contain an even number of digits");
    }

    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.as_bytes().chunks_exact(2) {
        let hi = decode_hex_nibble(pair[0] as char)?;
        let lo = decode_hex_nibble(pair[1] as char)?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn decode_hex_nibble(ch: char) -> Result<u8> {
    ch.to_digit(16)
        .map(|digit| digit as u8)
        .ok_or_else(|| anyhow!("invalid hex digit '{ch}'"))
}

async fn load_local_config_and_provider(
    path: &Path,
) -> Result<(VaultConfig, std::sync::Arc<dyn StorageProvider>)> {
    let manager = VaultManager::new();
    let provider = manager
        .registry()
        .resolve("local", local_provider_config(path))
        .context("Failed to resolve local storage provider")?;
    let config_path = axiomvault_common::VaultPath::parse(CONFIG_FILENAME)?;

    if !provider.exists(&config_path).await? {
        bail!("Vault configuration not found");
    }

    let config_bytes = provider.download(&config_path).await?;
    let config = VaultConfig::from_bytes(&config_bytes).context("Failed to decode vault config")?;
    Ok((config, provider))
}

fn local_provider_config(path: &Path) -> serde_json::Value {
    serde_json::json!({ "root": path.to_string_lossy().to_string() })
}

#[cfg(test)]
mod tests {
    use super::{decode_hardware_secret, load_hardware_secret_from_env};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn decodes_plaintext_secret() {
        let decoded = decode_hardware_secret("simulated-yubikey-response").unwrap();
        assert_eq!(decoded, b"simulated-yubikey-response");
    }

    #[test]
    fn decodes_hex_secret() {
        let decoded = decode_hardware_secret("hex:73696d756c617465642d796b").unwrap();
        assert_eq!(decoded, b"simulated-yk");
    }

    #[test]
    fn rejects_odd_length_hex_secret() {
        let err = decode_hardware_secret("hex:abc").unwrap_err();
        assert!(err.to_string().contains("even number of digits"));
    }

    #[test]
    fn loads_primary_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_primary = std::env::var("AXIOM_YUBIKEY_RESPONSE").ok();
        let original_fallback = std::env::var("AXIOM_HARDWARE_KEY_RESPONSE").ok();

        std::env::set_var("AXIOM_YUBIKEY_RESPONSE", "hex:616263");
        std::env::set_var("AXIOM_HARDWARE_KEY_RESPONSE", "ignored");

        let decoded = load_hardware_secret_from_env().unwrap();
        assert_eq!(decoded, b"abc");

        restore_env("AXIOM_YUBIKEY_RESPONSE", original_primary);
        restore_env("AXIOM_HARDWARE_KEY_RESPONSE", original_fallback);
    }

    fn restore_env(key: &str, value: Option<String>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }
}
