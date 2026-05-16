use crate::password::prompt_password;
use anyhow::{anyhow, bail, Context, Result};
use axiomvault_storage::StorageProvider;
use axiomvault_vault::{
    config::{HardwareKeyKind, HardwareKeyMetadata, CONFIG_FILENAME},
    VaultConfig, VaultManager, VaultSession,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const HARDWARE_SECRET_ENV_VARS: [&str; 2] =
    ["AXIOM_YUBIKEY_RESPONSE", "AXIOM_HARDWARE_KEY_RESPONSE"];

struct LoadedHardwareSecret {
    source_env_var: &'static str,
    bytes: Vec<u8>,
}

impl LoadedHardwareSecret {
    fn source_env_var(&self) -> &'static str {
        self.source_env_var
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl Drop for LoadedHardwareSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

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
    println!(" Secret source: {}", secret.source_env_var());
    println!(" Kind: YubiKey challenge-response bytes");
    Ok(())
}

pub(crate) async fn cmd_status(path: &Path) -> Result<()> {
    let (config, _) = load_local_config_and_provider(path).await?;
    println!("{}", format_hardware_key_status(&config, false));
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

fn load_hardware_secret_from_env() -> Result<LoadedHardwareSecret> {
    for env_var in HARDWARE_SECRET_ENV_VARS {
        if let Ok(mut value) = std::env::var(env_var) {
            if value.trim().is_empty() {
                value.zeroize();
                continue;
            }

            let decoded = decode_hardware_secret(&value)
                .with_context(|| format!("Failed to decode {env_var}"));
            value.zeroize();

            return decoded.map(|bytes| LoadedHardwareSecret {
                source_env_var: env_var,
                bytes,
            });
        }
    }

    bail!(
        "Set {} to the YubiKey challenge-response bytes (plain UTF-8 or hex:...)",
        hardware_secret_env_names().join(" or ")
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

fn format_hardware_key_status(config: &VaultConfig, include_metadata: bool) -> String {
    let status = config.hardware_key_status();
    let mut lines = vec![format!(
        "Hardware key enrolled: {}",
        if status.enrolled { "yes" } else { "no" }
    )];

    if include_metadata {
        if let Some(metadata) = status.metadata {
            lines.push(format!(" Kind: {:?}", metadata.kind));
            if let Some(label) = metadata.label {
                lines.push(format!(" Label: {label}"));
            }
            if let Some(key_id) = metadata.key_id {
                lines.push(format!(" Key ID: {key_id}"));
            }
            lines.push(format!(" Enrolled at: {}", metadata.enrolled_at));
        }
    }

    lines.join("\n")
}

fn hardware_secret_env_names() -> Vec<&'static str> {
    HARDWARE_SECRET_ENV_VARS.to_vec()
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
    serde_json::json!({
        "root": path.to_string_lossy().to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::{
        cmd_enroll, cmd_open, cmd_remove, cmd_status, cmd_test, decode_hardware_secret,
        format_hardware_key_status, load_hardware_secret_from_env, load_local_config_and_provider,
        local_provider_config,
    };
    use axiomvault_common::VaultId;
    use axiomvault_crypto::KdfParams;
    use axiomvault_vault::VaultManager;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const PASSWORD: &str = "test-password";
    const ENROLLED_RESPONSE: &str = "hex:73696d756c617465642d796b2d726573706f6e7365";
    const WRONG_RESPONSE: &str = "hex:77726f6e672d726573706f6e7365";

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
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let original_primary = std::env::var("AXIOM_YUBIKEY_RESPONSE").ok();
        let original_fallback = std::env::var("AXIOM_HARDWARE_KEY_RESPONSE").ok();
        std::env::set_var("AXIOM_YUBIKEY_RESPONSE", "hex:616263");
        std::env::set_var("AXIOM_HARDWARE_KEY_RESPONSE", "ignored");
        let decoded = load_hardware_secret_from_env().unwrap();
        assert_eq!(decoded.source_env_var(), "AXIOM_YUBIKEY_RESPONSE");
        assert_eq!(decoded.as_slice(), b"abc");
        restore_env("AXIOM_YUBIKEY_RESPONSE", original_primary);
        restore_env("AXIOM_HARDWARE_KEY_RESPONSE", original_fallback);
    }

    #[test]
    fn loads_fallback_env_var() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let original_primary = std::env::var("AXIOM_YUBIKEY_RESPONSE").ok();
        let original_fallback = std::env::var("AXIOM_HARDWARE_KEY_RESPONSE").ok();
        std::env::remove_var("AXIOM_YUBIKEY_RESPONSE");
        std::env::set_var("AXIOM_HARDWARE_KEY_RESPONSE", "hex:646566");
        let decoded = load_hardware_secret_from_env().unwrap();
        assert_eq!(decoded.source_env_var(), "AXIOM_HARDWARE_KEY_RESPONSE");
        assert_eq!(decoded.as_slice(), b"def");
        restore_env("AXIOM_YUBIKEY_RESPONSE", original_primary);
        restore_env("AXIOM_HARDWARE_KEY_RESPONSE", original_fallback);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn temp_vault_enroll_status_test_and_open_flow() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let temp_vault = TempVault::create("hardware-key-flow").await;
        let _env = TestEnv::set(PASSWORD, Some(ENROLLED_RESPONSE), None);

        cmd_enroll(temp_vault.path(), Some("desk yubikey"), Some("slot-2"))
            .await
            .unwrap();
        cmd_status(temp_vault.path()).await.unwrap();
        cmd_test(temp_vault.path()).await.unwrap();
        cmd_open(temp_vault.path()).await.unwrap();

        let (config, _) = load_local_config_and_provider(temp_vault.path())
            .await
            .unwrap();
        let public_status = format_hardware_key_status(&config, false);
        let private_status = format_hardware_key_status(&config, true);
        assert_eq!(public_status, "Hardware key enrolled: yes");
        assert!(private_status.contains("Label: desk yubikey"));
        assert!(private_status.contains("Key ID: slot-2"));
        assert!(private_status.contains("Enrolled at:"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_response_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let temp_vault = TempVault::create("hardware-key-wrong-response").await;
        let _env = TestEnv::set(PASSWORD, Some(ENROLLED_RESPONSE), None);
        cmd_enroll(temp_vault.path(), None, None).await.unwrap();

        let _env = TestEnv::set(PASSWORD, Some(WRONG_RESPONSE), None);
        let test_err = cmd_test(temp_vault.path()).await.unwrap_err();
        assert!(test_err
            .to_string()
            .contains("Hardware-key response did not verify"));

        let open_err = cmd_open(temp_vault.path()).await.unwrap_err();
        assert!(open_err
            .to_string()
            .contains("Hardware-key response did not verify"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remove_disables_subsequent_test_and_open() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let temp_vault = TempVault::create("hardware-key-remove").await;
        let _env = TestEnv::set(PASSWORD, Some(ENROLLED_RESPONSE), None);
        cmd_enroll(temp_vault.path(), None, None).await.unwrap();
        cmd_remove(temp_vault.path()).await.unwrap();

        let test_err = cmd_test(temp_vault.path()).await.unwrap_err();
        assert!(test_err
            .to_string()
            .contains("Failed to verify hardware key"));

        let open_err = cmd_open(temp_vault.path()).await.unwrap_err();
        assert!(open_err
            .to_string()
            .contains("Failed to verify hardware key"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_env_is_reported() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let temp_vault = TempVault::create("hardware-key-missing-env").await;
        let _env = TestEnv::set(PASSWORD, Some(ENROLLED_RESPONSE), None);
        cmd_enroll(temp_vault.path(), None, None).await.unwrap();

        let _env = TestEnv::set(PASSWORD, None, None);
        let err = cmd_test(temp_vault.path()).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("AXIOM_YUBIKEY_RESPONSE"));
        assert!(message.contains("AXIOM_HARDWARE_KEY_RESPONSE"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_env_is_reported() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let temp_vault = TempVault::create("hardware-key-malformed-env").await;
        let _env = TestEnv::set(PASSWORD, Some(ENROLLED_RESPONSE), None);
        cmd_enroll(temp_vault.path(), None, None).await.unwrap();

        let _env = TestEnv::set(PASSWORD, Some("hex:zz"), None);
        let err = cmd_test(temp_vault.path()).await.unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("Failed to decode AXIOM_YUBIKEY_RESPONSE"));
        assert!(message.contains("invalid hex digit"));
    }

    fn restore_env(key: &str, value: Option<String>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    struct TestEnv {
        password: Option<String>,
        primary: Option<String>,
        fallback: Option<String>,
    }

    impl TestEnv {
        fn set(password: &str, primary: Option<&str>, fallback: Option<&str>) -> Self {
            let previous = Self {
                password: std::env::var("AXIOM_PASSWORD").ok(),
                primary: std::env::var("AXIOM_YUBIKEY_RESPONSE").ok(),
                fallback: std::env::var("AXIOM_HARDWARE_KEY_RESPONSE").ok(),
            };

            std::env::set_var("AXIOM_PASSWORD", password);
            match primary {
                Some(value) => std::env::set_var("AXIOM_YUBIKEY_RESPONSE", value),
                None => std::env::remove_var("AXIOM_YUBIKEY_RESPONSE"),
            }
            match fallback {
                Some(value) => std::env::set_var("AXIOM_HARDWARE_KEY_RESPONSE", value),
                None => std::env::remove_var("AXIOM_HARDWARE_KEY_RESPONSE"),
            }

            previous
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            restore_env("AXIOM_PASSWORD", self.password.take());
            restore_env("AXIOM_YUBIKEY_RESPONSE", self.primary.take());
            restore_env("AXIOM_HARDWARE_KEY_RESPONSE", self.fallback.take());
        }
    }

    struct TempVault {
        path: PathBuf,
    }

    impl TempVault {
        async fn create(prefix: &str) -> Self {
            let path = unique_temp_dir(prefix);
            fs::create_dir_all(&path).unwrap();
            create_vault_at(&path).await;
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempVault {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    async fn create_vault_at(path: &Path) {
        let manager = VaultManager::new();
        manager
            .create_vault(
                VaultId::new("test-vault").unwrap(),
                PASSWORD.as_bytes(),
                "local",
                local_provider_config(path),
                KdfParams::interactive(),
            )
            .await
            .unwrap();
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("axiom-cli-{prefix}-{}-{nanos}", std::process::id()))
    }
}
