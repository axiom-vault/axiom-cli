use crate::password::vault_password;
use anyhow::{anyhow, bail, Context, Result};
use axiomvault_storage::StorageProvider;
use axiomvault_vault::{
    config::{HardwareKeyKind, HardwareKeyMetadata, CONFIG_FILENAME},
    VaultConfig, VaultManager, VaultSession,
};
use std::path::Path;
use zeroize::Zeroizing;

/// Minimum decoded length of a hardware-key response. A YubiKey HMAC-SHA1
/// response is 20 bytes. The core enforces the same floor as a backstop.
const MIN_RESPONSE_BYTES: usize = 16;
const RESPONSE_PROMPT: &str = "YubiKey response (hex:..., at least 16 bytes): ";
const RESPONSE_FORMAT_HINT: &str = "Enter the response as hex with a `hex:` prefix, \
     at least 16 bytes (32 hex digits); a YubiKey HMAC-SHA1 response is 20 bytes.";

pub(crate) async fn cmd_enroll(
    path: &Path,
    label: Option<&str>,
    key_id: Option<&str>,
) -> Result<()> {
    let password = vault_password("Enter password: ")?;
    let secret = read_hardware_response()?;
    enroll(path, label, key_id, &password, &secret).await
}

async fn enroll(
    path: &Path,
    label: Option<&str>,
    key_id: Option<&str>,
    password: &[u8],
    secret: &[u8],
) -> Result<()> {
    let manager = VaultManager::new();
    let provider_config = local_provider_config(path);
    let mut session = manager
        .open_vault("local", provider_config, password)
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
        .enroll_hardware_key(&master_key, secret, metadata)
        .context("Failed to enroll hardware key")?;
    manager
        .save_config(&mut session)
        .await
        .context("Failed to save hardware-key enrollment")?;

    println!("Hardware key enrolled successfully.");
    println!(" Kind: YubiKey challenge-response bytes");
    Ok(())
}

pub(crate) async fn cmd_status(path: &Path) -> Result<()> {
    let (config, _) = load_local_config_and_provider(path).await?;
    println!("{}", format_hardware_key_status(&config, false));
    Ok(())
}

pub(crate) async fn cmd_remove(path: &Path) -> Result<()> {
    let password = vault_password("Enter password: ")?;
    remove(path, &password).await
}

async fn remove(path: &Path, password: &[u8]) -> Result<()> {
    let manager = VaultManager::new();
    let provider_config = local_provider_config(path);
    let mut session = manager
        .open_vault("local", provider_config, password)
        .await
        .context("Failed to open vault")?;

    if !session.config().hardware_key_status().is_enrolled() {
        println!("No hardware key is enrolled for this vault.");
        return Ok(());
    }

    session.config_mut().remove_hardware_key();
    manager
        .save_config(&mut session)
        .await
        .context("Failed to save hardware-key removal")?;
    println!("Hardware key removed successfully.");
    Ok(())
}

pub(crate) async fn cmd_test(path: &Path) -> Result<()> {
    let (config, _) = load_local_config_and_provider(path).await?;
    let secret = read_hardware_response()?;
    verify_response(&config, &secret)
}

fn verify_response(config: &VaultConfig, secret: &[u8]) -> Result<()> {
    let verified = config
        .verify_hardware_key(secret)
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
    let secret = read_hardware_response()?;
    open_with_response(config, provider, &secret).await
}

async fn open_with_response(
    config: VaultConfig,
    provider: std::sync::Arc<dyn StorageProvider>,
    secret: &[u8],
) -> Result<()> {
    let master_key = config
        .verify_hardware_key(secret)
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

/// Read the hardware-key response from the terminal with echo off.
fn read_hardware_response() -> Result<Zeroizing<Vec<u8>>> {
    load_hardware_response(rpassword::ConfigBuilder::new().build())
}

/// Prompt for the response on the input `config` names (the terminal by
/// default), read it with echo off and decode it. No environment variable is
/// consulted.
fn load_hardware_response(config: rpassword::Config) -> Result<Zeroizing<Vec<u8>>> {
    let input = Zeroizing::new(
        rpassword::prompt_password_with_config(RESPONSE_PROMPT, config)
            .context("Failed to read hardware-key response")?,
    );
    decode_hardware_secret(&input)
}

/// Decode a `hex:` response and enforce the entropy floor. Errors never
/// include the input, so a typo does not leak part of the secret.
fn decode_hardware_secret(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("Hardware-key response cannot be empty. {RESPONSE_FORMAT_HINT}");
    }

    let Some(hex_value) = trimmed.strip_prefix("hex:") else {
        bail!("Plain-text hardware-key responses are not accepted. {RESPONSE_FORMAT_HINT}");
    };

    let bytes = decode_hex_secret(hex_value)?;
    if bytes.len() < MIN_RESPONSE_BYTES {
        bail!(
            "Hardware-key response is {} bytes, but at least {MIN_RESPONSE_BYTES} bytes \
             are required. {RESPONSE_FORMAT_HINT}",
            bytes.len()
        );
    }
    Ok(bytes)
}

fn decode_hex_secret(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        value
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace() && *ch != '_')
            .collect(),
    );

    if cleaned.is_empty() {
        bail!("hex hardware-key response cannot be empty");
    }
    if !cleaned.len().is_multiple_of(2) {
        bail!("hex hardware-key response must contain an even number of digits");
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(cleaned.len() / 2));
    for (index, pair) in cleaned.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = decode_hex_nibble(pair[0], index * 2)?;
        let lo = decode_hex_nibble(pair[1], index * 2 + 1)?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

/// Decode one hex digit. The error names only the byte position, never the
/// byte itself, so a typo does not leak part of the secret.
fn decode_hex_nibble(byte: u8, position: usize) -> Result<u8> {
    (byte as char)
        .to_digit(16)
        .map(|digit| digit as u8)
        .ok_or_else(|| {
            anyhow!(
                "invalid hex digit at byte position {position} \
                 (whitespace and underscores are not counted)"
            )
        })
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
        decode_hardware_secret, enroll, format_hardware_key_status, load_hardware_response,
        load_local_config_and_provider, local_provider_config, open_with_response, remove,
        verify_response,
    };
    use axiomvault_common::VaultId;
    use axiomvault_crypto::KdfParams;
    use axiomvault_vault::VaultManager;
    use std::{
        fs,
        io::Cursor,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    const PASSWORD: &[u8] = b"test-password";
    const ENROLLED_RESPONSE: &str = "hex:73696d756c617465642d796b2d726573706f6e7365";
    const WRONG_RESPONSE: &str = "hex:77726f6e672d726573706f6e73652d6279746573";
    /// 15 and 16 bytes of hex.
    const HEX_15: &str = "000102030405060708090a0b0c0d0e";
    const HEX_16: &str = "000102030405060708090a0b0c0d0e0f";

    fn scripted_input(input: &str) -> rpassword::Config {
        rpassword::ConfigBuilder::new()
            .input_reader(Cursor::new(input.as_bytes().to_vec()))
            .output_discard()
            .build()
    }

    #[test]
    fn rejects_15_byte_response() {
        let err = decode_hardware_secret(&format!("hex:{HEX_15}")).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("is 15 bytes"), "{message}");
        assert!(message.contains("at least 16 bytes"), "{message}");
        assert!(!message.contains(HEX_15), "{message}");
    }

    #[test]
    fn accepts_16_byte_response() {
        let decoded = decode_hardware_secret(&format!("hex:{HEX_16}")).unwrap();
        assert_eq!(decoded.as_slice(), (0u8..16).collect::<Vec<_>>().as_slice());
    }

    #[test]
    fn rejects_raw_non_hex_response() {
        let raw = "simulated-yubikey-response-long-enough";
        let err = decode_hardware_secret(raw).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Plain-text"), "{message}");
        assert!(message.contains("hex:"), "{message}");
        assert!(!message.contains(raw), "{message}");
    }

    #[test]
    fn rejects_unprefixed_hex_response() {
        let err = decode_hardware_secret(HEX_16).unwrap_err();
        assert!(!err.to_string().contains(HEX_16));
    }

    #[test]
    fn rejects_odd_length_hex_secret() {
        let err = decode_hardware_secret("hex:abc").unwrap_err();
        assert!(err.to_string().contains("even number of digits"));
    }

    #[test]
    fn invalid_hex_error_reports_position_without_the_character() {
        let err = decode_hardware_secret("hex:61 6Q").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("byte position 3"), "{message}");
        assert!(!message.contains('Q'), "{message}");
    }

    #[test]
    fn loader_ignores_response_environment_variables() {
        let env_value = format!("hex:{HEX_16}");
        let typed = "hex:ffeeddccbbaa99887766554433221100";
        let previous: Vec<_> = ["AXIOM_YUBIKEY_RESPONSE", "AXIOM_HARDWARE_KEY_RESPONSE"]
            .into_iter()
            .map(|name| (name, std::env::var_os(name)))
            .collect();
        for (name, _) in &previous {
            std::env::set_var(name, &env_value);
        }

        let loaded = load_hardware_response(scripted_input(&format!("{typed}\n")));
        let empty = load_hardware_response(scripted_input("\n"));

        for (name, value) in previous {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }

        assert_eq!(
            loaded.unwrap().as_slice(),
            decode_hardware_secret(typed).unwrap().as_slice()
        );
        let message = empty.unwrap_err().to_string();
        assert!(message.contains("cannot be empty"), "{message}");
    }

    #[test]
    fn loader_reports_malformed_input_without_the_value() {
        let err = load_hardware_response(scripted_input("hex:zz\n")).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("invalid hex digit"), "{message}");
        assert!(!message.contains("zz"), "{message}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn temp_vault_enroll_status_test_and_open_flow() {
        let temp_vault = TempVault::create("hardware-key-flow").await;
        let secret = decode_hardware_secret(ENROLLED_RESPONSE).unwrap();

        enroll(
            temp_vault.path(),
            Some("desk yubikey"),
            Some("slot-2"),
            PASSWORD,
            &secret,
        )
        .await
        .unwrap();

        let (config, provider) = load_local_config_and_provider(temp_vault.path())
            .await
            .unwrap();
        verify_response(&config, &secret).unwrap();
        let public_status = format_hardware_key_status(&config, false);
        let private_status = format_hardware_key_status(&config, true);
        open_with_response(config, provider, &secret).await.unwrap();

        assert_eq!(public_status, "Hardware key enrolled: yes");
        assert!(private_status.contains("Label: desk yubikey"));
        assert!(private_status.contains("Key ID: slot-2"));
        assert!(private_status.contains("Enrolled at:"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_response_is_rejected() {
        let temp_vault = TempVault::create("hardware-key-wrong-response").await;
        let secret = decode_hardware_secret(ENROLLED_RESPONSE).unwrap();
        enroll(temp_vault.path(), None, None, PASSWORD, &secret)
            .await
            .unwrap();

        let wrong = decode_hardware_secret(WRONG_RESPONSE).unwrap();
        let (config, provider) = load_local_config_and_provider(temp_vault.path())
            .await
            .unwrap();
        let test_err = verify_response(&config, &wrong).unwrap_err();
        assert!(test_err
            .to_string()
            .contains("Hardware-key response did not verify"));

        let open_err = open_with_response(config, provider, &wrong)
            .await
            .unwrap_err();
        assert!(open_err
            .to_string()
            .contains("Hardware-key response did not verify"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remove_disables_subsequent_test_and_open() {
        let temp_vault = TempVault::create("hardware-key-remove").await;
        let secret = decode_hardware_secret(ENROLLED_RESPONSE).unwrap();
        enroll(temp_vault.path(), None, None, PASSWORD, &secret)
            .await
            .unwrap();
        remove(temp_vault.path(), PASSWORD).await.unwrap();

        let (config, provider) = load_local_config_and_provider(temp_vault.path())
            .await
            .unwrap();
        let test_err = verify_response(&config, &secret).unwrap_err();
        assert!(test_err
            .to_string()
            .contains("Failed to verify hardware key"));

        let open_err = open_with_response(config, provider, &secret)
            .await
            .unwrap_err();
        assert!(open_err
            .to_string()
            .contains("Failed to verify hardware key"));
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
                PASSWORD,
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
