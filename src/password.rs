use crate::cli::KdfStrength;
use anyhow::{Context, Result};
use axiomvault_crypto::KdfParams;
use zeroize::{Zeroize, Zeroizing};

const MIN_PASSWORD_LENGTH: usize = 8;

/// Validate that a password meets the minimum length requirement.
pub(crate) fn validate_password_strength(password: &[u8]) -> Result<()> {
    if password.len() < MIN_PASSWORD_LENGTH {
        anyhow::bail!(
            "Password must be at least {} characters",
            MIN_PASSWORD_LENGTH
        );
    }
    Ok(())
}

/// Prompt for password securely.
pub(crate) fn prompt_password(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Allow non-interactive use via environment variable (useful for scripting/testing)
    if let Ok(mut pw) = std::env::var("AXIOMVAULT_PASSWORD") {
        if !pw.is_empty() {
            let bytes = Zeroizing::new(pw.as_bytes().to_vec());
            pw.zeroize();
            return Ok(bytes);
        }
    }
    let mut password = rpassword::prompt_password(prompt).context("Failed to read password")?;
    let bytes = Zeroizing::new(password.as_bytes().to_vec());
    password.zeroize();
    Ok(bytes)
}

/// Display recovery words and prompt user to confirm they've saved them.
pub(crate) fn display_recovery_words(words: &str) {
    println!();
    println!("=== RECOVERY KEY ===");
    println!("Write down these 24 words and store them in a safe place.");
    println!("You will need them to recover your vault if you forget your password.");
    println!();
    for (i, word) in words.split_whitespace().enumerate() {
        println!("  {:>2}. {}", i + 1, word);
    }
    println!();
    println!("WARNING: This is the only time the recovery key will be shown.");
    println!("If you lose it, you will not be able to recover your vault.");
    println!();
    print!("Press Enter after you have written down the recovery key...");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).ok();
}

/// Convert KDF strength enum to crypto params.
pub(crate) fn kdf_params_from(strength: KdfStrength) -> KdfParams {
    match strength {
        KdfStrength::Interactive => KdfParams::interactive(),
        KdfStrength::Moderate => KdfParams::moderate(),
        KdfStrength::Sensitive => KdfParams::sensitive(),
    }
}
