use crate::cli::KdfStrength;
use anyhow::{Context, Result};
use axiomvault_crypto::KdfParams;
use zeroize::{Zeroize, Zeroizing};

const MIN_PASSWORD_LENGTH: usize = 8;
const PASSWORD_ENV_VARS: [&str; 2] = ["AXIOM_PASSWORD", "AXIOMVAULT_PASSWORD"];

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
    // Allow non-interactive use via environment variable (useful for scripting/testing).
    for env_var in PASSWORD_ENV_VARS {
        if let Ok(mut pw) = std::env::var(env_var) {
            if !pw.is_empty() {
                let bytes = Zeroizing::new(pw.as_bytes().to_vec());
                pw.zeroize();
                return Ok(bytes);
            }
        }
    }

    let mut password = rpassword::prompt_password(prompt).context("Failed to read password")?;
    let bytes = Zeroizing::new(password.as_bytes().to_vec());
    password.zeroize();
    Ok(bytes)
}

/// Refuse a password-changing command while a password env var is set.
///
/// With the env var set, every prompt returns the same value, so the old and
/// new passwords would be identical and the command would silently do nothing.
pub(crate) fn ensure_no_env_password(command: &str) -> Result<()> {
    let set_var = PASSWORD_ENV_VARS
        .into_iter()
        .find(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()));
    refuse_env_password(set_var, command)
}

fn refuse_env_password(set_var: Option<&str>, command: &str) -> Result<()> {
    if let Some(name) = set_var {
        anyhow::bail!(
            "{name} is set, so `{command}` would reuse it for every password prompt \
             and change nothing. Unset {name} and run `{command}` again interactively."
        );
    }
    Ok(())
}

/// Allow recovery words to be printed only to an interactive terminal, so they
/// never end up in a file, a pipe or a log.
pub(crate) fn may_print_recovery_words(stdout_is_tty: bool) -> Result<()> {
    if !stdout_is_tty {
        anyhow::bail!(
            "Refusing to print the recovery key: standard output is not a terminal. \
             Run this command interactively, without redirecting or piping its output."
        );
    }
    Ok(())
}

/// Display recovery words and prompt user to confirm they've saved them.
pub(crate) fn display_recovery_words(words: &str) {
    println!();
    println!("=== RECOVERY KEY ===");
    println!("Write down these 24 words and store them in a safe place.");
    println!("You will need them to recover your vault if you forget your password.");
    println!();

    for (i, word) in words.split_whitespace().enumerate() {
        println!(" {:>2}. {}", i + 1, word);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn prompt_password_prefers_axiom_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_axiom = std::env::var("AXIOM_PASSWORD").ok();
        let original_legacy = std::env::var("AXIOMVAULT_PASSWORD").ok();

        std::env::set_var("AXIOM_PASSWORD", "new-secret");
        std::env::set_var("AXIOMVAULT_PASSWORD", "legacy-secret");

        let password = prompt_password("unused").unwrap();
        assert_eq!(password.as_slice(), b"new-secret");

        restore_env("AXIOM_PASSWORD", original_axiom);
        restore_env("AXIOMVAULT_PASSWORD", original_legacy);
    }

    #[test]
    fn prompt_password_falls_back_to_legacy_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_axiom = std::env::var("AXIOM_PASSWORD").ok();
        let original_legacy = std::env::var("AXIOMVAULT_PASSWORD").ok();

        std::env::remove_var("AXIOM_PASSWORD");
        std::env::set_var("AXIOMVAULT_PASSWORD", "legacy-secret");

        let password = prompt_password("unused").unwrap();
        assert_eq!(password.as_slice(), b"legacy-secret");

        restore_env("AXIOM_PASSWORD", original_axiom);
        restore_env("AXIOMVAULT_PASSWORD", original_legacy);
    }

    #[test]
    fn env_password_refuses_password_change() {
        let err = refuse_env_password(Some("AXIOM_PASSWORD"), "axiom password change")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Unset AXIOM_PASSWORD"), "{err}");
        assert!(err.contains("axiom password change"), "{err}");
    }

    #[test]
    fn no_env_password_allows_password_change() {
        assert!(refuse_env_password(None, "axiom password reset").is_ok());
    }

    #[test]
    fn ensure_no_env_password_detects_legacy_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original_axiom = std::env::var("AXIOM_PASSWORD").ok();
        let original_legacy = std::env::var("AXIOMVAULT_PASSWORD").ok();

        std::env::remove_var("AXIOM_PASSWORD");
        std::env::set_var("AXIOMVAULT_PASSWORD", "legacy-secret");
        let err = ensure_no_env_password("axiom password reset").unwrap_err();
        assert!(err.to_string().contains("AXIOMVAULT_PASSWORD"));

        restore_env("AXIOM_PASSWORD", original_axiom);
        restore_env("AXIOMVAULT_PASSWORD", original_legacy);
    }

    #[test]
    fn recovery_words_refused_when_stdout_is_not_a_tty() {
        let err = may_print_recovery_words(false).unwrap_err().to_string();
        assert!(err.contains("not a terminal"), "{err}");
        assert!(err.contains("interactively"), "{err}");
    }

    #[test]
    fn recovery_words_allowed_on_a_tty() {
        assert!(may_print_recovery_words(true).is_ok());
    }

    fn restore_env(key: &str, value: Option<String>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }
}
