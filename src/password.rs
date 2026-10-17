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
///
/// The password is always read from the terminal with echo off. There is no
/// environment-variable path: a secret in the environment is visible to child
/// processes and, on some systems, to other users through the process table.
pub(crate) fn prompt_password(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut password = rpassword::prompt_password(prompt).context("Failed to read password")?;
    let bytes = Zeroizing::new(password.as_bytes().to_vec());
    password.zeroize();
    Ok(bytes)
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

    /// Source-level check, because the prompt itself needs a terminal: the
    /// non-test part of this module must not read any environment variable.
    #[test]
    fn password_module_reads_no_environment_variable() {
        let source = include_str!("password.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        for needle in [
            "std::env",
            "env::var",
            "var_os",
            "AXIOM_PASSWORD",
            "AXIOMVAULT_PASSWORD",
        ] {
            assert!(!production.contains(needle), "found {needle}");
        }
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
}
