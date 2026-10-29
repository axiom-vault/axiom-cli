use crate::cli::KdfStrength;
use anyhow::{Context, Result};
use axiomvault_crypto::KdfParams;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

const MIN_PASSWORD_LENGTH: usize = 8;

/// Set once from the global `--password-file` flag.
static PASSWORD_FILE: OnceLock<PathBuf> = OnceLock::new();

/// Record the `--password-file` path for [`vault_password`].
pub(crate) fn set_password_file(path: PathBuf) {
    let _ = PASSWORD_FILE.set(path);
}

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
    let mut password = rpassword::prompt_password(prompt).context(
        "Failed to read password from the terminal. Run the command interactively; \
         --password-file covers only the password that opens an existing vault",
    )?;
    let bytes = Zeroizing::new(password.as_bytes().to_vec());
    password.zeroize();
    Ok(bytes)
}

/// The password that opens an existing vault: read from `--password-file`
/// when it was given, otherwise prompted. New passwords never come from here.
pub(crate) fn vault_password(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    match PASSWORD_FILE.get() {
        Some(path) => read_password_file(path),
        None => prompt_password(prompt),
    }
}

#[cfg(unix)]
fn read_password_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let not_regular =
        || anyhow::anyhow!("--password-file {} is not a regular file", path.display());
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read --password-file {}", path.display()))?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open --password-file {}", path.display()))?;
    // Check the opened file again, so a swap after the first check is caught.
    let metadata = file.metadata().context("Failed to read --password-file")?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    let capacity = usize::try_from(metadata.len())
        .unwrap_or(0)
        .saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.read_to_end(&mut bytes)
        .context("Failed to read --password-file")?;
    password_from_file_bytes(bytes, metadata.permissions().mode())
}

#[cfg(not(unix))]
fn read_password_file(_path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    anyhow::bail!(
        "--password-file is supported only on Unix, where its permissions can be checked. \
         Omit it and enter the password at the prompt."
    )
}

/// Validate a password file's mode and contents. Strips exactly one trailing
/// `\n` or `\r\n` and nothing else.
#[cfg(unix)]
fn password_from_file_bytes(
    mut bytes: Zeroizing<Vec<u8>>,
    mode: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "--password-file is accessible by group or others (mode {:03o}). \
             Run `chmod 600` on it and try again.",
            mode & 0o777
        );
    }
    let strip = if bytes.ends_with(b"\r\n") {
        2
    } else if bytes.ends_with(b"\n") {
        1
    } else {
        0
    };
    let len = bytes.len() - strip;
    bytes.truncate(len);
    if bytes.is_empty() {
        anyhow::bail!("--password-file is empty");
    }
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

/// Refuse a `--recovery-out` path that already exists, so this is known before
/// the vault is created rather than after.
pub(crate) fn check_recovery_out(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok() {
        anyhow::bail!(
            "--recovery-out {} already exists; it is never overwritten",
            path.display()
        );
    }
    // `write_recovery_words` would refuse later, after the vault exists.
    if cfg!(not(unix)) {
        anyhow::bail!(
            "--recovery-out is supported only on Unix, where owner-only permissions can be checked"
        );
    }
    Ok(())
}

/// Write recovery words, space-separated on one line, to a new file that only
/// the owner can read. Fails if the file already exists. The file is published
/// atomically, so a failed write leaves no partial file; a file created at the
/// path after the existence check would be replaced. The line is built in a
/// zeroizing buffer, so no unzeroized copy is made.
pub(crate) async fn write_recovery_words(path: &Path, words: &str) -> Result<()> {
    check_recovery_out(path)?;
    let mut line = Zeroizing::new(String::with_capacity(words.len() + 1));
    line.push_str(words);
    line.push('\n');
    crate::private_file::write_private_file(path, line.as_bytes())
        .await
        .with_context(|| format!("Failed to write --recovery-out {}", path.display()))
}

/// Display recovery words and prompt user to confirm they've saved them.
/// The prompt is skipped when stdin is not a terminal, where nobody could
/// answer it and it would only hang a script, CI job or service.
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

    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return;
    }

    print!("Press Enter after you have written down the recovery key...");
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

    #[cfg(unix)]
    fn from_file(bytes: &[u8], mode: u32) -> Result<Zeroizing<Vec<u8>>> {
        password_from_file_bytes(Zeroizing::new(bytes.to_vec()), mode)
    }

    #[cfg(unix)]
    #[test]
    fn password_file_0600_strips_one_trailing_newline() {
        assert_eq!(
            from_file(b"hunter22\n", 0o100600).unwrap().as_slice(),
            b"hunter22"
        );
        assert_eq!(
            from_file(b"hunter22\r\n", 0o600).unwrap().as_slice(),
            b"hunter22"
        );
        assert_eq!(
            from_file(b"hunter22\n\n", 0o600).unwrap().as_slice(),
            b"hunter22\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn password_file_without_trailing_newline_is_unchanged() {
        assert_eq!(
            from_file(b" hunter22 ", 0o400).unwrap().as_slice(),
            b" hunter22 "
        );
    }

    #[cfg(unix)]
    #[test]
    fn password_file_0644_is_refused() {
        let err = from_file(b"hunter22\n", 0o100644).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
        assert!(err.contains("644"), "{err}");
        assert!(!err.contains("hunter22"), "{err}");
        assert!(from_file(b"hunter22", 0o610).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn empty_password_file_is_refused() {
        for bytes in [&b""[..], b"\n", b"\r\n"] {
            let err = from_file(bytes, 0o600).unwrap_err().to_string();
            assert!(err.contains("empty"), "{err}");
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

    fn scratch_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("axiom-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_out_writes_words_to_a_new_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = scratch_path("recovery-new");
        check_recovery_out(&path).unwrap();
        write_recovery_words(&path, "abandon ability able")
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "abandon ability able\n"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn recovery_out_never_overwrites_an_existing_file() {
        let path = scratch_path("recovery-existing");
        std::fs::write(&path, "keep me").unwrap();
        let err = check_recovery_out(&path).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        assert!(write_recovery_words(&path, "abandon ability able")
            .await
            .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
        std::fs::remove_file(&path).unwrap();
    }
}
