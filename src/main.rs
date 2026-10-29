//! AxiomVault CLI - Command line interface for vault operations.
//!
//! This tool provides a command-line interface for creating, managing,
//! and operating on encrypted vaults.

mod cli;
mod commands;
mod completions;
mod conversions;
mod dispatch;
mod password;
mod private_file;

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use cli::{Cli, Commands};
use std::ffi::OsString;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn main() -> Result<()> {
    let cli = Cli::parse();
    // `axiom agent` builds its own Tokio runtime and tracing subscriber, so it
    // must run before either exists here.
    if matches!(cli.command, Commands::Agent { .. }) {
        return run_agent(agent_args(cli)?);
    }

    if let Some(path) = &cli.password_file {
        password::set_password_file(path.clone());
    }

    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(dispatch::dispatch(cli))
        .map_err(legacy_config_guidance)
}

/// Replace core's refusal of a vault config that embeds OAuth tokens with
/// what the user has to do about it (axiom-cli#22).
fn legacy_config_guidance(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<axiomvault_common::Error>() {
        Some(axiomvault_common::Error::LegacyConfigCredentials(detail)) => anyhow!(
            "this vault's config still embeds OAuth tokens from an older format, which axiom 2.0 refuses.\n\
             \n\
             Those tokens were stored in the vault config on the storage backend, so revoke or rotate\n\
             them at the provider (Google Drive or Dropbox), then authenticate again with\n\
             `axiom remote gdrive auth` or `axiom remote dropbox auth`.\n\
             \n\
             This version of axiom cannot open, upgrade or migrate this vault. Create a new one with\n\
             `axiom remote gdrive create` or `axiom remote dropbox create` and add your files to it\n\
             from a copy you still have.\n\
             \n\
             Details: {detail}"
        ),
        _ => error,
    }
}

/// The arguments after `axiom agent`. Refuses `--password-file`: the agent
/// takes the vault password only from the terminal.
fn agent_args(cli: Cli) -> Result<Vec<OsString>> {
    if cli.password_file.is_some() {
        bail!("`axiom agent` reads the password only from the terminal; --password-file is not accepted");
    }
    match cli.command {
        Commands::Agent { args } => Ok(args),
        _ => bail!("internal error: not an `axiom agent` command"),
    }
}

#[cfg(unix)]
fn run_agent(args: Vec<OsString>) -> Result<()> {
    axiomvault_agent::cli::run("axiom agent", args)
}

#[cfg(not(unix))]
fn run_agent(_args: Vec<OsString>) -> Result<()> {
    bail!("`axiom agent` is supported only on Unix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn agent_rejects_password_file() {
        let cli = Cli::try_parse_from(["axiom", "--password-file", "f", "agent", "unlock"])
            .expect("should parse");
        let err = agent_args(cli).unwrap_err();
        assert!(err.to_string().contains("--password-file"), "{err}");

        let cli = Cli::try_parse_from(["axiom", "agent", "unlock"]).expect("should parse");
        assert_eq!(agent_args(cli).unwrap(), ["unlock"]);
    }

    #[test]
    fn legacy_config_credentials_give_rotation_guidance() {
        // Shaped like the open paths: core's error under the command's context.
        let refused = Err::<(), _>(axiomvault_common::Error::LegacyConfigCredentials(
            "vault.config embeds OAuth credentials".to_string(),
        ))
        .context("Failed to open vault");
        let err = legacy_config_guidance(refused.unwrap_err());
        let message = err.to_string();
        for expected in [
            "embeds OAuth tokens from an older format",
            "revoke or rotate",
            "`axiom remote gdrive auth`",
            "`axiom remote dropbox auth`",
            "cannot open, upgrade or migrate",
            "Details: vault.config embeds OAuth credentials",
        ] {
            assert!(message.contains(expected), "{message}");
        }

        let other = legacy_config_guidance(anyhow!("Failed to open vault"));
        assert_eq!(other.to_string(), "Failed to open vault");
    }
}
