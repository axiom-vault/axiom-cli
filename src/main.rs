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

use anyhow::{bail, Result};
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

    #[test]
    fn agent_rejects_password_file() {
        let cli = Cli::try_parse_from(["axiom", "--password-file", "f", "agent", "unlock"])
            .expect("should parse");
        let err = agent_args(cli).unwrap_err();
        assert!(err.to_string().contains("--password-file"), "{err}");

        let cli = Cli::try_parse_from(["axiom", "agent", "unlock"]).expect("should parse");
        assert_eq!(agent_args(cli).unwrap(), ["unlock"]);
    }
}
