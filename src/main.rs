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
mod security;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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

    dispatch::dispatch(cli).await
}
