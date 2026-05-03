use crate::cli::Cli;
use anyhow::{Context, Result};
use clap::CommandFactory;
use clap_complete::Shell;
use std::path::PathBuf;

pub(crate) fn install_completions(shell: Shell) -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let (dir, filename) = match shell {
        Shell::Zsh => {
            let dir = PathBuf::from(&home).join(".zsh/completions");
            (dir, "_axiomvault".to_string())
        }
        Shell::Bash => {
            let dir = PathBuf::from(&home).join(".local/share/bash-completion/completions");
            (dir, "axiomvault".to_string())
        }
        Shell::Fish => {
            let dir = PathBuf::from(&home).join(".config/fish/completions");
            (dir, "axiomvault.fish".to_string())
        }
        _ => {
            anyhow::bail!(
                "Automatic installation not supported for {:?}. Use `axiomvault completions {:?}` and redirect to a file.",
                shell,
                shell,
            );
        }
    };

    std::fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;

    let dest = dir.join(&filename);
    let mut file = std::fs::File::create(&dest)
        .with_context(|| format!("Failed to create {}", dest.display()))?;
    clap_complete::generate(shell, &mut Cli::command(), "axiomvault", &mut file);

    println!("Completions installed to {}", dest.display());

    if shell == Shell::Zsh {
        println!();
        println!("Add the following to your ~/.zshrc if not already present:");
        println!();
        println!("  fpath=(~/.zsh/completions $fpath)");
        println!("  autoload -Uz compinit && compinit");
        println!();
        println!("Then restart your shell or run: exec zsh");
    }

    Ok(())
}
