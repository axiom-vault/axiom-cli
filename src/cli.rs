use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;

/// KDF strength level for key derivation.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum KdfStrength {
    /// Fast key derivation, lower security margin.
    Interactive,
    /// Balanced key derivation (default).
    Moderate,
    /// Slow key derivation, maximum security margin.
    Sensitive,
}

/// Conflict resolution strategy for sync operations.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ConflictStrategyArg {
    /// Keep both local and remote versions.
    KeepBoth,
    /// Prefer the local version.
    PreferLocal,
    /// Prefer the remote version.
    PreferRemote,
}

/// Sync mode for vault synchronisation.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum SyncModeArg {
    /// Sync only when explicitly triggered.
    Manual,
    /// Sync on file changes.
    OnDemand,
    /// Sync at a fixed interval.
    Periodic,
    /// Combine on-demand and periodic sync.
    Hybrid,
}

/// RAID mode for CLI configuration.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum RaidModeArg {
    /// Mirror (RAID 1): replicate to all backends.
    Mirror,
    /// Erasure coding (RAID 5/6): Reed-Solomon sharding.
    Erasure,
}

#[derive(Parser)]
#[command(name = "axiom")]
#[command(about = "AxiomVault - Encrypted vault management")]
#[command(version = option_env!("AXIOM_VERSION")
    .or(option_env!("AXIOMVAULT_VERSION"))
    .unwrap_or(env!("CARGO_PKG_VERSION")))]
pub(crate) struct Cli {
    /// Enable verbose logging.
    #[arg(short, long)]
    pub(crate) verbose: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Vault lifecycle and maintenance commands.
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    /// File and directory operations inside a vault.
    File {
        #[command(subcommand)]
        command: FileCommands,
    },
    /// Password management commands.
    Password {
        #[command(subcommand)]
        command: PasswordCommands,
    },
    /// Recovery key commands.
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommands,
    },
    /// Remote provider commands.
    Remote {
        #[command(subcommand)]
        command: RemoteCommands,
    },
    /// Vault synchronisation commands.
    Sync {
        #[command(subcommand)]
        command: SyncCommands,
    },
    /// RAID backend and redundancy commands.
    Raid {
        #[command(subcommand)]
        command: RaidCommands,
    },
    /// Mount the vault through supported access methods.
    Mount {
        #[command(subcommand)]
        command: MountCommands,
    },
    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
        /// Install completions to the standard location for the shell.
        #[arg(long)]
        install: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum VaultCommands {
    /// Create a new vault.
    Create {
        /// Vault name/identifier.
        #[arg(short, long)]
        name: String,
        /// Path to store the vault.
        #[arg(short, long)]
        path: PathBuf,
        /// KDF strength level.
        #[arg(short, long, value_enum, default_value_t = KdfStrength::Moderate)]
        strength: KdfStrength,
    },
    /// Open an existing vault and start interactive session.
    Open {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Show vault information.
    Info {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Check vault health and integrity.
    Check {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
        /// Run shallow check only (no password required).
        #[arg(long)]
        shallow: bool,
    },
    /// Migrate vault to the latest format version.
    Migrate {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
        /// Only show what migrations would run, without executing them.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum FileCommands {
    /// List contents of a vault directory.
    List {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Directory within vault (default: root).
        #[arg(short, long, default_value = "/")]
        dir: String,
    },
    /// Add a file to the vault.
    Add {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Source file to add.
        #[arg(short, long)]
        source: PathBuf,
        /// Destination path in vault.
        #[arg(short, long)]
        dest: String,
    },
    /// Extract a file from the vault.
    Extract {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Source path in vault.
        #[arg(short, long)]
        source: String,
        /// Destination file path.
        #[arg(short, long)]
        dest: PathBuf,
    },
    /// Create a directory in the vault.
    Mkdir {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Directory path to create.
        #[arg(short, long)]
        dir: String,
    },
    /// Remove a file from the vault.
    Remove {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Path to remove.
        #[arg(short = 'f', long)]
        file: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PasswordCommands {
    /// Change vault password.
    Change {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Reset vault password using recovery key words.
    Reset {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum RecoveryCommands {
    /// Show recovery key for a vault (requires password).
    ShowKey {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Migrate a legacy vault to support recovery keys.
    Enable {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum RemoteCommands {
    /// Google Drive remote commands.
    Gdrive {
        #[command(subcommand)]
        command: GdriveCommands,
    },
    /// iCloud remote support (coming soon).
    Icloud,
    /// Dropbox remote support (coming soon).
    Dropbox,
}

#[derive(Subcommand)]
pub(crate) enum GdriveCommands {
    /// Authenticate with Google Drive and get tokens.
    Auth {
        /// Optional custom client ID.
        #[arg(long)]
        client_id: Option<String>,
        /// Optional custom client secret.
        #[arg(long)]
        client_secret: Option<String>,
        /// Path to save tokens (JSON file).
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Create a vault on Google Drive.
    Create {
        /// Vault name/identifier.
        #[arg(short, long)]
        name: String,
        /// Google Drive folder ID where vault will be stored.
        #[arg(short, long)]
        folder_id: String,
        /// Path to tokens file.
        #[arg(short, long)]
        tokens: PathBuf,
        /// KDF strength level.
        #[arg(short, long, value_enum, default_value_t = KdfStrength::Moderate)]
        strength: KdfStrength,
    },
    /// Open a vault on Google Drive.
    Open {
        /// Google Drive folder ID where vault is stored.
        #[arg(short, long)]
        folder_id: String,
        /// Path to tokens file.
        #[arg(short, long)]
        tokens: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum SyncCommands {
    /// Sync vault with remote storage.
    Run {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Conflict resolution strategy.
        #[arg(short, long, value_enum, default_value_t = ConflictStrategyArg::KeepBoth)]
        strategy: ConflictStrategyArg,
    },
    /// Show sync status for the vault.
    Status {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
    },
    /// List sync conflicts.
    Conflicts {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
    },
    /// Resolve a sync conflict for a specific file.
    Resolve {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// File path in vault to resolve.
        #[arg(short, long)]
        file: String,
        /// Resolution strategy.
        #[arg(short, long, value_enum)]
        strategy: ConflictStrategyArg,
    },
    /// Configure sync mode for the vault.
    Configure {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Sync mode.
        #[arg(short, long, value_enum)]
        mode: SyncModeArg,
        /// Interval in seconds for periodic sync (required for periodic/hybrid modes).
        #[arg(short, long)]
        interval: Option<u64>,
    },
}

#[derive(Subcommand)]
pub(crate) enum RaidCommands {
    /// Add a storage backend to the RAID pool.
    AddBackend {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Provider type (local, gdrive, dropbox, onedrive, icloud).
        #[arg(short = 't', long)]
        provider: String,
        /// Provider configuration as a JSON string.
        #[arg(short, long)]
        config: String,
    },
    /// Remove a storage backend from the RAID pool.
    RemoveBackend {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Index of the backend to remove (shown in raid status).
        #[arg(short, long)]
        index: usize,
    },
    /// Show RAID status: mode, backends, health, and shard distribution.
    Status {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
    },
    /// Rebuild missing shards on a target backend.
    Rebuild {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// Target backend index to rebuild (defaults to first degraded backend).
        #[arg(short = 't', long)]
        target: Option<usize>,
    },
    /// Configure or change the RAID mode.
    Configure {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
        /// RAID mode.
        #[arg(long, value_enum)]
        mode: RaidModeArg,
        /// Number of data shards (required for erasure mode).
        #[arg(short = 'k', long)]
        data_shards: Option<usize>,
        /// Number of parity shards (required for erasure mode).
        #[arg(short = 'm', long)]
        parity_shards: Option<usize>,
    },
}

#[derive(Subcommand)]
pub(crate) enum MountCommands {
    /// Serve vault contents over WebDAV on the loopback interface.
    Webdav {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
        /// Port to listen on (default: 8080).
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    #[cfg(feature = "fuse")]
    /// Mount vault contents as a FUSE filesystem.
    Fuse {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
        /// Directory where the vault should be mounted.
        #[arg(value_name = "MOUNT_POINT")]
        mount_point: PathBuf,
        /// Allow users other than the owner to access the mount.
        #[arg(long)]
        allow_other: bool,
        /// Mount the vault read-only.
        #[arg(long)]
        read_only: bool,
        /// Disable kernel default permission checks.
        #[arg(long)]
        no_default_permissions: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_grouped_vault_create_command() {
        let cli = Cli::try_parse_from([
            "axiom", "vault", "create", "--name", "MyVault", "--path", "./vault",
        ])
        .expect("vault create should parse");

        match cli.command {
            Commands::Vault {
                command: VaultCommands::Create { name, path, .. },
            } => {
                assert_eq!(name, "MyVault");
                assert_eq!(path, PathBuf::from("./vault"));
            }
            _ => panic!("unexpected command tree"),
        }
    }

    #[test]
    fn parses_grouped_remote_gdrive_auth_command() {
        let cli = Cli::try_parse_from([
            "axiom",
            "remote",
            "gdrive",
            "auth",
            "--output",
            "tokens.json",
        ])
        .expect("remote gdrive auth should parse");

        match cli.command {
            Commands::Remote {
                command:
                    RemoteCommands::Gdrive {
                        command: GdriveCommands::Auth { output, .. },
                    },
            } => assert_eq!(output, PathBuf::from("tokens.json")),
            _ => panic!("unexpected command tree"),
        }
    }

    #[test]
    fn parses_grouped_mount_webdav_command() {
        let cli = Cli::try_parse_from([
            "axiom", "mount", "webdav", "--path", "./vault", "--port", "9090",
        ])
        .expect("mount webdav should parse");

        match cli.command {
            Commands::Mount {
                command: MountCommands::Webdav { path, port },
            } => {
                assert_eq!(path, PathBuf::from("./vault"));
                assert_eq!(port, 9090);
            }
            _ => panic!("unexpected command tree"),
        }
    }
}
