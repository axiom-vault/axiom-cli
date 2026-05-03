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
#[command(name = "axiomvault")]
#[command(about = "AxiomVault - Encrypted vault management")]
#[command(version = env!("AXIOMVAULT_VERSION"))]
pub(crate) struct Cli {
    /// Enable verbose logging.
    #[arg(short, long)]
    pub(crate) verbose: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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

    /// Show vault information.
    Info {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },

    /// Change vault password.
    ChangePassword {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },

    /// Show recovery key for a vault (requires password).
    ShowRecoveryKey {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },

    /// Reset vault password using recovery key words.
    ResetPassword {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },

    /// Migrate a legacy vault to support recovery keys.
    MigrateVault {
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

    /// Authenticate with Google Drive and get tokens.
    GdriveAuth {
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
    GdriveCreate {
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
    GdriveOpen {
        /// Google Drive folder ID where vault is stored.
        #[arg(short, long)]
        folder_id: String,

        /// Path to tokens file.
        #[arg(short, long)]
        tokens: PathBuf,
    },

    /// Sync vault with remote storage.
    Sync {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,

        /// Conflict resolution strategy.
        #[arg(short, long, value_enum, default_value_t = ConflictStrategyArg::KeepBoth)]
        strategy: ConflictStrategyArg,
    },

    /// Show sync status for the vault.
    SyncStatus {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
    },

    /// List sync conflicts.
    SyncConflicts {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
    },

    /// Resolve a sync conflict for a specific file.
    SyncResolve {
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
    SyncConfigure {
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

    /// Migrate vault to the latest format version.
    Migrate {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,

        /// Only show what migrations would run, without executing them.
        #[arg(long)]
        dry_run: bool,
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

    /// Add a storage backend to the RAID pool.
    RaidAddBackend {
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
    RaidRemoveBackend {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,

        /// Index of the backend to remove (shown in raid-status).
        #[arg(short, long)]
        index: usize,
    },

    /// Show RAID status: mode, backends, health, and shard distribution.
    RaidStatus {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,
    },

    /// Rebuild missing shards on a target backend.
    RaidRebuild {
        /// Path to the vault.
        #[arg(short = 'p', long)]
        vault_path: PathBuf,

        /// Target backend index to rebuild (defaults to first degraded backend).
        #[arg(short = 't', long)]
        target: Option<usize>,
    },

    /// Serve vault contents over WebDAV on the loopback interface.
    Webdav {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,

        /// Port to listen on (default: 8080).
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },

    /// Configure or change the RAID mode.
    RaidConfigure {
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
