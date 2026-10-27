use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::ffi::OsString;
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
#[command(
    version = option_env!("AXIOM_VERSION")
        .or(option_env!("AXIOMVAULT_VERSION"))
        .unwrap_or(env!("CARGO_PKG_VERSION"))
)]
pub(crate) struct Cli {
    /// Enable verbose logging.
    #[arg(short, long)]
    pub(crate) verbose: bool,
    /// Read the password that opens an existing vault from PATH instead of
    /// prompting. PATH must be a regular file with no group or other
    /// permissions (`chmod 600`); one trailing newline is stripped. Unix only.
    /// New passwords (vault create, password change and reset) are always prompted.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) password_file: Option<PathBuf>,
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
    /// Hardware-key commands backed by YubiKey challenge-response bytes.
    HardwareKey {
        #[command(subcommand)]
        command: HardwareKeyCommands,
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
    /// Run the key-holding agent for MCP/LLM access (serve, unlock, lock, status).
    ///
    /// Everything after `agent` is passed to the agent unchanged; see
    /// `axiom agent --help`.
    #[command(disable_help_flag = true)]
    Agent {
        /// Agent command and its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
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
        /// Write the recovery key to this new file (mode 0600) instead of
        /// printing it. An existing file is never overwritten.
        #[arg(long, value_name = "FILE")]
        recovery_out: Option<PathBuf>,
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
    /// Find vaults under a directory and show their unverified plaintext
    /// header (id, version, provider). No password is needed: the values are
    /// not authenticated and a crafted vault.config can show anything.
    List {
        /// Directory to search (repeatable).
        #[arg(long, value_name = "DIR", required = true)]
        root: Vec<PathBuf>,
        /// Maximum directory depth below each root (the root is depth 0).
        #[arg(long, default_value_t = 3)]
        depth: usize,
        /// Print JSON instead of a tab-separated table.
        #[arg(long)]
        json: bool,
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
}

#[derive(Subcommand)]
pub(crate) enum HardwareKeyCommands {
    /// Enroll a YubiKey challenge-response for a local vault (prompted, hex:..., at least 16 bytes).
    Enroll {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
        /// Optional human-readable label for the enrolled device.
        #[arg(long)]
        label: Option<String>,
        /// Optional device identifier or slot hint.
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Show whether a local vault has a hardware key enrolled.
    Status {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Remove the enrolled hardware key from a local vault.
    Remove {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Verify a prompted hardware-key response (hex:..., at least 16 bytes) against a local vault.
    Test {
        /// Path to the vault.
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Open a local vault with a prompted hardware-key response (hex:..., at least 16 bytes) instead of a password.
    Open {
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
        /// Path to save tokens (JSON file) (default: `<config dir>/axiomvault/gdrive-tokens.json`).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Create a vault on Google Drive.
    Create {
        /// Vault name/identifier.
        #[arg(short, long)]
        name: String,
        /// Google Drive folder ID where vault will be stored.
        #[arg(short, long)]
        folder_id: String,
        /// Path to tokens file (default: `<config dir>/axiomvault/gdrive-tokens.json`).
        #[arg(short, long)]
        tokens: Option<PathBuf>,
        /// KDF strength level.
        #[arg(short, long, value_enum, default_value_t = KdfStrength::Moderate)]
        strength: KdfStrength,
    },
    /// Open a vault on Google Drive.
    Open {
        /// Google Drive folder ID where vault is stored.
        #[arg(short, long)]
        folder_id: String,
        /// Path to tokens file (default: `<config dir>/axiomvault/gdrive-tokens.json`).
        #[arg(short, long)]
        tokens: Option<PathBuf>,
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
    /// List the current user's running WebDAV servers and FUSE mounts (Linux, macOS).
    List {
        /// Print JSON instead of a tab-separated table.
        #[arg(long)]
        json: bool,
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
            } => assert_eq!(output, Some(PathBuf::from("tokens.json"))),
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

    #[test]
    fn parses_grouped_hardware_key_enroll_command() {
        let cli = Cli::try_parse_from([
            "axiom",
            "hardware-key",
            "enroll",
            "--path",
            "./vault",
            "--label",
            "desk-key",
            "--key-id",
            "slot-2",
        ])
        .expect("hardware-key enroll should parse");

        match cli.command {
            Commands::HardwareKey {
                command:
                    HardwareKeyCommands::Enroll {
                        path,
                        label,
                        key_id,
                    },
            } => {
                assert_eq!(path, PathBuf::from("./vault"));
                assert_eq!(label.as_deref(), Some("desk-key"));
                assert_eq!(key_id.as_deref(), Some("slot-2"));
            }
            _ => panic!("unexpected command tree"),
        }
    }

    #[test]
    fn parses_grouped_hardware_key_open_command() {
        let cli = Cli::try_parse_from(["axiom", "hardware-key", "open", "--path", "./vault"])
            .expect("hardware-key open should parse");

        match cli.command {
            Commands::HardwareKey {
                command: HardwareKeyCommands::Open { path },
            } => assert_eq!(path, PathBuf::from("./vault")),
            _ => panic!("unexpected command tree"),
        }
    }

    #[test]
    fn vault_list_requires_root() {
        let err = Cli::try_parse_from(["axiom", "vault", "list"])
            .err()
            .expect("vault list without --root must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--root <DIR>"));
    }

    #[test]
    fn parses_vault_list_and_mount_list() {
        let cli = Cli::try_parse_from([
            "axiom", "vault", "list", "--root", "/a", "--root", "/b", "--json",
        ])
        .expect("vault list should parse");
        match cli.command {
            Commands::Vault {
                command: VaultCommands::List { root, depth, json },
            } => {
                assert_eq!(root, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
                assert_eq!(depth, 3);
                assert!(json);
            }
            _ => panic!("unexpected command tree"),
        }

        let cli = Cli::try_parse_from(["axiom", "mount", "list"]).expect("mount list should parse");
        assert!(matches!(
            cli.command,
            Commands::Mount {
                command: MountCommands::List { json: false }
            }
        ));
    }

    fn agent_args(argv: &[&str]) -> Vec<OsString> {
        match Cli::try_parse_from(argv)
            .expect("agent command should parse")
            .command
        {
            Commands::Agent { args } => args,
            _ => panic!("unexpected command tree"),
        }
    }

    #[test]
    fn agent_passes_arguments_through_verbatim() {
        assert_eq!(
            agent_args(&["axiom", "agent", "unlock", "--expect-uid", "1000"]),
            ["unlock", "--expect-uid", "1000"]
        );
        assert_eq!(
            agent_args(&["axiom", "agent", "serve", "--vault", "/v", "--allow-writes"]),
            ["serve", "--vault", "/v", "--allow-writes"]
        );
        assert!(agent_args(&["axiom", "agent"]).is_empty());
    }

    #[test]
    fn agent_help_reaches_the_agent() {
        assert_eq!(agent_args(&["axiom", "agent", "--help"]), ["--help"]);
        assert_eq!(agent_args(&["axiom", "agent", "-h"]), ["-h"]);
        assert_eq!(
            agent_args(&["axiom", "agent", "unlock", "--help"]),
            ["unlock", "--help"]
        );
    }
}
