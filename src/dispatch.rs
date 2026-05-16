use crate::cli::{
    Cli, Commands, DropboxCommands, FileCommands, GdriveCommands, HardwareKeyCommands,
    MountCommands, PasswordCommands, RaidCommands, RecoveryCommands, RemoteCommands, SyncCommands,
    VaultCommands,
};
use crate::{commands, completions};
use anyhow::{bail, Result};
use clap::CommandFactory;

pub(crate) async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Vault { command } => match command {
            VaultCommands::Create {
                name,
                path,
                strength,
            } => commands::vault::cmd_create(&name, &path, strength).await,
            VaultCommands::Open { path } => commands::vault::cmd_open(&path).await,
            VaultCommands::Info { path } => commands::vault::cmd_info(&path).await,
            VaultCommands::Check { path, shallow } => {
                commands::check::cmd_check(&path, shallow).await
            }
            VaultCommands::Migrate { path, dry_run } => {
                commands::migrate::cmd_migrate(&path, dry_run).await
            }
        },
        Commands::File { command } => match command {
            FileCommands::List { vault_path, dir } => {
                commands::vault::cmd_list(&vault_path, &dir).await
            }
            FileCommands::Add {
                vault_path,
                source,
                dest,
            } => commands::vault::cmd_add(&vault_path, &source, &dest).await,
            FileCommands::Extract {
                vault_path,
                source,
                dest,
            } => commands::vault::cmd_extract(&vault_path, &source, &dest).await,
            FileCommands::Mkdir { vault_path, dir } => {
                commands::vault::cmd_mkdir(&vault_path, &dir).await
            }
            FileCommands::Remove { vault_path, file } => {
                commands::vault::cmd_remove(&vault_path, &file).await
            }
        },
        Commands::Password { command } => match command {
            PasswordCommands::Change { path } => {
                commands::recovery::cmd_change_password(&path).await
            }
            PasswordCommands::Reset { path } => commands::recovery::cmd_reset_password(&path).await,
        },
        Commands::Recovery { command } => match command {
            RecoveryCommands::ShowKey { path } => {
                commands::recovery::cmd_show_recovery_key(&path).await
            }
            RecoveryCommands::Enable { path } => commands::recovery::cmd_migrate_vault(&path).await,
        },
        Commands::HardwareKey { command } => match command {
            HardwareKeyCommands::Enroll {
                path,
                label,
                key_id,
            } => {
                commands::hardware_key::cmd_enroll(&path, label.as_deref(), key_id.as_deref()).await
            }
            HardwareKeyCommands::Status { path } => commands::hardware_key::cmd_status(&path).await,
            HardwareKeyCommands::Remove { path } => commands::hardware_key::cmd_remove(&path).await,
            HardwareKeyCommands::Test { path } => commands::hardware_key::cmd_test(&path).await,
            HardwareKeyCommands::Open { path } => commands::hardware_key::cmd_open(&path).await,
        },
        Commands::Remote { command } => match command {
            RemoteCommands::Gdrive { command } => match command {
                GdriveCommands::Auth {
                    client_id,
                    client_secret,
                    output,
                } => commands::gdrive::cmd_gdrive_auth(client_id, client_secret, &output).await,
                GdriveCommands::Create {
                    name,
                    folder_id,
                    tokens,
                    strength,
                } => {
                    commands::gdrive::cmd_gdrive_create(&name, &folder_id, &tokens, strength).await
                }
                GdriveCommands::Open { folder_id, tokens } => {
                    commands::gdrive::cmd_gdrive_open(&folder_id, &tokens).await
                }
            },
            RemoteCommands::Dropbox { command } => match command {
                DropboxCommands::Auth {
                    app_key,
                    app_secret,
                    output,
                } => commands::dropbox::cmd_dropbox_auth(app_key, app_secret, &output).await,
                DropboxCommands::Create {
                    name,
                    root_path,
                    tokens,
                    strength,
                } => {
                    commands::dropbox::cmd_dropbox_create(&name, &root_path, &tokens, strength)
                        .await
                }
                DropboxCommands::Open { root_path, tokens } => {
                    commands::dropbox::cmd_dropbox_open(&root_path, &tokens).await
                }
            },
            RemoteCommands::Icloud => bail!("iCloud remote support is not implemented yet"),
        },
        Commands::Sync { command } => match command {
            SyncCommands::Run {
                vault_path,
                strategy,
            } => commands::sync::cmd_sync(&vault_path, strategy).await,
            SyncCommands::Status { vault_path } => {
                commands::sync::cmd_sync_status(&vault_path).await
            }
            SyncCommands::Conflicts { vault_path } => {
                commands::sync::cmd_sync_conflicts(&vault_path).await
            }
            SyncCommands::Resolve {
                vault_path,
                file,
                strategy,
            } => commands::sync::cmd_sync_resolve(&vault_path, &file, strategy).await,
            SyncCommands::Configure {
                vault_path,
                mode,
                interval,
            } => commands::sync::cmd_sync_configure(&vault_path, mode, interval).await,
        },
        Commands::Raid { command } => match command {
            RaidCommands::AddBackend {
                vault_path,
                provider,
                config,
            } => commands::raid::cmd_raid_add_backend(&vault_path, &provider, &config).await,
            RaidCommands::RemoveBackend { vault_path, index } => {
                commands::raid::cmd_raid_remove_backend(&vault_path, index).await
            }
            RaidCommands::Status { vault_path } => {
                commands::raid::cmd_raid_status(&vault_path).await
            }
            RaidCommands::Rebuild { vault_path, target } => {
                commands::raid::cmd_raid_rebuild(&vault_path, target).await
            }
            RaidCommands::Configure {
                vault_path,
                mode,
                data_shards,
                parity_shards,
            } => {
                commands::raid::cmd_raid_configure(&vault_path, mode, data_shards, parity_shards)
                    .await
            }
        },
        Commands::Mount { command } => match command {
            MountCommands::Webdav { path, port } => commands::webdav::cmd_webdav(&path, port).await,
            #[cfg(feature = "fuse")]
            MountCommands::Fuse {
                path,
                mount_point,
                allow_other,
                read_only,
                no_default_permissions,
            } => {
                commands::fuse::cmd_mount(
                    &path,
                    &mount_point,
                    allow_other,
                    read_only,
                    no_default_permissions,
                )
                .await
            }
        },
        Commands::Completions { shell, install } => {
            if install {
                completions::install_completions(shell)?;
            } else {
                clap_complete::generate(
                    shell,
                    &mut Cli::command(),
                    "axiom",
                    &mut std::io::stdout(),
                );
            }
            Ok(())
        }
    }
}
