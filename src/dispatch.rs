use anyhow::Result;
use clap::CommandFactory;

use crate::cli::{Cli, Commands};
use crate::{commands, completions};

pub(crate) async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Create {
            name,
            path,
            strength,
        } => commands::vault::cmd_create(&name, &path, strength).await,
        Commands::Open { path } => commands::vault::cmd_open(&path).await,
        Commands::List { vault_path, dir } => commands::vault::cmd_list(&vault_path, &dir).await,
        Commands::Add {
            vault_path,
            source,
            dest,
        } => commands::vault::cmd_add(&vault_path, &source, &dest).await,
        Commands::Extract {
            vault_path,
            source,
            dest,
        } => commands::vault::cmd_extract(&vault_path, &source, &dest).await,
        Commands::Mkdir { vault_path, dir } => commands::vault::cmd_mkdir(&vault_path, &dir).await,
        Commands::Remove { vault_path, file } => {
            commands::vault::cmd_remove(&vault_path, &file).await
        }
        Commands::Info { path } => commands::vault::cmd_info(&path).await,
        Commands::ChangePassword { path } => commands::recovery::cmd_change_password(&path).await,
        Commands::ShowRecoveryKey { path } => {
            commands::recovery::cmd_show_recovery_key(&path).await
        }
        Commands::ResetPassword { path } => commands::recovery::cmd_reset_password(&path).await,
        Commands::MigrateVault { path } => commands::recovery::cmd_migrate_vault(&path).await,
        Commands::Check { path, shallow } => commands::check::cmd_check(&path, shallow).await,
        Commands::GdriveAuth {
            client_id,
            client_secret,
            output,
        } => commands::gdrive::cmd_gdrive_auth(client_id, client_secret, &output).await,
        Commands::GdriveCreate {
            name,
            folder_id,
            tokens,
            strength,
        } => commands::gdrive::cmd_gdrive_create(&name, &folder_id, &tokens, strength).await,
        Commands::GdriveOpen { folder_id, tokens } => {
            commands::gdrive::cmd_gdrive_open(&folder_id, &tokens).await
        }
        Commands::Sync {
            vault_path,
            strategy,
        } => commands::sync::cmd_sync(&vault_path, strategy).await,
        Commands::SyncStatus { vault_path } => commands::sync::cmd_sync_status(&vault_path).await,
        Commands::SyncConflicts { vault_path } => {
            commands::sync::cmd_sync_conflicts(&vault_path).await
        }
        Commands::SyncResolve {
            vault_path,
            file,
            strategy,
        } => commands::sync::cmd_sync_resolve(&vault_path, &file, strategy).await,
        Commands::SyncConfigure {
            vault_path,
            mode,
            interval,
        } => commands::sync::cmd_sync_configure(&vault_path, mode, interval).await,
        Commands::Migrate { path, dry_run } => commands::migrate::cmd_migrate(&path, dry_run).await,
        Commands::Completions { shell, install } => {
            if install {
                completions::install_completions(shell)?;
            } else {
                clap_complete::generate(
                    shell,
                    &mut Cli::command(),
                    "axiomvault",
                    &mut std::io::stdout(),
                );
            }
            Ok(())
        }
        Commands::RaidAddBackend {
            vault_path,
            provider,
            config,
        } => commands::raid::cmd_raid_add_backend(&vault_path, &provider, &config).await,
        Commands::RaidRemoveBackend { vault_path, index } => {
            commands::raid::cmd_raid_remove_backend(&vault_path, index).await
        }
        Commands::RaidStatus { vault_path } => commands::raid::cmd_raid_status(&vault_path).await,
        Commands::RaidRebuild { vault_path, target } => {
            commands::raid::cmd_raid_rebuild(&vault_path, target).await
        }
        Commands::RaidConfigure {
            vault_path,
            mode,
            data_shards,
            parity_shards,
        } => {
            commands::raid::cmd_raid_configure(&vault_path, mode, data_shards, parity_shards).await
        }
        Commands::Webdav { path, port } => commands::webdav::cmd_webdav(&path, port).await,
        #[cfg(feature = "fuse")]
        Commands::Mount {
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
    }
}
