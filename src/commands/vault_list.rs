//! `axiom vault list`: find vaults under the given roots and print the
//! plaintext header of each `vault.config`. Never asks for a password and
//! never opens a vault.

use anyhow::{Context, Result};
use axiomvault_vault::VaultVersion;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "vault.config";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// The only fields read from `vault.config`. None of them is authenticated
/// without the password: `config_mac` is keyed from the master key.
#[derive(Deserialize)]
struct Header {
    id: String,
    version: VaultVersion,
    provider_type: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct VaultRow {
    path: String,
    id: Option<String>,
    id_verified: bool,
    version: Option<String>,
    provider: Option<String>,
    error: Option<String>,
}

/// Escape characters that a terminal would interpret: control characters
/// (ANSI escapes, tabs, newlines) and bidirectional overrides.
pub(crate) fn escape_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control()
            || matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn cmd_vault_list(roots: &[PathBuf], depth: usize, json: bool) -> Result<()> {
    let mut rows = Vec::new();
    for root in roots {
        let root = fs::canonicalize(root).with_context(|| {
            format!(
                "Cannot read root {}",
                escape_display(&root.display().to_string())
            )
        })?;
        let mut dirs = Vec::new();
        scan_root(&root, depth, &mut dirs);
        rows.extend(dirs.iter().map(|dir| read_row(dir)));
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        print!("{}", format_table(&rows));
    }
    if rows.is_empty() {
        eprintln!("No vaults found.");
    }
    Ok(())
}

/// Collect every directory under `root`, at most `max_depth` levels deep
/// (the root is depth 0), that contains a `vault.config`. Symlinks are not
/// followed, other filesystems are not entered, and a vault is not descended into.
pub(crate) fn scan_root(root: &Path, max_depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        return;
    };
    walk(root, &root_meta, 0, max_depth, out);
}

fn walk(
    dir: &Path,
    root_meta: &fs::Metadata,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<PathBuf>,
) {
    if fs::symlink_metadata(dir.join(CONFIG_FILE)).is_ok() {
        out.push(dir.to_path_buf());
        return;
    }
    if depth >= max_depth {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            fs::symlink_metadata(e.path())
                .map(|m| m.is_dir() && same_filesystem(&m, root_meta))
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();
    children.sort();
    for child in children {
        walk(&child, root_meta, depth + 1, max_depth, out);
    }
}

#[cfg(unix)]
fn same_filesystem(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev()
}

#[cfg(not(unix))]
fn same_filesystem(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    true
}

pub(crate) fn read_row(dir: &Path) -> VaultRow {
    let path = escape_display(&dir.display().to_string());
    match read_header(&dir.join(CONFIG_FILE)) {
        Ok(h) => VaultRow {
            path,
            id: Some(escape_display(&h.id)),
            id_verified: false,
            version: Some(h.version.to_string()),
            provider: Some(escape_display(&h.provider_type)),
            error: None,
        },
        Err(e) => VaultRow {
            path,
            id: None,
            id_verified: false,
            version: None,
            provider: None,
            error: Some(escape_display(&format!("{e:#}"))),
        },
    }
}

fn read_header(file: &Path) -> Result<Header> {
    if !fs::symlink_metadata(file)?.is_file() {
        anyhow::bail!("{CONFIG_FILE} is not a regular file");
    }
    let mut bytes = Vec::new();
    fs::File::open(file)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        anyhow::bail!("{CONFIG_FILE} is larger than 64 KiB");
    }
    serde_json::from_slice(&bytes).context("invalid vault.config")
}

fn format_table(rows: &[VaultRow]) -> String {
    let dash = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".to_string());
    let mut out = String::from("PATH\tID_UNVERIFIED\tVERSION\tPROVIDER\tSTATUS\n");
    for r in rows {
        let status = r
            .error
            .as_ref()
            .map_or("ok".to_string(), |e| format!("error: {e}"));
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            r.path,
            dash(&r.id),
            dash(&r.version),
            dash(&r.provider),
            status
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("axiom-vault-list-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(fs::canonicalize(&dir).unwrap())
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The JSON shape `VaultConfig::to_bytes` writes for a 2.0 vault.
    fn config_json(id: &str) -> String {
        serde_json::json!({
            "id": id,
            "version": {"major": 2, "minor": 0},
            "salt": vec![7u8; 32],
            "kdf_params": {"memory_cost": 65536, "time_cost": 3, "parallelism": 4},
            "provider_type": "local",
            "provider_config": {"root": "./v"},
            "created_at": "2026-10-01T12:00:00Z",
            "modified_at": "2026-10-01T12:00:00Z",
            "key_verification": vec![9u8; 40],
            "wrapped_master_key": vec![1u8; 60],
            "config_mac": vec![2u8; 32]
        })
        .to_string()
    }

    fn make_vault(dir: &Path, contents: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(CONFIG_FILE), contents).unwrap();
    }

    fn scan(root: &Path, depth: usize) -> Vec<PathBuf> {
        let mut out = Vec::new();
        scan_root(root, depth, &mut out);
        out
    }

    #[test]
    fn reads_header_and_marks_id_unverified() {
        let t = TempDir::new("header");
        make_vault(&t.0.join("a"), &config_json("3f2c9a1e-main"));
        let row = read_row(&t.0.join("a"));
        assert_eq!(row.id.as_deref(), Some("3f2c9a1e-main"));
        assert_eq!(row.version.as_deref(), Some("2.0"));
        assert_eq!(row.provider.as_deref(), Some("local"));
        assert!(!row.id_verified);
        assert!(row.error.is_none());
    }

    #[test]
    fn invalid_json_becomes_error_row() {
        let t = TempDir::new("badjson");
        make_vault(&t.0.join("bad"), "{not json");
        let row = read_row(&t.0.join("bad"));
        assert!(row
            .error
            .as_deref()
            .unwrap()
            .contains("invalid vault.config"));
        assert!(row.id.is_none());
        assert!(format_table(&[row]).contains("\terror: invalid vault.config"));
    }

    #[test]
    fn ansi_escape_in_id_is_escaped() {
        let t = TempDir::new("ansi");
        make_vault(&t.0.join("evil"), &config_json("x\u{1b}[31mred\tz"));
        let row = read_row(&t.0.join("evil"));
        let table = format_table(&[row]);
        assert!(!table.contains('\u{1b}'));
        assert!(table.contains("x\\u{1b}[31mred\\u{9}z"));
    }

    #[test]
    fn escape_display_handles_bidi_and_newlines() {
        assert_eq!(escape_display("a\u{202E}b\nc"), "a\\u{202e}b\\u{a}c");
        assert_eq!(escape_display("plain ü"), "plain ü");
    }

    #[test]
    fn oversized_config_is_rejected() {
        let t = TempDir::new("big");
        make_vault(&t.0.join("big"), &" ".repeat(MAX_CONFIG_BYTES as usize + 1));
        let row = read_row(&t.0.join("big"));
        assert!(row.error.unwrap().contains("larger than 64 KiB"));
    }

    #[test]
    fn respects_depth_and_does_not_descend_into_vaults() {
        let t = TempDir::new("depth");
        make_vault(&t.0.join("one"), &config_json("one"));
        make_vault(&t.0.join("one/nested"), &config_json("nested"));
        make_vault(&t.0.join("a/b/three"), &config_json("three"));
        make_vault(&t.0.join("a/b/c/four"), &config_json("four"));

        assert_eq!(scan(&t.0, 3), vec![t.0.join("a/b/three"), t.0.join("one")]);
        assert_eq!(
            scan(&t.0, 4),
            vec![
                t.0.join("a/b/c/four"),
                t.0.join("a/b/three"),
                t.0.join("one")
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symlinks() {
        let t = TempDir::new("symlink");
        let outside = TempDir::new("symlink-target");
        make_vault(&outside.0.join("v"), &config_json("outside"));
        std::os::unix::fs::symlink(&outside.0, t.0.join("link")).unwrap();
        assert!(scan(&t.0, 4).is_empty());
    }

    /// Source-level check: the listing code must not touch password input.
    #[test]
    fn list_code_requires_no_password() {
        let source = include_str!("vault_list.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        for needle in [
            "vault_password",
            "prompt_password",
            "password_file",
            "open_vault",
        ] {
            assert!(!production.contains(needle), "found {needle}");
        }
    }
}
