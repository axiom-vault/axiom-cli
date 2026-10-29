//! Runs the built `axiom` binary for `vault list` and `mount list` with no
//! terminal and no `--password-file`: both must succeed without a password.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn axiom(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_axiom"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run axiom")
}

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
        "wrapped_master_key": vec![1u8; 60]
    })
    .to_string()
}

fn write(dir: &Path, contents: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("vault.config"), contents).unwrap();
}

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("axiom-list-it-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write(&root.join("main"), &config_json("8c1d6f0e-main"));
        write(&root.join("work/sub"), &config_json("work"));
        write(&root.join("broken"), "{\"id\": ");
        write(&root.join("evil"), &config_json("evil\u{1b}[31mred"));
        write(&root.join("a/b/c/deep"), &config_json("too-deep"));
        Self(fs::canonicalize(root).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn vault_list_json_without_password() {
    let fx = Fixture::new("json");
    let out = axiom(&["vault", "list", "--root", fx.0.to_str().unwrap(), "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.stdout.contains(&0x1b));

    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    let by_path = |p: &str| {
        let path = fx.0.join(p).display().to_string();
        rows.iter()
            .find(|r| r["path"] == path.as_str())
            .unwrap_or_else(|| panic!("no row for {p}"))
            .clone()
    };
    assert_eq!(rows.len(), 4, "{rows:#?}");
    assert_eq!(by_path("main")["id"], "8c1d6f0e-main");
    assert_eq!(by_path("main")["version"], "2.0");
    assert_eq!(by_path("main")["provider"], "local");
    assert_eq!(by_path("work/sub")["id"], "work");
    assert!(by_path("broken")["error"].is_string());
    assert!(by_path("broken")["id"].is_null());
    assert_eq!(by_path("evil")["id"], "evil\\u{1b}[31mred");
    assert!(rows.iter().all(|r| r["id_verified"] == false));
    assert!(rows
        .iter()
        .all(|r| r["path"] != fx.0.join("a/b/c/deep").display().to_string().as_str()));
}

#[test]
fn vault_list_table_escapes_and_reports_errors() {
    let fx = Fixture::new("table");
    let out = axiom(&["vault", "list", "--root", fx.0.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("PATH\tID_UNVERIFIED\tVERSION\tPROVIDER\tSTATUS\n"));
    assert!(!stdout.contains('\u{1b}'));
    assert!(stdout.contains("evil\\u{1b}[31mred"));
    assert!(stdout.contains(&format!(
        "{}\t-\t-\t-\terror: ",
        fx.0.join("broken").display()
    )));
    assert!(!stdout.contains("too-deep"));
}

#[test]
fn vault_list_requires_root() {
    let out = axiom(&["vault", "list"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--root <DIR>"));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn mount_list_json_parses() {
    let out = axiom(&["mount", "list", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    for r in rows {
        let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 5);
        for k in ["kind", "pid", "vault_path", "address", "state"] {
            assert!(r.get(k).is_some(), "missing {k}");
        }
    }
}
