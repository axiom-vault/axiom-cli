//! Integration tests for `axiom file add` covering single files, recursive
//! directory trees, empty directories, conflicts, type collisions, and
//! symlink refusal. Every test uses a synthetic throwaway vault created
//! through the core API so the non-interactive CLI binary can be exercised.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use axiomvault_common::{VaultId, VaultPath};
use axiomvault_crypto::KdfParams;
use axiomvault_vault::{VaultManager, VaultOperations};

fn axiom(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_axiom"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run axiom")
}

fn run(args: &[&str]) -> Output {
    let out = axiom(args);
    assert!(
        out.status.success(),
        "axiom {:?} failed\nstdout: {}\nstderr: {}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn run_fail(args: &[&str]) -> Output {
    let out = axiom(args);
    assert!(
        !out.status.success(),
        "axiom {:?} was expected to fail but succeeded\nstdout: {}",
        args,
        String::from_utf8_lossy(&out.stdout)
    );
    out
}

struct VaultFixture {
    root: PathBuf,
    password_file: PathBuf,
}

impl VaultFixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("axiom-file-add-it-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let password = b"synthetic-password";
        let password_file = root.join("password.txt");
        fs::write(&password_file, b"synthetic-password\n").unwrap();
        let mut perms = fs::metadata(&password_file).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&password_file, perms).unwrap();

        let vault_path = root.join("vault");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let manager = VaultManager::new();
            let provider_config =
                serde_json::json!({"root": vault_path.to_string_lossy().to_string()});
            manager
                .create_vault(
                    VaultId::unique("TestVault").unwrap(),
                    password.as_slice(),
                    "local",
                    provider_config,
                    KdfParams::interactive(),
                )
                .await
                .expect("create synthetic vault");
        });

        Self {
            root,
            password_file,
        }
    }

    fn vault_path(&self) -> PathBuf {
        self.root.join("vault")
    }

    fn list_raw(&self, dir: &str) -> String {
        let out = run(&[
            "--password-file",
            self.password_file.to_str().unwrap(),
            "file",
            "list",
            "--vault-path",
            self.vault_path().to_str().unwrap(),
            "--dir",
            dir,
        ]);
        String::from_utf8(out.stdout).unwrap()
    }

    fn list(&self, dir: &str) -> Vec<(String, bool, u64)> {
        let stdout = self.list_raw(dir);
        stdout
            .lines()
            .skip(1) // "Contents of ..."
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let line = line.trim();
                if line.starts_with("[DIR]") {
                    let name = line
                        .strip_prefix("[DIR]")
                        .unwrap()
                        .trim()
                        .trim_end_matches('/')
                        .to_string();
                    (name, true, 0)
                } else {
                    let rest = line.strip_prefix("[FILE]").unwrap().trim();
                    let (name, size_part) = rest.rsplit_once(" (").unwrap();
                    let size = size_part
                        .trim_end_matches(')')
                        .trim_end_matches(" bytes")
                        .parse()
                        .unwrap();
                    (name.trim().to_string(), false, size)
                }
            })
            .collect()
    }

    fn add(&self, source: &Path, dest: &str) -> Output {
        run(&[
            "--password-file",
            self.password_file.to_str().unwrap(),
            "file",
            "add",
            "--vault-path",
            self.vault_path().to_str().unwrap(),
            "--source",
            source.to_str().unwrap(),
            "--dest",
            dest,
        ])
    }

    fn add_fail(&self, source: &Path, dest: &str) -> Output {
        run_fail(&[
            "--password-file",
            self.password_file.to_str().unwrap(),
            "file",
            "add",
            "--vault-path",
            self.vault_path().to_str().unwrap(),
            "--source",
            source.to_str().unwrap(),
            "--dest",
            dest,
        ])
    }

    fn extract(&self, source: &str, dest: &Path) {
        run(&[
            "--password-file",
            self.password_file.to_str().unwrap(),
            "file",
            "extract",
            "--vault-path",
            self.vault_path().to_str().unwrap(),
            "--source",
            source,
            "--dest",
            dest.to_str().unwrap(),
        ]);
    }
}

impl Drop for VaultFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn add_single_file_to_vault() {
    let fx = VaultFixture::new("single");
    let source = fx.root.join("secret.pdf");
    fs::write(&source, b"hello vault").unwrap();

    let out = fx.add(&source, "/secret.pdf");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("File added successfully"));
    assert!(stdout.contains("11 bytes"));

    let contents = fx.list("/");
    assert_eq!(contents, vec![("secret.pdf".to_string(), false, 11)]);

    let extracted = fx.root.join("extracted.pdf");
    fx.extract("/secret.pdf", &extracted);
    assert_eq!(fs::read(&extracted).unwrap(), b"hello vault");
}

#[test]
fn add_directory_tree_recursively() {
    let fx = VaultFixture::new("recursive");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(source.join("work")).unwrap();
    fs::create_dir_all(source.join("personal/trips")).unwrap();
    fs::write(source.join("readme.txt"), b"top").unwrap();
    fs::write(source.join("work/report.txt"), b"report").unwrap();
    fs::write(source.join("personal/trips/photo.jpg"), b"photo").unwrap();

    let out = fx.add(&source, "/Dokumente");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Directory added successfully"));

    let contents = fx.list("/");
    assert!(contents.iter().any(|(n, d, _)| n == "Dokumente" && *d));

    let contents = fx.list("/Dokumente");
    assert!(contents.iter().any(|(n, d, _)| n == "readme.txt" && !d));
    assert!(contents.iter().any(|(n, d, _)| n == "work" && *d));
    assert!(contents.iter().any(|(n, d, _)| n == "personal" && *d));

    let contents = fx.list("/Dokumente/work");
    assert_eq!(contents, vec![("report.txt".to_string(), false, 6)]);

    let contents = fx.list("/Dokumente/personal/trips");
    assert_eq!(contents, vec![("photo.jpg".to_string(), false, 5)]);

    let extracted = fx.root.join("out");
    fx.extract("/Dokumente/readme.txt", &extracted);
    assert_eq!(fs::read(&extracted).unwrap(), b"top");
}

#[test]
fn add_directory_tree_creates_empty_directories() {
    let fx = VaultFixture::new("empty-dirs");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(source.join("empty/nested")).unwrap();
    fs::write(source.join("file.txt"), b"x").unwrap();

    fx.add(&source, "/Dokumente");

    let contents = fx.list("/Dokumente");
    assert!(contents.iter().any(|(n, d, _)| n == "empty" && *d));
    assert!(contents.iter().any(|(n, d, _)| n == "file.txt" && !d));

    let contents = fx.list("/Dokumente/empty");
    assert!(contents.iter().any(|(n, d, _)| n == "nested" && *d));

    let contents = fx.list("/Dokumente/empty/nested");
    assert!(contents.is_empty());
}

#[test]
fn add_directory_reuses_existing_destination_directory() {
    let fx = VaultFixture::new("reuse-dest");
    run(&[
        "--password-file",
        fx.password_file.to_str().unwrap(),
        "file",
        "mkdir",
        "--vault-path",
        fx.vault_path().to_str().unwrap(),
        "--dir",
        "/Dokumente",
    ]);

    let source = fx.root.join("Dokumente");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("existing.txt"), b"kept").unwrap();

    fx.add(&source, "/Dokumente");

    let contents = fx.list("/Dokumente");
    assert_eq!(contents, vec![("existing.txt".to_string(), false, 4)]);
}

#[test]
fn add_directory_refuses_existing_file_destination() {
    let fx = VaultFixture::new("dest-file-collision");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"x").unwrap();

    // Place a file where the destination directory would be.
    let prefile = fx.root.join("prefile");
    fs::write(&prefile, b"blocked").unwrap();
    fx.add(&prefile, "/Dokumente");

    let out = fx.add_fail(&source, "/Dokumente");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists as a file") || stderr.contains("Path already exists"),
        "{stderr}"
    );
}

#[test]
fn add_directory_refuses_nested_type_collision() {
    let fx = VaultFixture::new("nested-collision");
    run(&[
        "--password-file",
        fx.password_file.to_str().unwrap(),
        "file",
        "mkdir",
        "--vault-path",
        fx.vault_path().to_str().unwrap(),
        "--dir",
        "/Dokumente",
    ]);
    run(&[
        "--password-file",
        fx.password_file.to_str().unwrap(),
        "file",
        "mkdir",
        "--vault-path",
        fx.vault_path().to_str().unwrap(),
        "--dir",
        "/Dokumente/work",
    ]);

    let source = fx.root.join("Dokumente");
    fs::create_dir_all(source.join("work")).unwrap();
    fs::write(source.join("work/report.txt"), b"report").unwrap();

    fx.add(&source, "/Dokumente");
    let contents = fx.list("/Dokumente/work");
    assert_eq!(contents, vec![("report.txt".to_string(), false, 6)]);

    // Now try to add a file whose relative path collides with the directory.
    let file_named_work = fx.root.join("work");
    fs::write(&file_named_work, b"not a dir").unwrap();
    let out = fx.add_fail(&file_named_work, "/Dokumente");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("directory already exists")
            || stderr.contains("Already exists")
            || stderr.contains("Path already exists"),
        "{stderr}"
    );
}

#[test]
fn add_directory_refuses_symlinks() {
    let fx = VaultFixture::new("symlink");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("real.txt"), b"ok").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(source.join("real.txt"), source.join("link.txt")).unwrap();
    }

    let out = fx.add_fail(&source, "/Dokumente");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("symlink") || stderr.contains("Refusing to add symlink"),
        "{stderr}"
    );
}

#[test]
fn add_single_file_still_follows_symlink() {
    let fx = VaultFixture::new("single-symlink");
    let target = fx.root.join("target.txt");
    fs::write(&target, b"via symlink").unwrap();
    let link = fx.root.join("link.txt");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &link).unwrap();
    }

    // On non-Unix platforms we cannot create a symlink, so skip the assertion.
    #[cfg(not(unix))]
    return;

    fx.add(&link, "/link.txt");
    let contents = fx.list("/");
    assert_eq!(contents, vec![("link.txt".to_string(), false, 11)]);
}

#[test]
fn add_directory_is_deterministic_across_unordered_sources() {
    // The local filesystem may return directory entries in any order. The
    // recursive import must produce the same vault tree regardless of that
    // order, which we verify by creating files in a non-sorted order and
    // checking that every expected file ends up at the right path.
    let fx = VaultFixture::new("deterministic");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(&source).unwrap();
    for name in ["c.txt", "a.txt", "b.txt"] {
        fs::write(source.join(name), name.as_bytes()).unwrap();
    }

    fx.add(&source, "/Dokumente");

    let contents = fx.list("/Dokumente");
    let mut names: Vec<String> = contents.into_iter().map(|(n, _, _)| n).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "a.txt".to_string(),
            "b.txt".to_string(),
            "c.txt".to_string()
        ]
    );
}

#[test]
#[cfg(unix)]
fn add_directory_refuses_top_level_symlink_with_trailing_slash() {
    let fx = VaultFixture::new("symlink-trailing-slash");
    let target = fx.root.join("real-dir");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("file.txt"), b"x").unwrap();

    let link = fx.root.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    for spelling in [
        format!("{}/", link.display()),
        format!("{}/.", link.display()),
    ] {
        let source = PathBuf::from(spelling);
        let out = fx.add_fail(&source, "/Dokumente");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("symlink") || stderr.contains("Refusing to add symlink"),
            "{stderr}"
        );
    }
}

#[test]
#[cfg(unix)]
fn add_directory_refuses_nested_symlink_to_directory() {
    let fx = VaultFixture::new("nested-symlink-dir");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(&source).unwrap();

    let target = fx.root.join("secret-dir");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("secret.txt"), b"secret").unwrap();

    std::os::unix::fs::symlink(&target, source.join("link-dir")).unwrap();

    let out = fx.add_fail(&source, "/Dokumente");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("symlink") || stderr.contains("Refusing to add symlink"),
        "{stderr}"
    );
}

#[test]
#[cfg(unix)]
fn add_directory_refuses_special_files() {
    let fx = VaultFixture::new("special-file");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("ok.txt"), b"ok").unwrap();

    let fifo = source.join("pipe");
    unsafe {
        let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(libc::mkfifo(path.as_ptr(), 0o600), 0);
    }

    let out = fx.add_fail(&source, "/Dokumente");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("special file") || stderr.contains("Refusing to add special file"),
        "{stderr}"
    );
}

#[test]
fn add_directory_preflight_refuses_non_representable_names() {
    let fx = VaultFixture::new("non-representable");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("ok.txt"), b"ok").unwrap();
    // Linux allows backslashes in file names, but they are not valid VaultPath components.
    fs::write(source.join("a\\b.txt"), b"bad").unwrap();

    let out = fx.add_fail(&source, "/Dokumente");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Invalid vault path component") || stderr.contains("Invalid relative path"),
        "{stderr}"
    );

    // Preflight should leave the destination empty.
    let contents = fx.list("/");
    assert!(!contents.iter().any(|(n, _, _)| n == "Dokumente"));
}

#[test]
fn add_directory_preflight_leaves_no_partial_tree_on_conflict() {
    let fx = VaultFixture::new("partial-conflict");
    run(&[
        "--password-file",
        fx.password_file.to_str().unwrap(),
        "file",
        "mkdir",
        "--vault-path",
        fx.vault_path().to_str().unwrap(),
        "--dir",
        "/Dokumente",
    ]);
    run(&[
        "--password-file",
        fx.password_file.to_str().unwrap(),
        "file",
        "mkdir",
        "--vault-path",
        fx.vault_path().to_str().unwrap(),
        "--dir",
        "/Dokumente/middle",
    ]);
    let preexisting = fx.root.join("preexisting.txt");
    fs::write(&preexisting, b"preexisting").unwrap();
    run(&[
        "--password-file",
        fx.password_file.to_str().unwrap(),
        "file",
        "add",
        "--vault-path",
        fx.vault_path().to_str().unwrap(),
        "--source",
        preexisting.to_str().unwrap(),
        "--dest",
        "/Dokumente/middle/file.txt",
    ]);

    let source = fx.root.join("Dokumente");
    fs::create_dir_all(source.join("middle")).unwrap();
    fs::write(source.join("first.txt"), b"first").unwrap();
    fs::write(source.join("middle/file.txt"), b"second").unwrap();

    let out = fx.add_fail(&source, "/Dokumente");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists") || stderr.contains("Cannot add file"),
        "{stderr}"
    );

    // Only the pre-existing file should exist; the new tree must not be partially imported.
    let contents = fx.list("/Dokumente");
    assert_eq!(contents, vec![("middle".to_string(), true, 0)]);
    let contents = fx.list("/Dokumente/middle");
    assert_eq!(contents, vec![("file.txt".to_string(), false, 11)]);
}

#[test]
fn add_directory_preflight_refuses_existing_file_in_tree_path() {
    let fx = VaultFixture::new("tree-path-file");
    run(&[
        "--password-file",
        fx.password_file.to_str().unwrap(),
        "file",
        "mkdir",
        "--vault-path",
        fx.vault_path().to_str().unwrap(),
        "--dir",
        "/Dokumente",
    ]);
    let placeholder = fx.root.join("placeholder.txt");
    fs::write(&placeholder, b"placeholder").unwrap();
    run(&[
        "--password-file",
        fx.password_file.to_str().unwrap(),
        "file",
        "add",
        "--vault-path",
        fx.vault_path().to_str().unwrap(),
        "--source",
        placeholder.to_str().unwrap(),
        "--dest",
        "/Dokumente/subdir",
    ]);

    let source = fx.root.join("Dokumente");
    fs::create_dir_all(source.join("subdir")).unwrap();
    fs::write(source.join("subdir/file.txt"), b"x").unwrap();

    let out = fx.add_fail(&source, "/Dokumente");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Cannot create directory")
            || stderr.contains("already exists")
            || stderr.contains("Path already exists"),
        "{stderr}"
    );
}

#[test]
fn file_list_escapes_control_characters() {
    let fx = VaultFixture::new("escape");
    let source = fx.root.join("Dokumente");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("plain.txt"), b"x").unwrap();

    fx.add(&source, "/Dokumente");

    // Add a file whose name contains an ANSI escape and a newline via core API.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let manager = VaultManager::new();
        let provider_config =
            serde_json::json!({"root": fx.vault_path().to_string_lossy().to_string()});
        let session = manager
            .open_vault("local", provider_config, b"synthetic-password")
            .await
            .unwrap();
        let ops = VaultOperations::new(&session).unwrap();
        ops.create_file(
            &VaultPath::parse("/Dokumente/\x1b[31mred\nline.txt").unwrap(),
            b"y",
        )
        .await
        .unwrap();
    });

    let stdout = fx.list_raw("/Dokumente");
    assert!(stdout.contains("\\x1b[31mred\\x0aline.txt"), "{stdout}");
    assert!(!stdout.contains("\x1b["), "{stdout}");
    assert!(!stdout.contains("red\nline"), "{stdout}");
}
