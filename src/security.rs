use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

/// Publishes a sensitive file privately and atomically without replacing an
/// existing path. The temporary file is created in the destination directory,
/// then linked into place so publication is an atomic no-clobber operation.
#[cfg(unix)]
pub(crate) fn publish_sensitive_file(destination: &Path, contents: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination has no file name")
    })?;

    // Fail before creating a temporary file when the destination already
    // exists, including when it is a symlink.
    if fs::symlink_metadata(destination).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }

    let mut nonce_bytes = [0_u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut nonce_bytes)?;
    let nonce = u128::from_ne_bytes(nonce_bytes);
    let mut temporary = None;
    for attempt in 0..128_u32 {
        let candidate = parent.join(format!(
            ".{}.axiom-tmp-{}-{nonce}-{attempt}",
            file_name.to_string_lossy(),
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a private temporary file",
        )
    })?;

    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("temporary file permissions are {mode:o}, expected 600"),
            ));
        }
        drop(file);
        fs::hard_link(&temporary_path, destination)?;
        fs::remove_file(&temporary_path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

/// Sensitive publication is deliberately unsupported where owner-only mode
/// and atomic no-clobber hard-link semantics have not been verified.
#[cfg(not(unix))]
pub(crate) fn publish_sensitive_file(_destination: &Path, _contents: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure sensitive-file publication is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("axiom-cli-security-{unique}"));
        fs::create_dir(&path).expect("temporary directory should be created");
        path
    }

    #[test]
    fn sensitive_publication_never_clobbers_an_existing_destination() {
        let dir = temp_dir();
        let destination = dir.join("secret.json");
        fs::write(&destination, b"original").expect("fixture should be written");

        let error = publish_sensitive_file(&destination, b"replacement")
            .expect_err("an existing destination must be rejected");

        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_publication_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let destination = dir.join("secret.json");
        publish_sensitive_file(&destination, b"secret").unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"secret");
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_publication_does_not_follow_destination_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir();
        let target = dir.join("target");
        let destination = dir.join("secret.json");
        fs::write(&target, b"original").unwrap();
        symlink(&target, &destination).unwrap();

        let error = publish_sensitive_file(&destination, b"replacement").unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&target).unwrap(), b"original");
        fs::remove_dir_all(dir).unwrap();
    }
}
