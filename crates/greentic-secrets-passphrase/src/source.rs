//! Non-interactive passphrase sources: stdin pipe and file.

use crate::error::{PassphraseError, Result};
use secrecy::SecretString;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Read a passphrase from the first line of standard input.
/// Trailing CR/LF is stripped. Empty line returns `InvalidPassphrase`.
pub fn read_passphrase_from_stdin() -> Result<SecretString> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(PassphraseError::InvalidPassphrase);
    }
    Ok(SecretString::from(trimmed))
}

/// Read a passphrase from a file. The file MUST be mode 0600 and owned
/// by the current user (POSIX). On Windows this function returns an
/// error directing users to `--passphrase-stdin`.
pub fn read_passphrase_from_file(path: &Path) -> Result<SecretString> {
    verify_file_security(path)?;
    let contents = std::fs::read_to_string(path)?;
    let trimmed = contents.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(PassphraseError::InvalidPassphrase);
    }
    Ok(SecretString::from(trimmed))
}

#[cfg(unix)]
fn verify_file_security(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(PassphraseError::InsecurePassphraseFile {
            path: path.to_path_buf(),
            mode,
        });
    }
    let current_uid = rustix::process::getuid().as_raw();
    if meta.uid() != current_uid {
        return Err(PassphraseError::UnownedPassphraseFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_file_security(path: &Path) -> Result<()> {
    Err(PassphraseError::InsecurePassphraseFile {
        path: path.to_path_buf(),
        mode: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    #[cfg(unix)]
    fn rejects_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), "passphrase\n").unwrap();
        let mut perms = std::fs::metadata(temp.path()).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(temp.path(), perms).unwrap();

        let err = read_passphrase_from_file(temp.path()).unwrap_err();
        match err {
            PassphraseError::InsecurePassphraseFile { mode, .. } => {
                assert_eq!(mode, 0o644);
            }
            other => panic!("expected InsecurePassphraseFile, got {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), "passphrase\n").unwrap();
        let mut perms = std::fs::metadata(temp.path()).unwrap().permissions();
        perms.set_mode(0o640);
        std::fs::set_permissions(temp.path(), perms).unwrap();

        let err = read_passphrase_from_file(temp.path()).unwrap_err();
        assert!(matches!(err, PassphraseError::InsecurePassphraseFile { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn accepts_mode_0600_file_owned_by_current_user() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(temp.path())
            .unwrap();
        f.write_all(b"my-secret-passphrase\n").unwrap();
        drop(f);
        let mut perms = std::fs::metadata(temp.path()).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(temp.path(), perms).unwrap();

        let pass = read_passphrase_from_file(temp.path()).unwrap();
        use secrecy::ExposeSecret;
        assert_eq!(pass.expose_secret(), "my-secret-passphrase");
    }

    #[test]
    #[cfg(unix)]
    fn rejects_empty_file() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut perms = std::fs::metadata(temp.path()).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(temp.path(), perms).unwrap();

        let err = read_passphrase_from_file(temp.path()).unwrap_err();
        assert!(matches!(err, PassphraseError::InvalidPassphrase));
    }
}
