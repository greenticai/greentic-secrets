//! `.encrypted-marker` sidecar file used to detect downgrade attacks.
//!
//! When a secret store is first persisted in encrypted format, a marker
//! file is written next to it containing the SHA-256 of the header bytes.
//! Subsequent loads check for the marker; if it is present but the store
//! is in legacy plaintext format, refuse to load (caller may pass
//! `--allow-downgrade` to override).

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
const MARKER_SUFFIX: &str = ".encrypted-marker";

/// Returns the marker path for a given secrets store path.
#[allow(dead_code)]
pub(crate) fn marker_path(store_path: &Path) -> PathBuf {
    let parent = store_path.parent().unwrap_or_else(|| Path::new("."));
    let name = store_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    parent.join(format!("{name}{MARKER_SUFFIX}"))
}

/// Compute the marker payload for a header byte slice.
#[allow(dead_code)]
pub(crate) fn marker_for_header(header_bytes: &[u8]) -> String {
    let digest = Sha256::digest(header_bytes);
    format!("sha256:{}", hex_lower(&digest))
}

#[allow(dead_code)]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Write/refresh the marker for a store path.
#[allow(dead_code)]
pub(crate) fn write_marker(store_path: &Path, header_bytes: &[u8]) -> io::Result<()> {
    let path = marker_path(store_path);
    fs::write(&path, marker_for_header(header_bytes))?;
    Ok(())
}

/// Returns true if a marker exists for this store path.
#[allow(dead_code)]
pub(crate) fn marker_exists(store_path: &Path) -> bool {
    marker_path(store_path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_payload_is_deterministic() {
        let m1 = marker_for_header(b"hello");
        let m2 = marker_for_header(b"hello");
        assert_eq!(m1, m2);
        assert!(m1.starts_with("sha256:"));
    }

    #[test]
    fn marker_path_appends_suffix() {
        let p = marker_path(Path::new("/tmp/.dev.secrets.env"));
        assert_eq!(p, PathBuf::from("/tmp/.dev.secrets.env.encrypted-marker"));
    }

    #[test]
    fn write_then_check_marker() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store.env");
        fs::write(&store, "stuff").unwrap();
        assert!(!marker_exists(&store));
        write_marker(&store, b"header bytes").unwrap();
        assert!(marker_exists(&store));
        let contents = fs::read_to_string(marker_path(&store)).unwrap();
        assert_eq!(contents, marker_for_header(b"header bytes"));
    }
}
