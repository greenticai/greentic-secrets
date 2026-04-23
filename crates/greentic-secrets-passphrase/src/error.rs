//! Error types for passphrase operations.

use std::path::PathBuf;

/// Result alias used across the crate.
pub type Result<T> = core::result::Result<T, PassphraseError>;

/// All error conditions surfaced by passphrase operations.
///
/// `InvalidPassphrase` deliberately collapses both wrong-passphrase and
/// tampered-ciphertext failures into one message so an attacker cannot
/// distinguish the two.
#[derive(thiserror::Error, Debug)]
pub enum PassphraseError {
    /// Wrong passphrase or tampered ciphertext (indistinguishable by design).
    #[error("passphrase incorrect")]
    InvalidPassphrase,

    /// Passphrase shorter than the enforced minimum during initial setup.
    #[error("passphrase must be at least {min} characters (got {actual})")]
    PassphraseTooShort {
        /// Required minimum length.
        min: usize,
        /// Length the user entered.
        actual: usize,
    },

    /// Confirmation passphrase did not match the first entry.
    #[error("passphrases do not match")]
    PassphraseMismatch,

    /// Maximum re-prompt attempts exceeded.
    #[error("maximum passphrase prompt attempts exceeded")]
    TooManyAttempts,

    /// Encrypted store header could not be parsed.
    #[error("encrypted store header is malformed: {reason}")]
    HeaderParseError {
        /// Human-readable parse failure reason (no raw bytes).
        reason: String,
    },

    /// Header advertises a version this build does not understand.
    #[error("encrypted store version {version} is not supported (this build supports v1)")]
    UnsupportedVersion {
        /// Version string from the file header.
        version: String,
    },

    /// Failed to read passphrase from terminal.
    #[error("failed to read passphrase from terminal: {0}")]
    TerminalIo(#[from] std::io::Error),

    /// Passphrase file is readable by users other than the owner.
    #[error("passphrase file {path} has insecure permissions ({mode:o}); must be 0600")]
    InsecurePassphraseFile {
        /// Path to the offending file.
        path: PathBuf,
        /// The file's current mode bits.
        mode: u32,
    },

    /// Passphrase file is not owned by the current user.
    #[error("passphrase file {path} is not owned by current user")]
    UnownedPassphraseFile {
        /// Path to the offending file.
        path: PathBuf,
    },

    /// Underlying KDF (Argon2id) returned an error. The wrapped string is
    /// the KDF crate's message; never includes passphrase or salt content.
    #[error("cannot derive key: {0}")]
    KdfError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_passphrase_message_does_not_leak_internals() {
        let err = PassphraseError::InvalidPassphrase;
        let msg = err.to_string();
        assert_eq!(msg, "passphrase incorrect");
        assert!(!msg.to_lowercase().contains("aes"));
        assert!(!msg.to_lowercase().contains("gcm"));
        assert!(!msg.to_lowercase().contains("auth"));
    }

    #[test]
    fn passphrase_too_short_includes_min_and_actual() {
        let err = PassphraseError::PassphraseTooShort { min: 12, actual: 8 };
        assert_eq!(err.to_string(), "passphrase must be at least 12 characters (got 8)");
    }
}
