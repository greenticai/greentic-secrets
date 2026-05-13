use thiserror::Error;

/// Result alias for secrets operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Result alias for decryption operations.
pub type DecryptResult<T> = core::result::Result<T, DecryptError>;

/// Canonical secrets error surface.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("secret identifier must not be empty")]
    InvalidIdentifier,
    #[error("{field} contains invalid characters: {value}")]
    InvalidCharacters { field: &'static str, value: String },
    #[error("{field} must not be empty")]
    EmptyComponent { field: &'static str },
    #[error("uri must start with secrets://")]
    InvalidScheme,
    #[error("uri is missing {field}")]
    MissingSegment { field: &'static str },
    #[error("uri contains unexpected extra segments")]
    ExtraSegments,
    #[error("invalid version segment: {value}")]
    InvalidVersion { value: String },
    #[error("encryption algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),
    #[error("encryption algorithm {0} requires the 'xchacha' feature")]
    AlgorithmFeatureUnavailable(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("passphrase incorrect")]
    InvalidPassphrase,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("invalid {0}: {1}")]
    Invalid(String, String),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("{entity} not found")]
    NotFound { entity: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecryptError {
    #[error("message authentication failed")]
    MacMismatch,
    #[error("key provider error: {0}")]
    Provider(String),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// Compatibility aliases preferred by downstream callers.
pub type SecretsResult<T> = Result<T>;
pub type SecretsError = Error;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_passphrase_message_is_stable() {
        let err = Error::InvalidPassphrase;
        assert_eq!(err.to_string(), "passphrase incorrect");
    }
}
