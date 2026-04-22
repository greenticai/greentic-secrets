//! Passphrase-based key derivation, prompting, and header format for
//! Greentic encrypted secret stores.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod header;
pub mod kdf;
pub mod prompt;
pub mod secret_bytes;
pub mod source;

// Re-exports — uncommented as each symbol is defined in subsequent tasks.
pub use error::PassphraseError;
// pub use header::{EncryptedHeader, KdfParams, peek_header};
pub use kdf::{derive_master_key, random_salt};
// pub use prompt::{PromptMode, prompt_passphrase};
pub use secret_bytes::MasterKey;
// pub use secrecy::SecretString;
// pub use source::{read_passphrase_from_file, read_passphrase_from_stdin};

/// Minimum passphrase length enforced by `PromptMode::Initial`.
pub const MIN_PASSPHRASE_LENGTH: usize = 12;

/// Maximum prompt re-attempt count.
pub const MAX_PROMPT_ATTEMPTS: u8 = 3;
