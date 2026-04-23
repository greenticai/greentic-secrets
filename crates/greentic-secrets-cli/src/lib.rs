//! Shared CLI helpers for binaries that consume Greentic encrypted secrets.
//!
//! Provides `passphrase::resolve(...)` which selects between TTY prompt,
//! stdin pipe, or 0600-mode file based on a `PassphraseSource`. Used by
//! `greentic-setup` (CLI) and `greentic-runner` (runtime) so the prompt
//! UX stays identical across binaries.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod passphrase;

// Re-export the underlying passphrase API so consumers only need this
// dependency.
pub use greentic_secrets_passphrase::{
    EncryptedHeader, KdfParams, MasterKey, PassphraseError, PromptMode, SecretString,
    derive_master_key, peek_header, prompt_passphrase, random_salt, read_passphrase_from_file,
    read_passphrase_from_stdin,
};
