//! Local development backend for the Greentic secrets core.

#![forbid(unsafe_code)]

mod backend;
mod dev_provider;
mod marker;
mod passphrase_provider;
mod persistence;
mod state;

pub use backend::DevBackend;
pub use dev_provider::DevKeyProvider;
pub use passphrase_provider::PassphraseKeyProvider;

// Convenience re-exports: downstream crates that consume PassphraseKeyProvider
// can pull the entire passphrase surface from a single dependency on
// greentic-secrets-provider-dev without needing to also depend on
// greentic-secrets-passphrase directly.
pub use greentic_secrets_passphrase::{
    EncryptedHeader, KdfParams, MasterKey, PassphraseError, PromptMode, SecretString,
    derive_master_key, peek_header, prompt_passphrase, random_salt,
    read_passphrase_from_file, read_passphrase_from_stdin,
};
