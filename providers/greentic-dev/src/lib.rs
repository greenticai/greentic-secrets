//! Local development backend for the Greentic secrets core.

#![forbid(unsafe_code)]

mod backend;
mod dev_provider;
mod passphrase_provider;
mod persistence;
mod state;

pub use backend::DevBackend;
pub use dev_provider::DevKeyProvider;
pub use passphrase_provider::PassphraseKeyProvider;
