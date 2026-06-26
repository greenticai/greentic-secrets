#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod backend;
pub mod error;
pub mod generation;
pub mod helpers;
pub mod key_provider;
pub mod provider_binding;
pub mod refs;
pub mod requirements;
pub mod result_ext;
pub mod serde_util;
pub mod types;
pub mod uri;

pub use backend::{SecretVersion, SecretsBackend, VersionedSecret};
pub use error::{DecryptError, DecryptResult, Error, Result, SecretsError, SecretsResult};
pub use generation::*;
pub use helpers::*;
pub use key_provider::*;
pub use provider_binding::*;
pub use refs::*;
pub use requirements::*;
pub use result_ext::*;
pub use serde_util::*;
pub use types::*;
pub use uri::*;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

pub type DynSecretsBackend = Arc<dyn SecretsBackend + Send + Sync>;

pub mod prelude {
    pub use crate::ResultExt;
    pub use crate::generation::{
        GeneratedSecretRequirement, GeneratedSecretScope, ManagedSecret, PackSecretRequirement,
        SecretSet, SecretSource, generated_scope_team,
    };
    pub use crate::refs::{SecretRef, SecretRefParseError};
    pub use crate::uri::*;
    pub use crate::{
        Envelope, KeyProvider, SecretIdentifier, SecretListItem, SecretMeta, SecretRecord,
        SecretsBackend, SecretsError, SecretsResult, record_from_plain, with_ttl,
    };
}
