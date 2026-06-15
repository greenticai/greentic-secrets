//! [`SecretsSink`] — the write-target abstraction for *promoting* a resolved
//! secret set to a destination backend (e.g. a cloud secret manager during a
//! cloud deploy).
//!
//! Per the consolidation design, the lib owns the trait and the promotion logic
//! ([`crate::provision::promote`]); the deployer keeps its CLI-shelling
//! implementation behind this trait rather than re-implementing the discovery /
//! resolution dance. [`StoreSink`] adapts any [`SecretsStore`] (e.g. the local
//! dev store) into a sink so local promotion uses the same code path.

use crate::errors::Result;
use crate::seed::SecretsStore;
use crate::uri::SecretUri;
use async_trait::async_trait;
use greentic_types::secrets::SecretFormat;

/// A destination secrets can be written to during promotion.
#[async_trait]
pub trait SecretsSink: Send + Sync {
    /// Write `value` for `uri` into the destination backend.
    async fn put_secret(&self, uri: &SecretUri, value: &[u8], format: SecretFormat) -> Result<()>;
}

/// Adapts any [`SecretsStore`] into a [`SecretsSink`], so the local dev store
/// (or broker store) can be a promotion target with the same code as a cloud
/// sink.
pub struct StoreSink<S: SecretsStore> {
    store: S,
}

impl<S: SecretsStore> StoreSink<S> {
    /// Wrap a store as a sink.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Borrow the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }
}

#[async_trait]
impl<S: SecretsStore> SecretsSink for StoreSink<S> {
    async fn put_secret(&self, uri: &SecretUri, value: &[u8], format: SecretFormat) -> Result<()> {
        self.store.put(&uri.to_string(), format, value).await
    }
}
