use greentic_secrets_spec::{KeyProvider, Scope, SecretsResult as Result};
use sha2::{Digest, Sha256};

pub(crate) const MASTER_KEY_ENV: &str = "GREENTIC_DEV_MASTER_KEY";

/// Simple development key provider that uses deterministic material to wrap DEKs.
#[derive(Clone, Default)]
pub struct DevKeyProvider {
    master_key: [u8; 32],
}

impl DevKeyProvider {
    /// Construct the provider from environment configuration.
    pub fn from_env() -> Self {
        let material = std::env::var(MASTER_KEY_ENV).unwrap_or_default();
        Self::from_material(material.as_bytes())
    }

    /// Construct the provider by hashing arbitrary input into a fixed-size key.
    pub fn from_material(input: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let digest = hasher.finalize();
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&digest);
        Self { master_key }
    }
}

impl KeyProvider for DevKeyProvider {
    fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> Result<Vec<u8>> {
        Ok(xor_with_key(dek, &self.master_key))
    }

    fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> Result<Vec<u8>> {
        Ok(xor_with_key(wrapped, &self.master_key))
    }
}

pub(crate) fn xor_with_key(input: &[u8], key: &[u8; 32]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ key[idx % key.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::Scope;

    fn sample_scope() -> Scope {
        Scope::new("dev", "acme", Some("payments".into())).unwrap()
    }

    #[test]
    fn key_provider_wrap_unwrap() {
        let provider = DevKeyProvider::from_material(b"material");
        let scope = sample_scope();
        let dek = vec![1, 2, 3, 4, 5];
        let wrapped = provider.wrap_dek(&scope, &dek).unwrap();
        assert_eq!(wrapped.len(), dek.len());
        assert_ne!(wrapped, dek);
        let unwrapped = provider.unwrap_dek(&scope, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }
}
