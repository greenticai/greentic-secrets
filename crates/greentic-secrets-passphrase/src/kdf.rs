//! Argon2id-based key derivation and salt generation.

use crate::error::{PassphraseError, Result};
use crate::secret_bytes::MasterKey;
use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};

/// Argon2id memory cost in KiB. 64 MiB matches OWASP 2024 baseline.
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
/// Argon2id time cost (iterations).
pub const ARGON2_TIME_COST: u32 = 3;
/// Argon2id parallelism.
pub const ARGON2_PARALLELISM: u32 = 1;

/// Generate 16 cryptographically random bytes for use as Argon2id salt.
///
/// # Panics
/// Panics if the OS RNG is unavailable. This is treated as fatal because
/// no useful key material can be derived without entropy.
pub fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).expect("OS RNG must be available");
    salt
}

/// Derive a 32-byte master key from a passphrase and salt using Argon2id
/// with the parameters configured at the top of this module.
pub fn derive_master_key(
    passphrase: &SecretString,
    salt: &[u8; 16],
) -> Result<MasterKey> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| PassphraseError::KdfError(format!("invalid params: {e}")))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(
            passphrase.expose_secret().as_bytes(),
            salt,
            &mut out,
        )
        .map_err(|e| PassphraseError::KdfError(e.to_string()))?;

    Ok(MasterKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use std::collections::HashSet;

    #[test]
    fn random_salt_is_16_bytes() {
        let salt = random_salt();
        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn random_salt_uniqueness_1000_samples() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(random_salt()));
        }
    }

    #[test]
    fn derive_master_key_deterministic_for_same_inputs() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let salt = [0x42u8; 16];
        let key1 = derive_master_key(&pass, &salt).unwrap();
        let key2 = derive_master_key(&pass, &salt).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn derive_master_key_differs_with_different_salt() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let key1 = derive_master_key(&pass, &[0x01u8; 16]).unwrap();
        let key2 = derive_master_key(&pass, &[0x02u8; 16]).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn derive_master_key_differs_with_different_passphrase() {
        let salt = [0x42u8; 16];
        let key1 = derive_master_key(&SecretString::from("foo".to_string()), &salt).unwrap();
        let key2 = derive_master_key(&SecretString::from("bar".to_string()), &salt).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
