//! AES-256-GCM key provider keyed by an Argon2id-derived master key.
//!
//! `#[allow(deprecated)]` is applied because aes-gcm 0.10's `Key::from_slice`
//! and `Nonce::from_slice` re-export `GenericArray` methods deprecated in
//! generic-array 1.x. The aes-gcm 0.11 release (still RC at time of writing)
//! drops these. Remove the allow when the workspace bumps to aes-gcm 0.11.
#![allow(deprecated)]

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use greentic_secrets_passphrase::MasterKey;
use greentic_secrets_spec::{KeyProvider, Scope, SecretsError as Error, SecretsResult as Result};

const NONCE_LEN: usize = 12;

/// Wraps DEKs using AES-256-GCM with a passphrase-derived master key.
///
/// Output layout: `nonce(12) || ciphertext || tag(16)`.
pub struct PassphraseKeyProvider {
    master_key: MasterKey,
    salt: [u8; 16],
}

impl PassphraseKeyProvider {
    /// Construct from a derived master key and the salt used to derive it.
    pub fn new(master_key: MasterKey, salt: [u8; 16]) -> Self {
        Self { master_key, salt }
    }

    /// Returns the salt this provider was created with.
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    fn cipher(&self) -> Aes256Gcm {
        let key = Key::<Aes256Gcm>::from_slice(self.master_key.as_bytes());
        Aes256Gcm::new(key)
    }
}

impl KeyProvider for PassphraseKeyProvider {
    fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher()
            .encrypt(nonce, dek)
            .map_err(|e| Error::Crypto(format!("aes-gcm encrypt: {e}")))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> Result<Vec<u8>> {
        if wrapped.len() < NONCE_LEN + 16 {
            // Map to InvalidPassphrase to avoid distinguishing "too short"
            // from "wrong key" — both surface as "passphrase incorrect"
            // upstream.
            return Err(Error::InvalidPassphrase);
        }
        let (nonce_bytes, ct) = wrapped.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher()
            .decrypt(nonce, ct)
            .map_err(|_| Error::InvalidPassphrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_passphrase::{derive_master_key, random_salt};
    use secrecy::SecretString;

    fn provider(passphrase: &str, salt: [u8; 16]) -> PassphraseKeyProvider {
        let mk = derive_master_key(&SecretString::from(passphrase.to_string()), &salt).unwrap();
        PassphraseKeyProvider::new(mk, salt)
    }

    fn scope() -> Scope {
        Scope::new("dev", "acme", Some("core".into())).unwrap()
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let salt = random_salt();
        let p = provider("correct horse battery staple", salt);
        let dek = vec![0xAA; 32];
        let wrapped = p.wrap_dek(&scope(), &dek).unwrap();
        assert_ne!(wrapped, dek);
        assert_eq!(wrapped.len(), NONCE_LEN + dek.len() + 16);
        let unwrapped = p.unwrap_dek(&scope(), &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn wrong_passphrase_fails_unwrap() {
        let salt = random_salt();
        let p1 = provider("correct horse battery staple", salt);
        let p2 = provider("wrong passphrase here!!", salt);
        let wrapped = p1.wrap_dek(&scope(), &[1, 2, 3]).unwrap();
        let err = p2.unwrap_dek(&scope(), &wrapped).unwrap_err();
        assert!(matches!(err, Error::InvalidPassphrase));
    }

    #[test]
    fn tampered_ciphertext_fails_unwrap() {
        let salt = random_salt();
        let p = provider("correct horse battery staple", salt);
        let mut wrapped = p.wrap_dek(&scope(), &[1, 2, 3]).unwrap();
        wrapped[NONCE_LEN] ^= 0x01;
        let err = p.unwrap_dek(&scope(), &wrapped).unwrap_err();
        assert!(matches!(err, Error::InvalidPassphrase));
    }

    #[test]
    fn tampered_nonce_fails_unwrap() {
        let salt = random_salt();
        let p = provider("correct horse battery staple", salt);
        let mut wrapped = p.wrap_dek(&scope(), &[1, 2, 3]).unwrap();
        wrapped[0] ^= 0x01;
        let err = p.unwrap_dek(&scope(), &wrapped).unwrap_err();
        assert!(matches!(err, Error::InvalidPassphrase));
    }

    #[test]
    fn truncated_ciphertext_fails_unwrap() {
        let salt = random_salt();
        let p = provider("correct horse battery staple", salt);
        let err = p.unwrap_dek(&scope(), &[0, 1, 2]).unwrap_err();
        assert!(matches!(err, Error::InvalidPassphrase));
    }

    #[test]
    fn nonce_uniqueness_across_calls() {
        let salt = random_salt();
        let p = provider("correct horse battery staple", salt);
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..1000 {
            let wrapped = p.wrap_dek(&scope(), &[0u8; 8]).unwrap();
            let nonce: [u8; NONCE_LEN] = wrapped[..NONCE_LEN].try_into().unwrap();
            assert!(nonces.insert(nonce));
        }
    }
}
