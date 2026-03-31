use crate::crypto::dek_cache::{CacheKey, DekCache, DekMaterial};
use crate::key_provider::KeyProvider;
use crate::spec_compat::{
    DecryptError, DecryptResult, EncryptionAlgorithm, Envelope, Error, Result, Scope, SecretMeta,
    SecretRecord,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use rand::Rng;
#[cfg(feature = "crypto-ring")]
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use sha2::Sha256;
use std::env;

const DEFAULT_DEK_LEN: usize = 32;
const HKDF_SALT_LEN: usize = 32;
#[cfg(feature = "crypto-ring")]
const NONCE_LEN: usize = 12;
#[cfg(feature = "crypto-ring")]
const TAG_LEN: usize = 16;
const ENC_ALGO_ENV: &str = "SECRETS_ENC_ALGO";

#[cfg(not(any(feature = "crypto-ring", feature = "crypto-none")))]
compile_error!("Enable either the `crypto-ring` or `crypto-none` feature for envelope encryption");

/// High-level service responsible for encrypting and decrypting secret records.
pub struct EnvelopeService<P>
where
    P: KeyProvider,
{
    provider: P,
    cache: DekCache,
    algorithm: EncryptionAlgorithm,
}

impl<P> EnvelopeService<P>
where
    P: KeyProvider,
{
    /// Constructs a new service with the supplied components.
    pub fn new(provider: P, cache: DekCache, algorithm: EncryptionAlgorithm) -> Self {
        Self {
            provider,
            cache,
            algorithm,
        }
    }

    /// Builds a service using environment configuration and default cache parameters.
    pub fn from_env(provider: P) -> Result<Self> {
        let algorithm = env::var(ENC_ALGO_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or_default();

        Ok(Self::new(provider, DekCache::from_env(), algorithm))
    }

    /// Currently configured algorithm.
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// Borrow the underlying DEK cache.
    pub fn cache(&self) -> &DekCache {
        &self.cache
    }

    /// Mutable access to the DEK cache.
    pub fn cache_mut(&mut self) -> &mut DekCache {
        &mut self.cache
    }

    /// Encrypts plaintext into a [`SecretRecord`] using envelope encryption.
    pub fn encrypt_record(&mut self, meta: SecretMeta, plaintext: &[u8]) -> Result<SecretRecord> {
        let cache_key = CacheKey::from_meta(&meta);
        let scope = meta.scope().clone();
        let info = meta.uri.to_string();

        let (dek, wrapped) = self.obtain_dek(&cache_key, &scope)?;

        let salt = random_bytes(HKDF_SALT_LEN);
        let key = derive_key(&dek, &salt, info.as_bytes())?;
        let (nonce, ciphertext) = encrypt_with_algorithm(self.algorithm, &key, plaintext)?;

        let envelope = Envelope {
            algorithm: self.algorithm,
            nonce,
            hkdf_salt: salt,
            wrapped_dek: wrapped.clone(),
        };

        Ok(SecretRecord::new(meta, ciphertext, envelope))
    }

    fn obtain_dek(&mut self, cache_key: &CacheKey, scope: &Scope) -> Result<(Vec<u8>, Vec<u8>)> {
        if let Some(material) = self.cache.get(cache_key) {
            return Ok((material.dek, material.wrapped));
        }

        let dek = generate_dek();
        let wrapped = self.provider.wrap_dek(scope, &dek)?;
        self.cache
            .insert(cache_key.clone(), dek.clone(), wrapped.clone());
        Ok((dek, wrapped))
    }

    /// Decrypts the ciphertext of a [`SecretRecord`].
    pub fn decrypt_record(&mut self, record: &SecretRecord) -> DecryptResult<Vec<u8>> {
        let cache_key = CacheKey::from_meta(&record.meta);
        let scope = record.meta.scope();
        let algorithm = record.envelope.algorithm;
        let info = record.meta.uri.to_string();

        let material = match self.cache.get(&cache_key) {
            Some(material) => material,
            None => {
                let dek = self
                    .provider
                    .unwrap_dek(scope, &record.envelope.wrapped_dek)
                    .map_err(|err| DecryptError::Provider(err.to_string()))?;
                let material = DekMaterial {
                    dek: dek.clone(),
                    wrapped: record.envelope.wrapped_dek.clone(),
                };
                self.cache.insert(
                    cache_key.clone(),
                    material.dek.clone(),
                    material.wrapped.clone(),
                );
                material
            }
        };

        let key = derive_key(&material.dek, &record.envelope.hkdf_salt, info.as_bytes())
            .map_err(|err| DecryptError::Crypto(err.to_string()))?;
        let plaintext =
            decrypt_with_algorithm(algorithm, &key, &record.envelope.nonce, &record.value)?;

        Ok(plaintext)
    }
}

fn encrypt_with_algorithm(
    algorithm: EncryptionAlgorithm,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let sealed = seal_aead(key, plaintext).map_err(|err| Error::Crypto(err.to_string()))?;
            let data = STANDARD
                .decode(sealed)
                .map_err(|err| Error::Crypto(err.to_string()))?;
            let nonce_len = EncryptionAlgorithm::Aes256Gcm.nonce_len();
            if data.len() < nonce_len {
                return Err(Error::Crypto("ciphertext too short".into()));
            }
            let (nonce, ciphertext) = data.split_at(nonce_len);
            Ok((nonce.to_vec(), ciphertext.to_vec()))
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            #[cfg(feature = "xchacha")]
            {
                // Fallback implementation that reuses AES-GCM under the hood while preserving
                // the XChaCha nonce width (24 bytes). The first 12 bytes store the AES nonce; the
                // remaining bytes are random padding so decryptions can reconstruct the original
                // AES inputs deterministically.
                let sealed =
                    seal_aead(key, plaintext).map_err(|err| Error::Crypto(err.to_string()))?;
                let data = STANDARD
                    .decode(sealed)
                    .map_err(|err| Error::Crypto(err.to_string()))?;
                let aes_nonce_len = EncryptionAlgorithm::Aes256Gcm.nonce_len();
                if data.len() < aes_nonce_len {
                    return Err(Error::Crypto("ciphertext too short".into()));
                }
                let (aes_nonce, ciphertext) = data.split_at(aes_nonce_len);
                let mut nonce = random_bytes(EncryptionAlgorithm::XChaCha20Poly1305.nonce_len());
                nonce[..aes_nonce_len].copy_from_slice(aes_nonce);
                Ok((nonce, ciphertext.to_vec()))
            }
            #[cfg(not(feature = "xchacha"))]
            {
                Err(Error::AlgorithmFeatureUnavailable(
                    algorithm.as_str().to_string(),
                ))
            }
        }
    }
}

fn decrypt_with_algorithm(
    algorithm: EncryptionAlgorithm,
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> DecryptResult<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
            combined.extend_from_slice(nonce);
            combined.extend_from_slice(ciphertext);
            let encoded = STANDARD.encode(combined);
            match open_aead(key, &encoded) {
                Ok(bytes) => Ok(bytes),
                Err(Error::Backend(message)) if message == "open failed" => {
                    Err(DecryptError::MacMismatch)
                }
                Err(err) => Err(DecryptError::Crypto(err.to_string())),
            }
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            #[cfg(feature = "xchacha")]
            {
                let aes_nonce_len = EncryptionAlgorithm::Aes256Gcm.nonce_len();
                if nonce.len() < aes_nonce_len {
                    return Err(DecryptError::Crypto(
                        "invalid nonce length for compatibility mode".into(),
                    ));
                }
                // Reconstruct the AES-compatible ciphertext produced by the fallback encryptor.
                let mut combined = Vec::with_capacity(aes_nonce_len + ciphertext.len());
                combined.extend_from_slice(&nonce[..aes_nonce_len]);
                combined.extend_from_slice(ciphertext);
                let encoded = STANDARD.encode(combined);
                match open_aead(key, &encoded) {
                    Ok(bytes) => Ok(bytes),
                    Err(Error::Backend(message)) if message == "open failed" => {
                        Err(DecryptError::MacMismatch)
                    }
                    Err(err) => Err(DecryptError::Crypto(err.to_string())),
                }
            }
            #[cfg(not(feature = "xchacha"))]
            {
                Err(DecryptError::Crypto(format!(
                    "algorithm {algorithm} unavailable"
                )))
            }
        }
    }
}

#[cfg(feature = "crypto-ring")]
fn seal_aead(key_bytes: &[u8], plaintext: &[u8]) -> Result<String> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)
        .map_err(|err| Error::Backend(format!("rng: {err:?}")))?;

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
        .map_err(|_| Error::Backend("invalid key".into()))?;
    let key = aead::LessSafeKey::new(key);

    let mut in_out = plaintext.to_vec();
    in_out.reserve(TAG_LEN);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut in_out,
    )
    .map_err(|_| Error::Backend("seal failed".into()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&in_out);
    Ok(STANDARD.encode(out))
}

#[cfg(feature = "crypto-ring")]
fn open_aead(key_bytes: &[u8], b64: &str) -> Result<Vec<u8>> {
    let data = STANDARD
        .decode(b64)
        .map_err(|_| Error::Invalid("ciphertext".into(), "b64".into()))?;
    if data.len() < NONCE_LEN {
        return Err(Error::Invalid("ciphertext".into(), "too short".into()));
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
        .map_err(|_| Error::Backend("invalid key".into()))?;
    let key = aead::LessSafeKey::new(key);

    let mut buffer = ct.to_vec();
    let plaintext = key
        .open_in_place(
            aead::Nonce::try_assume_unique_for_key(nonce)
                .map_err(|_| Error::Invalid("nonce".into(), "invalid length".into()))?,
            aead::Aad::empty(),
            &mut buffer,
        )
        .map_err(|_| Error::Backend("open failed".into()))?;

    Ok(plaintext.to_vec())
}

#[cfg(all(feature = "crypto-none", not(feature = "crypto-ring")))]
fn seal_aead(_key_bytes: &[u8], plaintext: &[u8]) -> Result<String> {
    Ok(STANDARD.encode(plaintext))
}

#[cfg(all(feature = "crypto-none", not(feature = "crypto-ring")))]
fn open_aead(_key_bytes: &[u8], b64: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(b64)
        .map_err(|_| Error::Invalid("ciphertext".into(), "b64".into()))
}

/// Derives a 256-bit subkey from the DEK using HKDF-SHA256 with the given salt and context info.
fn derive_key(dek: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), dek);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .map_err(|_| Error::Crypto("failed to derive key material".into()))?;
    Ok(okm)
}

fn generate_dek() -> Vec<u8> {
    random_bytes(DEFAULT_DEK_LEN)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; len];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut buffer);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::dek_cache::DekCache;
    use crate::key_provider::KeyProvider;
    use crate::spec_compat::{ContentType, Scope, SecretMeta, Visibility};
    use crate::uri::SecretUri;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Clone)]
    struct DummyProvider {
        wrap_calls: Arc<Mutex<usize>>,
        unwrap_calls: Arc<Mutex<usize>>,
    }

    impl DummyProvider {
        fn new() -> Self {
            Self {
                wrap_calls: Arc::new(Mutex::new(0)),
                unwrap_calls: Arc::new(Mutex::new(0)),
            }
        }

        fn calls(&self) -> (usize, usize) {
            (
                *self.wrap_calls.lock().unwrap(),
                *self.unwrap_calls.lock().unwrap(),
            )
        }
    }

    impl KeyProvider for DummyProvider {
        fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> Result<Vec<u8>> {
            *self.wrap_calls.lock().unwrap() += 1;
            Ok(dek.iter().map(|b| b ^ 0xAA).collect())
        }

        fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> Result<Vec<u8>> {
            *self.unwrap_calls.lock().unwrap() += 1;
            Ok(wrapped.iter().map(|b| b ^ 0xAA).collect())
        }
    }

    fn sample_meta(team: Option<&str>) -> SecretMeta {
        let scope = Scope::new(
            "prod".to_string(),
            "acme".to_string(),
            team.map(|t| t.to_string()),
        )
        .unwrap();
        let uri = SecretUri::new(scope.clone(), "kv", "api")
            .unwrap()
            .with_version(Some("v1"))
            .unwrap();
        SecretMeta::new(uri, Visibility::Team, ContentType::Opaque)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let provider = DummyProvider::new();
        let cache = DekCache::new(8, Duration::from_secs(300));
        let mut service = EnvelopeService::new(provider, cache, EncryptionAlgorithm::Aes256Gcm);

        let meta = sample_meta(Some("payments"));
        let plaintext = b"super-secret-data";
        let record = service
            .encrypt_record(meta.clone(), plaintext)
            .expect("encrypt");

        let recovered = service.decrypt_record(&record).expect("decrypt");
        assert_eq!(plaintext.to_vec(), recovered);
        assert_eq!(record.meta, meta);
    }

    #[test]
    fn tamper_detection() {
        let provider = DummyProvider::new();
        let cache = DekCache::new(8, Duration::from_secs(300));
        let mut service = EnvelopeService::new(provider, cache, EncryptionAlgorithm::Aes256Gcm);
        let meta = sample_meta(Some("payments"));

        let mut record = service.encrypt_record(meta, b"critical").expect("encrypt");
        record.value[0] ^= 0xFF;

        let err = service.decrypt_record(&record).unwrap_err();
        assert!(matches!(err, DecryptError::MacMismatch));
    }

    #[test]
    fn cache_hit_and_miss_behavior() {
        let provider = DummyProvider::new();
        let cache = DekCache::new(8, Duration::from_secs(300));
        let mut service =
            EnvelopeService::new(provider.clone(), cache, EncryptionAlgorithm::Aes256Gcm);
        let meta = sample_meta(Some("payments"));
        let plaintext = b"payload";

        service
            .encrypt_record(meta.clone(), plaintext)
            .expect("encrypt");
        let (wrap_calls, _) = provider.calls();
        assert_eq!(wrap_calls, 1);

        service
            .encrypt_record(meta.clone(), plaintext)
            .expect("encrypt again");
        let (wrap_calls, _) = provider.calls();
        assert_eq!(wrap_calls, 1, "expected cache hit to avoid wrapping");

        // Force TTL expiry by rebuilding cache with zero TTL.
        let (wrap_calls_before, _) = provider.calls();
        let mut service = EnvelopeService::new(
            provider.clone(),
            DekCache::new(8, Duration::from_secs(0)),
            EncryptionAlgorithm::Aes256Gcm,
        );
        service
            .encrypt_record(meta, plaintext)
            .expect("encrypt with fresh cache");
        let (wrap_calls, _) = provider.calls();
        assert!(
            wrap_calls > wrap_calls_before,
            "expected miss to invoke wrap again"
        );
    }
}
