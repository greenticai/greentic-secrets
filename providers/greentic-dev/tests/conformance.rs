#![cfg(feature = "integration")]

use anyhow::Result;
use secrets_provider_dev::{DevBackend, DevKeyProvider};
use secrets_provider_tests::{Capabilities, ConformanceSuite, ProviderUnderTest};

use async_trait::async_trait;
use greentic_secrets_spec::{
    ContentType, EncryptionAlgorithm, Envelope, KeyProvider, SecretMeta, SecretRecord, SecretUri,
    SecretsBackend, Visibility, types::Scope,
};

struct DevClient {
    backend: DevBackend,
}

impl DevClient {
    fn new() -> Self {
        Self {
            backend: DevBackend::new(),
        }
    }

    fn uri_for(&self, key: &str) -> SecretUri {
        let safe = key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>();
        let scope = Scope::new("integration", "dev", None).unwrap();
        SecretUri::new(scope, "conformance", safe).unwrap()
    }

    fn record(&self, uri: SecretUri, value: Vec<u8>) -> SecretRecord {
        let meta = SecretMeta::new(uri, Visibility::Tenant, ContentType::Text);
        let algo = EncryptionAlgorithm::Aes256Gcm;
        let envelope = Envelope {
            algorithm: algo,
            nonce: vec![0; algo.nonce_len()],
            hkdf_salt: Vec::new(),
            wrapped_dek: DevKeyProvider::from_env()
                .wrap_dek(meta.scope(), b"dev")
                .unwrap(),
        };
        SecretRecord::new(meta, value, envelope)
    }
}

#[async_trait]
impl ProviderUnderTest for DevClient {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let uri = self.uri_for(key);
        let record = self.record(uri, value.to_vec());
        self.backend.put(record)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let uri = self.uri_for(key);
        let found = self.backend.get(&uri, None)?;
        Ok(found.and_then(|v| v.record).map(|r| r.value))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let uri = self.uri_for(key);
        let _ = self.backend.delete(&uri)?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "integration test; requires GREENTIC_INTEGRATION=1"]
async fn conformance_dev_backend() -> Result<()> {
    if std::env::var("GREENTIC_INTEGRATION").unwrap_or_default() != "1" {
        eprintln!("GREENTIC_INTEGRATION=1 not set; skipping conformance");
        return Ok(());
    }
    let client = DevClient::new();
    ConformanceSuite::new("dev", &client, Capabilities::default())
        .run()
        .await
}
