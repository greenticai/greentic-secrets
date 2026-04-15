#![cfg(feature = "integration")]

use anyhow::Result;
use async_trait::async_trait;
use secrets_provider_k8s::build_backend;
use secrets_provider_tests::{Capabilities, ConformanceSuite, ProviderUnderTest};

use greentic_secrets_spec::{
    ContentType, EncryptionAlgorithm, Envelope, KeyProvider, SecretMeta, SecretRecord, SecretUri,
    SecretsBackend, Visibility, types::Scope,
};

struct K8sClient {
    backend: Box<dyn SecretsBackend>,
    key_provider: Box<dyn KeyProvider>,
}

impl K8sClient {
    async fn new() -> Result<Self> {
        let components = build_backend().await?;
        Ok(Self {
            backend: components.backend,
            key_provider: components.key_provider,
        })
    }

    fn uri_for(&self, key: &str) -> SecretUri {
        let safe = key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>();
        let scope = Scope::new("int", "k8s", None).unwrap();
        SecretUri::new(scope, "conformance", safe).unwrap()
    }

    fn record(&self, uri: SecretUri, value: Vec<u8>) -> SecretRecord {
        let meta = SecretMeta::new(uri, Visibility::Tenant, ContentType::Text);
        let algo = EncryptionAlgorithm::Aes256Gcm;
        let nonce = vec![0; algo.nonce_len()];
        let hkdf_salt = Vec::new();
        let wrapped_dek = self
            .key_provider
            .wrap_dek(meta.scope(), b"conformance-dek")
            .unwrap();
        let envelope = Envelope {
            algorithm: algo,
            nonce,
            hkdf_salt,
            wrapped_dek,
        };
        SecretRecord::new(meta, value, envelope)
    }
}

#[async_trait]
impl ProviderUnderTest for K8sClient {
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

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let scope = Scope::new("int", "k8s", None).unwrap();
        let items = self.backend.list(&scope, Some("conformance"), None)?;
        Ok(items
            .into_iter()
            .map(|item| item.uri.to_string())
            .filter(|uri| uri.contains(prefix))
            .collect())
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "integration test; requires GREENTIC_INTEGRATION=1"]
async fn conformance_k8s() -> Result<()> {
    if std::env::var("GREENTIC_INTEGRATION").unwrap_or_default() != "1" {
        eprintln!("GREENTIC_INTEGRATION=1 not set; skipping conformance");
        return Ok(());
    }
    let client = K8sClient::new().await?;
    ConformanceSuite::new("k8s", &client, Capabilities { list: true })
        .run()
        .await
}
