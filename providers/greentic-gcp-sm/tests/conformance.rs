#![cfg(feature = "integration")]

use anyhow::{Context, Result};
use async_trait::async_trait;
use secrets_provider_gcp_sm::build_backend;
use secrets_provider_tests::{Capabilities, ConformanceSuite, ProviderUnderTest, TestEnv};

use greentic_secrets_spec::{
    ContentType, EncryptionAlgorithm, Envelope, KeyProvider, SecretMeta, SecretRecord, SecretUri,
    SecretsBackend, Visibility, types::Scope,
};

struct GcpClient {
    backend: Box<dyn SecretsBackend>,
    key_provider: Box<dyn KeyProvider>,
    prefix: String,
}

impl GcpClient {
    async fn new(env: &TestEnv) -> Result<Self> {
        let prefix = env.prefix.base();
        unsafe {
            std::env::set_var("GREENTIC_GCP_SECRET_PREFIX", &prefix);
        }
        let components = build_backend().await?;
        Ok(Self {
            backend: components.backend,
            key_provider: components.key_provider,
            prefix,
        })
    }

    fn uri_for(&self, key: &str) -> SecretUri {
        let safe = format!("{}/{}", self.prefix, key).replace('/', "-");
        let scope = Scope::new("int", "gcp", None).unwrap();
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
impl ProviderUnderTest for GcpClient {
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
async fn conformance_gcp() -> Result<()> {
    if std::env::var("GREENTIC_INTEGRATION").unwrap_or_default() != "1" {
        eprintln!("GREENTIC_INTEGRATION=1 not set; skipping conformance");
        return Ok(());
    }
    let env = TestEnv::from_env("gcp");
    let project = std::env::var("GCP_PROJECT_ID")
        .or_else(|_| std::env::var("GCP_PROJECT"))
        .context("GCP_PROJECT_ID or GCP_PROJECT required")?;
    unsafe {
        std::env::set_var("GREENTIC_GCP_PROJECT", project);
    }
    let client = GcpClient::new(&env).await?;
    ConformanceSuite::new("gcp", &client, Capabilities::default())
        .run()
        .await
}
