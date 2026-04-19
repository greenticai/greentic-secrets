#![cfg(feature = "integration")]

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::{Client as KmsClient, types::KeyUsageType};
use secrets_provider_aws_sm::build_backend;
use secrets_provider_tests::{Capabilities, ConformanceSuite, ProviderUnderTest, TestEnv};

use greentic_secrets_spec::{
    ContentType, EncryptionAlgorithm, Envelope, KeyProvider, SecretMeta, SecretRecord, SecretUri,
    SecretsBackend, Visibility, types::Scope,
};

struct AwsClient {
    backend: Box<dyn SecretsBackend>,
    key_provider: Box<dyn KeyProvider>,
}

impl AwsClient {
    async fn new(env: &TestEnv) -> Result<Self> {
        set_prefix_env(env);
        ensure_kms_key().await?;
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
        let scope = Scope::new("int", "aws", None).unwrap();
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
impl ProviderUnderTest for AwsClient {
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

fn set_prefix_env(env: &TestEnv) {
    unsafe {
        std::env::set_var("GREENTIC_AWS_SECRET_PREFIX", env.prefix.base());
    }
}

async fn ensure_kms_key() -> Result<()> {
    if std::env::var("GREENTIC_AWS_KMS_KEY_ID").is_ok() {
        return Ok(());
    }
    if std::env::var("GREENTIC_AWS_SM_ENDPOINT").is_err()
        && std::env::var("AWS_ENDPOINT_URL").is_err()
    {
        anyhow::bail!("GREENTIC_AWS_KMS_KEY_ID must be set for real AWS runs");
    }

    let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let kms = KmsClient::new(&shared);
    let key = kms
        .create_key()
        .key_usage(KeyUsageType::EncryptDecrypt)
        .send()
        .await
        .context("failed to create KMS key (localstack)")?;
    let key_id = key
        .key_metadata()
        .map(|meta| meta.key_id().to_string())
        .context("missing key id from kms create")?;
    unsafe {
        std::env::set_var("GREENTIC_AWS_KMS_KEY_ID", key_id);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "integration test; requires GREENTIC_INTEGRATION=1"]
async fn conformance_aws() -> Result<()> {
    if std::env::var("GREENTIC_INTEGRATION").unwrap_or_default() != "1" {
        eprintln!("GREENTIC_INTEGRATION=1 not set; skipping conformance");
        return Ok(());
    }
    let env = TestEnv::from_env("aws");
    let client = AwsClient::new(&env).await?;
    ConformanceSuite::new("aws", &client, Capabilities::default())
        .run()
        .await
}
