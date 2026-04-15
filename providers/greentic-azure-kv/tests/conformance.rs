#![cfg(feature = "integration")]

use anyhow::Result;
use async_trait::async_trait;
use azure_core::auth::TokenCredential;
use azure_identity::{DefaultAzureCredential, TokenCredentialOptions};
use secrets_provider_azure_kv::build_backend;
use secrets_provider_tests::{Capabilities, ConformanceSuite, ProviderUnderTest, TestEnv};

use greentic_secrets_spec::{
    ContentType, EncryptionAlgorithm, Envelope, SecretMeta, SecretRecord, SecretUri, Visibility,
    types::Scope,
};

struct AzureClient {
    backend: Box<dyn greentic_secrets_spec::SecretsBackend>,
    key_provider: Box<dyn greentic_secrets_spec::KeyProvider>,
    prefix: String,
}

impl AzureClient {
    async fn new(env: &TestEnv) -> Result<Self> {
        let prefix = sanitize_prefix(&env.prefix.base());
        // Safe: setting process env for test prefix isolation.
        unsafe {
            std::env::set_var("GREENTIC_AZURE_SECRET_PREFIX", &prefix);
        }
        ensure_bearer_token().await?;
        let components = build_backend().await?;
        Ok(Self {
            backend: components.backend,
            key_provider: components.key_provider,
            prefix,
        })
    }

    fn uri_for(&self, key: &str) -> SecretUri {
        let sanitized = sanitize_key(&format!("{}/{}", self.prefix, key));
        let scope = Scope::new("int", "azure", None).unwrap();
        SecretUri::new(scope, "conformance", sanitized).unwrap()
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

fn sanitize_prefix(raw: &str) -> String {
    let mut out = raw
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>();
    if out.len() > 60 {
        out.truncate(60);
    }
    out.trim_matches('-').to_string()
}

fn sanitize_key(raw: &str) -> String {
    sanitize_prefix(raw)
}

async fn ensure_bearer_token() -> Result<()> {
    if std::env::var("GREENTIC_AZURE_BEARER_TOKEN")
        .or_else(|_| std::env::var("AZURE_KEYVAULT_BEARER_TOKEN"))
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return Ok(());
    }

    let credential: Box<dyn TokenCredential> = Box::new(DefaultAzureCredential::create(
        TokenCredentialOptions::default(),
    )?);

    let token = credential
        .get_token(&["https://vault.azure.net/.default"])
        .await?;
    let header = format!("Bearer {}", token.token.secret());
    // Safe: setting process env for test credential forwarding.
    unsafe {
        std::env::set_var("AZURE_KEYVAULT_BEARER_TOKEN", &header);
        std::env::set_var("GREENTIC_AZURE_BEARER_TOKEN", &header);
    }
    Ok(())
}

#[async_trait]
impl ProviderUnderTest for AzureClient {
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
async fn conformance_azure() -> Result<()> {
    if std::env::var("GREENTIC_INTEGRATION").unwrap_or_default() != "1" {
        eprintln!("GREENTIC_INTEGRATION=1 not set; skipping conformance");
        return Ok(());
    }
    let env = TestEnv::from_env("azure");
    let client = AzureClient::new(&env).await?;
    ConformanceSuite::new("azure", &client, Capabilities::default())
        .run()
        .await
}
