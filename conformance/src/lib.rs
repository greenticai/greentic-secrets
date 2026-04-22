mod util;

use anyhow::Result;
use uuid::Uuid;

pub async fn run() -> Result<()> {
    let raw_prefix = std::env::var("GTS_PREFIX").unwrap_or_else(|_| {
        let id = Uuid::new_v4().simple();
        format!("gtconf-{id}")
    });
    let base_prefix = suite::sanitize(&raw_prefix);

    #[cfg(feature = "provider-dev")]
    suite::run_dev(&base_prefix).await?;

    #[cfg(feature = "provider-aws")]
    suite::run_aws(&base_prefix).await?;

    #[cfg(feature = "provider-azure")]
    {
        match suite::azure_preflight(&base_prefix).await {
            suite::AzurePreflight::Ready(info) => {
                info.log();
                suite::run_azure(&base_prefix).await?;
            }
            suite::AzurePreflight::Skipped { reason } => {
                if suite::must_run("AZURE") {
                    return Err(anyhow::anyhow!(reason));
                }
                println!("Azure suite skipped: {reason}");
            }
        }
    }

    #[cfg(feature = "provider-gcp")]
    suite::run_gcp(&base_prefix).await?;

    #[cfg(feature = "provider-k8s")]
    suite::run_k8s(&base_prefix).await?;

    #[cfg(feature = "provider-vault")]
    suite::run_vault(&base_prefix).await?;

    #[cfg(not(any(
        feature = "provider-dev",
        feature = "provider-aws",
        feature = "provider-azure",
        feature = "provider-gcp",
        feature = "provider-k8s",
        feature = "provider-vault"
    )))]
    {
        let _ = base_prefix;
    }

    Ok(())
}

mod suite {
    use anyhow::{Result, anyhow};
    use greentic_secrets_spec::{
        ContentType, EncryptionAlgorithm, Envelope, KeyProvider, SecretMeta, SecretRecord,
        SecretUri, SecretsBackend, SecretsResult, Visibility,
    };
    #[cfg(feature = "provider-azure")]
    use reqwest::StatusCode;
    #[cfg(feature = "provider-azure")]
    use serde::Deserialize;
    use std::env;
    #[cfg(feature = "provider-azure")]
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};
    #[cfg(feature = "provider-azure")]
    use time::OffsetDateTime;
    use tokio::task;

    const CATEGORY: &str = "conformance";

    #[cfg(feature = "provider-azure")]
    pub(super) enum AzurePreflight {
        Ready(AzurePreflightInfo),
        Skipped { reason: String },
    }

    #[cfg(feature = "provider-azure")]
    pub(super) struct AzurePreflightInfo {
        scope: String,
        vault_url: String,
        expires_in: Duration,
    }

    #[cfg(feature = "provider-azure")]
    impl AzurePreflightInfo {
        pub(super) fn log(&self) {
            println!(
                "Azure KV preflight successful: vault_url={}, scope={}, token_expires_in={}s",
                self.vault_url,
                self.scope,
                self.expires_in.as_secs()
            );
        }
    }

    #[cfg(feature = "provider-azure")]
    pub(super) async fn azure_preflight(base_prefix: &str) -> AzurePreflight {
        match AzureCredentials::gather() {
            Err(reason) => AzurePreflight::Skipped { reason },
            Ok(creds) => match fetch_access_token(&creds).await {
                Ok(auth) => match ensure_wrap_key(&auth, base_prefix).await {
                    Ok(key_name) => {
                        // Propagate the key name and bearer token for provider setup.
                        unsafe {
                            std::env::set_var("GREENTIC_AZURE_KEY_NAME", &key_name);
                            std::env::set_var("GREENTIC_AZURE_BEARER_TOKEN", &auth.bearer);
                            std::env::set_var("AZURE_KEYVAULT_BEARER_TOKEN", &auth.bearer);
                        }
                        AzurePreflight::Ready(AzurePreflightInfo {
                            scope: auth.scope.clone(),
                            vault_url: auth.vault_url.clone(),
                            expires_in: auth.expires_in,
                        })
                    }
                    Err(reason) => AzurePreflight::Skipped { reason },
                },
                Err(reason) => AzurePreflight::Skipped { reason },
            },
        }
    }

    #[cfg(feature = "provider-azure")]
    struct AzureCredentials {
        scope: String,
        vault_url: String,
        mode: AzureAuthMode,
    }

    #[cfg(feature = "provider-azure")]
    enum AzureAuthMode {
        ClientSecret {
            tenant_id: String,
            client_id: String,
            client_secret: String,
        },
        Default,
    }

    #[cfg(feature = "provider-azure")]
    impl AzureCredentials {
        fn gather() -> Result<Self, String> {
            let mut missing = Vec::new();
            let mut diagnostics = Vec::new();

            let client_secret = env::var("AZURE_CLIENT_SECRET")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            let mode = if let Some(secret) = client_secret {
                let tenant_id = match env::var("AZURE_TENANT_ID") {
                    Ok(value) if !value.trim().is_empty() => value,
                    other => {
                        missing.push("AZURE_TENANT_ID");
                        diagnostics.push(format!("AZURE_TENANT_ID resolved to {:?}", other));
                        String::new()
                    }
                };

                let client_id = match env::var("AZURE_CLIENT_ID") {
                    Ok(value) if !value.trim().is_empty() => value,
                    other => {
                        missing.push("AZURE_CLIENT_ID");
                        diagnostics.push(format!("AZURE_CLIENT_ID resolved to {:?}", other));
                        String::new()
                    }
                };
                AzureAuthMode::ClientSecret {
                    tenant_id,
                    client_id,
                    client_secret: secret,
                }
            } else {
                AzureAuthMode::Default
            };

            let vault_url = match env::var("AZURE_KEYVAULT_URL")
                .or_else(|_| env::var("AZURE_KEYVAULT_URI"))
                .or_else(|_| env::var("GREENTIC_AZURE_VAULT_URI"))
            {
                Ok(value) if !value.trim().is_empty() => value,
                other => {
                    missing.push("AZURE_KEYVAULT_URL");
                    diagnostics.push(format!("AZURE_KEYVAULT_URL resolved to {:?}", other));
                    String::new()
                }
            };

            if !missing.is_empty() {
                let mut message = format!(
                    "Azure suite skipped: missing env vars {}",
                    missing.join(", ")
                );
                if !diagnostics.is_empty() {
                    message.push_str("; detail: ");
                    message.push_str(&diagnostics.join("; "));
                }
                return Err(message);
            }

            let scope = env::var("AZURE_KV_SCOPE")
                .unwrap_or_else(|_| "https://vault.azure.net/.default".to_string());

            Ok(Self {
                scope,
                vault_url,
                mode,
            })
        }
    }

    #[cfg(feature = "provider-azure")]
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct TokenCheckResponse {
        access_token: String,
        #[serde(default)]
        expires_in: Option<u64>,
    }

    #[cfg(feature = "provider-azure")]
    struct AzureAuthResult {
        scope: String,
        vault_url: String,
        expires_in: Duration,
        bearer: String,
    }

    #[cfg(feature = "provider-azure")]
    async fn ensure_wrap_key(auth: &AzureAuthResult, base_prefix: &str) -> Result<String, String> {
        if let Ok(existing) = std::env::var("GREENTIC_AZURE_KEY_NAME")
            && !existing.trim().is_empty()
        {
            return Ok(existing);
        }

        let default_name = sanitize(&format!("{base_prefix}-wrap"));
        let base_url = auth.vault_url.trim_end_matches('/');
        let create_url = format!("{base_url}/keys/{}/create?api-version=7.4", default_name);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|err| format!("Azure suite skipped: failed to build http client: {err}"))?;

        let payload = serde_json::json!({
            "kty": "RSA",
            "key_size": 2048
        });

        let response = client
            .post(&create_url)
            .bearer_auth(&auth.bearer)
            .json(&payload)
            .send()
            .await
            .map_err(|err| format!("Azure suite skipped: failed to create wrap key: {err}"))?;

        let status = response.status();
        if status.is_success() || status == StatusCode::CONFLICT {
            return Ok(default_name);
        }

        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<body unavailable>".into());
        Err(format!(
            "Azure suite skipped: failed to ensure wrap key. status={status}, body={body}. \
             Provide GREENTIC_AZURE_KEY_NAME or grant keys/create permission."
        ))
    }

    #[cfg(feature = "provider-azure")]
    async fn fetch_access_token(creds: &AzureCredentials) -> Result<AzureAuthResult, String> {
        match &creds.mode {
            AzureAuthMode::ClientSecret {
                tenant_id,
                client_id,
                client_secret,
            } => {
                let token_url = format!(
                    "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                    tenant_id
                );
                let params = [
                    ("client_id", client_id.as_str()),
                    ("client_secret", client_secret.as_str()),
                    ("scope", creds.scope.as_str()),
                    ("grant_type", "client_credentials"),
                ];

                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|err| format!("failed to build http client: {err}"))?;

                let response = client
                    .post(&token_url)
                    .form(&params)
                    .send()
                    .await
                    .map_err(|err| format!("token request failed: {err}"))?;

                let status = response.status();
                let raw_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<body unavailable>".into());

                if status != StatusCode::OK {
                    return Err(format!(
                        "Azure suite skipped: token endpoint returned {status}. body={raw_body}"
                    ));
                }

                let payload: TokenCheckResponse =
                serde_json::from_str(&raw_body).map_err(|err| {
                    format!(
                        "Azure suite skipped: failed to parse token response: {err}. raw_body={raw_body}"
                    )
                })?;

                let expires = payload.expires_in.unwrap_or(3600);

                Ok(AzureAuthResult {
                    scope: creds.scope.clone(),
                    vault_url: creds.vault_url.clone(),
                    expires_in: Duration::from_secs(expires.max(60)),
                    bearer: format!("Bearer {}", payload.access_token),
                })
            }
            AzureAuthMode::Default => {
                use azure_core::credentials::TokenCredential;

                let credential =
                    azure_identity::DeveloperToolsCredential::new(None).map_err(|err| {
                        format!(
                            "Azure suite skipped: failed to build developer tools credential: {err}"
                        )
                    })?;
                let token = credential
                    .get_token(&[creds.scope.as_str()], None)
                    .await
                    .map_err(|err| {
                        format!(
                            "Azure suite skipped: failed to acquire token via developer tools credential: {err}"
                        )
                    })?;
                let expires = token.expires_on;
                let now = OffsetDateTime::now_utc();
                let remaining = expires - now;
                let expires_in = remaining.whole_seconds().max(3600);

                Ok(AzureAuthResult {
                    scope: creds.scope.clone(),
                    vault_url: creds.vault_url.clone(),
                    expires_in: Duration::from_secs(expires_in.max(60) as u64),
                    bearer: format!("Bearer {}", token.token.secret()),
                })
            }
        }
    }

    pub(super) fn sanitize(value: &str) -> String {
        let mut out = String::new();
        for ch in value.chars() {
            match ch {
                'a'..='z' | '0'..='9' | '-' | '_' | '.' => out.push(ch),
                'A'..='Z' => out.push(ch.to_ascii_lowercase()),
                _ => out.push('-'),
            }
        }
        if out.is_empty() {
            "default".into()
        } else {
            out
        }
    }

    fn combine_tag(base: &str, provider: &str) -> String {
        sanitize(&format!("{base}-{provider}"))
    }

    fn make_scope(tag: &str) -> SecretsResult<greentic_secrets_spec::Scope> {
        greentic_secrets_spec::Scope::new(
            sanitize(&format!("{tag}-env")),
            sanitize(&format!("{tag}-tenant")),
            Some(sanitize(&format!("{tag}-team"))),
        )
    }

    fn make_uri(scope: &greentic_secrets_spec::Scope, tag: &str) -> SecretsResult<SecretUri> {
        SecretUri::new(scope.clone(), CATEGORY, sanitize(&format!("{tag}-secret")))
    }

    fn make_payload(tag: &str) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("payload::{tag}::{ts}")
    }

    fn build_record(uri: SecretUri, value: &str) -> SecretRecord {
        let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Opaque);
        meta.description = Some("conformance test secret".into());
        let envelope = Envelope {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![0u8; 12],
            hkdf_salt: vec![1u8; 16],
            wrapped_dek: vec![2u8; 32],
        };
        SecretRecord::new(meta, value.as_bytes().to_vec(), envelope)
    }

    fn convert<T>(res: SecretsResult<T>) -> Result<T> {
        res.map_err(anyhow::Error::from)
    }

    struct Cleanup {
        backend: Box<dyn SecretsBackend>,
        uri: SecretUri,
        delete_on_drop: bool,
    }

    impl Cleanup {
        fn new(backend: Box<dyn SecretsBackend>, uri: SecretUri) -> Self {
            Self {
                backend,
                uri,
                delete_on_drop: true,
            }
        }

        fn backend_mut(&mut self) -> &mut dyn SecretsBackend {
            &mut *self.backend
        }

        fn disarm(&mut self) {
            self.delete_on_drop = false;
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            if self.delete_on_drop {
                let _ = self.backend.delete(&self.uri);
            }
        }
    }

    #[allow(dead_code)]
    fn run_cycle(
        backend: Box<dyn SecretsBackend>,
        scope: greentic_secrets_spec::Scope,
        uri: SecretUri,
        payload: String,
    ) -> Result<()> {
        let mut cleanup = Cleanup::new(backend, uri.clone());
        let backend = cleanup.backend_mut();

        let record = build_record(uri.clone(), &payload);
        let put = convert(backend.put(record.clone()))?;
        assert!(put.version >= 1, "put should return a positive version");

        let fetched =
            convert(backend.get(&uri, None))?.expect("secret should exist immediately after put");
        let fetched_record = fetched
            .record()
            .expect("versioned secret must include record");
        assert_eq!(fetched_record.value, record.value);

        let listed = convert(backend.list(&scope, Some(CATEGORY), None))?;
        assert!(listed.iter().any(|item| item.uri == uri));

        let versions = convert(backend.versions(&uri))?;
        assert!(
            versions
                .iter()
                .any(|v| v.version == put.version && !v.deleted)
        );
        assert!(convert(backend.exists(&uri))?);

        let deleted = convert(backend.delete(&uri))?;
        assert!(deleted.deleted);

        assert!(convert(backend.get(&uri, None))?.is_none());
        assert!(!convert(backend.exists(&uri))?);

        let versions_after = convert(backend.versions(&uri))?;
        assert!(versions_after.iter().any(|v| v.deleted));

        let listed_after = convert(backend.list(&scope, Some(CATEGORY), None))?;
        assert!(listed_after.iter().all(|item| item.uri != uri));

        cleanup.disarm();
        Ok(())
    }

    #[cfg(feature = "provider-dev")]
    pub(super) async fn run_dev(base: &str) -> Result<()> {
        use greentic_secrets_provider_dev::DevBackend;

        let tag = combine_tag(base, "dev");
        let scope = convert(make_scope(&tag))?;
        let uri = convert(make_uri(&scope, &tag))?;
        let payload = make_payload(&tag);
        let backend: Box<dyn SecretsBackend> = Box::new(DevBackend::new());
        run_cycle(backend, scope, uri, payload)
    }

    #[cfg(feature = "provider-aws")]
    pub(super) async fn run_aws(base: &str) -> Result<()> {
        use greentic_secrets_provider_aws_sm::{BackendComponents, build_backend};

        run_provider_async(base, "aws", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            Ok((backend, Some(key_provider)))
        })
        .await
    }

    #[cfg(feature = "provider-azure")]
    pub(super) async fn run_azure(base: &str) -> Result<()> {
        use greentic_secrets_provider_azure_kv::{BackendComponents, build_backend};

        run_provider_async(base, "azure", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            Ok((backend, Some(key_provider)))
        })
        .await
    }

    #[cfg(feature = "provider-gcp")]
    pub(super) async fn run_gcp(base: &str) -> Result<()> {
        use greentic_secrets_provider_gcp_sm::{BackendComponents, build_backend};

        run_provider_async(base, "gcp", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            Ok((backend, Some(key_provider)))
        })
        .await
    }

    #[cfg(feature = "provider-k8s")]
    pub(super) async fn run_k8s(base: &str) -> Result<()> {
        use greentic_secrets_provider_k8s::{BackendComponents, build_backend};

        run_provider_async(base, "k8s", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            Ok((backend, Some(key_provider)))
        })
        .await
    }

    #[cfg(feature = "provider-vault")]
    pub(super) async fn run_vault(base: &str) -> Result<()> {
        use greentic_secrets_provider_vault_kv::{BackendComponents, build_backend};

        run_provider_async(base, "vault", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            Ok((backend, Some(key_provider)))
        })
        .await
    }

    #[allow(dead_code)]
    async fn run_provider_async<B, Fut>(base: &str, provider: &str, builder: B) -> Result<()>
    where
        B: Send + 'static + FnOnce() -> Fut,
        Fut: std::future::Future<
                Output = Result<(Box<dyn SecretsBackend>, Option<Box<dyn KeyProvider>>)>,
            > + Send
            + 'static,
    {
        let tag = combine_tag(base, provider);
        let scope = convert(make_scope(&tag))?;
        let uri = convert(make_uri(&scope, &tag))?;
        let payload = make_payload(&tag);

        let (backend, key_provider) = builder().await?;

        task::spawn_blocking(move || {
            let result = run_cycle(backend, scope, uri, payload);
            drop(key_provider);
            result
        })
        .await
        .map_err(|err| anyhow!("provider task panicked: {err}"))??;

        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn must_run(provider: &str) -> bool {
        let key = format!("GREENTIC_REQUIRE_{}", provider.to_ascii_uppercase());
        env::var(key)
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false)
    }
}
