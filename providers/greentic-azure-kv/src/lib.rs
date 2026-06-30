//! Azure Key Vault provider backed by the live REST APIs.
//!
//! Secrets are stored as JSON-encoded [`SecretRecord`] values inside Key Vault
//! secrets, while Data Encryption Keys (DEKs) are wrapped and unwrapped via
//! the configured Key Vault key. Authentication uses the OAuth2 client
//! credentials flow with values supplied through environment variables.

mod auth;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use greentic_secrets_core::{
    http::{Http, HttpBuilder, HttpResponse},
    rt,
};
use greentic_secrets_spec::{
    KeyProvider, Scope, SecretListItem, SecretRecord, SecretUri, SecretVersion, SecretsBackend,
    SecretsError, SecretsResult, VersionedSecret,
};
use reqwest::{
    Client, Method, StatusCode,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

use auth::{AuthError, KvAuthConfig, request_access_token};

const SECRETS_API_VERSION: &str = "7.4";
const KEYS_API_VERSION: &str = "7.4";
const DEFAULT_PREFIX: &str = "greentic";
const DEFAULT_TIMEOUT_SECS: u64 = 15;

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the Azure Key Vault backend using environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = Arc::new(AzureProviderConfig::from_env()?);
    let http = config.build_kv_http()?;
    let auth_client = config.build_auth_client()?;
    let auth = Arc::new(AzureAuth::new(&config, auth_client));

    let backend = AzureSecretsBackend::new(config.clone(), http.clone(), auth.clone());
    let key_provider = AzureKmsKeyProvider::new(config, http, auth);

    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
struct AzureProviderConfig {
    vault_uri: String,
    secret_prefix: String,
    key_name: String,
    key_algorithm: String,
    http_timeout: Duration,
    auth_mode: AzureAuthMode,
    tls_insecure_skip_verify: bool,
    proxy_url: Option<Url>,
}

#[derive(Clone)]
enum AzureAuthMode {
    ClientCredentials { config: KvAuthConfig },
    StaticToken { bearer: String },
}

fn uri_uses_loopback_host(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    lower.contains("127.0.0.1")
        || lower.contains("localhost")
        || lower.contains("[::1]")
        || lower.contains("::1")
}

impl AzureProviderConfig {
    fn from_env() -> Result<Self> {
        let vault_uri = env::var("AZURE_KEYVAULT_URL")
            .or_else(|_| env::var("AZURE_KEYVAULT_URI"))
            .or_else(|_| env::var("GREENTIC_AZURE_VAULT_URI"))
            .context(
                "set AZURE_KEYVAULT_URL (or AZURE_KEYVAULT_URI / GREENTIC_AZURE_VAULT_URI) with your Key Vault URL",
            )?;
        let mut static_token = env::var("GREENTIC_AZURE_BEARER_TOKEN")
            .or_else(|_| env::var("AZURE_KEYVAULT_BEARER_TOKEN"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        if static_token.is_none() && uri_uses_loopback_host(&vault_uri) {
            static_token = Some("emulator".to_string());
        }

        let tls_insecure_skip_verify = env::var("AZURE_KEYVAULT_INSECURE_SKIP_VERIFY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false);

        if tls_insecure_skip_verify {
            bail!("AZURE_KEYVAULT_INSECURE_SKIP_VERIFY is not permitted");
        }

        let auth_mode = if let Some(token) = static_token {
            AzureAuthMode::StaticToken { bearer: token }
        } else {
            let config = KvAuthConfig::from_env().context(
                "set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET to enable Azure Key Vault authentication",
            )?;
            AzureAuthMode::ClientCredentials { config }
        };

        let key_name = env::var("GREENTIC_AZURE_KEY_NAME")
            .context("set GREENTIC_AZURE_KEY_NAME with the Key Vault key to wrap DEKs")?;

        let key_algorithm = env::var("GREENTIC_AZURE_KEY_ALGORITHM")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "RSA-OAEP".to_string());

        let secret_prefix = env::var("GREENTIC_AZURE_SECRET_PREFIX")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_PREFIX.to_string());

        let timeout = env::var("GREENTIC_AZURE_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|secs| {
                if secs == 0 {
                    None
                } else {
                    Some(Duration::from_secs(secs))
                }
            })
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        let proxy_url = env::var("GREENTIC_AZURE_PROXY_URL")
            .or_else(|_| env::var("AZURE_KEYVAULT_PROXY_URL"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(|value| Url::parse(&value).context("invalid Azure proxy URL"))
            .transpose()?;

        Ok(Self {
            vault_uri: vault_uri.trim_end_matches('/').to_string(),
            secret_prefix,
            key_name,
            key_algorithm,
            http_timeout: timeout,
            auth_mode,
            tls_insecure_skip_verify,
            proxy_url,
        })
    }

    fn secrets_endpoint(&self) -> String {
        format!("{uri}/secrets", uri = self.vault_uri)
    }

    fn keys_endpoint(&self) -> String {
        format!("{uri}/keys", uri = self.vault_uri)
    }

    fn build_kv_http(&self) -> Result<Http> {
        let builder = self.base_http_builder();
        builder.build()
    }

    fn build_auth_client(&self) -> Result<Client> {
        let http = self.base_http_builder().build()?;
        Ok(http.client().clone())
    }

    fn base_http_builder(&self) -> HttpBuilder {
        let mut builder = Http::builder()
            .timeout(self.http_timeout)
            .insecure_tls(self.tls_insecure_skip_verify);
        if let Some(proxy) = self.proxy_url.clone() {
            builder = builder.proxy(Some(proxy));
        }
        builder
    }
}

#[derive(Clone)]
struct AzureSecretsBackend {
    config: Arc<AzureProviderConfig>,
    http: Http,
    auth: Arc<AzureAuth>,
}

impl AzureSecretsBackend {
    fn new(config: Arc<AzureProviderConfig>, http: Http, auth: Arc<AzureAuth>) -> Self {
        Self { config, http, auth }
    }

    fn secret_name(&self, uri: &SecretUri) -> String {
        runtime_secret_name(&self.config.secret_prefix, uri)
    }

    /// Pre-fix name for `uri`, used only as a read-fallback so secrets written
    /// before the collision fix stay resolvable. Never written to. See #101.
    fn legacy_secret_name(&self, uri: &SecretUri) -> String {
        legacy_runtime_secret_name(&self.config.secret_prefix, uri)
    }

    /// Versions stored under the legacy name that are attributable to `uri`.
    ///
    /// The legacy name can be shared by colliding URIs (the bug this fix
    /// removes), so a non-empty legacy object does NOT imply the data is
    /// `uri`'s. If any record under it names a different URI we ignore the whole
    /// object: serving or extending it would re-introduce the collision. Reads
    /// then see the secret as absent under the (now collision-free) new name,
    /// so it can be re-provisioned safely. Returns empty when there is no legacy
    /// name distinct from the new name or no attributable history.
    fn legacy_versions_for(&self, uri: &SecretUri) -> SecretsResult<Vec<StoredSecret>> {
        let legacy = self.legacy_secret_name(uri);
        if legacy == self.secret_name(uri) {
            return Ok(Vec::new());
        }
        let versions = self.load_all_versions(&legacy)?;
        if versions.is_empty() {
            return Ok(Vec::new());
        }
        if !legacy_history_attributable_to(&versions, uri) {
            tracing::warn!(
                uri = %uri,
                legacy = %legacy,
                "legacy Key Vault name is shared by colliding URIs; ignoring legacy history for this URI"
            );
            return Ok(Vec::new());
        }
        Ok(versions)
    }

    /// Full version history for `uri`: collision-safe-name versions plus any
    /// attributable legacy-name versions. New writes always target the
    /// collision-safe name and continue numbering above the legacy max, so the
    /// two histories never overlap and the secret is migrated forward on write.
    fn collect_versions(&self, uri: &SecretUri) -> SecretsResult<Vec<StoredSecret>> {
        let mut versions = self.load_all_versions(&self.secret_name(uri))?;
        versions.extend(self.legacy_versions_for(uri)?);
        versions.sort_by_key(|entry| entry.version);
        Ok(versions)
    }

    fn send(
        &self,
        method: Method,
        url: String,
        body: Option<Value>,
    ) -> SecretsResult<HttpResponse> {
        azure_request(
            &self.http,
            &self.auth,
            self.config.as_ref(),
            method,
            url,
            body,
        )
    }

    fn set_secret(&self, name: &str, payload: &StoredSecret) -> SecretsResult<()> {
        let url = format!(
            "{}/{}?api-version={}",
            self.config.secrets_endpoint(),
            name,
            SECRETS_API_VERSION
        );
        let encoded = encode_secret(payload)?;
        let body = json!({ "value": STANDARD.encode(encoded) });
        let response = self.send(Method::PUT, url, Some(body))?;
        let status = response.status();
        let body = response.text().map_err(|err| {
            SecretsError::Storage(format!("failed to read set-secret response: {err}"))
        })?;
        if !status.is_success() {
            return Err(SecretsError::Storage(format!(
                "set secret failed: {status} {body}"
            )));
        }
        Ok(())
    }

    fn get_latest(&self, name: &str) -> SecretsResult<Option<StoredSecret>> {
        let url = format!(
            "{}/{}?api-version={}",
            self.config.secrets_endpoint(),
            name,
            SECRETS_API_VERSION
        );
        let response = self.send(Method::GET, url, None)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => {
                let body = response.text().map_err(|err| {
                    SecretsError::Storage(format!("failed to read secret body: {err}"))
                })?;
                parse_secret_bundle(&body)
            }
            status => {
                let body = response.text().map_err(|err| {
                    SecretsError::Storage(format!("failed to read error body: {err}"))
                })?;
                Err(SecretsError::Storage(format!(
                    "get secret failed: {status} {body}"
                )))
            }
        }
    }

    fn get_version(&self, name: &str, version_id: &str) -> SecretsResult<Option<StoredSecret>> {
        let url = format!(
            "{}/{}/{}?api-version={}",
            self.config.secrets_endpoint(),
            name,
            version_id,
            SECRETS_API_VERSION
        );
        let response = self.send(Method::GET, url, None)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => {
                let body = response.text().map_err(|err| {
                    SecretsError::Storage(format!("failed to read secret version body: {err}"))
                })?;
                parse_secret_bundle(&body)
            }
            status => {
                let body = response.text().map_err(|err| {
                    SecretsError::Storage(format!("failed to read error body: {err}"))
                })?;
                Err(SecretsError::Storage(format!(
                    "get secret version failed: {status} {body}"
                )))
            }
        }
    }

    fn list_version_ids(&self, name: &str) -> SecretsResult<Vec<String>> {
        let mut url = format!(
            "{}/{}/versions?api-version={}",
            self.config.secrets_endpoint(),
            name,
            SECRETS_API_VERSION
        );
        let mut collected = Vec::new();

        loop {
            let response = self.send(Method::GET, url.clone(), None)?;
            match response.status() {
                StatusCode::NOT_FOUND => return Ok(Vec::new()),
                status if status.is_success() => {
                    let body = response.text().map_err(|err| {
                        SecretsError::Storage(format!("failed to read secret versions body: {err}"))
                    })?;
                    let parsed: SecretVersionListResponse =
                        serde_json::from_str(&body).map_err(|err| {
                            SecretsError::Storage(format!(
                                "failed to parse secret versions list: {err}; body={body}"
                            ))
                        })?;

                    if let Some(entries) = parsed.value {
                        for entry in entries {
                            if let Some(id) = extract_version_segment(&entry.id) {
                                collected.push(id.to_string());
                            }
                        }
                    }

                    if let Some(next) = parsed.next_link {
                        url = next;
                        continue;
                    }
                    break;
                }
                status => {
                    let body = response.text().map_err(|err| {
                        SecretsError::Storage(format!("failed to read error body: {err}"))
                    })?;
                    return Err(SecretsError::Storage(format!(
                        "list secret versions failed: {status} {body}"
                    )));
                }
            }
        }

        Ok(collected)
    }

    fn load_all_versions(&self, name: &str) -> SecretsResult<Vec<StoredSecret>> {
        let mut versions = Vec::new();
        let ids = self.list_version_ids(name)?;
        for version_id in ids {
            if let Some(stored) = self.get_version(name, &version_id)? {
                versions.push(stored);
            }
        }
        versions.sort_by_key(|entry| entry.version);
        Ok(versions)
    }
}

impl SecretsBackend for AzureSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        // Always write the collision-safe name; never extend a (possibly
        // shared) legacy object. Version numbering continues above any
        // attributable legacy history so the merged view stays monotonic.
        let versions = self.collect_versions(&record.meta.uri)?;
        let next_version = versions
            .iter()
            .map(|entry| entry.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let stored = StoredSecret::live(next_version, record.clone());
        self.set_secret(&self.secret_name(&record.meta.uri), &stored)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> SecretsResult<Option<VersionedSecret>> {
        if let Some(requested) = version {
            return Ok(self
                .collect_versions(uri)?
                .into_iter()
                .find(|entry| entry.version == requested && !entry.deleted)
                .and_then(StoredSecret::into_versioned));
        }

        // Latest-only fast path: new writes always go to the collision-safe
        // name, so if it has any version that version is the global latest
        // (a tombstone there means deleted). Only when the new name is absent
        // do we consult the attributable legacy history.
        let name = self.secret_name(uri);
        if let Some(entry) = self.get_latest(&name)? {
            return Ok(if entry.deleted {
                None
            } else {
                entry.into_versioned()
            });
        }
        Ok(self
            .legacy_versions_for(uri)?
            .into_iter()
            .max_by_key(|entry| entry.version)
            .filter(|entry| !entry.deleted)
            .and_then(StoredSecret::into_versioned))
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        let mut items = Vec::new();
        let mut url = format!(
            "{}?api-version={}",
            self.config.secrets_endpoint(),
            SECRETS_API_VERSION
        );

        loop {
            let response = self.send(Method::GET, url.clone(), None)?;
            let status = response.status();
            let body = response.text().map_err(|err| {
                SecretsError::Storage(format!("failed to read list response: {err}"))
            })?;
            if !status.is_success() {
                return Err(SecretsError::Storage(format!(
                    "list secrets failed: {status} {body}"
                )));
            }

            let parsed: SecretListResponse = serde_json::from_str(&body).map_err(|err| {
                SecretsError::Storage(format!(
                    "failed to decode list secrets response: {err}; body={body}"
                ))
            })?;

            if let Some(secrets) = parsed.value {
                for entry in secrets {
                    let Some(secret_name) = extract_secret_name(&entry.id) else {
                        continue;
                    };

                    if !secret_name.starts_with(&self.config.secret_prefix) {
                        continue;
                    }

                    if let Some(stored) = self.get_latest(secret_name)? {
                        if stored.deleted {
                            continue;
                        }
                        if let Some(record) = stored.record {
                            if record.meta.scope().env() != scope.env()
                                || record.meta.scope().tenant() != scope.tenant()
                            {
                                continue;
                            }
                            if scope.team().is_some() && record.meta.scope().team() != scope.team()
                            {
                                continue;
                            }
                            if let Some(prefix) = category_prefix
                                && !record.meta.uri.category().starts_with(prefix)
                            {
                                continue;
                            }
                            if let Some(prefix) = name_prefix
                                && !record.meta.uri.name().starts_with(prefix)
                            {
                                continue;
                            }
                            items.push(SecretListItem::from_meta(
                                &record.meta,
                                Some(stored.version.to_string()),
                            ));
                        }
                    }
                }
            }

            if let Some(next) = parsed.next_link {
                url = next;
                continue;
            }
            break;
        }

        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> SecretsResult<SecretVersion> {
        let versions = self.collect_versions(uri)?;
        if versions.is_empty() {
            return Err(SecretsError::NotFound {
                entity: uri.to_string(),
            });
        }

        let next_version = versions
            .iter()
            .map(|entry| entry.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        // Tombstone on the collision-safe name; it shadows any legacy live
        // version because it numbers above the legacy max.
        let tombstone = StoredSecret::tombstone(next_version);
        self.set_secret(&self.secret_name(uri), &tombstone)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        Ok(self
            .collect_versions(uri)?
            .into_iter()
            .map(|entry| SecretVersion {
                version: entry.version,
                deleted: entry.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> SecretsResult<bool> {
        Ok(self.get(uri, None)?.is_some())
    }
}

struct AzureAuth {
    cache: Arc<RwLock<Option<TokenCache>>>,
    token_client: Client,
    strategy: AzureAuthStrategy,
}

#[derive(Clone)]
enum AzureAuthStrategy {
    ClientCredentials { config: KvAuthConfig },
    StaticToken { header: String },
}

impl AzureAuth {
    fn new(config: &AzureProviderConfig, token_client: Client) -> Self {
        let strategy = match &config.auth_mode {
            AzureAuthMode::ClientCredentials { config } => {
                tracing::info!(
                    "azure credential: ClientSecretCredential (tenant_id={}, scope={})",
                    config.tenant_id,
                    config.scope
                );
                AzureAuthStrategy::ClientCredentials {
                    config: config.clone(),
                }
            }
            AzureAuthMode::StaticToken { bearer } => {
                tracing::info!("azure credential: static bearer token");
                let trimmed = bearer.trim();
                let header = if trimmed.to_ascii_lowercase().starts_with("bearer ") {
                    trimmed.to_string()
                } else {
                    format!("Bearer {trimmed}")
                };
                AzureAuthStrategy::StaticToken { header }
            }
        };

        Self {
            cache: Arc::new(RwLock::new(None)),
            token_client,
            strategy,
        }
    }

    fn bearer_token(&self) -> SecretsResult<String> {
        match &self.strategy {
            AzureAuthStrategy::StaticToken { header } => Ok(header.clone()),
            AzureAuthStrategy::ClientCredentials { config } => {
                rt::sync_await(self.fetch_or_refresh(config))
            }
        }
    }

    async fn fetch_or_refresh(&self, config: &KvAuthConfig) -> SecretsResult<String> {
        {
            let guard = self.cache.read().await;
            if let Some(cache) = guard.as_ref()
                && Instant::now() < cache.expires_at
            {
                return Ok(cache.header.clone());
            }
        }

        let token = request_access_token(&self.token_client, config)
            .await
            .map_err(|err| match err {
                AuthError::Unauthorized { status, body } => SecretsError::Backend(format!(
                    "Azure AAD rejected client credentials ({status}). body={body}"
                )),
                other => SecretsError::Backend(format!("failed to request azure token: {other}")),
            })?;

        let header = format!("Bearer {}", token.token);
        let entry = TokenCache {
            header: header.clone(),
            expires_at: Instant::now() + token.expires_in,
        };
        {
            let mut guard = self.cache.write().await;
            *guard = Some(entry);
        }
        Ok(header)
    }

    fn scope_hint(&self) -> Option<&str> {
        match &self.strategy {
            AzureAuthStrategy::ClientCredentials { config } => Some(config.scope.as_str()),
            AzureAuthStrategy::StaticToken { .. } => None,
        }
    }
}

struct TokenCache {
    header: String,
    expires_at: Instant,
}

#[derive(Clone)]
struct AzureKmsKeyProvider {
    config: Arc<AzureProviderConfig>,
    http: Http,
    auth: Arc<AzureAuth>,
}

impl AzureKmsKeyProvider {
    fn new(config: Arc<AzureProviderConfig>, http: Http, auth: Arc<AzureAuth>) -> Self {
        Self { config, http, auth }
    }

    fn send(
        &self,
        method: Method,
        url: String,
        body: Option<Value>,
    ) -> SecretsResult<HttpResponse> {
        azure_request(
            &self.http,
            &self.auth,
            self.config.as_ref(),
            method,
            url,
            body,
        )
    }

    fn key_operation(&self, operation: &str, body: Value) -> SecretsResult<Value> {
        let url = format!(
            "{}/{}/{}?api-version={}",
            self.config.keys_endpoint(),
            self.config.key_name,
            operation,
            KEYS_API_VERSION
        );

        let response = self.send(Method::POST, url, Some(body))?;
        let status = response.status();
        let payload = response
            .text()
            .map_err(|err| SecretsError::Backend(format!("failed to read key response: {err}")))?;
        if !status.is_success() {
            return Err(SecretsError::Backend(format!(
                "key operation failed: {status} {payload}"
            )));
        }

        serde_json::from_str(&payload).map_err(|err| {
            SecretsError::Backend(format!(
                "failed to parse key response: {err}; body={payload}"
            ))
        })
    }
}

impl KeyProvider for AzureKmsKeyProvider {
    fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let payload = json!({
            "alg": self.config.key_algorithm,
            "value": STANDARD.encode(dek),
        });
        let response = self.key_operation("wrapkey", payload)?;
        let wrapped = response
            .get("value")
            .and_then(|value| value.as_str())
            .ok_or_else(|| SecretsError::Backend("wrapkey response missing value".into()))?;
        STANDARD
            .decode(wrapped)
            .map_err(|err| SecretsError::Backend(format!("failed to decode wrapped key: {err}")))
    }

    fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let payload = json!({
            "alg": self.config.key_algorithm,
            "value": STANDARD.encode(wrapped),
        });
        let response = self.key_operation("unwrapkey", payload)?;
        let plaintext = response
            .get("value")
            .and_then(|value| value.as_str())
            .ok_or_else(|| SecretsError::Backend("unwrapkey response missing value".into()))?;
        STANDARD
            .decode(plaintext)
            .map_err(|err| SecretsError::Backend(format!("failed to decode unwrapped key: {err}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSecret {
    version: u64,
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<SecretRecord>,
}

impl StoredSecret {
    fn live(version: u64, record: SecretRecord) -> Self {
        Self {
            version,
            deleted: false,
            record: Some(record),
        }
    }

    fn tombstone(version: u64) -> Self {
        Self {
            version,
            deleted: true,
            record: None,
        }
    }

    fn into_versioned(self) -> Option<VersionedSecret> {
        self.record.map(|record| VersionedSecret {
            version: self.version,
            deleted: self.deleted,
            record: Some(record),
        })
    }
}

fn encode_secret(payload: &StoredSecret) -> SecretsResult<Vec<u8>> {
    serde_json::to_vec(payload)
        .map_err(|err| SecretsError::Storage(format!("failed to encode secret payload: {err}")))
}

fn azure_request(
    http: &Http,
    auth: &AzureAuth,
    config: &AzureProviderConfig,
    method: Method,
    url: String,
    body: Option<Value>,
) -> SecretsResult<HttpResponse> {
    let token = auth.bearer_token()?;
    let mut request = http.request(method, &url);
    let header = HeaderValue::from_str(&token)
        .map_err(|err| SecretsError::Backend(format!("invalid authorization header: {err}")))?;
    request = request.header(AUTHORIZATION, header);
    if let Some(payload) = body {
        request = request.json(&payload);
    }

    let response = request
        .send()
        .map_err(|err| SecretsError::Storage(format!("azure request failed: {err}")))?;

    if response.status() == StatusCode::UNAUTHORIZED {
        let scope_hint = auth.scope_hint().unwrap_or("unknown");
        let body = response.text().unwrap_or_default();
        let mut hint = format!(
            "Azure Key Vault returned 401 Unauthorized. Hint: ensure AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_KEYVAULT_URL are configured. Scope used: {scope_hint}. Key Vault URL: {}.",
            config.vault_uri
        );
        hint.push_str(" Verify credentials with: az account get-access-token --scope ");
        hint.push_str(scope_hint);
        hint.push_str(". Response body: ");
        hint.push_str(&body);
        return Err(SecretsError::Backend(hint));
    }

    Ok(response)
}

fn parse_secret_bundle(body: &str) -> SecretsResult<Option<StoredSecret>> {
    let bundle: SecretBundle = serde_json::from_str(body).map_err(|err| {
        SecretsError::Storage(format!("failed to parse secret bundle: {err}; body={body}"))
    })?;
    if let Some(value) = bundle.value {
        let decoded = STANDARD.decode(value).map_err(|err| {
            SecretsError::Storage(format!("failed to decode secret value: {err}"))
        })?;
        let stored: StoredSecret = serde_json::from_slice(&decoded).map_err(|err| {
            SecretsError::Storage(format!("failed to decode stored secret: {err}"))
        })?;
        Ok(Some(stored))
    } else {
        Ok(None)
    }
}

#[derive(Deserialize)]
struct SecretBundle {
    value: Option<String>,
}

#[derive(Deserialize)]
struct SecretListResponse {
    #[serde(default)]
    value: Option<Vec<SecretListEntry>>,
    #[serde(rename = "nextLink")]
    #[serde(default)]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct SecretListEntry {
    id: String,
}

#[derive(Deserialize)]
struct SecretVersionListResponse {
    #[serde(default)]
    value: Option<Vec<SecretVersionEntry>>,
    #[serde(rename = "nextLink")]
    #[serde(default)]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct SecretVersionEntry {
    id: String,
}

fn extract_secret_name(id: &str) -> Option<&str> {
    id.split('/').nth_back(0)
}

fn extract_version_segment(id: &str) -> Option<&str> {
    id.split('/').nth_back(0)
}

/// True when every record stored under a (possibly shared) legacy name belongs
/// to `uri`. A legacy name can collide across distinct URIs — that is the bug
/// this fix removes — so before treating legacy history as `uri`'s we require
/// that no stored record names a different URI. Tombstones carry no record and
/// are treated as `uri`'s.
fn legacy_history_attributable_to(versions: &[StoredSecret], uri: &SecretUri) -> bool {
    versions
        .iter()
        .all(|entry| entry.record.as_ref().is_none_or(|rec| rec.meta.uri == *uri))
}

fn runtime_secret_name(namespace_prefix: &str, uri: &SecretUri) -> String {
    greentic_secrets_spec::azure_key_vault_secret_name(namespace_prefix, uri)
}

fn legacy_runtime_secret_name(namespace_prefix: &str, uri: &SecretUri) -> String {
    greentic_secrets_spec::legacy_azure_key_vault_secret_name(namespace_prefix, uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::{Scope, SecretUri};
    use serial_test::serial;
    use std::env;

    fn set_env(key: &str, value: &str) {
        unsafe { env::set_var(key, value) };
    }

    fn clear_env(key: &str) {
        unsafe { env::remove_var(key) };
    }

    fn setup_env() {
        set_env("AZURE_KEYVAULT_URL", "http://127.0.0.1:9");
        set_env("GREENTIC_AZURE_KEY_NAME", "unit-key");
        set_env("GREENTIC_AZURE_SECRET_PREFIX", "unit");
        set_env("GREENTIC_AZURE_BEARER_TOKEN", "emulator");
        set_env("GREENTIC_AZURE_HTTP_TIMEOUT_SECS", "1");
        clear_env("AZURE_TENANT_ID");
        clear_env("AZURE_CLIENT_ID");
        clear_env("AZURE_CLIENT_SECRET");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn azure_provider_ok_under_tokio() {
        setup_env();
        let BackendComponents { backend, .. } = build_backend()
            .await
            .expect("backend builds with static token");

        let scope = Scope::new("dev", "tenant", None).expect("scope");
        let uri = SecretUri::new(scope, "category", "name").expect("uri");

        let result = backend.exists(&uri);
        assert!(
            result.is_err(),
            "call should attempt network and fail without panicking"
        );
    }

    #[test]
    fn runtime_secret_name_matches_spec_contract() {
        let uri = SecretUri::parse("secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key")
            .expect("valid uri");

        // Writes use the collision-safe spec derivation; the legacy fallback
        // mirrors the spec legacy derivation; the two must differ.
        assert_eq!(
            runtime_secret_name("greentic", &uri),
            greentic_secrets_spec::azure_key_vault_secret_name("greentic", &uri)
        );
        assert_eq!(
            legacy_runtime_secret_name("greentic", &uri),
            greentic_secrets_spec::legacy_azure_key_vault_secret_name("greentic", &uri)
        );
        assert_ne!(
            runtime_secret_name("greentic", &uri),
            legacy_runtime_secret_name("greentic", &uri)
        );
    }

    fn stored_for(uri: &SecretUri, version: u64) -> StoredSecret {
        use greentic_secrets_spec::{
            ContentType, EncryptionAlgorithm, Envelope, SecretMeta, SecretRecord, Visibility,
        };
        let meta = SecretMeta::new(uri.clone(), Visibility::Tenant, ContentType::Opaque);
        let envelope = Envelope {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: Vec::new(),
            hkdf_salt: Vec::new(),
            wrapped_dek: Vec::new(),
        };
        StoredSecret::live(version, SecretRecord::new(meta, Vec::new(), envelope))
    }

    #[test]
    fn legacy_history_attribution_guards_colliding_uris() {
        // `category=a, name=b-c` vs `category=a-b, name=c` collide under the
        // legacy derivation (the bug) but get distinct collision-safe names.
        let a = SecretUri::parse("secrets://dev/demo/_/a/b-c").unwrap();
        let b = SecretUri::parse("secrets://dev/demo/_/a-b/c").unwrap();
        assert_eq!(
            legacy_runtime_secret_name("p", &a),
            legacy_runtime_secret_name("p", &b)
        );
        assert_ne!(runtime_secret_name("p", &a), runtime_secret_name("p", &b));

        // A legacy bucket holding A's record is A's, but must NOT be attributed
        // to B — otherwise B's first write would land in A's secret and re-
        // introduce the collision this fix removes.
        let a_bucket = [stored_for(&a, 1)];
        assert!(legacy_history_attributable_to(&a_bucket, &a));
        assert!(!legacy_history_attributable_to(&a_bucket, &b));

        // Tombstones carry no record and pass; a mixed bucket is rejected.
        assert!(legacy_history_attributable_to(
            &[StoredSecret::tombstone(9)],
            &a
        ));
        assert!(!legacy_history_attributable_to(
            &[stored_for(&a, 1), stored_for(&b, 2)],
            &a
        ));
    }
}
