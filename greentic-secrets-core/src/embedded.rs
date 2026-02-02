use crate::broker::{BrokerSecret, SecretsBroker};
use crate::crypto::dek_cache::DekCache;
use crate::crypto::envelope::EnvelopeService;
use crate::key_provider::KeyProvider;
use crate::spec_compat::{
    ContentType, DecryptError, EncryptionAlgorithm, Error as CoreError, Result as CoreResult,
    Scope, SecretListItem, SecretMeta, SecretRecord, SecretUri, SecretVersion, SecretsBackend,
    VersionedSecret, Visibility,
};
#[cfg(feature = "nats")]
use async_nats;
#[cfg(feature = "nats")]
use futures::StreamExt;
use lru::LruCache;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::string::FromUtf8Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Errors surfaced by the embedded `SecretsCore` API.
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// Wrapper for core domain errors.
    #[error("{0}")]
    Core(#[from] CoreError),
    /// Wrapper for decrypt failures.
    #[error("{0}")]
    Decrypt(#[from] DecryptError),
    /// JSON serialisation failure.
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    /// UTF-8 decoding failure.
    #[error("{0}")]
    Utf8(#[from] FromUtf8Error),
    /// Builder validation error.
    #[error("{0}")]
    Builder(String),
}

impl SecretsError {
    fn not_found(uri: &SecretUri) -> Self {
        CoreError::NotFound {
            entity: uri.to_string(),
        }
        .into()
    }
}

/// Allow/deny policy for embedded access. Currently only `AllowAll`.
#[derive(Clone, Debug, Default)]
pub enum Policy {
    /// Permit every read/write operation.
    #[default]
    AllowAll,
}

impl Policy {
    fn should_include(&self, _meta: &SecretMeta) -> bool {
        true
    }
}

/// Runtime configuration captured when building a `SecretsCore`.
pub struct CoreConfig {
    /// Default tenant scope for the runtime.
    pub tenant: String,
    /// Optional team scope for the runtime.
    pub team: Option<String>,
    /// Default cache TTL applied to secrets.
    pub default_ttl: Duration,
    /// Optional NATS URL for future signalling hooks.
    pub nats_url: Option<String>,
    /// Names of the configured backends in iteration order.
    pub backends: Vec<String>,
    /// Active policy for evaluation (currently `AllowAll`).
    pub policy: Policy,
    /// Maximum number of cached entries retained.
    pub cache_capacity: usize,
}

struct BackendRegistration {
    name: String,
    backend: Box<dyn SecretsBackend>,
    key_provider: Box<dyn KeyProvider>,
}

impl BackendRegistration {
    fn new<B, K>(name: impl Into<String>, backend: B, key_provider: K) -> Self
    where
        B: SecretsBackend + 'static,
        K: KeyProvider + 'static,
    {
        Self {
            name: name.into(),
            backend: Box::new(backend),
            key_provider: Box::new(key_provider),
        }
    }

    fn memory() -> Self {
        Self::new("memory", MemoryBackend::new(), MemoryKeyProvider::default())
    }
}

/// Builder for constructing [`SecretsCore`] instances.
pub struct CoreBuilder {
    tenant: Option<String>,
    team: Option<String>,
    default_ttl: Option<Duration>,
    nats_url: Option<String>,
    backends: Vec<BackendRegistration>,
    policy: Option<Policy>,
    cache_capacity: Option<usize>,
    dev_backend_enabled: bool,
}

impl Default for CoreBuilder {
    fn default() -> Self {
        Self {
            tenant: None,
            team: None,
            default_ttl: None,
            nats_url: None,
            backends: Vec::new(),
            policy: None,
            cache_capacity: None,
            dev_backend_enabled: true,
        }
    }
}

impl CoreBuilder {
    /// Initialise the builder using environment configuration.
    ///
    /// * `GREENTIC_SECRETS_TENANT` sets the default tenant (default: `"default"`).
    /// * `GREENTIC_SECRETS_TEAM` sets an optional team scope.
    /// * `GREENTIC_SECRETS_CACHE_TTL_SECS` overrides the cache TTL (default: 300s).
    /// * `GREENTIC_SECRETS_NATS_URL` records the NATS endpoint (unused today).
    /// * `GREENTIC_SECRETS_DEV` enables the in-memory backend (default: enabled).
    pub fn from_env() -> Self {
        let mut builder = CoreBuilder::default();

        if let Ok(tenant) = std::env::var("GREENTIC_SECRETS_TENANT")
            && !tenant.trim().is_empty()
        {
            builder.tenant = Some(tenant);
        }

        if let Ok(team) = std::env::var("GREENTIC_SECRETS_TEAM")
            && !team.trim().is_empty()
        {
            builder.team = Some(team);
        }

        if let Ok(ttl) = std::env::var("GREENTIC_SECRETS_CACHE_TTL_SECS")
            && let Ok(seconds) = ttl.parse::<u64>()
        {
            builder.default_ttl = Some(Duration::from_secs(seconds.max(1)));
        }

        if let Ok(url) = std::env::var("GREENTIC_SECRETS_NATS_URL")
            && !url.trim().is_empty()
        {
            builder.nats_url = Some(url);
        }

        let dev_enabled = std::env::var("GREENTIC_SECRETS_DEV")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(true);
        builder.dev_backend_enabled = dev_enabled;

        builder
    }

    /// Set the tenant scope attached to the runtime.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Set an optional team scope.
    pub fn team<T: Into<String>>(mut self, team: T) -> Self {
        self.team = Some(team.into());
        self
    }

    /// Override the default cache TTL.
    pub fn default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = Some(ttl);
        self
    }

    /// Record an optional NATS URL.
    pub fn nats_url(mut self, url: impl Into<String>) -> Self {
        self.nats_url = Some(url.into());
        self
    }

    /// Override the cache capacity (number of entries).
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.cache_capacity = Some(capacity.max(1));
        self
    }

    /// Register a backend with its corresponding key provider.
    pub fn backend<B, K>(self, backend: B, key_provider: K) -> Self
    where
        B: SecretsBackend + 'static,
        K: KeyProvider + 'static,
    {
        self.backend_named("custom", backend, key_provider)
    }

    /// Register a backend with a specific identifier.
    pub fn backend_named<B, K>(
        mut self,
        name: impl Into<String>,
        backend: B,
        key_provider: K,
    ) -> Self
    where
        B: SecretsBackend + 'static,
        K: KeyProvider + 'static,
    {
        self.backends
            .push(BackendRegistration::new(name, backend, key_provider));
        self
    }

    /// Register a backend with the default memory key provider.
    pub fn with_backend<B>(self, name: impl Into<String>, backend: B) -> Self
    where
        B: SecretsBackend + 'static,
    {
        self.backend_named(name, backend, MemoryKeyProvider::default())
    }

    /// Remove any previously registered backends.
    pub fn clear_backends(&mut self) {
        self.backends.clear();
    }

    /// If no backends have been explicitly registered, add sensible defaults.
    ///
    /// The current implementation falls back to the environment backend and,
    /// when configured via `GREENTIC_SECRETS_FILE_ROOT`, the filesystem backend.
    /// Future revisions will extend this to include cloud provider probes.
    pub async fn auto_detect_backends(self) -> Self {
        #[allow(unused_mut)]
        let mut builder = self;
        if !builder.backends.is_empty() {
            return builder;
        }

        if std::env::var_os("GREENTIC_SECRETS_BACKENDS").is_some() {
            return builder;
        }

        if crate::probe::is_kubernetes().await {
            #[cfg(feature = "k8s")]
            {
                builder = builder.backend(
                    crate::backend::k8s::K8sBackend::new(),
                    MemoryKeyProvider::default(),
                );
            }
        }

        if crate::probe::is_aws().await {
            #[cfg(feature = "aws")]
            {
                let backend = crate::backend::aws::AwsSecretsManagerBackend::new();
                builder = builder.backend(backend, MemoryKeyProvider::default());
            }
        }

        if crate::probe::is_gcp().await {
            #[cfg(feature = "gcp")]
            {
                let backend = crate::backend::gcp::GcpSecretsManagerBackend::new();
                builder = builder.backend(backend, MemoryKeyProvider::default());
            }
        }

        if crate::probe::is_azure().await {
            #[cfg(feature = "azure")]
            {
                let backend = crate::backend::azure::AzureKeyVaultBackend::new();
                builder = builder.backend(backend, MemoryKeyProvider::default());
            }
        }

        #[cfg(feature = "env")]
        {
            builder = builder.backend(
                crate::backend::env::EnvBackend::new(),
                MemoryKeyProvider::default(),
            );
        }

        #[cfg(feature = "file")]
        {
            if let Ok(root) = std::env::var("GREENTIC_SECRETS_FILE_ROOT")
                && !root.is_empty()
            {
                builder = builder.backend(
                    crate::backend::file::FileBackend::new(root),
                    MemoryKeyProvider::default(),
                );
            }
        }

        builder
    }

    /// Override the policy (currently only `AllowAll` is supported).
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Build the [`SecretsCore`] instance.
    pub async fn build(mut self) -> Result<SecretsCore, SecretsError> {
        if self.backends.is_empty() {
            if self.dev_backend_enabled {
                self.backends.push(BackendRegistration::memory());
            } else {
                return Err(SecretsError::Builder(
                    "no backend registered and GREENTIC_SECRETS_DEV=0".to_string(),
                ));
            }
        }

        let tenant = self.tenant.unwrap_or_else(|| "default".to_string());
        let policy = self.policy.unwrap_or_default();
        let default_ttl = self.default_ttl.unwrap_or_else(|| Duration::from_secs(300));
        let cache_capacity = self.cache_capacity.unwrap_or(256);
        let registration = self.backends.remove(0);
        let backend_names = std::iter::once(registration.name.clone())
            .chain(self.backends.iter().map(|b| b.name.clone()))
            .collect();

        let crypto = EnvelopeService::new(
            registration.key_provider,
            DekCache::from_env(),
            EncryptionAlgorithm::Aes256Gcm,
        );
        let broker = SecretsBroker::new(registration.backend, crypto);

        let cache =
            LruCache::new(NonZeroUsize::new(cache_capacity).expect("cache capacity must be > 0"));
        let cache = Arc::new(Mutex::new(cache));

        let config = CoreConfig {
            tenant,
            team: self.team,
            default_ttl,
            nats_url: self.nats_url,
            backends: backend_names,
            policy: policy.clone(),
            cache_capacity,
        };

        let core = SecretsCore {
            config,
            broker: Arc::new(Mutex::new(broker)),
            cache: cache.clone(),
            cache_ttl: default_ttl,
            policy,
        };

        #[cfg(feature = "nats")]
        if let Some(url) = core.config.nats_url.clone() {
            spawn_invalidation_listener(cache, core.config.tenant.clone(), url);
        }

        Ok(core)
    }
}

type SharedBroker = Arc<Mutex<SecretsBroker<Box<dyn SecretsBackend>, Box<dyn KeyProvider>>>>;

/// Embedded secrets client that can be used directly from Rust runtimes.
pub struct SecretsCore {
    config: CoreConfig,
    broker: SharedBroker,
    cache: Arc<Mutex<LruCache<String, CacheEntry>>>,
    cache_ttl: Duration,
    policy: Policy,
}

impl SecretsCore {
    /// Start building a new embedded core instance.
    pub fn builder() -> CoreBuilder {
        CoreBuilder::from_env()
    }

    /// Access the runtime configuration.
    /// Return an immutable reference to the runtime configuration.
    pub fn config(&self) -> &CoreConfig {
        &self.config
    }

    /// Retrieve secret bytes for the provided URI.
    pub async fn get_bytes(&self, uri: &str) -> Result<Vec<u8>, SecretsError> {
        let uri = self.parse_uri(uri)?;
        self.ensure_scope_allowed(uri.scope())?;
        if let Some(bytes) = self.cached_value(&uri) {
            return Ok(bytes);
        }
        let secret = self
            .fetch_secret(&uri)?
            .ok_or_else(|| SecretsError::not_found(&uri))?;
        let value = secret.payload.clone();
        self.store_cache(uri.to_string(), &secret);
        Ok(value)
    }

    /// Retrieve a secret as UTF-8 text.
    pub async fn get_text(&self, uri: &str) -> Result<String, SecretsError> {
        let bytes = self.get_bytes(uri).await?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Retrieve a secret and deserialize it as JSON.
    pub async fn get_json<T: DeserializeOwned>(&self, uri: &str) -> Result<T, SecretsError> {
        let bytes = self.get_bytes(uri).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Retrieve a secret along with its metadata (decrypted).
    pub async fn get_secret_with_meta(
        &self,
        uri: &str,
    ) -> Result<crate::BrokerSecret, SecretsError> {
        let uri = self.parse_uri(uri)?;
        self.ensure_scope_allowed(uri.scope())?;
        let secret = self
            .fetch_secret(&uri)?
            .ok_or_else(|| SecretsError::not_found(&uri))?;
        self.store_cache(uri.to_string(), &secret);
        Ok(secret)
    }

    /// Store JSON content at the provided URI.
    pub async fn put_json<T: Serialize>(
        &self,
        uri: &str,
        value: &T,
    ) -> Result<SecretMeta, SecretsError> {
        let uri = self.parse_uri(uri)?;
        self.ensure_scope_allowed(uri.scope())?;
        let bytes = serde_json::to_vec(value)?;
        let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Json);
        meta.description = None;

        {
            let mut broker = self.broker.lock().unwrap();
            broker.put_secret(meta.clone(), &bytes)?;
        }

        self.store_cache(
            uri.to_string(),
            &BrokerSecret {
                version: 0,
                meta: meta.clone(),
                payload: bytes.clone(),
            },
        );

        Ok(meta)
    }

    /// Delete a secret.
    pub async fn delete(&self, uri: &str) -> Result<(), SecretsError> {
        let uri = self.parse_uri(uri)?;
        self.ensure_scope_allowed(uri.scope())?;
        {
            let broker = self.broker.lock().unwrap();
            broker.delete_secret(&uri)?;
        }
        let mut cache = self.cache.lock().unwrap();
        cache.pop(&uri.to_string());
        Ok(())
    }

    /// List secret metadata matching the provided prefix.
    pub async fn list(&self, prefix: &str) -> Result<Vec<SecretMeta>, SecretsError> {
        let (scope, category_prefix, name_prefix) = parse_prefix(prefix)?;
        self.ensure_scope_allowed(&scope)?;
        let items: Vec<SecretListItem> = {
            let broker = self.broker.lock().unwrap();
            broker.list_secrets(&scope, category_prefix.as_deref(), name_prefix.as_deref())?
        };

        let mut metas = Vec::with_capacity(items.len());
        for item in items {
            let mut meta = SecretMeta::new(item.uri.clone(), item.visibility, item.content_type);
            meta.description = None;
            if self.policy.should_include(&meta) {
                metas.push(meta);
            }
        }
        Ok(metas)
    }

    fn parse_uri(&self, uri: &str) -> Result<SecretUri, SecretsError> {
        Ok(SecretUri::parse(uri)?)
    }

    fn cached_value(&self, uri: &SecretUri) -> Option<Vec<u8>> {
        let key = uri.to_string();
        let mut cache = self.cache.lock().unwrap();
        if let Some(entry) = cache.get(&key)
            && entry.expires_at > Instant::now()
        {
            return Some(entry.value.clone());
        }
        cache.pop(&key);
        None
    }

    fn fetch_secret(&self, uri: &SecretUri) -> Result<Option<BrokerSecret>, SecretsError> {
        let mut broker = self.broker.lock().unwrap();
        Ok(broker.get_secret(uri)?)
    }

    fn store_cache(&self, key: String, secret: &BrokerSecret) {
        let mut cache = self.cache.lock().unwrap();
        let entry = CacheEntry {
            value: secret.payload.clone(),
            meta: secret.meta.clone(),
            expires_at: Instant::now() + self.cache_ttl,
        };
        cache.put(key, entry);
    }

    fn ensure_scope_allowed(&self, scope: &Scope) -> Result<(), SecretsError> {
        if scope.tenant() != self.config.tenant {
            return Err(SecretsError::Builder(format!(
                "tenant `{}` is not permitted for this runtime (allowed tenant: `{}`)",
                scope.tenant(),
                self.config.tenant
            )));
        }

        if let Some(expected_team) = self.config.team.as_ref() {
            match scope.team() {
                Some(team) if team == expected_team => Ok(()),
                Some(team) => Err(SecretsError::Builder(format!(
                    "team `{team}` is not permitted for this runtime (allowed team: `{expected_team}`)"
                ))),
                None => Ok(()),
            }
        } else {
            Ok(())
        }
    }

    /// Remove cached entries whose keys match the provided exact URIs or prefixes
    /// (indicated by a trailing `*`).
    #[cfg_attr(not(any(test, feature = "nats")), allow(dead_code))]
    pub fn purge_cache(&self, uris: &[String]) {
        let mut cache = self.cache.lock().unwrap();
        purge_patterns(&mut cache, uris);
    }
}

struct CacheEntry {
    value: Vec<u8>,
    #[allow(dead_code)]
    meta: SecretMeta,
    expires_at: Instant,
}

#[cfg_attr(not(any(test, feature = "nats")), allow(dead_code))]
fn purge_patterns(cache: &mut LruCache<String, CacheEntry>, patterns: &[String]) {
    for pattern in patterns {
        purge_pattern(cache, pattern);
    }
}

#[cfg_attr(not(any(test, feature = "nats")), allow(dead_code))]
fn purge_pattern(cache: &mut LruCache<String, CacheEntry>, pattern: &str) {
    if let Some(prefix) = pattern.strip_suffix('*') {
        let keys: Vec<String> = cache
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            cache.pop(&key);
        }
    } else {
        cache.pop(pattern);
    }
}

#[cfg(feature = "nats")]
fn spawn_invalidation_listener(
    cache: Arc<Mutex<LruCache<String, CacheEntry>>>,
    tenant: String,
    url: String,
) {
    let subject = format!("secrets.changed.{tenant}.*");
    tokio::spawn(async move {
        if let Ok(client) = async_nats::connect(&url).await
            && let Ok(mut sub) = client.subscribe(subject).await
        {
            while let Some(msg) = sub.next().await {
                if let Ok(payload) = serde_json::from_slice::<InvalidationMessage>(&msg.payload) {
                    let mut guard = cache.lock().unwrap();
                    purge_patterns(&mut guard, &payload.uris);
                }
            }
        }
    });
}

#[cfg(feature = "nats")]
#[derive(serde::Deserialize)]
struct InvalidationMessage {
    uris: Vec<String>,
}

/// Simple in-memory backend suitable for embedded usage and tests.
#[derive(Default)]
pub struct MemoryBackend {
    state: Mutex<HashMap<String, Vec<MemoryVersion>>>,
}

impl MemoryBackend {
    /// Construct a new empty backend.
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone)]
struct MemoryVersion {
    version: u64,
    deleted: bool,
    record: Option<SecretRecord>,
}

impl MemoryVersion {
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

    fn as_version(&self) -> SecretVersion {
        SecretVersion {
            version: self.version,
            deleted: self.deleted,
        }
    }

    fn as_versioned(&self) -> VersionedSecret {
        VersionedSecret {
            version: self.version,
            deleted: self.deleted,
            record: self.record.clone(),
        }
    }
}

impl SecretsBackend for MemoryBackend {
    fn put(&self, record: SecretRecord) -> CoreResult<SecretVersion> {
        let key = record.meta.uri.to_string();
        let mut guard = self.state.lock().unwrap();
        let entries = guard.entry(key).or_default();
        let next_version = entries.last().map(|v| v.version + 1).unwrap_or(1);
        entries.push(MemoryVersion::live(next_version, record));
        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> CoreResult<Option<VersionedSecret>> {
        let key = uri.to_string();
        let guard = self.state.lock().unwrap();
        let entries = match guard.get(&key) {
            Some(entries) => entries,
            None => return Ok(None),
        };

        if let Some(target) = version {
            let entry = entries.iter().find(|entry| entry.version == target);
            return Ok(entry.cloned().map(|entry| entry.as_versioned()));
        }

        if matches!(entries.last(), Some(entry) if entry.deleted) {
            return Ok(None);
        }

        let latest = entries.iter().rev().find(|entry| !entry.deleted).cloned();
        Ok(latest.map(|entry| entry.as_versioned()))
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> CoreResult<Vec<SecretListItem>> {
        let guard = self.state.lock().unwrap();
        let mut items = Vec::new();

        for versions in guard.values() {
            if matches!(versions.last(), Some(entry) if entry.deleted) {
                continue;
            }

            let latest = match versions.iter().rev().find(|entry| !entry.deleted) {
                Some(entry) => entry,
                None => continue,
            };

            let record = match &latest.record {
                Some(record) => record,
                None => continue,
            };

            let secret_scope = record.meta.scope();
            if scope.env() != secret_scope.env() || scope.tenant() != secret_scope.tenant() {
                continue;
            }
            if scope.team() != secret_scope.team() {
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
                Some(latest.version.to_string()),
            ));
        }

        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> CoreResult<SecretVersion> {
        let key = uri.to_string();
        let mut guard = self.state.lock().unwrap();
        let entries = guard.get_mut(&key).ok_or_else(|| CoreError::NotFound {
            entity: uri.to_string(),
        })?;
        let next_version = entries.last().map(|v| v.version + 1).unwrap_or(1);
        entries.push(MemoryVersion::tombstone(next_version));
        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> CoreResult<Vec<SecretVersion>> {
        let key = uri.to_string();
        let guard = self.state.lock().unwrap();
        let entries = guard.get(&key).cloned().unwrap_or_default();
        Ok(entries
            .into_iter()
            .map(|entry| entry.as_version())
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> CoreResult<bool> {
        let key = uri.to_string();
        let guard = self.state.lock().unwrap();
        Ok(guard
            .get(&key)
            .and_then(|versions| versions.last())
            .map(|latest| !latest.deleted)
            .unwrap_or(false))
    }
}

/// Simple in-memory key provider that uses XOR wrapping with per-scope keys.
#[derive(Default, Clone)]
pub struct MemoryKeyProvider {
    keys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryKeyProvider {
    /// Construct a new provider.
    pub fn new() -> Self {
        Self::default()
    }

    fn key_for_scope(&self, scope: &Scope) -> Vec<u8> {
        let mut guard = self.keys.lock().unwrap();
        guard
            .entry(scope_key(scope))
            .or_insert_with(|| {
                let mut buf = vec![0u8; 32];
                let mut rng = rand::rng();
                use rand::RngCore;
                rng.fill_bytes(&mut buf);
                buf
            })
            .clone()
    }
}

impl KeyProvider for MemoryKeyProvider {
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> CoreResult<Vec<u8>> {
        let key = self.key_for_scope(scope);
        Ok(xor(&key, dek))
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> CoreResult<Vec<u8>> {
        let key = self.key_for_scope(scope);
        Ok(xor(&key, wrapped))
    }
}

fn scope_key(scope: &Scope) -> String {
    format!(
        "{}:{}:{}",
        scope.env(),
        scope.tenant(),
        scope.team().unwrap_or("_")
    )
}

fn xor(key: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ key[idx % key.len()])
        .collect()
}

fn parse_prefix(prefix: &str) -> Result<(Scope, Option<String>, Option<String>), SecretsError> {
    const SCHEME: &str = "secrets://";
    if !prefix.starts_with(SCHEME) {
        return Err(SecretsError::Builder(
            "prefix must start with secrets://".into(),
        ));
    }

    let rest = &prefix[SCHEME.len()..];
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.len() < 3 {
        return Err(SecretsError::Builder(
            "prefix must include env/tenant/team segments".into(),
        ));
    }

    let env = segments[0];
    let tenant = segments[1];
    let team_segment = segments[2];
    let team = if team_segment == "_" || team_segment.is_empty() {
        None
    } else {
        Some(team_segment.to_string())
    };

    let scope = Scope::new(env.to_string(), tenant.to_string(), team.clone())?;

    let category_prefix = segments
        .get(3)
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let name_prefix = segments
        .get(4)
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    Ok((scope, category_prefix, name_prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration as TokioDuration, sleep};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

    #[test]
    fn builder_from_env_defaults() {
        unsafe {
            std::env::remove_var("GREENTIC_SECRETS_TENANT");
            std::env::remove_var("GREENTIC_SECRETS_TEAM");
            std::env::remove_var("GREENTIC_SECRETS_CACHE_TTL_SECS");
            std::env::remove_var("GREENTIC_SECRETS_NATS_URL");
        }

        let builder = CoreBuilder::from_env();
        assert!(builder.tenant.is_none());
        assert!(builder.backends.is_empty());
        assert!(builder.dev_backend_enabled);

        rt().block_on(async {
            let core = builder.build().await.unwrap();
            assert_eq!(core.config().backends.len(), 1);
        });
    }

    #[test]
    fn roundtrip_put_get_json() {
        rt().block_on(async {
            let core = SecretsCore::builder()
                .tenant("acme")
                .backend(MemoryBackend::new(), MemoryKeyProvider::default())
                .build()
                .await
                .unwrap();

            let uri = "secrets://dev/acme/_/configs/service";
            let payload = serde_json::json!({ "token": "secret" });
            let meta = core.put_json(uri, &payload).await.unwrap();
            assert_eq!(meta.uri.to_string(), uri);

            let value: serde_json::Value = core.get_json(uri).await.unwrap();
            assert_eq!(value, payload);
        });
    }

    #[test]
    fn cache_hit_and_expiry() {
        rt().block_on(async {
            let ttl = Duration::from_millis(50);
            let core = SecretsCore::builder()
                .tenant("acme")
                .default_ttl(ttl)
                .backend(MemoryBackend::new(), MemoryKeyProvider::default())
                .build()
                .await
                .unwrap();

            let uri = "secrets://dev/acme/_/configs/cache";
            core.put_json(uri, &serde_json::json!({"key": "value"}))
                .await
                .unwrap();

            // Populate cache
            core.get_bytes(uri).await.unwrap();
            let key = uri.to_string();
            {
                let cache = core.cache.lock().unwrap();
                assert!(cache.peek(&key).is_some());
            }

            // Hit should keep entry
            core.get_bytes(uri).await.unwrap();
            {
                let cache = core.cache.lock().unwrap();
                assert!(cache.peek(&key).is_some());
            }

            sleep(TokioDuration::from_millis(75)).await;

            core.get_bytes(uri).await.unwrap();
            {
                let cache = core.cache.lock().unwrap();
                let entry = cache.peek(&key).unwrap();
                assert!(entry.expires_at > Instant::now());
            }
        });
    }

    #[test]
    fn cache_invalidation_patterns() {
        rt().block_on(async {
            let core = SecretsCore::builder()
                .tenant("acme")
                .backend(MemoryBackend::new(), MemoryKeyProvider::default())
                .build()
                .await
                .unwrap();

            let uri_a = "secrets://dev/acme/_/configs/app";
            let uri_b = "secrets://dev/acme/_/configs/db";

            let record = serde_json::json!({"value": 1});
            core.put_json(uri_a, &record).await.unwrap();
            core.put_json(uri_b, &record).await.unwrap();

            // Ensure entries are cached.
            core.get_bytes(uri_a).await.unwrap();
            core.get_bytes(uri_b).await.unwrap();

            core.purge_cache(&[uri_a.to_string()]);

            assert!(
                core.cached_value(&SecretUri::try_from(uri_a).unwrap())
                    .is_none()
            );
            assert!(
                core.cached_value(&SecretUri::try_from(uri_b).unwrap())
                    .is_some()
            );

            core.purge_cache(&["secrets://dev/acme/_/configs/*".to_string()]);
            assert!(
                core.cached_value(&SecretUri::try_from(uri_b).unwrap())
                    .is_none()
            );
        });
    }

    #[test]
    fn auto_detect_skips_when_backends_present() {
        unsafe {
            std::env::remove_var("GREENTIC_SECRETS_FILE_ROOT");
        }
        rt().block_on(async {
            let builder =
                CoreBuilder::default().backend(MemoryBackend::new(), MemoryKeyProvider::default());
            let builder = builder.auto_detect_backends().await;
            let core = builder.build().await.unwrap();
            assert_eq!(core.config().backends.len(), 1);
            assert_eq!(core.config().backends[0], "custom");
        });
    }

    #[test]
    fn auto_detect_respects_backends_env_override() {
        unsafe {
            std::env::set_var("GREENTIC_SECRETS_BACKENDS", "aws");
            std::env::remove_var("GREENTIC_SECRETS_FILE_ROOT");
        }
        rt().block_on(async {
            let builder = CoreBuilder::default().auto_detect_backends().await;
            let core = builder.build().await.unwrap();
            assert_eq!(core.config().backends, vec!["memory".to_string()]);
        });
        unsafe {
            std::env::remove_var("GREENTIC_SECRETS_BACKENDS");
        }
    }
}
