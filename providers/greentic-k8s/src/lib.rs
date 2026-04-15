//! Kubernetes Secrets backend powered by the Kubernetes REST API.
//!
//! Each Greentic secret maps to a namespaced Kubernetes `Secret` resource.
//! Every write creates a new resource whose name encodes the version number,
//! preserving history. Deletions append a tombstone version. All operations
//! execute via the standard Kubernetes HTTPS endpoints using a bearer token
//! provided through environment variables.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use greentic_secrets_core::http::{Http, HttpResponse};
use greentic_secrets_spec::{
    Envelope, KeyProvider, Scope, SecretListItem, SecretMeta, SecretRecord, SecretUri,
    SecretVersion, SecretsBackend, SecretsError, SecretsResult, VersionedSecret,
};
use reqwest::{Certificate, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use url::form_urlencoded::byte_serialize;

const DEFAULT_NAMESPACE_PREFIX: &str = "greentic";
const DEFAULT_MAX_SECRET_SIZE: usize = 1_048_576; // 1 MiB
const NAMESPACE_MAX_LEN: usize = 63;
const SECRET_NAME_MAX_LEN: usize = 253;
const LABEL_KEY: &str = "greentic.ai/key";
const LABEL_VERSION: &str = "greentic.ai/version";
const LABEL_ENV: &str = "greentic.ai/env";
const LABEL_TENANT: &str = "greentic.ai/tenant";
const LABEL_TEAM: &str = "greentic.ai/team";
const LABEL_CATEGORY: &str = "greentic.ai/category";
const LABEL_NAME: &str = "greentic.ai/name";
const STATUS_LABEL: &str = "greentic.ai/status";

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the backend and key provider from environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = Arc::new(K8sProviderConfig::from_env()?);
    let http = config.build_http_client()?;

    let backend = K8sSecretsBackend::new(config.clone(), http.clone());
    let key_provider = K8sKeyProvider::new(config);
    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
struct K8sSecretsBackend {
    config: Arc<K8sProviderConfig>,
    http: Http,
}

impl K8sSecretsBackend {
    fn new(config: Arc<K8sProviderConfig>, http: Http) -> Self {
        Self { config, http }
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> SecretsResult<HttpResponse> {
        let url = format!(
            "{}/{}",
            self.config.api_server.trim_end_matches('/'),
            path.trim_start_matches('/')
        );

        let mut builder = self.http.request(method, url);
        builder = builder.bearer_auth(&self.config.bearer_token);
        if let Some(payload) = body {
            builder = builder.json(&payload);
        }

        builder
            .send()
            .map_err(|err| SecretsError::Storage(format!("kubernetes request failed: {err}")))
    }

    fn ensure_namespace(&self, namespace: &str) -> SecretsResult<()> {
        let path = format!("/api/v1/namespaces/{namespace}");
        let (status, body) = read_k8s_response(self.request(Method::GET, &path, None)?)?;
        if status == StatusCode::OK {
            return Ok(());
        }

        if status != StatusCode::NOT_FOUND {
            return Err(SecretsError::Storage(format!(
                "failed to inspect namespace: {status} {body}"
            )));
        }

        let create = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": namespace },
        });
        let (status, body) =
            read_k8s_response(self.request(Method::POST, "/api/v1/namespaces", Some(create))?)?;
        if !status.is_success() {
            return Err(SecretsError::Storage(format!(
                "failed to create namespace: {status} {body}"
            )));
        }
        Ok(())
    }

    fn put_secret(&self, namespace: &str, manifest: Value) -> SecretsResult<()> {
        let path = format!("/api/v1/namespaces/{namespace}/secrets");
        let (status, body) =
            read_k8s_response(self.request(Method::POST, &path, Some(manifest))?)?;
        if !status.is_success() {
            return Err(SecretsError::Storage(format!(
                "create secret failed: {status} {body}"
            )));
        }
        Ok(())
    }

    fn list_versions(&self, namespace: &str, key: &str) -> SecretsResult<Vec<SecretSnapshot>> {
        let mut snapshots = Vec::new();
        let selector = format!("{LABEL_KEY}={key}");
        let selector = percent_encode(&selector);
        let mut continue_token: Option<String> = None;

        loop {
            let mut path = format!(
                "/api/v1/namespaces/{namespace}/secrets?labelSelector={selector}&limit=100"
            );
            if let Some(token) = continue_token.as_ref() {
                path.push_str("&continue=");
                path.push_str(&percent_encode(token));
            }

            let (status, body) = read_k8s_response(self.request(Method::GET, &path, None)?)?;
            if status == StatusCode::NOT_FOUND {
                break;
            }
            if !status.is_success() {
                return Err(SecretsError::Storage(format!(
                    "list secrets failed: {status} {body}"
                )));
            }

            let mut list: SecretList = serde_json::from_str(&body).map_err(|err| {
                SecretsError::Storage(format!("failed to decode secret list: {err}; body={body}"))
            })?;

            for item in list.items.drain(..) {
                if let Some(snapshot) = parse_secret(item)? {
                    snapshots.push(snapshot);
                }
            }

            if let Some(token) = list.metadata.and_then(|meta| meta.continue_token) {
                continue_token = Some(token);
                continue;
            }
            break;
        }

        snapshots.sort_by_key(|snapshot| snapshot.version);
        Ok(snapshots)
    }
}

fn read_k8s_response(response: HttpResponse) -> SecretsResult<(StatusCode, String)> {
    let status = response.status();
    let body = response.text().map_err(|err| {
        SecretsError::Storage(format!("failed to read kubernetes response body: {err}"))
    })?;
    Ok((status, body))
}

impl SecretsBackend for K8sSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        if record.value.len() > self.config.max_secret_size {
            return Err(SecretsError::Storage(format!(
                "secret payload exceeds configured Kubernetes limit of {} bytes",
                self.config.max_secret_size
            )));
        }

        if self.config.use_sealed_secrets {
            return Err(SecretsError::Storage(
                "sealed secrets mode is not supported by the live Kubernetes backend".into(),
            ));
        }

        let namespace = namespace_for_scope(&self.config, record.meta.uri.scope());
        self.ensure_namespace(&namespace)?;

        let key = canonical_storage_key(&record.meta.uri);
        let versions = self.list_versions(&namespace, &key)?;
        let next_version = versions
            .last()
            .map(|snapshot| snapshot.version)
            .unwrap_or(0)
            .saturating_add(1);

        let name = secret_resource_name(&record.meta.uri, next_version);
        let manifest = secret_manifest(
            &record.meta.uri,
            Some(&record),
            &namespace,
            &name,
            &key,
            next_version,
            false,
        )?;
        self.put_secret(&namespace, manifest)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> SecretsResult<Option<VersionedSecret>> {
        let namespace = namespace_for_scope(&self.config, uri.scope());
        let key = canonical_storage_key(uri);
        let versions = self.list_versions(&namespace, &key)?;

        if let Some(requested) = version {
            for snapshot in versions {
                if snapshot.version == requested && !snapshot.deleted {
                    return snapshot.into_versioned();
                }
            }
            return Ok(None);
        }

        for snapshot in versions.into_iter().rev() {
            if snapshot.deleted {
                return Ok(None);
            }
            return snapshot.into_versioned();
        }

        Ok(None)
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        let namespace = namespace_for_scope(&self.config, scope);
        let (status, body) = read_k8s_response(self.request(
            Method::GET,
            &format!("/api/v1/namespaces/{namespace}/secrets?limit=250"),
            None,
        )?)?;
        if !status.is_success() {
            return Err(SecretsError::Storage(format!(
                "list secrets failed: {status} {body}"
            )));
        }

        let mut list: SecretList = serde_json::from_str(&body).map_err(|err| {
            SecretsError::Storage(format!("failed to decode secret list: {err}; body={body}"))
        })?;

        let mut items = Vec::new();
        for item in list.items.drain(..) {
            let Some(snapshot) = parse_secret(item)? else {
                continue;
            };
            if snapshot.deleted {
                continue;
            }

            if let Some(record) = snapshot.record.as_ref() {
                let record_scope = record.meta.uri.scope();
                if record_scope.env() != scope.env() || record_scope.tenant() != scope.tenant() {
                    continue;
                }
                if let Some(team) = scope.team()
                    && record_scope.team() != Some(team)
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

                let versioned = snapshot.into_versioned()?;
                if let Some(versioned) = versioned
                    && let Some(record) = versioned.record()
                {
                    items.push(SecretListItem::from_meta(
                        &record.meta,
                        Some(versioned.version.to_string()),
                    ));
                }
            }
        }

        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> SecretsResult<SecretVersion> {
        let namespace = namespace_for_scope(&self.config, uri.scope());
        let key = canonical_storage_key(uri);
        let versions = self.list_versions(&namespace, &key)?;
        if versions.is_empty() {
            return Err(SecretsError::NotFound {
                entity: uri.to_string(),
            });
        }

        let next_version = versions
            .last()
            .map(|snapshot| snapshot.version)
            .unwrap_or(0)
            .saturating_add(1);

        let name = secret_resource_name(uri, next_version);
        let manifest = secret_manifest(uri, None, &namespace, &name, &key, next_version, true)?;
        self.put_secret(&namespace, manifest)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        let namespace = namespace_for_scope(&self.config, uri.scope());
        let key = canonical_storage_key(uri);
        Ok(self
            .list_versions(&namespace, &key)?
            .into_iter()
            .map(|snapshot| SecretVersion {
                version: snapshot.version,
                deleted: snapshot.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> SecretsResult<bool> {
        Ok(self.get(uri, None)?.is_some())
    }
}

#[derive(Clone)]
struct K8sKeyProvider {
    config: Arc<K8sProviderConfig>,
}

impl K8sKeyProvider {
    fn new(config: Arc<K8sProviderConfig>) -> Self {
        Self { config }
    }

    fn derive_key(&self, alias: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(alias.as_bytes());
        hasher.finalize()[..32].to_vec()
    }
}

impl KeyProvider for K8sKeyProvider {
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let alias = self
            .config
            .key_aliases
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| SecretsError::Crypto("missing key material alias".into()))?;
        let key = self.derive_key(alias);
        Ok(xor_bytes(&key, dek))
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let alias = self
            .config
            .key_aliases
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| SecretsError::Crypto("missing key material alias".into()))?;
        let key = self.derive_key(alias);
        Ok(xor_bytes(&key, wrapped))
    }
}

fn xor_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ key[idx % key.len()])
        .collect()
}

#[derive(Clone, Debug)]
struct K8sProviderConfig {
    api_server: String,
    bearer_token: String,
    ca_bundle: Option<Vec<u8>>,
    insecure_skip_tls: bool,
    request_timeout: Duration,
    namespace_prefix: String,
    max_secret_size: usize,
    key_aliases: AliasMap,
    use_sealed_secrets: bool,
}

impl K8sProviderConfig {
    fn from_env() -> Result<Self> {
        let api_server = std::env::var("K8S_API_SERVER")
            .context("set K8S_API_SERVER to the Kubernetes API server URL")?;

        let bearer_token = match std::env::var("K8S_BEARER_TOKEN") {
            Ok(value) => value,
            Err(_) => {
                let path = std::env::var("K8S_BEARER_TOKEN_FILE")
                    .context("set K8S_BEARER_TOKEN or K8S_BEARER_TOKEN_FILE")?;
                String::from_utf8(fs::read(path)?).context("token file is not valid UTF-8")?
            }
        };

        let ca_bundle = std::env::var("K8S_CA_BUNDLE")
            .ok()
            .map(|path| fs::read(path).context("failed to read K8S_CA_BUNDLE"))
            .transpose()?;

        let insecure_skip_tls = std::env::var("K8S_INSECURE_SKIP_TLS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);

        let request_timeout = std::env::var("K8S_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(15));

        let namespace_prefix = std::env::var("K8S_NAMESPACE_PREFIX")
            .unwrap_or_else(|_| DEFAULT_NAMESPACE_PREFIX.to_string());
        let max_secret_size = std::env::var("K8S_SECRET_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_SECRET_SIZE);

        Ok(Self {
            api_server,
            bearer_token: bearer_token.trim().to_string(),
            ca_bundle,
            insecure_skip_tls,
            request_timeout,
            namespace_prefix,
            max_secret_size,
            key_aliases: AliasMap::from_env("K8S_KEK_ALIAS")?,
            use_sealed_secrets: cfg!(feature = "sealedsecrets"),
        })
    }

    fn build_http_client(&self) -> Result<Http> {
        let mut builder = reqwest::Client::builder().timeout(self.request_timeout);
        if let Some(ca) = self.ca_bundle.as_ref() {
            let cert = Certificate::from_pem(ca)
                .or_else(|_| Certificate::from_der(ca))
                .context("failed to parse K8S_CA_BUNDLE")?;
            builder = builder.add_root_certificate(cert);
        }
        if self.insecure_skip_tls {
            bail!("K8S_INSECURE_SKIP_TLS is not permitted");
        }
        Http::from_builder(builder).context("failed to build kubernetes HTTP client")
    }
}

#[derive(Clone, Debug)]
struct AliasMap {
    default: Option<String>,
    per_env: HashMap<String, String>,
    per_tenant: HashMap<(String, String), String>,
}

impl AliasMap {
    fn from_env(prefix: &str) -> Result<Self> {
        let default = std::env::var(prefix).ok();
        let mut per_env = HashMap::new();
        let mut per_tenant = HashMap::new();
        for (key, value) in std::env::vars() {
            if !key.starts_with(prefix) || key == prefix {
                continue;
            }
            let suffix = key.trim_start_matches(prefix).trim_matches('_');
            if suffix.is_empty() {
                continue;
            }
            let parts: Vec<&str> = suffix.split('_').collect();
            match parts.as_slice() {
                [env] => {
                    per_env.insert(env.to_lowercase(), value.clone());
                }
                [env, tenant] => {
                    per_tenant.insert((env.to_lowercase(), tenant.to_lowercase()), value.clone());
                }
                _ => {}
            }
        }
        Ok(Self {
            default,
            per_env,
            per_tenant,
        })
    }

    fn resolve(&self, env: &str, tenant: &str) -> Option<&str> {
        self.per_tenant
            .get(&(env.to_lowercase(), tenant.to_lowercase()))
            .or_else(|| self.per_env.get(&env.to_lowercase()))
            .or(self.default.as_ref())
            .map(String::as_str)
    }
}

#[derive(Deserialize)]
struct SecretList {
    items: Vec<SecretItem>,
    #[serde(default)]
    metadata: Option<ListMeta>,
}

#[derive(Deserialize)]
struct ListMeta {
    #[serde(rename = "continue")]
    #[serde(default)]
    continue_token: Option<String>,
}

#[derive(Deserialize)]
struct SecretItem {
    metadata: ItemMeta,
    #[serde(default)]
    data: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct ItemMeta {
    #[serde(default)]
    labels: HashMap<String, String>,
}

struct SecretSnapshot {
    version: u64,
    deleted: bool,
    record: Option<StoredRecord>,
}

impl SecretSnapshot {
    fn into_versioned(self) -> SecretsResult<Option<VersionedSecret>> {
        if self.deleted {
            return Ok(Some(VersionedSecret {
                version: self.version,
                deleted: true,
                record: None,
            }));
        }

        let record = self
            .record
            .ok_or_else(|| SecretsError::Storage("missing record".into()))?
            .into_record()?;

        Ok(Some(VersionedSecret {
            version: self.version,
            deleted: false,
            record: Some(record),
        }))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredRecord {
    meta: SecretMeta,
    envelope: StoredEnvelope,
    value: String,
}

impl StoredRecord {
    fn from_record(record: &SecretRecord) -> SecretsResult<Self> {
        Ok(Self {
            meta: record.meta.clone(),
            envelope: StoredEnvelope::from_envelope(&record.envelope),
            value: STANDARD.encode(&record.value),
        })
    }

    fn into_record(self) -> SecretsResult<SecretRecord> {
        Ok(SecretRecord::new(
            self.meta,
            decode_bytes(&self.value)?,
            self.envelope.into_envelope()?,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredEnvelope {
    algorithm: String,
    nonce: String,
    hkdf_salt: String,
    wrapped_dek: String,
}

impl StoredEnvelope {
    fn from_envelope(envelope: &Envelope) -> Self {
        Self {
            algorithm: envelope.algorithm.to_string(),
            nonce: STANDARD.encode(&envelope.nonce),
            hkdf_salt: STANDARD.encode(&envelope.hkdf_salt),
            wrapped_dek: STANDARD.encode(&envelope.wrapped_dek),
        }
    }

    fn into_envelope(self) -> SecretsResult<Envelope> {
        Ok(Envelope {
            algorithm: self
                .algorithm
                .parse()
                .map_err(|_| SecretsError::Storage("invalid algorithm".into()))?,
            nonce: decode_bytes(&self.nonce)?,
            hkdf_salt: decode_bytes(&self.hkdf_salt)?,
            wrapped_dek: decode_bytes(&self.wrapped_dek)?,
        })
    }
}

fn parse_secret(item: SecretItem) -> SecretsResult<Option<SecretSnapshot>> {
    let version = item
        .metadata
        .labels
        .get(LABEL_VERSION)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| SecretsError::Storage("secret missing version label".into()))?;

    let deleted = item.metadata.labels.get(STATUS_LABEL).map(String::as_str) == Some("deleted");

    let record = if let Some(data) = item.data.and_then(|mut map| map.remove("record")) {
        let decoded = decode_bytes(&data)?;
        let stored: StoredRecord = serde_json::from_slice(&decoded).map_err(|err| {
            SecretsError::Storage(format!("failed to decode secret payload: {err}"))
        })?;
        Some(stored)
    } else {
        None
    };

    Ok(Some(SecretSnapshot {
        version,
        deleted,
        record,
    }))
}

fn secret_manifest(
    uri: &SecretUri,
    record: Option<&SecretRecord>,
    namespace: &str,
    name: &str,
    key: &str,
    version: u64,
    deleted: bool,
) -> SecretsResult<Value> {
    let mut labels = Map::new();
    labels.insert(LABEL_KEY.into(), Value::String(key.to_string()));
    labels.insert(LABEL_VERSION.into(), Value::String(version.to_string()));
    labels.insert(
        LABEL_ENV.into(),
        Value::String(uri.scope().env().to_string()),
    );
    labels.insert(
        LABEL_TENANT.into(),
        Value::String(uri.scope().tenant().to_string()),
    );
    if let Some(team) = uri.scope().team() {
        labels.insert(LABEL_TEAM.into(), Value::String(team.to_string()));
    }
    labels.insert(
        LABEL_CATEGORY.into(),
        Value::String(uri.category().to_string()),
    );
    labels.insert(LABEL_NAME.into(), Value::String(uri.name().to_string()));
    if deleted {
        labels.insert(STATUS_LABEL.into(), Value::String("deleted".into()));
    }

    let mut metadata = Map::new();
    metadata.insert("name".into(), Value::String(name.to_string()));
    metadata.insert("namespace".into(), Value::String(namespace.to_string()));
    metadata.insert("labels".into(), Value::Object(labels));

    let mut resource = Map::new();
    resource.insert("apiVersion".into(), Value::String("v1".into()));
    resource.insert("kind".into(), Value::String("Secret".into()));
    resource.insert("metadata".into(), Value::Object(metadata));
    resource.insert("type".into(), Value::String("Opaque".into()));

    if let Some(record) = record {
        let stored = StoredRecord::from_record(record)?;
        let payload = serde_json::to_vec(&stored)
            .map_err(|err| SecretsError::Storage(format!("failed to encode payload: {err}")))?;
        let mut data = Map::new();
        data.insert("record".into(), Value::String(STANDARD.encode(payload)));
        resource.insert("data".into(), Value::Object(data));
    }

    Ok(Value::Object(resource))
}

fn namespace_for_scope(config: &K8sProviderConfig, scope: &Scope) -> String {
    let mut labels = Vec::new();
    if !config.namespace_prefix.is_empty() {
        labels.push(sanitize_label(&config.namespace_prefix));
    }
    labels.push(sanitize_label(scope.env()));
    labels.push(sanitize_label(scope.tenant()));
    join_labels(&labels, NAMESPACE_MAX_LEN)
}

fn secret_resource_name(uri: &SecretUri, version: u64) -> String {
    let mut labels = Vec::new();
    if let Some(team) = uri.scope().team() {
        labels.push(sanitize_label(team));
    }
    labels.push(sanitize_label(uri.category()));
    labels.push(sanitize_label(uri.name()));
    labels.push(sanitize_label(&format!("v{version:04}")));
    join_labels(&labels, SECRET_NAME_MAX_LEN)
}

fn sanitize_label(value: &str) -> String {
    let mut label = String::new();
    for ch in value.chars() {
        match ch {
            'a'..='z' | '0'..='9' => label.push(ch),
            'A'..='Z' => label.push(ch.to_ascii_lowercase()),
            '-' | '_' | '.' | '/' => {
                if !label.ends_with('-') {
                    label.push('-');
                }
            }
            _ => {}
        }
    }
    while label.starts_with('-') {
        label.remove(0);
    }
    while label.ends_with('-') {
        label.pop();
    }
    if label.is_empty() {
        "default".into()
    } else {
        label
    }
}

fn join_labels(labels: &[String], max_len: usize) -> String {
    let mut result = String::new();
    for label in labels {
        if label.is_empty() {
            continue;
        }
        if !result.is_empty() {
            result.push('-');
        }
        result.push_str(label);
    }
    if result.is_empty() {
        result.push_str("default");
    }
    if result.len() > max_len {
        result.truncate(max_len);
        while result.ends_with('-') {
            result.pop();
        }
        if result.is_empty() {
            result.push_str("default");
        }
    }
    result
}

fn canonical_storage_key(uri: &SecretUri) -> String {
    let raw = format!(
        "{}/{}/{}/{}/{}",
        uri.scope().env(),
        uri.scope().tenant(),
        uri.scope().team().unwrap_or("_"),
        uri.category(),
        uri.name()
    );
    sanitize_label(&raw)
}

fn decode_bytes(input: &str) -> SecretsResult<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(|err| SecretsError::Storage(err.to_string()))
}

fn percent_encode(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::Scope;
    use serial_test::serial;
    use std::env;

    fn set_env(key: &str, value: &str) {
        unsafe { env::set_var(key, value) };
    }

    fn clear_env(key: &str) {
        unsafe { env::remove_var(key) };
    }

    fn setup_env() {
        set_env("K8S_API_SERVER", "http://127.0.0.1:9");
        set_env("K8S_BEARER_TOKEN", "test-token");
        set_env("K8S_NAMESPACE_PREFIX", "unit");
        set_env("K8S_KEK_ALIAS", "default");
        set_env("K8S_HTTP_TIMEOUT_SECS", "1");
        clear_env("K8S_BEARER_TOKEN_FILE");
        clear_env("K8S_CA_BUNDLE");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn k8s_provider_ok_under_tokio() {
        setup_env();
        let BackendComponents { backend, .. } =
            build_backend().await.expect("k8s backend builds from env");

        let scope = Scope::new("dev", "tenant", None).expect("scope");
        let result = backend.list(&scope, None, None);
        assert!(
            result.is_err(),
            "list should attempt network and surface the failure without panicking"
        );
    }
}
