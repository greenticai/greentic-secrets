//! Google Secret Manager provider backed by the real GCP APIs.
//!
//! The implementation talks to Secret Manager and Cloud KMS over HTTPS using
//! a bearer token supplied via environment variables. Secret payloads store the
//! full [`SecretRecord`] structure serialized as JSON so we can faithfully
//! restore metadata when reading secrets back.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use greentic_secrets_core::http::{Http, HttpResponse};
use greentic_secrets_spec::{
    KeyProvider, Scope, SecretListItem, SecretRecord, SecretUri, SecretVersion, SecretsBackend,
    SecretsError, SecretsResult, VersionedSecret,
};
use reqwest::{
    Method, StatusCode,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;
use std::sync::Arc;
use std::time::Duration;

const SECRET_MANAGER_ENDPOINT: &str = "https://secretmanager.googleapis.com/v1";
const KMS_ENDPOINT: &str = "https://cloudkms.googleapis.com/v1";
const DEFAULT_PREFIX: &str = "greentic";
const DEFAULT_TIMEOUT_SECS: u64 = 15;

fn read_response_body(response: HttpResponse) -> SecretsResult<(StatusCode, String)> {
    let status = response.status();
    let body = response
        .text()
        .map_err(|err| SecretsError::Storage(format!("failed to read HTTP body: {err}")))?;
    Ok((status, body))
}

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the GCP backend using environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = Arc::new(GcpProviderConfig::from_env()?);
    let http = Http::new(config.timeout)?;

    let backend = GcpSecretsBackend::new(config.clone(), http.clone());
    let key_provider = GcpKmsKeyProvider::new(config, http);

    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
struct GcpProviderConfig {
    project: String,
    secret_prefix: String,
    kms_key_name: String,
    access_token: String,
    secret_endpoint: String,
    kms_endpoint: String,
    timeout: Duration,
}

impl GcpProviderConfig {
    fn from_env() -> Result<Self> {
        let project = env::var("GREENTIC_GCP_PROJECT")
            .or_else(|_| env::var("GCP_PROJECT"))
            .context("set GREENTIC_GCP_PROJECT or GCP_PROJECT with your project id")?;

        let kms_key_name = env::var("GREENTIC_GCP_KMS_KEY")
            .context("set GREENTIC_GCP_KMS_KEY with the full Cloud KMS key resource")?;

        let access_token = env::var("GREENTIC_GCP_ACCESS_TOKEN")
            .or_else(|_| env::var("GOOGLE_OAUTH_ACCESS_TOKEN"))
            .context("set GREENTIC_GCP_ACCESS_TOKEN (or GOOGLE_OAUTH_ACCESS_TOKEN) with a valid bearer token")?;

        let secret_prefix = env::var("GREENTIC_GCP_SECRET_PREFIX")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_PREFIX.to_string());

        let secret_endpoint = env::var("GREENTIC_GCP_SM_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| SECRET_MANAGER_ENDPOINT.to_string());

        let kms_endpoint = env::var("GREENTIC_GCP_KMS_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| KMS_ENDPOINT.to_string());

        let timeout = env::var("GREENTIC_GCP_HTTP_TIMEOUT_SECS")
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

        Ok(Self {
            project,
            secret_prefix,
            kms_key_name,
            access_token,
            secret_endpoint,
            kms_endpoint,
            timeout,
        })
    }

    fn bearer(&self) -> String {
        format!("Bearer {access_token}", access_token = self.access_token)
    }

    fn auth_header(&self) -> SecretsResult<HeaderValue> {
        HeaderValue::from_str(&self.bearer()).map_err(|err| {
            SecretsError::Storage(format!("invalid authorization header value: {err}"))
        })
    }
}

#[derive(Clone)]
pub struct GcpSecretsBackend {
    config: Arc<GcpProviderConfig>,
    http: Http,
}

impl GcpSecretsBackend {
    fn new(config: Arc<GcpProviderConfig>, http: Http) -> Self {
        Self { config, http }
    }

    fn secret_id(&self, uri: &SecretUri) -> String {
        runtime_secret_id(&self.config.secret_prefix, uri)
    }

    /// Pre-fix id for `uri`, used only as a read-fallback so secrets written
    /// before the collision fix stay resolvable. Never written to. See #102.
    fn legacy_secret_id(&self, uri: &SecretUri) -> String {
        legacy_runtime_secret_id(&self.config.secret_prefix, uri)
    }

    /// Versions stored under the legacy id that are attributable to `uri`.
    ///
    /// The legacy id can be shared by colliding URIs (the bug this fix removes),
    /// so a non-empty legacy resource does NOT imply the data is `uri`'s. If any
    /// record under it names a different URI we ignore the whole resource:
    /// serving or extending it would re-introduce the collision. Reads then see
    /// the secret as absent under the (now collision-free) new id, so it can be
    /// re-provisioned safely. Returns empty when there is no legacy id distinct
    /// from the new id or no attributable history.
    fn legacy_versions_for(&self, uri: &SecretUri) -> SecretsResult<Vec<StoredSecret>> {
        let legacy = self.legacy_secret_id(uri);
        if legacy == self.secret_id(uri) {
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
                "legacy Secret Manager id is shared by colliding URIs; ignoring legacy history for this URI"
            );
            return Ok(Vec::new());
        }
        Ok(versions)
    }

    /// Full version history for `uri`: collision-safe-id versions plus any
    /// attributable legacy-id versions. New writes always target the
    /// collision-safe id and continue numbering above the legacy max, so the
    /// two histories never overlap and the secret is migrated forward on write.
    fn collect_versions(&self, uri: &SecretUri) -> SecretsResult<Vec<StoredSecret>> {
        let mut versions = self.load_all_versions(&self.secret_id(uri))?;
        versions.extend(self.legacy_versions_for(uri)?);
        versions.sort_by_key(|stored| stored.version);
        Ok(versions)
    }

    fn secret_resource(&self, secret_id: &str) -> String {
        format!(
            "{}/projects/{}/secrets/{}",
            self.config.secret_endpoint, self.config.project, secret_id
        )
    }

    fn request(
        &self,
        method: Method,
        url: String,
        body: Option<Value>,
    ) -> SecretsResult<HttpResponse> {
        let mut request = self.http.request(method, &url);
        let auth = self.config.auth_header()?;
        request = request.header(AUTHORIZATION.clone(), auth);
        if let Some(payload) = body {
            request = request.json(&payload);
        }
        request
            .send()
            .map_err(|err| SecretsError::Storage(format!("http request failed: {err}")))
    }

    fn ensure_secret_exists(&self, secret_id: &str) -> SecretsResult<()> {
        let url = format!(
            "{endpoint}/projects/{project}/secrets?secretId={secret_id}",
            endpoint = self.config.secret_endpoint,
            project = self.config.project,
            secret_id = secret_id
        );
        let body = json!({
            "replication": {"automatic": {}},
        });

        let response = self.request(Method::POST, url, Some(body))?;
        let (status, details) = read_response_body(response)?;
        match status {
            StatusCode::OK | StatusCode::CREATED => Ok(()),
            StatusCode::CONFLICT => Ok(()),
            status => Err(SecretsError::Storage(format!(
                "create secret {secret_id} failed: {status} {details}"
            ))),
        }
    }

    fn write_version(&self, secret_id: &str, payload: &StoredSecret) -> SecretsResult<u64> {
        let resource = self.secret_resource(secret_id);
        let encoded = encode_secret(payload)?;
        let url = format!("{resource}:addVersion");
        let body = json!({
            "payload": {
                "data": STANDARD.encode(encoded),
            }
        });

        let response = self.request(Method::POST, url, Some(body))?;
        let (status, text) = read_response_body(response)?;
        if !status.is_success() {
            return Err(SecretsError::Storage(format!(
                "add secret version failed: {status} {text}"
            )));
        }

        let parsed: SecretVersionCreateResponse = serde_json::from_str(&text).map_err(|err| {
            SecretsError::Storage(format!(
                "failed to parse addVersion response: {err}; body={text}"
            ))
        })?;
        parse_version_from_name(&parsed.name)
    }

    fn fetch_version_by_name(&self, name: &str) -> SecretsResult<Option<StoredSecret>> {
        let url = format!("{name}:access");
        let response = self.request(Method::GET, url, None)?;
        let status = response.status();
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => {
                let body = response
                    .text()
                    .map_err(|err| SecretsError::Storage(format!("failed to read body: {err}")))?;
                let parsed: AccessSecretVersionResponse =
                    serde_json::from_str(&body).map_err(|err| {
                        SecretsError::Storage(format!(
                            "failed to decode access response: {err}; body={body}"
                        ))
                    })?;
                let data = parsed
                    .payload
                    .and_then(|payload| payload.data)
                    .ok_or_else(|| SecretsError::Storage("secret payload missing data".into()))?;
                let decoded = STANDARD
                    .decode(data)
                    .map_err(|err| SecretsError::Storage(format!("base64 decode failed: {err}")))?;
                let stored: StoredSecret = serde_json::from_slice(&decoded).map_err(|err| {
                    SecretsError::Storage(format!("failed to parse stored secret: {err}"))
                })?;
                Ok(Some(stored))
            }
            status => {
                let body = response
                    .text()
                    .map_err(|err| SecretsError::Storage(format!("failed to read body: {err}")))?;
                Err(SecretsError::Storage(format!(
                    "access secret version failed: {status} {body}"
                )))
            }
        }
    }

    fn load_all_versions(&self, secret_id: &str) -> SecretsResult<Vec<StoredSecret>> {
        let resource = self.secret_resource(secret_id);
        let mut collected = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut url = format!("{resource}/versions?pageSize=100");
            if let Some(token) = &page_token {
                url.push_str("&pageToken=");
                url.push_str(token);
            }

            let response = self.request(Method::GET, url, None)?;
            match response.status() {
                StatusCode::NOT_FOUND => return Ok(Vec::new()),
                status if status.is_success() => {
                    let body = response.text().map_err(|err| {
                        SecretsError::Storage(format!("failed to read body: {err}"))
                    })?;
                    let parsed: SecretVersionsListResponse =
                        serde_json::from_str(&body).map_err(|err| {
                            SecretsError::Storage(format!(
                                "failed to parse versions list: {err}; body={body}"
                            ))
                        })?;

                    if let Some(entries) = parsed.versions {
                        for entry in entries {
                            if let Some(stored) = self.fetch_version_by_name(&entry.name)? {
                                collected.push(stored);
                            }
                        }
                    }

                    if let Some(next) = parsed.next_page_token {
                        page_token = Some(next);
                        continue;
                    }
                    break;
                }
                status => {
                    let body = response.text().map_err(|err| {
                        SecretsError::Storage(format!("failed to read body: {err}"))
                    })?;
                    return Err(SecretsError::Storage(format!(
                        "list secret versions failed: {status} {body}"
                    )));
                }
            }
        }

        collected.sort_by_key(|item| item.version);
        Ok(collected)
    }

    fn fetch_latest(&self, secret_id: &str) -> SecretsResult<Option<StoredSecret>> {
        let resource = self.secret_resource(secret_id);
        let url = format!("{resource}/versions/latest:access");
        let response = self.request(Method::GET, url, None)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => {
                let body = response
                    .text()
                    .map_err(|err| SecretsError::Storage(format!("failed to read body: {err}")))?;
                let parsed: AccessSecretVersionResponse =
                    serde_json::from_str(&body).map_err(|err| {
                        SecretsError::Storage(format!(
                            "failed to decode access response: {err}; body={body}"
                        ))
                    })?;
                let payload = parsed
                    .payload
                    .and_then(|p| p.data)
                    .ok_or_else(|| SecretsError::Storage("secret payload missing data".into()))?;
                let decoded = STANDARD
                    .decode(payload)
                    .map_err(|err| SecretsError::Storage(format!("base64 decode failed: {err}")))?;
                let stored: StoredSecret = serde_json::from_slice(&decoded).map_err(|err| {
                    SecretsError::Storage(format!("failed to parse stored secret: {err}"))
                })?;
                Ok(Some(stored))
            }
            status => {
                let body = response
                    .text()
                    .map_err(|err| SecretsError::Storage(format!("failed to read body: {err}")))?;
                Err(SecretsError::Storage(format!(
                    "access latest secret version failed: {status} {body}"
                )))
            }
        }
    }
}

impl SecretsBackend for GcpSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        // Always write the collision-safe id; never extend a (possibly shared)
        // legacy resource. Version numbering continues above any attributable
        // legacy history so the merged view stays monotonic.
        let versions = self.collect_versions(&record.meta.uri)?;
        let next_version = versions
            .iter()
            .map(|stored| stored.version)
            .max()
            .unwrap_or(0)
            + 1;

        let secret_id = self.secret_id(&record.meta.uri);
        self.ensure_secret_exists(&secret_id)?;
        let stored = StoredSecret::live(next_version, record.clone());
        self.write_version(&secret_id, &stored)?;

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
                .find(|stored| stored.version == requested && !stored.deleted)
                .and_then(|stored| stored.into_versioned()));
        }

        // Latest-only fast path: new writes always go to the collision-safe id,
        // so if it has any version that version is the global latest (a
        // tombstone there means deleted). Only when the new id is absent do we
        // consult the attributable legacy history.
        let secret_id = self.secret_id(uri);
        if let Some(stored) = self.fetch_latest(&secret_id)? {
            return Ok(if stored.deleted {
                None
            } else {
                stored.into_versioned()
            });
        }
        Ok(self
            .legacy_versions_for(uri)?
            .into_iter()
            .max_by_key(|stored| stored.version)
            .filter(|stored| !stored.deleted)
            .and_then(|stored| stored.into_versioned()))
    }

    fn list(
        &self,
        scope: &Scope,
        _category_prefix: Option<&str>,
        _name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        let filter = format!(
            "name:{prefix}-{env}-{tenant}",
            prefix = self.config.secret_prefix,
            env = scope.env(),
            tenant = scope.tenant()
        );
        let url = format!(
            "{endpoint}/projects/{project}/secrets",
            endpoint = self.config.secret_endpoint,
            project = self.config.project
        );

        let auth = self.config.auth_header()?;
        let response = self
            .http
            .get(&url)
            .header(AUTHORIZATION.clone(), auth)
            .query(&[("filter", filter.as_str())])
            .send()
            .map_err(|err| SecretsError::Storage(format!("list secrets request failed: {err}")))?;

        let (status, body) = read_response_body(response)?;
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

        let mut items = Vec::new();
        if let Some(secrets) = parsed.secrets {
            for entry in secrets {
                let segments: Vec<&str> = entry.name.split('/').collect();
                if segments.len() < 4 {
                    continue;
                }
                let secret_id = segments.last().copied().unwrap_or(entry.name.as_str());
                if let Some(stored) = self.fetch_latest(secret_id)? {
                    if stored.deleted {
                        continue;
                    }
                    if let Some(record) = stored.record {
                        items.push(SecretListItem::from_meta(
                            &record.meta,
                            Some(stored.version.to_string()),
                        ));
                    }
                }
            }
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
            .map(|stored| stored.version)
            .max()
            .unwrap_or(0)
            + 1;
        // Tombstone on the collision-safe id; ensure its container exists (the
        // secret may have lived only under the legacy id until now). The
        // tombstone shadows any legacy live version because it numbers above
        // the legacy max.
        let secret_id = self.secret_id(uri);
        self.ensure_secret_exists(&secret_id)?;
        let tombstone = StoredSecret::tombstone(next_version);
        self.write_version(&secret_id, &tombstone)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        Ok(self
            .collect_versions(uri)?
            .into_iter()
            .map(|stored| SecretVersion {
                version: stored.version,
                deleted: stored.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> SecretsResult<bool> {
        Ok(self.get(uri, None)?.is_some())
    }
}

#[derive(Clone)]
pub struct GcpKmsKeyProvider {
    config: Arc<GcpProviderConfig>,
    http: Http,
}

impl GcpKmsKeyProvider {
    fn new(config: Arc<GcpProviderConfig>, http: Http) -> Self {
        Self { config, http }
    }

    fn kms_request(&self, action: &str, body: Value) -> SecretsResult<Value> {
        let url = format!(
            "{}/{action}",
            self.config.kms_endpoint.trim_end_matches('/'),
            action = action
        );
        let auth = self.config.auth_header()?;
        let response = self
            .http
            .post(&url)
            .header(AUTHORIZATION.clone(), auth)
            .json(&body)
            .send()
            .map_err(|err| SecretsError::Backend(format!("kms request failed: {err}")))?;

        let (status, text) = read_response_body(response)?;
        if !status.is_success() {
            return Err(SecretsError::Backend(format!(
                "kms call failed: {status} {text}"
            )));
        }

        serde_json::from_str(&text).map_err(|err| {
            SecretsError::Backend(format!("failed to parse kms response: {err}; body={text}"))
        })
    }
}

impl KeyProvider for GcpKmsKeyProvider {
    fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let payload = json!({
            "plaintext": STANDARD.encode(dek),
        });
        let response = self.kms_request(
            &format!("{key_name}:encrypt", key_name = self.config.kms_key_name),
            payload,
        )?;
        let ciphertext = response
            .get("ciphertext")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                SecretsError::Backend("kms encrypt response missing ciphertext".into())
            })?;
        STANDARD
            .decode(ciphertext)
            .map_err(|err| SecretsError::Backend(format!("kms ciphertext decode failed: {err}")))
    }

    fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let payload = json!({
            "ciphertext": STANDARD.encode(wrapped),
        });
        let response = self.kms_request(
            &format!("{key_name}:decrypt", key_name = self.config.kms_key_name),
            payload,
        )?;
        let plaintext = response
            .get("plaintext")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                SecretsError::Backend("kms decrypt response missing plaintext".into())
            })?;
        STANDARD
            .decode(plaintext)
            .map_err(|err| SecretsError::Backend(format!("kms plaintext decode failed: {err}")))
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
        Some(VersionedSecret {
            version: self.version,
            deleted: self.deleted,
            record: self.record,
        })
    }
}

fn encode_secret(payload: &StoredSecret) -> SecretsResult<Vec<u8>> {
    serde_json::to_vec(payload)
        .map_err(|err| SecretsError::Storage(format!("failed to serialize secret payload: {err}")))
}

fn parse_version_from_name(name: &str) -> SecretsResult<u64> {
    name.rsplit('/')
        .next()
        .ok_or_else(|| SecretsError::Storage(format!("invalid version name: {name}")))?
        .parse::<u64>()
        .map_err(|err| SecretsError::Storage(format!("invalid version number: {err}")))
}

#[derive(Deserialize)]
struct SecretVersionCreateResponse {
    name: String,
}

#[derive(Deserialize)]
struct AccessSecretVersionResponse {
    payload: Option<SecretPayload>,
}

#[derive(Deserialize)]
struct SecretPayload {
    data: Option<String>,
}

#[derive(Deserialize)]
struct SecretVersionsListResponse {
    #[serde(default)]
    versions: Option<Vec<SecretVersionEntry>>,
    #[serde(rename = "nextPageToken")]
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct SecretVersionEntry {
    name: String,
}

#[derive(Deserialize)]
struct SecretListResponse {
    #[serde(default)]
    secrets: Option<Vec<SecretListEntry>>,
}

#[derive(Deserialize)]
struct SecretListEntry {
    name: String,
}

/// True when every record stored under a (possibly shared) legacy id belongs to
/// `uri`. A legacy id can collide across distinct URIs — that is the bug this
/// fix removes — so before treating legacy history as `uri`'s we require that no
/// stored record names a different URI. Tombstones carry no record and are
/// treated as `uri`'s.
fn legacy_history_attributable_to(versions: &[StoredSecret], uri: &SecretUri) -> bool {
    versions.iter().all(|stored| {
        stored
            .record
            .as_ref()
            .is_none_or(|rec| rec.meta.uri == *uri)
    })
}

fn runtime_secret_id(namespace_prefix: &str, uri: &SecretUri) -> String {
    greentic_secrets_spec::gcp_secret_manager_secret_id(namespace_prefix, uri)
}

fn legacy_runtime_secret_id(namespace_prefix: &str, uri: &SecretUri) -> String {
    greentic_secrets_spec::legacy_gcp_secret_manager_secret_id(namespace_prefix, uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::{SecretUri, gcp_secret_manager_secret_id};

    #[test]
    fn runtime_secret_id_matches_spec_contract() {
        let uri = SecretUri::parse("secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key")
            .expect("valid uri");

        // Writes use the collision-safe spec derivation; the legacy fallback
        // mirrors the spec legacy derivation; the two must differ.
        assert_eq!(
            runtime_secret_id("greentic", &uri),
            gcp_secret_manager_secret_id("greentic", &uri)
        );
        assert_eq!(
            legacy_runtime_secret_id("greentic", &uri),
            greentic_secrets_spec::legacy_gcp_secret_manager_secret_id("greentic", &uri)
        );
        assert_ne!(
            runtime_secret_id("greentic", &uri),
            legacy_runtime_secret_id("greentic", &uri)
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
        // legacy derivation (the bug) but get distinct collision-safe ids.
        let a = SecretUri::parse("secrets://dev/demo/_/a/b-c").unwrap();
        let b = SecretUri::parse("secrets://dev/demo/_/a-b/c").unwrap();
        assert_eq!(
            legacy_runtime_secret_id("p", &a),
            legacy_runtime_secret_id("p", &b)
        );
        assert_ne!(runtime_secret_id("p", &a), runtime_secret_id("p", &b));

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
