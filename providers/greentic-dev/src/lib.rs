use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use fs2::FileExt;
use greentic_secrets_spec::{
    KeyProvider, Scope, SecretListItem, SecretRecord, SecretUri, SecretVersion, SecretsBackend,
    SecretsError as Error, SecretsResult as Result, VersionedSecret,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_PERSIST_PATH: &str = ".dev.secrets.env";
const PERSIST_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";
const ENV_KEY: &str = "SECRETS_BACKEND_STATE";
const MASTER_KEY_ENV: &str = "GREENTIC_DEV_MASTER_KEY";

/// Simple development key provider that uses deterministic material to wrap DEKs.
#[derive(Clone, Default)]
pub struct DevKeyProvider {
    master_key: [u8; 32],
}

impl DevKeyProvider {
    /// Construct the provider from environment configuration.
    pub fn from_env() -> Self {
        let material = std::env::var(MASTER_KEY_ENV).unwrap_or_default();
        Self::from_material(material.as_bytes())
    }

    /// Construct the provider by hashing arbitrary input into a fixed-size key.
    pub fn from_material(input: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let digest = hasher.finalize();
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&digest);
        Self { master_key }
    }
}

impl KeyProvider for DevKeyProvider {
    fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> Result<Vec<u8>> {
        Ok(xor_with_key(dek, &self.master_key))
    }

    fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> Result<Vec<u8>> {
        Ok(xor_with_key(wrapped, &self.master_key))
    }
}

fn xor_with_key(input: &[u8], key: &[u8; 32]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ key[idx % key.len()])
        .collect()
}

#[derive(Clone, Default)]
struct State {
    entries: BTreeMap<String, Vec<VersionEntry>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct VersionEntry {
    version: u64,
    deleted: bool,
    record: Option<SecretRecord>,
}

impl VersionEntry {
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

#[derive(Clone)]
struct Persistence {
    path: PathBuf,
}

impl Persistence {
    fn load(path: PathBuf) -> Result<(State, Self)> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|err| Error::Storage(err.to_string()))?;

        file.lock_exclusive()
            .map_err(|err| Error::Storage(err.to_string()))?;

        let result = (|| -> Result<State> {
            let reader = BufReader::new(&file);
            for line in reader.lines() {
                let line = line.map_err(|err| Error::Storage(err.to_string()))?;
                if line.trim().is_empty() || line.starts_with('#') {
                    continue;
                }

                if let Some((key, value)) = line.split_once('=')
                    && key.trim() == ENV_KEY
                {
                    let decoded = STANDARD_NO_PAD
                        .decode(value.trim())
                        .map_err(|err| Error::Storage(err.to_string()))?;
                    let persisted: PersistedState = serde_json::from_slice(&decoded)
                        .map_err(|err| Error::Storage(err.to_string()))?;
                    return Ok(persisted.into_state());
                }
            }
            Ok(State::default())
        })();

        let _ = fs2::FileExt::unlock(&file);
        result.map(|state| (state, Self { path }))
    }

    fn persist(&self, state: &State) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|err| Error::Storage(err.to_string()))?;

        file.lock_exclusive()
            .map_err(|err| Error::Storage(err.to_string()))?;

        let persisted = PersistedState::from_state(state);
        let json = serde_json::to_vec(&persisted).map_err(|err| Error::Storage(err.to_string()))?;
        let encoded = STANDARD_NO_PAD.encode(json);

        let mut writer = BufWriter::new(&file);
        writer
            .write_all(format!("{ENV_KEY}={encoded}\n").as_bytes())
            .map_err(|err| Error::Storage(err.to_string()))?;
        writer
            .flush()
            .map_err(|err| Error::Storage(err.to_string()))?;

        let _ = fs2::FileExt::unlock(&file);
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    secrets: Vec<PersistedSecret>,
}

impl PersistedState {
    fn from_state(state: &State) -> Self {
        let secrets = state
            .entries
            .iter()
            .map(|(key, versions)| PersistedSecret {
                key: key.clone(),
                versions: versions.clone(),
            })
            .collect();
        Self { secrets }
    }

    fn into_state(self) -> State {
        let mut entries = BTreeMap::new();
        for secret in self.secrets {
            entries.insert(secret.key, secret.versions);
        }
        State { entries }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedSecret {
    key: String,
    versions: Vec<VersionEntry>,
}

/// Development backend that stores ciphertexts in-memory with optional .env persistence.
#[derive(Clone)]
pub struct DevBackend {
    state: Arc<RwLock<State>>,
    persistence: Option<Persistence>,
}

impl Default for DevBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DevBackend {
    /// Construct a purely in-memory backend.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(State::default())),
            persistence: None,
        }
    }

    /// Construct a backend that persists state to the specified .env file.
    pub fn with_persistence<P: Into<PathBuf>>(path: P) -> Result<Self> {
        let path = path.into();
        let (state, persistence) = Persistence::load(path)?;
        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            persistence: Some(persistence),
        })
    }

    /// Construct from environment configuration. If the configured file does not exist,
    /// the backend falls back to in-memory storage.
    pub fn from_env() -> Result<Self> {
        if let Ok(path) = std::env::var(PERSIST_ENV) {
            return Self::with_persistence(PathBuf::from(path));
        }

        let default_path = PathBuf::from(DEFAULT_PERSIST_PATH);
        if default_path.exists() {
            Self::with_persistence(default_path)
        } else {
            Ok(Self::new())
        }
    }

    fn persist_if_needed(&self, state: State) -> Result<()> {
        if let Some(persistence) = &self.persistence {
            persistence.persist(&state)?;
        }
        Ok(())
    }
}

impl SecretsBackend for DevBackend {
    fn put(&self, record: SecretRecord) -> Result<SecretVersion> {
        let key = record.meta.uri.to_string();
        let mut state_guard = self.state.write();
        let versions = state_guard.entries.entry(key).or_default();
        let next_version = versions.last().map(|v| v.version + 1).unwrap_or(1);

        versions.push(VersionEntry::live(next_version, record));
        let snapshot = if self.persistence.is_some() {
            Some(state_guard.clone())
        } else {
            None
        };
        drop(state_guard);

        if let Some(state) = snapshot {
            self.persist_if_needed(state)?;
        }

        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> Result<Option<VersionedSecret>> {
        let key = uri.to_string();
        let state = self.state.read();
        let versions = match state.entries.get(&key) {
            Some(versions) => versions,
            None => return Ok(None),
        };

        if let Some(target) = version {
            let entry = versions.iter().find(|entry| entry.version == target);
            return Ok(entry.cloned().map(|entry| entry.as_versioned()));
        }

        if matches!(versions.last(), Some(entry) if entry.deleted) {
            return Ok(None);
        }

        let latest = versions.iter().rev().find(|entry| !entry.deleted).cloned();
        Ok(latest.map(|entry| entry.as_versioned()))
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> Result<Vec<SecretListItem>> {
        let state = self.state.read();
        let mut items = Vec::new();

        for versions in state.entries.values() {
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

        items.sort_by_key(|a| a.uri.to_string());
        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> Result<SecretVersion> {
        let key = uri.to_string();
        let mut state_guard = self.state.write();
        let versions = match state_guard.entries.get_mut(&key) {
            Some(versions) => versions,
            None => {
                return Err(Error::NotFound {
                    entity: uri.to_string(),
                });
            }
        };

        let has_live = versions.iter().any(|entry| !entry.deleted);
        if !has_live {
            return Err(Error::NotFound {
                entity: uri.to_string(),
            });
        }

        let next_version = versions.last().map(|v| v.version + 1).unwrap_or(1);
        versions.push(VersionEntry::tombstone(next_version));
        let snapshot = if self.persistence.is_some() {
            Some(state_guard.clone())
        } else {
            None
        };
        drop(state_guard);

        if let Some(state) = snapshot {
            self.persist_if_needed(state)?;
        }

        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> Result<Vec<SecretVersion>> {
        let key = uri.to_string();
        let state = self.state.read();
        let versions = match state.entries.get(&key) {
            Some(versions) => versions,
            None => return Ok(Vec::new()),
        };

        Ok(versions.iter().map(|entry| entry.as_version()).collect())
    }

    fn exists(&self, uri: &SecretUri) -> Result<bool> {
        let key = uri.to_string();
        let state = self.state.read();
        let versions = match state.entries.get(&key) {
            Some(versions) => versions,
            None => return Ok(false),
        };

        Ok(matches!(versions.last(), Some(entry) if !entry.deleted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::{
        ContentType, EncryptionAlgorithm, Envelope, SecretMeta, Visibility,
    };
    use serde_json::json;

    fn sample_scope() -> Scope {
        Scope::new("dev", "acme", Some("payments".into())).unwrap()
    }

    fn sample_uri(scope: &Scope, category: &str, name: &str) -> SecretUri {
        SecretUri::new(scope.clone(), category, name).unwrap()
    }

    fn record(uri: &SecretUri, content_type: ContentType, payload: Vec<u8>) -> SecretRecord {
        let meta = SecretMeta::new(uri.clone(), Visibility::Team, content_type);
        let envelope = Envelope {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: Vec::new(),
            hkdf_salt: Vec::new(),
            wrapped_dek: Vec::new(),
        };
        SecretRecord::new(meta, payload, envelope)
    }

    #[test]
    fn backend_put_get_latest_and_versioned() {
        let backend = DevBackend::new();
        let scope = sample_scope();
        let uri = sample_uri(&scope, "kv", "db-password");

        let payload_v1 = serde_json::to_vec(&json!({"password": "s3cr3t"})).unwrap();
        let v1 = backend
            .put(record(&uri, ContentType::Json, payload_v1.clone()))
            .unwrap();
        assert_eq!(v1.version, 1);

        let latest = backend.get(&uri, None).unwrap().expect("latest record");
        assert_eq!(latest.version, 1);
        let stored = latest.record.expect("record payload");
        assert_eq!(stored.value, payload_v1);
        assert_eq!(stored.meta.content_type, ContentType::Json);

        let payload_v2 = serde_json::to_vec(&json!({"password": "n3w"})).unwrap();
        let v2 = backend
            .put(record(&uri, ContentType::Json, payload_v2.clone()))
            .unwrap();
        assert_eq!(v2.version, 2);

        let latest = backend.get(&uri, None).unwrap().expect("latest record");
        assert_eq!(latest.version, 2);
        let stored = latest.record.expect("record payload");
        assert_eq!(stored.value, payload_v2);

        let version_one = backend.get(&uri, Some(1)).unwrap().expect("v1 record");
        assert_eq!(version_one.version, 1);
        let stored = version_one.record.expect("record payload");
        assert_eq!(
            stored.value,
            serde_json::to_vec(&json!({"password": "s3cr3t"})).unwrap()
        );
    }

    #[test]
    fn list_with_prefix() {
        let backend = DevBackend::new();
        let scope = sample_scope();
        let uri_api = sample_uri(&scope, "kv", "api-token");
        let uri_db = sample_uri(&scope, "kv", "db-password");
        let uri_cfg = sample_uri(&scope, "config", "feature-flags");

        backend
            .put(record(&uri_api, ContentType::Opaque, b"api".to_vec()))
            .unwrap();
        backend
            .put(record(&uri_db, ContentType::Text, b"db".to_vec()))
            .unwrap();
        backend
            .put(record(
                &uri_cfg,
                ContentType::Json,
                serde_json::to_vec(&json!({"feature": true})).unwrap(),
            ))
            .unwrap();

        let kv = backend.list(&scope, Some("kv"), None).unwrap();
        assert_eq!(kv.len(), 2);

        let api_only = backend.list(&scope, Some("kv"), Some("api")).unwrap();
        assert_eq!(api_only.len(), 1);
        assert!(api_only[0].uri.to_string().contains("api-token"));
    }

    #[test]
    fn delete_and_restore() {
        let backend = DevBackend::new();
        let scope = sample_scope();
        let uri = sample_uri(&scope, "kv", "session-key");

        backend
            .put(record(&uri, ContentType::Binary, vec![0x01, 0x02, 0x03]))
            .unwrap();

        assert!(backend.exists(&uri).unwrap());
        backend.delete(&uri).unwrap();
        assert!(!backend.exists(&uri).unwrap());
        assert!(backend.get(&uri, None).unwrap().is_none());

        backend
            .put(record(&uri, ContentType::Binary, vec![0xAA, 0xBB]))
            .unwrap();

        let latest = backend.get(&uri, None).unwrap().expect("restored");
        let record = latest.record.expect("record payload");
        assert_eq!(record.value, vec![0xAA, 0xBB]);
        assert!(backend.exists(&uri).unwrap());
    }

    #[test]
    fn content_types_round_trip() {
        let backend = DevBackend::new();
        let scope = sample_scope();

        let text_uri = sample_uri(&scope, "kv", "text");
        let bin_uri = sample_uri(&scope, "kv", "bin");

        backend
            .put(record(
                &text_uri,
                ContentType::Text,
                b"hello world".to_vec(),
            ))
            .unwrap();
        backend
            .put(record(&bin_uri, ContentType::Binary, vec![0, 1, 2, 3]))
            .unwrap();

        let text_record = backend
            .get(&text_uri, None)
            .unwrap()
            .unwrap()
            .record
            .unwrap();
        assert_eq!(text_record.meta.content_type, ContentType::Text);
        assert_eq!(text_record.value, b"hello world".to_vec());

        let bin_record = backend
            .get(&bin_uri, None)
            .unwrap()
            .unwrap()
            .record
            .unwrap();
        assert_eq!(bin_record.meta.content_type, ContentType::Binary);
        assert_eq!(bin_record.value, vec![0, 1, 2, 3]);
    }

    #[test]
    fn key_provider_wrap_unwrap() {
        let provider = DevKeyProvider::from_material(b"material");
        let scope = sample_scope();
        let dek = vec![1, 2, 3, 4, 5];
        let wrapped = provider.wrap_dek(&scope, &dek).unwrap();
        assert_eq!(wrapped.len(), dek.len());
        assert_ne!(wrapped, dek);
        let unwrapped = provider.unwrap_dek(&scope, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }
}
