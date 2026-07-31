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
use std::io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::NamedTempFile;

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

/// Whether two paths refer to the same store — lexically equal, or resolving to
/// the same file (catches a symlinked destination). Used to refuse an export
/// that would rewrite its own source.
fn paths_alias(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    matches!((a.canonicalize(), b.canonicalize()), (Ok(ca), Ok(cb)) if ca == cb)
}

/// The versionless canonical form of a stored key, or `None` if it is not a
/// parseable secret URI. Backend keys are `SecretUri::to_string()` outputs, so
/// this normally round-trips; `None` only for a corrupt store line.
fn versionless_key(key: &str) -> Option<String> {
    SecretUri::parse(key)
        .ok()?
        .with_version(None)
        .ok()
        .map(|uri| uri.to_string())
}

/// The versionless canonical form of each exclusion URI.
fn versionless_keys(uris: &[&SecretUri]) -> Result<Vec<String>> {
    uris.iter()
        .map(|uri| {
            (**uri)
                .clone()
                .with_version(None)
                .map(|normalized| normalized.to_string())
                .map_err(|err| Error::Storage(err.to_string()))
        })
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
    /// Parse the persisted state out of an already-open, already-locked file.
    /// Shared by [`load`](Self::load) (exclusive lock) and
    /// [`snapshot`](Self::snapshot) (shared lock).
    fn read_state(file: &std::fs::File) -> Result<State> {
        let reader = BufReader::new(file);
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
    }

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

        let result = Self::read_state(&file);

        let _ = fs2::FileExt::unlock(&file);
        result.map(|state| (state, Self { path }))
    }

    /// Read a consistent snapshot of the persisted state WITHOUT creating or
    /// modifying the file. Opens read-only (so a read-only store still works)
    /// and holds a shared lock during the read; the shared lock conflicts with
    /// [`persist`](Self::persist)'s exclusive lock, so a concurrent writer
    /// cannot yield a torn snapshot. A missing file is an error, never a
    /// silently-recreated empty state.
    fn snapshot(path: &Path) -> Result<State> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|err| Error::Storage(err.to_string()))?;
        file.lock_shared()
            .map_err(|err| Error::Storage(err.to_string()))?;
        let result = Self::read_state(&file);
        let _ = fs2::FileExt::unlock(&file);
        result
    }

    fn persist(&self, state: &State) -> Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .map_err(|err| Error::Storage(err.to_string()))?;

        file.lock_exclusive()
            .map_err(|err| Error::Storage(err.to_string()))?;

        let result = (|| -> Result<()> {
            file.set_len(0)
                .map_err(|err| Error::Storage(err.to_string()))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|err| Error::Storage(err.to_string()))?;

            let persisted = PersistedState::from_state(state);
            let json =
                serde_json::to_vec(&persisted).map_err(|err| Error::Storage(err.to_string()))?;
            let encoded = STANDARD_NO_PAD.encode(json);

            let mut writer = BufWriter::new(&file);
            writer
                .write_all(format!("{ENV_KEY}={encoded}\n").as_bytes())
                .map_err(|err| Error::Storage(err.to_string()))?;
            writer
                .flush()
                .map_err(|err| Error::Storage(err.to_string()))?;
            Ok(())
        })();

        let _ = fs2::FileExt::unlock(&file);
        result
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

    /// Write a sanitized copy of the dev-store persisted at `src` to `dest`,
    /// hard-excluding every entry whose URI is in `exclude`.
    ///
    /// Excluded URIs leave **no** residual ciphertext in `dest`: the whole key is
    /// dropped from the snapshot before it is ever written, unlike the
    /// tombstoning [`SecretsBackend::delete`] (which leaves the prior live
    /// version's encrypted `record` on disk). Intended for stripping
    /// control-plane material — e.g. a bound deployer credential — before a store
    /// is staged into an untrusted runtime seed.
    ///
    /// The operation is transactional and lock-safe:
    /// - it reads a consistent snapshot of `src` read-only under a shared lock
    ///   (which conflicts with the writer's exclusive lock), so a concurrent
    ///   writer cannot yield a torn or empty result and a `src` removed between
    ///   calls fails loudly instead of being recreated empty;
    /// - it never opens `src` for writing;
    /// - it builds the sanitized store in a private temp file in `dest`'s
    ///   directory and publishes it with a **no-clobber** rename, so `dest` never
    ///   transiently holds an excluded entry and any failure leaves `dest`
    ///   untouched.
    ///
    /// # Limitation
    ///
    /// The alias and no-clobber guards resolve pathnames, so the source-integrity
    /// and no-clobber guarantees assume the **directories on the `src` and `dest`
    /// paths are not concurrently manipulated by another actor** (e.g. a symlink
    /// in `dest`'s parent repointed between the snapshot and the publish). Callers
    /// must stage to a directory they control — a private temp dir is ideal.
    /// Hardening against a hostile dest-parent (openat/`O_NOFOLLOW`
    /// directory-handle operations) is out of scope for this local-store staging
    /// primitive.
    ///
    /// `src` must exist and `dest` must be a **fresh** path that does not yet
    /// exist and does not resolve to `src` — a pre-existing `dest` (including
    /// `src`, a symlink to it, or a file a live backend still holds open) is
    /// rejected rather than replaced, since replacing it could let a stale
    /// in-memory snapshot resurrect an excluded record at `dest`.
    pub fn export_excluding(src: &Path, dest: &Path, exclude: &[&SecretUri]) -> Result<()> {
        // Reject a destination that is (or resolves to) the source up front. This
        // is deterministic (no publish-time TOCTOU): were `src == dest`, a
        // concurrent unlink of `src` after the snapshot could otherwise let the
        // no-clobber publish succeed against the vanished pathname and recreate
        // the operator's store with excluded records removed.
        if paths_alias(src, dest) {
            return Err(Error::Storage(
                "export destination must differ from the source store".to_string(),
            ));
        }

        // Consistent read-only snapshot under a shared lock; src is never opened
        // for writing or created.
        let mut state = Persistence::snapshot(src)?;

        // Compare on canonical (versionless) identity on BOTH sides. DevStore
        // accepts version-qualified URIs, so a store can hold `…/name@1` and an
        // exclusion can be `…/name` (or `…/name@2`); every version of the
        // underlying secret must be stripped. Backend versions also live under a
        // single versionless key, so this strips the whole `Vec<VersionEntry>`.
        let excluded = versionless_keys(exclude)?;
        state
            .entries
            .retain(|stored_key, _| match versionless_key(stored_key) {
                Some(canonical) => !excluded.contains(&canonical),
                // An unparseable stored key cannot equal a well-formed excluded
                // URI, so it is never the excluded secret — keep it rather than
                // risk dropping an unrelated runtime entry.
                None => true,
            });

        let persisted = PersistedState::from_state(&state);
        let json = serde_json::to_vec(&persisted).map_err(|err| Error::Storage(err.to_string()))?;
        let encoded = STANDARD_NO_PAD.encode(json);

        // Publish atomically to a fresh dest: write a private temp file in dest's
        // directory, fsync, then rename with no-clobber. The excluded entries are
        // never written, so there is nothing to erase after the fact.
        let dir = dest
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut tmp = NamedTempFile::new_in(dir).map_err(|err| Error::Storage(err.to_string()))?;
        tmp.write_all(format!("{ENV_KEY}={encoded}\n").as_bytes())
            .map_err(|err| Error::Storage(err.to_string()))?;
        tmp.as_file()
            .sync_all()
            .map_err(|err| Error::Storage(err.to_string()))?;
        tmp.persist_noclobber(dest)
            .map_err(|err| Error::Storage(err.to_string()))?;
        Ok(())
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
    use std::fs;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const PERSIST_CHILD_ENV: &str = "GREENTIC_DEV_PERSIST_CHILD";

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

    #[test]
    fn persistence_does_not_truncate_before_lock() {
        if let Some(path) = std::env::var_os(PERSIST_CHILD_ENV) {
            Persistence {
                path: PathBuf::from(path),
            }
            .persist(&State::default())
            .unwrap();
            return;
        }

        let temp = std::env::temp_dir().join(format!(
            "greentic-dev-persist-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&temp).unwrap();
        let path = temp.join(".dev.secrets.env");
        let original = format!("{ENV_KEY}=eyJzZWNyZXRzIjpbXX0\n");
        fs::write(&path, &original).unwrap();

        let locked = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        locked.lock_exclusive().unwrap();

        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("persistence_does_not_truncate_before_lock")
            .arg("--exact")
            .env(PERSIST_CHILD_ENV, &path)
            .spawn()
            .unwrap();

        thread::sleep(Duration::from_millis(250));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);

        fs2::FileExt::unlock(&locked).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());

        DevBackend::with_persistence(&path).unwrap();
        fs::remove_dir_all(&temp).unwrap();
    }

    /// Decode the persisted `SECRETS_BACKEND_STATE=` blob and return the URI keys
    /// it actually holds on disk — so a test can assert on residual ciphertext,
    /// not just on what the API returns.
    fn persisted_keys(path: &std::path::Path) -> Vec<String> {
        let contents = fs::read_to_string(path).unwrap();
        let encoded = contents
            .lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{ENV_KEY}=")))
            .expect("persisted state line");
        let bytes = STANDARD_NO_PAD.decode(encoded.trim()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|secret| secret["key"].as_str().unwrap().to_string())
            .collect()
    }

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "greentic-dev-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    fn seed_store(path: &Path, entries: &[(&SecretUri, &[u8])]) {
        let backend = DevBackend::with_persistence(path).unwrap();
        for (uri, payload) in entries {
            backend
                .put(record(uri, ContentType::Text, payload.to_vec()))
                .unwrap();
        }
    }

    #[test]
    fn export_excluding_drops_only_excluded_keys_and_leaves_src_intact() {
        let temp = unique_temp_dir("export");
        let src = temp.join(".dev.secrets.env");
        let dest = temp.join(".seed.secrets.env");
        let scope = sample_scope();
        let cred = sample_uri(&scope, "kv", "deployer-credential");
        let runtime = sample_uri(&scope, "kv", "runtime-token");
        seed_store(&src, &[(&cred, b"SA-KEY"), (&runtime, b"tok")]);

        DevBackend::export_excluding(&src, &dest, &[&cred]).unwrap();

        // dest: the credential key is gone entirely (no record, no ciphertext);
        // the runtime secret is carried over.
        let dest_keys = persisted_keys(&dest);
        assert!(
            !dest_keys.contains(&cred.to_string()),
            "excluded credential must not persist in the staged copy"
        );
        assert!(
            dest_keys.contains(&runtime.to_string()),
            "runtime secret must survive the export"
        );

        // src: never modified — still resolves both entries.
        let src_keys = persisted_keys(&src);
        assert!(
            src_keys.contains(&cred.to_string()) && src_keys.contains(&runtime.to_string()),
            "source store must be left intact"
        );

        // A fresh reader (the workload's view of the staged file) cannot recover
        // the credential, but still resolves the runtime secret.
        let reopened = DevBackend::with_persistence(&dest).unwrap();
        assert!(reopened.get(&cred, None).unwrap().is_none());
        assert!(reopened.get(&runtime, None).unwrap().is_some());

        fs::remove_dir_all(&temp).unwrap();
    }

    #[test]
    fn export_excluding_removes_key_that_delete_would_leave_on_disk() {
        // Negative control: delete() only tombstones (the key + ciphertext stay
        // on disk — the H3 leak); export drops the whole key.
        let temp = unique_temp_dir("export-vs-delete");
        let src = temp.join(".dev.secrets.env");
        let dest = temp.join(".seed.secrets.env");
        let scope = sample_scope();
        let cred = sample_uri(&scope, "kv", "deployer-credential");

        seed_store(&src, &[(&cred, b"SA-KEY")]);
        let backend = DevBackend::with_persistence(&src).unwrap();
        backend.delete(&cred).unwrap();
        drop(backend);
        assert!(
            persisted_keys(&src).contains(&cred.to_string()),
            "delete tombstones but leaves the key + ciphertext on disk"
        );

        fs::remove_file(&src).unwrap();
        seed_store(&src, &[(&cred, b"SA-KEY")]);
        DevBackend::export_excluding(&src, &dest, &[&cred]).unwrap();
        assert!(
            !persisted_keys(&dest).contains(&cred.to_string()),
            "export drops the whole key — no residual ciphertext"
        );

        fs::remove_dir_all(&temp).unwrap();
    }

    #[test]
    fn export_excluding_rejects_missing_src_and_pre_existing_dest() {
        let temp = unique_temp_dir("export-guards");
        let src = temp.join(".dev.secrets.env");
        let dest = temp.join(".seed.secrets.env");
        let scope = sample_scope();
        let cred = sample_uri(&scope, "kv", "deployer-credential");

        // Missing src → error (no silent recreate), and no dest is created.
        assert!(DevBackend::export_excluding(&src, &dest, &[&cred]).is_err());
        assert!(!src.exists(), "a missing source must not be recreated");
        assert!(!dest.exists());

        seed_store(&src, &[(&cred, b"SA-KEY")]);

        // dest == src → rejected (no-clobber), src untouched.
        assert!(DevBackend::export_excluding(&src, &src, &[&cred]).is_err());
        assert!(
            persisted_keys(&src).contains(&cred.to_string()),
            "source must be untouched when dest resolves to it"
        );

        // A pre-existing, unrelated dest → rejected rather than replaced (a live
        // backend could still hold its stale state and later resurrect a record).
        fs::write(&dest, b"pre-existing\n").unwrap();
        assert!(DevBackend::export_excluding(&src, &dest, &[&cred]).is_err());
        assert_eq!(
            fs::read(&dest).unwrap(),
            b"pre-existing\n",
            "a pre-existing dest must be left untouched, not overwritten"
        );

        fs::remove_dir_all(&temp).unwrap();
    }

    #[test]
    fn export_excluding_normalizes_versioned_exclusions() {
        // A stored key is versionless; excluding it with an `@version` suffix
        // must still strip the whole (versioned + versionless) entry.
        let temp = unique_temp_dir("export-version");
        let src = temp.join(".dev.secrets.env");
        let dest = temp.join(".seed.secrets.env");
        let scope = sample_scope();
        let cred = sample_uri(&scope, "kv", "deployer-credential");
        seed_store(&src, &[(&cred, b"SA-KEY")]);

        let versioned = cred.clone().with_version(Some("1")).unwrap();
        DevBackend::export_excluding(&src, &dest, &[&versioned]).unwrap();
        assert!(
            !persisted_keys(&dest).contains(&cred.to_string()),
            "a version-qualified exclusion must strip the versionless stored key"
        );

        fs::remove_dir_all(&temp).unwrap();
    }

    #[test]
    fn export_excluding_strips_a_version_qualified_stored_key() {
        // The store itself holds a version-qualified key `…@1`; a versionless
        // exclusion must still strip it (canonical-identity comparison).
        let temp = unique_temp_dir("export-stored-version");
        let src = temp.join(".dev.secrets.env");
        let dest = temp.join(".seed.secrets.env");
        let scope = sample_scope();
        let cred = sample_uri(&scope, "kv", "deployer-credential");
        let versioned = cred.clone().with_version(Some("1")).unwrap();
        seed_store(&src, &[(&versioned, b"SA-KEY")]);
        assert!(
            persisted_keys(&src).iter().any(|key| key.ends_with("@1")),
            "the stored key is version-qualified"
        );

        DevBackend::export_excluding(&src, &dest, &[&cred]).unwrap();
        assert!(
            persisted_keys(&dest)
                .iter()
                .all(|key| !key.contains("deployer-credential")),
            "a versionless exclusion must strip a version-qualified stored key"
        );

        fs::remove_dir_all(&temp).unwrap();
    }

    #[test]
    fn export_excluding_with_no_exclusions_carries_all_entries() {
        let temp = unique_temp_dir("export-empty");
        let src = temp.join(".dev.secrets.env");
        let dest = temp.join(".seed.secrets.env");
        let scope = sample_scope();
        let a = sample_uri(&scope, "kv", "alpha");
        let b = sample_uri(&scope, "kv", "beta");
        seed_store(&src, &[(&a, b"1"), (&b, b"2")]);

        DevBackend::export_excluding(&src, &dest, &[]).unwrap();
        let keys = persisted_keys(&dest);
        assert!(keys.contains(&a.to_string()) && keys.contains(&b.to_string()));

        fs::remove_dir_all(&temp).unwrap();
    }
}
