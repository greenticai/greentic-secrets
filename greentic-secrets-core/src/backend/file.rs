use crate::spec_compat::{
    Error as CoreError, Result as CoreResult, Scope, SecretListItem, SecretRecord, SecretUri,
    SecretVersion, SecretsBackend, VersionedSecret,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Filesystem-backed secrets storage using JSON-serialised records.
#[derive(Debug, Clone)]
pub struct FileBackend {
    root: PathBuf,
}

impl FileBackend {
    /// Construct a new file backend rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path_for_uri(&self, uri: &SecretUri) -> PathBuf {
        self.root
            .join(normalise_segment(uri.scope().env()))
            .join(normalise_segment(uri.scope().tenant()))
            .join(
                uri.scope()
                    .team()
                    .map(normalise_segment)
                    .unwrap_or_else(|| "_".into()),
            )
            .join(normalise_segment(uri.category()))
            .join(normalise_segment(uri.name()))
    }

    fn read_record(&self, uri: &SecretUri) -> CoreResult<Option<SecretRecord>> {
        let path = self.path_for_uri(uri);
        match fs::read(&path) {
            Ok(bytes) => {
                let record: SecretRecord = serde_json::from_slice(&bytes)
                    .map_err(|err| CoreError::Storage(err.to_string()))?;
                Ok(Some(record))
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(CoreError::Storage(err.to_string()))
                }
            }
        }
    }

    fn write_record(&self, record: &SecretRecord) -> CoreResult<()> {
        let path = self.path_for_uri(&record.meta.uri);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| CoreError::Storage(err.to_string()))?;
        }
        let data = serde_json::to_vec(record).map_err(|err| CoreError::Storage(err.to_string()))?;
        let temp_path = temp_path_for(&path);
        let result = (|| -> CoreResult<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|err| CoreError::Storage(err.to_string()))?;
            file.write_all(&data)
                .and_then(|_| file.sync_all())
                .map_err(|err| CoreError::Storage(err.to_string()))?;
            drop(file);

            fs::rename(&temp_path, &path).map_err(|err| CoreError::Storage(err.to_string()))?;
            if let Some(parent) = path.parent() {
                sync_directory(parent);
            }
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn delete_record(&self, uri: &SecretUri) -> CoreResult<()> {
        let path = self.path_for_uri(uri);
        match fs::remove_file(&path) {
            Ok(_) => Ok(()),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    Err(CoreError::NotFound {
                        entity: uri.to_string(),
                    })
                } else {
                    Err(CoreError::Storage(err.to_string()))
                }
            }
        }
    }

    fn base_dir(&self, scope: &Scope) -> PathBuf {
        self.root
            .join(normalise_segment(scope.env()))
            .join(normalise_segment(scope.tenant()))
            .join(
                scope
                    .team()
                    .map(normalise_segment)
                    .unwrap_or_else(|| "_".into()),
            )
    }
}

impl SecretsBackend for FileBackend {
    fn put(&self, record: SecretRecord) -> CoreResult<SecretVersion> {
        self.write_record(&record)?;
        Ok(SecretVersion {
            version: 1,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> CoreResult<Option<VersionedSecret>> {
        if version.is_some() {
            // File backend stores only the latest version.
            return Ok(None);
        }
        match self.read_record(uri)? {
            Some(record) => Ok(Some(VersionedSecret {
                version: 1,
                deleted: false,
                record: Some(record),
            })),
            None => Ok(None),
        }
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> CoreResult<Vec<SecretListItem>> {
        let base = self.base_dir(scope);
        if !base.exists() {
            return Ok(vec![]);
        }

        let mut items = Vec::new();
        for category_entry in read_dir_filtered(&base)? {
            let category_name = category_entry.0;
            let category_path = category_entry.1;
            if let Some(prefix) = category_prefix
                && !category_name.starts_with(prefix)
            {
                continue;
            }

            for secret_entry in read_dir_filtered(&category_path)? {
                let secret_name = secret_entry.0;
                let secret_path = secret_entry.1;
                if let Some(prefix) = name_prefix
                    && !secret_name.starts_with(prefix)
                {
                    continue;
                }

                let contents =
                    fs::read(&secret_path).map_err(|err| CoreError::Storage(err.to_string()))?;
                let record: SecretRecord = serde_json::from_slice(&contents)
                    .map_err(|err| CoreError::Storage(err.to_string()))?;
                items.push(SecretListItem::from_meta(
                    &record.meta,
                    Some("1".to_string()),
                ));
            }
        }

        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> CoreResult<SecretVersion> {
        self.delete_record(uri)?;
        Ok(SecretVersion {
            version: 1,
            deleted: true,
        })
    }

    fn versions(&self, _uri: &SecretUri) -> CoreResult<Vec<SecretVersion>> {
        Ok(vec![SecretVersion {
            version: 1,
            deleted: false,
        }])
    }

    fn exists(&self, uri: &SecretUri) -> CoreResult<bool> {
        Ok(self.path_for_uri(uri).exists())
    }
}

fn normalise_segment(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            _ => '_',
        })
        .collect()
}

fn temp_path_for(path: &Path) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "secret".into());
    path.with_file_name(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        counter
    ))
}

fn sync_directory(path: &Path) {
    let Ok(file) = fs::File::open(path) else {
        return;
    };
    let _ = file.sync_all();
}

fn read_dir_filtered(path: &Path) -> CoreResult<Vec<(String, PathBuf)>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(|err| CoreError::Storage(err.to_string()))? {
        let entry = entry.map_err(|err| CoreError::Storage(err.to_string()))?;
        let file_type = entry
            .file_type()
            .map_err(|err| CoreError::Storage(err.to_string()))?;
        if file_type.is_dir() || file_type.is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            entries.push((name, entry.path()));
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_compat::{ContentType, Envelope, SecretMeta, Visibility};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;
    use tempfile::tempdir;

    fn sample_record(uri: SecretUri) -> SecretRecord {
        let mut meta = SecretMeta::new(uri, Visibility::Team, ContentType::Json);
        meta.description = Some("file backend".into());
        let envelope = Envelope {
            algorithm: crate::spec_compat::EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![1, 2, 3],
            hkdf_salt: vec![4, 5, 6],
            wrapped_dek: vec![7, 8, 9],
        };
        SecretRecord::new(meta, br#"{"token":"value"}"#.to_vec(), envelope)
    }

    fn large_record(uri: SecretUri, idx: usize) -> SecretRecord {
        let mut record = sample_record(uri);
        record.meta.description = Some(format!("{}-{idx}", "x".repeat(1_000_000)));
        record.value = format!(r#"{{"token":"value-{idx}"}}"#).into_bytes();
        record
    }

    #[test]
    fn file_backend_get_and_list() {
        let dir = tempdir().unwrap();
        let backend = FileBackend::new(dir.path());
        let scope = Scope::new("dev", "tenant", Some("team".into())).unwrap();
        let uri = SecretUri::new(scope.clone(), "configs", "service").unwrap();
        let record = sample_record(uri.clone());

        backend.write_record(&record).unwrap();

        let fetched = backend.get(&uri, None).unwrap().unwrap();
        assert_eq!(fetched.record.unwrap().meta.uri, record.meta.uri);

        let items = backend
            .list(&scope, Some("configs"), Some("service"))
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].uri, record.meta.uri);
    }

    #[test]
    fn file_backend_missing_returns_none() {
        let dir = tempdir().unwrap();
        let backend = FileBackend::new(dir.path());
        let scope = Scope::new("dev", "tenant", None).unwrap();
        let uri = SecretUri::new(scope, "configs", "missing").unwrap();
        assert!(backend.get(&uri, None).unwrap().is_none());
    }

    #[test]
    fn file_backend_concurrent_writes_do_not_expose_partial_json() {
        let dir = tempdir().unwrap();
        let backend = Arc::new(FileBackend::new(dir.path()));
        let scope = Scope::new("dev", "tenant", Some("team".into())).unwrap();
        let uri = SecretUri::new(scope, "configs", "service").unwrap();
        backend.write_record(&large_record(uri.clone(), 0)).unwrap();

        let writer_backend = backend.clone();
        let writer_uri = uri.clone();
        let done = Arc::new(AtomicBool::new(false));
        let writer_done = done.clone();
        let writer = thread::spawn(move || {
            for idx in 1..=40 {
                writer_backend
                    .write_record(&large_record(writer_uri.clone(), idx))
                    .unwrap();
            }
            writer_done.store(true, Ordering::Release);
        });

        let mut reads = 0;
        while !done.load(Ordering::Acquire) || reads < 200 {
            let found = backend.get(&uri, None).unwrap().expect("record exists");
            let record = found.record.expect("record payload");
            assert_eq!(record.meta.uri, uri);
            reads += 1;
        }

        writer.join().unwrap();
        let items = backend.list(uri.scope(), Some("configs"), None).unwrap();
        assert_eq!(items.len(), 1);
    }
}
