//! Disk persistence for `DevBackend`. Supports legacy plaintext format
//! and encrypted v1 format with header + AES-GCM body.

use crate::marker;
use crate::state::{PersistedState, State};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use fs2::FileExt;
use greentic_secrets_passphrase::header::{EncryptedHeader, parse as parse_header};
use greentic_secrets_spec::{
    KeyProvider, Scope, SecretsError as Error, SecretsResult as Result,
};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;

const ENV_KEY: &str = "SECRETS_BACKEND_STATE";

/// Loaded state plus a flag indicating which format the file was in.
pub(crate) enum LoadedState {
    Encrypted {
        state: State,
        #[allow(dead_code)]
        header: EncryptedHeader,
    },
    Legacy {
        state: State,
    },
}

/// Mode for `Persistence::persist_with_mode`.
pub(crate) enum PersistMode {
    Plaintext,
    Encrypted {
        provider: Arc<dyn KeyProvider>,
        salt: [u8; 16],
    },
}

#[derive(Clone)]
pub(crate) struct Persistence {
    pub(crate) path: PathBuf,
}

impl Persistence {
    /// Load state from disk. If the file has an encrypted header, the
    /// provider must be `Some` and able to decrypt; otherwise this
    /// returns `Error::InvalidPassphrase`.
    ///
    /// Downgrade-attack guard: if a marker file is present but the store
    /// is legacy plaintext, returns `Error::Backend(...)` unless
    /// `allow_downgrade == true`.
    pub(crate) fn load_with_provider(
        path: PathBuf,
        provider: Option<Arc<dyn KeyProvider>>,
        allow_downgrade: bool,
    ) -> Result<(LoadedState, Self)> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| Error::Storage(e.to_string()))?;
        }
        let raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&path)
                    .map_err(|e| Error::Storage(e.to_string()))?;
                return Ok((
                    LoadedState::Legacy {
                        state: State::default(),
                    },
                    Self { path },
                ));
            }
            Err(e) => return Err(Error::Storage(e.to_string())),
        };

        if raw.is_empty() {
            return Ok((
                LoadedState::Legacy {
                    state: State::default(),
                },
                Self { path },
            ));
        }

        if raw.starts_with(b"# greentic-encrypted:") {
            let (header, body) = parse_header(&raw)
                .map_err(|e| Error::Storage(format!("encrypted header: {e}")))?;
            let state = parse_encrypted_body(&body, provider.as_deref())?;
            return Ok((
                LoadedState::Encrypted { state, header },
                Self { path },
            ));
        }

        // Legacy path. Check downgrade guard.
        if !allow_downgrade && marker::marker_exists(&path) {
            return Err(Error::Backend(
                "refusing to load legacy plaintext store after encryption was previously enabled (downgrade-attack guard); pass --allow-downgrade to override".to_string(),
            ));
        }

        let state = parse_legacy_body(&raw)?;
        Ok((LoadedState::Legacy { state }, Self { path }))
    }

    /// Persist `state` using the given mode. Atomic write via tmp+rename
    /// while holding an exclusive file lock. When mode is `Encrypted`,
    /// the marker file is also written/refreshed.
    pub(crate) fn persist_with_mode(&self, state: &State, mode: PersistMode) -> Result<()> {
        let json = serde_json::to_vec(&PersistedState::from_state(state))
            .map_err(|e| Error::Storage(e.to_string()))?;

        let tmp_path = self.path.with_extension("tmp");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| Error::Storage(e.to_string()))?;
        file.lock_exclusive()
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut header_bytes: Vec<u8> = Vec::new();
        {
            let mut writer = BufWriter::new(&file);
            let body_b64 = match &mode {
                PersistMode::Plaintext => STANDARD_NO_PAD.encode(&json),
                PersistMode::Encrypted { provider, salt } => {
                    let ciphertext = provider.wrap_dek(&dummy_scope(), &json)?;
                    let header = EncryptedHeader::new(*salt);
                    header
                        .write(&mut header_bytes)
                        .map_err(|e| Error::Storage(e.to_string()))?;
                    writer
                        .write_all(&header_bytes)
                        .map_err(|e| Error::Storage(e.to_string()))?;
                    STANDARD_NO_PAD.encode(&ciphertext)
                }
            };
            writer
                .write_all(format!("{ENV_KEY}={body_b64}\n").as_bytes())
                .map_err(|e| Error::Storage(e.to_string()))?;
            writer
                .flush()
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        file.sync_all().map_err(|e| Error::Storage(e.to_string()))?;
        let _ = fs2::FileExt::unlock(&file);
        drop(file);

        std::fs::rename(&tmp_path, &self.path)
            .map_err(|e| Error::Storage(e.to_string()))?;

        if !header_bytes.is_empty() {
            marker::write_marker(&self.path, &header_bytes)
                .map_err(|e| Error::Storage(format!("marker: {e}")))?;
        }
        Ok(())
    }
}

fn parse_encrypted_body(body: &[u8], provider: Option<&dyn KeyProvider>) -> Result<State> {
    let provider = provider.ok_or(Error::InvalidPassphrase)?;
    let s = std::str::from_utf8(body)
        .map_err(|_| Error::Storage("body not utf-8".into()))?;
    let line = s
        .lines()
        .find(|l| l.starts_with("SECRETS_BACKEND_STATE="))
        .ok_or_else(|| Error::Storage("missing body".into()))?;
    let b64 = line.trim_start_matches("SECRETS_BACKEND_STATE=");
    let ciphertext = STANDARD_NO_PAD
        .decode(b64.trim())
        .map_err(|e| Error::Storage(e.to_string()))?;
    let plaintext = provider.unwrap_dek(&dummy_scope(), &ciphertext)?;
    let persisted: PersistedState =
        serde_json::from_slice(&plaintext).map_err(|e| Error::Storage(e.to_string()))?;
    Ok(persisted.into_state())
}

fn parse_legacy_body(raw: &[u8]) -> Result<State> {
    let s = std::str::from_utf8(raw).map_err(|_| Error::Storage("non-utf8".into()))?;
    for line in s.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == ENV_KEY
        {
            let decoded = STANDARD_NO_PAD
                .decode(v.trim())
                .map_err(|e| Error::Storage(e.to_string()))?;
            let persisted: PersistedState = serde_json::from_slice(&decoded)
                .map_err(|e| Error::Storage(e.to_string()))?;
            return Ok(persisted.into_state());
        }
    }
    Ok(State::default())
}

fn dummy_scope() -> Scope {
    // Scope is currently ignored by KeyProvider impls in this crate;
    // a placeholder is acceptable. If/when scoped keys are introduced,
    // this call site must be revisited.
    Scope::new("dev", "internal", None).expect("static scope is valid")
}
