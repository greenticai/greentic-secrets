use greentic_secrets_spec::{SecretRecord, SecretVersion, VersionedSecret};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Default)]
pub(crate) struct State {
    pub(crate) entries: BTreeMap<String, Vec<VersionEntry>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct VersionEntry {
    pub(crate) version: u64,
    pub(crate) deleted: bool,
    pub(crate) record: Option<SecretRecord>,
}

impl VersionEntry {
    pub(crate) fn live(version: u64, record: SecretRecord) -> Self {
        Self {
            version,
            deleted: false,
            record: Some(record),
        }
    }

    pub(crate) fn tombstone(version: u64) -> Self {
        Self {
            version,
            deleted: true,
            record: None,
        }
    }

    pub(crate) fn as_version(&self) -> SecretVersion {
        SecretVersion {
            version: self.version,
            deleted: self.deleted,
        }
    }

    pub(crate) fn as_versioned(&self) -> VersionedSecret {
        VersionedSecret {
            version: self.version,
            deleted: self.deleted,
            record: self.record.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PersistedState {
    pub(crate) secrets: Vec<PersistedSecret>,
}

impl PersistedState {
    pub(crate) fn from_state(state: &State) -> Self {
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

    pub(crate) fn into_state(self) -> State {
        let mut entries = BTreeMap::new();
        for secret in self.secrets {
            entries.insert(secret.key, secret.versions);
        }
        State { entries }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PersistedSecret {
    pub(crate) key: String,
    pub(crate) versions: Vec<VersionEntry>,
}
