use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use fs2::FileExt;
use greentic_secrets_spec::SecretsError as Error;
use greentic_secrets_spec::SecretsResult as Result;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use crate::state::{PersistedState, State};

pub(crate) const ENV_KEY: &str = "SECRETS_BACKEND_STATE";

#[derive(Clone)]
pub(crate) struct Persistence {
    pub(crate) path: PathBuf,
}

impl Persistence {
    pub(crate) fn load(path: PathBuf) -> Result<(State, Self)> {
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

    pub(crate) fn persist(&self, state: &State) -> Result<()> {
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
