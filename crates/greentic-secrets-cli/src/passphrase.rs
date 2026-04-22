//! Resolve the passphrase for the current process from one of three
//! sources, in priority order:
//!   1. `PassphraseSource::File(path)` — `--passphrase-file <PATH>`
//!   2. `PassphraseSource::Stdin` — `--passphrase-stdin` or `GREENTIC_PASSPHRASE_STDIN=1`
//!   3. `PassphraseSource::Tty(mode)` — interactive TTY prompt

use anyhow::{Context, Result, bail};
use greentic_secrets_passphrase::{
    PassphraseError, PromptMode, SecretString, prompt_passphrase, read_passphrase_from_file,
    read_passphrase_from_stdin,
};
use std::path::Path;

/// Where to read the passphrase from.
#[derive(Debug, Clone, Copy)]
pub enum PassphraseSource<'a> {
    /// Read from a 0600-mode file owned by the current user.
    File(&'a Path),
    /// Read first line of stdin (CI/daemon mode).
    Stdin,
    /// Prompt on the controlling TTY.
    Tty(PromptMode),
}

/// Resolve the passphrase using the given source.
///
/// On TTY-prompt failure due to missing terminal, returns a friendly
/// error directing the user to `--passphrase-stdin` or
/// `--passphrase-file`.
pub fn resolve(source: PassphraseSource<'_>) -> Result<SecretString> {
    match source {
        PassphraseSource::File(p) => read_passphrase_from_file(p)
            .with_context(|| format!("reading passphrase from {}", p.display())),
        PassphraseSource::Stdin => {
            read_passphrase_from_stdin().context("reading passphrase from stdin")
        }
        PassphraseSource::Tty(mode) => match prompt_passphrase(mode) {
            Ok(p) => Ok(p),
            Err(PassphraseError::TerminalIo(e))
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::Other =>
            {
                bail!(
                    "passphrase required but no TTY available; use --passphrase-stdin or --passphrase-file"
                );
            }
            Err(e) => Err(e.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn file_source_with_missing_file_returns_context_error() {
        let result = resolve(PassphraseSource::File(Path::new("/nonexistent/path/here")));
        let err = result.unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("reading passphrase from"),
            "expected context, got: {chain}"
        );
    }
}
