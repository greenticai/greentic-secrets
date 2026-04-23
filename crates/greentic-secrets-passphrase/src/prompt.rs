//! Interactive terminal prompts for passphrase entry.

use crate::error::{PassphraseError, Result};
use crate::{MAX_PROMPT_ATTEMPTS, MIN_PASSPHRASE_LENGTH};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

/// Prompt mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptMode {
    /// First-time setup: double-prompt with confirmation, enforce min length.
    Initial,
    /// Unlock existing store: single prompt, only enforce non-empty.
    Unlock,
}

/// Prompt the user for a passphrase from the controlling TTY.
///
/// Returns the entered passphrase wrapped in `SecretString` (zeroized on
/// drop). On `PromptMode::Initial`, prompts twice and confirms a match.
pub fn prompt_passphrase(mode: PromptMode) -> Result<SecretString> {
    match mode {
        PromptMode::Initial => prompt_initial(),
        PromptMode::Unlock => prompt_once("Enter passphrase to unlock secrets: "),
    }
}

fn prompt_initial() -> Result<SecretString> {
    for attempt in 1..=MAX_PROMPT_ATTEMPTS {
        let first = prompt_once(&format!(
            "Enter passphrase to protect secrets (min {MIN_PASSPHRASE_LENGTH} chars): "
        ))?;
        if let Err(e) = validate_initial(&first) {
            eprintln!("error: {e}");
            if attempt == MAX_PROMPT_ATTEMPTS {
                return Err(PassphraseError::TooManyAttempts);
            }
            continue;
        }
        let confirm = prompt_once("Confirm passphrase: ")?;
        if !constant_time_eq(&first, &confirm) {
            eprintln!("error: passphrases do not match");
            if attempt == MAX_PROMPT_ATTEMPTS {
                return Err(PassphraseError::TooManyAttempts);
            }
            continue;
        }
        return Ok(first);
    }
    Err(PassphraseError::TooManyAttempts)
}

fn prompt_once(message: &str) -> Result<SecretString> {
    let raw = rpassword::prompt_password(message)?;
    Ok(SecretString::from(raw))
}

/// Validate a passphrase against `PromptMode::Initial` rules.
/// Exposed (crate-public) for unit testing.
pub(crate) fn validate_initial(pass: &SecretString) -> Result<()> {
    let len = pass.expose_secret().chars().count();
    if len < MIN_PASSPHRASE_LENGTH {
        return Err(PassphraseError::PassphraseTooShort {
            min: MIN_PASSPHRASE_LENGTH,
            actual: len,
        });
    }
    Ok(())
}

/// Constant-time equality check on two `SecretString`s.
/// Exposed (crate-public) for unit testing.
pub(crate) fn constant_time_eq(a: &SecretString, b: &SecretString) -> bool {
    let a_bytes = a.expose_secret().as_bytes();
    let b_bytes = b.expose_secret().as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    a_bytes.ct_eq(b_bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_initial_accepts_min_length() {
        let pass = SecretString::from("a".repeat(MIN_PASSPHRASE_LENGTH));
        assert!(validate_initial(&pass).is_ok());
    }

    #[test]
    fn validate_initial_rejects_too_short() {
        let pass = SecretString::from("short".to_string());
        let err = validate_initial(&pass).unwrap_err();
        match err {
            PassphraseError::PassphraseTooShort { min, actual } => {
                assert_eq!(min, MIN_PASSPHRASE_LENGTH);
                assert_eq!(actual, 5);
            }
            other => panic!("expected PassphraseTooShort, got {other:?}"),
        }
    }

    #[test]
    fn validate_initial_counts_unicode_chars_not_bytes() {
        let pass = SecretString::from("\u{1F600}".repeat(12));
        assert!(validate_initial(&pass).is_ok());
    }

    #[test]
    fn constant_time_eq_returns_true_for_equal() {
        let a = SecretString::from("hello".to_string());
        let b = SecretString::from("hello".to_string());
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_returns_false_for_different() {
        let a = SecretString::from("hello".to_string());
        let b = SecretString::from("world".to_string());
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_returns_false_for_different_lengths() {
        let a = SecretString::from("short".to_string());
        let b = SecretString::from("much longer".to_string());
        assert!(!constant_time_eq(&a, &b));
    }
}
