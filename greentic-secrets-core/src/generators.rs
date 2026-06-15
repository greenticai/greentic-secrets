//! The concrete secret generator behind a pack's `generated` block — one
//! implementation shared by start/setup/deployer so a pack mints identical
//! material everywhere, instead of each repo carrying its own CSPRNG with a
//! slightly different alphabet/length.
//!
//! Faithful to the historical greentic-start `generated_secret_value`: policy
//! `random`, encodings `raw_text` (a 64-char ASCII alphabet), `base64url`
//! (URL-safe, no pad), and `hex` (lowercase). `length` is the character count
//! for `raw_text` and the raw random-byte count for `base64url`/`hex`.

use crate::errors::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use greentic_secrets_spec::GeneratedSecretRequirement;
use greentic_types::secrets::SecretFormat;
use rand::{Rng, RngExt};

/// Alphabet for the `raw_text` encoding — `[A-Za-z0-9_-]` (64 chars).
const RAW_TEXT_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// Mint a value for a pack-declared generated secret, returning the value bytes
/// and the [`SecretFormat`] they should be stored under.
///
/// Errors with [`Error::Invalid`] on an unsupported policy or encoding, matching
/// the runtime's historical behavior (a malformed pack fails loudly rather than
/// silently producing the wrong shape). Uses the crate's CSPRNG (`rand::rng()`).
pub fn generate_secret_value(
    generated: &GeneratedSecretRequirement,
) -> Result<(Vec<u8>, SecretFormat)> {
    if !generated.policy.eq_ignore_ascii_case("random") {
        return Err(Error::Invalid(
            "generated secret policy".to_string(),
            generated.policy.clone(),
        ));
    }
    let length = generated.length.max(1);
    let text = match generated.encoding.as_str() {
        "raw_text" => random_ascii(length),
        "base64url" => URL_SAFE_NO_PAD.encode(random_bytes(length)),
        "hex" => hex_encode(&random_bytes(length)),
        other => {
            return Err(Error::Invalid(
                "generated secret encoding".to_string(),
                other.to_string(),
            ));
        }
    };
    Ok((text.into_bytes(), SecretFormat::Text))
}

fn random_ascii(length: usize) -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(length);
    for _ in 0..length {
        let idx = rng.random_range(0..RAW_TEXT_ALPHABET.len());
        out.push(RAW_TEXT_ALPHABET[idx] as char);
    }
    out
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; len];
    rand::rng().fill_bytes(&mut buffer);
    buffer
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::GeneratedSecretScope;

    fn spec(encoding: &str, length: usize) -> GeneratedSecretRequirement {
        GeneratedSecretRequirement {
            policy: "random".to_string(),
            length,
            encoding: encoding.to_string(),
            scope: GeneratedSecretScope {
                level: "tenant".to_string(),
                team: Some("_".to_string()),
            },
            regenerate_if_present: false,
        }
    }

    #[test]
    fn raw_text_has_requested_length_and_charset() {
        let (bytes, fmt) = generate_secret_value(&spec("raw_text", 20)).unwrap();
        assert_eq!(fmt, SecretFormat::Text);
        assert_eq!(bytes.len(), 20);
        assert!(bytes.iter().all(|b| RAW_TEXT_ALPHABET.contains(b)));
    }

    #[test]
    fn hex_is_two_chars_per_byte() {
        let (bytes, _) = generate_secret_value(&spec("hex", 16)).unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn base64url_decodes_to_requested_byte_count() {
        let (b64, _) = generate_secret_value(&spec("base64url", 24)).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&b64).unwrap().len(), 24);
        // URL-safe, no padding.
        assert!(!b64.contains(&b'='));
        assert!(!b64.contains(&b'+'));
        assert!(!b64.contains(&b'/'));
    }

    #[test]
    fn two_generations_differ() {
        let (a, _) = generate_secret_value(&spec("raw_text", 20)).unwrap();
        let (b, _) = generate_secret_value(&spec("raw_text", 20)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn zero_length_is_clamped_to_one() {
        let (bytes, _) = generate_secret_value(&spec("raw_text", 0)).unwrap();
        assert_eq!(bytes.len(), 1);
    }

    #[test]
    fn unsupported_policy_and_encoding_error() {
        let mut bad_policy = spec("raw_text", 20);
        bad_policy.policy = "fixed".to_string();
        assert!(matches!(
            generate_secret_value(&bad_policy),
            Err(Error::Invalid(_, _))
        ));

        assert!(matches!(
            generate_secret_value(&spec("uuid", 20)),
            Err(Error::Invalid(_, _))
        ));
    }
}
