//! On-disk header format for encrypted secret stores.
//!
//! The encrypted format prefixes the existing single-line
//! `SECRETS_BACKEND_STATE=...` body with three header lines, all comments
//! starting with `#`:
//!
//! ```text
//! # greentic-encrypted: v1
//! # kdf: argon2id; m=65536; t=3; p=1
//! # salt: <base64-no-pad 16 bytes>
//! SECRETS_BACKEND_STATE=<base64 body>
//! ```

use crate::error::{PassphraseError, Result};
use crate::kdf::{ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME_COST};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// Header version string this build produces and accepts.
pub const VERSION: &str = "v1";
/// KDF identifier.
pub const KDF_NAME: &str = "argon2id";

/// Parsed header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedHeader {
    /// Format version (e.g. `"v1"`).
    pub version: String,
    /// KDF parameters.
    pub kdf: KdfParams,
    /// 16-byte Argon2id salt.
    pub salt: [u8; 16],
}

/// Argon2id parameters as recorded in the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

impl KdfParams {
    /// Returns the parameters this build defaults to.
    pub fn current() -> Self {
        Self {
            m: ARGON2_MEMORY_KIB,
            t: ARGON2_TIME_COST,
            p: ARGON2_PARALLELISM,
        }
    }
}

impl EncryptedHeader {
    /// Build a header for the current version and KDF parameters.
    pub fn new(salt: [u8; 16]) -> Self {
        Self {
            version: VERSION.to_string(),
            kdf: KdfParams::current(),
            salt,
        }
    }

    /// Serialize the header (3 lines, terminated by `\n`).
    pub fn write<W: Write>(&self, out: &mut W) -> std::io::Result<()> {
        writeln!(out, "# greentic-encrypted: {}", self.version)?;
        writeln!(
            out,
            "# kdf: {}; m={}; t={}; p={}",
            KDF_NAME, self.kdf.m, self.kdf.t, self.kdf.p
        )?;
        writeln!(out, "# salt: {}", STANDARD_NO_PAD.encode(self.salt))?;
        Ok(())
    }
}

/// Parse a header from a byte slice. Body bytes (after the header) are
/// returned as the second tuple element so callers can feed them to the
/// crypto layer.
pub fn parse(input: &[u8]) -> Result<(EncryptedHeader, Vec<u8>)> {
    let mut lines = input.split(|b| *b == b'\n');

    let version_line = lines.next().ok_or_else(|| PassphraseError::HeaderParseError {
        reason: "empty input".to_string(),
    })?;
    let version = parse_kv_line(version_line, "# greentic-encrypted:")?;
    if version != VERSION {
        return Err(PassphraseError::UnsupportedVersion { version });
    }

    let kdf_line = lines.next().ok_or_else(|| PassphraseError::HeaderParseError {
        reason: "missing kdf line".to_string(),
    })?;
    let kdf = parse_kdf_line(kdf_line)?;

    let salt_line = lines.next().ok_or_else(|| PassphraseError::HeaderParseError {
        reason: "missing salt line".to_string(),
    })?;
    let salt_b64 = parse_kv_line(salt_line, "# salt:")?;
    let salt_vec = STANDARD_NO_PAD
        .decode(&salt_b64)
        .map_err(|_| PassphraseError::HeaderParseError {
            reason: "salt base64 decode failed".to_string(),
        })?;
    if salt_vec.len() != 16 {
        return Err(PassphraseError::HeaderParseError {
            reason: format!("salt must be 16 bytes, got {}", salt_vec.len()),
        });
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_vec);

    let mut body_lines: Vec<_> = lines.collect();
    // Remove empty final element if present (result of trailing newline in input)
    if body_lines.last().map_or(false, |l| l.is_empty()) {
        body_lines.pop();
    }

    let mut body = Vec::new();
    for (idx, line) in body_lines.iter().enumerate() {
        if idx > 0 {
            body.push(b'\n');
        }
        body.extend_from_slice(line);
    }
    // Add back the trailing newline
    if !body.is_empty() {
        body.push(b'\n');
    }

    Ok((
        EncryptedHeader { version, kdf, salt },
        body,
    ))
}

fn parse_kv_line(line: &[u8], prefix: &str) -> Result<String> {
    let s = std::str::from_utf8(line).map_err(|_| PassphraseError::HeaderParseError {
        reason: "non-utf8 header line".to_string(),
    })?;
    let s = s.trim_end_matches('\r');
    let after = s.strip_prefix(prefix).ok_or_else(|| PassphraseError::HeaderParseError {
        reason: format!("expected line starting with `{prefix}`"),
    })?;
    Ok(after.trim().to_string())
}

fn parse_kdf_line(line: &[u8]) -> Result<KdfParams> {
    let raw = parse_kv_line(line, "# kdf:")?;
    let parts: Vec<&str> = raw.split(';').map(|p| p.trim()).collect();
    if parts.is_empty() || parts[0] != KDF_NAME {
        return Err(PassphraseError::HeaderParseError {
            reason: format!("unsupported kdf: {raw}"),
        });
    }
    let mut m = None;
    let mut t = None;
    let mut p = None;
    for kv in &parts[1..] {
        let (k, v) = kv.split_once('=').ok_or_else(|| PassphraseError::HeaderParseError {
            reason: format!("malformed kdf param: {kv}"),
        })?;
        let v: u32 = v.parse().map_err(|_| PassphraseError::HeaderParseError {
            reason: format!("non-numeric kdf param: {kv}"),
        })?;
        match k {
            "m" => m = Some(v),
            "t" => t = Some(v),
            "p" => p = Some(v),
            other => return Err(PassphraseError::HeaderParseError {
                reason: format!("unknown kdf param: {other}"),
            }),
        }
    }
    Ok(KdfParams {
        m: m.ok_or_else(|| PassphraseError::HeaderParseError { reason: "missing kdf.m".into() })?,
        t: t.ok_or_else(|| PassphraseError::HeaderParseError { reason: "missing kdf.t".into() })?,
        p: p.ok_or_else(|| PassphraseError::HeaderParseError { reason: "missing kdf.p".into() })?,
    })
}

/// Read only the leading header lines of `path` to detect format.
/// Returns `Ok(Some(header))` for v1 encrypted; `Ok(None)` for legacy/empty.
pub fn peek_header(path: &Path) -> Result<Option<EncryptedHeader>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut first = String::new();
    if reader.read_line(&mut first)? == 0 {
        return Ok(None);
    }
    if !first.starts_with("# greentic-encrypted:") {
        return Ok(None);
    }
    let mut buf = first.into_bytes();
    let mut second = String::new();
    reader.read_line(&mut second)?;
    buf.extend(second.into_bytes());
    let mut third = String::new();
    reader.read_line(&mut third)?;
    buf.extend(third.into_bytes());

    let (header, _body) = parse(&buf)?;
    Ok(Some(header))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> EncryptedHeader {
        EncryptedHeader::new([0xAAu8; 16])
    }

    #[test]
    fn round_trip_preserves_fields() {
        let header = sample_header();
        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();
        buf.extend_from_slice(b"SECRETS_BACKEND_STATE=YWJj\n");
        let (parsed, body) = parse(&buf).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(body, b"SECRETS_BACKEND_STATE=YWJj\n");
    }

    #[test]
    fn rejects_unknown_version() {
        let input = b"# greentic-encrypted: v2\n# kdf: argon2id; m=1; t=1; p=1\n# salt: AAAAAAAAAAAAAAAAAAAAAA\n";
        let err = parse(input).unwrap_err();
        match err {
            PassphraseError::UnsupportedVersion { version } => assert_eq!(version, "v2"),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_kdf_line() {
        let input = b"# greentic-encrypted: v1\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(err, PassphraseError::HeaderParseError { .. }));
    }

    #[test]
    fn rejects_unknown_kdf() {
        let input = b"# greentic-encrypted: v1\n# kdf: pbkdf2; m=1; t=1; p=1\n# salt: AAAAAAAAAAAAAAAAAAAAAA\n";
        let err = parse(input).unwrap_err();
        match err {
            PassphraseError::HeaderParseError { reason } => {
                assert!(reason.contains("unsupported kdf"));
            }
            other => panic!("expected HeaderParseError, got {other:?}"),
        }
    }

    #[test]
    fn rejects_short_salt() {
        let input = b"# greentic-encrypted: v1\n# kdf: argon2id; m=1; t=1; p=1\n# salt: AAAA\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(err, PassphraseError::HeaderParseError { .. }));
    }

    #[test]
    fn parse_never_panics_on_random_input() {
        let inputs: &[&[u8]] = &[
            b"",
            b"\n\n\n",
            b"# greentic-encrypted:",
            b"# greentic-encrypted: \n# kdf: \n# salt: \n",
            &[0xFF; 1000],
            b"# greentic-encrypted: v1\n# kdf: argon2id\n# salt: !!!\n",
        ];
        for input in inputs {
            let _ = parse(input);
        }
    }

    #[test]
    fn peek_header_returns_none_for_legacy_file() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), b"SECRETS_BACKEND_STATE=YWJj\n").unwrap();
        assert!(peek_header(temp.path()).unwrap().is_none());
    }

    #[test]
    fn peek_header_returns_none_for_empty_file() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        assert!(peek_header(temp.path()).unwrap().is_none());
    }

    #[test]
    fn peek_header_returns_header_for_v1_file() {
        let header = sample_header();
        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();
        buf.extend_from_slice(b"SECRETS_BACKEND_STATE=YWJj\n");

        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), &buf).unwrap();
        assert_eq!(peek_header(temp.path()).unwrap(), Some(header));
    }
}
