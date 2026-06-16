//! `secret://` deployment reference newtype.
//!
//! [`SecretRef`] wraps a `secret://<env>/<...>` URI — the *deployment-artifact*
//! pointer into an environment's secrets. It is distinct from the *runtime
//! store* URI ([`crate::SecretUri`], `secrets://`): the ref appears in
//! deploy-spec objects and persisted artifacts, while the store URI is what
//! backends read and write.
//!
//! This type was moved here from `greentic-deployer`'s `greentic-deploy-spec`
//! crate so the whole ecosystem shares one definition of the `secret://` scheme
//! and one authoritative `secret://` <-> `secrets://` converter (replacing the
//! `replacen`-based copies that previously lived in start/setup/deployer).

use crate::error::Result;
use crate::types::Scope;
use crate::uri::{SECRET_STORE_SCHEME, SecretUri, normalize_team};
use core::fmt;
use core::str::FromStr;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Scheme prefix for `secret://` deployment references.
pub const SECRET_SCHEME: &str = "secret://";

/// Reference into an environment's secrets: `secret://<env>/<path>`.
///
/// The first path segment after the scheme is the env id the ref is scoped to
/// and must be present and non-empty (see [`SecretRef::env_segment`]). The
/// concrete secret material never appears in the deployment object model — it is
/// resolved at runtime via [`SecretRef::to_store_uri`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct SecretRef(String);

impl SecretRef {
    /// Construct and validate a `secret://` reference.
    pub fn try_new(raw: impl Into<String>) -> core::result::Result<Self, SecretRefParseError> {
        let raw = raw.into();
        if !raw.starts_with(SECRET_SCHEME) {
            return Err(SecretRefParseError::MissingScheme);
        }
        if raw.len() == SECRET_SCHEME.len() {
            return Err(SecretRefParseError::EmptyPath);
        }
        // First segment after the scheme is the env identifier; refs are
        // documented as `secret://<env>/<path...>`. The env segment must be
        // present and non-empty so callers can scope a ref to its env.
        if env_segment_of(&raw).is_empty() {
            return Err(SecretRefParseError::EmptyEnvSegment);
        }
        Ok(Self(raw))
    }

    /// The raw `secret://...` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// First path segment after the scheme — the env id the ref is scoped to.
    pub fn env_segment(&self) -> &str {
        env_segment_of(&self.0)
    }

    /// Convert this deployment ref into the canonical runtime store URI
    /// (`secrets://`), applying [`normalize_team`] to the team segment.
    ///
    /// This is the single authoritative replacement for the `replacen`-based
    /// `secret_ref_to_store_uri` helpers previously duplicated across
    /// start/setup/deployer. It is only valid for *store-aligned* refs — those
    /// whose path is exactly `<env>/<tenant>/<team>/<category>/<name>`. Refs
    /// with a different shape (e.g. pack-config `secret://<env>/<bundle>/<pack>/<question>`)
    /// are resolved through their own mapping and return a parse error here
    /// rather than silently producing a wrong URI.
    pub fn to_store_uri(&self) -> Result<SecretUri> {
        let mut flipped = String::with_capacity(self.0.len() + 1);
        flipped.push_str(SECRET_STORE_SCHEME);
        flipped.push_str(&self.0[SECRET_SCHEME.len()..]);
        let parsed = SecretUri::parse(&flipped)?;
        // Re-canonicalize the team segment so a ref carrying `default` resolves
        // to the same `_` store location as a ref carrying `_`.
        let scope = Scope::new(
            parsed.scope().env(),
            parsed.scope().tenant(),
            normalize_team(parsed.scope().team()),
        )?;
        let mut uri = SecretUri::new(scope, parsed.category(), parsed.name())?;
        if let Some(version) = parsed.version() {
            uri = uri.with_version(Some(version))?;
        }
        Ok(uri)
    }

    /// Build a `secret://` deployment ref from a runtime store URI (the inverse
    /// prefix flip of [`SecretRef::to_store_uri`]).
    pub fn from_store_uri(uri: &SecretUri) -> core::result::Result<Self, SecretRefParseError> {
        let store = uri.to_string();
        let body = store.strip_prefix(SECRET_STORE_SCHEME).unwrap_or(&store);
        let mut raw = String::with_capacity(SECRET_SCHEME.len() + body.len());
        raw.push_str(SECRET_SCHEME);
        raw.push_str(body);
        Self::try_new(raw)
    }
}

/// The env segment — the first path component after the `secret://` scheme — of
/// a raw ref string. Callers guarantee the `secret://` prefix is present; the
/// segment is everything up to the first `/` (or the whole tail if there is
/// none). Shared by [`SecretRef::try_new`]'s validation and
/// [`SecretRef::env_segment`] so the slicing rule lives in one place.
fn env_segment_of(raw: &str) -> &str {
    let after_scheme = &raw[SECRET_SCHEME.len()..];
    match after_scheme.find('/') {
        Some(idx) => &after_scheme[..idx],
        None => after_scheme,
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefParseError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl TryFrom<String> for SecretRef {
    type Error = SecretRefParseError;

    fn try_from(value: String) -> core::result::Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.0
    }
}

/// Errors produced when parsing a [`SecretRef`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretRefParseError {
    /// The string did not start with `secret://`.
    #[error("secret-ref must start with `secret://`")]
    MissingScheme,
    /// The string was exactly `secret://` with no path.
    #[error("secret-ref path is empty")]
    EmptyPath,
    /// The first path segment (the env id) was empty.
    #[error("secret-ref must carry an env segment: `secret://<env>/<path>`")]
    EmptyEnvSegment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_store_aligned_ref() {
        let r = SecretRef::try_new("secret://dev/demo/_/messaging-slack/api_key").unwrap();
        assert_eq!(r.env_segment(), "dev");
        assert_eq!(r.as_str(), "secret://dev/demo/_/messaging-slack/api_key");
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(
            SecretRef::try_new("dev/demo").unwrap_err(),
            SecretRefParseError::MissingScheme
        );
    }

    #[test]
    fn rejects_empty_path() {
        assert_eq!(
            SecretRef::try_new("secret://").unwrap_err(),
            SecretRefParseError::EmptyPath
        );
    }

    #[test]
    fn rejects_empty_env_segment() {
        assert_eq!(
            SecretRef::try_new("secret:///demo/_/c/n").unwrap_err(),
            SecretRefParseError::EmptyEnvSegment
        );
    }

    #[test]
    fn to_store_uri_flips_scheme_and_normalizes_team() {
        let underscore = SecretRef::try_new("secret://dev/demo/_/messaging-slack/api_key")
            .unwrap()
            .to_store_uri()
            .unwrap();
        let defaulted = SecretRef::try_new("secret://dev/demo/default/messaging-slack/api_key")
            .unwrap()
            .to_store_uri()
            .unwrap();
        assert_eq!(
            underscore.to_string(),
            "secrets://dev/demo/_/messaging-slack/api_key"
        );
        // The `default` team collapses to the same `_` store location.
        assert_eq!(underscore, defaulted);
    }

    #[test]
    fn to_store_uri_preserves_real_team() {
        let uri = SecretRef::try_new("secret://dev/demo/legal/configs/url")
            .unwrap()
            .to_store_uri()
            .unwrap();
        assert_eq!(uri.to_string(), "secrets://dev/demo/legal/configs/url");
    }

    #[test]
    fn non_store_aligned_ref_errors_rather_than_misconverting() {
        // pack-config shape `secret://<env>/<bundle>/<pack>/<question>` is only
        // four path segments — it has no canonical store-URI flip.
        assert!(
            SecretRef::try_new("secret://dev/my-bundle/my-pack/question")
                .unwrap()
                .to_store_uri()
                .is_err()
        );
    }

    #[test]
    fn store_uri_round_trip() {
        let store = SecretUri::parse("secrets://dev/demo/_/messaging-slack/api_key").unwrap();
        let secret_ref = SecretRef::from_store_uri(&store).unwrap();
        assert_eq!(
            secret_ref.as_str(),
            "secret://dev/demo/_/messaging-slack/api_key"
        );
        assert_eq!(secret_ref.to_store_uri().unwrap(), store);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips_through_string() {
        let r = SecretRef::try_new("secret://dev/demo/_/messaging-slack/api_key").unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"secret://dev/demo/_/messaging-slack/api_key\"");
        let back: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
