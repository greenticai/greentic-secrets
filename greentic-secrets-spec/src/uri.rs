use crate::error::{Error, Result};
use crate::types::{Scope, validate_component, validate_version};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Scheme prefix for runtime secret store URIs (`secrets://`).
pub const SECRET_STORE_SCHEME: &str = "secrets://";
/// Placeholder segment used when a secret is not scoped to a specific team.
///
/// The default/empty team is always rendered as this `_` placeholder; see
/// [`normalize_team`].
pub const TEAM_PLACEHOLDER: &str = "_";

const SCHEME: &str = SECRET_STORE_SCHEME;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretUri {
    scope: Scope,
    category: String,
    name: String,
    version: Option<String>,
}

impl SecretUri {
    pub fn new(scope: Scope, category: impl Into<String>, name: impl Into<String>) -> Result<Self> {
        let category = category.into();
        let name = name.into();

        validate_component(&category, "category")?;
        validate_component(&name, "name")?;

        Ok(Self {
            scope,
            category,
            name,
            version: None,
        })
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn with_version(mut self, version: Option<&str>) -> Result<Self> {
        if let Some(value) = version {
            validate_version(value)?;
            self.version = Some(value.to_string());
        } else {
            self.version = None;
        }
        Ok(self)
    }

    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        if !raw.starts_with(SCHEME) {
            return Err(Error::InvalidScheme);
        }

        let path = &raw[SCHEME.len()..];
        let mut segments = path.split('/');

        let env = segments.next().ok_or(Error::MissingSegment {
            field: "environment",
        })?;
        let tenant = segments
            .next()
            .ok_or(Error::MissingSegment { field: "tenant" })?;
        let team_segment = segments
            .next()
            .ok_or(Error::MissingSegment { field: "team" })?;
        let category = segments
            .next()
            .ok_or(Error::MissingSegment { field: "category" })?;
        let name_segment = segments
            .next()
            .ok_or(Error::MissingSegment { field: "name" })?;

        if segments.next().is_some() {
            return Err(Error::ExtraSegments);
        }

        let team = if team_segment == TEAM_PLACEHOLDER {
            None
        } else {
            Some(team_segment.to_string())
        };

        let (name, version) = split_name_version(name_segment)?;

        let scope = Scope::new(env.to_string(), tenant.to_string(), team)?;
        let mut uri = SecretUri::new(scope, category, name)?;
        if let Some(version) = version {
            uri = uri.with_version(Some(&version))?;
        }

        Ok(uri)
    }

    fn format_team(team: Option<&str>) -> &str {
        team.unwrap_or(TEAM_PLACEHOLDER)
    }
}

fn split_name_version(segment: &str) -> Result<(&str, Option<String>)> {
    let mut parts = segment.split('@');
    let name = parts.next().unwrap_or_default();
    let version = parts.next();

    if parts.next().is_some() {
        return Err(Error::InvalidVersion {
            value: segment.to_string(),
        });
    }

    if let Some(v) = version {
        validate_version(v)?;
        Ok((name, Some(v.to_string())))
    } else {
        Ok((name, None))
    }
}

impl fmt::Display for SecretUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{SCHEME}{}/{}/{}/{}/{}",
            self.scope.env(),
            self.scope.tenant(),
            Self::format_team(self.scope.team()),
            self.category,
            self.name
        )?;

        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

impl FromStr for SecretUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        SecretUri::parse(s)
    }
}

impl SecretUri {
    pub fn into_string(self) -> String {
        self.to_string()
    }
}

impl TryFrom<&str> for SecretUri {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        SecretUri::parse(value)
    }
}

impl TryFrom<String> for SecretUri {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        SecretUri::parse(&value)
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecretUri {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SecretUri {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        SecretUri::parse(&value).map_err(serde::de::Error::custom)
    }
}

// No schema integration in this crate; downstream can wrap as needed.

/// Returns `true` when `team` represents the canonical "no specific team" value.
///
/// `None`, an empty/whitespace string, and a literal `default` (any case) all
/// denote the team-less scope. They are deliberately treated as equivalent: the
/// store renders them all as the [`TEAM_PLACEHOLDER`] (`_`) so a secret written
/// under one form is always found under the others.
pub fn is_default_team(team: Option<&str>) -> bool {
    match team {
        None => true,
        Some(value) => {
            let trimmed = value.trim();
            trimmed.is_empty() || trimmed.eq_ignore_ascii_case("default")
        }
    }
}

/// Canonicalize a team value for secret scoping.
///
/// Maps the default/empty team (see [`is_default_team`]) to `None` — which
/// renders as the `_` placeholder — and otherwise returns the trimmed team. This
/// is the single source of truth for the "`_` everywhere" rule: every secret URI
/// / [`crate::SecretRef`] construction must route its team segment through here
/// so `default` and `_` can never diverge across producers.
pub fn normalize_team(team: Option<&str>) -> Option<String> {
    if is_default_team(team) {
        None
    } else {
        team.map(|value| value.trim().to_string())
    }
}

/// Build a canonical secret store URI
/// (`secrets://<env>/<tenant>/<team|_>/<category>/<name>`), applying
/// [`normalize_team`] so the team segment is always canonical.
///
/// This is the one helper all consumers (setup/start/deployer) should call
/// instead of formatting the URI by hand.
pub fn canonical_secret_uri(
    env: &str,
    tenant: &str,
    team: Option<&str>,
    category: &str,
    name: &str,
) -> Result<SecretUri> {
    let scope = Scope::new(env, tenant, normalize_team(team))?;
    SecretUri::new(scope, category, name)
}

/// Canonicalize a raw secret name into the store-safe slug used in the trailing
/// segment of every `secrets://.../<name>` URI.
///
/// Lowercases ASCII, keeps `[a-z0-9_]`, maps `-`/`.`/`/`/space to `_`, drops any
/// other character, collapses runs of `_`, and trims leading/trailing `_`; an
/// input that reduces to nothing yields `"secret"`. This is the single
/// definition the whole ecosystem (setup/start/deployer) shares so a producer
/// and a reader can never derive a name differently — a secret written under
/// one normalization is always found under the other.
pub fn canonical_secret_name(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut prev_underscore = false;

    for ch in raw.chars() {
        let Some(normalized) = normalize_secret_name_char(ch) else {
            continue;
        };
        if normalized == '_' {
            if prev_underscore {
                continue;
            }
            prev_underscore = true;
        } else {
            prev_underscore = false;
        }
        result.push(normalized);
    }

    let trimmed = result.trim_matches('_');
    if trimmed.is_empty() {
        "secret".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_secret_name_char(ch: char) -> Option<char> {
    match ch {
        'A'..='Z' => Some(ch.to_ascii_lowercase()),
        'a'..='z' | '0'..='9' | '_' => Some(ch),
        '-' | '.' | ' ' | '/' => Some('_'),
        _ => None,
    }
}

/// Derive the environment-variable lookup key for a 5-segment `secrets://` store
/// URI.
///
/// `secrets://<env>/<tenant>/<team>/<category>/<name>` becomes
/// `GREENTIC_SECRET__<ENV>__<TENANT>__<TEAM>__<CATEGORY>__<NAME>`, with each
/// segment uppercased and every non-alphanumeric byte mapped to `_`. Returns
/// `None` when `uri` is not a 5-segment `secrets://` URI. The runtime reader and
/// the deployer's resolver share this so a secret exported as an env var is
/// found under exactly the key it was written as.
pub fn canonical_secret_store_key(uri: &str) -> Option<String> {
    let trimmed = uri.strip_prefix(SECRET_STORE_SCHEME)?;
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() != 5 {
        return None;
    }
    let mut parts = Vec::with_capacity(segments.len() + 1);
    parts.push("GREENTIC_SECRET".to_string());
    parts.extend(segments.into_iter().map(normalize_store_segment));
    Some(parts.join("__"))
}

fn normalize_store_segment(segment: &str) -> String {
    segment
        .chars()
        .map(|ch| match ch {
            'A'..='Z' | '0'..='9' => ch,
            'a'..='z' => ch.to_ascii_uppercase(),
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod canonical_tests {
    use super::*;

    #[test]
    fn default_team_variants_collapse_to_none() {
        for value in [
            None,
            Some(""),
            Some("   "),
            Some("default"),
            Some("Default"),
            Some("DEFAULT"),
        ] {
            assert!(
                is_default_team(value),
                "expected {value:?} to be the default team"
            );
            assert_eq!(
                normalize_team(value),
                None,
                "expected {value:?} to normalize to None"
            );
        }
    }

    #[test]
    fn real_team_is_preserved() {
        assert!(!is_default_team(Some("legal")));
        assert_eq!(normalize_team(Some("legal")), Some("legal".to_string()));
        assert_eq!(normalize_team(Some(" legal ")), Some("legal".to_string()));
    }

    #[test]
    fn canonical_uri_renders_underscore_for_default_team() {
        let none = canonical_secret_uri("dev", "demo", None, "messaging-slack", "api_key").unwrap();
        let explicit_default =
            canonical_secret_uri("dev", "demo", Some("default"), "messaging-slack", "api_key")
                .unwrap();
        assert_eq!(
            none.to_string(),
            "secrets://dev/demo/_/messaging-slack/api_key"
        );
        assert_eq!(none, explicit_default);
    }

    #[test]
    fn canonical_uri_keeps_real_team() {
        let uri = canonical_secret_uri("dev", "demo", Some("legal"), "configs", "url").unwrap();
        assert_eq!(uri.to_string(), "secrets://dev/demo/legal/configs/url");
    }

    #[test]
    fn canonical_secret_name_fixed_points_and_normalization() {
        // Already-canonical names are unchanged.
        assert_eq!(
            canonical_secret_name("telegram_bot_token"),
            "telegram_bot_token"
        );
        assert_eq!(canonical_secret_name("a1"), "a1");
        // Uppercase and separators normalize.
        assert_eq!(
            canonical_secret_name("TELEGRAM_BOT_TOKEN"),
            "telegram_bot_token"
        );
        assert_eq!(canonical_secret_name("bot-token"), "bot_token");
        assert_eq!(canonical_secret_name("a.b c/d"), "a_b_c_d");
        // Runs collapse and edges trim.
        assert_eq!(
            canonical_secret_name("double__underscore"),
            "double_underscore"
        );
        assert_eq!(canonical_secret_name("_leading"), "leading");
        assert_eq!(canonical_secret_name("trailing_"), "trailing");
        // Empty / all-dropped input falls back to a stable placeholder.
        assert_eq!(canonical_secret_name(""), "secret");
        assert_eq!(canonical_secret_name("***"), "secret");
    }

    #[test]
    fn canonical_secret_store_key_matches_runtime_shape() {
        assert_eq!(
            canonical_secret_store_key("secrets://dev/demo/_/openai/api_key").as_deref(),
            Some("GREENTIC_SECRET__DEV__DEMO_____OPENAI__API_KEY")
        );
        // Hyphenated category segments fold to `_`.
        assert_eq!(
            canonical_secret_store_key("secrets://dev/demo/legal/messaging-slack/bot_token")
                .as_deref(),
            Some("GREENTIC_SECRET__DEV__DEMO__LEGAL__MESSAGING_SLACK__BOT_TOKEN")
        );
        // Wrong scheme or wrong segment count yields None.
        assert_eq!(canonical_secret_store_key("secret://dev/demo/_/p/n"), None);
        assert_eq!(canonical_secret_store_key("secrets://dev/demo/_/p"), None);
        assert_eq!(
            canonical_secret_store_key("secrets://dev/demo/_/p/n/extra"),
            None
        );
    }
}
