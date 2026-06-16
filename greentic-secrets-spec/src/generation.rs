//! Vocabulary for *managed* secrets — the declarative, pack-declared model the
//! ecosystem uses to describe every secret a deployment needs, whether the
//! operator supplies the value or the system generates it.
//!
//! This is types only. The generator (CSPRNG material) and the
//! requirement→[`SecretSet`] discovery / provision pass live in
//! `greentic-secrets-core` (they need an RNG and store access). Keeping the
//! vocabulary here lets every repo agree on the shapes without pulling in the
//! runtime engine.
//!
//! The generation model mirrors a pack's `secret-requirements.json`
//! `generated` block exactly (`policy`/`length`/`encoding`/`scope`/
//! `regenerate_if_present`), so a pack authored once mints identical material in
//! start, setup, and the deployer rather than each rolling its own generator.

use crate::requirements::SecretFormat;
use crate::types::Scope;
use crate::uri::SecretUri;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The scope a generated secret is minted under, as declared by a pack.
///
/// `level` is `"tenant"`, `"team"`, etc.; a `tenant`-level secret is shared
/// across all teams. `team` is the explicit team, where `Some("_")` denotes the
/// team-less scope. The interpretation lives in [`generated_scope_team`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GeneratedSecretScope {
    /// Scope level (`"tenant"`, `"team"`, …).
    pub level: String,
    /// Explicit team, or `None`. `Some("_")` is the team-less scope.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub team: Option<String>,
}

/// How a system-generated secret's value is produced — a 1:1 model of a pack's
/// `secret-requirements.json` `generated` block.
///
/// The fields are part of the contract: a consumer that regenerates or rotates a
/// secret must produce a value of the same shape. The lib supports `policy =
/// "random"` with `encoding` one of `raw_text` (random ASCII), `base64url`
/// (URL-safe, no pad), or `hex` (lowercase). `length` is the character count for
/// `raw_text` and the raw random-byte count for `base64url`/`hex`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GeneratedSecretRequirement {
    /// Generation policy. Only `"random"` is supported today.
    pub policy: String,
    /// Character count (`raw_text`) or raw random-byte count (`base64url`/`hex`).
    pub length: usize,
    /// Value encoding: `raw_text` | `base64url` | `hex`.
    pub encoding: String,
    /// Scope the secret is minted under.
    pub scope: GeneratedSecretScope,
    /// Re-mint even when a value is already present.
    pub regenerate_if_present: bool,
}

/// The team a generated secret is minted under, given its declared scope and a
/// default team.
///
/// Mirrors the runtime rule: a `tenant`-level secret — or one that explicitly
/// scopes to the `_` team — is team-less (returns `None`); otherwise the
/// declared team wins, falling back to `default_team`. Sharing this keeps a
/// generated secret's URI identical across the producer that mints it and the
/// reader that resolves it.
pub fn generated_scope_team<'a>(
    generated: &'a GeneratedSecretRequirement,
    default_team: Option<&'a str>,
) -> Option<&'a str> {
    if generated.scope.level.eq_ignore_ascii_case("tenant")
        || generated.scope.team.as_deref() == Some("_")
    {
        return None;
    }
    generated.scope.team.as_deref().or(default_team)
}

/// A secret a pack declares it needs — the shared output type every consumer's
/// pack reader parses into, so the deployer, start, and setup agree on the
/// requirement model (including which secrets are system-generated).
///
/// `key` is expected to already be [`canonical_secret_name`](crate::canonical_secret_name)-
/// normalized by the reader. `aliases` are alternate names a previously-seeded
/// value may live under. `generated` carries the generation policy when the
/// system mints the value, and is `None` for operator-supplied secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PackSecretRequirement {
    /// Canonical secret name.
    pub key: String,
    /// Alternate names a previously-seeded value may live under.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub aliases: Vec<String>,
    /// Whether execution requires this secret.
    pub required: bool,
    /// Generation policy when the system mints this secret; `None` =
    /// operator-supplied.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub generated: Option<GeneratedSecretRequirement>,
}

impl PackSecretRequirement {
    /// A required, operator-supplied requirement for `key`.
    pub fn user_supplied(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            aliases: Vec::new(),
            required: true,
            generated: None,
        }
    }

    /// A required, system-generated requirement for `key`.
    pub fn generated(key: impl Into<String>, generated: GeneratedSecretRequirement) -> Self {
        Self {
            key: key.into(),
            aliases: Vec::new(),
            required: true,
            generated: Some(generated),
        }
    }

    /// True when the system mints this secret.
    pub fn is_generated(&self) -> bool {
        self.generated.is_some()
    }
}

/// Where a [`ManagedSecret`]'s value comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SecretSource {
    /// Provided by the operator/user (wizard, env var, paste).
    UserSupplied,
    /// Minted by the system using the given generation policy.
    Generated(GeneratedSecretRequirement),
}

/// A single secret the system manages, identified by its canonical runtime store
/// URI, tagged with how its value is obtained.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedSecret {
    /// Canonical store URI (`secrets://...`); team segment already normalized.
    pub uri: SecretUri,
    /// Whether the secret is mandatory for execution.
    pub required: bool,
    /// How the value is obtained.
    pub source: SecretSource,
    /// Preferred content format when known.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub format: Option<SecretFormat>,
    /// Operator-facing description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
}

impl ManagedSecret {
    /// A required, operator-supplied secret.
    pub fn user_supplied(uri: SecretUri) -> Self {
        Self {
            uri,
            required: true,
            source: SecretSource::UserSupplied,
            format: None,
            description: None,
        }
    }

    /// A required, system-generated secret.
    pub fn generated(uri: SecretUri, generated: GeneratedSecretRequirement) -> Self {
        Self {
            uri,
            required: true,
            source: SecretSource::Generated(generated),
            format: None,
            description: None,
        }
    }

    /// True when the value is system-generated.
    pub fn is_generated(&self) -> bool {
        matches!(self.source, SecretSource::Generated(_))
    }

    /// The generation policy for a system-generated secret, or `None` if
    /// user-supplied.
    pub fn generated_requirement(&self) -> Option<&GeneratedSecretRequirement> {
        match &self.source {
            SecretSource::Generated(generated) => Some(generated),
            SecretSource::UserSupplied => None,
        }
    }
}

/// The complete set of secrets a deployment scope needs — the single source of
/// truth consumed by both the local runtime (start) and cloud promotion
/// (deployer). It deliberately includes *generated* secrets so the deployer's
/// cloud path can no longer miss them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretSet {
    /// Scope all entries belong to.
    pub scope: Scope,
    /// The managed secrets, in declaration order.
    pub secrets: Vec<ManagedSecret>,
}

impl SecretSet {
    /// An empty set for the given scope.
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            secrets: Vec::new(),
        }
    }

    /// Append a managed secret.
    pub fn push(&mut self, secret: ManagedSecret) {
        self.secrets.push(secret);
    }

    /// Iterate the system-generated secrets.
    pub fn generated(&self) -> impl Iterator<Item = &ManagedSecret> {
        self.secrets.iter().filter(|secret| secret.is_generated())
    }

    /// Iterate the operator-supplied secrets.
    pub fn user_supplied(&self) -> impl Iterator<Item = &ManagedSecret> {
        self.secrets.iter().filter(|secret| !secret.is_generated())
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    fn raw_text(length: usize, level: &str, team: Option<&str>) -> GeneratedSecretRequirement {
        GeneratedSecretRequirement {
            policy: "random".to_string(),
            length,
            encoding: "raw_text".to_string(),
            scope: GeneratedSecretScope {
                level: level.to_string(),
                team: team.map(str::to_string),
            },
            regenerate_if_present: false,
        }
    }

    #[test]
    fn generated_requirement_serde_round_trips() {
        let g = raw_text(20, "tenant", Some("_"));
        let json = serde_json::to_string(&g).unwrap();
        let back: GeneratedSecretRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn generated_scope_team_collapses_tenant_and_underscore() {
        // tenant-level → team-less regardless of the declared team.
        assert_eq!(
            generated_scope_team(&raw_text(20, "tenant", None), Some("legal")),
            None
        );
        assert_eq!(
            generated_scope_team(&raw_text(20, "tenant", Some("legal")), Some("ops")),
            None
        );
        // explicit `_` team → team-less.
        assert_eq!(
            generated_scope_team(&raw_text(20, "team", Some("_")), Some("legal")),
            None
        );
        // real team scope wins, else falls back to the default team.
        assert_eq!(
            generated_scope_team(&raw_text(20, "team", Some("legal")), Some("ops")),
            Some("legal")
        );
        assert_eq!(
            generated_scope_team(&raw_text(20, "team", None), Some("ops")),
            Some("ops")
        );
    }

    #[test]
    fn managed_secret_partitions_by_source() {
        let scope = Scope::new("dev", "demo", None).unwrap();
        let mut set = SecretSet::new(scope);
        set.push(ManagedSecret::user_supplied(
            SecretUri::parse("secrets://dev/demo/_/messaging-slack/api_key").unwrap(),
        ));
        set.push(ManagedSecret::generated(
            SecretUri::parse("secrets://dev/demo/_/messaging-telegram/webhook_secret").unwrap(),
            raw_text(32, "tenant", Some("_")),
        ));
        assert_eq!(set.generated().count(), 1);
        assert_eq!(set.user_supplied().count(), 1);
    }
}
