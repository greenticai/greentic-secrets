use crate::error::{Error, Result};
use crate::{Scope, SecretUri};
use sha2::{Digest, Sha256};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_json::Value as JsonValue;

pub const SECRETS_PROVIDER_BINDING_SCHEMA_VERSION: &str = "greentic.secrets.binding.v1";
pub const SECRETS_PROVIDER_BINDING_PATH: &str = "state/config/platform/secrets-provider.json";
pub const LEGACY_SECRETS_PROVIDER_BINDING_PATH: &str = "config/platform/secrets-provider.json";

pub const AWS_SECRETS_PROVIDER_ID: &str = "greentic.secrets.aws-sm";
pub const AZURE_SECRETS_PROVIDER_ID: &str = "greentic.secrets.azure-kv";
pub const GCP_SECRETS_PROVIDER_ID: &str = "greentic.secrets.gcp-sm";
pub const K8S_SECRETS_PROVIDER_ID: &str = "greentic.secrets.k8s";
pub const VAULT_SECRETS_PROVIDER_ID: &str = "greentic.secrets.vault-kv";

const TEAM_PLACEHOLDER: &str = "_";

#[cfg(feature = "serde")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretsProviderBinding {
    pub schema_version: String,
    pub provider_id: String,
    pub pack: String,
    pub config: JsonValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSecretProvider {
    AwsSm,
    AzureKv,
    GcpSm,
}

impl NativeSecretProvider {
    pub fn from_provider_id(provider_id: &str) -> Result<Self> {
        match provider_id {
            AWS_SECRETS_PROVIDER_ID => Ok(Self::AwsSm),
            AZURE_SECRETS_PROVIDER_ID => Ok(Self::AzureKv),
            GCP_SECRETS_PROVIDER_ID => Ok(Self::GcpSm),
            other => Err(Error::Invalid(
                "provider_id".to_string(),
                format!("unsupported secrets provider id {other}"),
            )),
        }
    }

    pub fn provider_id(self) -> &'static str {
        match self {
            Self::AwsSm => AWS_SECRETS_PROVIDER_ID,
            Self::AzureKv => AZURE_SECRETS_PROVIDER_ID,
            Self::GcpSm => GCP_SECRETS_PROVIDER_ID,
        }
    }
}

pub fn is_supported_binding_provider_id(provider_id: &str) -> bool {
    matches!(
        provider_id,
        AWS_SECRETS_PROVIDER_ID
            | AZURE_SECRETS_PROVIDER_ID
            | GCP_SECRETS_PROVIDER_ID
            | K8S_SECRETS_PROVIDER_ID
            | VAULT_SECRETS_PROVIDER_ID
    )
}

pub fn native_secret_name(
    provider_id: &str,
    namespace_prefix: &str,
    uri: &SecretUri,
) -> Result<String> {
    match NativeSecretProvider::from_provider_id(provider_id)? {
        NativeSecretProvider::AwsSm => Ok(aws_secret_name(namespace_prefix, uri)),
        NativeSecretProvider::AzureKv => Ok(azure_key_vault_secret_name(namespace_prefix, uri)),
        NativeSecretProvider::GcpSm => Ok(gcp_secret_manager_secret_id(namespace_prefix, uri)),
    }
}

pub fn aws_secret_name(namespace_prefix: &str, uri: &SecretUri) -> String {
    format!(
        "{}/{}/{}/{}/{}/{}",
        namespace_prefix,
        uri.scope().env(),
        uri.scope().tenant(),
        uri.scope().team().unwrap_or(TEAM_PLACEHOLDER),
        uri.category(),
        uri.name()
    )
}

pub fn parse_aws_secret_name(namespace_prefix: &str, name: &str) -> Option<SecretUri> {
    let mut segments = name.split('/');
    let prefix_segment = segments.next()?;
    if prefix_segment != namespace_prefix {
        return None;
    }
    let env = segments.next()?;
    let tenant = segments.next()?;
    let team_segment = segments.next()?;
    let category = segments.next()?;
    let name_segment = segments.next()?;
    if segments.next().is_some() {
        return None;
    }

    let team = if team_segment == TEAM_PLACEHOLDER {
        None
    } else {
        Some(team_segment.to_string())
    };

    let scope = Scope::new(env.to_string(), tenant.to_string(), team).ok()?;
    SecretUri::new(scope, category, name_segment).ok()
}

// Azure Key Vault secret names match `^[0-9a-zA-Z-]+$` and are capped at 127
// characters. GCP Secret Manager secret IDs match `[a-zA-Z0-9_-]+` and are
// capped at 255. Both backends use the derived name as the storage read+write
// key (there is no label/tag indirection like the K8s provider), so the name
// MUST be collision-free: a fold that maps two distinct URIs onto one name is a
// silent overwrite, not a conflict error. See #101 (Azure) / #102 (GCP).
const AZURE_SECRET_NAME_MAX_LEN: usize = 127;
const GCP_SECRET_ID_MAX_LEN: usize = 255;
// "-" separator + 16 hex chars (64 bits) of disambiguating hash.
const COLLISION_HASH_HEX_LEN: usize = 16;

/// Canonical, collision-free key for a secret URI.
///
/// Joins the raw prefix + scope + category + name segments with `/`. Every
/// segment is validated to exclude `/`, so the boundaries are unambiguous and
/// distinct URIs always produce distinct keys. This value is only ever hashed
/// (never used as a storage key directly), so it must NOT be passed through the
/// lossy `*_component` folds — those map `/`, `-`, `_` and `.` all onto `-` and
/// would re-introduce the very collisions the hash exists to prevent.
fn canonical_secret_key(namespace_prefix: &str, uri: &SecretUri) -> String {
    format!(
        "{}/{}/{}/{}/{}/{}",
        namespace_prefix,
        uri.scope().env(),
        uri.scope().tenant(),
        uri.scope().team().unwrap_or(TEAM_PLACEHOLDER),
        uri.category(),
        uri.name()
    )
}

/// 64-bit lowercase-hex disambiguator derived from the canonical secret key.
fn collision_hash(namespace_prefix: &str, uri: &SecretUri) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_secret_key(namespace_prefix, uri).as_bytes());
    hex::encode(&hasher.finalize()[..COLLISION_HASH_HEX_LEN / 2])
}

/// Append `-<hash>` to a readable (possibly lossy) base, truncating the base so
/// the total length stays within `max_len`. Guarantees a non-empty, charset-safe
/// result whose suffix makes it collision-free across distinct URIs.
fn with_collision_suffix(base: &str, hash: &str, max_len: usize) -> String {
    let max_base = max_len - 1 - hash.len();
    let truncated = if base.len() > max_base {
        &base[..max_base]
    } else {
        base
    };
    let trimmed = truncated.trim_end_matches('-');
    let prefix = if trimmed.is_empty() { "s" } else { trimmed };
    format!("{prefix}-{hash}")
}

fn azure_readable_base(namespace_prefix: &str, uri: &SecretUri) -> String {
    // The teamless placeholder is mapped through the Azure component fold like
    // every other segment: Key Vault names allow only `[0-9a-zA-Z-]`, so the
    // raw `_` placeholder would otherwise emit an invalid name for the common
    // teamless URI. Collision-safety is unaffected — the hash suffix derives
    // from the canonical key, which keeps the raw `_` placeholder.
    format!(
        "{prefix}-{env}-{tenant}-{team}-{category}-{name}",
        prefix = azure_key_vault_component(namespace_prefix),
        env = azure_key_vault_component(uri.scope().env()),
        tenant = azure_key_vault_component(uri.scope().tenant()),
        team = azure_key_vault_component(uri.scope().team().unwrap_or(TEAM_PLACEHOLDER)),
        category = azure_key_vault_component(uri.category()),
        name = azure_key_vault_component(uri.name()),
    )
}

fn gcp_readable_base(namespace_prefix: &str, uri: &SecretUri) -> String {
    format!(
        "{}-{}-{}-{}-{}-{}",
        gcp_secret_manager_component(namespace_prefix),
        gcp_secret_manager_component(uri.scope().env()),
        gcp_secret_manager_component(uri.scope().tenant()),
        uri.scope()
            .team()
            .map(gcp_secret_manager_component)
            .unwrap_or_else(|| TEAM_PLACEHOLDER.to_string()),
        gcp_secret_manager_component(uri.category()),
        gcp_secret_manager_component(uri.name()),
    )
}

pub fn azure_key_vault_secret_name(namespace_prefix: &str, uri: &SecretUri) -> String {
    with_collision_suffix(
        &azure_readable_base(namespace_prefix, uri),
        &collision_hash(namespace_prefix, uri),
        AZURE_SECRET_NAME_MAX_LEN,
    )
}

pub fn gcp_secret_manager_secret_id(namespace_prefix: &str, uri: &SecretUri) -> String {
    with_collision_suffix(
        &gcp_readable_base(namespace_prefix, uri),
        &collision_hash(namespace_prefix, uri),
        GCP_SECRET_ID_MAX_LEN,
    )
}

/// Pre-fix Azure Key Vault name derivation. Lossy: distinct URIs can fold onto
/// the same name. Retained ONLY so the provider read-fallback can still resolve
/// secrets written before the collision fix; never use it for new writes. #101.
pub fn legacy_azure_key_vault_secret_name(namespace_prefix: &str, uri: &SecretUri) -> String {
    let base = azure_readable_base(namespace_prefix, uri);
    if base.len() <= 110 {
        return base;
    }
    let mut hasher = Sha256::new();
    hasher.update(base.as_bytes());
    let suffix = hex::encode(&hasher.finalize()[..6]);
    let mut truncated = base[..110].to_string();
    truncated.push('-');
    truncated.push_str(&suffix);
    truncated
}

/// Pre-fix GCP Secret Manager id derivation. Lossy: distinct URIs can fold onto
/// the same id. Retained ONLY for the provider read-fallback; never use it for
/// new writes. #102.
pub fn legacy_gcp_secret_manager_secret_id(namespace_prefix: &str, uri: &SecretUri) -> String {
    let mut id = gcp_readable_base(namespace_prefix, uri);
    if id.len() > 250 {
        id.truncate(250);
    }
    id
}

fn azure_key_vault_component(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '0'..='9' | 'a'..='z' | 'A'..='Z' | '-' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .collect()
}

fn gcp_secret_manager_component(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '0'..='9' | 'a'..='z' | 'A'..='Z' | '-' => c,
            '_' => '_',
            _ => '-',
        })
        .collect::<String>()
        .to_lowercase()
}

#[cfg(feature = "serde")]
pub fn validate_secrets_provider_binding(binding: &SecretsProviderBinding) -> Result<()> {
    if binding.schema_version != SECRETS_PROVIDER_BINDING_SCHEMA_VERSION {
        return Err(Error::Invalid(
            "schema_version".to_string(),
            format!(
                "expected {SECRETS_PROVIDER_BINDING_SCHEMA_VERSION}, got {}",
                binding.schema_version
            ),
        ));
    }
    if !is_supported_binding_provider_id(&binding.provider_id) {
        return Err(Error::Invalid(
            "provider_id".to_string(),
            format!("unsupported secrets provider id {}", binding.provider_id),
        ));
    }

    let pack = binding.pack.trim();
    if pack.is_empty() || pack.starts_with('/') || pack.contains("..") || pack.contains('\\') {
        return Err(Error::Invalid(
            "pack".to_string(),
            "provider pack must be a safe bundle-local path or ref".to_string(),
        ));
    }

    namespace_prefix_from_config(&binding.config)?;
    Ok(())
}

#[cfg(feature = "serde")]
pub fn namespace_prefix_from_config(config: &JsonValue) -> Result<&str> {
    let object = config.as_object().ok_or_else(|| {
        Error::Invalid(
            "config".to_string(),
            "provider config must be an object".to_string(),
        )
    })?;

    if object.contains_key("prefix") {
        return Err(Error::Invalid(
            "config.namespace_prefix".to_string(),
            "use namespace_prefix; prefix is not a valid provider binding field".to_string(),
        ));
    }

    object
        .get("namespace_prefix")
        .and_then(JsonValue::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            Error::Invalid(
                "config.namespace_prefix".to_string(),
                "provider config requires namespace_prefix".to_string(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL_URI: &str = "secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key";

    #[test]
    fn maps_canonical_uri_to_aws_runtime_secret_name() {
        let uri = SecretUri::parse(CANONICAL_URI).expect("valid canonical uri");
        let name = aws_secret_name("greentic", &uri);

        assert_eq!(
            name,
            "greentic/dev/demo/_/messaging-webchat-gui/jwt_signing_key"
        );
        assert_eq!(
            parse_aws_secret_name("greentic", &name).expect("parse native aws name"),
            uri
        );
    }

    fn is_hex16(s: &str) -> bool {
        s.len() == 16
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }

    #[test]
    fn maps_canonical_uri_to_cloud_native_names() {
        let uri = SecretUri::parse(CANONICAL_URI).expect("valid canonical uri");

        // AWS uses raw `/`-joined segments (unambiguous, round-trippable).
        assert_eq!(
            native_secret_name(AWS_SECRETS_PROVIDER_ID, "greentic", &uri).unwrap(),
            "greentic/dev/demo/_/messaging-webchat-gui/jwt_signing_key"
        );

        // Azure/GCP keep the readable (lossy) base but always append a
        // collision-free `-<hash>` suffix derived from the canonical key. The
        // teamless placeholder folds to `-` for Azure (no invalid `_`) but
        // stays `_` for GCP, which permits it.
        let azure = native_secret_name(AZURE_SECRETS_PROVIDER_ID, "greentic", &uri).unwrap();
        let azure_base = "greentic-dev-demo---messaging-webchat-gui-jwt-signing-key";
        let azure_suffix = azure.strip_prefix(&format!("{azure_base}-")).unwrap();
        assert!(is_hex16(azure_suffix), "azure suffix not 16 hex: {azure}");
        assert!(azure.len() <= AZURE_SECRET_NAME_MAX_LEN);
        assert!(
            azure.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "azure teamless name has an invalid char: {azure}"
        );

        let gcp = native_secret_name(GCP_SECRETS_PROVIDER_ID, "greentic", &uri).unwrap();
        let gcp_base = "greentic-dev-demo-_-messaging-webchat-gui-jwt_signing_key";
        let gcp_suffix = gcp.strip_prefix(&format!("{gcp_base}-")).unwrap();
        assert!(is_hex16(gcp_suffix), "gcp suffix not 16 hex: {gcp}");
        assert!(gcp.len() <= GCP_SECRET_ID_MAX_LEN);
    }

    #[test]
    fn legacy_cloud_names_pin_pre_fix_derivation() {
        // The read-fallback depends on the real-team legacy names staying
        // byte-for-byte stable. The teamless Azure name now folds the
        // placeholder to `-`; the pre-fix `_` form was an invalid Key Vault
        // name that could never have persisted data, so nothing relies on it.
        let uri = SecretUri::parse(CANONICAL_URI).expect("valid canonical uri");
        assert_eq!(
            legacy_azure_key_vault_secret_name("greentic", &uri),
            "greentic-dev-demo---messaging-webchat-gui-jwt-signing-key"
        );
        assert_eq!(
            legacy_gcp_secret_manager_secret_id("greentic", &uri),
            "greentic-dev-demo-_-messaging-webchat-gui-jwt_signing_key"
        );

        // A real team is folded identically before and after the fix, so its
        // legacy name is unchanged and pre-fix data stays resolvable.
        let team_uri = SecretUri::parse("secrets://dev/demo/myteam/cat/name").unwrap();
        assert_eq!(
            legacy_azure_key_vault_secret_name("greentic", &team_uri),
            "greentic-dev-demo-myteam-cat-name"
        );
    }

    #[test]
    fn cloud_names_do_not_collide_across_segment_boundaries() {
        // `category=a, name=b-c` vs `category=a-b, name=c` fold to the same
        // lossy base; the canonical-key hash must keep the names distinct.
        let a = SecretUri::parse("secrets://dev/demo/_/a/b-c").unwrap();
        let b = SecretUri::parse("secrets://dev/demo/_/a-b/c").unwrap();

        assert_ne!(
            azure_key_vault_secret_name("greentic", &a),
            azure_key_vault_secret_name("greentic", &b)
        );
        assert_ne!(
            gcp_secret_manager_secret_id("greentic", &a),
            gcp_secret_manager_secret_id("greentic", &b)
        );

        // The legacy derivations DID collide — this is the bug being fixed.
        assert_eq!(
            legacy_azure_key_vault_secret_name("greentic", &a),
            legacy_azure_key_vault_secret_name("greentic", &b)
        );
        assert_eq!(
            legacy_gcp_secret_manager_secret_id("greentic", &a),
            legacy_gcp_secret_manager_secret_id("greentic", &b)
        );
    }

    #[test]
    fn cloud_names_do_not_collide_across_separator_chars() {
        let dash = SecretUri::parse("secrets://dev/demo/_/cat/a-b").unwrap();
        let dot = SecretUri::parse("secrets://dev/demo/_/cat/a.b").unwrap();
        let under = SecretUri::parse("secrets://dev/demo/_/cat/a_b").unwrap();

        let az: Vec<_> = [&dash, &dot, &under]
            .iter()
            .map(|u| azure_key_vault_secret_name("greentic", u))
            .collect();
        assert_eq!(az.len(), 3);
        assert_ne!(az[0], az[1]);
        assert_ne!(az[1], az[2]);
        assert_ne!(az[0], az[2]);

        let gc: Vec<_> = [&dash, &dot, &under]
            .iter()
            .map(|u| gcp_secret_manager_secret_id("greentic", u))
            .collect();
        assert_ne!(gc[0], gc[1]);
        assert_ne!(gc[1], gc[2]);
        assert_ne!(gc[0], gc[2]);
    }

    #[test]
    fn cloud_names_are_deterministic() {
        let uri = SecretUri::parse(CANONICAL_URI).unwrap();
        assert_eq!(
            azure_key_vault_secret_name("greentic", &uri),
            azure_key_vault_secret_name("greentic", &uri)
        );
        assert_eq!(
            gcp_secret_manager_secret_id("greentic", &uri),
            gcp_secret_manager_secret_id("greentic", &uri)
        );
    }

    #[test]
    fn cloud_names_truncate_long_input_and_stay_valid_and_unique() {
        let uri = SecretUri::parse(CANONICAL_URI).unwrap();
        // Oversized namespace prefix forces truncation of the readable base.
        let long = "x".repeat(300);

        let az = azure_key_vault_secret_name(&long, &uri);
        assert_eq!(az.len(), AZURE_SECRET_NAME_MAX_LEN);
        assert!(az.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));

        let gc = gcp_secret_manager_secret_id(&long, &uri);
        assert_eq!(gc.len(), GCP_SECRET_ID_MAX_LEN);
        assert!(
            gc.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );

        // Two prefixes that truncate to the same base must still differ — the
        // hash covers the full canonical key, not the truncated base.
        let p1 = format!("{}aaa", "x".repeat(238));
        let p2 = format!("{}bbb", "x".repeat(238));
        assert_ne!(
            gcp_secret_manager_secret_id(&p1, &uri),
            gcp_secret_manager_secret_id(&p2, &uri)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn validates_runtime_binding_contract() {
        let binding = SecretsProviderBinding {
            schema_version: SECRETS_PROVIDER_BINDING_SCHEMA_VERSION.to_string(),
            provider_id: AWS_SECRETS_PROVIDER_ID.to_string(),
            pack: "providers/secrets/aws-sm.gtpack".to_string(),
            config: serde_json::json!({
                "tenant_id": "demo",
                "environment": "dev",
                "region": "eu-north-1",
                "namespace_prefix": "greentic"
            }),
            state: None,
        };

        validate_secrets_provider_binding(&binding).expect("valid binding");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn rejects_stale_prefix_alias() {
        let binding = SecretsProviderBinding {
            schema_version: SECRETS_PROVIDER_BINDING_SCHEMA_VERSION.to_string(),
            provider_id: GCP_SECRETS_PROVIDER_ID.to_string(),
            pack: "providers/secrets/gcp-sm.gtpack".to_string(),
            config: serde_json::json!({
                "tenant_id": "demo",
                "environment": "dev",
                "project_id": "demo-project",
                "namespace_prefix": "greentic",
                "prefix": "greentic"
            }),
            state: None,
        };

        let err = validate_secrets_provider_binding(&binding).expect_err("invalid binding");
        assert!(err.to_string().contains("namespace_prefix"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn accepts_non_cloud_binding_provider_ids_without_native_mapping() {
        let binding = SecretsProviderBinding {
            schema_version: SECRETS_PROVIDER_BINDING_SCHEMA_VERSION.to_string(),
            provider_id: VAULT_SECRETS_PROVIDER_ID.to_string(),
            pack: "providers/secrets/vault-kv.gtpack".to_string(),
            config: serde_json::json!({
                "tenant_id": "demo",
                "environment": "dev",
                "vault_addr": "https://vault.example.test",
                "mount_path": "secret",
                "auth_mode": "token",
                "namespace_prefix": "greentic"
            }),
            state: None,
        };

        validate_secrets_provider_binding(&binding).expect("valid vault binding");
        assert!(
            native_secret_name(
                VAULT_SECRETS_PROVIDER_ID,
                "greentic",
                &SecretUri::parse(CANONICAL_URI).unwrap()
            )
            .is_err()
        );
    }
}
