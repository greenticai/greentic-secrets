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

pub fn azure_key_vault_secret_name(namespace_prefix: &str, uri: &SecretUri) -> String {
    let base = format!(
        "{prefix}-{env}-{tenant}-{team}-{category}-{name}",
        prefix = azure_key_vault_component(namespace_prefix),
        env = azure_key_vault_component(uri.scope().env()),
        tenant = azure_key_vault_component(uri.scope().tenant()),
        team = uri
            .scope()
            .team()
            .map(azure_key_vault_component)
            .unwrap_or_else(|| TEAM_PLACEHOLDER.to_string()),
        category = azure_key_vault_component(uri.category()),
        name = azure_key_vault_component(uri.name()),
    );

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

pub fn gcp_secret_manager_secret_id(namespace_prefix: &str, uri: &SecretUri) -> String {
    let mut id = format!(
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
    );

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

    #[test]
    fn maps_canonical_uri_to_cloud_native_names() {
        let uri = SecretUri::parse(CANONICAL_URI).expect("valid canonical uri");

        assert_eq!(
            native_secret_name(AWS_SECRETS_PROVIDER_ID, "greentic", &uri).unwrap(),
            "greentic/dev/demo/_/messaging-webchat-gui/jwt_signing_key"
        );
        assert_eq!(
            native_secret_name(AZURE_SECRETS_PROVIDER_ID, "greentic", &uri).unwrap(),
            "greentic-dev-demo-_-messaging-webchat-gui-jwt-signing-key"
        );
        assert_eq!(
            native_secret_name(GCP_SECRETS_PROVIDER_ID, "greentic", &uri).unwrap(),
            "greentic-dev-demo-_-messaging-webchat-gui-jwt_signing_key"
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
