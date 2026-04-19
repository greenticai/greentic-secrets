#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Secrets domain pack validators.

use greentic_types_validate::{
    Diagnostic, ExtensionInline, PackManifest, PackValidator, ProviderExtensionInline, Severity,
};
use serde_json::Value;

const SECRET_REQUIREMENTS_PATHS: [&str; 2] = [
    "assets/secret-requirements.json",
    "assets/secret_requirements.json",
];

/// Returns the secrets-domain validators for Greentic packs.
pub fn secrets_validators() -> Vec<Box<dyn PackValidator>> {
    vec![
        Box::new(SecretRequirementsDeclValidator),
        Box::new(SecretRequirementsWellFormedValidator),
        Box::new(SecretKeyFormatValidator),
    ]
}

/// Returns true if the manifest appears to describe a secrets pack.
pub fn is_secrets_pack(manifest: &PackManifest) -> bool {
    pack_id_starts_with_secrets(manifest)
        || manifest_references_secret_requirements(manifest)
        || providers_hint_secrets(manifest)
}

fn pack_id_starts_with_secrets(manifest: &PackManifest) -> bool {
    manifest
        .pack_id
        .as_str()
        .to_ascii_lowercase()
        .starts_with("secrets-")
}

fn manifest_references_secret_requirements(manifest: &PackManifest) -> bool {
    if !manifest.secret_requirements.is_empty() {
        return true;
    }
    let Some(extensions) = manifest.extensions.as_ref() else {
        return false;
    };
    for (key, extension) in extensions {
        if SECRET_REQUIREMENTS_PATHS
            .iter()
            .any(|path| key.contains(path) || extension.kind.contains(path))
        {
            return true;
        }
        if let Some(location) = extension.location.as_ref()
            && SECRET_REQUIREMENTS_PATHS
                .iter()
                .any(|path| location.contains(path))
        {
            return true;
        }
        if let Some(inline) = extension.inline.as_ref()
            && inline_mentions_secret_requirements(inline)
        {
            return true;
        }
    }
    false
}

fn inline_mentions_secret_requirements(inline: &ExtensionInline) -> bool {
    match inline {
        ExtensionInline::Provider(_) => false,
        ExtensionInline::Other(value) => value_mentions_secret_requirements(value),
    }
}

fn value_mentions_secret_requirements(value: &Value) -> bool {
    match value {
        Value::String(text) => SECRET_REQUIREMENTS_PATHS
            .iter()
            .any(|path| text.contains(path)),
        Value::Array(items) => items.iter().any(value_mentions_secret_requirements),
        Value::Object(map) => map.values().any(value_mentions_secret_requirements),
        _ => false,
    }
}

fn providers_hint_secrets(manifest: &PackManifest) -> bool {
    manifest
        .provider_extension_inline()
        .map(provider_extension_mentions_secrets)
        .unwrap_or(false)
}

fn provider_extension_mentions_secrets(inline: &ProviderExtensionInline) -> bool {
    inline.providers.iter().any(provider_decl_mentions_secrets)
}

fn provider_decl_mentions_secrets(provider: &greentic_types_validate::ProviderDecl) -> bool {
    let mut fields = Vec::new();
    fields.push(provider.provider_type.as_str());
    fields.push(provider.config_schema_ref.as_str());
    if let Some(state_schema_ref) = provider.state_schema_ref.as_ref() {
        fields.push(state_schema_ref.as_str());
    }
    if let Some(docs_ref) = provider.docs_ref.as_ref() {
        fields.push(docs_ref.as_str());
    }
    fields.push(provider.runtime.world.as_str());
    fields.push(provider.runtime.component_ref.as_str());

    fields
        .into_iter()
        .any(|value| value.to_ascii_lowercase().contains("secrets"))
}

fn secrets_required_hint(manifest: &PackManifest) -> bool {
    is_secrets_pack(manifest)
        || !manifest.secret_requirements.is_empty()
        || manifest
            .capabilities
            .iter()
            .any(|cap| cap.name.to_ascii_lowercase().contains("secret"))
}

struct SecretRequirementsDeclValidator;

impl PackValidator for SecretRequirementsDeclValidator {
    fn id(&self) -> &'static str {
        "secrets.requirements.decl"
    }

    fn applies(&self, manifest: &PackManifest) -> bool {
        secrets_required_hint(manifest)
    }

    fn validate(&self, manifest: &PackManifest) -> Vec<Diagnostic> {
        if manifest_references_secret_requirements(manifest) {
            return Vec::new();
        }
        vec![diagnostic(
            Severity::Warn,
            "SEC_REQUIREMENTS_NOT_DISCOVERABLE",
            "Secrets are required but no secret requirements reference is discoverable.",
            Some("secret_requirements".to_owned()),
            Some(
                "Include assets/secret-requirements.json or embed secret requirements.".to_owned(),
            ),
        )]
    }
}

struct SecretRequirementsWellFormedValidator;

impl PackValidator for SecretRequirementsWellFormedValidator {
    fn id(&self) -> &'static str {
        "secrets.requirements.well_formed"
    }

    fn applies(&self, manifest: &PackManifest) -> bool {
        secrets_required_hint(manifest)
    }

    fn validate(&self, manifest: &PackManifest) -> Vec<Diagnostic> {
        if manifest.secret_requirements.is_empty() {
            return vec![diagnostic(
                Severity::Info,
                "SEC_REQ_PARSE_NEEDS_PACK_ACCESS",
                "Secret requirements parse checks require pack file access.",
                Some("secret_requirements".to_owned()),
                Some(
                    "Provide secret requirements in the manifest or validate with pack bytes."
                        .to_owned(),
                ),
            )];
        }

        let mut diagnostics = Vec::new();
        for (idx, req) in manifest.secret_requirements.iter().enumerate() {
            if req.key.as_str().trim().is_empty() {
                diagnostics.push(diagnostic(
                    Severity::Error,
                    "SEC_REQ_MISSING_KEY",
                    "Secret requirement is missing a key.",
                    Some(format!("secret_requirements.{idx}.key")),
                    Some("Provide a non-empty key for each secret requirement.".to_owned()),
                ));
            }
        }
        diagnostics
    }
}

struct SecretKeyFormatValidator;

impl PackValidator for SecretKeyFormatValidator {
    fn id(&self) -> &'static str {
        "secrets.requirements.key_format"
    }

    fn applies(&self, manifest: &PackManifest) -> bool {
        !manifest.secret_requirements.is_empty()
    }

    fn validate(&self, manifest: &PackManifest) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        for (idx, req) in manifest.secret_requirements.iter().enumerate() {
            let key = req.key.as_str();
            if key.trim().is_empty() {
                continue;
            }
            if is_upper_snake(key) || key.starts_with("greentic://") {
                continue;
            }
            diagnostics.push(diagnostic(
                Severity::Warn,
                "SEC_BAD_KEY_FORMAT",
                "Secret requirement key format should be UPPER_SNAKE or greentic:// URI.",
                Some(format!("secret_requirements.{idx}.key")),
                Some("Rename the key to UPPER_SNAKE or a greentic:// URI.".to_owned()),
            ));
        }
        diagnostics
    }
}

fn is_upper_snake(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn diagnostic(
    severity: Severity,
    code: &str,
    message: &str,
    path: Option<String>,
    hint: Option<String>,
) -> Diagnostic {
    Diagnostic {
        severity,
        code: code.to_owned(),
        message: message.to_owned(),
        path,
        hint,
        data: Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types_validate::{
        ExtensionRef, PROVIDER_EXTENSION_ID, PackId, PackKind, PackSignatures, ProviderDecl,
        ProviderRuntimeRef,
    };
    use semver::Version;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Debug, Deserialize)]
    struct SecretRequirementDecl {
        #[serde(default)]
        key: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        sensitive: Option<bool>,
        #[serde(default)]
        redact: Option<bool>,
    }

    impl SecretRequirementDecl {
        fn key_name(&self) -> Option<&str> {
            self.key
                .as_deref()
                .or(self.name.as_deref())
                .or(self.id.as_deref())
        }

        fn explicit_sensitivity(&self) -> Option<bool> {
            self.sensitive.or(self.redact)
        }
    }

    fn validate_secret_requirement_decls(
        decls: &[SecretRequirementDecl],
        implicit_sensitive: bool,
    ) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        for (idx, decl) in decls.iter().enumerate() {
            let key = decl.key_name().unwrap_or_default();
            if key.trim().is_empty() {
                diagnostics.push(diagnostic(
                    Severity::Error,
                    "SEC_REQ_MISSING_KEY",
                    "Secret requirement is missing a key.",
                    Some(format!("secret_requirements.{idx}.key")),
                    Some("Provide a non-empty key/name for each requirement.".to_owned()),
                ));
                continue;
            }
            match decl.explicit_sensitivity() {
                Some(false) => diagnostics.push(diagnostic(
                    Severity::Error,
                    "SEC_REQ_EXPLICITLY_NOT_SENSITIVE",
                    "Secret requirement explicitly marks non-sensitive data.",
                    Some(format!("secret_requirements.{idx}.sensitive")),
                    Some("Remove the explicit false or mark secrets as sensitive.".to_owned()),
                )),
                Some(true) => {}
                None if !implicit_sensitive => diagnostics.push(diagnostic(
                    Severity::Error,
                    "SEC_REQ_NOT_SENSITIVE",
                    "Secret requirement is not marked sensitive.",
                    Some(format!("secret_requirements.{idx}.sensitive")),
                    Some("Mark secrets as sensitive or use a secrets-only structure.".to_owned()),
                )),
                None => {}
            }
        }
        diagnostics
    }

    fn base_manifest(pack_id: &str) -> PackManifest {
        PackManifest {
            schema_version: "pack-v1".to_owned(),
            pack_id: pack_id.parse::<PackId>().expect("pack id"),
            name: None,
            version: Version::parse("0.1.0").expect("version"),
            kind: PackKind::Application,
            publisher: "greentic".to_owned(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: None,
        }
    }

    #[test]
    fn detects_secrets_pack_by_id_prefix() {
        let manifest = base_manifest("secrets-demo");
        assert!(is_secrets_pack(&manifest));
    }

    #[test]
    fn warns_when_secrets_requirements_missing() {
        let mut manifest = base_manifest("vendor.demo.pack");
        let provider = ProviderDecl {
            provider_type: "demo".to_owned(),
            capabilities: Vec::new(),
            ops: Vec::new(),
            config_schema_ref: "assets/schemas/secrets/demo/config.schema.json".to_owned(),
            state_schema_ref: None,
            runtime: ProviderRuntimeRef {
                component_ref: "component".to_owned(),
                export: "invoke".to_owned(),
                world: "greentic:provider-schema-core/schema-core@1.0.0".to_owned(),
            },
            docs_ref: None,
        };
        let inline = ProviderExtensionInline {
            providers: vec![provider],
            additional_fields: BTreeMap::new(),
        };
        let mut extensions = BTreeMap::new();
        extensions.insert(
            PROVIDER_EXTENSION_ID.to_owned(),
            ExtensionRef {
                kind: PROVIDER_EXTENSION_ID.to_owned(),
                version: "1.0.0".to_owned(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Provider(inline)),
            },
        );
        manifest.extensions = Some(extensions);

        let validator = SecretRequirementsDeclValidator;
        let diagnostics = validator.validate(&manifest);
        assert!(
            diagnostics
                .iter()
                .any(|diag| diag.code == "SEC_REQUIREMENTS_NOT_DISCOVERABLE")
        );
    }

    #[test]
    fn detects_missing_key() {
        let raw = r#"[{"sensitive": true}]"#;
        let decls: Vec<SecretRequirementDecl> = serde_json::from_str(raw).expect("parse");
        let diagnostics = validate_secret_requirement_decls(&decls, true);
        assert!(
            diagnostics
                .iter()
                .any(|diag| diag.code == "SEC_REQ_MISSING_KEY")
        );
    }

    #[test]
    fn detects_explicit_not_sensitive() {
        let raw = r#"[{"key": "API_KEY", "sensitive": false}]"#;
        let decls: Vec<SecretRequirementDecl> = serde_json::from_str(raw).expect("parse");
        let diagnostics = validate_secret_requirement_decls(&decls, true);
        assert!(
            diagnostics
                .iter()
                .any(|diag| diag.code == "SEC_REQ_EXPLICITLY_NOT_SENSITIVE")
        );
    }

    #[test]
    fn accepts_valid_sensitive_requirement() {
        let raw = r#"[{"key": "API_KEY", "sensitive": true}]"#;
        let decls: Vec<SecretRequirementDecl> = serde_json::from_str(raw).expect("parse");
        let diagnostics = validate_secret_requirement_decls(&decls, true);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn detects_secret_requirements_from_extension_location() {
        let mut manifest = base_manifest("vendor.demo.pack");
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "vendor.secret-req".to_owned(),
            ExtensionRef {
                kind: "vendor.secret-req".to_owned(),
                version: "1.0.0".to_owned(),
                digest: None,
                location: Some("assets/secret-requirements.json".to_owned()),
                inline: None,
            },
        );
        manifest.extensions = Some(extensions);

        assert!(manifest_references_secret_requirements(&manifest));
        assert!(is_secrets_pack(&manifest));
    }

    #[test]
    fn detects_secret_requirements_from_unknown_inline_payload() {
        let mut manifest = base_manifest("vendor.demo.pack");
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "vendor.secret-req".to_owned(),
            ExtensionRef {
                kind: "vendor.secret-req".to_owned(),
                version: "1.0.0".to_owned(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Other(serde_json::json!({
                    "path": "assets/secret_requirements.json"
                }))),
            },
        );
        manifest.extensions = Some(extensions);

        assert!(manifest_references_secret_requirements(&manifest));
    }

    #[test]
    fn key_format_validator_accepts_greentic_uri_keys() {
        let mut manifest = base_manifest("vendor.demo.pack");
        let mut requirement = greentic_types_validate::SecretRequirement::default();
        requirement.key = "greentic://tenant/configs/db".into();
        manifest.secret_requirements.push(requirement);

        let diagnostics = SecretKeyFormatValidator.validate(&manifest);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn validators_are_registered_in_expected_order() {
        let ids: Vec<_> = secrets_validators()
            .into_iter()
            .map(|validator| validator.id())
            .collect();
        assert_eq!(
            ids,
            vec![
                "secrets.requirements.decl",
                "secrets.requirements.well_formed",
                "secrets.requirements.key_format"
            ]
        );
    }

    #[test]
    fn well_formed_validator_reports_pack_access_requirement_without_embedded_requirements() {
        let manifest = base_manifest("vendor.demo.pack");
        let diagnostics = SecretRequirementsWellFormedValidator.validate(&manifest);
        assert!(
            diagnostics
                .iter()
                .any(|diag| diag.code == "SEC_REQ_PARSE_NEEDS_PACK_ACCESS")
        );
    }

    #[test]
    fn secrets_required_hint_detects_secret_capability_names() {
        let mut manifest = base_manifest("vendor.demo.pack");
        manifest
            .capabilities
            .push(greentic_types_validate::ComponentCapability {
                name: "secret-sync".into(),
                description: None,
            });

        assert!(secrets_required_hint(&manifest));
    }
}
