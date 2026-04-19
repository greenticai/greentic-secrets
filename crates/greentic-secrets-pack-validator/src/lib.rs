#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use greentic_types_validate::{
    PackManifest, ProviderDecl, ProviderExtensionInline, decode_pack_manifest,
};

wit_bindgen::generate!({
    world: "pack-validator",
    path: "wit/greentic/pack-validate@0.1.0",
});

use exports::greentic::pack_validate::validator::{Diagnostic, Guest, PackInputs};

const SECRET_REQUIREMENTS_ASSET: &str = "assets/secret-requirements.json";
const SECRET_REQUIREMENTS_ASSET_ALT: &str = "assets/secret_requirements.json";

struct SecretsPackValidator;

impl Guest for SecretsPackValidator {
    fn applies(inputs: PackInputs) -> bool {
        let file_index = inputs.file_index;
        let asset_present = has_secret_requirements_asset(&file_index);
        if let Some(manifest) = decode_manifest(&inputs.manifest_cbor) {
            secrets_required(&manifest) || asset_present
        } else {
            asset_present
        }
    }

    fn validate(inputs: PackInputs) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        let file_index = inputs.file_index;
        let asset_present = has_secret_requirements_asset(&file_index);
        let manifest = decode_manifest(&inputs.manifest_cbor);
        let secrets_required = manifest
            .as_ref()
            .map(secrets_required)
            .unwrap_or(asset_present);

        if !secrets_required {
            return diagnostics;
        }

        if !asset_present {
            diagnostics.push(diagnostic(
                "error",
                "SEC_REQUIREMENTS_ASSET_MISSING",
                "Secret requirements asset is missing from the pack.",
                Some(SECRET_REQUIREMENTS_ASSET.to_owned()),
                Some("Add assets/secret-requirements.json to the pack.".to_owned()),
            ));
        }

        if !can_check_sensitivity() {
            diagnostics.push(diagnostic(
                "warn",
                "SEC_SECRET_NOT_SENSITIVE",
                "Secret requirements sensitivity checks require asset bytes.",
                Some(SECRET_REQUIREMENTS_ASSET.to_owned()),
                Some(
                    "Provide secret-requirements.json bytes to enable sensitivity checks."
                        .to_owned(),
                ),
            ));
        }

        if let Some(manifest) = manifest.as_ref() {
            diagnostics.extend(validate_key_format(manifest));
        }

        diagnostics
    }
}

#[cfg(target_arch = "wasm32")]
export!(SecretsPackValidator);

fn decode_manifest(bytes: &[u8]) -> Option<PackManifest> {
    decode_pack_manifest(bytes).ok()
}

fn has_secret_requirements_asset(file_index: &[String]) -> bool {
    file_index
        .iter()
        .any(|entry| entry == SECRET_REQUIREMENTS_ASSET || entry == SECRET_REQUIREMENTS_ASSET_ALT)
}

fn secrets_required(manifest: &PackManifest) -> bool {
    let pack_id = manifest.pack_id.as_str().to_ascii_lowercase();
    if pack_id.starts_with("secrets-") || pack_id.contains(".secrets.") {
        return true;
    }
    if !manifest.secret_requirements.is_empty() {
        return true;
    }
    manifest
        .provider_extension_inline()
        .map(provider_extension_mentions_secrets)
        .unwrap_or(false)
}

fn provider_extension_mentions_secrets(inline: &ProviderExtensionInline) -> bool {
    inline.providers.iter().any(provider_decl_mentions_secrets)
}

fn provider_decl_mentions_secrets(provider: &ProviderDecl) -> bool {
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

fn validate_key_format(manifest: &PackManifest) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (idx, req) in manifest.secret_requirements.iter().enumerate() {
        let key = req.key.as_str();
        if key.is_empty() {
            continue;
        }
        if is_upper_snake(key) || key.starts_with("greentic://") {
            continue;
        }
        diagnostics.push(diagnostic(
            "warn",
            "SEC_BAD_KEY_FORMAT",
            "Secret requirement key format should be UPPER_SNAKE or greentic:// URI.",
            Some(format!("secret_requirements.{idx}.key")),
            Some("Rename the key to UPPER_SNAKE or a greentic:// URI.".to_owned()),
        ));
    }
    diagnostics
}

fn is_upper_snake(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn can_check_sensitivity() -> bool {
    false
}

fn diagnostic(
    severity: &str,
    code: &str,
    message: &str,
    path: Option<String>,
    hint: Option<String>,
) -> Diagnostic {
    Diagnostic {
        severity: severity.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
        path,
        hint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types_validate::{
        ExtensionInline, ExtensionRef, PROVIDER_EXTENSION_ID, PackId, PackKind, PackSignatures,
        ProviderRuntimeRef, SecretRequirement, encode_pack_manifest,
    };
    use semver::Version;
    use std::collections::BTreeMap;

    fn manifest_with_pack_id(pack_id: &str) -> PackManifest {
        PackManifest {
            schema_version: "pack-v1".into(),
            pack_id: PackId::new(pack_id).expect("pack id"),
            name: None,
            version: Version::parse("0.1.0").expect("version"),
            kind: PackKind::Application,
            publisher: "greentic".into(),
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

    fn provider_inline(component_ref: &str) -> ProviderExtensionInline {
        ProviderExtensionInline {
            providers: vec![ProviderDecl {
                provider_type: "vendor.provider".into(),
                capabilities: Vec::new(),
                ops: Vec::new(),
                config_schema_ref: "assets/schemas/secrets/demo/config.schema.json".into(),
                state_schema_ref: None,
                runtime: ProviderRuntimeRef {
                    component_ref: component_ref.into(),
                    export: "invoke".into(),
                    world: "greentic:provider/schema-core@1.0.0".into(),
                },
                docs_ref: None,
            }],
            additional_fields: BTreeMap::new(),
        }
    }

    #[test]
    fn detects_secret_requirements_assets() {
        assert!(has_secret_requirements_asset(&[
            "assets/secret-requirements.json".to_string()
        ]));
        assert!(has_secret_requirements_asset(&[
            "assets/secret_requirements.json".to_string()
        ]));
        assert!(!has_secret_requirements_asset(&["README.md".to_string()]));
    }

    #[test]
    fn secrets_required_for_pack_id_requirements_and_provider_hints() {
        let by_pack_id = manifest_with_pack_id("secrets-demo");
        assert!(secrets_required(&by_pack_id));

        let mut by_requirement = manifest_with_pack_id("vendor.demo");
        let mut requirement = SecretRequirement::default();
        requirement.key = "API_KEY".into();
        by_requirement.secret_requirements.push(requirement);
        assert!(secrets_required(&by_requirement));

        let mut by_provider = manifest_with_pack_id("vendor.demo");
        let mut extensions = BTreeMap::new();
        extensions.insert(
            PROVIDER_EXTENSION_ID.to_string(),
            ExtensionRef {
                kind: PROVIDER_EXTENSION_ID.into(),
                version: "1.0.0".into(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Provider(provider_inline(
                    "vendor.secrets.runtime",
                ))),
            },
        );
        by_provider.extensions = Some(extensions);
        assert!(secrets_required(&by_provider));
    }

    #[test]
    fn validate_key_format_warns_for_non_secret_style_keys() {
        let mut manifest = manifest_with_pack_id("vendor.demo");
        let mut bad = SecretRequirement::default();
        bad.key = "dbPassword".into();
        manifest.secret_requirements.push(bad);

        let diagnostics = validate_key_format(&manifest);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "SEC_BAD_KEY_FORMAT");
    }

    #[test]
    fn validate_key_format_accepts_upper_snake_and_uri_keys() {
        let mut manifest = manifest_with_pack_id("vendor.demo");
        let mut env_key = SecretRequirement::default();
        env_key.key = "DB_PASSWORD".into();
        let mut uri_key = SecretRequirement::default();
        uri_key.key = "greentic://tenant/configs/db".into();
        manifest.secret_requirements.extend([env_key, uri_key]);

        assert!(validate_key_format(&manifest).is_empty());
    }

    #[test]
    fn decode_manifest_roundtrips_encoded_bytes() {
        let manifest = manifest_with_pack_id("vendor.demo");
        let bytes = encode_pack_manifest(&manifest).expect("encode");
        let decoded = decode_manifest(&bytes).expect("decode");
        assert_eq!(decoded.pack_id, manifest.pack_id);
    }

    #[test]
    fn is_upper_snake_requires_only_upper_ascii_digits_or_underscores() {
        assert!(is_upper_snake("DB_PASSWORD_2"));
        assert!(!is_upper_snake("db_password"));
        assert!(!is_upper_snake("DB-PASSWORD"));
        assert!(!is_upper_snake(""));
    }

    #[test]
    fn provider_decl_only_matches_secretish_fields() {
        let non_secret = ProviderDecl {
            provider_type: "vendor.cache".into(),
            capabilities: Vec::new(),
            ops: Vec::new(),
            config_schema_ref: "assets/schemas/cache/config.schema.json".into(),
            state_schema_ref: None,
            runtime: ProviderRuntimeRef {
                component_ref: "vendor.cache.runtime".into(),
                export: "invoke".into(),
                world: "greentic:provider/schema-core@1.0.0".into(),
            },
            docs_ref: None,
        };
        assert!(!provider_decl_mentions_secrets(&non_secret));
        assert!(!provider_extension_mentions_secrets(
            &ProviderExtensionInline {
                providers: vec![non_secret],
                additional_fields: BTreeMap::new(),
            }
        ));
    }

    #[test]
    fn guest_applies_and_validate_cover_asset_and_missing_asset_paths() {
        let manifest = manifest_with_pack_id("secrets-demo");
        let manifest_cbor = encode_pack_manifest(&manifest).expect("encode");

        assert!(<SecretsPackValidator as Guest>::applies(PackInputs {
            manifest_cbor: manifest_cbor.clone(),
            sbom_json: "{}".into(),
            file_index: vec![SECRET_REQUIREMENTS_ASSET.to_owned()],
        }));

        let diagnostics = <SecretsPackValidator as Guest>::validate(PackInputs {
            manifest_cbor,
            sbom_json: "{}".into(),
            file_index: Vec::new(),
        });
        assert!(
            diagnostics
                .iter()
                .any(|diag| diag.code == "SEC_REQUIREMENTS_ASSET_MISSING")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diag| diag.code == "SEC_SECRET_NOT_SENSITIVE")
        );
    }

    #[test]
    fn guest_uses_asset_presence_when_manifest_cannot_be_decoded() {
        assert!(<SecretsPackValidator as Guest>::applies(PackInputs {
            manifest_cbor: vec![1, 2, 3],
            sbom_json: "{}".into(),
            file_index: vec![SECRET_REQUIREMENTS_ASSET_ALT.to_owned()],
        }));
    }
}
