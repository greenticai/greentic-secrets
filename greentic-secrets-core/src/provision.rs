//! Discovery, provisioning, and promotion — the orchestration that turns a set
//! of pack-declared requirements into materialized secrets and ships them where
//! they're needed.
//!
//! - [`discover_secret_set`] builds the canonical [`SecretSet`] for a scope and
//!   category from parsed [`PackSecretRequirement`]s, classifying each entry as
//!   operator-supplied or system-generated (carrying its generation policy). The
//!   set deliberately includes generated secrets so no downstream consumer can
//!   miss them.
//! - [`provision`] makes every entry exist in a store: it mints the missing
//!   generated ones (via [`generate_secret_value`]) and reports which
//!   operator-supplied ones are still absent. It is idempotent — existing values
//!   (including previously generated ones) are never overwritten.
//! - [`promote`] copies a set's values from a source store into a
//!   [`SecretsSink`] (e.g. a cloud secret manager). Because the set includes
//!   generated secrets, cloud promotion can no longer miss them — this is the
//!   root-cause fix for the cloud-deploy gap.

use crate::errors::{Error, Result};
use crate::generators::generate_secret_value;
use crate::seed::SecretsStore;
use crate::sink::SecretsSink;
use greentic_secrets_spec::{
    ManagedSecret, PackSecretRequirement, Scope, SecretSet, SecretSource, canonical_secret_uri,
    generated_scope_team, normalize_team,
};
use greentic_types::secrets::SecretFormat;

/// Build the canonical [`SecretSet`] for `scope`/`category` from a list of
/// parsed pack requirements.
///
/// Each requirement's `key` (already [`canonical_secret_name`](greentic_secrets_spec::canonical_secret_name)-
/// normalized by the reader) is rendered through [`canonical_secret_uri`] under
/// `category` (the provider/pack id). A generated requirement's team segment is
/// resolved with [`generated_scope_team`] (so a tenant-scoped secret lands under
/// `_`); an operator-supplied one inherits the scope's team. Call once per pack
/// and extend a single set across packs.
pub fn discover_secret_set(
    scope: Scope,
    category: &str,
    requirements: &[PackSecretRequirement],
) -> Result<SecretSet> {
    // Canonicalize the scope's team up front so the set is consistent.
    let scope = Scope::new(scope.env(), scope.tenant(), normalize_team(scope.team()))?;
    let mut set = SecretSet::new(scope.clone());

    for req in requirements {
        let team = match &req.generated {
            Some(generated) => generated_scope_team(generated, scope.team()).map(str::to_string),
            None => scope.team().map(str::to_string),
        };
        let uri = canonical_secret_uri(
            scope.env(),
            scope.tenant(),
            team.as_deref(),
            category,
            &req.key,
        )?;
        let mut managed = match &req.generated {
            Some(generated) => ManagedSecret::generated(uri, generated.clone()),
            None => ManagedSecret::user_supplied(uri),
        };
        managed.required = req.required;
        set.push(managed);
    }

    Ok(set)
}

/// Outcome of a [`provision`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProvisionReport {
    /// URIs that were freshly generated and written to the store.
    pub generated: Vec<String>,
    /// URIs already present in the store (left untouched).
    pub already_present: Vec<String>,
    /// Required operator-supplied URIs that are still absent.
    pub missing_required: Vec<String>,
    /// Optional operator-supplied URIs that are absent.
    pub missing_optional: Vec<String>,
}

impl ProvisionReport {
    /// True when no required operator-supplied secret is missing.
    pub fn is_satisfied(&self) -> bool {
        self.missing_required.is_empty()
    }
}

/// Ensure every secret in `set` exists in `store`: mint the missing generated
/// ones, and record which operator-supplied ones are absent.
///
/// Idempotent — a secret already present in the store is left untouched (the
/// model's `regenerate_if_present` is a rotation concern handled elsewhere, not
/// here).
pub async fn provision(set: &SecretSet, store: &dyn SecretsStore) -> Result<ProvisionReport> {
    let mut report = ProvisionReport::default();
    for managed in &set.secrets {
        let uri = managed.uri.to_string();
        if store_has(store, &uri).await? {
            report.already_present.push(uri);
            continue;
        }
        match &managed.source {
            SecretSource::Generated(generated) => {
                let (bytes, format) = generate_secret_value(generated)?;
                store.put(&uri, format, &bytes).await?;
                report.generated.push(uri);
            }
            SecretSource::UserSupplied => {
                if managed.required {
                    report.missing_required.push(uri);
                } else {
                    report.missing_optional.push(uri);
                }
            }
        }
    }
    Ok(report)
}

/// Outcome of a [`promote`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PromoteReport {
    /// URIs successfully written to the sink.
    pub promoted: Vec<String>,
    /// URIs in the set that had no value in the source store.
    pub missing: Vec<String>,
}

/// Copy every value in `set` from `source` into `sink`. Entries with no value in
/// the source store are recorded in [`PromoteReport::missing`] rather than
/// failing the whole promotion.
pub async fn promote(
    set: &SecretSet,
    source: &dyn SecretsStore,
    sink: &dyn SecretsSink,
) -> Result<PromoteReport> {
    let mut report = PromoteReport::default();
    for managed in &set.secrets {
        let uri = managed.uri.to_string();
        match source.get(&uri).await {
            Ok(bytes) => {
                let format = managed.format.clone().unwrap_or(SecretFormat::Text);
                sink.put_secret(&managed.uri, &bytes, format).await?;
                report.promoted.push(uri);
            }
            Err(Error::NotFound { .. }) => report.missing.push(uri),
            Err(err) => return Err(err),
        }
    }
    Ok(report)
}

async fn store_has(store: &dyn SecretsStore, uri: &str) -> Result<bool> {
    match store.get(uri).await {
        Ok(_) => Ok(true),
        Err(Error::NotFound { .. }) => Ok(false),
        Err(err) => Err(err),
    }
}

#[cfg(all(test, feature = "dev-store"))]
mod tests {
    use super::*;
    use crate::seed::DevStore;
    use greentic_secrets_spec::{GeneratedSecretRequirement, GeneratedSecretScope};
    use tempfile::tempdir;

    fn scope() -> Scope {
        Scope::new("dev", "demo", None).unwrap()
    }

    fn webhook_generated() -> GeneratedSecretRequirement {
        GeneratedSecretRequirement {
            policy: "random".to_string(),
            length: 32,
            encoding: "raw_text".to_string(),
            scope: GeneratedSecretScope {
                level: "tenant".to_string(),
                team: Some("_".to_string()),
            },
            regenerate_if_present: false,
        }
    }

    fn requirements() -> Vec<PackSecretRequirement> {
        vec![
            PackSecretRequirement::user_supplied("api_key"),
            PackSecretRequirement::generated("webhook_secret", webhook_generated()),
        ]
    }

    const WEBHOOK_URI: &str = "secrets://dev/demo/_/messaging-telegram/webhook_secret";

    #[test]
    fn discovery_classifies_generated_vs_supplied() {
        let set = discover_secret_set(scope(), "messaging-telegram", &requirements()).unwrap();
        assert_eq!(set.secrets.len(), 2);
        assert_eq!(set.user_supplied().count(), 1);
        assert_eq!(set.generated().count(), 1);
        // A tenant-scoped generated secret lands under the team-less `_` segment.
        assert!(set.generated().any(|m| m.uri.to_string() == WEBHOOK_URI));
    }

    #[tokio::test]
    async fn provision_mints_generated_and_flags_missing_supplied() {
        let dir = tempdir().unwrap();
        let store = DevStore::with_path(dir.path().join(".dev.secrets.env")).unwrap();
        let set = discover_secret_set(scope(), "messaging-telegram", &requirements()).unwrap();

        let report = provision(&set, &store).await.unwrap();
        assert_eq!(report.generated.len(), 1, "webhook secret should be minted");
        assert_eq!(
            report.missing_required.len(),
            1,
            "api_key is operator-supplied"
        );
        assert!(!report.is_satisfied());

        // The minted webhook secret is now readable and stable on a re-run.
        let first = store.get(WEBHOOK_URI).await.unwrap();
        assert_eq!(first.len(), 32);
        let report2 = provision(&set, &store).await.unwrap();
        assert!(report2.generated.is_empty(), "idempotent: already present");
        assert_eq!(
            store.get(WEBHOOK_URI).await.unwrap(),
            first,
            "value unchanged"
        );
    }

    #[tokio::test]
    async fn promote_copies_present_values_and_reports_missing() {
        let src_dir = tempdir().unwrap();
        let dst_dir = tempdir().unwrap();
        let source = DevStore::with_path(src_dir.path().join(".dev.secrets.env")).unwrap();
        let sink_store = DevStore::with_path(dst_dir.path().join(".dev.secrets.env")).unwrap();

        let set = discover_secret_set(scope(), "messaging-telegram", &requirements()).unwrap();
        // Only the generated secret gets materialized in the source.
        provision(&set, &source).await.unwrap();

        let sink = crate::sink::StoreSink::new(sink_store);
        let report = promote(&set, &source, &sink).await.unwrap();
        assert_eq!(
            report.promoted.len(),
            1,
            "generated webhook secret promoted"
        );
        assert_eq!(report.missing.len(), 1, "api_key never supplied");
        // The promoted value matches across stores.
        assert_eq!(
            sink.store().get(WEBHOOK_URI).await.unwrap(),
            source.get(WEBHOOK_URI).await.unwrap()
        );
    }
}
