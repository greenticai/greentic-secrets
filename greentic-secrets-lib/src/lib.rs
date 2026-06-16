pub use greentic_secrets_core as core;
pub use greentic_secrets_core::api_keys;
pub use greentic_secrets_core::provider_secrets;
pub use greentic_secrets_core::signing_keys;
pub use greentic_secrets_spec as spec;
pub use greentic_secrets_spec::{
    SecretFormat, SecretKey, SecretRequirement, SecretScope, SeedDoc, SeedEntry, SeedValue,
};
// Canonical secret identity + the `_`-everywhere team rule (consolidation PR1).
pub use greentic_secrets_spec::{
    SECRET_SCHEME, SECRET_STORE_SCHEME, SecretRef, SecretRefParseError, SecretUri,
    TEAM_PLACEHOLDER, canonical_secret_name, canonical_secret_store_key, canonical_secret_uri,
    is_default_team, normalize_team,
};
// Pack-declared requirement + generation vocabulary (consolidation PR1).
pub use greentic_secrets_spec::{
    GeneratedSecretRequirement, GeneratedSecretScope, ManagedSecret, PackSecretRequirement,
    SecretSet, SecretSource, generated_scope_team,
};

pub use greentic_secrets_api::*;

#[cfg(feature = "env")]
pub mod env;

#[cfg(feature = "env")]
pub use env::EnvSecretsManager;

#[cfg(feature = "providers-aws")]
pub use greentic_secrets_provider_aws as aws;
#[cfg(feature = "providers-azure")]
pub use greentic_secrets_provider_azure as azure;
#[cfg(feature = "providers-dev")]
pub use greentic_secrets_provider_dev_env as dev;
#[cfg(feature = "providers-gcp")]
pub use greentic_secrets_provider_gcp as gcp;
#[cfg(feature = "providers-k8s")]
pub use greentic_secrets_provider_k8s as k8s;
#[cfg(feature = "providers-vault")]
pub use greentic_secrets_provider_vault as vault;

#[cfg(feature = "providers-dev")]
pub use greentic_secrets_core::seed::DevStore;
pub use greentic_secrets_core::seed::{
    ApplyFailure, ApplyOptions, ApplyReport, BrokerStore, DevContext, NormalizedSeedEntry,
    SecretsStore, apply_seed, resolve_uri,
};

// Generation, discovery, provisioning, and promotion engine (consolidation PR2).
pub use greentic_secrets_core::{
    PromoteReport, ProvisionReport, SecretsSink, StoreSink, discover_secret_set,
    generate_secret_value, promote, provision,
};
