//! Core domain primitives shared across brokers, SDKs, and providers.

pub mod api_keys;
pub mod backend;
pub mod broker;
pub mod crypto;
pub mod embedded;
pub mod errors;
pub mod generators;
pub mod http;
#[cfg(feature = "imds")]
pub mod imds;
pub mod key_provider;
pub mod policy;
pub mod probe;
pub mod provider;
pub mod provider_secrets;
pub mod provision;
pub mod resolver;
pub mod rt;
pub mod seed;
pub mod signing_keys;
pub mod sink;
pub mod spec;
pub mod spec_compat;
pub mod spec_registry;
pub mod spec_schema;
pub mod spec_validate;
pub mod types;
pub mod uri;

pub use crate::spec_registry::SecretSpecRegistry;
pub use crate::spec_schema::specs_to_json_schema;
pub use crate::spec_validate::SecretValidationResult;
pub use api_keys::{
    billing_api_key_uri, distributor_api_key_uri, get_billing_provider_api_key_ref,
    get_distributor_api_key_ref, get_repo_api_key_ref, repo_api_key_uri,
};
#[cfg(feature = "aws")]
pub use backend::aws::AwsSecretsManagerBackend;
#[cfg(feature = "env")]
pub use backend::env::EnvBackend;
#[cfg(feature = "file")]
pub use backend::file::FileBackend;
#[cfg(feature = "k8s")]
pub use backend::k8s::K8sBackend;
pub use backend::{SecretVersion, SecretsBackend, VersionedSecret};
pub use broker::{BrokerSecret, SecretsBroker};
pub use crypto::dek_cache::DekCache;
pub use crypto::envelope::EnvelopeService;
pub use embedded::{
    CoreBuilder, CoreConfig, MemoryBackend, MemoryKeyProvider, Policy, SecretsCore, SecretsError,
};
pub use errors::{DecryptError, DecryptResult, Error, Result};
pub use generators::generate_secret_value;
pub use key_provider::KeyProvider;
pub use policy::{Authorizer, PolicyGuard, Principal};
pub use provider::Provider;
pub use provider_secrets::{
    ProviderSecret, events_provider_secret_uri, get_events_provider_secret,
    get_messaging_adapter_secret, messaging_adapter_secret_uri, ttl_duration, ttl_seconds,
};
pub use provision::{PromoteReport, ProvisionReport, discover_secret_set, promote, provision};
pub use resolver::{DefaultResolver, ResolverConfig};
#[cfg(feature = "dev-store")]
pub use seed::DevStore;
pub use seed::{
    ApplyFailure, ApplyOptions, ApplyReport, BrokerStore, DevContext, HttpStore,
    NormalizedSeedEntry, SecretsStore, apply_seed, resolve_uri,
};
pub use signing_keys::{SigningPurpose, get_signing_key_ref, signing_key_ref_uri};
pub use sink::{SecretsSink, StoreSink};
pub use spec::{SecretDescribable, SecretSpec};
pub use types::{
    ContentType, EncryptionAlgorithm, Envelope, Scope, SecretIdentifier, SecretListItem,
    SecretMeta, SecretRecord, Visibility,
};
pub use uri::SecretUri;
