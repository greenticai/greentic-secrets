#[cfg(feature = "env")]
use crate::backend::env::EnvBackend;
#[cfg(feature = "file")]
use crate::backend::file::FileBackend;
use crate::embedded::{CoreBuilder, MemoryBackend, MemoryKeyProvider, SecretsCore, SecretsError};
use crate::probe;
use crate::provider::Provider;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// High-level configuration for the default resolver.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    provider: Provider,
    tenant: Option<String>,
    team: Option<String>,
    cache_ttl: Option<Duration>,
    cache_capacity: Option<usize>,
    file_root: Option<PathBuf>,
    dev_fallback: bool,
}

impl ResolverConfig {
    /// Create a configuration with default values (auto provider detection).
    pub fn new() -> Self {
        Self {
            provider: Provider::Auto,
            tenant: None,
            team: None,
            cache_ttl: None,
            cache_capacity: None,
            file_root: None,
            dev_fallback: true,
        }
    }

    /// Load configuration from environment variables.
    ///
    /// * `GREENTIC_SECRETS_PROVIDER` selects the provider (`auto`, `local`, `aws`, `azure`,
    ///   `gcp`, `k8s`).
    /// * `GREENTIC_SECRETS_DEV` controls whether to fall back to the local backend (default: true).
    /// * `GREENTIC_SECRETS_FILE_ROOT` configures the local filesystem backend root.
    pub fn from_env() -> Self {
        let mut config = ResolverConfig::new();

        if let Ok(provider) = std::env::var("GREENTIC_SECRETS_PROVIDER")
            && let Some(parsed) = Provider::from_env_value(&provider)
        {
            config.provider = parsed;
        }

        let dev_fallback = std::env::var("GREENTIC_SECRETS_DEV")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(true);
        config.dev_fallback = dev_fallback;

        if let Ok(root) = std::env::var("GREENTIC_SECRETS_FILE_ROOT")
            && !root.trim().is_empty()
        {
            config.file_root = Some(PathBuf::from(root));
        }

        config
    }

    /// Override the provider selection.
    pub fn provider(mut self, provider: Provider) -> Self {
        self.provider = provider;
        self
    }

    /// Set the tenant scope for secrets.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Set the team scope.
    pub fn team(mut self, team: impl Into<String>) -> Self {
        self.team = Some(team.into());
        self
    }

    /// Override the default cache TTL.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }

    /// Override the cache capacity.
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.cache_capacity = Some(capacity);
        self
    }

    /// Configure the local filesystem backend root.
    pub fn file_root<P: AsRef<Path>>(mut self, root: P) -> Self {
        self.file_root = Some(root.as_ref().to_path_buf());
        self
    }

    /// Control whether local fallbacks are enabled when provider detection fails.
    pub fn dev_fallback(mut self, enabled: bool) -> Self {
        self.dev_fallback = enabled;
        self
    }
}

impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig::new()
    }
}

/// Resolver that selects an appropriate backend and exposes JSON/text helpers.
pub struct DefaultResolver {
    provider: Provider,
    core: SecretsCore,
}

impl DefaultResolver {
    /// Build a resolver using environment configuration.
    pub async fn new() -> Result<Self, SecretsError> {
        Self::from_config(ResolverConfig::from_env()).await
    }

    /// Build a resolver from the provided configuration.
    pub async fn from_config(config: ResolverConfig) -> Result<Self, SecretsError> {
        let mut builder = SecretsCore::builder();
        builder.clear_backends();

        if let Some(ref tenant) = config.tenant {
            builder = builder.tenant(tenant.clone());
        }

        if let Some(ref team) = config.team {
            builder = builder.team(team.clone());
        }

        if let Some(ttl) = config.cache_ttl {
            builder = builder.default_ttl(ttl);
        }

        if let Some(capacity) = config.cache_capacity {
            builder = builder.cache_capacity(capacity);
        }

        let requested = config.provider;
        let selected = if let Provider::Auto = requested {
            detect_provider().await
        } else {
            requested
        };

        let (builder, resolved) = configure_builder_for_provider(builder, &config, selected);
        let core = builder.build().await?;

        Ok(Self {
            provider: resolved,
            core,
        })
    }

    /// Returns the provider that was selected at runtime.
    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// Returns an immutable reference to the underlying [`SecretsCore`].
    pub fn core(&self) -> &SecretsCore {
        &self.core
    }
}

impl std::ops::Deref for DefaultResolver {
    type Target = SecretsCore;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

async fn detect_provider() -> Provider {
    if probe::is_kubernetes().await {
        return Provider::K8s;
    }

    if probe::is_aws().await {
        return Provider::Aws;
    }

    if probe::is_gcp().await {
        return Provider::Gcp;
    }

    if probe::is_azure().await {
        return Provider::Azure;
    }

    Provider::Local
}

fn configure_builder_for_provider(
    builder: CoreBuilder,
    config: &ResolverConfig,
    requested: Provider,
) -> (CoreBuilder, Provider) {
    match requested {
        Provider::Local => configure_local(builder, config),
        Provider::Aws => configure_aws(builder, config),
        Provider::Azure => configure_azure(builder, config),
        Provider::Gcp => configure_gcp(builder, config),
        Provider::K8s => configure_k8s(builder, config),
        Provider::Auto => configure_local(builder, config),
    }
}

fn configure_local(mut builder: CoreBuilder, config: &ResolverConfig) -> (CoreBuilder, Provider) {
    builder = builder.backend_named("memory", MemoryBackend::new(), MemoryKeyProvider::default());

    if config.dev_fallback {
        #[cfg(feature = "env")]
        {
            builder = builder.backend_named("env", EnvBackend::new(), MemoryKeyProvider::default());
        }
    }

    #[cfg(feature = "file")]
    if let Some(root) = config.file_root.as_ref() {
        builder = builder.backend_named(
            "file",
            FileBackend::new(root.clone()),
            MemoryKeyProvider::default(),
        );
    }

    (builder, Provider::Local)
}

fn configure_aws(builder: CoreBuilder, config: &ResolverConfig) -> (CoreBuilder, Provider) {
    #[cfg(feature = "aws")]
    {
        let _ = config;
        let builder = builder.backend_named(
            "aws",
            crate::backend::aws::AwsSecretsManagerBackend::new(),
            MemoryKeyProvider::default(),
        );
        (builder, Provider::Aws)
    }

    #[cfg(not(feature = "aws"))]
    {
        tracing::warn!(
            "aws provider requested but the `aws` feature is not enabled; falling back to local provider"
        );
        configure_local(builder, config)
    }
}

fn configure_azure(builder: CoreBuilder, config: &ResolverConfig) -> (CoreBuilder, Provider) {
    #[cfg(feature = "azure")]
    {
        let _ = config;
        let builder = builder.backend_named(
            "azure",
            crate::backend::azure::AzureKeyVaultBackend::new(),
            MemoryKeyProvider::default(),
        );
        (builder, Provider::Azure)
    }

    #[cfg(not(feature = "azure"))]
    {
        tracing::warn!(
            "azure provider requested but the `azure` feature is not enabled; falling back to local provider"
        );
        configure_local(builder, config)
    }
}

fn configure_gcp(builder: CoreBuilder, config: &ResolverConfig) -> (CoreBuilder, Provider) {
    #[cfg(feature = "gcp")]
    {
        let _ = config;
        let builder = builder.backend_named(
            "gcp",
            crate::backend::gcp::GcpSecretsManagerBackend::new(),
            MemoryKeyProvider::default(),
        );
        (builder, Provider::Gcp)
    }

    #[cfg(not(feature = "gcp"))]
    {
        tracing::warn!(
            "gcp provider requested but the `gcp` feature is not enabled; falling back to local provider"
        );
        configure_local(builder, config)
    }
}

fn configure_k8s(builder: CoreBuilder, config: &ResolverConfig) -> (CoreBuilder, Provider) {
    #[cfg(feature = "k8s")]
    {
        let _ = config;
        let builder = builder.backend_named(
            "k8s",
            crate::backend::k8s::K8sBackend::new(),
            MemoryKeyProvider::default(),
        );
        (builder, Provider::K8s)
    }

    #[cfg(not(feature = "k8s"))]
    {
        tracing::warn!(
            "k8s provider requested but the `k8s` feature is not enabled; falling back to local provider"
        );
        configure_local(builder, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::path::PathBuf;

    fn restore_env(key: &str, original: Option<std::ffi::OsString>) {
        match original {
            Some(value) => {
                // SAFETY: test restores the original environment value before returning.
                unsafe { std::env::set_var(key, value) }
            }
            None => {
                // SAFETY: test restores the original environment state before returning.
                unsafe { std::env::remove_var(key) }
            }
        }
    }

    #[tokio::test]
    async fn defaults_to_local_provider() {
        let resolver = DefaultResolver::from_config(
            ResolverConfig::new()
                .provider(Provider::Local)
                .tenant("example")
                .team("core"),
        )
        .await
        .expect("resolver");

        assert_eq!(resolver.provider(), Provider::Local);

        resolver
            .put_json(
                "secrets://dev/example/core/configs/api",
                &json!({ "token": "abc" }),
            )
            .await
            .expect("put");

        let value: Value = resolver
            .get_json("secrets://dev/example/core/configs/api")
            .await
            .expect("get");
        assert_eq!(value["token"], "abc");
    }

    #[tokio::test]
    async fn falls_back_when_feature_disabled() {
        let resolver = DefaultResolver::from_config(
            ResolverConfig::new()
                .provider(Provider::Aws)
                .tenant("test")
                .team("core"),
        )
        .await
        .expect("resolver");

        // When aws feature is disabled we should fall back to local to avoid panics.
        assert!(
            matches!(resolver.provider(), Provider::Aws | Provider::Local),
            "resolver should either use AWS (when feature enabled) or fallback to Local"
        );
    }

    #[test]
    fn from_env_reads_provider_dev_flag_and_file_root() {
        let provider_key = "GREENTIC_SECRETS_PROVIDER";
        let dev_key = "GREENTIC_SECRETS_DEV";
        let root_key = "GREENTIC_SECRETS_FILE_ROOT";
        let original_provider = std::env::var_os(provider_key);
        let original_dev = std::env::var_os(dev_key);
        let original_root = std::env::var_os(root_key);

        // SAFETY: this test restores the original process environment before returning.
        unsafe {
            std::env::set_var(provider_key, "local");
            std::env::set_var(dev_key, "0");
            std::env::set_var(root_key, "/tmp/greentic-secrets-tests");
        }

        let config = ResolverConfig::from_env();
        restore_env(provider_key, original_provider);
        restore_env(dev_key, original_dev);
        restore_env(root_key, original_root);

        assert_eq!(config.provider, Provider::Local);
        assert!(!config.dev_fallback);
        assert_eq!(
            config.file_root,
            Some(PathBuf::from("/tmp/greentic-secrets-tests"))
        );
    }

    #[test]
    fn builder_methods_override_configuration() {
        let config = ResolverConfig::new()
            .provider(Provider::K8s)
            .tenant("tenant-a")
            .team("core")
            .cache_ttl(Duration::from_secs(30))
            .cache_capacity(128)
            .file_root("/tmp/secrets")
            .dev_fallback(false);

        assert_eq!(config.provider, Provider::K8s);
        assert_eq!(config.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(config.team.as_deref(), Some("core"));
        assert_eq!(config.cache_ttl, Some(Duration::from_secs(30)));
        assert_eq!(config.cache_capacity, Some(128));
        assert_eq!(config.file_root, Some(PathBuf::from("/tmp/secrets")));
        assert!(!config.dev_fallback);
    }
}
