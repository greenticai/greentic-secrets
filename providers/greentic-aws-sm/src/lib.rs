use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_kms::{Client as KmsClient, primitives::Blob as KmsBlob};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_secretsmanager::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_secretsmanager::operation::list_secret_version_ids::ListSecretVersionIdsError;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType, Tag};
use aws_types::region::Region;
use greentic_secrets_core::rt;
use greentic_secrets_spec::{
    KeyProvider, Scope, SecretListItem, SecretRecord, SecretUri, SecretVersion, SecretsBackend,
    SecretsError, SecretsResult, VersionedSecret,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

const DEFAULT_PREFIX: &str = "gtsec";
const DEFAULT_STAGE: &str = "AWSCURRENT";
const PREFIX_ENV: &str = "GREENTIC_AWS_SECRET_PREFIX";
const STAGE_ENV: &str = "GREENTIC_AWS_VERSION_STAGE";
const KMS_KEY_ENV: &str = "GREENTIC_AWS_KMS_KEY_ID";
const REGION_ENV: &str = "GREENTIC_AWS_REGION";
const SM_ENDPOINT_ENV: &str = "GREENTIC_AWS_SM_ENDPOINT";
const KMS_ENDPOINT_ENV: &str = "GREENTIC_AWS_KMS_ENDPOINT";
const TEAM_PLACEHOLDER: &str = "_";

/// Components returned for integration with the broker/core wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Build the AWS Secrets Manager backend and corresponding KMS key provider.
pub async fn build_backend() -> Result<BackendComponents> {
    let (config, shared_config) = AwsProviderConfig::load_from_env().await?;

    let secrets_client = {
        let mut builder = aws_sdk_secretsmanager::config::Builder::from(&shared_config);
        if let Some(endpoint) = config.secrets_endpoint.as_deref() {
            builder = builder.endpoint_url(endpoint);
        }
        SecretsManagerClient::from_conf(builder.build())
    };

    let kms_client = {
        let mut builder = aws_sdk_kms::config::Builder::from(&shared_config);
        if let Some(endpoint) = config.kms_endpoint.as_deref() {
            builder = builder.endpoint_url(endpoint);
        }
        KmsClient::from_conf(builder.build())
    };

    let backend = AwsSecretsBackend::new(secrets_client, config.clone());
    let key_provider = AwsKmsKeyProvider::new(kms_client, config.clone());

    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
struct AwsProviderConfig {
    secret_prefix: String,
    version_stage: String,
    kms_key_id: String,
    secrets_endpoint: Option<String>,
    kms_endpoint: Option<String>,
    resource_tags: Vec<aws_sdk_secretsmanager::types::Tag>,
}

impl AwsProviderConfig {
    async fn load_from_env() -> Result<(Self, aws_types::SdkConfig)> {
        let prefix = env::var(PREFIX_ENV).unwrap_or_else(|_| DEFAULT_PREFIX.to_string());
        let stage = env::var(STAGE_ENV).unwrap_or_else(|_| DEFAULT_STAGE.to_string());
        let kms_key_id = env::var(KMS_KEY_ENV)
            .context("GREENTIC_AWS_KMS_KEY_ID must be set for the AWS provider")?;
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Ok(region) = env::var(REGION_ENV) {
            loader = loader.region(Region::new(region));
        }

        let shared_config = loader.load().await;
        let secrets_endpoint = env::var(SM_ENDPOINT_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty());
        let kms_endpoint = env::var(KMS_ENDPOINT_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty());
        let resource_tags = build_resource_tags();

        Ok((
            Self {
                secret_prefix: prefix,
                version_stage: stage,
                kms_key_id,
                secrets_endpoint,
                kms_endpoint,
                resource_tags,
            },
            shared_config,
        ))
    }

    fn secret_name(&self, uri: &SecretUri) -> String {
        runtime_secret_name(&self.secret_prefix, uri)
    }

    fn scope_prefix(&self, scope: &Scope) -> String {
        format!(
            "{prefix}/{env}/{tenant}/",
            prefix = self.secret_prefix,
            env = scope.env(),
            tenant = scope.tenant()
        )
    }
}

fn build_resource_tags() -> Vec<Tag> {
    let mut tags = Vec::new();
    tags.push(Tag::builder().key("greentic-ci").value("true").build());
    if let Ok(repo) = env::var("GITHUB_REPOSITORY") {
        tags.push(Tag::builder().key("greentic-repo").value(repo).build());
    }
    if let Ok(run_id) = env::var("GITHUB_RUN_ID") {
        let attempt = env::var("GITHUB_RUN_ATTEMPT").unwrap_or_default();
        let combined = if attempt.is_empty() {
            run_id
        } else {
            format!("{run_id}/{attempt}")
        };
        tags.push(Tag::builder().key("greentic-run").value(combined).build());
    }
    tags
}

#[derive(Clone)]
pub struct AwsSecretsBackend {
    client: SecretsManagerClient,
    config: AwsProviderConfig,
}

async fn fetch_secret_version_inner(
    client: SecretsManagerClient,
    secret_id: String,
    version_id: Option<String>,
) -> SecretsResult<Option<StoredSecret>> {
    let mut request = client.get_secret_value().secret_id(secret_id);
    if let Some(version) = version_id {
        request = request.version_id(version);
    }
    match request.send().await {
        Ok(output) => deserialize_secret_payload(output.secret_string(), output.secret_binary()),
        Err(err) => {
            if is_not_found(&err) {
                Ok(None)
            } else {
                Err(storage_error("get_secret_value", err))
            }
        }
    }
}

impl AwsSecretsBackend {
    fn new(client: SecretsManagerClient, config: AwsProviderConfig) -> Self {
        Self { client, config }
    }

    fn fetch_latest_version(&self, secret_id: &str) -> SecretsResult<Option<StoredSecret>> {
        let client = self.client.clone();
        let secret_id = secret_id.to_owned();
        rt::sync_await(async move { fetch_secret_version_inner(client, secret_id, None).await })
    }

    fn load_all_versions(&self, uri: &SecretUri) -> SecretsResult<Vec<StoredSecret>> {
        let client = self.client.clone();
        let secret_id = self.config.secret_name(uri);
        rt::sync_await(async move {
            let mut collected = Vec::new();
            let mut token: Option<String> = None;

            loop {
                let mut request = client
                    .list_secret_version_ids()
                    .secret_id(secret_id.clone())
                    .include_deprecated(true);

                if let Some(ref next) = token {
                    request = request.next_token(next);
                }

                let response = match request.send().await {
                    Ok(resp) => resp,
                    Err(err) => {
                        if is_not_found(&err) {
                            return Ok(Vec::new());
                        }
                        if list_versions_unsupported(&err) {
                            let latest =
                                fetch_secret_version_inner(client.clone(), secret_id.clone(), None)
                                    .await?;
                            return Ok(latest.into_iter().collect());
                        }
                        return Err(storage_error("list_secret_version_ids", err));
                    }
                };

                for entry in response.versions() {
                    if let Some(version_id) = entry.version_id()
                        && let Some(stored) = fetch_secret_version_inner(
                            client.clone(),
                            secret_id.clone(),
                            Some(version_id.to_string()),
                        )
                        .await?
                    {
                        collected.push(stored);
                    }
                }

                if let Some(next) = response.next_token() {
                    token = Some(next.to_string());
                } else {
                    break;
                }
            }

            collected.sort_by_key(|item| item.version);
            Ok(collected)
        })
    }

    fn ensure_secret_created(
        &self,
        secret_id: &str,
        payload: &str,
        record: Option<&SecretRecord>,
    ) -> SecretsResult<bool> {
        let client = self.client.clone();
        let secret_id = secret_id.to_owned();
        let payload = payload.to_owned();
        let description = record.and_then(|rec| rec.meta.description.clone());
        let config = self.config.clone();
        rt::sync_await(async move {
            let mut request = client
                .create_secret()
                .name(secret_id.clone())
                .secret_string(payload.clone());
            if !config.resource_tags.is_empty() {
                request = request.set_tags(Some(config.resource_tags.clone()));
            }
            if let Some(desc) = description.as_ref()
                && !desc.is_empty()
            {
                request = request.description(desc.clone());
            }

            match request.send().await {
                Ok(_) => Ok(true),
                Err(err) => {
                    if let SdkError::ServiceError(context) = &err
                        && context.err().is_resource_exists_exception()
                    {
                        return Ok(false);
                    }
                    Err(storage_error("create_secret", err))
                }
            }
        })
    }

    fn write_new_version(&self, secret_id: &str, payload: &str) -> SecretsResult<()> {
        let client = self.client.clone();
        let secret_id = secret_id.to_owned();
        let payload = payload.to_owned();
        let version_stage = self.config.version_stage.clone();
        rt::sync_await(async move {
            match client
                .put_secret_value()
                .secret_id(secret_id)
                .secret_string(payload)
                .set_version_stages(Some(vec![version_stage]))
                .send()
                .await
            {
                Ok(_) => Ok(()),
                Err(err) => Err(storage_error("put_secret_value", err)),
            }
        })
    }

    fn list_scope(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        let prefix = self.config.scope_prefix(scope);
        let client = self.client.clone();
        let secret_prefix = self.config.secret_prefix.clone();
        let scope_env = scope.env().to_string();
        let scope_tenant = scope.tenant().to_string();
        let scope_team = scope.team().map(|s| s.to_string());
        let category_prefix = category_prefix.map(|s| s.to_string());
        let name_prefix = name_prefix.map(|s| s.to_string());
        rt::sync_await(async move {
            let mut items = Vec::new();
            let mut token: Option<String> = None;

            loop {
                let mut request = client.list_secrets();
                let filter = Filter::builder()
                    .key(FilterNameStringType::Name)
                    .values(prefix.clone())
                    .build();
                request = request.filters(filter);
                if let Some(ref next) = token {
                    request = request.next_token(next);
                }

                let response = match request.send().await {
                    Ok(resp) => resp,
                    Err(err) => return Err(storage_error("list_secrets", err)),
                };

                for entry in response.secret_list() {
                    let name = match entry.name() {
                        Some(value) => value.to_string(),
                        None => continue,
                    };
                    if !name.starts_with(&prefix) {
                        continue;
                    }
                    let uri = match parse_secret_name(&secret_prefix, &name) {
                        Some(uri) => uri,
                        None => continue,
                    };
                    if uri.scope().env() != scope_env {
                        continue;
                    }
                    if uri.scope().tenant() != scope_tenant {
                        continue;
                    }
                    if let Some(ref team) = scope_team
                        && uri.scope().team() != Some(team.as_str())
                    {
                        continue;
                    }
                    if let Some(ref cat_prefix) = category_prefix
                        && !uri.category().starts_with(cat_prefix)
                    {
                        continue;
                    }
                    if let Some(ref name_prefix) = name_prefix
                        && !uri.name().starts_with(name_prefix)
                    {
                        continue;
                    }

                    if let Some(stored) =
                        fetch_secret_version_inner(client.clone(), name.clone(), None).await?
                    {
                        if stored.deleted {
                            continue;
                        }
                        if let Some(record) = stored.record {
                            let latest = Some(stored.version.to_string());
                            items.push(SecretListItem::from_meta(&record.meta, latest));
                        }
                    }
                }

                if let Some(next) = response.next_token() {
                    token = Some(next.to_string());
                } else {
                    break;
                }
            }

            Ok(items)
        })
    }
}

impl SecretsBackend for AwsSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        let secret_id = self.config.secret_name(&record.meta.uri);

        let versions = self.load_all_versions(&record.meta.uri)?;
        let next_version = versions
            .iter()
            .map(|stored| stored.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let stored = StoredSecret::live(next_version, record.clone());
        let payload = serde_json::to_string(&stored)
            .map_err(|err| SecretsError::Storage(format!("serialize secret payload: {err}")))?;

        if versions.is_empty() {
            let created = self.ensure_secret_created(&secret_id, &payload, Some(&record))?;
            if !created {
                self.write_new_version(&secret_id, &payload)?;
            }
        } else {
            self.write_new_version(&secret_id, &payload)?;
        }

        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> SecretsResult<Option<VersionedSecret>> {
        let secret_id = self.config.secret_name(uri);

        if let Some(version) = version {
            let versions = self.load_all_versions(uri)?;
            return Ok(versions
                .into_iter()
                .find(|stored| stored.version == version)
                .map(|stored| stored.into_versioned()));
        }

        match self.fetch_latest_version(&secret_id)? {
            Some(stored) if !stored.deleted => Ok(Some(stored.into_versioned())),
            _ => Ok(None),
        }
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        self.list_scope(scope, category_prefix, name_prefix)
    }

    fn delete(&self, uri: &SecretUri) -> SecretsResult<SecretVersion> {
        let secret_id = self.config.secret_name(uri);
        let versions = self.load_all_versions(uri)?;
        if versions.is_empty() {
            return Err(SecretsError::NotFound {
                entity: uri.to_string(),
            });
        }

        let next_version = versions
            .iter()
            .map(|stored| stored.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let stored = StoredSecret::tombstone(next_version);
        let payload = serde_json::to_string(&stored)
            .map_err(|err| SecretsError::Storage(format!("serialize tombstone payload: {err}")))?;

        self.write_new_version(&secret_id, &payload)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        Ok(self
            .load_all_versions(uri)?
            .into_iter()
            .map(|stored| SecretVersion {
                version: stored.version,
                deleted: stored.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> SecretsResult<bool> {
        Ok(self.get(uri, None)?.is_some())
    }
}

#[derive(Clone)]
pub struct AwsKmsKeyProvider {
    client: KmsClient,
    key_id: String,
}

impl AwsKmsKeyProvider {
    fn new(client: KmsClient, config: AwsProviderConfig) -> Self {
        Self {
            client,
            key_id: config.kms_key_id,
        }
    }

    fn context(scope: &Scope) -> HashMap<String, String> {
        let mut ctx = HashMap::new();
        ctx.insert("env".into(), scope.env().to_string());
        ctx.insert("tenant".into(), scope.tenant().to_string());
        if let Some(team) = scope.team() {
            ctx.insert("team".into(), team.to_string());
        }
        ctx
    }
}

impl KeyProvider for AwsKmsKeyProvider {
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let context = Self::context(scope);
        let client = self.client.clone();
        let key_id = self.key_id.clone();
        let dek = dek.to_vec();
        rt::sync_await(async move {
            match client
                .encrypt()
                .key_id(&key_id)
                .set_encryption_context(Some(context))
                .plaintext(KmsBlob::new(dek))
                .send()
                .await
            {
                Ok(output) => output
                    .ciphertext_blob()
                    .map(|blob| blob.as_ref().to_vec())
                    .ok_or_else(|| {
                        SecretsError::Backend("kms encrypt returned no ciphertext".into())
                    }),
                Err(err) => Err(SecretsError::Backend(format!("kms encrypt: {err}"))),
            }
        })
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let context = Self::context(scope);
        let client = self.client.clone();
        let key_id = self.key_id.clone();
        let wrapped = wrapped.to_vec();
        rt::sync_await(async move {
            match client
                .decrypt()
                .key_id(&key_id)
                .set_encryption_context(Some(context))
                .ciphertext_blob(KmsBlob::new(wrapped))
                .send()
                .await
            {
                Ok(output) => output
                    .plaintext()
                    .map(|blob| blob.as_ref().to_vec())
                    .ok_or_else(|| {
                        SecretsError::Backend("kms decrypt returned no plaintext".into())
                    }),
                Err(err) => Err(SecretsError::Backend(format!("kms decrypt: {err}"))),
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSecret {
    version: u64,
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<SecretRecord>,
}

impl StoredSecret {
    fn live(version: u64, record: SecretRecord) -> Self {
        Self {
            version,
            deleted: false,
            record: Some(record),
        }
    }

    fn tombstone(version: u64) -> Self {
        Self {
            version,
            deleted: true,
            record: None,
        }
    }

    fn into_versioned(self) -> VersionedSecret {
        VersionedSecret {
            version: self.version,
            deleted: self.deleted,
            record: self.record,
        }
    }
}

fn parse_secret_name(prefix: &str, name: &str) -> Option<SecretUri> {
    parse_runtime_secret_name(prefix, name)
}

fn runtime_secret_name(namespace_prefix: &str, uri: &SecretUri) -> String {
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

fn parse_runtime_secret_name(namespace_prefix: &str, name: &str) -> Option<SecretUri> {
    let mut segments = name.split('/');
    if segments.next()? != namespace_prefix {
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

fn deserialize_secret_payload(
    secret_string: Option<&str>,
    secret_binary: Option<&aws_smithy_types::Blob>,
) -> SecretsResult<Option<StoredSecret>> {
    if let Some(value) = secret_string {
        if value.trim().is_empty() {
            return Ok(None);
        }
        return serde_json::from_str::<StoredSecret>(value)
            .map(Some)
            .map_err(|err| SecretsError::Storage(format!("decode secret payload: {err}")));
    }

    if let Some(blob) = secret_binary {
        let bytes = blob.as_ref();
        if bytes.is_empty() {
            return Ok(None);
        }
        return serde_json::from_slice::<StoredSecret>(bytes)
            .map(Some)
            .map_err(|err| SecretsError::Storage(format!("decode secret payload: {err}")));
    }

    Ok(None)
}

fn is_not_found<T>(err: &SdkError<T>) -> bool
where
    T: aws_smithy_types::error::metadata::ProvideErrorMetadata + Send + Sync + std::fmt::Debug,
{
    if let SdkError::ServiceError(context) = err {
        return context.err().code() == Some("ResourceNotFoundException");
    }
    false
}

fn storage_error<T>(operation: &str, err: SdkError<T>) -> SecretsError
where
    T: std::fmt::Display,
{
    SecretsError::Storage(format!("{operation} failed: {err}"))
}

fn list_versions_unsupported(err: &SdkError<ListSecretVersionIdsError>) -> bool {
    match err {
        SdkError::DispatchFailure(_) => true,
        SdkError::ServiceError(ctx) => matches!(
            ctx.err().code(),
            Some("NotImplementedException") | Some("UnknownOperationException")
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_native_certs::load_native_certs;
    use serial_test::serial;
    use std::env;

    fn set_env(key: &str, value: &str) {
        unsafe { env::set_var(key, value) };
    }

    fn clear_env(key: &str) {
        unsafe { env::remove_var(key) };
    }

    fn setup_env() {
        set_env(
            "GREENTIC_AWS_KMS_KEY_ID",
            "arn:aws:kms:us-east-1:000000000000:key/test",
        );
        set_env("GREENTIC_AWS_SECRET_PREFIX", "unit");
        set_env("GREENTIC_AWS_VERSION_STAGE", "AWSCURRENT");
        set_env("GREENTIC_AWS_REGION", "us-east-1");
        set_env("AWS_ALLOW_HTTP", "1");
        set_env("AWS_ACCESS_KEY_ID", "test");
        set_env("AWS_SECRET_ACCESS_KEY", "test");
        set_env("AWS_SESSION_TOKEN", "test");
        set_env(SM_ENDPOINT_ENV, "http://127.0.0.1:9");
        set_env(KMS_ENDPOINT_ENV, "http://127.0.0.1:9");
        clear_env("AWS_PROFILE");
    }

    fn native_roots_available() -> bool {
        let certs = load_native_certs();
        if certs.certs.is_empty() {
            eprintln!("native root certs unavailable: {:?}", certs.errors);
            return false;
        }
        true
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn aws_provider_ok_under_tokio() {
        if !native_roots_available() {
            eprintln!("skipping aws_provider_ok_under_tokio: no native root certs");
            return;
        }

        setup_env();
        let BackendComponents { backend, .. } = build_backend()
            .await
            .expect("aws backend builds with env config");

        let scope = Scope::new("dev", "tenant", None).expect("scope");
        let result = backend.list(&scope, None, None);
        assert!(
            result.is_err(),
            "list should attempt network and bubble up errors without panicking"
        );
    }

    #[test]
    fn runtime_secret_name_matches_spec_contract() {
        let uri = SecretUri::parse("secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key")
            .expect("valid uri");
        let name = runtime_secret_name("greentic", &uri);

        assert_eq!(
            name,
            greentic_secrets_spec::aws_secret_name("greentic", &uri)
        );
        assert_eq!(
            parse_secret_name("greentic", &name),
            greentic_secrets_spec::parse_aws_secret_name("greentic", &name)
        );
    }
}
