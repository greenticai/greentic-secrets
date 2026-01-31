use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use greentic_secrets_core::SecretUri;
use greentic_secrets_core::{
    backend::SecretsBackend,
    broker::SecretsBroker,
    crypto::envelope::EnvelopeService,
    key_provider::KeyProvider,
    types::{ContentType, Scope, SecretListItem, SecretMeta, Visibility},
};
use greentic_types::secrets::SecretFormat;
use reqwest::{Client, Url};
use secrets_broker::models::{
    DeleteResponse, ListItem, ListSecretsResponse, PutSecretRequest, SecretResponse, ValueEncoding,
};
use secrets_broker::path::split_prefix;
use secrets_provider_dev::{DevBackend, DevKeyProvider};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::runtime::Runtime;

/// Tenant/team scope used when administering secrets.
#[derive(Clone)]
pub struct AdminScope {
    pub env: String,
    pub tenant: String,
    pub team: Option<String>,
}

/// Request payload for writing or updating a secret.
pub struct AdminSetRequest {
    pub scope: AdminScope,
    pub category: String,
    pub name: String,
    pub format: SecretFormat,
    pub visibility: Visibility,
    pub description: Option<String>,
    pub value: Vec<u8>,
}

/// Result returned after a successful set operation.
pub struct AdminSetResult {
    pub uri: String,
    pub version: u64,
}

/// Request payload for deleting a secret.
pub struct AdminDeleteRequest {
    pub scope: AdminScope,
    pub category: String,
    pub name: String,
}

/// Result returned after a delete operation.
pub struct AdminDeleteResult {
    pub uri: String,
    pub version: u64,
}

/// Compact view of a secret returned by the list command.
#[derive(Debug, Clone, Serialize)]
pub struct AdminListItem {
    pub uri: String,
    pub visibility: Visibility,
    pub content_type: ContentType,
    pub latest_version: Option<String>,
}

impl From<SecretListItem> for AdminListItem {
    fn from(item: SecretListItem) -> Self {
        Self {
            uri: item.uri.to_string(),
            visibility: item.visibility,
            content_type: item.content_type,
            latest_version: item.latest_version,
        }
    }
}

impl From<ListItem> for AdminListItem {
    fn from(item: ListItem) -> Self {
        Self {
            uri: item.uri,
            visibility: item.visibility,
            content_type: item.content_type,
            latest_version: item.latest_version,
        }
    }
}

/// Interface implemented by each provider-specific admin helper.
pub trait AdminClient {
    fn login(&mut self) -> Result<()>;
    fn list(&mut self, scope: &AdminScope, prefix: Option<&str>) -> Result<Vec<AdminListItem>>;
    fn set(&mut self, request: AdminSetRequest) -> Result<AdminSetResult>;
    fn delete(&mut self, request: AdminDeleteRequest) -> Result<AdminDeleteResult>;
}

/// Build a client tailored to the configured backend.
pub fn build_client(
    kind: &str,
    dev_store_path: PathBuf,
    broker_url: Option<String>,
    token: Option<String>,
) -> Result<Box<dyn AdminClient>> {
    match kind {
        "dev" | "none" => Ok(Box::new(DevAdminClient::new(dev_store_path)?)),
        _ => {
            let base = broker_url.ok_or_else(|| {
                anyhow!(
                    "secrets.kind={} requires --broker-url or secrets.endpoint",
                    kind
                )
            })?;
            Ok(Box::new(HttpAdminClient::new(base, token)?))
        }
    }
}

struct DevAdminClient {
    broker: Mutex<SecretsBroker<Box<dyn SecretsBackend>, Box<dyn KeyProvider>>>,
}

impl DevAdminClient {
    fn new(path: PathBuf) -> Result<Self> {
        let backend = DevBackend::with_persistence(path)
            .map_err(|err| anyhow!("failed to open dev backend: {err}"))?;
        let key_provider: Box<dyn KeyProvider> = Box::new(DevKeyProvider::from_env());
        let crypto = EnvelopeService::from_env(key_provider)?;
        let broker = SecretsBroker::new(Box::new(backend) as Box<dyn SecretsBackend>, crypto);
        Ok(Self {
            broker: Mutex::new(broker),
        })
    }

    fn scope_from_admin(scope: &AdminScope) -> Result<Scope> {
        Scope::new(scope.env.clone(), scope.tenant.clone(), scope.team.clone())
            .map_err(|err| anyhow!(err.to_string()))
    }

    fn uri_from_admin(scope: &AdminScope, category: &str, name: &str) -> Result<SecretUri> {
        let scope = Self::scope_from_admin(scope)?;
        SecretUri::new(scope, category.to_string(), name.to_string())
            .map_err(|err| anyhow!(err.to_string()))
    }
}

impl AdminClient for DevAdminClient {
    fn login(&mut self) -> Result<()> {
        Ok(())
    }

    fn list(&mut self, scope: &AdminScope, prefix: Option<&str>) -> Result<Vec<AdminListItem>> {
        let scope = Self::scope_from_admin(scope)?;
        let (category_prefix, name_prefix) = split_prefix(prefix);
        let broker = self.broker.lock().unwrap();
        let items = broker
            .list_secrets(&scope, category_prefix, name_prefix)
            .map_err(|err| anyhow!(err.to_string()))?
            .into_iter()
            .map(AdminListItem::from)
            .collect();
        Ok(items)
    }

    fn set(&mut self, request: AdminSetRequest) -> Result<AdminSetResult> {
        let uri = Self::uri_from_admin(&request.scope, &request.category, &request.name)?;
        let mut meta = SecretMeta::new(
            uri.clone(),
            request.visibility,
            format_to_content_type(request.format),
        );
        meta.description = request.description.clone();
        let mut broker = self.broker.lock().unwrap();
        let version = broker
            .put_secret(meta.clone(), &request.value)
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(AdminSetResult {
            uri: uri.to_string(),
            version: version.version,
        })
    }

    fn delete(&mut self, request: AdminDeleteRequest) -> Result<AdminDeleteResult> {
        let uri = Self::uri_from_admin(&request.scope, &request.category, &request.name)?;
        let broker = self.broker.lock().unwrap();
        let version = broker
            .delete_secret(&uri)
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(AdminDeleteResult {
            uri: uri.to_string(),
            version: version.version,
        })
    }
}

struct HttpAdminClient {
    client: Client,
    base_url: String,
    token: Option<String>,
    runtime: Runtime,
}

impl HttpAdminClient {
    fn new(base_url: String, token: Option<String>) -> Result<Self> {
        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        Ok(Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            runtime,
        })
    }

    fn list_url(&self, scope: &AdminScope) -> Result<Url> {
        let path = if let Some(team) = scope.team.as_deref() {
            format!(
                "{}/v1/{}/{}/{}/_list",
                self.base_url, scope.env, scope.tenant, team
            )
        } else {
            format!("{}/v1/{}/{}/_list", self.base_url, scope.env, scope.tenant)
        };
        Url::parse(&path).context("invalid broker URL")
    }

    fn secret_url(&self, scope: &AdminScope, category: &str, name: &str) -> Result<Url> {
        let path = if let Some(team) = scope.team.as_deref() {
            format!(
                "{}/v1/{}/{}/{}/{}/{}",
                self.base_url, scope.env, scope.tenant, team, category, name
            )
        } else {
            format!(
                "{}/v1/{}/{}/{}/{}",
                self.base_url, scope.env, scope.tenant, category, name
            )
        };
        Url::parse(&path).context("invalid broker URL")
    }

    fn uri_string(scope: &AdminScope, category: &str, name: &str) -> Result<String> {
        let scope = Scope::new(scope.env.clone(), scope.tenant.clone(), scope.team.clone())
            .map_err(|err| anyhow!(err.to_string()))?;
        let uri = SecretUri::new(scope, category.to_string(), name.to_string())
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(uri.to_string())
    }
}

impl AdminClient for HttpAdminClient {
    fn login(&mut self) -> Result<()> {
        Ok(())
    }

    fn list(&mut self, scope: &AdminScope, prefix: Option<&str>) -> Result<Vec<AdminListItem>> {
        let mut url = self.list_url(scope)?;
        if let Some(filter) = prefix {
            url.query_pairs_mut().append_pair("prefix", filter);
        }
        let response = self.runtime.block_on(async {
            let mut req = self.client.get(url);
            if let Some(token) = &self.token {
                req = req.bearer_auth(token);
            }
            let resp = req.send().await.map_err(|err| anyhow!(err.to_string()))?;
            if !resp.status().is_success() {
                return Err(anyhow!("broker returned {}", resp.status()));
            }
            resp.json::<ListSecretsResponse>()
                .await
                .map_err(|err| anyhow!(err.to_string()))
        })?;
        Ok(response
            .items
            .into_iter()
            .map(AdminListItem::from)
            .collect())
    }

    fn set(&mut self, request: AdminSetRequest) -> Result<AdminSetResult> {
        let url = self.secret_url(&request.scope, &request.category, &request.name)?;
        let (value, encoding) = match request.format {
            SecretFormat::Bytes => (
                STANDARD_NO_PAD.encode(&request.value),
                ValueEncoding::Base64,
            ),
            _ => (
                String::from_utf8(request.value.clone())
                    .map_err(|err| anyhow!("value is not valid UTF-8: {err}"))?,
                ValueEncoding::Utf8,
            ),
        };
        let body = PutSecretRequest {
            visibility: request.visibility,
            content_type: format_to_content_type(request.format),
            encoding,
            description: request.description.clone(),
            value,
        };
        let response = self.runtime.block_on(async {
            let mut req = self.client.put(url);
            if let Some(token) = &self.token {
                req = req.bearer_auth(token);
            }
            let resp = req
                .json(&body)
                .send()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            if !resp.status().is_success() {
                return Err(anyhow!("broker returned {}", resp.status()));
            }
            resp.json::<SecretResponse>()
                .await
                .map_err(|err| anyhow!(err.to_string()))
        })?;
        Ok(AdminSetResult {
            uri: response.uri,
            version: response.version,
        })
    }

    fn delete(&mut self, request: AdminDeleteRequest) -> Result<AdminDeleteResult> {
        let url = self.secret_url(&request.scope, &request.category, &request.name)?;
        let uri = Self::uri_string(&request.scope, &request.category, &request.name)?;
        let response = self.runtime.block_on(async {
            let mut req = self.client.delete(url);
            if let Some(token) = &self.token {
                req = req.bearer_auth(token);
            }
            let resp = req.send().await.map_err(|err| anyhow!(err.to_string()))?;
            if !resp.status().is_success() {
                return Err(anyhow!("broker returned {}", resp.status()));
            }
            resp.json::<DeleteResponse>()
                .await
                .map_err(|err| anyhow!(err.to_string()))
        })?;
        Ok(AdminDeleteResult {
            uri,
            version: response.version,
        })
    }
}

fn format_to_content_type(format: SecretFormat) -> ContentType {
    match format {
        SecretFormat::Text => ContentType::Text,
        SecretFormat::Json => ContentType::Json,
        SecretFormat::Bytes => ContentType::Binary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn dev_admin_set_list_delete() -> Result<()> {
        let temp = tempdir()?;
        let mut client = DevAdminClient::new(temp.path().join("dev-store"))?;
        let scope = AdminScope {
            env: "dev".into(),
            tenant: "acme".into(),
            team: Some("team-1".into()),
        };

        let request = AdminSetRequest {
            scope: scope.clone(),
            category: "configs".into(),
            name: "db_url".into(),
            format: SecretFormat::Text,
            visibility: Visibility::Tenant,
            description: Some("test secret".into()),
            value: b"postgres://localhost".to_vec(),
        };
        let result = client.set(request)?;
        assert!(result.version > 0);

        let items = client.list(&scope, Some("configs"))?;
        assert_eq!(items.len(), 1);
        assert!(items[0].uri.contains("configs/db_url"));

        client.delete(AdminDeleteRequest {
            scope: scope.clone(),
            category: "configs".into(),
            name: "db_url".into(),
        })?;
        let items = client.list(&scope, Some("configs"))?;
        assert!(items.is_empty());
        Ok(())
    }
}
