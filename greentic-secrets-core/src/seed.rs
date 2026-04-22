use crate::SecretsBackend;
use crate::broker::SecretsBroker;
use crate::crypto::envelope::EnvelopeService;
use crate::errors::{Error, Result};
use crate::key_provider::KeyProvider;
use crate::spec_compat::{ContentType, SecretMeta, Visibility};
use crate::uri::SecretUri;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use greentic_secrets_spec::{SeedDoc, SeedEntry, SeedValue};
use greentic_types::secrets::{SecretFormat, SecretRequirement, SecretScope};
#[cfg(feature = "schema-validate")]
use jsonschema::validator_for;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Minimal dev context used for resolving requirement keys into URIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevContext {
    pub env: String,
    pub tenant: String,
    pub team: Option<String>,
}

impl DevContext {
    pub fn new(env: impl Into<String>, tenant: impl Into<String>, team: Option<String>) -> Self {
        Self {
            env: env.into(),
            tenant: tenant.into(),
            team,
        }
    }
}

/// Resolve a requirement into a concrete URI for dev flows.
pub fn resolve_uri(ctx: &DevContext, req: &SecretRequirement) -> String {
    resolve_uri_with_category(ctx, req, "configs")
}

pub fn resolve_uri_with_category(
    ctx: &DevContext,
    req: &SecretRequirement,
    default_category: &str,
) -> String {
    let team = ctx.team.as_deref().unwrap_or("_");
    let key = normalize_req_key(req.key.as_str(), default_category);
    format!("secrets://{}/{}/{}/{}", ctx.env, ctx.tenant, team, key)
}

/// Normalized seed entry with bytes payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedSeedEntry {
    pub uri: String,
    pub format: SecretFormat,
    pub bytes: Vec<u8>,
    pub description: Option<String>,
}

/// Errors encountered while applying a seed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyFailure {
    pub uri: String,
    pub error: String,
}

/// Summary report from seed application.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplyReport {
    pub ok: usize,
    pub failed: Vec<ApplyFailure>,
}

/// Options for applying seeds.
#[derive(Default)]
pub struct ApplyOptions<'a> {
    pub requirements: Option<&'a [SecretRequirement]>,
    pub validate_schema: bool,
}

#[async_trait]
pub trait SecretsStore: Send + Sync {
    async fn put(&self, uri: &str, format: SecretFormat, bytes: &[u8]) -> Result<()>;
    async fn get(&self, uri: &str) -> Result<Vec<u8>>;
}

/// Apply all entries in a seed document to the provided store.
pub async fn apply_seed<S: SecretsStore + ?Sized>(
    store: &S,
    seed: &SeedDoc,
    options: ApplyOptions<'_>,
) -> ApplyReport {
    let mut ok = 0usize;
    let mut failed = Vec::new();
    let requirement_lookup = options.requirements.map(RequirementLookup::new);

    for entry in &seed.entries {
        if let Err(err) = validate_entry(entry, &options, requirement_lookup.as_ref()) {
            failed.push(ApplyFailure {
                uri: entry.uri.clone(),
                error: err.to_string(),
            });
            continue;
        }

        match normalize_seed_entry(entry) {
            Ok(normalized) => {
                if let Err(err) = store
                    .put(&normalized.uri, normalized.format, &normalized.bytes)
                    .await
                {
                    failed.push(ApplyFailure {
                        uri: normalized.uri,
                        error: err.to_string(),
                    });
                } else {
                    ok += 1;
                }
            }
            Err(err) => failed.push(ApplyFailure {
                uri: entry.uri.clone(),
                error: err.to_string(),
            }),
        }
    }

    ApplyReport { ok, failed }
}

fn normalize_seed_entry(entry: &SeedEntry) -> Result<NormalizedSeedEntry> {
    let bytes = match (&entry.format, &entry.value) {
        (SecretFormat::Text, SeedValue::Text { text }) => Ok(text.as_bytes().to_vec()),
        (SecretFormat::Json, SeedValue::Json { json }) => {
            serde_json::to_vec(json).map_err(|err| Error::Invalid("json".into(), err.to_string()))
        }
        (SecretFormat::Bytes, SeedValue::BytesB64 { bytes_b64 }) => STANDARD
            .decode(bytes_b64.as_bytes())
            .map_err(|err| Error::Invalid("bytes_b64".into(), err.to_string())),
        _ => Err(Error::Invalid(
            "seed".into(),
            "format/value mismatch".into(),
        )),
    }?;

    Ok(NormalizedSeedEntry {
        uri: entry.uri.clone(),
        format: entry.format.clone(),
        bytes,
        description: entry.description.clone(),
    })
}

fn validate_entry(
    entry: &SeedEntry,
    options: &ApplyOptions<'_>,
    requirement_lookup: Option<&RequirementLookup<'_>>,
) -> Result<()> {
    let uri = SecretUri::parse(&entry.uri)?;

    if let Some(reqs) = options.requirements {
        #[cfg(feature = "schema-validate")]
        if options.validate_schema
            && let Some(req) = find_requirement(&uri, reqs, requirement_lookup)
            && let (SecretFormat::Json, Some(schema), SeedValue::Json { json }) =
                (&entry.format, &req.schema, &entry.value)
        {
            validate_json_schema(json, schema)?;
        }
        #[cfg(not(feature = "schema-validate"))]
        let _ = find_requirement(&uri, reqs, requirement_lookup);
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct IndexedRequirement<'a> {
    position: usize,
    requirement: &'a SecretRequirement,
}

struct RequirementLookup<'a> {
    explicit: HashMap<String, Vec<IndexedRequirement<'a>>>,
    implicit: HashMap<String, Vec<IndexedRequirement<'a>>>,
}

impl<'a> RequirementLookup<'a> {
    fn new(requirements: &'a [SecretRequirement]) -> Self {
        let mut explicit = HashMap::new();
        let mut implicit = HashMap::new();

        for (position, requirement) in requirements.iter().enumerate() {
            let entry = IndexedRequirement {
                position,
                requirement,
            };
            let key = requirement.key.as_str().to_ascii_lowercase();
            if key.contains('/') {
                explicit.entry(key).or_insert_with(Vec::new).push(entry);
            } else {
                implicit.entry(key).or_insert_with(Vec::new).push(entry);
            }
        }

        Self { explicit, implicit }
    }

    fn find(&self, uri: &SecretUri) -> Option<&'a SecretRequirement> {
        let explicit = self
            .explicit
            .get(&format!("{}/{}", uri.category(), uri.name()))
            .into_iter()
            .flatten();
        let implicit = self.implicit.get(uri.name()).into_iter().flatten();

        explicit
            .chain(implicit)
            .filter(|entry| scopes_match(uri.scope(), entry.requirement.scope.as_ref()))
            .min_by_key(|entry| entry.position)
            .map(|entry| entry.requirement)
    }
}

fn find_requirement<'a>(
    uri: &SecretUri,
    requirements: &'a [SecretRequirement],
    requirement_lookup: Option<&RequirementLookup<'a>>,
) -> Option<&'a SecretRequirement> {
    if let Some(lookup) = requirement_lookup {
        return lookup.find(uri);
    }

    let key = format!("{}/{}", uri.category(), uri.name());
    requirements.iter().find(|req| {
        normalize_req_key(req.key.as_str(), uri.category()) == key
            && scopes_match(uri.scope(), req.scope.as_ref())
    })
}

fn normalize_req_key(key: &str, default_category: &str) -> String {
    let normalized = key.to_ascii_lowercase();
    if normalized.contains('/') {
        normalized
    } else {
        format!("{default_category}/{normalized}")
    }
}

fn scopes_match(uri_scope: &greentic_secrets_spec::Scope, req_scope: Option<&SecretScope>) -> bool {
    let Some(req_scope) = req_scope else {
        return true;
    };
    uri_scope.env() == req_scope.env
        && uri_scope.tenant() == req_scope.tenant
        && uri_scope.team() == req_scope.team.as_deref()
}

#[cfg(feature = "schema-validate")]
fn validate_json_schema(value: &serde_json::Value, schema: &serde_json::Value) -> Result<()> {
    let compiled =
        validator_for(schema).map_err(|err| Error::Invalid("schema".into(), err.to_string()))?;

    let messages: Vec<String> = compiled
        .iter_errors(value)
        .map(|err| err.to_string())
        .collect();
    if !messages.is_empty() {
        return Err(Error::Invalid("json".into(), messages.join("; ")));
    }
    Ok(())
}

fn format_to_content_type(format: SecretFormat) -> ContentType {
    match format {
        SecretFormat::Text => ContentType::Text,
        SecretFormat::Json => ContentType::Json,
        SecretFormat::Bytes => ContentType::Binary,
    }
}

/// Adapter that applies seeds against a broker-backed store.
pub struct BrokerStore<B, P>
where
    B: SecretsBackend,
    P: KeyProvider,
{
    broker: Arc<Mutex<SecretsBroker<B, P>>>,
}

impl<B, P> BrokerStore<B, P>
where
    B: SecretsBackend,
    P: KeyProvider,
{
    pub fn new(broker: SecretsBroker<B, P>) -> Self {
        Self {
            broker: Arc::new(Mutex::new(broker)),
        }
    }
}

#[async_trait]
impl<B, P> SecretsStore for BrokerStore<B, P>
where
    B: SecretsBackend + Send + Sync + 'static,
    P: KeyProvider + Send + Sync + 'static,
{
    async fn put(&self, uri: &str, format: SecretFormat, bytes: &[u8]) -> Result<()> {
        let uri = SecretUri::parse(uri)?;
        let mut broker = self.broker.lock().unwrap();
        let mut meta = SecretMeta::new(
            uri.clone(),
            Visibility::Team,
            format_to_content_type(format),
        );
        meta.description = None;
        broker.put_secret(meta, bytes)?;
        Ok(())
    }

    async fn get(&self, uri: &str) -> Result<Vec<u8>> {
        let uri = SecretUri::parse(uri)?;
        let mut broker = self.broker.lock().unwrap();
        let secret = broker
            .get_secret(&uri)
            .map_err(|err| Error::Backend(err.to_string()))?
            .ok_or_else(|| Error::NotFound {
                entity: uri.to_string(),
            })?;
        Ok(secret.payload)
    }
}

/// HTTP store adapter for talking to the broker service.
pub struct HttpStore {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl HttpStore {
    pub fn new(base_url: impl Into<String>, token: Option<String>) -> Self {
        Self::with_client(Client::new(), base_url, token)
    }

    pub fn with_client(client: Client, base_url: impl Into<String>, token: Option<String>) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token,
        }
    }
}

#[derive(serde::Serialize)]
struct PutBody {
    visibility: Visibility,
    content_type: ContentType,
    #[serde(default)]
    encoding: ValueEncoding,
    #[serde(default)]
    description: Option<String>,
    value: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
enum ValueEncoding {
    Utf8,
    Base64,
}

#[derive(serde::Deserialize)]
struct GetResponse {
    encoding: ValueEncoding,
    value: String,
}

#[async_trait]
impl SecretsStore for HttpStore {
    async fn put(&self, uri: &str, format: SecretFormat, bytes: &[u8]) -> Result<()> {
        let uri = SecretUri::parse(uri)?;
        let path = match uri.scope().team() {
            Some(team) => format!(
                "{}/v1/{}/{}/{}/{}/{}",
                self.base_url,
                uri.scope().env(),
                uri.scope().tenant(),
                team,
                uri.category(),
                uri.name()
            ),
            None => format!(
                "{}/v1/{}/{}/{}/{}",
                self.base_url,
                uri.scope().env(),
                uri.scope().tenant(),
                uri.category(),
                uri.name()
            ),
        };

        let encoding = match format {
            SecretFormat::Text | SecretFormat::Json => ValueEncoding::Utf8,
            SecretFormat::Bytes => ValueEncoding::Base64,
        };
        let payload = PutBody {
            visibility: Visibility::Team,
            content_type: format_to_content_type(format),
            encoding: encoding.clone(),
            description: None,
            value: match encoding {
                ValueEncoding::Utf8 => String::from_utf8(bytes.to_vec())
                    .map_err(|err| Error::Invalid("utf8".into(), err.to_string()))?,
                ValueEncoding::Base64 => STANDARD.encode(bytes),
            },
        };

        let mut req = self.client.put(path).json(&payload);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|err| Error::Backend(err.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Backend(format!("broker returned {}", resp.status())));
        }
        Ok(())
    }

    async fn get(&self, uri: &str) -> Result<Vec<u8>> {
        let uri = SecretUri::parse(uri)?;
        let path = match uri.scope().team() {
            Some(team) => format!(
                "{}/v1/{}/{}/{}/{}/{}",
                self.base_url,
                uri.scope().env(),
                uri.scope().tenant(),
                team,
                uri.category(),
                uri.name()
            ),
            None => format!(
                "{}/v1/{}/{}/{}/{}",
                self.base_url,
                uri.scope().env(),
                uri.scope().tenant(),
                uri.category(),
                uri.name()
            ),
        };

        let mut req = self.client.get(path);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|err| Error::Backend(err.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Backend(format!("broker returned {}", resp.status())));
        }
        let body: GetResponse = resp
            .json()
            .await
            .map_err(|err| Error::Backend(err.to_string()))?;
        let bytes = match body.encoding {
            ValueEncoding::Utf8 => Ok(body.value.into_bytes()),
            ValueEncoding::Base64 => STANDARD
                .decode(body.value.as_bytes())
                .map_err(|err| Error::Invalid("base64".into(), err.to_string())),
        }?;
        Ok(bytes)
    }
}

/// Convenience dev store backed by the dev provider.
#[cfg(feature = "dev-store")]
pub struct DevStore {
    inner: BrokerStore<Box<dyn SecretsBackend>, Box<dyn KeyProvider>>,
}

#[cfg(feature = "dev-store")]
impl DevStore {
    /// Open the default dev store using the dev provider's environment/path resolution.
    pub fn open_default() -> Result<Self> {
        use greentic_secrets_provider_dev::{DevBackend, DevKeyProvider};

        let backend = DevBackend::from_env().map_err(|err| Error::Backend(err.to_string()))?;
        let key_provider: Box<dyn KeyProvider> = Box::new(DevKeyProvider::from_env());
        let crypto = EnvelopeService::from_env(key_provider)?;
        let broker = SecretsBroker::new(Box::new(backend) as Box<dyn SecretsBackend>, crypto);
        Ok(Self {
            inner: BrokerStore::new(broker),
        })
    }

    /// Open a dev store with a specific persistence path.
    pub fn with_path(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        use greentic_secrets_provider_dev::{DevBackend, DevKeyProvider};

        let backend = DevBackend::with_persistence(path.into())
            .map_err(|err| Error::Backend(err.to_string()))?;
        let key_provider: Box<dyn KeyProvider> = Box::new(DevKeyProvider::from_env());
        let crypto = EnvelopeService::from_env(key_provider)?;
        let broker = SecretsBroker::new(Box::new(backend) as Box<dyn SecretsBackend>, crypto);
        Ok(Self {
            inner: BrokerStore::new(broker),
        })
    }
}

#[cfg(feature = "dev-store")]
#[async_trait]
impl SecretsStore for DevStore {
    async fn put(&self, uri: &str, format: SecretFormat, bytes: &[u8]) -> Result<()> {
        self.inner.put(uri, format, bytes).await
    }

    async fn get(&self, uri: &str) -> Result<Vec<u8>> {
        self.inner.get(uri).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::SeedValue;
    use reqwest::Client;
    use tempfile::tempdir;

    #[test]
    fn resolve_uri_formats_placeholder() {
        let ctx = DevContext::new("dev", "acme", None);
        let mut req = SecretRequirement::default();
        req.key = greentic_types::secrets::SecretKey::parse("configs/db").unwrap();
        req.required = true;
        req.scope = Some(SecretScope {
            env: "dev".into(),
            tenant: "acme".into(),
            team: None,
        });
        req.format = Some(SecretFormat::Text);
        let uri = resolve_uri(&ctx, &req);
        assert_eq!(uri, "secrets://dev/acme/_/configs/db");
    }

    #[test]
    fn resolve_uri_respects_custom_category() {
        let ctx = DevContext::new("dev", "acme", None);
        let mut req = SecretRequirement::default();
        req.key = greentic_types::secrets::SecretKey::parse("db").unwrap();
        let uri = resolve_uri_with_category(&ctx, &req, "greentic.secrets.fixture");
        assert_eq!(uri, "secrets://dev/acme/_/greentic.secrets.fixture/db");
    }

    #[tokio::test]
    #[cfg(feature = "dev-store")]
    async fn apply_seed_roundtrip_dev_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".dev.secrets.env");
        let store = DevStore::with_path(path).unwrap();

        let seed = SeedDoc {
            entries: vec![SeedEntry {
                uri: "secrets://dev/acme/_/configs/db".into(),
                format: SecretFormat::Text,
                description: Some("db".into()),
                value: SeedValue::Text {
                    text: "secret".into(),
                },
            }],
        };

        let report = apply_seed(&store, &seed, ApplyOptions::default()).await;
        assert_eq!(report.ok, 1);
        assert!(report.failed.is_empty());

        let fetched = store.get("secrets://dev/acme/_/configs/db").await.unwrap();
        assert_eq!(fetched, b"secret".to_vec());
    }

    #[test]
    fn normalize_seed_entry_supports_json_and_rejects_mismatches() {
        let json_entry = SeedEntry {
            uri: "secrets://dev/acme/_/configs/app".into(),
            format: SecretFormat::Json,
            description: Some("json".into()),
            value: SeedValue::Json {
                json: serde_json::json!({"enabled": true}),
            },
        };
        let normalized = normalize_seed_entry(&json_entry).expect("normalized");
        assert_eq!(normalized.bytes, br#"{"enabled":true}"#);

        let bad_entry = SeedEntry {
            uri: "secrets://dev/acme/_/configs/app".into(),
            format: SecretFormat::Bytes,
            description: None,
            value: SeedValue::Text {
                text: "wrong".into(),
            },
        };
        assert!(normalize_seed_entry(&bad_entry).is_err());
    }

    #[test]
    fn find_requirement_matches_normalized_key_and_scope() {
        let uri = SecretUri::parse("secrets://dev/acme/core/configs/db").expect("uri");
        let mut req = SecretRequirement::default();
        req.key = "DB".into();
        req.scope = Some(SecretScope {
            env: "dev".into(),
            tenant: "acme".into(),
            team: Some("core".into()),
        });
        let requirements = [req];

        let found = find_requirement(&uri, &requirements, None).expect("requirement");
        assert_eq!(found.key.as_str(), "DB");
    }

    #[test]
    fn scopes_match_requires_team_when_present() {
        let uri = SecretUri::parse("secrets://dev/acme/core/configs/db").expect("uri");
        let matching = SecretScope {
            env: "dev".into(),
            tenant: "acme".into(),
            team: Some("core".into()),
        };
        let mismatched = SecretScope {
            env: "dev".into(),
            tenant: "acme".into(),
            team: Some("other".into()),
        };

        assert!(scopes_match(uri.scope(), Some(&matching)));
        assert!(!scopes_match(uri.scope(), Some(&mismatched)));
        assert!(scopes_match(uri.scope(), None));
    }

    #[test]
    fn http_store_trims_trailing_slashes() {
        let store = HttpStore::with_client(
            Client::new(),
            "https://broker.example.test/",
            Some("token".into()),
        );
        assert_eq!(store.base_url, "https://broker.example.test");
        assert_eq!(store.token.as_deref(), Some("token"));
    }
}
