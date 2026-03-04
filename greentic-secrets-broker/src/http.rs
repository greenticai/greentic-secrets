use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::{Extension, Json, Router, routing::get, routing::post};
use serde::Deserialize;
use tracing::Instrument;

use crate::auth::{self, Action, AuthContext};
use crate::error::{AppError, AppErrorKind, attach_correlation};
use crate::models::{
    DeleteResponse, ListItem, ListSecretsResponse, PutSecretRequest, RotateRequest, SecretResponse,
    VersionInfo, VersionsResponse,
};
use crate::path::{build_scope, build_uri, split_name_version, split_prefix};
use crate::rotate;
use crate::state::AppState;
use crate::telemetry::{CorrelationId, correlation_layer, request_span, set_tenant_context};
use secrets_core::types::SecretMeta;

#[derive(Deserialize)]
struct ListQuery {
    prefix: Option<String>,
}

pub fn router(state: AppState) -> Router {
    let api = api_routes().layer(middleware::from_fn_with_state(
        state.clone(),
        auth::http_layer,
    ));

    Router::new()
        .route("/healthz", get(health_check))
        .merge(api)
        .layer(middleware::from_fn(correlation_layer))
        .with_state(state)
}

fn api_routes() -> Router<AppState> {
    Router::new()
        // Canonical API surface
        .route(
            "/v1/{env}/{tenant}/{category}/{name}",
            axum::routing::put(put_secret_no_team)
                .delete(delete_secret_no_team)
                .get(get_secret_no_team),
        )
        .route(
            "/v1/{env}/{tenant}/{category}/{name}/_versions",
            get(list_versions_no_team),
        )
        .route("/v1/{env}/{tenant}/_list", get(list_secrets_no_team))
        .route(
            "/v1/{env}/{tenant}/{team}/{category}/{name}",
            axum::routing::put(put_secret_with_team)
                .delete(delete_secret_with_team)
                .get(get_secret_with_team),
        )
        .route(
            "/v1/{env}/{tenant}/{team}/{category}/{name}/_versions",
            get(list_versions_with_team),
        )
        .route(
            "/v1/{env}/{tenant}/{team}/_list",
            get(list_secrets_with_team),
        )
        .route(
            "/v1/{env}/{tenant}/_rotate/{category}",
            post(rotate_no_team),
        )
        .route(
            "/v1/{env}/{tenant}/{team}/_rotate/{category}",
            post(rotate_with_team),
        )
        // Admin API aliases (backward-compatible; same handlers/auth/payloads).
        .route(
            "/admin/v1/{env}/{tenant}/{category}/{name}",
            axum::routing::put(put_secret_no_team)
                .delete(delete_secret_no_team)
                .get(get_secret_no_team),
        )
        .route(
            "/admin/v1/{env}/{tenant}/{category}/{name}/_versions",
            get(list_versions_no_team),
        )
        .route("/admin/v1/{env}/{tenant}/_list", get(list_secrets_no_team))
        .route(
            "/admin/v1/{env}/{tenant}/{team}/{category}/{name}",
            axum::routing::put(put_secret_with_team)
                .delete(delete_secret_with_team)
                .get(get_secret_with_team),
        )
        .route(
            "/admin/v1/{env}/{tenant}/{team}/{category}/{name}/_versions",
            get(list_versions_with_team),
        )
        .route(
            "/admin/v1/{env}/{tenant}/{team}/_list",
            get(list_secrets_with_team),
        )
        .route(
            "/admin/v1/{env}/{tenant}/_rotate/{category}",
            post(rotate_no_team),
        )
        .route(
            "/admin/v1/{env}/{tenant}/{team}/_rotate/{category}",
            post(rotate_with_team),
        )
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

async fn put_secret_no_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, category, name)): Path<(String, String, String, String)>,
    Json(request): Json<PutSecretRequest>,
) -> Result<impl IntoResponse, AppError> {
    put_secret(
        state,
        correlation,
        auth,
        env,
        tenant,
        None,
        category,
        name,
        request,
    )
    .await
}

async fn put_secret_with_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, team, category, name)): Path<(String, String, String, String, String)>,
    Json(request): Json<PutSecretRequest>,
) -> Result<impl IntoResponse, AppError> {
    put_secret(
        state,
        correlation,
        auth,
        env,
        tenant,
        Some(team),
        category,
        name,
        request,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn put_secret(
    state: AppState,
    correlation: CorrelationId,
    auth: AuthContext,
    env: String,
    tenant: String,
    team: Option<String>,
    category: String,
    name: String,
    request: PutSecretRequest,
) -> Result<impl IntoResponse, AppError> {
    let correlation_for_ctx = correlation.clone();
    let span = request_span("http.put", &correlation.0);
    async move {
        set_tenant_context(
            &env,
            &tenant,
            team.as_deref(),
            &correlation_for_ctx,
            Some(&auth),
        );
        state
            .authorizer
            .authorize(&auth, Action::Put, &tenant, team.as_deref())?;
        let scope = build_scope(&env, &tenant, team.as_deref())?;
        let uri = build_uri(scope.clone(), &category, &name)?;
        let (bytes, _encoding, content_type, visibility, description) = request.into_bytes()?;

        let mut meta = SecretMeta::new(uri.clone(), visibility, content_type);
        meta.description = description;

        let mut broker = state.broker.lock().await;
        let version = broker
            .put_secret(meta.clone(), &bytes)
            .map_err(AppError::from)?;
        let response = SecretResponse::from_meta(&meta, version.version, &bytes);
        Ok((StatusCode::CREATED, Json(response)))
    }
    .instrument(span)
    .await
    .map_err(|err: AppError| attach_correlation(err, &correlation))
}

async fn rotate_no_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, category)): Path<(String, String, String)>,
    maybe_request: Option<Json<RotateRequest>>,
) -> Result<impl IntoResponse, AppError> {
    let request = maybe_request.map(|Json(value)| value).unwrap_or_default();
    rotate_category(
        state,
        correlation,
        auth,
        env,
        tenant,
        None,
        category,
        request,
    )
    .await
}

async fn rotate_with_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, team, category)): Path<(String, String, String, String)>,
    maybe_request: Option<Json<RotateRequest>>,
) -> Result<impl IntoResponse, AppError> {
    let request = maybe_request.map(|Json(value)| value).unwrap_or_default();
    rotate_category(
        state,
        correlation,
        auth,
        env,
        tenant,
        Some(team),
        category,
        request,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn rotate_category(
    state: AppState,
    correlation: CorrelationId,
    auth: AuthContext,
    env: String,
    tenant: String,
    team: Option<String>,
    category: String,
    request: RotateRequest,
) -> Result<impl IntoResponse, AppError> {
    let correlation_for_ctx = correlation.clone();
    let correlation_for_job = correlation.clone();
    let span = request_span("http.rotate", &correlation.0);
    async move {
        set_tenant_context(
            &env,
            &tenant,
            team.as_deref(),
            &correlation_for_ctx,
            Some(&auth),
        );
        state
            .authorizer
            .authorize(&auth, Action::Rotate, &tenant, team.as_deref())?;
        let scope = build_scope(&env, &tenant, team.as_deref())?;
        let job_id = request
            .job_id
            .unwrap_or_else(|| correlation_for_job.0.clone());
        let response =
            rotate::execute_rotation(state.clone(), scope, &category, job_id, &auth.actor).await?;
        Ok((StatusCode::ACCEPTED, Json(response)))
    }
    .instrument(span)
    .await
    .map_err(|err: AppError| attach_correlation(err, &correlation))
}

async fn get_secret_no_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, category, name)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, AppError> {
    get_secret(state, correlation, auth, env, tenant, None, category, name).await
}

async fn get_secret_with_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, team, category, name)): Path<(String, String, String, String, String)>,
) -> Result<impl IntoResponse, AppError> {
    get_secret(
        state,
        correlation,
        auth,
        env,
        tenant,
        Some(team),
        category,
        name,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn get_secret(
    state: AppState,
    correlation: CorrelationId,
    auth: AuthContext,
    env: String,
    tenant: String,
    team: Option<String>,
    category: String,
    name_with_version: String,
) -> Result<impl IntoResponse, AppError> {
    let correlation_for_ctx = correlation.clone();
    let span = request_span("http.get", &correlation.0);
    async move {
        set_tenant_context(
            &env,
            &tenant,
            team.as_deref(),
            &correlation_for_ctx,
            Some(&auth),
        );
        state
            .authorizer
            .authorize(&auth, Action::Get, &tenant, team.as_deref())?;
        let (name, version) = split_name_version(&name_with_version)?;
        let scope = build_scope(&env, &tenant, team.as_deref())?;
        let uri = build_uri(scope.clone(), &category, &name)?;

        let mut broker = state.broker.lock().await;
        let result = match version {
            Some(ver) => broker
                .get_secret_version(&uri, Some(ver))
                .map_err(AppError::from)?,
            None => broker.get_secret(&uri).map_err(AppError::from)?,
        };

        match result {
            Some(secret) => {
                let response =
                    SecretResponse::from_meta(&secret.meta, secret.version, &secret.payload);
                Ok((StatusCode::OK, Json(response)))
            }
            None => Err(AppError::new(AppErrorKind::NotFound)),
        }
    }
    .instrument(span)
    .await
    .map_err(|err| attach_correlation(err, &correlation))
}

async fn list_secrets_no_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, AppError> {
    list_secrets(state, correlation, auth, env, tenant, None, query).await
}

async fn list_secrets_with_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, team)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, AppError> {
    list_secrets(state, correlation, auth, env, tenant, Some(team), query).await
}

async fn list_secrets(
    state: AppState,
    correlation: CorrelationId,
    auth: AuthContext,
    env: String,
    tenant: String,
    team: Option<String>,
    query: ListQuery,
) -> Result<impl IntoResponse, AppError> {
    let correlation_for_ctx = correlation.clone();
    let span = request_span("http.list", &correlation.0);
    async move {
        set_tenant_context(
            &env,
            &tenant,
            team.as_deref(),
            &correlation_for_ctx,
            Some(&auth),
        );
        state
            .authorizer
            .authorize(&auth, Action::List, &tenant, team.as_deref())?;
        let scope = build_scope(&env, &tenant, team.as_deref())?;
        let (category_prefix, name_prefix) = split_prefix(query.prefix.as_deref());

        let broker = state.broker.lock().await;
        let items = broker
            .list_secrets(&scope, category_prefix, name_prefix)
            .map_err(AppError::from)?
            .into_iter()
            .map(ListItem::from)
            .collect();

        Ok((StatusCode::OK, Json(ListSecretsResponse { items })))
    }
    .instrument(span)
    .await
    .map_err(|err| attach_correlation(err, &correlation))
}

async fn list_versions_no_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, category, name)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, AppError> {
    list_versions(state, correlation, auth, env, tenant, None, category, name).await
}

async fn list_versions_with_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, team, category, name)): Path<(String, String, String, String, String)>,
) -> Result<impl IntoResponse, AppError> {
    list_versions(
        state,
        correlation,
        auth,
        env,
        tenant,
        Some(team),
        category,
        name,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn list_versions(
    state: AppState,
    correlation: CorrelationId,
    auth: AuthContext,
    env: String,
    tenant: String,
    team: Option<String>,
    category: String,
    name: String,
) -> Result<impl IntoResponse, AppError> {
    let correlation_for_ctx = correlation.clone();
    let span = request_span("http.versions", &correlation.0);
    async move {
        set_tenant_context(
            &env,
            &tenant,
            team.as_deref(),
            &correlation_for_ctx,
            Some(&auth),
        );
        state
            .authorizer
            .authorize(&auth, Action::List, &tenant, team.as_deref())?;
        let scope = build_scope(&env, &tenant, team.as_deref())?;
        let uri = build_uri(scope, &category, &name)?;

        let broker = state.broker.lock().await;
        let versions = broker
            .versions(&uri)
            .map_err(AppError::from)?
            .into_iter()
            .map(VersionInfo::from)
            .collect();
        Ok((StatusCode::OK, Json(VersionsResponse { versions })))
    }
    .instrument(span)
    .await
    .map_err(|err| attach_correlation(err, &correlation))
}

async fn delete_secret_no_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, category, name)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, AppError> {
    delete_secret(state, correlation, auth, env, tenant, None, category, name).await
}

async fn delete_secret_with_team(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(auth): Extension<AuthContext>,
    Path((env, tenant, team, category, name)): Path<(String, String, String, String, String)>,
) -> Result<impl IntoResponse, AppError> {
    delete_secret(
        state,
        correlation,
        auth,
        env,
        tenant,
        Some(team),
        category,
        name,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn delete_secret(
    state: AppState,
    correlation: CorrelationId,
    auth: AuthContext,
    env: String,
    tenant: String,
    team: Option<String>,
    category: String,
    name: String,
) -> Result<impl IntoResponse, AppError> {
    let correlation_for_ctx = correlation.clone();
    let span = request_span("http.delete", &correlation.0);
    async move {
        set_tenant_context(
            &env,
            &tenant,
            team.as_deref(),
            &correlation_for_ctx,
            Some(&auth),
        );
        state
            .authorizer
            .authorize(&auth, Action::Delete, &tenant, team.as_deref())?;
        let scope = build_scope(&env, &tenant, team.as_deref())?;
        let uri = build_uri(scope, &category, &name)?;

        let broker = state.broker.lock().await;
        let version = broker.delete_secret(&uri).map_err(AppError::from)?;
        Ok((
            StatusCode::OK,
            Json(DeleteResponse {
                version: version.version,
                deleted: true,
            }),
        ))
    }
    .instrument(span)
    .await
    .map_err(|err| attach_correlation(err, &correlation))
}
