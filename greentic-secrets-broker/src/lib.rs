pub mod auth;
pub mod config;
pub mod error;
pub mod http;
pub mod models;
pub mod nats;
pub mod path;
pub mod rotate;
pub mod state;
pub mod telemetry;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use auth::Authorizer;
use greentic_config_types::{
    NetworkConfig, PathsConfig, SecretsBackendRefConfig, TelemetryConfig, TelemetryExporterKind,
};
use secrets_core::SecretsBroker;
use secrets_core::crypto::dek_cache::DekCache;
use secrets_core::crypto::envelope::EnvelopeService;
use secrets_core::types::EncryptionAlgorithm;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{info, warn};

pub use state::AppState;
pub use telemetry::CorrelationId;

#[derive(Clone)]
pub struct BrokerRuntimeConfig {
    pub http_addr: SocketAddr,
    pub nats_url: Option<String>,
    pub network: NetworkConfig,
    pub telemetry: TelemetryConfig,
    pub paths: PathsConfig,
    pub secrets: SecretsBackendRefConfig,
}

fn effective_backend(config: &SecretsBackendRefConfig) -> SecretsBackendRefConfig {
    if config.kind == "none" && std::env::var("GREENTIC_DEV_SECRETS_PATH").is_ok() {
        return SecretsBackendRefConfig {
            kind: "dev".to_string(),
            reference: None,
        };
    }
    config.clone()
}

pub async fn run(config: BrokerRuntimeConfig) -> anyhow::Result<()> {
    apply_network_env(&config.network);
    apply_telemetry_env(&config.telemetry);

    let state = build_state_with_backend(&config.secrets).await?;

    let http_listener = TcpListener::bind(config.http_addr).await.with_context(|| {
        format!(
            "failed to bind http listener on {addr}",
            addr = config.http_addr
        )
    })?;

    let http_addr = http_listener.local_addr()?;
    info!(%http_addr, "http server listening");

    let http_router = http::router(state.clone());
    let http_server = tokio::spawn(async move {
        axum::serve(http_listener, http_router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(anyhow::Error::from)
    });

    let maybe_nats = if let Some(url) = &config.nats_url {
        info!(nats_url = %url, "connecting to nats");
        let client = async_nats::connect(url)
            .await
            .with_context(|| "failed to connect to nats")?;
        Some(tokio::spawn(nats::run(client, state.clone())))
    } else {
        warn!("nats disabled; BROKER__NATS_URL not set");
        None
    };

    if let Some(nats_task) = maybe_nats {
        let (http_result, nats_result) = tokio::try_join!(http_server, nats_task)?;
        http_result?;
        nats_result?;
    } else {
        http_server.await??;
    }

    Ok(())
}

pub async fn build_state() -> anyhow::Result<AppState> {
    build_state_with_backend(&SecretsBackendRefConfig::default()).await
}

pub async fn build_state_with_backend(
    backend: &SecretsBackendRefConfig,
) -> anyhow::Result<AppState> {
    let backend = effective_backend(backend);
    let authorizer = Authorizer::from_env().await?;
    let components = config::load_backend_components(&backend.kind).await?;
    let crypto = EnvelopeService::new(
        components.key_provider,
        DekCache::from_env(),
        EncryptionAlgorithm::Aes256Gcm,
    );
    let broker = SecretsBroker::new(components.backend, crypto);
    Ok(AppState::new(
        Arc::new(Mutex::new(broker)),
        Arc::new(authorizer),
    ))
}

fn apply_network_env(network: &NetworkConfig) {
    if let Some(proxy) = &network.proxy_url {
        unsafe {
            std::env::set_var("HTTPS_PROXY", proxy);
            std::env::set_var("HTTP_PROXY", proxy);
        }
    }
    let _ = network.tls_mode;
}

fn apply_telemetry_env(telemetry: &TelemetryConfig) {
    if !telemetry.enabled {
        unsafe {
            std::env::set_var("OTEL_TRACES_EXPORTER", "none");
            std::env::set_var("OTEL_METRICS_EXPORTER", "none");
        }
        return;
    }

    if let Some(endpoint) = &telemetry.endpoint {
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint);
        }
    }
    if telemetry.sampling != 1.0 {
        unsafe {
            std::env::set_var("OTEL_TRACES_SAMPLER", "parentbased_traceidratio");
            std::env::set_var("OTEL_TRACES_SAMPLER_ARG", telemetry.sampling.to_string());
        }
    }
    match telemetry.exporter {
        TelemetryExporterKind::Otlp => unsafe {
            std::env::set_var("OTEL_TRACES_EXPORTER", "otlp");
            std::env::set_var("OTEL_METRICS_EXPORTER", "otlp");
        },
        TelemetryExporterKind::Gcp | TelemetryExporterKind::Azure | TelemetryExporterKind::Aws => {
            warn!(
                exporter = ?telemetry.exporter,
                "provider-specific telemetry exporter is not handled yet; falling back to OTLP"
            );
            unsafe {
                std::env::set_var("OTEL_TRACES_EXPORTER", "otlp");
                std::env::set_var("OTEL_METRICS_EXPORTER", "otlp");
            }
        }
        TelemetryExporterKind::Stdout => unsafe {
            std::env::set_var("OTEL_TRACES_EXPORTER", "stdout");
            std::env::set_var("OTEL_METRICS_EXPORTER", "none");
        },
        TelemetryExporterKind::None => unsafe {
            std::env::set_var("OTEL_TRACES_EXPORTER", "none");
            std::env::set_var("OTEL_METRICS_EXPORTER", "none");
        },
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            warn!(?err, "failed to install ctrl-c handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => warn!(?err, "failed to install sigterm handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
