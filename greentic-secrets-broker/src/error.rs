use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

use crate::telemetry::{CORRELATION_ID_HEADER, CorrelationId, correlation_header_value};

#[derive(Debug, Error)]
pub enum AppErrorKind {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unexpected error: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
#[error("{kind}")]
pub struct AppError {
    kind: AppErrorKind,
    correlation_id: Option<String>,
}

impl AppError {
    pub fn new(kind: AppErrorKind) -> Self {
        Self {
            kind,
            correlation_id: None,
        }
    }

    pub fn with_correlation(mut self, id: String) -> Self {
        self.correlation_id = Some(id);
        self
    }

    fn status(&self) -> StatusCode {
        match self.kind {
            AppErrorKind::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppErrorKind::NotFound => StatusCode::NOT_FOUND,
            AppErrorKind::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppErrorKind::Forbidden(_) => StatusCode::FORBIDDEN,
            AppErrorKind::Conflict(_) => StatusCode::CONFLICT,
            AppErrorKind::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn unauthorized<T: Into<String>>(message: T) -> Self {
        Self::new(AppErrorKind::Unauthorized(message.into()))
    }

    pub fn forbidden<T: Into<String>>(message: T) -> Self {
        Self::new(AppErrorKind::Forbidden(message.into()))
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: String,
    correlation_id: Option<&'a str>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let correlation = self.correlation_id.clone();
        let body = Json(ErrorBody {
            error: match &self.kind {
                AppErrorKind::BadRequest(_) => "bad_request",
                AppErrorKind::NotFound => "not_found",
                AppErrorKind::Unauthorized(_) => "unauthorized",
                AppErrorKind::Forbidden(_) => "forbidden",
                AppErrorKind::Conflict(_) => "conflict",
                AppErrorKind::Internal(_) => "internal",
            },
            message: self.kind.to_string(),
            correlation_id: correlation.as_deref(),
        });

        let mut response = (status, body).into_response();
        if let Some(id) = correlation {
            response
                .headers_mut()
                .insert(CORRELATION_ID_HEADER, correlation_header_value(&id));
        }
        response
    }
}

impl From<secrets_core::Error> for AppError {
    fn from(value: secrets_core::Error) -> Self {
        let kind = match value {
            secrets_core::Error::InvalidIdentifier
            | secrets_core::Error::InvalidCharacters { .. }
            | secrets_core::Error::EmptyComponent { .. }
            | secrets_core::Error::InvalidScheme
            | secrets_core::Error::MissingSegment { .. }
            | secrets_core::Error::ExtraSegments
            | secrets_core::Error::InvalidVersion { .. }
            | secrets_core::Error::UnsupportedAlgorithm(_)
            | secrets_core::Error::AlgorithmFeatureUnavailable(_)
            | secrets_core::Error::Invalid(_, _) => AppErrorKind::BadRequest(value.to_string()),
            secrets_core::Error::NotFound { .. } => AppErrorKind::NotFound,
            secrets_core::Error::Storage(err)
            | secrets_core::Error::Crypto(err)
            | secrets_core::Error::Backend(err) => AppErrorKind::Internal(err),
            secrets_core::Error::InvalidPassphrase => {
                AppErrorKind::Internal("backend key material rejected ciphertext".to_string())
            }
        };
        AppError::new(kind)
    }
}

impl From<secrets_core::DecryptError> for AppError {
    fn from(value: secrets_core::DecryptError) -> Self {
        let kind = match value {
            secrets_core::DecryptError::MacMismatch => {
                AppErrorKind::Conflict("integrity check failed".into())
            }
            secrets_core::DecryptError::Provider(err)
            | secrets_core::DecryptError::InvalidEnvelope(err)
            | secrets_core::DecryptError::Crypto(err) => AppErrorKind::Internal(err),
        };
        AppError::new(kind)
    }
}

pub fn attach_correlation(err: AppError, correlation: &CorrelationId) -> AppError {
    err.with_correlation(correlation.0.clone())
}
