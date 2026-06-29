//! Vault client-token acquisition.
//!
//! Two modes are supported:
//!
//! * **Static token** (`VAULT_TOKEN`) — the historical behaviour; the token is
//!   sent verbatim on every request.
//! * **Kubernetes workload identity** (`VAULT_K8S_ROLE`) — the pod's projected
//!   ServiceAccount JWT is exchanged for a short-lived Vault client token via
//!   `auth/<mount>/login`. No long-lived secret is baked into the workload; the
//!   identity is the pod's ServiceAccount and Vault owns the token's lifetime.
//!
//! The acquired token is cached and reused. When Vault rejects a request with
//! `403` and the identity is renewable (Kubernetes), the cached token is dropped
//! and re-acquired once — this absorbs token expiry without a background renewal
//! loop.

use std::fmt;
use std::sync::Mutex;

use anyhow::{Result, bail};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};

use greentic_secrets_spec::{SecretsError, SecretsResult};

/// Default path of the projected Kubernetes ServiceAccount token in a pod.
const DEFAULT_K8S_JWT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
/// Default Vault mount for the Kubernetes auth method.
const DEFAULT_K8S_MOUNT: &str = "kubernetes";

/// How a Vault client token is obtained.
enum Method {
    /// A static token supplied directly via `VAULT_TOKEN`.
    Token(String),
    /// Kubernetes auth: exchange the pod's ServiceAccount JWT for a Vault token.
    Kubernetes {
        role: String,
        jwt_path: String,
        mount: String,
    },
}

/// Resolves and caches the Vault client token for the configured identity.
pub(crate) struct VaultAuthenticator {
    method: Method,
    addr: String,
    namespace: Option<String>,
    cached: Mutex<Option<String>>,
}

impl VaultAuthenticator {
    /// Resolve the identity from the environment.
    ///
    /// `VAULT_TOKEN` wins when present (back-compat). Otherwise `VAULT_K8S_ROLE`
    /// selects Kubernetes workload identity, with the JWT path and auth mount
    /// overridable via `VAULT_K8S_JWT_PATH` / `VAULT_K8S_MOUNT`.
    pub(crate) fn from_env(addr: &str, namespace: Option<String>) -> Result<Self> {
        let method = if let Ok(token) = std::env::var("VAULT_TOKEN") {
            let token = token.trim().to_string();
            if token.is_empty() {
                bail!("VAULT_TOKEN is set but empty");
            }
            Method::Token(token)
        } else if let Ok(role) = std::env::var("VAULT_K8S_ROLE") {
            let role = role.trim().to_string();
            if role.is_empty() {
                bail!("VAULT_K8S_ROLE is set but empty");
            }
            let jwt_path = std::env::var("VAULT_K8S_JWT_PATH")
                .unwrap_or_else(|_| DEFAULT_K8S_JWT_PATH.to_string());
            let mount =
                std::env::var("VAULT_K8S_MOUNT").unwrap_or_else(|_| DEFAULT_K8S_MOUNT.to_string());
            Method::Kubernetes {
                role,
                jwt_path,
                mount,
            }
        } else {
            bail!(
                "configure Vault identity: set VAULT_TOKEN, or VAULT_K8S_ROLE for Kubernetes workload identity"
            );
        };

        Ok(Self {
            method,
            addr: addr.to_string(),
            namespace,
            cached: Mutex::new(None),
        })
    }

    /// Whether the token can be re-acquired (Kubernetes) versus fixed (static).
    /// Drives the re-login-on-403 retry — a static token never benefits.
    pub(crate) fn is_renewable(&self) -> bool {
        matches!(self.method, Method::Kubernetes { .. })
    }

    /// Drop the cached token so the next [`token`](Self::token) re-authenticates.
    pub(crate) fn invalidate(&self) {
        *self.lock() = None;
    }

    /// Return a usable Vault client token, logging in if none is cached.
    pub(crate) async fn token(&self, client: &Client) -> SecretsResult<String> {
        // Bind to a local so the guard drops before the await below — never hold
        // a std Mutex across the login round-trip.
        let cached = self.lock().clone();
        if let Some(existing) = cached {
            return Ok(existing);
        }
        // The login round-trip runs without the lock held; a concurrent caller
        // may log in too, which is harmless — each issued token is independently
        // valid, and the last writer simply wins the cache slot.
        let token = self.login(client).await?;
        *self.lock() = Some(token.clone());
        Ok(token)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.cached
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn login(&self, client: &Client) -> SecretsResult<String> {
        let (role, jwt_path, mount) = match &self.method {
            Method::Token(token) => return Ok(token.clone()),
            Method::Kubernetes {
                role,
                jwt_path,
                mount,
            } => (role, jwt_path, mount),
        };

        let jwt = std::fs::read_to_string(jwt_path).map_err(|err| {
            SecretsError::Backend(format!(
                "failed to read Kubernetes service-account token at {jwt_path}: {err}"
            ))
        })?;
        let (url, payload) = kubernetes_login_request(&self.addr, mount, role, jwt.trim());
        let mut builder = client.post(url).json(&payload);
        if let Some(namespace) = &self.namespace {
            builder = builder.header("X-Vault-Namespace", namespace);
        }
        let response = builder.send().await.map_err(|err| {
            SecretsError::Backend(format!("vault kubernetes login failed: {err}"))
        })?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(SecretsError::Backend(format!(
                "vault kubernetes login rejected: {status} {body}"
            )));
        }
        let parsed: LoginResponse = serde_json::from_str(&body).map_err(|err| {
            SecretsError::Backend(format!(
                "failed to parse vault login response: {err}; body={body}"
            ))
        })?;
        if parsed.auth.client_token.is_empty() {
            return Err(SecretsError::Backend(
                "vault login response missing client_token".into(),
            ));
        }
        Ok(parsed.auth.client_token)
    }
}

impl fmt::Debug for VaultAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the token material.
        let method = match &self.method {
            Method::Token(_) => "token",
            Method::Kubernetes { .. } => "kubernetes",
        };
        f.debug_struct("VaultAuthenticator")
            .field("method", &method)
            .field("addr", &self.addr)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

/// Build the `(url, json body)` for a Vault Kubernetes-auth login. Pure, so the
/// URL and payload shape are unit-testable without a live server.
pub(crate) fn kubernetes_login_request(
    addr: &str,
    mount: &str,
    role: &str,
    jwt: &str,
) -> (String, Value) {
    let url = format!(
        "{}/v1/auth/{}/login",
        addr.trim_end_matches('/'),
        mount.trim_matches('/')
    );
    (url, json!({ "role": role, "jwt": jwt }))
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: LoginAuth,
}

#[derive(Deserialize)]
struct LoginAuth {
    client_token: String,
}
