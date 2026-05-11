use crate::retry::parse_bool_env;
use serde_json::json;
use std::env;
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed test environment configuration.
#[derive(Debug, Clone)]
pub struct TestEnv {
    pub prefix: TestPrefix,
    pub cleanup: bool,
}

impl TestEnv {
    pub fn from_env(provider: &str) -> Self {
        let prefix = TestPrefix::from_env(provider);

        let keep = parse_bool_env("GREENTIC_TEST_KEEP");
        let cleanup = if keep {
            false
        } else if let Ok(value) = env::var("GREENTIC_TEST_CLEANUP") {
            parse_bool_env_value(&value, true)
        } else {
            true
        };

        Self { prefix, cleanup }
    }
}

#[derive(Debug, Clone)]
pub struct TestPrefix {
    provider: String,
    base: String,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl TestPrefix {
    pub fn from_env(provider: &str) -> Self {
        if let Ok(explicit) = env::var("GREENTIC_TEST_PREFIX") {
            return Self::new(provider, explicit);
        }

        let run_id = env::var("GITHUB_RUN_ID").ok();
        let run_attempt = env::var("GITHUB_RUN_ATTEMPT").ok();
        let repo = env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| "local".to_string());

        if let (Some(id), Some(attempt)) = (run_id, run_attempt) {
            let base = format!("ci/{provider}/{repo}/{id}/{attempt}");
            return Self::new(provider, base);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pid = std::process::id();
        let mut base = String::from("local/");
        let _ = write!(&mut base, "{provider}/{now}/{pid}");
        Self::new(provider, base)
    }

    fn new(provider: &str, base: String) -> Self {
        // The base flows directly into provider keys, which providers turn into
        // SecretUri components (validated against `[a-z0-9._-]+`). Sanitize once
        // here so every provider's wrapper sees an already-valid identifier.
        let base = sanitize_segment(&base);
        Self {
            provider: provider.to_string(),
            base,
            counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Returns a unique key prefix for the current test run.
    pub fn base(&self) -> String {
        self.base.clone()
    }

    /// Derive a unique secret key for a test case.
    ///
    /// Uses `-` rather than `/` between segments so keys are valid as
    /// `SecretUri` name components without further provider-side sanitization.
    pub fn key(&self, suffix: &str) -> String {
        let next = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let suffix = sanitize_segment(suffix);
        format!("{}-{suffix}-{next}", self.base)
    }

    /// Minimal JSON metadata used in debugging output.
    pub fn to_metadata(&self) -> serde_json::Value {
        json!({
            "provider": self.provider,
            "prefix": self.base,
        })
    }
}

/// Replace any character outside the SecretUri component charset
/// (`[a-z0-9._-]`) with `-`, lowercasing ASCII letters along the way.
fn sanitize_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            'a'..='z' | '0'..='9' | '-' | '_' | '.' => out.push(ch),
            'A'..='Z' => out.push(ch.to_ascii_lowercase()),
            _ => out.push('-'),
        }
    }
    out
}

fn parse_bool_env_value(value: &str, default_true: bool) -> bool {
    match value {
        "" => default_true,
        v if v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true") => true,
        v if v.eq_ignore_ascii_case("0") || v.eq_ignore_ascii_case("false") => false,
        _ => default_true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_local_prefix_when_no_ci_env() {
        let prefix = TestPrefix::new("dev", "local/test/123".to_string());
        // Slashes get normalised to dashes so the base is a valid SecretUri segment.
        assert_eq!(prefix.base(), "local-test-123");
        let k1 = prefix.key("a");
        let k2 = prefix.key("a");
        assert_ne!(k1, k2);
        // Keys must contain only chars accepted by SecretUri name validation.
        assert!(
            k1.chars()
                .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '_' | '.')),
            "key contains invalid chars: {k1}"
        );
    }
}
