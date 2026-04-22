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
    pub fn key(&self, suffix: &str) -> String {
        let next = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        assert!(prefix.base().starts_with("local/test/123"));
        let k1 = prefix.key("a");
        let k2 = prefix.key("a");
        assert_ne!(k1, k2);
    }
}
