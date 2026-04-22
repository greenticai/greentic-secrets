use crate::error::{AppError, AppErrorKind};
use secrets_core::{Scope, SecretUri};

pub fn build_scope(env: &str, tenant: &str, team: Option<&str>) -> Result<Scope, AppError> {
    let normalized = team.and_then(|value| match value {
        "_" => None,
        "" => None,
        other => Some(other.to_string()),
    });
    Scope::new(env.to_string(), tenant.to_string(), normalized).map_err(AppError::from)
}

pub fn build_uri(scope: Scope, category: &str, name: &str) -> Result<SecretUri, AppError> {
    SecretUri::new(scope, category.to_string(), name.to_string()).map_err(AppError::from)
}

pub fn split_name_version(input: &str) -> Result<(String, Option<u64>), AppError> {
    if let Some((name, version)) = input.rsplit_once('@') {
        if version.is_empty() {
            return Err(AppError::new(AppErrorKind::BadRequest(
                "version missing".into(),
            )));
        }
        let parsed = version
            .parse::<u64>()
            .map_err(|_| AppError::new(AppErrorKind::BadRequest("invalid version".into())))?;
        Ok((name.to_string(), Some(parsed)))
    } else {
        Ok((input.to_string(), None))
    }
}

pub fn split_prefix(prefix: Option<&str>) -> (Option<&str>, Option<&str>) {
    prefix.map_or((None, None), |value| {
        let mut parts = value.splitn(2, '/');
        let category = parts.next().filter(|s| !s.is_empty());
        let name = parts.next().filter(|s| !s.is_empty());
        (category, name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_scope_normalizes_placeholder_team() {
        let scope = build_scope("dev", "acme", Some("_")).expect("scope");
        assert_eq!(scope.env(), "dev");
        assert_eq!(scope.tenant(), "acme");
        assert_eq!(scope.team(), None);
    }

    #[test]
    fn build_uri_preserves_scope_and_segments() {
        let scope = build_scope("dev", "acme", Some("core")).expect("scope");
        let uri = build_uri(scope, "configs", "db").expect("uri");
        assert_eq!(uri.to_string(), "secrets://dev/acme/core/configs/db");
    }

    #[test]
    fn split_name_version_supports_optional_version() {
        assert_eq!(
            split_name_version("api-key@42").expect("versioned"),
            ("api-key".to_string(), Some(42))
        );
        assert_eq!(
            split_name_version("api-key").expect("unversioned"),
            ("api-key".to_string(), None)
        );
    }

    #[test]
    fn split_name_version_rejects_bad_versions() {
        assert!(split_name_version("api-key@").is_err());
        assert!(split_name_version("api-key@latest").is_err());
    }

    #[test]
    fn split_prefix_handles_partial_values() {
        assert_eq!(split_prefix(None), (None, None));
        assert_eq!(
            split_prefix(Some("configs/db")),
            (Some("configs"), Some("db"))
        );
        assert_eq!(split_prefix(Some("configs/")), (Some("configs"), None));
        assert_eq!(split_prefix(Some("/db")), (None, Some("db")));
    }
}
