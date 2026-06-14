# GCP Secret Manager secrets pack

## What it does
This pack provides Greentic secrets flows for GCP Secret Manager.

## Required inputs
Config:
- tenant_id
- environment
- project_id
- auth_mode
- namespace_prefix
- timeouts
- retry_policy
- redaction_policy

Optional secrets:
- gcp_service_account_json
- audit_sink_credentials (required when audit.sink_type is splunk, azure, gcp, or http)

## Safety guarantees
- Setup plans always redact secrets (no values in logs or reports).
- Dry-run mode does not make network calls.
