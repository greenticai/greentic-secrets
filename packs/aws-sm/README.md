# AWS Secrets Manager secrets pack

## What it does
This pack provides Greentic secrets flows for AWS Secrets Manager.

## Required inputs
Config:
- tenant_id
- environment
- region
- namespace_prefix
- timeouts
- retry_policy
- redaction_policy

Optional secrets:
- aws_access_key_id
- aws_secret_access_key
- aws_web_identity_token_file
- audit_sink_credentials (required when audit.sink_type is splunk, azure, gcp, or http)

## Safety guarantees
- Setup plans always redact secrets (no values in logs or reports).
- Dry-run mode does not make network calls.
