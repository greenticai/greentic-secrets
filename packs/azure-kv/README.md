# Azure Key Vault secrets pack

## What it does
This pack provides Greentic secrets flows for Azure Key Vault.

## Required inputs
Config:
- tenant_id
- environment
- vault_url
- auth_mode
- namespace_prefix
- timeouts
- retry_policy
- redaction_policy

Optional secrets:
- azure_client_secret
- audit_sink_credentials (required when audit.sink_type is splunk, azure, gcp, or http)

## Safety guarantees
- Setup plans always redact secrets (no values in logs or reports).
- Dry-run mode does not make network calls.
