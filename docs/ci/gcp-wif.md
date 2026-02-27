# GCP Secret Manager via Workload Identity Federation

Nightly/manual workflows run GCP Secret Manager conformance tests using GitHub OIDC (no JSON key).

## Workload Identity setup

1. Create a Workload Identity Pool and Provider that trusts GitHub:
   - Issuer: `https://token.actions.githubusercontent.com`
   - Allowed subject: `repo:greenticai/greentic-secrets:*`
2. Bind the provider to a service account used for tests.

## Required roles (least privilege)

Assign to the service account:
- `roles/secretmanager.secrets.create`
- `roles/secretmanager.secrets.delete`
- `roles/secretmanager.secrets.get`
- `roles/secretmanager.versions.add`
- `roles/secretmanager.versions.access`

Scope permissions to the project used for tests. Avoid broad `secretmanager.admin` if possible.

## Workflow variables

- `GCP_WORKLOAD_IDENTITY_PROVIDER`: Full resource name of the provider.
- `GCP_SERVICE_ACCOUNT`: Service account email to impersonate.
- `GCP_PROJECT_ID`: Project where secrets are created.

## Test behavior

- Auth via `google-github-actions/auth@v2` with WIF.
- Secrets prefixed with `GREENTIC_TEST_PREFIX` to isolate runs; prefix is sanitized for names.
- Conformance tests create secrets, add versions, read latest, and delete the secret resource on cleanup.


