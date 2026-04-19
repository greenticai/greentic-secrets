# Azure Key Vault OIDC setup

This repository runs Azure Key Vault integration tests using GitHub federated identity (no client secrets).

## Prerequisites

- Entra App Registration with federated credential bound to this repo/environment.
- Azure Key Vault instance for tests.
- RBAC role on Key Vault allowing secrets read/write and key wrap/unwrap (e.g., Key Vault Crypto User + Secrets Officer).

## Federated credential

Configure the app registration with a federated credential:

- Issuer: `https://token.actions.githubusercontent.com`
- Subject: `repo:greenticai/greentic-secrets:*`
- Audience: `api://AzureADTokenExchange`

## Workflow variables

- `AZURE_CLIENT_ID` – App registration client ID.
- `AZURE_TENANT_ID` – Tenant ID.
- `AZURE_SUBSCRIPTION_ID` – Subscription ID.
- `AZURE_KEYVAULT_NAME` – Key Vault name (tests derive `https://<name>.vault.azure.net`).

## Test expectations

- Workflow uses `azure/login@v2` (OIDC) then obtains a Vault access token via `az account get-access-token --resource https://vault.azure.net`.
- Key `greentic-conformance` is created if missing; name exported as `GREENTIC_AZURE_KEY_NAME`.
- Conformance tests use `GREENTIC_TEST_PREFIX` for unique secret names; names are sanitized (lowercase, `/` -> `-`) to meet Key Vault constraints.

