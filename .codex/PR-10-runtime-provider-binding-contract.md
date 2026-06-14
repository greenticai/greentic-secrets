# PR-10: Define runtime provider binding contract for deployer/start integration

## Current Baseline

`greentic-secrets` already has the provider/runtime primitives that
`greentic-start` and `greentic-deployer` should integrate against:

- `greentic-secrets-spec` defines canonical secret scopes and URIs:
  `secrets://{environment}/{tenant}/{team-or-_}/{category}/{name}`.
- `greentic-secrets-core` and the host provider crates implement concrete
  `SecretsBackend` behavior for dev/env/file and cloud providers.
- Provider packs exist for:
  - `greentic.secrets.aws-sm`
  - `greentic.secrets.gcp-sm`
  - `greentic.secrets.azure-kv`
  - `greentic.secrets.k8s`
  - `greentic.secrets.vault-kv`
- A host-side dev backend exists, but there is not currently a
  `greentic.secrets.dev` provider pack in `packs/`. If start/deployer need a
  local/dev binding target, this PR must either add that pack or explicitly
  document that local dev remains on the existing dev-store fallback.
- Provider pack manifests expose `greentic.provider-extension.v1` metadata with
  provider ids, config schema refs, runtime component refs, capabilities, and
  ops.
- Provider config schemas use `namespace_prefix`, not a generic `prefix`, and
  require `tenant_id` and `environment` in addition to provider-specific fields.

`greentic-start` and `greentic-deployer` currently agree that existing
`providers/secrets/*.gtpack` backend selectors are not enough. Those packs only
select the legacy start-side backend (`dev-store` or `env`). The new contract is
a separate deployer-generated provider binding file.

## Cross-Repo Alignment

This PR must align with:

- `../greentic-start/.codex/done/PR-SECRET-01-deployment-compat-harness.md`
- `../greentic-start/.codex/done/PR-SECRET-02-use-greentic-secrets-providers.md`
- `../greentic-deployer/.codex/done/PR-30-secrets-provider-binding.md`
- `../greentic-deployer/.codex/done/PR-29-runtime-secret-promotion.md`

Important compatibility constraint: deployer must preserve the current
environment-variable bridge until `greentic-start` can consume provider
bindings at runtime. Injecting a provider `.gtpack` alone is not proof that
runtime cloud-provider lookup is active.

## Goal

Define and validate `greentic.secrets.binding.v1`, the stable contract used by
deployer output to tell runtime which `greentic-secrets` provider pack to use
and how to configure it.

`greentic-start` should consume this contract without hard-coding AWS/GCP/Azure
branches. It should validate the binding and then use provider-pack metadata to
instantiate or invoke the selected provider.

## Binding Shape

The binding must identify:

- `schema_version`: exactly `greentic.secrets.binding.v1`
- `provider_id`: provider pack id, e.g. `greentic.secrets.aws-sm`
- `pack`: bundle-local path or resolvable ref for the provider pack
- `config`: provider config object, validated against the selected pack's
  `schemas.config` / `config_schema_ref`
- optional `state`: provider state path/ref when a provider needs persisted
  runtime state

Recommended runtime config path shared by start/deployer:

```text
state/config/platform/secrets-provider.json
```

Representative AWS binding:

```json
{
  "schema_version": "greentic.secrets.binding.v1",
  "provider_id": "greentic.secrets.aws-sm",
  "pack": "providers/secrets/aws-sm.gtpack",
  "config": {
    "tenant_id": "demo",
    "environment": "dev",
    "region": "eu-north-1",
    "namespace_prefix": "greentic/dev/demo/_",
    "audit": {
      "sink_type": "file",
      "sink_config_ref": "secrets://dev/demo/_/audit/sink"
    },
    "timeouts": {
      "connect_ms": 100,
      "op_ms": 1000
    },
    "retry_policy": {
      "max_attempts": 3,
      "base_backoff_ms": 100,
      "max_backoff_ms": 1000,
      "jitter": true
    },
    "redaction_policy": {
      "redact_values": true,
      "log_secret_refs_only": true
    }
  }
}
```

Provider-specific required config today:

- AWS: `tenant_id`, `environment`, `region`, `namespace_prefix`, `audit`,
  `timeouts`, `retry_policy`, `redaction_policy`; optional
  `assume_role_arn`, `kms_key_id`, `labels`.
- GCP: `tenant_id`, `environment`, `project_id`, `auth_mode`,
  `namespace_prefix`, `audit`, `timeouts`, `retry_policy`,
  `redaction_policy`; optional `location`, `labels`.
- Azure: `tenant_id`, `environment`, `vault_url`, `auth_mode`,
  `namespace_prefix`, `audit`, `timeouts`, `retry_policy`,
  `redaction_policy`; optional `client_id`, `labels`.

The canonical runtime secret URI remains:

```text
secrets://{environment}/{tenant}/{team-or-_}/{category}/{name}
```

For `greentic-start` call sites that currently say
`get_secret(provider, key, ctx)`, the `provider` argument maps to the URI
`category` segment. It is not the same as binding `provider_id`.

Example runtime URI:

```text
secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key
```

The selected provider maps that canonical URI into the target store's native
name using its own config, e.g. `namespace_prefix` plus URI scope/category/name.

## Implementation Tasks

1. Add Rust types for `SecretsProviderBinding` in `greentic-secrets-spec` or a
   shared crate that `greentic-start` can depend on without pulling in provider
   implementations.
2. Add a JSON schema for `greentic.secrets.binding.v1`.
3. Add validation helpers for:
   - schema version
   - provider id syntax
   - pack path/ref safety
   - config object presence
   - config validation against the provider pack's declared config schema
   - `namespace_prefix` safety/normalization
4. Add a pack compatibility helper that proves the binding `provider_id` matches
   a provider declared by `greentic.provider-extension.v1`.
5. Add fixtures for AWS/GCP/Azure bindings and a canonical URI resolution
   smoke. Add a dev binding fixture only if this PR also introduces a
   `greentic.secrets.dev` provider pack.
6. Document the runtime config path and keep it aligned with the start/deployer
   notes above.

## Tests

- Binding JSON schema accepts valid AWS/GCP/Azure examples using
  `namespace_prefix`.
- If a dev binding is supported, its fixture is backed by a real
  `greentic.secrets.dev` provider pack rather than an implied host-only backend.
- Binding JSON schema rejects missing `provider_id`, missing `pack`, missing
  `config`, invalid `schema_version`, and unknown top-level fields.
- Provider config validation rejects stale `prefix` fields when the selected
  provider schema requires `namespace_prefix`.
- Pack validation confirms provider packs declare the provider id used by a
  binding through `greentic.provider-extension.v1`.
- A compatibility fixture verifies a canonical URI such as:

```text
secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key
```

  can be mapped through a selected provider binding.

## Acceptance Criteria

- `greentic-start` can depend on binding types/schema instead of inventing local
  config.
- `greentic-deployer` can generate binding files validated by
  `greentic-secrets`.
- Provider packs can be checked for compatibility before cloud deploy.
- The binding is clearly distinct from the existing
  `assets/secrets_backend.json` / `assets/secrets-backend.json` backend selector.
- The current deployer env bridge remains a compatibility path until
  `greentic-start` provider-binding runtime support is merged and covered by the
  deployment compatibility harness.

## Dependencies

- `greentic-start` PR-SECRET-01 uses this schema in its test harness when
  available.
- `greentic-start` PR-SECRET-02 consumes the binding at runtime.
- `greentic-deployer` PR-30 emits the binding.
- `greentic-deployer` PR-29 remains the compatibility bridge that promotes
  runtime secrets to cloud stores and wires env-backed runtime lookup until the
  binding path is active.
