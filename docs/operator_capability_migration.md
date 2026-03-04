# Operator Capability Migration (Secrets Packs)

## Goal

Migrate secrets provider packs to explicit Operator capability offers without
breaking existing provider runtime behavior.

Target capability id:

- `greentic.cap.secrets.store.v1`

Extension key:

- `greentic.ext.capabilities.v1`

## Current state

Secrets packs currently publish provider metadata via
`greentic.provider-extension.v1` and run with existing setup/provider flows.
Capability-offer migration for `greentic.cap.secrets.store.v1` is now complete
for all current secrets packs.

Use the audit script:

```bash
./scripts/audit-capability-offers.sh
STRICT=1 ./scripts/audit-capability-offers.sh
```

## Safe rollout plan

1. Add capability offers in pack manifests as an additive change only.
2. Keep existing provider-extension metadata unchanged during migration.
3. Roll out one secrets pack at a time.
4. Validate Operator bootstrap/setup behavior with migrated and non-migrated
   packs coexisting.
5. Enable strict audit mode in CI only after all packs are migrated.

## Current status

`packs/aws-sm/pack.yaml`, `packs/azure-kv/pack.yaml`,
`packs/gcp-sm/pack.yaml`, `packs/k8s/pack.yaml`, and
`packs/vault-kv/pack.yaml` include additive
`greentic.ext.capabilities.v1` offers for:

- `cap_id: greentic.cap.secrets.store.v1`
- `provider.component_ref: greentic.secrets.provider.aws_sm` (AWS)
- `provider.component_ref: greentic.secrets.provider.azure_kv` (Azure)
- `provider.component_ref: greentic.secrets.provider.gcp_sm` (GCP)
- `provider.component_ref: greentic.secrets.provider.k8s` (K8s)
- `provider.component_ref: greentic.secrets.provider.vault_kv` (Vault)
- `provider.op: get_secret_value`

## Guardrails

- Do not remove or rename existing provider ops during migration.
- Do not change existing setup flow contracts in the same patch.
- Keep migration patches scoped to secrets packs only.
- Prefer deterministic offer ordering (explicit priority + stable offer ids).

## Minimum done criteria per pack

- `pack.yaml` includes `extensions.greentic.ext.capabilities.v1`.
- At least one offer declares:
  - `cap_id: greentic.cap.secrets.store.v1`
  - deterministic `offer_id`
  - `provider.component_ref`
  - `provider.op`
- Existing provider setup/diagnostics flows continue to work unchanged.
