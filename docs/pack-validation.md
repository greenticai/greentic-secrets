# Pack Validation (Secrets)

This repo ships a secrets-domain pack validator as a WASM component implementing
`greentic:pack-validate@0.1.0`. The validator is distributed in two forms:

- OCI component: `ghcr.io/greenticai/validators/secrets:<version>`
- Pack bundle: `dist/validators-secrets.gtpack`

## Validator extension declaration

Secrets packs declare the validator via a secrets extension entry in `pack.yaml`:

```yaml
extensions:
  greentic.secrets.validators.v1:
    kind: greentic.secrets.validators.v1
    version: "1.0.0"
    inline:
      validators:
        - id: greentic.validators.secrets
          world: "greentic:pack-validate/pack-validator@0.1.0"
          component_ref: ghcr.io/greenticai/validators/secrets:__PACK_VERSION__
```

## Diagnostic codes

| Code | Severity | Meaning |
| --- | --- | --- |
| `SEC_REQUIREMENTS_ASSET_MISSING` | Error | `assets/secret-requirements.json` is missing when secrets are required. |
| `SEC_REQUIREMENTS_INVALID_JSON` | Error | Secret requirements asset is not valid JSON (requires file bytes). |
| `SEC_SECRET_NOT_SENSITIVE` | Warn | Sensitivity checks require secret requirements bytes. |
| `SEC_BAD_KEY_FORMAT` | Warn | Secret keys are not UPPER_SNAKE or `greentic://` URIs. |

## Build

```bash
./scripts/build-validator-component.sh
./scripts/build-validator-pack.sh
```
