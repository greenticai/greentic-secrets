# SecretsValWasmPR-01 — Build and publish secrets pack validator as WASM + declare it in secrets extensions

**Repo:** `greentic-ai/greentic-secrets`

## Goal
Create a **secrets domain validator** as a WASM component implementing `greentic:pack-validate@0.1.0`, publish to OCI, and define how secrets packs/extensions reference it.

## Key safety invariant
No secret requirement can ever be non-sensitive.

## Deliverables
- `crates/greentic-secrets-pack-validator` (WASM component)
- `validators/secrets/` pack producing `dist/validators-secrets.gtpack`
- CI publish to `ghcr.io/greentic-ai/validators/secrets:<ver>`
- Docs: `docs/pack-validation.md`

## Validator rules (minimal)
- `SEC_REQUIREMENTS_ASSET_MISSING`: missing `assets/secret-requirements.json` when secrets are required
- `SEC_REQUIREMENTS_INVALID_JSON`: requirements asset not valid JSON (if validator is given bytes later; for now rely on presence checks only)
- `SEC_SECRET_NOT_SENSITIVE`: any explicit sensitive=false or missing sensitivity marker where required (implement only if requirements JSON is part of manifest_cbor or supplied; otherwise leave as Warn with hint)
- `SEC_BAD_KEY_FORMAT`: keys not matching allowed patterns (Warn ok initially)

## Inputs
Use only manifest_cbor + sbom_json + file_index. If requirements asset bytes are needed, add later via a controlled “read file bytes by path” extension with strict limits; do NOT do it in this PR.

## Acceptance criteria
- Builds, packages, and can be executed by greentic-pack doctor once validator support is merged.
