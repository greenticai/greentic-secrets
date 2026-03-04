# Broker Admin API E2E Smoke (No `cargo test`)

This smoke verifies that broker admin aliases (`/admin/v1/...`) behave exactly
like canonical routes (`/v1/...`) for authenticated requests.

## What this checks

- Broker starts with local `dev` backend.
- Authenticated `PUT` via `/admin/v1/...` returns `201`.
- Authenticated `GET` via `/admin/v1/...` and `/v1/...` both return `200`.
- Authenticated `_list` via `/admin/v1/...` and `/v1/...` both return `200`.
- JSON bodies for admin vs canonical responses are byte-for-byte equal.

## Run

From repo root:

```bash
./greentic-secrets/scripts/e2e_broker_admin_api.sh
```

Or from `greentic-secrets/`:

```bash
./scripts/e2e_broker_admin_api.sh
```

## Optional env overrides

- `BROKER_HOST` (default `127.0.0.1`)
- `BROKER_PORT` (default `18080`)
- `BROKER_BIND` (default `${BROKER_HOST}:${BROKER_PORT}`)
- `E2E_ENV_ID` (default `dev`)
- `E2E_TENANT` (default `acme`)
- `E2E_CATEGORY` (default `configs`)
- `E2E_NAME` (default `demo_key`)
- `E2E_VALUE_JSON` (default `{"hello":"world"}`)

Example:

```bash
BROKER_PORT=18081 E2E_TENANT=mytenant ./scripts/e2e_broker_admin_api.sh
```

## Notes

- Script does not run `cargo test`.
- Script starts broker with `cargo run` and stops it automatically on exit.
- Script generates an ephemeral Ed25519 JWT keypair and token for auth.
- Python deps required for token generation: `cryptography`, `pyjwt`.
