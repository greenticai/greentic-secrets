# greentic-secrets-broker

The Greentic secrets broker exposes the core secrets engine over HTTP and NATS so
applications can fetch, rotate, and manage secrets via a central service.

## HTTP API

The broker exposes two equivalent HTTP prefixes:

- `/v1/...` (existing canonical paths)
- `/admin/v1/...` (admin alias paths, same handlers/auth/contracts)

Supported operations (with and without `{team}` segment):

- `PUT /{prefix}/{env}/{tenant}/{category}/{name}`
- `GET /{prefix}/{env}/{tenant}/{category}/{name}`
- `DELETE /{prefix}/{env}/{tenant}/{category}/{name}`
- `GET /{prefix}/{env}/{tenant}/_list?prefix=<category[/name]>`
- `GET /{prefix}/{env}/{tenant}/{category}/{name}/_versions`
- `POST /{prefix}/{env}/{tenant}/_rotate/{category}`

Team-scoped variants:

- `/{prefix}/{env}/{tenant}/{team}/{category}/{name}`
- `/{prefix}/{env}/{tenant}/{team}/_list`
- `/{prefix}/{env}/{tenant}/{team}/{category}/{name}/_versions`
- `/{prefix}/{env}/{tenant}/{team}/_rotate/{category}`

## Local E2E Smoke

For a no-`cargo test` HTTP alias smoke (`/admin/v1` vs `/v1` parity), run:

```bash
./scripts/e2e_broker_admin_api.sh
```

Details and overrides are documented in:

- `docs/broker_admin_api_e2e.md`
