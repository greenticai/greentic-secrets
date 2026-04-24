# Greentic Secrets

The workspace provides two related entry points:

* **Embedded runtime (`secrets-core`)** – preferred path for applications to
  fetch secrets directly from Rust using the `SecretsCore` builder, optional
  cache, and pluggable backends.
* **HTTP/NATS broker (`secrets-broker`)** – optional control-plane surface for
  operators or cross-language clients.

## Quick start

| Goal | Crate | Example | Run it |
|---|---|---|---|
| Fetch a secret via embedded core (env/file) | `greentic-secrets-core` | `examples/embedded_fetch.rs` | `cargo run -p greentic-secrets-core --example embedded_fetch` |
| Self-describe & validate a secret spec | `greentic-secrets-core` | `examples/describe_and_validate.rs` | `cargo run -p greentic-secrets-core --example describe_and_validate` |
| Start the broker (HTTP/NATS) with one backend | `greentic-secrets-broker` | `examples/broker_startup.rs` | `cargo run -p greentic-secrets-broker --example broker_startup` |

## PR lane (emulators)

Spin up throwaway backends that mimic AWS Secrets Manager, Azure Key Vault, and Vault for PR validation:

1. (Optional) `cp .env.example .env` and edit ports/tokens if needed.
2. `make e2e` boots Docker Compose (`scripts/compose.e2e.yml`), seeds fixtures (`scripts/seed/*.sh`), runs the conformance crate, then tears everything down.
   3. Individual targets are available when iterating locally:
      - `make e2e-up` / `make e2e-down` to manage LocalStack (4566), Azure KV emulator (maps host `8080` → container `4997`, HTTPS), and Vault dev (8200).
        Override `AZURE_KV_IMAGE` or `AZURE_KV_PORT` to match your Docker setup (default image `jamesgoulddev/azure-keyvault-emulator:2.6.6`).
        Azure KV certificate/database files (self-signed with password `emulator`) live in `scripts/azurekv-certs/`; `make e2e-up` regenerates them with `openssl`/`sqlite3` when missing.
        LocalStack-compatible AWS credentials (`AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY/SESSION_TOKEN = test`) and a dummy `GREENTIC_AWS_KMS_KEY_ID` are pre-filled in `.env.example`.
        Azure requires a real AAD application; populate `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_KEYVAULT_URL` in `.env` (see comments in `.env.example`). The emulator still enforces token validation; scope defaults to `https://vault.azure.net/.default`.
   - `make e2e-seed` to re-run seeders.
   - `make e2e-test` to execute `greentic-secrets-conformance` with the env from `.env` (falls back to `.env.example`).

Each seeder is idempotent and logs the exact REST/CLI calls used so fixtures stay reproducible in CI.

### Telemetry

All binaries auto-initialise tracing via `greentic-types`. For local development configure OTLP with:

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
RUST_LOG=info
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=dev
```

### Minimal embedded usage (copy-paste)
```rust
use greentic_secrets_core::{SecretsCore, backends::EnvBackend};

fn main() {
    let core = SecretsCore::builder()
        .with_backend("env", EnvBackend::default())
        .build();
    let db_url = core.get("env:DB_URL").expect("DB_URL missing");
    println!("DB_URL = {}", db_url.redact_preview());
}
```

### Broker quick start (copy-paste)
```bash
# Minimal example — tweak ports/keys as needed
export SECRETS_BACKEND="env"
export RUST_LOG=info
cargo run -p greentic-secrets-broker --example broker_startup
```

### CLI quick start
```bash
# Install the CLI
cargo binstall greentic-secrets

# Prepare local dev store and context
greentic-secrets dev up
greentic-secrets ctx set --env dev --tenant example --team _

# Scaffold seed template from a pack metadata file containing secret_requirements
# (JSON/YAML or .gtpack zip with metadata.json or assets/secret-requirements.json)
greentic-secrets scaffold --pack path/to/pack.gtpack --out seeds.yaml

# When bootstrapping from a `.gtpack`, the scaffolded URIs now use the pack_id
# (e.g., `secrets://dev/example/_/greentic.secrets.aws-sm/db_url`) as the category
# segment so each pack's secrets remain grouped by its identifier.

# Fill interactively (or use --from-dotenv)
greentic-secrets wizard -i seeds.yaml -o seeds.yaml

# Apply to local dev store (default) or pass --broker-url to target the broker HTTP API
greentic-secrets apply -f seeds.yaml
```

### Admin command
`greentic-secrets admin` exposes tenant/team administration (dev is the default backend). Set the working context with `greentic-secrets ctx` or the `--env/--tenant/--team` flags (pass `--team _` to drop the team segment) and optionally point at a different dev store with `--store-path` or the broker API with `--broker-url`/`--token`.
- `greentic-secrets admin login` lets a provider hook in custom auth (no-op for the dev provider).
- `greentic-secrets admin list` enumerates secrets for the current scope; pass `--prefix category[/name]` to filter, `--json` for machine output, and use `--broker-url`/`--token` when talking to a remote broker.
- `greentic-secrets admin set --category configs --name db_url --format text --value 'postgres://...'` upserts a secret. Use `--value-file` to read bytes from disk, `--format bytes` together with base64 input, and `--visibility tenant` / `--description` as needed.
- `greentic-secrets admin delete --category configs --name db_url` deletes the secret at the given scope.

See `docs/seed-format.md` for the seed schema used by scaffold/wizard/apply.

### Providers (opt-in features)
Enable only what you deploy to:

```toml
# Direct dependency on the core crate plus a provider
greentic-secrets-core = "0.1"
greentic-secrets-provider-dev = "0.1"

# Or via the umbrella crate re-exports
greentic-secrets-lib = { version = "0.1", features = ["providers-dev"] }
```

```rust
// Direct core + provider crates
use greentic_secrets_core::SecretsCore;
use greentic_secrets_provider_dev_env::DevBackend;

# tokio::runtime::Runtime::new().unwrap().block_on(async {
let core = SecretsCore::builder()
    .with_backend("dev-env", DevBackend::new())
    .build()
    .await
    .unwrap();
# });

// Umbrella crate re-export
use greentic_secrets_lib::core::SecretsCore as UmbrellaCore;
use greentic_secrets_lib::dev::DevBackend as UmbrellaDevBackend;

# tokio::runtime::Runtime::new().unwrap().block_on(async {
let umbrella_core = UmbrellaCore::builder()
    .with_backend("dev-env", UmbrellaDevBackend::new())
    .build()
    .await
    .unwrap();
# });
```

## Embedded usage

```rust
use secrets_core::SecretsCore;
use std::time::Duration;

# tokio::runtime::Runtime::new().unwrap().block_on(async {
let core = SecretsCore::builder()
    .tenant("example-tenant")
    .default_ttl(Duration::from_secs(600))
    .build()
    .await
    .unwrap();

let pwd = core
    .get_text("secrets://dev/example-tenant/_/configs/db_password")
    .await;
println!("db_password: {:?}", pwd);
# });
```

See [`docs/embedded.md`](docs/embedded.md) for builder options, environment
variables, invalidation semantics, and end-to-end examples (including WASM host
export).

For backend mapping rules see [`docs/backends.md`](docs/backends.md); policy
notes live under [`docs/policy.md`](docs/policy.md). Operator-focused guidance
is captured in [`docs/security.md`](docs/security.md) and
[`docs/rotation.md`](docs/rotation.md). Events/messaging provider naming and
helper APIs are documented in [`docs/events_messaging_secrets.md`](docs/events_messaging_secrets.md).
Signing key reference helpers (no signing logic) are documented in
[`docs/signing_key_refs.md`](docs/signing_key_refs.md).
API key reference helpers for store/distributor/billing are in
[`docs/api_key_refs.md`](docs/api_key_refs.md).

## Component publishing

Build all wasm components and refresh digests:

```bash
bash scripts/build-components.sh
```

Build or publish only the audit exporter component:

```bash
COMPONENT_FILTER=greentic.secrets.audit_exporter bash scripts/build-components.sh
COMPONENT_FILTER=greentic.secrets.audit_exporter bash scripts/publish-components.sh
```

When building provider packs, the shared audit exporter component is prebuilt automatically if its digest is missing. Override with:

```bash
PREBUILD_COMPONENTS=0 bash scripts/build-provider-packs.sh
SHARED_COMPONENT_FILTER=greentic.secrets.audit_exporter bash scripts/build-provider-packs.sh
```

Published provider packs use both immutable version tags and `latest`:

```bash
ghcr.io/greenticai/packs/secrets/providers:<version>
ghcr.io/greenticai/packs/secrets/providers:latest
ghcr.io/greenticai/packs/secrets/aws-sm:<version>
ghcr.io/greenticai/packs/secrets/aws-sm:latest
```

The publish workflows push each `dist/packs/secrets-<provider>.gtpack` artifact
to `ghcr.io/<org>/packs/secrets/<provider>:<version>` and
`ghcr.io/<org>/packs/secrets/<provider>:latest`. The
`dist/packs/secrets-providers.gtpack` bundle is published as
`ghcr.io/<org>/packs/secrets/providers:<version>` and
`ghcr.io/<org>/packs/secrets/providers:latest`.

## Self-described secrets

Libraries can publish their required secrets by implementing
`SecretDescribable` and returning a static slice of `SecretSpec`. This allows
tooling to enumerate dependencies without instantiating the runtime core.

```rust
use secrets_core::{SecretDescribable, SecretSpec};

struct PaymentsSecrets;

impl SecretDescribable for PaymentsSecrets {
    fn secret_specs() -> &'static [SecretSpec] {
        &[SecretSpec {
            name: "PAYMENTS_API_TOKEN",
            description: Some("Token used to authenticate outbound payment calls"),
        }]
    }
}

let mut registry = secrets_core::SecretSpecRegistry::new();
registry.extend_with(PaymentsSecrets::secret_specs());
println!("{}", registry.to_markdown_table());

let validation = core
    .validate_specs_at_prefix("secrets://dev/example-tenant/_/", PaymentsSecrets::secret_specs())
    .await?;
if !validation.missing.is_empty() {
    eprintln!("missing secrets: {:?}", validation.missing);
}
```

## Runner policy & environment bindings

The workspace ships with `greentic-secrets-runner`, a small host bridge that
exposes `secrets.get` backed by the local environment. Access is denied unless
the tenant appears in a JSON allowlist, giving operators a deny-by-default
posture.

```json
{
  "tenants": {
    "acme": { "allow_env": ["TELEGRAM_BOT_TOKEN"] }
  },
  "global": { "allow_env": ["SENTRY_DSN"] }
}
```

```rust
use greentic_secrets_runner::{Bindings, TenantBinding, TenantCtx, secrets_get};

let bindings = Bindings::default()
    .with_tenant("acme", TenantBinding::new(["TELEGRAM_BOT_TOKEN"]));
let ctx = TenantCtx::new("prod", "acme");

let token = secrets_get(&bindings, "TELEGRAM_BOT_TOKEN", Some(&ctx))?;
assert_eq!(token, "actual-secret");
```

Secrets missing from the allowlist surface a stable `denied` error code. This
policy layer also prepares the runner to front future cloud backends—swap out
the environment provider for Vault, AWS, or GCP while reusing the same
allowlist configuration.

## Broker

The broker remains available for HTTP and NATS workflows. Build it with the
backend features you need and run it alongside your existing infrastructure.

## Releases & Publishing

Versions are sourced directly from each crate’s `Cargo.toml`. Every push to `master` checks for version bumps: if a crate changed, the workflow tags the commit as `<crate-name>-v<version>` and pushes the tag. The publish job then runs `cargo fmt`, `cargo clippy`, a full workspace build, and `cargo test` before invoking `katyo/publish-crates@v2`, which publishes only crates with new versions. Re-running on the same commit is safe: existing tags are skipped and already published versions short-circuit cleanly.

## Releasing

We publish workspace crates to crates.io via GitHub Actions:

- **Bump versions** in each `Cargo.toml` you want to release (or use your preferred versioning tool).
- **Tag the repo**: `git tag v0.1.3 && git push --tags`.
- CI publishes only crates whose new version isn’t yet on crates.io (in dependency order) and creates a GitHub Release.
- To validate before tagging, open a PR and check **“Check crates (package dry-run)”**.
- To publish one crate manually (e.g., a provider), use the **“Publish one crate”** workflow from the Actions tab.
- You can automate the bump/tag/push flow with `scripts/release.sh X.Y.Z`, which runs `cargo workspaces version`, dry-run packaging, regenerates `CHANGELOG.md`, and pushes the release tag.

Make sure the repository has the `CARGO_REGISTRY_TOKEN` secret set (crates.io → Account → New token).
