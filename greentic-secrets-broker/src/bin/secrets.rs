use std::process;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use secrets_core::{CoreBuilder, SecretDescribable, SecretSpec, SecretSpecRegistry};

/// Canonical environment identifier after A4b (`plans/next-gen-deployment.md`).
const DEFAULT_ENV_ID: &str = "local";
/// Legacy identifier — entries written before the A4b default flip remain
/// accepted by `specs check` for one release with a migration nudge.
const LEGACY_ENV_ID: &str = "dev";

/// Latches the legacy-prefix migration warning to a single emission per process.
static LEGACY_FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

mod telegram {
    include!("../../examples/plugins/telegram_secrets.rs");
}

mod weather {
    include!("../../examples/plugins/weather_secrets.rs");
}

#[derive(Parser)]
#[command(
    name = "secrets",
    version,
    about = "Inspect and validate secret specifications"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Specs {
        #[command(subcommand)]
        command: SpecsCommand,
    },
}

#[derive(Subcommand)]
enum SpecsCommand {
    Print(PrintArgs),
    Check(CheckArgs),
    Schema(SchemaArgs),
}

#[derive(Args)]
struct PrintArgs {
    /// Output format (`md` or `json`)
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Markdown)]
    format: OutputFormat,
    /// Limit to specific components (comma separated)
    #[arg(long, value_delimiter = ',')]
    components: Vec<Component>,
}

#[derive(Args)]
struct CheckArgs {
    /// Environment segment for the prefix (e.g. local, prod). Defaults to
    /// `local` per A4b — the legacy `dev` value is still accepted but
    /// downstream consumers route it through the dev→local compat alias
    /// in `greentic-setup` / `greentic-start`. When env resolves to `local`,
    /// any missing secret is also probed under `secrets://dev/...` with a
    /// one-time migration nudge.
    #[arg(long, default_value = DEFAULT_ENV_ID)]
    env: String,
    /// Tenant segment for the prefix
    #[arg(long)]
    tenant: String,
    /// Team segment for the prefix (use `_` for none)
    #[arg(long, default_value = "_")]
    team: String,
    /// Limit validation to specific components (comma separated)
    #[arg(long, value_delimiter = ',')]
    components: Vec<Component>,
}

#[derive(Args)]
struct SchemaArgs {
    /// Limit schema to specific components (comma separated)
    #[arg(long, value_delimiter = ',')]
    components: Vec<Component>,
    /// Pretty-print the schema output
    #[arg(long)]
    pretty: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    #[value(alias = "md")]
    Markdown,
    Json,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, ValueEnum)]
enum Component {
    Telegram,
    Weather,
}

#[greentic_types::telemetry::main(service_name = "greentic-secrets")]
async fn main() {
    if let Err(err) = real_main().await {
        eprintln!("secrets CLI failed: {err:#}");
        process::exit(1);
    }
}

async fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Specs { command } => match command {
            SpecsCommand::Print(args) => handle_print(args),
            SpecsCommand::Check(args) => handle_check(args).await,
            SpecsCommand::Schema(args) => handle_schema(args),
        },
    }
}

fn handle_print(args: PrintArgs) -> Result<()> {
    let components = resolve_components(args.components);
    let registry = build_registry(&components);
    match args.format {
        OutputFormat::Json => println!("{}", registry.to_json()),
        OutputFormat::Markdown => print!("{}", registry.to_markdown_table()),
    }
    Ok(())
}

fn handle_schema(args: SchemaArgs) -> Result<()> {
    let components = resolve_components(args.components);
    let registry = build_registry(&components);
    let schema = secrets_core::specs_to_json_schema(registry.all());
    if args.pretty {
        println!("{}", serde_json::to_string_pretty(&schema)?);
    } else {
        println!("{schema}");
    }
    Ok(())
}

async fn handle_check(args: CheckArgs) -> Result<()> {
    let CheckArgs {
        env,
        tenant,
        team,
        components,
    } = args;
    let components = resolve_components(components);
    let registry = build_registry(&components);
    let specs: Vec<_> = registry.all().cloned().collect();

    let dev_backend = secrets_provider_dev::DevBackend::from_env()
        .context("failed to configure development backend")?;
    let dev_key_provider = secrets_provider_dev::DevKeyProvider::from_env();

    let mut builder = CoreBuilder::default().backend(dev_backend, dev_key_provider);
    builder = builder.tenant(tenant.clone());
    if team != "_" {
        builder = builder.team(team.clone());
    }

    let core = builder
        .build()
        .await
        .context("failed to initialise secrets core")?;

    let (result, legacy_present) =
        validate_with_legacy_fallback(&core, &env, &tenant, &team, &specs).await?;

    if !legacy_present.is_empty() {
        warn_legacy_dev_once(&legacy_present);
    }

    if result.missing.is_empty() {
        println!("All secrets present");
        return Ok(());
    }

    eprintln!("Missing secrets: {}", result.missing.join(", "));
    process::exit(2);
}

/// Validate `specs` under `secrets://{env}/{tenant}/{team}/`. When `env` equals
/// the canonical default ([`DEFAULT_ENV_ID`]) and any specs are missing, re-probe
/// the misses under `secrets://{LEGACY_ENV_ID}/...` so dev-stores written before
/// the A4b default flip still validate. Returns the merged result plus the list
/// of spec names that resolved only through the legacy prefix (drives the
/// migration warn).
async fn validate_with_legacy_fallback(
    core: &secrets_core::SecretsCore,
    env: &str,
    tenant: &str,
    team: &str,
    specs: &[SecretSpec],
) -> Result<(secrets_core::SecretValidationResult, Vec<&'static str>)> {
    let base_prefix = format!("secrets://{env}/{tenant}/{team}/");
    let mut result = core
        .validate_specs_at_prefix(&base_prefix, specs)
        .await
        .context("failed to validate specs against backend")?;

    let mut legacy_present: Vec<&'static str> = Vec::new();
    if env == DEFAULT_ENV_ID && !result.missing.is_empty() {
        let legacy_prefix = format!("secrets://{LEGACY_ENV_ID}/{tenant}/{team}/");
        let missing_specs: Vec<SecretSpec> = specs
            .iter()
            .filter(|spec| result.missing.contains(&spec.name))
            .cloned()
            .collect();
        let legacy = core
            .validate_specs_at_prefix(&legacy_prefix, &missing_specs)
            .await
            .context("failed to validate specs against legacy `dev` prefix")?;

        for name in legacy.present {
            result.missing.retain(|m| m != &name);
            result.present.push(name);
            legacy_present.push(name);
        }
    }

    Ok((result, legacy_present))
}

fn warn_legacy_dev_once(names: &[&'static str]) {
    if LEGACY_FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
        return;
    }
    let joined = names.join(", ");
    let message = format!(
        "secrets specs check: {count} secret(s) resolved from legacy `secrets://{LEGACY_ENV_ID}/...` \
         prefix after env default flipped to `{DEFAULT_ENV_ID}` (A4b). \
         Migrate with `gtc op env migrate-dev --apply --target {DEFAULT_ENV_ID}`. \
         Names: [{joined}]",
        count = names.len(),
    );
    tracing::warn!(
        target: "greentic_secrets::compat",
        legacy_count = names.len(),
        legacy_names = %joined,
        "{message}"
    );
    eprintln!("warning: {message}");
}

fn resolve_components(mut components: Vec<Component>) -> Vec<Component> {
    if components.is_empty() {
        return Component::value_variants().to_vec();
    }
    components.sort();
    components.dedup();
    components
}

fn build_registry(components: &[Component]) -> SecretSpecRegistry {
    let mut registry = SecretSpecRegistry::new();
    for component in components {
        register_specs(component, &mut registry);
    }
    registry
}

fn register_specs(component: &Component, registry: &mut SecretSpecRegistry) {
    match component {
        Component::Telegram => registry.extend_with(telegram::TelegramSecrets::secret_specs()),
        Component::Weather => registry.extend_with(weather::WeatherSecrets::secret_specs()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TENANT: &str = "compat-tenant";
    const SPEC_PRESENT: SecretSpec = SecretSpec {
        name: "alpha-token",
        description: None,
    };
    const SPEC_MISSING: SecretSpec = SecretSpec {
        name: "beta-token",
        description: None,
    };

    async fn build_test_core() -> secrets_core::SecretsCore {
        let backend = secrets_provider_dev::DevBackend::new();
        let key_provider = secrets_provider_dev::DevKeyProvider::from_material(b"unit-test-key");
        CoreBuilder::default()
            .backend(backend, key_provider)
            .tenant(TEST_TENANT)
            .build()
            .await
            .expect("build SecretsCore")
    }

    #[tokio::test]
    async fn legacy_fallback_promotes_dev_entries_when_env_is_default() {
        let core = build_test_core().await;
        core.put_json(
            &format!(
                "secrets://{LEGACY_ENV_ID}/{TEST_TENANT}/_/configs/{}",
                SPEC_PRESENT.name
            ),
            &"v1",
        )
        .await
        .expect("seed legacy entry");

        let specs = [SPEC_PRESENT, SPEC_MISSING];
        let (result, legacy) =
            validate_with_legacy_fallback(&core, DEFAULT_ENV_ID, TEST_TENANT, "_", &specs)
                .await
                .expect("validate");

        assert_eq!(legacy, vec![SPEC_PRESENT.name]);
        assert!(result.present.contains(&SPEC_PRESENT.name));
        assert_eq!(result.missing, vec![SPEC_MISSING.name]);
    }

    #[tokio::test]
    async fn legacy_fallback_skipped_for_non_default_env() {
        let core = build_test_core().await;
        core.put_json(
            &format!(
                "secrets://{LEGACY_ENV_ID}/{TEST_TENANT}/_/configs/{}",
                SPEC_PRESENT.name
            ),
            &"v1",
        )
        .await
        .expect("seed legacy entry");

        let specs = [SPEC_PRESENT];
        let (result, legacy) =
            validate_with_legacy_fallback(&core, "prod", TEST_TENANT, "_", &specs)
                .await
                .expect("validate");

        // env != "local" → legacy is not probed; the secret is missing under prod.
        assert!(legacy.is_empty());
        assert_eq!(result.missing, vec![SPEC_PRESENT.name]);
    }

    #[tokio::test]
    async fn legacy_fallback_no_op_when_canonical_prefix_satisfies_specs() {
        let core = build_test_core().await;
        core.put_json(
            &format!(
                "secrets://{DEFAULT_ENV_ID}/{TEST_TENANT}/_/configs/{}",
                SPEC_PRESENT.name
            ),
            &"v1",
        )
        .await
        .expect("seed canonical entry");

        let specs = [SPEC_PRESENT];
        let (result, legacy) =
            validate_with_legacy_fallback(&core, DEFAULT_ENV_ID, TEST_TENANT, "_", &specs)
                .await
                .expect("validate");

        assert!(legacy.is_empty());
        assert!(result.missing.is_empty());
        assert_eq!(result.present, vec![SPEC_PRESENT.name]);
    }
}
