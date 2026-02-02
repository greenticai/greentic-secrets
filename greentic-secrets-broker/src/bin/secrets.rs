use std::process;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use secrets_core::{CoreBuilder, SecretDescribable, SecretSpecRegistry};

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
    /// Environment segment for the prefix (e.g. dev, prod)
    #[arg(long, default_value = "dev")]
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

    let base_prefix = format!("secrets://{env}/{tenant}/{team}/");
    let result = core
        .validate_specs_at_prefix(&base_prefix, &specs)
        .await
        .context("failed to validate specs against backend")?;

    if result.missing.is_empty() {
        println!("All secrets present");
        return Ok(());
    }

    eprintln!("Missing secrets: {}", result.missing.join(", "));
    process::exit(2);
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
