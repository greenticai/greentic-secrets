mod admin;
use admin::{AdminClient, AdminDeleteRequest, AdminScope, AdminSetRequest, build_client};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use greentic_config::{CliOverrides as ConfigOverrides, ConfigResolver, ResolvedConfig};
use greentic_config_types::{EnvId, GreenticConfig, NetworkConfig, TlsMode};
use greentic_secrets_core::seed::{
    ApplyOptions, ApplyReport, DevContext, DevStore, HttpStore, SecretsStore, apply_seed,
    resolve_uri_with_category,
};
use greentic_secrets_core::types::Visibility;
use greentic_secrets_spec::{SeedDoc, SeedEntry, SeedValue};
use greentic_types::decode_pack_manifest;
use greentic_types::secrets::{SecretFormat, SecretRequirement};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zip::ZipArchive;

#[derive(Parser)]
#[command(name = "greentic-secrets", version, about = "Greentic secrets CLI")]
struct Cli {
    #[command(flatten)]
    config: GlobalConfigOpts,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Default)]
struct GlobalConfigOpts {
    /// Override config file path (replaces project config)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override environment id
    #[arg(long)]
    env: Option<String>,
    /// Override tenant id
    #[arg(long)]
    tenant: Option<String>,
    /// Override team id
    #[arg(long)]
    team: Option<String>,
    /// Override greentic root directory
    #[arg(long)]
    greentic_root: Option<PathBuf>,
    /// Override state directory
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Verbose output (prints config source)
    #[arg(long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Dev(DevCmd),
    #[command(subcommand)]
    Ctx(CtxCmd),
    #[command(subcommand)]
    Admin(AdminCmd),
    Scaffold(ScaffoldCmd),
    Wizard(WizardCmd),
    Apply(ApplyCmd),
    Init(InitCmd),
    #[command(subcommand)]
    Config(ConfigCmd),
}

#[derive(Subcommand)]
enum ConfigCmd {
    Show,
    Explain,
}

#[derive(Subcommand)]
enum DevCmd {
    Up {
        #[arg(long)]
        store_path: Option<PathBuf>,
    },
    Down {
        #[arg(long)]
        destroy: bool,
        #[arg(long)]
        store_path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CtxCmd {
    Set(CtxSetArgs),
    Show,
}

#[derive(Subcommand)]
enum AdminCmd {
    Login(AdminActionArgs),
    List(AdminListArgs),
    Set(AdminSetArgs),
    Delete(AdminDeleteArgs),
}

#[derive(Args)]
struct AdminScopeArgs {
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    team: Option<String>,
}

#[derive(Args, Default)]
struct AdminCommonArgs {
    #[arg(long)]
    broker_url: Option<String>,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    store_path: Option<PathBuf>,
}

#[derive(Args)]
struct AdminActionArgs {
    #[command(flatten)]
    scope: AdminScopeArgs,
    #[command(flatten)]
    common: AdminCommonArgs,
}

#[derive(Args)]
struct AdminListArgs {
    #[command(flatten)]
    action: AdminActionArgs,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(ValueEnum, Clone, Copy)]
enum AdminSecretFormat {
    Text,
    Json,
    Bytes,
}

impl From<AdminSecretFormat> for SecretFormat {
    fn from(value: AdminSecretFormat) -> Self {
        match value {
            AdminSecretFormat::Text => SecretFormat::Text,
            AdminSecretFormat::Json => SecretFormat::Json,
            AdminSecretFormat::Bytes => SecretFormat::Bytes,
        }
    }
}

#[derive(ValueEnum, Clone, Copy)]
enum AdminVisibilityArg {
    User,
    Team,
    Tenant,
}

impl From<AdminVisibilityArg> for Visibility {
    fn from(value: AdminVisibilityArg) -> Self {
        match value {
            AdminVisibilityArg::User => Visibility::User,
            AdminVisibilityArg::Team => Visibility::Team,
            AdminVisibilityArg::Tenant => Visibility::Tenant,
        }
    }
}

#[derive(Args)]
struct AdminSetArgs {
    #[command(flatten)]
    action: AdminActionArgs,
    #[arg(long)]
    category: String,
    #[arg(long)]
    name: String,
    #[arg(long, value_enum, default_value_t = AdminSecretFormat::Text)]
    format: AdminSecretFormat,
    #[arg(long, value_enum)]
    visibility: Option<AdminVisibilityArg>,
    #[arg(long)]
    description: Option<String>,
    #[arg(
        long,
        conflicts_with = "value_file",
        required_unless_present = "value_file"
    )]
    value: Option<String>,
    #[arg(
        long,
        value_name = "path",
        conflicts_with = "value",
        required_unless_present = "value"
    )]
    value_file: Option<PathBuf>,
}

#[derive(Args)]
struct AdminDeleteArgs {
    #[command(flatten)]
    action: AdminActionArgs,
    #[arg(long)]
    category: String,
    #[arg(long)]
    name: String,
}

#[derive(Args)]
struct CtxSetArgs {
    #[arg(long)]
    env: String,
    #[arg(long)]
    tenant: String,
    #[arg(long)]
    team: Option<String>,
}

#[derive(Args)]
struct ScaffoldCmd {
    #[arg(long)]
    pack: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    team: Option<String>,
}

#[derive(Args)]
struct WizardCmd {
    #[arg(short = 'i', long)]
    input: PathBuf,
    #[arg(short = 'o', long)]
    output: PathBuf,
    #[arg(long = "from-dotenv")]
    from_dotenv: Option<PathBuf>,
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Args)]
struct ApplyCmd {
    #[arg(short = 'f', long)]
    file: PathBuf,
    #[arg(long)]
    pack: Option<PathBuf>,
    #[arg(long)]
    store_path: Option<PathBuf>,
    #[arg(long)]
    broker_url: Option<String>,
    #[arg(long)]
    token: Option<String>,
}

#[derive(Args)]
struct InitCmd {
    #[arg(long)]
    pack: PathBuf,
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    team: Option<String>,
    #[arg(long = "from-dotenv")]
    from_dotenv: Option<PathBuf>,
    #[arg(long)]
    non_interactive: bool,
    #[arg(long)]
    store_path: Option<PathBuf>,
    #[arg(long)]
    seed_out: Option<PathBuf>,
    #[arg(long)]
    broker_url: Option<String>,
    #[arg(long)]
    token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CtxFile {
    env: String,
    tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    team: Option<String>,
}

#[derive(Default)]
struct CtxOverrides {
    env: Option<String>,
    tenant: Option<String>,
    team: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let resolved = resolve_config(&cli)?;
    if cli.config.verbose {
        println!(
            "config loaded (root={}, state_dir={}, sources={:?})",
            resolved.config.paths.greentic_root.display(),
            resolved.config.paths.state_dir.display(),
            resolved.provenance
        );
        for warning in &resolved.warnings {
            eprintln!("warning: {warning}");
        }
    }

    match cli.command {
        Command::Dev(cmd) => handle_dev(cmd, &resolved.config),
        Command::Ctx(cmd) => handle_ctx(cmd, &resolved.config),
        Command::Admin(cmd) => handle_admin(cmd, &resolved),
        Command::Scaffold(cmd) => handle_scaffold(cmd, &resolved),
        Command::Wizard(cmd) => handle_wizard(cmd, &resolved),
        Command::Apply(cmd) => handle_apply(cmd, &resolved),
        Command::Init(cmd) => handle_init(cmd, &resolved),
        Command::Config(cmd) => handle_config_cmd(cmd, &resolved),
    }
}

fn resolve_config(cli: &Cli) -> Result<ResolvedConfig> {
    let mut overrides = ConfigOverrides::new();
    if let Some(env) = cli
        .config
        .env
        .as_deref()
        .and_then(|value| EnvId::try_from(value).ok())
    {
        overrides = overrides.with_env_id(env);
    }
    let mut resolver = ConfigResolver::new();
    if let Some(path) = cli.config.config.clone() {
        resolver = resolver.with_config_path(path);
    }
    resolver.with_cli_overrides_typed(overrides).load()
}

fn handle_config_cmd(cmd: ConfigCmd, resolved: &ResolvedConfig) -> Result<()> {
    match cmd {
        ConfigCmd::Show => {
            println!("{}", toml::to_string_pretty(&resolved.config)?);
        }
        ConfigCmd::Explain => {
            let report = resolved.explain();
            println!("{report:?}");
        }
    }
    Ok(())
}

fn handle_dev(cmd: DevCmd, cfg: &GreenticConfig) -> Result<()> {
    let store_path = dev_store_path(cfg);
    match cmd {
        DevCmd::Up {
            store_path: override_path,
        } => {
            let path = override_path.unwrap_or_else(|| store_path.clone());
            ensure_parent(&path)?;
            let _store = DevStore::with_path(&path).context("failed to prepare dev store")?;
            println!("Dev store ready at {}", path.display());
        }
        DevCmd::Down {
            destroy,
            store_path: override_path,
        } => {
            let path = override_path.unwrap_or(store_path);
            if destroy && path.exists() {
                fs::remove_file(&path).context("failed to remove dev store")?;
                println!("Removed dev store {}", path.display());
            } else {
                println!(
                    "Nothing to do (pass --destroy to remove {})",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

fn handle_ctx(cmd: CtxCmd, cfg: &GreenticConfig) -> Result<()> {
    let path = ctx_path(cfg);
    match cmd {
        CtxCmd::Set(args) => {
            let ctx = CtxFile {
                env: args.env,
                tenant: args.tenant,
                team: args.team,
            };
            write_ctx(&ctx, &path)?;
            println!("Context saved to {}", path.display());
        }
        CtxCmd::Show => {
            let ctx = read_ctx(&path).context("ctx not set; run ctx set")?;
            println!("env={}", ctx.env);
            println!("tenant={}", ctx.tenant);
            println!("team={}", ctx.team.as_deref().unwrap_or("_"));
        }
    }
    Ok(())
}

fn handle_admin(cmd: AdminCmd, resolved: &ResolvedConfig) -> Result<()> {
    let ctx_file = read_ctx(&ctx_path(&resolved.config)).ok();
    match cmd {
        AdminCmd::Login(action) => {
            let scope = admin_scope_from_args(&action.scope, resolved, ctx_file.as_ref())?;
            let mut client = build_admin_client(&action.common, resolved)?;
            client.login()?;
            println!("Logged in for {} tenant {}", scope.env, scope.tenant);
        }
        AdminCmd::List(args) => {
            let scope = admin_scope_from_args(&args.action.scope, resolved, ctx_file.as_ref())?;
            let mut client = build_admin_client(&args.action.common, resolved)?;
            let backend_desc = describe_admin_backend(&args.action.common, resolved);
            println!("Secrets backend: {backend_desc}");
            let items = client.list(&scope, args.prefix.as_deref())?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else if items.is_empty() {
                println!("no secrets found");
            } else {
                for item in items {
                    println!(
                        "{} [{:?}] {:?} {}",
                        item.uri,
                        item.visibility,
                        item.content_type,
                        item.latest_version.as_deref().unwrap_or("n/a")
                    );
                }
            }
        }
        AdminCmd::Set(args) => {
            let scope = admin_scope_from_args(&args.action.scope, resolved, ctx_file.as_ref())?;
            let mut client = build_admin_client(&args.action.common, resolved)?;
            let bytes = admin_value_bytes(&args)?;
            let result = client.set(AdminSetRequest {
                scope,
                category: args.category.clone(),
                name: args.name.clone(),
                format: SecretFormat::from(args.format),
                visibility: args.visibility.unwrap_or(AdminVisibilityArg::Tenant).into(),
                description: args.description.clone(),
                value: bytes,
            })?;
            println!("written {} (version {})", result.uri, result.version);
        }
        AdminCmd::Delete(args) => {
            let scope = admin_scope_from_args(&args.action.scope, resolved, ctx_file.as_ref())?;
            let mut client = build_admin_client(&args.action.common, resolved)?;
            let result = client.delete(AdminDeleteRequest {
                scope,
                category: args.category.clone(),
                name: args.name.clone(),
            })?;
            println!("deleted {} (version {})", result.uri, result.version);
        }
    }
    Ok(())
}

fn admin_scope_from_args(
    args: &AdminScopeArgs,
    resolved: &ResolvedConfig,
    ctx_file: Option<&CtxFile>,
) -> Result<AdminScope> {
    let drop_team = matches!(args.team.as_deref(), Some("_"));
    let overrides = CtxOverrides {
        env: args.env.clone(),
        tenant: args.tenant.clone(),
        team: if drop_team { None } else { args.team.clone() },
    };
    let mut ctx = resolve_ctx(&resolved.config, ctx_file, &overrides)
        .context("ctx not set; run `ctx set` or pass --env/--tenant")?;
    if drop_team {
        ctx.team = None;
    }
    let team = ctx.team.filter(|value| value != "_");
    Ok(AdminScope {
        env: ctx.env,
        tenant: ctx.tenant,
        team,
    })
}

fn build_admin_client(
    common: &AdminCommonArgs,
    resolved: &ResolvedConfig,
) -> Result<Box<dyn AdminClient>> {
    let store_path = common
        .store_path
        .clone()
        .unwrap_or_else(|| dev_store_path(&resolved.config));
    build_client(
        resolved.config.secrets.kind.as_str(),
        store_path,
        common.broker_url.clone(),
        common.token.clone(),
    )
}

fn describe_admin_backend(common: &AdminCommonArgs, resolved: &ResolvedConfig) -> String {
    let kind = resolved.config.secrets.kind.as_str();
    match kind {
        "dev" | "none" => {
            let store_path = common
                .store_path
                .clone()
                .unwrap_or_else(|| dev_store_path(&resolved.config));
            if kind == "none" {
                format!("secrets.kind=none (dev store at {})", store_path.display())
            } else {
                format!("dev store at {}", store_path.display())
            }
        }
        _ => {
            let broker_url = common
                .broker_url
                .as_deref()
                .unwrap_or("<unspecified broker URL>");
            format!("secrets.kind={} (broker at {})", kind, broker_url)
        }
    }
}

fn admin_value_bytes(args: &AdminSetArgs) -> Result<Vec<u8>> {
    if let Some(path) = args.value_file.as_deref() {
        return fs::read(path).with_context(|| format!("read value file {}", path.display()));
    }
    let value = args
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("value must be provided"))?;
    if matches!(args.format, AdminSecretFormat::Bytes) {
        STANDARD_NO_PAD
            .decode(value)
            .context("value must be base64 when format=bytes")
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

fn handle_scaffold(cmd: ScaffoldCmd, resolved: &ResolvedConfig) -> Result<()> {
    let ctx_file = read_ctx(&ctx_path(&resolved.config)).ok();
    let ctx = resolve_ctx(
        &resolved.config,
        ctx_file.as_ref(),
        &CtxOverrides {
            env: cmd.env.clone(),
            tenant: cmd.tenant.clone(),
            team: cmd.team.clone(),
        },
    )?;
    let requirements = read_pack_requirements(&cmd.pack)?;
    let category = requirements.pack_id.as_deref().unwrap_or("configs");
    let entries = requirements
        .secret_requirements
        .iter()
        .map(|req| scaffold_entry(&ctx, req, category))
        .collect();
    let doc = SeedDoc { entries };
    write_seed(&doc, &cmd.out)?;
    println!("Wrote scaffold to {}", cmd.out.display());
    Ok(())
}

fn handle_wizard(cmd: WizardCmd, _resolved: &ResolvedConfig) -> Result<()> {
    let mut doc = read_seed(&cmd.input)?;
    let dotenv = if let Some(path) = cmd.from_dotenv.as_ref() {
        Some(read_dotenv(path)?)
    } else {
        None
    };

    for entry in &mut doc.entries {
        let key = env_key_for_entry(entry);
        if let Some(map) = &dotenv
            && let Some(value) = map.get(&key)
        {
            fill_entry_from_str(entry, value)?;
            continue;
        }

        if cmd.non_interactive {
            continue;
        }

        println!("Value for {} ({:?})", entry.uri, entry.format);
        print!("> ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        fill_entry_from_str(entry, &trimmed)?;
    }

    write_seed(&doc, &cmd.output)?;
    println!("Wrote {}", cmd.output.display());
    Ok(())
}

fn handle_apply(cmd: ApplyCmd, resolved: &ResolvedConfig) -> Result<()> {
    let seed = read_seed(&cmd.file)?;
    let requirements = match cmd.pack {
        Some(path) => Some(read_pack_requirements(&path)?.secret_requirements),
        None => None,
    };
    let store: Box<dyn SecretsStore> = match cmd.broker_url {
        Some(url) => {
            ensure_online(&resolved.config.network, "broker apply")?;
            let client = build_http_client(&resolved.config.network)?;
            Box::new(HttpStore::with_client(client, url, cmd.token))
        }
        None => {
            let kind = resolved.config.secrets.kind.as_str();
            if kind != "dev" && kind != "none" {
                anyhow::bail!(
                    "secrets.kind={} requires --broker-url (or set secrets.kind=dev)",
                    resolved.config.secrets.kind
                );
            }
            if kind == "none" {
                eprintln!("warning: secrets.kind=none; using dev store for CLI apply");
            }
            Box::new(
                DevStore::with_path(
                    cmd.store_path
                        .unwrap_or_else(|| dev_store_path(&resolved.config)),
                )
                .context("failed to open dev store")?,
            )
        }
    };
    let options = ApplyOptions {
        requirements: requirements.as_deref(),
        ..ApplyOptions::default()
    };
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { apply_seed(store.as_ref(), &seed, options).await });
    print_report(&report);
    if report.failed.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("apply completed with failures"))
    }
}

fn handle_init(cmd: InitCmd, resolved: &ResolvedConfig) -> Result<()> {
    handle_dev(
        DevCmd::Up {
            store_path: cmd.store_path.clone(),
        },
        &resolved.config,
    )?;

    let ctx_file_path = ctx_path(&resolved.config);
    if read_ctx(&ctx_file_path).is_err() {
        let ctx = resolve_ctx(
            &resolved.config,
            None,
            &CtxOverrides {
                env: cmd.env.clone(),
                tenant: cmd.tenant.clone(),
                team: cmd.team.clone(),
            },
        )?;
        write_ctx(&ctx, &ctx_file_path)?;
        println!("Context written to {}", ctx_file_path.display());
    }

    let seed_out = cmd
        .seed_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("seeds.yaml"));

    handle_scaffold(
        ScaffoldCmd {
            pack: cmd.pack.clone(),
            out: seed_out.clone(),
            env: cmd.env.clone(),
            tenant: cmd.tenant.clone(),
            team: cmd.team.clone(),
        },
        resolved,
    )?;

    if cmd.non_interactive {
        handle_wizard(
            WizardCmd {
                input: seed_out.clone(),
                output: seed_out.clone(),
                from_dotenv: cmd.from_dotenv.clone(),
                non_interactive: true,
            },
            resolved,
        )?;
    } else {
        handle_wizard(
            WizardCmd {
                input: seed_out.clone(),
                output: seed_out.clone(),
                from_dotenv: cmd.from_dotenv.clone(),
                non_interactive: false,
            },
            resolved,
        )?;
    }

    handle_apply(
        ApplyCmd {
            file: seed_out,
            pack: Some(cmd.pack),
            store_path: cmd.store_path,
            broker_url: cmd.broker_url,
            token: cmd.token,
        },
        resolved,
    )
}

fn scaffold_entry(ctx: &CtxFile, req: &SecretRequirement, category: &str) -> SeedEntry {
    let uri = resolve_uri_with_category(
        &DevContext::new(&ctx.env, &ctx.tenant, ctx.team.clone()),
        req,
        category,
    );
    let placeholder = placeholder_value(req);
    let format = req.format.clone().unwrap_or(SecretFormat::Text);

    SeedEntry {
        uri,
        format,
        description: req.description.clone(),
        value: placeholder,
    }
}

fn placeholder_value(req: &SecretRequirement) -> SeedValue {
    let format = req.format.clone().unwrap_or(SecretFormat::Text);

    if let Some(first) = req.examples.first() {
        return match format {
            SecretFormat::Text => SeedValue::Text {
                text: first.clone(),
            },
            SecretFormat::Json => SeedValue::Json {
                json: serde_json::from_str(first)
                    .unwrap_or_else(|_| serde_json::Value::String(first.clone())),
            },
            SecretFormat::Bytes => SeedValue::BytesB64 {
                bytes_b64: STANDARD.encode(first.as_bytes()),
            },
        };
    }

    match format {
        SecretFormat::Text => SeedValue::Text {
            text: String::new(),
        },
        SecretFormat::Json => SeedValue::Json { json: json!({}) },
        SecretFormat::Bytes => SeedValue::BytesB64 {
            bytes_b64: String::new(),
        },
    }
}

fn read_pack_requirements(path: &Path) -> Result<PackRequirements> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read pack {}", path.display()))?;

    if looks_like_zip(&bytes) {
        return read_gtpack_zip(&bytes);
    }

    if let Ok(meta) = serde_json::from_slice::<PackMetadata>(&bytes) {
        return Ok(PackRequirements {
            secret_requirements: meta.secret_requirements,
            pack_id: meta.pack_id,
        });
    }
    let meta: PackMetadata =
        serde_yaml::from_slice(&bytes).context("pack is not valid JSON/YAML or .gtpack zip")?;
    Ok(PackRequirements {
        secret_requirements: meta.secret_requirements,
        pack_id: meta.pack_id,
    })
}

struct PackRequirements {
    secret_requirements: Vec<SecretRequirement>,
    pack_id: Option<String>,
}

#[derive(Deserialize)]
struct PackMetadata {
    #[serde(default)]
    pack_id: Option<String>,
    #[serde(default)]
    secret_requirements: Vec<SecretRequirement>,
}

fn read_seed(path: &Path) -> Result<SeedDoc> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read seed file {}", path.display()))?;
    serde_yaml::from_slice(&bytes)
        .or_else(|_| serde_json::from_slice(&bytes))
        .context("failed to parse seed file")
}

fn write_seed(doc: &SeedDoc, path: &Path) -> Result<()> {
    ensure_parent(path)?;
    let data = serde_yaml::to_string(doc)?;
    fs::write(path, data)?;
    Ok(())
}

fn read_ctx(path: &Path) -> Result<CtxFile> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let text = String::from_utf8(bytes)?;
    parse_ctx(&text).context("invalid ctx file")
}

fn write_ctx(ctx: &CtxFile, path: &Path) -> Result<()> {
    ensure_parent(path)?;
    let data = format!(
        "env = \"{}\"\ntenant = \"{}\"\nteam = {}\n",
        ctx.env,
        ctx.tenant,
        ctx.team
            .as_ref()
            .map(|t| format!("\"{t}\""))
            .unwrap_or_else(|| "null".into())
    );
    fs::write(path, data)?;
    Ok(())
}

fn parse_ctx(raw: &str) -> Option<CtxFile> {
    let mut map = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    let env = map.get("env")?.to_string();
    let tenant = map.get("tenant")?.to_string();
    let team = map.get("team").and_then(|v| {
        if v == "null" {
            None
        } else {
            Some(v.to_string())
        }
    });
    Some(CtxFile { env, tenant, team })
}

fn resolve_ctx(
    cfg: &GreenticConfig,
    ctx_file: Option<&CtxFile>,
    overrides: &CtxOverrides,
) -> Result<CtxFile> {
    let env = overrides
        .env
        .clone()
        .or_else(|| ctx_file.map(|c| c.env.clone()))
        .or_else(|| cfg.dev.as_ref().map(|d| d.default_env.to_string()))
        .or_else(|| Some(cfg.environment.env_id.to_string()))
        .ok_or_else(|| anyhow::anyhow!("env must be provided"))?;

    let tenant = overrides
        .tenant
        .clone()
        .or_else(|| ctx_file.map(|c| c.tenant.clone()))
        .or_else(|| cfg.dev.as_ref().map(|d| d.default_tenant.clone()))
        .ok_or_else(|| anyhow::anyhow!("tenant must be provided"))?;

    let team = overrides
        .team
        .clone()
        .or_else(|| ctx_file.and_then(|c| c.team.clone()))
        .or_else(|| cfg.dev.as_ref().and_then(|d| d.default_team.clone()));

    Ok(CtxFile { env, tenant, team })
}

fn ctx_path(cfg: &GreenticConfig) -> PathBuf {
    cfg.paths.state_dir.join("secrets.toml")
}

fn dev_store_path(cfg: &GreenticConfig) -> PathBuf {
    cfg.paths.state_dir.join("dev/.dev.secrets.env")
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn build_http_client(network: &NetworkConfig) -> Result<Client> {
    let mut builder = Client::builder();
    if let Some(proxy) = &network.proxy_url {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    if let Some(connect_timeout) = network.connect_timeout_ms {
        builder = builder.connect_timeout(Duration::from_millis(connect_timeout));
    }
    if let Some(timeout) = network.read_timeout_ms {
        builder = builder.timeout(Duration::from_millis(timeout));
    }
    if matches!(network.tls_mode, TlsMode::Disabled) {
        bail!("tls_mode=disabled is not permitted");
    }
    builder.build().map_err(Into::into)
}

fn ensure_online(_: &NetworkConfig, _: &str) -> Result<()> {
    Ok(())
}

fn read_dotenv(path: &Path) -> Result<HashMap<String, String>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(map)
}

fn fill_entry_from_str(entry: &mut SeedEntry, value: &str) -> Result<()> {
    match entry.format {
        SecretFormat::Text => {
            entry.value = SeedValue::Text {
                text: value.to_string(),
            };
        }
        SecretFormat::Json => {
            let parsed: serde_json::Value =
                serde_json::from_str(value).context("value is not valid JSON")?;
            entry.value = SeedValue::Json { json: parsed };
        }
        SecretFormat::Bytes => {
            let _ = STANDARD
                .decode(value.as_bytes())
                .context("value must be base64")?;
            entry.value = SeedValue::BytesB64 {
                bytes_b64: value.to_string(),
            };
        }
    }
    Ok(())
}

fn env_key_for_entry(entry: &SeedEntry) -> String {
    entry
        .uri
        .split('/')
        .next_back()
        .map(|s| s.to_string())
        .unwrap_or_default()
}

fn print_report(report: &ApplyReport) {
    println!("Applied {} entries", report.ok);
    if report.failed.is_empty() {
        println!("All entries applied successfully");
    } else {
        println!("Failures:");
        for failure in &report.failed {
            println!("- {}: {}", failure.uri, failure.error);
        }
    }
}

fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'P') && bytes.get(1) == Some(&b'K')
}

fn read_gtpack_zip(bytes: &[u8]) -> Result<PackRequirements> {
    let cursor = io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).context("failed to open gtpack zip")?;
    let mut last_err: Option<anyhow::Error> = None;
    for name in &[
        "assets/secret-requirements.json",
        "assets/secret_requirements.json",
        "secret-requirements.json",
        "secret_requirements.json",
    ] {
        match read_requirements_from_zip(&mut archive, name) {
            Ok(Some(reqs)) => {
                let pack_id = read_pack_id_from_archive(&mut archive);
                return Ok(PackRequirements {
                    secret_requirements: reqs,
                    pack_id,
                });
            }
            Ok(None) => {}
            Err(err) => {
                last_err = Some(err);
            }
        }
    }
    for name in &[
        "metadata.json",
        "pack-metadata.json",
        "pack/metadata.json",
        "gtpack/metadata.json",
    ] {
        let data = match archive.by_name(name) {
            Ok(mut file) => {
                let mut buffer = String::new();
                io::Read::read_to_string(&mut file, &mut buffer)
                    .context("failed to read metadata from gtpack")?;
                Some(buffer)
            }
            Err(err) => {
                last_err = Some(err.into());
                None
            }
        };

        if let Some(data) = data {
            let mut meta: PackMetadata =
                serde_json::from_str(&data).context("gtpack metadata is not valid JSON")?;
            let pack_id = read_pack_id_from_archive(&mut archive).or(meta.pack_id.take());
            return Ok(PackRequirements {
                secret_requirements: meta.secret_requirements,
                pack_id,
            });
        }
    }
    let pack_id = read_pack_id_from_archive(&mut archive);
    if pack_id.is_some() {
        return Ok(PackRequirements {
            secret_requirements: Vec::new(),
            pack_id,
        });
    }
    Err(anyhow::anyhow!(
        "gtpack missing metadata or secret requirements ({last_err:?})"
    ))
}

fn read_pack_id_from_archive(archive: &mut ZipArchive<io::Cursor<&[u8]>>) -> Option<String> {
    for name in &["manifest.cbor", "assets/manifest.cbor"] {
        if let Some(id) = read_pack_id_from_manifest(archive, name) {
            return Some(id);
        }
    }
    for name in &["pack.json", "assets/pack.json"] {
        if let Some(id) = read_pack_id_from_pack_json(archive, name) {
            return Some(id);
        }
    }
    None
}

fn read_pack_id_from_manifest(
    archive: &mut ZipArchive<io::Cursor<&[u8]>>,
    name: &str,
) -> Option<String> {
    let mut file = archive.by_name(name).ok()?;
    let mut data = Vec::new();
    io::Read::read_to_end(&mut file, &mut data).ok()?;
    decode_pack_manifest(&data)
        .ok()
        .map(|manifest| manifest.pack_id.to_string())
}

fn read_pack_id_from_pack_json(
    archive: &mut ZipArchive<io::Cursor<&[u8]>>,
    name: &str,
) -> Option<String> {
    let mut file = archive.by_name(name).ok()?;
    let mut data = String::new();
    io::Read::read_to_string(&mut file, &mut data).ok()?;
    serde_json::from_str::<Value>(&data)
        .ok()
        .and_then(|value| value.get("id")?.as_str().map(|id| id.to_string()))
}

fn read_requirements_from_zip(
    archive: &mut ZipArchive<io::Cursor<&[u8]>>,
    name: &str,
) -> Result<Option<Vec<SecretRequirement>>> {
    let mut file = match archive.by_name(name) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let mut data = Vec::new();
    io::Read::read_to_end(&mut file, &mut data)
        .context("failed to read secret requirements from gtpack")?;
    let reqs: Vec<SecretRequirement> =
        serde_json::from_slice(&data).context("gtpack secret requirements are not valid JSON")?;
    Ok(Some(reqs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use greentic_types::pack_manifest::{PackKind, PackManifest, PackSignatures};
    use greentic_types::{PackId, encode_pack_manifest};
    use semver::Version;
    use std::fs::File;
    use std::path::Path;
    use tempfile::tempdir;
    use zip::write::{FileOptions, ZipWriter};

    #[test]
    fn read_pack_requirements_reads_pack_id_from_manifest() -> Result<()> {
        let temp = tempdir().context("create tempdir")?;
        let pack_path = temp.path().join("fixture.gtpack");
        write_test_gtpack(&pack_path, "greentic.secrets.fixture")?;

        let requirements = read_pack_requirements(&pack_path)?;
        assert_eq!(
            requirements.pack_id.as_deref(),
            Some("greentic.secrets.fixture")
        );
        assert_eq!(requirements.secret_requirements.len(), 1);
        assert_eq!(requirements.secret_requirements[0].key.as_str(), "api_key");
        Ok(())
    }

    #[test]
    fn scaffold_entry_respects_pack_id_category() {
        let ctx = CtxFile {
            env: "dev".into(),
            tenant: "acme".into(),
            team: None,
        };
        let mut req = SecretRequirement::default();
        req.key = greentic_types::secrets::SecretKey::parse("api_key").unwrap();

        let entry = scaffold_entry(&ctx, &req, "greentic.secrets.fixture");
        assert_eq!(
            entry.uri,
            "secrets://dev/acme/_/greentic.secrets.fixture/api_key"
        );
    }

    fn write_test_gtpack(path: &Path, pack_id: &str) -> Result<()> {
        let pack_id = PackId::new(pack_id).map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let manifest = PackManifest {
            schema_version: "1".to_string(),
            pack_id,
            name: None,
            version: Version::parse("0.1.0").unwrap(),
            kind: PackKind::Provider,
            publisher: "greentic".into(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            secret_requirements: Vec::new(),
            signatures: PackSignatures::default(),
            bootstrap: None,
            extensions: None,
        };
        let manifest_bytes = encode_pack_manifest(&manifest)?;

        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);
        let opts = FileOptions::default();
        zip.start_file("manifest.cbor", opts)?;
        zip.write_all(&manifest_bytes)?;
        zip.start_file("assets/secret_requirements.json", opts)?;
        zip.write_all(br#"[{"key":"api_key","required":true}]"#)?;
        zip.finish()?;
        Ok(())
    }
}
