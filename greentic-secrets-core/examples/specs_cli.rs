use std::env;

use secrets_core::{SecretDescribable, SecretSpecRegistry, SecretsCore};
use tokio::runtime::Runtime;

mod telegram {
    include!("plugins/telegram_secrets.rs");
}
mod weather {
    include!("plugins/weather_secrets.rs");
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage());
    match cmd.as_str() {
        "specs" => handle_specs(args.collect())?,
        _ => usage(),
    }
    Ok(())
}

fn handle_specs(args: Vec<String>) -> anyhow::Result<()> {
    if args.is_empty() {
        return Err(anyhow::anyhow!("missing specs subcommand"));
    }
    let mut registry = SecretSpecRegistry::new();
    registry.extend_with(telegram::TelegramSecrets::secret_specs());
    registry.extend_with(weather::WeatherSecrets::secret_specs());

    match args[0].as_str() {
        "print" => {
            let format = args.get(1).map(String::as_str).unwrap_or("md");
            match format {
                "json" => println!("{}", registry.to_json()),
                "md" => print!("{}", registry.to_markdown_table()),
                _ => print!("{}", registry.to_markdown_table()),
            }
            Ok(())
        }
        "check" => {
            let env = args.get(1).map(String::as_str).unwrap_or("dev");
            let tenant = args.get(2).map(String::as_str).unwrap_or("example-tenant");
            let team = args.get(3).map(String::as_str).unwrap_or("_");
            let base = format!("secrets://{env}/{tenant}/{team}/");
            let specs: Vec<_> = registry.all().cloned().collect();
            let rt = Runtime::new()?;
            let core =
                rt.block_on(async { SecretsCore::builder().tenant(tenant).build().await })?;
            let result =
                rt.block_on(async { core.validate_specs_at_prefix(&base, &specs).await })?;
            if result.missing.is_empty() {
                println!("All secrets present");
                Ok(())
            } else {
                eprintln!("Missing secrets: {:?}", result.missing);
                std::process::exit(2);
            }
        }
        _ => Err(anyhow::anyhow!("unsupported specs subcommand")),
    }
}

fn usage() -> ! {
    eprintln!("Usage:\n  specs print [md|json]\n  specs check [env tenant team]");
    std::process::exit(1)
}
