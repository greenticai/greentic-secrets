use std::env;
use std::fs;

use anyhow::{Context, Result};
use greentic_types::ComponentManifest;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        anyhow::bail!("usage: manifest_inspect <component.cbor> [more.cbor ...]");
    }

    for path in args {
        let bytes = fs::read(&path).with_context(|| format!("read {path}"))?;
        let manifest: ComponentManifest =
            serde_cbor::from_slice(&bytes).with_context(|| format!("parse {path}"))?;
        println!("{} v{}", manifest.id, manifest.version);
        println!("  world: {}", manifest.world);
        println!("  supports: {:?}", manifest.supports);
        println!("  operations:");
        for operation in &manifest.operations {
            println!("    - {}", operation.name);
        }
        println!();
    }

    Ok(())
}
