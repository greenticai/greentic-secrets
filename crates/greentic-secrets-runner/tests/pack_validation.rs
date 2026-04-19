use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use greentic_types::PROVIDER_EXTENSION_ID;
use serde_cbor::Value as CborValue;
use serde_json::Value as JsonValue;
use serde_yaml::Value;
use zip::ZipArchive;

fn packs_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("packs")
}

fn has_command(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file()
        })
    })
}

#[test]
fn provider_packs_have_provider_core_extension_and_schemas() {
    let packs = ["aws-sm", "azure-kv", "gcp-sm", "k8s", "vault-kv"];
    for pack in packs {
        let pack_dir = packs_root().join(pack);
        let pack_yaml = pack_dir.join("pack.yaml");
        let raw = fs::read_to_string(&pack_yaml)
            .unwrap_or_else(|e| panic!("read {}: {e}", pack_yaml.display()));
        let doc: Value = serde_yaml::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse {}: {e}", pack_yaml.display()));

        let extensions = doc
            .get("extensions")
            .and_then(|v| v.get(PROVIDER_EXTENSION_ID))
            .unwrap_or_else(|| {
                panic!(
                    "missing {} in {}",
                    PROVIDER_EXTENSION_ID,
                    pack_yaml.display()
                )
            });
        let kind = extensions
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing kind in {}", pack_yaml.display()));
        assert_eq!(
            kind,
            PROVIDER_EXTENSION_ID,
            "provider extension kind mismatch in {}",
            pack_yaml.display()
        );
        let version = extensions
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing extension version in {}", pack_yaml.display()));
        assert_eq!(
            version,
            "1.0.0",
            "provider extension version must be 1.0.0 in {}",
            pack_yaml.display()
        );
        let provider = extensions
            .get("inline")
            .and_then(|v| v.get("providers"))
            .and_then(|v| v.get(0))
            .unwrap_or_else(|| panic!("missing inline.providers in {}", pack_yaml.display()));
        let runtime = provider
            .get("runtime")
            .unwrap_or_else(|| panic!("missing runtime in {}", pack_yaml.display()));
        let config_schema = provider
            .get("config_schema_ref")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let expected_config_schema = format!("assets/schemas/secrets/{pack}/config.schema.json");
        assert_eq!(
            config_schema,
            expected_config_schema,
            "provider config schema ref mismatch in {}",
            pack_yaml.display()
        );
        let world = runtime
            .get("world")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing runtime.world in {}", pack_yaml.display()));
        assert_eq!(
            world,
            "greentic:provider/schema-core@1.0.0",
            "provider-core world mismatch in {}",
            pack_yaml.display()
        );
        let export = runtime
            .get("export")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing runtime.export in {}", pack_yaml.display()));
        assert_eq!(
            export,
            "invoke",
            "export must be invoke in {}",
            pack_yaml.display()
        );
        runtime
            .get("component_ref")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing runtime.component_ref in {}", pack_yaml.display()));

        for rel in [
            format!("schemas/secrets/{pack}/config.schema.json"),
            format!("schemas/secrets/{pack}/secret.schema.json"),
        ] {
            let path = pack_dir.join(rel);
            assert!(path.exists(), "missing required schema {}", path.display());
        }

        let req_path = pack_dir.join("secret-requirements.json");
        assert!(
            req_path.exists(),
            "missing secret requirements {}",
            req_path.display()
        );
    }
}

#[test]
fn built_provider_gtpacks_embed_canonical_provider_extension() {
    if !has_command("greentic-pack") {
        eprintln!(
            "skipping built_provider_gtpacks_embed_canonical_provider_extension: greentic-pack is not installed"
        );
        return;
    }
    let packs = packs_root();
    let repo_root = packs
        .parent()
        .unwrap_or_else(|| panic!("packs directory missing parent for {}", packs.display()));
    let output = Command::new("bash")
        .arg("scripts/build-provider-packs.sh")
        .current_dir(repo_root)
        .env(
            "VALIDATE_GTPACK_BIN",
            env!("CARGO_BIN_EXE_validate_gtpack_extension"),
        )
        .output()
        .expect("spawn build-provider-packs.sh");
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");
        // Local/offline runs may not have OCI component blobs cached.
        // Treat this as an environment skip instead of a product failure.
        if combined.contains("offline cache miss for oci://ghcr.io/")
            && combined.contains("/components/")
        {
            eprintln!(
                "skipping built_provider_gtpacks_embed_canonical_provider_extension: missing offline OCI component cache"
            );
            return;
        }
        if combined.contains("can't find crate for `profiler_builtins`")
            || combined.contains("can't find crate for profiler_builtins")
            || (combined.contains("instrument-coverage") && combined.contains("wasm32"))
        {
            eprintln!(
                "skipping built_provider_gtpacks_embed_canonical_provider_extension: coverage instrumentation is unsupported for the wasm component build"
            );
            return;
        }
        panic!(
            "build-provider-packs.sh failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }

    let out_dir = repo_root.join("dist").join("packs");
    let mut packs = Vec::new();
    for entry in
        fs::read_dir(&out_dir).unwrap_or_else(|err| panic!("read_dir {}: {err}", out_dir.display()))
    {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("gtpack"))
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name != "secrets-providers.gtpack")
        {
            packs.push(path);
        }
    }
    assert!(
        !packs.is_empty(),
        "no .gtpack artifacts produced in {}",
        out_dir.display()
    );

    for pack in packs {
        let manifest_bytes = read_pack_member(&pack, "manifest.cbor")
            .unwrap_or_else(|| panic!("{} missing manifest.cbor", pack.display()));
        let doc: JsonValue = serde_cbor::from_slice(&manifest_bytes)
            .unwrap_or_else(|err| panic!("decode manifest from {}: {err}", pack.display()));
        let extensions = doc
            .get("extensions")
            .unwrap_or_else(|| panic!("{} missing extensions", pack.display()));
        let provider = extensions.get(PROVIDER_EXTENSION_ID).unwrap_or_else(|| {
            panic!(
                "{} missing provider extension {}",
                pack.display(),
                PROVIDER_EXTENSION_ID
            )
        });
        let kind = provider
            .get("kind")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        assert_eq!(
            kind,
            PROVIDER_EXTENSION_ID,
            "provider extension kind mismatch in {}",
            pack.display()
        );
        let version = provider
            .get("version")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        assert_eq!(
            version,
            "1.0.0",
            "provider extension version mismatch in {}",
            pack.display()
        );

        let entries = list_pack_entries(&pack);
        let slug = pack
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.strip_prefix("secrets-"))
            .unwrap_or_default();
        let required_assets = [
            "assets/secret-requirements.json".to_owned(),
            format!("assets/schemas/secrets/{slug}/config.schema.json"),
            format!("assets/schemas/secrets/{slug}/secret.schema.json"),
        ];
        for asset in required_assets.iter() {
            assert!(
                entries.contains(asset),
                "{} missing required asset {}",
                pack.display(),
                asset
            );
        }

        let sbom_bytes = read_pack_member(&pack, "sbom.cbor")
            .unwrap_or_else(|| panic!("{} missing sbom.cbor", pack.display()));
        let sbom: CborValue = serde_cbor::from_slice(&sbom_bytes)
            .unwrap_or_else(|err| panic!("decode sbom from {}: {err}", pack.display()));
        let sbom_strings = collect_cbor_strings(&sbom);

        for asset in required_assets.iter() {
            assert!(
                sbom_strings.contains(asset),
                "{} missing {} in SBOM",
                pack.display(),
                asset
            );
        }

        let entry_set: std::collections::HashSet<_> = entries.iter().cloned().collect();
        for value in sbom_strings.iter() {
            if is_pack_path(value) {
                assert!(
                    entry_set.contains(value),
                    "{} SBOM references missing entry {}",
                    pack.display(),
                    value
                );
            }
        }
    }
}

#[test]
fn minimal_fixture_pack_validates() {
    if !has_command("greentic-pack") {
        eprintln!("skipping minimal_fixture_pack_validates: greentic-pack is not installed");
        return;
    }
    let packs = packs_root();
    let repo_root = packs
        .parent()
        .unwrap_or_else(|| panic!("packs directory missing parent for {}", packs.display()));
    let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("minimal-secrets-pack");
    let staging_root = repo_root.join("target").join("fixture-packs");
    let staging = staging_root.join("minimal-secrets-pack");
    if staging.exists() {
        fs::remove_dir_all(&staging).expect("remove staging");
    }
    fs::create_dir_all(&staging_root).expect("create staging root");
    copy_dir_all(&fixture_src, &staging).expect("copy fixture");

    let lock_file = staging.join("pack.lock.json");
    let status = Command::new("greentic-pack")
        .args([
            "resolve",
            "--in",
            staging.to_str().expect("staging"),
            "--lock",
            lock_file.to_str().expect("lock"),
            "--offline",
        ])
        .status()
        .expect("run greentic-pack resolve");
    assert!(status.success(), "greentic-pack resolve failed");

    let pack_out = staging_root.join("minimal-secrets-pack.gtpack");
    let status = Command::new("greentic-pack")
        .args([
            "build",
            "--in",
            staging.to_str().expect("staging"),
            "--lock",
            lock_file.to_str().expect("lock"),
            "--gtpack-out",
            pack_out.to_str().expect("pack_out"),
            "--bundle",
            "none",
            "--offline",
            "--allow-oci-tags",
        ])
        .status()
        .expect("run greentic-pack build");
    assert!(status.success(), "greentic-pack build failed");

    let validator_pack = build_validator_pack(repo_root, &staging_root);

    let status = Command::new("greentic-pack")
        .args([
            "doctor",
            "--validate",
            "--pack",
            pack_out.to_str().expect("pack_out"),
            "--validator-pack",
            validator_pack.to_str().expect("validator_pack"),
            "--offline",
            "--allow-oci-tags",
        ])
        .status()
        .expect("run greentic-pack doctor");
    assert!(status.success(), "greentic-pack doctor failed");
}

fn read_pack_member(pack: &PathBuf, name_suffix: &str) -> Option<Vec<u8>> {
    let file = File::open(pack).ok()?;
    let mut archive = ZipArchive::new(file).ok()?;
    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx).ok()?;
        if entry.is_dir() {
            continue;
        }
        if entry.name().ends_with(name_suffix) {
            let mut buf = Vec::new();
            if entry.read_to_end(&mut buf).is_ok() {
                return Some(buf);
            }
        }
    }
    None
}

fn build_validator_pack(repo_root: &Path, staging_root: &Path) -> PathBuf {
    let validator_src = repo_root.join("validators").join("secrets");
    let validator_staging = staging_root.join("validators-secrets");

    if validator_staging.exists() {
        fs::remove_dir_all(&validator_staging).expect("remove validator staging");
    }
    copy_dir_all(&validator_src, &validator_staging).expect("copy validator source");

    let version = workspace_version(repo_root);
    inject_version(&validator_staging, &version).expect("inject validator version");

    let staging_str = validator_staging.to_str().expect("validator staging path");
    let lock_file = validator_staging.join("pack.lock.json");
    let lock_str = lock_file.to_str().expect("validator lock path");

    let status = Command::new("greentic-pack")
        .args([
            "resolve",
            "--in",
            staging_str,
            "--lock",
            lock_str,
            "--offline",
        ])
        .status()
        .expect("run greentic-pack resolve for validator");
    assert!(
        status.success(),
        "greentic-pack resolve failed for validator pack"
    );

    let pack_out = validator_staging.join("validators-secrets.gtpack");
    let pack_out_str = pack_out.to_str().expect("validator pack path");
    let status = Command::new("greentic-pack")
        .args([
            "build",
            "--in",
            staging_str,
            "--lock",
            lock_str,
            "--gtpack-out",
            pack_out_str,
            "--bundle",
            "none",
            "--offline",
            "--allow-oci-tags",
        ])
        .status()
        .expect("run greentic-pack build for validator");
    assert!(
        status.success(),
        "greentic-pack build failed for validator pack"
    );

    pack_out
}

fn workspace_version(repo_root: &Path) -> String {
    let manifest = repo_root.join("Cargo.toml");
    let content = fs::read_to_string(&manifest).expect("read workspace Cargo.toml");
    let mut in_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[workspace.package]" {
            in_section = true;
            continue;
        }
        if in_section {
            if trimmed.starts_with('[') {
                break;
            }
            if let Some(idx) = trimmed.find('=') {
                let key = trimmed[..idx].trim();
                if key == "version" {
                    let value = trimmed[idx + 1..].trim();
                    return value.trim_matches('"').to_string();
                }
            }
        }
    }
    panic!("workspace.package.version not found");
}

fn inject_version(staging: &Path, version: &str) -> std::io::Result<()> {
    for file in ["gtpack.yaml", "pack.yaml"] {
        let path = staging.join(file);
        if !path.exists() {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        if text.contains("__PACK_VERSION__") {
            let replaced = text.replace("__PACK_VERSION__", version);
            fs::write(&path, replaced)?;
        }
    }
    Ok(())
}

fn list_pack_entries(pack: &PathBuf) -> Vec<String> {
    let file = File::open(pack).expect("open pack");
    let mut archive = ZipArchive::new(file).expect("open pack archive");
    let mut entries = Vec::new();
    for idx in 0..archive.len() {
        let entry = archive.by_index(idx).expect("archive entry");
        if entry.is_dir() {
            continue;
        }
        entries.push(entry.name().to_string());
    }
    entries
}

fn collect_cbor_strings(value: &CborValue) -> Vec<String> {
    let mut out = Vec::new();
    collect_cbor_strings_inner(value, &mut out);
    out
}

fn collect_cbor_strings_inner(value: &CborValue, out: &mut Vec<String>) {
    match value {
        CborValue::Text(text) => out.push(text.to_string()),
        CborValue::Array(items) => {
            for item in items {
                collect_cbor_strings_inner(item, out);
            }
        }
        CborValue::Map(entries) => {
            for (key, value) in entries {
                collect_cbor_strings_inner(key, out);
                collect_cbor_strings_inner(value, out);
            }
        }
        _ => {}
    }
}

fn is_pack_path(value: &str) -> bool {
    value.starts_with("assets/")
        || value.starts_with("flows/")
        || value.starts_with("schemas/")
        || value.ends_with(".cbor")
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_all(&path, &target)?;
        } else {
            fs::copy(&path, &target)?;
        }
    }
    Ok(())
}
