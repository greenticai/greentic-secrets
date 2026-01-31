use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use greentic_component_runtime::CompError;
use greentic_component_runtime::{
    Bindings, ComponentRef, HostPolicy, LoadPolicy, bind, describe, invoke, load,
};
use greentic_component_store::ComponentStore;
use greentic_types::TenantCtx;
use serde_json::{Map, Value};
use wasmparser::{Parser, Payload};

pub enum WasmArtifactKind {
    Module,
    Component,
}

pub fn detect_wasm_kind(bytes: &[u8]) -> Result<WasmArtifactKind> {
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.context("parse wasm")?;
        if matches!(payload, Payload::ComponentSection { .. }) {
            return Ok(WasmArtifactKind::Component);
        }
    }
    Ok(WasmArtifactKind::Module)
}

pub struct ComponentRunRequest {
    pub component_path: PathBuf,
    pub step: String,
    pub input: Value,
    pub tenant_ctx: TenantCtx,
    pub config: Value,
    pub secrets: HashMap<String, String>,
    pub cache_dir: PathBuf,
}

pub fn run_node_component(req: ComponentRunRequest) -> Result<Value> {
    println!(
        "component detected at {}, using component runtime ({})",
        req.component_path.display(),
        req.step
    );

    let store = ComponentStore::new(&req.cache_dir)
        .with_context(|| format!("prepare component cache {}", req.cache_dir.display()))?;
    let store = Arc::new(store);
    let mut policy = LoadPolicy::new(store);
    policy = policy.with_host_policy(HostPolicy::default());

    let canonical_path = req
        .component_path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", req.component_path.display()))?;
    let cref = ComponentRef {
        name: req.step.clone(),
        locator: canonical_path.to_string_lossy().into_owned(),
    };

    let handle = load(&cref, &policy).map_err(|err| anyhow!(err))?;

    let bindings = Bindings::new(req.config.clone(), req.secrets.keys().cloned().collect());
    let secrets = req.secrets.clone();
    let mut resolver = move |key: &str, _: &TenantCtx| {
        secrets
            .get(key)
            .cloned()
            .ok_or_else(|| CompError::SecretNotDeclared(key.to_string()))
    };
    bind(&handle, &req.tenant_ctx, &bindings, &mut resolver).map_err(|err| anyhow!(err))?;

    let manifest = describe(&handle).map_err(|err| anyhow!(err))?;
    println!(
        "component manifest operations: {:?}",
        manifest
            .exports
            .iter()
            .map(|export| export.operation.clone())
            .collect::<Vec<_>>()
    );

    invoke(&handle, &req.step, &req.input, &req.tenant_ctx).map_err(|err| anyhow!(err))
}

#[allow(dead_code)]
pub fn resolve_setup_defaults(root: &Path) -> Result<Value> {
    let mut defaults = Map::new();
    let path = root.join("assets").join("setup.yaml");
    if !path.exists() {
        return Ok(Value::Object(defaults));
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let doc: serde_yaml::Value =
        serde_yaml::from_slice(&bytes).context("parse setup.yaml defaults")?;
    let questions = doc
        .get("questions")
        .and_then(|value| value.as_sequence())
        .cloned()
        .unwrap_or_default();
    for question in &questions {
        if let Some(name) = question.get("name").and_then(|value| value.as_str())
            && let Some(default) = question.get("default")
        {
            defaults.insert(name.to_string(), serde_json::to_value(default)?);
        }
    }
    Ok(Value::Object(defaults))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_wasm_module() {
        let bytes = wat::parse_str("(module)").unwrap();
        assert!(matches!(
            detect_wasm_kind(&bytes).unwrap(),
            WasmArtifactKind::Module
        ));
    }

    fn telegram_component_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../greentic-messaging-providers/packs/messaging-telegram/components/setup_default__apply.wasm",
        )
    }

    #[test]
    fn detect_wasm_component() {
        let path = telegram_component_path();
        let bytes = fs::read(path).unwrap();
        assert!(matches!(
            detect_wasm_kind(&bytes).unwrap(),
            WasmArtifactKind::Component
        ));
    }
}
