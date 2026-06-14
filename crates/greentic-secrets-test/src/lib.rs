use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use wasmtime::{Config, Engine, Instance, Module, Store};
use zip::ZipArchive;

use greentic_types::{PackKind, decode_pack_manifest};

const DEFAULT_PACK_GLOB: &str = "secrets-";
const LIVE_ENV_FLAG: &str = "GREENTIC_SECRETS_E2E_LIVE";
const NETWORK_ENV_FLAG: &str = "GREENTIC_SECRETS_E2E_ALLOW_NETWORK";
const DEFAULT_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct E2eOptions {
    pub packs_dir: PathBuf,
    pub provider_filter: Option<String>,
    pub report_path: Option<PathBuf>,
    pub dry_run: bool,
    pub live: bool,
    pub trace: bool,
    pub fixtures_root: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct E2eReport {
    pub summary: E2eSummary,
    pub packs: Vec<PackReport>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct E2eSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackReport {
    pub pack: String,
    pub version: String,
    pub status: String,
    pub stages: StageReport,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StageReport {
    pub requirements: String,
    pub setup: String,
    pub safety: String,
}

pub trait ProvisionRunner {
    fn dry_run_setup(
        &self,
        pack_path: &Path,
        provider_id: &str,
        install_id: &str,
        public_base_url: &str,
        answers: Option<&Path>,
        timeout: Duration,
    ) -> Result<Output>;
}

pub struct GreenticProvisionRunner {
    pub bin: String,
}

impl GreenticProvisionRunner {
    pub fn new() -> Self {
        let bin = std::env::var("GREENTIC_PROVISION_CLI")
            .unwrap_or_else(|_| "greentic-provision".to_owned());
        Self { bin }
    }
}

impl Default for GreenticProvisionRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisionRunner for GreenticProvisionRunner {
    fn dry_run_setup(
        &self,
        pack_path: &Path,
        provider_id: &str,
        install_id: &str,
        public_base_url: &str,
        answers: Option<&Path>,
        timeout: Duration,
    ) -> Result<Output> {
        let mut cmd = Command::new(&self.bin);
        cmd.arg("dry-run")
            .arg("setup")
            .arg("--executor")
            .arg("wasm")
            .arg("--pack")
            .arg(pack_path)
            .arg("--provider-id")
            .arg(provider_id)
            .arg("--install-id")
            .arg(install_id)
            .arg("--public-base-url")
            .arg(public_base_url)
            .arg("--json");
        if let Some(answers) = answers {
            cmd.arg("--answers").arg(answers);
        }
        run_with_timeout(&mut cmd, timeout)
    }
}

pub fn ensure_live_allowed() -> Result<()> {
    let live = std::env::var(LIVE_ENV_FLAG).unwrap_or_default() == "1";
    let network = std::env::var(NETWORK_ENV_FLAG).unwrap_or_default() == "1";
    if live && network {
        Ok(())
    } else {
        Err(anyhow!(
            "--live requires {}=1 and {}=1",
            LIVE_ENV_FLAG,
            NETWORK_ENV_FLAG
        ))
    }
}

pub fn run_e2e(options: E2eOptions) -> Result<E2eReport> {
    let runner = GreenticProvisionRunner::new();
    run_e2e_with_runner(options, &runner)
}

pub fn run_e2e_with_runner(options: E2eOptions, runner: &dyn ProvisionRunner) -> Result<E2eReport> {
    if options.live && options.dry_run {
        return Err(anyhow!("--live conflicts with --dry-run"));
    }
    if options.live {
        ensure_live_allowed()?;
    }

    let packs = discover_packs(&options.packs_dir, options.provider_filter.as_deref())?;
    let mut reports = Vec::new();
    let mut report_secrets = Vec::new();

    for pack_path in packs {
        let pack_label = pack_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();
        let mut diagnostics = Vec::new();
        let mut stages = StageReport {
            requirements: "pass".to_owned(),
            setup: "pass".to_owned(),
            safety: "pass".to_owned(),
        };

        let manifest = match read_pack_manifest(&pack_path) {
            Ok(manifest) => manifest,
            Err(err) => {
                diagnostics.push(format!("manifest error: {err}"));
                reports.push(failed_report(pack_label, "unknown", stages, diagnostics));
                continue;
            }
        };

        if manifest.kind != PackKind::Provider {
            continue;
        }

        let (pack_id, pack_version) = (manifest.pack_id.to_string(), manifest.version.to_string());

        let pack_extract = match extract_pack(&pack_path) {
            Ok(extract) => extract,
            Err(err) => {
                diagnostics.push(format!("pack extract error: {err}"));
                reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
                continue;
            }
        };

        if let Err(err) = write_provision_manifest(&pack_extract.root, &manifest) {
            diagnostics.push(format!("pack.json error: {err}"));
            reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
            continue;
        }

        let fixture_dir = resolve_fixture_dir(&options.fixtures_root, &pack_id, &pack_path);
        let requirements_expected = fixture_dir
            .as_ref()
            .map(|dir| dir.join("requirements.expected.json"));
        let setup_input = fixture_dir.as_ref().map(|dir| dir.join("setup.input.json"));
        let setup_expected_plan = fixture_dir
            .as_ref()
            .map(|dir| dir.join("setup.expected.plan.json"));

        let answers_value = load_answers(setup_input.as_deref().filter(|path| path.exists()))?;
        let requirements_flow =
            match run_requirements_flow(&pack_extract.root, &answers_value, options.timeout) {
                Ok(value) => value,
                Err(err) => {
                    stages.requirements = "fail".to_owned();
                    diagnostics.push(format!("requirements flow error: {err}"));
                    reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
                    continue;
                }
            };

        if let Some(requirements_value) = requirements_flow.as_ref()
            && let Some(expected_path) = requirements_expected
                .as_deref()
                .filter(|path| path.exists())
            && let Err(err) = assert_requirements_matches(expected_path, requirements_value)
        {
            stages.requirements = "fail".to_owned();
            diagnostics.push(format!("requirements fixture mismatch: {err}"));
            reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
            continue;
        }

        let requirements_data = match load_requirements(
            &pack_path,
            requirements_expected.as_deref(),
            requirements_flow.as_ref(),
        ) {
            Ok(data) => data,
            Err(err) => {
                stages.requirements = "fail".to_owned();
                diagnostics.push(format!("requirements error: {err}"));
                reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
                continue;
            }
        };

        let setup_output = match runner.dry_run_setup(
            &pack_extract.root,
            &pack_id,
            &format!("{pack_id}-install"),
            "https://example.invalid",
            setup_input.as_deref().filter(|path| path.exists()),
            options.timeout,
        ) {
            Ok(output) => output,
            Err(err) => {
                stages.setup = "fail".to_owned();
                diagnostics.push(format!("setup error: {err}"));
                reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
                continue;
            }
        };

        if !setup_output.status.success() {
            stages.setup = "fail".to_owned();
            diagnostics.push(format!(
                "setup failed: {}",
                String::from_utf8_lossy(&setup_output.stderr)
            ));
            reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
            continue;
        }

        let setup_stdout = String::from_utf8_lossy(&setup_output.stdout).to_string();
        let setup_stderr = String::from_utf8_lossy(&setup_output.stderr).to_string();
        let provision_result: Value = match serde_json::from_str(&setup_stdout) {
            Ok(value) => value,
            Err(err) => {
                stages.setup = "fail".to_owned();
                diagnostics.push(format!("setup json error: {err}"));
                reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
                continue;
            }
        };

        let plan = match provision_result.get("plan") {
            Some(plan) => plan.clone(),
            None => {
                stages.setup = "fail".to_owned();
                diagnostics.push("setup json missing plan".to_owned());
                reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
                continue;
            }
        };

        if let Some(requirements_value) = requirements_flow.as_ref()
            && let Err(err) = validate_answers(requirements_value, &answers_value)
        {
            stages.setup = "fail".to_owned();
            diagnostics.push(format!("validation error: {err}"));
            reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
            continue;
        }

        if let Some(expected_path) = setup_expected_plan.as_deref().filter(|path| path.exists())
            && let Err(err) = assert_plan_matches(expected_path, &plan)
        {
            stages.setup = "fail".to_owned();
            diagnostics.push(format!("plan fixture mismatch: {err}"));
            reports.push(failed_report(pack_label, pack_version, stages, diagnostics));
            continue;
        }

        if let Err(err) = check_plan_determinism(&plan) {
            stages.safety = "fail".to_owned();
            diagnostics.push(format!("plan nondeterministic: {err}"));
        }

        if let Err(err) = check_secrets_redacted(&plan) {
            stages.safety = "fail".to_owned();
            diagnostics.push(format!("secrets not redacted: {err}"));
        }

        let secret_values = collect_secret_values(
            setup_input.as_deref().filter(|path| path.exists()),
            &requirements_data,
        )?;
        report_secrets.extend(secret_values.iter().cloned());

        if let Err(err) = check_no_secret_leaks(
            &secret_values,
            &[setup_stdout.as_str(), setup_stderr.as_str()],
            &provision_result,
        ) {
            stages.safety = "fail".to_owned();
            diagnostics.push(err);
        }

        let status =
            if stages.requirements == "pass" && stages.setup == "pass" && stages.safety == "pass" {
                "pass"
            } else {
                "fail"
            };

        reports.push(PackReport {
            pack: pack_label,
            version: pack_version,
            status: status.to_owned(),
            stages,
            diagnostics,
        });
    }

    let summary = summarize(&reports);
    let report = E2eReport {
        summary,
        packs: reports,
    };
    let report_json = serde_json::to_string_pretty(&report)?;

    ensure_report_redaction(&report_json, &report_secrets)?;

    if let Some(path) = options.report_path.as_ref() {
        fs::write(path, &report_json)
            .with_context(|| format!("failed to write report {}", path.display()))?;
    }

    Ok(report)
}

fn summarize(reports: &[PackReport]) -> E2eSummary {
    let total = reports.len();
    let passed = reports.iter().filter(|r| r.status == "pass").count();
    let failed = total - passed;
    E2eSummary {
        total,
        passed,
        failed,
    }
}

fn failed_report(
    pack: String,
    version: impl Into<String>,
    stages: StageReport,
    diagnostics: Vec<String>,
) -> PackReport {
    PackReport {
        pack,
        version: version.into(),
        status: "fail".to_owned(),
        stages,
        diagnostics,
    }
}

struct ExtractedPack {
    root: PathBuf,
    _temp: TempDir,
}

fn extract_pack(path: &Path) -> Result<ExtractedPack> {
    let temp = TempDir::new().context("create pack temp dir")?;
    let file = fs::File::open(path).with_context(|| format!("open pack {}", path.display()))?;
    let mut archive = ZipArchive::new(file).context("read pack archive")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read pack entry")?;
        let out_path = temp.path().join(entry.name());
        if entry.is_dir() {
            fs::create_dir_all(&out_path).context("create pack dir")?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).context("create pack parent")?;
        }
        let mut out_file = fs::File::create(&out_path).context("write pack entry")?;
        std::io::copy(&mut entry, &mut out_file).context("copy pack entry")?;
    }
    Ok(ExtractedPack {
        root: temp.path().to_path_buf(),
        _temp: temp,
    })
}

fn read_pack_manifest(path: &Path) -> Result<greentic_types::PackManifest> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut archive = ZipArchive::new(file).context("open pack zip")?;
    let mut manifest_bytes = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read entry")?;
        if entry.name().ends_with("manifest.cbor") {
            std::io::Read::read_to_end(&mut entry, &mut manifest_bytes).context("read manifest")?;
            break;
        }
    }
    if manifest_bytes.is_empty() {
        return Err(anyhow!("manifest.cbor missing"));
    }
    decode_pack_manifest(&manifest_bytes).context("decode manifest")
}

#[derive(Serialize)]
struct ProvisionManifest {
    id: String,
    version: String,
    meta: ProvisionMeta,
    flows: Vec<ProvisionFlow>,
}

#[derive(Serialize, Default)]
struct ProvisionMeta {
    entry_flows: BTreeMap<String, String>,
    requires_public_base_url: bool,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
struct ProvisionFlow {
    entry: Option<String>,
    id: Option<String>,
    name: Option<String>,
}

fn write_provision_manifest(root: &Path, manifest: &greentic_types::PackManifest) -> Result<()> {
    let embedded_manifest = root.join("assets").join("pack.json");
    if embedded_manifest.exists() {
        let target = root.join("pack.json");
        fs::copy(&embedded_manifest, &target).context("copy pack.json")?;
        let embedded_wasm = root.join("assets").join("wasm");
        if embedded_wasm.exists() {
            let target_wasm = root.join("wasm");
            if target_wasm.exists() {
                fs::remove_dir_all(&target_wasm).context("remove existing wasm")?;
            }
            copy_dir_all(&embedded_wasm, &target_wasm)?;
        }
        return Ok(());
    }

    let mut entry_flows = BTreeMap::new();
    let mut flows = Vec::new();

    for flow in &manifest.flows {
        let flow_id = flow.id.as_str().to_owned();
        if flow.entrypoints.is_empty() {
            flows.push(ProvisionFlow {
                entry: None,
                id: Some(flow_id),
                name: None,
            });
            continue;
        }
        for entry in &flow.entrypoints {
            let entry_name = entry.to_owned();
            entry_flows
                .entry(entry_name.clone())
                .or_insert_with(|| flow_id.clone());
            flows.push(ProvisionFlow {
                entry: Some(entry_name),
                id: Some(flow_id.clone()),
                name: None,
            });
        }
    }

    let manifest = ProvisionManifest {
        id: manifest.pack_id.to_string(),
        version: manifest.version.to_string(),
        meta: ProvisionMeta {
            entry_flows,
            requires_public_base_url: false,
            capabilities: Vec::new(),
        },
        flows,
    };

    let path = root.join("pack.json");
    let json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&path, json).context("write pack.json")?;
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).context("create dir")?;
    for entry in fs::read_dir(src).context("read dir")? {
        let entry = entry.context("read entry")?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).context("copy file")?;
        }
    }
    Ok(())
}

fn discover_packs(root: &Path, filter: Option<&str>) -> Result<Vec<PathBuf>> {
    let mut packs = Vec::new();
    for entry in fs::read_dir(root).with_context(|| format!("read packs dir {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("gtpack") {
            continue;
        }
        if let Some(file_name) = path.file_name().and_then(|name| name.to_str())
            && !file_name.starts_with(DEFAULT_PACK_GLOB)
        {
            continue;
        }
        if let Some(filter) = filter {
            let value = filter.to_ascii_lowercase();
            let matches = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(|stem| stem.to_ascii_lowercase().contains(&value))
                .unwrap_or(false);
            if !matches {
                continue;
            }
        }
        packs.push(path);
    }
    if packs.is_empty() {
        return Err(anyhow!("no packs found in {}", root.display()));
    }
    packs.sort();
    Ok(packs)
}

fn resolve_fixture_dir(fixtures_root: &Path, pack_id: &str, pack_path: &Path) -> Option<PathBuf> {
    let slug = pack_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_prefix(DEFAULT_PACK_GLOB))
        .map(|value| value.to_owned())
        .or_else(|| pack_id.split('.').next_back().map(|value| value.to_owned()))?;
    let candidate = fixtures_root.join(&slug).join("fixtures");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

#[derive(Debug)]
struct RequirementsData {
    keys: HashSet<String>,
}

fn load_requirements(
    pack_path: &Path,
    fixture_path: Option<&Path>,
    flow_value: Option<&Value>,
) -> Result<RequirementsData> {
    if let Some(value) = flow_value {
        let keys = secret_keys_from_requirements(value);
        if !keys.is_empty() {
            return Ok(RequirementsData { keys });
        }
        let mut keys = HashSet::new();
        collect_requirement_keys(value, &mut keys);
        return Ok(RequirementsData { keys });
    }
    if let Some(path) = fixture_path
        && path.exists()
    {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read requirements fixture {}", path.display()))?;
        let value: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse requirements fixture {}", path.display()))?;
        let keys = secret_keys_from_requirements(&value);
        if !keys.is_empty() {
            return Ok(RequirementsData { keys });
        }
        let mut keys = HashSet::new();
        collect_requirement_keys(&value, &mut keys);
        return Ok(RequirementsData { keys });
    }

    let file =
        fs::File::open(pack_path).with_context(|| format!("open {}", pack_path.display()))?;
    let mut archive = ZipArchive::new(file).context("open pack zip")?;
    let mut buffer = String::new();
    let mut found = false;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read pack entry")?;
        if entry.name().ends_with("assets/secret-requirements.json")
            || entry.name().ends_with("assets/secret_requirements.json")
        {
            std::io::Read::read_to_string(&mut entry, &mut buffer)
                .context("read secret requirements")?;
            found = true;
            break;
        }
    }
    if !found {
        return Err(anyhow!("secret requirements asset missing"));
    }
    let value: Value = serde_json::from_str(&buffer).context("parse secret requirements")?;
    let mut keys = HashSet::new();
    if let Value::Array(items) = value {
        for item in items {
            if let Some(key) = item
                .get("key")
                .and_then(Value::as_str)
                .or_else(|| item.get("id").and_then(Value::as_str))
                .or_else(|| item.get("name").and_then(Value::as_str))
            {
                keys.insert(key.to_owned());
            }
        }
    }
    Ok(RequirementsData { keys })
}

fn load_answers(input_path: Option<&Path>) -> Result<Value> {
    if let Some(path) = input_path {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read setup input {}", path.display()))?;
        let value: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse setup input {}", path.display()))?;
        return Ok(value);
    }
    Ok(Value::Object(serde_json::Map::new()))
}

fn collect_requirement_keys(value: &Value, keys: &mut HashSet<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_requirement_keys(item, keys);
            }
        }
        Value::Object(map) => {
            if let Some(key) = map
                .get("key")
                .and_then(Value::as_str)
                .or_else(|| map.get("id").and_then(Value::as_str))
                .or_else(|| map.get("name").and_then(Value::as_str))
            {
                keys.insert(key.to_owned());
            }
            for value in map.values() {
                collect_requirement_keys(value, keys);
            }
        }
        _ => {}
    }
}

fn secret_keys_from_requirements(value: &Value) -> HashSet<String> {
    let mut keys = HashSet::new();
    let Some(secrets) = value.get("secrets") else {
        return keys;
    };
    let Some(secrets_obj) = secrets.as_object() else {
        return keys;
    };
    for field in ["required", "optional"] {
        if let Some(list) = secrets_obj.get(field).and_then(|v| v.as_array()) {
            for item in list {
                if let Some(key) = item.as_str()
                    && !key.trim().is_empty()
                {
                    keys.insert(key.to_string());
                }
            }
        }
    }
    keys
}

fn collect_secret_values(
    input_path: Option<&Path>,
    requirements: &RequirementsData,
) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let Some(path) = input_path else {
        return Ok(values);
    };
    let raw =
        fs::read_to_string(path).with_context(|| format!("read setup input {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse setup input {}", path.display()))?;
    collect_secret_values_inner(&value, &mut values, requirements);
    Ok(values)
}

fn collect_secret_values_inner(
    value: &Value,
    values: &mut Vec<String>,
    requirements: &RequirementsData,
) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if requirements.keys.contains(key) {
                    collect_leaf_strings(value, values);
                } else {
                    collect_secret_values_inner(value, values, requirements);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_secret_values_inner(item, values, requirements);
            }
        }
        _ => {}
    }
}

fn collect_leaf_strings(value: &Value, values: &mut Vec<String>) {
    match value {
        Value::String(value) => values.push(value.to_owned()),
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_leaf_strings(item, values)),
        Value::Object(map) => map
            .values()
            .for_each(|value| collect_leaf_strings(value, values)),
        _ => {}
    }
}

fn assert_requirements_matches(path: &Path, requirements: &Value) -> Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read requirements fixture {}", path.display()))?;
    let expected: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse requirements fixture {}", path.display()))?;
    if expected != *requirements {
        return Err(anyhow!("requirements do not match fixture"));
    }
    Ok(())
}

fn assert_plan_matches(path: &Path, plan: &Value) -> Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read plan fixture {}", path.display()))?;
    let expected: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse plan fixture {}", path.display()))?;
    if expected != *plan {
        return Err(anyhow!("plan does not match fixture"));
    }
    Ok(())
}

fn validate_answers(requirements: &Value, answers: &Value) -> Result<()> {
    let config_required = requirements
        .get("config")
        .and_then(|value| value.get("required"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let secret_required = requirements
        .get("secrets")
        .and_then(|value| value.get("required"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let enum_constraints = requirements
        .get("config")
        .and_then(|value| value.get("constraints"))
        .and_then(|value| value.get("enum"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let config_values = answers
        .get("config")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let secret_values = answers
        .get("secrets")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    for key in config_required {
        let key = key.as_str().unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let Some(value) = config_values.get(key) else {
            return Err(anyhow!("missing required config field {key}"));
        };
        if matches!(value, Value::String(text) if text.is_empty()) {
            return Err(anyhow!("missing required config field {key}"));
        }
    }

    for key in secret_required {
        let key = key.as_str().unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let Some(value) = secret_values.get(key) else {
            return Err(anyhow!("missing required secret field {key}"));
        };
        if matches!(value, Value::String(text) if text.is_empty()) {
            return Err(anyhow!("missing required secret field {key}"));
        }
    }

    for (key, values) in enum_constraints {
        let Some(allowed) = values.as_array() else {
            continue;
        };
        let Some(actual) = config_values.get(&key).and_then(Value::as_str) else {
            continue;
        };
        if !allowed.iter().any(|value| value.as_str() == Some(actual)) {
            return Err(anyhow!("invalid enum value for {key}"));
        }
    }

    Ok(())
}

fn check_plan_determinism(plan: &Value) -> Result<()> {
    let serialized_once = serde_json::to_string(plan)?;
    let serialized_twice = serde_json::to_string(plan)?;
    if serialized_once != serialized_twice {
        return Err(anyhow!("plan serialization drift"));
    }
    Ok(())
}

fn check_secrets_redacted(plan: &Value) -> Result<()> {
    let Some(secrets_patch) = plan.get("secrets_patch") else {
        return Ok(());
    };
    let Some(set) = secrets_patch.get("set") else {
        return Ok(());
    };
    if let Value::Object(map) = set {
        for (key, value) in map {
            let redacted = value
                .get("redacted")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let has_value = value
                .get("value")
                .and_then(|value| value.as_str())
                .is_some();
            if !redacted || has_value {
                return Err(anyhow!("secret {} not redacted", key));
            }
        }
    }
    Ok(())
}

fn check_no_secret_leaks(
    secret_values: &[String],
    output_streams: &[&str],
    result: &Value,
) -> Result<(), String> {
    if secret_values.is_empty() {
        return Ok(());
    }
    let diagnostics = result
        .get("diagnostics")
        .cloned()
        .unwrap_or(Value::Null)
        .to_string();
    let plan = result
        .get("plan")
        .cloned()
        .unwrap_or(Value::Null)
        .to_string();
    let mut corpus = String::new();
    corpus.push_str(&diagnostics);
    corpus.push_str(&plan);
    for stream in output_streams {
        corpus.push_str(stream);
    }
    for secret in secret_values {
        if secret.is_empty() {
            continue;
        }
        if corpus.contains(secret) {
            return Err(format!("secret value leaked: {}", secret));
        }
    }
    Ok(())
}

fn ensure_report_redaction(report_json: &str, secrets: &[String]) -> Result<()> {
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        if report_json.contains(secret) {
            return Err(anyhow!("report contains secret values"));
        }
    }
    Ok(())
}

fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let start = Instant::now();
    let mut child = cmd.spawn().context("spawn greentic-provision")?;
    loop {
        if let Some(status) = child.try_wait().context("wait on greentic-provision")? {
            let output = child.wait_with_output().unwrap_or_else(|_| Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
            return Ok(output);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            return Err(anyhow!("greentic-provision timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run_requirements_flow(root: &Path, answers: &Value, timeout: Duration) -> Result<Option<Value>> {
    let Some(component_path) = find_wasm_for_step(root, "requirements") else {
        return Ok(None);
    };
    let output = execute_wasm_step(&component_path, "requirements", answers, timeout)?;
    let value = output
        .get("requirements")
        .cloned()
        .unwrap_or_else(|| output.clone());
    Ok(Some(value))
}

fn find_wasm_for_step(root: &Path, step: &str) -> Option<PathBuf> {
    let candidates = [format!("setup_default__{step}")];
    let roots = [
        root.join("wasm"),
        root.join("components"),
        root.to_path_buf(),
    ];
    for candidate in candidates {
        for base in &roots {
            let wasm = base.join(format!("{candidate}.wasm"));
            if wasm.exists() {
                return Some(wasm);
            }
            let wat = base.join(format!("{candidate}.wat"));
            if wat.exists() {
                return Some(wat);
            }
        }
    }
    None
}

fn execute_wasm_step(
    path: &Path,
    step_name: &str,
    answers: &Value,
    timeout: Duration,
) -> Result<Value> {
    let wasm_bytes = load_component_bytes(path)?;
    let mut config = Config::new();
    config.epoch_interruption(true);
    let engine = Engine::new(&config)?;
    let mut store = Store::new(&engine, ());

    let engine_clone = engine.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done_for_timeout = Arc::clone(&done);
    let timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
    let epoch_handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        while !done_for_timeout.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                engine_clone.increment_epoch();
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    store.set_epoch_deadline(1);

    let module = Module::new(&engine, wasm_bytes)?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| anyhow!("missing exported memory"))?;

    let input = json!({
        "step": step_name,
        "inputs": { "answers": answers },
        "state": { "answers": answers, "previous": [] }
    });
    let input_bytes = serde_json::to_vec(&input)?;
    write_wasm_input(&memory, &mut store, &input_bytes)?;

    let func = instance
        .get_func(&mut store, "run")
        .ok_or_else(|| anyhow!("missing run export"))?;
    let func = func.typed::<(i32, i32), (i32, i32)>(&store)?;

    let result = func
        .call(&mut store, (4096i32, input_bytes.len() as i32))
        .map_err(|err| anyhow!("wasm trap: {err}"));
    done.store(true, Ordering::Release);
    let (output_ptr, output_len) = result?;
    let output = read_wasm_output(&memory, &mut store, output_ptr, output_len)?;

    let _ = epoch_handle.join();
    Ok(output)
}

fn load_component_bytes(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read component {}", path.display()))?;
    if path.extension().and_then(|ext| ext.to_str()) == Some("wat") {
        let wasm = wat::parse_bytes(&bytes).map_err(|err| anyhow!("failed to parse wat: {err}"))?;
        Ok(wasm.into())
    } else {
        Ok(bytes)
    }
}

fn write_wasm_input(
    memory: &wasmtime::Memory,
    store: &mut Store<()>,
    input_bytes: &[u8],
) -> Result<()> {
    let memory_size = memory.data_size(&store);
    let input_ptr = 4096usize;
    if input_ptr + input_bytes.len() > memory_size {
        return Err(anyhow!("wasm input too large"));
    }
    memory
        .write(store, input_ptr, input_bytes)
        .map_err(|err| anyhow!("memory write failed: {err}"))?;
    Ok(())
}

fn read_wasm_output(
    memory: &wasmtime::Memory,
    store: &mut Store<()>,
    output_ptr: i32,
    output_len: i32,
) -> Result<Value> {
    let output_len = output_len as usize;
    let mut buffer = vec![0u8; output_len];
    memory
        .read(store, output_ptr as usize, &mut buffer)
        .map_err(|err| anyhow!("memory read failed: {err}"))?;
    let value = serde_json::from_slice(&buffer)?;
    Ok(value)
}

impl Default for E2eOptions {
    fn default() -> Self {
        Self {
            packs_dir: PathBuf::from("dist/packs"),
            provider_filter: None,
            report_path: None,
            dry_run: true,
            live: false,
            trace: false,
            fixtures_root: PathBuf::from("packs"),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }
}
