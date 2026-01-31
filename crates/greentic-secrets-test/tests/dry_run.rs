use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{ExitStatus, Output};
use std::time::Duration;

use greentic_secrets_test::{E2eOptions, ProvisionRunner, run_e2e_with_runner};
use greentic_types::flow::{Flow, FlowHasher, FlowKind, FlowMetadata};
use greentic_types::pack_manifest::{PackFlowEntry, PackKind, PackManifest, PackSignatures};
use greentic_types::{FlowId, PackId, encode_pack_manifest};
use indexmap::IndexMap;
use serde_json::json;
use zip::ZipWriter;
use zip::write::FileOptions;

struct StubRunner {
    stdout: String,
    stderr: String,
    status: ExitStatus,
}

impl ProvisionRunner for StubRunner {
    fn dry_run_setup(
        &self,
        _pack_path: &std::path::Path,
        _provider_id: &str,
        _install_id: &str,
        _public_base_url: &str,
        _answers: Option<&std::path::Path>,
        _timeout: Duration,
    ) -> anyhow::Result<Output> {
        Ok(Output {
            status: self.status,
            stdout: self.stdout.as_bytes().to_vec(),
            stderr: self.stderr.as_bytes().to_vec(),
        })
    }
}

#[test]
fn dry_run_conformance_passes() {
    let temp = tempfile::tempdir().expect("temp dir");
    let packs_dir = temp.path().join("packs");
    fs::create_dir_all(&packs_dir).expect("packs dir");

    let pack_path = packs_dir.join("secrets-fixture.gtpack");
    write_pack(&pack_path, "greentic.secrets.fixture").expect("write pack");

    let fixtures_root = temp.path().join("packs");
    let fixture_dir = fixtures_root.join("fixture").join("fixtures");
    fs::create_dir_all(&fixture_dir).expect("fixture dir");
    fs::write(
        fixture_dir.join("requirements.expected.json"),
        json!({
            "provider_id": "greentic.secrets.fixture",
            "config": { "required": [], "optional": [], "constraints": {} },
            "secrets": { "required": ["API_KEY"], "optional": [], "constraints": {} },
            "capabilities": { "supports_read": true, "supports_write": true, "supports_delete": true },
            "setup_needs": { "public_base_url": false, "oauth": false, "subscriptions": false }
        })
        .to_string(),
    )
    .expect("requirements fixture");
    fs::write(
        fixture_dir.join("setup.input.json"),
        json!({ "config": {}, "secrets": { "API_KEY": "supersecret" } }).to_string(),
    )
    .expect("setup input");
    fs::write(
        fixture_dir.join("setup.expected.plan.json"),
        json!({
            "config_patch": {},
            "secrets_patch": {
                "set": {
                    "API_KEY": {"redacted": true, "value": null}
                },
                "delete": []
            },
            "webhook_ops": [],
            "subscription_ops": [],
            "oauth_ops": [],
            "notes": []
        })
        .to_string(),
    )
    .expect("expected plan");

    let provision_result = json!({
        "plan": {
            "config_patch": {},
            "secrets_patch": {
                "set": {
                    "API_KEY": {"redacted": true, "value": null}
                },
                "delete": []
            },
            "webhook_ops": [],
            "subscription_ops": [],
            "oauth_ops": [],
            "notes": []
        },
        "diagnostics": [],
        "step_results": null
    });

    let runner = StubRunner {
        stdout: provision_result.to_string(),
        stderr: String::new(),
        status: success_status(),
    };

    let report = run_e2e_with_runner(
        E2eOptions {
            packs_dir: packs_dir.clone(),
            fixtures_root,
            ..E2eOptions::default()
        },
        &runner,
    )
    .expect("run e2e");

    assert_eq!(report.summary.passed, 1);
    assert_eq!(report.summary.failed, 0);
    assert_eq!(report.packs[0].status, "pass");
}

#[test]
fn leaked_secret_fails() {
    let temp = tempfile::tempdir().expect("temp dir");
    let packs_dir = temp.path().join("packs");
    fs::create_dir_all(&packs_dir).expect("packs dir");

    let pack_path = packs_dir.join("secrets-fixture.gtpack");
    write_pack(&pack_path, "greentic.secrets.fixture").expect("write pack");

    let fixtures_root = temp.path().join("packs");
    let fixture_dir = fixtures_root.join("fixture").join("fixtures");
    fs::create_dir_all(&fixture_dir).expect("fixture dir");
    fs::write(
        fixture_dir.join("requirements.expected.json"),
        json!({
            "provider_id": "greentic.secrets.fixture",
            "config": { "required": [], "optional": [], "constraints": {} },
            "secrets": { "required": ["API_KEY"], "optional": [], "constraints": {} },
            "capabilities": { "supports_read": true, "supports_write": true, "supports_delete": true },
            "setup_needs": { "public_base_url": false, "oauth": false, "subscriptions": false }
        })
        .to_string(),
    )
    .expect("requirements fixture");
    fs::write(
        fixture_dir.join("setup.input.json"),
        json!({ "config": {}, "secrets": { "API_KEY": "supersecret" } }).to_string(),
    )
    .expect("setup input");

    let provision_result = json!({
        "plan": {
            "config_patch": {},
            "secrets_patch": {
                "set": {
                    "API_KEY": {"redacted": false, "value": "supersecret"}
                },
                "delete": []
            },
            "webhook_ops": [],
            "subscription_ops": [],
            "oauth_ops": [],
            "notes": []
        },
        "diagnostics": ["supersecret"],
        "step_results": null
    });

    let runner = StubRunner {
        stdout: provision_result.to_string(),
        stderr: String::new(),
        status: success_status(),
    };

    let err = run_e2e_with_runner(
        E2eOptions {
            packs_dir: packs_dir.clone(),
            fixtures_root,
            ..E2eOptions::default()
        },
        &runner,
    )
    .expect_err("run e2e should fail");
    assert!(err.to_string().contains("report contains secret values"));
}

fn write_pack(path: &PathBuf, pack_id: &str) -> anyhow::Result<()> {
    let manifest = build_manifest(pack_id)?;
    let bytes = encode_pack_manifest(&manifest)?;

    let file = fs::File::create(path)?;
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::default();

    zip.start_file("manifest.cbor", opts)?;
    zip.write_all(&bytes)?;

    zip.start_file("assets/secret-requirements.json", opts)?;
    zip.write_all(json!([{"key": "API_KEY"}]).to_string().as_bytes())?;

    zip.finish()?;
    Ok(())
}

fn build_manifest(pack_id: &str) -> anyhow::Result<PackManifest> {
    let flow_id = FlowId::new("setup-flow")?;
    let mut entrypoints = BTreeMap::new();
    entrypoints.insert("setup".to_string(), serde_json::Value::Null);
    entrypoints.insert("requirements".to_string(), serde_json::Value::Null);

    let flow = Flow {
        schema_version: "1".to_string(),
        id: flow_id.clone(),
        kind: FlowKind::ComponentConfig,
        entrypoints,
        nodes: IndexMap::with_hasher(FlowHasher::default()),
        metadata: FlowMetadata::default(),
    };

    let entry = PackFlowEntry {
        id: flow_id,
        kind: FlowKind::ComponentConfig,
        flow,
        tags: Vec::new(),
        entrypoints: vec!["setup".to_string(), "requirements".to_string()],
    };

    Ok(PackManifest {
        schema_version: "pack-v1".to_string(),
        pack_id: PackId::new(pack_id)?,
        name: None,
        version: semver::Version::parse("0.1.0")?,
        kind: PackKind::Provider,
        publisher: "Greentic".to_string(),
        components: Vec::new(),
        flows: vec![entry],
        dependencies: Vec::new(),
        capabilities: Vec::new(),
        secret_requirements: Vec::new(),
        signatures: PackSignatures::default(),
        bootstrap: None,
        extensions: None,
    })
}

fn success_status() -> ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }
}
