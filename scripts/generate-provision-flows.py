import json
import re
from pathlib import Path

SLUGS = ["aws-sm", "azure-kv", "gcp-sm", "k8s", "vault-kv"]
ROOT = Path(__file__).resolve().parent.parent
AUDIT_CREDENTIAL_SLUGS = {"aws-sm", "azure-kv", "gcp-sm"}
AUDIT_CREDENTIAL_SINKS = ["splunk", "azure", "gcp", "http"]


def extract_pack_id(pack_yaml: Path) -> str:
    text = pack_yaml.read_text()
    match = re.search(r"^pack_id:\s*(\S+)", text, re.M)
    if not match:
        raise SystemExit(f"pack_id not found in {pack_yaml}")
    return match.group(1)


def placeholder_from_schema(schema: dict):
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    schema_type = schema.get("type")
    if schema_type == "object":
        props = schema.get("properties", {})
        required = schema.get("required", [])
        return {key: placeholder_from_schema(props.get(key, {})) for key in required}
    if schema_type == "array":
        return []
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1
    if schema_type == "boolean":
        return True
    return "placeholder"


def write_wat(path: Path, payload: dict):
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    escaped = raw.replace("\\", "\\\\").replace('"', '\\"')
    wasm = "\n".join([
        "(module",
        "  (memory (export \"memory\") 1)",
        f"  (data (i32.const 0) \"{escaped}\")",
        "  (func (export \"run\") (param i32 i32) (result i32 i32)",
        "    (i32.const 0)",
        f"    (i32.const {len(raw)})",
        "  )",
        ")",
        "",
    ])
    path.write_text(wasm)


def enum_constraints(schema: dict):
    constraints = {}
    for key, value in schema.get("properties", {}).items():
        if isinstance(value, dict) and "enum" in value:
            constraints[key] = value["enum"]
    return constraints


def secret_key(item: dict):
    return item.get("id") or item.get("key")


for slug in SLUGS:
    pack_dir = ROOT / "packs" / slug
    pack_yaml = pack_dir / "pack.yaml"
    pack_id = extract_pack_id(pack_yaml)

    config_path = pack_dir / "schemas" / "secrets" / slug / "config.schema.json"
    secret_req_path = pack_dir / "secret-requirements.json"

    config = json.loads(config_path.read_text())
    secrets = json.loads(secret_req_path.read_text())

    required_config = config.get("required", [])
    optional_config = [key for key in config.get("properties", {}).keys() if key not in required_config]

    config_input = {
        key: placeholder_from_schema(config.get("properties", {}).get(key, {}))
        for key in required_config
    }

    secret_required = [secret_key(item) for item in secrets if item.get("required")]
    secret_optional = [secret_key(item) for item in secrets if not item.get("required")]
    setup_secret_keys = (
        secret_required
        if slug in AUDIT_CREDENTIAL_SLUGS
        else [secret_key(item) for item in secrets]
    )
    secret_constraints = {}
    if slug in AUDIT_CREDENTIAL_SLUGS:
        secret_constraints["required_when"] = {
            "audit_sink_credentials": {
                "config_path": "audit.sink_type",
                "values": AUDIT_CREDENTIAL_SINKS,
            }
        }

    requirements = {
        "provider_id": pack_id,
        "config": {
            "required": required_config,
            "optional": optional_config,
            "constraints": {"enum": enum_constraints(config)},
        },
        "secrets": {
            "required": secret_required,
            "optional": secret_optional,
            "constraints": secret_constraints,
        },
        "capabilities": {
            "supports_read": True,
            "supports_write": True,
            "supports_delete": True,
        },
        "setup_needs": {
            "public_base_url": False,
            "oauth": False,
            "subscriptions": False,
        },
    }

    setup_input = {
        "config": config_input,
        "secrets": {key: f"fake_{key}" for key in setup_secret_keys},
    }

    plan = {
        "config_patch": config_input,
        "secrets_patch": {
            "set": {key: {"redacted": True, "value": None} for key in setup_secret_keys},
            "delete": [],
        },
        "webhook_ops": [],
        "subscription_ops": [],
        "oauth_ops": [],
        "notes": [],
    }

    fixtures_dir = pack_dir / "fixtures"
    fixtures_dir.mkdir(exist_ok=True)

    (fixtures_dir / "requirements.expected.json").write_text(
        json.dumps(requirements, indent=2) + "\n"
    )
    (fixtures_dir / "setup.input.json").write_text(
        json.dumps(setup_input, indent=2) + "\n"
    )
    (fixtures_dir / "setup.expected.plan.json").write_text(
        json.dumps(plan, indent=2) + "\n"
    )

    wasm_dir = pack_dir / "wasm"
    wasm_dir.mkdir(exist_ok=True)

    write_wat(wasm_dir / "setup_default__requirements.wat", {"requirements": requirements})
    write_wat(
        wasm_dir / "setup_default__collect.wat",
        {
            "questions": {
                "config_required": required_config,
                "secrets_required": secret_required,
            }
        },
    )
    write_wat(wasm_dir / "setup_default__validate.wat", {"diagnostics": []})
    write_wat(wasm_dir / "setup_default__apply.wat", {"plan": plan})
    write_wat(
        wasm_dir / "setup_default__summary.wat",
        {"summary": {"status": "configured", "install_id": "install"}},
    )

    pack_json = {
        "id": pack_id,
        "version": "__PACK_VERSION__",
        "meta": {
            "entry_flows": {"setup": "setup_default", "requirements": "requirements"},
            "requires_public_base_url": False,
            "capabilities": [],
        },
        "flows": [
            {"entry": "setup", "id": "setup_default"},
            {"entry": "requirements", "id": "requirements"},
        ],
    }
    (pack_dir / "pack.json").write_text(json.dumps(pack_json, indent=2) + "\n")
