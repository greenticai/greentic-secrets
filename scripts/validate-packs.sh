#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="${ROOT_DIR}/packs"
PROVIDER_EXTENSION_ID="greentic.provider-extension.v1"

required_flows=(
  provider_onboard.ygtc
  provider_validate.ygtc
  provider_read_secret.ygtc
  provider_write_secret.ygtc
  provider_export_audit.ygtc
  provider_breakglass.ygtc
)

error=false

for pack in "${PACK_DIR}"/*; do
  [[ -d "${pack}" ]] || continue
  name=$(basename "${pack}")
  manifest="${pack}/pack.yaml"
  meta="${pack}/metadata.json"
  pack_json="${pack}/pack.json"
  cfg_schema="${pack}/schemas/secrets/${name}/config.schema.json"
  sec_schema="${pack}/schemas/secrets/${name}/secret.schema.json"
  state_schema="${pack}/schemas/secrets/${name}/state.schema.json"
  reqs_file="${pack}/secret-requirements.json"
  wasm_requirements="${pack}/wasm/setup_default__requirements.wat"
  wasm_collect="${pack}/wasm/setup_default__collect.wat"
  wasm_validate="${pack}/wasm/setup_default__validate.wat"
  wasm_apply="${pack}/wasm/setup_default__apply.wat"
  wasm_summary="${pack}/wasm/setup_default__summary.wat"

  echo "Validating pack ${name}"

  if [[ ! -f "${manifest}" ]]; then
    echo "  [ERROR] missing manifest ${manifest}" >&2; error=true; continue
  fi
  if [[ ! -f "${meta}" ]]; then
    echo "  [ERROR] missing metadata ${meta}" >&2; error=true
  fi
  if [[ ! -f "${pack_json}" ]]; then
    echo "  [ERROR] missing pack.json ${pack_json}" >&2; error=true
  fi
  if [[ ! -f "${reqs_file}" ]]; then
    echo "  [ERROR] missing secret requirements ${reqs_file}" >&2; error=true
  fi
  if [[ ! -f "${cfg_schema}" || ! -f "${sec_schema}" ]]; then
    echo "  [ERROR] missing schema files in ${pack}/schemas/secrets/${name}" >&2; error=true
  fi
  if [[ ! -f "${state_schema}" ]]; then
    echo "  [WARN] missing state schema (optional) ${state_schema}" >&2
  fi
  if [[ ! -f "${wasm_requirements}" || ! -f "${wasm_collect}" || ! -f "${wasm_validate}" || ! -f "${wasm_apply}" || ! -f "${wasm_summary}" ]]; then
    echo "  [ERROR] missing provisioning wasm in ${pack}/wasm" >&2; error=true
  fi
  for flow in "${required_flows[@]}"; do
    if [[ ! -f "${pack}/flows/${flow}" ]]; then
      echo "  [ERROR] missing flow ${flow}" >&2; error=true
    fi
  done

  # Basic manifest sanity with python (yaml required fields + provider ext).
  python3 - <<PY
import sys, yaml, pathlib
EXT_ID = "${PROVIDER_EXTENSION_ID}"
p = pathlib.Path("${manifest}")
data = yaml.safe_load(p.read_text())
required_entrypoints = ["onboard","validate","read_secret","write_secret","export_audit","breakglass"]
flow_entrypoints = set()
for flow in data.get("flows") or []:
    for entry in flow.get("entrypoints") or []:
        flow_entrypoints.add(entry)
missing = [e for e in required_entrypoints if e not in flow_entrypoints]
if missing:
    print(f"[ERROR] {p}: missing entrypoints {missing}")
    sys.exit(1)
exts = (data.get("extensions") or {}).get(EXT_ID) or {}
if not exts:
    print(f"[ERROR] {p}: missing extensions.{EXT_ID}")
    sys.exit(1)
kind = exts.get("kind")
if kind != EXT_ID:
    print(f"[ERROR] {p}: provider extension kind must be {EXT_ID}, got {kind!r}")
    sys.exit(1)
version = exts.get("version")
if version != "1.0.0":
    print(f"[ERROR] {p}: provider extension version must be 1.0.0")
    sys.exit(1)
inline = exts.get("inline") or {}
providers = inline.get("providers") or []
if not providers:
    print(f"[ERROR] {p}: provider extension inline.providers missing")
    sys.exit(1)
runtime = (providers[0] or {}).get("runtime") or {}
if runtime.get("world") != "greentic:provider/schema-core@1.0.0":
    print(f"[ERROR] {p}: provider extension runtime.world must be greentic:provider/schema-core@1.0.0")
    sys.exit(1)
if not runtime.get("component_ref") or not runtime.get("export"):
    print(f"[ERROR] {p}: provider extension runtime must set component_ref and export")
    sys.exit(1)
config_ref = providers[0].get("config_schema_ref")
expected_ref = f"assets/schemas/secrets/{p.parent.name}/config.schema.json"
if config_ref != expected_ref:
    print(f"[ERROR] {p}: provider extension config_schema_ref must be {expected_ref}")
    sys.exit(1)
PY
done

if [[ "${error}" == "true" ]]; then
  echo "Pack validation failed" >&2
  exit 1
fi

echo "All packs validated."
