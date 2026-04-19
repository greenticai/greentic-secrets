#!/usr/bin/env bash
set -euo pipefail

# Build provider-core components to wasm32-wasip2 and emit digests.
# Outputs artifacts to target/components and a digests.json manifest.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/target/components"
COMPONENT_FILTER_RAW="${COMPONENT_FILTER:-}"
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

VERSION="$(python3 - <<'PY'
import re
from pathlib import Path
text = Path("Cargo.toml").read_text()
match = re.search(r'\[workspace\.package\].*?^version\s*=\s*"([^"]+)"', text, re.M | re.S)
if not match:
    raise SystemExit("workspace.package.version not found")
print(match.group(1))
PY
)"

components=(
  "components/secrets-audit-exporter|secrets-audit-exporter|greentic.secrets.audit_exporter|greentic.secrets.audit_exporter"
  "components/secrets-provider-inmemory|secrets-provider-inmemory|greentic.secrets.provider.inmemory|greentic.secrets.provider.inmemory"
  "components/secrets-provider-aws-sm|secrets-provider-aws-sm|greentic.secrets.provider.aws_sm|greentic.secrets.provider.aws_sm"
  "components/secrets-provider-azure-kv|secrets-provider-azure-kv|greentic.secrets.provider.azure_kv|greentic.secrets.provider.azure_kv"
  "components/secrets-provider-gcp-sm|secrets-provider-gcp-sm|greentic.secrets.provider.gcp_sm|greentic.secrets.provider.gcp_sm"
  "components/secrets-provider-k8s|secrets-provider-k8s|greentic.secrets.provider.k8s|greentic.secrets.provider.k8s"
  "components/secrets-provider-vault-kv|secrets-provider-vault-kv|greentic.secrets.provider.vault_kv|greentic.secrets.provider.vault_kv"
)

component_selected() {
  local package_name="$1"
  local component_id="$2"
  local registry_name="$3"
  local item

  if [[ -z "${COMPONENT_FILTER_RAW}" ]]; then
    return 0
  fi

  IFS=',' read -ra requested <<< "${COMPONENT_FILTER_RAW}"
  for item in "${requested[@]}"; do
    item="$(printf '%s' "${item}" | xargs)"
    if [[ -z "${item}" ]]; then
      continue
    fi
    if [[ "${item}" == "${package_name}" || "${item}" == "${component_id}" || "${item}" == "${registry_name}" ]]; then
      return 0
    fi
  done
  return 1
}

echo "Building wasm components for version ${VERSION}"

rustup target add wasm32-wasip2 >/dev/null

registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greenticai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
REGISTRY_NAMESPACE="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"
echo "Publishing namespace: ${REGISTRY_NAMESPACE}"
if [[ -n "${COMPONENT_FILTER_RAW}" ]]; then
  echo "Component filter: ${COMPONENT_FILTER_RAW}"
fi

digests_json="${OUT_DIR}/digests.json"
echo "[]" > "${digests_json}"

for comp in "${components[@]}"; do
  IFS='|' read -r crate_path package_name component_id registry_name <<< "${comp}"
  if ! component_selected "${package_name}" "${component_id}" "${registry_name}"; then
    continue
  fi
  if [[ ! -d "${crate_path}" ]]; then
    echo "Skipping ${package_name}, path ${crate_path} not found" >&2
    continue
  fi
  echo ">> Building ${package_name}"
  cargo build -p "${package_name}" --release --target wasm32-wasip2
  artifact="${package_name//-/_}.wasm"
  wasm_path="${ROOT_DIR}/target/wasm32-wasip2/release/${artifact}"
  if [[ ! -f "${wasm_path}" ]]; then
    echo "  [ERROR] wasm artifact missing at ${wasm_path}" >&2
    exit 1
  fi
  local_path="${OUT_DIR}/${package_name}.wasm"
  cp "${wasm_path}" "${local_path}"
  content_digest="$(sha256sum "${wasm_path}" | awk '{print $1}')"
  ref="${REGISTRY_NAMESPACE}/${registry_name}:${VERSION}"
  local_ref="file://${local_path}"
  tmp="$(mktemp)"
  jq --arg id "${component_id}" --arg version "${VERSION}" --arg ref "${ref}" --arg digest "${content_digest}" --arg path "${package_name}.wasm" --arg local_ref "${local_ref}" \
    '. += [{"id":$id,"version":$version,"ref":$ref,"local_ref":$local_ref,"content_digest":$digest,"path":$path}]' \
    "${digests_json}" > "${tmp}"
  mv "${tmp}" "${digests_json}"
  echo "  built ${package_name}.wasm as ${component_id} content digest ${content_digest}"
done

echo "::notice::Component digests written to ${digests_json}"
