#!/usr/bin/env bash
set -euo pipefail

# Build provider-core components to wasm32-wasip2 and emit digests.
# Outputs artifacts to target/components and a digests.json manifest.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/target/components"
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
  secrets-provider-inmemory
  secrets-provider-aws-sm
  secrets-provider-azure-kv
  secrets-provider-gcp-sm
  secrets-provider-k8s
  secrets-provider-vault-kv
)

echo "Building wasm components for version ${VERSION}"

rustup target add wasm32-wasip2 >/dev/null

REGISTRY_NAMESPACE="ghcr.io/greenticai/components"
echo "Publishing namespace: ${REGISTRY_NAMESPACE}"

digests_json="${OUT_DIR}/digests.json"
echo "[]" > "${digests_json}"

for comp in "${components[@]}"; do
  crate_path="components/${comp}"
  if [[ ! -d "${crate_path}" ]]; then
    echo "Skipping ${comp}, path ${crate_path} not found" >&2
    continue
  fi
  echo ">> Building ${comp}"
  cargo build -p "${comp}" --release --target wasm32-wasip2
  artifact="${comp//-/_}.wasm"
  wasm_path="${ROOT_DIR}/target/wasm32-wasip2/release/${artifact}"
  if [[ ! -f "${wasm_path}" ]]; then
    echo "  [ERROR] wasm artifact missing at ${wasm_path}" >&2
    exit 1
  fi
  cp "${wasm_path}" "${OUT_DIR}/${comp}.wasm"
  digest="$(sha256sum "${wasm_path}" | awk '{print $1}')"
  ref="${REGISTRY_NAMESPACE}/${comp}:${VERSION}"
  tmp="$(mktemp)"
  jq --arg id "${comp}" --arg version "${VERSION}" --arg ref "${ref}" --arg digest "${digest}" --arg path "${comp}.wasm" \
    '. += [{"id":$id,"version":$version,"ref":$ref,"digest":$digest,"path":$path}]' \
    "${digests_json}" > "${tmp}"
  mv "${tmp}" "${digests_json}"
  echo "  built ${comp}.wasm digest ${digest}"
done

echo "::notice::Component digests written to ${digests_json}"
