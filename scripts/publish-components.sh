#!/usr/bin/env bash
set -euo pipefail

# Build and push wasm components to GHCR with digests.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIGESTS="${ROOT_DIR}/target/components/digests.json"
registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greenticai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
export COMPONENTS_REGISTRY="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"

"${ROOT_DIR}/scripts/build-components.sh"

if [[ ! -f "${DIGESTS}" ]]; then
  echo "digests.json not found after build" >&2
  exit 1
fi

if ! command -v oras >/dev/null 2>&1; then
  echo "oras CLI is required; install it before running publish." >&2
  exit 1
fi

GIT_SHA="$(git rev-parse HEAD)"

echo "Pushing components to GHCR"
jq -c '.[]' "${DIGESTS}" | while read -r entry; do
  id=$(echo "${entry}" | jq -r '.id')
  ref=$(echo "${entry}" | jq -r '.ref')
  digest=$(echo "${entry}" | jq -r '.digest')
  path=$(echo "${entry}" | jq -r '.path')
  wasm_path="${ROOT_DIR}/target/components/${path}"
  if [[ ! -f "${wasm_path}" ]]; then
    echo "[ERROR] missing artifact ${wasm_path}" >&2
    exit 1
  fi
  oras push "${ref}" \
    --disable-path-validation \
    "${wasm_path}:application/vnd.greentic.wasm.component" \
    --annotation "org.opencontainers.image.revision=${GIT_SHA}" \
    --annotation "greentic.component.id=${id}" \
    --annotation "greentic.component.digest=${digest}"
  echo "::notice::pushed ${ref}"
done
