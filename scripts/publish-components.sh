#!/usr/bin/env bash
set -euo pipefail

# Build and push wasm components to GHCR with digests.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIGESTS="${ROOT_DIR}/target/components/digests.json"
registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greenticai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
export COMPONENTS_REGISTRY="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"
COMPONENT_FILTER_RAW="${COMPONENT_FILTER:-}"

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
if [[ -n "${COMPONENT_FILTER_RAW}" ]]; then
  echo "Publishing component filter: ${COMPONENT_FILTER_RAW}"
fi
jq -c '.[]' "${DIGESTS}" | while read -r entry; do
  id=$(echo "${entry}" | jq -r '.id')
  ref=$(echo "${entry}" | jq -r '.ref')
  content_digest=$(echo "${entry}" | jq -r '.content_digest // .digest // empty')
  path=$(echo "${entry}" | jq -r '.path')
  if [[ -n "${COMPONENT_FILTER_RAW}" ]]; then
    package_name="${path%.wasm}"
    registry_name="${ref##*/}"
    registry_name="${registry_name%%:*}"
    match=0
    IFS=',' read -ra requested <<< "${COMPONENT_FILTER_RAW}"
    for item in "${requested[@]}"; do
      item="$(printf '%s' "${item}" | xargs)"
      if [[ -z "${item}" ]]; then
        continue
      fi
      if [[ "${item}" == "${id}" || "${item}" == "${package_name}" || "${item}" == "${registry_name}" ]]; then
        match=1
        break
      fi
    done
    if [[ "${match}" != "1" ]]; then
      continue
    fi
  fi
  wasm_path="${ROOT_DIR}/target/components/${path}"
  if [[ ! -f "${wasm_path}" ]]; then
    echo "[ERROR] missing artifact ${wasm_path}" >&2
    exit 1
  fi
  push_output="$(oras push "${ref}" \
    --disable-path-validation \
    "${wasm_path}:application/vnd.greentic.wasm.component" \
    --annotation "org.opencontainers.image.revision=${GIT_SHA}" \
    --annotation "greentic.component.id=${id}" \
    --annotation "greentic.component.digest=${content_digest}" 2>&1)"
  printf '%s\n' "${push_output}"
  oci_digest="$(printf '%s\n' "${push_output}" | awk '/Digest:/ {print $2}' | tail -n1)"
  if [[ -z "${oci_digest}" ]]; then
    echo "[ERROR] could not determine OCI manifest digest for ${ref}" >&2
    exit 1
  fi
  tmp="$(mktemp)"
  jq --arg id "${id}" --arg ref "${ref}" --arg oci_digest "${oci_digest}" \
    'map(if .id == $id and .ref == $ref then . + {"oci_digest": $oci_digest} else . end)' \
    "${DIGESTS}" > "${tmp}"
  mv "${tmp}" "${DIGESTS}"
  echo "::notice::pushed ${ref} (${oci_digest})"
done
