#!/usr/bin/env bash
set -euo pipefail

# Build and push the secrets pack validator wasm component to GHCR.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIGESTS="${ROOT_DIR}/target/validators/digests.json"

"${ROOT_DIR}/scripts/build-validator-component.sh"

if [[ ! -f "${DIGESTS}" ]]; then
  echo "digests.json not found after build" >&2
  exit 1
fi

if ! command -v oras >/dev/null 2>&1; then
  echo "oras CLI is required; install it before running publish." >&2
  exit 1
fi

GIT_SHA="$(git rev-parse HEAD)"

echo "Pushing validator component to GHCR"
jq -c '.[]' "${DIGESTS}" | while read -r entry; do
  id=$(echo "${entry}" | jq -r '.id')
  ref=$(echo "${entry}" | jq -r '.ref')
  digest=$(echo "${entry}" | jq -r '.digest')
  path=$(echo "${entry}" | jq -r '.path')
  wasm_path="${ROOT_DIR}/target/validators/${path}"
  if [[ ! -f "${wasm_path}" ]]; then
    echo "[ERROR] missing artifact ${wasm_path}" >&2
    exit 1
  fi
  push_output="$(oras push "${ref}" \
    --disable-path-validation \
    "${wasm_path}:application/vnd.greentic.wasm.component" \
    --annotation "org.opencontainers.image.revision=${GIT_SHA}" \
    --annotation "greentic.component.id=${id}" \
    --annotation "greentic.component.digest=${digest}" 2>&1)"
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
