#!/usr/bin/env bash
set -euo pipefail

# Build and push wasm components to GHCR with digests.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIGESTS="${ROOT_DIR}/target/components/digests.json"
registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greenticai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
export COMPONENTS_REGISTRY="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"
COMPONENT_FILTER_RAW="${COMPONENT_FILTER:-}"
ORAS_LOGIN_MODE="${ORAS_LOGIN_MODE:-auto}"

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
REGISTRY_HOST="${COMPONENTS_REGISTRY%%/*}"
OCI_USERNAME="${ORAS_USERNAME:-${GREENTIC_OCI_USERNAME:-${GHCR_USER:-}}}"
OCI_PASSWORD="${ORAS_PASSWORD:-${GREENTIC_OCI_PASSWORD:-${GHCR_TOKEN:-}}}"

maybe_oras_login() {
  case "${ORAS_LOGIN_MODE}" in
    skip)
      echo "Skipping oras login because ORAS_LOGIN_MODE=skip"
      return 0
      ;;
    auto)
      if [[ -z "${OCI_USERNAME}" || -z "${OCI_PASSWORD}" ]]; then
        echo "Skipping oras login because no OCI credentials were provided"
        echo "Set one of: ORAS_USERNAME/ORAS_PASSWORD, GREENTIC_OCI_USERNAME/GREENTIC_OCI_PASSWORD, or GHCR_USER/GHCR_TOKEN"
        return 0
      fi
      ;;
    require)
      if [[ -z "${OCI_USERNAME}" || -z "${OCI_PASSWORD}" ]]; then
        echo "[ERROR] ORAS_LOGIN_MODE=require but OCI credentials are missing" >&2
        echo "[ERROR] Set ORAS_USERNAME/ORAS_PASSWORD, GREENTIC_OCI_USERNAME/GREENTIC_OCI_PASSWORD, or GHCR_USER/GHCR_TOKEN" >&2
        exit 1
      fi
      ;;
    *)
      echo "[ERROR] unsupported ORAS_LOGIN_MODE=${ORAS_LOGIN_MODE}" >&2
      echo "[ERROR] expected one of: auto, require, skip" >&2
      exit 1
      ;;
  esac

  echo "Logging into ${REGISTRY_HOST} as ${OCI_USERNAME} using env-provided credentials"
  printf '%s\n' "${OCI_PASSWORD}" | oras login "${REGISTRY_HOST}" -u "${OCI_USERNAME}" --password-stdin
}

maybe_oras_login

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
  echo ">> Preparing push for ${id}"
  echo "   ref: ${ref}"
  echo "   wasm: ${wasm_path}"
  echo "   content digest: ${content_digest}"
  echo "   size bytes: $(stat -c%s "${wasm_path}")"
  echo "   checking GHCR auth with oras discover ${ref}"
  auth_probe_output="$(oras discover "${ref}" 2>&1 || true)"
  printf '%s\n' "${auth_probe_output}"
  echo "   starting oras push for ${ref}"
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
    echo "[ERROR] full oras push output was printed above" >&2
    exit 1
  fi
  tmp="$(mktemp)"
  jq --arg id "${id}" --arg ref "${ref}" --arg oci_digest "${oci_digest}" \
    'map(if .id == $id and .ref == $ref then . + {"oci_digest": $oci_digest} else . end)' \
    "${DIGESTS}" > "${tmp}"
  mv "${tmp}" "${DIGESTS}"
  echo "::notice::pushed ${ref} (${oci_digest})"
done
