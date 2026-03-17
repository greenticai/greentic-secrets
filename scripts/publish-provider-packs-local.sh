#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

PACK_USE_LOCAL_COMPONENTS="${PACK_USE_LOCAL_COMPONENTS:-1}"

PACKS_REGISTRY="${PACKS_REGISTRY:-${OCI_REGISTRY:-ghcr.io}}"
PACKS_NAMESPACE="${PACKS_NAMESPACE:-${OCI_NAMESPACE:-${GITHUB_REPOSITORY_OWNER:-greenticai}}}"
PACKS_REPO="${PACKS_REPO:-${OCI_REPO:-packs/secrets}}"

OCI_USERNAME="${OCI_USERNAME:-${GHCR_USERNAME:-${GITHUB_ACTOR:-${USER:-}}}}"
OCI_TOKEN="${OCI_TOKEN:-${GHCR_TOKEN:-${GITHUB_TOKEN:-${GH_PAT:-${gh_pat:-}}}}}"

echo "==> Build secrets provider packs"
PACKS_REGISTRY="${PACKS_REGISTRY}" \
PACKS_NAMESPACE="${PACKS_NAMESPACE}" \
PACKS_REPO="${PACKS_REPO}" \
PACK_USE_LOCAL_COMPONENTS="${PACK_USE_LOCAL_COMPONENTS}" \
./scripts/build-provider-packs.sh

if ! command -v oras >/dev/null 2>&1; then
  echo "oras is required for publish." >&2
  exit 1
fi

if [[ -n "${OCI_TOKEN}" ]]; then
  if [[ -z "${OCI_USERNAME}" ]]; then
    echo "OCI_USERNAME (or GHCR_USERNAME) is required when OCI_TOKEN is set." >&2
    exit 1
  fi
  echo "==> Authenticate to ${PACKS_REGISTRY} as ${OCI_USERNAME}"
  printf '%s' "${OCI_TOKEN}" | oras login "${PACKS_REGISTRY}" -u "${OCI_USERNAME}" --password-stdin >/dev/null
else
  echo "warning: OCI_TOKEN/GHCR_TOKEN not set; relying on existing oras login state"
fi

echo "==> Publish secrets packs (version + latest tags)"
OCI_REGISTRY="${PACKS_REGISTRY}" \
OCI_NAMESPACE="${PACKS_NAMESPACE}" \
OCI_REPO="${PACKS_REPO}" \
PACK_VERSION="${PACK_VERSION:-}" \
./scripts/publish-provider-packs.sh

if command -v jq >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/packs.lock.json" ]]; then
  echo "==> Published references"
  jq -r '.packs[] | [.name, .reference, (.latest_reference // "")] | @tsv' "${ROOT_DIR}/packs.lock.json"
fi
