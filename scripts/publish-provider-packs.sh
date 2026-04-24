#!/usr/bin/env bash
set -euo pipefail

# Push built provider pack artifacts to GHCR with both immutable version tags
# and a moving latest tag.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKS_DIR="${PACKS_DIR:-$ROOT_DIR/dist/packs}"
REGISTRY_OWNER="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greenticai}}"
LATEST_TAG="${LATEST_TAG:-latest}"

VERSION_FILE="${PACKS_DIR}/VERSION"
if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "[ERROR] missing ${VERSION_FILE}; build provider packs first" >&2
  exit 1
fi

VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"
if [[ -z "${VERSION}" ]]; then
  echo "[ERROR] ${VERSION_FILE} did not contain a version" >&2
  exit 1
fi

push_pack_ref() {
  local artifact="$1"
  local name="$2"
  local tag="$3"
  local ref="ghcr.io/${REGISTRY_OWNER}/greentic-packs/${name}:${tag}"
  oras push "${ref}" "${artifact}:application/vnd.greentic.pack+zip"
  echo "::notice::Pushed ${ref}"
}

for pack in "${PACKS_DIR}"/secrets-*.gtpack; do
  if [[ ! -f "${pack}" ]]; then
    echo "[ERROR] no provider pack artifacts found in ${PACKS_DIR}" >&2
    exit 1
  fi
  name="$(basename "${pack}" .gtpack)"
  push_pack_ref "${pack}" "${name}" "${VERSION}"
  push_pack_ref "${pack}" "${name}" "${LATEST_TAG}"
done

bundle="${PACKS_DIR}/secrets-providers.gtpack"
if [[ ! -f "${bundle}" ]]; then
  echo "[ERROR] missing bundle artifact ${bundle}" >&2
  exit 1
fi
push_pack_ref "${bundle}" "secrets-providers" "${VERSION}"
push_pack_ref "${bundle}" "secrets-providers" "${LATEST_TAG}"
