#!/usr/bin/env bash
set -euo pipefail

# Audits secrets provider packs for Operator capability-offer readiness.
# Default mode is informational and never fails CI.
# Set STRICT=1 to fail when required capability offers are missing.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STRICT="${STRICT:-0}"

missing=0
total=0

for pack in "${ROOT_DIR}"/packs/*/pack.yaml; do
  [[ -f "${pack}" ]] || continue

  # Audit only pack manifests that declare provider-extension metadata.
  if ! rg -q "greentic\\.provider-extension\\.v1" "${pack}"; then
    continue
  fi

  total=$((total + 1))
  rel="${pack#${ROOT_DIR}/}"

  has_ext=0
  has_cap=0
  if rg -q "greentic\\.ext\\.capabilities\\.v1" "${pack}"; then
    has_ext=1
  fi
  if rg -q "greentic\\.cap\\.secrets\\.store\\.v1" "${pack}"; then
    has_cap=1
  fi

  if [[ "${has_ext}" -eq 1 && "${has_cap}" -eq 1 ]]; then
    echo "OK   ${rel} (capability offers present)"
    continue
  fi

  missing=$((missing + 1))
  echo "WARN ${rel} (missing greentic.ext.capabilities.v1 / greentic.cap.secrets.store.v1)"
done

echo
echo "Audited packs: ${total}"
echo "Missing capability-offer mapping: ${missing}"

if [[ "${STRICT}" == "1" && "${missing}" -gt 0 ]]; then
  echo "STRICT=1 -> failing due to missing capability-offer mapping"
  exit 1
fi

