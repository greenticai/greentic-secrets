#!/usr/bin/env bash
set -euo pipefail

# Build enterprise provider .gtpack bundles from ./packs/<provider> using packc.
#
# Unlike the OAuth repo's descriptor packs, these provider packs resolve OCI
# component references during `greentic-pack resolve/build`, so the safe default
# is online mode. Callers can still force offline mode with `PACK_OFFLINE=1`.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist/packs}"
DIGESTS_JSON="$ROOT_DIR/target/components/digests.json"
VALIDATOR_PACK="$ROOT_DIR/dist/validators-secrets.gtpack"
PACKS_LOCKFILE="${PACKS_LOCKFILE:-$ROOT_DIR/packs.lock.json}"
PACK_OFFLINE="${PACK_OFFLINE:-0}"
registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greentic-ai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
components_registry="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"
oci_registry_host="${components_registry%%/*}"
ghcr_user="${GHCR_USERNAME:-${GITHUB_ACTOR:-${USER:-greentic-ai}}}"
ghcr_token="${gh_pat:-${GH_PAT:-${GHCR_TOKEN:-}}}"

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

providers=(
  aws-sm
  azure-kv
  gcp-sm
  k8s
  vault-kv
)
built_gtpacks=()

echo "Building provider packs for version ${VERSION}"
echo "Components registry namespace: ${components_registry}"

pack_mode_args=()
pack_mode_label="online"
if [[ "${PACK_OFFLINE}" == "1" ]]; then
  pack_mode_args=(--offline)
  pack_mode_label="offline"
fi
echo "Pack mode: ${pack_mode_label}"

if [[ -n "${ghcr_token}" ]]; then
  export GREENTIC_OCI_USERNAME="${GREENTIC_OCI_USERNAME:-${ghcr_user}}"
  export GREENTIC_OCI_PASSWORD="${GREENTIC_OCI_PASSWORD:-${ghcr_token}}"
  if command -v oras >/dev/null 2>&1; then
    printf '%s' "${ghcr_token}" | oras login "${oci_registry_host}" -u "${ghcr_user}" --password-stdin >/dev/null
    echo "Authenticated to ${oci_registry_host} as ${ghcr_user}"
  else
    echo "oras not found; relying on GREENTIC_OCI_USERNAME/GREENTIC_OCI_PASSWORD for OCI auth"
  fi
else
  echo "No GHCR token found in gh_pat/GH_PAT/GHCR_TOKEN; relying on existing OCI auth state"
fi

run_pack() {
  if [[ "${#pack_mode_args[@]}" -gt 0 ]]; then
    "$@" "${pack_mode_args[@]}"
  else
    "$@"
  fi
}

if [[ ! -f "${VALIDATOR_PACK}" ]]; then
  "${ROOT_DIR}/scripts/build-validator-pack.sh"
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
bundle_staging="${OUT_DIR}/secrets-providers"
rm -rf "${bundle_staging}"
mkdir -p "${bundle_staging}"
bundle_deps="${bundle_staging}/deps.tmp"
: > "${bundle_deps}"

for slug in "${providers[@]}"; do
  src="${ROOT_DIR}/packs/${slug}"
  if [[ ! -d "${src}" ]]; then
    echo "missing pack source: ${src}" >&2
    exit 1
  fi

  staging="${OUT_DIR}/secrets-${slug}"
  rm -rf "${staging}"
  mkdir -p "${staging}"

  rsync -a "${src}/" "${staging}/"

  # Inject version into manifest if placeholder present.
  for file in gtpack.yaml pack.yaml; do
    if [[ -f "${staging}/${file}" ]] && grep -q '__PACK_VERSION__' "${staging}/${file}"; then
      sed -i.bak "s/__PACK_VERSION__/${VERSION}/g" "${staging}/${file}"
      rm -f "${staging}/${file}.bak"
    fi
  done

  # Rewrite default component namespace so forks/orgs resolve correctly.
  sed -i.bak "s|ghcr.io/greentic-ai/components|${components_registry}|g" "${staging}/gtpack.yaml"
  rm -f "${staging}/gtpack.yaml.bak"

  # If digests are available, rewrite component URIs to pin them.
  if [[ -f "${DIGESTS_JSON}" ]]; then
    tmp="${staging}/gtpack.tmp.yaml"
    python3 - "$DIGESTS_JSON" "$staging/gtpack.yaml" > "${tmp}" <<'PY'
import json, sys, yaml
digests = {d["id"]: d for d in json.load(open(sys.argv[1]))}
manifest = yaml.safe_load(open(sys.argv[2]))
components = manifest.get("components") or []
for comp in components:
    did = comp.get("id")
    d = digests.get(did)
    if d:
        digest = str(d.get("digest", "")).strip()
        if digest.startswith("sha256:"):
            digest = digest[len("sha256:"):]
        comp["uri"] = f"{d['ref']}@sha256:{digest}"
manifest["components"] = components
yaml.safe_dump(manifest, sys.stdout, sort_keys=False)
PY
    mv "${tmp}" "${staging}/gtpack.yaml"
  fi

  python3 "${ROOT_DIR}/scripts/generate-flow-resolve-summary.py" "${staging}" "${DIGESTS_JSON}"

  LOCK_FILE="${staging}/pack.lock.json"
  run_pack greentic-pack resolve --in "${staging}" --lock "${LOCK_FILE}"
  run_pack greentic-pack build \
    --in "${staging}" \
    --lock "${LOCK_FILE}" \
    --gtpack-out "${OUT_DIR}/secrets-${slug}.gtpack" \
    --bundle none \
    --allow-oci-tags
  run_pack greentic-pack doctor \
    --validate \
    --pack "${OUT_DIR}/secrets-${slug}.gtpack" \
    --validator-pack "${VALIDATOR_PACK}" \
    --allow-oci-tags

  echo "::notice::built pack secrets-${slug}.gtpack"
  built_gtpacks+=("${OUT_DIR}/secrets-${slug}.gtpack")

  # Include in bundle deps.
  {
    echo "  - alias: ${slug}"
    echo "    pack_id: greentic.secrets.${slug}"
    echo "    version_req: \"=${VERSION}\""
  } >> "${bundle_staging}/deps.tmp"
done

if [[ "${#built_gtpacks[@]}" -gt 0 ]]; then
  "${ROOT_DIR}/scripts/validate-gtpack-extension.sh" "${built_gtpacks[@]}"
fi

echo "${VERSION}" > "${OUT_DIR}/VERSION"

# Build bundle pack with packc.
cat >"${bundle_staging}/pack.yaml" <<EOF
pack_id: greentic.secrets.providers
version: "${VERSION}"
kind: library
publisher: Greentic
components: []
dependencies:
$(sed 's/^/  /' "${bundle_staging}/deps.tmp")
flows: []
assets: []
EOF
rm -f "${bundle_staging}/deps.tmp"

LOCK_FILE="${bundle_staging}/pack.lock.json"
run_pack greentic-pack resolve --in "${bundle_staging}" --lock "${LOCK_FILE}"
run_pack greentic-pack build \
  --in "${bundle_staging}" \
  --lock "${LOCK_FILE}" \
  --gtpack-out "${OUT_DIR}/secrets-providers.gtpack" \
  --bundle none \
  --allow-oci-tags
run_pack greentic-pack doctor \
  --validate \
  --pack "${OUT_DIR}/secrets-providers.gtpack" \
  --validator-pack "${VALIDATOR_PACK}" \
  --allow-oci-tags

echo "::notice::built bundle pack secrets-providers.gtpack"

python3 - "${OUT_DIR}" "${VERSION}" "${PACKS_LOCKFILE}" <<'PY'
from pathlib import Path
import json
import os
import sys

out_dir = Path(sys.argv[1]).resolve()
version = sys.argv[2]
lock_path = Path(sys.argv[3]).resolve()
base_dir = lock_path.parent

packs = []
for pack_path in sorted(out_dir.glob("*.gtpack")):
    packs.append(
        {
            "name": pack_path.stem,
            "version": version,
            "artifact": os.path.relpath(pack_path, base_dir),
        }
    )

lock = {
    "version": version,
    "packs": packs,
}
lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
PY
