#!/usr/bin/env bash
set -euo pipefail

# Build enterprise provider .gtpack bundles from ./packs/<provider> using packc.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist/packs}"
DIGESTS_JSON="$ROOT_DIR/target/components/digests.json"
VALIDATOR_PACK="$ROOT_DIR/dist/validators-secrets.gtpack"

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

  # If digests are available, rewrite component URIs to pin them.
  if [[ -f "${DIGESTS_JSON}" ]]; then
    tmp="${staging}/gtpack.tmp.yaml"
    python3 - "$DIGESTS_JSON" "$staging/gtpack.yaml" > "${tmp}" <<'PY'
import json, sys, yaml
digests = {d["id"]: d for d in json.load(open(sys.argv[1]))}
manifest = yaml.safe_load(open(sys.argv[2]))
for comp in manifest.get("components", []):
    did = comp.get("id")
    d = digests.get(did)
    if d:
        comp["uri"] = f"{d['ref']}@sha256:{d['digest']}"
yaml.safe_dump(manifest, sys.stdout, sort_keys=False)
PY
    mv "${tmp}" "${staging}/gtpack.yaml"
  fi

  python3 "${ROOT_DIR}/scripts/generate-flow-resolve-summary.py" "${staging}" "${DIGESTS_JSON}"

  LOCK_FILE="${staging}/pack.lock.json"
  greentic-pack resolve --in "${staging}" --lock "${LOCK_FILE}" --offline
  greentic-pack build \
    --in "${staging}" \
    --lock "${LOCK_FILE}" \
    --gtpack-out "${OUT_DIR}/secrets-${slug}.gtpack" \
    --bundle none \
    --offline \
    --allow-oci-tags
  greentic-pack doctor \
    --validate \
    --pack "${OUT_DIR}/secrets-${slug}.gtpack" \
    --validator-pack "${VALIDATOR_PACK}" \
    --offline \
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
greentic-pack resolve --in "${bundle_staging}" --lock "${LOCK_FILE}" --offline
greentic-pack build \
  --in "${bundle_staging}" \
  --lock "${LOCK_FILE}" \
  --gtpack-out "${OUT_DIR}/secrets-providers.gtpack" \
  --bundle none \
  --offline \
  --allow-oci-tags
greentic-pack doctor \
  --validate \
  --pack "${OUT_DIR}/secrets-providers.gtpack" \
  --validator-pack "${VALIDATOR_PACK}" \
  --offline \
  --allow-oci-tags

echo "::notice::built bundle pack secrets-providers.gtpack"
