#!/usr/bin/env bash
set -euo pipefail

# Build enterprise provider .gtpack bundles from ./packs/<provider> using packc.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist/packs}"
DIGESTS_JSON="$ROOT_DIR/target/components/digests.json"
VALIDATOR_PACK="$ROOT_DIR/dist/validators-secrets.gtpack"
PACK_OFFLINE="${PACK_OFFLINE:-1}"
PACK_USE_LOCAL_COMPONENTS="${PACK_USE_LOCAL_COMPONENTS:-auto}"
registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greenticai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
components_registry="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"
PREBUILD_COMPONENTS="${PREBUILD_COMPONENTS:-auto}"
SHARED_COMPONENT_FILTER="${SHARED_COMPONENT_FILTER:-greentic.secrets.audit_exporter}"

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
echo "Shared component policy: ${PREBUILD_COMPONENTS}"
if [[ "${PACK_OFFLINE}" == "1" ]]; then
  PACK_MODE_ARGS=(--offline)
  echo "Pack mode: offline"
else
  PACK_MODE_ARGS=()
  echo "Pack mode: online"
fi

if [[ ! -f "${VALIDATOR_PACK}" ]]; then
  "${ROOT_DIR}/scripts/build-validator-pack.sh"
fi

if [[ "${PREBUILD_COMPONENTS}" == "1" || "${PREBUILD_COMPONENTS}" == "true" || "${PREBUILD_COMPONENTS}" == "yes" || "${PREBUILD_COMPONENTS}" == "auto" ]]; then
  need_prebuild=0
  if [[ "${PREBUILD_COMPONENTS}" != "auto" || ! -f "${DIGESTS_JSON}" ]]; then
    need_prebuild=1
  elif ! python3 - "${DIGESTS_JSON}" "${SHARED_COMPONENT_FILTER}" <<'PY'
import json, sys
path, raw = sys.argv[1], sys.argv[2]
requested = {item.strip() for item in raw.split(",") if item.strip()}
if not requested:
    raise SystemExit(0)
entries = json.load(open(path))
present = set()
for entry in entries:
    present.add(entry.get("id"))
    ref = entry.get("ref", "")
    if ref:
        present.add(ref.rsplit("/", 1)[-1].split(":", 1)[0])
    component_path = entry.get("path", "")
    if component_path.endswith(".wasm"):
        present.add(component_path[:-5])
missing = requested - present
raise SystemExit(1 if missing else 0)
PY
  then
    need_prebuild=1
  fi

  if [[ "${need_prebuild}" == "1" ]]; then
    echo "Prebuilding shared components: ${SHARED_COMPONENT_FILTER}"
    COMPONENT_FILTER="${SHARED_COMPONENT_FILTER}" "${ROOT_DIR}/scripts/build-components.sh"
    if [[ "${PACK_OFFLINE}" == "1" ]]; then
      echo "Note: offline pack builds still require those component OCI refs to be published or already cached."
      echo "      Prebuilding refreshes local wasm digests, but does not populate greentic-pack's OCI cache."
    fi
  else
    echo "Shared component digests already present for: ${SHARED_COMPONENT_FILTER}"
  fi
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
  sed -i.bak "s|ghcr.io/greenticai/components|${components_registry}|g" "${staging}/gtpack.yaml"
  rm -f "${staging}/gtpack.yaml.bak"

  # If digests are available, rewrite component URIs to pin them.
  # When PACK_USE_LOCAL_COMPONENTS is enabled and locally-built WASMs exist,
  # use file:// URIs so greentic-pack resolves from disk (no OCI pull needed).
  # This avoids "Not authorized" errors when OCI credentials are unavailable.
  use_local="0"
  if [[ "${PACK_USE_LOCAL_COMPONENTS}" == "1" || "${PACK_USE_LOCAL_COMPONENTS}" == "true" ]]; then
    use_local="1"
  elif [[ "${PACK_USE_LOCAL_COMPONENTS}" == "auto" && -f "${DIGESTS_JSON}" ]]; then
    # Auto-detect: use local files when digests exist and all referenced WASMs are present
    use_local="1"
    while IFS= read -r wasm_path; do
      if [[ ! -f "${OUT_DIR}/../components/${wasm_path}" && ! -f "${ROOT_DIR}/target/components/${wasm_path}" ]]; then
        use_local="0"
        break
      fi
    done < <(python3 -c "import json,sys; [print(e['path']) for e in json.load(open(sys.argv[1]))]" "${DIGESTS_JSON}" 2>/dev/null || true)
  fi

  if [[ -f "${DIGESTS_JSON}" ]]; then
    tmp="${staging}/gtpack.tmp.yaml"
    python3 - "$DIGESTS_JSON" "$staging/gtpack.yaml" "${use_local}" "${ROOT_DIR}/target/components" > "${tmp}" <<'PY'
import json, sys, os, yaml
digests = {d["id"]: d for d in json.load(open(sys.argv[1]))}
manifest = yaml.safe_load(open(sys.argv[2]))
use_local = sys.argv[3] == "1"
components_dir = sys.argv[4]
for comp in manifest.get("components", []):
    did = comp.get("id")
    d = digests.get(did)
    if d:
        wasm_path = os.path.join(components_dir, d.get("path", ""))
        if use_local and os.path.isfile(wasm_path):
            comp["uri"] = f"file://{os.path.abspath(wasm_path)}"
        else:
            oci_digest = str(d.get("oci_digest", "")).strip()
            if oci_digest:
                if not oci_digest.startswith("sha256:"):
                    oci_digest = f"sha256:{oci_digest}"
                comp["uri"] = f"{d['ref']}@{oci_digest}"
            else:
                comp["uri"] = d["ref"]
yaml.safe_dump(manifest, sys.stdout, sort_keys=False)
PY
    mv "${tmp}" "${staging}/gtpack.yaml"
  fi

  python3 "${ROOT_DIR}/scripts/generate-flow-resolve-summary.py" "${staging}" "${DIGESTS_JSON}"

  LOCK_FILE="${staging}/pack.lock.json"
  greentic-pack resolve --in "${staging}" --lock "${LOCK_FILE}" "${PACK_MODE_ARGS[@]}"
  greentic-pack build \
    --in "${staging}" \
    --lock "${LOCK_FILE}" \
    --gtpack-out "${OUT_DIR}/secrets-${slug}.gtpack" \
    --bundle none \
    "${PACK_MODE_ARGS[@]}" \
    --allow-oci-tags
  greentic-pack doctor \
    --validate \
    --pack "${OUT_DIR}/secrets-${slug}.gtpack" \
    --validator-pack "${VALIDATOR_PACK}" \
    "${PACK_MODE_ARGS[@]}" \
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
greentic-pack resolve --in "${bundle_staging}" --lock "${LOCK_FILE}" "${PACK_MODE_ARGS[@]}"
greentic-pack build \
  --in "${bundle_staging}" \
  --lock "${LOCK_FILE}" \
  --gtpack-out "${OUT_DIR}/secrets-providers.gtpack" \
  --bundle none \
  "${PACK_MODE_ARGS[@]}" \
  --allow-oci-tags
greentic-pack doctor \
  --validate \
  --pack "${OUT_DIR}/secrets-providers.gtpack" \
  --validator-pack "${VALIDATOR_PACK}" \
  "${PACK_MODE_ARGS[@]}" \
  --allow-oci-tags

echo "::notice::built bundle pack secrets-providers.gtpack"
