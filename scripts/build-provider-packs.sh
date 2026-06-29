#!/usr/bin/env bash
set -euo pipefail

# Build enterprise provider .gtpack bundles from ./packs/<provider> using packc.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist/packs}"
DIGESTS_JSON="$ROOT_DIR/target/components/digests.json"
VALIDATOR_PACK="$ROOT_DIR/dist/validators-secrets.gtpack"
VALIDATOR_DIGESTS_JSON="$ROOT_DIR/target/validators/digests.json"
PACK_OFFLINE="${PACK_OFFLINE:-1}"
PACK_USE_LOCAL_COMPONENTS="${PACK_USE_LOCAL_COMPONENTS:-auto}"
SKIP_DOCTOR="${SKIP_DOCTOR:-0}"
registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greenticai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
components_registry="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"
PREBUILD_COMPONENTS="${PREBUILD_COMPONENTS:-auto}"
SHARED_COMPONENT_FILTER="${SHARED_COMPONENT_FILTER:-greentic.secrets.audit_exporter,greentic.secrets.generators,greentic.secrets.policy_validator,greentic.secrets.provider.aws_sm,greentic.secrets.provider.azure_kv,greentic.secrets.provider.gcp_sm,greentic.secrets.provider.k8s,greentic.secrets.provider.vault_kv}"
PACK_COMPONENT_SOURCE="${PACK_COMPONENT_SOURCE:-auto}"

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
echo "Component source policy: ${PACK_COMPONENT_SOURCE}"
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

  resolved_source_mode="${PACK_COMPONENT_SOURCE}"
  if [[ "${resolved_source_mode}" == "auto" && "${use_local}" == "1" ]]; then
    resolved_source_mode="local"
  fi

  # Rewrite component URIs and detect unresolvable external components.
  has_external_unresolved=0
  if [[ -f "${DIGESTS_JSON}" || -f "${VALIDATOR_DIGESTS_JSON}" ]]; then
    tmp="${staging}/gtpack.tmp.yaml"
    has_external_unresolved=$(PACK_COMPONENT_SOURCE="${resolved_source_mode}" python3 - "$DIGESTS_JSON" "$VALIDATOR_DIGESTS_JSON" "$staging/gtpack.yaml" "${use_local}" "${ROOT_DIR}/target/components" "${tmp}" <<'PY'
import json, os, sys, yaml

component_digests_path, validator_digests_path, manifest_path, use_local_flag, components_dir, out_path = sys.argv[1:7]
source_mode = os.environ.get("PACK_COMPONENT_SOURCE", "auto").strip().lower()
if source_mode not in {"auto", "local", "registry"}:
    raise SystemExit(f"unsupported PACK_COMPONENT_SOURCE={source_mode!r}")

use_local = use_local_flag == "1"
has_unresolved = False
all_digests = []
for path in (component_digests_path, validator_digests_path):
    if path and os.path.exists(path):
        all_digests.extend(json.load(open(path)))

digests_by_id = {d["id"]: d for d in all_digests if d.get("id")}
digests_by_ref = {d["ref"]: d for d in all_digests if d.get("ref")}

def local_file_ref(digest_entry):
    wasm_path = os.path.join(components_dir, digest_entry.get("path", ""))
    if os.path.isfile(wasm_path):
        return f"file://{os.path.abspath(wasm_path)}"
    return ""

def resolved_ref(digest_entry):
    local_ref = str(digest_entry.get("local_ref", "")).strip() or local_file_ref(digest_entry)
    oci_digest = str(digest_entry.get("oci_digest", "")).strip()
    if source_mode == "local":
        return local_ref or digest_entry["ref"]
    if source_mode == "registry":
        if oci_digest:
            if not oci_digest.startswith("sha256:"):
                oci_digest = f"sha256:{oci_digest}"
            return f"{digest_entry['ref']}@{oci_digest}"
        return digest_entry["ref"]
    if oci_digest:
        if not oci_digest.startswith("sha256:"):
            oci_digest = f"sha256:{oci_digest}"
        return f"{digest_entry['ref']}@{oci_digest}"
    if local_ref:
        return local_ref
    return digest_entry["ref"]

def resolved_source(digest_entry):
    resolved = resolved_ref(digest_entry)
    return "file" if resolved.startswith("file://") else "oci"

def maybe_rewrite_component_ref(value):
    digest_entry = digests_by_ref.get(value)
    if digest_entry:
        return resolved_ref(digest_entry)
    bare_value = value.split("@", 1)[0]
    digest_entry = digests_by_ref.get(bare_value)
    if digest_entry:
        return resolved_ref(digest_entry)
    return value

def rewrite_extension_refs(node):
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if key == "component_ref" and isinstance(value, str):
                node[key] = maybe_rewrite_component_ref(value)
            else:
                rewrite_extension_refs(value)
    elif isinstance(node, list):
        for item in node:
            rewrite_extension_refs(item)

manifest = yaml.safe_load(open(manifest_path))
for comp in manifest.get("components", []):
    did = comp.get("id")
    digest_entry = digests_by_id.get(did)
    if digest_entry:
        comp["uri"] = resolved_ref(digest_entry)
        comp["source"] = resolved_source(digest_entry)
    elif use_local:
        has_unresolved = True
        print(f"  external component not available locally: {did}", file=sys.stderr)
rewrite_extension_refs(manifest.get("extensions", {}))
with open(out_path, "w") as f:
    yaml.safe_dump(manifest, f, sort_keys=False)
print("1" if has_unresolved else "0")
PY
    )
    if [[ -f "${tmp}" ]]; then
      mv "${tmp}" "${staging}/gtpack.yaml"
    fi
  fi

  python3 "${ROOT_DIR}/scripts/generate-flow-resolve-summary.py" "${staging}" "${DIGESTS_JSON}"

  if [[ "${has_external_unresolved}" == "1" && "${use_local}" == "1" ]]; then
    echo "::warning::Skipping resolve/build/doctor for secrets-${slug}: external components not available locally (dry-run only)"
    continue
  fi

  LOCK_FILE="${staging}/pack.lock.json"
  greentic-pack resolve --in "${staging}" --lock "${LOCK_FILE}" "${PACK_MODE_ARGS[@]}"
  greentic-pack build \
    --in "${staging}" \
    --lock "${LOCK_FILE}" \
    --gtpack-out "${OUT_DIR}/secrets-${slug}.gtpack" \
    --bundle none \
    "${PACK_MODE_ARGS[@]}" \
    --allow-oci-tags
  if [[ "${SKIP_DOCTOR}" != "1" ]]; then
    greentic-pack doctor \
      --validate \
      --pack "${OUT_DIR}/secrets-${slug}.gtpack" \
      --validator-pack "${VALIDATOR_PACK}" \
      "${PACK_MODE_ARGS[@]}" \
      --allow-oci-tags
  fi

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

if [[ ! -s "${bundle_deps}" ]]; then
  echo "::warning::No provider packs were built — skipping bundle pack"
  rm -f "${bundle_deps}"
  exit 0
fi

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
if [[ "${SKIP_DOCTOR}" != "1" ]]; then
  greentic-pack doctor \
    --validate \
    --pack "${OUT_DIR}/secrets-providers.gtpack" \
    --validator-pack "${VALIDATOR_PACK}" \
    "${PACK_MODE_ARGS[@]}" \
    --allow-oci-tags
fi

echo "::notice::built bundle pack secrets-providers.gtpack"
