#!/usr/bin/env bash
set -euo pipefail

# Build enterprise provider .gtpack bundles from ./packs/<provider> using packc.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist/packs}"
DIGESTS_JSON="$ROOT_DIR/target/components/digests.json"
VALIDATOR_PACK="$ROOT_DIR/dist/validators-secrets.gtpack"
VALIDATOR_DIGESTS_JSON="$ROOT_DIR/target/validators/digests.json"
PACK_OFFLINE="${PACK_OFFLINE:-1}"
registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greenticai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
components_registry="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"
PREBUILD_COMPONENTS="${PREBUILD_COMPONENTS:-auto}"
DEFAULT_COMPONENT_FILTER="greentic.secrets.audit_exporter,greentic.secrets.provider.aws_sm,greentic.secrets.provider.azure_kv,greentic.secrets.provider.gcp_sm,greentic.secrets.provider.k8s,greentic.secrets.provider.vault_kv"
SHARED_COMPONENT_FILTER="${SHARED_COMPONENT_FILTER:-${DEFAULT_COMPONENT_FILTER}}"
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
PACK_BUILD_ARGS=(--allow-pack-schema)
PACK_BUNDLE_MODE=cache

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
  for file in gtpack.yaml pack.yaml; do
    if [[ -f "${staging}/${file}" ]]; then
      sed -i.bak "s|ghcr.io/greenticai/components|${components_registry}|g" "${staging}/${file}"
      rm -f "${staging}/${file}.bak"
    fi
  done

  # Legacy pack.yaml files carry provider extensions but leave components empty,
  # while gtpack.yaml has the canonical component declarations. Keep both
  # manifests aligned so pack builds resolve the flow components.
  if [[ -f "${staging}/gtpack.yaml" && -f "${staging}/pack.yaml" ]]; then
    tmp="${staging}/pack.tmp.yaml"
    python3 - "${staging}/gtpack.yaml" "${staging}/pack.yaml" > "${tmp}" <<'PY'
import sys, yaml

gtpack_path, pack_path = sys.argv[1:3]
gtpack = yaml.safe_load(open(gtpack_path))
pack = yaml.safe_load(open(pack_path))
if gtpack.get("components") and not pack.get("components"):
    provider_world = "greentic:provider/schema-core@1.0.0"
    for extension in (pack.get("extensions") or {}).values():
        inline = extension.get("inline") if isinstance(extension, dict) else None
        providers = inline.get("providers") if isinstance(inline, dict) else None
        if isinstance(providers, list) and providers:
            runtime = providers[0].get("runtime") or {}
            provider_world = runtime.get("world") or provider_world
            break

    components = []
    for component in gtpack["components"]:
        item = dict(component)
        item.setdefault("world", provider_world)
        item.setdefault("supports", [])
        item.setdefault("profiles", {"default": "stateless", "supported": ["stateless"]})
        item.setdefault("capabilities", {"wasi": {}, "host": {}})
        item.setdefault("operations", [])
        components.append(item)
    pack["components"] = components
yaml.safe_dump(pack, sys.stdout, sort_keys=False)
PY
    mv "${tmp}" "${staging}/pack.yaml"
  fi

  # If digests are available, rewrite component URIs to pin them.
  if [[ -f "${DIGESTS_JSON}" || -f "${VALIDATOR_DIGESTS_JSON}" ]]; then
    for file in gtpack.yaml pack.yaml; do
      [[ -f "${staging}/${file}" ]] || continue
      tmp="${staging}/${file}.tmp"
      python3 - "$DIGESTS_JSON" "$VALIDATOR_DIGESTS_JSON" "$staging/${file}" > "${tmp}" <<'PY'
import json, os, shutil, sys, yaml
from pathlib import Path

component_digests_path, validator_digests_path, manifest_path = sys.argv[1:4]
source_mode = os.environ.get("PACK_COMPONENT_SOURCE", "auto").strip().lower()
if source_mode not in {"auto", "local", "registry"}:
    raise SystemExit(f"unsupported PACK_COMPONENT_SOURCE={source_mode!r}")

all_digests = []
for path in (component_digests_path, validator_digests_path):
    if path and os.path.exists(path):
        all_digests.extend(json.load(open(path)))

digests_by_id = {d["id"]: d for d in all_digests if d.get("id")}
digests_by_ref = {d["ref"]: d for d in all_digests if d.get("ref")}

def resolved_ref(digest_entry):
    local_ref = str(digest_entry.get("local_ref", "")).strip()
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
manifest_file = Path(manifest_path)
manifest_dir = manifest_file.parent
is_pack_yaml = manifest_file.name == "pack.yaml"
for comp in manifest.get("components", []):
    did = comp.get("id")
    d = digests_by_id.get(did)
    if d:
        comp["uri"] = resolved_ref(d)
        comp["source"] = resolved_source(d)
    if is_pack_yaml and d:
        dest_name = str(d.get("path", "")).strip()
        selected_ref = str(comp.get("uri", "")).strip()
        if selected_ref.startswith("file://"):
            source_path = Path(selected_ref[len("file://"):])
            dest_dir = manifest_dir / "components"
            dest_dir.mkdir(exist_ok=True)
            if not dest_name:
                dest_name = source_path.name
            dest_path = dest_dir / dest_name
            shutil.copy2(source_path, dest_path)
        if dest_name:
            comp["wasm"] = f"components/{dest_name}"
rewrite_extension_refs(manifest.get("extensions", {}))
yaml.safe_dump(manifest, sys.stdout, sort_keys=False)
PY
      mv "${tmp}" "${staging}/${file}"
    done
  fi

  python3 "${ROOT_DIR}/scripts/generate-flow-resolve-summary.py" "${staging}" "${DIGESTS_JSON}"

  LOCK_FILE="${staging}/pack.lock.json"
  greentic-pack resolve --in "${staging}" --lock "${LOCK_FILE}" "${PACK_MODE_ARGS[@]}"
  pack_build_cmd=(
    greentic-pack build
    --in "${staging}"
    --lock "${LOCK_FILE}"
    --gtpack-out "${OUT_DIR}/secrets-${slug}.gtpack"
    --bundle "${PACK_BUNDLE_MODE}"
  )
  if [[ "${#PACK_MODE_ARGS[@]}" -gt 0 ]]; then
    pack_build_cmd+=("${PACK_MODE_ARGS[@]}")
  fi
  if [[ "${#PACK_BUILD_ARGS[@]}" -gt 0 ]]; then
    pack_build_cmd+=("${PACK_BUILD_ARGS[@]}")
  fi
  pack_build_cmd+=(--allow-oci-tags)
  "${pack_build_cmd[@]}"
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
    echo "- alias: ${slug}"
    echo "  pack_id: greentic.secrets.${slug}"
    echo "  version_req: \"=${VERSION}\""
  } >> "${bundle_staging}/deps.tmp"
done

if [[ "${#built_gtpacks[@]}" -gt 0 ]]; then
  "${ROOT_DIR}/scripts/validate-gtpack-extension.sh" "${built_gtpacks[@]}"
fi

echo "${VERSION}" > "${OUT_DIR}/VERSION"

# Build bundle pack with packc.
python3 - "${bundle_staging}/deps.tmp" "${bundle_staging}/pack.yaml" "${VERSION}" <<'PY'
import sys
import yaml

deps_path, pack_path, version = sys.argv[1:4]
with open(deps_path) as fh:
    dependencies = yaml.safe_load(fh) or []

manifest = {
    "pack_id": "greentic.secrets.providers",
    "version": version,
    "kind": "library",
    "publisher": "Greentic",
    "components": [],
    "dependencies": dependencies,
    "flows": [],
    "assets": [],
}

with open(pack_path, "w") as fh:
    yaml.safe_dump(manifest, fh, sort_keys=False)
PY
rm -f "${bundle_staging}/deps.tmp"

LOCK_FILE="${bundle_staging}/pack.lock.json"
greentic-pack resolve --in "${bundle_staging}" --lock "${LOCK_FILE}" "${PACK_MODE_ARGS[@]}"
pack_build_cmd=(
  greentic-pack build
  --in "${bundle_staging}"
  --lock "${LOCK_FILE}"
  --gtpack-out "${OUT_DIR}/secrets-providers.gtpack"
  --bundle "${PACK_BUNDLE_MODE}"
)
if [[ "${#PACK_MODE_ARGS[@]}" -gt 0 ]]; then
  pack_build_cmd+=("${PACK_MODE_ARGS[@]}")
fi
if [[ "${#PACK_BUILD_ARGS[@]}" -gt 0 ]]; then
  pack_build_cmd+=("${PACK_BUILD_ARGS[@]}")
fi
pack_build_cmd+=(--allow-oci-tags)
"${pack_build_cmd[@]}"
greentic-pack doctor \
  --validate \
  --pack "${OUT_DIR}/secrets-providers.gtpack" \
  --validator-pack "${VALIDATOR_PACK}" \
  "${PACK_MODE_ARGS[@]}" \
  --allow-oci-tags

echo "::notice::built bundle pack secrets-providers.gtpack"
