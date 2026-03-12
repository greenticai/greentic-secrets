#!/usr/bin/env bash
set -euo pipefail

# Build enterprise provider .gtpack bundles from ./packs/<provider> using packc.
#
# Provider packs can resolve provider components from locally built artifacts.
# Use that path by default so pack builds do not depend on GHCR state.
# Callers can disable it with PACK_USE_LOCAL_COMPONENTS=0.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist/packs}"
DIGESTS_JSON="$ROOT_DIR/target/components/digests.json"
VALIDATOR_PACK="$ROOT_DIR/dist/validators-secrets.gtpack"
PACKS_LOCKFILE="${PACKS_LOCKFILE:-$ROOT_DIR/packs.lock.json}"
PACK_OFFLINE="${PACK_OFFLINE:-0}"
PACK_USE_LOCAL_COMPONENTS="${PACK_USE_LOCAL_COMPONENTS:-1}"
registry_owner="${REGISTRY_OWNER:-${GITHUB_REPOSITORY_OWNER:-greentic-ai}}"
registry_owner="$(printf '%s' "${registry_owner}" | tr '[:upper:]' '[:lower:]')"
packs_registry="${PACKS_REGISTRY:-ghcr.io}"
packs_namespace="${PACKS_NAMESPACE:-greenticai}"
packs_repo="${PACKS_REPO:-packs/secrets}"
packs_namespace="$(printf '%s' "${packs_namespace}" | tr '[:upper:]' '[:lower:]')"
packs_repo="$(printf '%s' "${packs_repo}" | tr '[:upper:]' '[:lower:]')"
components_registry="${COMPONENTS_REGISTRY:-ghcr.io/${registry_owner}/components}"
oci_registry_host="${components_registry%%/*}"
ghcr_user="${GHCR_USERNAME:-${GITHUB_ACTOR:-${USER:-greentic-ai}}}"
ghcr_token="${GHCR_TOKEN:-${GITHUB_TOKEN:-${gh_pat:-${GH_PAT:-}}}}"

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
built_components_ready=0

echo "Building provider packs for version ${VERSION}"
echo "Components registry namespace: ${components_registry}"

pack_mode_args=()
build_extra_args=()
provider_bundle_mode="none"
pack_mode_label="online"
if [[ "${PACK_OFFLINE}" == "1" ]]; then
  pack_mode_args=(--offline)
  pack_mode_label="offline"
fi
if [[ "${PACK_USE_LOCAL_COMPONENTS}" == "1" ]]; then
  build_extra_args+=(--allow-pack-schema)
  provider_bundle_mode="cache"
fi
echo "Pack mode: ${pack_mode_label}"
echo "Local provider components: ${PACK_USE_LOCAL_COMPONENTS}"

if [[ "${PACK_USE_LOCAL_COMPONENTS}" == "1" ]]; then
  echo "Using locally staged provider components; skipping GHCR auth for provider resolution"
elif [[ -n "${ghcr_token}" ]]; then
  export GREENTIC_OCI_USERNAME="${GREENTIC_OCI_USERNAME:-${ghcr_user}}"
  export GREENTIC_OCI_PASSWORD="${GREENTIC_OCI_PASSWORD:-${ghcr_token}}"
  if command -v oras >/dev/null 2>&1; then
    printf '%s' "${ghcr_token}" | oras login "${oci_registry_host}" -u "${ghcr_user}" --password-stdin >/dev/null
    echo "Authenticated to ${oci_registry_host} as ${ghcr_user}"
  else
    echo "oras not found; relying on GREENTIC_OCI_USERNAME/GREENTIC_OCI_PASSWORD for OCI auth"
  fi
else
  echo "No GHCR token found in GHCR_TOKEN/GITHUB_TOKEN/GH_PAT; relying on existing OCI auth state"
fi

ensure_local_components() {
  if [[ "${PACK_USE_LOCAL_COMPONENTS}" != "1" ]]; then
    return 0
  fi
  if [[ "${built_components_ready}" == "1" ]]; then
    return 0
  fi
  local required=(
    "${ROOT_DIR}/target/components/secrets-provider-aws-sm.wasm"
    "${ROOT_DIR}/target/components/secrets-provider-azure-kv.wasm"
    "${ROOT_DIR}/target/components/secrets-provider-gcp-sm.wasm"
    "${ROOT_DIR}/target/components/secrets-provider-k8s.wasm"
    "${ROOT_DIR}/target/components/secrets-provider-vault-kv.wasm"
  )
  local missing=0
  local artifact
  for artifact in "${required[@]}"; do
    if [[ ! -f "${artifact}" ]]; then
      missing=1
      break
    fi
  done
  if [[ "${missing}" == "1" ]]; then
    "${ROOT_DIR}/scripts/build-components.sh"
  fi
  built_components_ready=1
}

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

  if [[ "${PACK_USE_LOCAL_COMPONENTS}" == "1" ]]; then
    ensure_local_components
    case "${slug}" in
      aws-sm) provider_artifact="secrets-provider-aws-sm.wasm" ;;
      azure-kv) provider_artifact="secrets-provider-azure-kv.wasm" ;;
      gcp-sm) provider_artifact="secrets-provider-gcp-sm.wasm" ;;
      k8s) provider_artifact="secrets-provider-k8s.wasm" ;;
      vault-kv) provider_artifact="secrets-provider-vault-kv.wasm" ;;
      *)
        echo "unknown provider slug for local component mapping: ${slug}" >&2
        exit 1
        ;;
    esac
    provider_component_path="${ROOT_DIR}/target/components/${provider_artifact}"
    if [[ ! -f "${provider_component_path}" ]]; then
      echo "missing local provider component: ${provider_component_path}" >&2
      exit 1
    fi
    mkdir -p "${staging}/components"
    cp "${provider_component_path}" "${staging}/components/${provider_artifact}"
    staged_provider_component_path="${staging}/components/${provider_artifact}"
    provider_component_uri="file://${staged_provider_component_path}"
    python3 - "${staging}/gtpack.yaml" "${staging}/pack.yaml" "${provider_component_uri}" "${slug}" <<'PY'
from pathlib import Path
import sys
import yaml

gtpack_path = Path(sys.argv[1])
pack_path = Path(sys.argv[2])
component_uri = sys.argv[3]
slug = sys.argv[4]

provider_ids = {
    "aws-sm": "greentic.secrets.provider.aws_sm",
    "azure-kv": "greentic.secrets.provider.azure_kv",
    "gcp-sm": "greentic.secrets.provider.gcp_sm",
    "k8s": "greentic.secrets.provider.k8s",
    "vault-kv": "greentic.secrets.provider.vault_kv",
}
provider_id = provider_ids[slug]

gtpack = yaml.safe_load(gtpack_path.read_text()) or {}
for comp in gtpack.get("components") or []:
    if comp.get("id") == provider_id:
        comp["uri"] = component_uri
extensions = (gtpack.get("extensions") or {}).get("greentic.provider-extension.v1") or {}
provider = extensions.get("provider") or {}
runtime = provider.get("runtime") or {}
if runtime.get("component_ref"):
    runtime["component_ref"] = component_uri
yaml.safe_dump(gtpack, gtpack_path.open("w"), sort_keys=False)

pack = yaml.safe_load(pack_path.read_text()) or {}
extensions = (pack.get("extensions") or {}).get("greentic.provider-extension.v1") or {}
inline = extensions.get("inline") or {}
providers = inline.get("providers") or []
provider_runtime = {}
provider_ops = []
for provider in providers:
    runtime = (provider.get("runtime") or {})
    if runtime.get("component_ref"):
        runtime["component_ref"] = component_uri
    provider_runtime = runtime or provider_runtime
    provider_ops = list(provider.get("ops") or provider_ops)
pack["components"] = [
    {
        "id": provider_id,
        "version": str(pack.get("version") or "0.0.0"),
        "world": provider_runtime.get("world", "greentic:provider/schema-core@1.0.0"),
        "supports": [],
        "profiles": {
            "default": "stateless",
            "supported": ["stateless"],
        },
        "capabilities": {
            "wasi": {},
            "host": {},
        },
        "operations": [
            {
                "name": op,
                "input_schema": {},
                "output_schema": {},
            }
            for op in provider_ops
        ],
        "wasm": f"components/{Path(component_uri[len('file://'):]).name}",
    }
]
yaml.safe_dump(pack, pack_path.open("w"), sort_keys=False)
PY
  fi

  # If digests are available, rewrite component URIs to pin them.
  if [[ -f "${DIGESTS_JSON}" && "${PACK_USE_LOCAL_COMPONENTS}" != "1" ]]; then
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
    --bundle "${provider_bundle_mode}" \
    "${build_extra_args[@]}" \
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

python3 - "${OUT_DIR}" "${VERSION}" "${PACKS_LOCKFILE}" "${packs_registry}" "${packs_namespace}" "${packs_repo}" <<'PY'
from pathlib import Path
import json
import os
import sys

out_dir = Path(sys.argv[1]).resolve()
version = sys.argv[2]
lock_path = Path(sys.argv[3]).resolve()
registry = sys.argv[4]
namespace = sys.argv[5]
repo = sys.argv[6]
base_dir = lock_path.parent

pack_ids = {
    "secrets-aws-sm": "greentic.secrets.aws-sm",
    "secrets-azure-kv": "greentic.secrets.azure-kv",
    "secrets-gcp-sm": "greentic.secrets.gcp-sm",
    "secrets-k8s": "greentic.secrets.k8s",
    "secrets-providers": "greentic.secrets.providers",
    "secrets-vault-kv": "greentic.secrets.vault-kv",
}

packs = []
for pack_path in sorted(out_dir.glob("*.gtpack")):
    name = pack_path.stem
    pack_id = pack_ids.get(name)
    published_name = f"{pack_id}.gtpack" if pack_id else f"{name}.gtpack"
    packs.append(
        {
            "name": name,
            **({"pack_id": pack_id, "published_name": published_name} if pack_id else {}),
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
