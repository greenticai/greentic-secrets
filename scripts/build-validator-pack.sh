#!/usr/bin/env bash
set -euo pipefail

# Build secrets validator .gtpack bundle from ./validators/secrets using packc.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist"
VALIDATOR_DIGESTS="${ROOT_DIR}/target/validators/digests.json"
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

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

src="${ROOT_DIR}/validators/secrets"
if [[ ! -d "${src}" ]]; then
  echo "missing pack source: ${src}" >&2
  exit 1
fi

staging="${OUT_DIR}/validators-secrets"
rm -rf "${staging}"
mkdir -p "${staging}"
rsync -a "${src}/" "${staging}/"

for file in gtpack.yaml pack.yaml; do
  if [[ -f "${staging}/${file}" ]] && grep -q '__PACK_VERSION__' "${staging}/${file}"; then
    sed -i.bak "s/__PACK_VERSION__/${VERSION}/g" "${staging}/${file}"
    rm -f "${staging}/${file}.bak"
  fi
done

if [[ -f "${VALIDATOR_DIGESTS}" ]]; then
  for file in gtpack.yaml pack.yaml; do
    if [[ -f "${staging}/${file}" ]]; then
      tmp="${staging}/${file}.tmp"
      python3 - "${VALIDATOR_DIGESTS}" "${staging}/${file}" > "${tmp}" <<'PY'
import json, os, sys, yaml

digests = json.load(open(sys.argv[1]))
doc = yaml.safe_load(open(sys.argv[2]))
validator = next((entry for entry in digests if entry.get("id") == "greentic.validators.secrets"), None)
if validator is None:
    raise SystemExit("validator digest missing greentic.validators.secrets entry")

mode = os.environ.get("PACK_COMPONENT_SOURCE", "auto").strip().lower()
if mode == "registry":
    oci_digest = str(validator.get("oci_digest", "")).strip()
    if oci_digest:
        if not oci_digest.startswith("sha256:"):
            oci_digest = f"sha256:{oci_digest}"
        target_ref = f"{validator['ref']}@{oci_digest}"
    else:
        target_ref = validator["ref"]
elif mode == "local":
    target_ref = str(validator.get("local_ref", "")).strip() or validator["ref"]
else:
    oci_digest = str(validator.get("oci_digest", "")).strip()
    local_ref = str(validator.get("local_ref", "")).strip()
    if oci_digest:
        if not oci_digest.startswith("sha256:"):
            oci_digest = f"sha256:{oci_digest}"
        target_ref = f"{validator['ref']}@{oci_digest}"
    elif local_ref:
        target_ref = local_ref
    else:
        target_ref = validator["ref"]

target_source = "file" if target_ref.startswith("file://") else "oci"

for component in doc.get("components", []):
    if component.get("id") == "greentic.validators.secrets":
        component["uri"] = target_ref
        component["source"] = target_source

extensions = doc.get("extensions", {})
for extension in extensions.values():
    if not isinstance(extension, dict):
        continue
    validators = extension.get("validators")
    if isinstance(validators, list):
        for item in validators:
            if isinstance(item, dict) and item.get("id") == "greentic.validators.secrets":
                item["component_ref"] = target_ref
    inline = extension.get("inline")
    if isinstance(inline, dict):
        validators = inline.get("validators")
        if isinstance(validators, list):
            for item in validators:
                if isinstance(item, dict) and item.get("id") == "greentic.validators.secrets":
                    item["component_ref"] = target_ref

yaml.safe_dump(doc, sys.stdout, sort_keys=False)
PY
      mv "${tmp}" "${staging}/${file}"
    fi
  done
fi

LOCK_FILE="${staging}/pack.lock.json"
greentic-pack resolve --in "${staging}" --lock "${LOCK_FILE}" --offline
greentic-pack build \
  --in "${staging}" \
  --lock "${LOCK_FILE}" \
  --gtpack-out "${OUT_DIR}/validators-secrets.gtpack" \
  --bundle none \
  --offline \
  --allow-oci-tags

greentic-pack doctor \
  --pack "${OUT_DIR}/validators-secrets.gtpack" \
  --offline \
  --allow-oci-tags

echo "::notice::built pack validators-secrets.gtpack"
