#!/usr/bin/env bash
set -euo pipefail

# Build the secrets pack validator wasm component and emit a digests manifest.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/target/validators"
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

crate="greentic-secrets-pack-validator"
artifact="greentic_secrets_pack_validator.wasm"

echo "Building ${crate} for version ${VERSION}"
rustup target add wasm32-wasip2 >/dev/null
cargo build -p "${crate}" --release --target wasm32-wasip2

wasm_path="${ROOT_DIR}/target/wasm32-wasip2/release/${artifact}"
if [[ ! -f "${wasm_path}" ]]; then
  echo "[ERROR] wasm artifact missing at ${wasm_path}" >&2
  exit 1
fi

cp "${wasm_path}" "${OUT_DIR}/secrets-pack-validator.wasm"

digest="$(sha256sum "${wasm_path}" | awk '{print $1}')"
ref="ghcr.io/greenticai/validators/secrets:${VERSION}"
digests_json="${OUT_DIR}/digests.json"
echo "[]" > "${digests_json}"

tmp="$(mktemp)"
jq --arg id "greentic.validators.secrets" \
   --arg version "${VERSION}" \
   --arg ref "${ref}" \
   --arg digest "${digest}" \
   --arg path "secrets-pack-validator.wasm" \
   '. += [{"id":$id,"version":$version,"ref":$ref,"digest":$digest,"path":$path}]' \
   "${digests_json}" > "${tmp}"
mv "${tmp}" "${digests_json}"

echo "::notice::Validator digest written to ${digests_json}"
