#!/usr/bin/env bash
set -euo pipefail

# E2E smoke for broker HTTP aliases:
# - /admin/v1/... (new admin alias)
# - /v1/...       (canonical)
#
# No `cargo test` is used. The script runs the broker, performs authenticated
# HTTP calls, verifies response parity, then stops the broker.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${ROOT_DIR}"

HOST="${BROKER_HOST:-127.0.0.1}"
PORT="${BROKER_PORT:-18080}"
BASE_URL="http://${HOST}:${PORT}"
BIND_ADDR="${BROKER_BIND:-${HOST}:${PORT}}"

ENV_ID="${E2E_ENV_ID:-dev}"
TENANT="${E2E_TENANT:-acme}"
CATEGORY="${E2E_CATEGORY:-configs}"
NAME="${E2E_NAME:-demo_key}"
VALUE_JSON="${E2E_VALUE_JSON:-{\"hello\":\"world\"}}"

TMP_DIR="$(mktemp -d)"
LOG_FILE="${TMP_DIR}/broker.log"
PUB_FILE="${TMP_DIR}/jwt_pub.b64"
TOKEN_FILE="${TMP_DIR}/jwt_token.txt"
STORE_FILE="${TMP_DIR}/secrets.env"

BROKER_PID=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

cleanup() {
  if [[ -n "${BROKER_PID}" ]] && kill -0 "${BROKER_PID}" >/dev/null 2>&1; then
    kill "${BROKER_PID}" >/dev/null 2>&1 || true
    wait "${BROKER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

require_cmd cargo
require_cmd curl
require_cmd python3
require_cmd diff

cd "${WORKDIR}"

python3 - "${PUB_FILE}" "${TOKEN_FILE}" "${TENANT}" <<'PY'
import base64
import sys
import time

pub_file, token_file, tenant = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import jwt
except Exception as exc:  # pragma: no cover - runtime requirement check
    raise SystemExit(
        "Python deps are required: cryptography + pyjwt. "
        f"Import failure: {exc}"
    )

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
public_b64 = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii")

now = int(time.time())
claims = {
    "sub": "svc-e2e@greentic.dev",
    "iss": "https://local.test",
    "aud": "greentic-broker",
    "tenant": tenant,
    "roles": ["admin"],
    "actor": "script",
    "exp": now + 3600,
}
token = jwt.encode(claims, private_key, algorithm="EdDSA")

with open(pub_file, "w", encoding="utf-8") as f:
    f.write(public_b64)
with open(token_file, "w", encoding="utf-8") as f:
    f.write(token)
PY

TOKEN="$(cat "${TOKEN_FILE}")"
AUTH_HEADER="Authorization: Bearer ${TOKEN}"
PUT_PAYLOAD="$(python3 - "${VALUE_JSON}" <<'PY'
import json
import sys

value_raw = sys.argv[1]
print(
    json.dumps(
        {
            "content_type": "json",
            "encoding": "utf8",
            "visibility": "tenant",
            "value": value_raw,
        },
        separators=(",", ":"),
    )
)
PY
)"

echo "Starting broker on ${BIND_ADDR}..."
(
  export SECRETS_BACKEND=dev
  export GREENTIC_DEV_SECRETS_PATH="${STORE_FILE}"
  export AUTH_JWT_ISS="https://local.test"
  export AUTH_JWT_AUD="greentic-broker"
  AUTH_JWT_ED25519_PUB="$(cat "${PUB_FILE}")"
  export AUTH_JWT_ED25519_PUB
  cargo run -p greentic-secrets-broker --bin greentic-secrets-broker -- --bind "${BIND_ADDR}"
) >"${LOG_FILE}" 2>&1 &
BROKER_PID="$!"

echo "Waiting for broker health..."
for _ in $(seq 1 120); do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
  echo "Broker failed to become healthy. Log:" >&2
  cat "${LOG_FILE}" >&2
  exit 1
fi

ADMIN_URI="/admin/v1/${ENV_ID}/${TENANT}/${CATEGORY}/${NAME}"
CANON_URI="/v1/${ENV_ID}/${TENANT}/${CATEGORY}/${NAME}"
ADMIN_LIST_URI="/admin/v1/${ENV_ID}/${TENANT}/_list"
CANON_LIST_URI="/v1/${ENV_ID}/${TENANT}/_list"

echo "PUT ${ADMIN_URI}"
PUT_CODE="$(curl -sS -o "${TMP_DIR}/put_admin.json" -w "%{http_code}" \
  -X PUT "${BASE_URL}${ADMIN_URI}" \
  -H "${AUTH_HEADER}" \
  -H "content-type: application/json" \
  --data-binary "${PUT_PAYLOAD}")"
if [[ "${PUT_CODE}" != "201" ]]; then
  echo "PUT failed with status ${PUT_CODE}" >&2
  cat "${TMP_DIR}/put_admin.json" >&2
  exit 1
fi

echo "GET list via admin and canonical prefixes"
ADMIN_LIST_CODE="$(curl -sS -o "${TMP_DIR}/list_admin.json" -w "%{http_code}" \
  "${BASE_URL}${ADMIN_LIST_URI}" -H "${AUTH_HEADER}")"
CANON_LIST_CODE="$(curl -sS -o "${TMP_DIR}/list_v1.json" -w "%{http_code}" \
  "${BASE_URL}${CANON_LIST_URI}" -H "${AUTH_HEADER}")"
if [[ "${ADMIN_LIST_CODE}" != "200" || "${CANON_LIST_CODE}" != "200" ]]; then
  echo "List failed: admin=${ADMIN_LIST_CODE}, canonical=${CANON_LIST_CODE}" >&2
  cat "${TMP_DIR}/list_admin.json" >&2 || true
  cat "${TMP_DIR}/list_v1.json" >&2 || true
  exit 1
fi

echo "GET item via admin and canonical prefixes"
ADMIN_GET_CODE="$(curl -sS -o "${TMP_DIR}/get_admin.json" -w "%{http_code}" \
  "${BASE_URL}${ADMIN_URI}" -H "${AUTH_HEADER}")"
CANON_GET_CODE="$(curl -sS -o "${TMP_DIR}/get_v1.json" -w "%{http_code}" \
  "${BASE_URL}${CANON_URI}" -H "${AUTH_HEADER}")"
if [[ "${ADMIN_GET_CODE}" != "200" || "${CANON_GET_CODE}" != "200" ]]; then
  echo "Get failed: admin=${ADMIN_GET_CODE}, canonical=${CANON_GET_CODE}" >&2
  cat "${TMP_DIR}/get_admin.json" >&2 || true
  cat "${TMP_DIR}/get_v1.json" >&2 || true
  exit 1
fi

echo "Verifying JSON parity..."
diff -u "${TMP_DIR}/list_admin.json" "${TMP_DIR}/list_v1.json"
diff -u "${TMP_DIR}/get_admin.json" "${TMP_DIR}/get_v1.json"

echo "E2E PASS: /admin/v1 and /v1 parity verified"
echo "Artifacts were stored under: ${TMP_DIR} (removed on exit)"
