#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   LOCAL_CHECK_ONLINE=1 LOCAL_CHECK_STRICT=1 LOCAL_CHECK_VERBOSE=1 LOCAL_CHECK_COVERAGE=1 LOCAL_CHECK_PACKAGE=1 ci/local_check.sh
# Defaults: offline (LOCAL_CHECK_ONLINE=0), coverage/package disabled, non-strict, non-verbose.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Default offline unless explicitly enabled.
LOCAL_CHECK_ONLINE="${LOCAL_CHECK_ONLINE:-0}"
LOCAL_CHECK_STRICT="${LOCAL_CHECK_STRICT:-0}"
LOCAL_CHECK_VERBOSE="${LOCAL_CHECK_VERBOSE:-0}"
LOCAL_CHECK_COVERAGE="${LOCAL_CHECK_COVERAGE:-0}"
LOCAL_CHECK_PACKAGE="${LOCAL_CHECK_PACKAGE:-0}"
if [[ -n "${LOCAL_CHECKPACKAGE:-}" && "$LOCAL_CHECK_PACKAGE" == "0" ]]; then
  LOCAL_CHECK_PACKAGE="$LOCAL_CHECKPACKAGE"
fi

if [[ "$LOCAL_CHECK_ONLINE" != "1" ]]; then
  export CARGO_NET_OFFLINE=1
  CARGO_OFFLINE_ARGS=(--offline)
else
  CARGO_OFFLINE_ARGS=()
fi

if [[ "$LOCAL_CHECK_VERBOSE" == "1" ]]; then
  set -x
fi

export RUST_BACKTRACE=1

SKIPPED_STEPS=()
KIND_CLUSTER=""
VAULT_CONTAINER=""

cleanup() {
  if [[ -n "$KIND_CLUSTER" ]]; then
    kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
  fi
  if [[ -n "$VAULT_CONTAINER" ]]; then
    docker rm -f "$VAULT_CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

step() {
  printf "\n▶ %s\n" "$*"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

need() {
  local tool="$1"
  if have "$tool"; then
    return 0
  fi
  echo "[miss] $tool"
  if [[ "$LOCAL_CHECK_STRICT" == "1" ]]; then
    echo "[fail] Missing required tool '$tool' (LOCAL_CHECK_STRICT=1)" >&2
    exit 1
  fi
  return 1
}

ensure_core_tool() {
  local tool="$1"
  if ! need "$tool"; then
    echo "[fail] '$tool' is required for local CI checks" >&2
    exit 1
  fi
}

ensure_tools() {
  local tool
  for tool in "$@"; do
    need "$tool" || return 1
  done
  return 0
}

run_or_skip() {
  local desc="$1"
  shift
  if "$@"; then
    return 0
  fi
  SKIPPED_STEPS+=("$desc")
  echo "[skip] $desc"
  return 1
}

require_online() {
  if [[ "$LOCAL_CHECK_ONLINE" == "1" ]]; then
    return 0
  fi
  return 1
}

require_env_vars() {
  local var
  for var in "$@"; do
    if [[ -z "${!var:-}" ]]; then
      echo "[miss env] $var"
      if [[ "$LOCAL_CHECK_STRICT" == "1" ]]; then
        echo "[fail] Environment variable '$var' is required (LOCAL_CHECK_STRICT=1)" >&2
        exit 1
      fi
      return 1
    fi
  done
  return 0
}

docker_ready() {
  need docker || return 1
  if ! docker info >/dev/null 2>&1; then
    echo "[warn] docker daemon is not available"
    if [[ "$LOCAL_CHECK_STRICT" == "1" ]]; then
      echo "[fail] docker daemon unavailable (LOCAL_CHECK_STRICT=1)" >&2
      exit 1
    fi
    return 1
  fi
  return 0
}

show_tool_version() {
  local cmd="$1"
  local reason="$2"
  shift 2
  if have "$cmd"; then
    "$@" || true
  else
    echo "[warn] $cmd not available${reason:+ ($reason)}"
  fi
}

print_tool_versions() {
  step "Toolchain versions"
  show_tool_version cargo "" cargo --version
  show_tool_version rustc "" rustc --version
  show_tool_version rustfmt "required for cargo fmt" rustfmt --version
  show_tool_version cargo-clippy "install via 'rustup component add clippy' to run clippy" cargo clippy --version
  show_tool_version jq "needed for cargo package dry-runs" jq --version
  show_tool_version docker "required for KinD/Vault/local provider checks" docker --version
  show_tool_version kind "required for provider-k8s" kind --version
  show_tool_version kubectl "required for provider-k8s" kubectl version --client
  show_tool_version curl "required for Vault readiness + schema probes" curl --version
  show_tool_version cargo-tarpaulin "disable by uninstalling or set LOCAL_CHECK_STRICT=0" cargo tarpaulin --version
}

ensure_core_tool cargo
ensure_core_tool rustc

print_tool_versions

check_provider_blocking_guards() {
  step "Guard: providers avoid blocking HTTP/runtime APIs"
  if ! have rg; then
    echo "[warn] rg not available; skipping provider blocking guard"
    return
  fi
  if rg -n --glob 'providers/**' --glob '!providers/greentic-k8s/**' 'reqwest::blocking' >/dev/null; then
    echo "[fail] found forbidden reqwest::blocking usage outside the temporary k8s allowlist"
    rg -n --glob 'providers/**' --glob '!providers/greentic-k8s/**' 'reqwest::blocking'
    exit 1
  fi

  if rg -n 'reqwest::blocking' providers/greentic-k8s >/dev/null; then
    echo "[warn] providers/greentic-k8s still uses reqwest::blocking (allowed temporarily)"
  fi

  if rg -n --glob 'providers/**' 'tokio::runtime::Runtime::new' >/dev/null; then
    echo "[fail] found tokio::runtime::Runtime::new inside providers"
    rg -n --glob 'providers/**' 'tokio::runtime::Runtime::new'
    exit 1
  fi
}

check_provider_blocking_guards

run_fmt() {
  step "cargo fmt --all -- --check"
  cargo fmt --all -- --check
}

if run_or_skip "cargo fmt --all -- --check (requires cargo & rustfmt)" ensure_tools cargo rustfmt; then
  run_fmt
fi

run_clippy() {
  step "cargo clippy --workspace --all-targets -- -D warnings"
  cargo clippy --workspace --all-targets "${CARGO_OFFLINE_ARGS[@]}" -- -D warnings
}

if run_or_skip "cargo clippy --workspace --all-targets (requires cargo-clippy component)" ensure_tools cargo cargo-clippy; then
  run_clippy
fi

run_build() {
  step "cargo build --workspace --all-features --locked"
  cargo build --workspace --all-features --locked "${CARGO_OFFLINE_ARGS[@]}"
}

if run_or_skip "cargo build --workspace --all-features --locked" ensure_tools cargo; then
  run_build
fi

run_tests() {
  step "cargo test --workspace --all-features --locked -- --nocapture"
  cargo test --workspace --all-features --locked "${CARGO_OFFLINE_ARGS[@]}" -- --nocapture
}

if run_or_skip "cargo test --workspace --all-features --locked" ensure_tools cargo; then
  run_tests
fi

run_pack_doctor() {
  step "greentic-pack doctor --validate (secrets provider packs)"
  local out_dir="${REPO_ROOT}/dist/packs"
  OUT_DIR="${out_dir}" "${REPO_ROOT}/scripts/build-provider-packs.sh"
  for pack in "${out_dir}"/secrets-*.gtpack; do
    greentic-pack doctor \
      --validate \
      --pack "${pack}" \
      --validator-pack "${REPO_ROOT}/dist/validators-secrets.gtpack" \
      --offline \
      --allow-oci-tags
  done
}

if run_or_skip "greentic-pack doctor --validate secrets packs (requires greentic-pack)" \
  ensure_tools greentic-pack; then
  run_pack_doctor
fi

run_secrets_e2e() {
  step "greentic-secrets-test e2e (dry-run)"
  local out_dir="${REPO_ROOT}/dist/packs"
  OUT_DIR="${out_dir}" "${REPO_ROOT}/scripts/build-provider-packs.sh"
  cargo run -p greentic-secrets-test --bin greentic-secrets-test "${CARGO_OFFLINE_ARGS[@]}" -- e2e --packs "${out_dir}"
}

if run_or_skip "greentic-secrets-test e2e (requires greentic-provision)" \
  ensure_tools cargo greentic-provision; then
  run_secrets_e2e
fi

run_provision_fixtures() {
  step "greentic-provision dry-run fixtures (secrets packs)"
  "${REPO_ROOT}/scripts/validate-provision-fixtures.sh"
}

if run_or_skip "greentic-provision dry-run fixtures (requires greentic-provision)" \
  ensure_tools greentic-provision; then
  run_provision_fixtures
fi

package_publishable_crates() {
  step "cargo package (dry-run) for publishable crates"
  local pkg_list=""
  if have python3; then
    pkg_list="$(python3 <<'PY' 2>/dev/null
import json, subprocess, sys
data = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps"]))
publishable = {}
for pkg in data["packages"]:
    if pkg.get("source") is not None:
        continue
    publish = pkg.get("publish")
    if publish == ["false"]:
        continue
    publishable[pkg["id"]] = pkg["name"]
if not publishable:
    sys.exit(0)
graph = {pkg_id: set() for pkg_id in publishable}
resolve = data.get("resolve", {})
for node in resolve.get("nodes", []):
    node_id = node["id"]
    if node_id not in publishable:
        continue
    for dep in node.get("deps", []):
        dep_id = dep["pkg"]
        if dep_id in publishable:
            graph[node_id].add(dep_id)
sys.setrecursionlimit(10000)
order = []
temp = set()
perm = set()
def visit(node_id):
    if node_id in perm:
        return
    if node_id in temp:
        raise SystemExit("cycle detected in workspace dependency graph")
    temp.add(node_id)
    for dep_id in sorted(graph[node_id], key=lambda pid: publishable[pid]):
        visit(dep_id)
    temp.remove(node_id)
    perm.add(node_id)
    order.append(node_id)
for node_id in sorted(graph, key=lambda pid: publishable[pid]):
    visit(node_id)
print("\n".join(publishable[node_id] for node_id in order))
PY
)"
  fi
  if [[ -z "$pkg_list" ]]; then
    pkg_list="$(
      cargo metadata --format-version 1 \
        | jq -r '.packages[] | select(.publish != ["false"] and (.source == null)) | .name' \
        | sort -u
    )"
  fi
  if [[ -z "$pkg_list" ]]; then
    echo "No publishable crates detected"
    return
  fi
  if [[ "$LOCAL_CHECK_ONLINE" == "1" ]]; then
    if need curl && ! curl -sSf --max-time 5 https://index.crates.io/config.json >/dev/null 2>&1; then
      local msg="cargo package dry-run (crates.io unreachable)"
      if [[ "$LOCAL_CHECK_STRICT" == "1" ]]; then
        echo "[fail] $msg" >&2
        exit 1
      fi
      SKIPPED_STEPS+=("$msg")
      echo "[skip] $msg"
      return
    fi
  fi
  local -a failed_pkgs=()
  local -a pkg_args=(--allow-dirty)
  if [[ "$LOCAL_CHECK_ONLINE" != "1" ]]; then
    pkg_args+=(--offline)
  fi
  local pkg
  while IFS= read -r pkg; do
    [[ -z "$pkg" ]] && continue
    echo "→ Packaging $pkg"
    if ! cargo package -p "$pkg" "${pkg_args[@]}"; then
      echo "[warn] cargo package failed for $pkg"
      failed_pkgs+=("$pkg")
    fi
  done <<<"$pkg_list"
  if [[ "${#failed_pkgs[@]}" -ne 0 ]]; then
    if [[ "$LOCAL_CHECK_STRICT" == "1" ]]; then
      echo "[fail] cargo package dry-run failed for: ${failed_pkgs[*]}" >&2
      exit 1
    fi
    local summary="cargo package dry-run (failed for: ${failed_pkgs[*]})"
    SKIPPED_STEPS+=("$summary")
    echo "[skip] $summary"
  fi
}

should_run_package() {
  if [[ "$LOCAL_CHECK_PACKAGE" == "1" || "$LOCAL_CHECK_STRICT" == "1" ]]; then
    return 0
  fi
  echo "[info] Set LOCAL_CHECK_PACKAGE=1 (or LOCAL_CHECK_STRICT=1) to run cargo package dry-runs"
  return 1
}

if run_or_skip "cargo package dry-run (requires jq and LOCAL_CHECK_PACKAGE=1)" \
  should_run_package && ensure_tools cargo jq; then
  package_publishable_crates
fi

run_tarpaulin() {
  step "cargo tarpaulin --workspace --all-features"
  cargo tarpaulin \
    --workspace \
    --all-features \
    "${CARGO_OFFLINE_ARGS[@]}" \
    --timeout 600 \
    --out Lcov \
    --output-dir coverage
}

should_run_tarpaulin() {
  if [[ "$LOCAL_CHECK_COVERAGE" == "1" || "$LOCAL_CHECK_STRICT" == "1" ]]; then
    return 0
  fi
  echo "[info] Set LOCAL_CHECK_COVERAGE=1 (or LOCAL_CHECK_STRICT=1) to run coverage locally"
  return 1
}

if run_or_skip "cargo tarpaulin coverage (requires cargo-tarpaulin and LOCAL_CHECK_COVERAGE=1)" \
  should_run_tarpaulin && ensure_tools cargo cargo-tarpaulin; then
  run_tarpaulin
fi

run_conformance() {
  local provider="$1"
  step "Conformance: provider-${provider}"
  cargo run -p greentic-secrets-conformance "${CARGO_OFFLINE_ARGS[@]}" --features "provider-${provider}"
}

run_local_provider_k8s() {
  step "Conformance: provider-k8s (KinD)"
  local cluster="gts-local-check"
  KIND_CLUSTER="$cluster"
  if kind get clusters | grep -q "$cluster"; then
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  fi
  kind create cluster --name "$cluster" --wait 120s
  cargo run -p greentic-secrets-conformance "${CARGO_OFFLINE_ARGS[@]}" --features provider-k8s
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  KIND_CLUSTER=""
}

run_local_provider_vault() {
  step "Conformance: provider-vault (Vault dev server)"
  local name="gts-local-check-vault"
  VAULT_CONTAINER="$name"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --rm --name "$name" -e VAULT_DEV_ROOT_TOKEN_ID=root -p 8200:8200 hashicorp/vault:1.16 >/dev/null
  local addr="http://127.0.0.1:8200"
  local healthy=0
  for i in {1..20}; do
    if curl -fsS "$addr/v1/sys/health" >/dev/null; then
      healthy=1
      break
    fi
    sleep 1
  done
  if [[ "$healthy" -ne 1 ]]; then
    echo "[fail] Vault dev server did not become ready" >&2
    exit 1
  fi
  VAULT_ADDR="$addr" VAULT_TOKEN="root" cargo run -p greentic-secrets-conformance "${CARGO_OFFLINE_ARGS[@]}" --features provider-vault
  docker rm -f "$name" >/dev/null 2>&1 || true
  VAULT_CONTAINER=""
}

if run_or_skip "Conformance provider-dev" ensure_tools cargo; then
  run_conformance "dev"
fi

can_run_local_k8s() {
  if [[ "$LOCAL_CHECK_ONLINE" != "1" ]]; then
    echo "[info] Set LOCAL_CHECK_ONLINE=1 to run the KinD-based provider tests"
    return 1
  fi
  docker_ready || return 1
  ensure_tools kind kubectl || return 1
  return 0
}

can_run_local_vault() {
  if [[ "$LOCAL_CHECK_ONLINE" != "1" ]]; then
    echo "[info] Set LOCAL_CHECK_ONLINE=1 to run the Vault-based provider tests"
    return 1
  fi
  docker_ready || return 1
  ensure_tools curl || return 1
  return 0
}

if run_or_skip "Conformance provider-k8s (requires docker, kind, kubectl)" can_run_local_k8s; then
  run_local_provider_k8s
fi

if run_or_skip "Conformance provider-vault (requires docker & curl)" can_run_local_vault; then
  run_local_provider_vault
fi

can_run_live() {
  local provider="$1"
  shift
  if ! require_online; then
    echo "[info] LOCAL_CHECK_ONLINE=1 is required for live provider '$provider'"
    return 1
  fi
  if ! ensure_tools cargo; then
    return 1
  fi
  require_env_vars "$@"
}

if run_or_skip "Live conformance: provider-aws (requires LOCAL_CHECK_ONLINE=1)" \
  can_run_live "aws" GTS_REGION GTS_PREFIX; then
  step "Live conformance: provider-aws"
  cargo run -p greentic-secrets-conformance "${CARGO_OFFLINE_ARGS[@]}" --features provider-aws
fi

if run_or_skip "Live conformance: provider-azure (requires LOCAL_CHECK_ONLINE=1)" \
  can_run_live "azure" AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_KEYVAULT_URL AZURE_KV_SCOPE GTS_PREFIX; then
  step "Live conformance: provider-azure"
  cargo run -p greentic-secrets-conformance "${CARGO_OFFLINE_ARGS[@]}" --features provider-azure
fi

if run_or_skip "Live conformance: provider-gcp (requires LOCAL_CHECK_ONLINE=1)" \
  can_run_live "gcp" GTS_GCP_PROJECT GTS_PREFIX; then
  step "Live conformance: provider-gcp"
  cargo run -p greentic-secrets-conformance "${CARGO_OFFLINE_ARGS[@]}" --features provider-gcp
fi

printf "\nAll requested checks finished.\n"
if [[ "${#SKIPPED_STEPS[@]}" -gt 0 ]]; then
  printf "Skipped steps:\n"
  printf " - %s\n" "${SKIPPED_STEPS[@]}"
else
  printf "No steps were skipped.\n"
fi
