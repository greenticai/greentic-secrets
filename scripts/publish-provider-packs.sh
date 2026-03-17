#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

command -v oras >/dev/null 2>&1 || { echo "oras is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

OCI_REGISTRY="${OCI_REGISTRY:-ghcr.io}"
OCI_NAMESPACE="${OCI_NAMESPACE:-greenticai}"
OCI_REPO="${OCI_REPO:-packs/secrets}"
OCI_NAMESPACE="$(printf '%s' "${OCI_NAMESPACE}" | tr '[:upper:]' '[:lower:]')"
OCI_REPO="$(printf '%s' "${OCI_REPO}" | tr '[:upper:]' '[:lower:]')"
PACK_VERSION="${PACK_VERSION:-}"
if [ -z "${PACK_VERSION}" ]; then
  if [ -f "dist/packs/VERSION" ]; then
    PACK_VERSION="$(tr -d '[:space:]' < dist/packs/VERSION)"
  else
    PACK_VERSION="$(python3 - <<'PY'
from pathlib import Path
import re
text = Path("Cargo.toml").read_text(encoding="utf-8")
match = re.search(r'\[workspace\.package\].*?^version\s*=\s*"([^"]+)"', text, re.M | re.S)
if not match:
    raise SystemExit("workspace.package.version not found")
print(match.group(1))
PY
)"
  fi
fi
PACK_VERSION="${PACK_VERSION#v}"
PACK_MEDIA_TYPE="${PACK_MEDIA_TYPE:-application/vnd.greentic.gtpack.v1+zip}"

if ! compgen -G "dist/packs/*.gtpack" >/dev/null; then
  echo "No built packs found under dist/packs" >&2
  exit 1
fi

python3 - "${PACK_VERSION}" "${OCI_REGISTRY}" "${OCI_NAMESPACE}" "${OCI_REPO}" "${PACK_MEDIA_TYPE}" <<'PY'
from pathlib import Path
import json
import subprocess
import sys

pack_version, registry, namespace, repo, media_type = sys.argv[1:]
root = Path.cwd()
lock_path = root / "packs.lock.json"
lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else {"version": pack_version, "packs": []}
packs_by_name = {entry["name"]: entry for entry in lock.get("packs", [])}

def oras_artifact_arg(pack_path: Path) -> str:
    try:
        artifact_path = pack_path.relative_to(root)
    except ValueError:
        artifact_path = pack_path
    return f"{artifact_path.as_posix()}:{media_type}"

def published_name(name: str) -> str:
    entry = packs_by_name.get(name, {})
    canonical = entry.get("published_name")
    if canonical:
        return canonical

    pack_id = entry.get("pack_id")
    if pack_id:
        return f"{pack_id}.gtpack"

    if name.startswith("secrets-"):
        suffix = name[len("secrets-"):]
        return f"greentic.secrets.{suffix}.gtpack"

    return f"{name}.gtpack"

for pack_path in sorted((root / "dist" / "packs").glob("*.gtpack")):
    name = pack_path.stem
    repo_path = f"{registry}/{namespace}/{repo}/{published_name(name)}"
    version_ref = f"{repo_path}:{pack_version}"
    print(f"Publishing {pack_path.name} -> {version_ref}", flush=True)
    subprocess.run(
        [
            "oras",
            "push",
            version_ref,
            oras_artifact_arg(pack_path),
        ],
        check=True,
    )
    latest_ref = f"{repo_path}:latest"
    print(f"Publishing {pack_path.name} -> {latest_ref}", flush=True)
    subprocess.run(
        [
            "oras",
            "push",
            latest_ref,
            oras_artifact_arg(pack_path),
        ],
        check=True,
    )

    entry = packs_by_name.setdefault(name, {"name": name})
    entry["version"] = pack_version
    entry["published_name"] = published_name(name)
    entry["reference"] = f"oci://{version_ref}"
    entry["latest_reference"] = f"oci://{repo_path}:latest"

lock["version"] = pack_version
lock["packs"] = [packs_by_name[name] for name in sorted(packs_by_name)]
lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
PY

echo "Published secrets packs to ${OCI_REGISTRY}/${OCI_NAMESPACE}/${OCI_REPO}"
