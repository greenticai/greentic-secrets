#!/usr/bin/env python3
import json
import sys
import hashlib
import os
import re
from pathlib import Path

import yaml


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text())


def load_digests(path: Path):
    if not path or not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {entry["id"]: entry for entry in data}


_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_sha256_digest(raw: str):
    if not raw:
        return None
    value = raw.strip()
    if value.startswith("sha256:"):
        value = value[len("sha256:") :]
    value = value.lower()
    if _DIGEST_HEX_RE.fullmatch(value):
        return f"sha256:{value}"
    return None


def digest_for(component_id: str, uri: str, digests):
    if uri and uri.startswith("file://"):
        path = Path(uri[len("file://") :])
        if path.exists():
            return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), True
    if uri and "@sha256:" in uri:
        normalized = normalize_sha256_digest(uri.split("@sha256:", 1)[1])
        if normalized:
            return normalized, True
    entry = digests.get(component_id)
    if entry:
        normalized = normalize_sha256_digest(entry.get("digest", ""))
        if normalized:
            return normalized, True
    # Keep `digest` present for schema compatibility using a deterministic
    # placeholder, but avoid pinning source.ref when it is not trusted.
    synthetic = "sha256:" + hashlib.sha256((uri or component_id).encode()).hexdigest()
    return synthetic, False


def source_ref_for(uri: str, digest: str, pin_digest: bool, flow_path: Path):
    if not uri:
        return None
    if uri.startswith("file://"):
        raw_path = Path(uri[len("file://") :])
        if raw_path.is_absolute():
            try:
                rel_path = raw_path.relative_to(flow_path.parent)
            except ValueError:
                rel_path = Path(
                    os.path.relpath(raw_path, start=flow_path.parent)
                )
        else:
            rel_path = raw_path
        return {"kind": "local", "path": rel_path.as_posix()}
    if uri.startswith("oci://"):
        uri = uri[len("oci://") :]
    if pin_digest and digest and "@sha256:" not in uri:
        uri = f"{uri}@{digest}"
    return {"kind": "oci", "ref": uri}


def component_id_for_node(node: dict):
    if "component" in node:
        return (node.get("component") or {}).get("id")
    if "component.exec" in node:
        exec_node = node.get("component.exec") or {}
        return exec_node.get("component") or exec_node.get("component_id")
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: generate-flow-resolve-summary.py <pack_dir> [digests.json]", file=sys.stderr)
        raise SystemExit(2)

    pack_dir = Path(sys.argv[1])
    digests = load_digests(Path(sys.argv[2])) if len(sys.argv) > 2 else {}

    gtpack_path = pack_dir / "gtpack.yaml"
    if not gtpack_path.exists():
        raise SystemExit(f"missing gtpack.yaml in {pack_dir}")
    gtpack = load_yaml(gtpack_path) or {}
    components = {
        comp.get("id"): comp.get("uri")
        for comp in (gtpack.get("components") or [])
    }

    flows_dir = pack_dir / "flows"
    if not flows_dir.exists():
        return

    for flow_path in flows_dir.glob("*.ygtc"):
        flow = load_yaml(flow_path) or {}
        nodes = flow.get("nodes") or {}
        summary_nodes = {}
        for node_id, node in nodes.items():
            component_id = component_id_for_node(node)
            if not component_id:
                raise SystemExit(f"{flow_path}: node {node_id} missing component id")
            uri = components.get(component_id)
            if not uri:
                raise SystemExit(
                    f"{flow_path}: node {node_id} component {component_id} not in gtpack.yaml"
                )
            digest, pin_digest = digest_for(component_id, uri, digests)
            summary_node = {
                "component_id": component_id,
                "source": source_ref_for(uri, digest, pin_digest, flow_path),
                "digest": digest,
            }
            summary_nodes[node_id] = summary_node

        summary = {
            "schema_version": 1,
            "flow": flow_path.name,
            "nodes": summary_nodes,
        }
        out_path = flow_path.with_name(flow_path.name + ".resolve.summary.json")
        out_path.write_text(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
