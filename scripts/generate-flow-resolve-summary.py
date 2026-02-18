#!/usr/bin/env python3
import json
import sys
from pathlib import Path

import yaml


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text())


def load_digests(path: Path):
    if not path or not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {entry["id"]: entry for entry in data}


def digest_for(component_id: str, uri: str, digests):
    if uri and "@sha256:" in uri:
        return "sha256:" + uri.split("@sha256:", 1)[1], True
    entry = digests.get(component_id)
    if entry:
        digest = entry.get("digest", "")
        if digest and not digest.startswith("sha256:"):
            digest = f"sha256:{digest}"
        if digest:
            return digest, True
    # Keep `digest` present for schema compatibility, but avoid forcing
    # digest-pinned OCI resolution when no trusted digest is available.
    return "", False


def source_ref_for(uri: str, digest: str, pin_digest: bool):
    if not uri:
        return None
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
                "source": source_ref_for(uri, digest, pin_digest),
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
