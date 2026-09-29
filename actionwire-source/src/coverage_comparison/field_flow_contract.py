"""Domain contract for deterministic field-sensitive flow artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


class FieldFlowContractError(ValueError):
    """Raised when a field-flow row cannot be admitted fail closed."""


VALUE_AUTHORITIES = frozenset(
    {
        "model-arbitrary",
        "model-component",
        "model-basename",
        "model-enum",
        "internal-derived",
        "operator-config",
        "provider-response",
        "fixed",
    }
)
PROOF_KINDS = frozenset({"direct", "interprocedural", "explicit-bridge", "none"})
PATH_NODE_KINDS = frozenset(
    {
        "field-read",
        "assignment",
        "argument",
        "parameter",
        "return",
        "transform",
        "bridge",
        "sink-role",
    }
)
EXCLUSION_REASONS = frozenset(
    {
        "map-key-not-value",
        "whole-object-does-not-imply-property",
        "same-name-no-dataflow",
        "sibling-argument",
        "selector-not-selected-content",
        "operator-config",
        "provider-response",
        "missing-explicit-bridge",
        "no-field-flow",
        "no-authoritative-proof",
    }
)


def stable_identifier(prefix: str, payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:16]}"


def parse_location(value: str) -> tuple[str, int, int]:
    parts = value.rsplit(":", 2)
    if len(parts) != 3 or not parts[0]:
        raise FieldFlowContractError(f"invalid source location: {value!r}")
    try:
        line, column = int(parts[1]), int(parts[2])
    except ValueError as exc:
        raise FieldFlowContractError(f"invalid source location: {value!r}") from exc
    if line < 1 or column < 1:
        raise FieldFlowContractError(f"invalid source location: {value!r}")
    return parts[0], line, column


def parse_path_nodes(serialized: str) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    for raw in serialized.split(";"):
        token = raw.strip()
        if not token:
            continue
        if "@" not in token:
            raise FieldFlowContractError(f"path node lacks kind: {token!r}")
        kind, location = token.split("@", 1)
        if kind not in PATH_NODE_KINDS:
            raise FieldFlowContractError(f"unknown path node kind: {kind!r}")
        file, line, column = parse_location(location)
        nodes.append({"kind": kind, "file": file, "line": line, "column": column})
    if len(nodes) < 2 or nodes[0]["kind"] != "field-read":
        raise FieldFlowContractError("path must start at a field-read node")
    if nodes[-1]["kind"] != "sink-role":
        raise FieldFlowContractError("path must end at a sink-role node")
    return nodes


def parse_transforms(serialized: str) -> list[dict[str, str]]:
    return [
        {"kind": "call", "name": value}
        for value in dict.fromkeys(part.strip() for part in serialized.split(";"))
        if value
    ]


def source_hashes(source_root: Path, nodes: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    root = source_root.resolve()
    hashes: dict[str, str] = {}
    for relative in sorted({str(node["file"]) for node in nodes}):
        target = (root / relative).resolve()
        if root not in target.parents or not target.is_file():
            raise FieldFlowContractError(f"path node escapes or is missing: {relative}")
        hashes[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
    return hashes


def validate_common(record: Mapping[str, Any]) -> None:
    authority = record.get("value_authority")
    proof = record.get("proof_kind")
    nodes = record.get("path_nodes")
    if authority not in VALUE_AUTHORITIES:
        raise FieldFlowContractError(f"invalid value_authority: {authority!r}")
    if proof not in PROOF_KINDS:
        raise FieldFlowContractError(f"invalid proof_kind: {proof!r}")
    if not isinstance(nodes, list):
        raise FieldFlowContractError("path_nodes must be a list")
    if proof == "explicit-bridge" and not any(node.get("kind") == "bridge" for node in nodes):
        raise FieldFlowContractError("explicit-bridge proof lacks a bridge path node")


def canonical_payload(record: Mapping[str, Any], *, identifier_key: str) -> dict[str, Any]:
    return {key: record[key] for key in sorted(record) if key != identifier_key}
