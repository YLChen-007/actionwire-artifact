"""Post-alignment observations of statically reachable sink capabilities."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from src.projects import ProjectSpec

from .contracts import (
    CAPABILITY_OBSERVATION_SCHEMA_VERSION,
    AlignmentContractError,
)
from .inputs import HandlerProfile


@dataclass(frozen=True)
class HandlerCapabilities:
    sink_ids: tuple[str, ...]
    capability_classes: tuple[str, ...]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path, required: set[str]) -> list[dict[str, str]]:
    if not path.is_file():
        raise AlignmentContractError(f"missing capability observation input: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or not required <= set(reader.fieldnames):
            raise AlignmentContractError(f"{path}: missing required CSV columns")
        return [dict(row) for row in reader]


def load_handler_capabilities(
    specs: Sequence[ProjectSpec],
    profiles: Sequence[HandlerProfile],
    excluded: Sequence[dict[str, str]],
) -> tuple[dict[str, HandlerCapabilities], dict[str, dict[str, str]]]:
    profile_by_tool = {
        (row.project_id, row.tool["tool_name"]): row.handler_id for row in profiles
    }
    profiles_by_concrete_handler: dict[tuple[str, str, str, str], set[str]] = {}
    for profile in profiles:
        for handler in profile.tool.get("handlers", []):
            if not isinstance(handler, dict):
                continue
            key = (
                profile.project_id,
                str(handler.get("handler_func", "")),
                str(handler.get("file", "")),
                str(handler.get("line", "")),
            )
            if not all(key[1:]):
                raise AlignmentContractError(
                    f"{profile.project_id}:{profile.tool['tool_name']}: incomplete concrete handler identity"
                )
            profiles_by_concrete_handler.setdefault(key, set()).add(profile.handler_id)
    known_tools = set(profile_by_tool) | {
        (row["project"], row["tool_name"]) for row in excluded
    }
    sinks_by_handler: dict[str, set[str]] = {
        row.handler_id: set() for row in profiles
    }
    classes_by_handler: dict[str, set[str]] = {
        row.handler_id: set() for row in profiles
    }
    digests: dict[str, dict[str, str]] = {}
    for raw_spec in specs:
        spec = raw_spec.resolved()
        root = spec.output_root / "static" / "call-chains"
        manifest_path = root / "manifest.json"
        chains_path = root / "handler-sink-chains.csv"
        constraints_path = root / "sink-constraints.csv"
        if not manifest_path.is_file():
            raise AlignmentContractError(
                f"{spec.project_id}: missing call-chain manifest for capability observation"
            )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != "clawgap-pipeline-call-chains/v2":
            raise AlignmentContractError(
                f"{spec.project_id}: unsupported call-chain manifest schema"
            )
        if manifest.get("project") != spec.project_id:
            raise AlignmentContractError(
                f"{spec.project_id}: call-chain manifest project mismatch"
            )
        if manifest.get("revision") != spec.analysis_revision:
            raise AlignmentContractError(
                f"{spec.project_id}: call-chain manifest revision mismatch"
            )
        expected_outputs = {
            "handler_sink_chains": chains_path.resolve(),
            "sink_constraints": constraints_path.resolve(),
        }
        outputs = manifest.get("outputs", {})
        for key, expected in expected_outputs.items():
            supplied = outputs.get(key)
            if not isinstance(supplied, str) or Path(supplied).resolve() != expected:
                raise AlignmentContractError(
                    f"{spec.project_id}: call-chain manifest {key} path mismatch"
                )
        chains = _read_csv(
            chains_path,
            {
                "chain_id",
                "sink_id",
                "project_id",
                "tool_name",
                "handler_func",
                "handler_file",
                "handler_line",
            },
        )
        constraints = _read_csv(
            constraints_path,
            {"sink_id", "capability_class"},
        )
        constraint_by_sink: dict[str, str] = {}
        for row in constraints:
            sink_id = row["sink_id"].strip()
            capability_class = row["capability_class"].strip()
            if not sink_id or not capability_class or sink_id in constraint_by_sink:
                raise AlignmentContractError(
                    f"{spec.project_id}: invalid or duplicate sink constraint"
                )
            constraint_by_sink[sink_id] = capability_class
        for row in chains:
            if row["project_id"] != spec.project_id:
                raise AlignmentContractError(
                    f"{spec.project_id}: call-chain row project mismatch"
                )
            sink_id = row["sink_id"].strip()
            if sink_id not in constraint_by_sink:
                raise AlignmentContractError(
                    f"{spec.project_id}: missing constraint for {sink_id}"
                )
            concrete_key = (
                spec.project_id,
                row["handler_func"],
                row["handler_file"],
                row["handler_line"],
            )
            handler_ids = set(profiles_by_concrete_handler.get(concrete_key, set()))
            tool_key = (spec.project_id, row["tool_name"])
            direct_handler_id = profile_by_tool.get(tool_key)
            if direct_handler_id is not None:
                handler_ids = {direct_handler_id}
            if not handler_ids and tool_key in known_tools:
                continue
            if not handler_ids:
                raise AlignmentContractError(
                    f"{spec.project_id}: cannot join call-chain handler "
                    f"{row['handler_func']}@{row['handler_file']}:{row['handler_line']}"
                )
            for handler_id in handler_ids:
                sinks_by_handler[handler_id].add(sink_id)
                classes_by_handler[handler_id].add(constraint_by_sink[sink_id])
        digests[spec.project_id] = {
            "call_chain_manifest": _sha256_file(manifest_path),
            "handler_sink_chains": _sha256_file(chains_path),
            "sink_constraints": _sha256_file(constraints_path),
        }
    capabilities = {
        handler_id: HandlerCapabilities(
            sink_ids=tuple(sorted(sinks_by_handler[handler_id])),
            capability_classes=tuple(sorted(classes_by_handler[handler_id])),
        )
        for handler_id in sorted(sinks_by_handler)
    }
    return capabilities, digests


def build_type_capability_observations(
    catalog: dict[str, object],
    mappings: Sequence[dict[str, object]],
    capabilities: dict[str, HandlerCapabilities],
) -> list[dict[str, object]]:
    handler_by_member = {
        f"{row['project']}:{row['handler_id']}": str(row["handler_id"])
        for row in mappings
    }
    observations: list[dict[str, object]] = []
    for handler_type in catalog["types"]:  # type: ignore[index]
        members = []
        class_sets: list[tuple[str, ...]] = []
        for member in handler_type["members"]:
            handler_id = handler_by_member[member]
            observed = capabilities[handler_id]
            class_sets.append(observed.capability_classes)
            members.append(
                {
                    "member": member,
                    "sink_ids": list(observed.sink_ids),
                    "capability_classes": list(observed.capability_classes),
                }
            )
        nonempty = [row for row in class_sets if row]
        if not nonempty:
            status = "no-reachable-sink"
        elif len(nonempty) != len(class_sets):
            status = "partial"
        elif len(set(nonempty)) == 1:
            status = "uniform"
        else:
            status = "heterogeneous"
        observations.append(
            {
                "schema_version": CAPABILITY_OBSERVATION_SCHEMA_VERSION,
                "handler_type_id": handler_type["handler_type_id"],
                "status": status,
                "observed_capability_classes": sorted(
                    {capability for row in class_sets for capability in row}
                ),
                "members": members,
            }
        )
    return sorted(observations, key=lambda row: row["handler_type_id"])
