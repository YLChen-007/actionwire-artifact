"""Fresh cross-project handler specifications for direct type alignment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from src.handler_identity import stable_handler_id
from src.projects import ProjectSpec

from .contracts import AlignmentContractError


@dataclass(frozen=True)
class HandlerProfile:
    handler_id: str
    project_id: str
    revision: str
    tool: dict[str, Any]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_profiles(
    specs: Sequence[ProjectSpec],
) -> tuple[list[HandlerProfile], list[dict[str, str]], dict[str, dict[str, str]]]:
    profiles: list[HandlerProfile] = []
    excluded: list[dict[str, str]] = []
    digests: dict[str, dict[str, str]] = {}
    for raw_spec in specs:
        spec = raw_spec.resolved()
        inventory_path = (
            spec.output_root
            / "handler-specifications"
            / "tool-handler-specifications.json"
        )
        if not inventory_path.is_file():
            raise AlignmentContractError(
                f"missing handler alignment input for {spec.project_id}"
            )
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        if inventory.get("schema_version") != "clawgap/tool-handler-specifications/v2":
            raise AlignmentContractError(
                f"{spec.project_id}: unsupported handler specification schema"
            )
        project = inventory.get("project", {})
        if project.get("id") != spec.project_id:
            raise AlignmentContractError(
                f"{spec.project_id}: handler specification project mismatch"
            )
        if project.get("analysis_revision") != spec.analysis_revision:
            raise AlignmentContractError(
                f"{spec.project_id}: handler specification revision mismatch"
            )
        tools = inventory.get("tools")
        if not isinstance(tools, list):
            raise AlignmentContractError(f"{spec.project_id}: tools must be an array")
        by_name = {row.get("tool_name"): row for row in tools if isinstance(row, dict)}
        if len(by_name) != len(tools) or None in by_name:
            raise AlignmentContractError(
                f"{spec.project_id}: duplicate or invalid handler specifications"
            )
        inventory_digest = _sha256_file(inventory_path)
        digests[spec.project_id] = {
            "handler_specifications": inventory_digest,
        }
        for tool_name in sorted(by_name):
            tool = by_name[tool_name]
            expected_id = stable_handler_id(
                spec.project_id,
                spec.analysis_revision,
                tool_name,
                tool.get("handlers", []),
            )
            if (
                tool.get("resolution", {}).get("status") != "resolved"
                or tool.get("function") is None
            ):
                excluded.append(
                    {
                        "project": spec.project_id,
                        "handler_id": expected_id,
                        "tool_name": tool_name,
                        "reason": "unresolved-handler-specification",
                    }
                )
                continue
            profiles.append(
                HandlerProfile(
                    handler_id=expected_id,
                    project_id=spec.project_id,
                    revision=spec.analysis_revision,
                    tool=tool,
                )
            )
    profiles.sort(
        key=lambda row: (row.project_id, row.tool["tool_name"], row.handler_id)
    )
    excluded.sort(key=lambda row: (row["project"], row["tool_name"], row["handler_id"]))
    return profiles, excluded, digests
