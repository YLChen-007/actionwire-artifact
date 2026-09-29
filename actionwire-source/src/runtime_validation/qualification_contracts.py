"""Strict contracts for containerized adapter-qualification campaigns."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .campaign_contracts import PROBES, PROJECT_ADAPTERS, canonical_json, digest
from .contracts import ValidationError


QUALIFICATION_CASE_SCHEMA_VERSION = "clawgap-runtime-qualification-case/v1"
QUALIFICATION_CAMPAIGN_SCHEMA_VERSION = "clawgap-runtime-qualification-campaign/v1"
QUALIFICATION_RESULT_SCHEMA_VERSION = "clawgap-runtime-qualification-result/v1"
QUALIFICATION_EVENT_SCHEMA_VERSION = "clawgap-runtime-evidence-event/v1"

QUALIFICATION_STATUSES = {"qualified", "blocked", "inconclusive"}
FORCED_PATH_OUTCOMES = {"confirmed", "inconclusive"}
LIVE_TRIGGERABILITY_OUTCOMES = {
    "triggered",
    "not-triggered",
    "inconclusive",
    "not-run",
}

CASE_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "schemas"
    / "runtime-qualification-case-v1.schema.json"
)
EVENT_SCHEMA_PATH = (
    Path(__file__).resolve().parent / "schemas" / "runtime-evidence-event-v1.schema.json"
)


def stable_qualification_case_id(identity: Mapping[str, Any]) -> str:
    return "RVQ-" + digest(identity)[:16]


def qualification_case_content(case: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in case.items()
        if key not in {"case_id", "review", "selection"}
    }


def validate_qualification_case(case: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(case)
    schema = json.loads(CASE_SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path)
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(str(part) for part in item.path) or '<root>'}: {item.message}"
            for item in errors[:8]
        )
        raise ValidationError(f"qualification case schema validation failed: {details}")
    if value["schema_version"] != QUALIFICATION_CASE_SCHEMA_VERSION:
        raise ValidationError("unsupported qualification case schema")
    family = value["family"]
    if PROJECT_ADAPTERS.get(family["project"]) != family["adapter"]:
        raise ValidationError("qualification family adapter/project mismatch")
    if family["probe"] not in PROBES:
        raise ValidationError("qualification family uses an unknown probe")
    replay = value["replay"]
    if replay["tool_name"] != family["tool_name"]:
        raise ValidationError("qualification replay tool does not match family")
    native_case = value["native_case"]
    if (
        native_case.get("case_id") != value["origin"]["ground_truth_case_id"]
        or native_case.get("revision") != value["revision"]
        or native_case.get("source_binding") != value["source_binding"]
        or native_case.get("dependency_binding") != value["dependency_binding"]
    ):
        raise ValidationError("qualification case drifted from its reviewed native case")
    for side in ("exploit", "control"):
        if value["mock_provider"]["tool_calls"][side] != {
            "name": replay["tool_name"],
            "arguments": replay[f"{side}_args"],
        }:
            raise ValidationError(f"qualification mock {side} call does not bind replay")
    identity = qualification_case_content(value)
    if value["case_id"] != stable_qualification_case_id(identity):
        raise ValidationError("qualification case stable identity mismatch")
    return value


def validate_qualification_event(event: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(event)
    schema = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path)
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(str(part) for part in item.path) or '<root>'}: {item.message}"
            for item in errors[:4]
        )
        raise ValidationError(f"qualification evidence event schema failed: {details}")
    if value["schema_version"] != QUALIFICATION_EVENT_SCHEMA_VERSION:
        raise ValidationError("unsupported qualification evidence event")
    return value


@dataclass(frozen=True)
class QualificationGenerationRequest:
    source_campaign: Path
    out_dir: Path
    expected_families: int = 23


@dataclass(frozen=True)
class QualificationExpansionRequest:
    source_campaign: Path
    qualification_campaign: Path
    out_dir: Path
    expected_cases: int = 42
    expected_families: int = 23


@dataclass(frozen=True)
class QualificationRunRequest:
    campaign_dir: Path
    attempts: int = 3
    jobs: int = 1
    engine: str = "docker"

    def __post_init__(self) -> None:
        if self.attempts != 3:
            raise ValidationError("qualification campaigns require exactly three pairs")
        if self.jobs < 1:
            raise ValidationError("qualification jobs must be positive")
        if self.engine not in {"docker", "podman", "auto"}:
            raise ValidationError("qualification engine must be docker, podman, or auto")


@dataclass(frozen=True)
class QualificationCampaign:
    campaign_id: str
    root: Path
    cases: tuple[Mapping[str, Any], ...]
    selection: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class QualificationRun:
    campaign_id: str
    qualification_counts: Mapping[str, int]
    forced_path_counts: Mapping[str, int]
    live_triggerability_counts: Mapping[str, int]
    artifact_dir: Path
    results: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)


def canonical_jsonl(rows: list[Mapping[str, Any]]) -> str:
    return "".join(canonical_json(row) + "\n" for row in rows)
