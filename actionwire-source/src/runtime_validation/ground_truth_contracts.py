"""Contracts for report-centric ground-truth runtime validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .campaign_contracts import (
    ADAPTERS,
    FIXTURES,
    PROJECT_ADAPTERS,
    PROBES,
    STAGE_KINDS,
    VALUE_RELATIONS,
    digest,
)
from .contracts import ValidationError


GT_CASE_SCHEMA_VERSION = "clawgap-runtime-ground-truth-case/v1"
GT_CAMPAIGN_SCHEMA_VERSION = "clawgap-runtime-ground-truth-campaign/v1"
GT_AUDIT_SCHEMA_VERSION = "clawgap-runtime-ground-truth-audit/v1"
GT_REVIEW_SCHEMA_VERSION = "clawgap-runtime-ground-truth-review/v1"
GT_RESULT_SCHEMA_VERSION = "clawgap-runtime-ground-truth-result/v1"

SUPPORT_STATUSES = {
    "ready",
    "anchor-invalid",
    "generator-invalid",
    "review-rejected",
    "driver-unavailable",
    "fixture-unavailable",
}
RUNTIME_OUTCOMES = {
    "runtime-confirmed",
    "not-reproduced",
    "inconclusive",
    "not-run",
    "not-applicable",
}

SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "schemas"
    / "runtime-ground-truth-case-v1.schema.json"
)


def stable_gt_case_id(identity: Mapping[str, Any]) -> str:
    return "RVGT-" + digest(identity)[:16]


def gt_case_content(case: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in case.items() if key != "review"}


def gt_case_content_sha256(case: Mapping[str, Any]) -> str:
    return digest(gt_case_content(case))


def validate_ground_truth_case(case: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(case)
    errors = sorted(
        Draft202012Validator(
            json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        ).iter_errors(value),
        key=lambda row: list(row.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:8]
        )
        raise ValidationError(f"ground-truth case schema validation failed: {detail}")
    if value["schema_version"] != GT_CASE_SCHEMA_VERSION:
        raise ValidationError("unsupported ground-truth case schema version")
    if value["adapter"] not in ADAPTERS or PROJECT_ADAPTERS.get(value["project"]) != value["adapter"]:
        raise ValidationError("ground-truth adapter/project mismatch")
    if value["probe"] not in PROBES or value["fixture"] not in FIXTURES:
        raise ValidationError("unknown ground-truth probe or fixture")
    if value["matcher"]["relation"] not in VALUE_RELATIONS:
        raise ValidationError("unknown ground-truth matcher relation")
    kinds = [row["kind"] for row in value["observations"]]
    if any(kind not in STAGE_KINDS for kind in kinds):
        raise ValidationError("unknown ground-truth observation kind")
    if not kinds or kinds[0] != "handler" or "sink" not in kinds or kinds[-1] != "effect":
        raise ValidationError("ground-truth observations must be handler -> sink -> effect")
    if value["failure_mode"] == "wrong-check" and "gate" not in kinds:
        raise ValidationError("Wrong-Check ground truth requires an observed gate")
    if value["failure_mode"] == "missing-check" and "gate" in kinds:
        raise ValidationError("Missing-Check ground truth must not synthesize a gate")

    matcher = value["matcher"]
    source = (
        value["fixture_state"]
        if matcher["source"] == "fixture-state"
        else {
            "exploit": value["replay"]["exploit_args"],
            "control": value["replay"]["control_args"],
        }
    )

    def nested(arguments: Mapping[str, Any]) -> Any:
        current: Any = arguments
        for part in matcher["path"]:
            if not isinstance(current, Mapping) or part not in current:
                raise ValidationError("ground-truth matcher path is absent")
            current = current[part]
        return current

    exploit = nested(source["exploit"])
    control = nested(source["control"])
    if exploit != matcher["exploit_value"] or control != matcher["control_value"]:
        raise ValidationError("ground-truth matcher values do not bind their source")
    if exploit == control:
        raise ValidationError("ground-truth exploit/control matcher values must differ")
    if matcher["source"] == "tool-argument" and value["replay"]["exploit_args"] == value["replay"]["control_args"]:
        raise ValidationError("tool-argument exploit and control calls must differ")

    identity = {
        "report_id": value["report_id"],
        "project": value["project"],
        "revision": value["revision"],
        "failure_mode": value["failure_mode"],
        "replay": value["replay"],
        "matcher": value["matcher"],
        "fixture_state": value["fixture_state"],
        "observations": value["observations"],
    }
    if value["case_id"] != stable_gt_case_id(identity):
        raise ValidationError("ground-truth case stable identity mismatch")
    review = value["review"]
    if review["status"] == "approved" and review["reviewed_case_sha256"] != gt_case_content_sha256(value):
        raise ValidationError("ground-truth review hash does not bind the case")
    return value


@dataclass(frozen=True)
class GroundTruthAuditRequest:
    out_dir: Path


@dataclass(frozen=True)
class GroundTruthGenerationRequest:
    audit_dir: Path
    out_dir: Path
    model: str = "deepseek-v4-flash"
    base_url: str = "https://api.deepseek.com/v1"
    api_key_env: str = "DEEPSEEK_API_KEY"


@dataclass(frozen=True)
class GroundTruthReviewRequest:
    campaign_dir: Path
    model: str = "deepseek-v4-flash"
    base_url: str = "https://api.deepseek.com/v1"
    api_key_env: str = "DEEPSEEK_API_KEY"


@dataclass(frozen=True)
class GroundTruthRunRequest:
    campaign_dir: Path
    attempts: int = 3
    jobs: int = 4

    def __post_init__(self) -> None:
        if self.attempts != 3:
            raise ValidationError("ground-truth replay requires exactly three paired attempts")
        if self.jobs < 1:
            raise ValidationError("jobs must be positive")


@dataclass(frozen=True)
class GroundTruthAudit:
    audit_id: str
    root: Path
    reports: tuple[Mapping[str, Any], ...]
    counts: Mapping[str, int]


@dataclass(frozen=True)
class GroundTruthCampaignDefinition:
    campaign_id: str
    root: Path
    cases: tuple[Mapping[str, Any], ...]
    accounting: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class GroundTruthReview:
    campaign_id: str
    approved: int
    rejected: int
    artifact_dir: Path


@dataclass(frozen=True)
class GroundTruthCampaignRun:
    campaign_id: str
    support_counts: Mapping[str, int]
    outcome_counts: Mapping[str, int]
    report_results: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    artifact_dir: Path | None = None
