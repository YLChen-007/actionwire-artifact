"""Strict contracts and stable identities for chain-to-oracle comparison."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import validate as validate_schema

from .versions import (
    ASSESSMENT_SCHEMA_VERSION as ASSESSMENT_SCHEMA_VERSION,
    CANDIDATE_SCHEMA_VERSION as CANDIDATE_SCHEMA_VERSION,
    CHALLENGE_SCHEMA_VERSION as CHALLENGE_SCHEMA_VERSION,
    CHAT_SCHEMA_VERSION as CHAT_SCHEMA_VERSION,
    COMPARISON_SCHEMA_VERSION as COMPARISON_SCHEMA_VERSION,
    EXCLUSION_SCHEMA_VERSION as EXCLUSION_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION as MANIFEST_SCHEMA_VERSION,
)

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"

HSG_RE = re.compile(r"^HSG-[0-9a-f]{16}$")
HC_RE = re.compile(r"^HC-[0-9a-f]{16}$")
ST_RE = re.compile(r"^ST-[0-9a-f]{16}$")
CHAIN_RE = re.compile(r"^C-[0-9a-f]{12}$")
GATE_RE = re.compile(r"^GU[0-9a-f]{20}$")
REQUIREMENT_RE = re.compile(r"^R-[0-9a-f]{16}$")
CAPABILITY_REQUIREMENT_RE = re.compile(r"^CAPR-[0-9a-f]{16}$")
SOURCE_REQUIREMENT_RE = re.compile(r"^SR-[0-9a-f]{16}$")
LEARNED_REQUIREMENT_RE = re.compile(r"^LIR-[0-9a-f]{16}$")
CANDIDATE_RE = re.compile(r"^CAND-[0-9a-f]{16}$")
CANONICAL_REQUIREMENT_RE = re.compile(r"^CR-[0-9a-f]{16}$")


class CoverageComparisonError(ValueError):
    """Raised when a coverage-comparison input or response violates its contract."""


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_text(value: object, field: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise CoverageComparisonError(f"{field} must be a non-empty string")
    return " ".join(value.split())


def parse_json_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1])
            if text.lstrip().startswith("json"):
                text = text.lstrip()[4:].lstrip("\r\n")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CoverageComparisonError(f"response is not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CoverageComparisonError("response root must be an object")
    return value


def stable_candidate_id(
    *,
    group_id: str,
    project: str,
    revision: str,
    chain_id: str,
    requirement_id: str,
    failure_mode: str,
    gate_ids: Sequence[str],
) -> str:
    if not HSG_RE.fullmatch(group_id) or not CHAIN_RE.fullmatch(chain_id):
        raise CoverageComparisonError("candidate identity contains an invalid group or chain")
    if not REQUIREMENT_RE.fullmatch(requirement_id):
        raise CoverageComparisonError("candidate identity contains an invalid requirement")
    if failure_mode not in {"wrong-check", "missing-check"}:
        raise CoverageComparisonError("candidate failure mode must be uncovered")
    gates = sorted(set(gate_ids))
    if len(gates) != len(gate_ids) or any(not GATE_RE.fullmatch(row) for row in gates):
        raise CoverageComparisonError("candidate identity contains invalid gate IDs")
    return "CAND-" + digest(
        [group_id, project, revision, chain_id, requirement_id, failure_mode, gates]
    )[:16]


def _string_list(
    value: object,
    field: str,
    *,
    allowed: set[str] | None = None,
    require_nonempty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise CoverageComparisonError(f"{field} must be an array of non-empty strings")
    normalized = [" ".join(item.split()) for item in value]
    if len(normalized) != len(set(normalized)):
        raise CoverageComparisonError(f"{field} contains duplicates")
    if require_nonempty and not normalized:
        raise CoverageComparisonError(f"{field} must not be empty")
    if allowed is not None and not set(normalized) <= allowed:
        raise CoverageComparisonError(f"{field} contains unknown identifiers")
    return sorted(normalized)


def _line_evidence(value: object, *, card_lines: Sequence[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CoverageComparisonError("capability_line_refs must be an array")
    output: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {"start_line", "end_line"}:
            raise CoverageComparisonError("capability line reference has unexpected fields")
        start = row["start_line"]
        end = row["end_line"]
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 1
            or end < start
            or end > len(card_lines)
        ):
            raise CoverageComparisonError("capability line reference is out of range")
        key = (start, end)
        if key in seen:
            raise CoverageComparisonError("duplicate capability line reference")
        seen.add(key)
        output.append(
            {
                "start_line": start,
                "end_line": end,
                "quote": "\n".join(card_lines[start - 1 : end]),
            }
        )
    return sorted(output, key=lambda row: (row["start_line"], row["end_line"]))


def validate_comparison_response(
    response: Mapping[str, Any],
    *,
    group_id: str,
    chain_id: str,
    requirements: Mapping[str, Mapping[str, Any]],
    allowed_gate_ids: set[str],
    card_lines: Sequence[str],
) -> tuple[list[str], list[dict[str, Any]]]:
    if set(response) != {"group_id", "chain_id", "applicable_defaults", "requirements"}:
        raise CoverageComparisonError("comparison response has unexpected fields")
    if response["group_id"] != group_id or response["chain_id"] != chain_id:
        raise CoverageComparisonError("comparison response identity mismatch")
    defaults = _string_list(response["applicable_defaults"], "applicable_defaults")
    rows = response["requirements"]
    if not isinstance(rows, list):
        raise CoverageComparisonError("requirements must be an array")
    expected_ids = set(requirements)
    seen: list[str] = []
    output: list[dict[str, Any]] = []
    expected_fields = {
        "requirement_id",
        "applicability",
        "decision",
        "capability_line_refs",
        "call_shape_facts",
        "gate_ids",
        "covered_semantics",
        "gap",
        "uncertainty",
    }
    for raw in rows:
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            actual_fields = set(raw) if isinstance(raw, dict) else set()
            raise CoverageComparisonError(
                "requirement decision fields mismatch; "
                f"missing={sorted(expected_fields - actual_fields)}, "
                f"extra={sorted(actual_fields - expected_fields)}; "
                f"required={sorted(expected_fields)}"
            )
        requirement_id = raw["requirement_id"]
        if requirement_id not in expected_ids:
            raise CoverageComparisonError(f"unknown requirement {requirement_id!r}")
        applicability = raw["applicability"]
        decision = raw["decision"]
        if applicability not in {"applicable", "not-applicable", "unknown"}:
            raise CoverageComparisonError("invalid applicability verdict")
        if decision not in {
            "covered", "wrong-check", "missing-check", "not-applicable", "unknown"
        }:
            raise CoverageComparisonError("invalid coverage decision")
        line_evidence = _line_evidence(raw["capability_line_refs"], card_lines=card_lines)
        facts = _string_list(raw["call_shape_facts"], "call_shape_facts")
        gates = _string_list(raw["gate_ids"], "gate_ids", allowed=allowed_gate_ids)
        covered = normalize_text(raw["covered_semantics"], "covered_semantics", nullable=True)
        gap = normalize_text(raw["gap"], "gap", nullable=True)
        uncertainty = normalize_text(raw["uncertainty"], "uncertainty", nullable=True)

        if applicability == "applicable":
            if decision not in {"covered", "wrong-check", "missing-check"}:
                raise CoverageComparisonError("applicable requirement has incompatible decision")
            if not line_evidence or not facts or uncertainty is not None:
                raise CoverageComparisonError(
                    "applicable requirement needs card evidence and call-shape facts"
                )
            if decision == "covered" and (not gates or covered is None or gap is not None):
                raise CoverageComparisonError(
                    "covered decision invariant failed; requires nonempty gate_ids, "
                    "non-null covered_semantics, and null gap; "
                    f"actual gate_count={len(gates)}, "
                    f"covered_semantics_is_null={covered is None}, gap_is_null={gap is None}"
                )
            if decision == "wrong-check" and (
                not gates or covered is None or gap is None
            ):
                raise CoverageComparisonError(
                    "wrong-check decision invariant failed; requires nonempty gate_ids, "
                    "non-null covered_semantics, and non-null gap; "
                    f"actual gate_count={len(gates)}, "
                    f"covered_semantics_is_null={covered is None}, gap_is_null={gap is None}"
                )
            if decision == "missing-check" and (
                gates or covered is not None or gap is None
            ):
                raise CoverageComparisonError(
                    "missing-check decision invariant failed; requires empty gate_ids, "
                    "null covered_semantics, and non-null gap; "
                    f"actual gate_count={len(gates)}, "
                    f"covered_semantics_is_null={covered is None}, gap_is_null={gap is None}"
                )
        elif applicability == "not-applicable":
            if (
                decision != "not-applicable"
                or not line_evidence
                or not facts
                or gates
                or covered is not None
                or gap is not None
                or uncertainty is not None
            ):
                raise CoverageComparisonError("not-applicable decision invariant failed")
        else:
            if (
                decision != "unknown"
                or gates
                or covered is not None
                or gap is not None
                or uncertainty is None
            ):
                raise CoverageComparisonError("unknown decision invariant failed")
        output.append(
            {
                "requirement_id": requirement_id,
                "applicability": applicability,
                "decision": decision,
                "capability_evidence": line_evidence,
                "call_shape_facts": facts,
                "gate_ids": gates,
                "covered_semantics": covered,
                "gap": gap,
                "uncertainty": uncertainty,
            }
        )
        seen.append(requirement_id)
    if len(seen) != len(set(seen)) or set(seen) != expected_ids:
        raise CoverageComparisonError("response must cover every requirement exactly once")
    return defaults, sorted(output, key=lambda row: row["requirement_id"])


def validate_artifacts(
    *,
    comparisons: Sequence[Mapping[str, Any]],
    assessments: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
    capability_proposals: Sequence[Mapping[str, Any]] = (),
    capability_assessments: Sequence[Mapping[str, Any]] = (),
    capability_candidates_canonical: bool = True,
    source_proposals: Sequence[Mapping[str, Any]] = (),
    source_assessments: Sequence[Mapping[str, Any]] = (),
    source_candidates_canonical: bool = True,
    learned_requirements: Sequence[Mapping[str, Any]] = (),
    learned_assessments: Sequence[Mapping[str, Any]] = (),
    learned_candidates_canonical: bool = True,
    challenges: Sequence[Mapping[str, Any]] = (),
    exclusions: Sequence[Mapping[str, Any]],
    expected_comparison_keys: set[tuple[str, str]],
    expected_exclusion_keys: set[tuple[str, str]],
    expected_requirement_keys: set[tuple[str, str, str]],
    internal_legacy: bool = False,
) -> None:
    schemas = {
        "comparison": "coverage-comparison-v7.schema.json",
        "assessment": "coverage-requirement-assessment-v7.schema.json",
        "candidate": "coverage-candidate-v7.schema.json",
        "challenge": "coverage-requirement-challenge-v7.schema.json",
        "exclusion": "coverage-comparison-exclusion-v7.schema.json",
        "capability_proposal": "coverage-capability-requirement-proposal-v7.schema.json",
        "capability_assessment": "coverage-capability-assessment-v7.schema.json",
        "source_proposal": "coverage-source-requirement-proposal-v7.schema.json",
        "source_assessment": "coverage-source-requirement-assessment-v7.schema.json",
        "learned_requirement": "coverage-learned-requirement-v7.schema.json",
        "learned_assessment": "coverage-learned-assessment-v7.schema.json",
    }
    loaded = {
        key: json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
        for key, name in schemas.items()
    }
    for row in comparisons:
        validate_schema(instance=row, schema=loaded["comparison"])
    if not internal_legacy:
        for row in assessments:
            validate_schema(instance=row, schema=loaded["assessment"])
        for row in candidates:
            validate_schema(instance=row, schema=loaded["candidate"])
    for row in capability_proposals:
        validate_schema(instance=row, schema=loaded["capability_proposal"])
    for row in capability_assessments:
        validate_schema(instance=row, schema=loaded["capability_assessment"])
    for row in source_proposals:
        validate_schema(instance=row, schema=loaded["source_proposal"])
    for row in source_assessments:
        validate_schema(instance=row, schema=loaded["source_assessment"])
    for row in learned_requirements:
        validate_schema(instance=row, schema=loaded["learned_requirement"])
    for row in learned_assessments:
        validate_schema(instance=row, schema=loaded["learned_assessment"])
    if not internal_legacy:
        for row in challenges:
            validate_schema(instance=row, schema=loaded["challenge"])
    for row in exclusions:
        validate_schema(instance=row, schema=loaded["exclusion"])

    comparison_keys = [(row["project"], row["chain_id"]) for row in comparisons]
    exclusion_keys = [(row["project"], row["chain_id"]) for row in exclusions]
    assessment_keys = [
        (row["project"], row["chain_id"], row["requirement_id"])
        for row in assessments
    ]
    if len(comparison_keys) != len(set(comparison_keys)) or set(comparison_keys) != expected_comparison_keys:
        raise CoverageComparisonError("comparisons do not exactly cover eligible chains")
    if len(exclusion_keys) != len(set(exclusion_keys)) or set(exclusion_keys) != expected_exclusion_keys:
        raise CoverageComparisonError("exclusions do not exactly cover upstream exclusions")
    if set(comparison_keys) & set(exclusion_keys):
        raise CoverageComparisonError("a chain is both compared and excluded")
    if len(assessment_keys) != len(set(assessment_keys)) or set(assessment_keys) != expected_requirement_keys:
        raise CoverageComparisonError("assessments do not exactly cover chain requirements")

    assessment_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in assessments
    }
    capability_assessment_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in capability_assessments
    }
    if len(capability_assessment_by_key) != len(capability_assessments):
        raise CoverageComparisonError("duplicate capability assessment keys")
    proposal_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in capability_proposals
    }
    if len(proposal_by_key) != len(capability_proposals) or set(
        capability_assessment_by_key
    ) != set(proposal_by_key):
        raise CoverageComparisonError(
            "capability proposals and assessments must be one-to-one"
        )
    source_assessment_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in source_assessments
    }
    source_proposal_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in source_proposals
    }
    if len(source_assessment_by_key) != len(source_assessments) or set(
        source_assessment_by_key
    ) != set(source_proposal_by_key):
        raise CoverageComparisonError(
            "canonical source proposals and assessments must be one-to-one"
        )
    learned_assessment_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in learned_assessments
    }
    learned_requirement_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in learned_requirements
    }
    if len(learned_assessment_by_key) != len(learned_assessments) or set(
        learned_assessment_by_key
    ) != set(learned_requirement_by_key):
        raise CoverageComparisonError(
            "learned requirements and assessments must be one-to-one"
        )
    candidate_ids: list[str] = []
    candidate_keys: set[tuple[str, str, str]] = set()
    for row in candidates:
        key = (row["project"], row["chain_id"], row["requirement_id"])
        assessment = (
            assessment_by_key.get(key)
            or capability_assessment_by_key.get(key)
            or source_assessment_by_key.get(key)
            or learned_assessment_by_key.get(key)
        )
        if assessment is None or assessment["decision"] != row["failure_mode"]:
            raise CoverageComparisonError("candidate does not correspond to an uncovered assessment")
        if not internal_legacy:
            if not CANONICAL_REQUIREMENT_RE.fullmatch(row["requirement_id"]):
                raise CoverageComparisonError("candidate does not use a CR identity")
            expected_id = "CAND-" + digest(
                [
                    "coverage-candidate/v7",
                    row["group_id"],
                    row["project"],
                    row["revision"],
                    row["chain_id"],
                    row["requirement_id"],
                    row["failure_mode"],
                    sorted(row["gate_ids"]),
                ]
            )[:16]
            if row["candidate_id"] != expected_id:
                raise CoverageComparisonError("candidate stable identity mismatch")
        candidate_ids.append(row["candidate_id"])
        candidate_keys.add(key)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise CoverageComparisonError("duplicate candidate IDs")
    expected_candidate_keys = {
        key for key, row in assessment_by_key.items()
        if row["decision"] in {"wrong-check", "missing-check"}
    }
    if internal_legacy and capability_candidates_canonical:
        expected_candidate_keys |= {
            key
            for key, row in capability_assessment_by_key.items()
            if row["decision"] in {"wrong-check", "missing-check"}
            and proposal_by_key[key]["disposition"]
            in {"novel", "group-overlap-conflict"}
        }
    if internal_legacy and source_candidates_canonical:
        expected_candidate_keys |= {
            key
            for key, row in source_assessment_by_key.items()
            if row["decision"] in {"wrong-check", "missing-check"}
        }
    if internal_legacy and learned_candidates_canonical:
        expected_candidate_keys |= {
            key
            for key, row in learned_assessment_by_key.items()
            if row["decision"] in {"wrong-check", "missing-check"}
        }
    if candidate_keys != expected_candidate_keys:
        raise CoverageComparisonError("candidates do not exactly cover uncovered assessments")
    challenge_keys = [
        (row["project"], row["chain_id"], row["requirement_id"])
        for row in challenges
    ]
    if len(challenge_keys) != len(set(challenge_keys)):
        raise CoverageComparisonError("duplicate requirement challenge identities")
