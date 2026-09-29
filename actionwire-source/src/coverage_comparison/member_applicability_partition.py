"""Exhaustive partition and deterministic JSONL for member applicability."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import CoverageComparisonError, canonical_json, digest
from .member_applicability import (
    DECISIONS,
    MEMBER_APPLICABILITY_VERSION,
    evaluate_member_applicability,
)
from .member_applicability_facts import (
    member_binding_identity,
    validate_member_facts,
)


@dataclass(frozen=True)
class MemberApplicabilityRun:
    assessments: tuple[dict[str, Any], ...]


def _index(
    rows: Sequence[Mapping[str, Any]], label: str
) -> dict[tuple[str, ...], Mapping[str, Any]]:
    output: dict[tuple[str, ...], Mapping[str, Any]] = {}
    for row in rows:
        key = member_binding_identity(row)
        if key in output:
            raise CoverageComparisonError(f"duplicate {label} binding: {key}")
        output[key] = row
    return output


def validate_member_applicability_partition(
    rows: Sequence[Mapping[str, Any]], expected_bindings: Sequence[Mapping[str, Any]]
) -> None:
    expected = _index(expected_bindings, "expected")
    actual = _index(rows, "member applicability")
    if set(actual) != set(expected):
        raise CoverageComparisonError(
            "member applicability does not exhaustively partition bindings"
        )
    for row in rows:
        if (
            row.get("schema_version") != MEMBER_APPLICABILITY_VERSION
            or row.get("decision") not in DECISIONS
        ):
            raise CoverageComparisonError("invalid member applicability assessment")
        payload = {
            key: value
            for key, value in row.items()
            if key not in {"schema_version", "assessment_id"}
        }
        if row.get("assessment_id") != "MAP-" + digest(payload)[:16]:
            raise CoverageComparisonError(
                "member applicability assessment hash mismatch"
            )


def derive_member_applicability_partition(
    *,
    resolutions: Sequence[Mapping[str, Any]],
    member_facts: Sequence[Mapping[str, Any]],
    expected_bindings: Sequence[Mapping[str, Any]],
) -> MemberApplicabilityRun:
    resolution_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for row in resolutions:
        key = (str(row["group_id"]), str(row["requirement_id"]))
        if key in resolution_by_key:
            raise CoverageComparisonError(f"duplicate normative resolution: {key}")
        resolution_by_key[key] = row
    expected = _index(expected_bindings, "expected")
    facts = _index([validate_member_facts(row) for row in member_facts], "member facts")
    if set(facts) != set(expected):
        raise CoverageComparisonError(
            "member facts do not exactly cover expected bindings"
        )
    if set(resolution_by_key) != {(key[0], key[1]) for key in expected}:
        raise CoverageComparisonError(
            "normative resolutions do not exactly cover requirements"
        )
    rows = tuple(
        evaluate_member_applicability(
            resolution=resolution_by_key[(key[0], key[1])],
            member_facts=facts[key],
        )
        for key in sorted(expected)
    )
    validate_member_applicability_partition(rows, expected_bindings)
    return MemberApplicabilityRun(assessments=rows)


def serialize_member_applicability_jsonl(rows: Sequence[Mapping[str, Any]]) -> str:
    """Serialize assessments deterministically, including an empty partition."""

    ordered = sorted(rows, key=member_binding_identity)
    return "".join(canonical_json(dict(row)) + "\n" for row in ordered)
