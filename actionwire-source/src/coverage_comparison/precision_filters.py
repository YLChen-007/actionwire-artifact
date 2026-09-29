"""Deterministic precision filters for canonical coverage candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import CoverageComparisonError


PRECISION_FILTER_VERSION = "coverage-precision-filter/v10"
DIRECT_ENCODING_FACETS = {
    "model-controlled encoding",
    "model-controlled encoding-control",
    "model-controlled content-encoding",
}


@dataclass(frozen=True)
class PrecisionFilterRun:
    canonical_candidates: tuple[dict[str, Any], ...]
    dispositions: tuple[dict[str, Any], ...]


def _normalized(value: object) -> str:
    return " ".join(str(value or "").lower().split())


def _validation_by_candidate(
    validations: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    output: dict[str, Mapping[str, Any]] = {}
    for row in validations:
        candidate_id = str(row["provisional_candidate_id"])
        if candidate_id in output:
            raise CoverageComparisonError("duplicate precision validation identity")
        output[candidate_id] = row
    return output


def _comparison_control_signal(comparison: Mapping[str, Any]) -> str:
    source_parameters = [
        str(row.get("source_parameter", ""))
        for row in comparison.get("values", [])
        if isinstance(row, Mapping)
    ]
    return _normalized(
        " ".join(
            [
                str(comparison.get("controlled_argument", "")),
                *source_parameters,
            ]
        )
    )


def _duplicate_key(
    candidate: Mapping[str, Any], requirement: Mapping[str, Any]
) -> tuple[object, ...]:
    return (
        candidate["group_id"],
        candidate["project"],
        candidate["revision"],
        candidate["chain_id"],
        candidate["failure_mode"],
        tuple(sorted(str(value) for value in candidate.get("gate_ids", []))),
        _normalized(requirement["rule"]),
        _normalized(requirement["applicability"]),
        _normalized(requirement["security_effect"]),
        _normalized(requirement["enforcement_stage"]),
        _normalized(requirement["state_lifetime"]),
    )


def _candidate_priority(
    candidate: Mapping[str, Any],
    requirement: Mapping[str, Any],
    validation: Mapping[str, Any] | None,
) -> tuple[object, ...]:
    kinds = {str(row["kind"]) for row in candidate["provenance"]["sources"]}
    source_rank = min(
        (
            rank
            for kind, rank in {
                "learned-invariant": 0,
                "source-derived": 1,
                "capability-card": 2,
                "group-oracle": 3,
            }.items()
            if kind in kinds
        ),
        default=4,
    )
    return (
        0 if validation and validation.get("verdict") == "confirmed-uncovered" else 1,
        0 if requirement.get("evidence") else 1,
        source_rank,
        str(candidate["candidate_id"]),
    )


def _duplicate_winners(
    candidates: Sequence[Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    validations: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    grouped: dict[tuple[object, ...], list[Mapping[str, Any]]] = {}
    for candidate in candidates:
        requirement = requirements[str(candidate["requirement_id"])]
        grouped.setdefault(_duplicate_key(candidate, requirement), []).append(candidate)
    replacements: dict[str, str] = {}
    for rows in grouped.values():
        if len(rows) < 2:
            continue
        winner = min(
            rows,
            key=lambda row: _candidate_priority(
                row,
                requirements[str(row["requirement_id"])],
                validations.get(str(row["candidate_id"])),
            ),
        )
        for row in rows:
            if row["candidate_id"] != winner["candidate_id"]:
                replacements[str(row["candidate_id"])] = str(winner["candidate_id"])
    return replacements


def _validation_precision_failure(
    validation: Mapping[str, Any] | None,
) -> tuple[str, str] | None:
    if validation is None or validation.get("verdict") != "confirmed-uncovered":
        return None
    reason = _normalized(validation.get("reason"))
    effect = _normalized(validation.get("security_effect"))
    browser_compromise = "browser" in reason + " " + effect and "compromise" in reason + " " + effect
    indirect_markers = (
        "page-context js alone cannot",
        "actual secret exfiltration additionally requires",
        "exploitation of the exposed data requires",
        "to any compromise",
    )
    if browser_compromise and any(marker in reason + " " + effect for marker in indirect_markers):
        return (
            "impact-not-model-reachable",
            "claimed effect requires an independent browser compromise",
        )
    if "clause of the requirement is not independently source-supported" in reason:
        return (
            "requirement-overbroad",
            "source verdict admits an unsupported conjunctive rule clause",
        )
    return None


def filter_precision_candidates(
    *,
    candidates: Sequence[Mapping[str, Any]],
    requirements: Sequence[Mapping[str, Any]],
    comparisons: Sequence[Mapping[str, Any]],
    validations: Sequence[Mapping[str, Any]],
) -> PrecisionFilterRun:
    """Classify every candidate and promote only source-confirmed survivors."""

    requirement_by_id = {str(row["requirement_id"]): row for row in requirements}
    comparison_by_key = {
        (str(row["project"]), str(row["chain_id"])): row for row in comparisons
    }
    validation_by_id = _validation_by_candidate(validations)
    if any(str(row["requirement_id"]) not in requirement_by_id for row in candidates):
        raise CoverageComparisonError("precision candidate references unknown requirement")
    replacements = _duplicate_winners(
        candidates, requirement_by_id, validation_by_id
    )
    canonical: list[dict[str, Any]] = []
    dispositions: list[dict[str, Any]] = []
    for raw in sorted(candidates, key=lambda row: str(row["candidate_id"])):
        candidate = dict(raw)
        candidate_id = str(candidate["candidate_id"])
        requirement = requirement_by_id[str(candidate["requirement_id"])]
        comparison = comparison_by_key[(str(candidate["project"]), str(candidate["chain_id"]))]
        validation = validation_by_id.get(candidate_id)
        validation_failure = _validation_precision_failure(validation)
        replacement = replacements.get(candidate_id)
        applicability = _normalized(requirement["applicability"])
        facet = _normalized(requirement["controlled_facet"])
        control_signal = _comparison_control_signal(comparison)
        if replacement is not None:
            disposition, reason = "duplicate", "same effective invariant and gates"
        elif applicability.startswith("recommended"):
            disposition, reason = "recommendation-only", "non-normative applicability"
        elif facet in DIRECT_ENCODING_FACETS and not any(
            token in control_signal for token in ("encoding", "errors")
        ):
            disposition, reason = (
                "facet-not-controlled",
                "encoding/errors sink role is not handler-controlled",
            )
        elif validation is None:
            disposition, reason = (
                "needs-source-validation",
                "no content-bound source verdict",
            )
        elif validation["verdict"] != "confirmed-uncovered":
            disposition, reason = (
                "source-rejected",
                f"source verdict is {validation['verdict']}",
            )
        elif validation_failure is not None:
            disposition, reason = validation_failure
        else:
            disposition, reason = "confirmed", "source-confirmed uncovered invariant"
            canonical.append(candidate)
        dispositions.append(
            {
                "schema_version": PRECISION_FILTER_VERSION,
                "candidate_id": candidate_id,
                "project": candidate["project"],
                "chain_id": candidate["chain_id"],
                "requirement_id": candidate["requirement_id"],
                "disposition": disposition,
                "reason": reason,
                "replacement_candidate_id": replacement,
                "validation_id": validation.get("validation_id") if validation else None,
            }
        )
    return PrecisionFilterRun(
        canonical_candidates=tuple(canonical),
        dispositions=tuple(dispositions),
    )
