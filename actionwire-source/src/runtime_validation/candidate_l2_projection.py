"""Deterministic ground-truth projection for candidate L2 campaigns."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


ELIGIBLE = "eligible"
NON_APPLICABLE = "non-applicable"
CANDIDATE_MISSING = "candidate-missing"
CANDIDATE_LINKED = "candidate-linked"
LINKED_UNSUPPORTED = "linked-unsupported"


def identify_ground_truth(
    ground_truth: Mapping[str, Any], candidate_ids: set[str]
) -> dict[str, Any]:
    """Bind one GT row to the selected cohort without assigning a verdict."""

    historical = [str(item) for item in ground_truth.get("matched_candidate_ids") or []]
    matched = [item for item in historical if item in candidate_ids]
    missing = [item for item in historical if item not in candidate_ids]
    eligible = ground_truth.get("boundary_status") == ELIGIBLE
    if not eligible:
        disposition = NON_APPLICABLE
        reason = "boundary row is not candidate identifiable"
    elif matched:
        disposition = CANDIDATE_LINKED
        reason = "at least one selected candidate matches"
    else:
        disposition = CANDIDATE_MISSING
        reason = "eligible report has no candidate in the selected cohort"
    return {
        "report_id": str(ground_truth["report_id"]),
        "project": str(ground_truth["project"]),
        "boundary_status": str(ground_truth["boundary_status"]),
        "identified": eligible and bool(matched),
        "disposition": disposition,
        "matched_candidate_ids": matched,
        "candidate_ids_missing_from_cohort": missing,
        "reason": reason,
    }


def project_ground_truth(
    identification: Mapping[str, Any],
    result_by_candidate: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate candidate verdicts with one explicit confirmed-wins policy."""

    matched = [str(item) for item in identification["matched_candidate_ids"]]
    linked = [result_by_candidate[item] for item in matched if item in result_by_candidate]
    dispositions = {str(row.get("disposition")) for row in linked}
    if identification["boundary_status"] != ELIGIBLE:
        disposition = NON_APPLICABLE
    elif not matched:
        disposition = CANDIDATE_MISSING
    elif "runtime-confirmed" in dispositions:
        disposition = "runtime-confirmed"
    elif dispositions and dispositions <= {"not-reproduced"}:
        disposition = "not-reproduced"
    elif dispositions & {"inconclusive", "planning-blocked", "environment-blocked"}:
        disposition = "inconclusive"
    else:
        disposition = LINKED_UNSUPPORTED
    return {
        "schema_version": "clawgap-auto-l2-gt-projection/v2",
        **dict(identification),
        "disposition": disposition,
        "candidate_dispositions": {
            item: (
                result_by_candidate[item].get("disposition")
                if item in result_by_candidate
                else "not-selected"
            )
            for item in matched
        },
        "runtime_confirmed": disposition == "runtime-confirmed",
        "aggregation_policy": "confirmed-wins; healthy-not-reproduced-only",
    }


def project_all_ground_truth(
    identifications: Sequence[Mapping[str, Any]],
    results: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Project all report rows from one candidate result partition."""

    by_candidate = {str(row["candidate_id"]): row for row in results}
    return [project_ground_truth(row, by_candidate) for row in identifications]
