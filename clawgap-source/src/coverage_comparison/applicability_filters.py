"""Structured applicability and subsumption filters for deferred Group CRs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import CoverageComparisonError


APPLICABILITY_FILTER_VERSION = "coverage-applicability-filter/v12"
DIRECT_ROLE_FACETS = {
    "model-controlled content": ("content", "body", "message", "data", "text", "code"),
    "model-controlled content-control": ("content", "body", "message", "data", "text", "code"),
    "model-controlled content-validation": ("content", "body", "message", "data", "text", "code"),
    "model-controlled environment": ("env", "environment"),
    "model-controlled environment-control": ("env", "environment"),
    "model-controlled cwd": ("cwd", "workdir", "working_dir"),
    "model-controlled working-directory": ("cwd", "workdir", "working_dir"),
}
GENERIC_POLICY_RE = re.compile(
    r"distinguishable error|error messages.*filesystem|"
    r"content.*(?:executable|interpretable|sensitive data patterns)|"
    r"shell-flag must be disabled|known secret-token prefix|"
    r"shell-command guard must block access to internal|"
    r"output.*sanitiz|captured output.*untrusted",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ApplicabilityFilterRun:
    dispositions: tuple[dict[str, Any], ...]


def _normalized(value: object) -> str:
    return " ".join(str(value or "").lower().split())


def _control_signal(comparison: Mapping[str, Any]) -> str:
    return _normalized(
        " ".join(
            [
                str(comparison.get("controlled_argument", "")),
                *[
                    str(row.get("source_parameter", ""))
                    for row in comparison.get("values", [])
                    if isinstance(row, Mapping)
                ],
            ]
        )
    )


def _missing_role(
    requirement: Mapping[str, Any], comparison: Mapping[str, Any]
) -> str | None:
    facet = _normalized(requirement.get("controlled_facet"))
    tokens = DIRECT_ROLE_FACETS.get(facet)
    if tokens is None:
        return None
    signal = _control_signal(comparison)
    if any(token in signal for token in tokens):
        return None
    return facet.removeprefix("model-controlled ")


def _has_normative_evidence(requirement: Mapping[str, Any]) -> bool:
    if requirement.get("evidence"):
        return True
    asset = _normalized(requirement.get("protected_asset"))
    return not asset.startswith("project asset governed by")


def _generic_policy_without_boundary(requirement: Mapping[str, Any]) -> bool:
    if _has_normative_evidence(requirement):
        return False
    if requirement.get("policy_basis") != "group-oracle":
        return False
    return bool(
        GENERIC_POLICY_RE.search(
            str(requirement.get("rule", ""))
            + " "
            + str(requirement.get("applicability", ""))
        )
    )


def _subsumption_family(requirement: Mapping[str, Any]) -> str | None:
    rule = _normalized(requirement.get("rule"))
    operation = "read" if "read" in rule else "write" if "writ" in rule else None
    if operation is None or "symlink" not in rule:
        return None
    if not any(token in rule for token in ("outside", "escape", "allowed", "resolve")):
        return None
    return operation + "-symlink-escape"


def _subsumption_score(requirement: Mapping[str, Any]) -> tuple[int, int, str]:
    rule = _normalized(requirement.get("rule"))
    concepts = sum(
        token in rule
        for token in (
            "resolved",
            "absolute",
            "allowed directory",
            "traversal",
            "symlink",
            "escape",
        )
    )
    return concepts, len(rule), str(requirement["requirement_id"])


def _subsumed_candidates(
    candidates: Sequence[Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    active_ids: set[str],
) -> dict[str, str]:
    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for candidate in candidates:
        candidate_id = str(candidate["candidate_id"])
        if candidate_id not in active_ids:
            continue
        requirement = requirements[str(candidate["requirement_id"])]
        family = _subsumption_family(requirement)
        if family is None:
            continue
        key = (str(candidate["project"]), str(candidate["chain_id"]), family)
        grouped.setdefault(key, []).append(candidate)
    replacements: dict[str, str] = {}
    for rows in grouped.values():
        if len(rows) < 2:
            continue
        winner = max(
            rows,
            key=lambda row: _subsumption_score(
                requirements[str(row["requirement_id"])]
            ),
        )
        for row in rows:
            if row["candidate_id"] != winner["candidate_id"]:
                replacements[str(row["candidate_id"])] = str(winner["candidate_id"])
    return replacements


def apply_applicability_filters(
    *,
    candidates: Sequence[Mapping[str, Any]],
    requirements: Sequence[Mapping[str, Any]],
    comparisons: Sequence[Mapping[str, Any]],
    prior_dispositions: Sequence[Mapping[str, Any]],
) -> ApplicabilityFilterRun:
    """Refine only deferred candidates; preserve every prior audit row."""

    requirement_by_id = {str(row["requirement_id"]): row for row in requirements}
    comparison_by_key = {
        (str(row["project"]), str(row["chain_id"])): row for row in comparisons
    }
    candidate_by_id = {str(row["candidate_id"]): row for row in candidates}
    if len(candidate_by_id) != len(candidates):
        raise CoverageComparisonError("duplicate v12 applicability candidate")
    deferred = {
        str(row["candidate_id"])
        for row in prior_dispositions
        if row["disposition"] == "needs-source-validation"
    }
    preliminary: dict[str, tuple[str, str]] = {}
    for candidate_id in sorted(deferred):
        candidate = candidate_by_id[candidate_id]
        requirement = requirement_by_id[str(candidate["requirement_id"])]
        comparison = comparison_by_key[(str(candidate["project"]), str(candidate["chain_id"]))]
        missing_role = _missing_role(requirement, comparison)
        if missing_role is not None:
            preliminary[candidate_id] = (
                "role-not-controlled",
                f"handler input does not control the required {missing_role} sink role",
            )
            continue
        if _generic_policy_without_boundary(requirement):
            preliminary[candidate_id] = (
                "policy-evidence-missing",
                "generic hardening rule has no concrete source-backed boundary",
            )
    still_deferred = deferred - set(preliminary)
    replacements = _subsumed_candidates(
        candidates, requirement_by_id, still_deferred
    )
    output: list[dict[str, Any]] = []
    for raw in prior_dispositions:
        row = dict(raw)
        candidate_id = str(row["candidate_id"])
        transition = preliminary.get(candidate_id)
        if transition is not None:
            row.update(
                {
                    "schema_version": APPLICABILITY_FILTER_VERSION,
                    "prior_disposition": row["disposition"],
                    "disposition": transition[0],
                    "reason": transition[1],
                }
            )
        elif candidate_id in replacements:
            row.update(
                {
                    "schema_version": APPLICABILITY_FILTER_VERSION,
                    "prior_disposition": row["disposition"],
                    "disposition": "subsumed",
                    "reason": "a stronger same-chain CR covers this security family",
                    "replacement_candidate_id": replacements[candidate_id],
                }
            )
        output.append(row)
    return ApplicabilityFilterRun(dispositions=tuple(output))
