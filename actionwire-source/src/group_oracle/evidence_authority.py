"""Evidence-authority policy for committing group requirements."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


EVIDENCE_KINDS = frozenset(
    {
        "capability-card",
        "capability-policy",
        "documentation",
        "standard",
        "fixed-delta",
    }
)
CAPABILITY_ONLY_EVIDENCE_KINDS = frozenset({"capability-card"})
NORMATIVE_EVIDENCE_KINDS = EVIDENCE_KINDS - CAPABILITY_ONLY_EVIDENCE_KINDS
MANUAL_EVIDENCE_KINDS = NORMATIVE_EVIDENCE_KINDS - {"capability-policy"}


def is_normative_evidence(row: Mapping[str, Any]) -> bool:
    """Return whether an evidence row can authorize a normative requirement."""

    return row.get("kind") in NORMATIVE_EVIDENCE_KINDS


def normative_evidence_ids(
    rows: Sequence[Mapping[str, Any]],
) -> set[str]:
    """Return IDs whose evidence kind has normative authority."""

    return {
        row["evidence_id"]
        for row in rows
        if is_normative_evidence(row)
    }


def has_normative_support(
    evidence_ids: Sequence[str] | set[str],
    evidence_by_id: Mapping[str, Mapping[str, Any]],
) -> bool:
    """Return whether cited evidence includes at least one normative authority."""

    return any(
        evidence_id in evidence_by_id
        and is_normative_evidence(evidence_by_id[evidence_id])
        for evidence_id in evidence_ids
    )


def evidence_authority_payload(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, list[str] | str]:
    """Describe evidence authority explicitly in model-facing payloads."""

    normative = normative_evidence_ids(rows)
    capability_only = {
        row["evidence_id"]
        for row in rows
        if row.get("kind") in CAPABILITY_ONLY_EVIDENCE_KINDS
    }
    return {
        "schema_version": "group-oracle-evidence-authority/v1",
        "normative_evidence_ids": sorted(normative),
        "capability_only_evidence_ids": sorted(capability_only),
    }
