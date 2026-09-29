"""Validation of external normative-evidence authority inputs."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from src.group_oracle.evidence_authority import (
    CAPABILITY_ONLY_EVIDENCE_KINDS,
    NORMATIVE_EVIDENCE_KINDS as GROUP_NORMATIVE_EVIDENCE_KINDS,
)

from .applicability_contract import validate_applicability_contract
from .contracts import CoverageComparisonError


EVIDENCE_BASES = {
    "explicit-source-policy": {"explicit-source-policy"},
    "fixed-delta": {"fixed-delta"},
    "standard": {"explicit-source-policy"},
    "documentation": {"explicit-source-policy"},
    "learned-invariant": {"learned-security-invariant"},
    "capability-policy": {"explicit-source-policy"},
}
NORMATIVE_KINDS = GROUP_NORMATIVE_EVIDENCE_KINDS | {
    "explicit-source-policy",
    "learned-invariant",
}
SOURCE_EVIDENCE_KINDS = NORMATIVE_KINDS - {"learned-invariant"}
VERSION_RE = re.compile(r"^[a-z0-9][a-z0-9-]*/v[1-9][0-9]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def validate_evidence_rows(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    output: dict[str, Mapping[str, Any]] = {}
    allowed = NORMATIVE_KINDS | CAPABILITY_ONLY_EVIDENCE_KINDS
    for row in rows:
        evidence_id = str(row.get("evidence_id", ""))
        kind = str(row.get("kind", ""))
        if not evidence_id or kind not in allowed:
            raise CoverageComparisonError("invalid normative evidence row")
        if evidence_id in output:
            raise CoverageComparisonError(
                f"duplicate normative evidence: {evidence_id}"
            )
        if kind in SOURCE_EVIDENCE_KINDS | CAPABILITY_ONLY_EVIDENCE_KINDS:
            for field in ("source_path", "exact_quote", "supported_claim"):
                if not str(row.get(field, "")).strip():
                    raise CoverageComparisonError(
                        f"evidence {evidence_id} lacks {field}"
                    )
            if not SHA256_RE.fullmatch(str(row.get("sha256", ""))):
                raise CoverageComparisonError(
                    f"evidence {evidence_id} has invalid digest"
                )
        if kind == "capability-policy" and not VERSION_RE.fullmatch(
            str(row.get("policy_contract_schema_version", ""))
        ):
            raise CoverageComparisonError("capability-policy evidence is not versioned")
        output[evidence_id] = row
    return output


def validate_learned_catalog(
    catalog: Mapping[str, Any] | None,
) -> dict[str, Mapping[str, Any]]:
    if catalog is None:
        return {}
    if not VERSION_RE.fullmatch(str(catalog.get("schema_version", ""))):
        raise CoverageComparisonError("learned catalog lacks a schema version")
    patterns = catalog.get("patterns")
    if not isinstance(patterns, list):
        raise CoverageComparisonError("learned catalog patterns are invalid")
    output: dict[str, Mapping[str, Any]] = {}
    for pattern in patterns:
        if not isinstance(pattern, Mapping):
            raise CoverageComparisonError("invalid learned catalog pattern")
        requirement_id = str(pattern.get("requirement_id", ""))
        if not requirement_id.startswith("LIR-") or requirement_id in output:
            raise CoverageComparisonError("invalid learned requirement identity")
        contract = pattern.get("applicability_contract")
        if not isinstance(contract, Mapping):
            raise CoverageComparisonError(
                "learned invariant lacks applicability contract"
            )
        validate_applicability_contract(contract)
        output[requirement_id] = pattern
    return output
