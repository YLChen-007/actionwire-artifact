"""Generic normative-evidence resolution for member applicability."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from src.group_oracle.evidence_authority import CAPABILITY_ONLY_EVIDENCE_KINDS

from .applicability_contract import validate_applicability_contract
from .contracts import CoverageComparisonError, canonical_json, digest
from .normative_evidence_inputs import (
    EVIDENCE_BASES,
    NORMATIVE_KINDS,
    validate_evidence_rows,
    validate_learned_catalog,
)


NORMATIVE_EVIDENCE_RESOLUTION_VERSION = "coverage-normative-evidence-resolution/v15"
RESOLUTION_FIELDS = {
    "schema_version",
    "resolution_id",
    "group_id",
    "requirement_id",
    "status",
    "authority_kinds",
    "normative_evidence_ids",
    "supplemental_evidence_ids",
    "allowed_validation_policy_bases",
    "applicability_contract",
    "upstream_status",
    "reason",
}


def _resolution(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": NORMATIVE_EVIDENCE_RESOLUTION_VERSION,
        "resolution_id": "NER-" + digest(payload)[:16],
        **payload,
    }


def _sorted_strings(raw: object, field: str) -> list[str]:
    if not isinstance(raw, list) or any(
        not isinstance(value, str) or not value for value in raw
    ):
        raise CoverageComparisonError(f"invalid normative resolution {field}")
    if raw != sorted(set(raw)):
        raise CoverageComparisonError(f"non-canonical normative resolution {field}")
    return list(raw)


def validate_normative_evidence_resolution(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a resolver record before member-level applicability uses it."""

    if not isinstance(raw, Mapping) or set(raw) != RESOLUTION_FIELDS:
        raise CoverageComparisonError("normative evidence resolution fields mismatch")
    if raw["schema_version"] != NORMATIVE_EVIDENCE_RESOLUTION_VERSION:
        raise CoverageComparisonError("unsupported normative evidence resolution")
    status = str(raw["status"])
    if status not in {"normative", "non-normative", "upstream-incomplete"}:
        raise CoverageComparisonError("invalid normative evidence status")
    authority_kinds = _sorted_strings(raw["authority_kinds"], "authority_kinds")
    evidence_ids = _sorted_strings(
        raw["normative_evidence_ids"], "normative_evidence_ids"
    )
    _sorted_strings(raw["supplemental_evidence_ids"], "supplemental_evidence_ids")
    bases = _sorted_strings(
        raw["allowed_validation_policy_bases"],
        "allowed_validation_policy_bases",
    )
    if not set(authority_kinds) <= NORMATIVE_KINDS:
        raise CoverageComparisonError("invalid normative authority kinds")
    expected_bases = sorted(
        {basis for kind in authority_kinds for basis in EVIDENCE_BASES[kind]}
    )
    if bases != expected_bases:
        raise CoverageComparisonError("normative validation bases contradict authority")
    contract = raw["applicability_contract"]
    if contract is not None:
        contract = validate_applicability_contract(contract)
    if status == "normative" and (
        not authority_kinds or not evidence_ids or contract is None
    ):
        raise CoverageComparisonError("normative resolution lacks exact authority")
    if status == "non-normative" and (authority_kinds or evidence_ids or bases):
        raise CoverageComparisonError("non-normative resolution claims authority")
    if raw["upstream_status"] not in {"complete", "partial", "unknown"}:
        raise CoverageComparisonError("invalid normative resolution upstream status")
    if (
        not str(raw["group_id"])
        or not str(raw["requirement_id"])
        or not str(raw["reason"]).strip()
    ):
        raise CoverageComparisonError("incomplete normative resolution identity")
    payload = {
        key: raw[key]
        for key in RESOLUTION_FIELDS
        if key not in {"schema_version", "resolution_id"}
    }
    payload["applicability_contract"] = contract
    if raw["resolution_id"] != "NER-" + digest(payload)[:16]:
        raise CoverageComparisonError("normative evidence resolution hash mismatch")
    return {
        "schema_version": NORMATIVE_EVIDENCE_RESOLUTION_VERSION,
        "resolution_id": raw["resolution_id"],
        **payload,
    }


def resolve_normative_evidence(
    *,
    group_id: str,
    requirement_id: str,
    evidence_ids: Sequence[str],
    evidence_rows: Sequence[Mapping[str, Any]],
    applicability_contract: Mapping[str, Any] | None,
    learned_requirement_ids: Sequence[str] = (),
    learned_catalog: Mapping[str, Any] | None = None,
    upstream_status: str = "complete",
) -> dict[str, Any]:
    """Resolve authority without consulting reports, GT rows, or member identity."""

    if upstream_status not in {"complete", "partial", "unknown"}:
        raise CoverageComparisonError("invalid normative-evidence upstream status")
    evidence = validate_evidence_rows(evidence_rows)
    cited = list(map(str, evidence_ids))
    learned_ids = list(map(str, learned_requirement_ids))
    if len(cited) != len(set(cited)) or len(learned_ids) != len(set(learned_ids)):
        raise CoverageComparisonError("duplicate normative evidence reference")
    missing = set(cited) - set(evidence)
    if missing:
        raise CoverageComparisonError(f"unknown normative evidence: {sorted(missing)}")
    learned = validate_learned_catalog(learned_catalog)
    if set(learned_ids) - set(learned):
        raise CoverageComparisonError("unknown learned invariant authority")
    contract = (
        validate_applicability_contract(applicability_contract)
        if applicability_contract is not None
        else None
    )
    for learned_id in learned_ids:
        learned_contract = validate_applicability_contract(
            learned[learned_id]["applicability_contract"]
        )
        if contract is not None and canonical_json(contract) != canonical_json(
            learned_contract
        ):
            raise CoverageComparisonError("learned applicability contract mismatch")
        contract = learned_contract
    normative_ids = sorted(
        row for row in cited if str(evidence[row]["kind"]) in NORMATIVE_KINDS
    )
    supplemental_ids = sorted(
        row
        for row in cited
        if str(evidence[row]["kind"]) in CAPABILITY_ONLY_EVIDENCE_KINDS
    )
    authority_kinds = sorted(
        {str(evidence[row]["kind"]) for row in normative_ids}
        | ({"learned-invariant"} if learned_ids else set())
    )
    bases = sorted(
        {basis for kind in authority_kinds for basis in EVIDENCE_BASES[kind]}
    )
    if not authority_kinds:
        status = "non-normative"
        reason = "ordinary capability facts cannot authorize a requirement"
    elif upstream_status != "complete" or contract is None:
        status = "upstream-incomplete"
        reason = "normative inputs or applicability contract are incomplete"
    else:
        status = "normative"
        reason = "exact versioned normative authority resolves the requirement"
    return _resolution(
        {
            "group_id": group_id,
            "requirement_id": requirement_id,
            "status": status,
            "authority_kinds": authority_kinds,
            "normative_evidence_ids": normative_ids + sorted(learned_ids),
            "supplemental_evidence_ids": supplemental_ids,
            "allowed_validation_policy_bases": bases,
            "applicability_contract": contract,
            "upstream_status": upstream_status,
            "reason": reason,
        }
    )
