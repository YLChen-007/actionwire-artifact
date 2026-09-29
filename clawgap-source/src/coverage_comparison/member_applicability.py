"""Member-level applicability evaluation."""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import CoverageComparisonError, digest
from .member_applicability_facts import BINDING_FIELDS, validate_member_facts
from .normative_evidence import validate_normative_evidence_resolution


MEMBER_APPLICABILITY_VERSION = "coverage-member-applicability/v15"
DECISIONS = {"applicable", "not-applicable", "unknown", "upstream-incomplete"}


def _set_check(
    required: set[str], observed: set[str], completeness: str
) -> tuple[str, str]:
    missing = sorted(required - observed)
    if not missing:
        return "match", "all required values are witnessed"
    if completeness == "complete":
        return "mismatch", "missing required values: " + ",".join(missing)
    return "unknown", "member evidence is incomplete for: " + ",".join(missing)


def evaluate_member_applicability(
    *, resolution: Mapping[str, Any], member_facts: Mapping[str, Any]
) -> dict[str, Any]:
    """Derive exactly one fail-closed applicability decision for one member."""

    facts = validate_member_facts(member_facts)
    resolved = validate_normative_evidence_resolution(resolution)
    if (resolved["group_id"], resolved["requirement_id"]) != (
        facts["group_id"],
        facts["requirement_id"],
    ):
        raise CoverageComparisonError("normative resolution/member identity mismatch")
    contract = resolved["applicability_contract"]
    if resolved["status"] != "normative" or facts["upstream_status"] != "complete":
        decision, reason, checks = (
            "upstream-incomplete",
            "normative authority or member evidence is upstream-incomplete",
            {},
        )
    elif not isinstance(contract, Mapping):
        decision, reason, checks = (
            "upstream-incomplete",
            "missing applicability contract",
            {},
        )
    else:
        required_roles = set(contract["required_sink_roles"])
        witnessed_roles = {row["sink_role"] for row in facts["field_witnesses"]}
        allowed_authorities = set(contract["allowed_value_authorities"])
        authority_roles = {
            row["sink_role"]
            for row in facts["field_witnesses"]
            if row["value_authority"] in allowed_authorities
        }
        checks = {
            "sink_roles": _set_check(
                required_roles,
                witnessed_roles,
                facts["completeness"]["sink_roles"],
            ),
            "value_authorities": _set_check(
                required_roles,
                authority_roles,
                facts["completeness"]["value_authorities"],
            ),
            "capability_facets": _set_check(
                set(contract["required_capability_facets"]),
                set(facts["capability_facets"]),
                facts["completeness"]["capability_facets"],
            ),
            "boundary": _set_check(
                {str(contract["required_boundary"])},
                set(facts["boundaries"]),
                facts["completeness"]["boundary"],
            ),
            "effect": _set_check(
                {str(contract["required_effect"])},
                set(facts["effects"]),
                facts["completeness"]["effect"],
            ),
            "call_shape_predicates": _set_check(
                set(contract["call_shape_predicates"]),
                set(facts["call_shape_predicates"]),
                facts["completeness"]["call_shape_predicates"],
            ),
        }
        states = {value[0] for value in checks.values()}
        if "mismatch" in states:
            decision, reason = (
                "not-applicable",
                "one or more required dimensions are absent",
            )
        elif "unknown" in states:
            decision, reason = (
                "unknown",
                "one or more required dimensions remain unknown",
            )
        else:
            decision, reason = "applicable", "all member applicability dimensions match"
    audit_checks = {
        key: {"status": value[0], "reason": value[1]}
        for key, value in sorted(checks.items())
    }
    payload = {
        **{field: facts[field] for field in BINDING_FIELDS},
        "resolution_id": resolved["resolution_id"],
        "authority_kinds": resolved["authority_kinds"],
        "normative_evidence_ids": resolved["normative_evidence_ids"],
        "decision": decision,
        "applicability_contract": dict(contract)
        if isinstance(contract, Mapping)
        else None,
        "field_witnesses": facts["field_witnesses"],
        "checks": audit_checks,
        "reason": reason,
    }
    return {
        "schema_version": MEMBER_APPLICABILITY_VERSION,
        "assessment_id": "MAP-" + digest(payload)[:16],
        **payload,
    }
