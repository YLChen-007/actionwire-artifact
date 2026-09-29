"""v13 packet validation with strict refutation citation repair."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from .contracts import (
    CoverageComparisonError,
    canonical_json,
    parse_json_response,
)
from .inputs import CoverageChain
from .precision_validation import (
    PRECISION_PACKET_SYSTEM,
    PRECISION_REPAIR_SYSTEM,
    _contract_diagnostics,
)
from .source_validation import validate_source_response
from .source_validation_packets import (
    build_packet_repair_user,
    build_packet_validation_user,
    build_source_validation_packet,
    normalize_packet_validation_payload,
    parse_packet_validation_response,
)


V13_PROMPT_VERSION = "source-validation-packet-precision/v13"
V13_SYSTEM = PRECISION_PACKET_SYSTEM + """
For every not-applicable row, cite at least the exact sink line and either the handler or
controlled-value line. A fixed argument, absent sink role, or trusted receiver shown in the
packet is sufficient to refute applicability; do not return needs-deep merely because the
candidate's hypothesized capability is absent. Mixed confirmed/refuted verdicts are expected.
"""
V13_REPAIR_SYSTEM = PRECISION_REPAIR_SYSTEM + """
Repair not-applicable rows by citing the supplied sink plus handler or controlled-value spans.
When the packet proves a fixed argument or absent role, preserve not-applicable instead of
returning needs-deep. Never invent evidence outside source_spans.
"""
V13_RESPONSE_FIELDS = {
    "provisional_candidate_id",
    "verdict",
    "final_decision",
    "covering_gate_ids",
    "policy_basis",
    "controlled_flow",
    "sink_reachability",
    "gate_coverage",
    "impact",
    "impact_severity",
    "source_research_complete",
    "source_evidence",
    "preconditions",
    "security_effect",
    "uncertainties",
    "reason",
}


@dataclass(frozen=True)
class V13PacketResult:
    validations: tuple[dict[str, Any], ...]
    packet: dict[str, Any]
    chat: dict[str, Any]


def _parse_v13_response(
    raw: str, *, packet: Mapping[str, Any]
) -> tuple[str, dict[str, Any] | None, str]:
    try:
        return parse_packet_validation_response(raw, packet=packet)
    except CoverageComparisonError as first:
        value = parse_json_response(raw)
        validations = value.get("validations")
        if not isinstance(validations, list):
            raise first
        value["decision"] = "complete" if validations else "needs-deep"
        return parse_packet_validation_response(canonical_json(value), packet=packet)


def _normalize_policy_basis(
    payload: dict[str, Any], changes: list[str]
) -> None:
    allowed = {
        "explicit-source-policy",
        "fixed-delta",
        "inherent-security-boundary",
        "learned-security-invariant",
        "capability-only",
        "none",
        "unknown",
    }
    for row in payload.get("validations", []):
        basis = row.get("policy_basis")
        if basis in allowed:
            continue
        candidate_id = str(row.get("provisional_candidate_id"))
        roles = {
            evidence.get("role")
            for evidence in row.get("source_evidence", [])
            if isinstance(evidence, Mapping)
        }
        if row.get("verdict") == "confirmed-uncovered" and "policy" in roles:
            row["policy_basis"] = "explicit-source-policy"
            changes.append(f"{candidate_id}:normalized-policy-provenance")
            continue
        row["policy_basis"] = "none"
        changes.append(f"{candidate_id}:cleared-invalid-policy-basis")


def _strip_transport_fields(payload: dict[str, Any], changes: list[str]) -> None:
    for row in payload.get("validations", []):
        if not isinstance(row, dict):
            continue
        extras = sorted(set(row) - V13_RESPONSE_FIELDS)
        for field in extras:
            row.pop(field)
        if extras:
            changes.append(
                f"{row.get('provisional_candidate_id')}:stripped-fields="
                + ",".join(extras)
            )


def _fill_refutation_defaults(payload: dict[str, Any], changes: list[str]) -> None:
    defaults_by_verdict = {
        "not-applicable": {
            "final_decision": "not-applicable",
            "covering_gate_ids": [],
            "policy_basis": "none",
            "controlled_flow": "unknown",
            "sink_reachability": "confirmed",
            "gate_coverage": "unknown",
            "impact": "none",
            "impact_severity": "low",
            "source_research_complete": False,
            "preconditions": [],
            "security_effect": None,
            "uncertainties": [],
        },
        "unknown": {
            "final_decision": "unknown",
            "covering_gate_ids": [],
            "policy_basis": "unknown",
            "controlled_flow": "unknown",
            "sink_reachability": "unknown",
            "gate_coverage": "unknown",
            "impact": "unknown",
            "impact_severity": "unknown",
            "source_research_complete": False,
            "preconditions": [],
            "security_effect": None,
            "uncertainties": ["packet response omitted uncertainty details"],
        },
    }
    for row in payload.get("validations", []):
        if not isinstance(row, dict):
            continue
        defaults = defaults_by_verdict.get(str(row.get("verdict")))
        if defaults is None:
            continue
        added = []
        for field, value in defaults.items():
            if field in row:
                continue
            row[field] = value
            added.append(field)
        if added:
            changes.append(
                f"{row.get('provisional_candidate_id')}:filled-refutation-fields="
                + ",".join(sorted(added))
            )


def validate_v13_packet(
    *,
    chain: CoverageChain,
    candidates: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    spec: ProjectSpec,
    origin_witnesses: Sequence[Mapping[str, Any]],
    runner: Any,
) -> V13PacketResult:
    packet = build_source_validation_packet(
        chain=chain,
        candidates=candidates,
        assessments=assessments,
        requirements=requirements,
        spec=spec,
        same_origin_witnesses=origin_witnesses,
    )
    user = build_packet_validation_user(packet)
    raw = runner(V13_SYSTEM, user)
    exchanges = [{"system": V13_SYSTEM, "user": user, "response": raw}]
    repaired_once = False
    try:
        decision, payload, reason = _parse_v13_response(raw, packet=packet)
    except Exception as first:
        repair_user = build_packet_repair_user(
            packet=packet,
            invalid_response=raw,
            error=f"{type(first).__name__}: {first}",
        )
        repaired = runner(V13_REPAIR_SYSTEM, repair_user)
        exchanges.append(
            {"system": V13_REPAIR_SYSTEM, "user": repair_user, "response": repaired}
        )
        decision, payload, reason = _parse_v13_response(
            repaired, packet=packet
        )
        raw = repaired
        repaired_once = True
    if decision != "complete" or payload is None:
        repair_user = build_packet_repair_user(
            packet=packet,
            invalid_response=raw,
            error=(
                "needs-deep is not justified when the cited handler/sink line lies inside "
                "a supplied inclusive source span; use those exact lines and return one "
                "validation per candidate. Original reason: "
                + reason
            ),
        )
        repaired = runner(V13_REPAIR_SYSTEM, repair_user)
        exchanges.append(
            {"system": V13_REPAIR_SYSTEM, "user": repair_user, "response": repaired}
        )
        decision, payload, reason = _parse_v13_response(
            repaired, packet=packet
        )
        raw = repaired
        repaired_once = True
        if decision != "complete" or payload is None:
            raise CoverageComparisonError(
                f"{chain.project}:{chain.chain_id}: v13 repair remains deep: {reason}"
            )
    payload, normalizations = normalize_packet_validation_payload(payload, packet=packet)
    _normalize_policy_basis(payload, normalizations)
    _strip_transport_fields(payload, normalizations)
    _fill_refutation_defaults(payload, normalizations)
    try:
        records = validate_source_response(
            payload,
            chain=chain,
            candidates=candidates,
            assessments=assessments,
            source_root=spec.resolved().source_root,
            validation_input_sha256=packet["packet_digest"],
            prompt_version=V13_PROMPT_VERSION,
        )
    except Exception as first:
        if repaired_once:
            raise CoverageComparisonError(
                f"{chain.project}:{chain.chain_id}: repaired v13 packet violates contract"
            ) from first
        repair_user = build_packet_repair_user(
            packet=packet,
            invalid_response=raw,
            error=(
                f"{type(first).__name__}: {first}; "
                + _contract_diagnostics(payload)
            ),
        )
        repaired = runner(V13_REPAIR_SYSTEM, repair_user)
        exchanges.append(
            {"system": V13_REPAIR_SYSTEM, "user": repair_user, "response": repaired}
        )
        decision, repair_payload, reason = _parse_v13_response(
            repaired, packet=packet
        )
        if decision != "complete" or repair_payload is None:
            raise CoverageComparisonError(
                f"{chain.project}:{chain.chain_id}: v13 repair needs deep: {reason}"
            ) from first
        repair_payload, changes = normalize_packet_validation_payload(
            repair_payload, packet=packet
        )
        normalizations.extend(changes)
        _normalize_policy_basis(repair_payload, normalizations)
        _strip_transport_fields(repair_payload, normalizations)
        _fill_refutation_defaults(repair_payload, normalizations)
        records = validate_source_response(
            repair_payload,
            chain=chain,
            candidates=candidates,
            assessments=assessments,
            source_root=spec.resolved().source_root,
            validation_input_sha256=packet["packet_digest"],
            prompt_version=V13_PROMPT_VERSION,
        )
    subject = f"{chain.project}-{chain.chain_id}-precision-v13"
    return V13PacketResult(
        validations=tuple(records),
        packet=packet,
        chat={
            "schema_version": "source-validation-packet-chat/v13",
            "stage": "source-validate-v13",
            "subject": subject,
            "decision": decision,
            "reason": reason,
            "normalizations": normalizations,
            "exchanges": exchanges,
        },
    )
