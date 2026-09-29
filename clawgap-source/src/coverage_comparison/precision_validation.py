"""Packet-first source validation used by the precision publication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from .contracts import CoverageComparisonError
from .inputs import CoverageChain
from .source_validation import validate_source_response
from .source_validation_packets import (
    PACKET_REPAIR_SYSTEM,
    PACKET_VALIDATION_SYSTEM,
    build_packet_repair_user,
    build_packet_validation_user,
    build_source_validation_packet,
    normalize_packet_validation_payload,
    parse_packet_validation_response,
)


PRECISION_PACKET_PROMPT_VERSION = "source-validation-packet-precision/v10"
PRECISION_PACKET_SYSTEM = PACKET_VALIDATION_SYSTEM + """

Precision-v10 boundary rules:
- A tool's broad functional description does not by itself authorize a model to cross an
  ambient host boundary. Loopback/private/link-local/metadata services, agent credentials,
  procfs credential aliases, and an explicitly configured workspace remain protected unless
  the supplied source explicitly opts into that access.
- An approval or allowlist implementation establishes a policy boundary. Confirm a bypass only
  when the same effective command/value reaches the sink outside that decision; do not demand
  mandatory approval when the documented policy deliberately authorizes allowlisted commands.
- A fixed root/suffix, constant sink role, trusted registry lookup, or sanitizing transform can
  make a generic capability requirement not applicable even when taint reaches the sink.
- Confirm the narrow effective invariant only. Refute generic logging, encoding, timeout,
  content-censorship, or blocklist advice without a concrete protected asset and source-backed
  boundary.
- A dedicated prose statement of impact is not required. The exact sink/effect line and the
  handler return or propagation line may be cited again with role=impact when they prove the
  concrete read, write, request, execution, disclosure, or approval-bypass effect. Do not return
  needs-deep merely because the project source does not contain the English word "impact".
Return one validation for every supplied candidate; mixed verdicts are expected.
"""
PRECISION_REPAIR_SYSTEM = PACKET_REPAIR_SYSTEM + """
For precision-v10, preserve mixed verdicts and return one validation per candidate. If a
confirmed-uncovered row cannot cite handler, controlled-value, sink, policy, and impact roles
or cannot prove a non-capability-only basis, downgrade only that row. If the whole packet is
insufficient, return decision=needs-deep with validations=[] exactly.
The same exact source line may be cited under sink and impact roles when the operation itself
proves the concrete security effect; a separate impact comment is not required.
"""


@dataclass(frozen=True)
class PrecisionPacketResult:
    validations: tuple[dict[str, Any], ...]
    packet: dict[str, Any]
    chat: dict[str, Any]


def _contract_diagnostics(payload: Mapping[str, Any]) -> str:
    details: list[str] = []
    for row in payload.get("validations", []):
        if not isinstance(row, Mapping) or row.get("verdict") != "confirmed-uncovered":
            continue
        roles = {
            str(value.get("role"))
            for value in row.get("source_evidence", [])
            if isinstance(value, Mapping)
        }
        missing = sorted(
            {"handler", "controlled-value", "sink", "policy", "impact"} - roles
        )
        problems = []
        if missing:
            problems.append("missing_roles=" + ",".join(missing))
        if row.get("policy_basis") in {"capability-only", "none", "unknown"}:
            problems.append("unsupported_policy_basis")
        if row.get("controlled_flow") != "confirmed":
            problems.append("controlled_flow_not_confirmed")
        if row.get("sink_reachability") != "confirmed":
            problems.append("sink_reachability_not_confirmed")
        if row.get("gate_coverage") != "uncovered":
            problems.append("gate_coverage_not_uncovered")
        if row.get("impact") != "concrete":
            problems.append("impact_not_concrete")
        if row.get("impact_severity") == "unknown":
            problems.append("impact_severity_unknown")
        if row.get("source_research_complete") is not True:
            problems.append("research_incomplete")
        if row.get("security_effect") is None:
            problems.append("security_effect_missing")
        if row.get("uncertainties"):
            problems.append("uncertainties_nonempty")
        if row.get("covering_gate_ids"):
            problems.append("confirmed_row_has_covering_gates")
        if problems:
            details.append(
                f"{row.get('provisional_candidate_id')}:" + ",".join(problems)
            )
    return "; ".join(details) or "response violates the source-validation contract"


def validate_precision_packet(
    *,
    chain: CoverageChain,
    candidates: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    spec: ProjectSpec,
    origin_witnesses: Sequence[Mapping[str, Any]],
    runner: Any,
) -> PrecisionPacketResult:
    """Validate a same-chain batch without requiring every verdict to confirm."""

    packet = build_source_validation_packet(
        chain=chain,
        candidates=candidates,
        assessments=assessments,
        requirements=requirements,
        spec=spec,
        same_origin_witnesses=origin_witnesses,
    )
    user = build_packet_validation_user(packet)
    raw = runner(PRECISION_PACKET_SYSTEM, user)
    exchanges = [{"system": PRECISION_PACKET_SYSTEM, "user": user, "response": raw}]
    repaired_once = False
    try:
        decision, payload, reason = parse_packet_validation_response(raw, packet=packet)
    except Exception as first:
        repair_user = build_packet_repair_user(
            packet=packet,
            invalid_response=raw,
            error=f"{type(first).__name__}: {first}",
        )
        repaired = runner(PRECISION_REPAIR_SYSTEM, repair_user)
        exchanges.append(
            {
                "system": PRECISION_REPAIR_SYSTEM,
                "user": repair_user,
                "response": repaired,
            }
        )
        decision, payload, reason = parse_packet_validation_response(
            repaired, packet=packet
        )
        raw = repaired
        repaired_once = True
    if decision != "complete" or payload is None:
        raise CoverageComparisonError(
            f"{chain.project}:{chain.chain_id}: precision packet needs deep: {reason}"
        )
    payload, normalizations = normalize_packet_validation_payload(payload, packet=packet)
    try:
        records = validate_source_response(
            payload,
            chain=chain,
            candidates=candidates,
            assessments=assessments,
            source_root=spec.resolved().source_root,
            validation_input_sha256=packet["packet_digest"],
            prompt_version=PRECISION_PACKET_PROMPT_VERSION,
        )
    except Exception as first:
        if repaired_once:
            raise CoverageComparisonError(
                f"{chain.project}:{chain.chain_id}: repaired packet violates source contract"
            ) from first
        diagnostics = _contract_diagnostics(payload)
        repair_user = build_packet_repair_user(
            packet=packet,
            invalid_response=raw,
            error=f"{type(first).__name__}: {first}; {diagnostics}",
        )
        repaired = runner(PRECISION_REPAIR_SYSTEM, repair_user)
        exchanges.append(
            {
                "system": PRECISION_REPAIR_SYSTEM,
                "user": repair_user,
                "response": repaired,
            }
        )
        decision, repair_payload, reason = parse_packet_validation_response(
            repaired, packet=packet
        )
        if decision != "complete" or repair_payload is None:
            raise CoverageComparisonError(
                f"{chain.project}:{chain.chain_id}: precision packet repair needs deep: {reason}"
            ) from first
        repair_payload, repair_changes = normalize_packet_validation_payload(
            repair_payload, packet=packet
        )
        normalizations.extend(repair_changes)
        records = validate_source_response(
            repair_payload,
            chain=chain,
            candidates=candidates,
            assessments=assessments,
            source_root=spec.resolved().source_root,
            validation_input_sha256=packet["packet_digest"],
            prompt_version=PRECISION_PACKET_PROMPT_VERSION,
        )
    subject = f"{chain.project}-{chain.chain_id}-precision-v10"
    return PrecisionPacketResult(
        validations=tuple(records),
        packet=packet,
        chat={
            "schema_version": "source-validation-packet-chat/v10",
            "stage": "source-validate-precision",
            "subject": subject,
            "decision": decision,
            "reason": reason,
            "normalizations": normalizations,
            "exchanges": exchanges,
        },
    )
