"""Bounded final consistency review of gate-derived conditional policy clusters."""

from __future__ import annotations

import json

from src.gate_semantics.contracts import estimate_tokens

from .contracts import GroupOracleError, validate_component_response
from .evidence_authority import evidence_authority_payload, normative_evidence_ids
from .prompts import POLICY_CONSOLIDATION_SYSTEM, redact_credentials


def consolidate_policies(*, group, chains, clusters, proposals, evidence,
                         runner, validated_call, record_chat, token_limit):
    accepted = [row for row in clusters if row["decision"] == "add"]
    if not accepted:
        return clusters
    ids = {pid for row in accepted for pid in row["proposal_ids"]}
    payload = {
        "group_id": group["handler_sink_group_id"],
        "subject_proposal_ids": sorted(ids),
        "policy_clusters": accepted,
        "source_proposals": [proposals[pid] for pid in sorted(ids)],
        "member_semantic_ir": [row.semantic_ir for row in chains],
        "applicable_pinned_evidence": evidence,
        "evidence_authority": evidence_authority_payload(evidence),
    }
    user = redact_credentials(json.dumps(payload, ensure_ascii=False, indent=2))
    if estimate_tokens({"system": POLICY_CONSOLIDATION_SYSTEM, "user": user}) > token_limit:
        raise GroupOracleError("complete group policy-consolidation prompt exceeds token limit")
    revised, exchanges = validated_call(
        runner=runner, system=POLICY_CONSOLIDATION_SYSTEM, user=user,
        validator=lambda response: validate_component_response(
            response, expected_proposal_ids=ids,
            allowed_evidence_ids={row["evidence_id"] for row in evidence},
            normative_evidence_ids=normative_evidence_ids(evidence),
        ),
        context=f"{group['handler_sink_group_id']}: policy consolidation",
    )
    record_chat("policy", group["handler_sink_group_id"], exchanges)
    return [row for row in clusters if row["decision"] != "add"] + revised
