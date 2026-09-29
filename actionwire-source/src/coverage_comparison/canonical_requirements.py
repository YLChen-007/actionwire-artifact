"""Canonical CR v7 requirements, candidate identities, and risk routing."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import CoverageComparisonError, canonical_json, digest


CANONICAL_REQUIREMENT_SCHEMA_VERSION = "canonical-requirement/v7"
CANONICAL_CANDIDATE_SCHEMA_VERSION = "coverage-candidate/v7"
IDENTITY_MIGRATION_SCHEMA_VERSION = "coverage-identity-migration/v7"
ROUTER_SCHEMA_VERSION = "coverage-canonical-router/v7"

SOURCE_KINDS = {
    "group-oracle",
    "capability-card",
    "source-derived",
    "learned-invariant",
}
HIGH_RISK_CAPABILITIES = {
    "process-exec",
    "process-spawn",
    "file-write",
    "file-delete",
    "file-mutation",
    "network-navigation",
    "browser-navigation",
    "messaging",
    "approval-persistence",
    "permission-delegation",
    "subagent-delegation",
}
ROUTER_WEIGHTS = {
    "origin-changed": 100,
    "no-primary-candidate": 80,
    "learned-routed": 60,
    "semantic-ir-partial": 40,
    "group-oracle-partial": 30,
    "high-risk-capability": 20,
}


def normalize_identity_text(value: object, fallback: str) -> str:
    if isinstance(value, str) and value.strip():
        return " ".join(value.split())
    return fallback


def legacy_source_kind(requirement_id: str, row: Mapping[str, Any]) -> str:
    explicit = row.get("requirement_source")
    if explicit == "source-discovery":
        return "source-derived"
    if explicit in SOURCE_KINDS:
        return str(explicit)
    if requirement_id.startswith("CAPR-"):
        return "capability-card"
    if requirement_id.startswith("SR-"):
        return "source-derived"
    if requirement_id.startswith("LIR-"):
        return "learned-invariant"
    return "group-oracle"


def canonical_fields(
    row: Mapping[str, Any], *, source_kind: str
) -> dict[str, str]:
    rule = normalize_identity_text(
        row.get("rule", row.get("guard_rule", row.get("requirement_rule"))),
        "Require the concrete controlled sink capability to remain within its security boundary.",
    )
    applicability = normalize_identity_text(
        row.get("applicability", row.get("requirement_applicability")),
        "When the concrete model-controlled call can exercise this capability.",
    )
    dimension = normalize_identity_text(row.get("dimension"), "security-policy")
    controlled_facet = normalize_identity_text(
        row.get("controlled_facet", row.get("capability_facet")),
        f"model-controlled {dimension}",
    )
    enforcement_stage = normalize_identity_text(
        row.get("enforcement_stage"), "pre-effect"
    )
    state_lifetime = normalize_identity_text(row.get("state_lifetime"), "single-call")
    policy_basis = normalize_identity_text(row.get("policy_basis"), source_kind)
    protected_asset = normalize_identity_text(
        row.get("protected_asset", row.get("protected_asset_hypothesis")),
        f"project asset governed by {dimension}",
    )
    security_effect = normalize_identity_text(
        row.get("security_effect", row.get("risk_if_unguarded")), rule
    )
    return {
        "rule": rule,
        "applicability": applicability,
        "controlled_facet": controlled_facet,
        "enforcement_stage": enforcement_stage,
        "state_lifetime": state_lifetime,
        "policy_basis": policy_basis,
        "protected_asset": protected_asset,
        "security_effect": security_effect,
    }


def stable_cr_id(*, group_id: str, fields: Mapping[str, str]) -> str:
    identity = [
        CANONICAL_REQUIREMENT_SCHEMA_VERSION,
        group_id,
        fields["rule"],
        fields["applicability"],
        fields["controlled_facet"],
        fields["enforcement_stage"],
        fields["state_lifetime"],
        fields["security_effect"],
    ]
    return "CR-" + digest(identity)[:16]


def _evidence(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = row.get(
        "source_evidence",
        row.get("discovery_source_evidence", row.get("capability_evidence", [])),
    )
    return [dict(item) for item in raw] if isinstance(raw, list) else []


def canonicalize_requirement(
    row: Mapping[str, Any], *, group_id: str
) -> dict[str, Any]:
    old_id = str(row["requirement_id"])
    source_kind = legacy_source_kind(old_id, row)
    fields = canonical_fields(row, source_kind=source_kind)
    cr_id = stable_cr_id(group_id=group_id, fields=fields)
    source = {
        "legacy_requirement_id": old_id,
        "kind": source_kind,
        "payload_sha256": digest(dict(row)),
    }
    return {
        "schema_version": CANONICAL_REQUIREMENT_SCHEMA_VERSION,
        "requirement_id": cr_id,
        "group_id": group_id,
        **fields,
        "provenance": {"sources": [source]},
        "evidence": _evidence(row),
        "legacy_refines_requirement_ids": sorted(
            set(
                str(value)
                for value in row.get(
                    "refines_requirement_ids", row.get("overlap_requirement_ids", [])
                )
            )
        ),
        "refines_cr_ids": [],
    }


def merge_canonical_requirements(
    rows: Sequence[Mapping[str, Any]],
    *,
    allow_legacy_conflicts: bool = False,
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], str]]:
    by_id: dict[str, dict[str, Any]] = {}
    legacy_to_cr: dict[tuple[str, str], str] = {}
    for raw in rows:
        row = dict(raw)
        cr_id = str(row["requirement_id"])
        old_ids = [
            str(source["legacy_requirement_id"])
            for source in row["provenance"]["sources"]
        ]
        for old_id in old_ids:
            legacy_key = (str(row["group_id"]), old_id)
            prior = legacy_to_cr.setdefault(legacy_key, cr_id)
            if prior != cr_id and not allow_legacy_conflicts:
                raise CoverageComparisonError(
                    f"legacy requirement {old_id} maps to conflicting CR identities"
                )
        prior = by_id.get(cr_id)
        if prior is None:
            by_id[cr_id] = row
            continue
        for field in (
            "group_id",
            "rule",
            "applicability",
            "controlled_facet",
            "enforcement_stage",
            "state_lifetime",
            "security_effect",
        ):
            if prior[field] != row[field]:
                raise CoverageComparisonError(f"CR collision on {cr_id}:{field}")
        sources = {
            (item["legacy_requirement_id"], item["kind"], item["payload_sha256"]): item
            for item in [*prior["provenance"]["sources"], *row["provenance"]["sources"]]
        }
        prior["provenance"]["sources"] = [sources[key] for key in sorted(sources)]
        evidence = {canonical_json(item): item for item in [*prior["evidence"], *row["evidence"]]}
        prior["evidence"] = [evidence[key] for key in sorted(evidence)]
        prior["legacy_refines_requirement_ids"] = sorted(
            set(prior["legacy_refines_requirement_ids"])
            | set(row["legacy_refines_requirement_ids"])
        )
    for row in by_id.values():
        row["refines_cr_ids"] = sorted(
            {
                legacy_to_cr[(str(row["group_id"]), legacy)]
                for legacy in row.pop("legacy_refines_requirement_ids")
                if (str(row["group_id"]), legacy) in legacy_to_cr
                and legacy_to_cr[(str(row["group_id"]), legacy)]
                != row["requirement_id"]
            }
        )
    return sorted(by_id.values(), key=lambda item: item["requirement_id"]), legacy_to_cr


def stable_v7_candidate_id(
    *,
    group_id: str,
    project: str,
    revision: str,
    chain_id: str,
    requirement_id: str,
    failure_mode: str,
    gate_ids: Sequence[str],
) -> str:
    if not requirement_id.startswith("CR-"):
        raise CoverageComparisonError("v7 candidate requires a CR identity")
    return "CAND-" + digest(
        [
            CANONICAL_CANDIDATE_SCHEMA_VERSION,
            group_id,
            project,
            revision,
            chain_id,
            requirement_id,
            failure_mode,
            sorted(gate_ids),
        ]
    )[:16]


_CANDIDATE_COMMON = {
    "group_id",
    "handler_criterion_id",
    "sink_type_id",
    "project",
    "revision",
    "chain_id",
    "handler_id",
    "sink_id",
    "failure_mode",
    "gate_ids",
    "gate_semantics",
    "reason",
    "trigger_goal",
    "group_oracle_status",
    "semantic_ir_status",
    "capability_card",
}


def migrate_candidate(
    candidate: Mapping[str, Any],
    *,
    requirement: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    old = dict(candidate)
    old_id = str(old["candidate_id"])
    cr_id = str(requirement["requirement_id"])
    new_id = stable_v7_candidate_id(
        group_id=str(old["group_id"]),
        project=str(old["project"]),
        revision=str(old["revision"]),
        chain_id=str(old["chain_id"]),
        requirement_id=cr_id,
        failure_mode=str(old["failure_mode"]),
        gate_ids=[str(value) for value in old["gate_ids"]],
    )
    source_context = {
        key: value
        for key, value in old.items()
        if key
        not in _CANDIDATE_COMMON
        | {
            "schema_version",
            "candidate_id",
            "requirement_id",
            "requirement_rule",
            "requirement_applicability",
            "requirement_source",
            "provenance",
        }
    }
    migrated = {
        "schema_version": CANONICAL_CANDIDATE_SCHEMA_VERSION,
        "candidate_id": new_id,
        **{key: old[key] for key in sorted(_CANDIDATE_COMMON)},
        "requirement_id": cr_id,
        "requirement_rule": requirement["rule"],
        "requirement_applicability": requirement["applicability"],
        "provenance": requirement["provenance"],
        "source_context": source_context,
    }
    migration = {
        "schema_version": IDENTITY_MIGRATION_SCHEMA_VERSION,
        "old_requirement_id": str(old["requirement_id"]),
        "new_requirement_id": cr_id,
        "old_candidate_id": old_id,
        "new_candidate_id": new_id,
        "old_payload_sha256": digest(old),
        "new_payload_sha256": digest(migrated),
        "disposition": "one-to-one",
    }
    return migrated, migration


@dataclass(frozen=True)
class RouterResult:
    selected: tuple[dict[str, Any], ...]
    excluded: tuple[dict[str, Any], ...]
    config: Mapping[str, Any]


def _high_risk(capability_class: str) -> bool:
    normalized = capability_class.lower().replace("_", "-")
    return normalized in HIGH_RISK_CAPABILITIES or any(
        token in normalized
        for token in ("process", "spawn", "write", "delete", "navigation", "message", "approval", "permission", "delegation")
    )


def route_canonical_source_chains(
    *,
    chains: Sequence[Any],
    origin_audit: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
    learned_chain_ids: set[tuple[str, str]],
    required_regression_chain_ids: set[tuple[str, str]] | None = None,
    budget: int = 64,
    scope: str = "routed",
) -> RouterResult:
    if budget < 1:
        raise CoverageComparisonError("canonical source budget must be positive")
    if scope not in {"routed", "all"}:
        raise CoverageComparisonError("canonical source scope must be routed or all")
    required_regression_chain_ids = required_regression_chain_ids or set()
    excluded_by_chain: set[tuple[str, str]] = {
        (str(row["project"]), str(row["chain_id"]))
        for row in origin_audit
        if row["origin_disposition"] == "excluded"
    }
    candidate_counts: dict[tuple[str, str], int] = defaultdict(int)
    for candidate in candidates:
        candidate_counts[(str(candidate["project"]), str(candidate["chain_id"]))] += 1
    ranked: list[dict[str, Any]] = []
    for chain in chains:
        key = chain.key
        reasons: list[dict[str, Any]] = []
        if key in excluded_by_chain:
            reasons.append(
                {"reason": "origin-changed", "score": ROUTER_WEIGHTS["origin-changed"]}
            )
        if candidate_counts[key] == 0:
            reasons.append(
                {
                    "reason": "no-primary-candidate",
                    "score": ROUTER_WEIGHTS["no-primary-candidate"],
                }
            )
        if key in learned_chain_ids:
            reasons.append(
                {"reason": "learned-routed", "score": ROUTER_WEIGHTS["learned-routed"]}
            )
        if chain.semantic_ir["status"] == "partial":
            reasons.append(
                {
                    "reason": "semantic-ir-partial",
                    "score": ROUTER_WEIGHTS["semantic-ir-partial"],
                }
            )
        if chain.oracle["status"] == "partial":
            reasons.append(
                {
                    "reason": "group-oracle-partial",
                    "score": ROUTER_WEIGHTS["group-oracle-partial"],
                }
            )
        capability_class = str(chain.semantic_ir["sink_constraint"].get("capability_class", ""))
        if _high_risk(capability_class):
            reasons.append(
                {
                    "reason": "high-risk-capability",
                    "score": ROUTER_WEIGHTS["high-risk-capability"],
                }
            )
        ranked.append(
            {
                "schema_version": ROUTER_SCHEMA_VERSION,
                "project": chain.project,
                "revision": chain.revision,
                "chain_id": chain.chain_id,
                "score": sum(item["score"] for item in reasons),
                "reasons": reasons,
                "capability_class": capability_class,
                "selected": False,
                "selection_reason": None,
            }
        )
    ranked.sort(key=lambda row: (-row["score"], row["project"], row["chain_id"]))
    if scope == "all":
        selected_ids = {(row["project"], row["chain_id"]) for row in ranked}
    else:
        by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in ranked:
            by_project[row["project"]].append(row)
        eligible_ids = {(row["project"], row["chain_id"]) for row in ranked}
        unknown_required = required_regression_chain_ids - eligible_ids
        if unknown_required:
            raise CoverageComparisonError(
                "canonical source regression set contains unknown chains"
            )
        selected_ids: set[tuple[str, str]] = set(required_regression_chain_ids)
        if len(selected_ids) > budget:
            raise CoverageComparisonError(
                "canonical source regression set exceeds source budget"
            )
        for row in ranked:
            if (row["project"], row["chain_id"]) in selected_ids:
                row["selection_reason"] = "frozen-training-regression"
        for project in sorted(by_project):
            current = sum(key[0] == project for key in selected_ids)
            for row in by_project[project]:
                if current >= 3 or len(selected_ids) >= budget:
                    break
                key = (project, row["chain_id"])
                if key in selected_ids:
                    continue
                selected_ids.add(key)
                row["selection_reason"] = "project-quota"
                current += 1
        for row in ranked:
            if len(selected_ids) >= budget:
                break
            key = (row["project"], row["chain_id"])
            if key not in selected_ids:
                selected_ids.add(key)
                row["selection_reason"] = "global-score"
    for row in ranked:
        key = (row["project"], row["chain_id"])
        if key in selected_ids:
            row["selected"] = True
            row["selection_reason"] = row["selection_reason"] or "all-scope"
    config = {
        "schema_version": ROUTER_SCHEMA_VERSION,
        "scope": scope,
        "budget": budget,
        "project_quota": 3,
        "weights": dict(ROUTER_WEIGHTS),
        "required_training_regression_chains": [
            {"project": project, "chain_id": chain_id}
            for project, chain_id in sorted(required_regression_chain_ids)
        ],
        "selected": len(selected_ids),
        "eligible": len(ranked),
    }
    return RouterResult(
        selected=tuple(row for row in ranked if row["selected"]),
        excluded=tuple(row for row in ranked if not row["selected"]),
        config=config,
    )
