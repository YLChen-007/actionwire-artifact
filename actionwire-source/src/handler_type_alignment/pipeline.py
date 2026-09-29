"""Order-independent NanoBot-anchored intent-family alignment."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from src.projects import ProjectSpec

from .capability_observations import (
    build_type_capability_observations,
    load_handler_capabilities,
)
from .contracts import (
    CATALOG_SCHEMA_VERSION,
    CRITERION_SUPPORT_SCHEMA_VERSION,
    MAPPING_SCHEMA_VERSION,
    ORACLE_INHERITANCE_SCHEMA_VERSION,
    SINGLETON_AUDIT_SCHEMA_VERSION,
    AlignmentContractError,
    canonical_json,
    criterion_parent_key,
    merge_equivalent_criteria,
    parse_json_response,
    stable_criterion_id,
    stable_proposal_id,
    stable_type_id,
    validate_axis_conflict_response,
    validate_component_response,
    validate_final_artifacts,
    validate_profile_batch_response,
    validate_proposal_match_response,
    validate_reconciliation_response,
    validate_seed_response,
    validate_singleton_response,
)
from .inputs import HandlerProfile, load_profiles
from .prompts import (
    AXIS_CONFLICT_SYSTEM,
    CANONICALIZE_SYSTEM,
    COMPONENT_SYSTEM,
    PROPOSAL_MATCH_SYSTEM,
    RECONCILE_SYSTEM,
    REPAIR_SYSTEM,
    SEED_SYSTEM,
    SINGLETON_SYSTEM,
    build_canonicalize_user,
    build_axis_conflict_user,
    build_component_user,
    build_proposal_match_user,
    build_reconcile_user,
    build_repair_user,
    build_seed_user,
    build_singleton_user,
    likely_candidate_ids,
)
from .render import render_alignment_index


Runner = Callable[[str, str], str]
SEED_PROJECT = "nanobot"
SOURCE_BATCH_SIZE = 8


def _reset_generated_directory(path: Path) -> None:
    if path.exists() and not path.is_dir():
        raise AlignmentContractError(
            f"generated artifact root is not a directory: {path}"
        )
    if path.is_dir():
        shutil.rmtree(path)


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _write_json(path: Path, value: object) -> None:
    _atomic_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, values: Sequence[object]) -> None:
    _atomic_text(path, "".join(canonical_json(row) + "\n" for row in values))


def _validated_call(
    *,
    runner: Runner,
    system: str,
    user: str,
    validator: Callable[[dict[str, Any]], Any],
    context: str,
) -> tuple[Any, list[dict[str, str]]]:
    exchanges: list[dict[str, str]] = []
    raw = runner(system, user)
    exchanges.append({"system": system, "user": user, "response": raw})
    try:
        return validator(parse_json_response(raw)), exchanges
    except Exception as first:
        repair_user = build_repair_user(
            system,
            user,
            raw,
            f"{type(first).__name__}: {first}",
        )
        repaired = runner(REPAIR_SYSTEM, repair_user)
        exchanges.append(
            {"system": REPAIR_SYSTEM, "user": repair_user, "response": repaired}
        )
        try:
            return validator(parse_json_response(repaired)), exchanges
        except Exception as second:
            raise AlignmentContractError(
                f"{context}: unrepaired alignment response: "
                f"{type(second).__name__}: {second}"
            ) from second


def _member_key(profile: HandlerProfile) -> str:
    return f"{profile.project_id}:{profile.handler_id}"


def _family_criterion(profile: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: profile[key]
        for key in (
            "intent_family",
            "canonical_label",
            "operation_family",
            "resource_family",
            "effect",
            "compatibility_rule",
            "distinguishing_rule",
        )
    }


def _family_row(
    *,
    family_id: str,
    origin: str,
    criterion: Mapping[str, Any],
    members: Sequence[str],
    reason: str,
    evidence: Sequence[str],
) -> dict[str, Any]:
    sorted_members = sorted(set(members))
    if not sorted_members or len(sorted_members) != len(members):
        raise AlignmentContractError("family members must be non-empty and unique")
    return {
        "family_id": family_id,
        "origin": origin,
        "criterion": dict(criterion),
        "representative_handler": sorted_members[0],
        "members": sorted_members,
        "reason": reason,
        "evidence": list(evidence),
    }


def _build_seed_families(
    assignments: Sequence[dict[str, Any]], profiles_by_id: Mapping[str, HandlerProfile]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    type_by_handler: dict[str, str] = {}
    for assignment in assignments:
        handler_id = assignment["handler_id"]
        criterion = _family_criterion(assignment["profile"])
        handler_type_id = stable_type_id(criterion)
        by_type[handler_type_id].append(assignment)
        type_by_handler[handler_id] = handler_type_id
    families: list[dict[str, Any]] = []
    for handler_type_id in sorted(by_type):
        rows = sorted(by_type[handler_type_id], key=lambda row: row["handler_id"])
        members = [_member_key(profiles_by_id[row["handler_id"]]) for row in rows]
        families.append(
            _family_row(
                family_id=handler_type_id,
                origin="nanobot-seed",
                criterion=merge_equivalent_criteria(
                    [_family_criterion(row["profile"]) for row in rows]
                ),
                members=members,
                reason=rows[0]["reason"],
                evidence=rows[0]["evidence"],
            )
        )
    return families, type_by_handler


def _merge_family_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda row: row["family_id"])
    parent_ids = {
        stable_criterion_id(row["criterion"])
        for row in ordered
    }
    if len(parent_ids) != 1:
        raise AlignmentContractError("cannot merge leaves across parent criteria")
    members = sorted({member for row in ordered for member in row["members"]})
    anchors = [row for row in ordered if row["origin"] == "nanobot-seed"]
    if len(anchors) > 1:
        raise AlignmentContractError("cannot merge multiple frozen NanoBot anchors")
    if anchors:
        anchor = anchors[0]
        family_id = anchor["family_id"]
        origin = "nanobot-seed"
        criterion = anchor["criterion"]
    else:
        family_id = stable_proposal_id(members)
        origin = "external-global"
        criterion = merge_equivalent_criteria([row["criterion"] for row in ordered])
    return _family_row(
        family_id=family_id,
        origin=origin,
        criterion=criterion,
        members=members,
        reason=ordered[0]["reason"],
        evidence=ordered[0]["evidence"],
    )


def _merge_exact_intents(
    families: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for family in families:
        by_key[stable_type_id(family["criterion"])].append(family)
    merged = [_merge_family_rows(rows) for _key, rows in sorted(by_key.items())]
    return sorted(merged, key=lambda row: row["family_id"]), len(families) - len(merged)


def _connected_components(
    family_ids: Iterable[str], edges: Sequence[tuple[str, str]]
) -> list[list[str]]:
    adjacency = {family_id: set() for family_id in family_ids}
    for left, right in edges:
        if left not in adjacency or right not in adjacency:
            raise AlignmentContractError("proposed edge references unknown family")
        adjacency[left].add(right)
        adjacency[right].add(left)
    components: list[list[str]] = []
    seen: set[str] = set()
    for start in sorted(adjacency):
        if start in seen:
            continue
        pending = [start]
        component: list[str] = []
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            component.append(current)
            pending.extend(sorted(adjacency[current] - seen, reverse=True))
        components.append(sorted(component))
    return components


def _semantic_family_ids(
    families: Sequence[Mapping[str, Any]],
) -> list[str]:
    return [
        row["family_id"]
        for row in sorted(
            families,
            key=lambda row: (
                row["criterion"]["resource_family"],
                row["criterion"]["effect"],
                row["criterion"]["operation_family"],
                row["criterion"]["intent_family"],
                row["family_id"],
            ),
        )
    ]


def _adjudicated_family(
    group: Mapping[str, Any], families_by_id: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    sources = [families_by_id[source_id] for source_id in group["source_ids"]]
    parent_ids = {stable_criterion_id(source["criterion"]) for source in sources}
    if len(parent_ids) != 1:
        raise AlignmentContractError("adjudicated component spans parent criteria")
    members = sorted({member for source in sources for member in source["members"]})
    anchor_type_id = group["anchor_type_id"]
    if anchor_type_id is not None:
        anchor = families_by_id[anchor_type_id]
        return _family_row(
            family_id=anchor_type_id,
            origin="nanobot-seed",
            criterion=anchor["criterion"],
            members=members,
            reason=group["reason"],
            evidence=group["evidence"],
        )
    return _family_row(
        family_id=stable_proposal_id(members),
        origin="external-global",
        criterion=group["criterion"],
        members=members,
        reason=group["reason"],
        evidence=group["evidence"],
    )


def _adjudicate_edges(
    *,
    families: Sequence[dict[str, Any]],
    edges: Sequence[tuple[str, str]],
    stage: str,
    runner: Runner,
    profiles_by_id: Mapping[str, HandlerProfile],
    seed_type_ids: set[str],
    chats: dict[str, list[dict[str, str]]],
) -> tuple[list[dict[str, Any]], int]:
    families_by_id = {row["family_id"]: row for row in families}
    if len(families_by_id) != len(families):
        raise AlignmentContractError("family IDs collide before adjudication")
    output: list[dict[str, Any]] = []
    calls = 0
    for component in _connected_components(families_by_id, edges):
        if len(component) == 1:
            output.append(dict(families_by_id[component[0]]))
            continue
        calls += 1
        parent_ids = {
            stable_criterion_id(families_by_id[source_id]["criterion"])
            for source_id in component
        }
        if len(parent_ids) != 1:
            raise AlignmentContractError(
                "proposed match graph contains a cross-parent edge"
            )
        expected_parent = criterion_parent_key(
            families_by_id[component[0]]["criterion"]
        )
        groups, exchanges = _validated_call(
            runner=runner,
            system=COMPONENT_SYSTEM,
            user=build_component_user(component, families_by_id, profiles_by_id),
            validator=lambda response, ids=set(component): validate_component_response(
                response,
                expected_source_ids=ids,
                seed_type_ids=seed_type_ids,
                expected_parent_key=expected_parent,
            ),
            context=f"{stage}: component adjudication {calls}",
        )
        chats[f"adjudicate-{stage}-{calls:03d}"] = exchanges
        output.extend(_adjudicated_family(group, families_by_id) for group in groups)
    return sorted(output, key=lambda row: row["family_id"]), calls


def _attach_direct_matches(
    families: Sequence[dict[str, Any]],
    direct_matches: Mapping[str, dict[str, Any]],
    profiles_by_id: Mapping[str, HandlerProfile],
) -> list[dict[str, Any]]:
    by_id = {row["family_id"]: dict(row) for row in families}
    for handler_id, outcome in sorted(direct_matches.items()):
        anchor_id = outcome["handler_type_id"]
        if anchor_id not in by_id or by_id[anchor_id]["origin"] != "nanobot-seed":
            raise AlignmentContractError("direct match references missing frozen anchor")
        member = _member_key(profiles_by_id[handler_id])
        by_id[anchor_id]["members"] = sorted({*by_id[anchor_id]["members"], member})
        by_id[anchor_id]["representative_handler"] = by_id[anchor_id]["members"][0]
    return sorted(by_id.values(), key=lambda row: row["family_id"])


def _role_signatures(
    members: Sequence[str], profiles_by_handler: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    signatures: dict[tuple[tuple[str, ...], tuple[str, ...]], list[str]] = defaultdict(list)
    for member in members:
        handler_id = member.split(":", 1)[1]
        profile = profiles_by_handler[handler_id]
        key = (tuple(profile["core_roles"]), tuple(profile["optional_roles"]))
        signatures[key].append(member)
    return [
        {
            "core_roles": list(core_roles),
            "optional_roles": list(optional_roles),
            "members": sorted(signature_members),
        }
        for (core_roles, optional_roles), signature_members in sorted(signatures.items())
    ]


def _resolve_axis_conflicts(
    assignments: Sequence[dict[str, Any]],
    *,
    runner: Runner,
    profiles_by_id: Mapping[str, HandlerProfile],
    chats: dict[str, list[dict[str, str]]],
) -> tuple[list[dict[str, Any]], int]:
    by_intent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for assignment in assignments:
        by_intent[assignment["profile"]["intent_family"]].append(assignment)
    conflicts = {
        intent_family: rows
        for intent_family, rows in sorted(by_intent.items())
        if len(
            {
                canonical_json(criterion_parent_key(row["profile"]))
                for row in rows
            }
        )
        > 1
    }
    if not conflicts:
        return [dict(row) for row in assignments], 0
    allowed = {
        intent_family: [criterion_parent_key(row["profile"]) for row in rows]
        for intent_family, rows in conflicts.items()
    }
    resolutions, exchanges = _validated_call(
        runner=runner,
        system=AXIS_CONFLICT_SYSTEM,
        user=build_axis_conflict_user(conflicts, profiles_by_id),
        validator=lambda response: validate_axis_conflict_response(
            response, allowed_parent_keys=allowed
        ),
        context="normalized intent parent-axis conflict resolution",
    )
    chats["resolve-axis-conflicts"] = exchanges
    resolved_by_intent = {row["intent_family"]: row for row in resolutions}
    output: list[dict[str, Any]] = []
    for assignment in assignments:
        resolution = resolved_by_intent.get(assignment["profile"]["intent_family"])
        if resolution is None:
            output.append(dict(assignment))
            continue
        output.append(
            {
                **assignment,
                "profile": {
                    **assignment["profile"],
                    **criterion_parent_key(resolution),
                },
            }
        )
    remaining = {
        intent_family
        for intent_family, rows in by_intent.items()
        if len(
            {
                canonical_json(
                    criterion_parent_key(
                        next(
                            row["profile"]
                            for row in output
                            if row["handler_id"] == original["handler_id"]
                        )
                    )
                )
                for original in rows
            }
        )
        > 1
    }
    if remaining:
        raise AlignmentContractError(
            f"unresolved normalized-intent axis conflicts: {sorted(remaining)!r}"
        )
    return sorted(output, key=lambda row: row["handler_id"]), len(conflicts)


def _criterion_label(parent: Mapping[str, Any]) -> str:
    operation = str(parent["operation_family"]).replace("-", " ").title()
    resource = str(parent["resource_family"]).replace("-", " ")
    effect = str(parent["effect"]).replace("-", " ")
    return f"{operation} {resource} ({effect})"


def _build_criteria(types: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for handler_type in types:
        by_parent[handler_type["handler_criterion_id"]].append(handler_type)
    criteria: list[dict[str, Any]] = []
    for criterion_id, children in sorted(by_parent.items()):
        parent_keys = {
            canonical_json(criterion_parent_key(child["criterion"]))
            for child in children
        }
        if len(parent_keys) != 1:
            raise AlignmentContractError("one criterion contains conflicting parent axes")
        parent = criterion_parent_key(children[0]["criterion"])
        members = sorted(
            {member for child in children for member in child["members"]}
        )
        criteria.append(
            {
                "handler_criterion_id": criterion_id,
                "canonical_label": _criterion_label(parent),
                **parent,
                "child_type_ids": sorted(
                    child["handler_type_id"] for child in children
                ),
                "representative_handler": members[0],
                "members": members,
            }
        )
    return criteria


def _build_criterion_support(
    criteria: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": CRITERION_SUPPORT_SCHEMA_VERSION,
            "handler_criterion_id": row["handler_criterion_id"],
            "handler_count": len(row["members"]),
            "leaf_type_count": len(row["child_type_ids"]),
            "project_count": len(
                {member.split(":", 1)[0] for member in row["members"]}
            ),
            "projects": sorted(
                {member.split(":", 1)[0] for member in row["members"]}
            ),
            "members": list(row["members"]),
            "support": "singleton" if len(row["members"]) == 1 else "multi",
        }
        for row in criteria
    ]


def _build_oracle_inheritance(
    types: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": ORACLE_INHERITANCE_SCHEMA_VERSION,
            "handler_criterion_id": row["handler_criterion_id"],
            "handler_type_id": row["handler_type_id"],
            "inheritance_order": [
                row["handler_criterion_id"],
                row["handler_type_id"],
            ],
            "shared_parent_scope": "shared-requirements",
            "additive_leaf_delta_scope": "additive-delta",
        }
        for row in types
    ]


def _mapping(
    profile: HandlerProfile,
    *,
    decision: str,
    handler_criterion_id: str,
    handler_type_id: str,
    reference_handler: str,
    reason: str,
    evidence: Sequence[str],
) -> dict[str, Any]:
    return {
        "schema_version": MAPPING_SCHEMA_VERSION,
        "project": profile.project_id,
        "handler_id": profile.handler_id,
        "handler_name": profile.tool["tool_name"],
        "decision": decision,
        "handler_criterion_id": handler_criterion_id,
        "handler_type_id": handler_type_id,
        "reference_handler": reference_handler,
        "reason": reason,
        "evidence": list(evidence),
    }


def _merge_input_digests(
    handler_digests: dict[str, dict[str, str]],
    capability_digests: dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    if set(handler_digests) != set(capability_digests):
        raise AlignmentContractError("handler and capability input projects differ")
    return {
        project_id: {
            **handler_digests[project_id],
            **capability_digests[project_id],
        }
        for project_id in sorted(handler_digests)
    }


def run_handler_type_alignment(
    *,
    specs: Sequence[ProjectSpec],
    out_dir: Path,
    generation_command: str,
    runner: Runner,
) -> dict[str, Any]:
    profiles, excluded, handler_digests = load_profiles(specs)
    capabilities, capability_digests = load_handler_capabilities(
        specs, profiles, excluded
    )
    input_digests = _merge_input_digests(handler_digests, capability_digests)
    by_id = {row.handler_id: row for row in profiles}
    if len(by_id) != len(profiles):
        raise AlignmentContractError("handler IDs collide across projects")
    seed_profiles = [row for row in profiles if row.project_id == SEED_PROJECT]
    external_profiles = [row for row in profiles if row.project_id != SEED_PROJECT]
    if not seed_profiles:
        raise AlignmentContractError(
            "NanoBot seed catalog has no resolved handler specifications"
        )
    chats: dict[str, list[dict[str, str]]] = {}

    seed_assignments, chats["seed"] = _validated_call(
        runner=runner,
        system=SEED_SYSTEM,
        user=build_seed_user(seed_profiles),
        validator=lambda response: validate_seed_response(
            response, {row.handler_id for row in seed_profiles}
        ),
        context="NanoBot seed intent canonicalization",
    )

    canonical_by_handler: dict[str, dict[str, Any]] = {}
    external_by_project: dict[str, list[HandlerProfile]] = defaultdict(list)
    for profile in external_profiles:
        external_by_project[profile.project_id].append(profile)
    for project_id in sorted(external_by_project):
        batch = sorted(external_by_project[project_id], key=lambda row: row.handler_id)
        assignments, exchanges = _validated_call(
            runner=runner,
            system=CANONICALIZE_SYSTEM,
            user=build_canonicalize_user(batch),
            validator=lambda response, ids={row.handler_id for row in batch}: (
                validate_profile_batch_response(response, ids)
            ),
            context=f"{project_id}: handler intent canonicalization",
        )
        chats[f"canonicalize-{project_id}"] = exchanges
        canonical_by_handler.update({row["handler_id"]: row for row in assignments})

    resolved_assignments, axis_conflict_count = _resolve_axis_conflicts(
        [*seed_assignments, *canonical_by_handler.values()],
        runner=runner,
        profiles_by_id=by_id,
        chats=chats,
    )
    resolved_assignment_by_handler = {
        row["handler_id"]: row for row in resolved_assignments
    }
    seed_assignments = [
        resolved_assignment_by_handler[row.handler_id] for row in seed_profiles
    ]
    canonical_by_handler = {
        row.handler_id: resolved_assignment_by_handler[row.handler_id]
        for row in external_profiles
    }
    seed_families, _seed_type_by_handler = _build_seed_families(
        seed_assignments, by_id
    )
    seed_type_ids = {row["family_id"] for row in seed_families}

    profiles_by_parent: dict[str, list[HandlerProfile]] = defaultdict(list)
    for profile in external_profiles:
        parent_id = stable_criterion_id(
            canonical_by_handler[profile.handler_id]["profile"]
        )
        profiles_by_parent[parent_id].append(profile)
    reconciled_groups: list[dict[str, Any]] = []
    modeled_reconciliation_batches = 0
    deterministic_unanchored_blocks = 0
    for parent_id in sorted(profiles_by_parent):
        block = sorted(profiles_by_parent[parent_id], key=lambda row: row.handler_id)
        seed_siblings = [
            row
            for row in seed_families
            if stable_criterion_id(row["criterion"]) == parent_id
        ]
        expected_parent = criterion_parent_key(
            canonical_by_handler[block[0].handler_id]["profile"]
        )
        if not seed_siblings:
            deterministic_unanchored_blocks += 1
            by_exact_intent: dict[str, list[HandlerProfile]] = defaultdict(list)
            for profile in block:
                by_exact_intent[
                    stable_type_id(
                        canonical_by_handler[profile.handler_id]["profile"]
                    )
                ].append(profile)
            for exact_profiles in by_exact_intent.values():
                assignments = [
                    canonical_by_handler[profile.handler_id]
                    for profile in exact_profiles
                ]
                reconciled_groups.append(
                    {
                        "handler_ids": sorted(
                            profile.handler_id for profile in exact_profiles
                        ),
                        "decision": "new-type",
                        "handler_type_id": None,
                        "criterion": merge_equivalent_criteria(
                            [
                                _family_criterion(assignment["profile"])
                                for assignment in assignments
                            ]
                        ),
                        "reason": (
                            "Deterministic exact normalized-intent grouping in an "
                            "unanchored parent block."
                        ),
                        "evidence": sorted(
                            {
                                evidence
                                for assignment in assignments
                                for evidence in assignment["evidence"]
                            }
                        ),
                    }
                )
            continue
        modeled_reconciliation_batches += 1
        groups, exchanges = _validated_call(
            runner=runner,
            system=RECONCILE_SYSTEM,
            user=build_reconcile_user(
                block, canonical_by_handler, seed_siblings
            ),
            validator=lambda response, ids={row.handler_id for row in block}: (
                validate_reconciliation_response(
                    response,
                    expected_handler_ids=ids,
                    seed_type_ids={row["family_id"] for row in seed_siblings},
                    expected_parent_key=expected_parent,
                )
            ),
            context=f"{parent_id}: parent-block intent reconciliation",
        )
        chats[f"reconcile-{parent_id}"] = exchanges
        reconciled_groups.extend(groups)

    direct_matches: dict[str, dict[str, Any]] = {}
    proposals: list[dict[str, Any]] = []
    for group in reconciled_groups:
        if group["decision"] == "matched":
            for handler_id in group["handler_ids"]:
                direct_matches[handler_id] = group
            continue
        members = [_member_key(by_id[handler_id]) for handler_id in group["handler_ids"]]
        proposals.append(
            _family_row(
                family_id=stable_proposal_id(members),
                origin="external-global",
                criterion=group["criterion"],
                members=members,
                reason=group["reason"],
                evidence=group["evidence"],
            )
        )
    reconciled_handlers = set(direct_matches) | {
        member.split(":", 1)[1] for proposal in proposals for member in proposal["members"]
    }
    if reconciled_handlers != {row.handler_id for row in external_profiles}:
        raise AlignmentContractError("reconciliation did not cover every external handler")
    if len({row["family_id"] for row in proposals}) != len(proposals):
        raise AlignmentContractError("provisional proposal IDs collide")

    snapshot = sorted([*seed_families, *proposals], key=lambda row: row["family_id"])
    snapshots_by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    proposals_by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for family in snapshot:
        snapshots_by_parent[stable_criterion_id(family["criterion"])].append(family)
    for proposal in proposals:
        proposals_by_parent[stable_criterion_id(proposal["criterion"])].append(proposal)
    proposal_matches: list[dict[str, Any]] = []
    proposal_match_batches = 0
    for parent_id in sorted(proposals_by_parent):
        sibling_snapshot = sorted(
            snapshots_by_parent[parent_id], key=lambda row: row["family_id"]
        )
        sibling_ids = {row["family_id"] for row in sibling_snapshot}
        source_ids = _semantic_family_ids(proposals_by_parent[parent_id])
        if len(sibling_snapshot) == 1:
            proposal_matches.extend(
                {
                    "proposal_id": source_id,
                    "verdict": "distinct",
                    "selected_id": None,
                    "reason": "No sibling leaf candidate exists under this parent criterion.",
                    "evidence": ["deterministic:no-sibling-candidate"],
                }
                for source_id in source_ids
            )
            continue
        for offset in range(0, len(source_ids), SOURCE_BATCH_SIZE):
            batch_ids = source_ids[offset : offset + SOURCE_BATCH_SIZE]
            proposal_match_batches += 1
            matches, exchanges = _validated_call(
                runner=runner,
                system=PROPOSAL_MATCH_SYSTEM,
                user=build_proposal_match_user(batch_ids, sibling_snapshot, by_id),
                validator=lambda response, ids=set(batch_ids), candidates=sibling_ids: (
                    validate_proposal_match_response(
                        response,
                        expected_proposal_ids=ids,
                        allowed_candidate_ids=candidates,
                    )
                ),
                context=f"{parent_id}: sibling proposal batch {proposal_match_batches}",
            )
            key = f"match-proposals-{parent_id}-{proposal_match_batches:03d}"
            chats[key] = exchanges
            proposal_matches.extend(matches)
    normal_edges = [
        (row["proposal_id"], row["selected_id"])
        for row in proposal_matches
        if row["verdict"] == "matched"
    ]
    normal_families, normal_component_calls = _adjudicate_edges(
        families=snapshot,
        edges=normal_edges,
        stage="proposal",
        runner=runner,
        profiles_by_id=by_id,
        seed_type_ids=seed_type_ids,
        chats=chats,
    )
    normal_families = _attach_direct_matches(
        normal_families, direct_matches, by_id
    )
    preliminary_families, exact_normal_merges = _merge_exact_intents(normal_families)

    singleton_families = [
        row for row in preliminary_families if len(row["members"]) == 1
    ]
    singleton_assessments: list[dict[str, Any]] = []
    preliminary_by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    singleton_by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for family in preliminary_families:
        preliminary_by_parent[stable_criterion_id(family["criterion"])].append(family)
    for family in singleton_families:
        singleton_by_parent[stable_criterion_id(family["criterion"])].append(family)
    no_sibling_singletons: set[str] = set()
    singleton_challenge_batches = 0
    for parent_id in sorted(singleton_by_parent):
        sibling_snapshot = sorted(
            preliminary_by_parent[parent_id], key=lambda row: row["family_id"]
        )
        sibling_ids = {row["family_id"] for row in sibling_snapshot}
        source_ids = _semantic_family_ids(singleton_by_parent[parent_id])
        if len(sibling_snapshot) == 1:
            no_sibling_singletons.update(source_ids)
            continue
        singleton_preferred = {
            family_id: likely_candidate_ids(family_id, sibling_snapshot)
            for family_id in source_ids
        }
        for offset in range(0, len(source_ids), SOURCE_BATCH_SIZE):
            batch_ids = source_ids[offset : offset + SOURCE_BATCH_SIZE]
            singleton_challenge_batches += 1
            assessments, exchanges = _validated_call(
                runner=runner,
                system=SINGLETON_SYSTEM,
                user=build_singleton_user(batch_ids, sibling_snapshot, by_id),
                validator=lambda response, ids=set(batch_ids), candidates=sibling_ids: (
                    validate_singleton_response(
                        response,
                        expected_family_ids=ids,
                        allowed_candidate_ids=candidates,
                        seed_type_ids=seed_type_ids,
                        preferred_candidate_ids={
                            family_id: singleton_preferred[family_id]
                            for family_id in ids
                        },
                    )
                ),
                context=f"{parent_id}: singleton sibling batch {singleton_challenge_batches}",
            )
            key = (
                f"challenge-singletons-{parent_id}-"
                f"{singleton_challenge_batches:03d}"
            )
            chats[key] = exchanges
            singleton_assessments.extend(assessments)
    singleton_edges = [
        (row["family_id"], row["selected_id"])
        for row in singleton_assessments
        if row["verdict"] == "matched"
    ]
    final_families, singleton_component_calls = _adjudicate_edges(
        families=preliminary_families,
        edges=singleton_edges,
        stage="singleton",
        runner=runner,
        profiles_by_id=by_id,
        seed_type_ids=seed_type_ids,
        chats=chats,
    )
    final_families, exact_singleton_merges = _merge_exact_intents(final_families)

    assignment_profiles = {
        row["handler_id"]: row["profile"]
        for row in [*seed_assignments, *canonical_by_handler.values()]
    }
    all_types: list[dict[str, Any]] = []
    family_by_member: dict[str, dict[str, Any]] = {}
    for family in final_families:
        handler_type_id = stable_type_id(family["criterion"])
        handler_criterion_id = stable_criterion_id(family["criterion"])
        criterion = {
            **family["criterion"],
            "role_signatures": _role_signatures(
                family["members"], assignment_profiles
            ),
        }
        row = {
            "handler_type_id": handler_type_id,
            "handler_criterion_id": handler_criterion_id,
            "origin": family["origin"],
            "criterion": criterion,
            "representative_handler": family["representative_handler"],
            "members": family["members"],
        }
        all_types.append(row)
        for member in family["members"]:
            if member in family_by_member:
                raise AlignmentContractError("handler belongs to multiple final families")
            family_by_member[member] = {**family, "handler_type_id": handler_type_id}
    if len({row["handler_type_id"] for row in all_types}) != len(all_types):
        raise AlignmentContractError("final intent keys collide after reconciliation")
    all_types.sort(key=lambda row: row["handler_type_id"])

    mappings: list[dict[str, Any]] = []
    type_by_id = {row["handler_type_id"]: row for row in all_types}
    for profile in profiles:
        family = family_by_member[_member_key(profile)]
        handler_type_id = family["handler_type_id"]
        decision = (
            "new-type"
            if profile.project_id == SEED_PROJECT or family["origin"] != "nanobot-seed"
            else "matched"
        )
        mappings.append(
            _mapping(
                profile,
                decision=decision,
                handler_criterion_id=type_by_id[handler_type_id][
                    "handler_criterion_id"
                ],
                handler_type_id=handler_type_id,
                reference_handler=type_by_id[handler_type_id]["representative_handler"],
                reason=family["reason"],
                evidence=family["evidence"],
            )
        )
    mappings.sort(key=lambda row: (row["project"], row["handler_name"], row["handler_id"]))
    criteria = _build_criteria(all_types)
    catalog = {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "seed_project": SEED_PROJECT,
        "criteria": criteria,
        "types": all_types,
    }
    capability_observations = build_type_capability_observations(
        catalog, mappings, capabilities
    )
    criterion_support = _build_criterion_support(criteria)
    oracle_inheritance = _build_oracle_inheritance(all_types)

    assessment_by_id = {row["family_id"]: row for row in singleton_assessments}
    preliminary_by_member = {
        row["members"][0]: row
        for row in preliminary_families
        if len(row["members"]) == 1
    }
    final_type_by_preliminary_id: dict[str, str] = {}
    for preliminary in preliminary_families:
        final_type_ids = {
            family_by_member[member]["handler_type_id"]
            for member in preliminary["members"]
        }
        if len(final_type_ids) != 1:
            raise AlignmentContractError(
                "one preliminary leaf was split across final handler types"
            )
        final_type_by_preliminary_id[preliminary["family_id"]] = next(
            iter(final_type_ids)
        )
    singleton_audits: list[dict[str, Any]] = []
    for handler_type in all_types:
        if len(handler_type["members"]) != 1:
            continue
        member = handler_type["members"][0]
        preliminary = preliminary_by_member.get(member)
        if preliminary is None:
            raise AlignmentContractError("final singleton was not challenged")
        preliminary_id = preliminary["family_id"]
        handler_criterion_id = handler_type["handler_criterion_id"]
        sibling_proposal_ids = sorted(
            row["family_id"]
            for row in preliminary_by_parent[handler_criterion_id]
            if row["family_id"] != preliminary_id
        )
        siblings = sorted(
            {
                final_type_by_preliminary_id[proposal_id]
                for proposal_id in sibling_proposal_ids
            }
            - {handler_type["handler_type_id"]}
        )
        if preliminary_id in no_sibling_singletons:
            coverage_kind = "no-sibling-candidate"
            closest: list[str] = []
            reason = (
                "The parent criterion contains no other leaf candidate; "
                "the singleton boundary is deterministic."
            )
            evidence = ["deterministic:no-sibling-candidate"]
        else:
            coverage_kind = "complete-sibling-catalog"
            assessment = assessment_by_id[preliminary_id]
            closest = sorted(
                {
                    final_type_by_preliminary_id[candidate_id]
                    for candidate_id in assessment["closest_candidate_ids"]
                }
                - {handler_type["handler_type_id"]}
            )
            reason = assessment["distinguishing_reason"]
            evidence = assessment["evidence"]
            if assessment["verdict"] == "matched":
                selected_type_id = final_type_by_preliminary_id[
                    assessment["selected_id"]
                ]
                closest = sorted({*closest, selected_type_id})
                final_family = family_by_member[member]
                reason = final_family["reason"]
                evidence = final_family["evidence"]
        singleton_audits.append(
            {
                "schema_version": SINGLETON_AUDIT_SCHEMA_VERSION,
                "proposal_id": preliminary_id,
                "handler_criterion_id": handler_criterion_id,
                "member": member,
                "coverage_kind": coverage_kind,
                "candidate_family_ids": siblings,
                "verdict": "distinct",
                "selected_family_id": None,
                "closest_candidate_ids": closest,
                "distinguishing_reason": reason,
                "evidence": evidence,
                "final_handler_type_id": handler_type["handler_type_id"],
            }
        )
    singleton_audits.sort(key=lambda row: row["final_handler_type_id"])
    validate_final_artifacts(
        catalog,
        mappings,
        capability_observations,
        singleton_audits,
        criterion_support,
        oracle_inheritance,
        expected_handler_ids=set(by_id),
    )

    repository_root = out_dir / "repository"
    _reset_generated_directory(repository_root)
    _write_json(out_dir / "catalog.json", catalog)
    _write_jsonl(out_dir / "mappings.jsonl", mappings)
    _write_jsonl(out_dir / "singleton-audit.jsonl", singleton_audits)
    _write_jsonl(out_dir / "criterion-support.jsonl", criterion_support)
    _write_jsonl(
        out_dir / "handler-oracle-inheritance.jsonl", oracle_inheritance
    )
    _write_jsonl(
        out_dir / "capability-observations.jsonl", capability_observations
    )
    _write_json(out_dir / "excluded-handlers.json", excluded)
    for key, exchanges in chats.items():
        _write_json(
            repository_root / key / "chat.json",
            {
                "schema_version": "handler-type-alignment-chat/v4",
                "subject": key,
                "exchanges": exchanges,
            },
        )
    _atomic_text(
        out_dir / "alignment.md",
        render_alignment_index(
            generation_command,
            catalog,
            mappings,
            excluded,
            profiles,
            capability_observations,
            singleton_audits,
            criterion_support,
        ),
    )

    capability_counts: dict[str, int] = defaultdict(int)
    for observation in capability_observations:
        capability_counts[observation["status"]] += 1
    initial_family_count = len(seed_families) + len(proposals)
    counts = {
        "input_handlers": len(profiles) + len(excluded),
        "resolved_handlers": len(profiles),
        "unresolved_handlers": len(excluded),
        "handler_criteria": len(criteria),
        "singleton_criteria": sum(
            row["support"] == "singleton" for row in criterion_support
        ),
        "handler_types": len(all_types),
        "leaf_variants": len(all_types),
        "singleton_types": len(singleton_audits),
        "singleton_leaves": len(singleton_audits),
        "nanobot_seed_types": len(seed_families),
        "initial_proposals": len(proposals),
        "provisional_external_types": len(proposals),
        "proposal_match_batches": proposal_match_batches,
        "proposal_matches": sum(
            row["verdict"] == "matched" for row in proposal_matches
        ),
        "component_adjudications": normal_component_calls
        + singleton_component_calls,
        "reconciliation_merges": initial_family_count - len(preliminary_families),
        "deterministic_intent_merges": exact_normal_merges
        + exact_singleton_merges,
        "singleton_challenges": len(singleton_assessments),
        "singleton_challenge_batches": singleton_challenge_batches,
        "no_sibling_singletons": len(no_sibling_singletons),
        "singleton_matches": sum(
            row["verdict"] == "matched" for row in singleton_assessments
        ),
        "validated_singletons": len(singleton_audits),
        "external_types": sum(row["origin"] == "external-global" for row in all_types),
        "mappings": len(mappings),
        "matched": sum(row["decision"] == "matched" for row in mappings),
        "new_type": sum(row["decision"] == "new-type" for row in mappings),
        "canonicalization_batches": len(external_by_project),
        "reconciliation_batches": modeled_reconciliation_batches,
        "deterministic_unanchored_blocks": deterministic_unanchored_blocks,
        "axis_conflicting_intents": axis_conflict_count,
        "primary_requests": len(chats),
        "model_calls": sum(len(row) for row in chats.values()),
        "repair_calls": sum(len(row) - 1 for row in chats.values()),
        "capability_observations": dict(sorted(capability_counts.items())),
    }
    transport = (
        runner.audit_payload()
        if callable(getattr(runner, "audit_payload", None))
        else {"transport": "injected-runner"}
    )
    manifest = {
        "schema_version": "handler-type-alignment-manifest/v4",
        "generation_command": generation_command,
        "seed_project": SEED_PROJECT,
        "inputs": input_digests,
        "outputs": {
            "catalog": str(out_dir / "catalog.json"),
            "mappings": str(out_dir / "mappings.jsonl"),
            "singleton_audit": str(out_dir / "singleton-audit.jsonl"),
            "criterion_support": str(out_dir / "criterion-support.jsonl"),
            "handler_oracle_inheritance": str(
                out_dir / "handler-oracle-inheritance.jsonl"
            ),
            "capability_observations": str(
                out_dir / "capability-observations.jsonl"
            ),
            "excluded_handlers": str(out_dir / "excluded-handlers.json"),
            "report": str(out_dir / "alignment.md"),
        },
        "counts": counts,
        "transport": transport,
    }
    _write_json(out_dir / "manifest.json", manifest)
    return manifest
