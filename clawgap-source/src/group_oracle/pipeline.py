"""Order-independent HC/ST group-oracle construction."""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import tempfile
from copy import deepcopy
from collections import defaultdict, deque
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from src.gate_semantics.contracts import estimate_tokens
from src.projects import ProjectSpec

from .corrections import corrections_by_group, load_correction_ledger
from .contracts import (
    ASSESSMENT_SCHEMA_VERSION,
    CHAT_SCHEMA_VERSION,
    EXCLUSION_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    ORACLE_SCHEMA_VERSION,
    PROPOSAL_SCHEMA_VERSION,
    SEED_SCHEMA_VERSION,
    GroupOracleError,
    canonical_json,
    parse_json_response,
    stable_proposal_id,
    stable_requirement_id,
    validate_artifacts,
    validate_assessment_response,
    validate_component_response,
    validate_evidence_extension_response,
    validate_peer_response,
    validate_seed_response,
    validate_summary_response,
)
from .evidence_authority import (
    has_normative_support,
    is_normative_evidence,
    normative_evidence_ids,
)
from .inputs import OracleChain, OracleInputs, load_oracle_inputs
from .policy_consolidation import consolidate_policies
from .gate_qualification import qualify_inputs
from .prompts import (
    ASSESS_SYSTEM,
    COMPONENT_SYSTEM,
    EVIDENCE_EXTENSION_SYSTEM,
    PEER_SYSTEM,
    POLICY_CONSOLIDATION_SYSTEM,
    REPAIR_SYSTEM,
    SEED_SYSTEM,
    SUMMARY_SYSTEM,
    build_assessment_user,
    build_component_user,
    build_evidence_extension_user,
    build_peer_user,
    build_repair_user,
    build_seed_user,
    build_summary_user,
    contains_credentials,
    redact_credentials,
)
from .render import render_oracle_index


Runner = Callable[[str, str], str]
SEED_PROJECT = "nanobot"
BATCH_SIZE = 8
DEFAULT_INPUT_TOKEN_LIMIT = 96_000


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: object) -> None:
    _write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, rows: Sequence[object]) -> None:
    _write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def _publish_directory(staging: Path, out_dir: Path) -> None:
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    backup = out_dir.parent / f".{out_dir.name}.previous"
    if backup.exists():
        raise GroupOracleError(f"stale publication backup exists: {backup}")
    had_previous = out_dir.exists()
    try:
        if had_previous:
            os.replace(out_dir, backup)
        os.replace(staging, out_dir)
    except Exception:
        if had_previous and backup.exists() and not out_dir.exists():
            os.replace(backup, out_dir)
        raise
    if backup.exists():
        shutil.rmtree(backup)


def _read_prior_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GroupOracleError(
                f"invalid prior group-oracle row {path}:{number}: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise GroupOracleError(
                f"invalid prior group-oracle row {path}:{number}"
            )
        rows.append(row)
    return rows


def _prior_group_snapshot(out_dir: Path) -> dict[str, Any]:
    """Load the published per-HSG artifacts needed for content-bound reuse."""

    required = {
        "oracles": out_dir / "oracles.jsonl",
        "seeds": out_dir / "seed-profiles.jsonl",
        "proposals": out_dir / "proposals.jsonl",
        "assessments": out_dir / "proposal-assessments.jsonl",
        "evidence": out_dir / "evidence-index.json",
    }
    if not any(path.exists() for path in required.values()):
        return {}
    if any(not path.is_file() for path in required.values()):
        raise GroupOracleError("prior group-oracle publication is incomplete")
    manifest_path = out_dir / "manifest.json"
    try:
        prior_manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    except (OSError, json.JSONDecodeError) as exc:
        raise GroupOracleError(f"invalid prior group-oracle manifest: {exc}") from exc
    rows_by_kind = {
        name: _read_prior_jsonl(path)
        for name, path in required.items()
        if name != "evidence"
    }
    try:
        evidence_index = json.loads(required["evidence"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GroupOracleError(f"invalid prior evidence index: {exc}") from exc
    prior_evidence = evidence_index.get("evidence")
    if not isinstance(prior_evidence, list):
        raise GroupOracleError("invalid prior evidence index rows")

    chats: dict[tuple[str, str], list[dict[str, str]]] = {}
    semantic_ir_by_chain: dict[tuple[str, str], str] = {}
    repository = out_dir / "repository"
    if not repository.is_dir():
        raise GroupOracleError("prior group-oracle repository is missing")
    for path in sorted(repository.glob("*/*/chat.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GroupOracleError(f"invalid prior group-oracle chat {path}: {exc}") from exc
        if payload.get("schema_version") != CHAT_SCHEMA_VERSION:
            raise GroupOracleError(f"unsupported prior group-oracle chat {path}")
        stage = payload.get("stage")
        subject = payload.get("subject")
        exchanges = payload.get("exchanges")
        if (
            not isinstance(stage, str)
            or not isinstance(subject, str)
            or not isinstance(exchanges, list)
        ):
            raise GroupOracleError(f"invalid prior group-oracle chat payload {path}")
        chats[(stage, subject)] = exchanges
        for exchange in exchanges:
            if not isinstance(exchange, dict) or not isinstance(
                exchange.get("user"), str
            ):
                raise GroupOracleError(f"invalid prior group-oracle exchange {path}")
            try:
                user = json.loads(exchange["user"])
            except json.JSONDecodeError:
                continue
            if not isinstance(user, dict):
                continue
            seed_ref = user.get("seed_chain_ref")
            seed_ir = user.get("seed_semantic_ir")
            if isinstance(seed_ref, str) and isinstance(seed_ir, dict):
                project, chain_id = seed_ref.split(":", 1)
                semantic_ir_by_chain[(project, chain_id)] = canonical_json(seed_ir)
            candidate_chains = user.get("candidate_chains")
            if isinstance(candidate_chains, list):
                for candidate in candidate_chains:
                    if not isinstance(candidate, dict):
                        continue
                    ref = candidate.get("chain_ref")
                    semantic_ir = candidate.get("semantic_ir")
                    if isinstance(ref, str) and isinstance(semantic_ir, dict):
                        project, chain_id = ref.split(":", 1)
                        serialized = canonical_json(semantic_ir)
                        key = (project, chain_id)
                        prior = semantic_ir_by_chain.setdefault(key, serialized)
                        if prior != serialized:
                            raise GroupOracleError(
                                f"conflicting prior semantic IR for {ref}"
                            )
    return {
        **rows_by_kind,
        "construction_policy_sha256": prior_manifest.get("construction_policy_sha256"),
        "observed_gates_only": prior_manifest.get("observed_gates_only", False),
        "evidence": prior_evidence,
        "chats": chats,
        "semantic_ir_by_chain": semantic_ir_by_chain,
    }


def _construction_policy_sha256() -> str:
    """Bind whole-group reuse to the actual inference and repair instructions."""
    prompts = [SEED_SYSTEM, PEER_SYSTEM, EVIDENCE_EXTENSION_SYSTEM, ASSESS_SYSTEM,
               SUMMARY_SYSTEM, COMPONENT_SYSTEM, REPAIR_SYSTEM, POLICY_CONSOLIDATION_SYSTEM]
    return hashlib.sha256(canonical_json(prompts).encode()).hexdigest()


def _reusable_prior_groups(
    inputs: OracleInputs,
    prior: Mapping[str, Any],
    *,
    observed_gates_only: bool = False,
) -> set[str]:
    if not prior:
        return set()
    if prior.get("construction_policy_sha256") != _construction_policy_sha256():
        return set()
    if prior.get("observed_gates_only", False) != observed_gates_only:
        return set()
    prior_oracles = {row["group_id"]: row for row in prior["oracles"]}
    prior_evidence_by_id = {
        row["evidence_id"]: row for row in prior["evidence"]
    }
    reusable: set[str] = set()
    for group in inputs.security_groups:
        group_id = group["handler_sink_group_id"]
        oracle = prior_oracles.get(group_id)
        if oracle is None:
            continue
        expected_refs = sorted(
            (row["project"], row["chain_id"]) for row in group["chain_refs"]
        )
        prior_refs = sorted(
            (row["project"], row["chain_id"])
            for row in oracle["member_chain_refs"]
        )
        if (
            expected_refs != prior_refs
            or oracle["handler_criterion_id"] != group["handler_criterion_id"]
            or oracle["sink_type_id"] != group["sink_type_id"]
        ):
            continue
        if any(
            not has_normative_support(
                requirement["evidence_ids"], prior_evidence_by_id
            )
            for requirement in oracle["requirements"]
        ):
            continue
        if any(
            prior["semantic_ir_by_chain"].get(key)
            != canonical_json(inputs.chains[key].semantic_ir)
            for key in expected_refs
        ):
            continue
        current_evidence_ids = {
            row["evidence_id"] for row in inputs.evidence_by_group[group_id]
        }
        prior_evidence_ids = {
            row["evidence_id"]
            for row in prior["evidence"]
            if group["handler_criterion_id"]
            in row["applicability"]["handler_criterion_ids"]
            and group["sink_type_id"]
            in row["applicability"]["sink_type_ids"]
        }
        if current_evidence_ids == prior_evidence_ids:
            reusable.add(group_id)
    return reusable


def _validated_call(
    *,
    runner: Runner,
    system: str,
    user: str,
    validator: Callable[[Mapping[str, Any]], Any],
    context: str,
) -> tuple[Any, list[dict[str, str]]]:
    exchanges: list[dict[str, str]] = []
    raw = redact_credentials(runner(system, user))
    exchanges.append({"system": system, "user": user, "response": raw})
    try:
        return validator(parse_json_response(raw)), exchanges
    except Exception as first:
        repair_user = build_repair_user(
            system, user, raw, f"{type(first).__name__}: {first}"
        )
        repaired = redact_credentials(runner(REPAIR_SYSTEM, repair_user))
        exchanges.append(
            {"system": REPAIR_SYSTEM, "user": repair_user, "response": repaired}
        )
        try:
            return validator(parse_json_response(repaired)), exchanges
        except Exception as second:
            invalidate = getattr(runner, "invalidate_prompts", None)
            if callable(invalidate):
                invalidate([(system, user), (REPAIR_SYSTEM, repair_user)])
            raise GroupOracleError(
                f"{context}: unrepaired group-oracle response: "
                f"{type(second).__name__}: {second}"
            ) from second


def _chain_ref(chain: OracleChain) -> dict[str, str]:
    return {
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
    }


def _select_seed(
    group: Mapping[str, Any],
    chains: Sequence[OracleChain],
    sink_type: Mapping[str, Any],
) -> tuple[OracleChain, str]:
    complete = [row for row in chains if row.semantic_ir["status"] == "complete"]
    nanobot_complete = [row for row in complete if row.project == SEED_PROJECT]
    if sink_type["origin"] == "nanobot-seed" and nanobot_complete:
        return min(
            nanobot_complete, key=lambda row: row.chain_id
        ), "nanobot-complete-lexicographic"
    if complete:
        return min(
            complete, key=lambda row: (row.project, row.chain_id)
        ), "complete-lexicographic"
    return min(
        chains, key=lambda row: (row.project, row.chain_id)
    ), "partial-lexicographic"


def _pack_peer_batches(
    *,
    group: Mapping[str, Any],
    seed_profile: Mapping[str, Any],
    chains: Sequence[OracleChain],
    sink_type: Mapping[str, Any],
    token_limit: int,
) -> list[tuple[list[OracleChain], str]]:
    batches: list[tuple[list[OracleChain], str]] = []
    current: list[OracleChain] = []
    current_user = ""
    for chain in chains:
        one_user = build_peer_user(
            group=group, seed_profile=seed_profile, chains=[chain], st=sink_type
        )
        if estimate_tokens({"system": PEER_SYSTEM, "user": one_user}) > token_limit:
            raise GroupOracleError(
                f"{chain.ref}: complete peer prompt exceeds {token_limit} estimated tokens; "
                "semantic IR is never truncated"
            )
        candidate = [*current, chain]
        candidate_user = build_peer_user(
            group=group, seed_profile=seed_profile, chains=candidate, st=sink_type
        )
        if current and (
            len(candidate) > BATCH_SIZE
            or estimate_tokens({"system": PEER_SYSTEM, "user": candidate_user})
            > token_limit
        ):
            batches.append((current, current_user))
            current = [chain]
            current_user = one_user
        else:
            current = candidate
            current_user = candidate_user
    if current:
        batches.append((current, current_user))
    return batches


def _proposal(
    *, group_id: str, origin: str, chain: OracleChain, candidate: Mapping[str, Any]
) -> dict[str, Any]:
    origin_refs = [_chain_ref(chain)]
    proposal_id = stable_proposal_id(
        group_id,
        origin_refs,
        candidate["origin_gate_ids"],
        candidate["dimension"],
        candidate["rule"],
        candidate["applicability"],
    )
    row = {
        "schema_version": PROPOSAL_SCHEMA_VERSION,
        "proposal_id": proposal_id,
        "group_id": group_id,
        "origin": origin,
        "dimension": candidate["dimension"],
        "rule": candidate["rule"],
        "applicability": candidate["applicability"],
        "origin_chain_refs": origin_refs,
        "origin_gate_ids": candidate["origin_gate_ids"],
        "reason": candidate["reason"],
    }
    if candidate.get("origin_evidence_ids"):
        row["origin_evidence_ids"] = sorted(candidate["origin_evidence_ids"])
    return row


def _prior_requirement_continuity_proposals(
    *,
    group_id: str,
    group_chains: Sequence[OracleChain],
    current_evidence: Sequence[Mapping[str, Any]],
    prior_oracle: Mapping[str, Any] | None,
    prior_evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Carry forward still-bound requirements when an HSG input expands or drifts."""

    if prior_oracle is None:
        return []
    current_chains = {row.key: row for row in group_chains}
    current_evidence_by_id = {
        row["evidence_id"]: row for row in current_evidence
    }
    current_capability_by_path: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in current_evidence:
        if row["kind"] == "capability-card":
            current_capability_by_path[row["source_path"]].append(row)
    prior_evidence_by_id = {row["evidence_id"]: row for row in prior_evidence}
    proposals: list[dict[str, Any]] = []
    for requirement in prior_oracle["requirements"]:
        origin_refs = requirement["origin_chain_refs"]
        origin_keys = {
            (row["project"], row["chain_id"]) for row in origin_refs
        }
        if not origin_keys or not origin_keys <= set(current_chains):
            continue
        allowed_gates = {
            gate["gate_uid"]
            for key in origin_keys
            for gate in current_chains[key].semantic_ir["gates"]
        }
        if not set(requirement["origin_gate_ids"]) <= allowed_gates:
            continue
        remapped_evidence: list[str] = []
        for evidence_id in requirement["evidence_ids"]:
            if evidence_id in current_evidence_by_id:
                remapped_evidence.append(evidence_id)
                continue
            old = prior_evidence_by_id.get(evidence_id)
            if old is None or old.get("kind") != "capability-card":
                remapped_evidence = []
                break
            replacements = current_capability_by_path.get(old["source_path"], [])
            if len(replacements) != 1:
                remapped_evidence = []
                break
            remapped_evidence.append(replacements[0]["evidence_id"])
        if not remapped_evidence:
            continue
        if not has_normative_support(remapped_evidence, current_evidence_by_id):
            continue
        proposal_id = stable_proposal_id(
            group_id,
            origin_refs,
            requirement["origin_gate_ids"],
            requirement["dimension"],
            requirement["rule"],
            requirement["applicability"],
        )
        proposals.append(
            {
                "schema_version": PROPOSAL_SCHEMA_VERSION,
                "proposal_id": proposal_id,
                "group_id": group_id,
                "origin": "evidence",
                "dimension": requirement["dimension"],
                "rule": requirement["rule"],
                "applicability": requirement["applicability"],
                "origin_chain_refs": origin_refs,
                "origin_gate_ids": requirement["origin_gate_ids"],
                "origin_evidence_ids": sorted(set(remapped_evidence)),
                "reason": (
                    "Content-bound continuity of a previously committed requirement; "
                    "all origin chains, gates, and current capability evidence remain valid."
                ),
            }
        )
    return proposals


def _connected_components(edges: Sequence[tuple[str, str]]) -> list[list[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for left, right in edges:
        graph[left].add(right)
        graph[right].add(left)
    visited: set[str] = set()
    output: list[list[str]] = []
    for root in sorted(graph):
        if root in visited:
            continue
        visited.add(root)
        queue = deque([root])
        component: list[str] = []
        while queue:
            node = queue.popleft()
            component.append(node)
            for neighbor in sorted(graph[node]):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        output.append(sorted(component))
    return output


def _node_for_proposal(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "node_id": row["proposal_id"],
        "original_proposal_ids": [row["proposal_id"]],
        "dimension": row["dimension"],
        "rule": row["rule"],
        "applicability": row["applicability"],
    }


def _sanitize_peer_gate_ids(
    response: Mapping[str, Any],
    gate_ids_by_ref: Mapping[str, set[str]],
) -> Mapping[str, Any]:
    sanitized = deepcopy(response)
    chains = sanitized.get("chains")
    if not isinstance(chains, list):
        return sanitized
    for row in chains:
        if not isinstance(row, dict) or not isinstance(row.get("chain_ref"), str):
            continue
        allowed = gate_ids_by_ref.get(row["chain_ref"])
        candidates = row.get("candidate_requirements")
        if allowed is None or not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict) or not isinstance(
                candidate.get("origin_gate_ids"), list
            ):
                continue
            candidate["origin_gate_ids"] = [
                gate_id
                for gate_id in candidate["origin_gate_ids"]
                if isinstance(gate_id, str) and gate_id in allowed
            ]
    return sanitized


def _summarize_component(
    *,
    component: Sequence[str],
    proposals_by_id: Mapping[str, dict[str, Any]],
    runner: Runner,
    chat: Callable[[str, str, list[dict[str, str]]], None],
    group_id: str,
    component_number: int,
) -> tuple[list[dict[str, Any]], int]:
    nodes = [_node_for_proposal(proposals_by_id[row]) for row in component]
    level = 0
    calls = 0
    while len(nodes) > BATCH_SIZE:
        level += 1
        next_nodes: list[dict[str, Any]] = []
        for batch_number, offset in enumerate(range(0, len(nodes), BATCH_SIZE), 1):
            batch = nodes[offset : offset + BATCH_SIZE]
            expected = {row["node_id"] for row in batch}
            user = build_summary_user(batch)
            summaries, exchanges = _validated_call(
                runner=runner,
                system=SUMMARY_SYSTEM,
                user=user,
                validator=lambda response, ids=expected: validate_summary_response(
                    response, expected_proposal_ids=ids
                ),
                context=(
                    f"{group_id}: component {component_number} summary "
                    f"level {level} batch {batch_number}"
                ),
            )
            calls += 1
            chat(
                "summarize",
                (
                    f"{group_id}-C{component_number:03d}-"
                    f"L{level:02d}-B{batch_number:03d}"
                ),
                exchanges,
            )
            originals_by_node = {
                row["node_id"]: row["original_proposal_ids"] for row in batch
            }
            for summary in summaries:
                originals = sorted(
                    {
                        proposal_id
                        for node_id in summary["proposal_ids"]
                        for proposal_id in originals_by_node[node_id]
                    }
                )
                next_nodes.append(
                    {
                        "node_id": summary["summary_id"],
                        "original_proposal_ids": originals,
                        "dimension": summary["dimension"],
                        "rule": summary["rule"],
                        "applicability": summary["applicability"],
                        "reason": summary["reason"],
                    }
                )
        if len(next_nodes) >= len(nodes):
            raise GroupOracleError(
                f"{group_id}: component summary did not reduce {len(nodes)} nodes"
            )
        nodes = sorted(next_nodes, key=lambda row: row["node_id"])
    return nodes, calls


def _input_group_maps(
    inputs: OracleInputs,
) -> tuple[dict[str, set[tuple[str, str]]], dict[str, set[tuple[str, str]]]]:
    security = {
        row["handler_sink_group_id"]: {
            (ref["project"], ref["chain_id"]) for ref in row["chain_refs"]
        }
        for row in inputs.security_groups
    }
    excluded = {
        row["handler_sink_group_id"]: {
            (ref["project"], ref["chain_id"]) for ref in row["chain_refs"]
        }
        for row in inputs.excluded_groups
    }
    return security, excluded


def _select_input_groups(
    inputs: OracleInputs, group_ids: Sequence[str] | None
) -> tuple[OracleInputs, dict[str, Any]]:
    """Select complete groups without changing their frozen member semantics."""

    full_counts = {
        "input_handler_sink_groups": len(inputs.security_groups) + len(inputs.excluded_groups),
        "eligible_security_groups": len(inputs.security_groups),
        "eligible_chains": sum(row["chain_count"] for row in inputs.security_groups),
        "excluded_no_security_impact_groups": len(inputs.excluded_groups),
        "excluded_no_security_impact_chains": sum(
            row["chain_count"] for row in inputs.excluded_groups
        ),
    }
    if group_ids is None:
        return inputs, {"mode": "all", "full_input_counts": full_counts}
    if isinstance(group_ids, str) or not group_ids or any(
        not isinstance(group_id, str) for group_id in group_ids
    ):
        raise GroupOracleError("group_ids must be a non-empty sequence of HSG IDs")
    requested = set(group_ids)
    available = {row["handler_sink_group_id"] for row in inputs.security_groups}
    unknown = requested - available
    if unknown:
        raise GroupOracleError(
            "unknown or ineligible group IDs: " + ", ".join(sorted(unknown))
        )
    groups = tuple(
        row for row in inputs.security_groups if row["handler_sink_group_id"] in requested
    )
    member_keys = {
        (ref["project"], ref["chain_id"])
        for group in groups
        for ref in group["chain_refs"]
    }
    evidence_by_group = {
        group_id: inputs.evidence_by_group[group_id] for group_id in sorted(requested)
    }
    evidence_ids = {
        row["evidence_id"] for rows in evidence_by_group.values() for row in rows
    }
    selected = replace(
        inputs,
        security_groups=groups,
        excluded_groups=(),
        chains={key: row for key, row in inputs.chains.items() if key in member_keys},
        evidence_by_group=evidence_by_group,
        evidence_index={
            **inputs.evidence_index,
            "evidence": [
                row for row in inputs.evidence_index["evidence"]
                if row["evidence_id"] in evidence_ids
            ],
        },
    )
    return selected, {
        "mode": "selected-groups",
        "group_ids": sorted(requested),
        "full_input_counts": full_counts,
    }


def _guard_selected_publication(out_dir: Path, group_ids: Sequence[str]) -> None:
    """Prevent a scoped run from replacing a full or differently scoped publication."""

    canonical = Path(__file__).resolve().parents[2] / "output/cross-project/group-oracles"
    if out_dir.resolve() == canonical.resolve():
        raise GroupOracleError("selected-group runs must not overwrite canonical group oracles")
    requested = set(group_ids)
    for name in (
        "oracles.jsonl", "excluded-groups.jsonl", "seed-profiles.jsonl",
        "proposals.jsonl", "proposal-assessments.jsonl",
    ):
        path = out_dir / name
        if not path.is_file():
            continue
        existing = {row.get("group_id") for row in _read_prior_jsonl(path)}
        if not existing <= requested:
            raise GroupOracleError(
                "selected-group publication would overwrite unselected groups in " + str(path)
            )


def run_group_oracle(
    *,
    specs: Sequence[ProjectSpec],
    handler_root: Path,
    sink_root: Path,
    evidence_registry: Path,
    out_dir: Path,
    generation_command: str,
    runner: Runner,
    correction_ledger: Path | None = None,
    group_ids: Sequence[str] | None = None,
    reuse_prior: bool = True,
    observed_gates_only: bool = False,
    gate_qualification: Path | None = None,
    publish: bool = True,
    input_token_limit: int = DEFAULT_INPUT_TOKEN_LIMIT,
) -> dict[str, Any]:
    if input_token_limit < 1:
        raise GroupOracleError("input token limit must be positive")
    if observed_gates_only and correction_ledger is not None:
        raise GroupOracleError("observed-gates-only mode cannot inject correction-ledger requirements")
    if gate_qualification is not None and not observed_gates_only:
        raise GroupOracleError("reviewed gate qualification requires observed-gates-only mode")
    correction_binding: dict[str, Any] | None = None
    correction_groups: dict[str, tuple[Mapping[str, Any], ...]] = {}
    if correction_ledger is not None:
        ledger, correction_binding = load_correction_ledger(
            correction_ledger, evidence_registry=evidence_registry
        )
        correction_groups = corrections_by_group(ledger)
        baseline_group_root = Path(ledger["baseline"]["group_root"]).resolve()
        if out_dir.resolve() == baseline_group_root:
            raise GroupOracleError(
                "correction mode must not overwrite baseline group oracles"
            )
    inputs = load_oracle_inputs(
        specs,
        handler_root=handler_root,
        sink_root=sink_root,
        evidence_registry=evidence_registry,
    )
    inputs, selection_scope = _select_input_groups(inputs, group_ids)
    qualification_audit = None
    if gate_qualification is not None:
        inputs, qualification_audit = qualify_inputs(inputs, gate_qualification)
    if publish and group_ids is not None:
        _guard_selected_publication(out_dir, selection_scope["group_ids"])
    prior_snapshot = (
        _prior_group_snapshot(out_dir) if correction_ledger is None and reuse_prior else {}
    )
    reusable_group_ids = _reusable_prior_groups(
        inputs, prior_snapshot, observed_gates_only=observed_gates_only
    )
    prior_oracle_by_group = {
        row["group_id"]: row for row in prior_snapshot.get("oracles", [])
    }
    prior_seed_by_group = {
        row["group_id"]: row for row in prior_snapshot.get("seeds", [])
    }
    prior_proposals_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in prior_snapshot.get("proposals", []):
        prior_proposals_by_group[row["group_id"]].append(row)
    prior_assessments_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in prior_snapshot.get("assessments", []):
        prior_assessments_by_group[row["group_id"]].append(row)
    chats: dict[tuple[str, str], list[dict[str, str]]] = {}

    def record_chat(stage: str, subject: str, exchanges: list[dict[str, str]]) -> None:
        key = (stage, subject)
        if key in chats:
            raise GroupOracleError(f"duplicate audit subject {stage}/{subject}")
        chats[key] = exchanges

    oracles: list[dict[str, Any]] = []
    seeds: list[dict[str, Any]] = []
    proposals: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []
    peer_batches = 0
    assessment_batches = 0
    summary_calls = 0
    component_calls = 0
    evidence_extension_calls = 0
    evidence_extension_proposals = 0
    for group in inputs.security_groups:
        group_id = group["handler_sink_group_id"]
        if group_id in reusable_group_ids:
            oracles.append(deepcopy(prior_oracle_by_group[group_id]))
            seeds.append(deepcopy(prior_seed_by_group[group_id]))
            prior_group_proposals = deepcopy(prior_proposals_by_group[group_id])
            proposals.extend(prior_group_proposals)
            assessments.extend(
                deepcopy(prior_assessments_by_group[group_id])
            )
            for (stage, subject), exchanges in prior_snapshot["chats"].items():
                if subject == group_id or subject.startswith(group_id + "-"):
                    record_chat(stage, subject, deepcopy(exchanges))
                    if stage == "peer":
                        peer_batches += 1
                    elif stage == "assess":
                        assessment_batches += 1
                    elif stage == "summary":
                        summary_calls += 1
                    elif stage == "component":
                        component_calls += 1
                    elif stage == "evidence":
                        evidence_extension_calls += 1
            evidence_extension_proposals += sum(
                row["origin"] == "evidence" for row in prior_group_proposals
            )
            continue
        group_chains = sorted(
            (
                inputs.chains[(ref["project"], ref["chain_id"])]
                for ref in group["chain_refs"]
            ),
            key=lambda row: (row.project, row.chain_id),
        )
        sink_type = inputs.sink_types[group["sink_type_id"]]
        hc = inputs.handler_criteria[group["handler_criterion_id"]]
        evidence = list(inputs.evidence_by_group[group_id])
        allowed_evidence_ids = {row["evidence_id"] for row in evidence}
        authoritative_evidence_ids = normative_evidence_ids(evidence)
        seed, selection_policy = _select_seed(group, group_chains, sink_type)
        seed_user = build_seed_user(
            group=group, chain=seed, hc=hc, st=sink_type, evidence=evidence
        )
        if (
            estimate_tokens({"system": SEED_SYSTEM, "user": seed_user})
            > input_token_limit
        ):
            raise GroupOracleError(
                f"{seed.ref}: complete seed prompt exceeds {input_token_limit} estimated tokens; "
                "semantic IR is never truncated"
            )
        allowed_seed_gates = {row["gate_uid"] for row in seed.semantic_ir["gates"]}
        (policy_atoms, seed_candidates), exchanges = _validated_call(
            runner=runner,
            system=SEED_SYSTEM,
            user=seed_user,
            validator=lambda response, gid=group_id, gates=allowed_seed_gates: (
                validate_seed_response(response, group_id=gid, allowed_gate_ids=gates)
            ),
            context=f"{group_id}: seed profiling",
        )
        record_chat("seed", group_id, exchanges)
        seed_profile = {
            "schema_version": SEED_SCHEMA_VERSION,
            "group_id": group_id,
            "handler_criterion_id": group["handler_criterion_id"],
            "sink_type_id": group["sink_type_id"],
            "seed_chain_ref": _chain_ref(seed),
            "selection_policy": selection_policy,
            "policy_atoms": policy_atoms,
            "candidate_requirements": seed_candidates,
        }
        seeds.append(seed_profile)
        group_proposals: list[dict[str, Any]] = [
            _proposal(group_id=group_id, origin="seed", chain=seed, candidate=candidate)
            for candidate in seed_candidates
        ]
        continuity_rows = _prior_requirement_continuity_proposals(
            group_id=group_id,
            group_chains=group_chains,
            current_evidence=evidence,
            prior_oracle=prior_oracle_by_group.get(group_id),
            prior_evidence=prior_snapshot.get("evidence", []),
        )
        if observed_gates_only:
            continuity_rows = [row for row in continuity_rows if row["origin_gate_ids"]]
        continuity_proposal_ids = {
            row["proposal_id"] for row in continuity_rows
        }
        group_proposals.extend(continuity_rows)
        correction_locators = {
            locator
            for correction in correction_groups.get(group_id, ())
            for locator in correction["evidence_locators"]
        }
        evidence_by_locator = {row["locator"]: row for row in evidence}
        missing_locators = correction_locators - set(evidence_by_locator)
        if missing_locators:
            raise GroupOracleError(
                f"{group_id}: correction evidence is not applicable: "
                f"{sorted(missing_locators)}"
            )
        for locator in sorted(correction_locators):
            evidence_row = evidence_by_locator[locator]
            group_proposals.append(
                _proposal(
                    group_id=group_id,
                    origin="evidence",
                    chain=seed,
                    candidate={
                        "dimension": locator,
                        "rule": evidence_row["exact_quote"],
                        "applicability": (
                            "when the concrete call shape can exercise the described capability"
                        ),
                        "origin_gate_ids": [],
                        "origin_evidence_ids": [evidence_row["evidence_id"]],
                        "reason": "Deterministic source-backed correction-v2 proposal.",
                    },
                )
            )
        normative_evidence = [row for row in evidence if is_normative_evidence(row)]
        if normative_evidence and not observed_gates_only:
            evidence_user = build_evidence_extension_user(
                group=group,
                seed_profile=seed_profile,
                hc=hc,
                st=sink_type,
                evidence=normative_evidence,
            )
            if (
                estimate_tokens(
                    {"system": EVIDENCE_EXTENSION_SYSTEM, "user": evidence_user}
                )
                > input_token_limit
            ):
                raise GroupOracleError(
                    f"{group_id}: complete evidence-extension prompt exceeds "
                    f"{input_token_limit} estimated tokens"
                )
            allowed_normative_ids = {
                row["evidence_id"] for row in normative_evidence
            }
            evidence_candidates, exchanges = _validated_call(
                runner=runner,
                system=EVIDENCE_EXTENSION_SYSTEM,
                user=evidence_user,
                validator=lambda response, gid=group_id, ids=allowed_normative_ids: (
                    validate_evidence_extension_response(
                        response,
                        group_id=gid,
                        allowed_evidence_ids=ids,
                        normative_evidence_ids=ids,
                    )
                ),
                context=f"{group_id}: evidence extension",
            )
            evidence_extension_calls += 1
            record_chat("evidence", group_id, exchanges)
            evidence_rows = [
                _proposal(
                    group_id=group_id,
                    origin="evidence",
                    chain=seed,
                    candidate=candidate,
                )
                for candidate in evidence_candidates
            ]
            existing_ids = {row["proposal_id"] for row in group_proposals}
            evidence_rows = [
                row for row in evidence_rows if row["proposal_id"] not in existing_ids
            ]
            evidence_extension_proposals += len(evidence_rows)
            group_proposals.extend(evidence_rows)
        peers = [row for row in group_chains if row.key != seed.key]
        for batch_number, (batch, peer_user) in enumerate(
            _pack_peer_batches(
                group=group,
                seed_profile=seed_profile,
                chains=peers,
                sink_type=sink_type,
                token_limit=input_token_limit,
            ),
            1,
        ):
            peer_batches += 1
            expected_refs = {row.ref for row in batch}
            chains_by_ref = {row.ref: row for row in batch}
            gates_by_ref = {
                row.ref: {gate["gate_uid"] for gate in row.semantic_ir["gates"]}
                for row in batch
            }
            rows, exchanges = _validated_call(
                runner=runner,
                system=PEER_SYSTEM,
                user=peer_user,
                validator=lambda response, refs=expected_refs, gates=gates_by_ref: (
                    validate_peer_response(
                        (
                            _sanitize_peer_gate_ids(response, gates)
                            if correction_binding is not None
                            else response
                        ),
                        expected_chain_refs=refs,
                        gate_ids_by_ref=gates,
                    )
                ),
                context=f"{group_id}: peer batch {batch_number}",
            )
            record_chat("peer", f"{group_id}-B{batch_number:03d}", exchanges)
            for row in rows:
                chain = chains_by_ref[row["chain_ref"]]
                group_proposals.extend(
                    _proposal(
                        group_id=group_id,
                        origin="peer",
                        chain=chain,
                        candidate=candidate,
                    )
                    for candidate in row["candidate_requirements"]
                )
        by_proposal_id: dict[str, dict[str, Any]] = {}
        for proposal in group_proposals:
            prior = by_proposal_id.setdefault(proposal["proposal_id"], proposal)
            if prior != proposal:
                if proposal["proposal_id"] in continuity_proposal_ids and all(
                    prior[field] == proposal[field]
                    for field in (
                        "group_id",
                        "dimension",
                        "rule",
                        "applicability",
                    )
                ):
                    prior["origin_chain_refs"] = sorted(
                        {
                            canonical_json(ref): ref
                            for ref in [
                                *prior["origin_chain_refs"],
                                *proposal["origin_chain_refs"],
                            ]
                        }.values(),
                        key=lambda row: (row["project"], row["chain_id"]),
                    )
                    prior["origin_gate_ids"] = sorted(
                        set(prior["origin_gate_ids"])
                        | set(proposal["origin_gate_ids"])
                    )
                    # A fresh seed/peer candidate may have the same content ID as
                    # a reviewed continuity proposal. Preserve its authority too,
                    # not just its chain/gate provenance. Evidence-origin is the
                    # wire-contract variant that permits origin_evidence_ids.
                    prior["origin"] = "evidence"
                    prior["origin_evidence_ids"] = sorted(
                        set(prior.get("origin_evidence_ids", []))
                        | set(proposal.get("origin_evidence_ids", []))
                    )
                    prior["reason"] = (
                        "Content-bound continuity merged with an identical current "
                        "candidate; normative evidence and observed origins retained."
                    )
                    continue
                raise GroupOracleError(
                    f"{group_id}: proposal ID collision for different contents"
                )
        group_proposals = sorted(
            by_proposal_id.values(), key=lambda row: row["proposal_id"]
        )
        correction_evidence_ids = {
            evidence_by_locator[locator]["evidence_id"]
            for locator in correction_locators
        }
        forced_correction_proposal_ids = {
            row["proposal_id"]
            for row in group_proposals
            if set(row.get("origin_evidence_ids", [])) & correction_evidence_ids
        }
        forced_proposal_ids = (
            forced_correction_proposal_ids | continuity_proposal_ids
        )
        for proposal in group_proposals:
            if proposal["proposal_id"] in forced_proposal_ids and not (
                set(proposal.get("origin_evidence_ids", [])) & authoritative_evidence_ids
            ):
                raise GroupOracleError(
                    f"{group_id}: retained proposal lost normative origin evidence: "
                    f"{proposal['proposal_id']}"
                )
        proposals.extend(group_proposals)
        proposals_by_id = {row["proposal_id"]: row for row in group_proposals}
        group_assessments: list[dict[str, Any]] = []
        by_dimension: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for proposal in group_proposals:
            by_dimension[proposal["dimension"]].append(proposal)
        for dimension in sorted(by_dimension):
            dimension_rows = sorted(
                by_dimension[dimension], key=lambda row: row["proposal_id"]
            )
            for batch_number, offset in enumerate(
                range(0, len(dimension_rows), BATCH_SIZE), 1
            ):
                assessment_batches += 1
                source_ids = [
                    row["proposal_id"]
                    for row in dimension_rows[offset : offset + BATCH_SIZE]
                ]
                user = build_assessment_user(
                    group=group,
                    source_ids=source_ids,
                    dimension_proposals=dimension_rows,
                    evidence=evidence,
                    st=sink_type,
                )
                rows, exchanges = _validated_call(
                    runner=runner,
                    system=ASSESS_SYSTEM,
                    user=user,
                    validator=lambda response, ids=set(source_ids), allowed={row["proposal_id"] for row in dimension_rows}, evidence_ids=allowed_evidence_ids, normative_ids=authoritative_evidence_ids: (
                        validate_assessment_response(
                            response,
                            expected_proposal_ids=ids,
                            allowed_candidate_ids=allowed,
                            allowed_evidence_ids=evidence_ids,
                            normative_evidence_ids=normative_ids,
                        )
                    ),
                    context=f"{group_id}: {dimension} assessment batch {batch_number}",
                )
                record_chat(
                    "assess",
                    f"{group_id}-{dimension}-B{batch_number:03d}",
                    exchanges,
                )
                group_assessments.extend(rows)
        assessment_by_id = {row["proposal_id"]: row for row in group_assessments}
        if set(assessment_by_id) != set(proposals_by_id):
            raise GroupOracleError(f"{group_id}: proposal assessment coverage mismatch")
        for proposal_id, proposal in proposals_by_id.items():
            origin_evidence_ids = set(proposal.get("origin_evidence_ids", []))
            assessment = assessment_by_id[proposal_id]
            if (
                origin_evidence_ids
                and assessment["decision"] == "add"
                and not origin_evidence_ids <= set(assessment["evidence_ids"])
                and proposal_id not in continuity_proposal_ids
            ):
                raise GroupOracleError(
                    f"{group_id}: added evidence-origin proposal omits its source evidence"
                )
        edges = sorted(
            (row["proposal_id"], row["selected_proposal_id"])
            for row in group_assessments
            if row["decision"] == "already-covered"
            and row["proposal_id"] not in forced_proposal_ids
            and row["selected_proposal_id"] not in forced_proposal_ids
        )
        components = _connected_components(edges)
        component_members = {item for component in components for item in component}
        final_clusters: list[dict[str, Any]] = []
        for component_number, component in enumerate(components, 1):
            nodes, current_summary_calls = _summarize_component(
                component=component,
                proposals_by_id=proposals_by_id,
                runner=runner,
                chat=record_chat,
                group_id=group_id,
                component_number=component_number,
            )
            summary_calls += current_summary_calls
            user = build_component_user(
                group=group,
                proposal_ids=component,
                nodes=nodes,
                evidence=evidence,
                st=sink_type,
            )
            clusters, exchanges = _validated_call(
                runner=runner,
                system=COMPONENT_SYSTEM,
                user=user,
                validator=lambda response, ids=set(component), evidence_ids=allowed_evidence_ids, normative_ids=authoritative_evidence_ids: (
                    validate_component_response(
                        response,
                        expected_proposal_ids=ids,
                        allowed_evidence_ids=evidence_ids,
                        normative_evidence_ids=normative_ids,
                    )
                ),
                context=f"{group_id}: component {component_number}",
            )
            component_calls += 1
            record_chat("component", f"{group_id}-C{component_number:03d}", exchanges)
            final_clusters.extend(clusters)
        for proposal_id in sorted(set(proposals_by_id) - component_members):
            proposal = proposals_by_id[proposal_id]
            assessment = assessment_by_id[proposal_id]
            forced = proposal_id in forced_proposal_ids
            final_clusters.append(
                {
                    "proposal_ids": [proposal_id],
                    "decision": "add" if forced else assessment["decision"],
                    "dimension": proposal["dimension"],
                    "rule": proposal["rule"],
                    "applicability": proposal["applicability"],
                    "evidence_ids": (
                        proposal.get("origin_evidence_ids", [])
                        if forced
                        else assessment["evidence_ids"]
                    ),
                    "reason": (
                        (
                            "Preserved by content-bound requirement continuity."
                            if proposal_id in continuity_proposal_ids
                            else "Committed by the source-reviewed correction-v2 ledger."
                        )
                        if forced
                        else assessment["reason"]
                    ),
                }
            )
        if observed_gates_only:
            final_clusters = consolidate_policies(
                group=group, chains=group_chains, clusters=final_clusters,
                proposals=proposals_by_id, evidence=evidence, runner=runner,
                validated_call=_validated_call, record_chat=record_chat,
                token_limit=input_token_limit,
            )
        final_requirements: list[dict[str, Any]] = []
        rejected_ids: set[str] = set()
        final_requirement_by_proposal: dict[str, str] = {}
        final_cluster_by_proposal: dict[str, dict[str, Any]] = {}
        for cluster in sorted(final_clusters, key=lambda row: row["proposal_ids"]):
            cluster_ids = cluster["proposal_ids"]
            for proposal_id in cluster_ids:
                final_cluster_by_proposal[proposal_id] = cluster
            if (
                cluster["decision"] != "add"
                or not cluster["evidence_ids"]
                or not set(cluster["evidence_ids"]) & authoritative_evidence_ids
            ):
                rejected_ids.update(cluster_ids)
                continue
            requirement_id = stable_requirement_id(
                cluster["dimension"], cluster["rule"], cluster["applicability"]
            )
            origin_refs = sorted(
                {
                    canonical_json(ref): ref
                    for proposal_id in cluster_ids
                    for ref in proposals_by_id[proposal_id]["origin_chain_refs"]
                }.values(),
                key=lambda row: (row["project"], row["chain_id"]),
            )
            gate_ids = sorted(
                {
                    gate_id
                    for proposal_id in cluster_ids
                    for gate_id in proposals_by_id[proposal_id]["origin_gate_ids"]
                }
            )
            final_requirements.append(
                {
                    "requirement_id": requirement_id,
                    "dimension": cluster["dimension"],
                    "rule": cluster["rule"],
                    "applicability": cluster["applicability"],
                    "evidence_ids": cluster["evidence_ids"],
                    "source_proposal_ids": cluster_ids,
                    "origin_chain_refs": origin_refs,
                    "origin_gate_ids": gate_ids,
                }
            )
            for proposal_id in cluster_ids:
                final_requirement_by_proposal[proposal_id] = requirement_id
        requirements_by_id: dict[str, dict[str, Any]] = {}
        for requirement in final_requirements:
            prior = requirements_by_id.get(requirement["requirement_id"])
            if prior is None:
                requirements_by_id[requirement["requirement_id"]] = requirement
                continue
            if any(
                prior[field] != requirement[field]
                for field in ("dimension", "rule", "applicability")
            ):
                raise GroupOracleError(f"{group_id}: requirement ID collision")
            prior["evidence_ids"] = sorted(
                set(prior["evidence_ids"]) | set(requirement["evidence_ids"])
            )
            prior["source_proposal_ids"] = sorted(
                set(prior["source_proposal_ids"])
                | set(requirement["source_proposal_ids"])
            )
            prior["origin_chain_refs"] = sorted(
                {
                    canonical_json(ref): ref
                    for ref in [
                        *prior["origin_chain_refs"],
                        *requirement["origin_chain_refs"],
                    ]
                }.values(),
                key=lambda row: (row["project"], row["chain_id"]),
            )
            prior["origin_gate_ids"] = sorted(
                set(prior["origin_gate_ids"]) | set(requirement["origin_gate_ids"])
            )
        for proposal_id, row in sorted(assessment_by_id.items()):
            final_cluster = final_cluster_by_proposal[proposal_id]
            requirement_id = final_requirement_by_proposal.get(proposal_id)
            if requirement_id is not None:
                representative = min(
                    requirements_by_id[requirement_id]["source_proposal_ids"]
                )
                decision = "add" if proposal_id == representative else "already-covered"
                selected = None if proposal_id == representative else representative
            else:
                decision = "reject"
                selected = None
            assessments.append(
                {
                    "schema_version": ASSESSMENT_SCHEMA_VERSION,
                    "group_id": group_id,
                    "proposal_id": proposal_id,
                    "decision": decision,
                    "selected_proposal_id": selected,
                    "evidence_ids": final_cluster["evidence_ids"],
                    "reason": final_cluster["reason"],
                    "final_requirement_id": requirement_id,
                }
            )
        if correction_locators:
            required_evidence_ids = {
                evidence_by_locator[locator]["evidence_id"]
                for locator in correction_locators
            }
            committed_evidence_ids = {
                evidence_id
                for requirement in requirements_by_id.values()
                for evidence_id in requirement["evidence_ids"]
            }
            if not required_evidence_ids <= committed_evidence_ids:
                raise GroupOracleError(
                    f"{group_id}: source-backed correction requirements were rejected"
                )
        status = (
            "partial"
            if any(row.semantic_ir["status"] == "partial" for row in group_chains)
            or bool(rejected_ids)
            or not requirements_by_id
            else "complete"
        )
        oracles.append(
            {
                "schema_version": ORACLE_SCHEMA_VERSION,
                "group_id": group_id,
                "handler_criterion_id": group["handler_criterion_id"],
                "sink_type_id": group["sink_type_id"],
                "status": status,
                "seed": {**_chain_ref(seed), "selection_policy": selection_policy},
                "member_chain_refs": [_chain_ref(row) for row in group_chains],
                "requirements": sorted(
                    requirements_by_id.values(),
                    key=lambda row: row["requirement_id"],
                ),
                "rejected_proposal_ids": sorted(rejected_ids),
            }
        )
    exclusions = [
        {
            "schema_version": EXCLUSION_SCHEMA_VERSION,
            "group_id": group["handler_sink_group_id"],
            "handler_criterion_id": group["handler_criterion_id"],
            "sink_type_id": None,
            "group_scope": group["group_scope"],
            "downstream_oracle_eligible": False,
            "chain_count": group["chain_count"],
            "chain_refs": group["chain_refs"],
            "reason_code": "no-security-impact",
            "detail": group["reason"],
        }
        for group in inputs.excluded_groups
    ]
    oracles.sort(key=lambda row: row["group_id"])
    seeds.sort(key=lambda row: row["group_id"])
    proposals.sort(key=lambda row: (row["group_id"], row["proposal_id"]))
    assessments.sort(key=lambda row: (row["group_id"], row["proposal_id"]))
    exclusions.sort(key=lambda row: row["group_id"])
    expected_security, expected_excluded = _input_group_maps(inputs)
    empty_requirement_evidence = [
        (oracle["group_id"], requirement["requirement_id"])
        for oracle in oracles
        for requirement in oracle["requirements"]
        if not requirement["evidence_ids"]
    ]
    if empty_requirement_evidence:
        raise GroupOracleError(
            "requirements must retain current evidence: "
            + ", ".join(
                f"{group_id}:{requirement_id}"
                for group_id, requirement_id in empty_requirement_evidence
            )
        )
    if observed_gates_only and any(
        not requirement["origin_gate_ids"]
        for oracle in oracles
        for requirement in oracle["requirements"]
    ):
        raise GroupOracleError("observed-gates-only requirements must retain an observed origin gate")
    validate_artifacts(
        oracles=oracles,
        seeds=seeds,
        proposals=proposals,
        assessments=assessments,
        exclusions=exclusions,
        evidence_index=inputs.evidence_index,
        expected_security_groups=expected_security,
        expected_excluded_groups=expected_excluded,
    )
    report = render_oracle_index(
        generation_command=generation_command,
        oracles=oracles,
        exclusions=exclusions,
        proposals=proposals,
        evidence_index=inputs.evidence_index,
    )
    transport = (
        runner.audit_payload()
        if callable(getattr(runner, "audit_payload", None))
        else {"transport": "injected-runner", "available_tools": []}
    )
    estimated_input_tokens = sum(
        estimate_tokens({"system": exchange["system"], "user": exchange["user"]})
        for exchanges in chats.values()
        for exchange in exchanges
    )
    estimated_output_tokens = sum(
        estimate_tokens(exchange["response"])
        for exchanges in chats.values()
        for exchange in exchanges
    )
    token_usage = transport.setdefault("token_usage", {})
    transport_calls = transport.get("calls", [])
    provider_call_count = (
        sum(
            isinstance(row, dict) and isinstance(row.get("usage"), dict)
            for row in transport_calls
        )
        if isinstance(transport_calls, list)
        else 0
    )
    token_usage.update(
        {
            "estimated_full_run": True,
            "estimated_input_tokens": estimated_input_tokens,
            "estimated_output_tokens": estimated_output_tokens,
            "estimated_total_tokens": estimated_input_tokens + estimated_output_tokens,
            "provider_reported_call_count": provider_call_count,
            "provider_reported_call_scope": (
                "full-run"
                if provider_call_count == sum(len(rows) for rows in chats.values())
                else "live-subset-after-replay"
            ),
        }
    )
    counts = {
        "input_handler_sink_groups": len(inputs.security_groups)
        + len(inputs.excluded_groups),
        "eligible_security_groups": len(inputs.security_groups),
        "eligible_chains": sum(row["chain_count"] for row in inputs.security_groups),
        "group_oracles": len(oracles),
        "complete_oracles": sum(row["status"] == "complete" for row in oracles),
        "partial_oracles": sum(row["status"] == "partial" for row in oracles),
        "excluded_no_security_impact_groups": len(exclusions),
        "excluded_no_security_impact_chains": sum(
            row["chain_count"] for row in exclusions
        ),
        "seed_profiles": len(seeds),
        "peer_batches": peer_batches,
        "proposals": len(proposals),
        "proposal_assessment_batches": assessment_batches,
        "proposal_assessments": len(assessments),
        "component_adjudications": component_calls,
        "policy_consolidation_requests": sum(stage == "policy" for stage, _ in chats),
        "evidence_extension_requests": evidence_extension_calls,
        "evidence_extension_proposals": evidence_extension_proposals,
        "summary_interactions": summary_calls,
        "requirements": sum(len(row["requirements"]) for row in oracles),
        "distinct_requirements": len(
            {item["requirement_id"] for row in oracles for item in row["requirements"]}
        ),
        "rejected_proposals": sum(len(row["rejected_proposal_ids"]) for row in oracles),
        "evidence_records": len(inputs.evidence_index["evidence"]),
        "content_bound_reused_groups": len(reusable_group_ids),
        "inferred_groups": len(inputs.security_groups) - len(reusable_group_ids),
        "primary_requests": len(chats),
        "model_calls": sum(len(rows) for rows in chats.values()),
        "executed_model_calls": getattr(runner, "calls", sum(len(rows) for rows in chats.values())),
        "repair_calls": sum(len(rows) - 1 for rows in chats.values()),
    }
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "construction_policy_sha256": _construction_policy_sha256(),
        "observed_gates_only": observed_gates_only,
        "gate_qualification": qualification_audit,
        "generation_command": generation_command,
        "group_key": ["handler_criterion_id", "sink_type_id"],
        "group_id_field": "handler_sink_group_id",
        "input_token_limit": input_token_limit,
        "max_chains_per_peer_batch": BATCH_SIZE,
        "inputs": inputs.digests,
        "selection_scope": selection_scope,
        "outputs": {
            "oracles": str(out_dir / "oracles.jsonl"),
            "seed_profiles": str(out_dir / "seed-profiles.jsonl"),
            "proposals": str(out_dir / "proposals.jsonl"),
            "proposal_assessments": str(out_dir / "proposal-assessments.jsonl"),
            "excluded_groups": str(out_dir / "excluded-groups.jsonl"),
            "evidence_index": str(out_dir / "evidence-index.json"),
            "report": str(out_dir / "oracle-index.md"),
        },
        "counts": counts,
        "transport": transport,
    }
    if correction_binding is not None:
        manifest["analysis_mode"] = "post-hoc-correction-v2"
        manifest["post_hoc_ground_truth_informed"] = True
        manifest["correction"] = correction_binding
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{out_dir.name}.staging-", dir=out_dir.parent)
    )
    try:
        _write_jsonl(staging / "oracles.jsonl", oracles)
        _write_jsonl(staging / "seed-profiles.jsonl", seeds)
        _write_jsonl(staging / "proposals.jsonl", proposals)
        _write_jsonl(staging / "proposal-assessments.jsonl", assessments)
        _write_jsonl(staging / "excluded-groups.jsonl", exclusions)
        _write_json(staging / "evidence-index.json", inputs.evidence_index)
        _write_json(staging / "manifest.json", manifest)
        _write_text(staging / "oracle-index.md", report)
        for (stage, subject), exchanges in sorted(chats.items()):
            _write_json(
                staging / "repository" / stage / subject / "chat.json",
                {
                    "schema_version": CHAT_SCHEMA_VERSION,
                    "stage": stage,
                    "subject": subject,
                    "exchanges": exchanges,
                },
            )
        unsafe_paths = []
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            if contains_credentials(path.read_text(encoding="utf-8")):
                unsafe_paths.append(str(path.relative_to(staging)))
        if unsafe_paths:
            raise GroupOracleError(
                "credential-shaped data would enter group-oracle artifacts: "
                + ", ".join(unsafe_paths)
            )
        if publish:
            _publish_directory(staging, out_dir)
        else:
            shutil.rmtree(staging)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {"manifest": manifest, "report": report}
