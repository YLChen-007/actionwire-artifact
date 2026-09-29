"""Order-independent HC-conditioned global sink-type alignment."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from src.projects import ProjectSpec

from .contracts import (
    ASSESSMENT_SCHEMA_VERSION,
    CATALOG_SCHEMA_VERSION,
    CHAT_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    MAPPING_SCHEMA_VERSION,
    GROUP_SCHEMA_VERSION,
    SinkTypeAlignmentError,
    canonical_json,
    digest,
    parse_json_response,
    sha256_file,
    stable_proposal_id,
    stable_handler_sink_group_id,
    stable_sink_type_id,
    validate_canonicalize_response,
    validate_final_artifacts,
    validate_group_response,
    validate_handler_sink_groups,
    validate_match_response,
)
from .inputs import AlignmentInputs, SinkTarget, load_alignment_inputs
from .prompts import (
    CANONICALIZE_SYSTEM,
    COMPONENT_SYSTEM,
    MATCH_SYSTEM,
    RECONCILE_SYSTEM,
    REPAIR_SYSTEM,
    SEED_SYSTEM,
    build_canonicalize_user,
    build_component_user,
    build_match_user,
    build_reconcile_user,
    build_repair_user,
    build_seed_user,
    redact_credentials,
)
from .render import render_alignment_index


Runner = Callable[[str, str], str]
SEED_PROJECT = "nanobot"
BATCH_SIZE = 8
MATCHED_ON = ["capability", "controlled_parameter", "defaults", "call_shape"]
IDENTITY_BINDING_SCHEMA_VERSION = "sink-type-identity-binding/v1"


def _build_handler_sink_groups(
    mappings: Sequence[dict[str, Any]],
    *,
    eligible_chains: Sequence[dict[str, Any]],
    non_security_chains: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project chain mappings onto security and terminal no-impact groups."""

    eligible_by_chain = {
        (row["project"], row["chain_id"]): row for row in eligible_chains
    }
    buckets: dict[tuple[str, str, str | None], list[dict[str, Any]]] = defaultdict(list)
    for mapping in mappings:
        chain = eligible_by_chain[(mapping["project"], mapping["chain_id"])]
        buckets[
            ("security", mapping["handler_criterion_id"], mapping["sink_type_id"])
        ].append(chain)
    for chain in non_security_chains:
        buckets[("no-security-impact", chain["handler_criterion_id"], None)].append(
            chain
        )
    groups: list[dict[str, Any]] = []
    for (scope, hc, sink_type_id), rows in sorted(
        buckets.items(), key=lambda item: (item[0][0], item[0][1], item[0][2] or "")
    ):
        chain_refs = sorted(
            ({"project": row["project"], "chain_id": row["chain_id"]} for row in rows),
            key=lambda row: (row["project"], row["chain_id"]),
        )
        groups.append(
            {
                "schema_version": GROUP_SCHEMA_VERSION,
                "handler_sink_group_id": stable_handler_sink_group_id(
                    scope, hc, sink_type_id
                ),
                "group_scope": scope,
                "handler_criterion_id": hc,
                "sink_type_id": sink_type_id,
                "downstream_oracle_eligible": scope == "security",
                "chain_count": len(rows),
                "chain_refs": chain_refs,
                "projects": sorted({row["project"] for row in rows}),
                "handler_ids": sorted({row["handler_id"] for row in rows}),
                "handler_names": sorted({row["handler_name"] for row in rows}),
                "sink_refs": sorted(
                    {f"{row['project']}:{row['sink_id']}" for row in rows}
                ),
                "sink_names": sorted({row["sink_name"] for row in rows}),
                "reason": (
                    "Security-relevant chains share the same global HC/ST oracle key."
                    if scope == "security"
                    else "Handler impact primary and challenger classified every "
                    "reachable sink as no-security-impact; retain this terminal group "
                    "for accounting but do not send it to the downstream security oracle."
                ),
            }
        )
    return groups


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: object) -> None:
    _write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, values: Sequence[object]) -> None:
    _write_text(path, "".join(canonical_json(row) + "\n" for row in values))


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
            raise SinkTypeAlignmentError(
                f"{context}: unrepaired sink-alignment response: "
                f"{type(second).__name__}: {second}"
            ) from second


def _family(
    *,
    family_id: str,
    origin: str,
    criterion: Mapping[str, Any],
    target_ids: Sequence[str],
    targets_by_id: Mapping[str, SinkTarget],
    reason: str,
    evidence: Sequence[str],
) -> dict[str, Any]:
    members = sorted(set(target_ids))
    if not members or len(members) != len(target_ids):
        raise SinkTypeAlignmentError("sink family targets must be non-empty and unique")
    representative_target_id = min(
        members,
        key=lambda target_id: (
            targets_by_id[target_id].project,
            targets_by_id[target_id].sink_id,
            targets_by_id[target_id].handler_criterion_id,
            target_id,
        ),
    )
    return {
        "family_id": family_id,
        "origin": origin,
        "criterion": dict(criterion),
        "target_ids": members,
        "representative_target_id": representative_target_id,
        "handler_criterion_ids": sorted(
            {targets_by_id[target_id].handler_criterion_id for target_id in members}
        ),
        "reason": reason,
        "evidence": list(evidence),
    }


def _merge_family_rows(
    rows: Sequence[dict[str, Any]],
    *,
    family_id: str,
    origin: str,
    criterion: Mapping[str, Any],
    targets_by_id: Mapping[str, SinkTarget],
    reason: str,
    evidence: Sequence[str],
) -> dict[str, Any]:
    return _family(
        family_id=family_id,
        origin=origin,
        criterion=criterion,
        target_ids=sorted(
            {target for row in rows for target in row["target_ids"]}
        ),
        targets_by_id=targets_by_id,
        reason=reason,
        evidence=evidence,
    )


def _connected_components(edges: Sequence[tuple[str, str]]) -> list[list[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for left, right in edges:
        graph[left].add(right)
        graph[right].add(left)
    components: list[list[str]] = []
    visited: set[str] = set()
    for root in sorted(graph):
        if root in visited:
            continue
        queue = deque([root])
        visited.add(root)
        component: list[str] = []
        while queue:
            node = queue.popleft()
            component.append(node)
            for neighbor in sorted(graph[node]):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        components.append(sorted(component))
    return components


def _merge_exact_identity(
    families: Sequence[dict[str, Any]],
    targets_by_id: Mapping[str, SinkTarget],
) -> tuple[list[dict[str, Any]], int]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in families:
        grouped[stable_sink_type_id(row["criterion"])].append(row)
    output: list[dict[str, Any]] = []
    merges = 0
    for sink_type_id in sorted(grouped):
        rows = grouped[sink_type_id]
        anchors = [row for row in rows if row["origin"] == "nanobot-seed"]
        representative = min(rows, key=lambda row: row["representative_target_id"])
        criterion = anchors[0]["criterion"] if anchors else representative["criterion"]
        origin = "nanobot-seed" if anchors else "external-global"
        output.append(
            _merge_family_rows(
                rows,
                family_id=sink_type_id,
                origin=origin,
                criterion=criterion,
                targets_by_id=targets_by_id,
                reason=representative["reason"],
                evidence=representative["evidence"],
            )
        )
        merges += len(rows) - 1
    return output, merges


def _merge_same_concrete_sink(
    families: Sequence[dict[str, Any]],
    targets_by_id: Mapping[str, SinkTarget],
) -> tuple[list[dict[str, Any]], int]:
    """Force one global ST for the same revision-bound concrete sink."""

    parents = list(range(len(families)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    owner_by_sink: dict[tuple[str, str, str], int] = {}
    semantics_by_sink: dict[tuple[str, str, str], str] = {}
    for index, family in enumerate(families):
        for target_id in family["target_ids"]:
            target = targets_by_id[target_id]
            sink_key = (target.project, target.revision, target.sink_id)
            semantics = canonical_json(
                {
                    "sink_constraint": target.sink_constraint,
                    "capability_card": target.capability_card,
                }
            )
            previous_semantics = semantics_by_sink.setdefault(sink_key, semantics)
            if previous_semantics != semantics:
                raise SinkTypeAlignmentError(
                    f"{target.project}:{target.sink_id}: identical concrete sink "
                    "has conflicting semantic inputs"
                )
            previous = owner_by_sink.setdefault(sink_key, index)
            union(index, previous)

    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, family in enumerate(families):
        grouped[find(index)].append(family)
    output: list[dict[str, Any]] = []
    merges = 0
    for rows in grouped.values():
        if len(rows) == 1:
            output.append(rows[0])
            continue
        anchors = [row for row in rows if row["origin"] == "nanobot-seed"]
        criterion_source = min(
            anchors or rows, key=lambda row: row["representative_target_id"]
        )
        target_ids = sorted(
            {target_id for row in rows for target_id in row["target_ids"]}
        )
        family_indexes_by_sink: dict[tuple[str, str], set[int]] = defaultdict(set)
        for row_index, row in enumerate(rows):
            for target_id in row["target_ids"]:
                target = targets_by_id[target_id]
                family_indexes_by_sink[(target.project, target.sink_id)].add(row_index)
        shared_sinks = [
            f"{project}:{sink_id}"
            for (project, sink_id), indexes in sorted(family_indexes_by_sink.items())
            if len(indexes) > 1
        ]
        output.append(
            _family(
                family_id=stable_sink_type_id(criterion_source["criterion"]),
                origin=("nanobot-seed" if anchors else "external-global"),
                criterion=criterion_source["criterion"],
                target_ids=target_ids,
                targets_by_id=targets_by_id,
                reason=(
                    "Deterministic global merge for identical revision-bound "
                    "concrete sink identity."
                ),
                evidence=shared_sinks,
            )
        )
        merges += len(rows) - 1
    return sorted(output, key=lambda row: row["family_id"]), merges


def _publish_directory(staging: Path, out_dir: Path) -> None:
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    backup = out_dir.parent / f".{out_dir.name}.previous"
    if backup.exists():
        raise SinkTypeAlignmentError(f"stale publication backup exists: {backup}")
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


def _semantic_input_digest(target: SinkTarget) -> str:
    """Bind ST reuse to concrete sink semantics while excluding the HC axis."""

    payload = json.loads(
        redact_credentials(
            json.dumps(target.prompt_payload(), ensure_ascii=False, sort_keys=True)
        )
    )
    return digest(
        {
            "project": target.project,
            "revision": target.revision,
            "sink_id": target.sink_id,
            "sink_constraint": payload["sink_constraint"],
            "capability_card_markdown": payload["capability_card_markdown"],
        }
    )


def _load_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SinkTypeAlignmentError(
                f"invalid prior alignment row {path}:{number}: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise SinkTypeAlignmentError(
                f"invalid prior alignment row {path}:{number}: expected object"
            )
        rows.append(row)
    return rows


def _prior_prompt_semantic_digests(
    repository: Path,
    assessments_by_target: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    """Bootstrap HC-independent bindings from the prior audited canonical prompts."""

    output: dict[str, str] = {}
    if not repository.is_dir():
        return output
    for path in sorted(repository.glob("*/chat.json")):
        try:
            chat = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SinkTypeAlignmentError(
                f"invalid prior sink-alignment sidecar {path}: {exc}"
            ) from exc
        if chat.get("schema_version") != CHAT_SCHEMA_VERSION:
            raise SinkTypeAlignmentError(
                f"unsupported prior sink-alignment sidecar {path}"
            )
        exchanges = chat.get("exchanges")
        if not isinstance(exchanges, list):
            raise SinkTypeAlignmentError(
                f"invalid prior sink-alignment exchanges {path}"
            )
        for exchange in exchanges:
            if not isinstance(exchange, dict) or not isinstance(
                exchange.get("user"), str
            ):
                raise SinkTypeAlignmentError(
                    f"invalid prior sink-alignment exchange {path}"
                )
            try:
                request = json.loads(exchange["user"])
            except json.JSONDecodeError:
                continue
            targets = request.get("targets") if isinstance(request, dict) else None
            if not isinstance(targets, list):
                continue
            for payload in targets:
                if not isinstance(payload, dict):
                    raise SinkTypeAlignmentError(
                        f"invalid prior canonical target payload {path}"
                    )
                target_id = payload.get("target_id")
                assessment = assessments_by_target.get(str(target_id))
                required = {
                    "project",
                    "sink_id",
                    "sink_constraint",
                    "capability_card_markdown",
                }
                if assessment is None or not required <= set(payload):
                    raise SinkTypeAlignmentError(
                        f"unbound prior canonical target {target_id!r} in {path}"
                    )
                semantic_digest = digest(
                    {
                        "project": payload["project"],
                        "revision": assessment["revision"],
                        "sink_id": payload["sink_id"],
                        "sink_constraint": payload["sink_constraint"],
                        "capability_card_markdown": payload[
                            "capability_card_markdown"
                        ],
                    }
                )
                prior = output.setdefault(str(target_id), semantic_digest)
                if prior != semantic_digest:
                    raise SinkTypeAlignmentError(
                        f"conflicting prior semantic payloads for {target_id}"
                    )
    return output


def _load_prior_alignment(
    out_dir: Path,
    targets: Sequence[SinkTarget],
) -> dict[str, Any]:
    """Load content-bound ST assignments from the currently published alignment."""

    catalog_path = out_dir / "catalog.json"
    assessments_path = out_dir / "assessments.jsonl"
    if not catalog_path.exists() and not assessments_path.exists():
        return {
            "catalog": {},
            "matches": {},
            "digests": {},
            "binding_source": "none",
        }
    if not catalog_path.is_file() or not assessments_path.is_file():
        raise SinkTypeAlignmentError(
            "prior sink alignment is incomplete; catalog and assessments are both required"
        )
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SinkTypeAlignmentError(f"invalid prior sink catalog: {exc}") from exc
    rows = catalog.get("sink_types") if isinstance(catalog, dict) else None
    if catalog.get("schema_version") != CATALOG_SCHEMA_VERSION or not isinstance(
        rows, list
    ):
        raise SinkTypeAlignmentError("unsupported prior sink catalog")
    catalog_by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise SinkTypeAlignmentError("invalid prior sink catalog row")
        sink_type_id = row.get("sink_type_id")
        criterion = row.get("criterion")
        if (
            not isinstance(sink_type_id, str)
            or not isinstance(criterion, dict)
            or stable_sink_type_id(criterion) != sink_type_id
            or sink_type_id in catalog_by_id
        ):
            raise SinkTypeAlignmentError(
                f"invalid prior sink catalog identity {sink_type_id!r}"
            )
        catalog_by_id[sink_type_id] = row

    assessments = _load_jsonl_rows(assessments_path)
    assessments_by_target: dict[str, dict[str, Any]] = {}
    for row in assessments:
        target_id = row.get("target_id")
        sink_type_id = row.get("sink_type_id")
        if (
            not isinstance(target_id, str)
            or target_id in assessments_by_target
            or sink_type_id not in catalog_by_id
        ):
            raise SinkTypeAlignmentError(
                f"invalid prior sink assessment binding {target_id!r}"
            )
        assessments_by_target[target_id] = row

    binding_path = out_dir / "identity-reuse.jsonl"
    semantic_by_target: dict[str, str] = {}
    binding_source = "audited-canonical-prompts"
    if binding_path.is_file():
        binding_source = IDENTITY_BINDING_SCHEMA_VERSION
        for row in _load_jsonl_rows(binding_path):
            if set(row) != {
                "schema_version",
                "target_id",
                "project",
                "revision",
                "sink_id",
                "semantic_input_digest",
                "sink_type_id",
            } or row.get("schema_version") != IDENTITY_BINDING_SCHEMA_VERSION:
                raise SinkTypeAlignmentError("invalid prior ST identity binding row")
            target_id = row["target_id"]
            assessment = assessments_by_target.get(target_id)
            if (
                assessment is None
                or row["sink_type_id"] != assessment["sink_type_id"]
                or any(
                    row[field] != assessment[field]
                    for field in ("project", "revision", "sink_id")
                )
                or not isinstance(row["semantic_input_digest"], str)
                or len(row["semantic_input_digest"]) != 64
            ):
                raise SinkTypeAlignmentError(
                    f"stale prior ST identity binding {target_id!r}"
                )
            semantic_by_target[target_id] = row["semantic_input_digest"]
        if set(semantic_by_target) != set(assessments_by_target):
            raise SinkTypeAlignmentError(
                "prior ST identity bindings do not cover every assessment"
            )
    else:
        semantic_by_target = _prior_prompt_semantic_digests(
            out_dir / "repository", assessments_by_target
        )

    exact_by_target = assessments_by_target
    concrete: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for target_id, semantic_digest in semantic_by_target.items():
        assessment = assessments_by_target[target_id]
        key = (
            assessment["project"],
            assessment["revision"],
            assessment["sink_id"],
            semantic_digest,
        )
        prior = concrete.setdefault(key, assessment)
        if prior["sink_type_id"] != assessment["sink_type_id"]:
            raise SinkTypeAlignmentError(
                "one prior concrete sink semantic identity maps to multiple STs"
            )

    matches: dict[str, dict[str, Any]] = {}
    for target in targets:
        prior = exact_by_target.get(target.target_id)
        if prior is not None and prior.get("input_digest") == target.input_digest:
            matches[target.target_id] = {
                "assessment": prior,
                "prior_target_id": target.target_id,
                "reuse_kind": "exact-target-input",
            }
            continue
        semantic_digest = _semantic_input_digest(target)
        prior = concrete.get(
            (target.project, target.revision, target.sink_id, semantic_digest)
        )
        if prior is not None:
            matches[target.target_id] = {
                "assessment": prior,
                "prior_target_id": prior["target_id"],
                "reuse_kind": "concrete-sink-semantic",
            }
    digests = {
        "catalog": sha256_file(catalog_path),
        "assessments": sha256_file(assessments_path),
    }
    if binding_path.is_file():
        digests["identity_reuse"] = sha256_file(binding_path)
    return {
        "catalog": catalog_by_id,
        "matches": matches,
        "digests": digests,
        "binding_source": binding_source,
    }


def run_sink_type_alignment(
    *,
    specs: Sequence[ProjectSpec],
    handler_root: Path,
    out_dir: Path,
    generation_command: str,
    runner: Runner,
    publish: bool = True,
) -> dict[str, Any]:
    inputs: AlignmentInputs = load_alignment_inputs(specs, handler_root)
    targets = sorted(inputs.targets, key=lambda row: row.target_id)
    targets_by_id = {row.target_id: row for row in targets}
    prior_alignment = _load_prior_alignment(out_dir, targets)
    reuse_matches: dict[str, dict[str, Any]] = prior_alignment["matches"]
    chats: dict[str, list[dict[str, str]]] = {}
    canonical: dict[str, dict[str, Any]] = {}
    canonical_reasons: dict[str, tuple[str, list[str]]] = {}
    for target_id, reuse in reuse_matches.items():
        assessment = reuse["assessment"]
        prior_type = prior_alignment["catalog"][assessment["sink_type_id"]]
        canonical[target_id] = prior_type["criterion"]
        canonical_reasons[target_id] = (
            assessment["reason"],
            assessment["evidence"],
        )
    canonical_batches = 0
    model_targets = [row for row in targets if row.target_id not in reuse_matches]
    for offset in range(0, len(model_targets), BATCH_SIZE):
        batch = model_targets[offset : offset + BATCH_SIZE]
        canonical_batches += 1
        rows, exchanges = _validated_call(
            runner=runner,
            system=CANONICALIZE_SYSTEM,
            user=build_canonicalize_user(batch),
            validator=lambda response, ids={row.target_id for row in batch}: (
                validate_canonicalize_response(response, ids)
            ),
            context=f"canonicalize batch {canonical_batches}",
        )
        chats[f"canonicalize-{canonical_batches:03d}"] = exchanges
        for row in rows:
            canonical[row["target_id"]] = row["criterion"]
            canonical_reasons[row["target_id"]] = (row["reason"], row["evidence"])
    if set(canonical) != set(targets_by_id):
        raise SinkTypeAlignmentError("canonicalization does not cover every sink target")

    frozen_anchor_by_id: dict[str, dict[str, Any]] = {}
    for sink_type_id, row in prior_alignment["catalog"].items():
        frozen_anchor_by_id[sink_type_id] = {
            "family_id": sink_type_id,
            "origin": row["origin"],
            "criterion": row["criterion"],
            "target_ids": [],
            "representative_target_id": "",
            "handler_criterion_ids": list(
                row["associated_handler_criterion_ids"]
            ),
            "reason": "Prior content-bound global sink-type anchor.",
            "evidence": [f"prior-catalog:{sink_type_id}"],
        }
    reused_by_type: dict[str, list[str]] = defaultdict(list)
    for target_id, reuse in reuse_matches.items():
        reused_by_type[reuse["assessment"]["sink_type_id"]].append(target_id)
    for sink_type_id, target_ids in sorted(reused_by_type.items()):
        prior_type = prior_alignment["catalog"][sink_type_id]
        representative = min(target_ids)
        prior_assessment = reuse_matches[representative]["assessment"]
        frozen_anchor_by_id[sink_type_id] = _family(
            family_id=sink_type_id,
            origin=prior_type["origin"],
            criterion=prior_type["criterion"],
            target_ids=target_ids,
            targets_by_id=targets_by_id,
            reason=prior_assessment["reason"],
            evidence=prior_assessment["evidence"],
        )

    seed_targets = [
        row
        for row in model_targets
        if row.project == SEED_PROJECT
    ]
    new_seed_families: list[dict[str, Any]] = []
    if seed_targets:
        seed_groups, exchanges = _validated_call(
            runner=runner,
            system=SEED_SYSTEM,
            user=build_seed_user(seed_targets, canonical),
            validator=lambda response: validate_group_response(
                response,
                expected_source_ids={row.target_id for row in seed_targets},
                allowed_anchor_ids=set(),
                source_field="target_ids",
            ),
            context="NanoBot sink seed clustering",
        )
        chats["seed-nanobot"] = exchanges
        for group in seed_groups:
            criterion = group["criterion"]
            sink_type_id = stable_sink_type_id(criterion)
            new_seed_families.append(
                _family(
                    family_id=sink_type_id,
                    origin="nanobot-seed",
                    criterion=criterion,
                    target_ids=group["source_ids"],
                    targets_by_id=targets_by_id,
                    reason=group["reason"],
                    evidence=group["evidence"],
                )
            )
    new_seed_families, seed_exact_merges = _merge_exact_identity(
        new_seed_families, targets_by_id
    )
    for seed in new_seed_families:
        prior = frozen_anchor_by_id.get(seed["family_id"])
        if prior is not None and prior["target_ids"]:
            frozen_anchor_by_id[seed["family_id"]] = _merge_family_rows(
                [prior, seed],
                family_id=seed["family_id"],
                origin=prior["origin"],
                criterion=prior["criterion"],
                targets_by_id=targets_by_id,
                reason=seed["reason"],
                evidence=seed["evidence"],
            )
        else:
            frozen_anchor_by_id[seed["family_id"]] = seed
    anchors_by_hc: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for family in frozen_anchor_by_id.values():
        for hc in family["handler_criterion_ids"]:
            anchors_by_hc[hc].append(family)

    external_by_hc: dict[str, list[SinkTarget]] = defaultdict(list)
    for target in model_targets:
        if target.project != SEED_PROJECT:
            external_by_hc[target.handler_criterion_id].append(target)
    provisional: list[dict[str, Any]] = []
    anchored_additions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    reconciliation_batches = 0
    for hc in sorted(external_by_hc):
        sources = sorted(external_by_hc[hc], key=lambda row: row.target_id)
        anchors = sorted(anchors_by_hc.get(hc, []), key=lambda row: row["family_id"])
        allowed_anchors = {row["family_id"] for row in anchors}
        for offset in range(0, len(sources), BATCH_SIZE):
            batch = sources[offset : offset + BATCH_SIZE]
            reconciliation_batches += 1
            groups, exchanges = _validated_call(
                runner=runner,
                system=RECONCILE_SYSTEM,
                user=build_reconcile_user(hc, batch, canonical, anchors),
                validator=lambda response, ids={row.target_id for row in batch}, allowed=allowed_anchors: (
                    validate_group_response(
                        response,
                        expected_source_ids=ids,
                        allowed_anchor_ids=allowed,
                        source_field="target_ids",
                    )
                ),
                context=f"{hc}: external reconciliation batch {reconciliation_batches}",
            )
            chats[f"reconcile-{hc}-{offset // BATCH_SIZE + 1:03d}"] = exchanges
            for group in groups:
                anchor_id = group["anchor_sink_type_id"]
                if anchor_id is not None:
                    anchored_additions[anchor_id].append(
                        _family(
                            family_id=anchor_id,
                            origin="nanobot-seed",
                            criterion=next(
                                row["criterion"] for row in anchors if row["family_id"] == anchor_id
                            ),
                            target_ids=group["source_ids"],
                            targets_by_id=targets_by_id,
                            reason=group["reason"],
                            evidence=group["evidence"],
                        )
                    )
                else:
                    proposal_id = stable_proposal_id(group["source_ids"])
                    provisional.append(
                        _family(
                            family_id=proposal_id,
                            origin="external-global",
                            criterion=group["criterion"],
                            target_ids=group["source_ids"],
                            targets_by_id=targets_by_id,
                            reason=group["reason"],
                            evidence=group["evidence"],
                        )
                    )
    expanded_anchors: list[dict[str, Any]] = []
    for anchor in frozen_anchor_by_id.values():
        additions = anchored_additions.get(anchor["family_id"], [])
        current_rows = ([anchor] if anchor["target_ids"] else []) + additions
        if not current_rows:
            continue
        expanded_anchors.append(
            _merge_family_rows(
                current_rows,
                family_id=anchor["family_id"],
                origin=anchor["origin"],
                criterion=anchor["criterion"],
                targets_by_id=targets_by_id,
                reason=(additions[0]["reason"] if additions else anchor["reason"]),
                evidence=(
                    additions[0]["evidence"] if additions else anchor["evidence"]
                ),
            )
        )

    initial_families = sorted(
        [*expanded_anchors, *provisional], key=lambda row: row["family_id"]
    )
    initial_by_id = {row["family_id"]: row for row in initial_families}
    if len(initial_by_id) != len(initial_families):
        raise SinkTypeAlignmentError("initial sink families contain duplicate IDs")
    proposal_ids = sorted(row["family_id"] for row in provisional)
    match_rows: list[dict[str, Any]] = []
    proposal_match_batches = 0
    for offset in range(0, len(proposal_ids), BATCH_SIZE):
        batch_ids = proposal_ids[offset : offset + BATCH_SIZE]
        proposal_match_batches += 1
        rows, exchanges = _validated_call(
            runner=runner,
            system=MATCH_SYSTEM,
            user=build_match_user(batch_ids, initial_families, targets_by_id),
            validator=lambda response, ids=set(batch_ids), allowed=set(initial_by_id): (
                validate_match_response(
                    response,
                    expected_proposal_ids=ids,
                    allowed_candidate_ids=allowed,
                )
            ),
            context=f"global proposal match batch {proposal_match_batches}",
        )
        chats[f"match-{proposal_match_batches:03d}"] = exchanges
        match_rows.extend(rows)
    edges = [
        (row["proposal_id"], row["selected_id"])
        for row in match_rows
        if row["verdict"] == "matched"
    ]
    components = _connected_components(edges)
    consumed_proposals: set[str] = set()
    component_families: list[dict[str, Any]] = []
    component_calls = 0
    for component in components:
        source_ids = {row for row in component if row.startswith("SP-")}
        anchor_ids = {row for row in component if row.startswith("ST-")}
        if not source_ids:
            continue
        component_calls += 1
        groups, exchanges = _validated_call(
            runner=runner,
            system=COMPONENT_SYSTEM,
            user=build_component_user(component, initial_by_id, targets_by_id),
            validator=lambda response, sources=source_ids, anchors=anchor_ids: (
                validate_group_response(
                    response,
                    expected_source_ids=sources,
                    allowed_anchor_ids=anchors,
                    source_field="source_ids",
                )
            ),
            context=f"proposal component {component_calls}",
        )
        chats[f"component-{component_calls:03d}"] = exchanges
        consumed_proposals.update(source_ids)
        for group in groups:
            anchor_id = group["anchor_sink_type_id"]
            source_rows = [initial_by_id[row] for row in group["source_ids"]]
            if anchor_id is not None:
                anchor = initial_by_id[anchor_id]
                component_families.append(
                    _merge_family_rows(
                        [anchor, *source_rows],
                        family_id=anchor_id,
                        origin=anchor["origin"],
                        criterion=anchor["criterion"],
                        targets_by_id=targets_by_id,
                        reason=group["reason"],
                        evidence=group["evidence"],
                    )
                )
            else:
                target_ids = sorted(
                    {target for row in source_rows for target in row["target_ids"]}
                )
                component_families.append(
                    _family(
                        family_id=stable_proposal_id(target_ids),
                        origin="external-global",
                        criterion=group["criterion"],
                        target_ids=target_ids,
                        targets_by_id=targets_by_id,
                        reason=group["reason"],
                        evidence=group["evidence"],
                    )
                )
    frozen_ids = set(frozen_anchor_by_id)
    anchored_component_ids = {
        row["family_id"]
        for row in component_families
        if row["family_id"] in frozen_ids
    }
    final_prehashed = [
        row
        for row in expanded_anchors
        if row["family_id"] not in anchored_component_ids
    ]
    final_prehashed.extend(component_families)
    final_prehashed.extend(
        row for row in provisional if row["family_id"] not in consumed_proposals
    )
    final_families, exact_global_merges = _merge_exact_identity(
        final_prehashed, targets_by_id
    )
    final_families, concrete_sink_merges = _merge_same_concrete_sink(
        final_families, targets_by_id
    )
    final_families, post_concrete_exact_merges = _merge_exact_identity(
        final_families, targets_by_id
    )
    covered_targets = [
        target_id for row in final_families for target_id in row["target_ids"]
    ]
    if len(covered_targets) != len(set(covered_targets)) or set(covered_targets) != set(targets_by_id):
        raise SinkTypeAlignmentError("final sink families do not partition every target")

    catalog_rows: list[dict[str, Any]] = []
    family_by_target: dict[str, dict[str, Any]] = {}
    for family in sorted(final_families, key=lambda row: row["family_id"]):
        sink_type_id = stable_sink_type_id(family["criterion"])
        members = sorted(targets_by_id[target_id].member for target_id in family["target_ids"])
        representative_target = targets_by_id[family["representative_target_id"]]
        representative_sink = f"{representative_target.project}:{representative_target.sink_id}"
        catalog_rows.append(
            {
                "sink_type_id": sink_type_id,
                "origin": family["origin"],
                "criterion": family["criterion"],
                "representative_sink": representative_sink,
                "members": members,
                "associated_handler_criterion_ids": sorted(family["handler_criterion_ids"]),
            }
        )
        for target_id in family["target_ids"]:
            family_by_target[target_id] = {
                **family,
                "sink_type_id": sink_type_id,
                "reference_sink": representative_sink,
            }
    catalog_rows.sort(key=lambda row: row["sink_type_id"])
    catalog = {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "seed_project": SEED_PROJECT,
        "sink_types": catalog_rows,
    }
    identity_bindings = [
        {
            "schema_version": IDENTITY_BINDING_SCHEMA_VERSION,
            "target_id": target.target_id,
            "project": target.project,
            "revision": target.revision,
            "sink_id": target.sink_id,
            "semantic_input_digest": _semantic_input_digest(target),
            "sink_type_id": family_by_target[target.target_id]["sink_type_id"],
        }
        for target in targets
    ]
    assessments: list[dict[str, Any]] = []
    for target in targets:
        family = family_by_target[target.target_id]
        is_representative = target.target_id == family["representative_target_id"]
        decision = "new-type" if is_representative else "matched"
        reason, evidence = canonical_reasons[target.target_id]
        if family["reason"]:
            reason = family["reason"]
            evidence = family["evidence"]
        assessments.append(
            {
                "schema_version": ASSESSMENT_SCHEMA_VERSION,
                "target_id": target.target_id,
                "project": target.project,
                "revision": target.revision,
                "handler_criterion_id": target.handler_criterion_id,
                "handler_type_ids": list(target.handler_type_ids),
                "handler_ids": list(target.handler_ids),
                "sink_id": target.sink_id,
                "chain_ids": list(target.chain_ids),
                "input_digest": target.input_digest,
                "decision": decision,
                "sink_type_id": family["sink_type_id"],
                "reference_sink": family["reference_sink"],
                "matched_on": [] if decision == "new-type" else list(MATCHED_ON),
                "reason": reason,
                "evidence": evidence,
            }
        )
    assessments.sort(key=lambda row: row["target_id"])
    assessment_by_id = {row["target_id"]: row for row in assessments}
    target_by_chain = {
        (target.project, chain_id): target
        for target in targets
        for chain_id in target.chain_ids
    }
    mappings: list[dict[str, Any]] = []
    for chain in inputs.eligible_chains:
        target = target_by_chain[(chain["project"], chain["chain_id"])]
        assessment = assessment_by_id[target.target_id]
        mappings.append(
            {
                "schema_version": MAPPING_SCHEMA_VERSION,
                "project": chain["project"],
                "revision": chain["revision"],
                "chain_id": chain["chain_id"],
                "target_id": target.target_id,
                "sink_id": chain["sink_id"],
                "handler_id": chain["handler_id"],
                "handler_criterion_id": chain["handler_criterion_id"],
                "handler_type_id": chain["handler_type_id"],
                "decision": assessment["decision"],
                "sink_type_id": assessment["sink_type_id"],
                "reference_sink": assessment["reference_sink"],
                "matched_on": assessment["matched_on"],
                "reason": assessment["reason"],
                "evidence": assessment["evidence"],
            }
        )
    mappings.sort(key=lambda row: (row["project"], row["chain_id"]))
    exclusions = list(inputs.exclusions)
    validate_final_artifacts(
        catalog,
        mappings,
        assessments,
        exclusions,
        expected_structural_chain_keys=set(inputs.structural_chain_keys),
        expected_eligible_chain_keys=set(inputs.eligible_chain_keys),
    )
    handler_sink_groups = _build_handler_sink_groups(
        mappings,
        eligible_chains=inputs.eligible_chains,
        non_security_chains=inputs.non_security_chains,
    )
    validate_handler_sink_groups(
        handler_sink_groups, mappings, inputs.non_security_chains
    )
    report = render_alignment_index(
        generation_command,
        catalog,
        mappings,
        assessments,
        exclusions,
        handler_sink_groups,
    )
    security_groups = [
        row for row in handler_sink_groups if row["group_scope"] == "security"
    ]
    non_security_groups = [
        row
        for row in handler_sink_groups
        if row["group_scope"] == "no-security-impact"
    ]
    counts = {
        "structural_chains": len(inputs.structural_chain_keys),
        "eligible_semantic_chains": len(mappings),
        "excluded_chains": len(exclusions),
        "excluded_from_st_inference": len(exclusions),
        "terminal_grouped_exclusions": len(inputs.non_security_chains),
        "ungrouped_structural_chains": len(exclusions)
        - len(inputs.non_security_chains),
        "grouped_chains": sum(row["chain_count"] for row in handler_sink_groups),
        "handler_sink_groups": len(handler_sink_groups),
        "security_handler_sink_groups": len(security_groups),
        "no_security_impact_chains": len(inputs.non_security_chains),
        "no_security_impact_groups": len(non_security_groups),
        "downstream_oracle_groups": len(security_groups),
        "assessment_targets": len(assessments),
        "sink_types": len(catalog_rows),
        "nanobot_seed_types": sum(row["origin"] == "nanobot-seed" for row in catalog_rows),
        "external_types": sum(row["origin"] == "external-global" for row in catalog_rows),
        "matched_assessments": sum(row["decision"] == "matched" for row in assessments),
        "new_type_assessments": sum(row["decision"] == "new-type" for row in assessments),
        "canonicalization_batches": canonical_batches,
        "content_bound_reused_targets": len(reuse_matches),
        "exact_target_reuses": sum(
            row["reuse_kind"] == "exact-target-input"
            for row in reuse_matches.values()
        ),
        "concrete_sink_semantic_reuses": sum(
            row["reuse_kind"] == "concrete-sink-semantic"
            for row in reuse_matches.values()
        ),
        "model_canonicalized_targets": len(model_targets),
        "prior_catalog_anchors": len(prior_alignment["catalog"]),
        "reconciliation_batches": reconciliation_batches,
        "proposal_match_batches": proposal_match_batches,
        "component_adjudications": component_calls,
        "exact_identity_merges": (
            seed_exact_merges + exact_global_merges + post_concrete_exact_merges
        ),
        "identical_concrete_sink_merges": concrete_sink_merges,
        "primary_requests": len(chats),
        "model_calls": sum(len(rows) for rows in chats.values()),
        "repair_calls": sum(len(rows) - 1 for rows in chats.values()),
        "exclusion_reasons": dict(
            sorted(
                {
                    reason: sum(row["reason_code"] == reason for row in exclusions)
                    for reason in {row["reason_code"] for row in exclusions}
                }.items()
            )
        ),
    }
    transport = (
        runner.audit_payload()
        if callable(getattr(runner, "audit_payload", None))
        else {"transport": "injected-runner", "available_tools": []}
    )
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generation_command": generation_command,
        "seed_project": SEED_PROJECT,
        "handler_axis": "handler_criterion_id",
        "trace_handler_axis": "handler_type_id",
        "inputs": {
            **inputs.digests,
            "prior_alignment": {
                "binding_source": prior_alignment["binding_source"],
                **prior_alignment["digests"],
            },
        },
        "outputs": {
            "catalog": str(out_dir / "catalog.json"),
            "mappings": str(out_dir / "mappings.jsonl"),
            "assessments": str(out_dir / "assessments.jsonl"),
            "excluded_chains": str(out_dir / "excluded-chains.jsonl"),
            "handler_sink_groups": str(out_dir / "handler-sink-groups.jsonl"),
            "identity_reuse": str(out_dir / "identity-reuse.jsonl"),
            "report": str(out_dir / "alignment.md"),
        },
        "counts": counts,
        "transport": transport,
    }
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{out_dir.name}.staging-", dir=out_dir.parent)
    )
    try:
        _write_json(staging / "catalog.json", catalog)
        _write_jsonl(staging / "mappings.jsonl", mappings)
        _write_jsonl(staging / "assessments.jsonl", assessments)
        _write_jsonl(staging / "excluded-chains.jsonl", exclusions)
        _write_jsonl(staging / "handler-sink-groups.jsonl", handler_sink_groups)
        _write_jsonl(staging / "identity-reuse.jsonl", identity_bindings)
        _write_json(staging / "manifest.json", manifest)
        _write_text(staging / "alignment.md", report)
        for subject, exchanges in sorted(chats.items()):
            _write_json(
                staging / "repository" / subject / "chat.json",
                {
                    "schema_version": CHAT_SCHEMA_VERSION,
                    "subject": subject,
                    "exchanges": exchanges,
                },
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
