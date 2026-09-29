"""Canonical detector v15 member-applicability staging and publication."""

from __future__ import annotations

import csv
import os
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.pipeline.codeql import run_query
from src.projects import ProjectSpec
from src.sink_capacity.card_contract import CARD_SCHEMA_VERSION, parse_capability_card
from src.sink_capacity.effective_capability import derive_effective_capability_view

from .canonical_requirements import stable_v7_candidate_id
from .contracts import CoverageComparisonError, digest, sha256_file
from .field_flow_conversion import convert_rows
from .ground_truth import _render as render_ground_truth
from .learned_invariants import load_learned_catalog
from .member_applicability_partition import validate_member_applicability_partition
from .normative_evidence import validate_normative_evidence_resolution
from .prompts import contains_credentials
from .v8 import (
    _inventory,
    _read_json,
    _read_jsonl,
    _tree_digest,
    _write_json,
    _write_jsonl,
    _write_text,
)
from .v14 import validate_v14_artifacts
from .v15_artifacts import (
    filter_comparison_artifacts,
    ground_truth_partition,
    identity_migration,
    migrate_card_binding,
    validate_source_hashes,
    vulnerability_clusters,
)
from .v15_capability_dimensions import capability_dimensions
from .v15_member_projection import (
    FIELD_FLOW_EXCLUSION_VERSION,
    FIELD_FLOW_WITNESS_VERSION,
    build_call_shape_exclusions,
    build_member_projection,
    build_source_validation_field_flows,
    build_unknown_field_flow_exclusions,
    merge_field_flow_witnesses,
)
from .v15_normative_projection import build_normative_projection


ANALYSIS_MODE = "canonical-trained-detector/v15"
FREEZE_VERSION = "canonical-detector-generic-freeze/v15"
PUBLICATION_VERSION = "coverage-v15-publication/v15"
PUBLICATION_JOURNAL_VERSION = "coverage-v15-publication-journal/v1"
FALLBACK_VERSION = "coverage-training-fallback-overlay/v15"
FIELD_BINDING_VERSION = "field-flow-chain-binding/v1"
MAX_GENERIC_CANDIDATES = 90
MAX_TRAINING_FALLBACKS = 4


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _normalize_query_columns(rows: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    aliases = {
        "sourceParameter": "source_parameter",
        "sinkRole": "sink_role",
        "accessKind": "access_kind",
    }
    role_aliases = {
        "url": "destination-url",
        "cwd": "working-directory",
        "env": "environment",
    }
    normalized = [
        {aliases.get(key, key): value for key, value in row.items()} for row in rows
    ]
    for row in normalized:
        row["sink_role"] = role_aliases.get(row["sink_role"], row["sink_role"])
    return normalized


def _load_cards(repo_root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    card_root = repo_root / "src/sink_capacity/sink-capability-cards"
    payloads: dict[str, dict[str, Any]] = {}
    sha256: dict[str, str] = {}
    for path in sorted(card_root.glob("*.md")):
        if path.name == "index.md":
            continue
        relative = path.relative_to(repo_root).as_posix()
        payload = parse_capability_card(path.read_text(encoding="utf-8"))
        if payload["schema_version"] != CARD_SCHEMA_VERSION:
            raise CoverageComparisonError(f"legacy capability card remains: {relative}")
        payloads[relative] = payload
        sha256[relative] = sha256_file(path)
    if not payloads:
        raise CoverageComparisonError("v15 capability-card directory is empty")
    return payloads, sha256


def _semantic_chains(specs: Sequence[ProjectSpec]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for spec in specs:
        path = spec.output_root / "call-chain-semantics/call-chain-semantics.jsonl"
        for raw in _read_jsonl(path):
            row = dict(raw)
            row["_project"] = spec.project_id
            row["_revision"] = spec.analysis_revision
            output.append(row)
    return sorted(output, key=lambda row: (row["_project"], row["chain_id"]))


def _chain_bindings(
    *, spec: ProjectSpec, query_rows: Sequence[Mapping[str, str]]
) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    chains = _read_csv(spec.output_root / "static/call-chains/handler-sink-chains.csv")
    by_shape: dict[tuple[str, str, int, str, int, int], list[Mapping[str, str]]] = {}
    for chain in chains:
        for handler_name in {
            str(chain["handler_func"]),
            str(chain["handler_qualified_name"]),
        }:
            key = (
                handler_name,
                str(chain["handler_file"]),
                int(chain["handler_line"]),
                str(chain["sink_file"]),
                int(chain["sink_line"]),
                int(chain["sink_column"]),
            )
            by_shape.setdefault(key, []).append(chain)
    bindings: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for query in query_rows:
        shape = (
            str(query["handler_name"]),
            str(query["handler_file"]),
            int(query["handler_line"]),
            str(query["sink_file"]),
            int(query["sink_line"]),
            int(query["sink_column"]),
        )
        matched = {
            (str(row["chain_id"]), str(row["sink_id"]))
            for row in by_shape.get(shape, [])
        }
        identity = (*shape, str(query["sink_role"]))
        rows = bindings.setdefault(identity, [])
        for chain_id, sink_id in sorted(matched):
            binding = {
                "schema_version": FIELD_BINDING_VERSION,
                "project": spec.project_id,
                "revision": spec.analysis_revision,
                "chain_id": chain_id,
                "handler_id": "H-" + digest([spec.project_id, *shape[:3]])[:16],
                "sink_id": sink_id,
                "handler": {
                    "name": shape[0],
                    "file": shape[1],
                    "line": shape[2],
                },
                "sink": {
                    "file": shape[3],
                    "line": shape[4],
                    "column": shape[5],
                    "role": query["sink_role"],
                },
            }
            if binding not in rows:
                rows.append(binding)
    return bindings


def _normalize_ql_witness(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "project": row["project"],
        "revision": row["revision"],
        "chain_id": row["chain_id"],
        "requirement_id": None,
        "candidate_id": None,
        "tool_schema_field": row["field"],
        "handler_property_read": row["property_read"],
        "sink_role": row["sink_role"],
        "value_authority": row["value_authority"],
        "transforms": [value["name"] for value in row["transforms"]],
        "proof_kind": f"codeql-{row['proof_kind']}",
        "path_nodes": row["path_nodes"],
        "source_hashes": [
            {"path": path, "sha256": value}
            for path, value in sorted(row["source_hashes"].items())
        ],
        "sink": {"sink_id": row["sink_id"], "location": row["path_nodes"][-1]},
        "validation_id": None,
    }
    return {
        "schema_version": FIELD_FLOW_WITNESS_VERSION,
        "witness_id": "FFW-" + digest(payload)[:16],
        **payload,
    }


def _normalize_ql_exclusion(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "project": row["project"],
        "revision": row["revision"],
        "chain_id": row["chain_id"],
        "requirement_id": "",
        "sink_role": row["sink_role"],
        "tool_schema_field": row["field"],
        "value_authority": row["value_authority"],
        "reason": row["exclusion_reason"],
        "proof_kind": "codeql-field-flow-exclusion",
        # A bounded no-flow result can expose an unmodelled bridge. It is audit
        # evidence, not proof that the sink role is absent from the member.
        "authoritative": False,
        "source_hashes": [
            {"path": path, "sha256": value}
            for path, value in sorted(row["source_hashes"].items())
        ],
    }
    return {
        "schema_version": FIELD_FLOW_EXCLUSION_VERSION,
        "exclusion_id": "FFE-" + digest(payload)[:16],
        **payload,
    }


def _run_field_flow_queries(
    specs: Sequence[ProjectSpec], stage_root: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    witnesses: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    repository = stage_root / "repository/field-flow"
    for spec in specs:
        project_root = repository / spec.project_id
        witness_csv = project_root / "field-flow.csv"
        if witness_csv.is_file():
            witness_rows = _read_csv(witness_csv)
        else:
            witness_rows = run_query(
                spec.codeql_database,
                "get_field_flow.ql",
                witness_csv,
                query_pack=spec.query_pack,
                expected_language=spec.codeql_language,
            )
        if spec.project_id == "openclaw-cn":
            bridge_csv = project_root / "project-field-bridges.csv"
            if bridge_csv.is_file():
                bridge_rows = _read_csv(bridge_csv)
            else:
                bridge_rows = run_query(
                    spec.codeql_database,
                    "get_project_field_bridges.ql",
                    bridge_csv,
                    query_pack=spec.query_pack,
                    expected_language=spec.codeql_language,
                )
            witness_rows = [*witness_rows, *bridge_rows]
        exclusion_rows: list[dict[str, str]] = []
        witness_rows = _normalize_query_columns(witness_rows)
        bindings_by_key = _chain_bindings(spec=spec, query_rows=witness_rows)
        bindings = [
            binding
            for key in sorted(bindings_by_key)
            for binding in bindings_by_key[key]
        ]
        _write_jsonl(project_root / "chain-bindings.jsonl", bindings)
        unbound_rows = []
        for row in witness_rows:
            key = (
                row["handler_name"],
                row["handler_file"],
                int(row["handler_line"]),
                row["sink_file"],
                int(row["sink_line"]),
                int(row["sink_column"]),
                row["sink_role"],
            )
            if not bindings_by_key[key]:
                payload = {
                    "project": spec.project_id,
                    "handler": key[:3],
                    "sink": key[3:],
                    "field": row["field"],
                    "reason": "query row has no admitted structural chain",
                }
                unbound_rows.append(
                    {
                        "schema_version": "field-flow-unbound-query-row/v15",
                        "unbound_id": "FFU-" + digest(payload)[:16],
                        **payload,
                    }
                )
        _write_jsonl(
            project_root / "unbound-query-rows.jsonl",
            sorted(unbound_rows, key=lambda row: row["unbound_id"]),
        )
        for row in witness_rows:
            key = (
                row["handler_name"],
                row["handler_file"],
                int(row["handler_line"]),
                row["sink_file"],
                int(row["sink_line"]),
                int(row["sink_column"]),
                row["sink_role"],
            )
            for binding in bindings_by_key[key]:
                converted, _ = convert_rows([row], [], [binding], spec.source_root)
                witnesses.extend(map(_normalize_ql_witness, converted))
        for row in exclusion_rows:
            key = (
                row["handler_name"],
                row["handler_file"],
                int(row["handler_line"]),
                row["sink_file"],
                int(row["sink_line"]),
                int(row["sink_column"]),
                row["sink_role"],
            )
            for binding in bindings_by_key[key]:
                _, converted = convert_rows([], [row], [binding], spec.source_root)
                exclusions.extend(map(_normalize_ql_exclusion, converted))
    return witnesses, exclusions


def _effective_views(
    *,
    chains: Sequence[Mapping[str, Any]],
    cards: Mapping[str, Mapping[str, Any]],
    field_flows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    flows_by_key: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in field_flows:
        flows_by_key.setdefault((str(row["project"]), str(row["chain_id"])), []).append(
            row
        )
    output: list[dict[str, Any]] = []
    for chain in chains:
        project = str(chain["_project"])
        chain_id = str(chain["chain_id"])
        constraint = chain["sink_constraint"]
        card_path = str(constraint["capability_card"]["path"])
        card = cards.get(card_path)
        if card is None:
            raise CoverageComparisonError(
                f"{project}:{chain_id}: missing v2 card {card_path}"
            )
        authorities: dict[str, str] = {}
        transforms: dict[str, list[str]] = {}
        for role in card["roles"]:
            matching = [
                row
                for row in flows_by_key.get((project, chain_id), [])
                if row["sink_role"] == role["role_id"]
                or row["sink_role"]
                in {binding["expression"] for binding in role["bindings"]}
            ]
            for binding in role["bindings"]:
                if matching:
                    authorities[binding["expression"]] = str(
                        matching[0]["value_authority"]
                    )
                    transforms[binding["expression"]] = sorted(
                        {
                            str(value)
                            for row in matching
                            for value in row.get("transforms", [])
                        }
                    )
        view = derive_effective_capability_view(
            card=card,
            project=project,
            revision=str(chain["_revision"]),
            chain_id=chain_id,
            sink_constraint=constraint,
            authority_by_binding=authorities,
            transforms_by_binding=transforms,
            runtime_features=[str(card["runtime"]["language"])],
        )
        capability_class = str(card["capability_class"])
        boundary, effect, predicate = capability_dimensions(capability_class)
        output.append(
            {
                **view,
                "project": project,
                "revision": chain["_revision"],
                "capability_class": capability_class,
                "card_path": card_path,
                "normalized_boundaries": [boundary],
                "normalized_actual_effects": [effect],
                "normalized_call_shape_predicates": [predicate],
            }
        )
    return output


def _policy_basis_projection(
    *,
    validations: Sequence[Mapping[str, Any]],
    selected_ids: set[str],
    basis_by_candidate: Mapping[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    migration: list[dict[str, Any]] = []
    for raw in validations:
        row = dict(raw)
        candidate_id = str(row["provisional_candidate_id"])
        if candidate_id in selected_ids:
            old = str(row.get("policy_basis", ""))
            new = basis_by_candidate[candidate_id]
            row["policy_basis"] = new
            migration.append(
                {
                    "schema_version": "validation-policy-basis-migration/v15",
                    "candidate_id": candidate_id,
                    "validation_id": row["validation_id"],
                    "old_policy_basis": old,
                    "new_policy_basis": new,
                    "disposition": "unchanged"
                    if old == new
                    else "evidence-authoritative",
                }
            )
        rows.append(row)
    return rows, migration


def _render_summary(counts: Mapping[str, Any]) -> str:
    return "\n".join(
        [
            "# Canonical Coverage Detector v15",
            "",
            "> Generation command: `python -m src.coverage_comparison --all`",
            "",
            "<!-- BEGIN GENERATED REPORT -->",
            "",
            f"Generic canonical candidates: **{counts['generic_candidates']}**; "
            f"root-cause clusters: **{counts['vulnerability_clusters']}**.",
            "",
            f"Admitted normative CRs: **{counts['canonical_requirements']}**; ordinary "
            f"capability hypotheses: **{counts['capability_hypotheses']}**.",
            "",
            f"Member applicability: **{counts['member_applicability']}** pairs "
            f"({', '.join(f'`{key}` {value}' for key, value in sorted(counts['member_decisions'].items()))}).",
            "",
            f"Generic training diagnostic: **{counts['generic_training_found']}/43**; "
            f"training regression overlay: **{counts['training_found']}/43** with "
            f"**{counts['training_fallbacks']}** transitional fallbacks.",
            "",
            "`candidates.jsonl` is byte-equivalent to `generic-candidates.jsonl`. The "
            "training overlay is regression-only and is forbidden as held-out input.",
            "",
            "<!-- END GENERATED REPORT -->",
            "",
        ]
    )


def _generic_freeze(
    *,
    stage_root: Path,
    active_root: Path,
    repo_root: Path,
    capability_cards: Mapping[str, str],
) -> dict[str, Any]:
    artifacts = (
        "canonical-requirements.jsonl",
        "capability-card-identity-migration.jsonl",
        "requirement-applicability-contracts.jsonl",
        "normative-evidence-resolutions.jsonl",
        "capability-hypotheses.jsonl",
        "effective-capability-views.jsonl",
        "field-flow-witnesses.jsonl",
        "field-flow-exclusions.jsonl",
        "member-applicability-facts.jsonl",
        "member-applicability.jsonl",
        "member-applicability-removals.jsonl",
        "comparisons.jsonl",
        "requirement-assessments.jsonl",
        "provisional-candidates.jsonl",
        "generic-candidate-validations.jsonl",
        "generic-candidates.jsonl",
        "candidates.jsonl",
        "candidate-filter-dispositions.jsonl",
        "generic-ground-truth-coverage.jsonl",
        "vulnerability-clusters.jsonl",
    )
    implementation = (
        "src/coverage_comparison/applicability_contract.py",
        "src/coverage_comparison/normative_evidence.py",
        "src/coverage_comparison/normative_evidence_inputs.py",
        "src/coverage_comparison/member_applicability_facts.py",
        "src/coverage_comparison/member_applicability.py",
        "src/coverage_comparison/member_applicability_partition.py",
        "src/coverage_comparison/field_flow_contract.py",
        "src/coverage_comparison/field_flow_conversion.py",
        "src/coverage_comparison/v15_normative_projection.py",
        "src/coverage_comparison/v15_capability_dimensions.py",
        "src/coverage_comparison/capability-dimensions-v15.json",
        "src/coverage_comparison/v15_member_projection.py",
        "src/coverage_comparison/v15_artifacts.py",
        "src/coverage_comparison/v15.py",
        "src/ql/get_field_flow.ql",
        "src/ql/get_field_flow_exclusions.ql",
        "src/ql-js/get_field_flow.ql",
        "src/ql-js/get_field_flow_exclusions.ql",
        "src/ql-js/get_project_field_bridges.ql",
        "src/ql-js/field_flow/ProjectFieldBridges.qll",
    )
    return {
        "schema_version": FREEZE_VERSION,
        "base_v14_manifest_sha256": sha256_file(active_root / "manifest.json"),
        "artifacts": {name: sha256_file(stage_root / name) for name in artifacts},
        "implementation": {
            name: sha256_file(repo_root / name) for name in implementation
        },
        "capability_cards": dict(sorted(capability_cards.items())),
        "fallback_loaded": False,
    }


def _write_blocker(stage_root: Path, reason: str, details: Mapping[str, Any]) -> None:
    _write_json(
        stage_root / "v15-blockers.json",
        {
            "schema_version": "coverage-v15-blockers/v1",
            "reason": reason,
            "details": dict(details),
            "active_v14_preserved": True,
        },
    )


def prepare_v15(
    *,
    specs: Sequence[ProjectSpec],
    active_root: Path,
    group_root: Path,
    stage_root: Path,
    fallback_registry_path: Path,
    learned_catalog_path: Path,
) -> dict[str, Any]:
    """Build v15 entirely in staging; load training fallback only after generic freeze."""

    baseline = validate_v14_artifacts(active_root)["manifest"]
    if stage_root.exists():
        staged = _read_json(stage_root / "manifest.json")
        if staged.get("analysis_mode") != "canonical-trained-detector/v14":
            raise CoverageComparisonError(
                f"v15 staging directory is not resumable: {stage_root}"
            )
    else:
        shutil.copytree(active_root, stage_root)
    for obsolete in (
        "normativity-repair-registry-snapshot.json",
        "upstream-normativity-classifications.jsonl",
    ):
        (stage_root / obsolete).unlink(missing_ok=True)
    repo_root = Path(__file__).resolve().parents[2]
    cards, card_sha256 = _load_cards(repo_root)
    card_migration_path = (
        repo_root / "src/sink_capacity/sink-capability-cards/identity-migration.jsonl"
    )
    if not card_migration_path.is_file():
        raise CoverageComparisonError(
            "v15 capability-card identity migration is missing"
        )
    _write_text(
        stage_root / "capability-card-identity-migration.jsonl",
        card_migration_path.read_text(encoding="utf-8"),
    )
    ql_witnesses, ql_exclusions = _run_field_flow_queries(specs, stage_root)
    chains = _semantic_chains(specs)
    views = _effective_views(chains=chains, cards=cards, field_flows=ql_witnesses)

    prior_requirements = _read_jsonl(active_root / "canonical-requirements.jsonl")
    prior_comparisons = _read_jsonl(active_root / "comparisons.jsonl")
    prior_assessments = _read_jsonl(active_root / "requirement-assessments.jsonl")
    prior_provisional = _read_jsonl(active_root / "provisional-candidates.jsonl")
    prior_candidates = _read_jsonl(active_root / "candidates.jsonl")
    prior_validations = _read_jsonl(active_root / "candidate-validations.jsonl")
    prior_ground_truth = _read_jsonl(active_root / "ground-truth-coverage.jsonl")
    group_oracles = _read_jsonl(group_root / "oracles.jsonl")
    evidence_index = _read_json(group_root / "evidence-index.json")
    learned_catalog = load_learned_catalog(learned_catalog_path)
    projection = build_normative_projection(
        requirements=prior_requirements,
        comparisons=prior_comparisons,
        group_oracles=group_oracles,
        evidence_index=evidence_index,
        learned_catalog=learned_catalog,
        effective_views=views,
        card_payloads=cards,
    )
    admitted_ids = {
        str(row["requirement_id"]) for row in projection.admitted_requirements
    }
    contracts = {
        str(row["requirement_id"]): row["contract"] for row in projection.contracts
    }
    validation_by_id = {
        str(row["provisional_candidate_id"]): row for row in prior_validations
    }
    comparison_by_key = {
        (str(row["project"]), str(row["chain_id"])): row for row in prior_comparisons
    }
    requirement_by_id = {str(row["requirement_id"]): row for row in prior_requirements}

    generic_base = [
        row for row in prior_candidates if str(row["requirement_id"]) in admitted_ids
    ]
    source_flows = build_source_validation_field_flows(
        candidates=generic_base,
        requirements=requirement_by_id,
        contracts=contracts,
        validations=validation_by_id,
        comparisons=comparison_by_key,
    )
    field_flows = merge_field_flow_witnesses(ql_witnesses, source_flows)
    views = _effective_views(chains=chains, cards=cards, field_flows=field_flows)
    call_shape_exclusions = build_call_shape_exclusions(
        assessments=[
            row
            for row in prior_assessments
            if str(row["requirement_id"]) in admitted_ids
        ]
    )
    unknown_exclusions = build_unknown_field_flow_exclusions(
        comparisons=prior_comparisons,
        admitted_requirement_ids=admitted_ids,
        contracts=contracts,
        field_flow_witnesses=field_flows,
    )
    field_exclusions = sorted(
        [*ql_exclusions, *call_shape_exclusions, *unknown_exclusions],
        key=lambda row: str(row["exclusion_id"]),
    )
    member = build_member_projection(
        comparisons=prior_comparisons,
        assessments=prior_assessments,
        admitted_requirement_ids=admitted_ids,
        requirements=requirement_by_id,
        resolutions=projection.resolutions,
        contracts=contracts,
        effective_views=views,
        card_payloads=cards,
        field_flow_witnesses=field_flows,
        field_flow_exclusions=field_exclusions,
    )
    applicable = {
        (str(row["project"]), str(row["chain_id"]), str(row["requirement_id"]))
        for row in member.applicability.assessments
        if row["decision"] == "applicable"
    }
    generic_base = [
        row
        for row in generic_base
        if (str(row["project"]), str(row["chain_id"]), str(row["requirement_id"]))
        in applicable
    ]
    expected_generic_ids = {
        str(row["candidate_id"])
        for row in prior_candidates
        if str(row["requirement_id"]) in admitted_ids
    }
    generic_ids = {str(row["candidate_id"]) for row in generic_base}
    unexpected = sorted(generic_ids - expected_generic_ids)
    if unexpected:
        raise CoverageComparisonError(
            f"v15 generic member applicability added unexpected candidates: {unexpected}"
        )
    member_by_key = {
        (str(row["project"]), str(row["chain_id"]), str(row["requirement_id"])): row
        for row in member.applicability.assessments
    }
    prior_candidate_by_id = {str(row["candidate_id"]): row for row in prior_candidates}
    applicability_removals = []
    for candidate_id in sorted(expected_generic_ids - generic_ids):
        candidate = prior_candidate_by_id[candidate_id]
        decision = member_by_key[
            (
                str(candidate["project"]),
                str(candidate["chain_id"]),
                str(candidate["requirement_id"]),
            )
        ]
        if decision["decision"] == "applicable":
            raise CoverageComparisonError(
                f"{candidate_id}: applicable candidate disappeared from generic output"
            )
        payload = {
            "candidate_id": candidate_id,
            "project": candidate["project"],
            "chain_id": candidate["chain_id"],
            "requirement_id": candidate["requirement_id"],
            "member_assessment_id": decision["assessment_id"],
            "decision": decision["decision"],
            "reason": decision["reason"],
            "checks": decision["checks"],
        }
        applicability_removals.append(
            {
                "schema_version": "coverage-member-applicability-removal/v15",
                "removal_id": "MAR-" + digest(payload)[:16],
                **payload,
            }
        )
    generic_candidates = [
        migrate_card_binding(row, card_sha256=card_sha256, generic=True)
        for row in generic_base
    ]
    resolution_by_id = {
        str(row["requirement_id"]): row for row in projection.resolutions
    }
    basis_by_candidate = {
        str(row["candidate_id"]): resolution_by_id[str(row["requirement_id"])][
            "allowed_validation_policy_bases"
        ][0]
        for row in generic_candidates
    }
    projected_validations, basis_migration = _policy_basis_projection(
        validations=prior_validations,
        selected_ids=generic_ids,
        basis_by_candidate=basis_by_candidate,
    )
    projected_validation_by_id = {
        str(row["provisional_candidate_id"]): row for row in projected_validations
    }
    for candidate in generic_candidates:
        context = candidate.get("source_context")
        if (
            isinstance(context, dict)
            and candidate["candidate_id"] in basis_by_candidate
        ):
            context["policy_basis"] = basis_by_candidate[str(candidate["candidate_id"])]
    source_roots = {spec.project_id: spec.source_root for spec in specs}
    validate_source_hashes(
        candidates=generic_candidates,
        validations=projected_validation_by_id,
        source_roots=source_roots,
    )
    view_by_key = {(str(row["project"]), str(row["chain_id"])): row for row in views}
    comparisons, assessments = filter_comparison_artifacts(
        comparisons=prior_comparisons,
        assessments=prior_assessments,
        applicability=member.applicability.assessments,
        card_sha256=card_sha256,
        effective_views=view_by_key,
    )
    provisional = [
        migrate_card_binding(row, card_sha256=card_sha256, generic=True)
        for row in prior_provisional
        if str(row["requirement_id"]) in admitted_ids
        and (str(row["project"]), str(row["chain_id"]), str(row["requirement_id"]))
        in applicable
    ]
    generic_validations = [
        projected_validation_by_id[candidate_id] for candidate_id in sorted(generic_ids)
    ]
    generic_gt = ground_truth_partition(
        prior_ground_truth,
        candidate_ids=generic_ids,
        label="generic source-confirmed v15",
    )
    generic_found = sum(
        row.get("evaluation_partition") == "training" and row["status"] == "covered"
        for row in generic_gt
    )
    clusters = vulnerability_clusters(generic_candidates, projected_validation_by_id)
    generic_dispositions = []
    provisional_by_id = {str(row["candidate_id"]): row for row in prior_provisional}
    removal_by_id = {str(row["candidate_id"]): row for row in applicability_removals}
    for raw in _read_jsonl(active_root / "candidate-filter-dispositions.jsonl"):
        row = dict(raw)
        candidate = provisional_by_id.get(str(row["candidate_id"]))
        if candidate and str(candidate["requirement_id"]) not in admitted_ids:
            row.update(
                {
                    "schema_version": "coverage-generic-candidate-disposition/v15",
                    "prior_disposition": row["disposition"],
                    "disposition": "non-normative-capability-hypothesis",
                    "reason": "ordinary capability facts cannot authorize a generic requirement",
                }
            )
        elif str(row["candidate_id"]) in removal_by_id:
            removal = removal_by_id[str(row["candidate_id"])]
            row.update(
                {
                    "schema_version": "coverage-generic-candidate-disposition/v15",
                    "prior_disposition": row["disposition"],
                    "disposition": f"member-{removal['decision']}",
                    "reason": removal["reason"],
                    "member_assessment_id": removal["member_assessment_id"],
                }
            )
        generic_dispositions.append(row)

    _write_jsonl(
        stage_root / "canonical-requirements.jsonl", projection.admitted_requirements
    )
    _write_jsonl(
        stage_root / "requirement-applicability-contracts.jsonl", projection.contracts
    )
    _write_jsonl(
        stage_root / "normative-evidence-resolutions.jsonl", projection.resolutions
    )
    _write_jsonl(
        stage_root / "capability-hypotheses.jsonl", projection.capability_hypotheses
    )
    _write_jsonl(stage_root / "effective-capability-views.jsonl", views)
    _write_jsonl(stage_root / "field-flow-witnesses.jsonl", field_flows)
    _write_jsonl(stage_root / "field-flow-exclusions.jsonl", field_exclusions)
    _write_jsonl(stage_root / "member-applicability-facts.jsonl", member.member_facts)
    _write_jsonl(
        stage_root / "member-applicability.jsonl", member.applicability.assessments
    )
    _write_jsonl(
        stage_root / "member-applicability-removals.jsonl",
        applicability_removals,
    )
    _write_jsonl(stage_root / "comparisons.jsonl", comparisons)
    _write_jsonl(stage_root / "requirement-assessments.jsonl", assessments)
    _write_jsonl(stage_root / "provisional-candidates.jsonl", provisional)
    _write_jsonl(
        stage_root / "generic-candidate-validations.jsonl", generic_validations
    )
    _write_jsonl(stage_root / "generic-candidates.jsonl", generic_candidates)
    _write_jsonl(stage_root / "candidates.jsonl", generic_candidates)
    _write_jsonl(
        stage_root / "candidate-filter-dispositions.jsonl", generic_dispositions
    )
    _write_jsonl(stage_root / "generic-ground-truth-coverage.jsonl", generic_gt)
    _write_text(
        stage_root / "generic-ground-truth-coverage.md",
        render_ground_truth(
            "python -m src.coverage_comparison --all",
            generic_gt,
            baseline_counts=None,
            baseline_label="Canonical v15 generic training diagnostic",
            dispositions=[],
        ),
    )
    _write_jsonl(stage_root / "vulnerability-clusters.jsonl", clusters)
    _write_jsonl(
        stage_root / "validation-policy-basis-migration.jsonl", basis_migration
    )
    prior_origin = {
        str(row["candidate_id"]): row
        for row in _read_jsonl(active_root / "candidate-origin-audit.jsonl")
    }
    _write_jsonl(
        stage_root / "candidate-origin-audit.jsonl",
        [prior_origin[candidate_id] for candidate_id in sorted(generic_ids)],
    )
    freeze = _generic_freeze(
        stage_root=stage_root,
        active_root=active_root,
        repo_root=repo_root,
        capability_cards=card_sha256,
    )
    _write_json(stage_root / "generic-freeze-lock.json", freeze)

    # Training-only overlay begins here. No fallback registry was read above this line.
    fallback_registry = _read_json(fallback_registry_path)
    entries = fallback_registry.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_TRAINING_FALLBACKS:
        raise CoverageComparisonError(
            "v15 training fallback registry exceeds its contract"
        )
    fallback_ids = {str(row["candidate_id"]) for row in entries}
    if fallback_ids & generic_ids or not fallback_ids <= set(prior_candidate_by_id):
        raise CoverageComparisonError("v15 training fallback identity mismatch")
    fallback_candidates = [
        migrate_card_binding(
            prior_candidate_by_id[candidate_id],
            card_sha256=card_sha256,
            generic=False,
        )
        for candidate_id in sorted(fallback_ids)
    ]
    fallback_basis = {
        str(row["candidate_id"]): str(row["allowed_validation_policy_bases"][0])
        for row in entries
    }
    selected_ids = generic_ids | fallback_ids
    all_basis = {**basis_by_candidate, **fallback_basis}
    projected_validations, basis_migration = _policy_basis_projection(
        validations=prior_validations,
        selected_ids=selected_ids,
        basis_by_candidate=all_basis,
    )
    projected_validation_by_id = {
        str(row["provisional_candidate_id"]): row for row in projected_validations
    }
    training_candidates = sorted(
        [*generic_candidates, *fallback_candidates],
        key=lambda row: str(row["candidate_id"]),
    )
    validate_source_hashes(
        candidates=training_candidates,
        validations=projected_validation_by_id,
        source_roots=source_roots,
    )
    training_gt = ground_truth_partition(
        prior_ground_truth,
        candidate_ids=selected_ids,
        label="training-regression overlay",
    )
    training_found = sum(
        row.get("evaluation_partition") == "training" and row["status"] == "covered"
        for row in training_gt
    )
    if training_found != 43:
        _write_blocker(
            stage_root,
            "training regression recall gate failed",
            {"found": training_found, "expected": 43},
        )
        raise CoverageComparisonError(f"v15 training recall is {training_found}/43")
    fallback_flows = build_source_validation_field_flows(
        candidates=fallback_candidates,
        requirements=requirement_by_id,
        contracts=contracts,
        validations=projected_validation_by_id,
        comparisons=comparison_by_key,
    )
    _write_json(
        stage_root / "training-fallback-registry-snapshot.json", fallback_registry
    )
    _write_jsonl(stage_root / "training-fallback-field-flow.jsonl", fallback_flows)
    _write_jsonl(
        stage_root / "training-regression-candidates.jsonl", training_candidates
    )
    _write_jsonl(
        stage_root / "training-fallback-validations.jsonl",
        [
            projected_validation_by_id[candidate_id]
            for candidate_id in sorted(fallback_ids)
        ],
    )
    _write_jsonl(stage_root / "candidate-validations.jsonl", projected_validations)
    _write_jsonl(
        stage_root / "validation-policy-basis-migration.jsonl", basis_migration
    )
    _write_jsonl(stage_root / "ground-truth-coverage.jsonl", training_gt)
    _write_text(
        stage_root / "ground-truth-coverage.md",
        render_ground_truth(
            "python -m src.coverage_comparison --all",
            training_gt,
            baseline_counts=None,
            baseline_label="Canonical v15 training-regression overlay",
            dispositions=[],
        ),
    )
    _write_jsonl(
        stage_root / "ground-truth-reuse.jsonl",
        [
            {
                "schema_version": "ground-truth-reuse/v15",
                "report_id": row["report_id"],
                "candidate_partition": "training-regression-candidates.jsonl",
                "matched_candidate_ids": row["matched_candidate_ids"],
                "reuse_digest": digest(
                    [
                        row["report_id"],
                        row["chain_ids"],
                        row["matched_candidate_ids"],
                        [
                            digest(prior_candidate_by_id[candidate_id])
                            for candidate_id in row["matched_candidate_ids"]
                        ],
                    ]
                ),
            }
            for row in training_gt
        ],
    )
    gt_manifest = _read_json(stage_root / "ground-truth-manifest.json")
    gt_manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "candidate_partition": "training-regression-candidates.jsonl",
            "generic_candidate_partition": "generic-candidates.jsonl",
            "inputs": {
                **gt_manifest["inputs"],
                "candidates": sha256_file(
                    stage_root / "training-regression-candidates.jsonl"
                ),
                "generic_candidates": sha256_file(
                    stage_root / "generic-candidates.jsonl"
                ),
                "comparisons": sha256_file(stage_root / "comparisons.jsonl"),
            },
            "counts": {
                **gt_manifest["counts"],
                "covered_reports": 43,
                "missed_reports": 0,
                "generic_covered_reports": generic_found,
                "training_fallbacks": len(fallback_ids),
                "model_calls": 0,
                "repair_calls": 0,
            },
        }
    )
    _write_json(stage_root / "ground-truth-manifest.json", gt_manifest)

    migration = identity_migration(
        prior_requirements=prior_requirements,
        admitted_requirement_ids=admitted_ids,
        prior_candidates=prior_candidates,
        generic_candidate_ids=generic_ids,
        fallback_candidate_ids=fallback_ids,
        comparisons=prior_comparisons,
    )
    _write_jsonl(stage_root / "identity-migration-v15.jsonl", migration)
    member_counts = Counter(row["decision"] for row in member.applicability.assessments)
    generic_disposition_counts = Counter(
        row["disposition"] for row in generic_dispositions
    )
    counts = {
        **baseline["counts"],
        "v14_filter_dispositions": baseline["counts"].get("filter_dispositions", {}),
        "filter_dispositions": dict(sorted(generic_disposition_counts.items())),
        "canonical_requirements": len(projection.admitted_requirements),
        "capability_hypotheses": len(projection.capability_hypotheses),
        "provisional_candidates": len(provisional),
        "candidates": len(generic_candidates),
        "generic_candidates": len(generic_candidates),
        "training_regression_candidates": len(training_candidates),
        "training_fallbacks": len(fallback_ids),
        "source_confirmed_candidates": len(generic_candidates),
        "unvalidated_canonical_candidates": 0,
        "vulnerability_clusters": len(clusters),
        "field_flow_witnesses": len(field_flows),
        "field_flow_exclusions": len(field_exclusions),
        "effective_capability_views": len(views),
        "member_applicability": len(member.applicability.assessments),
        "member_applicability_removals": len(applicability_removals),
        "member_decisions": dict(sorted(member_counts.items())),
        "ordinary_capability_card_final_requirements": 0,
        "generic_training_found": generic_found,
        "generic_training_missed": 43 - generic_found,
        "training_found": training_found,
        "training_missed": 0,
    }
    if len(generic_candidates) > MAX_GENERIC_CANDIDATES:
        raise CoverageComparisonError("v15 generic candidate count exceeds v14")
    report = _render_summary(counts)
    _write_text(stage_root / "coverage-index.md", report)
    _write_text(stage_root / "precision-summary.md", report)
    manifest = dict(baseline)
    manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "generation_command": "python -m src.coverage_comparison --all",
            "counts": counts,
            "training_claim": (
                "43/43 training-regression overlay; generic held-out input is separate"
            ),
            "candidate_partitions": {
                "generic": "generic-candidates.jsonl",
                "canonical_alias": "candidates.jsonl",
                "training_regression": "training-regression-candidates.jsonl",
                "held_out_allowed": ["generic-candidates.jsonl", "candidates.jsonl"],
            },
            "member_applicability_contract": {
                "schema_version": "coverage-member-applicability/v15",
                "canonical_admission": ["applicable"],
                "fail_closed": ["unknown", "upstream-incomplete"],
            },
            "precision_contract": {
                **baseline["precision_contract"],
                "canonical_requires": "confirmed-uncovered+member-applicable",
                "ordinary_capability_card_normative": False,
                "report_specific_generic_repairs": 0,
                "training_fallbacks": len(fallback_ids),
                "root_cause_cluster_key": (
                    "project+actual-effect-sink+normalized-invariant+patch-locus"
                ),
            },
            "inputs": {
                **baseline["inputs"],
                "v14_manifest": sha256_file(active_root / "manifest.json"),
                "group_oracles": sha256_file(group_root / "oracles.jsonl"),
                "group_evidence_index": sha256_file(group_root / "evidence-index.json"),
                "learned_catalog": sha256_file(learned_catalog_path),
                "generic_freeze_lock": sha256_file(
                    stage_root / "generic-freeze-lock.json"
                ),
                "training_fallback_registry": sha256_file(fallback_registry_path),
            },
            "transport": {
                **baseline.get("transport", {}),
                "v15_live_model_calls": 0,
                "v15_source_agent_calls": 0,
            },
        }
    )
    _write_json(stage_root / "manifest.json", manifest)
    values = _inventory(stage_root)
    inventory = {
        "schema_version": PUBLICATION_VERSION,
        "source_mode": ANALYSIS_MODE,
        "file_count": len(values),
        "tree_sha256": _tree_digest(values),
        "files": values,
    }
    _write_json(stage_root / "artifact-inventory.json", inventory)
    manifest["artifact_inventory_sha256"] = sha256_file(
        stage_root / "artifact-inventory.json"
    )
    _write_json(stage_root / "manifest.json", manifest)
    new_text_files = (
        "coverage-index.md",
        "precision-summary.md",
        "generic-ground-truth-coverage.md",
        "ground-truth-coverage.md",
        "member-applicability.jsonl",
    )
    credential_hits = [
        name
        for name in new_text_files
        if contains_credentials((stage_root / name).read_text(encoding="utf-8"))
    ]
    if credential_hits:
        raise CoverageComparisonError(
            f"credential-shaped data in v15 generated artifacts: {credential_hits}"
        )
    return manifest


def validate_v15_artifacts(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("canonical v15 mode mismatch")
    generic = _read_jsonl(root / "generic-candidates.jsonl")
    canonical = _read_jsonl(root / "candidates.jsonl")
    training = _read_jsonl(root / "training-regression-candidates.jsonl")
    if canonical != generic:
        raise CoverageComparisonError(
            "v15 candidates.jsonl is not the generic canonical set"
        )
    generic_ids = {str(row["candidate_id"]) for row in generic}
    training_ids = {str(row["candidate_id"]) for row in training}
    if len(generic_ids) != len(generic) or len(training_ids) != len(training):
        raise CoverageComparisonError("v15 duplicate candidate identity")
    if (
        not generic_ids <= training_ids
        or len(training_ids - generic_ids) > MAX_TRAINING_FALLBACKS
    ):
        raise CoverageComparisonError("v15 training overlay partition failed")
    fallback_registry = _read_json(root / "training-fallback-registry-snapshot.json")
    fallback_ids = {str(row["candidate_id"]) for row in fallback_registry["entries"]}
    if fallback_ids != training_ids - generic_ids:
        raise CoverageComparisonError(
            "v15 fallback registry does not match overlay delta"
        )
    if any(row.get("source_context", {}).get("training_report_ids") for row in generic):
        raise CoverageComparisonError(
            "v15 generic candidate contains report-specific routing"
        )
    validations = {
        str(row["provisional_candidate_id"]): row
        for row in _read_jsonl(root / "generic-candidate-validations.jsonl")
    }
    if set(validations) != generic_ids or any(
        row["verdict"] != "confirmed-uncovered" for row in validations.values()
    ):
        raise CoverageComparisonError("v15 generic source-validation partition failed")
    applicability = _read_jsonl(root / "member-applicability.jsonl")
    member_facts = _read_jsonl(root / "member-applicability-facts.jsonl")
    validate_member_applicability_partition(applicability, member_facts)
    applicability_by_id = {str(row["assessment_id"]): row for row in applicability}
    removals = _read_jsonl(root / "member-applicability-removals.jsonl")
    if len({str(row["candidate_id"]) for row in removals}) != len(removals):
        raise CoverageComparisonError("v15 duplicate member applicability removal")
    for row in removals:
        assessment = applicability_by_id.get(str(row["member_assessment_id"]))
        if (
            assessment is None
            or assessment["decision"] == "applicable"
            or row["decision"] != assessment["decision"]
            or row["reason"] != assessment["reason"]
            or row["checks"] != assessment["checks"]
        ):
            raise CoverageComparisonError(
                "v15 member applicability removal lacks exact audit evidence"
            )
    applicable = {
        (str(row["project"]), str(row["chain_id"]), str(row["requirement_id"]))
        for row in applicability
        if row["decision"] == "applicable"
    }
    if any(
        (str(row["project"]), str(row["chain_id"]), str(row["requirement_id"]))
        not in applicable
        for row in generic
    ):
        raise CoverageComparisonError(
            "v15 generic candidate lacks member applicability"
        )
    if len(generic) > MAX_GENERIC_CANDIDATES:
        raise CoverageComparisonError("v15 generic candidate count exceeds the v14 cap")
    for candidate in generic:
        if candidate["candidate_id"] != stable_v7_candidate_id(
            group_id=candidate["group_id"],
            project=candidate["project"],
            revision=candidate["revision"],
            chain_id=candidate["chain_id"],
            requirement_id=candidate["requirement_id"],
            failure_mode=candidate["failure_mode"],
            gate_ids=candidate["gate_ids"],
        ):
            raise CoverageComparisonError("v15 candidate identity drift")
    requirements = _read_jsonl(root / "canonical-requirements.jsonl")
    resolutions = {
        str(row["requirement_id"]): validate_normative_evidence_resolution(row)
        for row in _read_jsonl(root / "normative-evidence-resolutions.jsonl")
    }
    if any(
        resolutions[str(row["requirement_id"])]["status"] != "normative"
        for row in requirements
    ):
        raise CoverageComparisonError("v15 admitted a non-normative requirement")
    if any(
        validations[str(candidate["candidate_id"])]["policy_basis"]
        not in resolutions[str(candidate["requirement_id"])][
            "allowed_validation_policy_bases"
        ]
        for candidate in generic
    ):
        raise CoverageComparisonError("v15 validation policy basis/provenance mismatch")
    witness_rows = _read_jsonl(root / "field-flow-witnesses.jsonl")
    exclusion_rows = _read_jsonl(root / "field-flow-exclusions.jsonl")
    if len({row["witness_id"] for row in witness_rows}) != len(witness_rows):
        raise CoverageComparisonError("v15 duplicate field-flow witness")
    if len({row["exclusion_id"] for row in exclusion_rows}) != len(exclusion_rows):
        raise CoverageComparisonError("v15 duplicate field-flow exclusion")
    generic_gt = [
        row
        for row in _read_jsonl(root / "generic-ground-truth-coverage.jsonl")
        if row.get("evaluation_partition") == "training"
    ]
    training_gt = [
        row
        for row in _read_jsonl(root / "ground-truth-coverage.jsonl")
        if row.get("evaluation_partition") == "training"
    ]
    if (
        len(generic_gt) != 43
        or len(training_gt) != 43
        or any(row["status"] != "covered" for row in training_gt)
    ):
        raise CoverageComparisonError("v15 training regression partition failed")
    clusters = _read_jsonl(root / "vulnerability-clusters.jsonl")
    clustered = [
        candidate_id for row in clusters for candidate_id in row["candidate_ids"]
    ]
    if len(clustered) != len(set(clustered)) or set(clustered) != generic_ids:
        raise CoverageComparisonError("v15 vulnerability cluster partition failed")
    freeze = _read_json(root / "generic-freeze-lock.json")
    if freeze.get("fallback_loaded") is not False:
        raise CoverageComparisonError(
            "v15 generic freeze was created after fallback load"
        )
    repo_root = Path(__file__).resolve().parents[2]
    for relative, expected in freeze["implementation"].items():
        if sha256_file(repo_root / relative) != expected:
            raise CoverageComparisonError(f"v15 generic freeze drift: {relative}")
    for relative, expected in freeze["capability_cards"].items():
        if sha256_file(repo_root / relative) != expected:
            raise CoverageComparisonError(f"v15 capability-card drift: {relative}")
    for relative, expected in freeze["artifacts"].items():
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v15 generic artifact drift: {relative}")
    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v15 inventory drift: {relative}")
    if inventory["tree_sha256"] != _tree_digest(inventory["files"]):
        raise CoverageComparisonError("v15 inventory tree drift")
    if manifest["artifact_inventory_sha256"] != sha256_file(
        root / "artifact-inventory.json"
    ):
        raise CoverageComparisonError("v15 manifest inventory binding failed")
    return {
        "manifest": manifest,
        "generic_candidates": len(generic),
        "training_candidates": len(training),
        "clusters": len(clusters),
        "generic_training_found": sum(row["status"] == "covered" for row in generic_gt),
        "training_found": 43,
    }


def _publication_journal_path(active_root: Path) -> Path:
    return active_root.parent / ".coverage-v15-publication-journal.json"


def _write_publication_journal(path: Path, payload: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    _write_json(temporary, payload)
    os.replace(temporary, path)


def _recover_v15_publication(
    *, active_root: Path, stage_root: Path, archive_root: Path, journal_path: Path
) -> None:
    journal = _read_json(journal_path)
    expected = {
        "active_root": str(active_root.resolve()),
        "stage_root": str(stage_root.resolve()),
        "archive_root": str(archive_root.resolve()),
    }
    if journal.get("schema_version") != PUBLICATION_JOURNAL_VERSION or any(
        journal.get(key) != value for key, value in expected.items()
    ):
        raise CoverageComparisonError("v15 publication journal identity mismatch")
    if active_root.exists() and stage_root.exists() and not archive_root.exists():
        journal_path.unlink()
        return
    if not active_root.exists() and stage_root.exists() and archive_root.exists():
        os.replace(archive_root, active_root)
        journal_path.unlink()
        return
    if active_root.exists() and not stage_root.exists() and archive_root.exists():
        os.replace(active_root, stage_root)
        os.replace(archive_root, active_root)
        journal_path.unlink()
        return
    raise CoverageComparisonError("v15 publication journal cannot be recovered safely")


def publish_v15(*, active_root: Path, stage_root: Path, archive_root: Path) -> None:
    journal_path = _publication_journal_path(active_root)
    if journal_path.exists():
        _recover_v15_publication(
            active_root=active_root,
            stage_root=stage_root,
            archive_root=archive_root,
            journal_path=journal_path,
        )
    if archive_root.exists():
        raise CoverageComparisonError(
            f"v15 rollback archive already exists: {archive_root}"
        )
    if not active_root.is_dir() or not stage_root.is_dir():
        raise CoverageComparisonError("v15 publication roots are incomplete")
    archive_root.parent.mkdir(parents=True, exist_ok=True)
    journal = {
        "schema_version": PUBLICATION_JOURNAL_VERSION,
        "state": "prepared",
        "active_root": str(active_root.resolve()),
        "stage_root": str(stage_root.resolve()),
        "archive_root": str(archive_root.resolve()),
        "active_manifest_sha256": sha256_file(active_root / "manifest.json"),
        "stage_manifest_sha256": sha256_file(stage_root / "manifest.json"),
    }
    _write_publication_journal(journal_path, journal)
    try:
        os.replace(active_root, archive_root)
        journal["state"] = "active-archived"
        _write_publication_journal(journal_path, journal)
        os.replace(stage_root, active_root)
        journal["state"] = "stage-promoted"
        _write_publication_journal(journal_path, journal)
        validate_v15_artifacts(active_root)
        journal["state"] = "validated"
        _write_publication_journal(journal_path, journal)
        journal_path.unlink()
    except Exception:
        if journal_path.exists():
            _recover_v15_publication(
                active_root=active_root,
                stage_root=stage_root,
                archive_root=archive_root,
                journal_path=journal_path,
            )
        raise
