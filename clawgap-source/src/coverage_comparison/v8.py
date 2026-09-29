"""Targeted canonical detector v8 publication for approval-policy requirements."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import validate as validate_schema

from src.gate_semantics.contracts import estimate_tokens
from src.projects import ProjectSpec

from .canonical_requirements import (
    IDENTITY_MIGRATION_SCHEMA_VERSION,
    canonicalize_requirement,
    migrate_candidate,
    route_canonical_source_chains,
)
from .contracts import (
    CHAT_SCHEMA_VERSION,
    COMPARISON_SCHEMA_VERSION,
    CoverageComparisonError,
    canonical_json,
    digest,
    sha256_file,
    validate_comparison_response,
)
from .ground_truth import (
    _candidate_prompt_record,
    _match_call,
    _render as render_ground_truth,
    _report_invariant,
    bind_ground_truth,
    deduplicate_ground_truth,
    discover_ground_truth,
)
from .inputs import CoverageChain, CoverageInputs, load_coverage_inputs
from .learned_invariants import load_learned_catalog, route_learned_requirements
from .pipeline import (
    _assessment_record,
    _candidate_record,
    _requirement_batches,
    _validated_call,
)
from .prompts import (
    COMPARE_SYSTEM,
    build_compare_user,
    build_ground_truth_match_user,
    contains_credentials,
)
from .same_origin import SameOriginRun, analyze_same_origin, audit_candidate_origins
from .versions import (
    ASSESSMENT_SCHEMA_VERSION,
    GROUND_TRUTH_PROMPT_VERSION,
    GT_CHAT_SCHEMA_VERSION,
    GT_MANIFEST_SCHEMA_VERSION,
)


ANALYSIS_MODE = "canonical-trained-detector/v8"
FREEZE_VERSION = "canonical-detector-freeze/v8"
PUBLICATION_VERSION = "coverage-v8-publication/v8"
APPROVAL_GROUP_ID = "HSG-cf83f5754609b70c"
APPROVAL_CHAIN_KEYS = {
    ("hermes-agent", "C-728f8e5e6c99"),
    ("mercury-agent", "C-11e5d5e54b4a"),
}
POLICY_DIMENSIONS = {
    "indirect-file-operands",
    "shell-expansion-semantics",
    "redirection-effect",
    "command-action-semantics",
}
TARGET_REPORT_IDS = {
    "GT-064e5e8cd701c4f3",
    "GT-da46e23775a545e1",
    "GT-a53f7c03db055552",
    "GT-e53a164b159182ee",
}
REQUIRED_FILES = (
    "manifest.json",
    "artifact-inventory.json",
    "detector-freeze-lock.json",
    "canonical-requirements.jsonl",
    "requirement-assessments.jsonl",
    "comparisons.jsonl",
    "provisional-candidates.jsonl",
    "candidate-validations.jsonl",
    "candidates.jsonl",
    "identity-migration.jsonl",
    "same-origin-witnesses.jsonl",
    "same-origin-exclusions.jsonl",
    "candidate-origin-audit.jsonl",
    "canonical-router-selected.jsonl",
    "canonical-router-excluded.jsonl",
    "ground-truth-coverage.jsonl",
    "ground-truth-manifest.json",
    "coverage-index.md",
)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CoverageComparisonError(f"expected object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise CoverageComparisonError(f"expected object: {path}:{number}")
        rows.append(value)
    return rows


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    _write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def _inventory(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and path.name not in {"manifest.json", "artifact-inventory.json"}
    }


def _tree_digest(values: Mapping[str, str]) -> str:
    return digest([[path, value] for path, value in sorted(values.items())])


def _render_v8_report(counts: Mapping[str, Any]) -> str:
    return "\n".join(
        [
            "# Canonical CR Coverage Comparison v8",
            "",
            "Reproduce from the repository root:",
            "",
            "```bash",
            "python -m src.coverage_comparison --all",
            "```",
            "",
            "<!-- BEGIN GENERATED REPORT -->",
            "",
            f"Structural chains: **{counts['structural_chains']}**; eligible comparisons: "
            f"**{counts['eligible_comparisons']}**; canonical requirements: "
            f"**{counts['canonical_requirements']}**.",
            "",
            f"Provisional candidates: **{counts['provisional_candidates']}**; canonical "
            f"SameOrigin survivors: **{counts['candidates']}**.",
            "",
            f"Approval-policy requirements: **{counts['approval_policy_requirements']}**; "
            f"approval-policy candidates: **{counts['approval_policy_candidates']}**.",
            "",
            f"SameOrigin witnesses/exclusions: **{counts['same_origin_witnesses']} / "
            f"{counts['same_origin_exclusions']}**; source router: "
            f"**{counts['router_selected']} selected / {counts['router_excluded']} excluded**.",
            "",
            f"Strict training recall: **{counts['training_found']}/43**. This detector uses "
            "rules learned from the training corpus; it is not a blind recall result.",
            "",
            "Source discovery calls for the approval-policy delta: **0**.",
            "",
            "<!-- END GENERATED REPORT -->",
            "",
        ]
    )


def _transport_audit(
    *,
    runner: Any,
    stage_root: Path,
    initial_transport_manifest: Path | None,
) -> dict[str, Any]:
    publication = runner.current_audit_payload()
    exchanges: list[dict[str, str]] = []
    for path in sorted((stage_root / "repository").glob("*/*/chat.json")):
        payload = _read_json(path)
        stage = payload.get("stage")
        subject = str(payload.get("subject", ""))
        is_v8_compare = stage == "compare" and subject in {
            "hermes-agent-C-728f8e5e6c99",
            "mercury-agent-C-11e5d5e54b4a",
        }
        is_v8_gt = stage == "ground-truth" and any(
            subject.startswith(report_id + "-") for report_id in TARGET_REPORT_IDS
        )
        if not (is_v8_compare or is_v8_gt):
            continue
        exchanges.extend(payload.get("exchanges", []))
    model_calls = len(exchanges)
    estimated_input = sum(
        estimate_tokens({"system": row["system"], "user": row["user"]})
        for row in exchanges
    )
    estimated_output = sum(estimate_tokens(row["response"]) for row in exchanges)
    initial: Mapping[str, Any] = publication
    if initial_transport_manifest is not None:
        initial = _read_json(initial_transport_manifest).get("transport", publication)
    calls = initial.get("calls", []) if isinstance(initial, Mapping) else []
    provider_calls = len(calls) if isinstance(calls, list) else 0
    return {
        "transport": "coverage-v8-audit/v8",
        "publication_replay": publication,
        "initial_generation": {
            "model_calls": model_calls,
            "provider_reported_calls": provider_calls,
            "unreported_provider_calls": max(model_calls - provider_calls, 0),
            "provider_token_usage": (
                dict(initial.get("token_usage", {}))
                if isinstance(initial, Mapping)
                else {}
            ),
            "estimated_input_tokens": estimated_input,
            "estimated_output_tokens": estimated_output,
            "estimated_total_tokens": estimated_input + estimated_output,
            "note": (
                "Provider usage covers only calls retained by the live runner audit; "
                "deterministic estimates cover all persisted v8 compare and GT exchanges."
            ),
        },
    }


def _git_commit() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True
    ).strip()


def _source_digests(paths: Sequence[Path], repo_root: Path) -> dict[str, str]:
    return {
        path.relative_to(repo_root).as_posix(): sha256_file(path)
        for path in sorted(set(paths))
    }


def _compare_chain(
    chain: CoverageChain, runner: Any
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, list[dict[str, str]]]]:
    requirements = {
        row["requirement_id"]: row for row in chain.oracle["requirements"]
    }
    defaults: list[str] = []
    rows: list[dict[str, Any]] = []
    chats: dict[str, list[dict[str, str]]] = {}
    batches = _requirement_batches(list(requirements))
    for batch_number, batch_ids in enumerate(batches, 1):
        selected = {requirement_id: requirements[requirement_id] for requirement_id in batch_ids}
        user = build_compare_user(chain, batch_ids)
        (batch_defaults, batch_rows), exchanges = _validated_call(
            runner=runner,
            system=COMPARE_SYSTEM,
            user=user,
            validator=lambda response, selected=selected: validate_comparison_response(
                response,
                group_id=chain.group_id,
                chain_id=chain.chain_id,
                requirements=selected,
                allowed_gate_ids={
                    row["gate_uid"] for row in chain.semantic_ir["gates"]
                },
                card_lines=chain.capability_card_lines,
            ),
            context=f"{chain.project}:{chain.chain_id}: v8 comparison batch {batch_number}",
        )
        defaults = sorted(set(defaults) | set(batch_defaults))
        rows.extend(batch_rows)
        subject = f"{chain.project}-{chain.chain_id}"
        if len(batches) > 1:
            subject += f"-B{batch_number:03d}"
        chats[subject] = exchanges
    rows.sort(key=lambda row: row["requirement_id"])
    assessments = [_assessment_record(chain, row) for row in rows]
    by_requirement = {row["requirement_id"]: row for row in assessments}
    candidates = [
        _candidate_record(chain, by_requirement[requirement_id], requirement)
        for requirement_id, requirement in sorted(requirements.items())
        if by_requirement[requirement_id]["decision"]
        in {"wrong-check", "missing-check"}
    ]
    comparison = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "group_id": chain.group_id,
        "handler_criterion_id": chain.handler_criterion_id,
        "sink_type_id": chain.sink_type_id,
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
        "handler_id": chain.handler_id,
        "sink_id": chain.sink_id,
        "sink_constraint_id": chain.semantic_ir["sink_constraint"]["constraint_id"],
        "group_oracle_status": chain.oracle["status"],
        "semantic_ir_status": chain.semantic_ir["status"],
        "status": "partial",
        "capability_card": {
            "path": chain.capability_card_path,
            "sha256": chain.capability_card_sha256,
        },
        "controlled_argument": chain.semantic_ir["sink_constraint"][
            "controlled_argument"
        ],
        "values": chain.semantic_ir["values"],
        "call_shape": chain.semantic_ir["sink_constraint"]["call_shape"],
        "applicable_defaults": defaults,
        "requirements": rows,
    }
    return comparison, assessments, candidates, chats


def _merge_requirements(
    existing: Sequence[dict[str, Any]], current_group: Mapping[str, Any]
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, str],
    dict[str, str],
]:
    by_id = {row["requirement_id"]: dict(row) for row in existing}
    all_legacy_to_cr: dict[str, str] = {}
    recomputed_group_legacy_to_cr: dict[str, str] = {}
    for row in existing:
        for source in row["provenance"]["sources"]:
            if row["group_id"] == APPROVAL_GROUP_ID:
                all_legacy_to_cr[source["legacy_requirement_id"]] = row[
                    "requirement_id"
                ]
    for requirement in current_group["requirements"]:
        canonical = canonicalize_requirement(
            requirement, group_id=APPROVAL_GROUP_ID
        )
        legacy_refines = canonical.pop("legacy_refines_requirement_ids")
        canonical["refines_cr_ids"] = sorted(
            all_legacy_to_cr[legacy]
            for legacy in legacy_refines
            if legacy in all_legacy_to_cr
        )
        prior = by_id.get(canonical["requirement_id"])
        if prior is None:
            by_id[canonical["requirement_id"]] = canonical
        else:
            for field in (
                "group_id",
                "rule",
                "applicability",
                "controlled_facet",
                "enforcement_stage",
                "state_lifetime",
                "security_effect",
            ):
                if prior[field] != canonical[field]:
                    raise CoverageComparisonError(
                        f"v8 CR continuity conflict {canonical['requirement_id']}:{field}"
                    )
            legacy_id = requirement["requirement_id"]
            prior["provenance"]["sources"] = [
                source
                for source in prior["provenance"]["sources"]
                if source["legacy_requirement_id"] != legacy_id
            ] + canonical["provenance"]["sources"]
            prior["provenance"]["sources"].sort(
                key=lambda row: (
                    row["legacy_requirement_id"],
                    row["kind"],
                    row["payload_sha256"],
                )
            )
        all_legacy_to_cr[requirement["requirement_id"]] = canonical[
            "requirement_id"
        ]
        recomputed_group_legacy_to_cr[requirement["requirement_id"]] = canonical[
            "requirement_id"
        ]
    return (
        sorted(by_id.values(), key=lambda row: row["requirement_id"]),
        by_id,
        all_legacy_to_cr,
        recomputed_group_legacy_to_cr,
    )


def _canonical_assessment(
    row: Mapping[str, Any], requirement_id: str
) -> dict[str, Any]:
    return {
        **dict(row),
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "requirement_id": requirement_id,
    }


def _canonical_comparison(
    comparison: Mapping[str, Any],
    *,
    legacy_to_cr: Mapping[str, str],
    prior: Mapping[str, Any] | None,
) -> dict[str, Any]:
    group_ids = set(legacy_to_cr.values())
    requirements = [
        {**row, "requirement_id": legacy_to_cr[row["requirement_id"]]}
        for row in comparison["requirements"]
    ]
    if prior is not None:
        requirements.extend(
            row
            for row in prior["requirements"]
            if row["requirement_id"] not in group_ids
        )
    return {
        **dict(comparison),
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "requirements": sorted(
            requirements, key=lambda row: row["requirement_id"]
        ),
    }


def _augment_origin_from_source_validation(
    *,
    origin: SameOriginRun,
    candidates: Sequence[Mapping[str, Any]],
    validations: Sequence[Mapping[str, Any]],
    specs: Sequence[ProjectSpec],
) -> tuple[SameOriginRun, int]:
    """Promote source-confirmed interprocedural order when static order is unknown."""

    validation_by_candidate = {
        row["provisional_candidate_id"]: row for row in validations
    }
    specs_by_project = {spec.project_id: spec.resolved() for spec in specs}
    exclusion_by_gate = {
        (row["project"], row["chain_id"], row["gate_uid"]): row
        for row in origin.exclusions
        if row["gate_uid"] is not None
    }
    witnesses = list(origin.witnesses)
    witness_by_gate = dict(origin.witness_by_gate)
    promoted_keys: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        key = (candidate["project"], candidate["chain_id"])
        missing = [
            gate_id
            for gate_id in candidate["gate_ids"]
            if (key[0], key[1], gate_id) not in witness_by_gate
        ]
        if not missing:
            continue
        validation = validation_by_candidate.get(candidate["candidate_id"])
        if validation is None or any(
            (
                validation.get("verdict") != "confirmed-uncovered",
                validation.get("source_research_complete") is not True,
                validation.get("controlled_flow") != "confirmed",
                validation.get("sink_reachability") != "confirmed",
                validation.get("gate_coverage") != "uncovered",
                validation.get("operational_error") is not None,
            )
        ):
            continue
        evidence = validation.get("source_evidence")
        roles = (
            {row.get("role") for row in evidence}
            if isinstance(evidence, list)
            else set()
        )
        if not {"handler", "sink", "gate"} <= roles:
            continue
        spec = specs_by_project.get(candidate["project"])
        if spec is None:
            continue
        evidence_valid = True
        for row in evidence:
            relative = Path(str(row.get("file", "")))
            if relative.is_absolute() or ".." in relative.parts:
                evidence_valid = False
                break
            source = spec.source_root / relative
            if not source.is_file() or sha256_file(source) != row.get("sha256"):
                evidence_valid = False
                break
        if not evidence_valid:
            continue
        for gate_id in missing:
            gate_key = (key[0], key[1], gate_id)
            exclusion = exclusion_by_gate.get(gate_key)
            if exclusion is None or exclusion["verdict"] != "unknown-order":
                continue
            base = {
                field: exclusion[field]
                for field in (
                    "project",
                    "revision",
                    "chain_id",
                    "handler_id",
                    "sink_id",
                    "gate_uid",
                    "controlled_value_id",
                    "handler_source_parameter",
                    "source_facet",
                    "checked_expression",
                    "checked_location",
                    "sink_argument",
                    "sink_location",
                    "t_to_gate",
                    "t_to_sink",
                )
            }
            witness = {
                "schema_version": "coverage-same-origin-witness/v7",
                "origin_witness_id": "ORIGIN-"
                + digest(
                    [
                        base,
                        "source-validation-interprocedural",
                        validation["validation_id"],
                    ]
                )[:16],
                **base,
                "proof_kind": "interprocedural",
                "effect_order": "pre-sink",
                "verdict": "same-origin-confirmed",
                "reason": (
                    "Content-bound source validation confirms handler flow, the cited "
                    "interprocedural gate path, and sink reachability before the effect; "
                    f"validation={validation['validation_id']}."
                ),
            }
            witnesses.append(witness)
            witness_by_gate[gate_key] = witness
            promoted_keys.add(gate_key)
    exclusions = [
        row
        for row in origin.exclusions
        if (row["project"], row["chain_id"], row["gate_uid"])
        not in promoted_keys
    ]
    return (
        SameOriginRun(
            witnesses=tuple(
                sorted(witnesses, key=lambda row: row["origin_witness_id"])
            ),
            exclusions=tuple(
                sorted(exclusions, key=lambda row: row["origin_witness_id"])
            ),
            qualified_chains=origin.qualified_chains,
            witness_by_gate=dict(sorted(witness_by_gate.items())),
            sink_witness_by_chain=origin.sink_witness_by_chain,
        ),
        len(promoted_keys),
    )


def _freeze_lock(
    *,
    repo_root: Path,
    specs: Sequence[ProjectSpec],
    inputs: CoverageInputs,
    router: Mapping[str, Any],
    training_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    prompt_paths = [
        repo_root / "src/coverage_comparison/__main__.py",
        repo_root / "src/coverage_comparison/v8.py",
        repo_root / "src/coverage_comparison/prompts.py",
        repo_root / "src/coverage_comparison/capability_analysis.py",
        repo_root / "src/coverage_comparison/source_discovery.py",
        repo_root / "src/coverage_comparison/learned_invariants.py",
        repo_root / "src/coverage_comparison/source_validation_prompts.py",
        repo_root / "src/group_oracle/pipeline.py",
        repo_root / "src/group_oracle/prompts.py",
        repo_root / "src/sink_capacity/policy_contract.py",
        repo_root
        / "src/sink_capacity/sink-capability-cards/prompt_dangerous_approval.md",
        repo_root
        / "src/sink_capacity/sink-capability-cards/mercury.command-approval.md",
        repo_root / "src/sink_type_alignment/pipeline.py",
        repo_root / "src/sink_type_alignment/prompts.py",
    ]
    ql_paths = [
        path
        for root in (repo_root / "src/ql", repo_root / "src/ql-js")
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".ql", ".qll", ".yml"}
    ]
    training = [
        row for row in training_rows if row.get("evaluation_partition") == "training"
    ]
    return {
        "schema_version": FREEZE_VERSION,
        "analysis_mode": ANALYSIS_MODE,
        "implementation_commit": _git_commit(),
        "cr_normalization": {
            "path": "src/coverage_comparison/canonical_requirements.py",
            "sha256": sha256_file(
                repo_root / "src/coverage_comparison/canonical_requirements.py"
            ),
        },
        "router": {"config": dict(router), "config_sha256": digest(dict(router))},
        "learned_catalog": {
            "path": "src/coverage_comparison/learned-invariants.json",
            "sha256": sha256_file(
                repo_root / "src/coverage_comparison/learned-invariants.json"
            ),
        },
        "prompts": _source_digests(prompt_paths, repo_root),
        "ql": {
            "files": _source_digests(ql_paths, repo_root),
            "tree_sha256": _tree_digest(_source_digests(ql_paths, repo_root)),
        },
        "project_revisions": {
            spec.project_id: spec.analysis_revision for spec in specs
        },
        "coverage_inputs": dict(inputs.digests),
        "training_ground_truth": {
            "workbook": {
                "path": "design/study/vuls-new-found/all-new-xclaw-vulnerabilities.xlsx",
                "sha256": sha256_file(
                    repo_root
                    / "design/study/vuls-new-found/all-new-xclaw-vulnerabilities.xlsx"
                ),
            },
            "selection": {
                "path": "design/common/groundtruth-oracle/groundtruth-oracles.csv",
                "sha256": sha256_file(
                    repo_root
                    / "design/common/groundtruth-oracle/groundtruth-oracles.csv"
                ),
            },
            "eligible_reports": len(training),
            "report_ids_sha256": digest(
                sorted(row["report_id"] for row in training)
            ),
        },
    }


def _selective_ground_truth_audit(
    *,
    specs: Sequence[ProjectSpec],
    active_root: Path,
    stage_root: Path,
    runner: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Reuse unchanged v7 GT rows and adjudicate only the four changed reports."""

    discovered, _ = discover_ground_truth(specs)
    reports, _ = bind_ground_truth(specs, deduplicate_ground_truth(discovered))
    reports_by_id = {row.report_id: row for row in reports}
    if not TARGET_REPORT_IDS <= set(reports_by_id):
        raise CoverageComparisonError("v8 target GT report identity drift")
    prior_rows = {
        row["report_id"]: row
        for row in _read_jsonl(active_root / "ground-truth-coverage.jsonl")
    }
    comparisons = {
        (row["project"], row["chain_id"]): row
        for row in _read_jsonl(stage_root / "comparisons.jsonl")
    }
    candidates_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for candidate in _read_jsonl(stage_root / "candidates.jsonl"):
        candidates_by_key.setdefault(
            (candidate["project"], candidate["chain_id"]), []
        ).append(candidate)
    rows: list[dict[str, Any]] = []
    chats: list[tuple[str, list[dict[str, str]]]] = []
    for report in reports:
        prior = prior_rows.get(report.report_id)
        if report.report_id not in TARGET_REPORT_IDS:
            if prior is None or (
                prior["project"] != report.project
                or prior["revision"] != report.revision
                or prior["boundary_status"] != report.boundary_status
                or prior["chain_ids"] != list(report.chain_ids)
                or prior["source_sha256"] != list(report.source_sha256)
            ):
                raise CoverageComparisonError(
                    f"non-target GT input drift requires a new audit: {report.report_id}"
                )
            rows.append(dict(prior))
            continue
        if (
            report.boundary_status != "eligible"
            or "C-11e5d5e54b4a" not in report.chain_ids
        ):
            raise CoverageComparisonError(
                f"{report.report_id}: Mercury approval-chain binding is absent"
            )
        assessments: list[dict[str, Any]] = []
        for chain_id in report.chain_ids:
            comparison = comparisons.get((report.project, chain_id))
            if comparison is None:
                raise CoverageComparisonError(
                    f"{report.report_id}: selected chain has no v8 comparison"
                )
            chain_summary = {
                "chain_id": chain_id,
                "handler_id": comparison["handler_id"],
                "sink_id": comparison["sink_id"],
                "handler_criterion_id": comparison["handler_criterion_id"],
                "sink_type_id": comparison["sink_type_id"],
                "controlled_argument": comparison["controlled_argument"],
                "call_shape": comparison["call_shape"],
            }
            for candidate in sorted(
                candidates_by_key.get((report.project, chain_id), []),
                key=lambda row: row["candidate_id"],
            ):
                user = build_ground_truth_match_user(
                    report_id=report.report_id,
                    project=report.project,
                    revision=report.revision,
                    report=_report_invariant(report),
                    chain=chain_summary,
                    candidate=_candidate_prompt_record(candidate),
                )
                assessment, exchanges = _match_call(
                    runner=runner,
                    user=user,
                    report_id=report.report_id,
                    candidate_id=candidate["candidate_id"],
                )
                assessment["chain_id"] = chain_id
                assessments.append(assessment)
                chats.append(
                    (f"{report.report_id}-{candidate['candidate_id']}", exchanges)
                )
        matched = sorted(
            row["candidate_id"]
            for row in assessments
            if row["verdict"] == "match"
        )
        rows.append(
            {
                "schema_version": "coverage-ground-truth-audit/v7",
                "report_id": report.report_id,
                "project": report.project,
                "revision": report.revision,
                "report_name": report.report_name,
                "source_files": list(report.source_files),
                "source_sha256": list(report.source_sha256),
                "boundary_status": report.boundary_status,
                "chain_ids": list(report.chain_ids),
                "rebase_evidence": list(report.rebase_evidence),
                "candidate_assessments": assessments,
                "matched_candidate_ids": matched,
                "status": "covered" if matched else "missed",
                "reason": (
                    "at least one current-chain candidate expresses the same security invariant"
                    if matched
                    else "all current-chain candidates express different security invariants"
                ),
                "evaluation_partition": "training",
            }
        )
    rows.sort(key=lambda row: row["report_id"])
    _write_jsonl(stage_root / "ground-truth-coverage.jsonl", rows)
    _write_text(
        stage_root / "ground-truth-coverage.md",
        render_ground_truth(
            "python -m src.coverage_comparison --all",
            rows,
            baseline_counts=None,
            baseline_label="Canonical v7 training baseline",
            dispositions=[],
        ),
    )
    sidecar_root = stage_root / "repository/ground-truth"
    for subject, exchanges in chats:
        _write_json(
            sidecar_root / subject / "chat.json",
            {
                "schema_version": GT_CHAT_SCHEMA_VERSION,
                "stage": "ground-truth",
                "subject": subject,
                "exchanges": exchanges,
            },
        )
    counts = {
        "ledger_reports": len(rows),
        "physical_files": len(discovered),
        "unique_reports": len(rows),
        "eligible_reports": sum(
            row["status"] in {"covered", "missed"} for row in rows
        ),
        "covered_reports": sum(row["status"] == "covered" for row in rows),
        "missed_reports": sum(row["status"] == "missed" for row in rows),
        "fixed_reports": sum(
            row["status"] == "fixed-at-analysis-revision" for row in rows
        ),
        "not_present_reports": sum(
            row["status"] == "not-present-at-analysis-revision" for row in rows
        ),
        "out_of_model_reports": sum(row["status"] == "out-of-model" for row in rows),
        "no_chain_reports": sum(
            row["status"] == "no-current-structural-chain" for row in rows
        ),
        "candidate_pair_assessments": sum(
            len(row["candidate_assessments"]) for row in rows
        ),
        "model_calls": sum(len(exchanges) for _, exchanges in chats),
        "repair_calls": sum(len(exchanges) - 1 for _, exchanges in chats),
        "content_bound_reused_reports": len(rows) - len(TARGET_REPORT_IDS),
        "readjudicated_reports": len(TARGET_REPORT_IDS),
    }
    gt_manifest = {
        "schema_version": GT_MANIFEST_SCHEMA_VERSION,
        "prompt_version": GROUND_TRUTH_PROMPT_VERSION,
        "generation_command": "python -m src.coverage_comparison --all",
        "analysis_mode": ANALYSIS_MODE,
        "inputs": {
            "coverage_manifest": sha256_file(stage_root / "manifest.json"),
            "candidates": sha256_file(stage_root / "candidates.jsonl"),
            "comparisons": sha256_file(stage_root / "comparisons.jsonl"),
            "v7_ground_truth": sha256_file(
                active_root / "ground-truth-coverage.jsonl"
            ),
        },
        "counts": counts,
        "transport": runner.current_audit_payload(),
    }
    _write_json(stage_root / "ground-truth-manifest.json", gt_manifest)
    return rows, gt_manifest


def prepare_v8(
    *,
    specs: Sequence[ProjectSpec],
    active_root: Path,
    stage_root: Path,
    handler_root: Path,
    sink_root: Path,
    group_root: Path,
    evidence_registry: Path,
    runner: Any,
    initial_transport_manifest: Path | None = None,
) -> dict[str, Any]:
    if stage_root.exists():
        raise CoverageComparisonError(f"v8 staging directory exists: {stage_root}")
    manifest = _read_json(active_root / "manifest.json")
    if manifest.get("analysis_mode") != "canonical-trained-detector/v7":
        raise CoverageComparisonError("v8 preparation requires the frozen v7 baseline")
    shutil.copytree(active_root, stage_root)
    inputs = load_coverage_inputs(
        specs,
        handler_root=handler_root,
        sink_root=sink_root,
        group_root=group_root,
        evidence_registry=evidence_registry,
    )
    if len(inputs.chains) != 485:
        raise CoverageComparisonError(
            f"v8 requires 485 eligible chains, got {len(inputs.chains)}"
        )
    selected_chains = [
        chain for chain in inputs.chains if chain.key in APPROVAL_CHAIN_KEYS
    ]
    if {chain.key for chain in selected_chains} != APPROVAL_CHAIN_KEYS or any(
        chain.group_id != APPROVAL_GROUP_ID for chain in selected_chains
    ):
        raise CoverageComparisonError("approval chain/HSG binding drift")
    approval_oracle = selected_chains[0].oracle
    dimensions = {
        row["dimension"]
        for row in approval_oracle["requirements"]
        if row["dimension"] in POLICY_DIMENSIONS
    }
    if dimensions != POLICY_DIMENSIONS or len(approval_oracle["requirements"]) != 6:
        raise CoverageComparisonError("approval HSG does not contain the required 2+4 rules")

    current_comparisons: dict[tuple[str, str], dict[str, Any]] = {}
    current_assessments: list[dict[str, Any]] = []
    raw_candidates: list[dict[str, Any]] = []
    compare_chats: dict[str, list[dict[str, str]]] = {}
    for chain in selected_chains:
        comparison, assessments, candidates, chats = _compare_chain(chain, runner)
        current_comparisons[chain.key] = comparison
        current_assessments.extend(assessments)
        raw_candidates.extend(candidates)
        compare_chats.update(chats)
    mercury_rows = current_comparisons[("mercury-agent", "C-11e5d5e54b4a")][
        "requirements"
    ]
    policy_ids = {
        row["requirement_id"]
        for row in approval_oracle["requirements"]
        if row["dimension"] in POLICY_DIMENSIONS
    }
    policy_results = {
        row["requirement_id"]: row for row in mercury_rows if row["requirement_id"] in policy_ids
    }
    if set(policy_results) != policy_ids or any(
        row["decision"] != "wrong-check" or not row["gate_ids"]
        for row in policy_results.values()
    ):
        raise CoverageComparisonError(
            "Mercury approval-policy requirements are not four precise wrong-checks"
        )

    existing_requirements = _read_jsonl(
        active_root / "canonical-requirements.jsonl"
    )
    (
        requirements,
        requirement_by_id,
        _all_legacy_to_cr,
        recomputed_group_legacy_to_cr,
    ) = _merge_requirements(
        existing_requirements, approval_oracle
    )
    _write_jsonl(stage_root / "canonical-requirements.jsonl", requirements)
    _write_jsonl(stage_root / "requirement-proposals.jsonl", requirements)

    existing_assessments = _read_jsonl(
        active_root / "requirement-assessments.jsonl"
    )
    approval_cr_ids = set(recomputed_group_legacy_to_cr.values())
    assessments = [
        row
        for row in existing_assessments
        if not (
            (row["project"], row["chain_id"]) in APPROVAL_CHAIN_KEYS
            and row["requirement_id"] in approval_cr_ids
        )
    ]
    assessments.extend(
        _canonical_assessment(
            row, recomputed_group_legacy_to_cr[row["requirement_id"]]
        )
        for row in current_assessments
    )
    assessments.sort(
        key=lambda row: (row["project"], row["chain_id"], row["requirement_id"])
    )
    _write_jsonl(stage_root / "requirement-assessments.jsonl", assessments)

    prior_comparisons = {
        (row["project"], row["chain_id"]): row
        for row in _read_jsonl(active_root / "comparisons.jsonl")
    }
    comparisons = [
        row for key, row in prior_comparisons.items() if key not in APPROVAL_CHAIN_KEYS
    ]
    comparisons.extend(
        _canonical_comparison(
            comparison,
            legacy_to_cr=recomputed_group_legacy_to_cr,
            prior=prior_comparisons.get(key),
        )
        for key, comparison in current_comparisons.items()
    )
    comparisons.sort(key=lambda row: (row["project"], row["chain_id"]))
    if len(comparisons) != 485:
        raise CoverageComparisonError("v8 comparisons do not partition 485 chains")
    _write_jsonl(stage_root / "comparisons.jsonl", comparisons)

    migrations = _read_jsonl(active_root / "identity-migration.jsonl")
    migration_by_requirement = {
        (row["group_id"], row["old_requirement_id"]): row
        for row in migrations
        if row["record_kind"] == "requirement"
    }
    for requirement in approval_oracle["requirements"]:
        cr_id = recomputed_group_legacy_to_cr[requirement["requirement_id"]]
        key = (APPROVAL_GROUP_ID, requirement["requirement_id"])
        migration = {
            "schema_version": IDENTITY_MIGRATION_SCHEMA_VERSION,
            "record_kind": "requirement",
            "group_id": APPROVAL_GROUP_ID,
            "old_requirement_id": requirement["requirement_id"],
            "new_requirement_id": cr_id,
            "old_candidate_id": None,
            "new_candidate_id": None,
            "old_payload_sha256": digest(requirement),
            "new_payload_sha256": digest(requirement_by_id[cr_id]),
            "disposition": "one-to-one",
        }
        prior = migration_by_requirement.get(key)
        if prior is None:
            migrations.append(migration)
        else:
            prior.update(migration)

    provisional = {
        row["candidate_id"]: row
        for row in _read_jsonl(active_root / "provisional-candidates.jsonl")
    }
    canonical = {
        row["candidate_id"]: row
        for row in _read_jsonl(active_root / "candidates.jsonl")
    }
    new_candidate_ids: set[str] = set()
    for raw in raw_candidates:
        cr_id = recomputed_group_legacy_to_cr[raw["requirement_id"]]
        migrated, ledger = migrate_candidate(
            raw, requirement=requirement_by_id[cr_id]
        )
        ledger.update(
            {"record_kind": "candidate", "group_id": APPROVAL_GROUP_ID}
        )
        provisional[migrated["candidate_id"]] = migrated
        canonical[migrated["candidate_id"]] = migrated
        migrations.append(ledger)
        new_candidate_ids.add(migrated["candidate_id"])
    provisional_rows = sorted(provisional.values(), key=lambda row: row["candidate_id"])

    origin = analyze_same_origin(chains=list(inputs.chains), specs=specs)
    origin, source_validation_origin_witnesses = (
        _augment_origin_from_source_validation(
            origin=origin,
            candidates=sorted(canonical.values(), key=lambda row: row["candidate_id"]),
            validations=_read_jsonl(stage_root / "candidate-validations.jsonl"),
            specs=specs,
        )
    )
    origin_audit = audit_candidate_origins(
        sorted(canonical.values(), key=lambda row: row["candidate_id"]), run=origin
    )
    excluded_candidates = {
        row["candidate_id"]
        for row in origin_audit
        if row["origin_disposition"] == "excluded"
    }
    if new_candidate_ids & excluded_candidates:
        raise CoverageComparisonError(
            "approval-policy candidate lacks strict SameOrigin proof"
        )
    canonical_rows = sorted(
        (
            row
            for candidate_id, row in canonical.items()
            if candidate_id not in excluded_candidates
        ),
        key=lambda row: row["candidate_id"],
    )
    _write_jsonl(stage_root / "provisional-candidates.jsonl", provisional_rows)
    _write_jsonl(stage_root / "candidates.jsonl", canonical_rows)
    _write_jsonl(
        stage_root / "same-origin-witnesses.jsonl",
        list(origin.witnesses),
    )
    _write_jsonl(
        stage_root / "same-origin-exclusions.jsonl",
        list(origin.exclusions),
    )
    canonical_origin_audit = []
    for row in origin_audit:
        if row["candidate_id"] in excluded_candidates:
            continue
        value = dict(row)
        value.pop("requirement_source", None)
        value["provenance"] = requirement_by_id[value["requirement_id"]][
            "provenance"
        ]
        canonical_origin_audit.append(value)
    _write_jsonl(
        stage_root / "candidate-origin-audit.jsonl",
        canonical_origin_audit,
    )

    learned_catalog = load_learned_catalog()
    learned_chain_ids = {
        chain.key
        for chain in inputs.chains
        if route_learned_requirements(chain, learned_catalog)
    }
    prior_gt = _read_jsonl(active_root / "ground-truth-coverage.jsonl")
    prior_candidates_by_id = {
        row["candidate_id"]: row
        for row in _read_jsonl(active_root / "candidates.jsonl")
    }
    source_cr_ids = {
        row["requirement_id"]
        for row in requirements
        if any(
            source["kind"] == "source-derived"
            for source in row["provenance"]["sources"]
        )
    }
    strict_ids = {
        candidate_id
        for row in prior_gt
        for candidate_id in row["matched_candidate_ids"]
    }
    required_source_chains = {
        (candidate["project"], candidate["chain_id"])
        for candidate_id, candidate in prior_candidates_by_id.items()
        if candidate_id in strict_ids
        and candidate["requirement_id"] in source_cr_ids
    }
    router = route_canonical_source_chains(
        chains=list(inputs.chains),
        origin_audit=origin_audit,
        candidates=canonical_rows,
        learned_chain_ids=learned_chain_ids,
        required_regression_chain_ids=required_source_chains,
        budget=64,
    )
    _write_jsonl(stage_root / "canonical-router-selected.jsonl", list(router.selected))
    _write_jsonl(stage_root / "canonical-router-excluded.jsonl", list(router.excluded))
    migrations.sort(
        key=lambda row: (
            row["record_kind"],
            row["group_id"],
            row["old_requirement_id"],
            row["old_candidate_id"] or "",
        )
    )
    _write_jsonl(stage_root / "identity-migration.jsonl", migrations)

    repository = stage_root / "repository" / "compare"
    for subject, exchanges in compare_chats.items():
        _write_json(
            repository / subject / "chat.json",
            {
                "schema_version": CHAT_SCHEMA_VERSION,
                "stage": "compare",
                "subject": subject,
                "exchanges": exchanges,
            },
        )

    counts = dict(manifest["counts"])
    counts.update(
        {
            "structural_chains": 603,
            "eligible_comparisons": 485,
            "canonical_requirements": len(requirements),
            "identity_requirement_rows": sum(
                row["record_kind"] == "requirement" for row in migrations
            ),
            "identity_candidate_rows": sum(
                row["record_kind"] == "candidate" for row in migrations
            ),
            "provisional_candidates": len(provisional_rows),
            "candidates": len(canonical_rows),
            "same_origin_witnesses": len(origin.witnesses),
            "same_origin_exclusions": len(origin.exclusions),
            "source_validation_origin_witnesses": source_validation_origin_witnesses,
            "router_selected": len(router.selected),
            "router_excluded": len(router.excluded),
            "approval_policy_requirements": 4,
            "approval_policy_candidates": sum(
                row["requirement_id"]
                in {
                    recomputed_group_legacy_to_cr[requirement_id]
                    for requirement_id in policy_ids
                }
                for row in canonical_rows
            ),
        }
    )
    manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "generation_command": "python -m src.coverage_comparison --all",
            "evaluation_partition": "training",
            "router": dict(router.config),
            "inputs": {
                **manifest.get("inputs", {}),
                "v7_manifest": sha256_file(active_root / "manifest.json"),
                "group_oracles": sha256_file(group_root / "oracles.jsonl"),
                "sink_alignment": sha256_file(sink_root / "manifest.json"),
            },
            "counts": counts,
            "training_claim": "training recall; not blind generalization",
            "approval_policy_contract": {
                "schema_version": "approval-policy-contract/v1",
                "group_id": APPROVAL_GROUP_ID,
                "policy_dimensions": sorted(POLICY_DIMENSIONS),
                "source_discovery_calls": 0,
            },
            "transport": runner.current_audit_payload(),
        }
    )
    freeze = _freeze_lock(
        repo_root=Path(__file__).resolve().parents[2],
        specs=specs,
        inputs=inputs,
        router=router.config,
        training_rows=prior_gt,
    )
    _write_json(stage_root / "detector-freeze-lock.json", freeze)
    manifest["inputs"]["detector_freeze_lock"] = sha256_file(
        stage_root / "detector-freeze-lock.json"
    )
    _write_json(stage_root / "manifest.json", manifest)

    training_rows, _ = _selective_ground_truth_audit(
        specs=specs,
        active_root=active_root,
        stage_root=stage_root,
        runner=runner,
    )
    found = sum(
        row["evaluation_partition"] == "training" and row["status"] == "covered"
        for row in training_rows
    )
    missed = sum(
        row["evaluation_partition"] == "training" and row["status"] == "missed"
        for row in training_rows
    )
    if found < 39 or found + missed != 43:
        raise CoverageComparisonError(
            f"v8 training gate requires at least 39/43, got {found}/43"
        )
    manifest = _read_json(stage_root / "manifest.json")
    manifest["analysis_mode"] = ANALYSIS_MODE
    manifest["generation_command"] = "python -m src.coverage_comparison --all"
    manifest["evaluation_partition"] = "training"
    manifest["router"] = dict(router.config)
    manifest["inputs"] = {
        **manifest.get("inputs", {}),
        "v7_manifest": sha256_file(active_root / "manifest.json"),
        "group_oracles": sha256_file(group_root / "oracles.jsonl"),
        "sink_alignment": sha256_file(sink_root / "manifest.json"),
        "detector_freeze_lock": sha256_file(
            stage_root / "detector-freeze-lock.json"
        ),
    }
    manifest["counts"] = {
        **counts,
        "training_found": found,
        "training_missed": missed,
    }
    manifest["training_claim"] = "training recall; not blind generalization"
    manifest["approval_policy_contract"] = {
        "schema_version": "approval-policy-contract/v1",
        "group_id": APPROVAL_GROUP_ID,
        "policy_dimensions": sorted(POLICY_DIMENSIONS),
        "source_discovery_calls": 0,
    }
    manifest["transport"] = _transport_audit(
        runner=runner,
        stage_root=stage_root,
        initial_transport_manifest=initial_transport_manifest,
    )
    _write_text(stage_root / "coverage-index.md", _render_v8_report(manifest["counts"]))
    _write_json(stage_root / "manifest.json", manifest)
    values = _inventory(stage_root)
    inventory = {
        "schema_version": PUBLICATION_VERSION,
        "source_mode": "canonical-trained-detector/v7",
        "file_count": len(values),
        "tree_sha256": _tree_digest(values),
        "files": values,
    }
    _write_json(stage_root / "artifact-inventory.json", inventory)
    manifest["artifact_inventory_sha256"] = sha256_file(
        stage_root / "artifact-inventory.json"
    )
    _write_json(stage_root / "manifest.json", manifest)
    if any(
        contains_credentials(path.read_text(encoding="utf-8"))
        for path in stage_root.rglob("*")
        if path.is_file()
    ):
        raise CoverageComparisonError("credential-shaped data in v8 staging")
    return manifest


def publish_v8(*, active_root: Path, stage_root: Path, archive_root: Path) -> None:
    if not stage_root.is_dir():
        raise CoverageComparisonError("v8 staging directory is missing")
    if archive_root.exists():
        raise CoverageComparisonError(f"v7 archive already exists: {archive_root}")
    archive_root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(active_root, archive_root)
        os.replace(stage_root, active_root)
    except Exception:
        if archive_root.exists() and not active_root.exists():
            os.replace(archive_root, active_root)
        raise


def validate_v8_artifacts(root: Path) -> dict[str, Any]:
    root = root.resolve()
    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    if missing:
        raise CoverageComparisonError(f"canonical v8 artifact is incomplete: {missing}")
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("canonical v8 analysis mode mismatch")
    freeze = _read_json(root / "detector-freeze-lock.json")
    schema_root = Path(__file__).resolve().parent / "schemas"
    validate_schema(
        freeze,
        _read_json(schema_root / "canonical-detector-freeze-v8.schema.json"),
    )
    if manifest.get("inputs", {}).get("detector_freeze_lock") != sha256_file(
        root / "detector-freeze-lock.json"
    ):
        raise CoverageComparisonError("v8 detector freeze binding mismatch")
    if freeze["router"]["config_sha256"] != digest(manifest["router"]):
        raise CoverageComparisonError("v8 router freeze mismatch")
    repo_root = Path(__file__).resolve().parents[2]
    frozen_paths = {
        freeze["cr_normalization"]["path"]: freeze["cr_normalization"]["sha256"],
        freeze["learned_catalog"]["path"]: freeze["learned_catalog"]["sha256"],
        freeze["training_ground_truth"]["workbook"]["path"]: freeze[
            "training_ground_truth"
        ]["workbook"]["sha256"],
        freeze["training_ground_truth"]["selection"]["path"]: freeze[
            "training_ground_truth"
        ]["selection"]["sha256"],
        **freeze["prompts"],
        **freeze["ql"]["files"],
    }
    for relative, expected in frozen_paths.items():
        path = (repo_root / relative).resolve(strict=True)
        path.relative_to(repo_root)
        if sha256_file(path) != expected:
            raise CoverageComparisonError(f"v8 detector freeze drift: {relative}")

    requirements = _read_jsonl(root / "canonical-requirements.jsonl")
    requirement_schema = _read_json(schema_root / "canonical-requirement-v7.schema.json")
    for row in requirements:
        validate_schema(row, requirement_schema)
    requirement_ids = {row["requirement_id"] for row in requirements}
    if len(requirement_ids) != len(requirements):
        raise CoverageComparisonError("duplicate v8 CR identities")
    policy_requirements = [
        row
        for row in requirements
        if row["group_id"] == APPROVAL_GROUP_ID
        and any(
            source["legacy_requirement_id"].startswith("R-")
            and source["legacy_requirement_id"]
            in {
                "R-39fd7182e4819be4",
                "R-5ff8d96e70b48f97",
                "R-63ca669bc5973150",
                "R-70d193945028a481",
            }
            for source in row["provenance"]["sources"]
        )
    ]
    if len(policy_requirements) != 4:
        raise CoverageComparisonError("v8 does not contain four approval-policy CRs")

    candidate_schema = _read_json(schema_root / "coverage-candidate-v7.schema.json")
    provisional = _read_jsonl(root / "provisional-candidates.jsonl")
    candidates = _read_jsonl(root / "candidates.jsonl")
    for row in [*provisional, *candidates]:
        validate_schema(row, candidate_schema)
        if row["requirement_id"] not in requirement_ids:
            raise CoverageComparisonError("v8 candidate references unknown CR")
        from .canonical_requirements import stable_v7_candidate_id

        if row["candidate_id"] != stable_v7_candidate_id(
            group_id=row["group_id"],
            project=row["project"],
            revision=row["revision"],
            chain_id=row["chain_id"],
            requirement_id=row["requirement_id"],
            failure_mode=row["failure_mode"],
            gate_ids=row["gate_ids"],
        ):
            raise CoverageComparisonError("v8 candidate identity mismatch")
    if len({row["candidate_id"] for row in provisional}) != len(provisional):
        raise CoverageComparisonError("duplicate v8 provisional candidates")
    if len({row["candidate_id"] for row in candidates}) != len(candidates):
        raise CoverageComparisonError("duplicate v8 canonical candidates")
    if not {row["candidate_id"] for row in candidates} <= {
        row["candidate_id"] for row in provisional
    }:
        raise CoverageComparisonError("v8 canonical candidates are not provisional")

    comparisons = _read_jsonl(root / "comparisons.jsonl")
    assessments = _read_jsonl(root / "requirement-assessments.jsonl")
    comparison_schema = _read_json(schema_root / "coverage-comparison-v7.schema.json")
    assessment_schema = _read_json(
        schema_root / "coverage-requirement-assessment-v7.schema.json"
    )
    for row in comparisons:
        validate_schema(row, comparison_schema)
    for row in assessments:
        validate_schema(row, assessment_schema)
    if len(comparisons) != 485 or len(
        {(row["project"], row["chain_id"]) for row in comparisons}
    ) != 485:
        raise CoverageComparisonError("v8 comparisons do not cover 485 chains")
    mercury = next(
        row
        for row in comparisons
        if (row["project"], row["chain_id"])
        == ("mercury-agent", "C-11e5d5e54b4a")
    )
    policy_cr_ids = {row["requirement_id"] for row in policy_requirements}
    policy_rows = [
        row for row in mercury["requirements"] if row["requirement_id"] in policy_cr_ids
    ]
    if len(policy_rows) != 4 or any(
        row["decision"] != "wrong-check" or not row["gate_ids"]
        for row in policy_rows
    ):
        raise CoverageComparisonError("Mercury v8 policy decisions are not four wrong-checks")

    selected = _read_jsonl(root / "canonical-router-selected.jsonl")
    excluded = _read_jsonl(root / "canonical-router-excluded.jsonl")
    if len(selected) > 64 or len(selected) + len(excluded) != 485 or len(
        {(row["project"], row["chain_id"]) for row in [*selected, *excluded]}
    ) != 485:
        raise CoverageComparisonError("v8 router does not partition 485 chains")
    origin_audit = _read_jsonl(root / "candidate-origin-audit.jsonl")
    if any(row["origin_disposition"] != "eligible" for row in origin_audit):
        raise CoverageComparisonError("v8 canonical candidate has origin mismatch")
    if {row["candidate_id"] for row in origin_audit} != {
        row["candidate_id"] for row in candidates
    }:
        raise CoverageComparisonError("v8 candidate origin audit coverage mismatch")

    ground_truth = _read_jsonl(root / "ground-truth-coverage.jsonl")
    training = [row for row in ground_truth if row.get("evaluation_partition") == "training"]
    found = sum(row["status"] == "covered" for row in training)
    missed = sum(row["status"] == "missed" for row in training)
    if found < 39 or found + missed != 43:
        raise CoverageComparisonError(
            f"v8 training recall gate failed: {found}/{found + missed}"
        )
    counts = manifest["counts"]
    expected_counts = {
        "eligible_comparisons": len(comparisons),
        "canonical_requirements": len(requirements),
        "provisional_candidates": len(provisional),
        "candidates": len(candidates),
        "router_selected": len(selected),
        "router_excluded": len(excluded),
        "training_found": found,
        "training_missed": missed,
    }
    if any(counts.get(key) != value for key, value in expected_counts.items()):
        raise CoverageComparisonError("v8 manifest artifact counts drifted")

    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        path = root / relative
        if not path.is_file() or sha256_file(path) != expected:
            raise CoverageComparisonError(f"v8 artifact inventory drift: {relative}")
    if inventory["tree_sha256"] != _tree_digest(inventory["files"]):
        raise CoverageComparisonError("v8 artifact tree digest mismatch")
    if manifest.get("artifact_inventory_sha256") != sha256_file(
        root / "artifact-inventory.json"
    ):
        raise CoverageComparisonError("v8 manifest inventory binding mismatch")
    return {
        "manifest": manifest,
        "requirements": len(requirements),
        "candidates": len(candidates),
        "training_found": found,
        "training_missed": missed,
    }


def analysis_plan_v8(root: Path) -> Mapping[str, Any]:
    result = validate_v8_artifacts(root)
    counts = result["manifest"]["counts"]
    return {
        "analysis_mode": ANALYSIS_MODE,
        "eligible_chains": counts["eligible_comparisons"],
        "canonical_requirements": counts["canonical_requirements"],
        "same_origin_witnesses": counts["same_origin_witnesses"],
        "same_origin_exclusions": counts["same_origin_exclusions"],
        "router_selected": counts["router_selected"],
        "router_excluded": counts["router_excluded"],
        "training_recall": f"{result['training_found']}/43",
        "claim": "training evaluation; not blind recall",
    }
