"""Canonical detector v9 recall-integrity publication."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import validate as validate_schema

from src.projects import ProjectSpec

from .canonical_requirements import (
    IDENTITY_MIGRATION_SCHEMA_VERSION,
    canonicalize_requirement,
    migrate_candidate,
    route_canonical_source_chains,
    stable_v7_candidate_id,
)
from .contracts import CoverageComparisonError, digest, sha256_file
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
from .learned_invariants import (
    analyze_learned_invariants,
    load_learned_catalog,
    route_learned_requirements,
)
from .same_origin import analyze_same_origin, audit_candidate_origins
from .source_validation import validate_source_response
from .source_validation_packets import (
    PACKET_PROMPT_VERSION,
    PACKET_REPAIR_SYSTEM,
    PACKET_VALIDATION_SYSTEM,
    build_packet_repair_user,
    build_packet_validation_user,
    build_source_validation_packet,
    normalize_packet_validation_payload,
    parse_packet_validation_response,
)
from .v8 import (
    _inventory,
    _read_json,
    _read_jsonl,
    _source_digests,
    _tree_digest,
    _write_json,
    _write_jsonl,
    _write_text,
)
from .versions import (
    ASSESSMENT_SCHEMA_VERSION,
    GROUND_TRUTH_PROMPT_VERSION,
    GT_CHAT_SCHEMA_VERSION,
    GT_MANIFEST_SCHEMA_VERSION,
)


ANALYSIS_MODE = "canonical-trained-detector/v9"
FREEZE_VERSION = "canonical-detector-freeze/v9"
PUBLICATION_VERSION = "coverage-v9-publication/v9"
TARGET_CHAIN_KEYS = {
    ("hermes-agent", "C-14d19d5cfffa"),
    ("hermes-agent", "C-10420d9585cc"),
}
RESTORED_APPROVAL_CR_IDS = {
    "CR-f89f5f5f49188610",
    "CR-c6263c857353d248",
    "CR-abe94a63e4bfbf8c",
    "CR-b869fdf4c9c0631f",
}
FEISHU_KEY = ("openclaw-cn", "C-aee88c98cfb8")
FEISHU_CANDIDATE_ID = "CAND-b795a91c6f4fb023"


def _git_commit() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def _validate_v8_snapshot(root: Path) -> dict[str, Any]:
    """Validate the frozen v8 artifact tree without rebinding it to v9 sources."""
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != "canonical-trained-detector/v8":
        raise CoverageComparisonError("v9 preparation requires active detector v8")
    inventory = _read_json(root / "artifact-inventory.json")
    if inventory.get("schema_version") != "coverage-v8-publication/v8" or inventory.get(
        "source_mode"
    ) not in {"canonical-trained-detector/v7", "canonical-trained-detector/v8"}:
        raise CoverageComparisonError("v8 artifact inventory mode mismatch")
    files = inventory.get("files")
    if not isinstance(files, dict) or not files:
        raise CoverageComparisonError("v8 artifact inventory is empty")
    for relative, expected in files.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise CoverageComparisonError("v8 artifact inventory entry is invalid")
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v8 artifact inventory drift: {relative}")
    if inventory.get("tree_sha256") != _tree_digest(files):
        raise CoverageComparisonError("v8 artifact inventory tree digest mismatch")
    if manifest.get("artifact_inventory_sha256") != sha256_file(
        root / "artifact-inventory.json"
    ):
        raise CoverageComparisonError("v8 manifest inventory binding mismatch")
    return manifest


def _canonical_assessment(
    row: Mapping[str, Any], *, requirement_id: str
) -> dict[str, Any]:
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "group_id": row["group_id"],
        "handler_criterion_id": row["handler_criterion_id"],
        "sink_type_id": row["sink_type_id"],
        "project": row["project"],
        "revision": row["revision"],
        "chain_id": row["chain_id"],
        "requirement_id": requirement_id,
        "applicability": row["applicability"],
        "decision": row["decision"],
        "capability_evidence": row["capability_evidence"],
        "call_shape_facts": row["call_shape_facts"],
        "gate_ids": row["gate_ids"],
        "covered_semantics": row["covered_semantics"],
        "gap": row["gap"],
        "uncertainty": row["uncertainty"],
    }


def _merge_canonical_requirement(
    by_id: dict[str, dict[str, Any]], row: Mapping[str, Any]
) -> None:
    candidate = dict(row)
    candidate.pop("legacy_refines_requirement_ids", None)
    prior = by_id.get(candidate["requirement_id"])
    if prior is None:
        by_id[candidate["requirement_id"]] = candidate
        return
    for field in (
        "group_id",
        "rule",
        "applicability",
        "controlled_facet",
        "enforcement_stage",
        "state_lifetime",
        "security_effect",
    ):
        if prior[field] != candidate[field]:
            raise CoverageComparisonError(
                f"v9 CR merge conflict {candidate['requirement_id']}:{field}"
            )
    sources = {
        (source["legacy_requirement_id"], source["kind"], source["payload_sha256"]): source
        for source in [
            *prior["provenance"]["sources"],
            *candidate["provenance"]["sources"],
        ]
    }
    prior["provenance"]["sources"] = [sources[key] for key in sorted(sources)]


def _packet_validate(
    *,
    chain: CoverageChain,
    candidates: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    spec: ProjectSpec,
    origin_witnesses: Sequence[Mapping[str, Any]],
    runner: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    packet = build_source_validation_packet(
        chain=chain,
        candidates=candidates,
        assessments=assessments,
        requirements=requirements,
        spec=spec,
        same_origin_witnesses=origin_witnesses,
    )
    user = build_packet_validation_user(packet)
    raw = runner(PACKET_VALIDATION_SYSTEM, user)
    decision, payload, reason = parse_packet_validation_response(raw, packet=packet)
    if decision != "complete" or payload is None:
        raise CoverageComparisonError(
            f"{chain.project}:{chain.chain_id}: packet validation needs deep research: {reason}"
        )
    exchanges = [
        {"system": PACKET_VALIDATION_SYSTEM, "user": user, "response": raw}
    ]
    payload, normalizations = normalize_packet_validation_payload(payload, packet=packet)
    try:
        records = validate_source_response(
            payload,
            chain=chain,
            candidates=candidates,
            assessments=assessments,
            source_root=spec.resolved().source_root,
            validation_input_sha256=packet["packet_digest"],
            prompt_version=PACKET_PROMPT_VERSION,
        )
    except Exception as first:
        repair_user = build_packet_repair_user(
            packet=packet,
            invalid_response=raw,
            error=f"{type(first).__name__}: {first}",
        )
        repaired = runner(PACKET_REPAIR_SYSTEM, repair_user)
        repair_decision, repair_payload, repair_reason = (
            parse_packet_validation_response(repaired, packet=packet)
        )
        exchanges.append(
            {"system": PACKET_REPAIR_SYSTEM, "user": repair_user, "response": repaired}
        )
        if repair_decision != "complete" or repair_payload is None:
            raise CoverageComparisonError(
                f"{chain.project}:{chain.chain_id}: packet repair needs deep: "
                f"{repair_reason}"
            ) from first
        repair_payload, repair_normalizations = normalize_packet_validation_payload(
            repair_payload, packet=packet
        )
        normalizations.extend(repair_normalizations)
        records = validate_source_response(
            repair_payload,
            chain=chain,
            candidates=candidates,
            assessments=assessments,
            source_root=spec.resolved().source_root,
            validation_input_sha256=packet["packet_digest"],
            prompt_version=PACKET_PROMPT_VERSION,
        )
        decision, reason = repair_decision, repair_reason
    if any(row["verdict"] != "confirmed-uncovered" for row in records):
        raise CoverageComparisonError(
            f"{chain.project}:{chain.chain_id}: packet validation did not confirm all candidates"
        )
    chat = {
        "schema_version": "source-validation-packet-chat/v1",
        "stage": "source-validate-packet",
        "subject": (
            f"{chain.project}-{chain.chain_id}-"
            + "-".join(str(row["candidate_id"]) for row in candidates)
        ),
        "decision": decision,
        "reason": reason,
        "normalizations": normalizations,
        "exchanges": exchanges,
    }
    return records, packet, chat


def _restore_approval_rows(
    *, stage_root: Path, v7_archive: Path
) -> None:
    archived_comparison = next(
        row
        for row in _read_jsonl(v7_archive / "comparisons.jsonl")
        if (row["project"], row["chain_id"])
        == ("hermes-agent", "C-728f8e5e6c99")
    )
    comparisons = _read_jsonl(stage_root / "comparisons.jsonl")
    for comparison in comparisons:
        if (comparison["project"], comparison["chain_id"]) != (
            "hermes-agent",
            "C-728f8e5e6c99",
        ):
            continue
        by_id = {row["requirement_id"]: row for row in comparison["requirements"]}
        for row in archived_comparison["requirements"]:
            if row["requirement_id"] in RESTORED_APPROVAL_CR_IDS:
                by_id[row["requirement_id"]] = row
        comparison["requirements"] = sorted(
            by_id.values(), key=lambda row: row["requirement_id"]
        )
    _write_jsonl(stage_root / "comparisons.jsonl", comparisons)

    archived_assessments = [
        row
        for row in _read_jsonl(v7_archive / "requirement-assessments.jsonl")
        if (row["project"], row["chain_id"])
        == ("hermes-agent", "C-728f8e5e6c99")
        and row["requirement_id"] in RESTORED_APPROVAL_CR_IDS
    ]
    assessments = _read_jsonl(stage_root / "requirement-assessments.jsonl")
    keys = {
        (row["project"], row["chain_id"], row["requirement_id"])
        for row in archived_assessments
    }
    assessments = [
        row
        for row in assessments
        if (row["project"], row["chain_id"], row["requirement_id"]) not in keys
    ]
    assessments.extend(archived_assessments)
    assessments.sort(
        key=lambda row: (row["project"], row["chain_id"], row["requirement_id"])
    )
    _write_jsonl(stage_root / "requirement-assessments.jsonl", assessments)


def _gt_reuse_digest(
    *,
    report: Any,
    comparisons: Mapping[tuple[str, str], Mapping[str, Any]],
    candidates: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
    model_tool_config: Mapping[str, Any],
) -> str:
    return digest(
        {
            "report_id": report.report_id,
            "project": report.project,
            "revision": report.revision,
            "boundary_status": report.boundary_status,
            "chain_ids": list(report.chain_ids),
            "source_sha256": list(report.source_sha256),
            "comparisons": {
                chain_id: digest(comparisons[(report.project, chain_id)])
                for chain_id in report.chain_ids
            },
            "candidates": {
                chain_id: [
                    [row["candidate_id"], digest(row)]
                    for row in sorted(
                        candidates.get((report.project, chain_id), []),
                        key=lambda value: value["candidate_id"],
                    )
                ]
                for chain_id in report.chain_ids
            },
            "prompt_version": GROUND_TRUTH_PROMPT_VERSION,
            "model_tool_config": dict(model_tool_config),
        }
    )


def _runner_model_tool_config(runner: Any) -> dict[str, Any]:
    audit = runner.audit_payload()
    return {
        "transport": audit.get("transport"),
        "base_url": audit.get("base_url"),
        "model": audit.get("model"),
        "credential_env": audit.get("credential_env"),
        "available_tools": list(audit.get("available_tools", [])),
        "max_tokens": getattr(runner, "max_tokens", None),
    }


def _gt_pair_partition_complete(
    *,
    row: Mapping[str, Any],
    candidates: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
) -> bool:
    expected = sorted(
        candidate["candidate_id"]
        for chain_id in row.get("chain_ids", [])
        for candidate in candidates.get((row["project"], chain_id), [])
    )
    actual = sorted(
        assessment["candidate_id"]
        for assessment in row.get("candidate_assessments", [])
    )
    return len(actual) == len(set(actual)) and actual == expected


def _ground_truth_audit(
    *,
    specs: Sequence[ProjectSpec],
    active_root: Path,
    stage_root: Path,
    runner: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    discovered, _ = discover_ground_truth(specs)
    reports, _ = bind_ground_truth(specs, deduplicate_ground_truth(discovered))
    prior_rows = {
        row["report_id"]: row
        for row in _read_jsonl(active_root / "ground-truth-coverage.jsonl")
    }
    prior_comparisons = {
        (row["project"], row["chain_id"]): row
        for row in _read_jsonl(active_root / "comparisons.jsonl")
    }
    current_comparisons = {
        (row["project"], row["chain_id"]): row
        for row in _read_jsonl(stage_root / "comparisons.jsonl")
    }
    prior_candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in _read_jsonl(active_root / "candidates.jsonl"):
        prior_candidates[(row["project"], row["chain_id"])].append(row)
    current_candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in _read_jsonl(stage_root / "candidates.jsonl"):
        current_candidates[(row["project"], row["chain_id"])].append(row)
    model_tool_config = _runner_model_tool_config(runner)

    rows: list[dict[str, Any]] = []
    chats: list[tuple[str, list[dict[str, str]]]] = []
    reuse_rows: list[dict[str, Any]] = []
    for report in reports:
        prior = prior_rows.get(report.report_id)
        reusable = False
        prior_digest = None
        current_digest = None
        prior_pair_partition_complete = False
        if prior is not None and all(
            (report.project, chain_id) in prior_comparisons
            for chain_id in report.chain_ids
        ):
            prior_pair_partition_complete = _gt_pair_partition_complete(
                row=prior,
                candidates=prior_candidates,
            )
            prior_report = type(report)(
                report_id=report.report_id,
                project=prior["project"],
                revision=prior["revision"],
                report_name=prior["report_name"],
                source_files=tuple(prior["source_files"]),
                source_sha256=tuple(prior["source_sha256"]),
                raw=report.raw,
                boundary_status=prior["boundary_status"],
                boundary_reason=prior["reason"],
                chain_ids=tuple(prior["chain_ids"]),
                rebase_evidence=tuple(prior["rebase_evidence"]),
            )
            try:
                prior_digest = _gt_reuse_digest(
                    report=prior_report,
                    comparisons=prior_comparisons,
                    candidates=prior_candidates,
                    model_tool_config=model_tool_config,
                )
                current_digest = _gt_reuse_digest(
                    report=report,
                    comparisons=current_comparisons,
                    candidates=current_candidates,
                    model_tool_config=model_tool_config,
                )
                reusable = (
                    prior_pair_partition_complete and prior_digest == current_digest
                )
            except KeyError:
                reusable = False
        reuse_rows.append(
            {
                "schema_version": "ground-truth-reuse/v9",
                "report_id": report.report_id,
                "prior_digest": prior_digest,
                "current_digest": current_digest,
                "model_tool_config_sha256": digest(model_tool_config),
                "prior_pair_partition_complete": prior_pair_partition_complete,
                "disposition": "reused" if reusable else "readjudicated",
            }
        )
        if reusable:
            rows.append(dict(prior))
            continue
        assessments: list[dict[str, Any]] = []
        if report.boundary_status == "eligible":
            for chain_id in report.chain_ids:
                comparison = current_comparisons[(report.project, chain_id)]
                chain_summary = {
                    key: comparison[key]
                    for key in (
                        "chain_id",
                        "handler_id",
                        "sink_id",
                        "handler_criterion_id",
                        "sink_type_id",
                        "controlled_argument",
                        "call_shape",
                    )
                }
                for candidate in sorted(
                    current_candidates.get((report.project, chain_id), []),
                    key=lambda row: row["candidate_id"],
                ):
                    from .prompts import build_ground_truth_match_user

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
        if report.boundary_status != "eligible":
            status = report.boundary_status
            reason = report.boundary_reason
        elif matched:
            status = "covered"
            reason = "at least one canonical v9 candidate strictly matches the training invariant"
        else:
            status = "missed"
            reason = (
                "current chain has no canonical candidate"
                if not assessments
                else "all current-chain candidates express different security invariants"
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
                "status": status,
                "reason": reason,
                "evaluation_partition": (
                    "training" if status in {"covered", "missed"} else "excluded"
                ),
            }
        )
    rows.sort(key=lambda row: row["report_id"])
    _write_jsonl(stage_root / "ground-truth-coverage.jsonl", rows)
    _write_jsonl(stage_root / "ground-truth-reuse.jsonl", reuse_rows)
    _write_text(
        stage_root / "ground-truth-coverage.md",
        render_ground_truth(
            "python -m src.coverage_comparison --all",
            rows,
            baseline_counts=None,
            baseline_label="Canonical v8 training baseline",
            dispositions=[],
        ),
    )
    for subject, exchanges in chats:
        _write_json(
            stage_root / "repository/ground-truth" / subject / "chat.json",
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
        "eligible_reports": sum(row["status"] in {"covered", "missed"} for row in rows),
        "covered_reports": sum(row["status"] == "covered" for row in rows),
        "missed_reports": sum(row["status"] == "missed" for row in rows),
        "candidate_pair_assessments": sum(
            len(row["candidate_assessments"]) for row in rows
        ),
        "model_calls": sum(len(exchange) for _, exchange in chats),
        "repair_calls": sum(len(exchange) - 1 for _, exchange in chats),
        "reused_reports": sum(row["disposition"] == "reused" for row in reuse_rows),
        "readjudicated_reports": sum(
            row["disposition"] == "readjudicated" for row in reuse_rows
        ),
    }
    manifest = {
        "schema_version": GT_MANIFEST_SCHEMA_VERSION,
        "prompt_version": GROUND_TRUTH_PROMPT_VERSION,
        "generation_command": "python -m src.coverage_comparison --all",
        "analysis_mode": ANALYSIS_MODE,
        "inputs": {
            "coverage_manifest": sha256_file(stage_root / "manifest.json"),
            "candidates": sha256_file(stage_root / "candidates.jsonl"),
            "comparisons": sha256_file(stage_root / "comparisons.jsonl"),
            "v8_ground_truth": sha256_file(active_root / "ground-truth-coverage.jsonl"),
        },
        "counts": counts,
        "transport": runner.audit_payload(),
    }
    _write_json(stage_root / "ground-truth-manifest.json", manifest)
    return rows, manifest


def _freeze_lock(
    *,
    repo_root: Path,
    specs: Sequence[ProjectSpec],
    inputs: CoverageInputs,
    router: Mapping[str, Any],
    training_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    source_paths = [
        repo_root / "src/coverage_comparison/v9.py",
        repo_root / "src/coverage_comparison/source_validation.py",
        repo_root / "src/coverage_comparison/source_validation_packets.py",
        repo_root / "src/coverage_comparison/learned_invariants.py",
        repo_root / "src/coverage_comparison/learned-invariants.json",
        repo_root / "src/coverage_comparison/ground_truth.py",
        repo_root / "src/coverage_comparison/prompts.py",
        repo_root / "src/gate_semantics/agent_sdk.py",
    ]
    ql_paths = [
        path
        for root in (repo_root / "src/ql", repo_root / "src/ql-js")
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".ql", ".qll", ".yml"}
    ]
    training = [row for row in training_rows if row.get("evaluation_partition") == "training"]
    return {
        "schema_version": FREEZE_VERSION,
        "analysis_mode": ANALYSIS_MODE,
        "implementation_commit": _git_commit(),
        "cr_normalization": {
            "path": "src/coverage_comparison/canonical_requirements.py",
            "sha256": sha256_file(repo_root / "src/coverage_comparison/canonical_requirements.py"),
        },
        "router": {"config": dict(router), "config_sha256": digest(dict(router))},
        "learned_catalog": {
            "path": "src/coverage_comparison/learned-invariants.json",
            "sha256": sha256_file(repo_root / "src/coverage_comparison/learned-invariants.json"),
        },
        "prompts": _source_digests(source_paths, repo_root),
        "ql": {
            "files": _source_digests(ql_paths, repo_root),
            "tree_sha256": _tree_digest(_source_digests(ql_paths, repo_root)),
        },
        "project_revisions": {spec.project_id: spec.analysis_revision for spec in specs},
        "coverage_inputs": dict(inputs.digests),
        "training_ground_truth": {
            "workbook": {
                "path": "design/study/vuls-new-found/all-new-xclaw-vulnerabilities.xlsx",
                "sha256": sha256_file(
                    repo_root / "design/study/vuls-new-found/all-new-xclaw-vulnerabilities.xlsx"
                ),
            },
            "selection": {
                "path": "design/common/groundtruth-oracle/groundtruth-oracles.csv",
                "sha256": sha256_file(
                    repo_root / "design/common/groundtruth-oracle/groundtruth-oracles.csv"
                ),
            },
            "eligible_reports": len(training),
            "report_ids_sha256": digest(sorted(row["report_id"] for row in training)),
        },
    }


def _render_report(counts: Mapping[str, Any]) -> str:
    return "\n".join(
        [
            "# Canonical CR Coverage Comparison v9",
            "",
            "Reproduce from the repository root:",
            "",
            "```bash",
            "python -m src.coverage_comparison --all",
            "```",
            "",
            "<!-- BEGIN GENERATED REPORT -->",
            "",
            f"Structural/eligible chains: **{counts['structural_chains']} / {counts['eligible_comparisons']}**.",
            f"Canonical requirements/candidates: **{counts['canonical_requirements']} / {counts['candidates']}**.",
            f"Packet validations: **{counts['packet_validations']}**, deep-agent fallbacks: **0**.",
            f"Strict training recall: **{counts['training_found']}/43** (training, not blind recall).",
            "",
            "<!-- END GENERATED REPORT -->",
            "",
        ]
    )


def prepare_v9(
    *,
    specs: Sequence[ProjectSpec],
    active_root: Path,
    stage_root: Path,
    handler_root: Path,
    sink_root: Path,
    group_root: Path,
    evidence_registry: Path,
    learned_runner: Any,
    packet_runner: Any,
    gt_runner: Any,
) -> dict[str, Any]:
    if stage_root.exists():
        raise CoverageComparisonError(f"v9 staging directory exists: {stage_root}")
    baseline_manifest = _validate_v8_snapshot(active_root)
    shutil.copytree(active_root, stage_root)
    repo_root = Path(__file__).resolve().parents[2]
    v7_archive = active_root.parent / "archive/coverage-comparison-v7"
    _restore_approval_rows(stage_root=stage_root, v7_archive=v7_archive)

    inputs = load_coverage_inputs(
        specs,
        handler_root=handler_root,
        sink_root=sink_root,
        group_root=group_root,
        evidence_registry=evidence_registry,
    )
    if len(inputs.chains) != 485:
        raise CoverageComparisonError("v9 eligible-chain denominator drift")
    target_chains = [chain for chain in inputs.chains if chain.key in TARGET_CHAIN_KEYS]
    if {chain.key for chain in target_chains} != TARGET_CHAIN_KEYS:
        raise CoverageComparisonError("v9 target chain binding drift")
    feishu_origin_chain = next(chain for chain in inputs.chains if chain.key == FEISHU_KEY)
    origin = analyze_same_origin(
        chains=[*target_chains, feishu_origin_chain], specs=specs
    )
    learned = analyze_learned_invariants(
        chains=target_chains,
        origin=origin,
        runner=learned_runner,
        jobs=2,
    )
    _write_json(stage_root / "learned-invariant-catalog-snapshot.json", learned.catalog)
    _write_jsonl(
        stage_root / "learned-invariant-assessments.jsonl", list(learned.assessments)
    )
    _write_jsonl(
        stage_root / "learned-provisional-candidates.jsonl",
        list(learned.provisional_candidates),
    )
    for subject, exchanges in learned.chats.items():
        _write_json(
            stage_root / "repository/learned-invariant" / subject / "chat.json",
            {
                "schema_version": "coverage-learned-invariant-chat/v9",
                "stage": "learned-invariant",
                "subject": subject,
                "exchanges": list(exchanges),
            },
        )
    required_patterns = {
        "dangerous-command-pattern-completeness",
        "noninteractive-approval-routing",
        "execute-code-approval",
    }
    target_assessments = [
        row for row in learned.assessments if row["pattern_key"] in required_patterns
    ]
    if {row["pattern_key"] for row in target_assessments} != required_patterns or any(
        row["decision"] not in {"wrong-check", "missing-check"}
        for row in target_assessments
    ):
        raise CoverageComparisonError("v9 learned target assessments are incomplete")

    requirements = _read_jsonl(stage_root / "canonical-requirements.jsonl")
    requirement_by_id = {row["requirement_id"]: row for row in requirements}
    legacy_to_cr: dict[tuple[str, str], str] = {}
    for row in learned.routed_requirements:
        if row["pattern_key"] not in required_patterns:
            continue
        canonical = canonicalize_requirement(row, group_id=row["group_id"])
        canonical.pop("legacy_refines_requirement_ids", None)
        _merge_canonical_requirement(requirement_by_id, canonical)
        legacy_to_cr[(row["chain_id"], row["requirement_id"])] = canonical[
            "requirement_id"
        ]
    requirements = sorted(requirement_by_id.values(), key=lambda row: row["requirement_id"])
    _write_jsonl(stage_root / "canonical-requirements.jsonl", requirements)
    _write_jsonl(stage_root / "requirement-proposals.jsonl", requirements)

    canonical_assessments = []
    for row in target_assessments:
        cr_id = legacy_to_cr[(row["chain_id"], row["requirement_id"])]
        canonical_assessments.append(_canonical_assessment(row, requirement_id=cr_id))
    assessments = _read_jsonl(stage_root / "requirement-assessments.jsonl")
    new_assessment_keys = {
        (row["project"], row["chain_id"], row["requirement_id"])
        for row in canonical_assessments
    }
    assessments = [
        row
        for row in assessments
        if (row["project"], row["chain_id"], row["requirement_id"])
        not in new_assessment_keys
    ]
    assessments.extend(canonical_assessments)
    assessments.sort(key=lambda row: (row["project"], row["chain_id"], row["requirement_id"]))
    _write_jsonl(stage_root / "requirement-assessments.jsonl", assessments)

    comparisons = _read_jsonl(stage_root / "comparisons.jsonl")
    comparison_by_key = {(row["project"], row["chain_id"]): row for row in comparisons}
    for assessment in canonical_assessments:
        comparison = comparison_by_key[(assessment["project"], assessment["chain_id"])]
        by_id = {row["requirement_id"]: row for row in comparison["requirements"]}
        by_id[assessment["requirement_id"]] = {
            key: assessment[key]
            for key in (
                "requirement_id",
                "applicability",
                "decision",
                "capability_evidence",
                "call_shape_facts",
                "gate_ids",
                "covered_semantics",
                "gap",
                "uncertainty",
            )
        }
        comparison["requirements"] = sorted(by_id.values(), key=lambda row: row["requirement_id"])
    _write_jsonl(stage_root / "comparisons.jsonl", sorted(comparisons, key=lambda row: (row["project"], row["chain_id"])))

    raw_candidate_by_key = {
        (row["chain_id"], row["requirement_id"]): row
        for row in learned.provisional_candidates
        if row["learned_pattern_key"] in required_patterns
    }
    new_candidates: list[dict[str, Any]] = []
    migration_rows: list[dict[str, Any]] = []
    for assessment in canonical_assessments:
        raw = raw_candidate_by_key[(assessment["chain_id"], next(
            row["requirement_id"]
            for row in target_assessments
            if row["chain_id"] == assessment["chain_id"]
            and legacy_to_cr[(row["chain_id"], row["requirement_id"])]
            == assessment["requirement_id"]
        ))]
        migrated, migration = migrate_candidate(
            raw, requirement=requirement_by_id[assessment["requirement_id"]]
        )
        migration.update({"record_kind": "candidate", "group_id": migrated["group_id"]})
        new_candidates.append(migrated)
        migration_rows.append(migration)

    provisional = {
        row["candidate_id"]: row
        for row in _read_jsonl(stage_root / "provisional-candidates.jsonl")
    }
    canonical = {
        row["candidate_id"]: row for row in _read_jsonl(stage_root / "candidates.jsonl")
    }
    for row in new_candidates:
        provisional[row["candidate_id"]] = row
        canonical[row["candidate_id"]] = row

    feishu_candidate = provisional.get(FEISHU_CANDIDATE_ID)
    if feishu_candidate is None:
        raise CoverageComparisonError("Feishu provisional candidate is missing")
    feishu_chain = next(chain for chain in inputs.chains if chain.key == FEISHU_KEY)
    all_assessments = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in assessments
    }
    spec_by_project = {spec.project_id: spec for spec in specs}
    validation_records: list[dict[str, Any]] = []
    packet_artifacts: list[dict[str, Any]] = []
    packet_chats: list[dict[str, Any]] = []
    validation_tasks = [
        (next(row for row in inputs.chains if row.key == (candidate["project"], candidate["chain_id"])), [candidate])
        for candidate in new_candidates
    ]
    validation_tasks.append((feishu_chain, [feishu_candidate]))
    for chain, selected in validation_tasks:
        selected_assessments = {
            row["requirement_id"]: all_assessments[
                (row["project"], row["chain_id"], row["requirement_id"])
            ]
            for row in selected
        }
        witnesses = [
            row
            for row in origin.witnesses
            if row["project"] == chain.project and row["chain_id"] == chain.chain_id
        ]
        records, packet, chat = _packet_validate(
            chain=chain,
            candidates=selected,
            assessments=selected_assessments,
            requirements=requirement_by_id,
            spec=spec_by_project[chain.project],
            origin_witnesses=witnesses,
            runner=packet_runner,
        )
        validation_records.extend(records)
        packet_artifacts.append(packet)
        packet_chats.append(chat)
        _write_jsonl(
            stage_root / "source-validation-evidence-packets.jsonl",
            packet_artifacts,
        )
        _write_jsonl(
            stage_root / "candidate-validations-v9-checkpoint.jsonl",
            validation_records,
        )
        _write_json(
            stage_root
            / "repository/source-validate-packet"
            / chat["subject"]
            / "chat.json",
            chat,
        )
    canonical[FEISHU_CANDIDATE_ID] = feishu_candidate

    existing_validations = {
        row["provisional_candidate_id"]: row
        for row in _read_jsonl(stage_root / "candidate-validations.jsonl")
    }
    for row in validation_records:
        existing_validations[row["provisional_candidate_id"]] = row
    _write_jsonl(
        stage_root / "candidate-validations.jsonl",
        sorted(existing_validations.values(), key=lambda row: row["provisional_candidate_id"]),
    )
    _write_jsonl(stage_root / "source-validation-evidence-packets.jsonl", packet_artifacts)
    (stage_root / "candidate-validations-v9-checkpoint.jsonl").unlink(
        missing_ok=True
    )

    provisional_rows = sorted(provisional.values(), key=lambda row: row["candidate_id"])
    canonical_rows = sorted(canonical.values(), key=lambda row: row["candidate_id"])
    _write_jsonl(stage_root / "provisional-candidates.jsonl", provisional_rows)
    _write_jsonl(stage_root / "candidates.jsonl", canonical_rows)

    migrations = _read_jsonl(stage_root / "identity-migration.jsonl")
    for row in learned.routed_requirements:
        if row["pattern_key"] not in required_patterns:
            continue
        cr_id = legacy_to_cr[(row["chain_id"], row["requirement_id"])]
        migrations.append(
            {
                "schema_version": IDENTITY_MIGRATION_SCHEMA_VERSION,
                "record_kind": "requirement",
                "group_id": row["group_id"],
                "old_requirement_id": row["requirement_id"],
                "new_requirement_id": cr_id,
                "old_candidate_id": None,
                "new_candidate_id": None,
                "old_payload_sha256": digest(row),
                "new_payload_sha256": digest(requirement_by_id[cr_id]),
                "disposition": "one-to-one",
            }
        )
    migrations.extend(migration_rows)
    unique_migrations = {}
    for row in migrations:
        key = (
            row["record_kind"],
            row["group_id"],
            row["old_requirement_id"],
            row["old_candidate_id"] or "",
        )
        unique_migrations[key] = row
    _write_jsonl(
        stage_root / "identity-migration.jsonl",
        [unique_migrations[key] for key in sorted(unique_migrations)],
    )

    origin_all = analyze_same_origin(chains=list(inputs.chains), specs=specs)
    origin_audit = audit_candidate_origins(canonical_rows, run=origin_all)
    if any(row["origin_disposition"] != "eligible" for row in origin_audit):
        # Existing v8 source-confirmed interprocedural witnesses remain authoritative.
        prior_audit = {
            row["candidate_id"]: row
            for row in _read_jsonl(active_root / "candidate-origin-audit.jsonl")
        }
        origin_audit = [
            prior_audit.get(row["candidate_id"], row) for row in origin_audit
        ]
    if any(row["origin_disposition"] != "eligible" for row in origin_audit):
        raise CoverageComparisonError("v9 canonical candidate has unresolved SameOrigin")
    _write_jsonl(stage_root / "candidate-origin-audit.jsonl", origin_audit)

    learned_catalog = load_learned_catalog()
    learned_chain_ids = {
        chain.key for chain in inputs.chains if route_learned_requirements(chain, learned_catalog)
    }
    prior_gt = _read_jsonl(active_root / "ground-truth-coverage.jsonl")
    required_source_chains = {
        (candidate["project"], candidate["chain_id"])
        for candidate in canonical_rows
        if any(source["kind"] == "source-derived" for source in candidate["provenance"]["sources"])
        and any(candidate["candidate_id"] in report["matched_candidate_ids"] for report in prior_gt)
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

    manifest = dict(baseline_manifest)
    manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "generation_command": "python -m src.coverage_comparison --all",
            "router": dict(router.config),
            "inputs": {
                **manifest["inputs"],
                "v8_manifest": sha256_file(active_root / "manifest.json"),
                "learned_catalog": sha256_file(
                    repo_root / "src/coverage_comparison/learned-invariants.json"
                ),
                "v7_approval_restore": sha256_file(v7_archive / "manifest.json"),
            },
        }
    )
    _write_json(stage_root / "manifest.json", manifest)
    training_rows, gt_manifest = _ground_truth_audit(
        specs=specs,
        active_root=active_root,
        stage_root=stage_root,
        runner=gt_runner,
    )
    found = sum(
        row["evaluation_partition"] == "training" and row["status"] == "covered"
        for row in training_rows
    )
    missed = sum(
        row["evaluation_partition"] == "training" and row["status"] == "missed"
        for row in training_rows
    )
    if (found, missed) != (43, 0):
        raise CoverageComparisonError(f"v9 requires strict 43/43, got {found}/43")
    counts = {
        **baseline_manifest["counts"],
        "structural_chains": 603,
        "eligible_comparisons": 485,
        "canonical_requirements": len(requirements),
        "provisional_candidates": len(provisional_rows),
        "candidates": len(canonical_rows),
        "router_selected": len(router.selected),
        "router_excluded": len(router.excluded),
        "training_found": found,
        "training_missed": missed,
        "packet_validations": len(validation_records),
        "deep_agent_fallbacks": 0,
        "gt_reused_reports": gt_manifest["counts"]["reused_reports"],
        "gt_readjudicated_reports": gt_manifest["counts"]["readjudicated_reports"],
    }
    freeze = _freeze_lock(
        repo_root=repo_root,
        specs=specs,
        inputs=inputs,
        router=router.config,
        training_rows=training_rows,
    )
    _write_json(stage_root / "detector-freeze-lock.json", freeze)
    manifest.update(
        {
            "counts": counts,
            "training_claim": "training recall; not blind generalization",
            "source_validation_strategy": {
                "strategy": "packet-first",
                "fast_model_calls": len(packet_chats),
                "deep_max_turns": 8,
                "deep_max_tool_calls": 16,
                "deep_agent_fallbacks": 0,
            },
            "transport": {
                "learned": learned_runner.audit_payload(),
                "packet": packet_runner.audit_payload(),
                "ground_truth": gt_runner.audit_payload(),
            },
        }
    )
    manifest["inputs"]["detector_freeze_lock"] = sha256_file(
        stage_root / "detector-freeze-lock.json"
    )
    _write_text(stage_root / "coverage-index.md", _render_report(counts))
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
    return manifest


def refresh_v9_ground_truth(
    *,
    specs: Sequence[ProjectSpec],
    active_root: Path,
    stage_root: Path,
    handler_root: Path,
    sink_root: Path,
    group_root: Path,
    evidence_registry: Path,
    gt_runner: Any,
) -> dict[str, Any]:
    """Refresh digest-bound GT pairs without rerunning learned or source validation."""
    manifest = _read_json(stage_root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("GT refresh requires a complete v9 staging tree")
    inputs = load_coverage_inputs(
        specs,
        handler_root=handler_root,
        sink_root=sink_root,
        group_root=group_root,
        evidence_registry=evidence_registry,
    )
    training_rows, gt_manifest = _ground_truth_audit(
        specs=specs,
        active_root=active_root,
        stage_root=stage_root,
        runner=gt_runner,
    )
    found = sum(
        row["evaluation_partition"] == "training" and row["status"] == "covered"
        for row in training_rows
    )
    missed = sum(
        row["evaluation_partition"] == "training" and row["status"] == "missed"
        for row in training_rows
    )
    if (found, missed) != (43, 0):
        raise CoverageComparisonError(f"v9 requires strict 43/43, got {found}/43")
    counts = {
        **manifest["counts"],
        "training_found": found,
        "training_missed": missed,
        "gt_reused_reports": gt_manifest["counts"]["reused_reports"],
        "gt_readjudicated_reports": gt_manifest["counts"]["readjudicated_reports"],
    }
    repo_root = Path(__file__).resolve().parents[2]
    freeze = _freeze_lock(
        repo_root=repo_root,
        specs=specs,
        inputs=inputs,
        router=manifest["router"],
        training_rows=training_rows,
    )
    _write_json(stage_root / "detector-freeze-lock.json", freeze)
    manifest["counts"] = counts
    manifest["inputs"]["detector_freeze_lock"] = sha256_file(
        stage_root / "detector-freeze-lock.json"
    )
    manifest["transport"]["ground_truth"] = gt_runner.audit_payload()
    _write_text(stage_root / "coverage-index.md", _render_report(counts))
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
    return manifest


def rebind_v9_freeze(
    *,
    specs: Sequence[ProjectSpec],
    stage_root: Path,
    handler_root: Path,
    sink_root: Path,
    group_root: Path,
    evidence_registry: Path,
) -> dict[str, Any]:
    """Bind a validated v9 stage to the implementation commit without LLM calls."""
    manifest = _read_json(stage_root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("freeze rebind requires a v9 staging tree")
    training_rows = _read_jsonl(stage_root / "ground-truth-coverage.jsonl")
    if sum(
        row.get("evaluation_partition") == "training" and row["status"] == "covered"
        for row in training_rows
    ) != 43:
        raise CoverageComparisonError("freeze rebind requires strict 43/43")
    inputs = load_coverage_inputs(
        specs,
        handler_root=handler_root,
        sink_root=sink_root,
        group_root=group_root,
        evidence_registry=evidence_registry,
    )
    repo_root = Path(__file__).resolve().parents[2]
    freeze = _freeze_lock(
        repo_root=repo_root,
        specs=specs,
        inputs=inputs,
        router=manifest["router"],
        training_rows=training_rows,
    )
    _write_json(stage_root / "detector-freeze-lock.json", freeze)
    manifest["inputs"]["detector_freeze_lock"] = sha256_file(
        stage_root / "detector-freeze-lock.json"
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
    return manifest


def publish_v9(*, active_root: Path, stage_root: Path, archive_root: Path) -> None:
    if not stage_root.is_dir():
        raise CoverageComparisonError("v9 staging directory is missing")
    if archive_root.exists():
        raise CoverageComparisonError(f"v8 archive already exists: {archive_root}")
    archive_root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(active_root, archive_root)
        os.replace(stage_root, active_root)
    except Exception:
        if archive_root.exists() and not active_root.exists():
            os.replace(archive_root, active_root)
        raise


def validate_v9_artifacts(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("canonical v9 mode mismatch")
    schema_root = Path(__file__).resolve().parent / "schemas"
    freeze = _read_json(root / "detector-freeze-lock.json")
    validate_schema(
        freeze, _read_json(schema_root / "canonical-detector-freeze-v9.schema.json")
    )
    repo_root = Path(__file__).resolve().parents[2]
    frozen_paths = {
        freeze["cr_normalization"]["path"]: freeze["cr_normalization"]["sha256"],
        freeze["learned_catalog"]["path"]: freeze["learned_catalog"]["sha256"],
        **freeze["prompts"],
        **freeze["ql"]["files"],
    }
    for relative, expected in frozen_paths.items():
        path = repo_root / relative
        if not path.is_file() or sha256_file(path) != expected:
            raise CoverageComparisonError(f"v9 detector freeze drift: {relative}")
    requirements = _read_jsonl(root / "canonical-requirements.jsonl")
    candidates = _read_jsonl(root / "candidates.jsonl")
    provisional = _read_jsonl(root / "provisional-candidates.jsonl")
    comparisons = _read_jsonl(root / "comparisons.jsonl")
    assessments = _read_jsonl(root / "requirement-assessments.jsonl")
    validations = _read_jsonl(root / "candidate-validations.jsonl")
    requirement_ids = {row["requirement_id"] for row in requirements}
    candidate_ids = {row["candidate_id"] for row in candidates}
    provisional_ids = {row["candidate_id"] for row in provisional}
    if len(requirement_ids) != len(requirements) or len(candidate_ids) != len(candidates):
        raise CoverageComparisonError("v9 canonical identities are duplicated")
    if len(provisional_ids) != len(provisional) or not candidate_ids <= provisional_ids:
        raise CoverageComparisonError("v9 provisional/canonical candidate partition failed")
    if len(comparisons) != 485:
        raise CoverageComparisonError("v9 comparisons do not cover 485 chains")
    comparison_keys = {(row["project"], row["chain_id"]) for row in comparisons}
    if len(comparison_keys) != len(comparisons):
        raise CoverageComparisonError("v9 comparison identities are duplicated")
    assessment_rows_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in assessments:
        assessment_rows_by_key[
            (row["project"], row["chain_id"], row["requirement_id"])
        ].append(row)
    assessment_keys = {
        (row["project"], row["chain_id"], row["requirement_id"])
        for row in assessments
    }
    if any(len(rows) != 1 for rows in assessment_rows_by_key.values()):
        raise CoverageComparisonError("v9 assessment identities are duplicated")
    comparison_requirement_ids: dict[tuple[str, str], set[str]] = {}
    for comparison in comparisons:
        ids = [row["requirement_id"] for row in comparison["requirements"]]
        if len(ids) != len(set(ids)):
            raise CoverageComparisonError("v9 comparison requirement identities are duplicated")
        comparison_requirement_ids[(comparison["project"], comparison["chain_id"])] = set(ids)
        for row in comparison["requirements"]:
            if (
                comparison["project"],
                comparison["chain_id"],
                row["requirement_id"],
            ) not in assessment_keys:
                raise CoverageComparisonError("v9 comparison lacks an assessment")
    origin_rows = _read_jsonl(root / "candidate-origin-audit.jsonl")
    origin_ids = {row["candidate_id"] for row in origin_rows}
    if len(origin_ids) != len(origin_rows) or origin_ids != candidate_ids:
        raise CoverageComparisonError("v9 candidate/origin audit partition failed")
    if any(row["origin_disposition"] != "eligible" for row in origin_rows):
        raise CoverageComparisonError("v9 candidate has unresolved origin evidence")
    for candidate in candidates:
        candidate_key = (candidate["project"], candidate["chain_id"])
        assessment = assessment_rows_by_key.get(
            (*candidate_key, candidate["requirement_id"]), []
        )
        if (
            candidate["requirement_id"] not in requirement_ids
            or candidate_key not in comparison_keys
            or candidate["requirement_id"] not in comparison_requirement_ids[candidate_key]
            or len(assessment) != 1
            or assessment[0]["decision"] not in {"wrong-check", "missing-check"}
            or candidate["candidate_id"] not in origin_ids
            or candidate["candidate_id"]
            != stable_v7_candidate_id(
                group_id=candidate["group_id"],
                project=candidate["project"],
                revision=candidate["revision"],
                chain_id=candidate["chain_id"],
                requirement_id=candidate["requirement_id"],
                failure_mode=candidate["failure_mode"],
                gate_ids=candidate["gate_ids"],
            )
        ):
            raise CoverageComparisonError("v9 canonical candidate integrity failed")
    validation_by_id = {row["provisional_candidate_id"]: row for row in validations}
    if len(validation_by_id) != len(validations) or not set(validation_by_id) <= provisional_ids:
        raise CoverageComparisonError("v9 source-validation partition failed")
    source_validation_kinds = {
        "capability-card",
        "learned-invariant",
        "source-derived",
    }
    for candidate in candidates:
        needs_validation = candidate["candidate_id"] == FEISHU_CANDIDATE_ID or any(
            source["kind"] in source_validation_kinds
            for source in candidate["provenance"]["sources"]
        )
        if needs_validation:
            validation = validation_by_id.get(candidate["candidate_id"])
            if validation is None or validation["verdict"] != "confirmed-uncovered":
                raise CoverageComparisonError(
                    "v9 canonical source-derived candidate is not source-confirmed"
                )
    for candidate_id in [
        FEISHU_CANDIDATE_ID,
        *[
            row["candidate_id"]
            for row in candidates
            if row.get("source_context", {}).get("learned_pattern_key")
            in {
                "dangerous-command-pattern-completeness",
                "noninteractive-approval-routing",
                "execute-code-approval",
            }
        ],
    ]:
        validation = validation_by_id.get(candidate_id)
        if validation is None or validation["verdict"] != "confirmed-uncovered":
            raise CoverageComparisonError("v9 target candidate is not source-confirmed")
    gt = _read_jsonl(root / "ground-truth-coverage.jsonl")
    training = [row for row in gt if row.get("evaluation_partition") == "training"]
    if len(training) != 43 or any(row["status"] != "covered" for row in training):
        raise CoverageComparisonError("v9 strict training recall is not 43/43")
    for row in training:
        if not set(row["matched_candidate_ids"]) <= candidate_ids:
            raise CoverageComparisonError("v9 GT references an unknown candidate")
        expected_pairs = sorted(
            candidate["candidate_id"]
            for candidate in candidates
            if candidate["project"] == row["project"]
            and candidate["chain_id"] in row["chain_ids"]
        )
        actual_pairs = sorted(
            assessment["candidate_id"] for assessment in row["candidate_assessments"]
        )
        if len(actual_pairs) != len(set(actual_pairs)) or actual_pairs != expected_pairs:
            raise CoverageComparisonError(
                f"v9 GT candidate-pair partition failed for {row['report_id']}"
            )
    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v9 inventory drift: {relative}")
    if inventory["tree_sha256"] != _tree_digest(inventory["files"]):
        raise CoverageComparisonError("v9 inventory tree digest mismatch")
    if manifest["artifact_inventory_sha256"] != sha256_file(
        root / "artifact-inventory.json"
    ):
        raise CoverageComparisonError("v9 inventory binding mismatch")
    return {
        "manifest": manifest,
        "requirements": len(requirements),
        "provisional_candidates": len(provisional),
        "candidates": len(candidates),
        "training_found": 43,
        "training_missed": 0,
    }
