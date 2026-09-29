"""Canonical detector v13 bounded-deferred precision publication."""

from __future__ import annotations

import json
import os
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from .applicability_filters import apply_applicability_filters
from .canonical_requirements import stable_v7_candidate_id
from .contracts import CoverageComparisonError, digest, sha256_file
from .ground_truth import _render as render_ground_truth
from .inputs import load_coverage_inputs
from .precision_filters import filter_precision_candidates
from .source_validation import _failure_record
from .v8 import (
    _inventory,
    _read_json,
    _read_jsonl,
    _tree_digest,
    _write_json,
    _write_jsonl,
    _write_text,
)
from .v10 import _filter_ground_truth
from .v12 import validate_v12_artifacts
from .v13_selection import (
    partition_upstream_incomplete,
    select_dense_chain_batches,
)
from .v13_validation import validate_v13_packet


ANALYSIS_MODE = "canonical-trained-detector/v13"
FREEZE_VERSION = "canonical-detector-precision-freeze/v13"
PUBLICATION_VERSION = "coverage-v13-publication/v13"
TARGET_REMAINING = 120


def _recover_packets(stage_root: Path) -> list[dict[str, Any]]:
    packets = _read_jsonl(stage_root / "source-validation-evidence-packets.jsonl")
    digests = {row["packet_digest"] for row in packets}
    for chat_path in sorted(
        (stage_root / "repository/source-validate-v13").glob("*/chat.json")
    ):
        chat = _read_json(chat_path)
        user = chat["exchanges"][0]["user"]
        marker = "Validate this source evidence packet:\n"
        if not user.startswith(marker):
            raise CoverageComparisonError("v13 resumable packet chat is malformed")
        packet = json.loads(user[len(marker) :])
        if packet["packet_digest"] not in digests:
            packets.append(packet)
            digests.add(packet["packet_digest"])
    return packets


def _filter_rows(
    *,
    candidates: Sequence[Mapping[str, Any]],
    requirements: Sequence[Mapping[str, Any]],
    comparisons: Sequence[Mapping[str, Any]],
    validations: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], tuple[dict[str, Any], ...]]:
    precision = filter_precision_candidates(
        candidates=candidates,
        requirements=requirements,
        comparisons=comparisons,
        validations=validations,
    )
    applicability = apply_applicability_filters(
        candidates=candidates,
        requirements=requirements,
        comparisons=comparisons,
        prior_dispositions=precision.dispositions,
    )
    dispositions = list(
        partition_upstream_incomplete(
        candidates=candidates,
        dispositions=applicability.dispositions,
        )
    )
    validation_by_id = {
        str(row["provisional_candidate_id"]): row for row in validations
    }
    for row in dispositions:
        if row["disposition"] != "source-rejected":
            continue
        validation = validation_by_id.get(str(row["candidate_id"]))
        if validation is None or validation["verdict"] not in {
            "unknown",
            "upstream-inconsistent",
        }:
            continue
        row["disposition"] = (
            "operational-failure"
            if validation.get("operational_error")
            else "source-unknown"
        )
        row["reason"] = validation["reason"]
    return list(precision.canonical_candidates), tuple(dispositions)


def _write_ground_truth(
    stage_root: Path,
    *,
    base_rows: Sequence[Mapping[str, Any]],
    candidate_ids: set[str],
) -> list[dict[str, Any]]:
    rows = _filter_ground_truth(base_rows, candidate_ids=candidate_ids)
    found = sum(
        row.get("evaluation_partition") == "training" and row["status"] == "covered"
        for row in rows
    )
    if found != 43:
        raise CoverageComparisonError(f"v13 strict recall regressed to {found}/43")
    _write_jsonl(stage_root / "ground-truth-coverage.jsonl", rows)
    _write_text(
        stage_root / "ground-truth-coverage.md",
        render_ground_truth(
            "python -m src.coverage_comparison --all",
            rows,
            baseline_counts=None,
            baseline_label="Canonical v12 training baseline",
            dispositions=[],
        ),
    )
    _write_jsonl(
        stage_root / "ground-truth-reuse.jsonl",
        [
            {
                "schema_version": "ground-truth-reuse/v13",
                "report_id": row["report_id"],
                "disposition": "unchanged-candidate-payload-subset-reused",
                "matched_candidate_ids": row["matched_candidate_ids"],
            }
            for row in rows
        ],
    )
    manifest = _read_json(stage_root / "ground-truth-manifest.json")
    manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "generation_command": "python -m src.coverage_comparison --all",
            "inputs": {
                **manifest["inputs"],
                "candidates": sha256_file(stage_root / "candidates.jsonl"),
                "comparisons": sha256_file(stage_root / "comparisons.jsonl"),
            },
            "counts": {
                **manifest["counts"],
                "covered_reports": 43,
                "missed_reports": 0,
                "candidate_pair_assessments": sum(
                    len(row["candidate_assessments"]) for row in rows
                ),
                "model_calls": 0,
                "repair_calls": 0,
                "reused_reports": len(rows),
                "readjudicated_reports": 0,
            },
        }
    )
    _write_json(stage_root / "ground-truth-manifest.json", manifest)
    return rows


def _render_summary(counts: Mapping[str, Any]) -> str:
    return "\n".join(
        [
            "# Canonical Coverage Precision v13",
            "",
            "> Generation command: `python -m src.coverage_comparison --all`",
            "",
            "<!-- BEGIN GENERATED REPORT -->",
            "",
            f"Precision input: **{counts['precision_input_candidates']}**; canonical "
            f"source-confirmed candidates: **{counts['candidates']}**.",
            "",
            f"Remaining needs-source-validation: **{counts['needs_source_validation']}** "
            f"and total unresolved: **{counts['unresolved_candidates']}** (target < 150); "
            f"upstream-incomplete: **{counts['upstream_incomplete']}**.",
            "",
            f"v13 packet validations: **{counts['v13_packet_validations']}** across "
            f"**{counts['v13_packet_chains']}** chains; strict training recall: "
            f"**{counts['training_found']}/43**.",
            "",
            "Filter dispositions: "
            + ", ".join(
                f"`{key}` **{value}**"
                for key, value in sorted(counts["filter_dispositions"].items())
            )
            + ".",
            "",
            "<!-- END GENERATED REPORT -->",
            "",
        ]
    )


def prepare_v13(
    *,
    specs: Sequence[ProjectSpec],
    active_root: Path,
    base_v9_root: Path,
    stage_root: Path,
    handler_root: Path,
    sink_root: Path,
    group_root: Path,
    evidence_registry: Path,
    packet_runner: Any,
) -> dict[str, Any]:
    baseline = validate_v12_artifacts(active_root)["manifest"]
    checkpoint = stage_root / "candidate-validations-v13-checkpoint.jsonl"
    resumed = stage_root.exists()
    if resumed:
        if (
            _read_json(stage_root / "manifest.json").get("analysis_mode")
            != "canonical-trained-detector/v12"
            or not checkpoint.is_file()
        ):
            raise CoverageComparisonError("v13 staging is not resumable")
    else:
        shutil.copytree(active_root, stage_root)
    inputs = load_coverage_inputs(
        specs,
        handler_root=handler_root,
        sink_root=sink_root,
        group_root=group_root,
        evidence_registry=evidence_registry,
    )
    if len(inputs.chains) != 485:
        raise CoverageComparisonError("v13 eligible-chain denominator drift")
    candidates = _read_jsonl(base_v9_root / "candidates.jsonl")
    requirements = _read_jsonl(stage_root / "canonical-requirements.jsonl")
    comparisons = _read_jsonl(stage_root / "comparisons.jsonl")
    base_validations = _read_jsonl(active_root / "candidate-validations.jsonl")
    validations = _read_jsonl(checkpoint) if checkpoint.is_file() else base_validations
    _, dispositions = _filter_rows(
        candidates=candidates,
        requirements=requirements,
        comparisons=comparisons,
        validations=validations,
    )
    batches = select_dense_chain_batches(
        candidates=candidates,
        dispositions=dispositions,
        target_remaining=TARGET_REMAINING,
        max_batch_size=4,
    )
    requirement_by_id = {row["requirement_id"]: row for row in requirements}
    assessment_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in _read_jsonl(stage_root / "requirement-assessments.jsonl")
    }
    chain_by_key = {chain.key: chain for chain in inputs.chains}
    spec_by_project = {spec.project_id: spec for spec in specs}
    origin_witnesses = _read_jsonl(base_v9_root / "same-origin-witnesses.jsonl")
    validation_by_id = {row["provisional_candidate_id"]: row for row in validations}
    packets = _recover_packets(stage_root)
    packet_digests = {row["packet_digest"] for row in packets}
    for batch in batches:
        chain = chain_by_key[(batch.project, batch.chain_id)]
        selected = list(batch.candidates)
        selected_assessments = {
            row["requirement_id"]: assessment_by_key[
                (row["project"], row["chain_id"], row["requirement_id"])
            ]
            for row in selected
        }
        try:
            result = validate_v13_packet(
                chain=chain,
                candidates=selected,
                assessments=selected_assessments,
                requirements=requirement_by_id,
                spec=spec_by_project[batch.project],
                origin_witnesses=[
                    row
                    for row in origin_witnesses
                    if row["project"] == batch.project
                    and row["chain_id"] == batch.chain_id
                ],
                runner=packet_runner,
            )
        except CoverageComparisonError as error:
            failure_digest = digest(
                [
                    "v13-packet-failure",
                    batch.project,
                    batch.chain_id,
                    [row["candidate_id"] for row in selected],
                    str(error),
                ]
            )
            for candidate in selected:
                failure = _failure_record(
                    chain=chain,
                    candidate=candidate,
                    primary=selected_assessments[candidate["requirement_id"]],
                    validation_input_sha256=failure_digest,
                    error=f"{type(error).__name__}: {error}",
                    prompt_version="source-validation-packet-precision/v13",
                )
                validation_by_id[candidate["candidate_id"]] = failure
            _write_json(
                stage_root
                / "repository/source-validate-v13"
                / f"{batch.project}-{batch.chain_id}-B{batch.index}-failure"
                / "failure.json",
                {
                    "schema_version": "source-validation-packet-failure/v13",
                    "project": batch.project,
                    "chain_id": batch.chain_id,
                    "candidate_ids": [row["candidate_id"] for row in selected],
                    "error": str(error),
                    "failure_digest": failure_digest,
                },
            )
            _write_jsonl(
                checkpoint,
                [validation_by_id[key] for key in sorted(validation_by_id)],
            )
            continue
        for row in result.validations:
            validation_by_id[row["provisional_candidate_id"]] = row
        if result.packet["packet_digest"] not in packet_digests:
            packets.append(result.packet)
            packet_digests.add(result.packet["packet_digest"])
        suffix = digest([row["candidate_id"] for row in selected])[:10]
        result.chat["subject"] += f"-v13-B{batch.index}-{suffix}"
        _write_json(
            stage_root
            / "repository/source-validate-v13"
            / result.chat["subject"]
            / "chat.json",
            result.chat,
        )
        _write_jsonl(
            checkpoint,
            [validation_by_id[key] for key in sorted(validation_by_id)],
        )
        _write_jsonl(stage_root / "source-validation-evidence-packets.jsonl", packets)
    validations = [validation_by_id[key] for key in sorted(validation_by_id)]
    _write_jsonl(stage_root / "candidate-validations.jsonl", validations)
    _write_jsonl(stage_root / "source-validation-evidence-packets.jsonl", packets)
    checkpoint.unlink(missing_ok=True)
    canonical, dispositions = _filter_rows(
        candidates=candidates,
        requirements=requirements,
        comparisons=comparisons,
        validations=validations,
    )
    candidate_ids = {row["candidate_id"] for row in canonical}
    _write_jsonl(stage_root / "candidates.jsonl", canonical)
    _write_jsonl(stage_root / "candidate-filter-dispositions.jsonl", list(dispositions))
    _write_jsonl(
        stage_root / "candidate-origin-audit.jsonl",
        [
            row
            for row in _read_jsonl(base_v9_root / "candidate-origin-audit.jsonl")
            if row["candidate_id"] in candidate_ids
        ],
    )
    _write_ground_truth(
        stage_root,
        base_rows=_read_jsonl(base_v9_root / "ground-truth-coverage.jsonl"),
        candidate_ids=candidate_ids,
    )
    disposition_counts = Counter(row["disposition"] for row in dispositions)
    unresolved = sum(
        disposition_counts[key]
        for key in (
            "needs-source-validation",
            "source-unknown",
            "operational-failure",
        )
    )
    if unresolved >= 150:
        raise CoverageComparisonError("v13 deferred candidate target was not met")
    base_validation_ids = {row["validation_id"] for row in base_validations}
    new_validations = [
        row for row in validations if row["validation_id"] not in base_validation_ids
    ]
    counts = {
        **baseline["counts"],
        "precision_input_candidates": len(candidates),
        "candidates": len(canonical),
        "source_confirmed_candidates": len(canonical),
        "unvalidated_canonical_candidates": 0,
        "needs_source_validation": disposition_counts["needs-source-validation"],
        "upstream_incomplete": disposition_counts["upstream-incomplete"],
        "unresolved_candidates": unresolved,
        "v13_packet_validations": len(new_validations),
        "v13_packet_chains": len(
            {(row["project"], row["chain_id"]) for row in new_validations}
        ),
        "training_found": 43,
        "training_missed": 0,
        "filter_dispositions": dict(sorted(disposition_counts.items())),
    }
    report = _render_summary(counts)
    _write_text(stage_root / "coverage-index.md", report)
    _write_text(stage_root / "precision-summary.md", report)
    repo_root = Path(__file__).resolve().parents[2]
    freeze = {
        "schema_version": FREEZE_VERSION,
        "base_v12_manifest_sha256": sha256_file(active_root / "manifest.json"),
        "base_v9_candidates_sha256": sha256_file(base_v9_root / "candidates.jsonl"),
        "implementation": {
            relative: sha256_file(repo_root / relative)
            for relative in (
                "src/coverage_comparison/v13.py",
                "src/coverage_comparison/v13_selection.py",
                "src/coverage_comparison/applicability_filters.py",
                "src/coverage_comparison/precision_filters.py",
                "src/coverage_comparison/precision_validation.py",
                "src/coverage_comparison/v13_validation.py",
                "src/coverage_comparison/source_validation_packets.py",
            )
        },
        "filter_dispositions_sha256": sha256_file(
            stage_root / "candidate-filter-dispositions.jsonl"
        ),
        "candidate_validations_sha256": sha256_file(
            stage_root / "candidate-validations.jsonl"
        ),
    }
    _write_json(stage_root / "precision-freeze-lock.json", freeze)
    manifest = dict(baseline)
    manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "generation_command": "python -m src.coverage_comparison --all",
            "counts": counts,
            "precision_contract": {
                **baseline["precision_contract"],
                "deferred_candidate_target": 149,
                "unvalidated_selection_target": TARGET_REMAINING,
                "partial_group_fail_closed": True,
                "dense_chain_batch_size": 4,
            },
            "inputs": {
                **baseline["inputs"],
                "v12_manifest": sha256_file(active_root / "manifest.json"),
                "precision_freeze_lock": sha256_file(
                    stage_root / "precision-freeze-lock.json"
                ),
            },
            "transport": {
                **baseline.get("transport", {}),
                "v13_packet": packet_runner.audit_payload(),
                "v13_packet_resume": {
                    "resumed": resumed,
                    "provider_usage_covers_current_process_only": resumed,
                },
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
    return manifest


def validate_v13_artifacts(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("canonical v13 mode mismatch")
    candidates = _read_jsonl(root / "candidates.jsonl")
    candidate_ids = {row["candidate_id"] for row in candidates}
    validation_by_id = {
        row["provisional_candidate_id"]: row
        for row in _read_jsonl(root / "candidate-validations.jsonl")
    }
    if len(candidate_ids) != len(candidates) or any(
        validation_by_id.get(candidate_id, {}).get("verdict") != "confirmed-uncovered"
        for candidate_id in candidate_ids
    ):
        raise CoverageComparisonError("v13 canonical source-validation invariant failed")
    dispositions = _read_jsonl(root / "candidate-filter-dispositions.jsonl")
    if {
        row["candidate_id"]
        for row in dispositions
        if row["disposition"] == "confirmed"
    } != candidate_ids:
        raise CoverageComparisonError("v13 candidate/filter partition failed")
    unresolved = sum(
        row["disposition"]
        in {"needs-source-validation", "source-unknown", "operational-failure"}
        for row in dispositions
    )
    if unresolved >= 150:
        raise CoverageComparisonError("v13 deferred target drift")
    for candidate in candidates:
        if candidate["candidate_id"] != stable_v7_candidate_id(
            group_id=candidate["group_id"],
            project=candidate["project"],
            revision=candidate["revision"],
            chain_id=candidate["chain_id"],
            requirement_id=candidate["requirement_id"],
            failure_mode=candidate["failure_mode"],
            gate_ids=candidate["gate_ids"],
        ):
            raise CoverageComparisonError("v13 canonical identity drift")
    origin_ids = {
        row["candidate_id"]
        for row in _read_jsonl(root / "candidate-origin-audit.jsonl")
        if row["origin_disposition"] == "eligible"
    }
    if origin_ids != candidate_ids:
        raise CoverageComparisonError("v13 origin partition failed")
    training = [
        row
        for row in _read_jsonl(root / "ground-truth-coverage.jsonl")
        if row.get("evaluation_partition") == "training"
    ]
    if len(training) != 43 or any(row["status"] != "covered" for row in training):
        raise CoverageComparisonError("v13 strict recall is not 43/43")
    freeze = _read_json(root / "precision-freeze-lock.json")
    repo_root = Path(__file__).resolve().parents[2]
    for relative, expected in freeze["implementation"].items():
        if sha256_file(repo_root / relative) != expected:
            raise CoverageComparisonError(f"v13 freeze drift: {relative}")
    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v13 inventory drift: {relative}")
    if inventory["tree_sha256"] != _tree_digest(inventory["files"]):
        raise CoverageComparisonError("v13 inventory tree drift")
    if manifest["artifact_inventory_sha256"] != sha256_file(
        root / "artifact-inventory.json"
    ):
        raise CoverageComparisonError("v13 manifest inventory binding failed")
    return {
        "manifest": manifest,
        "candidates": len(candidates),
        "training_found": 43,
        "training_missed": 0,
    }


def publish_v13(*, active_root: Path, stage_root: Path, archive_root: Path) -> None:
    if archive_root.exists():
        raise CoverageComparisonError(f"v12 archive already exists: {archive_root}")
    archive_root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(active_root, archive_root)
        os.replace(stage_root, active_root)
    except Exception:
        if archive_root.exists() and not active_root.exists():
            os.replace(archive_root, active_root)
        raise
