"""Canonical detector v11 direct-impact precision publication."""

from __future__ import annotations

import os
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from .canonical_requirements import stable_v7_candidate_id
from .contracts import CoverageComparisonError, sha256_file
from .precision_filters import filter_precision_candidates
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


ANALYSIS_MODE = "canonical-trained-detector/v11"
FREEZE_VERSION = "canonical-detector-precision-freeze/v11"
PUBLICATION_VERSION = "coverage-v11-publication/v11"


def _validate_v10_snapshot(root: Path) -> dict[str, Any]:
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != "canonical-trained-detector/v10":
        raise CoverageComparisonError("v11 preparation requires active v10")
    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v10 snapshot drift: {relative}")
    if inventory["tree_sha256"] != _tree_digest(inventory["files"]):
        raise CoverageComparisonError("v10 snapshot tree drift")
    return manifest


def _render(counts: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Canonical Coverage Precision v11",
            "",
            "> Generation command: `python -m src.coverage_comparison --all`",
            "",
            "<!-- BEGIN GENERATED REPORT -->",
            "",
            f"Input candidates: **{counts['precision_input_candidates']}**; canonical "
            f"source-confirmed candidates: **{counts['candidates']}**.",
            "",
            f"Strict source-confirmed training recall: **{counts['training_found']}/43**.",
            "",
            "v11 additionally requires direct model-reachable impact without a second "
            "independent compromise, and full evidence for every conjunctive rule clause.",
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


def prepare_v11(
    *, active_root: Path, base_v9_root: Path, stage_root: Path
) -> dict[str, Any]:
    if stage_root.exists():
        raise CoverageComparisonError(f"v11 staging directory exists: {stage_root}")
    baseline = _validate_v10_snapshot(active_root)
    if _read_json(base_v9_root / "manifest.json").get("analysis_mode") != "canonical-trained-detector/v9":
        raise CoverageComparisonError("v11 base v9 archive mode mismatch")
    shutil.copytree(active_root, stage_root)
    requirements = _read_jsonl(stage_root / "canonical-requirements.jsonl")
    comparisons = _read_jsonl(stage_root / "comparisons.jsonl")
    validations = _read_jsonl(stage_root / "candidate-validations.jsonl")
    input_candidates = _read_jsonl(base_v9_root / "candidates.jsonl")
    filtered = filter_precision_candidates(
        candidates=input_candidates,
        requirements=requirements,
        comparisons=comparisons,
        validations=validations,
    )
    candidates = list(filtered.canonical_candidates)
    candidate_ids = {row["candidate_id"] for row in candidates}
    _write_jsonl(stage_root / "candidates.jsonl", candidates)
    _write_jsonl(
        stage_root / "candidate-filter-dispositions.jsonl",
        list(filtered.dispositions),
    )
    origin = _read_jsonl(stage_root / "candidate-origin-audit.jsonl")
    _write_jsonl(
        stage_root / "candidate-origin-audit.jsonl",
        [row for row in origin if row["candidate_id"] in candidate_ids],
    )
    ground_truth = _filter_ground_truth(
        _read_jsonl(stage_root / "ground-truth-coverage.jsonl"),
        candidate_ids=candidate_ids,
    )
    _write_jsonl(stage_root / "ground-truth-coverage.jsonl", ground_truth)
    found = sum(
        row.get("evaluation_partition") == "training" and row["status"] == "covered"
        for row in ground_truth
    )
    if found != 43:
        raise CoverageComparisonError(f"v11 strict recall regressed to {found}/43")
    disposition_counts = Counter(row["disposition"] for row in filtered.dispositions)
    counts = {
        **baseline["counts"],
        "precision_input_candidates": len(input_candidates),
        "candidates": len(candidates),
        "source_confirmed_candidates": len(candidates),
        "unvalidated_canonical_candidates": 0,
        "training_found": found,
        "training_missed": 0,
        "filter_dispositions": dict(sorted(disposition_counts.items())),
    }
    report = _render(counts)
    _write_text(stage_root / "coverage-index.md", report)
    _write_text(stage_root / "precision-summary.md", report)
    repo_root = Path(__file__).resolve().parents[2]
    freeze = {
        "schema_version": FREEZE_VERSION,
        "base_v10_manifest_sha256": sha256_file(active_root / "manifest.json"),
        "base_v9_candidates_sha256": sha256_file(base_v9_root / "candidates.jsonl"),
        "implementation": {
            relative: sha256_file(repo_root / relative)
            for relative in (
                "src/coverage_comparison/v11.py",
                "src/coverage_comparison/precision_filters.py",
            )
        },
        "filter_dispositions_sha256": sha256_file(
            stage_root / "candidate-filter-dispositions.jsonl"
        ),
    }
    _write_json(stage_root / "precision-freeze-lock.json", freeze)
    manifest = dict(baseline)
    manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "generation_command": "python -m src.coverage_comparison --all",
            "counts": counts,
            "training_claim": "source-confirmed training recall; not blind generalization",
            "precision_contract": {
                **baseline["precision_contract"],
                "direct_model_reachable_impact": True,
                "full_conjunctive_rule_support": True,
            },
            "inputs": {
                **baseline["inputs"],
                "v10_manifest": sha256_file(active_root / "manifest.json"),
                "precision_freeze_lock": sha256_file(
                    stage_root / "precision-freeze-lock.json"
                ),
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


def validate_v11_artifacts(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("canonical v11 mode mismatch")
    candidates = _read_jsonl(root / "candidates.jsonl")
    candidate_ids = {row["candidate_id"] for row in candidates}
    if len(candidate_ids) != len(candidates):
        raise CoverageComparisonError("v11 duplicate canonical identity")
    validation_by_id = {
        row["provisional_candidate_id"]: row
        for row in _read_jsonl(root / "candidate-validations.jsonl")
    }
    if any(
        validation_by_id.get(candidate_id, {}).get("verdict") != "confirmed-uncovered"
        for candidate_id in candidate_ids
    ):
        raise CoverageComparisonError("v11 candidate is not source-confirmed")
    dispositions = _read_jsonl(root / "candidate-filter-dispositions.jsonl")
    if {
        row["candidate_id"]
        for row in dispositions
        if row["disposition"] == "confirmed"
    } != candidate_ids:
        raise CoverageComparisonError("v11 filter partition mismatch")
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
            raise CoverageComparisonError("v11 canonical identity drift")
    origin_ids = {
        row["candidate_id"]
        for row in _read_jsonl(root / "candidate-origin-audit.jsonl")
        if row["origin_disposition"] == "eligible"
    }
    if origin_ids != candidate_ids:
        raise CoverageComparisonError("v11 origin partition mismatch")
    training = [
        row
        for row in _read_jsonl(root / "ground-truth-coverage.jsonl")
        if row.get("evaluation_partition") == "training"
    ]
    if len(training) != 43 or any(row["status"] != "covered" for row in training):
        raise CoverageComparisonError("v11 strict recall is not 43/43")
    freeze = _read_json(root / "precision-freeze-lock.json")
    repo_root = Path(__file__).resolve().parents[2]
    for relative, expected in freeze["implementation"].items():
        if sha256_file(repo_root / relative) != expected:
            raise CoverageComparisonError(f"v11 freeze drift: {relative}")
    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v11 inventory drift: {relative}")
    if inventory["tree_sha256"] != _tree_digest(inventory["files"]):
        raise CoverageComparisonError("v11 inventory tree drift")
    return {
        "manifest": manifest,
        "candidates": len(candidates),
        "training_found": 43,
        "training_missed": 0,
    }


def publish_v11(*, active_root: Path, stage_root: Path, archive_root: Path) -> None:
    if archive_root.exists():
        raise CoverageComparisonError(f"v10 archive already exists: {archive_root}")
    archive_root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(active_root, archive_root)
        os.replace(stage_root, active_root)
    except Exception:
        if archive_root.exists() and not active_root.exists():
            os.replace(archive_root, active_root)
        raise
