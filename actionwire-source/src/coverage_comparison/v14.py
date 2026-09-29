"""Canonical detector v14 upstream-normativity publication."""

from __future__ import annotations

import os
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from .canonical_requirements import stable_v7_candidate_id
from .contracts import CoverageComparisonError, digest, sha256_file
from .ground_truth import _render as render_ground_truth
from .normative_filter import apply_normativity_filter
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
from .v13 import validate_v13_artifacts


ANALYSIS_MODE = "canonical-trained-detector/v14"
FREEZE_VERSION = "canonical-detector-precision-freeze/v14"
PUBLICATION_VERSION = "coverage-v14-publication/v14"
CLUSTER_VERSION = "coverage-vulnerability-cluster/v14"


def _clusters(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        grouped[
            (
                str(candidate["project"]),
                str(candidate["sink_id"]),
                str(candidate["requirement_id"]),
            )
        ].append(candidate)
    output: list[dict[str, Any]] = []
    for key, rows in sorted(grouped.items()):
        candidate_ids = sorted(str(row["candidate_id"]) for row in rows)
        output.append(
            {
                "schema_version": CLUSTER_VERSION,
                "cluster_id": "VULCL-" + digest([CLUSTER_VERSION, *key])[:16],
                "project": key[0],
                "sink_id": key[1],
                "requirement_id": key[2],
                "candidate_ids": candidate_ids,
                "chain_ids": sorted({str(row["chain_id"]) for row in rows}),
                "failure_modes": sorted(
                    {str(row["failure_mode"]) for row in rows}
                ),
                "rule": rows[0]["requirement_rule"],
            }
        )
    return output


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
        raise CoverageComparisonError(f"v14 strict recall regressed to {found}/43")
    _write_jsonl(stage_root / "ground-truth-coverage.jsonl", rows)
    _write_text(
        stage_root / "ground-truth-coverage.md",
        render_ground_truth(
            "python -m src.coverage_comparison --all",
            rows,
            baseline_counts=None,
            baseline_label="Canonical v13 training baseline",
            dispositions=[],
        ),
    )
    _write_jsonl(
        stage_root / "ground-truth-reuse.jsonl",
        [
            {
                "schema_version": "ground-truth-reuse/v14",
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
            "# Canonical Coverage Precision v14",
            "",
            "> Generation command: `python -m src.coverage_comparison --all`",
            "",
            "<!-- BEGIN GENERATED REPORT -->",
            "",
            f"Precision input: **{counts['precision_input_candidates']}**; canonical "
            f"source-confirmed candidates: **{counts['candidates']}**; root-cause "
            f"clusters: **{counts['vulnerability_clusters']}**.",
            "",
            f"Upstream ordinary-card-only rows removed from the active candidate set: "
            f"**{counts['upstream_non_normative']}**; exact member-scoped provenance "
            f"repairs: **{counts['normativity_repairs']}**.",
            "",
            f"Strict source-confirmed training recall: **{counts['training_found']}/43**.",
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


def prepare_v14(
    *,
    active_root: Path,
    base_v9_root: Path,
    group_root: Path,
    stage_root: Path,
    repair_registry_path: Path,
) -> dict[str, Any]:
    if stage_root.exists():
        raise CoverageComparisonError(f"v14 staging directory exists: {stage_root}")
    baseline = validate_v13_artifacts(active_root)["manifest"]
    shutil.copytree(active_root, stage_root)
    candidates = _read_jsonl(base_v9_root / "candidates.jsonl")
    current_candidates = {
        row["candidate_id"]: row for row in _read_jsonl(active_root / "candidates.jsonl")
    }
    requirements = _read_jsonl(stage_root / "canonical-requirements.jsonl")
    validations = _read_jsonl(stage_root / "candidate-validations.jsonl")
    prior_dispositions = _read_jsonl(
        stage_root / "candidate-filter-dispositions.jsonl"
    )
    group_oracles = _read_jsonl(group_root / "oracles.jsonl")
    evidence_index = _read_json(group_root / "evidence-index.json")
    repair_registry = _read_json(repair_registry_path)
    run = apply_normativity_filter(
        candidates=candidates,
        requirements=requirements,
        validations=validations,
        prior_dispositions=prior_dispositions,
        group_oracles=group_oracles,
        evidence_index=evidence_index,
        repair_registry=repair_registry,
    )
    confirmed_ids = {
        str(row["candidate_id"])
        for row in run.dispositions
        if row["disposition"] == "confirmed"
    }
    unknown_confirmed = confirmed_ids - set(current_candidates)
    if unknown_confirmed:
        raise CoverageComparisonError("v14 revived noncanonical v13 candidates")
    canonical = [current_candidates[key] for key in sorted(confirmed_ids)]
    _write_jsonl(stage_root / "candidates.jsonl", canonical)
    _write_jsonl(
        stage_root / "candidate-filter-dispositions.jsonl", list(run.dispositions)
    )
    _write_jsonl(
        stage_root / "upstream-normativity-classifications.jsonl",
        list(run.classifications),
    )
    _write_json(stage_root / "normativity-repair-registry-snapshot.json", repair_registry)
    base_origin = {
        row["candidate_id"]: row
        for row in _read_jsonl(base_v9_root / "candidate-origin-audit.jsonl")
    }
    _write_jsonl(
        stage_root / "candidate-origin-audit.jsonl",
        [base_origin[key] for key in sorted(confirmed_ids)],
    )
    clusters = _clusters(canonical)
    _write_jsonl(stage_root / "vulnerability-clusters.jsonl", clusters)
    _write_ground_truth(
        stage_root,
        base_rows=_read_jsonl(base_v9_root / "ground-truth-coverage.jsonl"),
        candidate_ids=confirmed_ids,
    )
    disposition_counts = Counter(row["disposition"] for row in run.dispositions)
    classifications = Counter(row["status"] for row in run.classifications)
    repair_count = sum(bool(row["repair_keys"]) for row in run.classifications)
    counts = {
        **baseline["counts"],
        "precision_input_candidates": len(candidates),
        "candidates": len(canonical),
        "source_confirmed_candidates": len(canonical),
        "unvalidated_canonical_candidates": 0,
        "vulnerability_clusters": len(clusters),
        "upstream_non_normative": disposition_counts[
            "non-normative-capability-only"
        ],
        "normativity_repairs": repair_count,
        "normativity_unresolved": disposition_counts["normativity-unresolved"],
        "training_found": 43,
        "training_missed": 0,
        "filter_dispositions": dict(sorted(disposition_counts.items())),
        "normativity_classifications": dict(sorted(classifications.items())),
    }
    report = _render_summary(counts)
    _write_text(stage_root / "coverage-index.md", report)
    _write_text(stage_root / "precision-summary.md", report)
    repo_root = Path(__file__).resolve().parents[2]
    implementation = (
        "src/group_oracle/evidence_authority.py",
        "src/group_oracle/prompts.py",
        "src/group_oracle/contracts.py",
        "src/group_oracle/pipeline.py",
        "src/coverage_comparison/normative_filter.py",
        "src/coverage_comparison/normative-provenance-repairs-v14.json",
        "src/coverage_comparison/v14.py",
    )
    freeze = {
        "schema_version": FREEZE_VERSION,
        "base_v13_manifest_sha256": sha256_file(active_root / "manifest.json"),
        "base_v9_candidates_sha256": sha256_file(base_v9_root / "candidates.jsonl"),
        "group_oracles_sha256": sha256_file(group_root / "oracles.jsonl"),
        "group_evidence_index_sha256": sha256_file(
            group_root / "evidence-index.json"
        ),
        "implementation": {
            relative: sha256_file(repo_root / relative) for relative in implementation
        },
        "normativity_classifications_sha256": sha256_file(
            stage_root / "upstream-normativity-classifications.jsonl"
        ),
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
            "training_claim": (
                "source-confirmed training recall with member-scoped provenance repairs; "
                "not blind generalization"
            ),
            "precision_contract": {
                **baseline["precision_contract"],
                "ordinary_capability_card_normative": False,
                "member_scoped_normativity_repairs": repair_count,
                "validation_policy_basis_effective": "evidence-authoritative",
                "root_cause_cluster_key": "project+sink+requirement",
            },
            "inputs": {
                **baseline["inputs"],
                "v13_manifest": sha256_file(active_root / "manifest.json"),
                "group_oracles": sha256_file(group_root / "oracles.jsonl"),
                "group_evidence_index": sha256_file(
                    group_root / "evidence-index.json"
                ),
                "normativity_repair_registry": sha256_file(repair_registry_path),
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


def validate_v14_artifacts(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("canonical v14 mode mismatch")
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
        raise CoverageComparisonError("v14 canonical source-validation invariant failed")
    dispositions = _read_jsonl(root / "candidate-filter-dispositions.jsonl")
    if {
        row["candidate_id"]
        for row in dispositions
        if row["disposition"] == "confirmed"
    } != candidate_ids:
        raise CoverageComparisonError("v14 candidate/filter partition failed")
    classifications = {
        row["candidate_id"]: row
        for row in _read_jsonl(root / "upstream-normativity-classifications.jsonl")
    }
    if any(
        classifications[candidate_id]["status"]
        not in {"normative", "not-group-oracle"}
        for candidate_id in candidate_ids
    ):
        raise CoverageComparisonError("v14 canonical candidate lacks normative authority")
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
            raise CoverageComparisonError("v14 canonical identity drift")
    origin_ids = {
        row["candidate_id"]
        for row in _read_jsonl(root / "candidate-origin-audit.jsonl")
        if row["origin_disposition"] == "eligible"
    }
    if origin_ids != candidate_ids:
        raise CoverageComparisonError("v14 origin partition failed")
    clusters = _read_jsonl(root / "vulnerability-clusters.jsonl")
    clustered = [candidate_id for row in clusters for candidate_id in row["candidate_ids"]]
    if len(clustered) != len(set(clustered)) or set(clustered) != candidate_ids:
        raise CoverageComparisonError("v14 vulnerability cluster partition failed")
    training = [
        row
        for row in _read_jsonl(root / "ground-truth-coverage.jsonl")
        if row.get("evaluation_partition") == "training"
    ]
    if len(training) != 43 or any(row["status"] != "covered" for row in training):
        raise CoverageComparisonError("v14 strict recall is not 43/43")
    freeze = _read_json(root / "precision-freeze-lock.json")
    repo_root = Path(__file__).resolve().parents[2]
    for relative, expected in freeze["implementation"].items():
        if sha256_file(repo_root / relative) != expected:
            raise CoverageComparisonError(f"v14 freeze drift: {relative}")
    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v14 inventory drift: {relative}")
    if inventory["tree_sha256"] != _tree_digest(inventory["files"]):
        raise CoverageComparisonError("v14 inventory tree drift")
    if manifest["artifact_inventory_sha256"] != sha256_file(
        root / "artifact-inventory.json"
    ):
        raise CoverageComparisonError("v14 manifest inventory binding failed")
    return {
        "manifest": manifest,
        "candidates": len(candidates),
        "clusters": len(clusters),
        "training_found": 43,
        "training_missed": 0,
    }


def publish_v14(*, active_root: Path, stage_root: Path, archive_root: Path) -> None:
    if archive_root.exists():
        raise CoverageComparisonError(f"v13 archive already exists: {archive_root}")
    archive_root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(active_root, archive_root)
        os.replace(stage_root, active_root)
    except Exception:
        if archive_root.exists() and not active_root.exists():
            os.replace(archive_root, active_root)
        raise
