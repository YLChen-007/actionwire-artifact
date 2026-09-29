"""Canonical detector v10 precision-hardening publication."""

from __future__ import annotations

import json
import os
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from .canonical_requirements import stable_v7_candidate_id
from .contracts import CoverageComparisonError, sha256_file
from .ground_truth import _render as render_ground_truth
from .inputs import load_coverage_inputs
from .precision_filters import filter_precision_candidates
from .precision_validation import validate_precision_packet
from .v8 import (
    _inventory,
    _read_json,
    _read_jsonl,
    _tree_digest,
    _write_json,
    _write_jsonl,
    _write_text,
)
from .v9 import validate_v9_artifacts


ANALYSIS_MODE = "canonical-trained-detector/v10"
FREEZE_VERSION = "canonical-detector-precision-freeze/v10"
PUBLICATION_VERSION = "coverage-v10-publication/v10"


def _target_validation_ids(
    *,
    ground_truth: Sequence[Mapping[str, Any]],
    dispositions: Sequence[Mapping[str, Any]],
) -> set[str]:
    by_id = {str(row["candidate_id"]): row for row in dispositions}
    confirmed = {
        candidate_id
        for candidate_id, row in by_id.items()
        if row["disposition"] == "confirmed"
    }
    targets: set[str] = set()
    for report in ground_truth:
        if report.get("evaluation_partition") != "training":
            continue
        matched = {str(value) for value in report.get("matched_candidate_ids", [])}
        if matched & confirmed:
            continue
        eligible = {
            candidate_id
            for candidate_id in matched
            if by_id.get(candidate_id, {}).get("disposition")
            == "needs-source-validation"
        }
        if not eligible:
            raise CoverageComparisonError(
                f"v10 has no source-validation target for {report['report_id']}"
            )
        targets.update(eligible)
    return targets


def _filter_ground_truth(
    rows: Sequence[Mapping[str, Any]], *, candidate_ids: set[str]
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        assessments = [
            dict(value)
            for value in row.get("candidate_assessments", [])
            if value["candidate_id"] in candidate_ids
        ]
        matched = sorted(
            value["candidate_id"]
            for value in assessments
            if value["verdict"] == "match"
        )
        row["candidate_assessments"] = assessments
        row["matched_candidate_ids"] = matched
        if row.get("evaluation_partition") == "training":
            row["status"] = "covered" if matched else "missed"
            row["reason"] = (
                "at least one source-confirmed canonical v10 candidate strictly matches "
                "the training invariant"
                if matched
                else "no source-confirmed canonical v10 candidate matches the training invariant"
            )
        output.append(row)
    return sorted(output, key=lambda row: row["report_id"])


def _render_summary(counts: Mapping[str, Any]) -> str:
    dispositions = counts["filter_dispositions"]
    return "\n".join(
        [
            "# Canonical Coverage Precision v10",
            "",
            "> Generation command: `python -m src.coverage_comparison --all`",
            "",
            "<!-- BEGIN GENERATED REPORT -->",
            "",
            f"Input canonical candidates: **{counts['precision_input_candidates']}**; "
            f"source-confirmed canonical candidates: **{counts['candidates']}**.",
            "",
            "Filter dispositions: "
            + ", ".join(
                f"`{key}` **{value}**" for key, value in sorted(dispositions.items())
            )
            + ".",
            "",
            f"Canonical strict training recall: **{counts['training_found']}/43**. "
            "The three source-transplant records remain a separate synthetic-inclusive "
            "detectability result.",
            "",
            "Only `confirmed-uncovered` candidates are canonical. Recommendation-only, "
            "facet-mismatched, duplicate, refuted, unknown, and unvalidated rows remain "
            "auditable in provisional/filter ledgers.",
            "",
            "<!-- END GENERATED REPORT -->",
            "",
        ]
    )


def _freeze_lock(
    *, repo_root: Path, active_root: Path, stage_root: Path
) -> dict[str, Any]:
    implementation = [
        "src/coverage_comparison/v10.py",
        "src/coverage_comparison/precision_filters.py",
        "src/coverage_comparison/precision_validation.py",
    ]
    return {
        "schema_version": FREEZE_VERSION,
        "base_v9_manifest_sha256": sha256_file(active_root / "manifest.json"),
        "base_v9_candidates_sha256": sha256_file(active_root / "candidates.jsonl"),
        "implementation": {
            relative: sha256_file(repo_root / relative) for relative in implementation
        },
        "filter_dispositions_sha256": sha256_file(
            stage_root / "candidate-filter-dispositions.jsonl"
        ),
        "candidate_validations_sha256": sha256_file(
            stage_root / "candidate-validations.jsonl"
        ),
    }


def _update_inventory(stage_root: Path, manifest: dict[str, Any]) -> None:
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


def prepare_v10(
    *,
    specs: Sequence[ProjectSpec],
    active_root: Path,
    stage_root: Path,
    handler_root: Path,
    sink_root: Path,
    group_root: Path,
    evidence_registry: Path,
    packet_runner: Any,
) -> dict[str, Any]:
    """Build a source-confirmed v10 stage without mutating active v9."""

    baseline = validate_v9_artifacts(active_root)["manifest"]
    resumed = stage_root.exists()
    if resumed:
        staged_mode = _read_json(stage_root / "manifest.json").get("analysis_mode")
        checkpoint = stage_root / "candidate-validations-v10-checkpoint.jsonl"
        if staged_mode != "canonical-trained-detector/v9" or not checkpoint.is_file():
            raise CoverageComparisonError(
                f"v10 staging directory is not resumable: {stage_root}"
            )
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
        raise CoverageComparisonError("v10 eligible-chain denominator drift")

    requirements = _read_jsonl(stage_root / "canonical-requirements.jsonl")
    comparisons = _read_jsonl(stage_root / "comparisons.jsonl")
    input_candidates = _read_jsonl(stage_root / "candidates.jsonl")
    base_validation_ids = {
        row["validation_id"]
        for row in _read_jsonl(active_root / "candidate-validations.jsonl")
    }
    checkpoint = stage_root / "candidate-validations-v10-checkpoint.jsonl"
    validations = _read_jsonl(
        checkpoint if checkpoint.is_file() else stage_root / "candidate-validations.jsonl"
    )
    ground_truth = _read_jsonl(stage_root / "ground-truth-coverage.jsonl")
    initial = filter_precision_candidates(
        candidates=input_candidates,
        requirements=requirements,
        comparisons=comparisons,
        validations=validations,
    )
    target_ids = _target_validation_ids(
        ground_truth=ground_truth, dispositions=initial.dispositions
    )
    candidate_by_id = {row["candidate_id"]: row for row in input_candidates}
    requirement_by_id = {row["requirement_id"]: row for row in requirements}
    assessment_by_key = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in _read_jsonl(stage_root / "requirement-assessments.jsonl")
    }
    origin_witnesses = _read_jsonl(stage_root / "same-origin-witnesses.jsonl")
    chain_by_key = {chain.key: chain for chain in inputs.chains}
    spec_by_project = {spec.project_id: spec for spec in specs}
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate_id in sorted(target_ids):
        candidate = candidate_by_id[candidate_id]
        grouped[(candidate["project"], candidate["chain_id"])].append(candidate)

    validation_by_id = {row["provisional_candidate_id"]: row for row in validations}
    packets = _read_jsonl(stage_root / "source-validation-evidence-packets.jsonl")
    packet_digests = {row["packet_digest"] for row in packets}
    for chat_path in sorted(
        (stage_root / "repository/source-validate-precision").glob("*/chat.json")
    ):
        chat = _read_json(chat_path)
        user = chat["exchanges"][0]["user"]
        marker = "Validate this source evidence packet:\n"
        if not user.startswith(marker):
            raise CoverageComparisonError("v10 resumable packet chat is malformed")
        packet = json.loads(user[len(marker) :])
        if packet["packet_digest"] not in packet_digests:
            packets.append(packet)
            packet_digests.add(packet["packet_digest"])
    for key in sorted(grouped):
        chain = chain_by_key[key]
        selected = grouped[key]
        selected_assessments = {
            row["requirement_id"]: assessment_by_key[
                (row["project"], row["chain_id"], row["requirement_id"])
            ]
            for row in selected
        }
        result = validate_precision_packet(
            chain=chain,
            candidates=selected,
            assessments=selected_assessments,
            requirements=requirement_by_id,
            spec=spec_by_project[chain.project],
            origin_witnesses=[
                row
                for row in origin_witnesses
                if row["project"] == chain.project and row["chain_id"] == chain.chain_id
            ],
            runner=packet_runner,
        )
        for row in result.validations:
            validation_by_id[row["provisional_candidate_id"]] = row
        packets.append(result.packet)
        packet_digests.add(result.packet["packet_digest"])
        _write_json(
            stage_root
            / "repository/source-validate-precision"
            / result.chat["subject"]
            / "chat.json",
            result.chat,
        )
        _write_jsonl(
            stage_root / "candidate-validations-v10-checkpoint.jsonl",
            [validation_by_id[key] for key in sorted(validation_by_id)],
        )
        _write_jsonl(stage_root / "source-validation-evidence-packets.jsonl", packets)

    validations = [validation_by_id[key] for key in sorted(validation_by_id)]
    _write_jsonl(stage_root / "candidate-validations.jsonl", validations)
    _write_jsonl(stage_root / "source-validation-evidence-packets.jsonl", packets)
    (stage_root / "candidate-validations-v10-checkpoint.jsonl").unlink(missing_ok=True)
    final = filter_precision_candidates(
        candidates=input_candidates,
        requirements=requirements,
        comparisons=comparisons,
        validations=validations,
    )
    candidates = list(final.canonical_candidates)
    candidate_ids = {row["candidate_id"] for row in candidates}
    _write_jsonl(stage_root / "candidates.jsonl", candidates)
    _write_jsonl(
        stage_root / "candidate-filter-dispositions.jsonl", list(final.dispositions)
    )
    prior_origin = _read_jsonl(stage_root / "candidate-origin-audit.jsonl")
    _write_jsonl(
        stage_root / "candidate-origin-audit.jsonl",
        [row for row in prior_origin if row["candidate_id"] in candidate_ids],
    )
    training = _filter_ground_truth(ground_truth, candidate_ids=candidate_ids)
    _write_jsonl(stage_root / "ground-truth-coverage.jsonl", training)
    _write_text(
        stage_root / "ground-truth-coverage.md",
        render_ground_truth(
            "python -m src.coverage_comparison --all",
            training,
            baseline_counts=None,
            baseline_label="Canonical v9 training baseline",
            dispositions=[],
        ),
    )
    _write_jsonl(
        stage_root / "ground-truth-reuse.jsonl",
        [
            {
                "schema_version": "ground-truth-reuse/v10",
                "report_id": row["report_id"],
                "disposition": "candidate-subset-reused",
                "candidate_payloads_unchanged": True,
                "matched_candidate_ids": row["matched_candidate_ids"],
            }
            for row in training
        ],
    )
    found = sum(
        row.get("evaluation_partition") == "training" and row["status"] == "covered"
        for row in training
    )
    if found != 43:
        missed = [
            row["report_id"]
            for row in training
            if row.get("evaluation_partition") == "training" and row["status"] != "covered"
        ]
        raise CoverageComparisonError(
            f"v10 source-confirmed recall is {found}/43; missed={missed}"
        )
    ground_truth_manifest = _read_json(stage_root / "ground-truth-manifest.json")
    ground_truth_manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "generation_command": "python -m src.coverage_comparison --all",
            "inputs": {
                **ground_truth_manifest["inputs"],
                "candidates": sha256_file(stage_root / "candidates.jsonl"),
                "comparisons": sha256_file(stage_root / "comparisons.jsonl"),
            },
            "counts": {
                **ground_truth_manifest["counts"],
                "covered_reports": found,
                "missed_reports": 0,
                "candidate_pair_assessments": sum(
                    len(row["candidate_assessments"]) for row in training
                ),
                "model_calls": 0,
                "repair_calls": 0,
                "reused_reports": len(training),
                "readjudicated_reports": 0,
            },
        }
    )
    _write_json(stage_root / "ground-truth-manifest.json", ground_truth_manifest)

    disposition_counts = Counter(row["disposition"] for row in final.dispositions)
    counts = {
        **baseline["counts"],
        "precision_input_candidates": len(input_candidates),
        "provisional_candidates": len(
            _read_jsonl(stage_root / "provisional-candidates.jsonl")
        ),
        "candidates": len(candidates),
        "source_confirmed_candidates": len(candidates),
        "unvalidated_canonical_candidates": 0,
        "precision_packet_validations": sum(
            row["validation_id"] not in base_validation_ids for row in validations
        ),
        "precision_packet_chains": len(
            {
                (row["project"], row["chain_id"])
                for row in validations
                if row["validation_id"] not in base_validation_ids
            }
        ),
        "training_found": found,
        "training_missed": 0,
        "filter_dispositions": dict(sorted(disposition_counts.items())),
    }
    manifest = dict(baseline)
    manifest.update(
        {
            "analysis_mode": ANALYSIS_MODE,
            "generation_command": "python -m src.coverage_comparison --all",
            "counts": counts,
            "training_claim": "source-confirmed training recall; not blind generalization",
            "precision_contract": {
                "canonical_requires": "confirmed-uncovered",
                "recommendation_candidates": 0,
                "facet_origin_mismatches": 0,
                "duplicate_candidates": 0,
                "unvalidated_candidates": 0,
            },
            "transport": {
                **baseline.get("transport", {}),
                "precision_packet": packet_runner.audit_payload(),
                "precision_packet_resume": {
                    "resumed": resumed,
                    "provider_usage_covers_current_process_only": resumed,
                },
            },
            "inputs": {
                **baseline["inputs"],
                "v9_manifest": sha256_file(active_root / "manifest.json"),
            },
        }
    )
    _write_text(stage_root / "coverage-index.md", _render_summary(counts))
    _write_text(stage_root / "precision-summary.md", _render_summary(counts))
    repo_root = Path(__file__).resolve().parents[2]
    freeze = _freeze_lock(
        repo_root=repo_root, active_root=active_root, stage_root=stage_root
    )
    _write_json(stage_root / "precision-freeze-lock.json", freeze)
    manifest["inputs"]["precision_freeze_lock"] = sha256_file(
        stage_root / "precision-freeze-lock.json"
    )
    _write_json(stage_root / "manifest.json", manifest)
    _update_inventory(stage_root, manifest)
    return manifest


def validate_v10_artifacts(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest = _read_json(root / "manifest.json")
    if manifest.get("analysis_mode") != ANALYSIS_MODE:
        raise CoverageComparisonError("canonical v10 mode mismatch")
    requirements = _read_jsonl(root / "canonical-requirements.jsonl")
    candidates = _read_jsonl(root / "candidates.jsonl")
    provisional = _read_jsonl(root / "provisional-candidates.jsonl")
    comparisons = _read_jsonl(root / "comparisons.jsonl")
    validations = _read_jsonl(root / "candidate-validations.jsonl")
    dispositions = _read_jsonl(root / "candidate-filter-dispositions.jsonl")
    candidate_ids = {row["candidate_id"] for row in candidates}
    if len(candidate_ids) != len(candidates):
        raise CoverageComparisonError("v10 duplicate canonical candidate identity")
    if not candidate_ids <= {row["candidate_id"] for row in provisional}:
        raise CoverageComparisonError("v10 canonical candidate is not provisional")
    validation_by_id = {row["provisional_candidate_id"]: row for row in validations}
    if any(
        validation_by_id.get(candidate_id, {}).get("verdict") != "confirmed-uncovered"
        for candidate_id in candidate_ids
    ):
        raise CoverageComparisonError("v10 canonical candidate is not source-confirmed")
    if {row["candidate_id"] for row in dispositions if row["disposition"] == "confirmed"} != candidate_ids:
        raise CoverageComparisonError("v10 filter/canonical partition mismatch")
    if any(
        row["disposition"] == "confirmed" and row["replacement_candidate_id"] is not None
        for row in dispositions
    ):
        raise CoverageComparisonError("v10 confirmed duplicate candidate")
    if len(comparisons) != 485:
        raise CoverageComparisonError("v10 comparison denominator drift")
    requirement_ids = {row["requirement_id"] for row in requirements}
    for candidate in candidates:
        if candidate["requirement_id"] not in requirement_ids or candidate["candidate_id"] != stable_v7_candidate_id(
            group_id=candidate["group_id"],
            project=candidate["project"],
            revision=candidate["revision"],
            chain_id=candidate["chain_id"],
            requirement_id=candidate["requirement_id"],
            failure_mode=candidate["failure_mode"],
            gate_ids=candidate["gate_ids"],
        ):
            raise CoverageComparisonError("v10 canonical identity drift")
    origin_ids = {
        row["candidate_id"]
        for row in _read_jsonl(root / "candidate-origin-audit.jsonl")
        if row["origin_disposition"] == "eligible"
    }
    if origin_ids != candidate_ids:
        raise CoverageComparisonError("v10 origin audit partition mismatch")
    training = [
        row
        for row in _read_jsonl(root / "ground-truth-coverage.jsonl")
        if row.get("evaluation_partition") == "training"
    ]
    if len(training) != 43 or any(row["status"] != "covered" for row in training):
        raise CoverageComparisonError("v10 strict source-confirmed recall is not 43/43")
    if any(not set(row["matched_candidate_ids"]) <= candidate_ids for row in training):
        raise CoverageComparisonError("v10 GT references noncanonical candidate")
    freeze = _read_json(root / "precision-freeze-lock.json")
    repo_root = Path(__file__).resolve().parents[2]
    if freeze.get("schema_version") != FREEZE_VERSION:
        raise CoverageComparisonError("v10 precision freeze schema mismatch")
    for relative, expected in freeze["implementation"].items():
        if sha256_file(repo_root / relative) != expected:
            raise CoverageComparisonError(f"v10 precision freeze drift: {relative}")
    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        if sha256_file(root / relative) != expected:
            raise CoverageComparisonError(f"v10 inventory drift: {relative}")
    if inventory["tree_sha256"] != _tree_digest(inventory["files"]):
        raise CoverageComparisonError("v10 inventory tree digest mismatch")
    if manifest["artifact_inventory_sha256"] != sha256_file(
        root / "artifact-inventory.json"
    ):
        raise CoverageComparisonError("v10 manifest inventory binding mismatch")
    return {
        "manifest": manifest,
        "candidates": len(candidates),
        "training_found": 43,
        "training_missed": 0,
    }


def publish_v10(*, active_root: Path, stage_root: Path, archive_root: Path) -> None:
    if not stage_root.is_dir():
        raise CoverageComparisonError("v10 staging directory is missing")
    if archive_root.exists():
        raise CoverageComparisonError(f"v9 archive already exists: {archive_root}")
    archive_root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(active_root, archive_root)
        os.replace(stage_root, active_root)
    except Exception:
        if archive_root.exists() and not active_root.exists():
            os.replace(archive_root, active_root)
        raise
