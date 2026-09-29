"""Fail-closed selection of canonical CR v7 strict-matched candidates."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project
from src.coverage_comparison.versions import (
    CANDIDATE_SCHEMA_VERSION,
    COMPARISON_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
)

from .campaign_contracts import digest
from .contracts import ValidationError, sha256_file


LOCATION_RE = re.compile(r"^(?P<path>.+?):(?P<line>[0-9]+)(?::[0-9]+)?$")
REQUIRED_ARTIFACTS = (
    "manifest.json",
    "ground-truth-manifest.json",
    "comparisons.jsonl",
    "ground-truth-coverage.jsonl",
)


@dataclass(frozen=True)
class SelectedCandidate:
    candidate: Mapping[str, Any]
    comparison: Mapping[str, Any]
    reports: tuple[Mapping[str, Any], ...]
    source_files: tuple[Mapping[str, str], ...]
    semantic_snapshot: Mapping[str, Any]


@dataclass(frozen=True)
class CoveredSelection:
    coverage_root: Path
    candidate_artifact: str
    candidates: tuple[SelectedCandidate, ...]
    covered_reports: tuple[Mapping[str, Any], ...]
    artifact_sha256: Mapping[str, str]
    match_references: int

    @property
    def candidate_ids(self) -> tuple[str, ...]:
        return tuple(row.candidate["candidate_id"] for row in self.candidates)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid campaign input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"campaign input must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValidationError(f"cannot read campaign input {path}: {exc}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{line_number}: expected object")
        rows.append(value)
    return rows


def _location_paths(value: Any) -> set[str]:
    output: set[str] = set()
    if isinstance(value, Mapping):
        location = value.get("location")
        if isinstance(location, str):
            match = LOCATION_RE.match(location.strip())
            if match:
                output.add(match.group("path"))
        for item in value.values():
            output.update(_location_paths(item))
    elif isinstance(value, list):
        for item in value:
            output.update(_location_paths(item))
    return output


def _source_bindings(
    project: str, reports: tuple[Mapping[str, Any], ...]
) -> tuple[dict[str, str], ...]:
    spec = get_project(project)
    files: dict[str, str] = {}
    for report in reports:
        for raw_path in report["source_files"]:
            gt = _read_json(Path(__file__).resolve().parents[2] / raw_path)
            for relative in sorted(_location_paths(gt)):
                path = Path(relative)
                if path.is_absolute() or ".." in path.parts:
                    continue
                source = spec.source_root / path
                if source.is_file():
                    files[relative] = sha256_file(source)
    if not files:
        raise ValidationError(
            f"{project}: strict-matched reports do not resolve any bound source files"
        )
    return tuple(
        {"path": path, "sha256": value} for path, value in sorted(files.items())
    )


def select_covered_candidates(
    coverage_root: Path,
    *,
    expected_candidates: int = 61,
    expected_match_references: int = 76,
    expected_covered_reports: int = 43,
) -> CoveredSelection:
    """Select the exact frozen training-regression candidate denominator."""

    root = coverage_root.resolve()
    missing = [name for name in REQUIRED_ARTIFACTS if not (root / name).is_file()]
    if missing:
        raise ValidationError(f"coverage root is missing required artifacts: {missing}")
    artifact_sha256 = {name: sha256_file(root / name) for name in REQUIRED_ARTIFACTS}
    gt_manifest = _read_json(root / "ground-truth-manifest.json")
    manifest = _read_json(root / "manifest.json")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValidationError("runtime campaign requires coverage-comparison v7")
    mode = manifest.get("analysis_mode")
    if mode not in {
        "canonical-trained-detector/v14",
        "canonical-trained-detector/v15",
    }:
        raise ValidationError(
            "runtime campaign requires canonical trained-detector artifacts"
        )
    candidate_artifact = (
        "training-regression-candidates.jsonl"
        if mode == "canonical-trained-detector/v15"
        else "candidates.jsonl"
    )
    if not (root / candidate_artifact).is_file():
        raise ValidationError(
            f"coverage root is missing training candidate artifact: {candidate_artifact}"
        )
    artifact_sha256[candidate_artifact] = sha256_file(root / candidate_artifact)
    precision = manifest.get("precision_contract", {})
    if manifest.get("counts", {}).get(
        "unvalidated_canonical_candidates"
    ) != 0 or precision.get("canonical_requires") not in {
        "confirmed-uncovered",
        "confirmed-uncovered+member-applicable",
    }:
        raise ValidationError("runtime campaign requires source-confirmed candidates")
    counts = gt_manifest.get("counts", {})
    if counts.get("covered_reports") != expected_covered_reports:
        raise ValidationError(
            "covered-report denominator drift: "
            f"expected {expected_covered_reports}, got {counts.get('covered_reports')}"
        )

    candidates = _read_jsonl(root / candidate_artifact)
    for candidate in candidates:
        provenance = candidate.get("provenance")
        if (
            candidate.get("schema_version") != CANDIDATE_SCHEMA_VERSION
            or not isinstance(provenance, Mapping)
            or not isinstance(provenance.get("sources"), list)
            or not provenance["sources"]
            or not str(candidate.get("requirement_id", "")).startswith("CR-")
        ):
            raise ValidationError(
                "runtime campaign requires canonical training candidates"
            )
    candidate_by_id = {row.get("candidate_id"): row for row in candidates}
    if len(candidate_by_id) != len(candidates) or None in candidate_by_id:
        raise ValidationError("candidate artifact contains missing or duplicate IDs")
    comparisons = _read_jsonl(root / "comparisons.jsonl")
    if any(
        row.get("schema_version") != COMPARISON_SCHEMA_VERSION for row in comparisons
    ):
        raise ValidationError("runtime campaign requires v7 comparisons")
    comparison_by_key = {(row["project"], row["chain_id"]): row for row in comparisons}
    if len(comparison_by_key) != len(comparisons):
        raise ValidationError("comparison artifact contains duplicate chain identities")

    covered = tuple(
        row
        for row in _read_jsonl(root / "ground-truth-coverage.jsonl")
        if row.get("status") == "covered"
    )
    if len(covered) != expected_covered_reports:
        raise ValidationError("ground-truth coverage rows disagree with the manifest")
    reports_by_candidate: dict[str, list[Mapping[str, Any]]] = {}
    match_references = 0
    for report in covered:
        for candidate_id in report.get("matched_candidate_ids", []):
            match_references += 1
            candidate = candidate_by_id.get(candidate_id)
            if candidate is None:
                raise ValidationError(
                    f"ground-truth match references unknown {candidate_id}"
                )
            if candidate["project"] != report["project"]:
                raise ValidationError(f"{candidate_id}: report/project mismatch")
            if candidate["chain_id"] not in report["chain_ids"]:
                raise ValidationError(f"{candidate_id}: report/chain mismatch")
            reports_by_candidate.setdefault(candidate_id, []).append(report)
    if match_references != expected_match_references:
        raise ValidationError(
            f"strict-match reference drift: expected {expected_match_references}, got {match_references}"
        )
    if len(reports_by_candidate) != expected_candidates:
        raise ValidationError(
            f"strict-matched candidate drift: expected {expected_candidates}, got {len(reports_by_candidate)}"
        )

    selected: list[SelectedCandidate] = []
    source_cache: dict[tuple[str, tuple[str, ...]], tuple[dict[str, str], ...]] = {}
    for candidate_id in sorted(reports_by_candidate):
        candidate = candidate_by_id[candidate_id]
        comparison = comparison_by_key.get(
            (candidate["project"], candidate["chain_id"])
        )
        if comparison is None:
            raise ValidationError(f"{candidate_id}: missing chain comparison")
        if any(
            comparison[field] != candidate[field]
            for field in (
                "group_id",
                "handler_criterion_id",
                "sink_type_id",
                "revision",
            )
        ):
            raise ValidationError(f"{candidate_id}: comparison identity mismatch")
        reports = tuple(
            sorted(reports_by_candidate[candidate_id], key=lambda row: row["report_id"])
        )
        report_key = (candidate["project"], tuple(row["report_id"] for row in reports))
        source_files = source_cache.setdefault(
            report_key, _source_bindings(candidate["project"], reports)
        )
        semantic_snapshot = {
            "comparison": comparison,
            "candidate_gate_semantics": candidate.get("gate_semantics", []),
        }
        selected.append(
            SelectedCandidate(
                candidate=candidate,
                comparison=comparison,
                reports=reports,
                source_files=source_files,
                semantic_snapshot=semantic_snapshot,
            )
        )
    if len({row.candidate["candidate_id"] for row in selected}) != len(selected):
        raise ValidationError("selected candidate IDs are not unique")
    return CoveredSelection(
        coverage_root=root,
        candidate_artifact=candidate_artifact,
        candidates=tuple(selected),
        covered_reports=covered,
        artifact_sha256=artifact_sha256,
        match_references=match_references,
    )


def selected_candidate_binding(row: SelectedCandidate) -> dict[str, str]:
    return {
        "candidate_row": digest(row.candidate),
        "semantic_row": digest(row.semantic_snapshot),
    }
