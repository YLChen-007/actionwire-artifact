"""Strict runtime-oracle loading and revision/source binding."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from src.projects import ProjectSpec

from .contracts import ORACLE_SCHEMA_VERSION, ValidationError, sha256_file


MODULE_DIR = Path(__file__).resolve().parent
REPO_ROOT = MODULE_DIR.parents[1]
SCHEMA_PATH = MODULE_DIR / "schemas" / "runtime-trigger-oracle-v1.schema.json"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"runtime oracle not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid runtime oracle JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"runtime oracle must be a JSON object: {path}")
    return value


def oracle_path(spec: ProjectSpec, report_name: str) -> Path:
    return spec.design_root / "runtime-validation" / "oracles" / f"{report_name}.json"


def load_oracle(spec: ProjectSpec, report_name: str) -> dict[str, Any]:
    path = oracle_path(spec, report_name)
    value = _load_json(path)
    schema = _load_json(SCHEMA_PATH)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value), key=lambda row: list(row.path)
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:8]
        )
        raise ValidationError(f"runtime oracle schema validation failed: {details}")
    if value["schema_version"] != ORACLE_SCHEMA_VERSION:
        raise ValidationError(
            "runtime oracle schema version does not match the implementation"
        )
    if value["project"] != spec.project_id:
        raise ValidationError(
            f"runtime oracle project {value['project']!r} does not match {spec.project_id!r}"
        )
    if value["report_name"] != report_name:
        raise ValidationError(
            "runtime oracle report_name does not match the requested report"
        )
    return value


def _relative_file(root: Path, raw_path: str, field: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValidationError(f"{field} must be a repository-relative path")
    path = root / candidate
    if not path.is_file():
        raise ValidationError(f"{field} does not exist: {raw_path}")
    return path


def verify_source_binding(
    spec: ProjectSpec, oracle: Mapping[str, Any]
) -> dict[str, Any]:
    binding = oracle["source_binding"]
    expected_revision = binding["analysis_revision"]
    if expected_revision != spec.analysis_revision:
        raise ValidationError(
            "runtime oracle analysis revision does not match the project registry: "
            f"{expected_revision} != {spec.analysis_revision}"
        )

    files: list[dict[str, str]] = []
    for index, record in enumerate(binding["files"]):
        relative = record["path"]
        path = _relative_file(
            spec.source_root, relative, f"source_binding.files[{index}].path"
        )
        actual = sha256_file(path)
        expected = record["sha256"]
        if actual != expected:
            raise ValidationError(
                f"source hash mismatch for {relative}: expected {expected}, got {actual}"
            )
        files.append({"path": relative, "sha256": actual})

    ground_truth = oracle["ground_truth"]
    gt_path = _relative_file(REPO_ROOT, ground_truth["path"], "ground_truth.path")
    gt_actual = sha256_file(gt_path)
    if gt_actual != ground_truth["sha256"]:
        raise ValidationError(
            f"ground-truth hash mismatch for {ground_truth['path']}: "
            f"expected {ground_truth['sha256']}, got {gt_actual}"
        )

    return {
        "analysis_revision": expected_revision,
        "files": files,
        "ground_truth": {"path": ground_truth["path"], "sha256": gt_actual},
    }
