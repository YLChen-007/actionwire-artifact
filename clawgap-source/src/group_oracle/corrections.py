"""Fail-closed validation for post-hoc coverage correction ledgers."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from jsonschema import validate as validate_schema

from .contracts import GroupOracleError, sha256_file


CORRECTION_SCHEMA_VERSION = "coverage-correction-ledger/v2"
CORRECTION_SCHEMA = (
    Path(__file__).resolve().parent / "schemas/missed-report-corrections-v2.schema.json"
)
EXPECTED_ACTION_PARTITION = {"add": 9, "refine": 8, "reassess": 3}
EXPECTED_OVERLAY_PATHS = {
    "benchmark/python/AstrBot/astrbot/core/tools/computer_tools/fs.py",
    "design/AstrBot/astrbot-4.25.2-acceptance.json",
}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GroupOracleError(f"invalid correction input {path}: {exc}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GroupOracleError(f"invalid correction input {path}: {exc}") from exc
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GroupOracleError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise GroupOracleError(f"{path}:{number}: expected object")
        rows.append(row)
    return rows


def _repo_path(
    repo_root: Path, raw: str, context: str, *, allow_bound_symlink: bool = False
) -> Path:
    path = Path(raw)
    lexical = path if path.is_absolute() else repo_root / path
    resolved = lexical.absolute() if allow_bound_symlink else lexical.resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError as exc:
        raise GroupOracleError(f"{context}: path escapes repository") from exc
    return resolved


def load_correction_ledger(
    ledger_path: Path,
    *,
    evidence_registry: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    repo_root = Path(__file__).resolve().parents[2]
    ledger_path = _repo_path(repo_root, str(ledger_path), "correction ledger")
    ledger = _read_json(ledger_path)
    validate_schema(instance=ledger, schema=_read_json(CORRECTION_SCHEMA))
    if ledger.get("schema_version") != CORRECTION_SCHEMA_VERSION:
        raise GroupOracleError("unsupported correction ledger schema")

    baseline = ledger["baseline"]
    group_root = _repo_path(repo_root, baseline["group_root"], "baseline group root")
    coverage_root = _repo_path(
        repo_root, baseline["coverage_root"], "baseline coverage root"
    )
    bound_files = {
        "group_manifest": (
            group_root / "manifest.json",
            baseline["group_manifest_sha256"],
        ),
        "coverage_manifest": (
            coverage_root / "manifest.json",
            baseline["coverage_manifest_sha256"],
        ),
        "ground_truth_manifest": (
            coverage_root / "ground-truth-manifest.json",
            baseline["ground_truth_manifest_sha256"],
        ),
    }
    for name, (path, expected) in bound_files.items():
        if not path.is_file() or sha256_file(path) != expected:
            raise GroupOracleError(f"correction ledger baseline {name} digest drift")

    provenance = baseline["provenance"]
    overlay_bindings: dict[str, tuple[Path, str]] = {}
    for row in provenance["source_bindings"]:
        raw_path = row["path"]
        path = _repo_path(repo_root, raw_path, "correction baseline overlay")
        if raw_path in overlay_bindings:
            raise GroupOracleError("correction baseline overlay has duplicate paths")
        overlay_bindings[raw_path] = (path, row["sha256"])
    if set(overlay_bindings) != EXPECTED_OVERLAY_PATHS:
        raise GroupOracleError("correction baseline overlay source set drift")
    for raw_path, (path, expected) in overlay_bindings.items():
        if not path.is_file() or sha256_file(path) != expected:
            raise GroupOracleError(
                f"correction baseline overlay digest drift: {raw_path}"
            )

    baseline_gt = _read_jsonl(coverage_root / "ground-truth-coverage.jsonl")
    missed = {
        row["report_id"]: row for row in baseline_gt if row.get("status") == "missed"
    }
    corrections = ledger["corrections"]
    by_report = {row["report_id"]: row for row in corrections}
    if len(by_report) != len(corrections) or set(by_report) != set(missed):
        raise GroupOracleError(
            "correction ledger must exactly cover baseline missed reports"
        )
    if Counter(row["action"] for row in corrections) != EXPECTED_ACTION_PARTITION:
        raise GroupOracleError(
            "correction action partition must be add=9/refine=8/reassess=3"
        )

    comparisons = {
        (row["project"], row["chain_id"]): row
        for row in _read_jsonl(coverage_root / "comparisons.jsonl")
    }
    baseline_oracles = {
        row["group_id"]: row for row in _read_jsonl(group_root / "oracles.jsonl")
    }
    for report_id, correction in sorted(by_report.items()):
        gt = missed[report_id]
        if (
            correction["project"] != gt["project"]
            or correction["report_name"] != gt["report_name"]
            or correction["revision"] != gt["revision"]
            or sorted(correction["chain_ids"]) != sorted(gt["chain_ids"])
        ):
            raise GroupOracleError(f"{report_id}: correction identity or chains drift")
        source = _repo_path(
            repo_root,
            correction["source_report"]["path"],
            f"{report_id} source report",
            allow_bound_symlink=True,
        )
        if (
            not source.is_file()
            or sha256_file(source) != correction["source_report"]["sha256"]
        ):
            raise GroupOracleError(f"{report_id}: source report digest drift")
        actual_groups: dict[str, tuple[str, str]] = {}
        for chain_id in correction["chain_ids"]:
            comparison = comparisons.get((correction["project"], chain_id))
            if comparison is None:
                raise GroupOracleError(
                    f"{report_id}: baseline comparison missing {chain_id}"
                )
            actual_groups[comparison["group_id"]] = (
                comparison["handler_criterion_id"],
                comparison["sink_type_id"],
            )
        declared_groups = {
            row["group_id"]: (row["handler_criterion_id"], row["sink_type_id"])
            for row in correction["groups"]
        }
        if actual_groups != declared_groups:
            raise GroupOracleError(f"{report_id}: HSG/HC/ST binding drift")
        available_requirements = {
            requirement["requirement_id"]
            for group_id in actual_groups
            for requirement in baseline_oracles[group_id]["requirements"]
        }
        if not set(correction["existing_requirement_ids"]) <= available_requirements:
            raise GroupOracleError(f"{report_id}: unknown existing requirement binding")
        if correction["action"] == "reassess" and correction["evidence_locators"]:
            raise GroupOracleError(f"{report_id}: reassess rows must not add evidence")
        if correction["action"] != "reassess" and not correction["evidence_locators"]:
            raise GroupOracleError(
                f"{report_id}: add/refine rows require correction evidence"
            )
        deficiency = correction.get("evidence_deficiency")
        if deficiency is not None:
            if correction["action"] == "reassess":
                raise GroupOracleError(
                    f"{report_id}: reassess rows cannot declare evidence deficiency"
                )
            for anchor in deficiency["source_anchors"]:
                raw_path = anchor.split(":", 1)[0]
                anchor_path = _repo_path(
                    repo_root,
                    raw_path,
                    f"{report_id} evidence-deficiency anchor",
                    allow_bound_symlink=True,
                )
                if not anchor_path.is_file():
                    raise GroupOracleError(
                        f"{report_id}: evidence-deficiency anchor is not a file: "
                        f"{raw_path}"
                    )

    registry_binding: dict[str, Any] | None = None
    if evidence_registry is not None:
        registry_path = _repo_path(
            repo_root, str(evidence_registry), "correction evidence registry"
        )
        registry = _read_json(registry_path)
        evidence_rows = registry.get("evidence", [])
        available_locators = {row["locator"] for row in evidence_rows}
        if len(available_locators) != len(evidence_rows):
            raise GroupOracleError(
                "correction evidence registry has duplicate locators"
            )
        required_locators = {
            locator for row in corrections for locator in row["evidence_locators"]
        }
        if required_locators != available_locators:
            raise GroupOracleError(
                "correction evidence registry locator set mismatch: "
                f"missing={sorted(required_locators - available_locators)}; "
                f"stale={sorted(available_locators - required_locators)}"
            )
        registry_binding = {
            "path": str(registry_path.relative_to(repo_root)),
            "sha256": sha256_file(registry_path),
        }

    binding = {
        "path": str(ledger_path.relative_to(repo_root)),
        "sha256": sha256_file(ledger_path),
        "post_hoc_ground_truth_informed": True,
        "baseline": {
            name: {"path": str(path.relative_to(repo_root)), "sha256": expected}
            for name, (path, expected) in bound_files.items()
        },
        "baseline_provenance": {
            "classification": provenance["classification"],
            "overlay_id": provenance["overlay_id"],
            "source_bindings": [
                {"path": raw_path, "sha256": expected}
                for raw_path, (_path, expected) in sorted(overlay_bindings.items())
            ],
        },
        "counts": dict(sorted(Counter(row["action"] for row in corrections).items())),
    }
    if registry_binding is not None:
        binding["evidence_registry"] = registry_binding
    return ledger, binding


def corrections_by_group(
    ledger: Mapping[str, Any],
) -> dict[str, tuple[Mapping[str, Any], ...]]:
    output: dict[str, list[Mapping[str, Any]]] = {}
    for correction in ledger["corrections"]:
        for group in correction["groups"]:
            output.setdefault(group["group_id"], []).append(correction)
    return {
        group_id: tuple(sorted(rows, key=lambda row: row["report_id"]))
        for group_id, rows in output.items()
    }


def resolve_correction_requirement_ids(
    correction: Mapping[str, Any],
    *,
    corrected_oracles: Mapping[str, Mapping[str, Any]],
    baseline_oracles: Mapping[str, Mapping[str, Any]],
) -> set[str]:
    requirement_ids: set[str] = set()
    for group in correction["groups"]:
        group_id = group["group_id"]
        corrected = corrected_oracles[group_id]["requirements"]
        requirement_ids.update(
            row["requirement_id"]
            for row in corrected
            if row["dimension"] in correction["evidence_locators"]
        )
        for existing_id in correction["existing_requirement_ids"]:
            direct = next(
                (row for row in corrected if row["requirement_id"] == existing_id),
                None,
            )
            if direct is not None:
                requirement_ids.add(existing_id)
                continue
            baseline = next(
                (
                    row
                    for row in baseline_oracles[group_id]["requirements"]
                    if row["requirement_id"] == existing_id
                ),
                None,
            )
            if baseline is None:
                continue
            requirement_ids.update(
                row["requirement_id"]
                for row in corrected
                if row["rule"] == baseline["rule"]
                or row["dimension"] == baseline["dimension"]
            )
    return requirement_ids
