"""Fail-closed validation and replay of canonical CR v7 artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import validate

from .canonical_requirements import (
    stable_v7_candidate_id,
)
from .contracts import CoverageComparisonError, SCHEMA_DIR, digest, sha256_file
from .versions import ASSESSMENT_SCHEMA_VERSION, COMPARISON_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION


REQUIRED_V7_FILES = (
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


def _schema(name: str) -> dict[str, Any]:
    return _read_json(SCHEMA_DIR / name)


def _expected_legacy_identities(root: Path) -> tuple[set[tuple[str, str]], set[str]]:
    cross_root = root.parent
    archive = cross_root / "archive/coverage-v6"
    training = archive / "coverage-comparison-training-v6"
    requirement_ids: set[tuple[str, str]] = set()
    for group_root in (
        cross_root / "group-oracles",
        cross_root / "group-oracles-corrected-v2",
    ):
        for oracle in _read_jsonl(group_root / "oracles.jsonl"):
            requirement_ids.update(
                (str(oracle["group_id"]), str(row["requirement_id"]))
                for row in oracle["requirements"]
            )
    for name in (
        "capability-requirement-proposals.jsonl",
        "source-requirement-proposals.jsonl",
        "learned-invariant-requirements.jsonl",
    ):
        for row in _read_jsonl(training / name):
            requirement_ids.add((str(row["group_id"]), str(row["requirement_id"])))
    candidate_ids: set[str] = set()
    for path in (
        archive / "coverage-comparison/candidates.jsonl",
        training / "candidates.jsonl",
        training / "provisional-candidates.jsonl",
        training / "learned-provisional-candidates.jsonl",
        training / "origin-rebound-provisional-candidates.jsonl",
        archive / "coverage-comparison-corrected-v2/candidates.jsonl",
    ):
        candidate_ids.update(str(row["candidate_id"]) for row in _read_jsonl(path))
    return requirement_ids, candidate_ids


def validate_v7_artifacts(root: Path) -> dict[str, Any]:
    root = root.resolve()
    missing = [name for name in REQUIRED_V7_FILES if not (root / name).is_file()]
    if missing:
        raise CoverageComparisonError(f"canonical v7 artifact is incomplete: {missing}")
    manifest = _read_json(root / "manifest.json")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise CoverageComparisonError("canonical manifest is not coverage v7")
    if manifest.get("analysis_mode") != "canonical-trained-detector/v7":
        raise CoverageComparisonError("canonical manifest analysis mode mismatch")
    freeze_lock = _read_json(root / "detector-freeze-lock.json")
    validate(freeze_lock, _schema("canonical-detector-freeze-v7.schema.json"))
    if freeze_lock.get("schema_version") != "canonical-detector-freeze/v7":
        raise CoverageComparisonError("canonical detector freeze lock is not v7")
    if freeze_lock.get("analysis_mode") != manifest.get("analysis_mode"):
        raise CoverageComparisonError("canonical detector freeze mode mismatch")
    if manifest.get("inputs", {}).get("detector_freeze_lock") != sha256_file(
        root / "detector-freeze-lock.json"
    ):
        raise CoverageComparisonError("canonical detector freeze binding mismatch")
    if freeze_lock.get("router", {}).get("config_sha256") != digest(
        manifest.get("router")
    ):
        raise CoverageComparisonError("canonical detector router freeze mismatch")
    repository_root = Path(__file__).resolve().parents[2]
    frozen_paths = {
        freeze_lock["cr_normalization"]["path"]: freeze_lock["cr_normalization"][
            "sha256"
        ],
        freeze_lock["learned_catalog"]["path"]: freeze_lock["learned_catalog"][
            "sha256"
        ],
        freeze_lock["training_ground_truth"]["workbook"]["path"]: freeze_lock[
            "training_ground_truth"
        ]["workbook"]["sha256"],
        freeze_lock["training_ground_truth"]["selection"]["path"]: freeze_lock[
            "training_ground_truth"
        ]["selection"]["sha256"],
        **freeze_lock["prompts"],
        **freeze_lock["ql"]["files"],
    }
    for relative, expected in frozen_paths.items():
        path = (repository_root / relative).resolve(strict=True)
        path.relative_to(repository_root)
        if sha256_file(path) != expected:
            raise CoverageComparisonError(f"detector freeze source drift: {relative}")

    requirements = _read_jsonl(root / "canonical-requirements.jsonl")
    requirement_schema = _schema("canonical-requirement-v7.schema.json")
    for row in requirements:
        validate(row, requirement_schema)
    requirement_ids = {row["requirement_id"] for row in requirements}
    if len(requirement_ids) != len(requirements):
        raise CoverageComparisonError("duplicate canonical CR identities")

    candidates = _read_jsonl(root / "candidates.jsonl")
    provisional_candidates = _read_jsonl(root / "provisional-candidates.jsonl")
    validations = _read_jsonl(root / "candidate-validations.jsonl")
    candidate_schema = _schema("coverage-candidate-v7.schema.json")
    for row in [*provisional_candidates, *candidates]:
        validate(row, candidate_schema)
        if row["requirement_id"] not in requirement_ids:
            raise CoverageComparisonError("candidate references unknown CR identity")
        expected = stable_v7_candidate_id(
            group_id=row["group_id"],
            project=row["project"],
            revision=row["revision"],
            chain_id=row["chain_id"],
            requirement_id=row["requirement_id"],
            failure_mode=row["failure_mode"],
            gate_ids=row["gate_ids"],
        )
        if row["candidate_id"] != expected:
            raise CoverageComparisonError("canonical candidate identity mismatch")
    if len({row["candidate_id"] for row in candidates}) != len(candidates):
        raise CoverageComparisonError("duplicate canonical candidate identities")
    if len({row["candidate_id"] for row in provisional_candidates}) != len(
        provisional_candidates
    ):
        raise CoverageComparisonError("duplicate provisional candidate identities")
    if not {row["candidate_id"] for row in candidates} <= {
        row["candidate_id"] for row in provisional_candidates
    }:
        raise CoverageComparisonError("canonical candidates are not provisional survivors")
    validation_schema = _schema("canonical-candidate-validation-v7.schema.json")
    provisional_ids = {row["candidate_id"] for row in provisional_candidates}
    for row in validations:
        validate(row, validation_schema)
        if row["provisional_candidate_id"] not in provisional_ids:
            raise CoverageComparisonError(
                "candidate validation references an unknown provisional candidate"
            )
        if row["requirement_id"] not in requirement_ids:
            raise CoverageComparisonError(
                "candidate validation references an unknown CR identity"
            )

    migrations = _read_jsonl(root / "identity-migration.jsonl")
    migration_schema = _schema("coverage-identity-migration-v7.schema.json")
    for row in migrations:
        validate(row, migration_schema)
    candidate_migrations = [row for row in migrations if row["record_kind"] == "candidate"]
    if len({row["old_candidate_id"] for row in candidate_migrations}) != len(candidate_migrations):
        raise CoverageComparisonError("identity ledger does not uniquely cover old candidates")
    expected_requirements, expected_candidates = _expected_legacy_identities(root)
    migrated_requirements = {
        (str(row["group_id"]), str(row["old_requirement_id"]))
        for row in migrations
        if row["record_kind"] == "requirement"
    }
    migrated_candidates = {
        str(row["old_candidate_id"])
        for row in candidate_migrations
    }
    if migrated_requirements != expected_requirements:
        raise CoverageComparisonError(
            "identity ledger does not exactly cover legacy requirements"
        )
    if migrated_candidates != expected_candidates:
        raise CoverageComparisonError(
            "identity ledger does not exactly cover legacy candidates"
        )

    selected = _read_jsonl(root / "canonical-router-selected.jsonl")
    excluded = _read_jsonl(root / "canonical-router-excluded.jsonl")
    router_schema = _schema("coverage-canonical-router-v7.schema.json")
    for row in [*selected, *excluded]:
        validate(row, router_schema)
    router_keys = [(row["project"], row["chain_id"]) for row in [*selected, *excluded]]
    router_scope = manifest.get("router", {}).get("scope")
    budget = manifest.get("router", {}).get("budget")
    invalid_partition = len(router_keys) != 484 or len(set(router_keys)) != 484
    invalid_budget = (
        router_scope == "routed"
        and (not isinstance(budget, int) or len(selected) > budget)
    )
    invalid_all_scope = router_scope == "all" and (
        len(selected) != 484 or bool(excluded)
    )
    if invalid_partition or invalid_budget or invalid_all_scope:
        raise CoverageComparisonError("canonical router does not partition 484 chains")

    comparisons = _read_jsonl(root / "comparisons.jsonl")
    assessments = _read_jsonl(root / "requirement-assessments.jsonl")
    comparison_schema = _schema("coverage-comparison-v7.schema.json")
    assessment_schema = _schema("coverage-requirement-assessment-v7.schema.json")
    for row in comparisons:
        validate(row, comparison_schema)
    for row in assessments:
        validate(row, assessment_schema)
    if any(row.get("schema_version") != COMPARISON_SCHEMA_VERSION for row in comparisons):
        raise CoverageComparisonError("comparison schema is not v7")
    if any(row.get("schema_version") != ASSESSMENT_SCHEMA_VERSION for row in assessments):
        raise CoverageComparisonError("assessment schema is not v7")
    if len(comparisons) != 484:
        raise CoverageComparisonError("canonical comparisons do not cover 484 chains")
    if any(row["requirement_id"] not in requirement_ids for row in assessments):
        raise CoverageComparisonError("assessment references an unknown CR identity")
    if any(
        requirement["requirement_id"] not in requirement_ids
        for comparison in comparisons
        for requirement in comparison["requirements"]
    ):
        raise CoverageComparisonError("comparison references an unknown CR identity")

    counts = manifest["counts"]
    expected_counts = {
        "canonical_requirements": len(requirements),
        "identity_requirement_rows": sum(
            row["record_kind"] == "requirement" for row in migrations
        ),
        "identity_candidate_rows": len(candidate_migrations),
        "provisional_candidates": len(provisional_candidates),
        "candidates": len(candidates),
        "router_selected": len(selected),
        "router_excluded": len(excluded),
    }
    if any(counts.get(key) != value for key, value in expected_counts.items()):
        raise CoverageComparisonError("canonical manifest artifact counts drifted")

    ground_truth = _read_jsonl(root / "ground-truth-coverage.jsonl")
    training = [row for row in ground_truth if row.get("evaluation_partition") == "training"]
    found = sum(row["status"] == "covered" for row in training)
    missed = sum(row["status"] == "missed" for row in training)
    if (found, missed) != (35, 8):
        raise CoverageComparisonError("canonical training recall drifted from 35/43")

    inventory = _read_json(root / "artifact-inventory.json")
    for relative, expected in inventory["files"].items():
        path = root / relative
        if not path.is_file() or sha256_file(path) != expected:
            raise CoverageComparisonError(f"artifact inventory drift: {relative}")
    actual_tree = digest(
        [[path, value] for path, value in sorted(inventory["files"].items())]
    )
    if actual_tree != inventory["tree_sha256"]:
        raise CoverageComparisonError("artifact inventory tree digest mismatch")
    if manifest.get("artifact_inventory_sha256") != sha256_file(
        root / "artifact-inventory.json"
    ):
        raise CoverageComparisonError("manifest inventory binding mismatch")
    return {
        "manifest": manifest,
        "requirements": len(requirements),
        "candidates": len(candidates),
        "router_selected": len(selected),
        "router_excluded": len(excluded),
        "training_found": found,
        "training_missed": missed,
    }


def analysis_plan(root: Path) -> Mapping[str, Any]:
    result = validate_v7_artifacts(root)
    counts = result["manifest"]["counts"]
    return {
        "analysis_mode": "canonical-trained-detector/v7",
        "eligible_chains": counts["eligible_comparisons"],
        "canonical_requirements": counts["canonical_requirements"],
        "learned_routed_chains": counts["learned_routed_chains"],
        "learned_routed_pairs": counts["learned_routed_pairs"],
        "same_origin_witnesses": counts["same_origin_witnesses"],
        "same_origin_exclusions": counts["same_origin_exclusions"],
        "router_selected": counts["router_selected"],
        "router_excluded": counts["router_excluded"],
        "provider_tokens": result["manifest"]["transport"]["provider_tokens"],
        "training_recall": f"{result['training_found']}/43",
        "claim": "training evaluation; not blind recall",
    }
