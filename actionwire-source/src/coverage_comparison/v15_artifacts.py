"""Pure artifact transformations used by the canonical detector v15 rollout."""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

from .contracts import CoverageComparisonError, digest, sha256_file
from .v10 import _filter_ground_truth


CLUSTER_VERSION = "coverage-vulnerability-cluster/v15"
IDENTITY_MIGRATION_VERSION = "coverage-v15-identity-migration/v1"


def migrate_card_binding(
    row: Mapping[str, Any], *, card_sha256: Mapping[str, str], generic: bool
) -> dict[str, Any]:
    output = deepcopy(dict(row))
    card = output.get("capability_card")
    if isinstance(card, dict):
        path = str(card["path"])
        if path not in card_sha256:
            raise CoverageComparisonError(f"unknown v2 capability card: {path}")
        card["sha256"] = card_sha256[path]
    if generic:
        context = output.get("source_context")
        if isinstance(context, dict):
            context.pop("training_report_ids", None)
    return output


def filter_comparison_artifacts(
    *,
    comparisons: Sequence[Mapping[str, Any]],
    assessments: Sequence[Mapping[str, Any]],
    applicability: Sequence[Mapping[str, Any]],
    card_sha256: Mapping[str, str],
    effective_views: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    applicable = {
        (str(row["project"]), str(row["chain_id"]), str(row["requirement_id"]))
        for row in applicability
        if row["decision"] == "applicable"
    }
    output_comparisons: list[dict[str, Any]] = []
    for raw in comparisons:
        row = migrate_card_binding(raw, card_sha256=card_sha256, generic=False)
        key = (str(row["project"]), str(row["chain_id"]))
        row["requirements"] = [
            requirement
            for requirement in row["requirements"]
            if (*key, str(requirement["requirement_id"])) in applicable
        ]
        view = effective_views[key]
        row["applicable_defaults"] = sorted(
            f"{default['default_id']}={default['value']}"
            for default in view.get("active_defaults", [])
        )
        output_comparisons.append(row)
    output_assessments = [
        {**dict(row), "capability_evidence": []}
        for row in assessments
        if (
            str(row["project"]),
            str(row["chain_id"]),
            str(row["requirement_id"]),
        )
        in applicable
    ]
    return output_comparisons, output_assessments


def vulnerability_clusters(
    candidates: Sequence[Mapping[str, Any]],
    validations: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = defaultdict(
        list
    )
    for candidate in candidates:
        validation = validations[str(candidate["candidate_id"])]
        patch_loci = sorted(
            {
                str(row["file"])
                for row in validation.get("source_evidence", [])
                if row.get("role") in {"gate", "policy"} and row.get("file")
            }
        )
        patch_locus = patch_loci[0] if patch_loci else str(candidate["sink_id"])
        normalized_invariant = " ".join(
            str(candidate["requirement_rule"]).lower().split()
        )
        key = (
            str(candidate["project"]),
            str(candidate["sink_id"]),
            normalized_invariant,
            patch_locus,
        )
        grouped[key].append(candidate)
    output: list[dict[str, Any]] = []
    for key, rows in sorted(grouped.items()):
        candidate_ids = sorted(str(row["candidate_id"]) for row in rows)
        output.append(
            {
                "schema_version": CLUSTER_VERSION,
                "cluster_id": "VULCL-" + digest([CLUSTER_VERSION, *key])[:16],
                "project": key[0],
                "actual_effect_sink": key[1],
                "normalized_invariant": key[2],
                "patch_locus": key[3],
                "candidate_ids": candidate_ids,
                "chain_ids": sorted({str(row["chain_id"]) for row in rows}),
                "requirement_ids": sorted({str(row["requirement_id"]) for row in rows}),
                "failure_modes": sorted({str(row["failure_mode"]) for row in rows}),
            }
        )
    return output


def ground_truth_partition(
    rows: Sequence[Mapping[str, Any]], *, candidate_ids: set[str], label: str
) -> list[dict[str, Any]]:
    output = _filter_ground_truth(rows, candidate_ids=candidate_ids)
    for row in output:
        if row.get("evaluation_partition") != "training":
            continue
        row["reason"] = (
            f"at least one {label} candidate strictly matches the training invariant"
            if row["status"] == "covered"
            else f"no {label} candidate strictly matches the training invariant"
        )
    return output


def identity_migration(
    *,
    prior_requirements: Sequence[Mapping[str, Any]],
    admitted_requirement_ids: set[str],
    prior_candidates: Sequence[Mapping[str, Any]],
    generic_candidate_ids: set[str],
    fallback_candidate_ids: set[str],
    comparisons: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for requirement in prior_requirements:
        requirement_id = str(requirement["requirement_id"])
        rows.append(
            {
                "schema_version": IDENTITY_MIGRATION_VERSION,
                "identity_kind": "canonical-requirement",
                "old_id": requirement_id,
                "new_id": requirement_id
                if requirement_id in admitted_requirement_ids
                else None,
                "disposition": (
                    "one-to-one"
                    if requirement_id in admitted_requirement_ids
                    else "removed-hypothesis"
                ),
            }
        )
    for candidate in prior_candidates:
        candidate_id = str(candidate["candidate_id"])
        if candidate_id in generic_candidate_ids:
            disposition = "one-to-one-generic"
        elif candidate_id in fallback_candidate_ids:
            disposition = "training-overlay-only"
        else:
            disposition = "removed-not-applicable"
        rows.append(
            {
                "schema_version": IDENTITY_MIGRATION_VERSION,
                "identity_kind": "candidate",
                "old_id": candidate_id,
                "new_id": candidate_id
                if disposition != "removed-not-applicable"
                else None,
                "disposition": disposition,
            }
        )
    for identity_kind, field in (
        ("sink-type", "sink_type_id"),
        ("handler-sink-group", "group_id"),
    ):
        for value in sorted({str(row[field]) for row in comparisons}):
            rows.append(
                {
                    "schema_version": IDENTITY_MIGRATION_VERSION,
                    "identity_kind": identity_kind,
                    "old_id": value,
                    "new_id": value,
                    "disposition": "one-to-one",
                }
            )
    return sorted(rows, key=lambda row: (row["identity_kind"], row["old_id"]))


def validate_source_hashes(
    *,
    candidates: Sequence[Mapping[str, Any]],
    validations: Mapping[str, Mapping[str, Any]],
    source_roots: Mapping[str, Path],
) -> None:
    for candidate in candidates:
        candidate_id = str(candidate["candidate_id"])
        validation = validations.get(candidate_id)
        if validation is None or validation.get("verdict") != "confirmed-uncovered":
            raise CoverageComparisonError(
                f"{candidate_id}: no confirmed source validation"
            )
        root = source_roots[str(candidate["project"])].resolve()
        for evidence in validation.get("source_evidence", []):
            relative = Path(str(evidence["file"]))
            target = (root / relative).resolve()
            if root not in target.parents or not target.is_file():
                raise CoverageComparisonError(
                    f"{candidate_id}: source evidence path is missing or escapes root"
                )
            if sha256_file(target) != evidence["sha256"]:
                raise CoverageComparisonError(f"{candidate_id}: source evidence drift")
