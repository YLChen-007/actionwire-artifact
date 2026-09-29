"""Revision-bound input loading for requirement-level coverage comparison."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from jsonschema import validate as validate_schema

from src.group_oracle.contracts import SCHEMA_DIR as ORACLE_SCHEMA_DIR
from src.group_oracle.inputs import OracleChain, load_oracle_inputs
from src.projects import ProjectSpec
from src.sink_capacity.card_migration import validates_digest_transition
from src.sink_type_alignment.contracts import SCHEMA_DIR as SINK_SCHEMA_DIR

from .contracts import EXCLUSION_SCHEMA_VERSION, CoverageComparisonError, sha256_file
from .prompts import contains_credentials


@dataclass(frozen=True)
class CoverageChain:
    project: str
    revision: str
    chain_id: str
    handler_id: str
    handler_criterion_id: str
    handler_type_id: str
    sink_id: str
    sink_type_id: str
    group_id: str
    oracle: dict[str, Any]
    semantic_ir: dict[str, Any]
    capability_card_path: str
    capability_card_sha256: str
    capability_card: str
    capability_card_lines: tuple[str, ...]
    requirement_evidence: tuple[dict[str, Any], ...]

    @property
    def key(self) -> tuple[str, str]:
        return self.project, self.chain_id


@dataclass(frozen=True)
class CoverageInputs:
    chains: tuple[CoverageChain, ...]
    exclusions: tuple[dict[str, Any], ...]
    digests: dict[str, Any]
    structural_chain_count: int


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise CoverageComparisonError(f"missing coverage-comparison input: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageComparisonError(f"invalid JSON input {path}: {exc}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise CoverageComparisonError(f"missing coverage-comparison input: {path}")
    output: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CoverageComparisonError(
                f"{path}:{number}: invalid JSON: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise CoverageComparisonError(f"{path}:{number}: row must be an object")
        output.append(row)
    return output


def _read_csv_ids(path: Path, *, project: str) -> set[tuple[str, str]]:
    if not path.is_file():
        raise CoverageComparisonError(f"{project}: missing structural chains {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"project_id", "chain_id"} <= set(
            reader.fieldnames
        ):
            raise CoverageComparisonError(
                f"{project}: invalid structural chain columns"
            )
        output: set[tuple[str, str]] = set()
        for row in reader:
            if row["project_id"] != project:
                raise CoverageComparisonError(
                    f"{project}: structural chain identity mismatch"
                )
            key = (project, row["chain_id"])
            if key in output:
                raise CoverageComparisonError(
                    f"{project}: duplicate structural chain {key}"
                )
            output.add(key)
    return output


def _capability_card(
    *, repo_root: Path, raw_path: str, expected_digest: str, context: str
) -> tuple[str, tuple[str, ...]]:
    path = Path(raw_path)
    resolved = path.resolve() if path.is_absolute() else (repo_root / path).resolve()
    card_root = (repo_root / "src/sink_capacity/sink-capability-cards").resolve()
    try:
        resolved.relative_to(card_root)
    except ValueError as exc:
        raise CoverageComparisonError(
            f"{context}: capability card is outside the existing card oracle"
        ) from exc
    if not resolved.is_file():
        raise CoverageComparisonError(f"{context}: capability card does not exist")
    actual_digest = sha256_file(resolved)
    if not validates_digest_transition(
        card_path=raw_path,
        expected_sha256=expected_digest,
        actual_sha256=actual_digest,
        ledger_path=card_root / "identity-migration.jsonl",
    ):
        raise CoverageComparisonError(f"{context}: capability-card digest drift")
    text = resolved.read_text(encoding="utf-8")
    if contains_credentials(text):
        raise CoverageComparisonError(f"{context}: unsafe capability-card content")
    lines = tuple(text.splitlines())
    if not lines:
        raise CoverageComparisonError(f"{context}: empty capability card")
    return text, lines


def load_coverage_inputs(
    specs: Sequence[ProjectSpec],
    *,
    handler_root: Path,
    sink_root: Path,
    group_root: Path,
    evidence_registry: Path,
) -> CoverageInputs:
    repo_root = Path(__file__).resolve().parents[2]
    resolved_specs = sorted(
        (spec.resolved() for spec in specs), key=lambda spec: spec.project_id
    )
    # Reuse the upstream loader as the canonical validation of handler/sink catalogs,
    # mappings, revisions, semantic IR, evidence paths, and capability-card digests.
    try:
        upstream = load_oracle_inputs(
            resolved_specs,
            handler_root=handler_root,
            sink_root=sink_root,
            evidence_registry=evidence_registry,
        )
    except Exception as exc:
        raise CoverageComparisonError(f"upstream validation failed: {exc}") from exc

    oracle_path = group_root / "oracles.jsonl"
    exclusion_path = group_root / "excluded-groups.jsonl"
    evidence_path = group_root / "evidence-index.json"
    group_manifest_path = group_root / "manifest.json"
    oracles = _read_jsonl(oracle_path)
    group_exclusions = _read_jsonl(exclusion_path)
    evidence_index = _read_json(evidence_path)
    group_manifest = _read_json(group_manifest_path)
    oracle_schema = _read_json(ORACLE_SCHEMA_DIR / "group-oracle-v1.schema.json")
    group_exclusion_schema = _read_json(
        ORACLE_SCHEMA_DIR / "group-oracle-exclusion-v1.schema.json"
    )
    evidence_schema = _read_json(
        ORACLE_SCHEMA_DIR / "oracle-evidence-index-v1.schema.json"
    )
    for row in oracles:
        validate_schema(instance=row, schema=oracle_schema)
    for row in group_exclusions:
        validate_schema(instance=row, schema=group_exclusion_schema)
    validate_schema(instance=evidence_index, schema=evidence_schema)
    if group_manifest.get("schema_version") != "group-oracle-manifest/v1":
        raise CoverageComparisonError("unsupported group-oracle manifest")
    for name, path in {
        "oracles": oracle_path,
        "excluded_groups": exclusion_path,
        "evidence_index": evidence_path,
    }.items():
        declared = group_manifest.get("outputs", {}).get(name)
        if not isinstance(declared, str) or Path(declared).resolve() != path.resolve():
            raise CoverageComparisonError(f"group-oracle {name} path mismatch")
    upstream_digests = group_manifest.get("inputs")
    if upstream_digests != upstream.digests:
        raise CoverageComparisonError("group-oracle input binding is stale")

    evidence_by_id = {row["evidence_id"]: row for row in evidence_index["evidence"]}
    if len(evidence_by_id) != len(evidence_index["evidence"]):
        raise CoverageComparisonError("duplicate group-oracle evidence IDs")
    oracle_by_group = {row["group_id"]: row for row in oracles}
    if len(oracle_by_group) != len(oracles):
        raise CoverageComparisonError("duplicate group oracle IDs")
    expected_group_ids = {
        row["handler_sink_group_id"] for row in upstream.security_groups
    }
    if set(oracle_by_group) != expected_group_ids:
        raise CoverageComparisonError(
            "group oracles do not exactly cover security groups"
        )

    mapping_rows = _read_jsonl(sink_root / "mappings.jsonl")
    mapping_schema = _read_json(SINK_SCHEMA_DIR / "sink-type-mapping-v1.schema.json")
    for row in mapping_rows:
        validate_schema(instance=row, schema=mapping_schema)
    mapping_by_key = {(row["project"], row["chain_id"]): row for row in mapping_rows}
    if len(mapping_by_key) != len(mapping_rows):
        raise CoverageComparisonError("duplicate sink mappings")

    chains: list[CoverageChain] = []
    covered: set[tuple[str, str]] = set()
    for group in upstream.security_groups:
        group_id = group["handler_sink_group_id"]
        oracle = oracle_by_group[group_id]
        expected_refs = {
            (row["project"], row["chain_id"]) for row in group["chain_refs"]
        }
        actual_refs = {
            (row["project"], row["chain_id"]) for row in oracle["member_chain_refs"]
        }
        if actual_refs != expected_refs:
            raise CoverageComparisonError(f"{group_id}: oracle membership mismatch")
        for key in sorted(expected_refs):
            if key in covered:
                raise CoverageComparisonError(f"duplicate eligible chain {key}")
            covered.add(key)
            chain: OracleChain = upstream.chains[key]
            mapping = mapping_by_key.get(key)
            if mapping is None:
                raise CoverageComparisonError(f"{key}: missing sink mapping")
            if (
                chain.handler_criterion_id != oracle["handler_criterion_id"]
                or chain.sink_type_id != oracle["sink_type_id"]
                or mapping["handler_criterion_id"] != oracle["handler_criterion_id"]
                or mapping["sink_type_id"] != oracle["sink_type_id"]
                or mapping["handler_type_id"] != chain.handler_type_id
            ):
                raise CoverageComparisonError(f"{key}: HC/ST/HT binding disagreement")
            semantic = chain.semantic_ir
            if semantic["handler"].get("tool_name") != mapping.get(
                "tool_name", semantic["handler"].get("tool_name")
            ):
                raise CoverageComparisonError(f"{key}: handler identity disagreement")
            constraint = semantic["sink_constraint"]
            if constraint["sink_id"] != mapping["sink_id"]:
                raise CoverageComparisonError(f"{key}: sink identity disagreement")
            raw_path = constraint["capability_card"]["path"]
            card_digest = constraint["capability_card"]["sha256"]
            card, card_lines = _capability_card(
                repo_root=repo_root,
                raw_path=raw_path,
                expected_digest=card_digest,
                context=f"{key[0]}:{key[1]}",
            )
            evidence_ids = {
                evidence_id
                for requirement in oracle["requirements"]
                for evidence_id in requirement["evidence_ids"]
            }
            if not evidence_ids <= set(evidence_by_id):
                raise CoverageComparisonError(
                    f"{key}: oracle references unknown evidence"
                )
            chains.append(
                CoverageChain(
                    project=key[0],
                    revision=chain.revision,
                    chain_id=key[1],
                    handler_id=mapping["handler_id"],
                    handler_criterion_id=oracle["handler_criterion_id"],
                    handler_type_id=mapping["handler_type_id"],
                    sink_id=mapping["sink_id"],
                    sink_type_id=oracle["sink_type_id"],
                    group_id=group_id,
                    oracle=oracle,
                    semantic_ir=semantic,
                    capability_card_path=raw_path,
                    capability_card_sha256=card_digest,
                    capability_card=card,
                    capability_card_lines=card_lines,
                    requirement_evidence=tuple(
                        evidence_by_id[row] for row in sorted(evidence_ids)
                    ),
                )
            )

    sink_exclusion_path = sink_root / "excluded-chains.jsonl"
    sink_exclusions = _read_jsonl(sink_exclusion_path)
    sink_exclusion_schema = _read_json(
        SINK_SCHEMA_DIR / "sink-type-exclusion-v1.schema.json"
    )
    for row in sink_exclusions:
        validate_schema(instance=row, schema=sink_exclusion_schema)
    exclusions = tuple(
        sorted(
            (
                {
                    "schema_version": EXCLUSION_SCHEMA_VERSION,
                    "project": row["project"],
                    "revision": row["revision"],
                    "chain_id": row["chain_id"],
                    "sink_id": row["sink_id"],
                    "handler_id": row["handler_id"],
                    "tool_name": row["tool_name"],
                    "reason_code": row["reason_code"],
                    "detail": row["detail"],
                }
                for row in sink_exclusions
            ),
            key=lambda row: (row["project"], row["chain_id"]),
        )
    )
    excluded_keys = {(row["project"], row["chain_id"]) for row in exclusions}
    if len(excluded_keys) != len(exclusions):
        raise CoverageComparisonError("duplicate coverage exclusions")

    structural: set[tuple[str, str]] = set()
    project_digests: dict[str, Any] = {}
    sink_manifest = _read_json(sink_root / "manifest.json")
    for spec in resolved_specs:
        structural_path = (
            spec.output_root / "static/call-chains/handler-sink-chains.csv"
        )
        manifest_path = spec.output_root / "static/call-chains/manifest.json"
        structural |= _read_csv_ids(structural_path, project=spec.project_id)
        declared = sink_manifest["inputs"]["projects"][spec.project_id]
        if declared["handler_sink_chains"] != sha256_file(structural_path):
            raise CoverageComparisonError(
                f"{spec.project_id}: structural chain digest drift"
            )
        if declared["structural_manifest"] != sha256_file(manifest_path):
            raise CoverageComparisonError(
                f"{spec.project_id}: structural manifest digest drift"
            )
        project_digests[spec.project_id] = {
            "revision": spec.analysis_revision,
            "structural_manifest": sha256_file(manifest_path),
            "handler_sink_chains": sha256_file(structural_path),
        }
    eligible_keys = {row.key for row in chains}
    if eligible_keys & excluded_keys or eligible_keys | excluded_keys != structural:
        missing = sorted(structural - eligible_keys - excluded_keys)
        extra = sorted((eligible_keys | excluded_keys) - structural)
        raise CoverageComparisonError(
            f"eligible/excluded chains do not partition structural chains; "
            f"missing={missing[:5]}, extra={extra[:5]}"
        )
    group_excluded_keys = {
        (ref["project"], ref["chain_id"])
        for group in group_exclusions
        for ref in group["chain_refs"]
    }
    impact_keys = {
        (row["project"], row["chain_id"])
        for row in exclusions
        if row["reason_code"] == "impact-pruned"
    }
    if group_excluded_keys != impact_keys:
        raise CoverageComparisonError("group and sink no-impact exclusions disagree")

    return CoverageInputs(
        chains=tuple(sorted(chains, key=lambda row: row.key)),
        exclusions=exclusions,
        structural_chain_count=len(structural),
        digests={
            "handler_alignment": upstream.digests["handler_alignment"],
            "sink_alignment": upstream.digests["sink_alignment"],
            "group_oracle": {
                "oracles": sha256_file(oracle_path),
                "excluded_groups": sha256_file(exclusion_path),
                "evidence_index": sha256_file(evidence_path),
                "manifest": sha256_file(group_manifest_path),
            },
            "evidence_registry": upstream.digests["evidence_registry"],
            "projects": {
                project: {
                    **upstream.digests["projects"][project],
                    **project_digests[project],
                }
                for project in sorted(project_digests)
            },
            "capability_cards": {
                row.capability_card_path: row.capability_card_sha256
                for row in sorted(chains, key=lambda item: item.capability_card_path)
            },
        },
    )
