"""Revision-bound input loading for HC/ST group-oracle construction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import validate as validate_schema

from src.call_chain_semantics.contracts import SCHEMA_DIR as CHAIN_SCHEMA_DIR
from src.handler_type_alignment.contracts import SCHEMA_DIR as HANDLER_SCHEMA_DIR
from src.projects import ProjectSpec
from src.sink_capacity.card_migration import validates_digest_transition
from src.sink_capacity.policy_contract import (
    CapabilityPolicyError,
    parse_approval_policy_contract,
)
from src.sink_type_alignment.contracts import SCHEMA_DIR as SINK_SCHEMA_DIR
from src.sink_type_alignment.contracts import validate_handler_sink_groups

from .contracts import (
    EVIDENCE_SCHEMA_VERSION,
    REGISTRY_SCHEMA_VERSION,
    GroupOracleError,
    sha256_file,
    stable_evidence_id,
)
from .evidence_authority import MANUAL_EVIDENCE_KINDS
from .prompts import contains_credentials, redact_credentials


@dataclass(frozen=True)
class OracleChain:
    project: str
    revision: str
    chain_id: str
    handler_criterion_id: str
    handler_type_id: str
    sink_type_id: str
    semantic_ir: dict[str, Any]
    capability_card: str
    capability_card_path: str
    capability_evidence_id: str

    @property
    def key(self) -> tuple[str, str]:
        return self.project, self.chain_id

    @property
    def ref(self) -> str:
        return f"{self.project}:{self.chain_id}"


@dataclass(frozen=True)
class OracleInputs:
    handler_criteria: Mapping[str, dict[str, Any]]
    sink_types: Mapping[str, dict[str, Any]]
    security_groups: tuple[dict[str, Any], ...]
    excluded_groups: tuple[dict[str, Any], ...]
    chains: Mapping[tuple[str, str], OracleChain]
    evidence_index: dict[str, Any]
    evidence_by_group: Mapping[str, tuple[dict[str, Any], ...]]
    digests: dict[str, Any]


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise GroupOracleError(f"missing group-oracle input: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GroupOracleError(f"invalid JSON input {path}: {exc}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise GroupOracleError(f"missing group-oracle input: {path}")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GroupOracleError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise GroupOracleError(f"{path}:{number}: row must be an object")
        rows.append(value)
    return rows


def _manifest_path(value: object, expected: Path, context: str) -> None:
    if not isinstance(value, str) or Path(value).resolve() != expected.resolve():
        raise GroupOracleError(f"{context}: manifest path mismatch")


def _repository_path(repo_root: Path, raw: str, context: str) -> Path:
    path = Path(raw)
    if path.is_absolute():
        resolved = path.resolve()
    else:
        if ".." in path.parts:
            raise GroupOracleError(f"{context}: unsafe repository path")
        resolved = (repo_root / path).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise GroupOracleError(f"{context}: path escapes repository root") from exc
    if not resolved.is_file():
        raise GroupOracleError(f"{context}: evidence source does not exist")
    return resolved


def _manual_evidence(
    *, repo_root: Path, registry_path: Path, valid_hcs: set[str], valid_sts: set[str]
) -> list[dict[str, Any]]:
    registry_path = _repository_path(repo_root, str(registry_path), "evidence registry")
    registry = _read_json(registry_path)
    version = registry.get("schema_version")
    schema_name = (
        "oracle-evidence-registry-v2.schema.json"
        if version == "oracle-evidence-registry/v2"
        else "oracle-evidence-registry-v1.schema.json"
    )
    registry_schema = _read_json(
        Path(__file__).resolve().parent / "schemas" / schema_name
    )
    validate_schema(instance=registry, schema=registry_schema)
    if version not in {REGISTRY_SCHEMA_VERSION, "oracle-evidence-registry/v2"}:
        raise GroupOracleError("unsupported oracle evidence registry schema")
    registry_rows = list(registry["evidence"])
    if version == "oracle-evidence-registry/v2":
        base_path = _repository_path(
            repo_root, registry["base_registry"], "base evidence registry"
        )
        if sha256_file(base_path) != registry["base_sha256"]:
            raise GroupOracleError("base evidence registry digest drift")
        base = _read_json(base_path)
        base_schema = _read_json(
            Path(__file__).resolve().parent
            / "schemas/oracle-evidence-registry-v1.schema.json"
        )
        validate_schema(instance=base, schema=base_schema)
        if base.get("schema_version") != REGISTRY_SCHEMA_VERSION:
            raise GroupOracleError("v2 evidence registry must extend a v1 registry")
        registry_rows = [*base["evidence"], *registry_rows]
    output: list[dict[str, Any]] = []
    for number, row in enumerate(registry_rows, 1):
        if row["kind"] not in MANUAL_EVIDENCE_KINDS:
            raise GroupOracleError(f"manual evidence {number}: unsupported kind")
        hcs = sorted(row["applicability"]["handler_criterion_ids"])
        sts = sorted(row["applicability"]["sink_type_ids"])
        if not hcs and not sts:
            raise GroupOracleError(
                f"manual evidence {number}: applicability must name an HC or ST"
            )
        if not set(hcs) <= valid_hcs or not set(sts) <= valid_sts:
            raise GroupOracleError(
                f"manual evidence {number}: unknown HC/ST applicability"
            )
        source = _repository_path(
            repo_root, row["source_path"], f"manual evidence {number}"
        )
        actual_digest = sha256_file(source)
        if actual_digest != row["sha256"]:
            raise GroupOracleError(f"manual evidence {number}: source digest drift")
        text = source.read_text(encoding="utf-8")
        if row["exact_quote"] not in text:
            raise GroupOracleError(f"manual evidence {number}: exact quote not found")
        if contains_credentials(row["exact_quote"]):
            raise GroupOracleError(
                f"manual evidence {number}: exact quote contains credential-shaped data"
            )
        evidence_id = stable_evidence_id(
            row["kind"],
            row["source_path"],
            actual_digest,
            row["locator"],
            row["exact_quote"],
            row["supported_claim"],
        )
        output.append(
            {
                "evidence_id": evidence_id,
                "kind": row["kind"],
                "applicability": {
                    "handler_criterion_ids": hcs,
                    "sink_type_ids": sts,
                },
                "source_path": row["source_path"],
                "sha256": actual_digest,
                "locator": row["locator"],
                "exact_quote": row["exact_quote"],
                "supported_claim": row["supported_claim"],
            }
        )
    ids = [row["evidence_id"] for row in output]
    if len(ids) != len(set(ids)):
        raise GroupOracleError("manual evidence registry contains duplicate evidence")
    return sorted(output, key=lambda row: row["evidence_id"])


def _validate_upstream(
    *,
    specs: Sequence[ProjectSpec],
    handler_root: Path,
    sink_root: Path,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    handler_catalog_path = handler_root / "catalog.json"
    handler_mappings_path = handler_root / "mappings.jsonl"
    handler_manifest_path = handler_root / "manifest.json"
    handler_catalog = _read_json(handler_catalog_path)
    handler_mappings = _read_jsonl(handler_mappings_path)
    handler_manifest = _read_json(handler_manifest_path)
    validate_schema(
        instance=handler_catalog,
        schema=_read_json(HANDLER_SCHEMA_DIR / "handler-type-catalog-v4.schema.json"),
    )
    mapping_schema = _read_json(
        HANDLER_SCHEMA_DIR / "handler-type-mapping-v2.schema.json"
    )
    for row in handler_mappings:
        validate_schema(instance=row, schema=mapping_schema)
    if handler_manifest.get("schema_version") != "handler-type-alignment-manifest/v4":
        raise GroupOracleError("unsupported handler alignment manifest")
    _manifest_path(
        handler_manifest.get("outputs", {}).get("catalog"),
        handler_catalog_path,
        "handler catalog",
    )
    _manifest_path(
        handler_manifest.get("outputs", {}).get("mappings"),
        handler_mappings_path,
        "handler mappings",
    )
    criteria = {row["handler_criterion_id"]: row for row in handler_catalog["criteria"]}
    if len(criteria) != len(handler_catalog["criteria"]):
        raise GroupOracleError("duplicate handler criteria")
    handler_mapping_by_key = {
        (row["project"], row["handler_id"]): row for row in handler_mappings
    }
    if len(handler_mapping_by_key) != len(handler_mappings):
        raise GroupOracleError("duplicate handler mappings")

    sink_catalog_path = sink_root / "catalog.json"
    sink_mappings_path = sink_root / "mappings.jsonl"
    sink_groups_path = sink_root / "handler-sink-groups.jsonl"
    sink_exclusions_path = sink_root / "excluded-chains.jsonl"
    sink_manifest_path = sink_root / "manifest.json"
    sink_catalog = _read_json(sink_catalog_path)
    sink_mappings = _read_jsonl(sink_mappings_path)
    sink_groups = _read_jsonl(sink_groups_path)
    sink_exclusions = _read_jsonl(sink_exclusions_path)
    sink_manifest = _read_json(sink_manifest_path)
    validate_schema(
        instance=sink_catalog,
        schema=_read_json(SINK_SCHEMA_DIR / "sink-type-catalog-v1.schema.json"),
    )
    sink_mapping_schema = _read_json(
        SINK_SCHEMA_DIR / "sink-type-mapping-v1.schema.json"
    )
    group_schema = _read_json(SINK_SCHEMA_DIR / "handler-sink-group-v1.schema.json")
    exclusion_schema = _read_json(
        SINK_SCHEMA_DIR / "sink-type-exclusion-v1.schema.json"
    )
    for row in sink_mappings:
        validate_schema(instance=row, schema=sink_mapping_schema)
    for row in sink_groups:
        validate_schema(instance=row, schema=group_schema)
    for row in sink_exclusions:
        validate_schema(instance=row, schema=exclusion_schema)
    if sink_manifest.get("schema_version") != "sink-type-alignment-manifest/v1":
        raise GroupOracleError("unsupported sink alignment manifest")
    for name, path in {
        "catalog": sink_catalog_path,
        "mappings": sink_mappings_path,
        "handler_sink_groups": sink_groups_path,
        "excluded_chains": sink_exclusions_path,
    }.items():
        _manifest_path(sink_manifest.get("outputs", {}).get(name), path, f"sink {name}")
    expected_handler_digests = sink_manifest.get("inputs", {}).get(
        "handler_alignment", {}
    )
    for name, path in {
        "catalog": handler_catalog_path,
        "mappings": handler_mappings_path,
        "manifest": handler_manifest_path,
    }.items():
        if expected_handler_digests.get(name) != sha256_file(path):
            raise GroupOracleError(f"sink alignment has stale handler {name} digest")
    sink_types = {row["sink_type_id"]: row for row in sink_catalog["sink_types"]}
    if len(sink_types) != len(sink_catalog["sink_types"]):
        raise GroupOracleError("duplicate sink types")
    for row in sink_mappings:
        handler = handler_mapping_by_key.get((row["project"], row["handler_id"]))
        if handler is None or (
            handler["handler_criterion_id"] != row["handler_criterion_id"]
            or handler["handler_type_id"] != row["handler_type_id"]
        ):
            raise GroupOracleError(
                f"{row['project']}:{row['chain_id']}: handler/sink mapping disagreement"
            )
        if row["sink_type_id"] not in sink_types:
            raise GroupOracleError(f"{row['chain_id']}: unknown sink type")
    impact_pruned: list[dict[str, Any]] = []
    for row in sink_exclusions:
        if row["reason_code"] != "impact-pruned":
            continue
        handler = handler_mapping_by_key.get((row["project"], row["handler_id"]))
        if handler is None:
            raise GroupOracleError(
                f"{row['project']}:{row['chain_id']}: no-impact exclusion has no "
                "resolved handler mapping"
            )
        impact_pruned.append(
            {
                "project": row["project"],
                "chain_id": row["chain_id"],
                "handler_criterion_id": handler["handler_criterion_id"],
            }
        )
    try:
        validate_handler_sink_groups(sink_groups, sink_mappings, impact_pruned)
    except Exception as exc:
        raise GroupOracleError(
            f"sink handler-group reconstruction failed: {exc}"
        ) from exc
    group_refs = [
        (ref["project"], ref["chain_id"])
        for group in sink_groups
        for ref in group["chain_refs"]
    ]
    if len(group_refs) != len(set(group_refs)):
        raise GroupOracleError("sink handler groups contain duplicate chain membership")
    valid_projects = {spec.project_id: spec.resolved() for spec in specs}
    sink_project_inputs = sink_manifest.get("inputs", {}).get("projects", {})
    if set(sink_project_inputs) != set(valid_projects):
        raise GroupOracleError("sink manifest project coverage mismatch")
    for project, spec in valid_projects.items():
        if sink_project_inputs[project].get("revision") != spec.analysis_revision:
            raise GroupOracleError(f"{project}: sink manifest revision mismatch")
    handler_digests = {
        "catalog": sha256_file(handler_catalog_path),
        "mappings": sha256_file(handler_mappings_path),
        "manifest": sha256_file(handler_manifest_path),
    }
    sink_digests = {
        "catalog": sha256_file(sink_catalog_path),
        "mappings": sha256_file(sink_mappings_path),
        "handler_sink_groups": sha256_file(sink_groups_path),
        "excluded_chains": sha256_file(sink_exclusions_path),
        "manifest": sha256_file(sink_manifest_path),
    }
    return (
        criteria,
        sink_types,
        sink_mappings,
        sink_groups,
        handler_digests,
        sink_digests,
    )


def load_oracle_inputs(
    specs: Sequence[ProjectSpec],
    *,
    handler_root: Path,
    sink_root: Path,
    evidence_registry: Path,
) -> OracleInputs:
    repo_root = Path(__file__).resolve().parents[2]
    resolved_specs = sorted(
        (spec.resolved() for spec in specs), key=lambda spec: spec.project_id
    )
    (
        handler_criteria,
        sink_types,
        sink_mappings,
        sink_groups,
        handler_digests,
        sink_digests,
    ) = _validate_upstream(
        specs=resolved_specs, handler_root=handler_root, sink_root=sink_root
    )
    mapping_by_key = {(row["project"], row["chain_id"]): row for row in sink_mappings}
    if len(mapping_by_key) != len(sink_mappings):
        raise GroupOracleError("duplicate sink chain mappings")
    semantic_schema = _read_json(
        CHAIN_SCHEMA_DIR / "call-chain-semantic-ir-v3.schema.json"
    )
    semantic_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    project_digests: dict[str, Any] = {}
    for spec in resolved_specs:
        semantic_path = (
            spec.output_root / "call-chain-semantics" / "call-chain-semantics.jsonl"
        )
        manifest_path = spec.output_root / "call-chain-semantics" / "manifest.json"
        manifest = _read_json(manifest_path)
        project_identity = manifest.get("project", {})
        if (
            project_identity.get("id") != spec.project_id
            or project_identity.get("revision") != spec.analysis_revision
        ):
            raise GroupOracleError(
                f"{spec.project_id}: semantic manifest identity mismatch"
            )
        sink_project = _read_json(sink_root / "manifest.json")["inputs"]["projects"][
            spec.project_id
        ]
        if sink_project["semantic_manifest"] != sha256_file(manifest_path):
            raise GroupOracleError(f"{spec.project_id}: semantic manifest digest drift")
        if sink_project["call_chain_semantics"] != sha256_file(semantic_path):
            raise GroupOracleError(f"{spec.project_id}: semantic IR digest drift")
        for row in _read_jsonl(semantic_path):
            validate_schema(instance=row, schema=semantic_schema)
            if row["project"] != {
                "id": spec.project_id,
                "revision": spec.analysis_revision,
            }:
                raise GroupOracleError(
                    f"{spec.project_id}:{row.get('chain_id')}: semantic identity mismatch"
                )
            key = (spec.project_id, row["chain_id"])
            if key in semantic_by_key:
                raise GroupOracleError(f"duplicate semantic chain {key}")
            semantic_by_key[key] = row
        project_digests[spec.project_id] = {
            "revision": spec.analysis_revision,
            "semantic_manifest": sha256_file(manifest_path),
            "call_chain_semantics": sha256_file(semantic_path),
        }
    if set(mapping_by_key) != set(semantic_by_key) & set(mapping_by_key):
        missing = sorted(set(mapping_by_key) - set(semantic_by_key))
        raise GroupOracleError(f"mapped chains lack semantic IR: {missing[:5]}")

    capability_evidence: dict[tuple[str, str, str], dict[str, Any]] = {}
    capability_policy_evidence: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    chains: dict[tuple[str, str], OracleChain] = {}
    for key, mapping in sorted(mapping_by_key.items()):
        semantic = semantic_by_key.get(key)
        if semantic is None:
            raise GroupOracleError(f"{key}: mapped chain lacks semantic IR")
        constraint = semantic["sink_constraint"]
        if constraint["sink_id"] != mapping["sink_id"]:
            raise GroupOracleError(f"{key}: sink mapping/semantic disagreement")
        raw_path = constraint["capability_card"]["path"]
        path = _repository_path(repo_root, raw_path, f"{key}: capability card")
        card_digest = sha256_file(path)
        if not validates_digest_transition(
            card_path=raw_path,
            expected_sha256=constraint["capability_card"]["sha256"],
            actual_sha256=card_digest,
            ledger_path=(
                repo_root
                / "src/sink_capacity/sink-capability-cards/identity-migration.jsonl"
            ),
        ):
            raise GroupOracleError(f"{key}: capability-card digest drift")
        card_text = path.read_text(encoding="utf-8")
        claim = f"Pinned capability semantics for {mapping['sink_type_id']}."
        safe_card_text = redact_credentials(card_text)
        evidence_id = stable_evidence_id(
            "capability-card",
            raw_path,
            card_digest,
            "complete-card",
            safe_card_text,
            claim,
        )
        evidence = {
            "evidence_id": evidence_id,
            "kind": "capability-card",
            "applicability": {
                "handler_criterion_ids": [mapping["handler_criterion_id"]],
                "sink_type_ids": [mapping["sink_type_id"]],
            },
            "source_path": raw_path,
            "sha256": card_digest,
            "locator": "complete-card",
            # The source digest binds the complete original card. Persist and prompt with a
            # credential-safe rendering so credential-shaped examples never enter artifacts.
            "exact_quote": safe_card_text,
            "supported_claim": claim,
        }
        evidence_key = (raw_path, card_digest, mapping["sink_type_id"])
        prior = capability_evidence.get(evidence_key)
        if prior is not None:
            merged_hcs = sorted(
                set(prior["applicability"]["handler_criterion_ids"])
                | {mapping["handler_criterion_id"]}
            )
            merged_sts = sorted(
                set(prior["applicability"]["sink_type_ids"]) | {mapping["sink_type_id"]}
            )
            prior["applicability"] = {
                "handler_criterion_ids": merged_hcs,
                "sink_type_ids": merged_sts,
            }
            evidence_id = prior["evidence_id"]
        else:
            capability_evidence[evidence_key] = evidence
        try:
            policy_requirements = parse_approval_policy_contract(card_text)
        except CapabilityPolicyError as exc:
            raise GroupOracleError(f"{key}: invalid capability policy: {exc}") from exc
        for policy in policy_requirements:
            locator = f"policy_contract.requirements[policy_id={policy['policy_id']}]"
            claim = (
                f"{policy['rule']} Applicability: {policy['applicability']} "
                f"Security effect: {policy['security_effect']}"
            )
            policy_evidence_id = stable_evidence_id(
                "capability-policy",
                raw_path,
                card_digest,
                locator,
                policy["exact_quote"],
                claim,
            )
            policy_row = {
                "evidence_id": policy_evidence_id,
                "kind": "capability-policy",
                "applicability": {
                    "handler_criterion_ids": [mapping["handler_criterion_id"]],
                    "sink_type_ids": [mapping["sink_type_id"]],
                },
                "source_path": raw_path,
                "sha256": card_digest,
                "locator": locator,
                "exact_quote": policy["exact_quote"],
                "supported_claim": claim,
            }
            policy_key = (
                raw_path,
                card_digest,
                mapping["sink_type_id"],
                policy["policy_id"],
            )
            prior_policy = capability_policy_evidence.get(policy_key)
            if prior_policy is None:
                capability_policy_evidence[policy_key] = policy_row
            else:
                prior_policy["applicability"] = {
                    "handler_criterion_ids": sorted(
                        set(prior_policy["applicability"]["handler_criterion_ids"])
                        | {mapping["handler_criterion_id"]}
                    ),
                    "sink_type_ids": sorted(
                        set(prior_policy["applicability"]["sink_type_ids"])
                        | {mapping["sink_type_id"]}
                    ),
                }
        chains[key] = OracleChain(
            project=mapping["project"],
            revision=mapping["revision"],
            chain_id=mapping["chain_id"],
            handler_criterion_id=mapping["handler_criterion_id"],
            handler_type_id=mapping["handler_type_id"],
            sink_type_id=mapping["sink_type_id"],
            semantic_ir=semantic,
            capability_card=safe_card_text,
            capability_card_path=raw_path,
            capability_evidence_id=evidence_id,
        )

    security_groups = tuple(
        sorted(
            (row for row in sink_groups if row["downstream_oracle_eligible"]),
            key=lambda row: row["handler_sink_group_id"],
        )
    )
    excluded_groups = tuple(
        sorted(
            (row for row in sink_groups if not row["downstream_oracle_eligible"]),
            key=lambda row: row["handler_sink_group_id"],
        )
    )
    covered: list[tuple[str, str]] = []
    for group in security_groups:
        if group["group_scope"] != "security" or group["sink_type_id"] is None:
            raise GroupOracleError(
                f"{group['handler_sink_group_id']}: invalid security group"
            )
        refs = {(row["project"], row["chain_id"]) for row in group["chain_refs"]}
        expected = {
            key
            for key, mapping in mapping_by_key.items()
            if mapping["handler_criterion_id"] == group["handler_criterion_id"]
            and mapping["sink_type_id"] == group["sink_type_id"]
        }
        if refs != expected:
            raise GroupOracleError(
                f"{group['handler_sink_group_id']}: reconstructed HC/ST membership mismatch"
            )
        covered.extend(refs)
    if len(covered) != len(set(covered)) or set(covered) != set(mapping_by_key):
        raise GroupOracleError("security groups do not exactly partition sink mappings")

    manual = _manual_evidence(
        repo_root=repo_root,
        registry_path=evidence_registry,
        valid_hcs=set(handler_criteria),
        valid_sts=set(sink_types),
    )
    evidence_rows = sorted(
        [
            *capability_evidence.values(),
            *capability_policy_evidence.values(),
            *manual,
        ],
        key=lambda row: row["evidence_id"],
    )
    evidence_index = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence": evidence_rows,
    }
    evidence_by_group: dict[str, tuple[dict[str, Any], ...]] = {}
    for group in security_groups:
        hc = group["handler_criterion_id"]
        st = group["sink_type_id"]
        applicable = []
        for row in evidence_rows:
            hcs = row["applicability"]["handler_criterion_ids"]
            sts = row["applicability"]["sink_type_ids"]
            # Empty axes are wildcards. When both axes are named, both must match;
            # otherwise evidence for one capability under an HC could leak to another ST.
            if (not hcs or hc in hcs) and (not sts or st in sts):
                applicable.append(row)
        evidence_by_group[group["handler_sink_group_id"]] = tuple(applicable)
    return OracleInputs(
        handler_criteria=handler_criteria,
        sink_types=sink_types,
        security_groups=security_groups,
        excluded_groups=excluded_groups,
        chains=chains,
        evidence_index=evidence_index,
        evidence_by_group=evidence_by_group,
        digests={
            "handler_alignment": handler_digests,
            "sink_alignment": sink_digests,
            "evidence_registry": sha256_file(evidence_registry),
            "projects": project_digests,
        },
    )
