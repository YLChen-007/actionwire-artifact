"""Strict contracts and stable identities for group-oracle construction."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import validate as validate_schema

from .evidence_authority import (
    EVIDENCE_KINDS,
    has_normative_support,
)


ORACLE_SCHEMA_VERSION = "group-oracle/v1"
SEED_SCHEMA_VERSION = "group-oracle-seed-profile/v1"
PROPOSAL_SCHEMA_VERSION = "group-oracle-proposal/v1"
ASSESSMENT_SCHEMA_VERSION = "group-oracle-proposal-assessment/v1"
EXCLUSION_SCHEMA_VERSION = "group-oracle-exclusion/v1"
EVIDENCE_SCHEMA_VERSION = "oracle-evidence-index/v1"
REGISTRY_SCHEMA_VERSION = "oracle-evidence-registry/v1"
MANIFEST_SCHEMA_VERSION = "group-oracle-manifest/v1"
CHAT_SCHEMA_VERSION = "group-oracle-chat/v1"
SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"

SLUG_RE = re.compile(r"^[a-z][a-z0-9-]*$")
NON_SLUG = re.compile(r"[^a-z0-9]+")
HC_RE = re.compile(r"^HC-[0-9a-f]{16}$")
ST_RE = re.compile(r"^ST-[0-9a-f]{16}$")
HSG_RE = re.compile(r"^HSG-[0-9a-f]{16}$")
CHAIN_RE = re.compile(r"^C-[0-9a-f]{12}$")
GATE_RE = re.compile(r"^GU[0-9a-f]{20}$")
class GroupOracleError(ValueError):
    """Raised when an oracle input or response violates its contract."""


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GroupOracleError(f"{field} must be a non-empty string")
    return " ".join(value.split())


def normalize_slug(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GroupOracleError(f"{field} must be a non-empty semantic slug")
    normalized = NON_SLUG.sub("-", value.strip().lower()).strip("-")
    if normalized and normalized[0].isdigit():
        normalized = "value-" + normalized
    if not SLUG_RE.fullmatch(normalized):
        raise GroupOracleError(f"{field} cannot be normalized to a semantic slug")
    return normalized


def stable_policy_atom_id(group_id: str, fields: Mapping[str, Any]) -> str:
    return "PA-" + digest([group_id, fields])[:16]


def stable_proposal_id(
    group_id: str,
    origin_chain_refs: Sequence[Mapping[str, str]],
    origin_gate_ids: Sequence[str],
    dimension: str,
    rule: str,
    applicability: str,
) -> str:
    refs = sorted(
        {f"{row['project']}:{row['chain_id']}" for row in origin_chain_refs}
    )
    if not refs:
        raise GroupOracleError("proposal must have at least one originating chain")
    identity = [
        group_id,
        refs,
        sorted(set(origin_gate_ids)),
        normalize_slug(dimension, "dimension"),
        normalize_text(rule, "rule"),
        normalize_text(applicability, "applicability"),
    ]
    return "RP-" + digest(identity)[:16]


def stable_requirement_id(dimension: str, rule: str, applicability: str) -> str:
    identity = [
        normalize_slug(dimension, "dimension"),
        normalize_text(rule, "rule"),
        normalize_text(applicability, "applicability"),
    ]
    return "R-" + digest(identity)[:16]


def stable_evidence_id(
    kind: str, path: str, sha256: str, locator: str, exact_quote: str, claim: str
) -> str:
    if kind not in EVIDENCE_KINDS:
        raise GroupOracleError(f"unsupported evidence kind {kind!r}")
    return "EV-" + digest([kind, path, sha256, locator, exact_quote, claim])[:16]


def stable_summary_id(proposal_ids: Sequence[str]) -> str:
    members = sorted(set(proposal_ids))
    if not members or len(members) != len(proposal_ids):
        raise GroupOracleError("summary members must be non-empty and unique")
    return "RS-" + digest(members)[:16]


def parse_json_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1])
            if text.lstrip().startswith("json"):
                text = text.lstrip()[4:].lstrip("\r\n")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GroupOracleError(f"response is not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise GroupOracleError("response root must be an object")
    return value


def _string_list(value: object, field: str, allowed: set[str] | None = None) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise GroupOracleError(f"{field} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise GroupOracleError(f"{field} contains duplicate values")
    if allowed is not None and not set(value) <= allowed:
        raise GroupOracleError(f"{field} contains unknown identifiers")
    return sorted(value)


def _candidate(row: object, *, allowed_gate_ids: set[str]) -> dict[str, Any]:
    fields = {
        "dimension", "rule", "applicability", "origin_gate_ids", "reason"
    }
    if not isinstance(row, dict) or set(row) != fields:
        raise GroupOracleError("candidate requirement has unexpected fields")
    gate_ids = _string_list(row["origin_gate_ids"], "origin_gate_ids", allowed_gate_ids)
    if not gate_ids:
        raise GroupOracleError(
            "gate-derived candidate requirement requires at least one origin gate"
        )
    return {
        "dimension": normalize_slug(row["dimension"], "dimension"),
        "rule": normalize_text(row["rule"], "rule"),
        "applicability": normalize_text(row["applicability"], "applicability"),
        "origin_gate_ids": gate_ids,
        "reason": normalize_text(row["reason"], "reason"),
    }


def validate_seed_response(
    response: Mapping[str, Any], *, group_id: str, allowed_gate_ids: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if set(response) != {"group_id", "policy_atoms", "candidate_requirements"}:
        raise GroupOracleError("seed response has unexpected fields")
    if response["group_id"] != group_id:
        raise GroupOracleError("seed response group ID mismatch")
    atoms_raw = response["policy_atoms"]
    if not isinstance(atoms_raw, list):
        raise GroupOracleError("policy_atoms must be an array")
    atoms: list[dict[str, Any]] = []
    atom_fields = {
        "subject_role", "operation", "dimension", "effect", "timing", "scope",
        "failure_behavior", "source_gate_ids",
    }
    for row in atoms_raw:
        if not isinstance(row, dict) or set(row) != atom_fields:
            raise GroupOracleError("policy atom has unexpected fields")
        fields = {
            "subject_role": normalize_slug(row["subject_role"], "subject_role"),
            "operation": normalize_slug(row["operation"], "operation"),
            "dimension": normalize_slug(row["dimension"], "dimension"),
            "effect": normalize_slug(row["effect"], "effect"),
            "timing": normalize_slug(row["timing"], "timing"),
            "scope": normalize_slug(row["scope"], "scope"),
            "failure_behavior": normalize_slug(
                row["failure_behavior"], "failure_behavior"
            ),
            "source_gate_ids": _string_list(
                row["source_gate_ids"], "source_gate_ids", allowed_gate_ids
            ),
        }
        atoms.append(
            {
                "policy_atom_id": stable_policy_atom_id(group_id, fields),
                **fields,
            }
        )
    atom_ids = [row["policy_atom_id"] for row in atoms]
    if len(atom_ids) != len(set(atom_ids)):
        raise GroupOracleError("seed response contains duplicate policy atoms")
    candidates_raw = response["candidate_requirements"]
    if not isinstance(candidates_raw, list):
        raise GroupOracleError("candidate_requirements must be an array")
    candidates = [
        _candidate(row, allowed_gate_ids=allowed_gate_ids) for row in candidates_raw
    ]
    return sorted(atoms, key=lambda row: row["policy_atom_id"]), candidates


def validate_peer_response(
    response: Mapping[str, Any],
    *,
    expected_chain_refs: set[str],
    gate_ids_by_ref: Mapping[str, set[str]],
) -> list[dict[str, Any]]:
    if set(response) != {"chains"} or not isinstance(response["chains"], list):
        raise GroupOracleError("peer response must contain chains")
    output: list[dict[str, Any]] = []
    seen: list[str] = []
    for row in response["chains"]:
        if not isinstance(row, dict) or set(row) != {
            "chain_ref", "candidate_requirements"
        }:
            raise GroupOracleError("peer chain row has unexpected fields")
        chain_ref = row["chain_ref"]
        if chain_ref not in expected_chain_refs:
            raise GroupOracleError(f"unknown peer chain reference {chain_ref!r}")
        proposals = row["candidate_requirements"]
        if not isinstance(proposals, list):
            raise GroupOracleError("peer candidate_requirements must be an array")
        output.append(
            {
                "chain_ref": chain_ref,
                "candidate_requirements": [
                    _candidate(item, allowed_gate_ids=gate_ids_by_ref[chain_ref])
                    for item in proposals
                ],
            }
        )
        seen.append(chain_ref)
    if len(seen) != len(set(seen)) or set(seen) != expected_chain_refs:
        raise GroupOracleError("peer response must cover every chain exactly once")
    return sorted(output, key=lambda row: row["chain_ref"])


def validate_evidence_extension_response(
    response: Mapping[str, Any],
    *,
    group_id: str,
    allowed_evidence_ids: set[str],
    normative_evidence_ids: set[str],
) -> list[dict[str, Any]]:
    if set(response) != {"group_id", "candidate_requirements"}:
        raise GroupOracleError("evidence-extension response has unexpected fields")
    if response["group_id"] != group_id:
        raise GroupOracleError("evidence-extension response group ID mismatch")
    raw = response["candidate_requirements"]
    if not isinstance(raw, list):
        raise GroupOracleError("evidence-extension candidates must be an array")
    output: list[dict[str, Any]] = []
    identities: set[str] = set()
    fields = {"dimension", "rule", "applicability", "evidence_ids", "reason"}
    for row in raw:
        if not isinstance(row, dict) or set(row) != fields:
            raise GroupOracleError("evidence-extension candidate has unexpected fields")
        evidence_ids = _string_list(
            row["evidence_ids"], "evidence_ids", allowed_evidence_ids
        )
        if not evidence_ids:
            raise GroupOracleError("evidence-extension candidate requires evidence")
        if not set(evidence_ids) & normative_evidence_ids:
            raise GroupOracleError(
                "evidence-extension candidate requires normative evidence; "
                "capability-card evidence alone is insufficient"
            )
        candidate = {
            "dimension": normalize_slug(row["dimension"], "dimension"),
            "rule": normalize_text(row["rule"], "rule"),
            "applicability": normalize_text(row["applicability"], "applicability"),
            "origin_gate_ids": [],
            "origin_evidence_ids": evidence_ids,
            "reason": normalize_text(row["reason"], "reason"),
        }
        identity = canonical_json(
            [candidate["dimension"], candidate["rule"], candidate["applicability"]]
        )
        if identity in identities:
            raise GroupOracleError("duplicate evidence-extension candidate")
        identities.add(identity)
        output.append(candidate)
    return sorted(
        output,
        key=lambda row: (row["dimension"], row["rule"], row["applicability"]),
    )


def validate_assessment_response(
    response: Mapping[str, Any],
    *,
    expected_proposal_ids: set[str],
    allowed_candidate_ids: set[str],
    allowed_evidence_ids: set[str],
    normative_evidence_ids: set[str],
) -> list[dict[str, Any]]:
    if set(response) != {"assessments"} or not isinstance(
        response["assessments"], list
    ):
        raise GroupOracleError("assessment response must contain assessments")
    output: list[dict[str, Any]] = []
    seen: list[str] = []
    for row in response["assessments"]:
        fields = {
            "proposal_id", "decision", "selected_proposal_id", "evidence_ids", "reason"
        }
        if not isinstance(row, dict) or set(row) != fields:
            actual = set(row) if isinstance(row, dict) else set()
            raise GroupOracleError(
                "assessment row fields mismatch; "
                f"missing={sorted(fields - actual)}, extra={sorted(actual - fields)}"
            )
        proposal_id = row["proposal_id"]
        if proposal_id not in expected_proposal_ids:
            raise GroupOracleError(f"unknown assessed proposal {proposal_id!r}")
        decision = row["decision"]
        selected = row["selected_proposal_id"]
        evidence_ids = _string_list(
            row["evidence_ids"], "evidence_ids", allowed_evidence_ids
        )
        if decision == "add":
            if selected is not None or not evidence_ids:
                raise GroupOracleError("add requires evidence and no selected proposal")
            if not set(evidence_ids) & normative_evidence_ids:
                raise GroupOracleError(
                    "add requires normative evidence; capability-card evidence alone "
                    "is insufficient"
                )
        elif decision == "already-covered":
            if selected not in allowed_candidate_ids or selected == proposal_id:
                raise GroupOracleError("already-covered requires another allowed proposal")
        elif decision == "reject":
            if selected is not None:
                raise GroupOracleError("reject cannot select another proposal")
        else:
            raise GroupOracleError(f"invalid proposal decision {decision!r}")
        output.append(
            {
                "proposal_id": proposal_id,
                "decision": decision,
                "selected_proposal_id": selected,
                "evidence_ids": evidence_ids,
                "reason": normalize_text(row["reason"], "reason"),
            }
        )
        seen.append(proposal_id)
    if len(seen) != len(set(seen)) or set(seen) != expected_proposal_ids:
        raise GroupOracleError("assessments must cover every proposal exactly once")
    return sorted(output, key=lambda row: row["proposal_id"])


def validate_summary_response(
    response: Mapping[str, Any], *, expected_proposal_ids: set[str]
) -> list[dict[str, Any]]:
    if set(response) != {"summaries"} or not isinstance(response["summaries"], list):
        raise GroupOracleError("summary response must contain summaries")
    output: list[dict[str, Any]] = []
    covered: list[str] = []
    for row in response["summaries"]:
        if not isinstance(row, dict) or set(row) != {
            "proposal_ids", "dimension", "rule", "applicability", "reason"
        }:
            raise GroupOracleError("summary row has unexpected fields")
        proposal_ids = _string_list(
            row["proposal_ids"], "proposal_ids", expected_proposal_ids
        )
        if not proposal_ids:
            raise GroupOracleError("summary cannot be empty")
        output.append(
            {
                "summary_id": stable_summary_id(proposal_ids),
                "proposal_ids": proposal_ids,
                "dimension": normalize_slug(row["dimension"], "dimension"),
                "rule": normalize_text(row["rule"], "rule"),
                "applicability": normalize_text(
                    row["applicability"], "applicability"
                ),
                "reason": normalize_text(row["reason"], "reason"),
            }
        )
        covered.extend(proposal_ids)
    if len(covered) != len(set(covered)) or set(covered) != expected_proposal_ids:
        raise GroupOracleError("summaries must partition every proposal exactly once")
    return sorted(output, key=lambda row: row["summary_id"])


def validate_component_response(
    response: Mapping[str, Any],
    *,
    expected_proposal_ids: set[str],
    allowed_evidence_ids: set[str],
    normative_evidence_ids: set[str],
) -> list[dict[str, Any]]:
    if set(response) != {"clusters"} or not isinstance(response["clusters"], list):
        raise GroupOracleError("component response must contain clusters")
    output: list[dict[str, Any]] = []
    covered: list[str] = []
    for row in response["clusters"]:
        fields = {
            "proposal_ids", "decision", "dimension", "rule", "applicability",
            "evidence_ids", "reason",
        }
        if not isinstance(row, dict) or set(row) != fields:
            raise GroupOracleError("component cluster has unexpected fields")
        proposal_ids = _string_list(
            row["proposal_ids"], "proposal_ids", expected_proposal_ids
        )
        if not proposal_ids:
            raise GroupOracleError("component cluster cannot be empty")
        decision = row["decision"]
        evidence_ids = _string_list(
            row["evidence_ids"], "evidence_ids", allowed_evidence_ids
        )
        if decision == "add" and not evidence_ids:
            raise GroupOracleError("an added component requires pinned evidence")
        if decision == "add" and not set(evidence_ids) & normative_evidence_ids:
            raise GroupOracleError(
                "an added component requires normative evidence; capability-card "
                "evidence alone is insufficient"
            )
        if decision not in {"add", "reject"}:
            raise GroupOracleError("component decision must be add or reject")
        output.append(
            {
                "proposal_ids": proposal_ids,
                "decision": decision,
                "dimension": normalize_slug(row["dimension"], "dimension"),
                "rule": normalize_text(row["rule"], "rule"),
                "applicability": normalize_text(
                    row["applicability"], "applicability"
                ),
                "evidence_ids": evidence_ids,
                "reason": normalize_text(row["reason"], "reason"),
            }
        )
        covered.extend(proposal_ids)
    if len(covered) != len(set(covered)) or set(covered) != expected_proposal_ids:
        raise GroupOracleError("component clusters must partition every proposal")
    return sorted(output, key=lambda row: row["proposal_ids"])


def validate_artifacts(
    *,
    oracles: Sequence[dict[str, Any]],
    seeds: Sequence[dict[str, Any]],
    proposals: Sequence[dict[str, Any]],
    assessments: Sequence[dict[str, Any]],
    exclusions: Sequence[dict[str, Any]],
    evidence_index: dict[str, Any],
    expected_security_groups: Mapping[str, set[tuple[str, str]]],
    expected_excluded_groups: Mapping[str, set[tuple[str, str]]],
) -> None:
    schemas = {
        "oracle": "group-oracle-v1.schema.json",
        "seed": "group-oracle-seed-profile-v1.schema.json",
        "proposal": "group-oracle-proposal-v1.schema.json",
        "assessment": "group-oracle-proposal-assessment-v1.schema.json",
        "exclusion": "group-oracle-exclusion-v1.schema.json",
        "evidence": "oracle-evidence-index-v1.schema.json",
    }
    loaded = {
        key: json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
        for key, name in schemas.items()
    }
    for row in oracles:
        validate_schema(instance=row, schema=loaded["oracle"])
    for row in seeds:
        validate_schema(instance=row, schema=loaded["seed"])
    for row in proposals:
        validate_schema(instance=row, schema=loaded["proposal"])
    for row in assessments:
        validate_schema(instance=row, schema=loaded["assessment"])
    for row in exclusions:
        validate_schema(instance=row, schema=loaded["exclusion"])
    validate_schema(instance=evidence_index, schema=loaded["evidence"])
    oracle_ids = [row["group_id"] for row in oracles]
    excluded_ids = [row["group_id"] for row in exclusions]
    if len(oracle_ids) != len(set(oracle_ids)) or set(oracle_ids) != set(expected_security_groups):
        raise GroupOracleError("oracles do not exactly cover eligible security groups")
    if len(excluded_ids) != len(set(excluded_ids)) or set(excluded_ids) != set(expected_excluded_groups):
        raise GroupOracleError("excluded groups do not exactly cover no-impact groups")
    if set(oracle_ids) & set(excluded_ids):
        raise GroupOracleError("a group is both processed and excluded")
    seed_ids = [row["group_id"] for row in seeds]
    if len(seed_ids) != len(set(seed_ids)) or set(seed_ids) != set(oracle_ids):
        raise GroupOracleError("seed profiles do not exactly cover oracle groups")
    for row in oracles:
        actual = {(ref["project"], ref["chain_id"]) for ref in row["member_chain_refs"]}
        if actual != expected_security_groups[row["group_id"]]:
            raise GroupOracleError(f"{row['group_id']}: oracle member coverage mismatch")
        requirement_ids = [item["requirement_id"] for item in row["requirements"]]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise GroupOracleError(f"{row['group_id']}: duplicate requirements")
        for item in row["requirements"]:
            if stable_requirement_id(
                item["dimension"], item["rule"], item["applicability"]
            ) != item["requirement_id"]:
                raise GroupOracleError(
                    f"{row['group_id']}:{item['requirement_id']}: requirement hash mismatch"
                )
    evidence_by_id = {
        row["evidence_id"]: row for row in evidence_index["evidence"]
    }
    evidence_set = set(evidence_by_id)
    for row in oracles:
        for item in row["requirements"]:
            if not set(item["evidence_ids"]) <= evidence_set:
                raise GroupOracleError(
                    f"{row['group_id']}:{item['requirement_id']}: unknown evidence"
                )
            if not has_normative_support(item["evidence_ids"], evidence_by_id):
                raise GroupOracleError(
                    f"{row['group_id']}:{item['requirement_id']}: requirement lacks "
                    "normative evidence authority"
                )
    requirements_by_group = {
        row["group_id"]: {
            item["requirement_id"]: set(item["source_proposal_ids"])
            for item in row["requirements"]
        }
        for row in oracles
    }
    proposal_ids = [row["proposal_id"] for row in proposals]
    assessment_ids = [row["proposal_id"] for row in assessments]
    if len(proposal_ids) != len(set(proposal_ids)):
        raise GroupOracleError("duplicate proposal IDs")
    if len(assessment_ids) != len(set(assessment_ids)) or set(assessment_ids) != set(proposal_ids):
        raise GroupOracleError("proposal assessments do not exactly cover proposals")
    assessments_by_id = {row["proposal_id"]: row for row in assessments}
    added_by_requirement: dict[tuple[str, str], list[str]] = {}
    for proposal in proposals:
        assessment = assessments_by_id[proposal["proposal_id"]]
        if assessment["group_id"] != proposal["group_id"]:
            raise GroupOracleError("proposal assessment group mismatch")
        requirement_id = assessment["final_requirement_id"]
        if assessment["decision"] == "reject":
            if requirement_id is not None or assessment["selected_proposal_id"] is not None:
                raise GroupOracleError("rejected assessment references a final requirement")
            continue
        group_requirements = requirements_by_group[proposal["group_id"]]
        if requirement_id not in group_requirements:
            raise GroupOracleError("accepted assessment references an unknown requirement")
        sources = group_requirements[requirement_id]
        if proposal["proposal_id"] not in sources:
            raise GroupOracleError("requirement provenance omits its assessed proposal")
        selected = assessment["selected_proposal_id"]
        if assessment["decision"] == "add" and selected is not None:
            raise GroupOracleError("added assessment cannot select another proposal")
        if assessment["decision"] == "add":
            added_by_requirement.setdefault(
                (proposal["group_id"], requirement_id), []
            ).append(proposal["proposal_id"])
        if assessment["decision"] == "already-covered" and (
            selected is None or selected not in sources
        ):
            raise GroupOracleError(
                "already-covered assessment must select the same final component"
            )
    for group_id, requirements in requirements_by_group.items():
        for requirement_id, sources in requirements.items():
            if added_by_requirement.get((group_id, requirement_id)) != [min(sources)]:
                raise GroupOracleError(
                    "final requirement must have one lexicographic add representative"
                )
    evidence_ids = [row["evidence_id"] for row in evidence_index["evidence"]]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise GroupOracleError("duplicate evidence IDs")
