"""Detector-v15 normative admission and executable contract projection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .applicability_contract import APPLICABILITY_CONTRACT_VERSION
from .contracts import CoverageComparisonError, digest
from .normative_evidence import resolve_normative_evidence
from .normative_evidence_inputs import NORMATIVE_KINDS
from .v15_capability_dimensions import capability_dimensions, primary_sink_role


MODEL_AUTHORITIES = (
    "model-arbitrary",
    "model-component",
    "model-basename",
    "model-enum",
)
ROLE_ALIASES = {
    "destination-url": ("url", "uri", "destination", "host", "network"),
    "command": ("command", "argv", "shell", "executable", "process"),
    "code": ("code", "script", "expression", "eval"),
    "expression": ("expression", "code", "eval", "javascript"),
    "path": ("path", "file", "directory", "workspace"),
    "source-path": ("source", "path", "file", "copy"),
    "destination-path": ("destination", "target", "path", "file", "copy"),
    "content": ("content", "body", "text", "payload", "message"),
    "request-body": ("body", "json", "data", "payload", "request"),
    "message-content": ("message", "content", "text", "mention"),
    "environment": ("environment", "env", "variable"),
    "working-directory": ("working directory", "cwd", "directory"),
    "recipient": ("recipient", "channel", "destination", "target"),
    "primary-input": ("input", "argument", "value"),
}
POLICY_BASIS_TO_EVIDENCE = {
    "explicit-source-policy": "explicit-source-policy",
    "inherent-security-boundary": "explicit-source-policy",
    "fixed-delta": "fixed-delta",
}


@dataclass(frozen=True)
class NormativeProjection:
    admitted_requirements: tuple[dict[str, Any], ...]
    capability_hypotheses: tuple[dict[str, Any], ...]
    resolutions: tuple[dict[str, Any], ...]
    contracts: tuple[dict[str, Any], ...]


def _role_score(role: Mapping[str, Any], text: str) -> tuple[int, str]:
    role_id = str(role["role_id"])
    aliases = ROLE_ALIASES.get(role_id, tuple(role_id.split("-")))
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text).lower()
    haystack = {
        token[:-1] if token.endswith("s") and len(token) > 3 else token
        for token in re.findall(r"[a-z0-9]+", expanded)
    }

    def contains(value: str) -> bool:
        parts = {
            token[:-1] if token.endswith("s") and len(token) > 3 else token
            for token in re.findall(r"[a-z0-9]+", value.lower())
        }
        return bool(parts) and parts <= haystack

    score = sum(3 if " " in alias else 2 for alias in aliases if contains(alias))
    score += 4 if contains(role_id) else 0
    for binding in role.get("matched_bindings", []):
        token = str(binding).lower()
        score += 3 if token and contains(token) else 0
    return score, role_id


def _explicit_controlled_roles(
    available_roles: set[str], controlled_facet: str
) -> tuple[str, ...]:
    """Map exact model-field/call-shape identifiers before prose scoring."""

    normalized = re.sub(
        r"\b(args|params|action|options)\[['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\]",
        r"\1.\2",
        controlled_facet,
    )

    patterns = (
        (
            "environment",
            r"(?:\b(?:args|params|action|options)\.env\b|\benv\s*=|\b(?:env|environment)[ -]?(?:parameter|argument|override|field)\b)",
        ),
        (
            "working-directory",
            r"(?:\b(?:args|params|action|options)\.(?:cwd|working_dir|workdir)\b|\b(?:cwd|working[ _-]?dir)[ -]?(?:parameter|argument|field)\b)",
        ),
        (
            "destination-url",
            r"(?:\b(?:args|params|action|options)\.(?:url|targetUrl|mediaUrl|image_url|destinationUrl)\b|\b(?:url|uri|destination)[ -]?(?:parameter|argument|field)\b)",
        ),
        (
            "path",
            r"(?:\b(?:args|params|action|options)\.path\b|\b(?:file_path|source_path|destination_path)\b|\bpath[ -]?(?:parameter|argument|field)\b)",
        ),
        (
            "code",
            r"(?:\b(?:args|params|action|options)\.(?:code|expression|script)\b|\b(?:code|expression|script)[ -]?(?:parameter|argument|field)\b)",
        ),
        (
            "command",
            r"(?:\b(?:args|params|action|options)\.command\b|\bcommand[ -]?(?:parameter|argument|field)\b)",
        ),
        (
            "content",
            r"(?:\b(?:args|params|action|options)\.(?:message|formatted_body|content|text)\b|\b(?:message|content|text)[ -]?(?:parameter|argument|field)\b)",
        ),
        (
            "request-body",
            r"\b(?:args|params)\.(?:json|data|body|payload|request)\b",
        ),
        ("payload", r"\b(?:rpc-payload|args\.payload|params\.payload)\b"),
    )
    return tuple(
        role
        for role, pattern in patterns
        if role in available_roles and re.search(pattern, normalized, re.IGNORECASE)
    )


def infer_applicability_contract(
    *,
    requirement: Mapping[str, Any],
    member_comparisons: Sequence[Mapping[str, Any]],
    effective_views: Mapping[tuple[str, str], Mapping[str, Any]],
    card_payloads: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Infer one project-neutral executable predicate from requirement and sink facts."""

    text = " ".join(
        str(requirement.get(field, ""))
        for field in (
            "rule",
            "applicability",
            "controlled_facet",
            "security_effect",
        )
    )
    role_rows: dict[str, dict[str, Any]] = {}
    capability_classes: set[str] = set()
    for comparison in member_comparisons:
        key = (str(comparison["project"]), str(comparison["chain_id"]))
        view = effective_views.get(key, {})
        for role in view.get("roles", []):
            if role.get("matched_bindings"):
                role_rows.setdefault(str(role["role_id"]), dict(role))
        card_path = str(comparison["capability_card"]["path"])
        card = card_payloads.get(card_path)
        if card is not None:
            capability_classes.add(str(card["capability_class"]))
            for role in card.get("roles", []):
                role_rows.setdefault(str(role["role_id"]), dict(role))
    if not role_rows:
        raise CoverageComparisonError(
            f"{requirement['requirement_id']}: no sink role can define applicability"
        )
    dimensions = {capability_dimensions(value) for value in capability_classes}
    if len(dimensions) > 1:
        raise CoverageComparisonError(
            f"{requirement['requirement_id']}: member capability dimensions disagree"
        )
    capability_class = next(iter(capability_classes or {"unknown-capability"}))
    controlled_text = str(requirement.get("controlled_facet", ""))
    explicit_roles = _explicit_controlled_roles(set(role_rows), controlled_text)
    normative_text = " ".join(
        str(requirement.get(field, ""))
        for field in ("rule", "applicability", "security_effect")
    )
    normative_roles = _explicit_controlled_roles(set(role_rows), normative_text)
    if (
        explicit_roles
        and normative_roles
        and not set(explicit_roles) & set(normative_roles)
    ):
        raise CoverageComparisonError(
            f"{requirement['requirement_id']}: controlled facet conflicts with normative role"
        )

    def ranked_role(role: Mapping[str, Any]) -> tuple[int, str]:
        role_id = str(role["role_id"])
        score = _role_score(role, text)[0] + 5 * _role_score(role, controlled_text)[0]
        if role_id == "environment" and not re.search(
            r"(?:\b(?:args|params|action|options)\.env\b|\benv\s*=|\b(?:env|environment)[ -]?(?:parameter|argument|override|field)\b)",
            text,
            re.IGNORECASE,
        ):
            score = 0
        return score, role_id

    ranked_roles = sorted(
        (ranked_role(role) for role in role_rows.values()),
        key=lambda row: (-row[0], row[1]),
    )
    tied_roles = [
        role_id for score, role_id in ranked_roles if score == ranked_roles[0][0]
    ]
    if explicit_roles:
        required_roles = list(explicit_roles)
    elif normative_roles:
        required_roles = list(normative_roles)
    elif len(tied_roles) == 1:
        required_roles = [tied_roles[0]]
    else:
        primary_role = primary_sink_role(sorted(capability_classes))
        if primary_role not in tied_roles:
            raise CoverageComparisonError(
                f"{requirement['requirement_id']}: ambiguous required sink role"
            )
        required_roles = [primary_role]
    boundary, effect, predicate = capability_dimensions(capability_class)
    required_facet = f"capability-family:{effect}"
    return {
        "schema_version": APPLICABILITY_CONTRACT_VERSION,
        "required_sink_roles": required_roles,
        "allowed_value_authorities": list(MODEL_AUTHORITIES),
        "required_capability_facets": [required_facet],
        "required_boundary": boundary,
        "required_effect": effect,
        "call_shape_predicates": [predicate],
    }


def _baseline_requirements(
    group_oracles: Sequence[Mapping[str, Any]],
) -> tuple[dict[tuple[str, str], Mapping[str, Any]], dict[str, str]]:
    requirements: dict[tuple[str, str], Mapping[str, Any]] = {}
    statuses: dict[str, str] = {}
    for oracle in group_oracles:
        group_id = str(oracle["group_id"])
        if group_id in statuses:
            raise CoverageComparisonError(f"duplicate Group Oracle: {group_id}")
        statuses[group_id] = str(oracle["status"])
        for requirement in oracle.get("requirements", []):
            key = (group_id, str(requirement["requirement_id"]))
            if key in requirements:
                raise CoverageComparisonError(f"duplicate baseline requirement: {key}")
            requirements[key] = requirement
    return requirements, statuses


def _source_evidence(requirement: Mapping[str, Any]) -> list[dict[str, Any]]:
    kind = POLICY_BASIS_TO_EVIDENCE.get(str(requirement.get("policy_basis")))
    if kind is None:
        return []
    output: list[dict[str, Any]] = []
    for row in requirement.get("evidence", []):
        if row.get("role") != "policy":
            continue
        payload = [
            kind,
            row.get("file"),
            row.get("sha256"),
            row.get("excerpt"),
            row.get("claim"),
        ]
        output.append(
            {
                "evidence_id": "NEV-" + digest(payload)[:16],
                "kind": kind,
                "source_path": row["file"],
                "sha256": row["sha256"],
                "exact_quote": row["excerpt"],
                "supported_claim": row["claim"],
            }
        )
    return output


def _learned_ids(
    requirement: Mapping[str, Any], learned_by_id: Mapping[str, Mapping[str, Any]]
) -> tuple[list[str], list[str]]:
    output: list[str] = []
    missing: list[str] = []
    for source in requirement["provenance"]["sources"]:
        if source.get("kind") != "learned-invariant":
            continue
        learned_id = str(source["legacy_requirement_id"])
        if learned_id not in learned_by_id:
            missing.append(learned_id)
        else:
            output.append(learned_id)
    return sorted(set(output)), sorted(set(missing))


def _projected_learned_catalog(
    learned_ids: Sequence[str],
    learned_by_id: Mapping[str, Mapping[str, Any]],
    contract: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    if not learned_ids:
        return None
    patterns = []
    for learned_id in learned_ids:
        pattern = dict(learned_by_id[learned_id])
        prior = pattern.get("applicability_contract")
        if prior is not None and prior != contract:
            raise CoverageComparisonError(
                f"{learned_id}: learned applicability contract mismatch"
            )
        pattern["applicability_contract"] = dict(contract)
        patterns.append(pattern)
    return {
        "schema_version": "learned-invariant-catalog/v15",
        "patterns": patterns,
    }


def build_normative_projection(
    *,
    requirements: Sequence[Mapping[str, Any]],
    comparisons: Sequence[Mapping[str, Any]],
    group_oracles: Sequence[Mapping[str, Any]],
    evidence_index: Mapping[str, Any],
    learned_catalog: Mapping[str, Any],
    effective_views: Sequence[Mapping[str, Any]],
    card_payloads: Mapping[str, Mapping[str, Any]],
) -> NormativeProjection:
    """Resolve every CR without consulting GT reports or report identities."""

    comparison_by_group: dict[str, list[Mapping[str, Any]]] = {}
    for comparison in comparisons:
        comparison_by_group.setdefault(str(comparison["group_id"]), []).append(
            comparison
        )
    view_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for row in effective_views:
        key = (str(row["project"]), str(row["chain_id"]))
        if key in view_by_key:
            raise CoverageComparisonError(f"duplicate effective view: {key}")
        view_by_key[key] = row
    baseline, group_status = _baseline_requirements(group_oracles)
    raw_evidence = [dict(row) for row in evidence_index.get("evidence", [])]
    for row in raw_evidence:
        if row.get("kind") == "capability-policy":
            card = card_payloads.get(str(row.get("source_path", "")), {})
            source_version = card.get("policy_contract", {}).get("schema_version")
            declared_version = row.get("policy_contract_schema_version")
            if (
                declared_version
                and source_version
                and declared_version != source_version
            ):
                raise CoverageComparisonError("capability-policy version mismatch")
            if source_version:
                row["policy_contract_schema_version"] = source_version
    learned_by_id: dict[str, Mapping[str, Any]] = {}
    for row in learned_catalog["patterns"]:
        learned_id = str(row["requirement_id"])
        if learned_id in learned_by_id:
            raise CoverageComparisonError(f"duplicate learned invariant: {learned_id}")
        learned_by_id[learned_id] = row
    all_evidence: dict[str, dict[str, Any]] = {}
    for row in raw_evidence:
        evidence_id = str(row["evidence_id"])
        if evidence_id in all_evidence:
            raise CoverageComparisonError(f"duplicate evidence identity: {evidence_id}")
        all_evidence[evidence_id] = row
    evidence_ids_by_requirement: dict[str, list[str]] = {}
    learned_ids_by_requirement: dict[str, list[str]] = {}
    upstream_by_requirement: dict[str, str] = {}
    contracts: list[dict[str, Any]] = []
    requirement_rows = sorted(requirements, key=lambda row: str(row["requirement_id"]))
    requirement_ids = [str(row["requirement_id"]) for row in requirement_rows]
    if len(requirement_ids) != len(set(requirement_ids)):
        raise CoverageComparisonError("duplicate canonical requirement identity")
    for requirement in requirement_rows:
        requirement_id = str(requirement["requirement_id"])
        cited: set[str] = set()
        source_rows = _source_evidence(requirement)
        learned_ids, missing_learned_ids = _learned_ids(requirement, learned_by_id)
        learned_ids_by_requirement[requirement_id] = learned_ids
        for row in source_rows:
            prior = all_evidence.setdefault(str(row["evidence_id"]), row)
            if prior != row:
                raise CoverageComparisonError("normative evidence identity collision")
            cited.add(str(row["evidence_id"]))
        for learned_id in missing_learned_ids:
            row = {
                "evidence_id": f"NEV-unresolved-{learned_id[4:]}",
                "kind": "learned-invariant",
                "catalog_resolution": "missing",
            }
            prior = all_evidence.setdefault(str(row["evidence_id"]), row)
            if prior != row:
                raise CoverageComparisonError("unresolved learned evidence collision")
            cited.add(str(row["evidence_id"]))
        source_kinds = {
            str(source["kind"]) for source in requirement["provenance"]["sources"]
        }
        for source in requirement["provenance"]["sources"]:
            if source.get("kind") != "group-oracle":
                continue
            legacy_id = str(source["legacy_requirement_id"])
            baseline_row = baseline.get((str(requirement["group_id"]), legacy_id))
            if baseline_row is not None:
                cited.update(map(str, baseline_row.get("evidence_ids", [])))
        potential_normative = bool(source_rows or learned_ids) or any(
            str(all_evidence[evidence_id]["kind"]) in NORMATIVE_KINDS
            for evidence_id in cited
        )
        try:
            contract = infer_applicability_contract(
                requirement=requirement,
                member_comparisons=comparison_by_group.get(
                    str(requirement["group_id"]), []
                ),
                effective_views=view_by_key,
                card_payloads=card_payloads,
            )
        except CoverageComparisonError:
            if potential_normative:
                raise
            contract = None
        if contract is not None:
            contracts.append(
                {
                    "schema_version": "coverage-requirement-applicability-binding/v15",
                    "group_id": requirement["group_id"],
                    "requirement_id": requirement_id,
                    "contract": contract,
                }
            )
        evidence_ids_by_requirement[requirement_id] = sorted(cited)
        if missing_learned_ids:
            upstream = "unknown"
        elif potential_normative or source_kinds & {
            "source-derived",
            "learned-invariant",
        }:
            upstream = "complete"
        else:
            upstream = group_status.get(str(requirement["group_id"]), "unknown")
        upstream_by_requirement[requirement_id] = upstream
    evidence_rows = list(all_evidence.values())
    resolutions: list[dict[str, Any]] = []
    admitted: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    contract_by_id = {row["requirement_id"]: row["contract"] for row in contracts}
    for requirement in requirement_rows:
        requirement_id = str(requirement["requirement_id"])
        resolution = resolve_normative_evidence(
            group_id=str(requirement["group_id"]),
            requirement_id=requirement_id,
            evidence_ids=evidence_ids_by_requirement[requirement_id],
            evidence_rows=evidence_rows,
            applicability_contract=contract_by_id.get(requirement_id),
            learned_requirement_ids=learned_ids_by_requirement[requirement_id],
            learned_catalog=_projected_learned_catalog(
                learned_ids_by_requirement[requirement_id],
                learned_by_id,
                contract_by_id.get(requirement_id),
            ),
            upstream_status=upstream_by_requirement[requirement_id],
        )
        resolutions.append(resolution)
        if resolution["status"] == "normative":
            admitted.append(dict(requirement))
        elif resolution["status"] == "non-normative":
            hypotheses.append(
                {
                    "schema_version": "coverage-capability-hypothesis/v15",
                    "hypothesis_id": "CAPH-" + digest(requirement)[:16],
                    "group_id": requirement["group_id"],
                    "requirement_id": requirement_id,
                    "rule": requirement["rule"],
                    "applicability": requirement["applicability"],
                    "reason": resolution["reason"],
                    "provenance": requirement["provenance"],
                }
            )
    return NormativeProjection(
        admitted_requirements=tuple(admitted),
        capability_hypotheses=tuple(hypotheses),
        resolutions=tuple(resolutions),
        contracts=tuple(contracts),
    )
