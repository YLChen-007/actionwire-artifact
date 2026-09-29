"""Fail-closed normativity checks for Group Oracle candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import CoverageComparisonError


NORMATIVITY_FILTER_VERSION = "coverage-upstream-normativity-filter/v14"
NORMATIVITY_REPAIR_REGISTRY_VERSION = "coverage-normativity-repair-registry/v1"
NORMATIVE_EVIDENCE_KINDS = {"capability-policy", "fixed-delta"}
VALIDATION_BASES_BY_EVIDENCE_KIND = {
    "capability-policy": {"explicit-source-policy"},
    "fixed-delta": {"fixed-delta"},
    "explicit-source-policy": {"explicit-source-policy"},
    "inherent-security-boundary": {"inherent-security-boundary"},
    "learned-security-invariant": {"learned-security-invariant"},
}
ACTIVE_DISPOSITIONS = {"confirmed", "needs-source-validation"}


@dataclass(frozen=True)
class NormativityFilterRun:
    classifications: tuple[dict[str, Any], ...]
    dispositions: tuple[dict[str, Any], ...]


def _index_unique(
    rows: Sequence[Mapping[str, Any]], key_name: str, label: str
) -> dict[str, Mapping[str, Any]]:
    output: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        key = str(row[key_name])
        if key in output:
            raise CoverageComparisonError(f"duplicate {label}: {key}")
        output[key] = row
    return output


def _evidence_rows(evidence_index: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = evidence_index.get("evidence")
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise CoverageComparisonError("invalid Group Oracle evidence index")
    return rows


def _baseline_requirements(
    group_oracles: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str], Mapping[str, Any]]:
    output: dict[tuple[str, str], Mapping[str, Any]] = {}
    for oracle in group_oracles:
        group_id = str(oracle["group_id"])
        for requirement in oracle.get("requirements", []):
            key = (group_id, str(requirement["requirement_id"]))
            if key in output:
                raise CoverageComparisonError(
                    f"duplicate baseline Group Oracle requirement: {key}"
                )
            output[key] = requirement
    return output


def _repair_entries(
    registry: Mapping[str, Any],
) -> dict[tuple[str, str, str, str], Mapping[str, Any]]:
    if registry.get("schema_version") != NORMATIVITY_REPAIR_REGISTRY_VERSION:
        raise CoverageComparisonError("invalid normativity repair registry version")
    rows = registry.get("entries")
    if not isinstance(rows, list):
        raise CoverageComparisonError("normativity repair registry entries must be a list")
    output: dict[tuple[str, str, str, str], Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise CoverageComparisonError("invalid normativity repair entry")
        key = tuple(
            str(row[field])
            for field in ("group_id", "legacy_requirement_id", "project", "chain_id")
        )
        evidence_kind = str(row.get("evidence_kind", ""))
        allowed = row.get("allowed_validation_policy_bases")
        evidence_ids = row.get("evidence_ids")
        if evidence_kind not in VALIDATION_BASES_BY_EVIDENCE_KIND:
            raise CoverageComparisonError(f"invalid repair evidence kind: {evidence_kind}")
        if not isinstance(allowed, list) or not allowed:
            raise CoverageComparisonError("repair entry needs validation policy bases")
        if not set(map(str, allowed)) <= VALIDATION_BASES_BY_EVIDENCE_KIND[evidence_kind]:
            raise CoverageComparisonError("repair policy basis contradicts evidence kind")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            raise CoverageComparisonError("repair entry needs exact evidence ids")
        if not str(row.get("reason", "")).strip():
            raise CoverageComparisonError("repair entry needs an audit reason")
        if key in output:
            raise CoverageComparisonError(f"duplicate normativity repair entry: {key}")
        output[key] = row
    return output


def _legacy_group_ids(requirement: Mapping[str, Any]) -> tuple[str, ...]:
    sources = requirement.get("provenance", {}).get("sources", [])
    if not sources or any(source.get("kind") != "group-oracle" for source in sources):
        return ()
    return tuple(sorted({str(source["legacy_requirement_id"]) for source in sources}))


def _classification(
    *,
    candidate: Mapping[str, Any],
    requirement: Mapping[str, Any],
    baseline: Mapping[tuple[str, str], Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    repairs: Mapping[tuple[str, str, str, str], Mapping[str, Any]],
) -> dict[str, Any]:
    group_id = str(candidate["group_id"])
    source_kinds = {
        str(row.get("kind"))
        for row in requirement.get("provenance", {}).get("sources", [])
    }
    legacy_ids = _legacy_group_ids(requirement)
    kinds: set[str] = set()
    evidence_ids: set[str] = set()
    allowed_bases: set[str] = set()
    repair_keys: list[str] = []
    repair_effective_basis: str | None = None
    missing_baseline = False
    for legacy_id in legacy_ids:
        baseline_row = baseline.get((group_id, legacy_id))
        if baseline_row is None:
            missing_baseline = True
        else:
            for evidence_id in map(str, baseline_row.get("evidence_ids", [])):
                evidence_row = evidence.get(evidence_id)
                if evidence_row is None:
                    raise CoverageComparisonError(f"unknown Group Oracle evidence: {evidence_id}")
                evidence_ids.add(evidence_id)
                kind = str(evidence_row["kind"])
                kinds.add(kind)
                allowed_bases.update(VALIDATION_BASES_BY_EVIDENCE_KIND.get(kind, ()))
        repair_key = (
            group_id,
            legacy_id,
            str(candidate["project"]),
            str(candidate["chain_id"]),
        )
        repair = repairs.get(repair_key)
        if repair is not None:
            repair_keys.append("|".join(repair_key))
            kinds.add(str(repair["evidence_kind"]))
            evidence_ids.update(map(str, repair["evidence_ids"]))
            allowed_bases.update(map(str, repair["allowed_validation_policy_bases"]))
            repair_effective_basis = next(
                iter(map(str, repair["allowed_validation_policy_bases"]))
            )
    effective_policy_basis = None
    if repair_keys:
        effective_policy_basis = repair_effective_basis
    elif "fixed-delta" in kinds:
        effective_policy_basis = "fixed-delta"
    elif "capability-policy" in kinds:
        effective_policy_basis = "explicit-source-policy"
    if not legacy_ids and source_kinds == {"capability-card"}:
        kinds.add("capability-card")
        status, reason = (
            "non-normative",
            "ordinary capability-card facts cannot establish a security requirement",
        )
    elif not legacy_ids:
        status, reason = "not-group-oracle", "requirement has non-Group provenance"
    elif repair_keys or kinds & NORMATIVE_EVIDENCE_KINDS:
        status, reason = "normative", "exact normative evidence supports this binding"
    elif kinds == {"capability-card"}:
        status, reason = (
            "non-normative",
            "ordinary capability-card facts cannot establish a security requirement",
        )
    else:
        status, reason = "unresolved", "no exact normative Group Oracle evidence"
        if missing_baseline:
            reason += "; baseline requirement binding is missing"
    return {
        "schema_version": NORMATIVITY_FILTER_VERSION,
        "candidate_id": candidate["candidate_id"],
        "project": candidate["project"],
        "chain_id": candidate["chain_id"],
        "group_id": group_id,
        "requirement_id": candidate["requirement_id"],
        "legacy_requirement_ids": list(legacy_ids),
        "evidence_ids": sorted(evidence_ids),
        "evidence_kinds": sorted(kinds),
        "repair_keys": sorted(repair_keys),
        "allowed_validation_policy_bases": sorted(allowed_bases),
        "effective_policy_basis": effective_policy_basis,
        "status": status,
        "reason": reason,
    }


def apply_normativity_filter(
    *,
    candidates: Sequence[Mapping[str, Any]],
    requirements: Sequence[Mapping[str, Any]],
    validations: Sequence[Mapping[str, Any]],
    prior_dispositions: Sequence[Mapping[str, Any]],
    group_oracles: Sequence[Mapping[str, Any]],
    evidence_index: Mapping[str, Any],
    repair_registry: Mapping[str, Any],
) -> NormativityFilterRun:
    """Classify Group requirements and preserve every supplied audit row."""

    candidate_by_id = _index_unique(candidates, "candidate_id", "candidate")
    requirement_by_id = _index_unique(requirements, "requirement_id", "requirement")
    validation_by_id = _index_unique(
        validations, "provisional_candidate_id", "source validation"
    )
    evidence = _index_unique(_evidence_rows(evidence_index), "evidence_id", "evidence")
    baseline = _baseline_requirements(group_oracles)
    repairs = _repair_entries(repair_registry)
    classifications = [
        _classification(
            candidate=candidate,
            requirement=requirement_by_id[str(candidate["requirement_id"])],
            baseline=baseline,
            evidence=evidence,
            repairs=repairs,
        )
        for candidate in sorted(candidates, key=lambda row: str(row["candidate_id"]))
    ]
    classification_by_id = {str(row["candidate_id"]): row for row in classifications}
    output: list[dict[str, Any]] = []
    for raw in prior_dispositions:
        row = dict(raw)
        candidate_id = str(row["candidate_id"])
        if candidate_id not in candidate_by_id:
            raise CoverageComparisonError("audit disposition references unknown candidate")
        classification = classification_by_id[candidate_id]
        validation = validation_by_id.get(candidate_id)
        basis = str(validation.get("policy_basis", "")) if validation else ""
        transition: tuple[str, str] | None = None
        if classification["status"] == "non-normative":
            transition = ("non-normative-capability-only", classification["reason"])
        elif classification["status"] == "unresolved":
            transition = ("normativity-unresolved", classification["reason"])
        elif (
            classification["status"] == "normative"
            and validation is not None
            and basis not in classification["allowed_validation_policy_bases"]
        ):
            row.update(
                {
                    "schema_version": NORMATIVITY_FILTER_VERSION,
                    "validation_policy_basis_original": basis or None,
                    "effective_policy_basis": classification[
                        "effective_policy_basis"
                    ],
                    "policy_basis_repaired": True,
                    "normativity_reason": (
                        f"validation policy basis {basis or '<missing>'} was replaced by "
                        "the evidence-authoritative basis"
                    ),
                }
            )
        if transition is not None and row.get("disposition") in ACTIVE_DISPOSITIONS:
            row.update(
                {
                    "schema_version": NORMATIVITY_FILTER_VERSION,
                    "prior_disposition": row["disposition"],
                    "disposition": transition[0],
                    "reason": transition[1],
                }
            )
        output.append(row)
    return NormativityFilterRun(
        classifications=tuple(classifications), dispositions=tuple(output)
    )
