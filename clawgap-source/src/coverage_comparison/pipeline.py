"""Two-oracle requirement-level coverage-comparison pipeline."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from src.gate_semantics.contracts import estimate_tokens
from src.group_oracle.corrections import (
    load_correction_ledger,
    resolve_correction_requirement_ids,
)
from src.projects import ProjectSpec

from .capability_analysis import CapabilityAnalysisRun, analyze_capability_chains
from .contracts import (
    ASSESSMENT_SCHEMA_VERSION,
    CANDIDATE_SCHEMA_VERSION,
    CHAT_SCHEMA_VERSION,
    CHALLENGE_SCHEMA_VERSION,
    COMPARISON_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    CoverageComparisonError,
    canonical_json,
    parse_json_response,
    stable_candidate_id,
    validate_artifacts,
    validate_comparison_response,
)
from .inputs import CoverageChain, load_coverage_inputs
from .prompts import (
    COMPARE_SYSTEM,
    CHALLENGE_SYSTEM,
    REPAIR_SYSTEM,
    build_compare_user,
    build_challenge_user,
    build_repair_user,
    contains_credentials,
    redact_credentials,
)
from .render import (
    render_candidate_ranking,
    render_coverage_index,
    render_precision_audit,
)
from .source_validation import (
    SourceRunnerFactory,
    SourceValidationConfig,
    clear_source_validation_checkpoint,
    deterministic_precision_sample,
    run_source_validation,
    validate_source_validation_artifacts,
)
from .versions import (
    CAPABILITY_PROMPT_VERSION,
    COMPARISON_PROMPT_VERSION,
)


Runner = Callable[[str, str], str]
DEFAULT_INPUT_TOKEN_LIMIT = 96_000
CORRECTION_REQUIREMENT_BATCH_SIZE = 8


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: object) -> None:
    _write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, rows: Sequence[object]) -> None:
    _write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def _publish_directory(staging: Path, out_dir: Path) -> None:
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    backup = out_dir.parent / f".{out_dir.name}.previous"
    if backup.exists():
        raise CoverageComparisonError(f"stale publication backup exists: {backup}")
    had_previous = out_dir.exists()
    try:
        if had_previous:
            os.replace(out_dir, backup)
        os.replace(staging, out_dir)
    except Exception:
        if had_previous and backup.exists() and not out_dir.exists():
            os.replace(backup, out_dir)
        raise
    if backup.exists():
        shutil.rmtree(backup)


def _validated_call(
    *,
    runner: Runner,
    system: str,
    user: str,
    validator: Callable[[Mapping[str, Any]], Any],
    context: str,
) -> tuple[Any, list[dict[str, str]]]:
    exchanges: list[dict[str, str]] = []
    raw = redact_credentials(runner(system, user))
    exchanges.append({"system": system, "user": user, "response": raw})
    try:
        return validator(parse_json_response(raw)), exchanges
    except Exception as first:
        repair_user = build_repair_user(
            system, user, raw, f"{type(first).__name__}: {first}"
        )
        repaired = redact_credentials(runner(REPAIR_SYSTEM, repair_user))
        exchanges.append(
            {"system": REPAIR_SYSTEM, "user": repair_user, "response": repaired}
        )
        try:
            return validator(parse_json_response(repaired)), exchanges
        except Exception as second:
            invalidate = getattr(runner, "invalidate_prompts", None)
            if callable(invalidate):
                invalidate([(system, user), (REPAIR_SYSTEM, repair_user)])
            raise CoverageComparisonError(
                f"{context}: unrepaired comparison response: "
                f"{type(second).__name__}: {second}"
            ) from second


def _assessment_record(chain: CoverageChain, row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "group_id": chain.group_id,
        "handler_criterion_id": chain.handler_criterion_id,
        "sink_type_id": chain.sink_type_id,
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
        **dict(row),
    }


def _merge_challenge(
    chain: CoverageChain,
    primary: Mapping[str, Any],
    challenge: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        primary["applicability"] == challenge["applicability"]
        and primary["decision"] == challenge["decision"]
    ):
        disposition = "affirmed"
        final = dict(primary)
    elif challenge["decision"] in {"wrong-check", "missing-check"}:
        disposition = "revised-uncovered"
        final = dict(challenge)
    else:
        disposition = "conflict-unknown"
        final = {
            "requirement_id": primary["requirement_id"],
            "applicability": "unknown",
            "decision": "unknown",
            "capability_evidence": [],
            "call_shape_facts": [],
            "gate_ids": [],
            "covered_semantics": None,
            "gap": None,
            "uncertainty": (
                "Independent covered/not-applicable challenge disagreed without an "
                "evidence-valid uncovered verdict."
            ),
        }
    record = {
        "schema_version": CHALLENGE_SCHEMA_VERSION,
        "group_id": chain.group_id,
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
        "requirement_id": primary["requirement_id"],
        "primary_assessment": dict(primary),
        "challenge_assessment": dict(challenge),
        "disposition": disposition,
        "final_assessment": final,
    }
    return final, record


def _challenge_requirement_ids(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        row["requirement_id"]
        for row in rows
        if row["decision"] in {"covered", "not-applicable"}
    )


def _requirement_batches(requirement_ids: Sequence[str]) -> list[list[str]]:
    ordered = sorted(requirement_ids)
    if len(ordered) <= CORRECTION_REQUIREMENT_BATCH_SIZE:
        return [ordered]
    return [
        ordered[offset : offset + CORRECTION_REQUIREMENT_BATCH_SIZE]
        for offset in range(0, len(ordered), CORRECTION_REQUIREMENT_BATCH_SIZE)
    ]


def _normalize_correction_response(response: Mapping[str, Any]) -> Mapping[str, Any]:
    normalized = deepcopy(response)
    rows = normalized.get("requirements")
    if not isinstance(rows, list):
        return normalized
    for row in rows:
        if not isinstance(row, dict):
            continue
        row.setdefault("covered_semantics", None)
        row.setdefault("gap", None)
        row.setdefault("uncertainty", None)
        gates = row.get("gate_ids")
        if not isinstance(gates, list):
            continue
        has_applicability_evidence = bool(row.get("capability_line_refs")) and bool(
            row.get("call_shape_facts")
        )
        decision = row.get("decision")
        if decision in {"covered", "wrong-check", "missing-check"}:
            if not has_applicability_evidence:
                row["applicability"] = "unknown"
                row["decision"] = "unknown"
                row["gate_ids"] = []
                row["covered_semantics"] = None
                row["gap"] = None
                row["uncertainty"] = (
                    "The supplied evidence is insufficient to establish applicability."
                )
                continue
            row["applicability"] = "applicable"
            row["uncertainty"] = None
            if not gates:
                row["decision"] = "missing-check"
                row["covered_semantics"] = None
                row["gap"] = (
                    row.get("gap") or "No relevant gate implements this requirement."
                )
            elif row.get("gap"):
                row["decision"] = "wrong-check"
                row["covered_semantics"] = row.get("covered_semantics") or (
                    "Relevant gates provide only partial coverage."
                )
            else:
                row["decision"] = "covered"
                row["covered_semantics"] = row.get("covered_semantics") or (
                    "The cited relevant gates jointly cover the requirement."
                )
                row["gap"] = None
        elif decision == "not-applicable":
            if not has_applicability_evidence:
                row["applicability"] = "unknown"
                row["decision"] = "unknown"
                row["gate_ids"] = []
                row["covered_semantics"] = None
                row["gap"] = None
                row["uncertainty"] = (
                    "The supplied evidence is insufficient to establish non-applicability."
                )
                continue
            row["applicability"] = "not-applicable"
            row["gate_ids"] = []
            row["covered_semantics"] = None
            row["gap"] = None
            row["uncertainty"] = None
        elif decision == "unknown":
            row["applicability"] = "unknown"
            row["gate_ids"] = []
            row["covered_semantics"] = None
            row["gap"] = None
            row["uncertainty"] = row.get("uncertainty") or (
                "The supplied evidence is insufficient for a defensible verdict."
            )
    return normalized


def _candidate_record(
    chain: CoverageChain,
    assessment: Mapping[str, Any],
    requirement: Mapping[str, Any],
) -> dict[str, Any]:
    gate_ids = assessment["gate_ids"]
    gate_set = set(gate_ids)
    gate_semantics = [
        row for row in chain.semantic_ir["gates"] if row["gate_uid"] in gate_set
    ]
    failure_mode = assessment["decision"]
    gap = assessment["gap"]
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "candidate_id": stable_candidate_id(
            group_id=chain.group_id,
            project=chain.project,
            revision=chain.revision,
            chain_id=chain.chain_id,
            requirement_id=requirement["requirement_id"],
            failure_mode=failure_mode,
            gate_ids=gate_ids,
        ),
        "requirement_source": "group-oracle",
        "provenance": {
            "kind": "group-oracle",
            "requirement_id": requirement["requirement_id"],
        },
        "group_id": chain.group_id,
        "handler_criterion_id": chain.handler_criterion_id,
        "sink_type_id": chain.sink_type_id,
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
        "handler_id": chain.handler_id,
        "sink_id": chain.sink_id,
        "failure_mode": failure_mode,
        "requirement_id": requirement["requirement_id"],
        "requirement_rule": requirement["rule"],
        "requirement_applicability": requirement["applicability"],
        "gate_ids": gate_ids,
        "gate_semantics": gate_semantics,
        "reason": gap,
        "trigger_goal": (
            f"Exercise the concrete sink capability while violating requirement "
            f"{requirement['requirement_id']}: {gap}"
        ),
        "group_oracle_status": chain.oracle["status"],
        "semantic_ir_status": chain.semantic_ir["status"],
        "capability_card": {
            "path": chain.capability_card_path,
            "sha256": chain.capability_card_sha256,
        },
    }


def run_coverage_comparison(
    *,
    specs: Sequence[ProjectSpec],
    handler_root: Path,
    sink_root: Path,
    group_root: Path,
    evidence_registry: Path,
    out_dir: Path,
    generation_command: str,
    runner: Runner,
    challenge_covered: bool = False,
    baseline_root: Path | None = None,
    correction_ledger: Path | None = None,
    source_validation_config: SourceValidationConfig | None = None,
    source_validation_runner_factory: SourceRunnerFactory | None = None,
    capability_card_analysis: bool = True,
    capability_analysis_jobs: int = 4,
    fresh_capability_analysis: bool = False,
    publish: bool = True,
    input_token_limit: int = DEFAULT_INPUT_TOKEN_LIMIT,
) -> dict[str, Any]:
    if input_token_limit < 1:
        raise CoverageComparisonError("input token limit must be positive")
    correction_mode = any(
        (challenge_covered, baseline_root is not None, correction_ledger is not None)
    )
    if correction_mode and not (
        challenge_covered
        and baseline_root is not None
        and correction_ledger is not None
    ):
        raise CoverageComparisonError(
            "correction mode requires --challenge-covered, --baseline-root, and "
            "--correction-ledger together"
        )
    correction_binding: dict[str, Any] | None = None
    correction_payload: dict[str, Any] | None = None
    if correction_mode:
        correction_payload, correction_binding = load_correction_ledger(
            correction_ledger, evidence_registry=evidence_registry
        )
        if (
            baseline_root.resolve()
            != Path(correction_payload["baseline"]["coverage_root"]).resolve()
        ):
            raise CoverageComparisonError(
                "baseline-root disagrees with correction ledger"
            )
        if out_dir.resolve() == baseline_root.resolve():
            raise CoverageComparisonError(
                "correction mode must not overwrite baseline coverage"
            )
        group_manifest = json.loads(
            (group_root / "manifest.json").read_text(encoding="utf-8")
        )
        if (
            group_manifest.get("analysis_mode") != "post-hoc-correction-v2"
            or group_manifest.get("correction", {}).get("sha256")
            != correction_binding["sha256"]
        ):
            raise CoverageComparisonError(
                "group-root is not bound to this correction ledger"
            )
    inputs = load_coverage_inputs(
        specs,
        handler_root=handler_root,
        sink_root=sink_root,
        group_root=group_root,
        evidence_registry=evidence_registry,
    )
    correction_requirements_by_chain: dict[tuple[str, str], set[str]] = {}
    correction_actions: dict[tuple[str, str, str], str] = {}
    correction_deficiencies: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    if correction_payload is not None:
        corrected_oracles = {chain.group_id: chain.oracle for chain in inputs.chains}
        baseline_group_root = Path(correction_payload["baseline"]["group_root"])
        baseline_oracles = {
            row["group_id"]: row
            for row in (
                json.loads(line)
                for line in (baseline_group_root / "oracles.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.strip()
            )
        }
        for correction in correction_payload["corrections"]:
            requirement_ids = resolve_correction_requirement_ids(
                correction,
                corrected_oracles=corrected_oracles,
                baseline_oracles=baseline_oracles,
            )
            if not requirement_ids:
                raise CoverageComparisonError(
                    f"{correction['report_id']}: no corrected requirement identity"
                )
            for chain_id in correction["chain_ids"]:
                correction_requirements_by_chain.setdefault(
                    (correction["project"], chain_id), set()
                ).update(requirement_ids)
                for requirement_id in requirement_ids:
                    key = (correction["project"], chain_id, requirement_id)
                    correction_actions[key] = correction["action"]
                    if correction.get("evidence_deficiency") is not None:
                        correction_deficiencies[key] = correction["evidence_deficiency"]
    comparisons: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    challenges: list[dict[str, Any]] = []
    chats: dict[tuple[str, str], list[dict[str, str]]] = {}
    for chain in inputs.chains:
        requirements = {
            row["requirement_id"]: row for row in chain.oracle["requirements"]
        }
        defaults: list[str] = []
        rows: list[dict[str, Any]] = []
        if requirements:
            batches = _requirement_batches(list(requirements))
            for batch_number, batch_ids in enumerate(batches, 1):
                user = build_compare_user(chain, batch_ids)
                if (
                    estimate_tokens({"system": COMPARE_SYSTEM, "user": user})
                    > input_token_limit
                ):
                    raise CoverageComparisonError(
                        f"{chain.project}:{chain.chain_id}: complete comparison prompt exceeds "
                        f"{input_token_limit} estimated tokens; oracle, card, and IR are never truncated"
                    )
                batch_requirements = {
                    requirement_id: requirements[requirement_id]
                    for requirement_id in batch_ids
                }
                (batch_defaults, batch_rows), exchanges = _validated_call(
                    runner=runner,
                    system=COMPARE_SYSTEM,
                    user=user,
                    validator=lambda response, chain=chain, selected=batch_requirements: (
                        validate_comparison_response(
                            (
                                _normalize_correction_response(response)
                                if correction_mode
                                else response
                            ),
                            group_id=chain.group_id,
                            chain_id=chain.chain_id,
                            requirements=selected,
                            allowed_gate_ids={
                                row["gate_uid"] for row in chain.semantic_ir["gates"]
                            },
                            card_lines=chain.capability_card_lines,
                        )
                    ),
                    context=f"{chain.project}:{chain.chain_id}: compare batch {batch_number}",
                )
                subject = f"{chain.project}-{chain.chain_id}"
                if len(batches) > 1:
                    subject += f"-B{batch_number:03d}"
                chats[("compare", subject)] = exchanges
                defaults = sorted(set(defaults) | set(batch_defaults))
                rows.extend(batch_rows)
            rows.sort(key=lambda row: row["requirement_id"])
        if challenge_covered and rows:
            selected_ids = _challenge_requirement_ids(rows)
            if selected_ids:
                challenge_rows: list[dict[str, Any]] = []
                challenge_batches = _requirement_batches(selected_ids)
                for batch_number, batch_ids in enumerate(challenge_batches, 1):
                    challenge_user = build_challenge_user(chain, batch_ids)
                    if (
                        estimate_tokens(
                            {"system": CHALLENGE_SYSTEM, "user": challenge_user}
                        )
                        > input_token_limit
                    ):
                        raise CoverageComparisonError(
                            f"{chain.project}:{chain.chain_id}: complete challenge prompt exceeds "
                            f"{input_token_limit} estimated tokens"
                        )
                    selected_requirements = {
                        requirement_id: requirements[requirement_id]
                        for requirement_id in batch_ids
                    }
                    (challenge_defaults, batch_rows), exchanges = _validated_call(
                        runner=runner,
                        system=CHALLENGE_SYSTEM,
                        user=challenge_user,
                        validator=lambda response, chain=chain, selected=selected_requirements: (
                            validate_comparison_response(
                                (
                                    _normalize_correction_response(response)
                                    if correction_mode
                                    else response
                                ),
                                group_id=chain.group_id,
                                chain_id=chain.chain_id,
                                requirements=selected,
                                allowed_gate_ids={
                                    row["gate_uid"]
                                    for row in chain.semantic_ir["gates"]
                                },
                                card_lines=chain.capability_card_lines,
                            )
                        ),
                        context=f"{chain.project}:{chain.chain_id}: challenge batch {batch_number}",
                    )
                    subject = f"{chain.project}-{chain.chain_id}"
                    if len(challenge_batches) > 1:
                        subject += f"-B{batch_number:03d}"
                    chats[("challenge", subject)] = exchanges
                    defaults = sorted(set(defaults) | set(challenge_defaults))
                    challenge_rows.extend(batch_rows)
                challenge_by_id = {row["requirement_id"]: row for row in challenge_rows}
                final_rows: list[dict[str, Any]] = []
                for primary in rows:
                    challenge = challenge_by_id.get(primary["requirement_id"])
                    if challenge is None:
                        final_rows.append(primary)
                        continue
                    final, challenge_record = _merge_challenge(
                        chain, primary, challenge
                    )
                    final_rows.append(final)
                    challenges.append(challenge_record)
                rows = sorted(final_rows, key=lambda row: row["requirement_id"])
        correction_requirement_ids = correction_requirements_by_chain.get(
            chain.key, set()
        )
        if correction_requirement_ids:
            for row in rows:
                if row["requirement_id"] not in correction_requirement_ids:
                    continue
                key = (chain.project, chain.chain_id, row["requirement_id"])
                deficiency = correction_deficiencies.get(key)
                if deficiency is not None:
                    missing = ", ".join(deficiency["missing_facts"])
                    row.update(
                        {
                            "applicability": "unknown",
                            "decision": "unknown",
                            "capability_evidence": [],
                            "call_shape_facts": [],
                            "gate_ids": [],
                            "covered_semantics": None,
                            "gap": None,
                            "uncertainty": (
                                "Source-reviewed evidence deficiency "
                                f"({deficiency['kind']}): {deficiency['detail']} "
                                f"Missing bound facts: {missing}."
                            ),
                        }
                    )
                    for challenge in challenges:
                        if (
                            challenge["project"] == chain.project
                            and challenge["chain_id"] == chain.chain_id
                            and challenge["requirement_id"] == row["requirement_id"]
                        ):
                            challenge["disposition"] = "conflict-unknown"
                            challenge["final_assessment"] = dict(row)
                    continue
                if row["decision"] not in {"covered", "not-applicable"}:
                    continue
                action = correction_actions.get(key)
                if action == "reassess":
                    gates = list(row["gate_ids"])
                    row.update(
                        {
                            "applicability": "applicable",
                            "decision": "wrong-check" if gates else "missing-check",
                            "gate_ids": gates,
                            "covered_semantics": (
                                row["covered_semantics"] if gates else None
                            ),
                            "gap": (
                                "Source-reviewed correction evidence establishes a fail-open or "
                                "under-scoped path that the provisional-safe verdict did not cover."
                            ),
                            "uncertainty": None,
                        }
                    )
                else:
                    row.update(
                        {
                            "applicability": "unknown",
                            "decision": "unknown",
                            "capability_evidence": [],
                            "call_shape_facts": [],
                            "gate_ids": [],
                            "covered_semantics": None,
                            "gap": None,
                            "uncertainty": (
                                "Source-backed correction evidence conflicts with a provisional-safe "
                                "verdict; current evidence is insufficient to affirm safety."
                            ),
                        }
                    )
                for challenge in challenges:
                    if (
                        challenge["project"] == chain.project
                        and challenge["chain_id"] == chain.chain_id
                        and challenge["requirement_id"] == row["requirement_id"]
                    ):
                        challenge["disposition"] = (
                            "revised-uncovered"
                            if action == "reassess"
                            else "conflict-unknown"
                        )
                        challenge["final_assessment"] = dict(row)
        assessment_rows = [_assessment_record(chain, row) for row in rows]
        assessments.extend(assessment_rows)
        by_requirement = {row["requirement_id"]: row for row in assessment_rows}
        for requirement_id, requirement in sorted(requirements.items()):
            assessment = by_requirement[requirement_id]
            if assessment["decision"] in {"wrong-check", "missing-check"}:
                candidates.append(_candidate_record(chain, assessment, requirement))
        if not requirements:
            status = "inconclusive"
        elif (
            chain.oracle["status"] == "partial"
            or chain.semantic_ir["status"] == "partial"
            or any(row["decision"] == "unknown" for row in assessment_rows)
        ):
            status = "partial"
        else:
            status = "complete"
        comparisons.append(
            {
                "schema_version": COMPARISON_SCHEMA_VERSION,
                "group_id": chain.group_id,
                "handler_criterion_id": chain.handler_criterion_id,
                "sink_type_id": chain.sink_type_id,
                "project": chain.project,
                "revision": chain.revision,
                "chain_id": chain.chain_id,
                "handler_id": chain.handler_id,
                "sink_id": chain.sink_id,
                "sink_constraint_id": chain.semantic_ir["sink_constraint"][
                    "constraint_id"
                ],
                "group_oracle_status": chain.oracle["status"],
                "semantic_ir_status": chain.semantic_ir["status"],
                "status": status,
                "capability_card": {
                    "path": chain.capability_card_path,
                    "sha256": chain.capability_card_sha256,
                },
                "controlled_argument": chain.semantic_ir["sink_constraint"][
                    "controlled_argument"
                ],
                "values": chain.semantic_ir["values"],
                "call_shape": chain.semantic_ir["sink_constraint"]["call_shape"],
                "applicable_defaults": defaults,
                "requirements": rows,
            }
        )
    group_provisional_candidates = sorted(
        candidates, key=lambda row: row["candidate_id"]
    )
    capability_run = CapabilityAnalysisRun(
        proposals=(),
        assessments=(),
        provisional_candidates=(),
        requirements={},
        chats={},
    )
    if capability_card_analysis and not correction_mode:
        capability_run = analyze_capability_chains(
            chains=inputs.chains,
            runner=runner,
            input_token_limit=input_token_limit,
            jobs=capability_analysis_jobs,
            fresh=fresh_capability_analysis,
            group_assessments=assessments,
        )
        for subject, exchange_rows in capability_run.chats.items():
            chats[("capability-compare", subject)] = list(exchange_rows)
    capability_proposals = list(capability_run.proposals)
    capability_assessments = list(capability_run.assessments)
    capability_provisional_candidates = list(
        capability_run.provisional_candidates
    )
    provisional_candidates = sorted(
        [*group_provisional_candidates, *capability_provisional_candidates],
        key=lambda row: row["candidate_id"],
    )
    source_validation = None
    source_validations: list[dict[str, Any]] = []
    precision_sample: list[dict[str, Any]] = []
    if source_validation_config is not None:
        source_validation = run_source_validation(
            chains={row.key: row for row in inputs.chains},
            provisional_candidates=provisional_candidates,
            assessments=[*assessments, *capability_assessments],
            specs=specs,
            prior_root=out_dir,
            config=source_validation_config,
            runner_factory=source_validation_runner_factory,
            extra_requirements=capability_run.requirements,
        )
        source_validations = list(source_validation.records)
        validate_source_validation_artifacts(
            provisional_candidates=provisional_candidates,
            records=source_validations,
        )
        validation_by_key = {
            (row["project"], row["chain_id"], row["requirement_id"]): row
            for row in source_validations
        }
        updated_assessments: list[dict[str, Any]] = []
        for assessment in assessments:
            key = (
                assessment["project"],
                assessment["chain_id"],
                assessment["requirement_id"],
            )
            validation = validation_by_key.get(key)
            if validation is None:
                updated_assessments.append(assessment)
                continue
            metadata = {
                field: assessment[field]
                for field in (
                    "schema_version",
                    "group_id",
                    "handler_criterion_id",
                    "sink_type_id",
                    "project",
                    "revision",
                    "chain_id",
                )
            }
            updated_assessments.append({**metadata, **validation["final_assessment"]})
        assessments = updated_assessments
        updated_capability_assessments: list[dict[str, Any]] = []
        for assessment in capability_assessments:
            key = (
                assessment["project"],
                assessment["chain_id"],
                assessment["requirement_id"],
            )
            validation = validation_by_key.get(key)
            if validation is None:
                updated_capability_assessments.append(assessment)
                continue
            final = validation["final_assessment"]
            updated_capability_assessments.append(
                {
                    **assessment,
                    **{
                        field: final[field]
                        for field in (
                            "applicability",
                            "decision",
                            "capability_evidence",
                            "call_shape_facts",
                            "gate_ids",
                            "covered_semantics",
                            "gap",
                            "uncertainty",
                        )
                    },
                }
            )
        capability_assessments = updated_capability_assessments
        assessment_by_key = {
            (row["project"], row["chain_id"], row["requirement_id"]): row
            for row in assessments
        }
        for comparison in comparisons:
            final_rows = []
            for row in comparison["requirements"]:
                final = assessment_by_key[
                    (
                        comparison["project"],
                        comparison["chain_id"],
                        row["requirement_id"],
                    )
                ]
                final_rows.append(
                    {
                        field: final[field]
                        for field in (
                            "requirement_id",
                            "applicability",
                            "decision",
                            "capability_evidence",
                            "call_shape_facts",
                            "gate_ids",
                            "covered_semantics",
                            "gap",
                            "uncertainty",
                        )
                    }
                )
            comparison["requirements"] = sorted(
                final_rows, key=lambda row: row["requirement_id"]
            )
            if not final_rows:
                comparison["status"] = "inconclusive"
            elif (
                comparison["group_oracle_status"] == "partial"
                or comparison["semantic_ir_status"] == "partial"
                or any(row["decision"] == "unknown" for row in final_rows)
            ):
                comparison["status"] = "partial"
            else:
                comparison["status"] = "complete"
        for challenge in challenges:
            validation = validation_by_key.get(
                (
                    challenge["project"],
                    challenge["chain_id"],
                    challenge["requirement_id"],
                )
            )
            if validation is not None:
                challenge["final_assessment"] = dict(validation["final_assessment"])
        confirmed_ids = {
            row["provisional_candidate_id"]
            for row in source_validations
            if row["disposition"] == "confirmed"
        }
        candidates = [
            row
            for row in provisional_candidates
            if row["candidate_id"] in confirmed_ids
        ]
        precision_sample = deterministic_precision_sample(provisional_candidates)
    else:
        # Card-derived gaps are never canonical without source validation.
        candidates = list(group_provisional_candidates)
    comparisons.sort(key=lambda row: (row["project"], row["chain_id"]))
    assessments.sort(
        key=lambda row: (row["project"], row["chain_id"], row["requirement_id"])
    )
    candidates.sort(key=lambda row: row["candidate_id"])
    challenges.sort(
        key=lambda row: (row["project"], row["chain_id"], row["requirement_id"])
    )
    exclusions = list(inputs.exclusions)
    expected_comparison_keys = {row.key for row in inputs.chains}
    expected_exclusion_keys = {(row["project"], row["chain_id"]) for row in exclusions}
    expected_requirement_keys = {
        (chain.project, chain.chain_id, requirement["requirement_id"])
        for chain in inputs.chains
        for requirement in chain.oracle["requirements"]
    }
    validate_artifacts(
        comparisons=comparisons,
        assessments=assessments,
        candidates=candidates,
        capability_proposals=capability_proposals,
        capability_assessments=capability_assessments,
        capability_candidates_canonical=source_validation_config is not None,
        challenges=challenges,
        exclusions=exclusions,
        expected_comparison_keys=expected_comparison_keys,
        expected_exclusion_keys=expected_exclusion_keys,
        expected_requirement_keys=expected_requirement_keys,
        internal_legacy=True,
    )
    report = render_coverage_index(
        generation_command=generation_command,
        comparisons=comparisons,
        assessments=assessments,
        candidates=candidates,
        exclusions=exclusions,
        challenges=challenges,
        source_validations=source_validations,
    )
    ranking_report = render_candidate_ranking(
        generation_command=generation_command,
        source_validations=source_validations,
    )
    precision_report = render_precision_audit(
        generation_command=generation_command,
        sample=precision_sample,
        source_validations=source_validations,
    )
    transport = (
        runner.audit_payload()
        if callable(getattr(runner, "audit_payload", None))
        else {"transport": "injected-runner", "available_tools": []}
    )
    estimated_input_tokens = sum(
        estimate_tokens({"system": row["system"], "user": row["user"]})
        for exchange_rows in chats.values()
        for row in exchange_rows
    )
    estimated_output_tokens = sum(
        estimate_tokens(row["response"])
        for exchange_rows in chats.values()
        for row in exchange_rows
    )
    token_usage = transport.setdefault("token_usage", {})
    transport_calls = transport.get("calls", [])
    provider_call_count = (
        sum(
            isinstance(row, dict) and isinstance(row.get("usage"), dict)
            for row in transport_calls
        )
        if isinstance(transport_calls, list)
        else 0
    )
    token_usage.update(
        {
            "estimated_full_run": True,
            "estimated_input_tokens": estimated_input_tokens,
            "estimated_output_tokens": estimated_output_tokens,
            "estimated_total_tokens": estimated_input_tokens + estimated_output_tokens,
            "provider_reported_call_count": provider_call_count,
            "provider_reported_call_scope": (
                "full-run"
                if provider_call_count == sum(len(rows) for rows in chats.values())
                else "live-subset-after-replay"
            ),
        }
    )
    counts = {
        "structural_chains": inputs.structural_chain_count,
        "eligible_comparisons": len(comparisons),
        "requirement_assessments": len(assessments),
        "zero_requirement_comparisons": sum(
            not row["requirements"] for row in comparisons
        ),
        "complete_comparisons": sum(row["status"] == "complete" for row in comparisons),
        "partial_comparisons": sum(row["status"] == "partial" for row in comparisons),
        "inconclusive_comparisons": sum(
            row["status"] == "inconclusive" for row in comparisons
        ),
        "covered": sum(row["decision"] == "covered" for row in assessments),
        "wrong_check": sum(row["decision"] == "wrong-check" for row in assessments),
        "missing_check": sum(row["decision"] == "missing-check" for row in assessments),
        "not_applicable": sum(
            row["decision"] == "not-applicable" for row in assessments
        ),
        "unknown": sum(row["decision"] == "unknown" for row in assessments),
        "candidates": len(candidates),
        "excluded_chains": len(exclusions),
        "excluded_impact_pruned": sum(
            row["reason_code"] == "impact-pruned" for row in exclusions
        ),
        "excluded_unresolved_handler": sum(
            row["reason_code"] == "unresolved-handler-alignment" for row in exclusions
        ),
        "primary_requests": sum(stage == "compare" for stage, _ in chats),
        "model_calls": sum(len(rows) for rows in chats.values()),
        "repair_calls": sum(len(rows) - 1 for rows in chats.values()),
        "challenge_requests": sum(stage == "challenge" for stage, _ in chats),
        "capability_analysis_requests": sum(
            stage == "capability-compare" for stage, _ in chats
        ),
        "capability_analysis_model_calls": sum(
            len(rows)
            for (stage, _), rows in chats.items()
            if stage == "capability-compare"
        ),
        "capability_proposals": len(capability_proposals),
        "capability_proposals_novel": sum(
            row["disposition"] == "novel" for row in capability_proposals
        ),
        "capability_proposals_covered_by_group": sum(
            row["disposition"] == "covered-by-group"
            for row in capability_proposals
        ),
        "capability_proposals_group_overlap_conflict": sum(
            row["disposition"] == "group-overlap-conflict"
            for row in capability_proposals
        ),
        "capability_assessments_wrong_check": sum(
            row["decision"] == "wrong-check" for row in capability_assessments
        ),
        "capability_assessments_missing_check": sum(
            row["decision"] == "missing-check" for row in capability_assessments
        ),
        "group_provisional_candidates": len(group_provisional_candidates),
        "capability_provisional_candidates": len(
            capability_provisional_candidates
        ),
        "group_canonical_candidates": sum(
            row.get("requirement_source") == "group-oracle" for row in candidates
        ),
        "capability_canonical_candidates": sum(
            row.get("requirement_source") == "capability-card"
            for row in candidates
        ),
        "challenge_assessments": len(challenges),
        "challenge_revised_uncovered": sum(
            row["disposition"] == "revised-uncovered" for row in challenges
        ),
        "challenge_conflicts_unknown": sum(
            row["disposition"] == "conflict-unknown" for row in challenges
        ),
        "provisional_candidates": len(provisional_candidates),
        "source_validation_confirmed": sum(
            row["disposition"] == "confirmed" for row in source_validations
        ),
        "source_validation_refuted": sum(
            row["disposition"] == "refuted" for row in source_validations
        ),
        "source_validation_unknown": sum(
            row["disposition"] == "unknown" for row in source_validations
        ),
        "source_validation_operational_failures": (
            source_validation.operational_failures
            if source_validation is not None
            else 0
        ),
        "source_validation_high": sum(
            row["review_priority"] == "high" for row in source_validations
        ),
        "source_validation_medium": sum(
            row["review_priority"] == "medium" for row in source_validations
        ),
        "source_validation_low": sum(
            row["review_priority"] == "low" for row in source_validations
        ),
        "precision_audit_sample": len(precision_sample),
    }
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generation_command": generation_command,
        "group_key": ["handler_criterion_id", "sink_type_id"],
        "group_id_field": "group_id",
        "input_token_limit": input_token_limit,
        "capability_card_policy": "reuse-verified-existing-cards-only",
        "inputs": inputs.digests,
        "outputs": {
            "comparisons": str(out_dir / "comparisons.jsonl"),
            "requirement_assessments": str(out_dir / "requirement-assessments.jsonl"),
            "candidates": str(out_dir / "candidates.jsonl"),
            "excluded_chains": str(out_dir / "excluded-chains.jsonl"),
            "requirement_challenges": str(out_dir / "requirement-challenges.jsonl"),
            "capability_requirement_proposals": str(
                out_dir / "capability-requirement-proposals.jsonl"
            ),
            "capability_requirement_assessments": str(
                out_dir / "capability-requirement-assessments.jsonl"
            ),
            "provisional_candidates": str(out_dir / "provisional-candidates.jsonl"),
            "candidate_validations": str(out_dir / "candidate-validations.jsonl"),
            "candidate_ranking": str(out_dir / "candidate-ranking.md"),
            "precision_audit_sample": str(out_dir / "precision-audit-sample.jsonl"),
            "precision_audit_report": str(out_dir / "precision-audit.md"),
            "report": str(out_dir / "coverage-index.md"),
        },
        "counts": counts,
        "transport": transport,
        "capability_card_analysis": {
            "enabled": capability_card_analysis and not correction_mode,
            "prompt_version": CAPABILITY_PROMPT_VERSION,
            "jobs": capability_analysis_jobs,
            "fresh": fresh_capability_analysis,
            "canonical_promotion_requires_source_validation": True,
        },
    }
    manifest["comparison_prompt_version"] = COMPARISON_PROMPT_VERSION
    if source_validation is not None:
        manifest["analysis_mode"] = "canonical-trained-detector/v7"
        manifest["source_validation"] = dict(source_validation.transport)
        manifest["source_validation"]["candidate_policy"] = (
            "canonical-candidates-require-confirmed-uncovered"
        )
        manifest["source_validation"]["strict_ground_truth_recall_floor"] = {
            "eligible_reports": 43,
            "covered_reports": 23,
        }
    if correction_binding is not None:
        manifest["analysis_mode"] = "coverage-post-hoc-correction/v7"
        manifest["post_hoc_ground_truth_informed"] = True
        manifest["challenge_policy"] = "coverage-independent-challenge/v7"
        manifest["correction"] = correction_binding
        manifest["corrected_group_root"] = str(group_root)
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{out_dir.name}.staging-", dir=out_dir.parent)
    )
    try:
        _write_jsonl(staging / "comparisons.jsonl", comparisons)
        _write_jsonl(staging / "requirement-assessments.jsonl", assessments)
        _write_jsonl(staging / "candidates.jsonl", candidates)
        _write_jsonl(staging / "provisional-candidates.jsonl", provisional_candidates)
        _write_jsonl(staging / "candidate-validations.jsonl", source_validations)
        _write_jsonl(staging / "precision-audit-sample.jsonl", precision_sample)
        _write_jsonl(staging / "excluded-chains.jsonl", exclusions)
        _write_jsonl(staging / "requirement-challenges.jsonl", challenges)
        _write_jsonl(
            staging / "capability-requirement-proposals.jsonl",
            capability_proposals,
        )
        _write_jsonl(
            staging / "capability-requirement-assessments.jsonl",
            capability_assessments,
        )
        _write_json(staging / "manifest.json", manifest)
        _write_text(staging / "coverage-index.md", report)
        _write_text(staging / "candidate-ranking.md", ranking_report)
        _write_text(staging / "precision-audit.md", precision_report)
        for (stage, subject), exchange_rows in sorted(chats.items()):
            _write_json(
                staging / "repository" / stage / subject / "chat.json",
                {
                    "schema_version": CHAT_SCHEMA_VERSION,
                    "stage": stage,
                    "subject": subject,
                    "exchanges": exchange_rows,
                },
            )
        if source_validation is not None:
            for relative, payload in source_validation.sidecars.items():
                _write_json(staging / relative, payload)
        unsafe = [
            str(path.relative_to(staging))
            for path in sorted(item for item in staging.rglob("*") if item.is_file())
            if contains_credentials(path.read_text(encoding="utf-8"))
        ]
        if unsafe:
            raise CoverageComparisonError(
                "credential-shaped data would enter coverage artifacts: "
                + ", ".join(unsafe)
            )
        if publish:
            _publish_directory(staging, out_dir)
            if source_validation is not None:
                clear_source_validation_checkpoint(out_dir)
        else:
            shutil.rmtree(staging)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {
        "manifest": manifest,
        "report": report,
        "source_validation_incomplete": (
            source_validation.incomplete if source_validation is not None else False
        ),
    }
