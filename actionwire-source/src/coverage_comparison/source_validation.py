"""Blind source-agent validation for provisional coverage candidates."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from jsonschema import validate as validate_schema

from src.gate_semantics.agent_sdk import (
    ALL_RESEARCH_TOOLS,
    BUILTIN_RESEARCH_TOOLS,
    ClaudeCLIRunner,
    aggregate_token_usage,
    build_sdk_runner,
)
from src.projects import ProjectSpec

from .contracts import (
    SCHEMA_DIR,
    CoverageComparisonError,
    canonical_json,
    digest,
    normalize_text,
    parse_json_response,
    sha256_file,
)
from .inputs import CoverageChain
from .prompts import contains_credentials, redact_credentials
from .source_validation_prompts import (
    LEARNED_SOURCE_VALIDATION_SYSTEM,
    SOURCE_VALIDATION_PROMPT_VERSION,
    SOURCE_VALIDATION_REPAIR_SYSTEM,
    SOURCE_VALIDATION_SYSTEM,
    build_source_validation_repair_user,
    build_source_validation_user,
)
from .source_validation_packets import (
    PACKET_PROMPT_VERSION,
    PACKET_SCHEMA_VERSION,
    PACKET_VALIDATION_SYSTEM,
    build_packet_validation_user,
    build_source_validation_packet,
    normalize_packet_validation_payload,
    parse_packet_validation_response,
)
from .versions import (
    AGENT_AUDIT_SCHEMA_VERSION,
    AGENT_CHAT_SCHEMA_VERSION,
    PRECISION_AUDIT_SCHEMA_VERSION,
    SOURCE_VALIDATION_CACHE_VERSION,
    SOURCE_VALIDATION_SCHEMA_VERSION,
    SOURCE_VALIDATION_TRANSPORT_VERSION,
)

DEFAULT_CANDIDATES_PER_BATCH = 4

_ASSESSMENT_FIELDS = (
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
_RESPONSE_FIELDS = {
    "provisional_candidate_id",
    "verdict",
    "final_decision",
    "covering_gate_ids",
    "policy_basis",
    "controlled_flow",
    "sink_reachability",
    "gate_coverage",
    "impact",
    "impact_severity",
    "source_research_complete",
    "source_evidence",
    "preconditions",
    "security_effect",
    "uncertainties",
    "reason",
}
_EVIDENCE_ROLES = {
    "handler",
    "controlled-value",
    "gate",
    "sink",
    "policy",
    "impact",
}


class SourceRunner(Protocol):
    def __call__(self, system: str, user: str) -> str: ...

    def close(self) -> None: ...


SourceRunnerFactory = Callable[[ProjectSpec, "SourceValidationConfig"], SourceRunner]


@dataclass(frozen=True)
class SourceValidationConfig:
    model: str | None = None
    agent_transport: str = "sdk"
    enable_lsp: bool = True
    jobs: int = 4
    timeout: int = 900
    max_turns: int = 8
    max_tool_calls: int = 16
    candidates_per_batch: int = DEFAULT_CANDIDATES_PER_BATCH
    fresh: bool = False
    cache_namespace: str = "source-validate"
    learned_invariant_policy: bool = False
    strategy: str = "packet-first"
    allowed_source_files: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.agent_transport not in {"sdk", "cli"}:
            raise CoverageComparisonError(
                "source-validation transport must be sdk or cli"
            )
        for label, value in {
            "source-validation jobs": self.jobs,
            "source-validation timeout": self.timeout,
            "source-validation max turns": self.max_turns,
            "source-validation max tool calls": self.max_tool_calls,
            "source-validation batch size": self.candidates_per_batch,
        }.items():
            if value < 1:
                raise CoverageComparisonError(f"{label} must be positive")
        if not re.fullmatch(r"source-validate(?:-[a-z0-9-]+)?", self.cache_namespace):
            raise CoverageComparisonError("invalid source-validation cache namespace")
        if self.strategy not in {"packet-first", "agent-only"}:
            raise CoverageComparisonError(
                "source-validation strategy must be packet-first or agent-only"
            )
        if self.strategy == "packet-first" and self.agent_transport != "sdk":
            raise CoverageComparisonError(
                "packet-first deep fallback requires the SDK transport"
            )

    def tool_profile(self) -> list[str]:
        tools = (
            list(ALL_RESEARCH_TOOLS)
            if self.agent_transport == "sdk" and self.enable_lsp
            else list(BUILTIN_RESEARCH_TOOLS)
        )
        if self.allowed_source_files:
            tools = [
                tool
                for tool in tools
                if tool not in {"Glob", "mcp__lsp__lsp_workspace_symbols"}
            ]
        return tools

    def prompt_version(self) -> str:
        return SOURCE_VALIDATION_PROMPT_VERSION

    def system_prompt(self) -> str:
        return (
            LEARNED_SOURCE_VALIDATION_SYSTEM
            if self.learned_invariant_policy
            else SOURCE_VALIDATION_SYSTEM
        )

    def cache_version(self) -> str:
        return SOURCE_VALIDATION_CACHE_VERSION


@dataclass(frozen=True)
class SourceValidationRun:
    records: tuple[dict[str, Any], ...]
    sidecars: Mapping[str, Mapping[str, Any]]
    transport: Mapping[str, Any]
    provisional_count: int
    confirmed_count: int
    refuted_count: int
    unknown_count: int
    operational_failures: int
    reused_chains: int
    generated_chains: int

    @property
    def incomplete(self) -> bool:
        return bool(self.unknown_count or self.operational_failures)


@dataclass(frozen=True)
class _ChainOutcome:
    records: tuple[dict[str, Any], ...]
    sidecars: Mapping[str, Mapping[str, Any]]
    audit: Mapping[str, Any]
    reused: bool
    operational_failures: int


def _assessment_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {field: row[field] for field in _ASSESSMENT_FIELDS}


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise CoverageComparisonError(f"{field} must be an array of non-empty strings")
    output = [" ".join(item.split()) for item in value]
    if len(output) != len(set(output)):
        raise CoverageComparisonError(f"{field} contains duplicates")
    return output


def _source_evidence(
    value: object,
    *,
    source_root: Path,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CoverageComparisonError("source_evidence must be an array")
    output: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != {
            "role",
            "file",
            "line_start",
            "line_end",
            "claim",
        }:
            raise CoverageComparisonError(
                f"source_evidence[{index}] has unexpected fields"
            )
        role = raw["role"]
        if role not in _EVIDENCE_ROLES:
            raise CoverageComparisonError(f"source_evidence[{index}].role is invalid")
        relative = raw["file"]
        if not isinstance(relative, str) or not relative.strip():
            raise CoverageComparisonError(
                f"source_evidence[{index}].file must be non-empty"
            )
        relative_path = Path(relative)
        if relative_path.is_absolute():
            raise CoverageComparisonError("source evidence path must be relative")
        try:
            resolved = (source_root / relative_path).resolve(strict=True)
            normalized_relative = resolved.relative_to(source_root).as_posix()
        except (OSError, RuntimeError, ValueError) as exc:
            raise CoverageComparisonError(
                f"source evidence path escapes source root: {relative!r}"
            ) from exc
        if not resolved.is_file():
            raise CoverageComparisonError(
                f"source evidence is not a file: {normalized_relative}"
            )
        line_start = raw["line_start"]
        line_end = raw["line_end"]
        if (
            not isinstance(line_start, int)
            or isinstance(line_start, bool)
            or not isinstance(line_end, int)
            or isinstance(line_end, bool)
            or line_start < 1
            or line_end < line_start
            or line_end - line_start > 2_000
        ):
            raise CoverageComparisonError(
                f"source_evidence[{index}] has an invalid line range"
            )
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        if line_end > len(lines):
            raise CoverageComparisonError(
                f"source_evidence[{index}] ends beyond {normalized_relative}"
            )
        if not isinstance(raw["claim"], str):
            raise CoverageComparisonError(
                f"source_evidence[{index}].claim must be a string"
            )
        claim = normalize_text(
            redact_credentials(raw["claim"]),
            f"source_evidence[{index}].claim",
        )
        for chunk_start in range(line_start, line_end + 1, 160):
            chunk_end = min(line_end, chunk_start + 159)
            output.append(
                {
                    "role": role,
                    "file": normalized_relative,
                    "line_start": chunk_start,
                    "line_end": chunk_end,
                    "claim": claim,
                    "sha256": sha256_file(resolved),
                    "excerpt": redact_credentials(
                        "\n".join(lines[chunk_start - 1 : chunk_end])
                    ),
                }
            )
    keys = [canonical_json(row) for row in output]
    if len(keys) != len(set(keys)):
        raise CoverageComparisonError("source_evidence contains duplicates")
    return sorted(
        output,
        key=lambda row: (
            row["file"],
            row["line_start"],
            row["line_end"],
            row["role"],
        ),
    )


def _final_assessment(
    primary: Mapping[str, Any],
    *,
    verdict: str,
    covering_gate_ids: Sequence[str],
    reason: str,
) -> dict[str, Any]:
    final = _assessment_payload(primary)
    if verdict == "confirmed-uncovered":
        return final
    if verdict == "not-applicable":
        final.update(
            {
                "applicability": "not-applicable",
                "decision": "not-applicable",
                "gate_ids": [],
                "covered_semantics": None,
                "gap": None,
                "uncertainty": None,
            }
        )
        return final
    if verdict == "covered":
        final.update(
            {
                "applicability": "applicable",
                "decision": "covered",
                "gate_ids": list(covering_gate_ids),
                "covered_semantics": reason,
                "gap": None,
                "uncertainty": None,
            }
        )
        return final
    final.update(
        {
            "applicability": "unknown",
            "decision": "unknown",
            "capability_evidence": [],
            "call_shape_facts": [],
            "gate_ids": [],
            "covered_semantics": None,
            "gap": None,
            "uncertainty": reason,
        }
    )
    return final


def _review_priority(
    chain: CoverageChain,
    *,
    verdict: str,
    impact_severity: str,
    preconditions: Sequence[str],
) -> str | None:
    if verdict != "confirmed-uncovered":
        return None
    if (
        impact_severity == "high"
        and not preconditions
        and chain.oracle["status"] == "complete"
        and chain.semantic_ir["status"] == "complete"
    ):
        return "high"
    if impact_severity == "low" or len(preconditions) >= 3:
        return "low"
    return "medium"


def validate_source_response(
    response: Mapping[str, Any],
    *,
    chain: CoverageChain,
    candidates: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    source_root: Path,
    validation_input_sha256: str,
    prompt_version: str = SOURCE_VALIDATION_PROMPT_VERSION,
) -> list[dict[str, Any]]:
    """Validate one agent response and derive canonical final assessments."""

    if set(response) != {"project", "revision", "chain_id", "validations"}:
        raise CoverageComparisonError(
            "source-validation response has unexpected fields"
        )
    if (
        response["project"] != chain.project
        or response["revision"] != chain.revision
        or response["chain_id"] != chain.chain_id
    ):
        raise CoverageComparisonError("source-validation response identity mismatch")
    rows = response["validations"]
    if not isinstance(rows, list):
        raise CoverageComparisonError("source-validation validations must be an array")
    candidate_by_id = {str(row["candidate_id"]): row for row in candidates}
    allowed_gate_ids = {
        str(row["gate_uid"]) for row in chain.semantic_ir.get("gates", [])
    }
    output: list[dict[str, Any]] = []
    seen: list[str] = []
    for raw in rows:
        if isinstance(raw, dict):
            raw_candidate_id = raw.get("provisional_candidate_id")
            raw_candidate = candidate_by_id.get(str(raw_candidate_id))
            if raw_candidate and raw_candidate.get("requirement_source") == "learned-invariant":
                raw = dict(raw)
                for metadata_field in (
                    "controlled_facet",
                    "effective_sink_facet",
                    "origin_witness_ids",
                ):
                    raw.pop(metadata_field, None)
        if not isinstance(raw, dict) or set(raw) != _RESPONSE_FIELDS:
            raise CoverageComparisonError(
                "source-validation candidate row has unexpected fields"
            )
        candidate_id = raw["provisional_candidate_id"]
        if candidate_id not in candidate_by_id:
            raise CoverageComparisonError(
                "source validation references unknown candidate"
            )
        candidate = candidate_by_id[candidate_id]
        requirement_id = str(candidate["requirement_id"])
        primary = assessments[requirement_id]
        verdict = raw["verdict"]
        if verdict not in {
            "confirmed-uncovered",
            "not-applicable",
            "covered",
            "upstream-inconsistent",
            "unknown",
        }:
            raise CoverageComparisonError("invalid source-validation verdict")
        final_decision = raw["final_decision"]
        covering_gate_ids = _string_list(raw["covering_gate_ids"], "covering_gate_ids")
        covering_gate_ids_valid = set(covering_gate_ids) <= allowed_gate_ids
        if verdict != "covered" and not covering_gate_ids_valid:
            raise CoverageComparisonError("covering_gate_ids contains unknown gates")
        policy_basis = raw["policy_basis"]
        if policy_basis not in {
            "explicit-source-policy",
            "fixed-delta",
            "inherent-security-boundary",
            "learned-security-invariant",
            "capability-only",
            "none",
            "unknown",
        }:
            raise CoverageComparisonError("invalid source-validation policy basis")
        controlled_flow = raw["controlled_flow"]
        sink_reachability = raw["sink_reachability"]
        if controlled_flow not in {"confirmed", "refuted", "unknown"}:
            raise CoverageComparisonError("invalid controlled_flow")
        if sink_reachability not in {"confirmed", "refuted", "unknown"}:
            raise CoverageComparisonError("invalid sink_reachability")
        gate_coverage = raw["gate_coverage"]
        if gate_coverage not in {
            "uncovered",
            "covered",
            "uncatalogued-check",
            "unknown",
        }:
            raise CoverageComparisonError("invalid gate_coverage")
        impact = raw["impact"]
        if impact not in {"concrete", "none", "unknown"}:
            raise CoverageComparisonError("invalid impact")
        impact_severity = raw["impact_severity"]
        if impact_severity not in {"high", "medium", "low", "unknown"}:
            raise CoverageComparisonError("invalid impact_severity")
        research_complete = raw["source_research_complete"]
        if not isinstance(research_complete, bool):
            raise CoverageComparisonError("source_research_complete must be boolean")
        evidence = _source_evidence(raw["source_evidence"], source_root=source_root)
        preconditions = _string_list(raw["preconditions"], "preconditions")
        uncertainties = _string_list(raw["uncertainties"], "uncertainties")
        security_effect = normalize_text(
            raw["security_effect"], "security_effect", nullable=True
        )
        reason = normalize_text(raw["reason"], "reason")
        evidence_roles = {row["role"] for row in evidence}
        normalized_invalid_covered = bool(
            verdict == "covered"
            and (
                not covering_gate_ids
                or not covering_gate_ids_valid
                or gate_coverage != "covered"
                or "gate" not in evidence_roles
                or uncertainties
            )
        )
        if normalized_invalid_covered:
            verdict = "upstream-inconsistent"
            final_decision = "unknown"
            covering_gate_ids = []
            gate_coverage = (
                "uncatalogued-check"
                if not covering_gate_ids_valid
                else "unknown"
            )
            if not uncertainties:
                uncertainties = [
                    "The reported covering check could not satisfy the supplied GU and "
                    "source-evidence contract."
                ]
        expected_final = {
            "confirmed-uncovered": candidate["failure_mode"],
            "not-applicable": "not-applicable",
            "covered": "covered",
            "upstream-inconsistent": "unknown",
            "unknown": "unknown",
        }[verdict]
        if final_decision != expected_final:
            raise CoverageComparisonError(
                "source-validation final decision contradicts verdict"
            )
        if verdict == "confirmed-uncovered":
            required_roles = {"handler", "controlled-value", "sink", "policy", "impact"}
            if (
                covering_gate_ids
                or policy_basis in {"capability-only", "none", "unknown"}
                or controlled_flow != "confirmed"
                or sink_reachability != "confirmed"
                or gate_coverage != "uncovered"
                or impact != "concrete"
                or impact_severity == "unknown"
                or not research_complete
                or not required_roles <= evidence_roles
                or security_effect is None
                or uncertainties
            ):
                raise CoverageComparisonError(
                    "confirmed-uncovered source-validation invariant failed"
                )
        elif verdict == "covered":
            pass
        elif verdict == "not-applicable":
            if (
                covering_gate_ids
                or "sink" not in evidence_roles
                or not ({"controlled-value", "handler"} & evidence_roles)
            ):
                raise CoverageComparisonError(
                    "not-applicable source-validation invariant failed"
                )
        elif covering_gate_ids:
            raise CoverageComparisonError(
                "unknown/inconsistent validation cannot cite covering gates"
            )
        final = _final_assessment(
            primary,
            verdict=verdict,
            covering_gate_ids=covering_gate_ids,
            reason=str(reason),
        )
        output.append(
            {
                "schema_version": SOURCE_VALIDATION_SCHEMA_VERSION,
                "validation_id": "SVAL-"
                + digest(
                    [
                        candidate_id,
                        prompt_version,
                        validation_input_sha256,
                    ]
                )[:16],
                "validation_input_sha256": validation_input_sha256,
                "group_id": chain.group_id,
                "project": chain.project,
                "revision": chain.revision,
                "chain_id": chain.chain_id,
                "provisional_candidate_id": candidate_id,
                "requirement_id": requirement_id,
                "requirement_source": candidate.get(
                    "requirement_source", "group-oracle"
                ),
                "primary_failure_mode": candidate["failure_mode"],
                "verdict": verdict,
                "disposition": (
                    "confirmed"
                    if verdict == "confirmed-uncovered"
                    else "refuted"
                    if verdict in {"not-applicable", "covered"}
                    else "unknown"
                ),
                "primary_assessment": _assessment_payload(primary),
                "final_assessment": final,
                "review_priority": _review_priority(
                    chain,
                    verdict=verdict,
                    impact_severity=impact_severity,
                    preconditions=preconditions,
                ),
                "policy_basis": policy_basis,
                "controlled_flow": controlled_flow,
                "sink_reachability": sink_reachability,
                "gate_coverage": gate_coverage,
                "covering_gate_ids": covering_gate_ids,
                "impact": impact,
                "impact_severity": impact_severity,
                "source_research_complete": research_complete,
                "source_evidence": evidence,
                "preconditions": preconditions,
                "security_effect": security_effect,
                "uncertainties": uncertainties,
                "reason": reason,
                "operational_error": None,
            }
        )
        seen.append(candidate_id)
    if len(seen) != len(set(seen)) or set(seen) != set(candidate_by_id):
        raise CoverageComparisonError(
            "source validation must cover every provisional candidate exactly once"
        )
    return sorted(output, key=lambda row: row["provisional_candidate_id"])


def _failure_record(
    *,
    chain: CoverageChain,
    candidate: Mapping[str, Any],
    primary: Mapping[str, Any],
    validation_input_sha256: str,
    error: str,
    prompt_version: str = SOURCE_VALIDATION_PROMPT_VERSION,
) -> dict[str, Any]:
    reason = "Source validation failed or remained unresolved: " + " ".join(
        error.split()
    )
    final = _final_assessment(
        primary,
        verdict="unknown",
        covering_gate_ids=[],
        reason=reason,
    )
    candidate_id = str(candidate["candidate_id"])
    return {
        "schema_version": SOURCE_VALIDATION_SCHEMA_VERSION,
        "validation_id": "SVAL-"
        + digest(
        [candidate_id, prompt_version, validation_input_sha256]
        )[:16],
        "validation_input_sha256": validation_input_sha256,
        "group_id": chain.group_id,
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
        "provisional_candidate_id": candidate_id,
        "requirement_id": candidate["requirement_id"],
        "requirement_source": candidate.get("requirement_source", "group-oracle"),
        "primary_failure_mode": candidate["failure_mode"],
        "verdict": "unknown",
        "disposition": "unknown",
        "primary_assessment": _assessment_payload(primary),
        "final_assessment": final,
        "review_priority": None,
        "policy_basis": "unknown",
        "controlled_flow": "unknown",
        "sink_reachability": "unknown",
        "gate_coverage": "unknown",
        "covering_gate_ids": [],
        "impact": "unknown",
        "impact_severity": "unknown",
        "source_research_complete": False,
        "source_evidence": [],
        "preconditions": [],
        "security_effect": None,
        "uncertainties": [reason],
        "reason": reason,
        "operational_error": " ".join(error.split()),
    }


def default_source_runner_factory(
    spec: ProjectSpec,
    config: SourceValidationConfig,
) -> SourceRunner:
    resolved = spec.resolved()
    if config.agent_transport == "sdk":
        return build_sdk_runner(
            source_root=resolved.source_root,
            model=config.model or resolved.llm.model,
            timeout=config.timeout,
            max_turns=config.max_turns,
            enable_lsp=config.enable_lsp,
            allowed_source_files=config.allowed_source_files,
            max_tool_calls=config.max_tool_calls,
        )
    return ClaudeCLIRunner(
        source_root=resolved.source_root,
        model=config.model or resolved.llm.model,
        timeout=config.timeout,
        max_turns=config.max_turns,
    )


def _runner_payload(runner: SourceRunner, name: str) -> dict[str, Any]:
    method = getattr(runner, name, None)
    if not callable(method):
        return {}
    value = method()
    if not isinstance(value, dict):
        return {}
    return json.loads(redact_credentials(json.dumps(value, ensure_ascii=False)))


def _versioned_agent_sidecar(
    payload: Mapping[str, Any], *, schema_version: str
) -> dict[str, Any]:
    """Attach the coverage-owned v7 envelope to an agent SDK payload."""

    return {**dict(payload), "schema_version": schema_version}


def _close_runner(runner: SourceRunner) -> None:
    close = getattr(runner, "close", None)
    if callable(close):
        close()


def _validated_agent_call(
    *,
    runner: SourceRunner,
    chain: CoverageChain,
    candidates: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    source_root: Path,
    validation_input_sha256: str,
    config: SourceValidationConfig,
) -> list[dict[str, Any]]:
    system = config.system_prompt()
    user = build_source_validation_user(
        chain,
        candidates,
        assessments,
        requirements,
        prompt_version=config.prompt_version(),
    )
    raw = redact_credentials(runner(system, user))
    try:
        return validate_source_response(
            parse_json_response(raw),
            chain=chain,
            candidates=candidates,
            assessments=assessments,
            source_root=source_root,
            validation_input_sha256=validation_input_sha256,
            prompt_version=config.prompt_version(),
        )
    except Exception as first:
        repair_user = build_source_validation_repair_user(
            system,
            user,
            raw,
            f"{type(first).__name__}: {first}",
        )
        repaired = redact_credentials(
            runner(SOURCE_VALIDATION_REPAIR_SYSTEM, repair_user)
        )
        try:
            return validate_source_response(
                parse_json_response(repaired),
                chain=chain,
                candidates=candidates,
                assessments=assessments,
                source_root=source_root,
                validation_input_sha256=validation_input_sha256,
                prompt_version=config.prompt_version(),
            )
        except Exception as second:
            raise CoverageComparisonError(
                f"{chain.project}:{chain.chain_id}: unrepaired source validation: "
                f"{type(second).__name__}: {second}"
            ) from second


def _chain_input_digest(
    *,
    chain: CoverageChain,
    candidates: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    config: SourceValidationConfig,
) -> str:
    return digest(
        {
            "prompt_version": config.prompt_version(),
            "project": chain.project,
            "revision": chain.revision,
            "chain_id": chain.chain_id,
            "semantic_ir": chain.semantic_ir,
            "candidates": list(candidates),
            "assessments": {
                key: _assessment_payload(value)
                for key, value in sorted(assessments.items())
            },
            "requirements": {
                key: dict(value) for key, value in sorted(requirements.items())
            },
            "transport": config.agent_transport,
            "model": config.model,
            "tools": config.tool_profile(),
            "batch_size": config.candidates_per_batch,
            "timeout": config.timeout,
            "max_turns": config.max_turns,
            "max_tool_calls": config.max_tool_calls,
            "strategy": config.strategy,
            "packet_prompt_version": (
                PACKET_PROMPT_VERSION
                if config.strategy == "packet-first"
                else None
            ),
            **(
                {
                    "cache_namespace": config.cache_namespace,
                    "learned_invariant_policy": True,
                }
                if config.learned_invariant_policy
                or config.cache_namespace != "source-validate"
                else {}
            ),
        }
    )


def _cache_paths(
    root: Path,
    chain: CoverageChain,
    namespace: str = "source-validate",
) -> dict[str, Path]:
    subject = f"{chain.project}-{chain.chain_id}"
    base = root / "repository" / namespace / subject
    return {
        "result": base / "result.json",
        "chat": base / "chat.json",
        "audit": base / "audit.json",
        "packet": base / "evidence-packet.json",
        "packet_chat": base / "packet-chat.json",
    }


def source_validation_checkpoint_root(out_dir: Path) -> Path:
    return out_dir.parent / f".{out_dir.name}.source-validation-checkpoint"


def clear_source_validation_checkpoint(out_dir: Path) -> None:
    shutil.rmtree(source_validation_checkpoint_root(out_dir), ignore_errors=True)


def _write_checkpoint_payload(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _checkpoint_outcome(
    checkpoint_root: Path,
    outcome: _ChainOutcome,
) -> None:
    for relative, payload in outcome.sidecars.items():
        _write_checkpoint_payload(checkpoint_root / relative, payload)


def _cache_source_files(records: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    output: dict[str, str] = {}
    for record in records:
        for evidence in record["source_evidence"]:
            prior = output.setdefault(evidence["file"], evidence["sha256"])
            if prior != evidence["sha256"]:
                raise CoverageComparisonError("conflicting source evidence digests")
    return dict(sorted(output.items()))


def _load_cache(
    *,
    prior_root: Path,
    chain: CoverageChain,
    source_root: Path,
    input_digest: str,
    candidate_ids: set[str],
    namespace: str,
    cache_version: str,
    prompt_version: str,
) -> _ChainOutcome | None:
    paths = _cache_paths(prior_root, chain, namespace)
    if not all(paths[key].is_file() for key in ("result", "chat", "audit")):
        return None
    try:
        payload = json.loads(paths["result"].read_text(encoding="utf-8"))
        if payload.get("validation_stage") == "packet" and not all(
            paths[key].is_file() for key in ("packet", "packet_chat")
        ):
            return None
        if (
            payload.get("schema_version") != cache_version
            or payload.get("input_digest") != input_digest
            or payload.get("prompt_version") != prompt_version
        ):
            return None
        source_files = payload.get("source_files")
        if not isinstance(source_files, dict):
            return None
        for relative, expected in source_files.items():
            path = (source_root / relative).resolve(strict=True)
            path.relative_to(source_root)
            if not path.is_file() or sha256_file(path) != expected:
                return None
        records = payload.get("records")
        if (
            not isinstance(records, list)
            or {
                row.get("provisional_candidate_id")
                for row in records
                if isinstance(row, dict)
            }
            != candidate_ids
        ):
            return None
        chat = json.loads(paths["chat"].read_text(encoding="utf-8"))
        audit = json.loads(paths["audit"].read_text(encoding="utf-8"))
        sidecars = {
            str(paths["result"].relative_to(prior_root)): payload,
            str(paths["chat"].relative_to(prior_root)): chat,
            str(paths["audit"].relative_to(prior_root)): audit,
        }
        if payload.get("validation_stage") == "packet":
            for key in ("packet", "packet_chat"):
                sidecars[str(paths[key].relative_to(prior_root))] = json.loads(
                    paths[key].read_text(encoding="utf-8")
                )
        return _ChainOutcome(
            records=tuple(records),
            sidecars=sidecars,
            audit=audit,
            reused=True,
            operational_failures=sum(
                bool(row.get("operational_error")) for row in records
            ),
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        return None


def _run_chain(
    *,
    chain: CoverageChain,
    candidates: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    spec: ProjectSpec,
    config: SourceValidationConfig,
    prior_root: Path,
    checkpoint_root: Path,
    runner_factory: SourceRunnerFactory,
    packet_runner: Callable[[str, str], str] | None,
) -> _ChainOutcome:
    source_root = spec.resolved().source_root
    input_digest = _chain_input_digest(
        chain=chain,
        candidates=candidates,
        assessments=assessments,
        requirements=requirements,
        config=config,
    )
    candidate_ids = {str(row["candidate_id"]) for row in candidates}
    if not config.fresh:
        for cache_root in (checkpoint_root, prior_root):
            cached = _load_cache(
                prior_root=cache_root,
                chain=chain,
                source_root=source_root,
                input_digest=input_digest,
                candidate_ids=candidate_ids,
                namespace=config.cache_namespace,
                cache_version=config.cache_version(),
                prompt_version=config.prompt_version(),
            )
            if cached is not None:
                print(
                    f"source validation {chain.project}:{chain.chain_id}: content replay",
                    file=sys.stderr,
                    flush=True,
                )
                return cached
    packet_sidecars: dict[str, Mapping[str, Any]] = {}
    effective_config = config
    if config.strategy == "packet-first":
        if packet_runner is None:
            raise CoverageComparisonError(
                "packet-first source validation requires a no-tool packet runner"
            )
        packet = build_source_validation_packet(
            chain=chain,
            candidates=candidates,
            assessments=assessments,
            requirements=requirements,
            spec=spec,
        )
        packet_user = build_packet_validation_user(packet)
        packet_raw = redact_credentials(
            packet_runner(PACKET_VALIDATION_SYSTEM, packet_user)
        )
        packet_validation_error = None
        try:
            decision, packet_payload, packet_reason = (
                parse_packet_validation_response(packet_raw, packet=packet)
            )
        except Exception as exc:
            decision = "needs-deep"
            packet_payload = None
            packet_reason = "packet response failed its deterministic contract"
            packet_validation_error = f"{type(exc).__name__}: {exc}"
        relative = _cache_paths(Path("."), chain, config.cache_namespace)
        packet_sidecars = {
            str(relative["packet"]): packet,
            str(relative["packet_chat"]): {
                "schema_version": PACKET_SCHEMA_VERSION,
                "prompt_version": PACKET_PROMPT_VERSION,
                "decision": decision,
                "reason": packet_reason,
                "validation_error": packet_validation_error,
                "exchanges": [
                    {
                        "system": PACKET_VALIDATION_SYSTEM,
                        "user": packet_user,
                        "response": packet_raw,
                    }
                ],
            },
        }
        if packet_payload is not None:
            packet_payload, packet_normalizations = normalize_packet_validation_payload(
                packet_payload, packet=packet
            )
            packet_sidecars[str(relative["packet_chat"])] = {
                **packet_sidecars[str(relative["packet_chat"])],
                "normalizations": packet_normalizations,
            }
            try:
                records = validate_source_response(
                    packet_payload,
                    chain=chain,
                    candidates=candidates,
                    assessments=assessments,
                    source_root=source_root,
                    validation_input_sha256=packet["packet_digest"],
                    prompt_version=PACKET_PROMPT_VERSION,
                )
            except Exception as exc:
                packet_validation_error = f"{type(exc).__name__}: {exc}"
                packet_sidecars[str(relative["packet_chat"])] = {
                    **packet_sidecars[str(relative["packet_chat"])],
                    "decision": "needs-deep",
                    "reason": "complete packet response failed source validation",
                    "validation_error": packet_validation_error,
                }
                packet_payload = None
            if packet_payload is None:
                records = []
        if packet_payload is not None:
            cache_payload = {
                "schema_version": config.cache_version(),
                "prompt_version": config.prompt_version(),
                "input_digest": input_digest,
                "source_files": _cache_source_files(records),
                "packet_digest": packet["packet_digest"],
                "validation_stage": "packet",
                "records": records,
            }
            sidecars = {
                str(relative["result"]): cache_payload,
                **packet_sidecars,
            }
            outcome = _ChainOutcome(
                records=tuple(records),
                sidecars=sidecars,
                audit={
                    "transport": "packet-no-tools/v1",
                    "packet_digest": packet["packet_digest"],
                    "tool_calls": 0,
                    "turns": 1,
                    "normalizations": packet_normalizations,
                },
                reused=False,
                operational_failures=0,
            )
            _checkpoint_outcome(checkpoint_root, outcome)
            return outcome
        effective_config = replace(
            config,
            allowed_source_files=tuple(
                sorted({str(row["file"]) for row in packet["source_spans"]})
            ),
        )
    runner = runner_factory(spec, effective_config)
    records: list[dict[str, Any]] = []
    failures = 0
    try:
        ordered = sorted(candidates, key=lambda row: row["candidate_id"])
        for offset in range(0, len(ordered), config.candidates_per_batch):
            batch = ordered[offset : offset + config.candidates_per_batch]
            print(
                f"source validation {chain.project}:{chain.chain_id}: "
                f"batch {offset // config.candidates_per_batch + 1}",
                file=sys.stderr,
                flush=True,
            )
            try:
                records.extend(
                    _validated_agent_call(
                        runner=runner,
                        chain=chain,
                        candidates=batch,
                        assessments=assessments,
                        requirements=requirements,
                        source_root=source_root,
                        validation_input_sha256=input_digest,
                        config=effective_config,
                    )
                )
            except Exception as exc:
                if len(batch) == 1:
                    failures += 1
                    error = f"{type(exc).__name__}: {exc}"
                    records.append(
                        _failure_record(
                            chain=chain,
                            candidate=batch[0],
                            primary=assessments[
                                str(batch[0]["requirement_id"])
                            ],
                            validation_input_sha256=input_digest,
                            error=error,
                            prompt_version=config.prompt_version(),
                        )
                    )
                    continue
                print(
                    f"source validation {chain.project}:{chain.chain_id}: "
                    "batch response invalid; retrying candidates individually",
                    file=sys.stderr,
                    flush=True,
                )
                for candidate in batch:
                    try:
                        records.extend(
                            _validated_agent_call(
                                runner=runner,
                                chain=chain,
                                candidates=[candidate],
                                assessments=assessments,
                                requirements=requirements,
                                source_root=source_root,
                                validation_input_sha256=input_digest,
                                config=effective_config,
                            )
                        )
                    except Exception as isolated_exc:
                        failures += 1
                        error = (
                            f"{type(isolated_exc).__name__}: {isolated_exc}; "
                            f"original batch error: {type(exc).__name__}: {exc}"
                        )
                        records.append(
                            _failure_record(
                                chain=chain,
                                candidate=candidate,
                                primary=assessments[
                                    str(candidate["requirement_id"])
                                ],
                                validation_input_sha256=input_digest,
                                error=error,
                                prompt_version=config.prompt_version(),
                            )
                        )
        chat = _versioned_agent_sidecar(
            _runner_payload(runner, "chat_payload"),
            schema_version=AGENT_CHAT_SCHEMA_VERSION,
        )
        audit = _versioned_agent_sidecar(
            _runner_payload(runner, "audit_payload"),
            schema_version=AGENT_AUDIT_SCHEMA_VERSION,
        )
    finally:
        _close_runner(runner)
    records.sort(key=lambda row: row["provisional_candidate_id"])
    if {row["provisional_candidate_id"] for row in records} != candidate_ids:
        raise CoverageComparisonError(
            f"{chain.project}:{chain.chain_id}: source validations do not partition candidates"
        )
    cache_payload = {
        "schema_version": config.cache_version(),
        "prompt_version": config.prompt_version(),
        "input_digest": input_digest,
        "source_files": _cache_source_files(records),
        "records": records,
    }
    relative = _cache_paths(Path("."), chain, config.cache_namespace)
    sidecars = {
        str(relative["result"]): cache_payload,
        str(relative["chat"]): chat,
        str(relative["audit"]): audit,
        **packet_sidecars,
    }
    outcome = _ChainOutcome(
        records=tuple(records),
        sidecars=sidecars,
        audit=audit,
        reused=False,
        operational_failures=failures,
    )
    _checkpoint_outcome(checkpoint_root, outcome)
    return outcome


def run_source_validation(
    *,
    chains: Mapping[tuple[str, str], CoverageChain],
    provisional_candidates: Sequence[Mapping[str, Any]],
    assessments: Sequence[Mapping[str, Any]],
    specs: Sequence[ProjectSpec],
    prior_root: Path,
    config: SourceValidationConfig,
    runner_factory: SourceRunnerFactory | None = None,
    packet_runner: Callable[[str, str], str] | None = None,
    extra_requirements: Mapping[tuple[str, str, str], Mapping[str, Any]] | None = None,
) -> SourceValidationRun:
    """Validate every provisional candidate and retain a complete audit partition."""

    config.validate()
    if not provisional_candidates:
        return SourceValidationRun(
            records=(),
            sidecars={},
            transport={
                "transport": SOURCE_VALIDATION_TRANSPORT_VERSION,
                "prompt_version": config.prompt_version(),
                "available_tools": config.tool_profile(),
                "sessions": 0,
                "token_usage": aggregate_token_usage([]),
            },
            provisional_count=0,
            confirmed_count=0,
            refuted_count=0,
            unknown_count=0,
            operational_failures=0,
            reused_chains=0,
            generated_chains=0,
        )
    spec_by_project = {spec.project_id: spec.resolved() for spec in specs}
    assessment_by_key = {
        (str(row["project"]), str(row["chain_id"]), str(row["requirement_id"])): row
        for row in assessments
    }
    candidates_by_chain: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    candidate_ids: list[str] = []
    for candidate in provisional_candidates:
        key = (str(candidate["project"]), str(candidate["chain_id"]))
        if key not in chains:
            raise CoverageComparisonError(
                "provisional candidate references unknown chain"
            )
        if key[0] not in spec_by_project:
            raise CoverageComparisonError(
                f"source validation has no ProjectSpec for {key[0]}"
            )
        candidates_by_chain.setdefault(key, []).append(candidate)
        candidate_ids.append(str(candidate["candidate_id"]))
    if len(candidate_ids) != len(set(candidate_ids)):
        raise CoverageComparisonError("duplicate provisional candidate IDs")
    factory = runner_factory or default_source_runner_factory
    checkpoint_root = source_validation_checkpoint_root(prior_root)
    bound_extra_requirements = extra_requirements or {}

    def task(key: tuple[str, str]) -> _ChainOutcome:
        chain = chains[key]
        selected = candidates_by_chain[key]
        selected_assessments = {
            str(candidate["requirement_id"]): assessment_by_key[
                (key[0], key[1], str(candidate["requirement_id"]))
            ]
            for candidate in selected
        }
        requirements: dict[str, Mapping[str, Any]] = {
            str(row["requirement_id"]): row for row in chain.oracle["requirements"]
        }
        for candidate in selected:
            requirement_id = str(candidate["requirement_id"])
            if requirement_id in requirements:
                continue
            extra = bound_extra_requirements.get((key[0], key[1], requirement_id))
            if extra is None:
                raise CoverageComparisonError(
                    f"missing capability requirement for {key}:{requirement_id}"
                )
            requirements[requirement_id] = extra
        return _run_chain(
            chain=chain,
            candidates=selected,
            assessments=selected_assessments,
            requirements=requirements,
            spec=spec_by_project[key[0]],
            config=config,
            prior_root=prior_root,
            checkpoint_root=checkpoint_root,
            runner_factory=factory,
            packet_runner=packet_runner,
        )

    outcomes: dict[tuple[str, str], _ChainOutcome] = {}
    ordered_keys = sorted(candidates_by_chain)
    with ThreadPoolExecutor(max_workers=min(config.jobs, len(ordered_keys))) as pool:
        futures = {pool.submit(task, key): key for key in ordered_keys}
        for future in as_completed(futures):
            key = futures[future]
            try:
                outcomes[key] = future.result()
            except Exception as exc:
                if "live source-agent transport is disabled" in str(exc):
                    raise CoverageComparisonError(str(exc)) from exc
                chain = chains[key]
                selected = candidates_by_chain[key]
                input_digest = _chain_input_digest(
                    chain=chain,
                    candidates=selected,
                    assessments={
                        str(candidate["requirement_id"]): assessment_by_key[
                            (key[0], key[1], str(candidate["requirement_id"]))
                        ]
                        for candidate in selected
                    },
                    requirements={
                        str(candidate["requirement_id"]): (
                            next(
                                row
                                for row in chain.oracle["requirements"]
                                if row["requirement_id"]
                                == candidate["requirement_id"]
                            )
                            if str(candidate["requirement_id"]).startswith("R-")
                            else bound_extra_requirements[
                                (key[0], key[1], str(candidate["requirement_id"]))
                            ]
                        )
                        for candidate in selected
                    },
                    config=config,
                )
                error = f"{type(exc).__name__}: {exc}"
                failed = tuple(
                    _failure_record(
                        chain=chain,
                        candidate=candidate,
                        primary=assessment_by_key[
                            (key[0], key[1], str(candidate["requirement_id"]))
                        ],
                        validation_input_sha256=input_digest,
                        error=error,
                        prompt_version=config.prompt_version(),
                    )
                    for candidate in selected
                )
                relative = _cache_paths(Path("."), chain, config.cache_namespace)
                audit = {"error": error, "token_usage": aggregate_token_usage([])}
                sidecars = {
                    str(relative["result"]): {
                        "schema_version": config.cache_version(),
                        "prompt_version": config.prompt_version(),
                        "input_digest": input_digest,
                        "source_files": {},
                        "records": list(failed),
                    },
                    str(relative["chat"]): {
                        "schema_version": AGENT_CHAT_SCHEMA_VERSION,
                        "error": error,
                        "turns": [],
                    },
                    str(relative["audit"]): {
                        **audit,
                        "schema_version": AGENT_AUDIT_SCHEMA_VERSION,
                    },
                }
                outcomes[key] = _ChainOutcome(
                    records=failed,
                    sidecars=sidecars,
                    audit=audit,
                    reused=False,
                    operational_failures=len(failed),
                )
    records = tuple(
        sorted(
            (record for key in ordered_keys for record in outcomes[key].records),
            key=lambda row: row["provisional_candidate_id"],
        )
    )
    if {row["provisional_candidate_id"] for row in records} != set(candidate_ids):
        raise CoverageComparisonError(
            "source validations do not exactly cover provisional candidates"
        )
    sidecars: dict[str, Mapping[str, Any]] = {}
    for key in ordered_keys:
        for relative, payload in outcomes[key].sidecars.items():
            if relative in sidecars and sidecars[relative] != payload:
                raise CoverageComparisonError("source-validation sidecar collision")
            sidecars[relative] = payload
    usages = [outcomes[key].audit.get("token_usage") for key in ordered_keys]
    if any(
        contains_credentials(canonical_json(row))
        for row in [*records, *sidecars.values()]
    ):
        raise CoverageComparisonError("credential-shaped data in source validation")
    confirmed = sum(row["disposition"] == "confirmed" for row in records)
    refuted = sum(row["disposition"] == "refuted" for row in records)
    unknown = sum(row["disposition"] == "unknown" for row in records)
    return SourceValidationRun(
        records=records,
        sidecars=dict(sorted(sidecars.items())),
        transport={
            "transport": SOURCE_VALIDATION_TRANSPORT_VERSION,
            "prompt_version": config.prompt_version(),
            "model": config.model,
            "agent_transport": config.agent_transport,
            "available_tools": config.tool_profile(),
            "source_root_policy": "source-root-pretool/v1",
            "cache_namespace": config.cache_namespace,
            "jobs_requested": config.jobs,
            "jobs_effective": min(config.jobs, len(ordered_keys)),
            "sessions": len(ordered_keys),
            "reused_sessions": sum(outcomes[key].reused for key in ordered_keys),
            "generated_sessions": sum(not outcomes[key].reused for key in ordered_keys),
            "token_usage": aggregate_token_usage(usages),
        },
        provisional_count=len(provisional_candidates),
        confirmed_count=confirmed,
        refuted_count=refuted,
        unknown_count=unknown,
        operational_failures=sum(
            outcomes[key].operational_failures for key in ordered_keys
        ),
        reused_chains=sum(outcomes[key].reused for key in ordered_keys),
        generated_chains=sum(not outcomes[key].reused for key in ordered_keys),
    )


def deterministic_precision_sample(
    provisional_candidates: Sequence[Mapping[str, Any]],
    *,
    sample_size: int = 100,
) -> list[dict[str, Any]]:
    """Select a deterministic project/failure-mode proportional blind audit sample."""

    if sample_size < 1:
        raise CoverageComparisonError("precision sample size must be positive")
    total = len(provisional_candidates)
    if not total:
        return []
    selected_size = min(sample_size, total)
    strata: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for candidate in provisional_candidates:
        key = (str(candidate["project"]), str(candidate["failure_mode"]))
        strata.setdefault(key, []).append(candidate)
    allocations: dict[tuple[str, str], int] = {}
    remainders: list[tuple[float, tuple[str, str]]] = []
    allocated = 0
    for key, rows in sorted(strata.items()):
        exact = selected_size * len(rows) / total
        base = min(len(rows), int(exact))
        allocations[key] = base
        allocated += base
        remainders.append((exact - base, key))
    for _remainder, key in sorted(remainders, key=lambda row: (-row[0], row[1])):
        if allocated >= selected_size:
            break
        if allocations[key] < len(strata[key]):
            allocations[key] += 1
            allocated += 1
    chosen: list[Mapping[str, Any]] = []
    for key, rows in sorted(strata.items()):
        ordered = sorted(
            rows,
            key=lambda row: digest(
                ["coverage-source-validation-precision-v1", row["candidate_id"]]
            ),
        )
        chosen.extend(ordered[: allocations[key]])
    chosen.sort(key=lambda row: row["candidate_id"])
    sample = [
        {
            "schema_version": PRECISION_AUDIT_SCHEMA_VERSION,
            "sample_ordinal": number,
            "candidate_id": row["candidate_id"],
            "project": row["project"],
            "chain_id": row["chain_id"],
            "requirement_id": row["requirement_id"],
            "requirement_source": row.get("requirement_source", "group-oracle"),
            "failure_mode": row["failure_mode"],
            "blind_adjudication": None,
            "adjudication_reason": None,
            "source_evidence": [],
        }
        for number, row in enumerate(chosen, 1)
    ]
    schema = json.loads(
        (SCHEMA_DIR / "coverage-precision-audit-sample-v7.schema.json").read_text(
            encoding="utf-8"
        )
    )
    for row in sample:
        validate_schema(instance=row, schema=schema)
    return sample


def validate_source_validation_artifacts(
    *,
    provisional_candidates: Sequence[Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
) -> None:
    """Require a schema-valid, exact validation partition of provisional candidates."""

    schema = json.loads(
        (SCHEMA_DIR / "coverage-candidate-source-validation-v7.schema.json").read_text(
            encoding="utf-8"
        )
    )
    for record in records:
        validate_schema(instance=record, schema=schema)
    provisional_ids = [str(row["candidate_id"]) for row in provisional_candidates]
    record_ids = [str(row["provisional_candidate_id"]) for row in records]
    if len(provisional_ids) != len(set(provisional_ids)):
        raise CoverageComparisonError("duplicate provisional candidate IDs")
    if len(record_ids) != len(set(record_ids)) or set(record_ids) != set(
        provisional_ids
    ):
        raise CoverageComparisonError(
            "source validations do not exactly partition provisional candidates"
        )
    candidate_by_id = {str(row["candidate_id"]): row for row in provisional_candidates}
    for record in records:
        candidate = candidate_by_id[str(record["provisional_candidate_id"])]
        primary = record["primary_assessment"]
        final = record["final_assessment"]
        if (
            primary["requirement_id"] != candidate["requirement_id"]
            or primary["decision"] != candidate["failure_mode"]
            or record["primary_failure_mode"] != candidate["failure_mode"]
            or record["requirement_source"]
            != candidate.get("requirement_source", "group-oracle")
        ):
            raise CoverageComparisonError(
                "source-validation primary assessment does not match candidate"
            )
        expected_disposition = (
            "confirmed"
            if final["decision"] in {"wrong-check", "missing-check"}
            else "refuted"
            if final["decision"] in {"covered", "not-applicable"}
            else "unknown"
        )
        if record["disposition"] != expected_disposition:
            raise CoverageComparisonError(
                "source-validation disposition contradicts final assessment"
            )
