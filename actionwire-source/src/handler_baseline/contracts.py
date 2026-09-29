"""Contracts, validation, identities, and token accounting for the baseline."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.gate_semantics.agent_sdk import aggregate_token_usage, normalize_token_usage


TRIAL_SCHEMA_VERSION = "claude-handler-baseline-trial/v1"
FINDING_SCHEMA_VERSION = "claude-handler-baseline-finding/v1"
VULNERABILITY_SCHEMA_VERSION = "claude-handler-baseline-vulnerability/v1"
MANIFEST_SCHEMA_VERSION = "claude-handler-baseline-manifest/v1"
GROUND_TRUTH_SCHEMA_VERSION = "claude-handler-baseline-ground-truth/v1"
GROUND_TRUTH_MANIFEST_VERSION = "claude-handler-baseline-ground-truth-manifest/v1"
TRANSPORT_VERSION = "claude-code-bwrap/v1"

CREDENTIAL_RE = re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{10,}\b")
TRIAL_ID_RE = re.compile(r"^HB-[0-9a-f]{16}$")
FINDING_ID_RE = re.compile(r"^HBF-[0-9a-f]{16}$")
VULNERABILITY_ID_RE = re.compile(r"^HBV-[0-9a-f]{16}$")

ALL_FINDINGS_POLICY = "all-findings"
MOST_CREDIBLE_VULNERABILITIES_POLICY = "most-credible-vulnerabilities"
REPORT_POLICIES = (ALL_FINDINGS_POLICY, MOST_CREDIBLE_VULNERABILITIES_POLICY)


class BaselineError(ValueError):
    """Raised when an experiment input or artifact violates its contract."""


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contains_credentials(value: str) -> bool:
    return CREDENTIAL_RE.search(value) is not None


def redact_credentials(value: str) -> str:
    return CREDENTIAL_RE.sub("[REDACTED_CREDENTIAL]", value)


def finding_response_json_schema() -> dict[str, Any]:
    evidence = {
        "type": "object",
        "additionalProperties": False,
        "required": ["file", "line_start", "line_end", "quote"],
        "properties": {
            "file": {"type": "string", "minLength": 1},
            "line_start": {"type": "integer", "minimum": 1},
            "line_end": {"type": "integer", "minimum": 1},
            "quote": {"type": "string", "minLength": 1},
        },
    }
    gate = {
        "type": "object",
        "additionalProperties": False,
        "required": ["location", "semantics", "evidence"],
        "properties": {
            "location": {"type": "string", "minLength": 1},
            "semantics": {"type": "string", "minLength": 1},
            "evidence": {"type": "array", "minItems": 1, "items": evidence},
        },
    }
    finding = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "failure_mode",
            "controlled_input",
            "sink_capability",
            "sink_location",
            "sink_argument",
            "call_path",
            "relevant_gates",
            "uncovered_requirement",
            "trigger_property",
            "reason",
            "confidence",
            "evidence",
        ],
        "properties": {
            "failure_mode": {"enum": ["wrong-check", "missing-check"]},
            "controlled_input": {"type": "string", "minLength": 1},
            "sink_capability": {"type": "string", "minLength": 1},
            "sink_location": {"type": "string", "minLength": 1},
            "sink_argument": {"type": "string", "minLength": 1},
            "call_path": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "relevant_gates": {"type": "array", "items": gate},
            "uncovered_requirement": {"type": "string", "minLength": 1},
            "trigger_property": {"type": "string", "minLength": 1},
            "reason": {"type": "string", "minLength": 1},
            "confidence": {"enum": ["high", "medium", "low"]},
            "evidence": {"type": "array", "minItems": 1, "items": evidence},
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["trial_id", "verdict", "findings", "negative_evidence", "uncertainty"],
        "properties": {
            "trial_id": {"type": "string", "pattern": r"^HB-[0-9a-f]{16}$"},
            "verdict": {"enum": ["findings", "no-finding", "unknown"]},
            "findings": {"type": "array", "items": finding},
            "negative_evidence": {"type": "array", "items": evidence},
            "uncertainty": {"type": ["string", "null"]},
        },
        "allOf": [
            {
                "if": {"properties": {"verdict": {"const": "findings"}}},
                "then": {
                    "properties": {
                        "findings": {"type": "array", "minItems": 1},
                        "uncertainty": {"type": "null"},
                    }
                },
            },
            {
                "if": {"properties": {"verdict": {"const": "no-finding"}}},
                "then": {
                    "properties": {
                        "findings": {"type": "array", "maxItems": 0},
                        "negative_evidence": {"type": "array", "minItems": 1},
                        "uncertainty": {"type": "null"},
                    }
                },
            },
            {
                "if": {"properties": {"verdict": {"const": "unknown"}}},
                "then": {
                    "properties": {
                        "findings": {"type": "array", "maxItems": 0},
                        "uncertainty": {"type": "string", "minLength": 1},
                    }
                },
            },
        ],
    }


def credible_vulnerability_response_json_schema() -> dict[str, Any]:
    evidence = {
        "type": "object",
        "additionalProperties": False,
        "required": ["file", "line_start", "line_end", "quote"],
        "properties": {
            "file": {"type": "string", "minLength": 1},
            "line_start": {"type": "integer", "minimum": 1},
            "line_end": {"type": "integer", "minimum": 1},
            "quote": {"type": "string", "minLength": 1},
        },
    }
    gate = {
        "type": "object",
        "additionalProperties": False,
        "required": ["location", "semantics", "evidence"],
        "properties": {
            "location": {"type": "string", "minLength": 1},
            "semantics": {"type": "string", "minLength": 1},
            "evidence": {"type": "array", "minItems": 1, "items": evidence},
        },
    }
    security_boundary = {
        "type": "object",
        "additionalProperties": False,
        "required": ["protected_asset", "trust_boundary", "requirement_source", "evidence"],
        "properties": {
            "protected_asset": {"type": "string", "minLength": 1},
            "trust_boundary": {"type": "string", "minLength": 1},
            "requirement_source": {"type": "string", "minLength": 1},
            "evidence": {"type": "array", "minItems": 1, "items": evidence},
        },
    }
    capability_delta = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "intended_capability",
            "unauthorized_capability",
            "why_not_equivalent",
            "evidence",
        ],
        "properties": {
            "intended_capability": {"type": "string", "minLength": 1},
            "unauthorized_capability": {"type": "string", "minLength": 1},
            "why_not_equivalent": {"type": "string", "minLength": 1},
            "evidence": {"type": "array", "minItems": 1, "items": evidence},
        },
    }
    credibility_fields = (
        "model_control_proven",
        "handler_reachability_proven",
        "security_boundary_proven",
        "gate_defect_proven",
        "trigger_effect_proven",
        "not_intended_behavior",
        "no_equivalent_capability",
        "realistic_preconditions",
    )
    vulnerability = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "rank",
            "failure_mode",
            "controlled_input",
            "sink_capability",
            "sink_location",
            "sink_argument",
            "call_path",
            "relevant_gates",
            "uncovered_requirement",
            "trigger_property",
            "realistic_preconditions",
            "security_boundary",
            "capability_delta",
            "credibility_checks",
            "selection_reason",
            "reason",
            "confidence",
            "evidence",
        ],
        "properties": {
            "rank": {"type": "integer", "minimum": 1, "maximum": 2},
            "failure_mode": {"enum": ["wrong-check", "missing-check"]},
            "controlled_input": {"type": "string", "minLength": 1},
            "sink_capability": {"type": "string", "minLength": 1},
            "sink_location": {"type": "string", "minLength": 1},
            "sink_argument": {"type": "string", "minLength": 1},
            "call_path": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "relevant_gates": {"type": "array", "items": gate},
            "uncovered_requirement": {"type": "string", "minLength": 1},
            "trigger_property": {"type": "string", "minLength": 1},
            "realistic_preconditions": {"type": "string", "minLength": 1},
            "security_boundary": security_boundary,
            "capability_delta": capability_delta,
            "credibility_checks": {
                "type": "object",
                "additionalProperties": False,
                "required": list(credibility_fields),
                "properties": {name: {"const": True} for name in credibility_fields},
            },
            "selection_reason": {"type": "string", "minLength": 1},
            "reason": {"type": "string", "minLength": 1},
            "confidence": {"const": "high"},
            "evidence": {"type": "array", "minItems": 1, "items": evidence},
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "trial_id",
            "verdict",
            "vulnerabilities",
            "negative_evidence",
            "uncertainty",
        ],
        "properties": {
            "trial_id": {"type": "string", "pattern": r"^HB-[0-9a-f]{16}$"},
            "verdict": {"enum": ["vulnerabilities", "no-vulnerability", "unknown"]},
            "vulnerabilities": {
                "type": "array",
                "minItems": 0,
                "maxItems": 2,
                "items": vulnerability,
            },
            "negative_evidence": {"type": "array", "items": evidence},
            "uncertainty": {"type": ["string", "null"]},
        },
        "allOf": [
            {
                "if": {"properties": {"verdict": {"const": "vulnerabilities"}}},
                "then": {
                    "properties": {
                        "vulnerabilities": {"type": "array", "minItems": 1, "maxItems": 2},
                        "uncertainty": {"type": "null"},
                    }
                },
            },
            {
                "if": {"properties": {"verdict": {"const": "no-vulnerability"}}},
                "then": {
                    "properties": {
                        "vulnerabilities": {"type": "array", "maxItems": 0},
                        "negative_evidence": {"type": "array", "minItems": 1},
                        "uncertainty": {"type": "null"},
                    }
                },
            },
            {
                "if": {"properties": {"verdict": {"const": "unknown"}}},
                "then": {
                    "properties": {
                        "vulnerabilities": {"type": "array", "maxItems": 0},
                        "uncertainty": {"type": "string", "minLength": 1},
                    }
                },
            },
        ],
    }


def response_json_schema(report_policy: str = ALL_FINDINGS_POLICY) -> dict[str, Any]:
    if report_policy == ALL_FINDINGS_POLICY:
        return finding_response_json_schema()
    if report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY:
        return credible_vulnerability_response_json_schema()
    raise BaselineError(f"unknown report policy: {report_policy}")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BaselineError(f"{field} must be a non-empty string")
    return " ".join(value.split())


def _validate_evidence(
    rows: object,
    *,
    source_root: Path,
    field: str,
    require_nonempty: bool = True,
    allow_adjacent_range_repair: bool = False,
) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or (require_nonempty and not rows):
        raise BaselineError(f"{field} must be a non-empty array")
    output: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict) or set(raw) != {"file", "line_start", "line_end", "quote"}:
            raise BaselineError(f"{field}[{index}] has unexpected fields")
        relative = Path(_text(raw["file"], f"{field}[{index}].file"))
        if relative.is_absolute():
            raise BaselineError(f"{field}[{index}].file must be relative to /workspace")
        try:
            path = (source_root / relative).resolve()
            path.relative_to(source_root.resolve())
        except (OSError, RuntimeError, ValueError) as exc:
            raise BaselineError(f"{field}[{index}].file escapes source root") from exc
        if not path.is_file():
            raise BaselineError(f"{field}[{index}].file does not exist: {relative}")
        start, end = raw["line_start"], raw["line_end"]
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 1
            or end < start
        ):
            raise BaselineError(f"{field}[{index}] has invalid line range")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if end > len(lines):
            raise BaselineError(f"{field}[{index}] line range exceeds file")
        quote = _text(raw["quote"], f"{field}[{index}].quote")
        actual = " ".join("\n".join(lines[start - 1 : end]).split())
        if " ".join(quote.split()) not in actual:
            repaired = False
            if allow_adjacent_range_repair:
                for radius in range(1, 4):
                    expanded_start = max(1, start - radius)
                    expanded_end = min(len(lines), end + radius)
                    expanded = " ".join(
                        "\n".join(lines[expanded_start - 1 : expanded_end]).split()
                    )
                    if " ".join(quote.split()) in expanded:
                        start, end = expanded_start, expanded_end
                        repaired = True
                        break
            if not repaired:
                raise BaselineError(f"{field}[{index}].quote is not present in cited lines")
        output.append(
            {"file": relative.as_posix(), "line_start": start, "line_end": end, "quote": quote}
        )
    return output


def validate_finding_response(
    value: Mapping[str, Any], *, trial_id: str, source_root: Path
) -> dict[str, Any]:
    expected = {"trial_id", "verdict", "findings", "negative_evidence", "uncertainty"}
    if set(value) != expected or value.get("trial_id") != trial_id:
        raise BaselineError("response fields or trial identity mismatch")
    verdict = value.get("verdict")
    if verdict not in {"findings", "no-finding", "unknown"}:
        raise BaselineError("invalid verdict")
    raw_findings = value.get("findings")
    if not isinstance(raw_findings, list):
        raise BaselineError("findings must be an array")
    uncertainty = value.get("uncertainty")
    if uncertainty is not None:
        uncertainty = _text(uncertainty, "uncertainty")
    raw_negative = value.get("negative_evidence")
    if not isinstance(raw_negative, list):
        raise BaselineError("negative_evidence must be an array")
    # Negative evidence is a proof obligation only for no-finding. Claude often
    # supplies supplementary negative citations alongside positive findings; they
    # do not support those findings and must not invalidate otherwise strict finding
    # evidence. Normalize such unused material away.
    negative = (
        _validate_evidence(
            raw_negative,
            source_root=source_root,
            field="negative_evidence",
            require_nonempty=True,
        )
        if verdict == "no-finding"
        else []
    )
    if verdict == "findings" and not raw_findings:
        raise BaselineError("findings verdict requires at least one finding")
    if verdict != "findings" and raw_findings:
        raise BaselineError("non-finding verdict must not contain findings")
    if verdict == "unknown" and uncertainty is None:
        raise BaselineError("unknown verdict requires uncertainty")
    if verdict != "unknown" and uncertainty is not None:
        raise BaselineError("only unknown verdict may contain uncertainty")

    normalized: list[dict[str, Any]] = []
    finding_fields = {
        "failure_mode", "controlled_input", "sink_capability", "sink_location",
        "sink_argument", "call_path", "relevant_gates", "uncovered_requirement",
        "trigger_property", "reason", "confidence", "evidence",
    }
    for number, raw in enumerate(raw_findings, 1):
        if not isinstance(raw, dict) or set(raw) != finding_fields:
            raise BaselineError(f"finding {number} has unexpected fields")
        mode = raw["failure_mode"]
        if mode not in {"wrong-check", "missing-check"}:
            raise BaselineError(f"finding {number} has invalid failure_mode")
        gates = raw["relevant_gates"]
        if not isinstance(gates, list):
            raise BaselineError(f"finding {number}.relevant_gates must be an array")
        if (mode == "wrong-check") != bool(gates):
            raise BaselineError(
                f"finding {number}: wrong-check requires gates and missing-check forbids them"
            )
        normalized_gates: list[dict[str, Any]] = []
        for gate_number, gate in enumerate(gates, 1):
            if not isinstance(gate, dict) or set(gate) != {"location", "semantics", "evidence"}:
                raise BaselineError(f"finding {number}.gate {gate_number} has unexpected fields")
            normalized_gates.append(
                {
                    "location": _text(gate["location"], "gate.location"),
                    "semantics": _text(gate["semantics"], "gate.semantics"),
                    "evidence": _validate_evidence(
                        gate["evidence"], source_root=source_root,
                        field=f"finding[{number}].gate[{gate_number}].evidence",
                    ),
                }
            )
        call_path = raw["call_path"]
        if not isinstance(call_path, list) or not call_path:
            raise BaselineError(f"finding {number}.call_path must be non-empty")
        confidence = raw["confidence"]
        if confidence not in {"high", "medium", "low"}:
            raise BaselineError(f"finding {number} has invalid confidence")
        row = {
            "failure_mode": mode,
            "controlled_input": _text(raw["controlled_input"], "controlled_input"),
            "sink_capability": _text(raw["sink_capability"], "sink_capability"),
            "sink_location": _text(raw["sink_location"], "sink_location"),
            "sink_argument": _text(raw["sink_argument"], "sink_argument"),
            "call_path": [_text(item, "call_path item") for item in call_path],
            "relevant_gates": normalized_gates,
            "uncovered_requirement": _text(raw["uncovered_requirement"], "uncovered_requirement"),
            "trigger_property": _text(raw["trigger_property"], "trigger_property"),
            "reason": _text(raw["reason"], "reason"),
            "confidence": confidence,
            "evidence": _validate_evidence(
                raw["evidence"], source_root=source_root,
                field=f"finding[{number}].evidence",
            ),
        }
        row["finding_id"] = "HBF-" + digest([trial_id, row])[:16]
        normalized.append(row)
    if len({row["finding_id"] for row in normalized}) != len(normalized):
        raise BaselineError("response contains duplicate findings")
    return {
        "trial_id": trial_id,
        "verdict": verdict,
        "findings": normalized,
        "negative_evidence": negative,
        "uncertainty": uncertainty,
    }


def _validate_gate_rows(
    rows: object, *, source_root: Path, field: str
) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise BaselineError(f"{field} must be an array")
    output: list[dict[str, Any]] = []
    for number, gate in enumerate(rows, 1):
        if not isinstance(gate, dict) or set(gate) != {"location", "semantics", "evidence"}:
            raise BaselineError(f"{field}[{number}] has unexpected fields")
        output.append(
            {
                "location": _text(gate["location"], f"{field}[{number}].location"),
                "semantics": _text(gate["semantics"], f"{field}[{number}].semantics"),
                "evidence": _validate_evidence(
                    gate["evidence"],
                    source_root=source_root,
                    field=f"{field}[{number}].evidence",
                    allow_adjacent_range_repair=True,
                ),
            }
        )
    return output


def _validate_proof_object(
    raw: object,
    *,
    text_fields: set[str],
    source_root: Path,
    field: str,
) -> dict[str, Any]:
    expected = {*text_fields, "evidence"}
    if not isinstance(raw, dict) or set(raw) != expected:
        raise BaselineError(f"{field} has unexpected fields")
    return {
        **{name: _text(raw[name], f"{field}.{name}") for name in sorted(text_fields)},
        "evidence": _validate_evidence(
            raw["evidence"],
            source_root=source_root,
            field=f"{field}.evidence",
            allow_adjacent_range_repair=True,
        ),
    }


def validate_credible_vulnerability_response(
    value: Mapping[str, Any], *, trial_id: str, source_root: Path
) -> dict[str, Any]:
    expected = {"trial_id", "verdict", "vulnerabilities", "negative_evidence", "uncertainty"}
    if set(value) != expected or value.get("trial_id") != trial_id:
        raise BaselineError("response fields or trial identity mismatch")
    verdict = value.get("verdict")
    if verdict not in {"vulnerabilities", "no-vulnerability", "unknown"}:
        raise BaselineError("invalid credible-vulnerability verdict")
    raw_vulnerabilities = value.get("vulnerabilities")
    if not isinstance(raw_vulnerabilities, list):
        raise BaselineError("vulnerabilities must be an array")
    if len(raw_vulnerabilities) > 2:
        raise BaselineError("at most two vulnerabilities may be reported")
    if verdict == "vulnerabilities" and not raw_vulnerabilities:
        raise BaselineError("vulnerabilities verdict requires one or two vulnerabilities")
    if verdict != "vulnerabilities" and raw_vulnerabilities:
        raise BaselineError("non-vulnerability verdict must not contain vulnerabilities")

    uncertainty = value.get("uncertainty")
    if uncertainty is not None:
        uncertainty = _text(uncertainty, "uncertainty")
    if verdict == "unknown" and uncertainty is None:
        raise BaselineError("unknown verdict requires uncertainty")
    if verdict != "unknown" and uncertainty is not None:
        raise BaselineError("only unknown verdict may contain uncertainty")
    raw_negative = value.get("negative_evidence")
    if not isinstance(raw_negative, list):
        raise BaselineError("negative_evidence must be an array")
    negative = (
        _validate_evidence(
            raw_negative,
            source_root=source_root,
            field="negative_evidence",
            require_nonempty=True,
            allow_adjacent_range_repair=True,
        )
        if verdict == "no-vulnerability"
        else []
    )

    vulnerability_fields = {
        "rank",
        "failure_mode",
        "controlled_input",
        "sink_capability",
        "sink_location",
        "sink_argument",
        "call_path",
        "relevant_gates",
        "uncovered_requirement",
        "trigger_property",
        "realistic_preconditions",
        "security_boundary",
        "capability_delta",
        "credibility_checks",
        "selection_reason",
        "reason",
        "confidence",
        "evidence",
    }
    credibility_fields = {
        "model_control_proven",
        "handler_reachability_proven",
        "security_boundary_proven",
        "gate_defect_proven",
        "trigger_effect_proven",
        "not_intended_behavior",
        "no_equivalent_capability",
        "realistic_preconditions",
    }
    normalized: list[dict[str, Any]] = []
    for number, raw in enumerate(raw_vulnerabilities, 1):
        if not isinstance(raw, dict) or set(raw) != vulnerability_fields:
            raise BaselineError(f"vulnerability {number} has unexpected fields")
        rank = raw["rank"]
        if not isinstance(rank, int) or isinstance(rank, bool) or rank != number:
            raise BaselineError("vulnerability ranks must be contiguous from 1")
        if raw["confidence"] != "high":
            raise BaselineError("credible vulnerabilities must have high confidence")
        mode = raw["failure_mode"]
        if mode not in {"wrong-check", "missing-check"}:
            raise BaselineError(f"vulnerability {number} has invalid failure_mode")
        gates = _validate_gate_rows(
            raw["relevant_gates"],
            source_root=source_root,
            field=f"vulnerability[{number}].relevant_gates",
        )
        if (mode == "wrong-check") != bool(gates):
            raise BaselineError(
                f"vulnerability {number}: wrong-check requires gates and missing-check forbids them"
            )
        call_path = raw["call_path"]
        if not isinstance(call_path, list) or not call_path:
            raise BaselineError(f"vulnerability {number}.call_path must be non-empty")
        checks = raw["credibility_checks"]
        if not isinstance(checks, dict) or set(checks) != credibility_fields:
            raise BaselineError(f"vulnerability {number}.credibility_checks mismatch")
        if any(checks[name] is not True for name in credibility_fields):
            raise BaselineError(
                f"vulnerability {number} has an unproven credibility obligation"
            )
        boundary = _validate_proof_object(
            raw["security_boundary"],
            text_fields={"protected_asset", "trust_boundary", "requirement_source"},
            source_root=source_root,
            field=f"vulnerability[{number}].security_boundary",
        )
        delta = _validate_proof_object(
            raw["capability_delta"],
            text_fields={
                "intended_capability",
                "unauthorized_capability",
                "why_not_equivalent",
            },
            source_root=source_root,
            field=f"vulnerability[{number}].capability_delta",
        )
        row = {
            "rank": rank,
            "failure_mode": mode,
            "controlled_input": _text(raw["controlled_input"], "controlled_input"),
            "sink_capability": _text(raw["sink_capability"], "sink_capability"),
            "sink_location": _text(raw["sink_location"], "sink_location"),
            "sink_argument": _text(raw["sink_argument"], "sink_argument"),
            "call_path": [_text(item, "call_path item") for item in call_path],
            "relevant_gates": gates,
            "uncovered_requirement": _text(
                raw["uncovered_requirement"], "uncovered_requirement"
            ),
            "trigger_property": _text(raw["trigger_property"], "trigger_property"),
            "realistic_preconditions": _text(
                raw["realistic_preconditions"], "realistic_preconditions"
            ),
            "security_boundary": boundary,
            "capability_delta": delta,
            "credibility_checks": {name: True for name in sorted(credibility_fields)},
            "selection_reason": _text(raw["selection_reason"], "selection_reason"),
            "reason": _text(raw["reason"], "reason"),
            "confidence": "high",
            "evidence": _validate_evidence(
                raw["evidence"],
                source_root=source_root,
                field=f"vulnerability[{number}].evidence",
                allow_adjacent_range_repair=True,
            ),
        }
        identity = {
            "failure_mode": row["failure_mode"],
            "controlled_input": row["controlled_input"],
            "sink_capability": row["sink_capability"],
            "sink_location": row["sink_location"],
            "sink_argument": row["sink_argument"],
            "call_path": row["call_path"],
            "relevant_gates": [
                {"location": gate["location"], "semantics": gate["semantics"]}
                for gate in row["relevant_gates"]
            ],
            "uncovered_requirement": row["uncovered_requirement"],
            "security_boundary": {
                key: boundary[key]
                for key in ("protected_asset", "trust_boundary", "requirement_source")
            },
            "capability_delta": {
                key: delta[key]
                for key in (
                    "intended_capability",
                    "unauthorized_capability",
                    "why_not_equivalent",
                )
            },
        }
        row["vulnerability_id"] = "HBV-" + digest([trial_id, identity])[:16]
        normalized.append(row)
    identities = [row["vulnerability_id"] for row in normalized]
    if len(set(identities)) != len(identities):
        raise BaselineError("response contains duplicate vulnerability invariants")
    return {
        "trial_id": trial_id,
        "verdict": verdict,
        "vulnerabilities": normalized,
        "negative_evidence": negative,
        "uncertainty": uncertainty,
    }


def validate_response(
    value: Mapping[str, Any],
    *,
    trial_id: str,
    source_root: Path,
    report_policy: str = ALL_FINDINGS_POLICY,
) -> dict[str, Any]:
    if report_policy == ALL_FINDINGS_POLICY:
        return validate_finding_response(value, trial_id=trial_id, source_root=source_root)
    if report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY:
        return validate_credible_vulnerability_response(
            value, trial_id=trial_id, source_root=source_root
        )
    raise BaselineError(f"unknown report policy: {report_policy}")


def parse_claude_envelope(raw: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError("Claude CLI returned invalid JSON envelope") from exc
    if not isinstance(envelope, dict):
        raise BaselineError("Claude CLI envelope must be an object")
    if envelope.get("is_error"):
        raise BaselineError(str(envelope.get("result") or "Claude CLI returned an error"))
    structured = envelope.get("structured_output")
    if not isinstance(structured, dict):
        result = envelope.get("result")
        if isinstance(result, dict):
            structured = result
        elif isinstance(result, str):
            text = result.strip()
            if text.startswith("```"):
                lines = text.splitlines()
                if lines and lines[-1].strip() == "```":
                    text = "\n".join(lines[1:-1])
                    if text.lstrip().startswith("json"):
                        text = text.lstrip()[4:].lstrip()
            try:
                structured = json.loads(text)
            except json.JSONDecodeError as exc:
                raise BaselineError("Claude result does not contain structured JSON") from exc
    if not isinstance(structured, dict):
        raise BaselineError("Claude structured output must be an object")
    usage = envelope.get("usage") or envelope.get("modelUsage") or envelope.get("model_usage")
    return structured, normalize_token_usage(usage), redact_credentials(raw)


def aggregate_calls(calls: Sequence[Mapping[str, Any]]) -> dict[str, int | bool]:
    usages = [row["usage"] for row in calls if isinstance(row.get("usage"), dict)]
    return aggregate_token_usage(usages)
