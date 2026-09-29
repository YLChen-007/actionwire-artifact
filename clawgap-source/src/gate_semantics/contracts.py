"""GateSemanticIRV1 schemas and semantic validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
SEMANTIC_SCHEMA_PATH = SCHEMA_DIR / "gate-semantic-ir-v1.schema.json"
ANALYSIS_SCHEMA_PATH = SCHEMA_DIR / "gate-analysis-response-v1.schema.json"
COMPOUND_SEMANTIC_SCHEMA_PATH = SCHEMA_DIR / "gate-semantic-ir-v2.schema.json"
COMPOUND_ANALYSIS_SCHEMA_PATH = SCHEMA_DIR / "gate-analysis-response-v2.schema.json"

MODES = {"predicate", "filter", "transform", "constraint"}
OPERATIONS = {
    "derive",
    "normalize",
    "allow-if",
    "block-if",
    "admit-if",
    "drop-if",
    "transform",
    "constrain",
    "prompt",
    "unknown",
}
REJECTING_OPERATIONS = {"block-if", "drop-if"}
BYPASS_PASS_OPERATIONS = {"allow-if", "admit-if"}
STATUS_VALUES = {"complete", "partial"}
IR_FIELDS = {
    "gate_id",
    "mode",
    "input",
    "output",
    "summary",
    "steps",
    "default",
    "on_error",
    "reject_examples",
    "bypass_examples",
    "status",
}
STEP_FIELDS = {"id", "op", "rule", "when", "unless", "source_rules"}
EXAMPLE_FIELDS = {"input", "rejected_by", "reason", "precondition"}
BYPASS_EXAMPLE_FIELDS = {
    "input",
    "passed_by",
    "reason",
    "potential_security_impact",
    "precondition",
}
COMPOUND_IR_FIELDS = {
    "schema_version",
    "gate_id",
    "mode",
    "kind",
    "input",
    "output",
    "summary",
    "entry",
    "checks",
    "policies",
    "terminals",
    "default",
    "on_error",
    "unresolved",
    "status",
}
COMPOUND_CHECK_FIELDS = {
    "id",
    "op",
    "summary",
    "input",
    "output",
    "rule",
    "outcomes",
    "on_error",
    "policy_refs",
    "reject_examples",
    "unresolved",
}
COMPOUND_POLICY_FIELDS = {"id", "summary", "matching", "rules"}
COMPOUND_POLICY_RULE_FIELDS = {"id", "rule"}
COMPOUND_SCHEMA_VERSION = "gate-semantic-ir/v2"
REGULAR_HARD_TOKEN_LIMIT = 2000
COMPOUND_HARD_TOKEN_LIMIT = 8000


class ContractError(ValueError):
    """Raised when an LLM response violates a gate semantic contract."""

    def __init__(self, errors: list[str], *, raw_responses: list[str] | None = None):
        self.errors = errors
        self.raw_responses = list(raw_responses or [])
        super().__init__("; ".join(errors))


def word_count(value: str) -> int:
    return len(re.findall(r"\b[\w'-]+\b", value, flags=re.UNICODE))


def estimate_tokens(value: object) -> int:
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    try:
        import tiktoken

        return len(tiktoken.get_encoding("cl100k_base").encode(serialized))
    except Exception:
        return max(1, (len(serialized) + 3) // 4)


def _extra_fields(value: dict[str, Any], allowed: set[str], label: str) -> list[str]:
    extras = sorted(set(value) - allowed)
    return (
        [f"{label} contains unsupported fields: {', '.join(extras)}"] if extras else []
    )


def _require_string(
    value: dict[str, Any], key: str, label: str, errors: list[str]
) -> str:
    current = value.get(key)
    if not isinstance(current, str) or not current.strip():
        errors.append(f"{label}.{key} must be a non-empty string")
        return ""
    return current.strip()


def validate_semantic_ir(
    ir: dict[str, Any],
    *,
    expected_gate_id: str | None = None,
    expected_mode: str | None = None,
    expected_input_id: str | None = None,
    expected_output_id: str | None = None,
    hard_token_limit: int = REGULAR_HARD_TOKEN_LIMIT,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(ir, dict):
        return ["semantic_ir must be a JSON object"]
    errors.extend(_extra_fields(ir, IR_FIELDS, "semantic_ir"))
    missing = sorted(IR_FIELDS - set(ir))
    if missing:
        errors.append(f"semantic_ir is missing fields: {', '.join(missing)}")

    gate_id = _require_string(ir, "gate_id", "semantic_ir", errors)
    mode = _require_string(ir, "mode", "semantic_ir", errors)
    input_value = _require_string(ir, "input", "semantic_ir", errors)
    output_value = _require_string(ir, "output", "semantic_ir", errors)
    summary = _require_string(ir, "summary", "semantic_ir", errors)
    _require_string(ir, "default", "semantic_ir", errors)
    _require_string(ir, "on_error", "semantic_ir", errors)

    if expected_gate_id and gate_id != expected_gate_id:
        errors.append(
            f"semantic_ir.gate_id must equal {expected_gate_id!r}, got {gate_id!r}"
        )
    if expected_mode and mode != expected_mode:
        errors.append(f"semantic_ir.mode must equal {expected_mode!r}, got {mode!r}")
    if mode and mode not in MODES:
        errors.append(f"semantic_ir.mode is not supported: {mode!r}")
    if expected_input_id and not input_value.startswith(expected_input_id + ":"):
        errors.append(
            f"semantic_ir.input must start with {expected_input_id!r} followed by ':'"
        )
    if expected_output_id and not output_value.startswith(expected_output_id + ":"):
        errors.append(
            f"semantic_ir.output must start with {expected_output_id!r} followed by ':'"
        )
    if summary:
        if "\n" in summary:
            errors.append("semantic_ir.summary must be one line")
        if word_count(summary) > 35:
            errors.append("semantic_ir.summary exceeds 35 words")

    steps = ir.get("steps")
    step_ops: dict[str, str] = {}
    if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
        errors.append("semantic_ir.steps must contain between 1 and 8 atoms")
        steps = []
    for index, step in enumerate(steps, 1):
        label = f"semantic_ir.steps[{index - 1}]"
        if not isinstance(step, dict):
            errors.append(f"{label} must be an object")
            continue
        errors.extend(_extra_fields(step, STEP_FIELDS, label))
        step_id = _require_string(step, "id", label, errors)
        operation = _require_string(step, "op", label, errors)
        rule = _require_string(step, "rule", label, errors)
        if step_id != f"S{index}":
            errors.append(f"{label}.id must be S{index}")
        if operation and operation not in OPERATIONS:
            errors.append(f"{label}.op is not supported: {operation!r}")
        if rule and word_count(rule) > 25:
            errors.append(f"{label}.rule exceeds 25 words")
        for optional in ("when", "unless"):
            if optional in step and (
                not isinstance(step[optional], str) or not step[optional].strip()
            ):
                errors.append(
                    f"{label}.{optional} must be a non-empty string when present"
                )
        if "source_rules" in step:
            source_rules = step["source_rules"]
            if not isinstance(source_rules, list) or not source_rules:
                errors.append(
                    f"{label}.source_rules must be a non-empty list when present"
                )
            else:
                normalized_rules: list[str] = []
                for rule_index, source_rule in enumerate(source_rules):
                    source_label = f"{label}.source_rules[{rule_index}]"
                    if not isinstance(source_rule, str) or not source_rule.strip():
                        errors.append(f"{source_label} must be a non-empty string")
                        continue
                    normalized_rules.append(source_rule.strip())
                if len(normalized_rules) != len(set(normalized_rules)):
                    errors.append(f"{label}.source_rules must not contain duplicates")
        if step_id:
            if step_id in step_ops:
                errors.append(f"duplicate semantic atom id: {step_id}")
            step_ops[step_id] = operation

    examples = ir.get("reject_examples")
    if not isinstance(examples, list) or len(examples) > 2:
        errors.append(
            "semantic_ir.reject_examples must be a list of at most two examples"
        )
        examples = []
    for index, example in enumerate(examples):
        label = f"semantic_ir.reject_examples[{index}]"
        if not isinstance(example, dict):
            errors.append(f"{label} must be an object")
            continue
        errors.extend(_extra_fields(example, EXAMPLE_FIELDS, label))
        _require_string(example, "input", label, errors)
        rejected_by = _require_string(example, "rejected_by", label, errors)
        reason = _require_string(example, "reason", label, errors)
        if reason and word_count(reason) > 20:
            errors.append(f"{label}.reason exceeds 20 words")
        if rejected_by not in step_ops:
            errors.append(
                f"{label}.rejected_by references unknown atom {rejected_by!r}"
            )
        elif step_ops[rejected_by] not in REJECTING_OPERATIONS:
            errors.append(
                f"{label}.rejected_by must reference block-if/drop-if, "
                f"got {step_ops[rejected_by]!r}"
            )
        if "precondition" in example and (
            not isinstance(example["precondition"], str)
            or not example["precondition"].strip()
        ):
            errors.append(f"{label}.precondition must be non-empty when present")

    bypass_examples = ir.get("bypass_examples")
    if not isinstance(bypass_examples, list) or len(bypass_examples) > 5:
        errors.append(
            "semantic_ir.bypass_examples must be a list of at most five examples"
        )
        bypass_examples = []
    for index, example in enumerate(bypass_examples):
        label = f"semantic_ir.bypass_examples[{index}]"
        if not isinstance(example, dict):
            errors.append(f"{label} must be an object")
            continue
        errors.extend(_extra_fields(example, BYPASS_EXAMPLE_FIELDS, label))
        _require_string(example, "input", label, errors)
        passed_by = _require_string(example, "passed_by", label, errors)
        reason = _require_string(example, "reason", label, errors)
        impact = _require_string(
            example, "potential_security_impact", label, errors
        )
        if reason and word_count(reason) > 20:
            errors.append(f"{label}.reason exceeds 20 words")
        if impact and word_count(impact) > 25:
            errors.append(
                f"{label}.potential_security_impact exceeds 25 words"
            )
        if passed_by not in step_ops:
            errors.append(
                f"{label}.passed_by references unknown atom {passed_by!r}"
            )
        elif step_ops[passed_by] not in BYPASS_PASS_OPERATIONS:
            errors.append(
                f"{label}.passed_by must reference allow-if/admit-if, "
                f"got {step_ops[passed_by]!r}"
            )
        if "precondition" in example and (
            not isinstance(example["precondition"], str)
            or not example["precondition"].strip()
        ):
            errors.append(f"{label}.precondition must be non-empty when present")

    status = ir.get("status")
    if status not in STATUS_VALUES:
        errors.append("semantic_ir.status must be 'complete' or 'partial'")
    if any(op == "unknown" for op in step_ops.values()) and status != "partial":
        errors.append(
            "semantic_ir.status must be partial when an unknown atom is present"
        )
    if mode == "transform" and examples:
        errors.append("transform gates must not fabricate reject_examples")
    if mode == "transform" and bypass_examples:
        errors.append("transform gates must not fabricate bypass_examples")

    tokens = estimate_tokens(ir)
    if tokens > hard_token_limit:
        errors.append(
            f"semantic_ir is approximately {tokens} tokens; hard limit is {hard_token_limit}"
        )
    return errors


def validate_analysis_response(
    response: dict[str, Any],
    *,
    expected_gate_id: str | None = None,
    expected_mode: str | None = None,
    expected_input_id: str | None = None,
    expected_output_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    if not isinstance(response, dict):
        raise ContractError(["LLM response must be a JSON object"])

    if "semantic_ir" in response:
        extras = sorted(set(response) - {"semantic_ir", "evidence"})
        errors = (
            [f"analysis response contains unsupported fields: {', '.join(extras)}"]
            if extras
            else []
        )
        ir = response.get("semantic_ir")
        evidence = response.get("evidence", {})
    else:
        errors = []
        ir = response
        evidence = {}

    ir_errors = validate_semantic_ir(
        ir,
        expected_gate_id=expected_gate_id,
        expected_mode=expected_mode,
        expected_input_id=expected_input_id,
        expected_output_id=expected_output_id,
    )
    errors.extend(ir_errors)

    if not isinstance(evidence, dict):
        errors.append("analysis response evidence must be an object")
        evidence = {}
    else:
        steps = ir.get("steps", []) if isinstance(ir, dict) else []
        step_ids = {step.get("id") for step in steps if isinstance(step, dict)}
        for step_id, spans in evidence.items():
            if step_id not in step_ids:
                errors.append(f"evidence references unknown semantic atom {step_id!r}")
            if not isinstance(spans, list):
                errors.append(f"evidence.{step_id} must be a list")
                continue
            if not spans:
                errors.append(
                    f"evidence.{step_id} must contain at least one source span"
                )
            for index, span in enumerate(spans):
                if not isinstance(span, dict):
                    errors.append(f"evidence.{step_id}[{index}] must be an object")
                    continue
                required = {"file", "line_start", "line_end"}
                if not required.issubset(span):
                    errors.append(
                        f"evidence.{step_id}[{index}] must contain file, line_start, line_end"
                    )
                    continue
                extras = sorted(set(span) - required)
                if extras:
                    errors.append(
                        f"evidence.{step_id}[{index}] contains unsupported fields: "
                        f"{', '.join(extras)}"
                    )
                if not isinstance(span["file"], str) or not span["file"].strip():
                    errors.append(
                        f"evidence.{step_id}[{index}].file must be a non-empty string"
                    )
                if (
                    not isinstance(span["line_start"], int)
                    or isinstance(span["line_start"], bool)
                    or span["line_start"] < 1
                ):
                    errors.append(
                        f"evidence.{step_id}[{index}].line_start must be a positive integer"
                    )
                if (
                    not isinstance(span["line_end"], int)
                    or isinstance(span["line_end"], bool)
                    or span["line_end"] < 1
                ):
                    errors.append(
                        f"evidence.{step_id}[{index}].line_end must be a positive integer"
                    )
        if isinstance(steps, list):
            for step_id in sorted(
                value for value in step_ids if isinstance(value, str)
            ):
                if step_id not in evidence:
                    errors.append(f"evidence is missing semantic atom {step_id!r}")

    if errors:
        raise ContractError(errors)
    return ir, evidence


def _validate_compound_examples(
    examples: object,
    *,
    check_id: str,
    operation: str,
    label: str,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(examples, list) or len(examples) > 2:
        return [f"{label} must be a list of at most two examples"]
    for index, example in enumerate(examples):
        current = f"{label}[{index}]"
        if not isinstance(example, dict):
            errors.append(f"{current} must be an object")
            continue
        errors.extend(_extra_fields(example, EXAMPLE_FIELDS, current))
        _require_string(example, "input", current, errors)
        rejected_by = _require_string(example, "rejected_by", current, errors)
        reason = _require_string(example, "reason", current, errors)
        if rejected_by and rejected_by != check_id:
            errors.append(f"{current}.rejected_by must equal {check_id!r}")
        if rejected_by and operation not in REJECTING_OPERATIONS:
            errors.append(f"{current} belongs to non-rejecting operation {operation!r}")
        if reason and word_count(reason) > 20:
            errors.append(f"{current}.reason exceeds 20 words")
        if "precondition" in example and (
            not isinstance(example["precondition"], str)
            or not example["precondition"].strip()
        ):
            errors.append(f"{current}.precondition must be non-empty when present")
    return errors


def validate_compound_semantic_ir(
    ir: dict[str, Any],
    *,
    profile: dict[str, Any],
    expected_gate_id: str | None = None,
    expected_mode: str | None = None,
    expected_input_id: str | None = None,
    expected_output_id: str | None = None,
    hard_token_limit: int = COMPOUND_HARD_TOKEN_LIMIT,
) -> list[str]:
    """Validate the complete, self-contained IR used by exceptional compound gates."""

    errors: list[str] = []
    if not isinstance(ir, dict):
        return ["semantic_ir must be a JSON object"]
    errors.extend(_extra_fields(ir, COMPOUND_IR_FIELDS, "semantic_ir"))
    missing = sorted(COMPOUND_IR_FIELDS - set(ir))
    if missing:
        errors.append(f"semantic_ir is missing fields: {', '.join(missing)}")

    schema_version = _require_string(ir, "schema_version", "semantic_ir", errors)
    gate_id = _require_string(ir, "gate_id", "semantic_ir", errors)
    mode = _require_string(ir, "mode", "semantic_ir", errors)
    kind = _require_string(ir, "kind", "semantic_ir", errors)
    input_value = _require_string(ir, "input", "semantic_ir", errors)
    output_value = _require_string(ir, "output", "semantic_ir", errors)
    summary = _require_string(ir, "summary", "semantic_ir", errors)
    entry = _require_string(ir, "entry", "semantic_ir", errors)
    _require_string(ir, "default", "semantic_ir", errors)
    _require_string(ir, "on_error", "semantic_ir", errors)

    if schema_version and schema_version != COMPOUND_SCHEMA_VERSION:
        errors.append(
            f"semantic_ir.schema_version must equal {COMPOUND_SCHEMA_VERSION!r}"
        )
    if kind and kind != "compound":
        errors.append("semantic_ir.kind must equal 'compound'")
    if expected_gate_id and gate_id != expected_gate_id:
        errors.append(
            f"semantic_ir.gate_id must equal {expected_gate_id!r}, got {gate_id!r}"
        )
    if expected_mode and mode != expected_mode:
        errors.append(f"semantic_ir.mode must equal {expected_mode!r}, got {mode!r}")
    if mode and mode not in MODES:
        errors.append(f"semantic_ir.mode is not supported: {mode!r}")
    if expected_input_id and not input_value.startswith(expected_input_id + ":"):
        errors.append(
            f"semantic_ir.input must start with {expected_input_id!r} followed by ':'"
        )
    if expected_output_id and not output_value.startswith(expected_output_id + ":"):
        errors.append(
            f"semantic_ir.output must start with {expected_output_id!r} followed by ':'"
        )
    if summary and ("\n" in summary or word_count(summary) > 35):
        errors.append("semantic_ir.summary must be one line of at most 35 words")
    expected_entry = profile.get("entry_check")
    if entry and entry != expected_entry:
        errors.append(f"semantic_ir.entry must equal {expected_entry!r}")

    required_checks = profile.get("required_checks", [])
    expected_check_ids = [item.get("id") for item in required_checks]
    expected_checks = {item.get("id"): item for item in required_checks}
    checks = ir.get("checks")
    if not isinstance(checks, list):
        errors.append("semantic_ir.checks must be a list")
        checks = []
    actual_check_ids = [item.get("id") for item in checks if isinstance(item, dict)]
    if actual_check_ids != expected_check_ids:
        errors.append(
            "semantic_ir.checks must contain every required child check exactly once "
            "and in profile order"
        )
    policy_ids: set[str] = set()
    for index, check in enumerate(checks):
        label = f"semantic_ir.checks[{index}]"
        if not isinstance(check, dict):
            errors.append(f"{label} must be an object")
            continue
        errors.extend(_extra_fields(check, COMPOUND_CHECK_FIELDS, label))
        missing_check = sorted(COMPOUND_CHECK_FIELDS - set(check))
        if missing_check:
            errors.append(f"{label} is missing fields: {', '.join(missing_check)}")
        check_id = _require_string(check, "id", label, errors)
        operation = _require_string(check, "op", label, errors)
        check_summary = _require_string(check, "summary", label, errors)
        _require_string(check, "input", label, errors)
        _require_string(check, "output", label, errors)
        rule = _require_string(check, "rule", label, errors)
        _require_string(check, "on_error", label, errors)
        expected = expected_checks.get(check_id, {})
        if operation and operation not in OPERATIONS:
            errors.append(f"{label}.op is not supported: {operation!r}")
        if expected and operation != expected.get("op"):
            errors.append(
                f"{label}.op must equal profile operation {expected.get('op')!r}"
            )
        if check_summary and ("\n" in check_summary or word_count(check_summary) > 35):
            errors.append(f"{label}.summary must be one line of at most 35 words")
        if rule and word_count(rule) > 60:
            errors.append(f"{label}.rule exceeds 60 words")
        outcomes = check.get("outcomes")
        if not isinstance(outcomes, dict) or any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(value, str)
            or not value.strip()
            for key, value in (outcomes.items() if isinstance(outcomes, dict) else [])
        ):
            errors.append(f"{label}.outcomes must map non-empty labels to targets")
        elif expected and outcomes != expected.get("outcomes"):
            errors.append(f"{label}.outcomes must exactly match the source profile")
        policy_refs = check.get("policy_refs")
        if not isinstance(policy_refs, list) or any(
            not isinstance(item, str) or not item for item in policy_refs
        ):
            errors.append(f"{label}.policy_refs must be a list of identifiers")
            policy_refs = []
        elif expected and policy_refs != expected.get("policy_refs", []):
            errors.append(f"{label}.policy_refs must exactly match the source profile")
        policy_ids.update(policy_refs)
        unresolved = check.get("unresolved")
        if not isinstance(unresolved, list) or any(
            not isinstance(item, str) or not item.strip() for item in unresolved
        ):
            errors.append(f"{label}.unresolved must be a list of strings")
            unresolved = []
        required_unresolved = set(expected.get("required_unresolved", []))
        if not required_unresolved.issubset(unresolved):
            errors.append(
                f"{label}.unresolved must preserve required dependencies: "
                + ", ".join(sorted(required_unresolved))
            )
        errors.extend(
            _validate_compound_examples(
                check.get("reject_examples"),
                check_id=check_id,
                operation=operation,
                label=f"{label}.reject_examples",
            )
        )

    expected_policies = profile.get("policies", [])
    expected_policy_ids = [item.get("id") for item in expected_policies]
    expected_policy_map = {item.get("id"): item for item in expected_policies}
    policies = ir.get("policies")
    if not isinstance(policies, list):
        errors.append("semantic_ir.policies must be a list")
        policies = []
    actual_policy_ids = [item.get("id") for item in policies if isinstance(item, dict)]
    if actual_policy_ids != expected_policy_ids:
        errors.append(
            "semantic_ir.policies must contain every required policy exactly once "
            "and in profile order"
        )
    for index, policy in enumerate(policies):
        label = f"semantic_ir.policies[{index}]"
        if not isinstance(policy, dict):
            errors.append(f"{label} must be an object")
            continue
        errors.extend(_extra_fields(policy, COMPOUND_POLICY_FIELDS, label))
        missing_policy = sorted(COMPOUND_POLICY_FIELDS - set(policy))
        if missing_policy:
            errors.append(f"{label} is missing fields: {', '.join(missing_policy)}")
        policy_id = _require_string(policy, "id", label, errors)
        policy_summary = _require_string(policy, "summary", label, errors)
        matching = _require_string(policy, "matching", label, errors)
        if policy_summary and word_count(policy_summary) > 35:
            errors.append(f"{label}.summary exceeds 35 words")
        if matching and word_count(matching) > 60:
            errors.append(f"{label}.matching exceeds 60 words")
        expected_policy = expected_policy_map.get(policy_id, {})
        expected_rule_ids = [
            item.get("id") for item in expected_policy.get("items", [])
        ]
        rules = policy.get("rules")
        if not isinstance(rules, list):
            errors.append(f"{label}.rules must be a list")
            rules = []
        actual_rule_ids = [item.get("id") for item in rules if isinstance(item, dict)]
        if actual_rule_ids != expected_rule_ids:
            errors.append(
                f"{label}.rules must preserve every source policy entry exactly once "
                "and in source order"
            )
        for rule_index, policy_rule in enumerate(rules):
            rule_label = f"{label}.rules[{rule_index}]"
            if not isinstance(policy_rule, dict):
                errors.append(f"{rule_label} must be an object")
                continue
            errors.extend(
                _extra_fields(policy_rule, COMPOUND_POLICY_RULE_FIELDS, rule_label)
            )
            _require_string(policy_rule, "id", rule_label, errors)
            policy_rule_text = _require_string(policy_rule, "rule", rule_label, errors)
            if policy_rule_text and word_count(policy_rule_text) > 50:
                errors.append(f"{rule_label}.rule exceeds 50 words")

    unknown_policy_refs = sorted(policy_ids - set(expected_policy_ids))
    if unknown_policy_refs:
        errors.append(
            "semantic_ir.checks reference unknown policies: "
            + ", ".join(unknown_policy_refs)
        )
    terminals = ir.get("terminals")
    if terminals != profile.get("terminals"):
        errors.append("semantic_ir.terminals must exactly match the source profile")
    unresolved = ir.get("unresolved")
    if not isinstance(unresolved, list) or any(
        not isinstance(item, str) or not item.strip() for item in unresolved
    ):
        errors.append("semantic_ir.unresolved must be a list of strings")
        unresolved = []
    forced_unresolved = set(profile.get("forced_unresolved", []))
    if not forced_unresolved.issubset(unresolved):
        errors.append(
            "semantic_ir.unresolved must preserve required dependencies: "
            + ", ".join(sorted(forced_unresolved))
        )
    status = ir.get("status")
    if status not in STATUS_VALUES:
        errors.append("semantic_ir.status must be 'complete' or 'partial'")
    has_unknown = any(
        isinstance(item, dict) and item.get("op") == "unknown" for item in checks
    )
    if (forced_unresolved or has_unknown) and status != "partial":
        errors.append(
            "semantic_ir.status must be partial for unresolved compound checks"
        )
    tokens = estimate_tokens(ir)
    if tokens > hard_token_limit:
        errors.append(
            f"semantic_ir is approximately {tokens} tokens; hard limit is {hard_token_limit}"
        )
    return errors


def validate_compound_analysis_response(
    response: dict[str, Any],
    *,
    profile: dict[str, Any],
    expected_gate_id: str | None = None,
    expected_mode: str | None = None,
    expected_input_id: str | None = None,
    expected_output_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    """Validate a compound LLM response and its audit-only evidence map."""

    if not isinstance(response, dict):
        raise ContractError(["LLM response must be a JSON object"])
    extras = sorted(set(response) - {"semantic_ir", "evidence"})
    errors = (
        [f"analysis response contains unsupported fields: {', '.join(extras)}"]
        if extras
        else []
    )
    ir = response.get("semantic_ir")
    evidence = response.get("evidence")
    errors.extend(
        validate_compound_semantic_ir(
            ir,
            profile=profile,
            expected_gate_id=expected_gate_id,
            expected_mode=expected_mode,
            expected_input_id=expected_input_id,
            expected_output_id=expected_output_id,
        )
    )
    expected_evidence_ids = {
        item.get("id") for item in profile.get("required_checks", [])
    } | {item.get("id") for item in profile.get("policies", [])}
    if not isinstance(evidence, dict):
        errors.append("analysis response evidence must be an object")
        evidence = {}
    else:
        actual_evidence_ids = set(evidence)
        if actual_evidence_ids != expected_evidence_ids:
            errors.append(
                "analysis response evidence must cover every child check and policy "
                "exactly once"
            )
        for unit_id, spans in evidence.items():
            if not isinstance(spans, list) or not spans:
                errors.append(f"evidence.{unit_id} must be a non-empty list")
                continue
            for index, span in enumerate(spans):
                label = f"evidence.{unit_id}[{index}]"
                if not isinstance(span, dict):
                    errors.append(f"{label} must be an object")
                    continue
                required = {"file", "line_start", "line_end"}
                if set(span) != required:
                    errors.append(
                        f"{label} must contain only file, line_start, line_end"
                    )
                    continue
                if not isinstance(span["file"], str) or not span["file"].strip():
                    errors.append(f"{label}.file must be a non-empty string")
                for key in ("line_start", "line_end"):
                    if (
                        not isinstance(span[key], int)
                        or isinstance(span[key], bool)
                        or span[key] < 1
                    ):
                        errors.append(f"{label}.{key} must be a positive integer")
    if errors:
        raise ContractError(errors)
    return ir, evidence


def parse_json_response(raw: str) -> dict[str, Any]:
    value = raw.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", value, flags=re.DOTALL)
    if fenced:
        value = fenced.group(1)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        candidates: list[tuple[int, dict[str, Any]]] = []
        last_error: json.JSONDecodeError | None = None
        for start, character in enumerate(value):
            if character != "{":
                continue
            try:
                candidate, end = decoder.raw_decode(value[start:])
            except json.JSONDecodeError as exc:
                last_error = exc
                continue
            if isinstance(candidate, dict):
                candidates.append((end, candidate))
        if not candidates:
            if last_error is None:
                raise ContractError(["LLM response does not contain a JSON object"])
            raise ContractError([f"invalid JSON response: {last_error}"])
        _length, parsed = max(candidates, key=lambda item: item[0])
    if not isinstance(parsed, dict):
        raise ContractError(["LLM response JSON must be an object"])
    return parsed


def load_schema(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
