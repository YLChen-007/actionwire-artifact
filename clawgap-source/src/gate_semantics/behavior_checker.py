"""Source-profile checker and behavior-complete IR recovery for policy gates.

The LLM remains useful for discovering ordinary gate semantics.  Exact matcher tables,
gate-internal control flow, state effects, and external-dependency completeness are not safe to
accept as prose, so this module deterministically recovers and validates those fields for
source shapes whose policy inventory is known.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "gate-semantic-ir/v3"
CHECKER_VERSION = "gate-semantic-checker/v1"
HARD_TOKEN_LIMIT = 8000
SCHEMA_PATH = (
    Path(__file__).resolve().parent / "schemas" / "gate-semantic-ir-v3.schema.json"
)


class SemanticCheckError(ValueError):
    """Raised when a source profile cannot be recovered exactly."""


@dataclass(frozen=True)
class BehaviorProfile:
    profile_id: str
    semantic_ir: dict[str, Any]
    evidence: dict[str, list[dict[str, Any]]]
    legacy_findings: tuple[str, ...]


def _stable_id(gate_id: str, label: str, prefix: str = "V") -> str:
    digest = hashlib.sha256(f"{gate_id}:{label}".encode("utf-8")).hexdigest()[:12]
    return prefix + digest


def _span(file: str, line_start: int, line_end: int | None = None) -> dict[str, Any]:
    return {
        "file": file,
        "line_start": line_start,
        "line_end": line_start if line_end is None else line_end,
    }


def _source(source_root: Path, rel: str) -> tuple[str, ast.Module]:
    text = (source_root / rel).read_text(encoding="utf-8")
    return text, ast.parse(text, filename=rel)


def _assignment(module: ast.Module, name: str) -> ast.AST:
    for statement in module.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in statement.targets
        ):
            return statement
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == name
        ):
            return statement
    raise SemanticCheckError(f"missing source assignment {name}")


def _assignment_value(module: ast.Module, name: str) -> ast.AST:
    statement = _assignment(module, name)
    value = getattr(statement, "value", None)
    if value is None:
        raise SemanticCheckError(f"source assignment {name} has no value")
    return value


def _function(module: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [
        node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(matches) != 1:
        raise SemanticCheckError(f"expected one source function {name}, got {len(matches)}")
    return matches[0]


def _static_string(node: ast.AST, module: ast.Module, seen: set[str] | None = None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _static_string(node.left, module, seen) + _static_string(
            node.right, module, seen
        )
    if isinstance(node, ast.Name):
        current_seen = set(seen or ())
        if node.id in current_seen:
            raise SemanticCheckError(f"recursive string assignment {node.id}")
        current_seen.add(node.id)
        return _static_string(_assignment_value(module, node.id), module, current_seen)
    raise SemanticCheckError(f"unsupported static string expression {ast.dump(node)}")


def _flags(node: ast.AST | None, module: ast.Module) -> list[str]:
    if node is None:
        return []
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return [*_flags(node.left, module), *_flags(node.right, module)]
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return [f"{node.value.id}.{node.attr}"]
    if isinstance(node, ast.Name):
        return _flags(_assignment_value(module, node.id), module)
    if isinstance(node, ast.Constant) and node.value == 0:
        return []
    raise SemanticCheckError(f"unsupported regex flags {ast.dump(node)}")


def _compiled_regex(node: ast.AST, module: ast.Module) -> tuple[str, list[str]]:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
        and node.func.attr == "compile"
        and node.args
    ):
        raise SemanticCheckError(f"expected re.compile call, got {ast.dump(node)}")
    return (
        _static_string(node.args[0], module),
        _flags(node.args[1], module) if len(node.args) > 1 else [],
    )


def _prompt_template(function: ast.AST) -> str:
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign) or not any(
            isinstance(target, ast.Name) and target.id == "prompt"
            for target in node.targets
        ):
            continue
        if not isinstance(node.value, ast.JoinedStr):
            raise SemanticCheckError("smart approval prompt is not an f-string")
        parts: list[str] = []
        for value in node.value.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue) and isinstance(
                value.value, ast.Name
            ):
                parts.append("{" + value.value.id + "}")
            else:
                raise SemanticCheckError("unsupported smart approval prompt expression")
        return "".join(parts)
    raise SemanticCheckError("missing smart approval prompt")


def _base(
    payload: dict[str, Any],
    *,
    summary: str,
    inputs: list[dict[str, str]],
    activation: list[dict[str, str]],
    derived_values: list[dict[str, Any]],
    entry: str,
    checks: list[dict[str, Any]],
    policies: list[dict[str, Any]],
    outcomes: dict[str, dict[str, str]],
    state_effects: list[dict[str, str]],
    dependencies: list[dict[str, Any]],
    default: str,
    on_error: str,
    unresolved: list[str],
) -> dict[str, Any]:
    status = "partial" if unresolved else "complete"
    return {
        "schema_version": SCHEMA_VERSION,
        "gate_id": str(payload["gate_id"]),
        "mode": str(payload["gate"]["mode"]),
        "kind": "behavior-complete",
        "summary": summary,
        "inputs": inputs,
        "activation": activation,
        "derived_values": derived_values,
        "entry": entry,
        "checks": checks,
        "policies": policies,
        "outcomes": outcomes,
        "state_effects": state_effects,
        "dependencies": dependencies,
        "default": default,
        "on_error": on_error,
        "unresolved": unresolved,
        "completeness": {
            "control_flow": "complete",
            "policy": "complete",
            "context": "complete",
            "dependencies": status,
            "overall": status,
            "reasons": (
                ["Outcome-affecting external dependencies remain unresolved."]
                if unresolved
                else []
            ),
        },
        "status": status,
    }


def _hardline_profile(payload: dict[str, Any], source_root: Path) -> BehaviorProfile:
    rel = "tools/approval.py"
    _text, module = _source(source_root, rel)
    table_statement = _assignment(module, "HARDLINE_PATTERNS")
    table = _assignment_value(module, "HARDLINE_PATTERNS")
    if not isinstance(table, (ast.List, ast.Tuple)) or len(table.elts) != 12:
        raise SemanticCheckError("HARDLINE_PATTERNS must contain exactly 12 entries")
    rules: list[dict[str, str]] = []
    for index, item in enumerate(table.elts, 1):
        if not isinstance(item, ast.Tuple) or len(item.elts) != 2:
            raise SemanticCheckError("invalid HARDLINE_PATTERNS entry")
        pattern = _static_string(item.elts[0], module)
        description = _static_string(item.elts[1], module)
        rules.append(
            {
                "id": f"H{index:02d}",
                "matcher": pattern,
                "meaning": description,
                "outcome": "T_BLOCK",
            }
        )

    gate_id = str(payload["gate_id"])
    v_command = str(payload["checked_value"]["value_id"])
    v_env = _stable_id(gate_id, "env-type")
    v_normalized = _stable_id(gate_id, "normalized-command")
    ir = _base(
        payload,
        summary=(
            "Blocks normalized commands matching any of twelve unconditional "
            "host-destructive command policies before configurable approval bypasses."
        ),
        inputs=[
            {"id": v_command, "meaning": "command string", "source": "detect_hardline_command.command"},
            {"id": v_env, "meaning": "terminal backend type", "source": "check_all_command_guards.env_type"},
        ],
        activation=[
            {
                "id": "A1",
                "condition": "env_type not in ('docker', 'singularity', 'modal', 'daytona', 'vercel_sandbox')",
                "when_true": "C1",
                "when_false": "T_NOT_EVALUATED",
            }
        ],
        derived_values=[
            {
                "id": v_normalized,
                "meaning": "normalized lowercase command",
                "sources": [v_command],
                "operations": [
                    "strip ECMA-48 ANSI escape sequences",
                    "remove U+0000 null bytes",
                    "Unicode normalize with NFKC",
                    "lowercase",
                ],
                "used_by": ["C1"],
            }
        ],
        entry="A1",
        checks=[
            {
                "id": "C1",
                "op": "block-if",
                "summary": "Search the normalized command against every hardline rule in source order.",
                "reads": [v_normalized],
                "rule": "The first matching hardline regex blocks and returns its paired description; no match passes.",
                "policy_refs": ["P_HARDLINE"],
                "outcomes": {"match": "T_BLOCK", "no_match": "T_PASS"},
                "on_error": "Normalization or regex exceptions propagate from the gate.",
                "reject_examples": [
                    {"input": "rm -rf /", "rejected_by": "C1", "reason": "Matches H01 root deletion policy."},
                    {"input": ":(){ :|:& };:", "rejected_by": "C1", "reason": "Matches H07 fork bomb policy."},
                ],
            }
        ],
        policies=[
            {
                "id": "P_HARDLINE",
                "kind": "regex-table",
                "summary": "Twelve source-defined unconditional command block rules.",
                "input_values": [v_normalized],
                "match": "Python regex search in source order; first match wins",
                "flags": ["re.IGNORECASE", "re.DOTALL"],
                "template": None,
                "rules": rules,
            }
        ],
        outcomes={
            "T_NOT_EVALUATED": {"decision": "not-evaluated", "effect": "Container backend returns approved before this gate is called."},
            "T_BLOCK": {"decision": "block", "effect": "Return the hardline block result with the matched policy description."},
            "T_PASS": {"decision": "pass", "effect": "Return (False, None) and continue to later command guards."},
        },
        state_effects=[],
        dependencies=[],
        default="No hardline rule matches, so the callsite continues.",
        on_error="An exception propagates through the guard call; terminal_tool's outer handler converts it to an execution-error JSON result.",
        unresolved=[],
    )
    evidence = {
        "A1": [_span(rel, 929, 931)],
        "C1": [_span(rel, 193, 203), _span(rel, 329, 344)],
        "P_HARDLINE": [
            _span(rel, int(table_statement.lineno), int(table_statement.end_lineno)),
            _span(rel, 186, 190),
        ],
    }
    return BehaviorProfile(
        profile_id="hermes-hardline-command/v1",
        semantic_ir=ir,
        evidence=evidence,
        legacy_findings=(
            "legacy-ir-omits-12-rule-policy-table",
            "legacy-ir-omits-container-activation",
            "legacy-ir-cannot-scope-normalized-value",
            "slice-reported-resolved-normalize-helper-as-unresolved",
        ),
    )


def _foreground_profile(payload: dict[str, Any], source_root: Path) -> BehaviorProfile:
    rel = "tools/terminal_tool.py"
    _text, module = _source(source_root, rel)
    shell_pattern, shell_flags = _compiled_regex(
        _assignment_value(module, "_SHELL_LEVEL_BACKGROUND_RE"), module
    )
    inline_pattern, inline_flags = _compiled_regex(
        _assignment_value(module, "_INLINE_BACKGROUND_AMP_RE"), module
    )
    trailing_pattern, trailing_flags = _compiled_regex(
        _assignment_value(module, "_TRAILING_BACKGROUND_AMP_RE"), module
    )
    long_table_statement = _assignment(module, "_LONG_LIVED_FOREGROUND_PATTERNS")
    long_table = _assignment_value(module, "_LONG_LIVED_FOREGROUND_PATTERNS")
    if not isinstance(long_table, (ast.Tuple, ast.List)) or len(long_table.elts) != 8:
        raise SemanticCheckError("long-lived pattern table must contain eight entries")
    long_meanings = [
        "npm, pnpm, yarn, or bun dev/start/serve/watch command, with optional run",
        "docker compose up command",
        "next dev command",
        "vite command followed by whitespace or end of input",
        "nodemon command",
        "uvicorn command",
        "gunicorn command",
        "python or python3 -m http.server command",
    ]
    long_rules: list[dict[str, str]] = []
    long_flags: list[str] | None = None
    for index, (item, meaning) in enumerate(
        zip(long_table.elts, long_meanings, strict=True), 1
    ):
        pattern, flags = _compiled_regex(item, module)
        if long_flags is None:
            long_flags = flags
        elif flags != long_flags:
            raise SemanticCheckError("long-lived pattern flags are inconsistent")
        long_rules.append(
            {
                "id": f"L{index:02d}",
                "matcher": pattern,
                "meaning": meaning,
                "outcome": "T_BLOCK",
            }
        )

    gate_id = str(payload["gate_id"])
    v_command = str(payload["checked_value"]["value_id"])
    v_background = _stable_id(gate_id, "background")
    v_help = _stable_id(gate_id, "help-normalized")
    ir = _base(
        payload,
        summary=(
            "Rejects foreground shell commands using unmanaged backgrounding or exact "
            "long-lived process patterns, while exempting narrowly recognized help and version invocations."
        ),
        inputs=[
            {"id": v_command, "meaning": "raw shell command string", "source": "_foreground_background_guidance.command"},
            {"id": v_background, "meaning": "terminal background-mode flag", "source": "terminal_tool.background"},
        ],
        activation=[
            {"id": "A1", "condition": "background is falsey (`not background`)", "when_true": "C1", "when_false": "T_NOT_EVALUATED"}
        ],
        derived_values=[
            {
                "id": v_help,
                "meaning": "lowercase whitespace-collapsed command used only by the informational exception",
                "sources": [v_command],
                "operations": ["lowercase", "split on whitespace", "join tokens with one ASCII space"],
                "used_by": ["C1"],
            }
        ],
        entry="A1",
        checks=[
            {
                "id": "C1", "op": "allow-if", "summary": "Recognize exact help and version suffix forms.",
                "reads": [v_help],
                "rule": "Pass if the derived value contains ' --help' or ' --version', or ends with ' -h' or ' -v'.",
                "policy_refs": [], "outcomes": {"match": "T_PASS", "no_match": "C2"},
                "on_error": "String-operation exceptions propagate to terminal_tool's outer handler.", "reject_examples": []
            },
            {
                "id": "C2", "op": "block-if", "summary": "Detect shell-level background wrapper words.",
                "reads": [v_command], "rule": "Regex-search the raw command for a shell wrapper policy match.",
                "policy_refs": ["P_SHELL_WRAPPER"], "outcomes": {"match": "T_BLOCK", "no_match": "C3"},
                "on_error": "Regex exceptions propagate to terminal_tool's outer handler.",
                "reject_examples": [{"input": "nohup node server.js", "rejected_by": "C2", "reason": "Matches B01 nohup wrapper policy."}]
            },
            {
                "id": "C3", "op": "block-if", "summary": "Detect inline or trailing ampersand backgrounding.",
                "reads": [v_command], "rule": "Regex-search the raw command for either ampersand policy.",
                "policy_refs": ["P_AMPERSAND"], "outcomes": {"match": "T_BLOCK", "no_match": "C4"},
                "on_error": "Regex exceptions propagate to terminal_tool's outer handler.", "reject_examples": []
            },
            {
                "id": "C4", "op": "block-if", "summary": "Detect source-defined long-lived foreground commands.",
                "reads": [v_command], "rule": "Regex-search the raw command against all eight long-lived policies in source order.",
                "policy_refs": ["P_LONG_LIVED"], "outcomes": {"match": "T_BLOCK", "no_match": "T_PASS"},
                "on_error": "Regex exceptions propagate to terminal_tool's outer handler.",
                "reject_examples": [{"input": "python3 -m http.server", "rejected_by": "C4", "reason": "Matches L08 HTTP server policy."}]
            }
        ],
        policies=[
            {
                "id": "P_SHELL_WRAPPER", "kind": "regex-table", "summary": "Shell-level background wrapper matcher.",
                "input_values": [v_command], "match": "Python regex search", "flags": shell_flags, "template": None,
                "rules": [{"id": "B01", "matcher": shell_pattern, "meaning": "nohup, disown, or setsid at regex word boundaries", "outcome": "T_BLOCK"}]
            },
            {
                "id": "P_AMPERSAND", "kind": "regex-table", "summary": "Inline and trailing ampersand backgrounding matchers.",
                "input_values": [v_command], "match": "Python regex search; either entry blocks", "flags": sorted(set(inline_flags + trailing_flags)), "template": None,
                "rules": [
                    {"id": "B02", "matcher": inline_pattern, "meaning": "ampersand surrounded by whitespace", "outcome": "T_BLOCK"},
                    {"id": "B03", "matcher": trailing_pattern, "meaning": "whitespace-prefixed trailing ampersand with optional comment", "outcome": "T_BLOCK"}
                ]
            },
            {
                "id": "P_LONG_LIVED", "kind": "regex-table", "summary": "Eight long-lived foreground command matchers.",
                "input_values": [v_command], "match": "Python regex search in source order", "flags": long_flags or [], "template": None, "rules": long_rules
            }
        ],
        outcomes={
            "T_NOT_EVALUATED": {"decision": "not-evaluated", "effect": "Background terminal calls skip this gate."},
            "T_PASS": {"decision": "pass", "effect": "Return None and continue terminal_tool."},
            "T_BLOCK": {"decision": "block", "effect": "Return guidance text; the callsite returns an error JSON and does not execute the command."}
        },
        state_effects=[], dependencies=[],
        default="Unmatched foreground commands return None and continue.",
        on_error="Errors propagate from the helper and are converted by terminal_tool's outer exception handler into an execution-error JSON result.",
        unresolved=[]
    )
    evidence = {
        "A1": [_span(rel, 1725, 1733)],
        "C1": [_span(rel, 1557, 1575)],
        "C2": [_span(rel, 1542, 1582)],
        "C3": [_span(rel, 1543, 1588)],
        "C4": [_span(rel, 1545, 1598)],
        "P_SHELL_WRAPPER": [_span(rel, 1542)],
        "P_AMPERSAND": [_span(rel, 1543, 1544)],
        "P_LONG_LIVED": [_span(rel, int(long_table_statement.lineno), int(long_table_statement.end_lineno))],
    }
    return BehaviorProfile(
        profile_id="hermes-foreground-guidance/v1", semantic_ir=ir, evidence=evidence,
        legacy_findings=(
            "legacy-ir-mis-scopes-help-normalization",
            "legacy-ir-inexact-help-predicate",
            "legacy-ir-omits-background-activation",
            "legacy-ir-compresses-11-regex-rules",
        )
    )


def _smart_profile(payload: dict[str, Any], source_root: Path) -> BehaviorProfile:
    rel = "tools/approval.py"
    _text, module = _source(source_root, rel)
    function = _function(module, "_smart_approve")
    template = _prompt_template(function)
    required_prompt_text = [
        "APPROVE if the command is clearly safe",
        "DENY if the command could genuinely damage the system",
        "ESCALATE if you're uncertain",
        "Respond with exactly one word: APPROVE, DENY, or ESCALATE",
    ]
    if any(value not in template for value in required_prompt_text):
        raise SemanticCheckError("smart approval prompt policy changed")

    gate_id = str(payload["gate_id"])
    v_command = str(payload["checked_value"]["value_id"])
    v_description = _stable_id(gate_id, "description")
    v_mode = _stable_id(gate_id, "approval-mode")
    v_warnings = _stable_id(gate_id, "warnings")
    v_prompt = _stable_id(gate_id, "review-prompt")
    v_answer_raw = _stable_id(gate_id, "answer-raw")
    v_answer = _stable_id(gate_id, "answer-normalized")
    unresolved = ["external-decision:auxiliary-llm-approval-response"]
    ir = _base(
        payload,
        summary=(
            "Routes warned commands through an auxiliary LLM policy, parses approve or deny substrings in priority order, and escalates uncertainty or failure to manual review."
        ),
        inputs=[
            {"id": v_command, "meaning": "warned terminal command", "source": "_smart_approve.command"},
            {"id": v_description, "meaning": "combined warning descriptions", "source": "_smart_approve.description"},
            {"id": v_mode, "meaning": "configured approval mode", "source": "check_all_command_guards.approval_mode"},
            {"id": v_warnings, "meaning": "unapproved Tirith and dangerous-pattern warnings", "source": "check_all_command_guards.warnings"},
            {"id": v_answer_raw, "meaning": "auxiliary LLM response content, or null content", "source": "_smart_approve.call_llm response"}
        ],
        activation=[
            {"id": "A1", "condition": "warnings is nonempty", "when_true": "A2", "when_false": "T_ALLOW_NO_WARNINGS"},
            {"id": "A2", "condition": "approval_mode == 'smart'", "when_true": "C1", "when_false": "T_MANUAL"}
        ],
        derived_values=[
            {"id": v_prompt, "meaning": "security-review prompt with command and warning description", "sources": [v_command, v_description], "operations": ["interpolate command and description into P_SMART_REVIEW template"], "used_by": ["C1"]},
            {"id": v_answer, "meaning": "normalized auxiliary response", "sources": [v_answer_raw], "operations": ["use empty string for null content", "strip surrounding whitespace", "uppercase"], "used_by": ["C2", "C3"]}
        ],
        entry="A1",
        checks=[
            {
                "id": "C1", "op": "prompt", "summary": "Request an auxiliary security verdict under the embedded review policy.",
                "reads": [v_prompt], "rule": "Call call_llm for task approval with temperature 0 and max_tokens 16.",
                "policy_refs": ["P_SMART_REVIEW"], "outcomes": {"response": "C2", "exception": "T_ESCALATE"},
                "on_error": "Catch every exception and escalate.", "reject_examples": []
            },
            {
                "id": "C2", "op": "allow-if", "summary": "Give APPROVE substring priority over every other response token.",
                "reads": [v_answer], "rule": "If the normalized answer contains APPROVE anywhere, return approve.",
                "policy_refs": [], "outcomes": {"match": "T_APPROVE", "no_match": "C3"},
                "on_error": "Parsing exceptions are caught by the function and escalate.", "reject_examples": []
            },
            {
                "id": "C3", "op": "block-if", "summary": "Recognize DENY only when no APPROVE substring was present.",
                "reads": [v_answer], "rule": "If the normalized answer contains DENY, return deny; otherwise escalate.",
                "policy_refs": [], "outcomes": {"match": "T_DENY", "no_match": "T_ESCALATE"},
                "on_error": "Parsing exceptions are caught by the function and escalate.", "reject_examples": []
            }
        ],
        policies=[
            {
                "id": "P_SMART_REVIEW", "kind": "prompt-policy", "summary": "Source-defined auxiliary command risk-review instructions.",
                "input_values": [v_command, v_description], "match": "External LLM judgment; not deterministic", "flags": [], "template": template,
                "rules": [
                    {"id": "R01", "matcher": "APPROVE if clearly safe, including benign scripts, safe file operations, development tools, package installs, and git operations.", "meaning": "request an APPROVE response for clearly safe commands", "outcome": "T_APPROVE"},
                    {"id": "R02", "matcher": "DENY if genuinely damaging, including important-path recursive deletion, system-file overwrite, fork bombs, disk wiping, or database dropping.", "meaning": "request a DENY response for genuinely dangerous commands", "outcome": "T_DENY"},
                    {"id": "R03", "matcher": "ESCALATE if uncertain.", "meaning": "request escalation for uncertainty", "outcome": "T_ESCALATE"}
                ]
            }
        ],
        outcomes={
            "T_ALLOW_NO_WARNINGS": {"decision": "pass", "effect": "The enclosing guard returns approved before smart review."},
            "T_MANUAL": {"decision": "pending", "effect": "Skip smart review and continue to the configured manual approval route."},
            "T_APPROVE": {"decision": "pass", "effect": "Approve the command, mark smart_approved, and return before manual prompting."},
            "T_DENY": {"decision": "block", "effect": "Return the smart-denied block result and instruct the caller not to retry."},
            "T_ESCALATE": {"decision": "pending", "effect": "Fall through to the manual approval route."}
        },
        state_effects=[
            {"id": "E1", "when": "T_APPROVE", "effect": "Grant session approval for every warning policy key before returning approved."}
        ],
        dependencies=[
            {"id": "DEP_AUX_LLM", "kind": "external-decision", "contract": "May return arbitrary response content or raise after provider routing and retries.", "result_domain": ["content containing APPROVE", "content containing DENY without APPROVE", "other or empty content", "exception"], "affects_outcome": True, "resolved": False}
        ],
        default="Responses containing neither APPROVE nor DENY escalate to manual review.",
        on_error="Every import, provider, request, response-shape, and parsing exception is caught and escalates to manual review.",
        unresolved=unresolved
    )
    evidence = {
        "A1": [_span(rel, 1011, 1012)], "A2": [_span(rel, 1018, 1020)],
        "C1": [_span(rel, 752, 774)], "C2": [_span(rel, 776, 779), _span(rel, 1021, 1029)],
        "C3": [_span(rel, 780, 787), _span(rel, 1030, 1038)], "P_SMART_REVIEW": [_span(rel, 755, 767)],
        "E1": [_span(rel, 1021, 1029)]
    }
    return BehaviorProfile(
        profile_id="hermes-smart-approval/v1", semantic_ir=ir, evidence=evidence,
        legacy_findings=(
            "legacy-ir-omits-description-input",
            "legacy-ir-omits-prompt-policy",
            "legacy-ir-omits-session-state-effect",
            "legacy-ir-marks-outcome-affecting-external-decision-complete",
        )
    )


def _command_type_profile(
    payload: dict[str, Any], source_root: Path
) -> BehaviorProfile | None:
    """Recover the compact V1 contract for the terminal command type guard."""

    if payload.get("project", {}).get("name", "hermes-agent") != "hermes-agent":
        return None
    gate = payload.get("gate", {})
    if (
        gate.get("qualified_function") != "isinstance"
        or gate.get("call_expression") != "isinstance(command, str)"
    ):
        return None
    callsite = payload.get("callsite", {})
    span = callsite.get("span", {})
    rel = str(span.get("file", ""))
    line = span.get("start_line")
    if not rel or not isinstance(line, int):
        raise SemanticCheckError("command type profile requires an exact callsite span")
    _text, module = _source(source_root, rel)
    matches: list[ast.If] = []
    for node in ast.walk(module):
        if not isinstance(node, ast.If) or node.lineno != line:
            continue
        test = node.test
        if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not):
            continue
        call = test.operand
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "isinstance"
            and len(call.args) == 2
            and not call.keywords
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == "command"
            and isinstance(call.args[1], ast.Name)
            and call.args[1].id == "str"
        ):
            continue
        matches.append(node)
    if len(matches) != 1:
        raise SemanticCheckError(
            f"expected one inverted command str guard at {rel}:{line}, got {len(matches)}"
        )
    branch = matches[0]
    branch_source = ast.get_source_segment(_text, branch) or ""
    required_fragments = [
        '"output": ""',
        '"exit_code": -1',
        '"status": "error"',
        "Invalid command: expected string",
    ]
    if any(fragment not in branch_source for fragment in required_fragments):
        raise SemanticCheckError("command type rejection result changed")

    gate_id = str(payload["gate_id"])
    input_id = str(payload["checked_value"]["value_id"])
    output_id = str(gate["output_value_id"])
    ir = {
        "gate_id": gate_id,
        "mode": "predicate",
        "input": f"{input_id}: terminal command value",
        "output": f"{output_id}: pass/block decision; command remains unchanged",
        "summary": "Rejects terminal command values that are not instances of the built-in string type before command execution.",
        "steps": [
            {
                "id": "S1",
                "op": "block-if",
                "rule": "Command is not a str instance; log its type and return error JSON with empty output and exit code -1.",
            }
        ],
        "default": "String instances, including str subclasses, continue unchanged.",
        "on_error": "Unexpected rejection-branch errors propagate to the enclosing terminal exception handler.",
        "reject_examples": [
            {
                "input": "123",
                "rejected_by": "S1",
                "reason": "An integer is not a str instance.",
            }
        ],
        "bypass_examples": [],
        "status": "complete",
    }
    evidence = {
        "S1": [_span(rel, int(branch.lineno), int(branch.end_lineno))]
    }
    return BehaviorProfile(
        profile_id="hermes-command-type/v1",
        semantic_ir=ir,
        evidence=evidence,
        legacy_findings=("legacy-ir-differs-from-source-profile",),
    )


def build_behavior_profile(
    slice_payload: dict[str, Any], source_root: Path
) -> BehaviorProfile | None:
    if (
        slice_payload.get("project", {}).get("name", "hermes-agent")
        != "hermes-agent"
    ):
        return None
    qualified = str(slice_payload.get("gate", {}).get("qualified_function", ""))
    if qualified == "tools.approval.detect_hardline_command":
        return _hardline_profile(slice_payload, source_root)
    if qualified == "tools.terminal_tool._foreground_background_guidance":
        return _foreground_profile(slice_payload, source_root)
    if qualified == "tools.approval._smart_approve":
        return _smart_profile(slice_payload, source_root)
    return None


def validate_behavior_semantic_ir(
    ir: dict[str, Any], *, expected: dict[str, Any] | None = None
) -> list[str]:
    """Validate graph references, value scoping, completeness, and optional profile equality."""

    errors: list[str] = []
    if not isinstance(ir, dict):
        return ["behavior semantic IR must be an object"]
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        from jsonschema import Draft202012Validator

        for error in Draft202012Validator(schema).iter_errors(ir):
            location = ".".join(str(item) for item in error.absolute_path)
            errors.append(f"{location or 'semantic_ir'}: {error.message}")
    except ImportError:
        if ir.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"schema_version must equal {SCHEMA_VERSION}")

    input_ids = {
        item.get("id") for item in ir.get("inputs", []) if isinstance(item, dict)
    }
    derived_ids = {
        item.get("id")
        for item in ir.get("derived_values", [])
        if isinstance(item, dict)
    }
    value_ids = input_ids | derived_ids
    if None in value_ids:
        errors.append("every input and derived value must have an ID")
    if len(value_ids) != len(ir.get("inputs", [])) + len(ir.get("derived_values", [])):
        errors.append("input and derived value IDs must be unique")
    check_ids = {item.get("id") for item in ir.get("checks", []) if isinstance(item, dict)}
    activation_ids = {item.get("id") for item in ir.get("activation", []) if isinstance(item, dict)}
    outcome_ids = set(ir.get("outcomes", {})) if isinstance(ir.get("outcomes"), dict) else set()
    policy_ids = {item.get("id") for item in ir.get("policies", []) if isinstance(item, dict)}
    targets = check_ids | activation_ids | outcome_ids
    if ir.get("entry") not in targets:
        errors.append("entry references an unknown activation, check, or outcome")
    for activation in ir.get("activation", []):
        if isinstance(activation, dict):
            for key in ("when_true", "when_false"):
                if activation.get(key) not in targets:
                    errors.append(f"activation {activation.get('id')} has unknown target {activation.get(key)}")
    for check in ir.get("checks", []):
        if not isinstance(check, dict):
            continue
        for value_id in check.get("reads", []):
            if value_id not in value_ids:
                errors.append(f"check {check.get('id')} reads unknown value {value_id}")
        for policy_id in check.get("policy_refs", []):
            if policy_id not in policy_ids:
                errors.append(f"check {check.get('id')} references unknown policy {policy_id}")
        for target in check.get("outcomes", {}).values():
            if target not in targets:
                errors.append(f"check {check.get('id')} has unknown target {target}")
    for derived in ir.get("derived_values", []):
        if not isinstance(derived, dict):
            continue
        for source_id in derived.get("sources", []):
            if source_id not in value_ids:
                errors.append(
                    f"derived value {derived.get('id')} has unknown source {source_id}"
                )
        for check_id in derived.get("used_by", []):
            if check_id not in check_ids:
                errors.append(f"derived value {derived.get('id')} has unknown user {check_id}")
    for policy in ir.get("policies", []):
        if not isinstance(policy, dict):
            continue
        for value_id in policy.get("input_values", []):
            if value_id not in value_ids:
                errors.append(
                    f"policy {policy.get('id')} reads unknown value {value_id}"
                )
        for rule in policy.get("rules", []):
            if isinstance(rule, dict) and rule.get("outcome") not in outcome_ids:
                errors.append(
                    f"policy {policy.get('id')} rule {rule.get('id')} has unknown outcome {rule.get('outcome')}"
                )
    for effect in ir.get("state_effects", []):
        if isinstance(effect, dict) and effect.get("when") not in outcome_ids:
            errors.append(
                f"state effect {effect.get('id')} has unknown outcome {effect.get('when')}"
            )
    unresolved = ir.get("unresolved", [])
    status = ir.get("status")
    completeness = ir.get("completeness", {})
    if unresolved and status != "partial":
        errors.append("unresolved dependencies require partial status")
    if status != completeness.get("overall"):
        errors.append("status must equal completeness.overall")
    unresolved_dependencies = [
        dependency
        for dependency in ir.get("dependencies", [])
        if isinstance(dependency, dict)
        and dependency.get("affects_outcome") is True
        and dependency.get("resolved") is False
    ]
    if unresolved_dependencies and not unresolved:
        errors.append("unresolved outcome-affecting dependencies require unresolved entries")
    if unresolved_dependencies and completeness.get("dependencies") != "partial":
        errors.append("unresolved outcome-affecting dependencies require partial dependency completeness")
    if expected is not None and ir != expected:
        errors.append("semantic IR differs from the deterministic source profile")

    from .contracts import estimate_tokens

    if estimate_tokens(ir) > HARD_TOKEN_LIMIT:
        errors.append(f"behavior semantic IR exceeds {HARD_TOKEN_LIMIT} tokens")
    return errors


def check_and_upgrade_semantic(
    *,
    slice_payload: dict[str, Any],
    semantic_ir: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    source_root: Path,
) -> tuple[
    dict[str, Any],
    dict[str, list[dict[str, Any]]],
    dict[str, Any],
]:
    """Return a checked V3 when a deterministic source profile exists."""

    compact_profile = _command_type_profile(slice_payload, source_root)
    if compact_profile is not None:
        expected = copy.deepcopy(compact_profile.semantic_ir)
        from .contracts import validate_semantic_ir

        errors = validate_semantic_ir(
            expected,
            expected_gate_id=str(slice_payload["gate_id"]),
            expected_mode=str(slice_payload["gate"]["mode"]),
            expected_input_id=str(slice_payload["checked_value"]["value_id"]),
            expected_output_id=str(slice_payload["gate"]["output_value_id"]),
        )
        if errors:
            raise SemanticCheckError("; ".join(errors))
        if semantic_ir == expected:
            return expected, copy.deepcopy(compact_profile.evidence), {
                "checker_version": CHECKER_VERSION,
                "verdict": "verified",
                "profile_id": compact_profile.profile_id,
                "original_schema_version": "gate-semantic-ir/v1",
                "final_schema_version": "gate-semantic-ir/v1",
                "findings": [],
                "source_coverage_units": sorted(compact_profile.evidence),
            }
        return expected, copy.deepcopy(compact_profile.evidence), {
            "checker_version": CHECKER_VERSION,
            "verdict": "recovered",
            "profile_id": compact_profile.profile_id,
            "original_schema_version": semantic_ir.get(
                "schema_version", "gate-semantic-ir/v1"
            ),
            "final_schema_version": "gate-semantic-ir/v1",
            "findings": list(compact_profile.legacy_findings),
            "original_semantic_ir": semantic_ir,
            "source_coverage_units": sorted(compact_profile.evidence),
        }

    profile = build_behavior_profile(slice_payload, source_root)
    if profile is None:
        return semantic_ir, evidence, {
            "checker_version": CHECKER_VERSION,
            "verdict": "not-profiled",
            "profile_id": None,
            "original_schema_version": semantic_ir.get("schema_version", "gate-semantic-ir/v1"),
            "final_schema_version": semantic_ir.get("schema_version", "gate-semantic-ir/v1"),
            "findings": ["no-deterministic-source-profile"],
        }

    upgraded = copy.deepcopy(profile.semantic_ir)
    errors = validate_behavior_semantic_ir(upgraded, expected=profile.semantic_ir)
    if errors:
        raise SemanticCheckError("; ".join(errors))
    if semantic_ir.get("schema_version") == SCHEMA_VERSION and semantic_ir == upgraded:
        return upgraded, copy.deepcopy(profile.evidence), {
            "checker_version": CHECKER_VERSION,
            "verdict": "verified",
            "profile_id": profile.profile_id,
            "original_schema_version": SCHEMA_VERSION,
            "final_schema_version": SCHEMA_VERSION,
            "findings": [],
            "source_coverage_units": sorted(profile.evidence),
        }
    report = {
        "checker_version": CHECKER_VERSION,
        "verdict": "recovered",
        "profile_id": profile.profile_id,
        "original_schema_version": semantic_ir.get("schema_version", "gate-semantic-ir/v1"),
        "final_schema_version": SCHEMA_VERSION,
        "findings": list(profile.legacy_findings),
        "original_semantic_ir": semantic_ir,
        "source_coverage_units": sorted(profile.evidence),
    }
    return upgraded, copy.deepcopy(profile.evidence), report
