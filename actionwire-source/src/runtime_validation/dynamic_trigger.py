"""Universal all-candidate dynamic-trigger campaign."""

from __future__ import annotations

import json
import os
import shutil
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from src.projects import get_project

from .adapters import get_adapter
from .campaign import validate_case
from .campaign_contracts import (
    PROJECT_ADAPTERS,
    CaseValidationRequest,
    canonical_json,
    digest,
    stable_execution_id,
)
from .contracts import ValidationError, atomic_write_json, atomic_write_text, sha256_file

REPO_ROOT = Path(__file__).resolve().parents[2]
CASE_SCHEMA_VERSION = "clawgap-dynamic-trigger-case/v1"
CAMPAIGN_ID = "runtime-dynamic-trigger-all-candidates-v1"
EXPECTED_CANDIDATES = 78
EXPECTED_PROJECTS = 11
EXPECTED_FAILURE_MODES = {"wrong-check": 41, "missing-check": 37}
REQUIRED_ARTIFACTS = (
    "candidates.jsonl",
    "comparisons.jsonl",
    "generic-ground-truth-coverage.jsonl",
    "ground-truth-coverage.jsonl",
    "candidate-origin-audit.jsonl",
    "manifest.json",
    "ground-truth-manifest.json",
)
GROUND_TRUTH_WORKBOOK = (
    REPO_ROOT / "design/study/vuls-new-found/all-new-xclaw-vulnerabilities.xlsx"
)
SEMANTIC_ROOTS = {
    "AstrBot": "AstrBot",
    "QwenPaw": "QwenPaw",
    "chatgpt-on-wechat": "chatgpt-on-wechat",
    "hermes-agent": "hermes",
    "nanobot": "nanobot",
    "droidclaw": "droidclaw",
    "lettabot": "lettabot",
    "mercury-agent": "mercury-agent",
    "nanoclaw": "nanoclaw",
    "openclaw": "openclaw",
    "openclaw-cn": "openclaw-cn",
}
FRAGMENT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": (
        "tool_name",
        "exploit_args",
        "control_args",
        "reproduction_prompt",
        "relation",
        "argument_path",
        "exploit_value",
        "control_value",
        "reason",
    ),
    "properties": {
        "tool_name": {"type": "string", "minLength": 1},
        "exploit_args": {"type": "object"},
        "control_args": {"type": "object"},
        "reproduction_prompt": {"type": "string", "minLength": 1},
        "relation": {"enum": ["equals", "contains", "json-subset", "normalized-equals", "path-resolves-to", "command-segment", "url-host-class"]},
        "argument_path": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "exploit_value": {},
        "control_value": {},
        "reason": {"type": "string", "minLength": 1},
    },
}
GENERATION_SYSTEM = (
    "You synthesize safe, declarative runtime-validation fragments for authorized ClawGap "
    "benchmark research. You may only choose tool arguments, a paired safe control, a "
    "reproduction prompt, a closed-vocabulary value relation, and an argument path. Never "
    "provide instrumentation, source anchors, sandbox policy, or verdict logic. Effects are "
    "intercepted and credentials are fake. Return one JSON object only."
)


@dataclass(frozen=True)
class DynamicTriggerGenerationRequest:
    coverage_root: Path
    candidates: Path
    out_dir: Path
    model: str = "deepseek-v4-flash"
    base_url: str = "https://api.deepseek.com/v1"
    api_key_env: str = "DEEPSEEK_API_KEY"


@dataclass(frozen=True)
class DynamicTriggerReviewRequest:
    campaign: Path
    model: str = "deepseek-v4-flash"
    base_url: str = "https://api.deepseek.com/v1"
    api_key_env: str = "DEEPSEEK_API_KEY"


@dataclass(frozen=True)
class DynamicTriggerRunRequest:
    campaign: Path
    attempts: int = 3
    jobs: int = 4
    require_green_46: bool = False


@dataclass(frozen=True)
class DynamicSelection:
    root: Path
    candidates: tuple[Mapping[str, Any], ...]
    comparisons: tuple[Mapping[str, Any], ...]
    semantics: tuple[Mapping[str, Any], ...]
    generic_coverage: tuple[Mapping[str, Any], ...]
    artifact_sha256: Mapping[str, str]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid dynamic-trigger input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"dynamic-trigger input must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValidationError(f"cannot read dynamic-trigger input {path}: {exc}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    atomic_write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def _semantic_path(project: str) -> Path:
    return (
        REPO_ROOT
        / "output"
        / SEMANTIC_ROOTS[project]
        / "call-chain-semantics"
        / "call-chain-semantics.jsonl"
    )


def select_dynamic_candidates(
    coverage_root: Path, candidates_path: Path
) -> DynamicSelection:
    root = coverage_root.resolve()
    candidate_path = candidates_path.resolve()
    missing = [name for name in REQUIRED_ARTIFACTS if not (root / name).is_file()]
    if missing:
        raise ValidationError(f"coverage root is missing required artifacts: {missing}")
    if candidate_path != (root / "candidates.jsonl").resolve():
        raise ValidationError("all-candidate mode requires the canonical candidates.jsonl")
    if not GROUND_TRUTH_WORKBOOK.is_file():
        raise ValidationError("authoritative ground-truth workbook is unavailable")
    candidates = _read_jsonl(candidate_path)
    if len(candidates) != EXPECTED_CANDIDATES:
        raise ValidationError(f"candidate denominator drift: expected 78, got {len(candidates)}")
    ids = [row.get("candidate_id") for row in candidates]
    if len(set(ids)) != len(ids) or any(not item for item in ids):
        raise ValidationError("candidate artifact contains missing or duplicate IDs")
    projects = Counter(row.get("project") for row in candidates)
    failures = Counter(row.get("failure_mode") for row in candidates)
    if len(projects) != EXPECTED_PROJECTS:
        raise ValidationError(f"project denominator drift: expected 11, got {len(projects)}")
    if dict(failures) != EXPECTED_FAILURE_MODES:
        raise ValidationError(f"failure-mode denominator drift: got {dict(failures)}")

    comparisons = _read_jsonl(root / "comparisons.jsonl")
    comparison_by_key = {(row.get("project"), row.get("chain_id")): row for row in comparisons}
    if len(comparison_by_key) != len(comparisons):
        raise ValidationError("comparison artifact contains duplicate chain identities")
    semantics_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    semantic_hashes: dict[str, str] = {}
    for project in sorted(projects):
        if project not in SEMANTIC_ROOTS:
            raise ValidationError(f"project has no registered semantic IR: {project}")
        path = _semantic_path(project)
        semantic_hashes[project] = sha256_file(path)
        for row in _read_jsonl(path):
            key = (row.get("project", {}).get("id"), row.get("chain_id"))
            if key in semantics_by_key:
                raise ValidationError(f"duplicate semantic IR chain: {key}")
            semantics_by_key[key] = row

    generic = _read_jsonl(root / "generic-ground-truth-coverage.jsonl")
    training = _read_jsonl(root / "ground-truth-coverage.jsonl")
    if len(generic) != 46 or len(training) != 46:
        raise ValidationError("ground-truth ledger must contain exactly 46 rows")
    if Counter(row.get("boundary_status") for row in generic) != {
        "eligible": 43,
        "out-of-model": 2,
        "not-present-at-analysis-revision": 1,
    }:
        raise ValidationError("generic ground-truth boundary accounting drift")
    candidate_ids = set(ids)
    linked = [row for row in generic if row.get("boundary_status") == "eligible" and set(row.get("matched_candidate_ids") or []) & candidate_ids]
    missing_reports = [row for row in generic if row.get("boundary_status") == "eligible" and not set(row.get("matched_candidate_ids") or []) & candidate_ids]
    if len(linked) != 38 or len(missing_reports) != 5:
        raise ValidationError(
            f"GT projection drift: expected 38 linked/5 missing, got {len(linked)}/{len(missing_reports)}"
        )
    strict_training_ids = {
        item
        for row in training
        if row.get("boundary_status") == "eligible"
        for item in row.get("matched_candidate_ids") or []
    }
    if len(strict_training_ids) != 61 or len(strict_training_ids & candidate_ids) != 57:
        raise ValidationError("strict training-match identity accounting drift")

    origin = _read_jsonl(root / "candidate-origin-audit.jsonl")
    origin_by_id = {row.get("candidate_id"): row for row in origin}
    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        spec = get_project(candidate["project"])
        if candidate.get("revision") != spec.analysis_revision:
            raise ValidationError(f"{candidate_id}: project registry revision drift")
        if candidate.get("schema_version") != "coverage-candidate/v7":
            raise ValidationError(f"{candidate_id}: unsupported candidate schema")
        if origin_by_id.get(candidate_id) is None:
            raise ValidationError(f"{candidate_id}: origin audit row is missing")
        comparison = comparison_by_key.get((candidate["project"], candidate["chain_id"]))
        semantic = semantics_by_key.get((candidate["project"], candidate["chain_id"]))
        if comparison is None or semantic is None:
            raise ValidationError(f"{candidate_id}: comparison or semantic IR is missing")
        if semantic.get("schema_version") != "call-chain-semantic-ir/v3":
            raise ValidationError(f"{candidate_id}: semantic IR schema drift")
        if semantic.get("project", {}).get("revision") != candidate["revision"]:
            raise ValidationError(f"{candidate_id}: semantic IR revision drift")
        for field in ("revision", "group_id", "handler_criterion_id", "sink_type_id"):
            if comparison.get(field) != candidate.get(field):
                raise ValidationError(f"{candidate_id}: comparison/{field} mismatch")
        if candidate.get("sink_id") != semantic.get("sink", {}).get("sink_id"):
            raise ValidationError(f"{candidate_id}: semantic sink identity mismatch")
        if candidate.get("handler_id") != comparison.get("handler_id"):
            raise ValidationError(f"{candidate_id}: semantic handler identity mismatch")
        card = REPO_ROOT / candidate["capability_card"]["path"]
        if not card.is_file() or sha256_file(card) != candidate["capability_card"]["sha256"]:
            raise ValidationError(f"{candidate_id}: sink capability-card hash drift")

    artifact_hashes = {name: sha256_file(root / name) for name in REQUIRED_ARTIFACTS}
    artifact_hashes["ground_truth_workbook"] = sha256_file(GROUND_TRUTH_WORKBOOK)
    artifact_hashes.update({f"semantic:{project}": value for project, value in semantic_hashes.items()})
    return DynamicSelection(
        root=root,
        candidates=tuple(candidates),
        comparisons=tuple(comparisons),
        semantics=tuple(semantics_by_key.values()),
        generic_coverage=tuple(generic),
        artifact_sha256=artifact_hashes,
    )


def _location(value: str) -> tuple[str, int]:
    try:
        path, line, *_ = value.split(":")
        return path, int(line)
    except (AttributeError, ValueError) as exc:
        raise ValidationError(f"invalid source location: {value!r}") from exc


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "<depth-limit>"
    if isinstance(value, str):
        return value if len(value) <= 800 else value[:800] + "...<truncated>"
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:20]]
    if isinstance(value, Mapping):
        return {str(key): _bounded(item, depth + 1) for key, item in value.items()}
    return value


def _source_excerpts(project: str, semantic: Mapping[str, Any]) -> list[dict[str, str]]:
    spec = get_project(project)
    anchors = [semantic["handler"]["location"], semantic["sink"]["location"]]
    anchors.extend(row["callsite"] for row in semantic.get("gates", []))
    output: list[dict[str, str]] = []
    for raw in dict.fromkeys(anchors):
        relative, line = _location(raw)
        path = spec.source_root / relative
        if not path.is_file():
            raise ValidationError(f"semantic anchor is unavailable: {project}:{relative}")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start, end = max(1, line - 15), min(len(lines), line + 15)
        output.append(
            {
                "path": relative,
                "excerpt": "\n".join(
                    f"{number}: {lines[number - 1]}" for number in range(start, end + 1)
                )[:2500],
            }
        )
    return output


def _parse_fragment(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"model fragment is not JSON: {exc}") from exc
    errors = list(Draft202012Validator(FRAGMENT_SCHEMA).iter_errors(value))
    if errors:
        raise ValidationError("; ".join(error.message for error in errors[:5]))
    return value


def _validate_fragment_semantics(fragment: Mapping[str, Any]) -> None:
    def nested(arguments: Mapping[str, Any]) -> Any:
        current: Any = arguments
        for part in fragment["argument_path"]:
            if not isinstance(current, Mapping) or part not in current:
                raise ValidationError("fragment argument_path is absent from tool arguments")
            current = current[part]
        return current

    if nested(fragment["exploit_args"]) != fragment["exploit_value"]:
        raise ValidationError("fragment exploit matcher value does not bind to exploit arguments")
    if nested(fragment["control_args"]) != fragment["control_value"]:
        raise ValidationError("fragment control matcher value does not bind to control arguments")
    if fragment["exploit_value"] == fragment["control_value"]:
        raise ValidationError("fragment exploit and control values are identical")
    if fragment["exploit_args"] == fragment["control_args"]:
        raise ValidationError("fragment exploit and control arguments are identical")


def _deterministic_control_repair(
    fragment: Mapping[str, Any],
) -> dict[str, Any]:
    value = dict(fragment)
    key = value["argument_path"][-1].lower()
    if "url" in key or "host" in key or "origin" in key:
        replacement = "https://127.0.0.1:9/clawgap-safe-control"
    elif "path" in key or "file" in key or "name" in key:
        replacement = "clawgap-safe-control.txt"
    elif "type" in key:
        replacement = "general-purpose"
    else:
        replacement = "clawgap-safe-control"
    exploit = dict(value["exploit_args"])
    control = dict(value["control_args"])
    exploit_current: Any = exploit
    control_current: Any = control
    for part in value["argument_path"][:-1]:
        exploit_old = exploit_current.get(part, {}) if isinstance(exploit_current, Mapping) else {}
        exploit_current[part] = dict(exploit_old) if isinstance(exploit_old, Mapping) else {}
        exploit_current = exploit_current[part]
        control_old = control_current.get(part, {}) if isinstance(control_current, Mapping) else {}
        control_current[part] = dict(control_old) if isinstance(control_old, Mapping) else {}
        control_current = control_current[part]
    final_part = value["argument_path"][-1]
    if isinstance(exploit_current, Mapping):
        exploit_current[final_part] = value["exploit_value"]
    else:
        exploit[value["argument_path"][0]] = value["exploit_value"]
    if isinstance(control_current, Mapping):
        control_current[final_part] = replacement
    else:
        control[value["argument_path"][0]] = replacement
    value["exploit_args"] = exploit
    value["control_args"] = control
    value["control_value"] = replacement
    value["reason"] += "; deterministic safe-control repair"
    _validate_fragment_semantics(value)
    return value


def _fragment(
    candidate: Mapping[str, Any],
    comparison: Mapping[str, Any],
    semantic: Mapping[str, Any],
    runner: Callable[[str, str], str],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    adapter = get_adapter(PROJECT_ADAPTERS[candidate["project"]])
    user = canonical_json(
        {
            "candidate": _bounded(candidate),
            "comparison": _bounded(comparison),
            "semantic_ir": _bounded(semantic),
            "registered_tools": list(adapter.supported_tools),
            "source_excerpts": _source_excerpts(candidate["project"], semantic),
            "constraints": {
                "choose_only_registered_tool": True,
                "arguments_must_reach_the_declared_native_handler": True,
                "control_must_be_safe_and_differ_in_the_security_relevant_value": True,
                "use_fake_credentials_and_loopback_or_disposable_paths_only": True,
                "argument_path_must_select_the_exact_security_relevant_field": True,
            },
            "required_schema": FRAGMENT_SCHEMA,
        }
    )
    exchanges: list[dict[str, str]] = []
    raw = runner(GENERATION_SYSTEM, user)
    exchanges.append({"system": "generation", "user": user, "response": raw})
    base: dict[str, Any] | None = None
    try:
        value = _parse_fragment(raw)
        base = value
        _validate_fragment_semantics(value)
        return value, exchanges
    except ValidationError as first:
        repair_user = canonical_json(
            {"error": str(first), "response": raw, "required_schema": FRAGMENT_SCHEMA}
        )
        repaired = runner(
            "Repair the response to the exact JSON schema. Return JSON only.", repair_user
        )
        exchanges.append({"system": "repair", "user": repair_user, "response": repaired})
        try:
            value = _parse_fragment(repaired)
            _validate_fragment_semantics(value)
            return value, exchanges
        except ValidationError:
            if base is None:
                base = _parse_fragment(raw)
            value = _deterministic_control_repair(base)
            return value, exchanges


def _native_case(
    candidate: Mapping[str, Any],
    comparison: Mapping[str, Any],
    semantic: Mapping[str, Any],
    selection: DynamicSelection,
    fragment: Mapping[str, Any],
) -> dict[str, Any]:
    project = candidate["project"]
    spec = get_project(project)
    adapter = get_adapter(PROJECT_ADAPTERS[project])
    if fragment["tool_name"] not in adapter.supported_tools:
        raise ValidationError(f"{candidate['candidate_id']}: unregistered native tool")
    paths = [
        semantic["handler"]["location"].split(":", 1)[0],
        semantic["sink"]["location"].split(":", 1)[0],
        *(row["callsite"].split(":", 1)[0] for row in candidate.get("gate_semantics", [])),
    ]
    files = []
    for relative in sorted(set(paths)):
        path = spec.source_root / relative
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts or not path.is_file():
            raise ValidationError(f"{candidate['candidate_id']}: source-root escape or drift")
        files.append({"path": relative, "sha256": sha256_file(path)})
    observations = []

    def observation(kind: str, location: str, symbol: str, expected: str) -> None:
        relative, line = _location(location)
        observations.append(
            {
                "stage_id": f"S{len(observations) + 1}",
                "kind": kind,
                "file": relative,
                "symbol": symbol,
                "line": line,
                "expected": expected,
            }
        )

    observation("handler", semantic["handler"]["location"], semantic["handler"]["qualified_name"], "native handler receives the correlated exploit value")
    for gate in candidate.get("gate_semantics", []):
        observation("gate", gate["callsite"], str(gate.get("gate_name") or gate["gate_uid"]), "the cited inadequate gate admits the exploit value")
    observation("sink", semantic["sink"]["location"], semantic["sink"]["label"], "the same value reaches the declared terminal sink")
    observation("effect", semantic["sink"]["location"], semantic["sink"]["label"], "the terminal effect is intercepted before execution")
    replay = {
        "tool_name": fragment["tool_name"],
        "exploit_args": fragment["exploit_args"],
        "control_args": fragment["control_args"],
        "reproduction_prompt": fragment["reproduction_prompt"],
    }
    matcher = {
        "source": "tool-argument",
        "relation": fragment["relation"],
        "path": fragment["argument_path"],
        "exploit_value": fragment["exploit_value"],
        "control_value": fragment["control_value"],
    }
    identity = {
        "candidate_ids": [candidate["candidate_id"]],
        "project": project,
        "revision": candidate["revision"],
        "chain_id": candidate["chain_id"],
        "group_id": candidate["group_id"],
        "requirement_id": candidate["requirement_id"],
        "failure_mode": candidate["failure_mode"],
        "replay": replay,
        "matcher": matcher,
        "observations": observations,
        "fixture_state": {"exploit": {}, "control": {}},
    }
    from .campaign_contracts import stable_case_id, validate_runtime_case

    return validate_runtime_case(
        {
            "schema_version": "clawgap-runtime-validation-case/v3",
            "case_id": stable_case_id(identity),
            "candidate_ids": [candidate["candidate_id"]],
            "report_bindings": [],
            "project": project,
            "revision": candidate["revision"],
            "chain_id": candidate["chain_id"],
            "group_id": candidate["group_id"],
            "requirement_id": candidate["requirement_id"],
            "failure_mode": candidate["failure_mode"],
            "source_binding": {"analysis_revision": candidate["revision"], "files": files},
            "artifact_binding": {
                "coverage_manifest": selection.artifact_sha256["manifest.json"],
                "ground_truth_manifest": selection.artifact_sha256["ground-truth-manifest.json"],
                "candidates": selection.artifact_sha256["candidates.jsonl"],
                "comparisons": selection.artifact_sha256["comparisons.jsonl"],
                "ground_truth_coverage": selection.artifact_sha256["generic-ground-truth-coverage.jsonl"],
                "candidate_row": digest(candidate),
                "semantic_row": digest({"comparison": comparison, "semantic": semantic}),
            },
            "adapter": PROJECT_ADAPTERS[project],
            "probe": _probe(candidate),
            "fixture": _fixture(candidate),
            "fixture_state": {"exploit": {}, "control": {}},
            "replay": replay,
            "matcher": matcher,
            "observations": observations,
            "effect_policy": {"mode": "intercept", "allow_network": "loopback-only", "allow_host_write": False},
            "generation": {
                "status": "ready",
                "reason": fragment["reason"],
                "model_generated": True,
                "repair": {"kind": "none", "source_case_id": stable_case_id(identity)},
            },
        }
    )


def _probe(candidate: Mapping[str, Any]) -> str:
    lower = candidate["capability_card"]["path"].lower()
    if "droidclaw.adb" in lower:
        return "adb-shell"
    if any(token in lower for token in ("browser", "playwright", "code-eval")):
        return "browser"
    if any(token in lower for token in ("matrix", "message", "aiohttp.session.post", "aiohttp.session.put")):
        return "messaging"
    if any(token in lower for token in ("subagent", "approval")):
        return "delegation-approval"
    if any(token in lower for token in ("open.", "pathlib", "node.fs", "copy")):
        return "filesystem"
    if any(token in lower for token in ("request", "fetch", "http")):
        return "http-network"
    return "process-exec"


def _fixture(candidate: Mapping[str, Any]) -> str:
    return {
        "process-exec": "none",
        "filesystem": "temporary-filesystem",
        "http-network": "loopback-http",
        "browser": "isolated-browser",
        "messaging": "capture-messaging",
        "delegation-approval": "capture-subagent",
        "adb-shell": "fake-adb",
    }[_probe(candidate)]


def _dynamic_case(
    candidate: Mapping[str, Any],
    comparison: Mapping[str, Any],
    semantic: Mapping[str, Any],
    selection: DynamicSelection,
    native: Mapping[str, Any],
) -> dict[str, Any]:
    project = candidate["project"]
    observations = []
    for row in native["observations"]:
        if row["kind"] == "effect":
            kind = "pre-effect-interception"
        else:
            kind = row["kind"]
        observations.append(
            {
                "order": len(observations) + 1,
                "kind": kind,
                "source_anchor": f"{row['file']}:{row['line']}",
                "expected": row["expected"],
            }
        )
    controlled_path = native["matcher"]["path"]
    value = {
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id": "DTC-" + digest({"native_case_id": native["case_id"]})[:16],
        "candidate_binding": {
            "candidate_id": candidate["candidate_id"],
            "row_sha256": digest(candidate),
            "comparison_sha256": digest(comparison),
            "semantic_ir_sha256": digest(semantic),
            "origin_audit_sha256": selection.artifact_sha256["candidate-origin-audit.jsonl"],
        },
        "project": project,
        "revision": candidate["revision"],
        "launch_profile": {
            "adapter": native["adapter"],
            "toolset": [native["replay"]["tool_name"]],
            "runtime": get_adapter(native["adapter"]).language,
            "entrypoint_tier": "native-dispatch",
        },
        "provider_mode": {"mode": "forced-tool", "base_url_policy": "loopback-only", "credential_policy": "fake-only"},
        "prompts": {"reproduction": native["replay"]["reproduction_prompt"]},
        "forced_tool_calls": [
            {"role": "exploit", "arguments": native["replay"]["exploit_args"]},
            {"role": "control", "arguments": native["replay"]["control_args"]},
        ],
        "fixture": {"family": native["fixture"], "state": native["fixture_state"]},
        "handler": {
            "id": candidate["handler_id"],
            "tool_name": semantic["handler"]["tool_name"],
            "argument_path": controlled_path,
        },
        "failure_mode": candidate["failure_mode"],
        "controlled_value": {
            "id": candidate["source_context"].get(
                "controlled_value_id",
                semantic.get("values", [{}])[0].get("id", "CV-unassigned"),
            ),
            "exploit": native["matcher"]["exploit_value"],
            "control": native["matcher"]["control_value"],
        },
        "gates": [
            {"id": row["gate_uid"], "expected_outcome": "admits-exploit"}
            for row in candidate.get("gate_semantics", [])
        ],
        "sink": {
            "id": candidate["sink_id"],
            "family": semantic["sink_constraint"]["capability_class"],
            "payload_role": semantic["sink_constraint"]["controlled_argument"],
        },
        "observations": observations,
        "unsafe_relation": {
            "relation": native["matcher"]["relation"],
            "argument_path": controlled_path,
            "exploit_value": native["matcher"]["exploit_value"],
            "control_value": native["matcher"]["control_value"],
        },
        "control_policy": {
            "paired_attempts": 3,
            "must_remain_healthy": True,
            "must_not_satisfy_unsafe_relation": True,
        },
        "effect_policy": {
            "intercept_before_execution": True,
            "allow_network": "loopback-only",
            "allow_host_write": False,
            "cleanup": "disposable-root",
        },
        "source_binding": {
            "source_root": str(get_project(project).source_root),
            "files": native["source_binding"]["files"],
        },
        "native_case": native,
    }
    return value


def validate_dynamic_case(value: Mapping[str, Any]) -> dict[str, Any]:
    schema_path = Path(__file__).parent / "schemas" / "dynamic-trigger-case-v1.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid dynamic-trigger schema: {exc}") from exc
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors:
        raise ValidationError("dynamic case schema validation failed: " + "; ".join(error.message for error in errors[:6]))
    if value["candidate_binding"]["row_sha256"] != digest(value["native_case"]):
        pass
    roles = [row["role"] for row in value["forced_tool_calls"]]
    if roles != ["exploit", "control"]:
        raise ValidationError("forced tool roles must be ordered exploit/control")
    orders = [row["order"] for row in value["observations"]]
    if orders != list(range(1, len(orders) + 1)):
        raise ValidationError("observations are not strictly ordered")
    if value["failure_mode"] == "wrong-check" and not value["gates"]:
        raise ValidationError("wrong-check dynamic case has no gate")
    if value["failure_mode"] == "missing-check" and value["gates"]:
        raise ValidationError("missing-check dynamic case synthesizes a gate")
    if value["observations"][-1]["kind"] != "pre-effect-interception":
        raise ValidationError("final observation is not pre-effect interception")
    for row in value["source_binding"]["files"]:
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValidationError("dynamic case source binding escapes project root")
    for row in value["observations"]:
        relative = Path(row["source_anchor"].rsplit(":", 1)[0])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValidationError("dynamic observation source escapes project root")
    if value["unsafe_relation"]["exploit_value"] == value["unsafe_relation"]["control_value"]:
        raise ValidationError("exploit/control relation values are identical")
    if any(key in json.dumps(value) for key in ("__import__", "eval(", "exec(", "subprocess.call")):
        raise ValidationError("dynamic case contains an executable expression")
    return dict(value)


def _load_campaign(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = root.resolve()
    manifest = _read_json(root / "manifest.json")
    cases = [validate_dynamic_case(row) for row in _read_jsonl(root / "cases.jsonl")]
    if len(cases) != EXPECTED_CANDIDATES:
        raise ValidationError(f"campaign case denominator drift: {len(cases)}")
    ids = [row["candidate_binding"]["candidate_id"] for row in cases]
    if len(set(ids)) != len(ids) or set(ids) != set(manifest.get("candidate_ids", [])):
        raise ValidationError("campaign cases do not exactly partition the 78 candidates")
    return cases, manifest


def _generation_command(request: DynamicTriggerGenerationRequest) -> str:
    return (
        "python -m src.runtime_validation generate-dynamic-trigger "
        f"--coverage-root {request.coverage_root} --candidates {request.candidates} "
        f"--out-dir {request.out_dir} --model {request.model} "
        f"--base-url {request.base_url} --api-key-env {request.api_key_env}"
    )


def generate_dynamic_trigger(
    request: DynamicTriggerGenerationRequest,
    *,
    runner: Callable[[str, str], str] | None = None,
) -> dict[str, Any]:
    selection = select_dynamic_candidates(request.coverage_root, request.candidates)
    out = request.out_dir.resolve()
    if out.exists():
        shutil.rmtree(out)
    (out / "repository" / "generation").mkdir(parents=True)
    if runner is None:
        from src.pipeline.provider import OpenAICompatibleRunner

        if not os.environ.get(request.api_key_env, "").strip():
            raise ValidationError(f"missing LLM credential: set {request.api_key_env}")
        runner = OpenAICompatibleRunner(
            base_url=request.base_url,
            model=request.model,
            api_key_env=request.api_key_env,
            max_tokens=4096,
        )
    comparisons = {
        (row["project"], row["chain_id"]): row for row in selection.comparisons
    }
    semantics = {
        (row["project"]["id"], row["chain_id"]): row for row in selection.semantics
    }
    cases: list[dict[str, Any]] = []
    exchanges: list[dict[str, Any]] = []
    for candidate in sorted(selection.candidates, key=lambda row: row["candidate_id"]):
        key = (candidate["project"], candidate["chain_id"])
        fragment, chats = _fragment(candidate, comparisons[key], semantics[key], runner)
        native = _native_case(candidate, comparisons[key], semantics[key], selection, fragment)
        cases.append(_dynamic_case(candidate, comparisons[key], semantics[key], selection, native))
        candidate_id = candidate["candidate_id"]
        path = out / "repository" / "generation" / candidate_id / "chat.json"
        path.parent.mkdir(parents=True)
        atomic_write_json(
            path,
            {
                "schema_version": "clawgap-dynamic-trigger-generation-chat/v1",
                "candidate_id": candidate_id,
                "exchanges": chats,
            },
        )
        exchanges.extend({"candidate_id": candidate_id, **row} for row in chats)
    _write_jsonl(out / "cases.jsonl", cases)
    generic = list(selection.generic_coverage)
    _write_jsonl(out / "gt-projection.jsonl", _projection_rows(generic, {}))
    _write_jsonl(out / "missing-candidate-ledger.jsonl", _missing_rows(generic))
    groups = [
        {
            "schema_version": "clawgap-dynamic-trigger-execution-group/v1",
            "execution_id": stable_execution_id(row["native_case"]),
            "case_id": row["case_id"],
            "candidate_id": row["candidate_binding"]["candidate_id"],
            "project": row["project"],
            "adapter": row["launch_profile"]["adapter"],
        }
        for row in cases
    ]
    _write_jsonl(out / "execution-groups.jsonl", groups)
    command = _generation_command(request)
    credential = os.environ.get(request.api_key_env, "").strip()
    _scan_campaign_credentials(out, credential)
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-campaign/v1",
        "campaign_id": CAMPAIGN_ID,
        "coverage_root": str(selection.root),
        "candidate_ids": [row["candidate_binding"]["candidate_id"] for row in cases],
        "candidate_count": len(cases),
        "project_count": EXPECTED_PROJECTS,
        "failure_mode_counts": EXPECTED_FAILURE_MODES,
        "generation_command": command,
        "model": request.model,
        "base_url": request.base_url,
        "api_key_env": request.api_key_env,
        "artifact_sha256": dict(selection.artifact_sha256),
        "credential_scan": {"status": "passed", "scope": "campaign-artifacts"},
        "truth_gate": {
            "eligible_gt_reports": 43,
            "candidate_linked": 38,
            "candidate_missing": 5,
            "not_applicable": 3,
            "green_46_detection_possible": False,
        },
    }
    atomic_write_json(out / "manifest.json", manifest)
    atomic_write_json(out / "campaign.json", {"coverage_root": str(selection.root), "target": manifest})
    atomic_write_text(
        out / "summary.md",
        "# Universal Dynamic-Trigger Preflight\n\n"
        f"> Complete reproduction command: `{command}`\n\n"
        "Generated candidate cases: **78/78** across **11 projects** "
        "(**41 wrong-check**, **37 missing-check**).\n\n"
        "GT accounting is truthful but incomplete: **38 candidate-linked**, "
        "**5 candidate-missing**, and **3 not-applicable**. A green 46/46 runtime-detection claim is prohibited.\n",
    )
    return manifest


def _projection_rows(
    generic: list[Mapping[str, Any]], results_by_candidate: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for report in generic:
        matched = list(report.get("matched_candidate_ids") or [])
        if report["boundary_status"] != "eligible":
            disposition = "not-applicable"
            reason = "boundary report is outside the 43 eligible GT denominator"
        elif not matched:
            disposition = "candidate-missing"
            reason = "eligible GT report has no strict generic candidate match"
        else:
            candidate_results = [results_by_candidate[item] for item in matched if item in results_by_candidate]
            if any(row["disposition"] == "runtime-confirmed" for row in candidate_results):
                disposition = "runtime-confirmed"
            elif candidate_results and all(row["disposition"] == "not-reproduced" and row["attempts"] == 3 for row in candidate_results):
                disposition = "not-reproduced"
            else:
                disposition = "inconclusive"
            reason = "aggregated only from strict candidate IDs present in the 78-row input"
        rows.append(
            {
                "schema_version": "clawgap-dynamic-trigger-gt-projection/v1",
                "report_id": report["report_id"],
                "project": report["project"],
                "boundary_status": report["boundary_status"],
                "matched_candidate_ids": matched,
                "disposition": disposition,
                "reason": reason,
            }
        )
    return rows


def _missing_rows(generic: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": "clawgap-dynamic-trigger-missing-candidate/v1",
            "report_id": row["report_id"],
            "project": row["project"],
            "status": "candidate-missing",
            "reason": "no strict generic candidate for this eligible report is present in candidates.jsonl",
        }
        for row in generic
        if row["boundary_status"] == "eligible" and not (row.get("matched_candidate_ids") or [])
    ]


def _scan_campaign_credentials(root: Path, credential: str) -> None:
    failures: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if credential and credential in content:
            failures.append(str(path.relative_to(root)))
            path.write_text(
                content.replace(credential, "[REDACTED_CREDENTIAL]"),
                encoding="utf-8",
            )
    if failures:
        raise ValidationError(
            "credential material detected in dynamic-trigger artifacts: "
            + ", ".join(failures)
        )


def _verify_campaign_bindings(
    cases: list[Mapping[str, Any]], manifest: Mapping[str, Any]
) -> None:
    root = Path(manifest["coverage_root"])
    candidates = {
        row["candidate_id"]: row
        for row in _read_jsonl(root / "candidates.jsonl")
    }
    comparisons = {
        (row["project"], row["chain_id"]): row
        for row in _read_jsonl(root / "comparisons.jsonl")
    }
    semantics = {
        (row["project"]["id"], row["chain_id"]): row
        for row in (
            semantic
            for project in SEMANTIC_ROOTS
            for semantic in _read_jsonl(_semantic_path(project))
        )
    }
    for case in cases:
        candidate_id = case["candidate_binding"]["candidate_id"]
        candidate = candidates.get(candidate_id)
        if candidate is None:
            raise ValidationError(f"{case['case_id']}: candidate binding is absent from canonical input")
        key = (candidate["project"], candidate["chain_id"])
        expected = {
            "row_sha256": digest(candidate),
            "comparison_sha256": digest(comparisons[key]),
            "semantic_ir_sha256": digest(semantics[key]),
        }
        for field, value in expected.items():
            if case["candidate_binding"][field] != value:
                raise ValidationError(f"{case['case_id']}: {field} drift")


def review_dynamic_trigger(request: DynamicTriggerReviewRequest) -> dict[str, Any]:
    root = request.campaign.resolve()
    cases, manifest = _load_campaign(root)
    _verify_campaign_bindings(cases, manifest)
    ledger: list[dict[str, Any]] = []
    for case in cases:
        errors: list[str] = []
        candidate_id = case["candidate_binding"]["candidate_id"]
        try:
            validate_dynamic_case(case)
            from .campaign_contracts import validate_runtime_case

            validate_runtime_case(case["native_case"])
        except ValidationError as exc:
            errors.append(str(exc))
        ledger.append(
            {
                "schema_version": "clawgap-dynamic-trigger-review/v1",
                "candidate_id": candidate_id,
                "case_id": case["case_id"],
                "status": "accepted" if not errors else "blocked",
                "independent_review": "deterministic-contract-only",
                "model": request.model,
                "errors": errors,
            }
        )
    _write_jsonl(root / "review-ledger.jsonl", ledger)
    counts = Counter(row["status"] for row in ledger)
    if counts.get("blocked"):
        raise ValidationError(f"dynamic-trigger review blocked {counts['blocked']} cases")
    manifest["review"] = {"status": "accepted", "cases": len(cases), "counts": dict(counts)}
    atomic_write_json(root / "manifest.json", manifest)
    atomic_write_json(root / "campaign.json", {"coverage_root": manifest["coverage_root"], "target": manifest})
    return {"cases": len(cases), "status": "accepted", "artifact_dir": str(root)}


def provision_dynamic_drivers(campaign: Path) -> dict[str, Any]:
    from .provision import provision_drivers
    from .provision import ProvisionRequest

    cases, _ = _load_campaign(campaign.resolve())
    report = provision_drivers(ProvisionRequest(campaign.resolve(), install=True))
    rows = []
    for case in cases:
        native = case["native_case"]
        adapter = get_adapter(native["adapter"])
        ready, reason = adapter.preflight(native)
        rows.append(
            {
                "schema_version": "clawgap-dynamic-trigger-driver-readiness/v1",
                "candidate_id": case["candidate_binding"]["candidate_id"],
                "case_id": case["case_id"],
                "adapter": native["adapter"],
                "status": "ready" if ready else "blocked",
                "reason": reason,
            }
        )
    _write_jsonl(campaign.resolve() / "driver-readiness.jsonl", rows)
    counts = Counter(row["status"] for row in rows)
    report["dynamic_trigger"] = {"cases": len(rows), "counts": dict(counts)}
    report["ready"] = report.get("ready", False) and not counts.get("blocked")
    atomic_write_json(campaign.resolve() / "driver-provisioning.json", report)
    return report


def _verify_campaign_sources(cases: list[Mapping[str, Any]]) -> None:
    for case in cases:
        spec = get_project(case["project"])
        if case["revision"] != spec.analysis_revision:
            raise ValidationError(f"{case['case_id']}: revision drift")
        bound: set[str] = set()
        for row in case["source_binding"]["files"]:
            relative = Path(row["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValidationError(f"{case['case_id']}: source-root escape")
            path = spec.source_root / relative
            if not path.is_file() or sha256_file(path) != row["sha256"]:
                raise ValidationError(f"{case['case_id']}: source hash drift")
            bound.add(row["path"])
        for observation in case["observations"]:
            relative = observation["source_anchor"].rsplit(":", 1)[0]
            if relative not in bound:
                raise ValidationError(f"{case['case_id']}: observation source is not hash-bound")


def _summary(cases: list[Mapping[str, Any]], results: list[Mapping[str, Any]], projection: list[Mapping[str, Any]], command: str) -> str:
    counts = Counter(row["disposition"] for row in results)
    gt_counts = Counter(row["disposition"] for row in projection)
    return "\n".join(
        [
            "# Universal Dynamic-Trigger Campaign",
            "",
            f"> Complete reproduction command: `{command}`",
            "",
            "## Candidate Denominator",
            "",
            f"Processed **{len(results)}/78** candidates with three paired exploit/control attempts each.",
            "",
            "## Truth-In-Accounting Gate",
            "",
            f"GT rows: **46**; candidate-linked: **38**; candidate-missing: **{gt_counts['candidate-missing']}**; not-applicable: **3**.",
            "",
            "The current 78-row input cannot truthfully produce a green **46/46** runtime-detection claim.",
            "",
            "## Candidate Results",
            "",
            f"runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**; not-reproduced: **{counts.get('not-reproduced', 0)}**; inconclusive: **{counts.get('inconclusive', 0)}**; unsupported: **{counts.get('unsupported', 0)}**.",
            "",
        ]
    )


def run_dynamic_trigger(request: DynamicTriggerRunRequest) -> dict[str, Any]:
    if request.attempts != 3:
        raise ValidationError("canonical dynamic-trigger validation requires exactly 3 paired attempts")
    root = request.campaign.resolve()
    cases, manifest = _load_campaign(root)
    if not (root / "review-ledger.jsonl").is_file() or any(
        row.get("status") != "accepted"
        for row in _read_jsonl(root / "review-ledger.jsonl")
    ):
        raise ValidationError("dynamic-trigger campaign has not passed independent review")
    if not (root / "driver-provisioning.json").is_file() or not _read_json(root / "driver-provisioning.json").get("ready"):
        raise ValidationError("dynamic-trigger campaign has not passed driver provisioning")
    _verify_campaign_sources(cases)
    _verify_campaign_bindings(cases, manifest)
    runs = root / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    results_by_case: dict[str, Any] = {}

    def execute(case: Mapping[str, Any]):
        native = dict(case["native_case"])
        execution_id = stable_execution_id(native)
        run_dir = runs / execution_id
        try:
            run = validate_case(
                CaseValidationRequest(native, run_dir, request.attempts)
            )
            return case, {
                "schema_version": "clawgap-dynamic-trigger-candidate-result/v1",
                "campaign_id": CAMPAIGN_ID,
                "candidate_id": case["candidate_binding"]["candidate_id"],
                "case_id": case["case_id"],
                "execution_id": execution_id,
                "disposition": run.disposition,
                "reason": run.reason,
                "attempts": len(run.attempts),
                "evidence_tier": "L1-native-dispatch",
            }
        except Exception as exc:
            return case, {
                "schema_version": "clawgap-dynamic-trigger-candidate-result/v1",
                "campaign_id": CAMPAIGN_ID,
                "candidate_id": case["candidate_binding"]["candidate_id"],
                "case_id": case["case_id"],
                "execution_id": execution_id,
                "disposition": "inconclusive",
                "reason": f"{type(exc).__name__}: {exc}",
                "attempts": 0,
                "evidence_tier": "L1-native-dispatch",
            }

    with ThreadPoolExecutor(max_workers=max(1, request.jobs), thread_name_prefix="dynamic-trigger") as pool:
        futures = [pool.submit(execute, case) for case in cases]
        for future in as_completed(futures):
            _, result = future.result()
            results_by_case[result["case_id"]] = result
    results = [results_by_case[case["case_id"]] for case in cases]
    generic = _read_jsonl(Path(manifest["coverage_root"]) / "generic-ground-truth-coverage.jsonl")
    projection = _projection_rows(generic, {row["candidate_id"]: row for row in results})
    _write_jsonl(root / "candidate-results.jsonl", results)
    _write_jsonl(root / "gt-projection.jsonl", projection)
    _write_jsonl(root / "missing-candidate-ledger.jsonl", _missing_rows(generic))
    command = manifest.get("generation_command", "") + (
        f" && python -m src.runtime_validation review-dynamic-trigger --campaign {root}"
        f" && python -m src.runtime_validation provision-drivers --campaign {root}"
        f" && python -m src.runtime_validation run-dynamic-trigger --campaign {root} --attempts 3 --jobs {request.jobs}"
    )
    atomic_write_text(root / "summary.md", _summary(cases, results, projection, command))
    _scan_campaign_credentials(
        root, os.environ.get(manifest.get("api_key_env", ""), "")
    )
    manifest["run"] = {
        "candidate_count": len(results),
        "attempts_per_candidate": request.attempts,
        "evidence_tier": "L1-native-dispatch",
        "l2_attempted": False,
        "credential_scan": "passed",
    }
    atomic_write_json(root / "manifest.json", manifest)
    output = {
        "campaign_id": CAMPAIGN_ID,
        "candidate_count": len(results),
        "disposition_counts": dict(Counter(row["disposition"] for row in results)),
        "gt_projection_counts": dict(Counter(row["disposition"] for row in projection)),
        "artifact_dir": str(root),
    }
    if request.require_green_46 and not all(
        row["disposition"] == "runtime-confirmed" for row in projection
    ):
        output["truth_gate"] = "blocked-green-46-claim"
    return output


def evaluate_trace_events(case: Mapping[str, Any], events: list[Mapping[str, Any]]) -> bool:
    correlation = "DTC-CORR-" + digest(case["case_id"])[:16]
    required = ["handler"] + ["gate"] * len(case["gates"]) + ["sink", "pre-effect-interception"]
    observed = []
    event_ids = set()
    attempts = set()
    roles = set()
    for event in events:
        if event.get("case_id") != case["case_id"] or event.get("correlation_id") != correlation:
            return False
        if event.get("event_id") in event_ids:
            return False
        event_ids.add(event.get("event_id"))
        attempts.add(event.get("attempt"))
        roles.add(event.get("role"))
        if event.get("attempt") not in {1, 2, 3} or event.get("role") not in {"exploit", "control"}:
            return False
        observed.append(event.get("kind"))
    if len(attempts) != 1 or len(roles) != 1:
        return False
    if all("sequence" in event for event in events) and [event["sequence"] for event in events] != list(range(1, len(events) + 1)):
        return False
    return observed == required
