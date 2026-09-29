"""Automatic, source-bound generation of candidate runtime replay cases."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from src.pipeline.provider import OpenAICompatibleRunner
from src.projects import get_project

from .campaign_contracts import (
    CAMPAIGN_SCHEMA_VERSION,
    CASE_SCHEMA_VERSION,
    EXECUTION_GROUP_SCHEMA_VERSION,
    CampaignDefinition,
    CampaignGenerationRequest,
    PROJECT_ADAPTERS,
    canonical_json,
    digest,
    stable_case_id,
    stable_execution_id,
    validate_runtime_case,
)
from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    contains_credentials,
    redact_text,
    sha256_file,
)
from .pipeline import _credential_scan
from .selection import CoveredSelection, SelectedCandidate, select_covered_candidates


REPO_ROOT = Path(__file__).resolve().parents[2]
FRAGMENT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "status",
        "reason",
        "tool_name",
        "exploit_args",
        "control_args",
        "reproduction_prompt",
        "relation",
        "argument_path",
        "exploit_value",
        "control_value",
    ],
    "properties": {
        "status": {"enum": ["ready", "unsupported"]},
        "reason": {"type": "string", "minLength": 1},
        "tool_name": {"type": "string", "minLength": 1},
        "exploit_args": {"type": "object"},
        "control_args": {"type": "object"},
        "reproduction_prompt": {"type": "string", "minLength": 1},
        "relation": {
            "enum": [
                "equals",
                "contains",
                "json-subset",
                "normalized-equals",
                "path-resolves-to",
                "command-segment",
                "url-host-class",
            ]
        },
        "argument_path": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "minLength": 1},
        },
        "exploit_value": {},
        "control_value": {},
    },
}
LOCATION_RE = re.compile(r"^(?P<path>.+?):(?P<line>[0-9]+)(?::[0-9]+)?$")


class ExactGenerationRunner:
    """Byte-exact prompt replay with a noncanonical resumable checkpoint."""

    def __init__(self, live_runner: Callable[[str, str], str], out_dir: Path):
        self.live_runner = live_runner
        self.checkpoint = (
            out_dir.parent / f".{out_dir.name}.generation-checkpoint.jsonl"
        )
        self.cache: dict[tuple[str, str], str] = {}
        self.calls = 0
        self.hits = 0
        self.misses = 0
        self.prior_transport: dict[str, Any] | None = None
        if self.checkpoint.is_file():
            for number, line in enumerate(
                self.checkpoint.read_text(encoding="utf-8").splitlines(), 1
            ):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValidationError(
                        f"invalid generation checkpoint {self.checkpoint}:{number}: {exc}"
                    ) from exc
                if not isinstance(row, dict) or set(row) != {
                    "system",
                    "user",
                    "response",
                }:
                    raise ValidationError(f"invalid generation checkpoint row {number}")
                key = (row["system"], row["user"])
                prior = self.cache.setdefault(key, row["response"])
                if prior != row["response"]:
                    raise ValidationError("conflicting exact generation responses")
        manifest_path = out_dir / "generation-manifest.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            transport = manifest.get("transport")
            if isinstance(transport, dict):
                self.prior_transport = transport
        repository = out_dir / "repository" / "generation"
        if repository.is_dir():
            for path in sorted(repository.glob("*/chat.json")):
                payload = json.loads(path.read_text(encoding="utf-8"))
                if (
                    payload.get("schema_version")
                    != "clawgap-runtime-case-generation-chat/v1"
                ):
                    raise ValidationError(
                        f"unsupported generation replay sidecar: {path}"
                    )
                for exchange in payload.get("exchanges", []):
                    if not isinstance(exchange, dict) or set(exchange) != {
                        "system",
                        "user",
                        "response",
                    }:
                        raise ValidationError(
                            f"invalid generation replay exchange: {path}"
                        )
                    if any(contains_credentials(exchange[field]) for field in exchange):
                        raise ValidationError(
                            f"credential-shaped generation replay: {path}"
                        )
                    key = (exchange["system"], exchange["user"])
                    prior = self.cache.setdefault(key, exchange["response"])
                    if prior != exchange["response"]:
                        raise ValidationError("conflicting generation replay responses")

    def __call__(self, system: str, user: str) -> str:
        system = redact_text(system)
        user = redact_text(user)
        self.calls += 1
        cached = self.cache.get((system, user))
        if cached is not None:
            self.hits += 1
            print(
                f"runtime case {self.calls}: exact replay", file=sys.stderr, flush=True
            )
            return cached
        self.misses += 1
        print(
            f"runtime case {self.calls}: live generation", file=sys.stderr, flush=True
        )
        response = redact_text(self.live_runner(system, user))
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        with self.checkpoint.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"system": system, "user": user, "response": response},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        self.cache[(system, user)] = response
        return response

    def audit_payload(self) -> dict[str, Any]:
        if self.misses == 0 and self.prior_transport is not None:
            payload = dict(self.prior_transport)
        else:
            payload = (
                dict(self.live_runner.audit_payload())
                if callable(getattr(self.live_runner, "audit_payload", None))
                else {"transport": "injected-runner", "available_tools": []}
            )
        payload["prompt_replay"] = {
            "enabled": True,
            "exact_prompt_hits": self.hits,
            "exact_prompt_misses": self.misses,
        }
        return payload

    def clear_checkpoint(self) -> None:
        self.checkpoint.unlink(missing_ok=True)


def _parse_response(raw: str) -> dict[str, Any]:
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
        raise ValidationError(f"case generation response is not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError("case generation response must be an object")
    # DeepSeek occasionally wraps a requested scalar enum or one path key in a
    # singleton array. This normalization is lossless and does not invent any
    # tool argument, control, source anchor, or runtime verdict.
    if (
        isinstance(value.get("relation"), list)
        and len(value["relation"]) == 1
        and isinstance(value["relation"][0], str)
    ):
        value["relation"] = value["relation"][0]
    if isinstance(value.get("argument_path"), str) and value["argument_path"]:
        value["argument_path"] = [value["argument_path"]]
    errors = sorted(
        Draft202012Validator(FRAGMENT_SCHEMA).iter_errors(value),
        key=lambda row: list(row.path),
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:8]
        )
        raise ValidationError(f"case generation response schema failed: {details}")
    return value


def _load_report(report: Mapping[str, Any]) -> dict[str, Any]:
    path = REPO_ROOT / report["source_files"][0]
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError(f"ground-truth report is not an object: {path}")
    return value


def _first_location(value: Any, keys: tuple[str, ...]) -> tuple[str, str, int | None]:
    for key in keys:
        rows = value.get(key, []) if isinstance(value, Mapping) else []
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            raw = row.get("location") or row.get("to") or row.get("from")
            if not isinstance(raw, str):
                continue
            match = LOCATION_RE.match(raw.strip())
            if match:
                return (
                    match.group("path"),
                    str(row.get("name") or row.get("symbol") or key),
                    int(match.group("line")),
                )
    return "", "", None


def _probe_and_fixture(card_path: str) -> tuple[str, str, str]:
    lower = card_path.lower()
    if "droidclaw.adb" in lower:
        return "adb-shell", "fake-adb", "intercept"
    if any(token in lower for token in ("browser", "playwright", "code-eval")):
        return "browser", "isolated-browser", "sandbox"
    if any(
        token in lower
        for token in (
            "matrix",
            "message",
            "aiohttp.session.post",
            "aiohttp.session.put",
        )
    ):
        return "messaging", "capture-messaging", "intercept"
    if any(token in lower for token in ("subagent", "approval")):
        return "delegation-approval", "capture-subagent", "intercept"
    if any(token in lower for token in ("open.", "pathlib", "node.fs", "copy")):
        return "filesystem", "temporary-filesystem", "sandbox"
    if any(token in lower for token in ("request", "fetch", "http")):
        return "http-network", "loopback-http", "intercept"
    return "process-exec", "none", "intercept"


def _observations(row: SelectedCandidate) -> list[dict[str, Any]]:
    report = _load_report(row.reports[0])
    handler_file, handler_symbol, handler_line = _first_location(
        report, ("d5_tool_handler_entry",)
    )
    sink_file, sink_symbol, sink_line = _first_location(report, ("d5_sink_points",))
    observations: list[dict[str, Any]] = [
        {
            "stage_id": "S1",
            "kind": "handler",
            "file": handler_file,
            "symbol": handler_symbol,
            "line": handler_line,
            "expected": "generated exploit argument is observed at the native handler",
        }
    ]
    if row.candidate["failure_mode"] == "wrong-check":
        for gate in row.candidate.get("gate_semantics", []):
            raw = str(gate.get("callsite") or "")
            match = LOCATION_RE.match(raw)
            observations.append(
                {
                    "stage_id": f"S{len(observations) + 1}",
                    "kind": "gate",
                    "file": match.group("path") if match else "",
                    "symbol": str(
                        gate.get("gate_name") or gate.get("gate_uid") or "gate"
                    ),
                    "line": int(match.group("line")) if match else None,
                    "expected": "the declared inadequate gate admits the exploit carrier",
                }
            )
    observations.extend(
        [
            {
                "stage_id": f"S{len(observations) + 1}",
                "kind": "sink",
                "file": sink_file,
                "symbol": sink_symbol,
                "line": sink_line,
                "expected": "the correlated exploit carrier reaches the terminal sink",
            },
            {
                "stage_id": f"S{len(observations) + 2}",
                "kind": "effect",
                "file": sink_file,
                "symbol": sink_symbol,
                "line": sink_line,
                "expected": "the effect is intercepted or confined by the capability sandbox",
            },
        ]
    )
    return observations


def _bounded_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 5:
        return "<depth-limit>"
    if isinstance(value, str):
        return value if len(value) <= 800 else value[:800] + "...<truncated>"
    if isinstance(value, list):
        return [_bounded_value(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, Mapping):
        return {
            str(key): _bounded_value(item, depth=depth + 1)
            for key, item in value.items()
        }
    return value


def _bounded_report(report: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "report_name",
        "verdict_reason",
        "d5_tool_handler_entry",
        "d5_param_extraction",
        "d5_gate_points",
        "d5_gate_missing_check",
        "d5_sink_points",
        "d5_cross_component",
        "d5_defect_location",
        "d5_gate_structure_justification",
    )
    return {field: _bounded_value(report[field]) for field in fields if field in report}


def _source_excerpts(row: SelectedCandidate, limit: int = 6000) -> list[dict[str, str]]:
    spec = get_project(row.candidate["project"])
    output: list[dict[str, str]] = []
    remaining = limit
    lines_by_path: dict[str, set[int]] = {}
    for report_binding in row.reports:
        report = _load_report(report_binding)

        def collect(value: Any) -> None:
            if isinstance(value, Mapping):
                raw = value.get("location") or value.get("from") or value.get("to")
                if isinstance(raw, str):
                    match = LOCATION_RE.match(raw.strip())
                    if match:
                        lines_by_path.setdefault(match.group("path"), set()).add(
                            int(match.group("line"))
                        )
                for item in value.values():
                    collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(report)
    for binding in row.source_files:
        if remaining <= 0:
            break
        source_lines = (
            (spec.source_root / binding["path"])
            .read_text(encoding="utf-8", errors="replace")
            .splitlines()
        )
        anchors = sorted(lines_by_path.get(binding["path"], {1}))[:3]
        chunks: list[str] = []
        for line in anchors:
            start = max(1, line - 20)
            end = min(len(source_lines), line + 20)
            chunks.append(
                f"# lines {start}-{end}\n"
                + "\n".join(
                    f"{number}: {source_lines[number - 1]}"
                    for number in range(start, end + 1)
                )
            )
        excerpt = "\n\n".join(chunks)[: min(remaining, 2500)]
        remaining -= len(excerpt)
        output.append({"path": binding["path"], "excerpt": excerpt})
    return output


SYSTEM_PROMPT = """You generate one declarative, safe runtime replay fragment for a security candidate.
Return exactly one JSON object with only the requested top-level keys. Do not repeat or summarize
the evidence object. Do not output code, shell setup commands, module paths, or prose outside JSON.
The exploit_args and control_args are JSON arguments for the named model-facing tool. The control
must differ in the security-sensitive facet and must not satisfy the exploit matcher. If the source
evidence is insufficient to construct both calls, return status=unsupported with empty argument
objects. Use only the relation vocabulary provided in the requested JSON shape."""


def _user_prompt(row: SelectedCandidate) -> str:
    reports = [_bounded_report(_load_report(report)) for report in row.reports]
    candidate = row.candidate
    payload = {
        "required_shape": {
            "status": "ready|unsupported",
            "reason": "non-empty string",
            "tool_name": "registered model-facing tool name",
            "exploit_args": {},
            "control_args": {},
            "reproduction_prompt": "human-readable description; not executed",
            "relation": sorted(FRAGMENT_SCHEMA["properties"]["relation"]["enum"]),
            "argument_path": ["one", "or", "more", "JSON", "keys"],
            "exploit_value": "exact JSON value selected from exploit_args",
            "control_value": "different exact JSON value selected from control_args",
        },
        "candidate": {
            key: candidate[key]
            for key in (
                "candidate_id",
                "project",
                "chain_id",
                "failure_mode",
                "requirement_id",
                "requirement_rule",
                "reason",
                "trigger_goal",
                "gate_ids",
            )
        },
        "comparison": {
            key: row.comparison[key]
            for key in (
                "project",
                "revision",
                "chain_id",
                "call_shape",
                "controlled_argument",
                "values",
            )
        },
        "ground_truth": reports,
        "source_excerpts": _source_excerpts(row),
        "instruction": "Return the required_shape object now; do not echo this evidence.",
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)


def _unsupported_fragment(row: SelectedCandidate, reason: str) -> dict[str, Any]:
    report = _load_report(row.reports[0])
    tool_name = "unknown"
    entries = report.get("d5_tool_handler_entry", [])
    if isinstance(entries, list) and entries and isinstance(entries[0], Mapping):
        tool_name = str(entries[0].get("name") or "unknown")
    return {
        "status": "unsupported",
        "reason": reason,
        "tool_name": tool_name,
        "exploit_args": {},
        "control_args": {},
        "reproduction_prompt": row.candidate["trigger_goal"],
        "relation": "equals",
        "argument_path": ["unsupported"],
        "exploit_value": None,
        "control_value": None,
    }


def _generate_fragment(
    row: SelectedCandidate, runner: Callable[[str, str], str]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    user = _user_prompt(row)
    exchanges: list[dict[str, str]] = []
    raw = runner(SYSTEM_PROMPT, user)
    exchanges.append(
        {
            "system": redact_text(SYSTEM_PROMPT),
            "user": redact_text(user),
            "response": redact_text(raw),
        }
    )
    try:
        return _parse_response(raw), exchanges
    except ValidationError as first:
        repair_system = "Repair the supplied response to the exact requested JSON schema. Return JSON only."
        repair_user = json.dumps(
            {
                "error": str(first),
                "invalid_response": raw,
                "required_schema": FRAGMENT_SCHEMA,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        repaired = runner(repair_system, repair_user)
        exchanges.append(
            {
                "system": redact_text(repair_system),
                "user": redact_text(repair_user),
                "response": redact_text(repaired),
            }
        )
        try:
            return _parse_response(repaired), exchanges
        except ValidationError as second:
            return _unsupported_fragment(
                row, f"automatic generation failed: {second}"
            ), exchanges


def _compile_case(
    row: SelectedCandidate,
    fragment: Mapping[str, Any],
    selection: CoveredSelection,
) -> dict[str, Any]:
    candidate = row.candidate
    probe, fixture, effect_mode = _probe_and_fixture(
        candidate["capability_card"]["path"]
    )
    report_bindings = []
    for report in row.reports:
        for path, sha256 in zip(
            report["source_files"], report["source_sha256"], strict=True
        ):
            report_bindings.append(
                {
                    "report_id": report["report_id"],
                    "report_name": report["report_name"],
                    "path": path,
                    "sha256": sha256,
                }
            )
    replay = {
        "tool_name": fragment["tool_name"],
        "exploit_args": fragment["exploit_args"],
        "control_args": fragment["control_args"],
        "reproduction_prompt": fragment["reproduction_prompt"],
    }
    matcher = {
        "relation": fragment["relation"],
        "argument_path": fragment["argument_path"],
        "exploit_value": fragment["exploit_value"],
        "control_value": fragment["control_value"],
    }
    observations = _observations(row)
    identity = {
        "candidate_ids": [candidate["candidate_id"]],
        "project": candidate["project"],
        "revision": candidate["revision"],
        "chain_id": candidate["chain_id"],
        "group_id": candidate["group_id"],
        "requirement_id": candidate["requirement_id"],
        "failure_mode": candidate["failure_mode"],
        "replay": replay,
        "matcher": matcher,
        "observations": observations,
    }
    case = {
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id": stable_case_id(identity),
        "candidate_ids": [candidate["candidate_id"]],
        "report_bindings": sorted(
            {canonical_json(item): item for item in report_bindings}.values(),
            key=lambda item: (item["report_id"], item["path"]),
        ),
        "project": candidate["project"],
        "revision": candidate["revision"],
        "chain_id": candidate["chain_id"],
        "group_id": candidate["group_id"],
        "requirement_id": candidate["requirement_id"],
        "failure_mode": candidate["failure_mode"],
        "source_binding": {
            "analysis_revision": candidate["revision"],
            "files": list(row.source_files),
        },
        "artifact_binding": {
            "coverage_manifest": selection.artifact_sha256["manifest.json"],
            "ground_truth_manifest": selection.artifact_sha256[
                "ground-truth-manifest.json"
            ],
            "candidates": selection.artifact_sha256[selection.candidate_artifact],
            "comparisons": selection.artifact_sha256["comparisons.jsonl"],
            "ground_truth_coverage": selection.artifact_sha256[
                "ground-truth-coverage.jsonl"
            ],
            "candidate_row": digest(candidate),
            "semantic_row": digest(row.semantic_snapshot),
        },
        "adapter": PROJECT_ADAPTERS[candidate["project"]],
        "probe": probe,
        "fixture": fixture,
        "replay": replay,
        "matcher": matcher,
        "observations": observations,
        "effect_policy": {
            "mode": effect_mode,
            "allow_network": "loopback-only",
            "allow_host_write": False,
        },
        "generation": {
            "status": fragment["status"],
            "reason": fragment["reason"],
            "model_generated": True,
        },
    }
    return validate_runtime_case(case)


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    atomic_write_text(
        path,
        "".join(canonical_json(row) + "\n" for row in rows),
    )


def generate_covered_campaign(
    request: CampaignGenerationRequest,
    *,
    runner: Callable[[str, str], str] | None = None,
) -> CampaignDefinition:
    """Generate the canonical CR v7 strict-matched replay campaign."""

    selection = select_covered_candidates(
        request.coverage_root,
        expected_candidates=request.expected_candidates,
        expected_match_references=request.expected_match_references,
        expected_covered_reports=request.expected_covered_reports,
    )
    live = runner or OpenAICompatibleRunner(
        base_url=request.base_url,
        model=request.model,
        api_key_env=request.api_key_env,
        max_tokens=4096,
    )
    replay = ExactGenerationRunner(live, request.out_dir)
    cases: list[dict[str, Any]] = []
    chats: dict[str, list[dict[str, str]]] = {}
    for number, selected in enumerate(selection.candidates, 1):
        candidate_id = selected.candidate["candidate_id"]
        print(
            f"runtime case generation {number}/{len(selection.candidates)}: {candidate_id}",
            file=sys.stderr,
            flush=True,
        )
        fragment, exchanges = _generate_fragment(selected, replay)
        try:
            case = _compile_case(selected, fragment, selection)
        except ValidationError as exc:
            case = _compile_case(
                selected,
                _unsupported_fragment(
                    selected, f"generated case failed compilation: {exc}"
                ),
                selection,
            )
        cases.append(case)
        chats[candidate_id] = exchanges

    groups_by_id: dict[str, dict[str, Any]] = {}
    for case in cases:
        execution_id = stable_execution_id(case)
        group = groups_by_id.setdefault(
            execution_id,
            {
                "schema_version": EXECUTION_GROUP_SCHEMA_VERSION,
                "execution_id": execution_id,
                "case_ids": [],
                "candidate_ids": [],
                "project": case["project"],
                "revision": case["revision"],
                "execution_identity_sha256": digest(
                    {
                        key: case[key]
                        for key in (
                            "project",
                            "revision",
                            "chain_id",
                            "adapter",
                            "probe",
                            "fixture",
                            "replay",
                            "observations",
                            "effect_policy",
                        )
                    }
                ),
            },
        )
        group["case_ids"].append(case["case_id"])
        group["candidate_ids"].extend(case["candidate_ids"])
    execution_groups = []
    for group in groups_by_id.values():
        group["case_ids"] = sorted(set(group["case_ids"]))
        group["candidate_ids"] = sorted(set(group["candidate_ids"]))
        execution_groups.append(group)
    execution_groups.sort(key=lambda row: row["execution_id"])

    campaign_identity = {
        "artifact_sha256": selection.artifact_sha256,
        "candidate_ids": list(selection.candidate_ids),
        "case_ids": sorted(case["case_id"] for case in cases),
    }
    campaign_id = "RVCAMP-" + digest(campaign_identity)[:16]
    campaign = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "analysis_mode": "canonical-trained-detector/v8",
        "execution_mode": "native-tool-replay-only",
        "coverage_root": str(selection.coverage_root),
        "target": {
            "covered_reports": len(selection.covered_reports),
            "candidate_ids": list(selection.candidate_ids),
            "candidates": len(selection.candidates),
            "match_references": selection.match_references,
        },
        "artifact_sha256": dict(selection.artifact_sha256),
        "attempts": 3,
        "paired_controls": True,
    }
    out = request.out_dir.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-", dir=out.parent))
    backup = out.parent / f".{out.name}.backup-{os.getpid()}"
    if backup.exists():
        shutil.rmtree(staging)
        raise ValidationError(f"stale generation backup blocks publication: {backup}")
    try:
        _write_jsonl(staging / "cases.jsonl", cases)
        _write_jsonl(staging / "execution-groups.jsonl", execution_groups)
        atomic_write_json(staging / "campaign.json", campaign)
        for candidate_id, exchanges in chats.items():
            path = staging / "repository" / "generation" / candidate_id / "chat.json"
            atomic_write_json(
                path,
                {
                    "schema_version": "clawgap-runtime-case-generation-chat/v1",
                    "candidate_id": candidate_id,
                    "exchanges": exchanges,
                },
            )
        manifest = {
            "schema_version": "clawgap-runtime-validation-generation-manifest/v1",
            "campaign_id": campaign_id,
            "generation_command": (
                "python -m src.runtime_validation generate-covered "
                f"--coverage-root {request.coverage_root} --out-dir {request.out_dir} "
                f"--model {request.model} --base-url {request.base_url} "
                f"--api-key-env {request.api_key_env}"
            ),
            "counts": {
                "covered_reports": len(selection.covered_reports),
                "candidate_ids": len(selection.candidates),
                "match_references": selection.match_references,
                "ready_cases": sum(
                    case["generation"]["status"] == "ready" for case in cases
                ),
                "unsupported_cases": sum(
                    case["generation"]["status"] == "unsupported" for case in cases
                ),
                "execution_groups": len(execution_groups),
            },
            "transport": replay.audit_payload(),
            "outputs": {
                name: sha256_file(staging / name)
                for name in (
                    "campaign.json",
                    "cases.jsonl",
                    "execution-groups.jsonl",
                )
            },
        }
        atomic_write_json(staging / "generation-manifest.json", manifest)
        _credential_scan(staging, ())
        if out.exists():
            os.replace(out, backup)
        try:
            os.replace(staging, out)
        except Exception:
            if backup.exists() and not out.exists():
                os.replace(backup, out)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    replay.clear_checkpoint()
    return CampaignDefinition(
        campaign_id=campaign_id,
        root=out,
        cases=tuple(cases),
        execution_groups=tuple(execution_groups),
        target_candidate_ids=selection.candidate_ids,
        manifest=manifest,
    )
