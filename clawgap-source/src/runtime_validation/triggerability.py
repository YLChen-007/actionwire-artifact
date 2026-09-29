"""Ground-truth model-facing tool-triggerability audit."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project

from .adapters import CapabilitySandbox, get_adapter
from .campaign import load_campaign_definition
from .campaign_contracts import canonical_json
from .contracts import ValidationError, atomic_write_json, atomic_write_text, sha256_file
from .pipeline import _artifact_hashes, _credential_scan


REPO_ROOT = Path(__file__).resolve().parents[2]
LOCATION_RE = re.compile(r"^(?P<path>.+?):(?P<line>[0-9]+)(?:\s+\(.+\))?$")


@dataclass(frozen=True)
class TriggerabilityRequest:
    campaign_dir: Path
    out_dir: Path
    jobs: int = 4


def _w(path: str, line: int, needle: str) -> dict[str, Any]:
    return {"path": path, "line": line, "needle": needle}


PROJECT_FLOWS: dict[str, dict[str, Any]] = {
    "AstrBot": {
        "exposure": _w("astrbot/core/astr_main_agent.py", 377, "FileReadTool"),
        "dispatch": _w("astrbot/core/astr_agent_tool_exec.py", 702, "tool.call"),
    },
    "QwenPaw": {
        "exposure": _w("src/qwenpaw/agents/react_agent.py", 359, "register_tool_function"),
        "dispatch": _w("src/qwenpaw/agents/tool_guard_mixin.py", 138, "_acting"),
    },
    "chatgpt-on-wechat": {
        "exposure": _w("agent/tools/tool_manager.py", 82, "self.tool_classes"),
        "dispatch": _w("agent/protocol/agent_stream.py", 994, "execute_tool"),
    },
    "hermes-agent": {
        "exposure": _w("model_tools.py", 392, "registry.get_definitions"),
        "dispatch": _w("model_tools.py", 766, "registry.dispatch"),
    },
    "nanobot": {
        "exposure": _w("nanobot/agent/loop.py", 198, "get_definitions"),
        "dispatch": _w("nanobot/agent/tools/registry.py", 54, "tool.execute"),
    },
    "droidclaw": {
        "exposure": _w("src/kernel.ts", 376, "getDecisionStreaming"),
        "dispatch": _w("src/kernel.ts", 410, "executeAction"),
    },
    "lettabot": {
        "exposure": _w(
            "vendor-source/letta-code-v0.19.5/src/tools/toolDefinitions.ts",
            221,
            "Task:",
        ),
        "dispatch": _w(
            "vendor-source/letta-code-v0.19.5/src/tools/manager.ts",
            1252,
            "executeTool",
        ),
    },
    "mercury-agent": {
        "exposure": _w("src/core/agent.ts", 1247, "capabilities.getTools"),
        "dispatch": _w("src/capabilities/shell/run-command.ts", 97, "execute: async"),
    },
    "nanoclaw": {
        "exposure": _w(
            "container/agent-runner/src/mcp-tools/server.ts",
            38,
            "ListToolsRequestSchema",
        ),
        "dispatch": _w("container/agent-runner/src/mcp-tools/server.ts", 48, "tool.handler"),
    },
    "openclaw": {
        "exposure": _w("src/agents/pi-tools.ts", 268, "createExecTool"),
        "dispatch": _w("src/agents/pi-tool-definition-adapter.ts", 96, "tool.execute"),
    },
    "openclaw-cn": {
        "exposure": _w("src/agents/openclaw-tools.ts", 90, "createMessageTool"),
        "dispatch": _w("src/agents/pi-tool-definition-adapter.ts", 69, "tool.execute"),
    },
}


TOOL_SURFACES: dict[tuple[str, str], dict[str, Any]] = {
    ("AstrBot", "astrbot_file_read_tool"): {
        "kind": "function-tool",
        "handler": _w("astrbot/core/tools/computer_tools/fs.py", 245, "async def call"),
        "registration": _w("astrbot/core/astr_main_agent.py", 377, "FileReadTool"),
        "condition": "available when the main agent computer-use tools are enabled",
    },
    ("AstrBot", "astrbot_file_write_tool"): {
        "kind": "function-tool",
        "handler": _w("astrbot/core/tools/computer_tools/fs.py", 313, "async def call"),
        "registration": _w("astrbot/core/astr_main_agent.py", 378, "FileWriteTool"),
        "condition": "available when the main agent computer-use tools are enabled",
    },
    ("QwenPaw", "execute_shell_command"): {
        "kind": "function-tool",
        "handler": _w("src/qwenpaw/agents/tools/shell.py", 367, "execute_shell_command"),
        "registration": _w("src/qwenpaw/agents/react_agent.py", 286, "execute_shell_command"),
        "condition": "builtin is exposed unless disabled by agent tool configuration",
    },
    ("chatgpt-on-wechat", "bash"): {
        "kind": "function-tool",
        "handler": _w("agent/tools/bash/bash.py", 59, "def execute"),
        "registration": _w("agent/tools/__init__.py", 117, "Bash"),
        "condition": "tool may be removed by project tool configuration",
    },
    ("chatgpt-on-wechat", "read"): {
        "kind": "function-tool",
        "handler": _w("agent/tools/read/read.py", 63, "def execute"),
        "registration": _w("agent/tools/__init__.py", 114, "Read"),
        "condition": "tool may be removed by project tool configuration",
    },
    ("chatgpt-on-wechat", "browser"): {
        "kind": "function-tool",
        "handler": _w("agent/tools/browser/browser_tool.py", 112, "def execute"),
        "registration": _w("agent/tools/__init__.py", 127, "BrowserTool"),
        "condition": "requires optional browser dependencies and tool enablement",
    },
    ("chatgpt-on-wechat", "vision"): {
        "kind": "function-tool",
        "handler": _w("agent/tools/vision/vision.py", 130, "def execute"),
        "registration": _w("agent/tools/__init__.py", 126, "Vision"),
        "condition": "handler is exposed; provider availability affects completion after entry",
    },
    ("chatgpt-on-wechat", "web_fetch"): {
        "kind": "function-tool",
        "handler": _w("agent/tools/web_fetch/web_fetch.py", 101, "def execute"),
        "registration": _w("agent/tools/__init__.py", 125, "WebFetch"),
        "condition": "tool may be removed by project tool configuration",
    },
    ("hermes-agent", "read_file"): {
        "kind": "function-tool",
        "handler": _w("tools/file_tools.py", 1093, "_handle_read_file"),
        "registration": _w("tools/file_tools.py", 1140, 'name="read_file"'),
        "condition": "file toolset and its check function must be available",
    },
    ("hermes-agent", "skill_view"): {
        "kind": "function-tool",
        "handler": _w("tools/skills_tool.py", 1500, "_skill_view_with_bump"),
        "registration": _w("tools/skills_tool.py", 1525, "registry.register"),
        "condition": "skills toolset and its check function must be available",
    },
    ("hermes-agent", "send_message"): {
        "kind": "function-tool",
        "handler": _w("tools/send_message_tool.py", 148, "send_message_tool"),
        "registration": _w("tools/send_message_tool.py", 1782, 'name="send_message"'),
        "condition": "messaging toolset/check must pass for the active gateway platform",
    },
    ("hermes-agent", "terminal"): {
        "kind": "function-tool",
        "handler": _w("tools/terminal_tool.py", 2321, "_handle_terminal"),
        "registration": _w("tools/terminal_tool.py", 2334, "registry.register"),
        "condition": "terminal toolset/check and selected backend must be available",
    },
    ("hermes-agent", "browser_console"): {
        "kind": "function-tool",
        "handler": _w("tools/browser_tool.py", 3508, "handler=lambda"),
        "registration": _w("tools/browser_tool.py", 3505, 'name="browser_console"'),
        "condition": "browser toolset/check and browser backend must be available",
    },
    ("hermes-agent", "execute_code"): {
        "kind": "function-tool",
        "handler": _w("tools/code_execution_tool.py", 934, "def execute_code"),
        "registration": _w("tools/code_execution_tool.py", 1611, 'name="execute_code"'),
        "condition": "code_execution toolset/check and local sandbox backend must be available",
    },
    ("nanobot", "exec"): {
        "kind": "function-tool",
        "handler": _w("nanobot/agent/tools/shell.py", 93, "async def execute"),
        "registration": _w("nanobot/agent/loop.py", 123, "ExecTool"),
        "condition": "normal agent loop must enable the builtin exec tool",
    },
    ("droidclaw", "shell"): {
        "kind": "structured-action",
        "handler": _w("src/actions.ts", 699, "executeShell"),
        "registration": _w("src/actions.ts", 197, 'case "shell"'),
        "condition": "LLM returns ActionDecision JSON; this is not a function-tools API call",
    },
    ("lettabot", "Task"): {
        "kind": "function-tool",
        "handler": _w(
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Task.ts",
            410,
            "function task",
        ),
        "registration": _w(
            "vendor-source/letta-code-v0.19.5/src/tools/toolDefinitions.ts",
            221,
            "Task:",
        ),
        "condition": "Task must be included in the configured allowed tool set",
    },
    ("mercury-agent", "run_command"): {
        "kind": "function-tool",
        "handler": _w("src/capabilities/shell/run-command.ts", 97, "execute: async"),
        "registration": _w("src/capabilities/registry.ts", 188, "run_command"),
        "condition": "shell capability must be enabled and the agent must not be in plan-only mode",
    },
    ("nanoclaw", "send_file"): {
        "kind": "mcp-tool",
        "handler": _w("container/agent-runner/src/mcp-tools/core.ts", 149, "async handler"),
        "registration": _w("container/agent-runner/src/mcp-tools/core.ts", 263, "registerTools"),
        "condition": "the built-in NanoClaw MCP server must be connected to the agent runner",
    },
    ("openclaw", "exec"): {
        "kind": "function-tool",
        "handler": _w("src/agents/bash-tools.exec.ts", 832, "execute: async"),
        "registration": _w("src/agents/pi-tools.ts", 268, "createExecTool"),
        "condition": "exec remains subject to host, security, approval, and sandbox configuration",
    },
    ("openclaw-cn", "exec"): {
        "kind": "function-tool",
        "handler": _w("src/agents/bash-tools.exec.ts", 743, "execute: async"),
        "registration": _w("src/agents/pi-tools.ts", 277, "createExecTool"),
        "condition": "exec remains subject to host, security, approval, and sandbox configuration",
    },
    ("openclaw-cn", "browser"): {
        "kind": "function-tool",
        "handler": _w("src/agents/tools/browser-tool.ts", 271, "execute: async"),
        "registration": _w("src/agents/openclaw-tools.ts", 103, "createBrowserTool"),
        "condition": "browser target/backend must be enabled for the active agent",
    },
    ("openclaw-cn", "apply_patch"): {
        "kind": "function-tool",
        "handler": _w("src/agents/apply-patch.ts", 94, "execute: async"),
        "registration": _w("src/agents/pi-tools.ts", 313, "createApplyPatchTool"),
        "condition": "workspace writes and apply-patch capability must be enabled",
    },
    ("openclaw-cn", "message"): {
        "kind": "function-tool",
        "handler": _w("src/agents/tools/message-tool.ts", 398, "execute: async"),
        "registration": _w("src/agents/openclaw-tools.ts", 90, "createMessageTool"),
        "condition": "message action/channel/account configuration must allow the requested operation",
    },
}


def _verify_witness(project: str, witness: Mapping[str, Any]) -> dict[str, Any]:
    root = get_project(project).source_root
    relative = Path(str(witness["path"]))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValidationError("tool-triggerability witness escapes project root")
    path = root / relative
    if not path.is_file():
        return {**witness, "valid": False, "reason": "source file is unavailable"}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    line = int(witness["line"])
    if line < 1 or line > len(lines):
        return {
            **witness,
            "valid": False,
            "reason": f"line is outside source (file has {len(lines)} lines)",
        }
    source_line = lines[line - 1]
    valid = str(witness["needle"]) in source_line
    return {
        **witness,
        "valid": valid,
        "source_sha256": sha256_file(path),
        "source_line": source_line.strip(),
        "reason": "matched current source" if valid else "expected text is absent at line",
    }


def _d5_anchor(report: Mapping[str, Any], project: str, entry: Mapping[str, Any]) -> dict[str, Any]:
    raw = str(entry.get("location") or "")
    match = LOCATION_RE.match(raw)
    if not match:
        return {"location": raw, "valid": False, "reason": "unparseable D5 location"}
    witness = {
        "path": match.group("path"),
        "line": int(match.group("line")),
        "needle": str(entry.get("name") or ""),
    }
    checked = _verify_witness(project, witness)
    return {"location": raw, **checked}


def _handler_observed(result: Mapping[str, Any]) -> tuple[bool, list[str]]:
    exploit = result.get("exploit", {})
    native = exploit.get("native_result", {}) if isinstance(exploit, Mapping) else {}
    if isinstance(native, Mapping) and isinstance(native.get("stage_events"), list):
        stages = [str(row.get("stage_id")) for row in native["stage_events"] if isinstance(row, Mapping)]
    else:
        stages = [str(item) for item in exploit.get("observed_stages", [])]
    return "S1" in stages, stages


def _native_probe(case: Mapping[str, Any], surface: Mapping[str, Any]) -> dict[str, Any]:
    probe_case = json.loads(canonical_json(case))
    handler = surface["handler"]
    probe_case["observations"] = [
        {
            "stage_id": "S1",
            "kind": "handler",
            "file": handler["path"],
            "symbol": handler["needle"],
            "line": handler["line"],
            "expected": "native dispatcher entered the current model-facing handler",
        }
    ]
    adapter = get_adapter(probe_case["adapter"])
    supported, reason = adapter.preflight(probe_case)
    if not supported or adapter.driver is None:
        return {"status": "unavailable", "handler_observed": False, "reason": reason}
    temporary = tempfile.TemporaryDirectory(prefix="clawgap-tool-triggerability-")
    root = Path(temporary.name)
    sandbox = CapabilitySandbox(root / "sandbox", probe_case)
    sandbox.prepare()
    attempt_dir = root / "attempt"
    attempt_dir.mkdir()
    try:
        result = adapter.driver(probe_case, 1, attempt_dir, sandbox)
        observed, stages = _handler_observed(result)
        return {
            "status": "observed" if observed else "not-observed",
            "handler_observed": observed,
            "observed_stages": stages,
            "reason": "native JSON dispatch entered S1" if observed else "native dispatch did not emit S1",
        }
    except Exception as exc:
        return {
            "status": "error",
            "handler_observed": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }
    finally:
        temporary.cleanup()


def _markdown(rows: list[Mapping[str, Any]], command: str) -> str:
    counts = {}
    for row in rows:
        counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1
    lines = [
        "# Ground-Truth LLM Tool Triggerability Audit",
        "",
        f"> Complete reproduction command: `{command}`",
        "",
        "This audit answers whether each ground truth has a current model-facing tool/action route and whether a sandboxed native JSON call reaches its handler. It does not test whether a natural-language prompt makes a live LLM select that route.",
        "",
        "## Results",
        "",
        f"Reports: **{len(rows)}**; function/MCP-tool triggerable: **{counts.get('tool-call-triggerable', 0)}**; "
        f"LLM structured-action triggerable: **{counts.get('structured-action-triggerable', 0)}**; "
        f"inconclusive: **{counts.get('inconclusive', 0)}**; not triggerable: **{counts.get('not-tool-triggerable', 0)}**.",
        "",
        "| Report | Project | Model-facing surface | Disposition | Native handler | Conditions |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        names = ", ".join(f"`{item['tool_name']}` ({item['kind']})" for item in row["surfaces"])
        native = ", ".join(
            f"{item['tool_name']}: {'yes' if item['native_probe']['handler_observed'] else item['native_probe']['status']}"
            for item in row["surfaces"]
        )
        conditions = "; ".join(sorted({item["condition"] for item in row["surfaces"]}))
        lines.append(
            f"| `{row['report_id']}` {row['report_name']} | `{row['project']}` | {names} | "
            f"`{row['disposition']}` | {native} | {conditions.replace('|', '\\|')} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "`tool-call-triggerable` proves source registration/exposure plus native handler reach from a JSON tool call. `structured-action-triggerable` is LLM-mediated but is not a function-tool API. Conditional availability remains important: toolsets, project configuration, approval mode, providers, browser/gateway services, and channel/account configuration may hide or block a tool in a particular deployment.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_ground_truth_tool_triggerability(request: TriggerabilityRequest) -> dict[str, Any]:
    campaign = load_campaign_definition(request.campaign_dir)
    case_by_tool: dict[tuple[str, str], Mapping[str, Any]] = {}
    reports: dict[str, dict[str, Any]] = {}
    for case in campaign.cases:
        case_by_tool.setdefault((case["project"], case["replay"]["tool_name"]), case)
        for binding in case["report_bindings"]:
            report = reports.setdefault(
                binding["report_id"],
                {
                    "report_id": binding["report_id"],
                    "report_name": binding["report_name"],
                    "project": case["project"],
                    "path": binding["path"],
                    "sha256": binding["sha256"],
                },
            )
            if report["project"] != case["project"]:
                raise ValidationError("ground-truth report is bound to multiple projects")
    if len(reports) != 37:
        raise ValidationError(f"tool-triggerability target drift: expected 37 reports, got {len(reports)}")

    used_surfaces: set[tuple[str, str]] = set()
    parsed_reports: dict[str, dict[str, Any]] = {}
    for report_id, binding in reports.items():
        path = Path(binding["path"])
        if not path.is_absolute():
            path = REPO_ROOT / path
        if not path.is_file() or sha256_file(path) != binding["sha256"]:
            raise ValidationError(f"ground-truth report binding drift: {report_id}")
        value = json.loads(path.read_text(encoding="utf-8"))
        entries = value.get("d5_tool_handler_entry") or []
        if not isinstance(entries, list) or not entries:
            raise ValidationError(f"ground-truth report lacks D5 handler evidence: {report_id}")
        parsed_reports[report_id] = value
        for entry in entries:
            key = (binding["project"], str(entry.get("name") or ""))
            if key not in TOOL_SURFACES:
                raise ValidationError(f"unregistered triggerability surface: {key}")
            used_surfaces.add(key)

    native_results: dict[tuple[str, str], dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=request.jobs, thread_name_prefix="tool-triggerability") as pool:
        futures = {}
        for key in sorted(used_surfaces):
            case = case_by_tool.get(key)
            if case is None:
                native_results[key] = {
                    "status": "not-run-no-generated-case",
                    "handler_observed": False,
                    "reason": "no generated runtime case uses this secondary handler",
                }
                continue
            futures[pool.submit(_native_probe, case, TOOL_SURFACES[key])] = key
        for future in as_completed(futures):
            native_results[futures[future]] = future.result()

    rows: list[dict[str, Any]] = []
    for report_id, binding in sorted(reports.items()):
        report = parsed_reports[report_id]
        surface_rows = []
        for entry in report["d5_tool_handler_entry"]:
            tool_name = str(entry["name"])
            key = (binding["project"], tool_name)
            surface = TOOL_SURFACES[key]
            handler = _verify_witness(binding["project"], surface["handler"])
            registration = _verify_witness(binding["project"], surface["registration"])
            flow = PROJECT_FLOWS[binding["project"]]
            exposure = _verify_witness(binding["project"], flow["exposure"])
            dispatch = _verify_witness(binding["project"], flow["dispatch"])
            static_valid = all(
                item["valid"] for item in (handler, registration, exposure, dispatch)
            )
            surface_rows.append(
                {
                    "tool_name": tool_name,
                    "kind": surface["kind"],
                    "condition": surface["condition"],
                    "handler": handler,
                    "registration": registration,
                    "model_exposure": exposure,
                    "dispatch": dispatch,
                    "static_valid": static_valid,
                    "native_probe": native_results[key],
                    "d5_anchor": _d5_anchor(report, binding["project"], entry),
                }
            )
        function_rows = [row for row in surface_rows if row["kind"] != "structured-action"]
        action_rows = [row for row in surface_rows if row["kind"] == "structured-action"]
        if any(row["static_valid"] and row["native_probe"]["handler_observed"] for row in function_rows):
            disposition = "tool-call-triggerable"
        elif any(row["static_valid"] and row["native_probe"]["handler_observed"] for row in action_rows):
            disposition = "structured-action-triggerable"
        elif any(not row["static_valid"] or row["native_probe"]["status"] in {"error", "unavailable"} for row in surface_rows):
            disposition = "inconclusive"
        else:
            disposition = "not-tool-triggerable"
        rows.append(
            {
                "schema_version": "clawgap-ground-truth-tool-triggerability/v1",
                "campaign_id": campaign.campaign_id,
                "report_id": report_id,
                "report_name": binding["report_name"],
                "project": binding["project"],
                "ground_truth_path": str(Path(binding["path"])),
                "ground_truth_sha256": binding["sha256"],
                "surfaces": surface_rows,
                "disposition": disposition,
                "live_prompt_selection": "not-tested",
            }
        )

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1
    command = (
        "python -m src.runtime_validation audit-gt-tool-triggerability "
        f"--campaign {request.campaign_dir} --out-dir {request.out_dir} --jobs {request.jobs}"
    )
    out = request.out_dir.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-", dir=out.parent))
    backup = out.parent / f".{out.name}.backup-{os.getpid()}"
    try:
        atomic_write_text(
            staging / "ground-truth-tool-triggerability.jsonl",
            "".join(canonical_json(row) + "\n" for row in rows),
        )
        atomic_write_text(staging / "summary.md", _markdown(rows, command))
        manifest = {
            "schema_version": "clawgap-ground-truth-tool-triggerability-manifest/v1",
            "campaign_id": campaign.campaign_id,
            "generation_command": command,
            "target_reports": len(rows),
            "disposition_counts": dict(sorted(counts.items())),
            "live_prompt_selection": "not-tested",
            "artifact_sha256": _artifact_hashes(staging),
        }
        atomic_write_json(staging / "manifest.json", manifest)
        _credential_scan(staging, ())
        if backup.exists():
            raise ValidationError(f"stale triggerability backup blocks publication: {backup}")
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
    return {**manifest, "artifact_dir": str(out), "rows": rows}
