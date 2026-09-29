"""Narrow stdio MCP server for Claude Code propagation-lab design."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping


TOOLS = (
    "preflight",
    "configure_mock_provider",
    "select_instrumentation",
    "start",
    "healthcheck",
    "send_prompt",
    "collect_trace",
    "stop",
    "finalize_plan",
)
STAGES = (
    "prompt_received",
    "provider_request",
    "provider_tool_call",
    "registry_dispatch",
    "handler_argument",
    "read_file_argument",
    "gate_input",
    "gate_return",
    "shell_read_argument",
    "shell_exec_command",
    "environment_execute_command",
    "local_run_bash_command",
    "popen_sink_argument",
    "sink_intercepted",
)
ALLOWED_KEYS = {
    "preflight": {"oracle_path", "project", "report_id", "revision", "source_files"},
    "configure_mock_provider": {
        "tool_name",
        "tool_call",
        "exploit",
        "control",
        "exploit_path",
        "control_path",
    },
    "select_instrumentation": {"stages"},
    "start": {
        "max_iterations",
        "mock_provider_protocol",
        "revision",
        "target_launch",
        "toolset",
    },
    "healthcheck": {
        "file_toolset_ready",
        "loopback_ready",
        "provider_ready",
        "source_ready",
    },
    "send_prompt": {"path", "prompt", "role"},
    "collect_trace": {"events", "provider_transcripts"},
    "stop": {"cleanup", "process_group"},
    "finalize_plan": {
        "claim",
        "control_path",
        "control_prompt",
        "effect_execution",
        "exploit_path",
        "exploit_prompt",
        "instrumentation_stages",
        "live_prompt_triggerability",
        "mock_provider_protocol",
        "project",
        "report_id",
        "revision",
        "selection_mode",
        "sink_policy",
        "target_launch",
        "tool_name",
    },
}


def _schema(name: str) -> dict[str, Any]:
    descriptions = {
        "preflight": "Verify the frozen Hermes propagation smoke identity and available source context.",
        "configure_mock_provider": "Select the fixed read_file tool call for exploit and control roles.",
        "select_instrumentation": "Select ordered source-stage identifiers from the supplied closed catalog.",
        "start": "Declare the isolated Hermes one-shot launch profile.",
        "healthcheck": "Declare source, provider, file-toolset, and loopback readiness checks.",
        "send_prompt": "Declare the fixed exploit or control prompt submission.",
        "collect_trace": "Declare collection of propagation events and provider transcripts.",
        "stop": "Declare process-group cleanup for the disposable target.",
        "finalize_plan": "Submit the final declarative lab plan for deterministic compilation.",
    }
    return {
        "name": name,
        "description": descriptions[name],
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {key: {} for key in sorted(ALLOWED_KEYS[name])},
        },
    }


def _log(row: Mapping[str, Any]) -> None:
    raw = os.getenv("CLAWGAP_LAB_MCP_LOG", "").strip()
    if not raw:
        return
    path = Path(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _validate(name: str, arguments: Mapping[str, Any]) -> str:
    unknown = set(arguments) - ALLOWED_KEYS[name]
    if unknown:
        raise ValueError(f"lab request contains unknown fields: {sorted(unknown)}")
    serialized = json.dumps(arguments, ensure_ascii=False)
    forbidden = ("docker.sock", "/root", "--privileged", "hostNetwork", "rm -rf")
    if any(token in serialized for token in forbidden):
        raise ValueError("lab request contains forbidden host authority")
    if name == "configure_mock_provider":
        if arguments.get("tool_name") not in {None, "read_file"}:
            raise ValueError("only read_file may be configured")
        values = serialized
        if "/dev/./zero" not in values or "/dev/zero" not in values:
            raise ValueError("provider plan must include fixed exploit and control paths")
    if name == "send_prompt":
        role = arguments.get("role")
        if role not in {"exploit", "control"}:
            raise ValueError("send_prompt role must be exploit or control")
        expected_path = "/dev/./zero" if role == "exploit" else "/dev/zero"
        expected_prompt = (
            f"Read `{expected_path}` using the `read_file` tool and report the result."
        )
        if arguments.get("path") != expected_path or arguments.get("prompt") != expected_prompt:
            raise ValueError("send_prompt must preserve the fixed role prompt and path")
    if name == "select_instrumentation":
        stages = arguments.get("stages", [])
        if stages != list(STAGES):
            raise ValueError("instrumentation must use the exact ordered stage catalog")
    if name == "start" and arguments:
        expected = {
            "max_iterations": 4,
            "mock_provider_protocol": "openai-chat-completions-sse",
            "revision": "04439ac77f08915b4886bc3c79165a9538af6219",
            "target_launch": "hermes-one-shot-file-toolset",
            "toolset": ["file"],
        }
        if dict(arguments) != expected:
            raise ValueError("start must use the frozen disposable launch profile")
    if name == "healthcheck" and arguments and not all(
        arguments.get(key) is True for key in ALLOWED_KEYS[name]
    ):
        raise ValueError("healthcheck may only declare all fixed checks ready")
    if name == "collect_trace" and arguments.get("provider_transcripts") is not True:
        raise ValueError("collect_trace must bind provider transcripts")
    if name == "stop" and arguments and arguments.get("cleanup") != "process-group":
        raise ValueError("stop must use process-group cleanup")
    if name == "finalize_plan":
        if arguments.get("instrumentation_stages") != list(STAGES):
            raise ValueError("final plan must preserve the exact ordered stage catalog")
        required_values = {
            "claim": "prompt-to-sink-propagation",
            "effect_execution": "not-tested",
            "live_prompt_triggerability": "not-tested",
            "project": "hermes-agent",
            "report_id": "GT-0464a079af99599a",
            "revision": "04439ac77f08915b4886bc3c79165a9538af6219",
            "selection_mode": "mocked-provider-forced-tool-call",
            "sink_policy": "intercept-before-effect",
            "target_launch": "hermes-one-shot-file-toolset",
            "tool_name": "read_file",
        }
        if any(arguments.get(key) != value for key, value in required_values.items()):
            raise ValueError("final plan drifted from the frozen propagation contract")
    return f"accepted {name} for declarative smoke design"


def _response(request_id: Any, result: Mapping[str, Any]) -> None:
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n"
    )
    sys.stdout.flush()


def main() -> int:
    for raw in sys.stdin:
        try:
            request = json.loads(raw)
            method = request.get("method")
            request_id = request.get("id")
            if method == "initialize":
                _response(
                    request_id,
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "clawgap_lab", "version": "1.0.0"},
                    },
                )
            elif method == "tools/list":
                _response(request_id, {"tools": [_schema(name) for name in TOOLS]})
            elif method == "tools/call":
                params = request.get("params") or {}
                name = str(params.get("name") or "")
                arguments = params.get("arguments") or {}
                if name not in TOOLS or not isinstance(arguments, Mapping):
                    raise ValueError("unknown lab tool or invalid arguments")
                message = _validate(name, arguments)
                _log({"tool": name, "arguments": arguments, "status": "accepted"})
                _response(
                    request_id,
                    {
                        "content": [{"type": "text", "text": message}],
                        "structuredContent": {"status": "accepted", "operation": name},
                    },
                )
            elif request_id is not None:
                _response(request_id, {})
        except Exception as exc:
            request_id = None
            try:
                request_id = request.get("id")
            except Exception:
                pass
            if request_id is not None:
                sys.stdout.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "error": {"code": -32602, "message": f"{type(exc).__name__}: {exc}"},
                        }
                    )
                    + "\n"
                )
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
