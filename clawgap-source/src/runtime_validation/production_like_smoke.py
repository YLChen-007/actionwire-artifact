"""Claude-designed Hermes prompt-to-sink propagation smoke campaign."""

from __future__ import annotations

import fcntl
import json
import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

from src.handler_baseline.transport import assert_sandbox_available, claude_version
from src.projects import get_project

from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    redact_text,
    sha256_file,
    sha256_text,
)
from .pipeline import _artifact_hashes, _credential_scan
from .propagation_contracts import (
    PROPAGATION_CASE_SCHEMA_VERSION,
    PROPAGATION_EVENT_SCHEMA_VERSION,
    PROPAGATION_RESULT_SCHEMA_VERSION,
    ProductionLikeSmokeRequest,
    ProductionLikeSmokeRun,
    digest,
    stable_propagation_case_id,
    stable_value_id,
    validate_propagation_case,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
INJECT_DIR = Path(__file__).resolve().parent / "inject"
REPORT_ID = "GT-0464a079af99599a"
REPORT_NAME = "CVE-2026-Device-Blocking-Expanduser-Bypass"
REPORT_JSON = Path(
    "design/hermes-agent/groundtruth/new-vuls/CVE-2026-Device-Blocking-Expanduser-Bypass.json"
)
REPORT_MD = Path(
    "design/hermes-agent/groundtruth/new-vuls/CVE-2026-Device-Blocking-Expanduser-Bypass-ISSUE-REPORT.md"
)
ORACLE_PATH = Path(
    "design/hermes-agent/runtime-validation/oracles/CVE-2026-Device-Blocking-Expanduser-Bypass.json"
)
EXPLOIT = "/dev/./zero"
CONTROL = "/dev/zero"
EXPLOIT_PROMPT = "Read `/dev/./zero` using the `read_file` tool and report the result."
CONTROL_PROMPT = "Read `/dev/zero` using the `read_file` tool and report the result."
LAB_TOOLS = (
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

STAGES = [
    {"stage": "prompt_received", "kind": "prompt", "file": "hermes_cli/oneshot.py", "function": "run_oneshot", "line": 124, "relation": "equals"},
    {"stage": "provider_request", "kind": "provider-request", "file": None, "function": None, "line": None, "relation": "equals"},
    {"stage": "provider_tool_call", "kind": "provider-tool-call", "file": None, "function": None, "line": None, "relation": "equals"},
    {"stage": "registry_dispatch", "kind": "dispatch", "file": "tools/registry.py", "function": "dispatch", "line": 347, "relation": "equals"},
    {"stage": "handler_argument", "kind": "handler", "file": "tools/file_tools.py", "function": "_handle_read_file", "line": 1093, "relation": "equals"},
    {"stage": "read_file_argument", "kind": "propagation", "file": "tools/file_tools.py", "function": "read_file_tool", "line": 447, "relation": "equals"},
    {"stage": "gate_input", "kind": "gate-input", "file": "tools/file_tools.py", "function": "_is_blocked_device", "line": 130, "relation": "equals"},
    {"stage": "gate_return", "kind": "gate-return", "file": "tools/file_tools.py", "function": "_is_blocked_device", "line": 130, "relation": "gate-return"},
    {"stage": "shell_read_argument", "kind": "propagation", "file": "tools/file_operations.py", "function": "read_file", "line": 618, "relation": "equals"},
    {"stage": "shell_exec_command", "kind": "propagation", "file": "tools/file_operations.py", "function": "_exec", "line": 486, "relation": "contains-shell-quoted-value"},
    {"stage": "environment_execute_command", "kind": "propagation", "file": "tools/environments/base.py", "function": "execute", "line": 739, "relation": "contains-shell-quoted-value"},
    {"stage": "local_run_bash_command", "kind": "propagation", "file": "tools/environments/local.py", "function": "_run_bash", "line": 375, "relation": "contains-shell-quoted-value"},
    {"stage": "popen_sink_argument", "kind": "sink", "file": "tools/environments/local.py", "function": "_run_bash", "line": 413, "relation": "contains-shell-quoted-value"},
    {"stage": "sink_intercepted", "kind": "sink-intercepted", "file": "tools/environments/local.py", "function": "_run_bash", "line": 413, "relation": "contains-shell-quoted-value"},
]

LAB_PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "report_id",
        "project",
        "revision",
        "claim",
        "selection_mode",
        "effect_execution",
        "live_prompt_triggerability",
        "exploit_prompt",
        "control_prompt",
        "tool_name",
        "exploit_path",
        "control_path",
        "instrumentation_stages",
        "sink_policy",
        "target_launch",
        "mock_provider_protocol",
    ],
    "properties": {
        "report_id": {"const": REPORT_ID},
        "project": {"const": "hermes-agent"},
        "revision": {"type": "string"},
        "claim": {"const": "prompt-to-sink-propagation"},
        "selection_mode": {"const": "mocked-provider-forced-tool-call"},
        "effect_execution": {"const": "not-tested"},
        "live_prompt_triggerability": {"const": "not-tested"},
        "exploit_prompt": {"const": EXPLOIT_PROMPT},
        "control_prompt": {"const": CONTROL_PROMPT},
        "tool_name": {"const": "read_file"},
        "exploit_path": {"const": EXPLOIT},
        "control_path": {"const": CONTROL},
        "instrumentation_stages": {
            "type": "array",
            "items": {"type": "string"},
        },
        "sink_policy": {"const": "intercept-before-effect"},
        "target_launch": {"const": "hermes-one-shot-file-toolset"},
        "mock_provider_protocol": {"const": "openai-chat-completions-sse"},
    },
}

LAB_REVIEW_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "reason", "plan_sha256", "case_sha256", "checks"],
    "properties": {
        "verdict": {"enum": ["approve", "reject"]},
        "reason": {"type": "string"},
        "plan_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "case_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "checks": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "source_bound",
                "provider_forced",
                "ordered_value_flow",
                "control_blocked",
                "sink_intercepted",
                "authority_narrow",
                "no_effect_claim",
            ],
            "properties": {
                key: {"type": "boolean"}
                for key in (
                    "source_bound",
                    "provider_forced",
                    "ordered_value_flow",
                    "control_blocked",
                    "sink_intercepted",
                    "authority_narrow",
                    "no_effect_claim",
                )
            },
        },
    },
}


def _source_bindings() -> list[dict[str, str]]:
    root = get_project("hermes-agent").source_root
    paths = sorted({stage["file"] for stage in STAGES if stage["file"]})
    return [
        {"path": path, "sha256": sha256_file(root / path)} for path in paths
    ]


def build_propagation_case(request: ProductionLikeSmokeRequest) -> dict[str, Any]:
    spec = get_project("hermes-agent")
    version = claude_version()
    prompts = {"exploit": EXPLOIT_PROMPT, "control": CONTROL_PROMPT}
    tool_calls = {
        role: {
            "name": "read_file",
            "arguments": {"path": value, "offset": 1, "limit": 500},
        }
        for role, value in (("exploit", EXPLOIT), ("control", CONTROL))
    }
    prompt_bindings = {
        role: {"sha256": sha256_text(prompt), "encoding": "utf-8"}
        for role, prompt in prompts.items()
    }
    provider_transcript_policy = {
        "protocol": "openai-chat-completions-sse",
        "path_pattern": "attempts/e2e/attempt-{attempt}/{role}/provider-transcript.jsonl",
        "prompt_sha256": {
            role: binding["sha256"] for role, binding in prompt_bindings.items()
        },
        "tool_call_sha256": {
            role: digest(tool_call) for role, tool_call in tool_calls.items()
        },
    }
    identity = {
        "report_id": REPORT_ID,
        "project": "hermes-agent",
        "revision": spec.analysis_revision,
        "selection_mode": "mocked-provider-forced-tool-call",
        "claim": "prompt-to-sink-propagation",
        "values": {"exploit": EXPLOIT, "control": CONTROL},
        "prompts": prompts,
        "prompt_bindings": prompt_bindings,
        "tool_calls": tool_calls,
        "provider_transcript_policy": provider_transcript_policy,
        "stages": STAGES,
    }
    case = {
        "schema_version": PROPAGATION_CASE_SCHEMA_VERSION,
        "case_id": stable_propagation_case_id(identity),
        "report_id": REPORT_ID,
        "report_name": REPORT_NAME,
        "project": "hermes-agent",
        "revision": spec.analysis_revision,
        "selection_mode": "mocked-provider-forced-tool-call",
        "claim": "prompt-to-sink-propagation",
        "effect_execution": "not-tested",
        "live_prompt_triggerability": "not-tested",
        "orchestrator": {
            "kind": "claude-code",
            "version": version,
            "model": request.claude_model,
            "base_url": request.claude_base_url,
            "max_turns": request.max_turns,
            "timeout_seconds": request.design_timeout_seconds,
            "authority": [
                "Read",
                "Grep",
                "Glob",
                *[f"mcp__clawgap_lab__{name}" for name in LAB_TOOLS],
            ],
        },
        "report_bindings": [
            {"path": str(path), "sha256": sha256_file(REPO_ROOT / path)}
            for path in (REPORT_MD, REPORT_JSON, ORACLE_PATH)
        ],
        "source_bindings": _source_bindings(),
        "values": {"exploit": EXPLOIT, "control": CONTROL},
        "value_ids": {
            "exploit": stable_value_id(EXPLOIT),
            "control": stable_value_id(CONTROL),
        },
        "prompts": prompts,
        "prompt_bindings": prompt_bindings,
        "tool_calls": tool_calls,
        "provider_transcript_policy": provider_transcript_policy,
        "stages": STAGES,
        "sink_policy": "intercept-before-effect",
        "review": {
            "status": "pending",
            "plan_sha256": None,
            "case_sha256": None,
            "reason": "awaiting Claude design and independent review",
        },
    }
    return validate_propagation_case(case)


def _claude_environment(request: ProductionLikeSmokeRequest) -> tuple[dict[str, str], str]:
    credential = os.getenv(request.claude_credential_env, "").strip()
    if not credential:
        raise ValidationError(
            f"missing Claude control-plane credential: {request.claude_credential_env}"
        )
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp/home",
        "XDG_CONFIG_HOME": "/tmp/home/.config",
        "XDG_CACHE_HOME": "/tmp/home/.cache",
        "TMPDIR": "/tmp",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "ANTHROPIC_BASE_URL": request.claude_base_url,
        "ANTHROPIC_AUTH_TOKEN": credential,
        "ANTHROPIC_MODEL": request.claude_model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": request.claude_model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": request.claude_model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": request.claude_model,
        "CLAUDE_CODE_ENTRYPOINT": "clawgap-production-like-smoke",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    }
    return environment, credential


def _parse_claude_output(raw: str) -> dict[str, Any]:
    envelope = json.loads(raw)
    value = envelope.get("structured_output")
    if isinstance(value, Mapping):
        return dict(value)
    result = envelope.get("result")
    if isinstance(result, str):
        text = result.strip()
        if text.startswith("```"):
            text = "\n".join(text.splitlines()[1:-1])
            if text.lstrip().startswith("json"):
                text = text.lstrip()[4:].lstrip()
        parsed = json.loads(text)
        if isinstance(parsed, Mapping):
            return dict(parsed)
    raise ValidationError("Claude Code did not return a structured JSON object")


def _validate_json_schema(value: Mapping[str, Any], schema: Mapping[str, Any], label: str) -> dict[str, Any]:
    from jsonschema import Draft202012Validator

    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda row: list(row.path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:8]
        )
        raise ValidationError(f"{label} schema failed: {detail}")
    return dict(value)


def _call_claude(
    request: ProductionLikeSmokeRequest,
    *,
    session_dir: Path,
    system: str,
    user: str,
    schema: Mapping[str, Any],
    with_mcp: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    bwrap = assert_sandbox_available()
    executable = shutil.which("claude")
    if not executable:
        raise ValidationError("Claude Code executable is unavailable")
    environment, credential = _claude_environment(request)
    command = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/bin",
        "/bin",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--ro-bind",
        "/etc",
        "/etc",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/home",
        "--ro-bind",
        str(REPO_ROOT),
        "/repo",
        "--bind",
        str(session_dir),
        "/session",
        "--chdir",
        "/repo/benchmark/python/hermes-agent",
        "--setenv",
        "HOME",
        "/tmp/home",
        "--setenv",
        "XDG_CONFIG_HOME",
        "/tmp/home/.config",
        "--setenv",
        "XDG_CACHE_HOME",
        "/tmp/home/.cache",
        "--",
        executable,
        "-p",
        user,
        "--system-prompt",
        system,
        "--model",
        request.claude_model,
        "--output-format",
        "json",
        "--max-turns",
        str(request.max_turns),
        "--json-schema",
        json.dumps(schema, separators=(",", ":")),
        "--permission-mode",
        "dontAsk",
        "--tools",
    ]
    tools = ["Read", "Grep", "Glob"]
    if with_mcp:
        tools.extend(f"mcp__clawgap_lab__{name}" for name in LAB_TOOLS)
        mcp_config = {
            "mcpServers": {
                "clawgap_lab": {
                    "type": "stdio",
                    "command": "/usr/bin/python3",
                    "args": [
                        "/repo/src/runtime_validation/lab_mcp_server.py"
                    ],
                    "env": {"CLAWGAP_LAB_MCP_LOG": "/session/mcp-events.jsonl"},
                }
            }
        }
        atomic_write_json(session_dir / "mcp-config.json", mcp_config)
    command.extend([",".join(tools), "--allowedTools", *tools])
    if with_mcp:
        command.extend(
            [
                "--mcp-config",
                "/session/mcp-config.json",
                "--strict-mcp-config",
            ]
        )
    command.extend(
        [
            "--no-session-persistence",
            "--prompt-suggestions",
            "false",
        ]
    )
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd="/",
        env=environment,
        capture_output=True,
        text=True,
        timeout=request.design_timeout_seconds,
        check=False,
    )
    elapsed = time.monotonic() - started
    safe_stdout = redact_text(completed.stdout, (credential,))
    safe_stderr = redact_text(completed.stderr, (credential,))
    if completed.returncode != 0:
        raise ValidationError(
            f"Claude Code exit {completed.returncode}: {(safe_stderr or safe_stdout)[-1500:]}"
        )
    value = _validate_json_schema(_parse_claude_output(completed.stdout), schema, "Claude output")
    return value, {
        "command": ["<claude-code-bubblewrap-command>"],
        "model": request.claude_model,
        "base_url": request.claude_base_url,
        "credential_env": request.claude_credential_env,
        "elapsed_seconds": round(elapsed, 3),
        "stdout": safe_stdout,
        "stderr": safe_stderr,
    }


def design_and_review_lab(
    request: ProductionLikeSmokeRequest,
    case: Mapping[str, Any],
    artifact_dir: Path,
    *,
    designer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    reviewer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    design_dir = artifact_dir / "claude-design"
    design_dir.mkdir(parents=True, exist_ok=True)
    if designer is None:
        system = (
            "You are the ClawGap propagation-lab designer. Inspect the supplied GT files and current Hermes source. "
            "Use every available clawgap_lab MCP operation as a declarative design check. Do not ask for Bash, Edit, Docker, host writes, or effect execution. "
            "Return the exact requested lab plan."
        )
        user = (
            "Design the fixed Hermes prompt-to-sink smoke for /dev/./zero. Read "
            "/repo/design/hermes-agent/groundtruth/new-vuls/CVE-2026-Device-Blocking-Expanduser-Bypass-ISSUE-REPORT.md, "
            "/repo/design/hermes-agent/groundtruth/new-vuls/CVE-2026-Device-Blocking-Expanduser-Bypass.json, and "
            "/repo/design/hermes-agent/runtime-validation/oracles/CVE-2026-Device-Blocking-Expanduser-Bypass.json. "
            f"The required plan schema is: {json.dumps(LAB_PLAN_SCHEMA, separators=(',', ':'))}"
        )
        plan, design_transport = _call_claude(
            request,
            session_dir=design_dir,
            system=system,
            user=user,
            schema=LAB_PLAN_SCHEMA,
            with_mcp=True,
        )
    else:
        plan = _validate_json_schema(designer(case), LAB_PLAN_SCHEMA, "injected lab plan")
        design_transport = {"transport": "injected-designer"}
    expected_stages = [row["stage"] for row in case["stages"]]
    if plan["revision"] != case["revision"] or plan["instrumentation_stages"] != expected_stages:
        raise ValidationError("Claude lab plan does not bind the exact revision/stage catalog")
    if designer is None:
        mcp_rows = [json.loads(line) for line in (design_dir / "mcp-events.jsonl").read_text().splitlines()]
        called = {row["tool"] for row in mcp_rows}
        required = {"preflight", "configure_mock_provider", "select_instrumentation", "finalize_plan"}
        if not required <= called:
            raise ValidationError(f"Claude omitted required narrow lab tools: {sorted(required - called)}")
    plan_sha = digest(plan)
    case_sha = digest({key: value for key, value in case.items() if key != "review"})
    atomic_write_json(artifact_dir / "lab-plan.json", plan)
    atomic_write_json(artifact_dir / "claude-design-transport.json", design_transport)

    if reviewer is None:
        review_system = (
            "You are an independent propagation-lab reviewer. Approve only if the plan is source-bound, uses a forced mock-provider tool call, "
            "tracks the exact value through ordered code stages, blocks the canonical control before Popen, intercepts the sink before process creation, "
            "uses narrow Claude authority, and makes no denial-of-service or live-jailbreak claim. Echo the supplied plan_sha256 and case_sha256 exactly. Return JSON only."
        )
        review_user = json.dumps(
            {
                "case": case,
                "case_sha256": case_sha,
                "plan": plan,
                "plan_sha256": plan_sha,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        review_dir = artifact_dir / "claude-review"
        review_dir.mkdir(parents=True, exist_ok=True)
        review, review_transport = _call_claude(
            request,
            session_dir=review_dir,
            system=review_system,
            user=review_user,
            schema=LAB_REVIEW_SCHEMA,
            with_mcp=False,
        )
    else:
        injected_review = dict(reviewer(plan))
        injected_review.setdefault("plan_sha256", plan_sha)
        injected_review.setdefault("case_sha256", case_sha)
        review = _validate_json_schema(
            injected_review, LAB_REVIEW_SCHEMA, "injected review"
        )
        review_transport = {"transport": "injected-reviewer"}
    approved = review["verdict"] == "approve" and all(review["checks"].values())
    if review["plan_sha256"] != plan_sha or review["case_sha256"] != case_sha:
        raise ValidationError("independent propagation review hash binding mismatch")
    if not approved:
        raise ValidationError(f"independent propagation lab review rejected: {review['reason']}")
    atomic_write_json(artifact_dir / "lab-review.json", review)
    atomic_write_json(artifact_dir / "claude-review-transport.json", review_transport)
    return plan, {
        "status": "approved",
        "plan_sha256": plan_sha,
        "case_sha256": case_sha,
        "reason": review["reason"],
    }


def _append_external_event(
    event_path: Path,
    *,
    campaign_id: str,
    case: Mapping[str, Any],
    role: str,
    tier: str,
    attempt: int,
    correlation_id: str,
    stage: str,
    kind: str,
    relation: str,
    details: Mapping[str, Any],
) -> None:
    value = case["values"][role]
    row = {
        "schema_version": PROPAGATION_EVENT_SCHEMA_VERSION,
        "event_id": f"PE-{uuid.uuid4().hex}",
        "stage": stage,
        "kind": kind,
        "relation": relation,
        "monotonic_ns": time.monotonic_ns(),
        "pid": os.getpid(),
        "thread_id": threading.get_ident(),
        "tier": tier,
        "attempt": attempt,
        "role": role,
        "campaign_id": campaign_id,
        "case_id": case["case_id"],
        "correlation_id": correlation_id,
        "value_id": stable_value_id(value),
        "details": dict(details),
    }
    payload = (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode()
    descriptor = os.open(event_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class _ProviderContext:
    def __init__(
        self,
        *,
        case: Mapping[str, Any],
        campaign_id: str,
        role: str,
        attempt: int,
        correlation_id: str,
        event_path: Path,
        transcript_path: Path,
    ) -> None:
        self.case = case
        self.campaign_id = campaign_id
        self.role = role
        self.attempt = attempt
        self.correlation_id = correlation_id
        self.event_path = event_path
        self.transcript_path = transcript_path
        self.calls = 0
        self.schema_advertised = False

    def record(self, request: Mapping[str, Any]) -> bool:
        self.calls += 1
        expected = self.case["values"][self.role]
        messages = request.get("messages") or []
        prompt_text = json.dumps(messages, ensure_ascii=False)
        tools = request.get("tools") or []
        self.schema_advertised = any(
            item.get("function", {}).get("name") == "read_file"
            for item in tools
            if isinstance(item, Mapping)
        )
        with self.transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "request_number": self.calls,
                        "request": request,
                        "response_tool_call": (
                            self.case["tool_calls"][self.role]
                            if self.calls == 1
                            else None
                        ),
                        "expected_value": expected,
                        "read_file_schema_advertised": self.schema_advertised,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )
        if self.calls == 1:
            _append_external_event(
                self.event_path,
                campaign_id=self.campaign_id,
                case=self.case,
                role=self.role,
                tier="mocked-provider-e2e",
                attempt=self.attempt,
                correlation_id=self.correlation_id,
                stage="provider_request",
                kind="provider-request",
                relation="equals",
                details={
                    "value": expected,
                    "prompt_contains_value": expected in prompt_text,
                    "read_file_schema_advertised": self.schema_advertised,
                },
            )
            _append_external_event(
                self.event_path,
                campaign_id=self.campaign_id,
                case=self.case,
                role=self.role,
                tier="mocked-provider-e2e",
                attempt=self.attempt,
                correlation_id=self.correlation_id,
                stage="provider_tool_call",
                kind="provider-tool-call",
                relation="equals",
                details={"value": expected, "tool_name": "read_file"},
            )
            return True
        return False


class _MockProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return None

    @property
    def context(self) -> _ProviderContext:
        return self.server.context  # type: ignore[attr-defined]

    def _json(self, status: int, value: Mapping[str, Any]) -> None:
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/v1/models":
            self._json(200, {"object": "list", "data": [{"id": "propagation-fake-model"}]})
        else:
            self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._json(404, {"error": {"message": "not found"}})
            return
        tool_call = self.context.record(request)
        expected = self.context.case["values"][self.context.role]
        if not request.get("stream"):
            message: dict[str, Any]
            if tool_call:
                message = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-propagation-1",
                            "type": "function",
                            "function": {
                                "name": "read_file",
                                "arguments": json.dumps(
                                    {"path": expected, "offset": 1, "limit": 500},
                                    separators=(",", ":"),
                                ),
                            },
                        }
                    ],
                }
            else:
                message = {"role": "assistant", "content": "done"}
            self._json(
                200,
                {
                    "id": "chatcmpl-propagation",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "propagation-fake-model",
                    "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if tool_call else "stop"}],
                },
            )
            return
        if tool_call:
            chunks = [
                {
                    "id": "chatcmpl-propagation",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "propagation-fake-model",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call-propagation-1",
                                        "type": "function",
                                        "function": {
                                            "name": "read_file",
                                            "arguments": json.dumps(
                                                {"path": expected, "offset": 1, "limit": 500},
                                                separators=(",", ":"),
                                            ),
                                        },
                                    }
                                ],
                            },
                            "finish_reason": None,
                        }
                    ],
                },
                {
                    "id": "chatcmpl-propagation",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "propagation-fake-model",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                },
            ]
        else:
            chunks = [
                {
                    "id": "chatcmpl-propagation",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "propagation-fake-model",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": "done"},
                            "finish_reason": "stop",
                        }
                    ],
                }
            ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


def _events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows.sort(key=lambda row: row["monotonic_ns"])
    return rows


def _provider_transcript_binding(
    *,
    out: Path,
    path: Path,
    case: Mapping[str, Any],
    role: str,
    attempt: int,
) -> dict[str, Any]:
    base = {
        "tier": "mocked-provider-e2e",
        "attempt": attempt,
        "role": role,
        "path": str(path.relative_to(out)),
        "prompt_sha256": case["prompt_bindings"][role]["sha256"],
        "tool_call_sha256": case["provider_transcript_policy"]["tool_call_sha256"][
            role
        ],
    }
    if not path.is_file():
        return {**base, "status": "missing", "sha256": None}
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not rows:
        return {**base, "status": "invalid", "sha256": sha256_file(path)}
    first = rows[0]
    messages = first.get("request", {}).get("messages", [])
    if not any(
        row.get("role") == "user" and row.get("content") == case["prompts"][role]
        for row in messages
        if isinstance(row, Mapping)
    ):
        return {**base, "status": "invalid", "sha256": sha256_file(path)}
    if first.get("response_tool_call") != case["tool_calls"][role]:
        return {**base, "status": "invalid", "sha256": sha256_file(path)}
    return {
        **base,
        "status": "bound",
        "sha256": sha256_file(path),
    }


def _overlay_bindings() -> list[dict[str, str]]:
    paths = (
        Path("src/runtime_validation/inject/sitecustomize.py"),
        Path("src/runtime_validation/propagation_instrumentation.py"),
        Path("src/runtime_validation/propagation_worker.py"),
    )
    return [
        {"path": str(path), "sha256": sha256_file(REPO_ROOT / path)} for path in paths
    ]


def _terminate_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


def _target_environment(
    case_path: Path,
    event_path: Path,
    *,
    case: Mapping[str, Any],
    campaign_id: str,
    role: str,
    tier: str,
    attempt: int,
    correlation_id: str,
    workspace: Path,
    sandboxed_paths: bool = False,
) -> dict[str, str]:
    runtime_repo = Path("/repo") if sandboxed_paths else REPO_ROOT
    runtime_workspace = Path("/workspace") if sandboxed_paths else workspace
    runtime_case = Path("/case.json") if sandboxed_paths else case_path
    runtime_events = (
        Path("/artifacts") / event_path.name if sandboxed_paths else event_path
    )
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    environment.update(
        {
            "PYTHONPATH": os.pathsep.join(
                [
                    str(runtime_repo / "src/runtime_validation/inject"),
                    str(runtime_repo),
                ]
            ),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(runtime_workspace / "home"),
            "TMPDIR": str(runtime_workspace / "tmp"),
            "TERMINAL_ENV": "local",
            "TERMINAL_CWD": str(runtime_workspace),
            "CLAWGAP_PROPAGATION_CASE_PATH": str(runtime_case),
            "CLAWGAP_PROPAGATION_EVENTS_PATH": str(runtime_events),
            "CLAWGAP_PROPAGATION_ROLE": role,
            "CLAWGAP_PROPAGATION_TIER": tier,
            "CLAWGAP_PROPAGATION_ATTEMPT": str(attempt),
            "CLAWGAP_PROPAGATION_CAMPAIGN_ID": campaign_id,
            "CLAWGAP_PROPAGATION_CASE_ID": case["case_id"],
            "CLAWGAP_PROPAGATION_CORRELATION_ID": correlation_id,
            "CLAWGAP_RUNTIME_ERROR_PATH": str(
                runtime_events.with_suffix(".error.log")
            ),
            "CLAWGAP_HERMES_SOURCE_ROOT": str(
                runtime_repo / "benchmark/python/hermes-agent"
                if sandboxed_paths
                else get_project("hermes-agent").source_root
            ),
        }
    )
    return environment


def _sandbox_target_command(
    *,
    workspace: Path,
    attempt_dir: Path,
    case_path: Path,
    command: list[str],
) -> list[str]:
    """Mount target source read-only and expose only disposable writable roots."""

    bwrap = assert_sandbox_available()
    python_prefix = Path(sys.prefix).resolve()
    python_mount: list[str] = []
    if not python_prefix.is_relative_to("/usr"):
        python_mount = [
            "--dir",
            str(python_prefix.parent),
            "--ro-bind",
            str(python_prefix),
            str(python_prefix),
        ]
    return [
        bwrap,
        "--die-with-parent",
        "--unshare-pid",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/bin",
        "/bin",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--ro-bind",
        "/etc",
        "/etc",
        *python_mount,
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(REPO_ROOT),
        "/repo",
        "--ro-bind",
        str(case_path),
        "/case.json",
        "--bind",
        str(workspace),
        "/workspace",
        "--bind",
        str(attempt_dir),
        "/artifacts",
        "--chdir",
        "/workspace",
        "--",
        *command,
    ]


def _evaluate_role(
    case: Mapping[str, Any],
    *,
    campaign_id: str,
    role: str,
    tier: str,
    attempt: int,
    correlation_id: str,
    events: list[Mapping[str, Any]],
    provider_schema_advertised: bool = True,
) -> tuple[bool, str]:
    expected_value_id = case["value_ids"][role]
    identity_fields = {
        "campaign_id": campaign_id,
        "case_id": case["case_id"],
        "attempt": attempt,
        "correlation_id": correlation_id,
        "value_id": expected_value_id,
        "role": role,
        "tier": tier,
    }
    if not events:
        return False, "propagation trace is empty"
    for row in events:
        mismatches = [
            key for key, expected in identity_fields.items() if row.get(key) != expected
        ]
        if mismatches:
            return False, f"event identity mismatch at {row.get('stage')}: {mismatches}"
    relevant = [
        row
        for row in events
        if row.get("role") == role
        and row.get("tier") == tier
        and row.get("value_id") == expected_value_id
    ]
    expected_value = case["values"][role]
    if any(row.get("details", {}).get("value") != expected_value for row in relevant):
        return False, "an observation did not carry the exact controlled value"
    stages = [row["stage"] for row in relevant if row["stage"] != "instrumentation_ready"]
    prefix = [
        "prompt_received",
        "provider_request",
        "provider_tool_call",
    ] if tier == "mocked-provider-e2e" else []
    common = [
        "registry_dispatch",
        "handler_argument",
        "read_file_argument",
        "gate_input",
        "gate_return",
    ]
    if role == "exploit":
        required = prefix + common + [
            "shell_read_argument",
            "shell_exec_command",
            "environment_execute_command",
            "local_run_bash_command",
            "popen_sink_argument",
            "sink_intercepted",
        ]
        gate = next((row for row in relevant if row["stage"] == "gate_return"), None)
        if (
            stages == prefix + common
            and gate is not None
            and gate["details"].get("return_value") is True
            and not any(
                row["stage"] in {"popen_sink_argument", "sink_intercepted"}
                for row in relevant
            )
        ):
            return False, "healthy-negative: exploit was blocked at the proven device gate"
        if stages != required:
            return False, f"ordered exploit stages differ: observed={stages}, required={required}"
        if gate is None or gate["details"].get("return_value") is not False:
            return False, "exploit gate did not return false"
        sink = next((row for row in relevant if row["stage"] == "sink_intercepted"), None)
        if sink is None or sink["details"].get("process_created") is not False:
            return False, "matching sink was not intercepted before process creation"
    else:
        required = prefix + common
        gate = next((row for row in relevant if row["stage"] == "gate_return"), None)
        if stages != required:
            return False, f"ordered control stages differ: observed={stages}, required={required}"
        if gate is None or gate["details"].get("return_value") is not True:
            return False, "control gate did not return true"
        if any(row["stage"] in {"popen_sink_argument", "sink_intercepted"} for row in relevant):
            return False, "control reached the Popen sink"
    if tier == "mocked-provider-e2e" and not provider_schema_advertised:
        return False, "Hermes did not advertise the read_file tool schema"
    if tier == "mocked-provider-e2e":
        provider_request = next(
            (row for row in relevant if row["stage"] == "provider_request"), None
        )
        if provider_request is None or not provider_request["details"].get(
            "prompt_contains_value"
        ):
            return False, "mock provider request did not contain the prompt value"
    relations = {row["stage"]: row["relation"] for row in case["stages"]}
    for row in relevant:
        if row["stage"] == "instrumentation_ready":
            continue
        if row.get("relation") != relations[row["stage"]]:
            return False, f"relation mismatch at {row['stage']}"
    shell_quote = shlex.quote(expected_value)
    for row in relevant:
        if row["stage"] in {
            "shell_exec_command",
            "environment_execute_command",
            "local_run_bash_command",
        } and shell_quote not in row["details"].get("command", ""):
            return False, f"shell-quoted value missing at {row['stage']}"
        if (
            row["stage"] == "popen_sink_argument"
            and shell_quote not in row["details"].get("payload", "")
        ):
            return False, "shell-quoted value missing from Popen arguments"
    return True, "exact prompt-to-sink value propagation satisfied"


def _run_native_role(
    case: Mapping[str, Any],
    case_path: Path,
    *,
    campaign_id: str,
    role: str,
    attempt: int,
    attempt_dir: Path,
    timeout: int,
) -> dict[str, Any]:
    attempt_dir.mkdir(parents=True, exist_ok=False)
    event_path = attempt_dir / "events.jsonl"
    correlation_id = f"{case['case_id']}:native:{attempt}:{role}"
    with tempfile.TemporaryDirectory(prefix="clawgap-propagation-native-") as temporary:
        workspace = Path(temporary)
        (workspace / "home").mkdir()
        (workspace / "tmp").mkdir()
        environment = _target_environment(
            case_path,
            event_path,
            case=case,
            campaign_id=campaign_id,
            role=role,
            tier="native-replay",
            attempt=attempt,
            correlation_id=correlation_id,
            workspace=workspace,
            sandboxed_paths=True,
        )
        command = _sandbox_target_command(
            workspace=workspace,
            attempt_dir=attempt_dir,
            case_path=case_path,
            command=[
                sys.executable,
                "-m",
                "src.runtime_validation.propagation_worker",
                "--case",
                "/case.json",
                "--role",
                role,
                "--result",
                "/artifacts/worker-result.json",
            ],
        )
        process = subprocess.Popen(
            command,
            cwd="/",
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        process_status = "completed"
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process_status = "timeout"
            _terminate_group(process)
            stdout, stderr = process.communicate()
    atomic_write_text(attempt_dir / "stdout.log", stdout)
    atomic_write_text(attempt_dir / "stderr.log", stderr)
    rows = _events(event_path)
    passed, reason = _evaluate_role(
        case,
        campaign_id=campaign_id,
        role=role,
        tier="native-replay",
        attempt=attempt,
        correlation_id=correlation_id,
        events=rows,
    )
    result = {
        "tier": "native-replay",
        "attempt": attempt,
        "role": role,
        "correlation_id": correlation_id,
        "process_status": process_status,
        "returncode": process.returncode,
        "passed": passed,
        "healthy_negative": reason.startswith("healthy-negative:"),
        "reason": reason,
        "events": len(rows),
    }
    atomic_write_json(attempt_dir / "result.json", result)
    return result


def _run_e2e_role(
    case: Mapping[str, Any],
    case_path: Path,
    *,
    campaign_id: str,
    role: str,
    attempt: int,
    attempt_dir: Path,
    timeout: int,
) -> dict[str, Any]:
    attempt_dir.mkdir(parents=True, exist_ok=False)
    event_path = attempt_dir / "events.jsonl"
    transcript_path = attempt_dir / "provider-transcript.jsonl"
    correlation_id = f"{case['case_id']}:e2e:{attempt}:{role}"
    context = _ProviderContext(
        case=case,
        campaign_id=campaign_id,
        role=role,
        attempt=attempt,
        correlation_id=correlation_id,
        event_path=event_path,
        transcript_path=transcript_path,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockProviderHandler)
    server.context = context  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process: subprocess.Popen[str] | None = None
    process_status = "setup-error"
    stdout = ""
    stderr = ""
    try:
        with tempfile.TemporaryDirectory(prefix="clawgap-propagation-e2e-") as temporary:
            workspace = Path(temporary)
            hermes_home = workspace / "home"
            temp_root = workspace / "tmp"
            hermes_home.mkdir()
            temp_root.mkdir()
            config = {
                "model": {"default": "propagation-fake-model", "provider": "clawgap-propagation"},
                "providers": {
                    "clawgap-propagation": {
                        "name": "ClawGap Propagation Provider",
                        "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                        "default_model": "propagation-fake-model",
                        "model": "propagation-fake-model",
                        "key_env": "PROPAGATION_FAKE_API_KEY",
                        "api_mode": "chat_completions",
                    }
                },
            }
            atomic_write_text(hermes_home / "config.yaml", json.dumps(config, indent=2) + "\n")
            atomic_write_text(hermes_home / ".env", "")
            environment = _target_environment(
                case_path,
                event_path,
                case=case,
                campaign_id=campaign_id,
                role=role,
                tier="mocked-provider-e2e",
                attempt=attempt,
                correlation_id=correlation_id,
                workspace=workspace,
                sandboxed_paths=True,
            )
            environment.update(
                {
                    "HERMES_HOME": "/workspace/home",
                    "HERMES_INFERENCE_MODEL": "propagation-fake-model",
                    "HERMES_INFERENCE_PROVIDER": "clawgap-propagation",
                    "HERMES_MAX_ITERATIONS": "4",
                    "PROPAGATION_FAKE_API_KEY": "runtime-fake-key",
                    "NO_PROXY": "127.0.0.1,localhost,::1",
                    "no_proxy": "127.0.0.1,localhost,::1",
                }
            )
            launcher = "/repo/benchmark/python/hermes-agent/hermes"
            command = _sandbox_target_command(
                workspace=workspace,
                attempt_dir=attempt_dir,
                case_path=case_path,
                command=[
                    sys.executable,
                    launcher,
                    "--ignore-rules",
                    "--accept-hooks",
                    "--yolo",
                    "--model",
                    "propagation-fake-model",
                    "--provider",
                    "clawgap-propagation",
                    "--toolsets",
                    "file",
                    "-z",
                    case["prompts"][role],
                ],
            )
            process = subprocess.Popen(
                command,
                cwd="/",
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            started = time.monotonic()
            while True:
                try:
                    stdout, stderr = process.communicate(timeout=0.1)
                    process_status = "completed" if process.returncode == 0 else "error"
                    break
                except subprocess.TimeoutExpired:
                    rows = _events(event_path) if event_path.is_file() else []
                    if role == "exploit" and any(row["stage"] == "sink_intercepted" for row in rows):
                        process_status = "terminated-after-sink"
                        _terminate_group(process)
                        stdout, stderr = process.communicate()
                        break
                    if time.monotonic() - started >= timeout:
                        process_status = "timeout"
                        _terminate_group(process)
                        stdout, stderr = process.communicate()
                        break
    finally:
        if process is not None:
            _terminate_group(process)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    atomic_write_text(attempt_dir / "stdout.log", stdout)
    atomic_write_text(attempt_dir / "stderr.log", stderr)
    rows = _events(event_path)
    passed, reason = _evaluate_role(
        case,
        campaign_id=campaign_id,
        role=role,
        tier="mocked-provider-e2e",
        attempt=attempt,
        correlation_id=correlation_id,
        events=rows,
        provider_schema_advertised=context.schema_advertised,
    )
    result = {
        "tier": "mocked-provider-e2e",
        "attempt": attempt,
        "role": role,
        "correlation_id": correlation_id,
        "process_status": process_status,
        "returncode": None if process is None else process.returncode,
        "provider_calls": context.calls,
        "read_file_schema_advertised": context.schema_advertised,
        "passed": passed,
        "healthy_negative": reason.startswith("healthy-negative:"),
        "reason": reason,
        "events": len(rows),
    }
    atomic_write_json(attempt_dir / "result.json", result)
    return result


def _run_sandbox_canaries(
    *,
    case: Mapping[str, Any],
    case_path: Path,
    campaign_id: str,
    out: Path,
) -> dict[str, Any]:
    canary_dir = out / "sandbox-canary"
    if canary_dir.exists():
        shutil.rmtree(canary_dir)
    canary_dir.mkdir(parents=True)
    event_path = canary_dir / "events.jsonl"
    correlation_id = f"{case['case_id']}:sandbox-canary"
    with tempfile.TemporaryDirectory(prefix="clawgap-propagation-canary-") as temporary:
        workspace = Path(temporary)
        (workspace / "home").mkdir()
        (workspace / "tmp").mkdir()
        environment = _target_environment(
            case_path,
            event_path,
            case=case,
            campaign_id=campaign_id,
            role="exploit",
            tier="sandbox-canary",
            attempt=0,
            correlation_id=correlation_id,
            workspace=workspace,
            sandboxed_paths=True,
        )
        script = "\n".join(
            [
                "import json, os, socket",
                "from pathlib import Path",
                "result = {}",
                "try:",
                "    Path('/repo/.clawgap-write-canary').write_text('blocked')",
                "    result['read_only_source_write_blocked'] = False",
                "except OSError:",
                "    result['read_only_source_write_blocked'] = True",
                "sock = socket.socket()",
                "try:",
                "    sock.connect(('198.51.100.1', 9))",
                "    result['external_network_blocked'] = False",
                "except OSError as exc:",
                "    result['external_network_blocked'] = 'denies non-loopback network' in str(exc)",
                "finally:",
                "    sock.close()",
                "markers = ('API_KEY', 'AUTH_TOKEN', 'PASSWORD', 'CREDENTIAL', 'SECRET')",
                "result['inherited_credential_variables'] = sorted(key for key in os.environ if any(marker in key.upper() for marker in markers))",
                "Path('/artifacts/result.json').write_text(json.dumps(result, sort_keys=True) + '\\n')",
            ]
        )
        command = _sandbox_target_command(
            workspace=workspace,
            attempt_dir=canary_dir,
            case_path=case_path,
            command=[sys.executable, "-c", script],
        )
        completed = subprocess.run(
            command,
            cwd="/",
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    atomic_write_text(canary_dir / "stdout.log", completed.stdout)
    atomic_write_text(canary_dir / "stderr.log", completed.stderr)
    result_path = canary_dir / "result.json"
    if completed.returncode != 0 or not result_path.is_file():
        raise ValidationError(
            f"sandbox canary failed with exit {completed.returncode}: {completed.stderr[-1000:]}"
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if not result.get("read_only_source_write_blocked"):
        raise ValidationError("sandbox canary could write to the benchmark source mount")
    if not result.get("external_network_blocked"):
        raise ValidationError("sandbox canary did not block external target network")
    if result.get("inherited_credential_variables"):
        raise ValidationError("sandbox target inherited credential-bearing variables")
    return result


def _summary(result: Mapping[str, Any], command: str) -> str:
    claim = (
        "Validated claim: the exact `/dev/./zero` value propagated from the prompt and forced provider tool call through the real Hermes dispatcher and source stages into the intercepted `subprocess.Popen` arguments."
        if result["disposition"] == "prompt-to-sink-confirmed"
        else "The prompt-to-sink propagation claim was not confirmed; inspect the paired traces and tier outcomes."
    )
    return "\n".join(
        [
            "# Hermes Prompt-to-Sink Propagation Smoke Test",
            "",
            f"> Complete reproduction command: `{command}`",
            "",
            f"Disposition: **{result['disposition']}**.",
            "",
            f"Native replay: **{result['native_outcome']}**; mocked-provider E2E: **{result['e2e_outcome']}**.",
            "",
            claim,
            "",
            "No matching sink child process or denial-of-service effect was executed. Live-model tool selection and jailbreak success were not tested.",
            "",
        ]
    )


def run_production_like_smoke(
    request: ProductionLikeSmokeRequest,
    *,
    designer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    reviewer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> ProductionLikeSmokeRun:
    out = request.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    case = build_propagation_case(request)
    reusable_plan = out / "lab-plan.json"
    reusable_review = out / "lab-review.json"
    reusable = False
    if (
        designer is None
        and reviewer is None
        and reusable_plan.is_file()
        and reusable_review.is_file()
    ):
        try:
            plan = _validate_json_schema(
                json.loads(reusable_plan.read_text(encoding="utf-8")),
                LAB_PLAN_SCHEMA,
                "reused lab plan",
            )
            reviewed = _validate_json_schema(
                json.loads(reusable_review.read_text(encoding="utf-8")),
                LAB_REVIEW_SCHEMA,
                "reused lab review",
            )
            plan_sha = digest(plan)
            case_sha = digest(
                {key: value for key, value in case.items() if key != "review"}
            )
            reusable = (
                plan["revision"] == case["revision"]
                and plan["instrumentation_stages"]
                == [row["stage"] for row in case["stages"]]
                and reviewed["verdict"] == "approve"
                and all(reviewed["checks"].values())
                and reviewed["plan_sha256"] == plan_sha
                and reviewed["case_sha256"] == case_sha
            )
        except (ValidationError, json.JSONDecodeError, OSError):
            reusable = False
    if reusable:
        review = {
            "status": "approved",
            "plan_sha256": reviewed["plan_sha256"],
            "case_sha256": reviewed["case_sha256"],
            "reason": reviewed["reason"],
        }
    else:
        plan, review = design_and_review_lab(
            request, case, out, designer=designer, reviewer=reviewer
        )
    case = dict(case)
    case["review"] = review
    case = validate_propagation_case(case)
    case_path = out / "case.json"
    atomic_write_json(case_path, case)
    atomic_write_json(
        out / "instrumentation-manifest.json",
        {
            "schema_version": "clawgap-prompt-to-sink-instrumentation/v1",
            "mode": "sys.settrace-plus-Popen-interceptor",
            "source_bindings": case["source_bindings"],
            "overlay_bindings": _overlay_bindings(),
            "stages": case["stages"],
            "source_maps": [
                {
                    "stage": row["stage"],
                    "file": row["file"],
                    "function": row["function"],
                    "line": row["line"],
                }
                for row in case["stages"]
                if row["file"] is not None
            ],
            "benchmark_mount": "read-only",
            "benchmark_files_modified": False,
        },
    )
    campaign_id = "RVGTP-CAMP-" + digest(
        {"case_id": case["case_id"], "plan_sha256": review["plan_sha256"]}
    )[:16]
    sandbox_canaries = _run_sandbox_canaries(
        case=case,
        case_path=case_path,
        campaign_id=campaign_id,
        out=out,
    )
    atomic_write_json(
        out / "sandbox-canaries.json",
        {
            "schema_version": "clawgap-sandbox-canaries/v1",
            "campaign_id": campaign_id,
            "case_id": case["case_id"],
            **sandbox_canaries,
        },
    )
    attempts_root = out / "attempts"
    if attempts_root.exists():
        shutil.rmtree(attempts_root)
    native_rows = []
    e2e_rows = []
    for attempt in range(1, request.attempts + 1):
        for role in ("exploit", "control"):
            native_rows.append(
                _run_native_role(
                    case,
                    case_path,
                    campaign_id=campaign_id,
                    role=role,
                    attempt=attempt,
                    attempt_dir=out / "attempts" / "native" / f"attempt-{attempt:03d}" / role,
                    timeout=request.timeout_seconds,
                )
            )
            e2e_rows.append(
                _run_e2e_role(
                    case,
                    case_path,
                    campaign_id=campaign_id,
                    role=role,
                    attempt=attempt,
                    attempt_dir=out / "attempts" / "e2e" / f"attempt-{attempt:03d}" / role,
                    timeout=request.timeout_seconds,
                )
            )
    def tier_outcome(rows: list[Mapping[str, Any]]) -> str:
        if len(rows) != request.attempts * 2:
            return "inconclusive"
        exploits = [row for row in rows if row["role"] == "exploit"]
        controls = [row for row in rows if row["role"] == "control"]
        if len(exploits) != request.attempts or len(controls) != request.attempts:
            return "inconclusive"
        if all(row["passed"] for row in exploits + controls):
            return "confirmed"
        if all(row["healthy_negative"] for row in exploits) and all(
            row["passed"] for row in controls
        ):
            return "not-reproduced"
        return "inconclusive"

    native_outcome = tier_outcome(native_rows)
    e2e_outcome = tier_outcome(e2e_rows)
    if native_outcome == e2e_outcome == "confirmed":
        disposition = "prompt-to-sink-confirmed"
    elif native_outcome == e2e_outcome == "not-reproduced":
        disposition = "not-reproduced"
    else:
        disposition = "inconclusive"
    transcript_bindings = [
        _provider_transcript_binding(
            out=out,
            path=(
                out
                / "attempts"
                / "e2e"
                / f"attempt-{attempt:03d}"
                / role
                / "provider-transcript.jsonl"
            ),
            case=case,
            role=role,
            attempt=attempt,
        )
        for attempt in range(1, request.attempts + 1)
        for role in ("exploit", "control")
    ]
    if any(row["status"] != "bound" for row in transcript_bindings):
        e2e_outcome = "inconclusive"
        disposition = "inconclusive"
    atomic_write_json(
        out / "provider-transcript-bindings.json",
        {
            "schema_version": "clawgap-provider-transcript-bindings/v1",
            "case_id": case["case_id"],
            "campaign_id": campaign_id,
            "bindings": transcript_bindings,
        },
    )
    source_root = get_project("hermes-agent").source_root
    for binding in case["source_bindings"]:
        if sha256_file(source_root / binding["path"]) != binding["sha256"]:
            raise ValidationError(
                f"benchmark source changed during smoke: {binding['path']}"
            )
    command = (
        "python -m src.runtime_validation run-production-like-smoke "
        f"--out-dir {request.out_dir} --claude-model {request.claude_model} "
        f"--claude-base-url {request.claude_base_url} "
        f"--claude-credential-env {request.claude_credential_env} "
        f"--attempts {request.attempts} --timeout {request.timeout_seconds}"
    )
    result = {
        "schema_version": PROPAGATION_RESULT_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "case_id": case["case_id"],
        "report_id": REPORT_ID,
        "disposition": disposition,
        "native_outcome": native_outcome,
        "e2e_outcome": e2e_outcome,
        "effect_execution": "not-tested",
        "live_prompt_triggerability": "not-tested",
        "attempts_per_tier": request.attempts,
        "lab_plan_sha256": review["plan_sha256"],
        "lab_review_sha256": sha256_file(out / "lab-review.json"),
        "instrumentation_manifest_sha256": sha256_file(
            out / "instrumentation-manifest.json"
        ),
        "provider_transcript_bindings_sha256": sha256_file(
            out / "provider-transcript-bindings.json"
        ),
        "claude_plan": plan,
    }
    atomic_write_json(out / "result.json", result)
    atomic_write_text(out / "summary.md", _summary(result, command))
    atomic_write_json(
        out / "safety-canaries.json",
        {
            "schema_version": "clawgap-production-like-smoke-canaries/v1",
            "external_target_network": not sandbox_canaries[
                "external_network_blocked"
            ],
            "provider_loopback_only": True,
            "benchmark_mounted_read_only": sandbox_canaries[
                "read_only_source_write_blocked"
            ],
            "target_environment_inherited_credentials": bool(
                sandbox_canaries["inherited_credential_variables"]
            ),
            "host_filesystem_escape_observed": False,
            "target_process_groups_terminated": all(
                row.get("returncode") is not None for row in native_rows + e2e_rows
            ),
            "bound_source_modified": False,
            "matching_sink_child_process_created": False,
            "denial_of_service_executed": False,
            "live_prompt_selection_tested": False,
        },
    )
    manifest = {
        "schema_version": "clawgap-production-like-smoke-manifest/v1",
        "campaign_id": campaign_id,
        "case_id": case["case_id"],
        "generation_command": command,
        "disposition": disposition,
        "runtime": {
            "python": platform.python_version(),
            "claude_code": case["orchestrator"]["version"],
            "claude_model": request.claude_model,
        },
        "artifact_sha256": _artifact_hashes(out),
    }
    atomic_write_json(out / "manifest.json", manifest)
    credential = os.getenv(request.claude_credential_env, "").strip()
    _credential_scan(out, (credential,) if credential else ())
    return ProductionLikeSmokeRun(
        campaign_id,
        case["case_id"],
        disposition,
        native_outcome,
        e2e_outcome,
        out,
    )
