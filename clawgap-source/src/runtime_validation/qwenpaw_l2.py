"""Targeted forced-provider L2 runtime for the linked QwenPaw candidate."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project

from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    contains_credentials,
    redact_text,
    sha256_file,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("QwenPaw")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
TARGET_CANDIDATES = ("CAND-f7360b9369fcf464",)
CAMPAIGN_ID = "runtime-dynamic-trigger-qwenpaw-l2-v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-qwenpaw-l2-result/v1"
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-qwenpaw-l2-event/v1"
MODEL_NAME = "clawgap-qwenpaw-l2"
PROVIDER_CREDENTIAL = "clawgap-loopback-mock"
MEMBER_USERNAME = "clawgap-member"
ENV_MARKER_KEY = "CLAWGAP_QWENPAW_INHERITED_ENV"
ENV_MARKER_VALUE = "clawgap-inherited-environment"
CANARY_CONTENT = "clawgap-qwenpaw-host-canary\n"
IDENTITY_FIELDS = (
    "candidate_id",
    "case_id",
    "attempt",
    "role",
    "correlation_id",
    "fixture_id",
)
NORMALIZED_STAGES = (
    "case_bound",
    "source_verified",
    "fixture_prepared",
    "launch_started",
    "prompt_received",
    "provider_request",
    "provider_tool_call_or_decision",
    "registry_or_native_dispatch",
    "handler_entered",
    "controlled_argument_recorded",
    "gate_observed",
    "missing_check_boundary_confirmed",
    "sink_reached",
    "pre_effect_interception",
    "target_completed",
    "cleanup_verified",
)
NEIGHBORING_RULE_IDS = (
    "TOOL_CMD_PROC_ENVIRON",
    "TOOL_CMD_JQ_SYSTEM",
    "TOOL_CMD_JQ_FILE_FLAGS",
)
CITED_SOURCE_HASHES = {
    "pyproject.toml": (
        "7967fda553a86648e554bc228936421d8cb8d5eb35211370764752e9eea8834c"
    ),
    "src/qwenpaw/cli/main.py": (
        "cd68eb6ab4a5498836a5a47e450047e55d524b69dd5aa311fc718e45f51ac30d"
    ),
    "src/qwenpaw/app/routers/console.py": (
        "da86231125cd4827c3e2dce5f309a6524e737a1e95fdd508f4106b9571be6e80"
    ),
    "src/qwenpaw/agents/tool_guard_mixin.py": (
        "6ba93742d3f8dee81c9cdd23095da21f3c3013e870dd706226b1368e0c2df731"
    ),
    "src/qwenpaw/security/tool_guard/rules/dangerous_shell_commands.yaml": (
        "138904e36b497e300ab93722db569f454c55a02ae1d08726034603695b4624f8"
    ),
    "src/qwenpaw/agents/tools/shell.py": (
        "c623869934cd291ef320e93ace6a6f1c66bfff911f7b6d319c404282b2ca62b6"
    ),
}


@dataclass(frozen=True)
class QwenPawL2RunRequest:
    campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    out_dir: Path = ...
    attempts: int = 3
    timeout: int = 180
    build_timeout: int = 1800
    candidate_id: str | None = None
    build_dir: Path | None = None


@dataclass
class PairOutcome:
    healthy: bool
    triggered: bool
    errors: list[str]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValidationError(
            f"cannot read QwenPaw L2 artifact {path}: {exc}"
        ) from exc
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists():
        shutil.rmtree(path)


def _select_cases(
    campaign: Path,
    candidate_id: str | None = None,
) -> list[dict[str, Any]]:
    cases = _read_jsonl(campaign / "cases.jsonl")
    selected = {
        str(row.get("candidate_binding", {}).get("candidate_id")): row
        for row in cases
        if row.get("project") == "QwenPaw"
    }
    expected = set(TARGET_CANDIDATES)
    if not expected.issubset(selected):
        missing = sorted(expected - set(selected))
        raise ValidationError(
            "QwenPaw targeted L2 source campaign is missing GT-linked "
            "candidates: " + ", ".join(missing)
        )
    if candidate_id is None:
        return [selected[item] for item in TARGET_CANDIDATES]
    if candidate_id not in expected:
        raise ValidationError(
            "requested QwenPaw candidate is not the GT-linked targeted L2 candidate"
        )
    return [selected[candidate_id]]


def _candidate_id(case: Mapping[str, Any]) -> str:
    return str(case["candidate_binding"]["candidate_id"])


def _tool_name(case: Mapping[str, Any]) -> str:
    return str(case["handler"]["tool_name"])


def _role_arguments(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    row = next(row for row in case["forced_tool_calls"] if row["role"] == role)
    return dict(row["arguments"])


def _sink_anchor(case: Mapping[str, Any]) -> str:
    return str(case["observations"][-1]["source_anchor"])


def _expected_gate_ids(case: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(str(row.get("id")) for row in case.get("gates", []))


def _expected_stages(case: Mapping[str, Any]) -> tuple[str, ...]:
    return NORMALIZED_STAGES


def _source_bindings(cases: list[Mapping[str, Any]]) -> dict[str, str]:
    required_files = {
        "pyproject.toml",
        "src/qwenpaw/cli/main.py",
        "src/qwenpaw/app/_app.py",
        "src/qwenpaw/app/routers/console.py",
        "src/qwenpaw/providers/openai_provider.py",
        "src/qwenpaw/agents/react_agent.py",
        "src/qwenpaw/agents/tool_guard_mixin.py",
        "src/qwenpaw/security/tool_guard/engine.py",
        "src/qwenpaw/security/tool_guard/rules/dangerous_shell_commands.yaml",
        "src/qwenpaw/agents/tools/shell.py",
        "src/runtime_validation/environment_fixtures/python/mcp_streamablehttp_client.py",
    }
    for case in cases:
        if case.get("revision") != PROJECT.analysis_revision:
            raise ValidationError("QwenPaw case revision does not match registry")
    bindings: dict[str, str] = {}
    for relative in sorted(required_files):
        source = (
            REPO_ROOT / relative
            if relative.startswith("src/runtime_validation/")
            else SOURCE_ROOT / relative
        )
        if not source.is_file():
            raise ValidationError(f"QwenPaw bound source is missing: {relative}")
        digest_value = sha256_file(source)
        expected = CITED_SOURCE_HASHES.get(relative)
        if expected is not None and digest_value != expected:
            raise ValidationError(
                f"QwenPaw cited source hash drift: {relative}: {digest_value}"
            )
        bindings[relative] = digest_value
    _validate_missing_jq_environment_rule(
        SOURCE_ROOT
        / "src/qwenpaw/security/tool_guard/rules/dangerous_shell_commands.yaml"
    )
    return bindings


def _validate_missing_jq_environment_rule(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    for rule_id in NEIGHBORING_RULE_IDS:
        if source.count(f"- id: {rule_id}") != 1:
            raise ValidationError(
                f"QwenPaw neighboring command rule is not uniquely bound: {rule_id}"
            )
    if "TOOL_CMD_JQ_ENV" in source or "jq $ENV" in source:
        raise ValidationError(
            "QwenPaw source now appears to contain the reviewed jq environment rule"
        )


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(
            f"QwenPaw instrumentation marker mismatch ({label}): {count}"
        )
    return source.replace(old, new, 1)


def _instrumentation_helper() -> str:
    return r'''import asyncio
import json
import os
import shutil
import time


_original_create_subprocess_shell = asyncio.create_subprocess_shell
_state = {
    "tool": None,
    "command": None,
    "sink_emitted": False,
}


def _event(stage, detail):
    path = os.environ.get("CLAWGAP_L2_EVENT_PATH")
    if not path:
        return
    row = {
        "schema_version": "clawgap-dynamic-trigger-qwenpaw-l2-event/v1",
        "stage": stage,
        "candidate_id": os.environ.get("CLAWGAP_L2_CANDIDATE_ID"),
        "case_id": os.environ.get("CLAWGAP_L2_CASE_ID"),
        "attempt": int(os.environ.get("CLAWGAP_L2_ATTEMPT", "0")),
        "role": os.environ.get("CLAWGAP_L2_ROLE"),
        "correlation_id": os.environ.get("CLAWGAP_L2_CORRELATION_ID"),
        "fixture_id": os.environ.get("CLAWGAP_L2_FIXTURE_ID"),
        "detail": detail,
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(row, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)


def _complete():
    marker = os.environ.get("CLAWGAP_L2_COMPLETE_PATH")
    if marker:
        with open(marker, "w", encoding="utf-8") as stream:
            stream.write(str(time.time()))


def clawgap_native_dispatch(tool_call):
    _event(
        "registry_or_native_dispatch",
        {
            "tool_name": tool_call.get("name"),
            "arguments": tool_call.get("input", {}),
            "runtime": "ToolGuardMixin._acting",
        },
    )


def clawgap_repair_tool_call(tool_call):
    """Apply QwenPaw's documented raw-input repair before guard execution."""
    if not isinstance(tool_call, dict):
        return
    tool_input = tool_call.get("input")
    raw_input = tool_call.get("raw_input")
    if tool_input or not isinstance(raw_input, str) or raw_input == "{}":
        return
    try:
        parsed = json.loads(raw_input)
    except (json.JSONDecodeError, TypeError):
        return
    if isinstance(parsed, dict) and parsed:
        tool_call["input"] = parsed


def clawgap_handler(arguments):
    _state.update(
        {
            "tool": "execute_shell_command",
            "command": arguments.get("command"),
            "sink_emitted": False,
        }
    )
    _event("handler_entered", {"arguments": arguments})


def clawgap_controlled(argument_path, value, normalized=None):
    _state["command"] = value
    _event(
        "controlled_argument_recorded",
        {"argument_path": argument_path, "value": value, "normalized": normalized},
    )
    _event(
        "missing_check_boundary_confirmed",
        {
            "missing_check": True,
            "policy": "jq-environment-object-classification",
            "value": value,
        },
    )


def clawgap_gate(tool_name, params, result):
    findings = [finding.to_dict() for finding in (result.findings if result else [])]
    rule_ids = [str(row.get("rule_id")) for row in findings]
    _event(
        "gate_observed",
        {
            "gate_ids": [],
            "name": "ToolGuardEngine aggregation",
            "tool_name": tool_name,
            "findings": findings,
            "rule_ids": rule_ids,
            "admitted": not findings,
            "guardians_used": list(result.guardians_used) if result else [],
        },
    )


class _FakeProcess:
    returncode = 0
    pid = 424242

    async def communicate(self):
        return b"clawgap intercepted jq before execution\n", b""

    async def wait(self):
        return 0

    def kill(self):
        return None

    def terminate(self):
        return None


async def _intercept_create_subprocess_shell(command, *args, **kwargs):
    if _state.get("tool") != "execute_shell_command" or command != _state.get("command"):
        return await _original_create_subprocess_shell(command, *args, **kwargs)
    if _state["sink_emitted"]:
        return _FakeProcess()
    _state["sink_emitted"] = True
    env = kwargs.get("env") or {}
    path = env.get("PATH", "")
    jq_path = shutil.which("jq", path=path) if path else None
    marker = os.environ.get("CLAWGAP_QWENPAW_INHERITED_ENV")
    detail = {
        "command": command,
        "cwd": kwargs.get("cwd"),
        "marker_key_present": ENV_MARKER_KEY in env if hasattr(env, "__contains__") else False,
        "marker_value": "[redacted]" if ENV_MARKER_KEY in env else None,
        "resolved_jq": jq_path,
        "fake_jq_executed": False,
        "fake_jq_invocation_marker_present": os.path.exists(
            "/tmp/.clawgap-jq-invoked"
        ),
        "sink_anchor": "src/qwenpaw/agents/tools/shell.py:447",
    }
    _event("sink_reached", detail)
    _event("pre_effect_interception", {**detail, "executed": False})
    _event("target_completed", {"sink_anchor": detail["sink_anchor"]})
    _complete()
    return _FakeProcess()


ENV_MARKER_KEY = "CLAWGAP_QWENPAW_INHERITED_ENV"
asyncio.create_subprocess_shell = _intercept_create_subprocess_shell
'''


def _instrument_project(project: Path) -> dict[str, str]:
    helper_path = project / "src/clawgap_l2_runtime.py"
    atomic_write_text(helper_path, _instrumentation_helper())

    main_path = project / "src/qwenpaw/cli/main.py"
    main_source = main_path.read_text(encoding="utf-8")
    main_source = _replace_once(
        main_source,
        "from __future__ import annotations\n",
        "from __future__ import annotations\n\nimport clawgap_l2_runtime\n",
        "CLI runtime bootstrap",
    )
    main_path.write_text(main_source, encoding="utf-8")

    guard_path = project / "src/qwenpaw/agents/tool_guard_mixin.py"
    guard_source = guard_path.read_text(encoding="utf-8")
    guard_source = _replace_once(
        guard_source,
        "from __future__ import annotations\n",
        "from __future__ import annotations\n\nfrom clawgap_l2_runtime import (\n    clawgap_native_dispatch,\n    clawgap_repair_tool_call,\n)\n",
        "ToolGuard native import",
    )
    guard_source = _replace_once(
        guard_source,
        '        ctx = getattr(self, "_request_context", None) or {}\n',
        '        clawgap_repair_tool_call(tool_call)\n        clawgap_native_dispatch(tool_call)\n        ctx = getattr(self, "_request_context", None) or {}\n',
        "ToolGuard native dispatch",
    )
    guard_path.write_text(guard_source, encoding="utf-8")

    engine_path = project / "src/qwenpaw/security/tool_guard/engine.py"
    engine_source = engine_path.read_text(encoding="utf-8")
    engine_source = _replace_once(
        engine_source,
        "from __future__ import annotations\n",
        "from __future__ import annotations\n\nfrom clawgap_l2_runtime import clawgap_gate\n",
        "ToolGuardEngine import",
    )
    engine_source = _replace_once(
        engine_source,
        '        result.guard_duration_seconds = time.monotonic() - t0\n        return result\n',
        '        result.guard_duration_seconds = time.monotonic() - t0\n        clawgap_gate(tool_name, params, result)\n        return result\n',
        "ToolGuardEngine aggregation",
    )
    engine_path.write_text(engine_source, encoding="utf-8")

    shell_path = project / "src/qwenpaw/agents/tools/shell.py"
    shell_source = shell_path.read_text(encoding="utf-8")
    shell_source = (
        "from clawgap_l2_runtime import (\n"
        "    clawgap_controlled,\n"
        "    clawgap_handler,\n"
        ")\n" + shell_source
    )
    shell_source = _replace_once(
        shell_source,
        '    cmd = _collapse_embedded_newlines((command or "").strip())\n\n    if isinstance(timeout, str):\n',
        '    clawgap_handler({"command": command, "timeout": timeout, "cwd": cwd})\n    cmd = _collapse_embedded_newlines((command or "").strip())\n    clawgap_controlled(["command"], command, normalized=cmd)\n\n    if isinstance(timeout, str):\n',
        "execute_shell_command handler and controlled command",
    )
    shell_path.write_text(shell_source, encoding="utf-8")

    transformed_files = (
        "src/clawgap_l2_runtime.py",
        "src/qwenpaw/cli/main.py",
        "src/qwenpaw/agents/tool_guard_mixin.py",
        "src/qwenpaw/security/tool_guard/engine.py",
        "src/qwenpaw/agents/tools/shell.py",
    )
    return {
        relative: sha256_file(project / relative)
        for relative in transformed_files
    }


def _render_build_copy(
    destination: Path, source_bindings: Mapping[str, str]
) -> dict[str, Any]:
    project = destination / "project"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    shutil.copytree(
        SOURCE_ROOT,
        project,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            ".clawgap-venv",
            "node_modules",
        ),
    )
    transformed = _instrument_project(project)
    return {
        "schema_version": "clawgap-qwenpaw-transformed-source-manifest/v1",
        "revision": PROJECT.analysis_revision,
        "original": dict(source_bindings),
        "transformed": transformed,
        "runtime_adapter": (
            "source-bound dispatch, guard, handler, missing-boundary, and "
            "process-sink instrumentation in the disposable build copy"
        ),
    }


def _run(
    command: list[str],
    *,
    cwd: Path,
    log_path: Path,
    timeout: int,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=None if env is None else dict(env),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    atomic_write_text(log_path, redact_text(completed.stdout or ""))
    return completed


def _prepare_build(
    directory: Path,
    source_bindings: Mapping[str, str],
    timeout: int,
) -> dict[str, Any]:
    harness_path = REPO_ROOT / "src/runtime_validation/qwenpaw_l2.py"
    harness_sha256 = sha256_file(harness_path)
    dependency_sha256 = sha256_file(SOURCE_ROOT / "pyproject.toml")
    shim_source = (
        REPO_ROOT
        / "src/runtime_validation/environment_fixtures/python/mcp_streamablehttp_client.py"
    )
    shim_sha256 = sha256_file(shim_source)
    manifest_path = directory / "transformed-source-manifest.json"
    venv_python = directory / ".clawgap-venv/bin/python"
    if manifest_path.is_file() and venv_python.is_file():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version")
            == "clawgap-qwenpaw-transformed-source-manifest/v1"
            and prior.get("revision") == PROJECT.analysis_revision
            and prior.get("original") == dict(source_bindings)
            and prior.get("dependency_pyproject_sha256") == dependency_sha256
            and prior.get("dependency_shim_sha256") == shim_sha256
            and prior.get("harness_sha256") == harness_sha256
            and prior.get("interpreter_sha256") == sha256_file(venv_python)
        ):
            return prior

    manifest = _render_build_copy(directory, source_bindings)
    venv_dir = directory / ".clawgap-venv"
    if venv_dir.exists():
        shutil.rmtree(venv_dir)
    (directory / "build-home").mkdir(parents=True, exist_ok=True)
    base_python = Path(shutil.which("python") or sys.executable)
    bootstrap = _run(
        [str(base_python), "-m", "venv", "--system-site-packages", str(venv_dir)],
        cwd=directory,
        log_path=directory / "venv.log",
        timeout=min(timeout, 300),
    )
    if bootstrap.returncode != 0 or not venv_python.is_file():
        raise ValidationError(
            f"QwenPaw disposable Python environment failed: {bootstrap.returncode}"
        )
    uv_path = shutil.which("uv")
    if uv_path is None:
        raise ValidationError("QwenPaw targeted L2 requires uv")
    install = _run(
        [
            uv_path,
            "pip",
            "install",
            "--python",
            str(venv_python),
            "--no-deps",
            "-e",
            str(directory / "project"),
            "agentscope==1.0.20",
            "agentscope-runtime==1.1.6",
            "mcp==1.27.2",
            "segno==1.6.6",
            "reme-ai==0.3.1.8",
            "qdrant-client==1.16.0",
            "agent-client-protocol==0.9.0",
        ],
        cwd=directory,
        log_path=directory / "dependency-install.log",
        timeout=timeout,
        env={
            "PATH": f"{venv_dir / 'bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "HOME": str(directory / "build-home"),
            "UV_CACHE_DIR": str(directory / "uv-cache"),
            "NO_COLOR": "1",
        },
    )
    if install.returncode != 0:
        raise ValidationError(
            f"QwenPaw dependency installation failed: {install.returncode}"
        )
    site_packages = next(
        (venv_dir / "lib").glob("python*/site-packages"),
        None,
    )
    if site_packages is None:
        raise ValidationError("QwenPaw disposable site-packages directory is missing")
    shutil.copy2(shim_source, site_packages / "mcp/client/streamablehttp_client.py")
    probe = _run(
        [
            str(venv_python),
            "-c",
            "import mcp.client.streamablehttp_client; import qwenpaw.cli.main",
        ],
        cwd=directory / "project",
        log_path=directory / "import-probe.log",
        timeout=min(timeout, 180),
        env={
            "PYTHONPATH": str(directory / "project/src"),
            "HOME": str(directory / "build-home"),
            "PATH": f"{venv_dir / 'bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "NO_COLOR": "1",
        },
    )
    if probe.returncode != 0:
        raise ValidationError(
            f"QwenPaw transformed runtime import probe failed: {probe.returncode}"
        )
    manifest.update(
        {
            "dependency_pyproject_sha256": dependency_sha256,
            "dependency_shim_sha256": shim_sha256,
            "harness_sha256": harness_sha256,
            "interpreter_sha256": sha256_file(venv_python),
        }
    )
    atomic_write_json(manifest_path, manifest)
    return manifest


class QwenPawProviderServer:
    """Strict non-streaming OpenAI-compatible loopback provider."""

    def __init__(
        self,
        *,
        role: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        transcript_path: Path,
    ) -> None:
        self.role = role
        self.tool_name = tool_name
        self.arguments = dict(arguments)
        self.transcript_path = transcript_path
        self._lock = threading.Lock()
        self._chat_requests = 0
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def _record(self, row: dict[str, Any]) -> None:
        with self._lock:
            with self.transcript_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")

    def _json(self, handler: BaseHTTPRequestHandler, value: Mapping[str, Any]) -> None:
        payload = json.dumps(value, sort_keys=True).encode()
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)

    def _sse(
        self, handler: BaseHTTPRequestHandler, chunks: list[Mapping[str, Any]]
    ) -> None:
        payload = "".join(
            f"data: {json.dumps(chunk, sort_keys=True, ensure_ascii=False)}\n\n"
            for chunk in chunks
        )
        payload += "data: [DONE]\n\n"
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Cache-Control", "no-cache")
        handler.send_header("Content-Length", str(len(payload.encode())))
        handler.end_headers()
        handler.wfile.write(payload.encode())

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _route(self) -> None:
                from urllib.parse import urlsplit

                split = urlsplit(self.path)
                path = split.path
                authorization = self.headers.get("Authorization", "")
                if path == "/v1/models" and self.command == "GET":
                    if authorization != f"Bearer {PROVIDER_CREDENTIAL}":
                        self.send_error(401)
                        return
                    server._json(
                        self,
                        {
                            "object": "list",
                            "data": [
                                {
                                    "id": MODEL_NAME,
                                    "object": "model",
                                    "owned_by": "clawgap",
                                }
                            ],
                        },
                    )
                    return
                if path != "/v1/chat/completions" or self.command != "POST":
                    server._record(
                        {
                            "path": path,
                            "method": self.command,
                            "response_kind": "unsupported",
                            "authorization_valid": False,
                        }
                    )
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    body = json.loads(self.rfile.read(length))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body = {}
                tools = body.get("tools") or []
                tool_names = [
                    str(item.get("function", {}).get("name"))
                    for item in tools
                    if isinstance(item, dict)
                ]
                server._chat_requests += 1
                request_kind = (
                    "tool_call" if server._chat_requests == 1 else "continuation"
                )
                server._record(
                    {
                        "ordinal": server._chat_requests,
                        "path": path,
                        "method": self.command,
                        "authorization_redacted": "Bearer [redacted]",
                        "authorization_valid": authorization
                        == f"Bearer {PROVIDER_CREDENTIAL}",
                        "model": body.get("model"),
                        "stream": body.get("stream") is True,
                        "tool_names": tool_names,
                        "response_kind": request_kind,
                        "message_count": len(body.get("messages") or []),
                    }
                )
                if request_kind == "tool_call":
                    server._sse(
                        self,
                        [
                            {
                                "id": f"chatcmpl-clawgap-{server.role}",
                                "object": "chat.completion.chunk",
                                "created": 1,
                                "model": MODEL_NAME,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {
                                            "role": "assistant",
                                            "tool_calls": [
                                                {
                                                    "index": 0,
                                                    "id": f"call-clawgap-{server.role}",
                                                    "type": "function",
                                                    "function": {
                                                        "name": server.tool_name,
                                                        "arguments": "",
                                                    },
                                                }
                                            ],
                                        },
                                        "finish_reason": None,
                                    }
                                ],
                            },
                            {
                                "id": f"chatcmpl-clawgap-{server.role}",
                                "object": "chat.completion.chunk",
                                "created": 1,
                                "model": MODEL_NAME,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {
                                            "tool_calls": [
                                                {
                                                    "index": 0,
                                                    "function": {
                                                        "arguments": json.dumps(
                                                            server.arguments,
                                                            sort_keys=True,
                                                        )
                                                    },
                                                }
                                            ]
                                        },
                                        "finish_reason": None,
                                    }
                                ],
                            },
                            {
                                "id": f"chatcmpl-clawgap-{server.role}",
                                "object": "chat.completion.chunk",
                                "created": 1,
                                "model": MODEL_NAME,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {},
                                        "finish_reason": "tool_calls",
                                    }
                                ],
                            },
                        ],
                    )
                    return
                server._sse(
                    self,
                    [
                        {
                            "id": "chatcmpl-clawgap-final",
                            "object": "chat.completion.chunk",
                            "created": 1,
                            "model": MODEL_NAME,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"role": "assistant", "content": "done"},
                                    "finish_reason": None,
                                }
                            ],
                        },
                        {
                            "id": "chatcmpl-clawgap-final",
                            "object": "chat.completion.chunk",
                            "created": 1,
                            "model": MODEL_NAME,
                            "choices": [
                                {"index": 0, "delta": {}, "finish_reason": "stop"}
                            ],
                        },
                    ],
                )

            do_GET = _route
            do_POST = _route
            do_PUT = _route
            do_PATCH = _route
            do_DELETE = _route

        return Handler

    def start(self) -> None:
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        shutdown = threading.Thread(target=self._server.shutdown, daemon=True)
        shutdown.start()
        shutdown.join(timeout=3)
        self._server.server_close()


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _render_provider_config(
    secret_root: Path,
    *,
    provider_base_url: str,
) -> tuple[Path, Path]:
    custom_dir = secret_root / "providers/custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    provider_path = custom_dir / "clawgap.json"
    active_path = secret_root / "providers/active_model.json"
    atomic_write_json(
        provider_path,
        {
            "id": "clawgap",
            "name": "ClawGap Loopback Fixture",
            "base_url": provider_base_url,
            "api_key": PROVIDER_CREDENTIAL,
            "chat_model": "OpenAIChatModel",
            "extra_models": [
                {"id": MODEL_NAME, "name": "ClawGap QwenPaw L2"}
            ],
        },
    )
    atomic_write_json(
        active_path,
        {"provider_id": "clawgap", "model": MODEL_NAME},
    )
    return provider_path, active_path


def _prepare_role(
    directory: Path,
    build_project: Path,
    *,
    base_url: str,
) -> dict[str, Any]:
    runtime = directory / "runtime"
    runtime.mkdir(parents=True, exist_ok=False)
    for name in ("home", "tmp", "working", "secret"):
        (runtime / name).mkdir()
    role_project = runtime / "project"
    shutil.copytree(
        build_project,
        role_project,
        ignore=shutil.ignore_patterns(".clawgap-venv", "uv-cache", "build-home"),
    )
    provider_path, active_path = _render_provider_config(
        runtime / "secret",
        provider_base_url=base_url,
    )
    fake_bin = runtime / "fake-bin"
    fake_bin.mkdir()
    fake_jq = fake_bin / "jq"
    atomic_write_text(
        fake_jq,
        "#!/bin/sh\nprintf x > /tmp/.clawgap-jq-invoked\nexit 97\n",
    )
    fake_jq.chmod(0o755)
    return {
        "schema_version": "clawgap-qwenpaw-l2-fixture-manifest/v1",
        "runtime_root": str(runtime),
        "provider_config": str(provider_path),
        "active_model_config": str(active_path),
        "fake_jq": str(fake_jq),
        "fake_jq_sha256": sha256_file(fake_jq),
        "reviewed_cwd": "/tmp",
        "mount_namespace": True,
        "role_root": str(runtime),
    }


def _disable_auto_title(runtime: Path) -> None:
    agent_config = runtime / "working/workspaces/default/agent.json"
    deadline = time.monotonic() + 30
    while not agent_config.is_file() and time.monotonic() < deadline:
        time.sleep(0.1)
    if not agent_config.is_file():
        raise ValidationError("QwenPaw default agent config was not initialized")
    value = json.loads(agent_config.read_text(encoding="utf-8"))
    running = value.setdefault("running", {})
    running.setdefault("auto_title_config", {})["enabled"] = False
    agent_config.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _http_json(
    url: str,
    payload: Mapping[str, Any] | None = None,
    method: str = "GET",
    timeout: int = 30,
) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValidationError(f"QwenPaw app request failed: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError("QwenPaw app returned a non-object response")
    return value


def _http_text(
    url: str,
    payload: Mapping[str, Any],
    timeout: int,
) -> str:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ValidationError(f"QwenPaw console chat failed: {exc}") from exc


def _launch_and_prompt(
    *,
    runtime: Path,
    role_project: Path,
    build_python: Path,
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    fixture: Mapping[str, Any],
    environment: Mapping[str, str],
    app_port: int,
    timeout: int,
) -> tuple[int, str, str]:
    executable = build_python.parent / "qwenpaw"
    fake_jq = Path(str(fixture["fake_jq"]))
    mount_script = (
        "mount -t tmpfs tmpfs /tmp && "
        "mkdir -p /tmp/.clawgap-bin && "
        f"cp {shlex.quote(str(fake_jq))} /tmp/.clawgap-bin/jq && "
        "chmod 755 /tmp/.clawgap-bin/jq && "
        f"exec {shlex.quote(str(executable))} app "
        f"--host 127.0.0.1 --port {app_port}"
    )
    command = [
        "unshare",
        "--mount",
        "--propagation",
        "private",
        "/bin/sh",
        "-c",
        mount_script,
    ]
    launch_log_path = runtime.parent / "launch.log"
    output = ""
    chat = ""
    process_exit: int | None = None
    with launch_log_path.open("w", encoding="utf-8") as launch_log:
        process = subprocess.Popen(
            command,
            cwd=role_project,
            env=dict(environment),
            stdout=launch_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        base = f"http://127.0.0.1:{app_port}"
        try:
            deadline = time.monotonic() + min(timeout, 120)
            last_error: Exception | None = None
            while time.monotonic() < deadline:
                try:
                    version = _http_json(f"{base}/api/version", timeout=3)
                    if version.get("version"):
                        last_error = None
                        break
                    last_error = ValidationError("QwenPaw version response drifted")
                except ValidationError as exc:
                    last_error = exc
                time.sleep(0.5)
            if last_error is not None:
                raise last_error
            _disable_auto_title(runtime)
            prompt = str(
                case.get("prompts", {}).get(
                    "reproduction", "clawgap forced provider tool carrier"
                )
            )
            session_id = f"clawgap-l2-{role}-{attempt}"
            chat = _http_text(
                f"{base}/api/console/chat",
                {
                    "channel": "console",
                    "user_id": MEMBER_USERNAME,
                    "session_id": session_id,
                    "input": [
                        {
                            "role": "user",
                            "content": [{"type": "text", "text": prompt}],
                        }
                    ],
                },
                timeout=timeout,
            )
            atomic_write_text(runtime.parent / "chat-response.sse", redact_text(chat))
            atomic_write_json(
                runtime.parent / "prompt-receipt.json",
                {
                    "username": MEMBER_USERNAME,
                    "session_id": session_id,
                    "prompt": prompt,
                    "input_path": "/api/console/chat",
                },
            )
            complete = runtime.parent / "complete.marker"
            complete_deadline = time.monotonic() + 20
            while time.monotonic() < complete_deadline and not complete.is_file():
                time.sleep(0.1)
            if not complete.is_file():
                raise ValidationError(
                    "QwenPaw target did not reach the reviewed pre-effect boundary"
                )
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
            process_exit = process.returncode
    output = launch_log_path.read_text(encoding="utf-8", errors="replace")
    atomic_write_text(launch_log_path, redact_text(output))
    assert process_exit is not None
    return process_exit, output, chat


def _verify_fixture(runtime: Path, fixture: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        fake_jq = Path(str(fixture["fake_jq"]))
        if not fake_jq.is_file():
            errors.append("confined fake jq fixture disappeared")
        elif sha256_file(fake_jq) != fixture["fake_jq_sha256"]:
            errors.append("confined fake jq fixture changed")
        provider = json.loads(Path(str(fixture["provider_config"])).read_text())
        active = json.loads(Path(str(fixture["active_model_config"])).read_text())
        if provider.get("base_url", "").startswith("http://127.0.0.1:") is False:
            errors.append("provider base URL drifted from loopback")
        if active != {"provider_id": "clawgap", "model": MODEL_NAME}:
            errors.append("active model identity drifted")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"fixture verification failed: {exc}")
    return errors


def _cleanup_role(directory: Path, runtime: Path) -> list[str]:
    errors: list[str] = []
    try:
        _remove_path(runtime)
    except OSError as exc:
        errors.append(f"remove disposable role root: {exc}")
    if runtime.exists():
        errors.append("disposable QwenPaw role root remains")
    try:
        if directory.joinpath("host-effect-canary.txt").read_text(
            encoding="utf-8"
        ) != CANARY_CONTENT:
            errors.append("host-effect canary changed")
    except OSError as exc:
        errors.append(f"host-effect canary verification: {exc}")
    return errors


def _source_anchor(stage: str, detail: Mapping[str, Any]) -> str:
    if stage == "registry_or_native_dispatch":
        return "src/qwenpaw/agents/tool_guard_mixin.py:138"
    if stage == "handler_entered":
        return "src/qwenpaw/agents/tools/shell.py:367"
    if stage == "controlled_argument_recorded":
        return "src/qwenpaw/agents/tools/shell.py:399"
    if stage == "gate_observed":
        return "src/qwenpaw/security/tool_guard/engine.py:242"
    if stage == "missing_check_boundary_confirmed":
        return (
            "src/qwenpaw/security/tool_guard/rules/dangerous_shell_commands.yaml:247"
        )
    if stage in {"sink_reached", "pre_effect_interception", "target_completed"}:
        return str(detail.get("sink_anchor", ""))
    return "src/runtime_validation/qwenpaw_l2.py"


def _base_event(
    stage: str,
    detail: Mapping[str, Any],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "",
        "stage": stage,
        "candidate_id": _candidate_id(case),
        "case_id": str(case["case_id"]),
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{case['case_id']}:{attempt}:{role}",
        "fixture_id": f"qwenpaw-l2:{case['case_id']}:{role}",
        "source_anchor": "src/runtime_validation/qwenpaw_l2.py",
        "detail": dict(detail),
    }


def _normalize_events(
    raw_events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    source_bindings: Mapping[str, str],
    fixture: Mapping[str, Any],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    cleanup_errors: list[str],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    events.append(
        _base_event(
            "case_bound",
            {"candidate_binding": dict(case["candidate_binding"])},
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "source_verified",
            {"revision": PROJECT.analysis_revision, "source_hashes": dict(source_bindings)},
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "fixture_prepared",
            {
                "fake_jq": fixture["fake_jq"],
                "fake_jq_sha256": fixture["fake_jq_sha256"],
                "reviewed_cwd": fixture["reviewed_cwd"],
                "mount_namespace": fixture["mount_namespace"],
            },
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "launch_started",
            {
                "entrypoint": ".clawgap-venv/bin/qwenpaw app",
                "input": "/api/console/chat",
            },
            case,
            attempt,
            role,
        )
    )
    prompt = json.loads(
        Path(str(fixture["role_root"]))
        .parent.joinpath("prompt-receipt.json")
        .read_text(encoding="utf-8")
    )
    events.append(
        _base_event(
            "prompt_received",
            {
                "username": prompt["username"],
                "session_id": prompt["session_id"],
                "prompt": prompt["prompt"],
                "input_path": prompt["input_path"],
            },
            case,
            attempt,
            role,
        )
    )
    chat_rows = [
        row for row in provider_rows if row.get("path") == "/v1/chat/completions"
    ]
    provider = chat_rows[0] if chat_rows else {}
    events.append(
        _base_event(
            "provider_request",
            {
                "protocol": "openai-chat-completions-sse/v1",
                "path": provider.get("path"),
                "model": provider.get("model"),
                "stream": provider.get("stream"),
                "authorization_redacted": provider.get(
                    "authorization_redacted", "Bearer [redacted]"
                ),
            },
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "provider_tool_call_or_decision",
            {
                "tool_name": _tool_name(case),
                "arguments": _role_arguments(case, role),
                "response_kind": provider.get("response_kind"),
            },
            case,
            attempt,
            role,
        )
    )
    stage_rank = {stage: index for index, stage in enumerate(NORMALIZED_STAGES)}
    for raw in sorted(
        raw_events,
        key=lambda row: stage_rank.get(str(row.get("stage")), 10**6),
    ):
        row = _base_event(
            str(raw["stage"]), dict(raw.get("detail", {})), case, attempt, role
        )
        row["source_anchor"] = _source_anchor(str(raw["stage"]), row["detail"])
        events.append(row)
    cleanup_detail: dict[str, Any] = {
        "runtime_removed": not Path(str(fixture["role_root"])).exists(),
        "host_canary_unchanged": not cleanup_errors,
    }
    if cleanup_errors:
        cleanup_detail["cleanup_errors"] = cleanup_errors
    events.append(_base_event("cleanup_verified", cleanup_detail, case, attempt, role))
    for ordinal, event in enumerate(events, 1):
        event["event_id"] = f"{event['correlation_id']}:{ordinal}"
        event["ordinal"] = ordinal
    return events


def _transcript_errors(
    provider_rows: list[Mapping[str, Any]],
    case: Mapping[str, Any],
) -> list[str]:
    chat_rows = [
        row for row in provider_rows if row.get("path") == "/v1/chat/completions"
    ]
    if not chat_rows:
        return ["QwenPaw provider transcript is empty"]
    errors: list[str] = []
    if not 1 <= len(chat_rows) <= 2:
        errors.append(f"QwenPaw chat request count drifted: {len(chat_rows)}")
    first = chat_rows[0]
    if first.get("model") != MODEL_NAME:
        errors.append("QwenPaw provider model drifted")
    if first.get("stream") is not True:
        errors.append("QwenPaw provider did not use its native SSE mode")
    if first.get("authorization_valid") is not True:
        errors.append("QwenPaw provider authorization drifted")
    if _tool_name(case) not in set(first.get("tool_names", [])):
        errors.append("real QwenPaw provider request did not expose the reviewed tool")
    if first.get("response_kind") != "tool_call":
        errors.append("first QwenPaw provider response was not the forced tool call")
    if len(chat_rows) > 1 and chat_rows[1].get("response_kind") != "continuation":
        errors.append("QwenPaw provider continuation accounting drifted")
    unsupported = [
        row for row in provider_rows if row.get("response_kind") == "unsupported"
    ]
    if unsupported:
        errors.append("QwenPaw provider accessed an unsupported endpoint")
    return errors


def _sink_matches(
    case: Mapping[str, Any],
    role: str,
    sink: Mapping[str, Any] | None,
) -> bool:
    if sink is None or role != "exploit":
        return False
    detail = dict(sink.get("detail", {}))
    arguments = _role_arguments(case, "exploit")
    command = str(arguments["command"])
    return (
        detail.get("command") == command
        and (".env" in command or "$ENV" in command)
        and detail.get("cwd") == arguments.get("cwd")
        and detail.get("marker_key_present") is True
        and detail.get("marker_value") == "[redacted]"
        and str(detail.get("resolved_jq", "")).startswith("/tmp/.clawgap-bin/")
        and detail.get("fake_jq_executed") is False
        and detail.get("fake_jq_invocation_marker_present") is False
    )


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    process_exit: int,
    cleanup_errors: list[str],
) -> PairOutcome:
    errors = [*cleanup_errors, *_transcript_errors(provider_rows, case)]
    if process_exit not in {0, -signal.SIGTERM, -signal.SIGINT, 130, 143}:
        errors.append(f"real QwenPaw process exited with {process_exit}")
    if not events:
        return PairOutcome(False, False, [*errors, "empty normalized event trace"])

    first = events[0]
    identity = {key: first.get(key) for key in IDENTITY_FIELDS}
    for event in events:
        row = {key: event.get(key) for key in IDENTITY_FIELDS}
        if row != identity:
            errors.append("cross-attempt or cross-correlation event stitching")
            break
    stages = [str(event.get("stage")) for event in events]
    if stages != list(_expected_stages(case)):
        errors.append(f"event sequence mismatch: {stages}")

    arguments = _role_arguments(case, role)
    native = next(
        (row for row in events if row.get("stage") == "registry_or_native_dispatch"),
        None,
    )
    if native is None or native.get("detail", {}).get("tool_name") != _tool_name(case):
        errors.append("QwenPaw native tool dispatch was not observed")
    provider_call = next(
        (
            row
            for row in events
            if row.get("stage") == "provider_tool_call_or_decision"
        ),
        None,
    )
    if provider_call is None or provider_call.get("detail", {}).get(
        "arguments"
    ) != arguments:
        errors.append("reviewed provider tool arguments drifted")
    handler = next(
        (row for row in events if row.get("stage") == "handler_entered"), None
    )
    if handler is None or handler.get("detail", {}).get("arguments", {}).get(
        "command"
    ) != arguments["command"]:
        errors.append("native QwenPaw shell handler was not entered with exact command")
    controlled = next(
        (row for row in events if row.get("stage") == "controlled_argument_recorded"),
        None,
    )
    if controlled is None or controlled.get("detail", {}).get("value") != arguments[
        "command"
    ]:
        errors.append("model-controlled command drifted before normalization")

    gate = next((row for row in events if row.get("stage") == "gate_observed"), None)
    if gate is None:
        errors.append("ToolGuard allow decision was not observed")
    else:
        detail = gate.get("detail", {})
        if detail.get("admitted") is not True or detail.get("findings") != []:
            errors.append("ToolGuard denied or produced findings for the reviewed carrier")
        if set(NEIGHBORING_RULE_IDS).intersection(detail.get("rule_ids", [])):
            errors.append("a neighboring jq/proc rule unexpectedly matched")
        if detail.get("gate_ids") != list(_expected_gate_ids(case)):
            errors.append("QwenPaw gate identity accounting drifted")
    missing = next(
        (row for row in events if row.get("stage") == "missing_check_boundary_confirmed"),
        None,
    )
    if missing is None or missing.get("detail", {}).get("missing_check") is not True:
        errors.append("missing jq environment-object boundary was not recorded")

    sink = next((row for row in events if row.get("stage") == "sink_reached"), None)
    interception = next(
        (row for row in events if row.get("stage") == "pre_effect_interception"), None
    )
    if sink is None or interception is None:
        errors.append("pre-effect process sink boundary was incomplete")
    else:
        if sink.get("detail", {}).get("sink_anchor") != _sink_anchor(case):
            errors.append("carrier did not reach the cited terminal process sink")
        if interception.get("detail", {}).get("executed") is not False:
            errors.append("process sink was not intercepted before execution")
    triggered = _sink_matches(case, role, sink)
    if role == "control" and triggered:
        errors.append("safe jq control satisfied the exploit-only environment witness")
    if role == "exploit" and not triggered:
        errors.append("exploit did not satisfy the jq environment disclosure witness")
    return PairOutcome(not errors, triggered, errors)


def _run_role_attempt(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    build_python: Path,
    source_bindings: Mapping[str, str],
    request: QwenPawL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    directory = directory.resolve()
    _remove_path(directory)
    directory.mkdir(parents=True)
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    complete_path = directory / "complete.marker"
    directory.joinpath("host-effect-canary.txt").write_text(
        CANARY_CONTENT, encoding="utf-8"
    )
    transcript_path.write_text("", encoding="utf-8")
    event_path.write_text("", encoding="utf-8")
    provider = QwenPawProviderServer(
        role=role,
        tool_name=_tool_name(case),
        arguments=_role_arguments(case, role),
        transcript_path=transcript_path,
    )
    provider.start()
    app_port = _free_loopback_port()
    runtime = directory / "runtime"
    fixture: dict[str, Any] = {}
    process_exit = 124
    try:
        base_url = f"http://127.0.0.1:{provider.port}/v1"
        runtime = directory / "runtime"
        fixture = _prepare_role(directory, build_project, base_url=base_url)
        environment = {
            "PATH": f"/tmp/.clawgap-bin:{build_python.parent}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "HOME": str(runtime / "home"),
            "TMPDIR": str(runtime / "tmp"),
            "QWENPAW_WORKING_DIR": str(runtime / "working"),
            "QWENPAW_SECRET_DIR": str(runtime / "secret"),
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONPATH": str(runtime / "project/src"),
            ENV_MARKER_KEY: ENV_MARKER_VALUE,
            "CLAWGAP_L2_EVENT_PATH": str(event_path),
            "CLAWGAP_L2_COMPLETE_PATH": str(complete_path),
            "CLAWGAP_L2_CANDIDATE_ID": _candidate_id(case),
            "CLAWGAP_L2_CASE_ID": str(case["case_id"]),
            "CLAWGAP_L2_ATTEMPT": str(attempt),
            "CLAWGAP_L2_ROLE": role,
            "CLAWGAP_L2_CORRELATION_ID": f"{case['case_id']}:{attempt}:{role}",
            "CLAWGAP_L2_FIXTURE_ID": f"qwenpaw-l2:{case['case_id']}:{role}",
        }
        process_exit, _output, _chat = _launch_and_prompt(
            runtime=runtime,
            role_project=runtime / "project",
            build_python=build_python,
            case=case,
            role=role,
            attempt=attempt,
            fixture=fixture,
            environment=environment,
            app_port=app_port,
            timeout=request.timeout,
        )
    except Exception as exc:
        if runtime.exists():
            _cleanup_role(directory, runtime)
        provider.stop()
        return PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []
    finally:
        provider.stop()

    raw_events = _read_jsonl(event_path)
    provider_rows = _read_jsonl(transcript_path)
    cleanup_errors = [* _verify_fixture(runtime, fixture), *_cleanup_role(directory, runtime)]
    try:
        events = _normalize_events(
            raw_events,
            provider_rows,
            source_bindings,
            fixture,
            case,
            attempt,
            role,
            cleanup_errors,
        )
        if cleanup_errors and events:
            events[-1]["detail"]["cleanup_errors"] = cleanup_errors
        _write_jsonl(directory / "events.jsonl", events)
        outcome = _evaluate_pair(
            case,
            role,
            events,
            provider_rows,
            process_exit,
            cleanup_errors,
        )
        return outcome, events
    except Exception as exc:
        return PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []


def _candidate_disposition(outcomes: list[PairOutcome]) -> tuple[str, str]:
    if any(not outcome.healthy for outcome in outcomes):
        return (
            "inconclusive",
            "one or more paired attempts had infrastructure or trace failures",
        )
    if all(outcome.triggered for outcome in outcomes):
        return (
            "runtime-confirmed",
            "all paired forced-provider E2E attempts satisfied the oracle",
        )
    if not any(outcome.triggered for outcome in outcomes):
        return (
            "not-reproduced",
            "all paired forced-provider E2E attempts completed without the exploit sequence",
        )
    return "inconclusive", "paired exploit outcomes were inconsistent"


def _artifact_credential_scan(root: Path) -> str:
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    )
    return "failed" if contains_credentials(text) else "passed"


def _reproduction_command(request: QwenPawL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-qwenpaw-l2"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.campaign.resolve() != DEFAULT_SOURCE_CAMPAIGN.resolve():
        command += f" --campaign {request.campaign}"
    if request.candidate_id is not None:
        command += f" --candidate-id {request.candidate_id}"
    return command


def _artifact_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }


def run_qwenpaw_l2(request: QwenPawL2RunRequest) -> dict[str, Any]:
    started = time.time()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError(
            "QwenPaw targeted L2 timeouts and attempts must be positive"
        )
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    cases = _select_cases(request.campaign.resolve(), candidate_id=request.candidate_id)
    source_bindings = _source_bindings(cases)
    actual_build_dir = (
        request.build_dir.resolve()
        if request.build_dir
        else request.out_dir.resolve() / "build"
    )
    build_manifest = _prepare_build(
        actual_build_dir, source_bindings, request.build_timeout
    )
    build_project = actual_build_dir / "project"
    build_python = actual_build_dir / ".clawgap-venv/bin/python"
    if request.build_dir is not None:
        published_build = request.out_dir.resolve() / "build"
        _remove_path(published_build)
        published_build.mkdir(parents=True)
        shutil.copyfile(
            actual_build_dir / "transformed-source-manifest.json",
            published_build / "transformed-source-manifest.json",
        )
    else:
        shutil.copyfile(
            actual_build_dir / "transformed-source-manifest.json",
            request.out_dir.resolve() / "transformed-source-manifest.json",
        )

    results: list[dict[str, Any]] = []
    for case in cases:
        pair_outcomes: list[PairOutcome] = []
        for attempt in range(1, request.attempts + 1):
            role_outcomes: dict[str, PairOutcome] = {}
            for role in ("exploit", "control"):
                directory = (
                    request.out_dir
                    / "runs"
                    / str(case["case_id"])
                    / f"attempt-{attempt}"
                    / role
                )
                outcome, _events = _run_role_attempt(
                    case,
                    role,
                    attempt,
                    directory,
                    build_project,
                    build_python,
                    source_bindings,
                    request,
                )
                role_outcomes[role] = outcome
            exploit = role_outcomes["exploit"]
            control = role_outcomes["control"]
            pair_outcomes.append(
                PairOutcome(
                    exploit.healthy and control.healthy,
                    exploit.healthy and control.healthy and exploit.triggered,
                    [*exploit.errors, *control.errors],
                )
            )
        disposition, reason = _candidate_disposition(pair_outcomes)
        results.append(
            {
                "schema_version": RESULT_SCHEMA_VERSION,
                "campaign_id": CAMPAIGN_ID,
                "candidate_id": _candidate_id(case),
                "case_id": case["case_id"],
                "project": "QwenPaw",
                "disposition": disposition,
                "evidence_tier": L2_EVIDENCE_TIER,
                "attempts": request.attempts,
                "reason": reason,
                "attempt_errors": [
                    outcome.errors for outcome in pair_outcomes if outcome.errors
                ],
                "payload_repair_applied": False,
                "trace_accounting": {
                    "expected": request.attempts * 2,
                    "valid": sum(outcome.healthy for outcome in pair_outcomes) * 2,
                    "blocked": sum(not outcome.healthy for outcome in pair_outcomes) * 2,
                    "not_launched": 0
                    if all(outcome.healthy for outcome in pair_outcomes)
                    else sum(2 for outcome in pair_outcomes if not outcome.healthy),
                },
            }
        )

    if request.build_dir is None:
        _remove_path(actual_build_dir)
    _write_jsonl(request.out_dir / "cases.jsonl", cases)
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "candidate_id": row["candidate_id"],
                "case_id": row["case_id"],
                "project": "QwenPaw",
                "status": row["disposition"],
                "evidence_tier": row["evidence_tier"],
            }
            for row in results
        ],
    )
    counts: dict[str, int] = {}
    for row in results:
        counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1
    for path in (
        path for path in (request.out_dir / "runs").rglob("*") if path.name == "runtime"
    ):
        try:
            _remove_path(path)
        except OSError:
            pass
    credential_scan = _artifact_credential_scan(request.out_dir)
    disposable_workspaces_removed = not any(
        path.is_dir()
        for path in (request.out_dir / "runs").rglob("*")
        if path.name == "runtime"
    )
    if credential_scan != "passed" or not disposable_workspaces_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
        counts = {"inconclusive": len(results)}
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-qwenpaw-l2-manifest/v1",
        "campaign_id": CAMPAIGN_ID,
        "source_campaign": str(request.campaign),
        "candidate_count": len(results),
        "attempt_pairs": request.attempts,
        "status_counts": counts,
        "evidence_tier": L2_EVIDENCE_TIER,
        "targeted_only": True,
        "canonical_all_candidate_l2": False,
        "source_bindings": source_bindings,
        "source_drift": False,
        "dependency_pyproject": sha256_file(SOURCE_ROOT / "pyproject.toml"),
        "harness_bindings": {
            "src/runtime_validation/qwenpaw_l2.py": sha256_file(
                REPO_ROOT / "src/runtime_validation/qwenpaw_l2.py"
            )
        },
        "transformed_source_manifest": build_manifest,
        "credential_scan": credential_scan,
        "disposable_workspaces_removed": disposable_workspaces_removed,
        "artifact_sha256": _artifact_hashes(request.out_dir.resolve()),
        "reproduction_command": _reproduction_command(request),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "completed_at": _utc_now(),
    }
    atomic_write_json(request.out_dir.resolve() / "manifest.json", manifest)
    return manifest
