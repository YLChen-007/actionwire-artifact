"""Targeted forced-provider L2 runtime for linked AstrBot candidates."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import socket
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
PROJECT = get_project("AstrBot")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
TARGET_CANDIDATES = (
    "CAND-12536711cca9c235",
    "CAND-1a069517d7740b35",
    "CAND-36a7affd32f9adf1",
)
CAMPAIGN_ID = "runtime-dynamic-trigger-astrbot-l2-v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-astrbot-l2-result/v1"
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-astrbot-l2-event/v1"
MODEL_NAME = "clawgap-astrbot-l2"
PROVIDER_CREDENTIAL = "clawgap-loopback-mock"
DASHBOARD_PASSWORD = "ClawGapProbe1"
MEMBER_USERNAME = "clawgap-member"
ADMIN_USERNAME = "astrbot"
CANARY_CONTENT = "clawgap-astrbot-host-canary\n"
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
FAMILIES = {
    "CAND-12536711cca9c235": "plugin-skill-edit",
    "CAND-1a069517d7740b35": "plugin-skill-write",
    "CAND-36a7affd32f9adf1": "workspace-hardlink-write",
}
CITED_SOURCE_HASHES = {
    "astrbot/core/tools/computer_tools/fs.py": (
        "8e30a7f2d5feca48476dbe10bb52a6187ad4ffbdc07cd7adbdf7520303a8b45d"
    ),
    "astrbot/core/computer/booters/local.py": (
        "ba0df5731b1c28814a9bafba9d16dcb8a0914fd66e0b21594a2078667d79fd29"
    ),
}


@dataclass(frozen=True)
class AstrBotL2RunRequest:
    campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    out_dir: Path = ...
    attempts: int = 3
    timeout: int = 150
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
            f"cannot read AstrBot L2 artifact {path}: {exc}"
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
        if row.get("project") == "AstrBot"
    }
    expected = set(TARGET_CANDIDATES)
    if not expected.issubset(selected):
        missing = sorted(expected - set(selected))
        raise ValidationError(
            "AstrBot targeted L2 source campaign is missing GT-linked "
            "candidates: " + ", ".join(missing)
        )
    if candidate_id is None:
        return [selected[item] for item in TARGET_CANDIDATES]
    if candidate_id not in expected:
        raise ValidationError(
            "requested AstrBot candidate is not a GT-linked targeted L2 candidate"
        )
    return [selected[candidate_id]]


def _candidate_id(case: Mapping[str, Any]) -> str:
    return str(case["candidate_binding"]["candidate_id"])


def _family(case: Mapping[str, Any]) -> str:
    return FAMILIES[_candidate_id(case)]


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
        "astrbot/cli/__main__.py",
        "astrbot/core/provider/sources/openai_source.py",
        "astrbot/core/agent/runners/tool_loop_agent_runner.py",
        "astrbot/core/astr_agent_tool_exec.py",
        "astrbot/dashboard/routes/open_api.py",
        "astrbot/dashboard/routes/chat.py",
        "astrbot/core/tools/computer_tools/fs.py",
        "astrbot/core/computer/booters/local.py",
    }
    for case in cases:
        if case.get("revision") != PROJECT.analysis_revision:
            raise ValidationError("AstrBot case revision does not match registry")
    bindings: dict[str, str] = {}
    for relative in sorted(required_files):
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"AstrBot bound source is missing: {relative}")
        digest_value = sha256_file(source)
        expected = CITED_SOURCE_HASHES.get(relative)
        if expected is not None and digest_value != expected:
            raise ValidationError(
                f"AstrBot cited source hash drift: {relative}: {digest_value}"
            )
        bindings[relative] = digest_value
    return bindings


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(
            f"AstrBot instrumentation marker mismatch ({label}): {count}"
        )
    return source.replace(old, new, 1)


def _instrumentation_helper() -> str:
    return r'''import builtins
import io
import json
import os
import time


_original_open = builtins.open
_state = {
    "tool": None,
    "value": None,
    "resolved": None,
    "sink_emitted": False,
}


def _event(stage, detail):
    path = os.environ.get("CLAWGAP_L2_EVENT_PATH")
    if not path:
        return
    row = {
        "schema_version": "clawgap-dynamic-trigger-astrbot-l2-event/v1",
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
        with _original_open(marker, "w", encoding="utf-8") as stream:
            stream.write(str(time.time()))


def clawgap_native_dispatch(tool_name, arguments):
    _event(
        "registry_or_native_dispatch",
        {"tool_name": tool_name, "arguments": arguments, "runtime": "ToolLoopAgentRunner"},
    )


def clawgap_handler(tool_name, arguments):
    _state.update({"tool": tool_name, "value": None, "resolved": None, "sink_emitted": False})
    _event("handler_entered", {"tool_name": tool_name, "arguments": arguments})


def clawgap_controlled(argument_path, value, resolved=None):
    _state["value"] = value
    _state["resolved"] = resolved
    _event(
        "controlled_argument_recorded",
        {"argument_path": argument_path, "value": value, "resolved": resolved},
    )


def clawgap_gate(name, detail):
    gate_ids = [
        item for item in os.environ.get("CLAWGAP_L2_GATE_IDS", "").split(",") if item
    ]
    _event("gate_observed", {"gate_ids": gate_ids, "name": name, **detail})


def clawgap_missing_check(detail):
    policy = os.environ.get("CLAWGAP_L2_MISSING_CHECK_POLICY", "")
    _event("missing_check_boundary_confirmed", {"missing_check": True, "policy": policy, **detail})


def _emit_sink(anchor, detail):
    if _state["sink_emitted"]:
        return
    _state["sink_emitted"] = True
    payload = dict(detail)
    payload["sink_anchor"] = anchor
    expected = os.environ.get("CLAWGAP_L2_EXPECTED_SINK_PATH")
    if expected:
        payload["expected_path"] = expected
    outside = os.environ.get("CLAWGAP_L2_OUTSIDE_TARGET")
    if outside:
        try:
            payload["samefile_with_outside_target"] = os.path.samefile(detail["path"], outside)
        except OSError:
            payload["samefile_with_outside_target"] = False
    _event("sink_reached", payload)
    _event("pre_effect_interception", {**payload, "executed": False})
    _event("target_completed", {"sink_anchor": anchor})
    _complete()


def _intercept_open(*args, **kwargs):
    value = args[0] if args else kwargs.get("file")
    mode = str(args[1] if len(args) > 1 else kwargs.get("mode", "r"))
    if (
        _state.get("tool") in {"astrbot_file_write_tool", "astrbot_file_edit_tool"}
        and isinstance(value, str)
        and value == _state.get("resolved")
        and any(flag in mode for flag in ("w", "a", "x"))
    ):
        anchor = (
            "astrbot/core/computer/booters/local.py:280"
            if _state["tool"] == "astrbot_file_write_tool"
            else "astrbot/core/computer/booters/local.py:264"
        )
        _emit_sink(anchor, {"path": value, "mode": mode})
        return io.StringIO("")
    return _original_open(*args, **kwargs)


builtins.open = _intercept_open
'''


def _instrument_project(project: Path) -> dict[str, str]:
    helper_path = project / "clawgap_l2_runtime.py"
    atomic_write_text(helper_path, _instrumentation_helper())

    cli_path = project / "astrbot/cli/__main__.py"
    cli_source = cli_path.read_text(encoding="utf-8")
    cli_source = _replace_once(
        cli_source,
        "import click\n\nfrom . import __version__\n",
        "import click\n\nimport clawgap_l2_runtime\n\nfrom . import __version__\n",
        "CLI runtime bootstrap",
    )
    cli_path.write_text(cli_source, encoding="utf-8")

    runner_path = (
        project
        / "astrbot/core/agent/runners/tool_loop_agent_runner.py"
    )
    runner_source = runner_path.read_text(encoding="utf-8")
    runner_source = (
        "from clawgap_l2_runtime import clawgap_native_dispatch\n"
        + runner_source
    )
    runner_source = _replace_once(
        runner_source,
        '                #  Some API may return None for tools with no parameters\n                if func_tool_args is None:\n                    func_tool_args = {}\n                logger.info(f"使用工具：{func_tool_name}，参数：{func_tool_args}")\n',
        '                #  Some API may return None for tools with no parameters\n                if func_tool_args is None:\n                    func_tool_args = {}\n                clawgap_native_dispatch(func_tool_name, func_tool_args)\n                logger.info(f"使用工具：{func_tool_name}，参数：{func_tool_args}")\n',
        "ToolLoop native dispatch",
    )
    runner_path.write_text(runner_source, encoding="utf-8")

    fs_path = project / "astrbot/core/tools/computer_tools/fs.py"
    fs_source = fs_path.read_text(encoding="utf-8")
    fs_source = (
        "from clawgap_l2_runtime import (\n"
        "    clawgap_controlled,\n"
        "    clawgap_gate,\n"
        "    clawgap_handler,\n"
        "    clawgap_missing_check,\n"
        ")\n"
        + fs_source
    )
    fs_source = _replace_once(
        fs_source,
        '    normalized_path = _resolve_tool_path(path, local_env=local_env, umo=umo)\n    if not normalized_path:\n        raise ValueError("`path` must be a non-empty string.")\n    if restricted:\n        allowed_roots = _read_allowed_roots(umo)\n    if restricted and not _is_path_within_allowed_roots(\n        normalized_path,\n        umo=umo,\n        allowed_roots=allowed_roots,\n    ):\n',
        '    normalized_path = _resolve_tool_path(path, local_env=local_env, umo=umo)\n    if not normalized_path:\n        raise ValueError("`path` must be a non-empty string.")\n    clawgap_controlled(["path"], path, resolved=normalized_path)\n    if restricted:\n        allowed_roots = _read_allowed_roots(umo)\n        admitted = _is_path_within_allowed_roots(\n            normalized_path, umo=umo, allowed_roots=allowed_roots\n        )\n        clawgap_gate(\n            "read_style_path_containment",\n            {"path": normalized_path, "admitted": admitted, "restricted": True},\n        )\n        clawgap_missing_check({"path": normalized_path, "admitted": admitted})\n    if restricted and not _is_path_within_allowed_roots(\n        normalized_path,\n        umo=umo,\n        allowed_roots=allowed_roots,\n    ):\n',
        "shared path containment boundary",
    )
    fs_source = _replace_once(
        fs_source,
        '    async def call(\n        self,\n        context: ContextWrapper[AstrAgentContext],\n        path: str,\n        content: str,\n    ) -> ToolExecResult:\n        local_env = is_local_runtime(context)\n        restricted = _is_restricted_env(context)\n        try:\n',
        '    async def call(\n        self,\n        context: ContextWrapper[AstrAgentContext],\n        path: str,\n        content: str,\n    ) -> ToolExecResult:\n        local_env = is_local_runtime(context)\n        restricted = _is_restricted_env(context)\n        clawgap_handler("astrbot_file_write_tool", {"path": path, "content": content})\n        try:\n',
        "FileWrite handler entry",
    )
    fs_source = _replace_once(
        fs_source,
        '    async def call(\n        self,\n        context: ContextWrapper[AstrAgentContext],\n        path: str,\n        old: str,\n        new: str,\n        replace_all: bool = False,\n    ) -> ToolExecResult:\n        umo = str(context.context.event.unified_msg_origin)\n        local_env = is_local_runtime(context)\n        restricted = _is_restricted_env(context)\n        try:\n',
        '    async def call(\n        self,\n        context: ContextWrapper[AstrAgentContext],\n        path: str,\n        old: str,\n        new: str,\n        replace_all: bool = False,\n    ) -> ToolExecResult:\n        umo = str(context.context.event.unified_msg_origin)\n        local_env = is_local_runtime(context)\n        restricted = _is_restricted_env(context)\n        clawgap_handler("astrbot_file_edit_tool", {"path": path, "old": old, "new": new})\n        try:\n',
        "FileEdit handler entry",
    )
    fs_path.write_text(fs_source, encoding="utf-8")

    dashboard_path = project / "astrbot/dashboard/server.py"
    dashboard_source = dashboard_path.read_text(encoding="utf-8")
    dashboard_source = _replace_once(
        dashboard_source,
        '        self.app = Quart("dashboard", static_folder=self.data_path, static_url_path="/")\n',
        '        _clawgap_root = Path(__file__).resolve().parent.parent.parent\n'
        '        self.app = Quart(\n'
        '            "dashboard",\n'
        '            static_folder=self.data_path,\n'
        '            static_url_path="/",\n'
        '            instance_path=str(_clawgap_root / "instance"),\n'
        '            root_path=str(_clawgap_root),\n'
        '        )\n',
        "dashboard package-path compatibility adapter",
    )
    dashboard_path.write_text(dashboard_source, encoding="utf-8")

    transformed_files = (
        "clawgap_l2_runtime.py",
        "astrbot/cli/__main__.py",
        "astrbot/core/agent/runners/tool_loop_agent_runner.py",
        "astrbot/core/tools/computer_tools/fs.py",
        "astrbot/dashboard/server.py",
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
            "run.log",
        ),
    )
    dashboard_dist = project / "astrbot/dashboard/dist"
    dashboard_dist.mkdir(parents=True, exist_ok=True)
    (dashboard_dist / "index.html").write_text(
        "<!doctype html><title>AstrBot ClawGap L2</title>\n",
        encoding="utf-8",
    )
    transformed = _instrument_project(project)
    return {
        "schema_version": "clawgap-astrbot-transformed-source-manifest/v1",
        "revision": PROJECT.analysis_revision,
        "original": dict(source_bindings),
        "transformed": transformed,
        "runtime_adapter": (
            "source-bound provider, dispatch, handler, gate, and filesystem sink "
            "instrumentation in the disposable build copy"
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
    harness_path = REPO_ROOT / "src/runtime_validation/astrbot_l2.py"
    harness_sha256 = sha256_file(harness_path)
    dependency_sha256 = sha256_file(SOURCE_ROOT / "pyproject.toml")
    manifest_path = directory / "transformed-source-manifest.json"
    venv_python = directory / ".clawgap-venv/bin/python"
    if manifest_path.is_file() and venv_python.is_file():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version")
            == "clawgap-astrbot-transformed-source-manifest/v1"
            and prior.get("revision") == PROJECT.analysis_revision
            and prior.get("original") == dict(source_bindings)
            and prior.get("dependency_pyproject_sha256") == dependency_sha256
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
        [
            str(base_python),
            "-m",
            "venv",
            "--system-site-packages",
            str(venv_dir),
        ],
        cwd=directory,
        log_path=directory / "venv.log",
        timeout=min(timeout, 300),
    )
    if bootstrap.returncode != 0 or not venv_python.is_file():
        raise ValidationError(
            f"AstrBot disposable Python environment failed: {bootstrap.returncode}"
        )
    uv_path = shutil.which("uv")
    if uv_path is None:
        raise ValidationError("AstrBot targeted L2 requires uv for the pinned editable build")
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
            f"AstrBot editable dependency installation failed: {install.returncode}"
        )
    probe = _run(
        [
            str(venv_python),
            "-c",
            "import astrbot, astrbot.core, astrbot.core.provider.sources.openai_source",
        ],
        cwd=directory / "project",
        log_path=directory / "import-probe.log",
        timeout=min(timeout, 120),
        env={
            "ASTRBOT_ROOT": str(directory / "project"),
            "HOME": str(directory / "build-home"),
            "PATH": f"{venv_dir / 'bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
        },
    )
    if probe.returncode != 0:
        raise ValidationError(
            f"AstrBot transformed runtime import probe failed: {probe.returncode}"
        )
    manifest.update(
        {
            "dependency_pyproject_sha256": dependency_sha256,
            "harness_sha256": harness_sha256,
            "interpreter_sha256": sha256_file(venv_python),
        }
    )
    atomic_write_json(manifest_path, manifest)
    return manifest


class AstrBotProviderServer:
    """Small strict OpenAI-compatible SSE loopback used by the real client."""

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
                                {"id": MODEL_NAME, "object": "model", "owned_by": "clawgap"}
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
                    call_id = f"call-clawgap-{server.role}"
                    chunks = [
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
                                                "id": call_id,
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
                    ]
                    server._sse(self, chunks)
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


def _normalized_umo(session_id: str) -> str:
    umo = f"webchat:FriendMessage:webchat!{MEMBER_USERNAME}!{session_id}"
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", umo.strip())
    return normalized or "unknown"


def _workspace_root(runtime: Path, session_id: str) -> Path:
    return (
        runtime
        / "data"
        / "workspaces"
        / _normalized_umo(session_id)
    ).resolve(strict=False)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _configure_role(
    runtime: Path,
    source_config: Path,
    *,
    provider_base_url: str,
    app_port: int,
) -> Path:
    data = runtime / "data"
    data.mkdir(parents=True, exist_ok=True)
    config_path = data / "cmd_config.json"
    shutil.copy2(source_config, config_path)
    value = json.loads(config_path.read_text(encoding="utf-8-sig"))
    value["provider"] = [
        {
            "id": "clawgap",
            "provider": "openai",
            "type": "openai_chat_completion",
            "provider_type": "chat_completion",
            "enable": True,
            "key": [PROVIDER_CREDENTIAL],
            "api_base": provider_base_url,
            "timeout": 30,
            "proxy": "",
            "custom_headers": {},
            "model": MODEL_NAME,
            "modalities": ["text", "tool_use"],
        }
    ]
    provider_settings = value.setdefault("provider_settings", {})
    provider_settings["default_provider_id"] = "clawgap"
    provider_settings["computer_use_runtime"] = "local"
    provider_settings["computer_use_require_admin"] = True
    value["admins_id"] = [ADMIN_USERNAME]
    dashboard = value.setdefault("dashboard", {})
    dashboard.update(
        {
            "username": ADMIN_USERNAME,
            "pbkdf2_password": (
                "pbkdf2_sha256$600000$74fd00ecb9aff68f597a31a62096e2f7$"
                "76005b6d00b47bd3f6c9a0d2e767cd0b03ad8b9b7844b245b2020505b31e962f"
            ),
            "password_change_required": False,
            "host": "127.0.0.1",
            "port": app_port,
        }
    )
    config_path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return config_path


def _sha_or_none(path: Path) -> str | None:
    return sha256_file(path) if path.is_file() else None


def _prepare_fixture(
    *,
    runtime: Path,
    case: Mapping[str, Any],
    role: str,
    session_id: str,
) -> dict[str, Any]:
    family = _family(case)
    workspace = _workspace_root(runtime, session_id)
    workspace.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}
    symlinks: dict[str, str] = {}
    outside_target: Path | None = None
    expected_sink_path: Path
    exploit_only = role == "exploit"

    if family in {"plugin-skill-write", "plugin-skill-edit"}:
        plugin = runtime / "data/plugins/demo/skills/SKILL.md"
        skills = runtime / "data/skills/SKILL.md"
        plugin.parent.mkdir(parents=True, exist_ok=True)
        skills.parent.mkdir(parents=True, exist_ok=True)
        plugin.write_text("original\n", encoding="utf-8")
        skills.write_text("original\n", encoding="utf-8")
        if family == "plugin-skill-write":
            label = workspace / "data/skills/SKILL.md"
            label.parent.mkdir(parents=True, exist_ok=True)
            label.symlink_to(skills.resolve())
            symlinks[str(label)] = str(skills.resolve())
        else:
            plugin_label = workspace / "data/plugins/demo/skills/SKILL.md"
            skills_label = workspace / "data/skills/SKILL.md"
            plugin_label.parent.mkdir(parents=True, exist_ok=True)
            skills_label.parent.mkdir(parents=True, exist_ok=True)
            plugin_label.symlink_to(plugin.resolve())
            skills_label.symlink_to(skills.resolve())
            symlinks[str(plugin_label)] = str(plugin.resolve())
            symlinks[str(skills_label)] = str(skills.resolve())
        expected_sink_path = plugin if exploit_only else skills
        source_files = [plugin, skills]
    else:
        outside_dir = runtime / "outside"
        outside_dir.mkdir(parents=True, exist_ok=True)
        outside_target = outside_dir / "secret.txt"
        outside_target.write_text("clawgap-outside-canary\n", encoding="utf-8")
        alias = workspace / "hardlink_to_outside.txt"
        safe = workspace / "safe_file.txt"
        os.link(outside_target, alias)
        safe.write_text("clawgap-safe-control\n", encoding="utf-8")
        expected_sink_path = alias if exploit_only else safe
        source_files = [alias, safe, outside_target]

    for path in source_files:
        files[str(path)] = sha256_file(path)

    manifest = {
        "schema_version": "clawgap-astrbot-l2-fixture-manifest/v1",
        "family": family,
        "role": role,
        "session_id": session_id,
        "workspace": str(workspace),
        "files": files,
        "symlinks": symlinks,
        "outside_target": str(outside_target) if outside_target else None,
        "expected_sink_path": str(expected_sink_path),
        "role_root": str(runtime),
    }
    return manifest


def _prepare_role(
    directory: Path,
    build_project: Path,
    *,
    base_url: str,
    case: Mapping[str, Any],
    role: str,
    app_port: int,
) -> tuple[Path, Path, Path, str, dict[str, Any]]:
    runtime = directory / "runtime"
    home = runtime / "home"
    temporary = runtime / "tmp"
    runtime.mkdir(parents=True, exist_ok=False)
    home.mkdir()
    temporary.mkdir()
    (runtime / ".astrbot").mkdir()
    shutil.copytree(
        build_project,
        runtime,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(".clawgap-venv", "uv-cache", "build-home"),
    )
    config_source = build_project / "data/cmd_config.json"
    session_id = f"clawgap-l2-{role}-{int(time.time())}"
    config_path = _configure_role(
        runtime,
        config_source,
        provider_base_url=base_url,
        app_port=app_port,
    )
    shutil.copy2(config_path, directory / "cmd_config.json")
    fixture = _prepare_fixture(
        runtime=runtime,
        case=case,
        role=role,
        session_id=session_id,
    )
    atomic_write_json(directory / "fixture-manifest.json", fixture)
    return runtime, home, temporary, session_id, fixture


def _seed_session(
    *,
    python: Path,
    runtime: Path,
    role_project: Path,
    session_id: str,
) -> None:
    code = (
        "import asyncio; from astrbot.core import db_helper; "
        f"asyncio.run(db_helper.create_platform_session(creator={MEMBER_USERNAME!r}, "
        f"platform_id='webchat', session_id={session_id!r}, "
        "display_name='ClawGap L2'))"
    )
    completed = subprocess.run(
        [str(python), "-c", code],
        cwd=role_project,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
        check=False,
        env={
            "ASTRBOT_ROOT": str(runtime),
            "PYTHONPATH": str(role_project),
            "HOME": str(runtime / "home"),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "NO_COLOR": "1",
        },
    )
    atomic_write_text(
        role_project.parent / "session-seed.log",
        redact_text(completed.stdout or ""),
    )
    if completed.returncode != 0:
        raise ValidationError(
            "AstrBot real database/session seeding failed: "
            f"{completed.returncode}"
        )


def _http_json(
    url: str,
    payload: Mapping[str, Any],
    token: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValidationError(f"AstrBot dashboard/OpenAPI request failed: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError("AstrBot dashboard/OpenAPI returned a non-object response")
    return value


def _http_text(
    url: str,
    payload: Mapping[str, Any],
    token: str | None = None,
    timeout: int = 30,
) -> str:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ValidationError(f"AstrBot dashboard/OpenAPI request failed: {exc}") from exc


def _require_ok(value: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    if value.get("code") not in {None, 0, 200} or value.get("status") == "error":
        raise ValidationError(f"AstrBot {label} failed: {value}")
    return value


def _launch_and_prompt(
    *,
    runtime: Path,
    role_project: Path,
    build_python: Path,
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    session_id: str,
    fixture: Mapping[str, Any],
    environment: Mapping[str, str],
    app_port: int,
    timeout: int,
) -> tuple[int, str, str]:
    family = _family(case)
    astrbot_executable = build_python.parent / "astrbot"
    command: list[str]
    if family == "workspace-hardlink-write":
        mount_script = (
            "mount -t tmpfs tmpfs /tmp && "
            f"ln -s {shlex.quote(str(fixture['workspace']))} /tmp/allowed_root && "
            f"exec {shlex.quote(str(astrbot_executable))} run --port {app_port}"
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
    else:
        command = [str(astrbot_executable), "run", "--port", str(app_port)]

    launch_log_path = runtime.parent / "launch.log"
    output = ""
    process_exit: int | None = None
    with launch_log_path.open("w", encoding="utf-8") as launch_log:
        process = subprocess.Popen(
            command,
            cwd=runtime,
            env=dict(environment),
            stdout=launch_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        base = f"http://127.0.0.1:{app_port}"
        login: Mapping[str, Any] = {}
        api_key = ""
        chat = ""
        try:
            deadline = time.monotonic() + min(timeout, 90)
            last_error: Exception | None = None
            while time.monotonic() < deadline:
                try:
                    login = _require_ok(
                        _http_json(
                            f"{base}/api/auth/login",
                            {
                                "username": ADMIN_USERNAME,
                                "password": DASHBOARD_PASSWORD,
                            },
                            timeout=3,
                        ),
                        "dashboard login",
                    )
                    last_error = None
                    break
                except ValidationError as exc:
                    last_error = exc
                    time.sleep(0.5)
            if last_error is not None:
                raise last_error
            dashboard_token = str(login.get("data", {}).get("token") or "")
            if not dashboard_token:
                raise ValidationError("AstrBot dashboard login did not return a token")
            created = _require_ok(
                _http_json(
                    f"{base}/api/apikey/create",
                    {
                        "name": f"clawgap-l2-{role}-{attempt}",
                        "scopes": ["chat"],
                    },
                    dashboard_token,
                ),
                "API-key creation",
            )
            api_key = str(created.get("data", {}).get("api_key") or "")
            if not api_key:
                raise ValidationError("AstrBot API-key creation did not return a key")
            prompt = str(
                case.get("prompts", {}).get(
                    "reproduction", "clawgap forced provider tool carrier"
                )
            )
            chat = _http_text(
                f"{base}/api/v1/chat",
                {
                    "username": MEMBER_USERNAME,
                    "session_id": session_id,
                    "config_id": "default",
                    "message": prompt,
                    "enable_streaming": True,
                },
                api_key,
                timeout=timeout,
            )
            atomic_write_text(
                runtime.parent / "chat-response.txt",
                redact_text(chat),
            )
            atomic_write_json(
                runtime.parent / "prompt-receipt.json",
                {
                    "username": MEMBER_USERNAME,
                    "session_id": session_id,
                    "prompt": prompt,
                    "api_scopes": ["chat"],
                    "role": role,
                },
            )
            complete = runtime.parent / "complete.marker"
            complete_deadline = time.monotonic() + 15
            while time.monotonic() < complete_deadline and not complete.is_file():
                time.sleep(0.1)
            if not complete.is_file():
                raise ValidationError(
                    "AstrBot target did not reach the reviewed pre-effect boundary"
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
    family = str(fixture["family"])
    try:
        if family in {"plugin-skill-write", "plugin-skill-edit"}:
            plugin = runtime / "data/plugins/demo/skills/SKILL.md"
            skills = runtime / "data/skills/SKILL.md"
            if plugin.read_text(encoding="utf-8") != "original\n":
                errors.append("plugin-skill fixture changed before cleanup")
            if skills.read_text(encoding="utf-8") != "original\n":
                errors.append("safe skills fixture changed before cleanup")
        else:
            outside = Path(str(fixture["outside_target"]))
            if outside.read_text(encoding="utf-8") != "clawgap-outside-canary\n":
                errors.append("outside-workspace hardlink target changed")
        expected = Path(str(fixture["expected_sink_path"]))
        if not expected.exists():
            errors.append("reviewed sink fixture disappeared before verification")
    except OSError as exc:
        errors.append(f"fixture verification failed: {exc}")
    return errors


def _cleanup_role(
    directory: Path,
    runtime: Path,
) -> list[str]:
    errors: list[str] = []
    try:
        _remove_path(runtime)
    except OSError as exc:
        errors.append(f"remove disposable role root: {exc}")
    if runtime.exists():
        errors.append("disposable AstrBot role root remains")
    try:
        if directory.joinpath("host-effect-canary.txt").read_text(
            encoding="utf-8"
        ) != CANARY_CONTENT:
            errors.append("host-effect canary changed")
    except OSError as exc:
        errors.append(f"host-effect canary verification: {exc}")
    return errors


def _source_anchor(stage: str, detail: Mapping[str, Any], family: str) -> str:
    if stage == "registry_or_native_dispatch":
        return "astrbot/core/agent/runners/tool_loop_agent_runner.py:1037"
    if stage == "handler_entered":
        return (
            "astrbot/core/tools/computer_tools/fs.py:313"
            if family == "plugin-skill-write"
            or family == "workspace-hardlink-write"
            else "astrbot/core/tools/computer_tools/fs.py:388"
        )
    if stage in {"controlled_argument_recorded"}:
        return "astrbot/core/tools/computer_tools/fs.py:176"
    if stage in {"gate_observed", "missing_check_boundary_confirmed"}:
        return "astrbot/core/tools/computer_tools/fs.py:181"
    if stage in {"sink_reached", "pre_effect_interception", "target_completed"}:
        return str(detail.get("sink_anchor", ""))
    return "src/runtime_validation/astrbot_l2.py"


def _base_event(
    stage: str,
    detail: Mapping[str, Any],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
) -> dict[str, Any]:
    candidate_id = _candidate_id(case)
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "",
        "stage": stage,
        "candidate_id": candidate_id,
        "case_id": str(case["case_id"]),
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{case['case_id']}:{attempt}:{role}",
        "fixture_id": f"astrbot-l2:{case['case_id']}:{role}",
        "source_anchor": "src/runtime_validation/astrbot_l2.py",
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
    family = _family(case)
    events: list[dict[str, Any]] = []
    events.append(
        _base_event(
            "case_bound",
            {
                "candidate_binding": dict(case["candidate_binding"]),
                "runtime_family": "python",
            },
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "source_verified",
            {
                "revision": PROJECT.analysis_revision,
                "source_hashes": dict(source_bindings),
            },
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "fixture_prepared",
            {
                "family": family,
                "workspace": fixture["workspace"],
                "symlinks": dict(fixture["symlinks"]),
                "outside_target": fixture["outside_target"],
                "expected_sink_path": fixture["expected_sink_path"],
            },
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "launch_started",
            {"entrypoint": ".clawgap-venv/bin/astrbot run", "input": "dashboard-openapi"},
            case,
            attempt,
            role,
        )
    )
    prompt = json.loads(
        Path(str(fixture["role_root"])).parent.joinpath("prompt-receipt.json").read_text(
            encoding="utf-8"
        )
    )
    events.append(
        _base_event(
            "prompt_received",
            {
                "username": prompt["username"],
                "session_id": prompt["session_id"],
                "prompt": prompt["prompt"],
            },
            case,
            attempt,
            role,
        )
    )
    provider = provider_rows[0] if provider_rows else {}
    events.append(
        _base_event(
            "provider_request",
            {
                "protocol": "openai-chat-completions/v1",
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
    for raw in raw_events:
        row = _base_event(
            str(raw["stage"]),
            dict(raw.get("detail", {})),
            case,
            attempt,
            role,
        )
        row["source_anchor"] = _source_anchor(str(raw["stage"]), row["detail"], family)
        events.append(row)
    cleanup_detail: dict[str, Any] = {
        "runtime_removed": not Path(str(fixture["role_root"])).exists(),
        "host_canary_unchanged": not cleanup_errors,
    }
    if cleanup_errors:
        cleanup_detail["cleanup_errors"] = cleanup_errors
    events.append(
        _base_event("cleanup_verified", cleanup_detail, case, attempt, role)
    )
    for ordinal, event in enumerate(events, 1):
        event["event_id"] = f"{event['correlation_id']}:{ordinal}"
        event["ordinal"] = ordinal
    return events


def _transcript_errors(
    provider_rows: list[Mapping[str, Any]],
    case: Mapping[str, Any],
    role: str,
) -> list[str]:
    errors: list[str]
    if not provider_rows:
        return ["AstrBot provider transcript is empty"]
    errors = []
    if not 1 <= len(provider_rows) <= 2:
        errors.append(
            f"AstrBot provider request count drifted: {len(provider_rows)}"
        )
    first = provider_rows[0]
    if first.get("path") != "/v1/chat/completions":
        errors.append("AstrBot provider used an unsupported endpoint")
    if first.get("model") != MODEL_NAME:
        errors.append("AstrBot provider model drifted")
    if first.get("stream") is not True:
        errors.append("AstrBot provider did not use reviewed SSE mode")
    if first.get("authorization_valid") is not True:
        errors.append("AstrBot provider authorization drifted")
    if _tool_name(case) not in set(first.get("tool_names", [])):
        errors.append("real AstrBot provider request did not expose the reviewed tool")
    if first.get("response_kind") != "tool_call":
        errors.append("first AstrBot provider response was not the forced tool call")
    if len(provider_rows) > 1 and provider_rows[1].get("response_kind") != "continuation":
        errors.append("AstrBot provider continuation accounting drifted")
    return errors


def _sink_matches(
    case: Mapping[str, Any],
    role: str,
    sink: Mapping[str, Any] | None,
) -> bool:
    if sink is None or role != "exploit":
        return False
    candidate_id = _candidate_id(case)
    detail = dict(sink.get("detail", {}))
    if candidate_id in {
        "CAND-12536711cca9c235",
        "CAND-1a069517d7740b35",
    }:
        return (
            detail.get("path") == detail.get("expected_path")
            and str(detail.get("path", "")).endswith(
                "data/plugins/demo/skills/SKILL.md"
            )
        )
    if candidate_id == "CAND-36a7affd32f9adf1":
        return (
            detail.get("path") == detail.get("expected_path")
            and detail.get("samefile_with_outside_target") is True
            and str(detail.get("path", "")).endswith(
                "hardlink_to_outside.txt"
            )
        )
    return False


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    process_exit: int,
    cleanup_errors: list[str],
) -> PairOutcome:
    errors = [*cleanup_errors, *_transcript_errors(provider_rows, case, role)]
    if process_exit not in {0, -signal.SIGTERM, -signal.SIGINT, 130, 143}:
        errors.append(f"real AstrBot process exited with {process_exit}")
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
    argument_path = list(case["handler"]["argument_path"])
    value: Any = arguments
    for part in argument_path:
        value = value[part]
    handler = next(
        (row for row in events if row.get("stage") == "handler_entered"), None
    )
    if handler is None or handler.get("detail", {}).get("tool_name") != _tool_name(case):
        errors.append("native AstrBot handler was not entered")
    controlled = next(
        (
            row
            for row in events
            if row.get("stage") == "controlled_argument_recorded"
        ),
        None,
    )
    if controlled is None or controlled.get("detail", {}).get("value") != value:
        errors.append("model-controlled value drifted before the handler sink path")

    gate = next(
        (row for row in events if row.get("stage") == "gate_observed"), None
    )
    if gate is None or gate.get("detail", {}).get("admitted") is not True:
        errors.append("reviewed pathname containment did not admit the carrier")
    expected_gate_ids = _expected_gate_ids(case)
    if gate is not None and gate.get("detail", {}).get("gate_ids") != list(
        expected_gate_ids
    ):
        errors.append("gate identity accounting drifted")
    missing = next(
        (
            row
            for row in events
            if row.get("stage") == "missing_check_boundary_confirmed"
        ),
        None,
    )
    if missing is None or missing.get("detail", {}).get("missing_check") is not True:
        errors.append("missing-check boundary was not recorded")

    sink = next((row for row in events if row.get("stage") == "sink_reached"), None)
    interception = next(
        (row for row in events if row.get("stage") == "pre_effect_interception"), None
    )
    if sink is None or interception is None:
        errors.append("pre-effect sink boundary was incomplete")
    else:
        if sink.get("detail", {}).get("sink_anchor") != _sink_anchor(case):
            errors.append("carrier did not reach the cited terminal sink anchor")
        if interception.get("detail", {}).get("executed") is not False:
            errors.append("sink was not intercepted before execution")

    triggered = _sink_matches(case, role, sink)
    if role == "control" and triggered:
        errors.append("safe control satisfied an exploit-only sink predicate")
    if role == "exploit" and not triggered:
        errors.append("exploit did not satisfy the candidate-specific sink witness")
    return PairOutcome(not errors, triggered, errors)


def _run_role_attempt(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    build_python: Path,
    source_bindings: Mapping[str, str],
    request: AstrBotL2RunRequest,
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
    fixture_server = AstrBotProviderServer(
        role=role,
        tool_name=_tool_name(case),
        arguments=_role_arguments(case, role),
        transcript_path=transcript_path,
    )
    fixture_server.start()
    app_port = _free_loopback_port()
    runtime = directory / "runtime"
    fixture: dict[str, Any] = {}
    process_exit = 124
    try:
        base_url = f"http://127.0.0.1:{fixture_server.port}/v1"
        runtime, home, temporary, session_id, fixture = _prepare_role(
            directory,
            build_project,
            base_url=base_url,
            case=case,
            role=role,
            app_port=app_port,
        )
        _seed_session(
            python=build_python,
            runtime=runtime,
            role_project=runtime,
            session_id=session_id,
        )
        environment = {
            "PATH": f"{build_python.parent}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "HOME": str(home),
            "TMPDIR": str(temporary),
            "ASTRBOT_ROOT": str(runtime),
            "PYTHONPATH": str(runtime),
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "PYTHONUNBUFFERED": "1",
            "CLAWGAP_L2_EVENT_PATH": str(event_path),
            "CLAWGAP_L2_COMPLETE_PATH": str(complete_path),
            "CLAWGAP_L2_CANDIDATE_ID": _candidate_id(case),
            "CLAWGAP_L2_CASE_ID": str(case["case_id"]),
            "CLAWGAP_L2_ATTEMPT": str(attempt),
            "CLAWGAP_L2_ROLE": role,
            "CLAWGAP_L2_CORRELATION_ID": f"{case['case_id']}:{attempt}:{role}",
            "CLAWGAP_L2_FIXTURE_ID": f"astrbot-l2:{case['case_id']}:{role}",
            "CLAWGAP_L2_FAMILY": _family(case),
            "CLAWGAP_L2_GATE_IDS": ",".join(_expected_gate_ids(case)),
            "CLAWGAP_L2_MISSING_CHECK_POLICY": (
                "write-specific-allowed-root-separation"
                if _family(case) != "workspace-hardlink-write"
                else "filesystem-object-or-inode-identity"
            ),
            "CLAWGAP_L2_EXPECTED_SINK_PATH": str(fixture["expected_sink_path"]),
            "CLAWGAP_L2_OUTSIDE_TARGET": str(fixture["outside_target"] or ""),
        }
        process_exit, _output, _chat = _launch_and_prompt(
            runtime=runtime,
            role_project=runtime,
            build_python=build_python,
            case=case,
            role=role,
            attempt=attempt,
            session_id=session_id,
            fixture=fixture,
            environment=environment,
            app_port=app_port,
            timeout=request.timeout,
        )
    except Exception as exc:
        if runtime.exists():
            _cleanup_role(directory, runtime)
        fixture_server.stop()
        return PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []
    finally:
        fixture_server.stop()

    raw_events = _read_jsonl(event_path)
    provider_rows = _read_jsonl(transcript_path)
    fixture_errors = _verify_fixture(runtime, fixture)
    cleanup_errors = [*fixture_errors, *_cleanup_role(directory, runtime)]
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


def _reproduction_command(request: AstrBotL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-astrbot-l2"
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
        if path.is_file() and path.name not in {"manifest.json"}
    }


def run_astrbot_l2(request: AstrBotL2RunRequest) -> dict[str, Any]:
    started = time.time()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError(
            "AstrBot targeted L2 timeouts and attempts must be positive"
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
        published_build_dir = request.out_dir.resolve() / "build"
        _remove_path(published_build_dir)
        published_build_dir.mkdir(parents=True)
        shutil.copyfile(
            actual_build_dir / "transformed-source-manifest.json",
            published_build_dir / "transformed-source-manifest.json",
        )
    else:
        shutil.copyfile(
            actual_build_dir / "transformed-source-manifest.json",
            request.out_dir.resolve() / "transformed-source-manifest.json",
        )

    results: list[dict[str, Any]] = []
    for case in cases:
        candidate_id = _candidate_id(case)
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
                "candidate_id": candidate_id,
                "case_id": case["case_id"],
                "project": "AstrBot",
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
                    else sum(
                        2
                        for outcome in pair_outcomes
                        if not outcome.healthy
                    ),
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
                "project": "AstrBot",
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
        path
        for path in (request.out_dir / "runs").rglob("*")
        if path.name == "runtime"
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
    artifact_hashes = _artifact_hashes(request.out_dir.resolve())
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-astrbot-l2-manifest/v1",
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
            "src/runtime_validation/astrbot_l2.py": sha256_file(
                REPO_ROOT / "src/runtime_validation/astrbot_l2.py"
            )
        },
        "transformed_source_manifest": build_manifest,
        "credential_scan": credential_scan,
        "disposable_workspaces_removed": disposable_workspaces_removed,
        "artifact_sha256": artifact_hashes,
        "reproduction_command": _reproduction_command(request),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "completed_at": _utc_now(),
    }
    atomic_write_json(request.out_dir.resolve() / "manifest.json", manifest)
    return manifest
