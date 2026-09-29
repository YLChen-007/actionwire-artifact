"""Targeted forced-provider L2 runtime for linked CowAgent candidates."""

from __future__ import annotations

import json
import os
import select
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
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
    redact_value,
    redact_text,
    sha256_file,
)
from .campaign_contracts import canonical_json, digest


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("chatgpt-on-wechat")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
HISTORICAL_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/coverage-comparison/training-regression-candidates.jsonl"
)
TARGET_CANDIDATES = (
    "CAND-2b4f8af87ad95c56",
    "CAND-7afa41ea2e82453d",
    "CAND-70cbbd81dff4ec04",
    "CAND-c93d316d66e49992",
    "CAND-f4a49abfcf4c992c",
    "CAND-ff3a7b0ab4b0a449",
)
HISTORICAL_TARGET_CANDIDATES = (
    "CAND-34bd5e2a040b5664",
    "CAND-0e7d7aea6fed1ab0",
)
CURRENT_CAMPAIGN_ID = "runtime-dynamic-trigger-chatgpt-on-wechat-l2-v1"
HISTORICAL_CAMPAIGN_ID = (
    "runtime-dynamic-trigger-chatgpt-on-wechat-historical-l2-v1"
)
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-chatgpt-on-wechat-l2-result/v1"
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-chatgpt-on-wechat-l2-event/v1"
MODEL_NAME = "clawgap-cowagent-l2"
VISION_MODEL_NAME = "gpt-clawgap-vision-l2"
CANARY_CONTENT = "clawgap-chatgpt-on-wechat-host-canary\n"
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
    "sink_reached",
    "pre_effect_interception",
    "target_completed",
    "cleanup_verified",
)
FAMILIES = {
    "CAND-2b4f8af87ad95c56": "read",
    "CAND-7afa41ea2e82453d": "read-missing-check",
    "CAND-70cbbd81dff4ec04": "bash-retry",
    "CAND-c93d316d66e49992": "bash-retry",
    "CAND-f4a49abfcf4c992c": "bash-primary",
    "CAND-ff3a7b0ab4b0a449": "bash-primary",
    "CAND-34bd5e2a040b5664": "web-fetch-missing-check",
    "CAND-0e7d7aea6fed1ab0": "vision-missing-check",
}


@dataclass(frozen=True)
class ChatGPTOnWeChatL2RunRequest:
    campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    out_dir: Path = ...
    attempts: int = 3
    timeout: int = 120
    build_timeout: int = 1800
    candidate_id: str | None = None
    build_dir: Path | None = None
    historical: bool = False


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
            f"cannot read CowAgent L2 artifact {path}: {exc}"
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


def _historical_case(row: Mapping[str, Any]) -> dict[str, Any]:
    candidate_id = str(row["candidate_id"])
    if candidate_id == "CAND-34bd5e2a040b5664":
        case_id = "AL2-cowagent-webfetch-ssrf-v1"
        tool_name = "web_fetch"
        forced = [
            {
                "role": "exploit",
                "arguments": {
                    "url": "http://127.0.0.1/clawgap-special-use-marker"
                },
            },
            {
                "role": "control",
                "arguments": {
                    "url": "https://clawgap-public-control.invalid/safe-page"
                },
            },
        ]
        sink_anchor = "agent/tools/web_fetch/web_fetch.py:121"
        argument_path = ["url"]
    elif candidate_id == "CAND-0e7d7aea6fed1ab0":
        case_id = "AL2-cowagent-vision-ssrf-v1"
        tool_name = "vision"
        forced = [
            {
                "role": "exploit",
                "arguments": {
                    "image": "http://127.0.0.1/clawgap-special-use-image.jpg",
                    "question": "Describe the reviewed fixture image.",
                },
            },
            {
                "role": "control",
                "arguments": {
                    "image": (
                        "https://clawgap-public-control.invalid/safe-image.jpg"
                    ),
                    "question": "Describe the reviewed safe image.",
                },
            },
        ]
        sink_anchor = "agent/tools/vision/vision.py:600"
        argument_path = ["image"]
    else:
        raise ValidationError("unsupported historical CowAgent candidate")
    return {
        "schema_version": "clawgap-dynamic-trigger-chatgpt-on-wechat-l2-case/v1",
        "project": "chatgpt-on-wechat",
        "revision": PROJECT.analysis_revision,
        "case_id": case_id,
        "candidate_binding": {
            "candidate_id": candidate_id,
            "row_sha256": digest(row),
        },
        "handler": {
            "argument_path": argument_path,
            "id": row.get("handler_id"),
            "tool_name": tool_name,
        },
        "gates": [],
        "sink": {"family": "network-request", "payload_role": "url"},
        "tool_or_action_name": tool_name,
        "forced_tool_calls": forced,
        "family": FAMILIES[candidate_id],
        "sink_anchor": sink_anchor,
        "historical_post_hoc": True,
        "execution_eligible": True,
    }


def _select_cases(
    campaign: Path,
    candidate_id: str | None = None,
    historical: bool = False,
) -> list[dict[str, Any]]:
    if not historical:
        cases = _read_jsonl(campaign / "cases.jsonl")
        selected = {
            str(row.get("candidate_binding", {}).get("candidate_id")): row
            for row in cases
            if row.get("project") == "chatgpt-on-wechat"
        }
        expected = set(TARGET_CANDIDATES)
        if not expected.issubset(selected):
            missing = sorted(expected - set(selected))
            raise ValidationError(
                "CowAgent targeted L2 source campaign is missing GT-linked "
                "candidates: " + ", ".join(missing)
            )
        if candidate_id is not None:
            if candidate_id in HISTORICAL_TARGET_CANDIDATES:
                return [selected[candidate_id]]
            if candidate_id not in expected:
                raise ValidationError(
                    "requested CowAgent candidate is not a current GT-linked "
                    "targeted L2 candidate"
                )
            return [selected[candidate_id]]
        return [selected[item] for item in TARGET_CANDIDATES]

    rows = _read_jsonl(campaign)
    selected = {
        str(row.get("candidate_id")): row
        for row in rows
        if row.get("project") == "chatgpt-on-wechat"
    }
    expected = set(HISTORICAL_TARGET_CANDIDATES)
    if not expected.issubset(selected):
        raise ValidationError("historical CowAgent candidate rows are missing")
    ids = (
        (candidate_id,)
        if candidate_id is not None
        else HISTORICAL_TARGET_CANDIDATES
    )
    if candidate_id is not None and candidate_id not in expected:
        raise ValidationError(
            "requested candidate is not an admitted historical CowAgent overlay ID"
        )
    return [_historical_case(selected[item]) for item in ids]


def _source_bindings(cases: list[Mapping[str, Any]]) -> dict[str, str]:
    required_files = {
        "requirements.txt",
        "app.py",
        "config.py",
        "channel/terminal/terminal_channel.py",
        "channel/chat_channel.py",
        "bridge/agent_bridge.py",
        "bridge/agent_initializer.py",
        "agent/protocol/agent_stream.py",
        "agent/tools/tool_manager.py",
        "agent/tools/base_tool.py",
        "models/openai/openai_http_client.py",
        "models/openai_compatible_bot.py",
        "agent/tools/bash/bash.py",
        "agent/tools/read/read.py",
        "agent/tools/web_fetch/web_fetch.py",
        "agent/tools/vision/vision.py",
        "agent/tools/browser/browser_tool.py",
    }
    for case in cases:
        if case.get("revision") != PROJECT.analysis_revision:
            raise ValidationError("CowAgent case revision does not match registry")
    bindings: dict[str, str] = {}
    for relative in sorted(required_files):
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"CowAgent bound source is missing: {relative}")
        bindings[relative] = sha256_file(source)
    browser_source = (
        SOURCE_ROOT / "agent/tools/browser/browser_tool.py"
    ).read_text(encoding="utf-8")
    if 'url = "https://" + url' not in browser_source:
        raise ValidationError(
            "CowAgent browser source no longer contains the reviewed non-http(s) "
            "URL rewrite contradiction"
        )
    return bindings


def _replace_once(
    source: str, old: str, new: str, label: str
) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(
            f"CowAgent instrumentation marker mismatch ({label}): {count}"
        )
    return source.replace(old, new, 1)


def _instrumentation_helper() -> str:
    return r'''import builtins
import io
import json
import os
import subprocess
import time

import requests


_original_run = subprocess.run
_original_open = builtins.open
_original_requests_get = requests.get
_state = {
    "tool": None,
    "value": None,
    "sink_anchor": None,
}


class _FakeResponse:
    status_code = 200
    headers = {"Content-Type": "text/html; charset=utf-8"}
    content = b"clawgap intercepted fixture"
    text = "clawgap intercepted fixture"
    encoding = "utf-8"

    def raise_for_status(self):
        return None


def _event(stage, detail):
    path = os.environ.get("CLAWGAP_L2_EVENT_PATH")
    if not path:
        return
    row = {
        "schema_version": "clawgap-dynamic-trigger-chatgpt-on-wechat-l2-event/v1",
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


def _emit_sink(anchor, detail):
    payload = dict(detail)
    payload["sink_anchor"] = anchor
    _event("sink_reached", payload)
    _event("pre_effect_interception", {**payload, "executed": False})
    _event("target_completed", {"sink_anchor": anchor})
    _complete()


def clawgap_native_dispatch(tool_name, arguments):
    _event(
        "registry_or_native_dispatch",
        {"tool_name": tool_name, "runtime": "AgentStreamExecutor"},
    )


def clawgap_handler(tool_name, arguments):
    _state["tool"] = tool_name
    _state["value"] = None
    _event("handler_entered", {"tool_name": tool_name, "arguments": arguments})


def clawgap_controlled(argument_path, value, resolved=None):
    _state["value"] = value
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
    _event("missing_check_boundary_confirmed", {"missing_check": True, **detail})


def _intercept_run(*args, **kwargs):
    family = os.environ.get("CLAWGAP_L2_FAMILY", "")
    role = os.environ.get("CLAWGAP_L2_ROLE", "")
    if _state.get("tool") != "bash":
        return _original_run(*args, **kwargs)
    command = args[0] if args else kwargs.get("args")
    is_retry = isinstance(command, (list, tuple))
    if family == "bash-retry" and not is_retry:
        if role == "exploit":
            return subprocess.CompletedProcess(args, 126, "", "")
        _emit_sink(
            "agent/tools/bash/bash.py:116",
            {"command": command, "argv": [str(command)]},
        )
        return subprocess.CompletedProcess(
            args, 0, "clawgap intercepted safe control\n", ""
        )
    anchor = (
        "agent/tools/bash/bash.py:142"
        if family == "bash-retry"
        else "agent/tools/bash/bash.py:116"
    )
    detail = {
        "command": command,
        "argv": [str(item) for item in command] if is_retry else [str(command)],
        "retry_list": is_retry,
    }
    _emit_sink(anchor, detail)
    return subprocess.CompletedProcess(
        args, 0, "clawgap intercepted safe carrier\n", ""
    )


def _intercept_open(*args, **kwargs):
    value = args[0] if args else kwargs.get("file")
    if _state.get("tool") == "read" and value == os.environ.get(
        "CLAWGAP_L2_RESOLVED_VALUE"
    ):
        _emit_sink(
            "agent/tools/read/read.py:248",
            {"path": value, "read_mode": "text"},
        )
        return io.StringIO("clawgap intercepted read fixture\n")
    return _original_open(*args, **kwargs)


def _intercept_get(*args, **kwargs):
    url = args[0] if args else kwargs.get("url")
    if _state.get("tool") in {"web_fetch", "vision"} and url == _state.get("value"):
        if _state["tool"] == "web_fetch":
            anchor = "agent/tools/web_fetch/web_fetch.py:121"
        else:
            anchor = "agent/tools/vision/vision.py:600"
        _emit_sink(anchor, {"url": url, "method": "GET"})
        return _FakeResponse()
    return _original_requests_get(*args, **kwargs)


subprocess.run = _intercept_run
builtins.open = _intercept_open
requests.get = _intercept_get
'''


def _instrument_project(project: Path) -> dict[str, str]:
    helper_path = project / "clawgap_l2_runtime.py"
    atomic_write_text(helper_path, _instrumentation_helper())

    app_path = project / "app.py"
    app_source = app_path.read_text(encoding="utf-8")
    app_source = _replace_once(
        app_source,
        "import os\nimport signal\nimport sys\nimport time\n",
        "import os\nimport signal\nimport sys\nimport time\n\nimport clawgap_l2_runtime\n",
        "app runtime bootstrap",
    )
    app_path.write_text(app_source, encoding="utf-8")

    initializer_path = project / "bridge/agent_initializer.py"
    initializer_source = initializer_path.read_text(encoding="utf-8")
    initializer_source = _replace_once(
        initializer_source,
        '    def _setup_memory_system(self, workspace_root: str, session_id: Optional[str] = None):\n        """\n        Setup memory system\n        \n        Returns:\n            (memory_manager, memory_tools) tuple\n        """\n        memory_manager = None\n',
        '    def _setup_memory_system(self, workspace_root: str, session_id: Optional[str] = None):\n        """\n        Setup memory system\n        \n        Returns:\n            (memory_manager, memory_tools) tuple\n        """\n        return None, []\n        memory_manager = None\n',
        "disable irrelevant memory embedding adapter",
    )
    initializer_path.write_text(initializer_source, encoding="utf-8")

    stream_path = project / "agent/protocol/agent_stream.py"
    stream_source = stream_path.read_text(encoding="utf-8")
    stream_source = (
        "from clawgap_l2_runtime import clawgap_native_dispatch\n"
        + stream_source
    )
    stream_source = _replace_once(
        stream_source,
        '        tool_name = tool_call["name"]\n        tool_id = tool_call["id"]\n        arguments = tool_call["arguments"]\n',
        '        tool_name = tool_call["name"]\n        tool_id = tool_call["id"]\n        arguments = tool_call["arguments"]\n        clawgap_native_dispatch(tool_name, arguments)\n',
        "AgentStream native dispatch",
    )
    stream_path.write_text(stream_source, encoding="utf-8")

    bash_path = project / "agent/tools/bash/bash.py"
    bash_source = bash_path.read_text(encoding="utf-8")
    bash_source = (
        "from clawgap_l2_runtime import clawgap_controlled, clawgap_gate, clawgap_handler\n"
        + bash_source
    )
    bash_source = _replace_once(
        bash_source,
        '        command = args.get("command", "").strip()\n        timeout = args.get("timeout", self.default_timeout)\n',
        '        command = args.get("command", "").strip()\n        timeout = args.get("timeout", self.default_timeout)\n        clawgap_handler("bash", args)\n        clawgap_controlled(["command"], command)\n',
        "Bash handler entry",
    )
    bash_source = _replace_once(
        bash_source,
        '            warning = self._get_safety_warning(command)\n            if warning:\n',
        '            warning = self._get_safety_warning(command)\n            clawgap_gate(\n                "bash_safety_warning",\n                {"command": command, "warning": warning, "admitted": not warning},\n            )\n            if warning:\n',
        "Bash safety gate",
    )
    bash_path.write_text(bash_source, encoding="utf-8")

    read_path = project / "agent/tools/read/read.py"
    read_source = read_path.read_text(encoding="utf-8")
    read_source = (
        "from clawgap_l2_runtime import (\n"
        "    clawgap_controlled,\n"
        "    clawgap_gate,\n"
        "    clawgap_handler,\n"
        "    clawgap_missing_check,\n"
        ")\n"
        + read_source
    )
    read_source = _replace_once(
        read_source,
        '        path = args.get("path", "") or args.get("location", "")\n        path = path.strip() if isinstance(path, str) else ""\n',
        '        path = args.get("path", "") or args.get("location", "")\n        path = path.strip() if isinstance(path, str) else ""\n        clawgap_handler("read", args)\n',
        "Read handler entry",
    )
    read_source = _replace_once(
        read_source,
        '        absolute_path = self._resolve_path(path)\n        \n        # Security check: Prevent reading sensitive config files\n',
        '        absolute_path = self._resolve_path(path)\n        clawgap_controlled(["path"], path, absolute_path)\n        os.environ["CLAWGAP_L2_RESOLVED_VALUE"] = absolute_path\n        clawgap_missing_check({"policy": "general-sensitive-file-or-procfs-identity-validation", "path": absolute_path})\n        \n        # Security check: Prevent reading sensitive config files\n',
        "Read controlled argument and missing sensitive-file boundary",
    )
    read_source = _replace_once(
        read_source,
        '        # Check if file exists\n        if not os.path.exists(absolute_path):\n',
        '        clawgap_gate("read_env_deny", {"path": absolute_path, "admitted": True})\n        # Check if file exists\n        if not os.path.exists(absolute_path):\n',
        "Read env deny gate",
    )
    read_source = _replace_once(
        read_source,
        '        # Check file type\n        file_ext = Path(absolute_path).suffix.lower()\n',
        '        clawgap_gate(\n            "read_existence_and_readability",\n            {"path": absolute_path, "checks": ["existence", "readability"], "admitted": True},\n        )\n        # Check file type\n        file_ext = Path(absolute_path).suffix.lower()\n',
        "Read existence and readability gates",
    )
    read_path.write_text(read_source, encoding="utf-8")

    web_path = project / "agent/tools/web_fetch/web_fetch.py"
    web_source = web_path.read_text(encoding="utf-8")
    web_source = (
        "from clawgap_l2_runtime import (\n"
        "    clawgap_controlled,\n"
        "    clawgap_gate,\n"
        "    clawgap_handler,\n"
        "    clawgap_missing_check,\n"
        ")\n"
        + web_source
    )
    web_source = _replace_once(
        web_source,
        '        url = args.get("url", "").strip()\n        if not url:\n',
        '        clawgap_handler("web_fetch", args)\n        url = args.get("url", "").strip()\n        clawgap_controlled(["url"], url)\n        if not url:\n',
        "WebFetch handler entry",
    )
    web_source = _replace_once(
        web_source,
        '        if parsed.scheme not in ("http", "https"):\n            return ToolResult.fail("Error: Invalid URL (must start with http:// or https://)")\n\n        if _is_document_url(url):\n',
        '        if parsed.scheme not in ("http", "https"):\n            return ToolResult.fail("Error: Invalid URL (must start with http:// or https://)")\n        clawgap_gate("web_fetch_scheme", {"url": url, "admitted": True})\n        clawgap_missing_check({"policy": "resolved-destination-ssrf-validation", "url": url})\n\n        if _is_document_url(url):\n',
        "WebFetch scheme gate and missing SSRF boundary",
    )
    web_path.write_text(web_source, encoding="utf-8")

    vision_path = project / "agent/tools/vision/vision.py"
    vision_source = vision_path.read_text(encoding="utf-8")
    vision_source = (
        "from clawgap_l2_runtime import (\n"
        "    clawgap_controlled,\n"
        "    clawgap_handler,\n"
        "    clawgap_missing_check,\n"
        ")\n"
        + vision_source
    )
    vision_source = _replace_once(
        vision_source,
        '        image = args.get("image", "").strip()\n        question = args.get("question", "").strip()\n',
        '        clawgap_handler("vision", args)\n        image = args.get("image", "").strip()\n        question = args.get("question", "").strip()\n        clawgap_controlled(["image"], image)\n',
        "Vision handler entry",
    )
    vision_source = _replace_once(
        vision_source,
        '        if image.startswith(("http://", "https://")):\n            return self._download_to_data_url(image)\n',
        '        if image.startswith(("http://", "https://")):\n            clawgap_missing_check({"policy": "resolved-destination-ssrf-validation", "url": image})\n            return self._download_to_data_url(image)\n',
        "Vision missing SSRF boundary",
    )
    vision_path.write_text(vision_source, encoding="utf-8")

    transformed_files = (
        "clawgap_l2_runtime.py",
        "app.py",
        "bridge/agent_initializer.py",
        "agent/protocol/agent_stream.py",
        "agent/tools/bash/bash.py",
        "agent/tools/read/read.py",
        "agent/tools/web_fetch/web_fetch.py",
        "agent/tools/vision/vision.py",
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
            ".agentfuzz-main-venv",
            "node_modules",
            "run.log",
        ),
    )
    transformed = _instrument_project(project)
    return {
        "schema_version": (
            "clawgap-chatgpt-on-wechat-transformed-source-manifest/v1"
        ),
        "revision": PROJECT.analysis_revision,
        "original": dict(source_bindings),
        "transformed": transformed,
        "runtime_adapter": (
            "disable irrelevant memory embeddings in the disposable role copy"
        ),
        "browser_file_scheme_boundary": "planning-blocked-source-contradiction",
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
    harness_sha256 = sha256_file(
        REPO_ROOT / "src/runtime_validation/chatgpt_on_wechat_l2.py"
    )
    requirements_sha256 = sha256_file(SOURCE_ROOT / "requirements.txt")
    manifest_path = directory / "transformed-source-manifest.json"
    venv_python = directory / ".clawgap-venv/bin/python"
    if manifest_path.is_file() and venv_python.is_file():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version")
            == "clawgap-chatgpt-on-wechat-transformed-source-manifest/v1"
            and prior.get("revision") == PROJECT.analysis_revision
            and prior.get("original") == dict(source_bindings)
            and prior.get("dependency_requirements_sha256") == requirements_sha256
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
            f"CowAgent disposable Python environment failed: {bootstrap.returncode}"
        )
    install = _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-r",
            str(SOURCE_ROOT / "requirements.txt"),
        ],
        cwd=directory,
        log_path=directory / "pip-install.log",
        timeout=timeout,
        env={
            "PATH": f"{venv_dir / 'bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "HOME": str(directory / "build-home"),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "NO_COLOR": "1",
        },
    )
    if install.returncode != 0:
        raise ValidationError(
            f"CowAgent dependency installation failed: {install.returncode}"
        )
    probe = _run(
        [
            str(venv_python),
            "-c",
            "import aiohttp, requests, PIL, dotenv, yaml, web; import app",
        ],
        cwd=directory / "project",
        log_path=directory / "build-probe.log",
        timeout=60,
    )
    if probe.returncode != 0:
        raise ValidationError("instrumented CowAgent build probe failed")
    (directory / "build-home").mkdir(parents=True, exist_ok=True)
    manifest.update(
        {
            "build_exit_code": install.returncode,
            "dependency_requirements_sha256": requirements_sha256,
            "harness_sha256": harness_sha256,
            "interpreter_sha256": sha256_file(venv_python),
            "python_version": _run(
                [str(venv_python), "--version"],
                cwd=directory,
                log_path=directory / "python-version.log",
                timeout=10,
            ).stdout.strip(),
        }
    )
    atomic_write_json(manifest_path, manifest)
    shutil.rmtree(directory / "build-home")
    return manifest


class CowAgentFixtureServer:
    """Loopback OpenAI fixture for the real CowAgent HTTP client."""

    def __init__(
        self,
        *,
        role: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        family: str,
        transcript_path: Path,
    ):
        self.role = role
        self.tool_name = tool_name
        self.arguments = dict(arguments)
        self.family = family
        self.transcript_path = transcript_path
        self.requests: list[str] = []
        self.valid_request = False
        self.unsupported: list[str] = []
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:
                return

            def _record(
                self,
                body: str,
                request_kind: str,
                valid: bool,
                reason: str = "",
            ) -> None:
                row = canonical_json(
                    {
                        "schema_version": (
                            "clawgap-chatgpt-on-wechat-provider-transcript/v1"
                        ),
                        "timestamp": _utc_now(),
                        "method": self.command,
                        "path": self.path,
                        "request_kind": request_kind,
                        "authorization": "Bearer [REDACTED_CREDENTIAL]",
                        "valid": valid,
                        "reason": reason,
                        "body": redact_value(
                            json.loads(body) if body else None,
                            secrets=("clawgap-loopback-mock",),
                        ),
                    }
                )
                with server.transcript_path.open("a", encoding="utf-8") as stream:
                    stream.write(row + "\n")

            def _error(self, message: str, status: int) -> None:
                payload = json.dumps(
                    {"error": {"message": message, "type": "clawgap_invalid_request"}}
                ).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _sse(self, chunks: list[dict[str, Any]]) -> None:
                payload = "".join(
                    f"data: {json.dumps(chunk, sort_keys=True)}\n\n"
                    for chunk in chunks
                ).encode("utf-8")
                payload += b"data: [DONE]\n\n"
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("cache-control", "no-cache")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _json(self, value: Mapping[str, Any]) -> None:
                payload = json.dumps(value, sort_keys=True).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _route(self) -> None:
                path = self.path.split("?", 1)[0]
                size = int(self.headers.get("content-length") or 0)
                raw = (
                    self.rfile.read(size).decode("utf-8", errors="replace")
                    if size
                    else ""
                )
                if self.command != "POST" or path != "/v1/chat/completions":
                    server.unsupported.append(f"{self.command} {path}")
                    self._record(raw, "unsupported", False, "unsupported endpoint")
                    self._error("CowAgent fixture endpoint is not implemented", 404)
                    return
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    body = None
                if not isinstance(body, dict):
                    self._record(raw, "invalid", False, "invalid JSON")
                    self._error("invalid request body", 400)
                    return
                tools = body.get("tools") or []
                tool_names = {
                    str(row.get("function", {}).get("name"))
                    for row in tools
                    if isinstance(row, dict)
                }
                messages = body.get("messages")
                has_tool_result = any(
                    isinstance(row, dict) and row.get("role") == "tool"
                    for row in messages
                    if isinstance(messages, list)
                )
                has_image_content = any(
                    isinstance(part, dict) and part.get("type") == "image_url"
                    for row in messages
                    if isinstance(row, dict)
                    for part in row.get("content") or []
                    if isinstance(row.get("content"), list)
                )
                if not has_tool_result and tools and server.tool_name in tool_names:
                    request_kind = "forced-tool-call"
                elif has_image_content and not tools:
                    request_kind = "vision-backend"
                elif has_tool_result:
                    request_kind = "continuation"
                else:
                    request_kind = "unknown"

                expected_model = (
                    VISION_MODEL_NAME
                    if request_kind == "vision-backend"
                    else MODEL_NAME
                )
                valid = (
                    body.get("model") == expected_model
                    and isinstance(messages, list)
                    and bool(messages)
                    and self.headers.get("Authorization")
                    == "Bearer clawgap-loopback-mock"
                    and (
                        request_kind != "forced-tool-call"
                        or body.get("stream") is True
                    )
                )
                server.valid_request = server.valid_request or valid
                self._record(
                    raw,
                    request_kind,
                    valid,
                    "" if valid else "provider request drift",
                )
                if not valid or request_kind == "unknown":
                    self._error("request does not match CowAgent fixture contract", 400)
                    return

                with server._lock:
                    server.requests.append(request_kind)
                    number = len(server.requests)
                expected_vision = server.family == "vision-missing-check"
                allowed = (
                    ["forced-tool-call", "vision-backend", "continuation"]
                    if expected_vision
                    else ["forced-tool-call", "continuation"]
                )
                if number > len(allowed) or request_kind != allowed[number - 1]:
                    self._error("provider request sequence drift", 409)
                    return
                if request_kind == "forced-tool-call":
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
                                {"index": 0, "delta": {}, "finish_reason": "tool_calls"}
                            ],
                        },
                    ]
                    self._sse(chunks)
                    return
                if request_kind == "vision-backend":
                    self._json(
                        {
                            "id": "chatcmpl-clawgap-vision-backend",
                            "object": "chat.completion",
                            "model": MODEL_NAME,
                            "choices": [
                                {
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": "clawgap safe image fixture",
                                    },
                                    "finish_reason": "stop",
                                }
                            ],
                        }
                    )
                    return
                self._sse(
                    [
                        {
                            "id": "chatcmpl-clawgap-final",
                            "object": "chat.completion.chunk",
                            "created": 1,
                            "model": MODEL_NAME,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"content": "done"},
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
                    ]
                )

            do_GET = _route
            do_POST = _route
            do_PUT = _route
            do_PATCH = _route
            do_DELETE = _route

        return Handler

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        shutdown = threading.Thread(target=self._server.shutdown, daemon=True)
        shutdown.start()
        shutdown.join(timeout=0.5)
        self._server.server_close()
        self._thread.join(timeout=0.5)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])


def _family(case: Mapping[str, Any]) -> str:
    return FAMILIES[str(case["candidate_binding"]["candidate_id"])]


def _role_arguments(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    return dict(
        next(row for row in case["forced_tool_calls"] if row["role"] == role)[
            "arguments"
        ]
    )


def _tool_name(case: Mapping[str, Any]) -> str:
    return str(case.get("tool_or_action_name") or case["handler"]["tool_name"])


def _sink_anchor(case: Mapping[str, Any]) -> str:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    if candidate_id in {"CAND-70cbbd81dff4ec04", "CAND-c93d316d66e49992"}:
        return "agent/tools/bash/bash.py:142"
    if candidate_id in {"CAND-f4a49abfcf4c992c", "CAND-ff3a7b0ab4b0a449"}:
        return "agent/tools/bash/bash.py:116"
    if candidate_id in {"CAND-2b4f8af87ad95c56", "CAND-7afa41ea2e82453d"}:
        return "agent/tools/read/read.py:248"
    if candidate_id == "CAND-34bd5e2a040b5664":
        return "agent/tools/web_fetch/web_fetch.py:121"
    if candidate_id == "CAND-0e7d7aea6fed1ab0":
        return "agent/tools/vision/vision.py:600"
    raise ValidationError("unsupported CowAgent sink family")


def _expected_gate_ids(case: Mapping[str, Any]) -> list[str]:
    return [str(row["id"]) for row in case.get("gates", [])]


def _base_event(
    stage: str,
    detail: Mapping[str, Any],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
) -> dict[str, Any]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": f"{case['case_id']}:{attempt}:{role}:{stage}",
        "stage": stage,
        "candidate_id": candidate_id,
        "case_id": case["case_id"],
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{case['case_id']}:{attempt}:{role}",
        "fixture_id": f"chatgpt-on-wechat-l2:{case['case_id']}:{role}",
        "detail": dict(detail),
    }


def _expected_stages(case: Mapping[str, Any]) -> list[str]:
    stages = list(NORMALIZED_STAGES)
    if not _expected_gate_ids(case):
        index = stages.index("gate_observed")
        stages[index] = "missing_check_boundary_confirmed"
    return stages


def _normalize_events(
    raw_events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    fixture_files: Mapping[str, str],
) -> list[dict[str, Any]]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    events: list[dict[str, Any]] = []
    for stage, detail in (
        ("case_bound", {"candidate_id": candidate_id}),
        ("source_verified", {"revision": case["revision"]}),
        (
            "fixture_prepared",
            {"files": {key: "sha256" for key in sorted(fixture_files)}},
        ),
        ("launch_started", {"entrypoint": "python app.py", "channel": "terminal"}),
        ("prompt_received", {"message": "environment probe"}),
    ):
        events.append(_base_event(stage, detail, case, attempt, role))

    forced_request = next(
        (
            row
            for row in provider_rows
            if row.get("request_kind") == "forced-tool-call"
        ),
        None,
    )
    if forced_request is None:
        raise RuntimeError("real CowAgent provider client did not issue a tool request")
    events.append(
        _base_event(
            "provider_request",
            {
                "method": forced_request["method"],
                "path": forced_request["path"],
                "protocol": "openai-chat-completions/v1",
                "body_model": forced_request.get("body", {}).get("model"),
                "request_kind": forced_request.get("request_kind"),
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
            },
            case,
            attempt,
            role,
        )
    )

    def raw(stage: str) -> list[Mapping[str, Any]]:
        return [row for row in raw_events if row.get("stage") == stage]

    native = raw("registry_or_native_dispatch")
    if len(native) != 1:
        raise RuntimeError("native AgentStream dispatch was not observed exactly once")
    events.append(dict(native[0]))
    for stage in ("handler_entered", "controlled_argument_recorded"):
        rows = raw(stage)
        if len(rows) != 1:
            raise RuntimeError(f"{stage} was not observed exactly once")
        events.append(dict(rows[0]))
    gate_rows = raw("gate_observed")
    missing_rows = raw("missing_check_boundary_confirmed")
    if _expected_gate_ids(case):
        if not gate_rows:
            raise RuntimeError("cited CowAgent gates were not observed")
        observed_ids = {
            item
            for row in gate_rows
            for item in row.get("detail", {}).get("gate_ids", [])
        }
        if observed_ids != set(_expected_gate_ids(case)):
            raise RuntimeError("observed CowAgent gate identity drift")
        events.append(
            _base_event(
                "gate_observed",
                {
                    "gate_ids": _expected_gate_ids(case),
                    "observations": [
                        dict(row.get("detail", {})) for row in gate_rows
                    ],
                },
                case,
                attempt,
                role,
            )
        )
    else:
        if not missing_rows:
            raise RuntimeError("missing-check boundary was not observed")
        events.append(
            _base_event(
                "missing_check_boundary_confirmed",
                {
                    "missing_check": True,
                    "observations": [
                        dict(row.get("detail", {})) for row in missing_rows
                    ],
                },
                case,
                attempt,
                role,
            )
        )
    for stage in (
        "sink_reached",
        "pre_effect_interception",
        "target_completed",
    ):
        rows = raw(stage)
        if len(rows) != 1:
            raise RuntimeError(f"{stage} was not observed exactly once")
        events.append(dict(rows[0]))
    events.append(
        _base_event(
            "cleanup_verified",
            {"canary_healthy": True, "disposable_roots_removed": True},
            case,
            attempt,
            role,
        )
    )
    identity = {
        "candidate_id": candidate_id,
        "case_id": case["case_id"],
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{case['case_id']}:{attempt}:{role}",
        "fixture_id": f"chatgpt-on-wechat-l2:{case['case_id']}:{role}",
    }
    for ordinal, event in enumerate(events, 1):
        for key, value in identity.items():
            event[key] = value
        event["ordinal"] = ordinal
        event["process_identity"] = "cowagent-app"
        event["source_anchor"] = str(
            event.get("detail", {}).get("sink_anchor")
            or (
                "agent/protocol/agent_stream.py:929"
                if event["stage"] == "registry_or_native_dispatch"
                else "app.py"
            )
        )
    return events


def _cowagent_config(base_url: str, workspace: Path, state: Path) -> str:
    return json.dumps(
        {
            "channel_type": "terminal",
            "bot_type": "openai",
            "model": MODEL_NAME,
            "open_ai_api_key": "clawgap-loopback-mock",
            "open_ai_api_base": base_url,
            "single_chat_prefix": [""],
            "group_chat_prefix": [""],
            "web_console": False,
            "use_linkai": False,
            "knowledge": False,
            "speech_recognition": False,
            "always_reply_voice": False,
            "agent": True,
            "agent_workspace": str(workspace),
            "agent_max_steps": 3,
            "enable_thinking": False,
            "appdata_dir": str(state / "appdata"),
            "proxy": "",
            "tools": {
                "bash": {"cwd": str(workspace), "safety_mode": True},
                "read": {"cwd": str(workspace)},
                "web_fetch": {"cwd": str(workspace)},
                "vision": {},
            },
            "tool": {"vision": {"model": VISION_MODEL_NAME}},
        },
        indent=2,
        sort_keys=True,
    )


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _prepare_role(
    directory: Path,
    base_url: str,
    case: Mapping[str, Any],
    role: str,
    build_project: Path,
) -> tuple[dict[str, str], Path, Path, Path, Path, Path]:
    runtime = directory / "runtime"
    project = runtime / "project"
    home = directory / "home"
    state = directory / "state"
    workspace = directory / "workspace"
    temporary = directory / "tmp"
    runtime.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        build_project,
        project,
        ignore=shutil.ignore_patterns("__pycache__", "run.log"),
    )
    for path in (home, state, workspace, temporary):
        path.mkdir(parents=True, exist_ok=True)

    arguments = _role_arguments(case, role)
    if arguments.get("path") == "/tmp/control.txt":
        atomic_write_text(temporary / "control.txt", "clawgap safe control\n")
    config_path = project / "config.json"
    atomic_write_text(config_path, _cowagent_config(base_url, workspace, state))
    canary = directory / "host-effect-canary.txt"
    atomic_write_text(canary, CANARY_CONTENT)
    fixture_files = {
        str(config_path): sha256_file(config_path),
        str(canary): sha256_file(canary),
    }
    if (temporary / "control.txt").is_file():
        fixture_files[str(temporary / "control.txt")] = sha256_file(
            temporary / "control.txt"
        )
    atomic_write_json(
        directory / "fixture-manifest.json",
        {
            "schema_version": (
                "clawgap-chatgpt-on-wechat-fixture-manifest/v1"
            ),
            "files": fixture_files,
            "mount_namespace": {"host_tmp": str(temporary), "target": "/tmp"},
        },
    )
    return project, home, state, workspace, temporary, config_path


def _cleanup_role(
    directory: Path,
    runtime: Path,
    home: Path,
    state: Path,
    workspace: Path,
    temporary: Path,
) -> list[str]:
    errors: list[str] = []
    for path in (runtime, home, state, workspace, temporary):
        try:
            _remove_path(path)
            if path.exists():
                _remove_path(path)
        except OSError as exc:
            errors.append(f"remove {path.name}: {exc}")
        if path.exists():
            errors.append(f"remove {path.name}: disposable root remains")
    try:
        if directory.joinpath("host-effect-canary.txt").read_text(
            encoding="utf-8"
        ) != CANARY_CONTENT:
            errors.append("host-effect canary changed")
    except OSError as exc:
        errors.append(f"host-effect canary verification: {exc}")
    return errors


def _launch_role(
    *,
    runtime: Path,
    python: Path,
    app_path: Path,
    environment: Mapping[str, str],
    temporary: Path,
    complete_path: Path,
    timeout: int,
) -> tuple[int, str]:
    temporary = temporary.resolve()
    mount_script = (
        f"mount --rbind {shlex.quote(str(temporary))} /tmp && "
        f"exec {shlex.quote(str(python))} {shlex.quote(str(app_path))}"
    )
    process = subprocess.Popen(
        [
            "unshare",
            "--mount",
            "--propagation",
            "private",
            "/bin/sh",
            "-c",
            mount_script,
        ],
        cwd=runtime,
        env=dict(environment),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    output = bytearray()
    prompt_sent = False
    interrupted = False
    deadline = time.monotonic() + timeout
    stdout_fd = process.stdout.fileno()
    try:
        while time.monotonic() < deadline:
            readable, _writable, _errored = select.select(
                [stdout_fd], [], [], 0.2
            )
            if readable:
                try:
                    chunk = os.read(stdout_fd, 4096)
                except BlockingIOError:
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                elif process.poll() is not None:
                    break
            elif process.poll() is not None:
                break
            text = output.decode("utf-8", errors="replace")
            if not prompt_sent and "Please input your question" in text:
                process.stdin.write(b"environment probe\n")
                process.stdin.flush()
                prompt_sent = True
            if complete_path.is_file() and not interrupted:
                time.sleep(0.25)
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                interrupted = True
        if not prompt_sent:
            raise RuntimeError("real CowAgent terminal channel never reached readiness")
        if not complete_path.is_file():
            raise RuntimeError("target did not reach the reviewed pre-effect boundary")
        if process.poll() is None:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        while True:
            readable, _writable, _errored = select.select([stdout_fd], [], [], 0)
            if not readable:
                break
            chunk = os.read(stdout_fd, 4096)
            if not chunk:
                break
            output.extend(chunk)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        process.stdout.close()
        process.stdin.close()
    return process.returncode, output.decode("utf-8", errors="replace")


def _transcript_errors(
    fixture: CowAgentFixtureServer,
    provider_rows: list[Mapping[str, Any]],
    case: Mapping[str, Any],
    role: str,
) -> list[str]:
    errors: list[str] = []
    expected = (
        ["forced-tool-call", "vision-backend", "continuation"]
        if _family(case) == "vision-missing-check"
        else ["forced-tool-call", "continuation"]
    )
    if fixture.requests != expected:
        errors.append(
            "provider sequence drift: "
            f"expected {expected}, observed {fixture.requests}"
        )
    if fixture.unsupported:
        errors.append(f"unsupported provider endpoints: {fixture.unsupported}")
    if any(row.get("valid") is not True for row in provider_rows):
        errors.append("one or more real provider requests failed contract validation")
    forced = [
        row for row in provider_rows if row.get("request_kind") == "forced-tool-call"
    ]
    if len(forced) != 1:
        errors.append("exactly one forced provider tool-call turn was not observed")
        return errors
    request = forced[0]
    body = request.get("body") or {}
    tool_names = {
        str(row.get("function", {}).get("name"))
        for row in body.get("tools", [])
        if isinstance(row, dict)
    }
    if (
        request.get("path") != "/v1/chat/completions"
        or body.get("model") != MODEL_NAME
        or _tool_name(case) not in tool_names
        or body.get("stream") is not True
    ):
        errors.append("forced provider request did not match the reviewed contract")
    if _family(case) == "vision-missing-check":
        backend = [
            row
            for row in provider_rows
            if row.get("request_kind") == "vision-backend"
        ]
        if len(backend) != 1 or backend[0].get("body", {}).get(
            "model"
        ) != VISION_MODEL_NAME:
            errors.append("vision backend model or request shape drifted")
    if role == "control" and fixture.requests.count("forced-tool-call") != 1:
        errors.append("control provider turn was not uniquely bound")
    return errors


def _sink_matches(case: Mapping[str, Any], role: str, sink: Mapping[str, Any]) -> bool:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    detail = sink.get("detail", {})
    if candidate_id in {"CAND-2b4f8af87ad95c56", "CAND-7afa41ea2e82453d"}:
        return role == "exploit" and str(detail.get("path", "")).startswith(
            "/proc/self/"
        )
    if candidate_id in {
        "CAND-70cbbd81dff4ec04",
        "CAND-c93d316d66e49992",
        "CAND-f4a49abfcf4c992c",
        "CAND-ff3a7b0ab4b0a449",
    }:
        command = detail.get("command")
        return role == "exploit" and command in (
            "rm -rf --no-preserve-root /",
            ["rm", "-rf", "--no-preserve-root", "/"],
        )
    if candidate_id in {
        "CAND-34bd5e2a040b5664",
        "CAND-0e7d7aea6fed1ab0",
    }:
        url = str(detail.get("url", ""))
        return role == "exploit" and url.startswith("http://127.0.0.1/")
    return False


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    fixture: CowAgentFixtureServer,
    provider_rows: list[Mapping[str, Any]],
    process_exit: int,
    cleanup_errors: list[str],
) -> PairOutcome:
    errors = [*cleanup_errors, *_transcript_errors(fixture, provider_rows, case, role)]
    if process_exit not in {0, -signal.SIGINT, 130}:
        errors.append(f"real CowAgent process exited with {process_exit}")
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
    if stages != _expected_stages(case):
        errors.append(f"event sequence mismatch: {stages}")

    arguments = _role_arguments(case, role)
    argument_path = list(case["handler"]["argument_path"])
    value = arguments
    for part in argument_path:
        value = value[part]
    handler = next(
        (row for row in events if row.get("stage") == "handler_entered"), None
    )
    if handler is None or handler.get("detail", {}).get("tool_name") != _tool_name(case):
        errors.append("native CowAgent handler was not entered")
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

    expected_gates = _expected_gate_ids(case)
    if expected_gates:
        gate = next(
            (row for row in events if row.get("stage") == "gate_observed"), None
        )
        if gate is None or gate.get("detail", {}).get("gate_ids") != expected_gates:
            errors.append("cited gate identities were not observed")
        elif not all(
            row.get("admitted") is True
            for row in gate.get("detail", {}).get("observations", [])
        ):
            errors.append("a cited gate denied the reviewed carrier")
    else:
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
        if role == "exploit" and sink.get("detail", {}).get("sink_anchor") != _sink_anchor(
            case
        ):
            errors.append("exploit did not reach the cited terminal sink anchor")
        if interception.get("detail", {}).get("executed") is not False:
            errors.append("sink was not intercepted before execution")

    triggered = sink is not None and _sink_matches(case, role, sink)
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
    python: Path,
    request: ChatGPTOnWeChatL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    directory = directory.resolve()
    _remove_path(directory)
    directory.mkdir(parents=True)
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    complete_path = directory / "complete.marker"
    launch_log = directory / "launch.log"
    atomic_write_text(transcript_path, "")
    atomic_write_text(event_path, "")
    fixture = CowAgentFixtureServer(
        role=role,
        tool_name=_tool_name(case),
        arguments=_role_arguments(case, role),
        family=_family(case),
        transcript_path=transcript_path,
    )
    fixture.start()
    fixture_files: dict[str, str] = {}
    runtime = home = state = workspace = temporary = Path("/")
    process_exit = 124
    output = ""
    try:
        base_url = f"http://127.0.0.1:{fixture.port}/v1"
        runtime, home, state, workspace, temporary, config_path = _prepare_role(
            directory, base_url, case, role, build_project
        )
        fixture_manifest = json.loads(
            (directory / "fixture-manifest.json").read_text(encoding="utf-8")
        )
        fixture_files = dict(fixture_manifest["files"])
        build_manifest_path = build_project.parent / "transformed-source-manifest.json"
        shutil.copy2(
            build_manifest_path, directory / "transformed-source-manifest.json"
        )
        environment = {
            "PATH": f"{build_project.parent / '.clawgap-venv/bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "HOME": str(home),
            "TMPDIR": str(temporary),
            "OPENAI_API_KEY": "clawgap-loopback-mock",
            "OPENAI_API_BASE": base_url,
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "PYTHONUNBUFFERED": "1",
            "CLAWGAP_L2_EVENT_PATH": str(event_path),
            "CLAWGAP_L2_COMPLETE_PATH": str(complete_path),
            "CLAWGAP_L2_CANDIDATE_ID": str(
                case["candidate_binding"]["candidate_id"]
            ),
            "CLAWGAP_L2_CASE_ID": str(case["case_id"]),
            "CLAWGAP_L2_ATTEMPT": str(attempt),
            "CLAWGAP_L2_ROLE": role,
            "CLAWGAP_L2_CORRELATION_ID": f"{case['case_id']}:{attempt}:{role}",
            "CLAWGAP_L2_FIXTURE_ID": (
                f"chatgpt-on-wechat-l2:{case['case_id']}:{role}"
            ),
            "CLAWGAP_L2_FAMILY": _family(case),
            "CLAWGAP_L2_GATE_IDS": ",".join(_expected_gate_ids(case)),
        }
        process_exit, output = _launch_role(
            runtime=runtime,
            python=python,
            app_path=build_project / "app.py",
            environment=environment,
            temporary=temporary,
            complete_path=complete_path,
            timeout=request.timeout,
        )
        atomic_write_text(launch_log, redact_text(output))
    except Exception as exc:
        atomic_write_text(
            launch_log,
            redact_text(output + f"\nCLAWGAP_ERROR: {type(exc).__name__}: {exc}\n"),
        )
        return PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []
    finally:
        fixture.stop()

    raw_events = _read_jsonl(event_path)
    provider_rows = _read_jsonl(transcript_path)
    cleanup_errors = _cleanup_role(
        directory, runtime, home, state, workspace, temporary
    )
    try:
        events = _normalize_events(
            raw_events, provider_rows, case, attempt, role, fixture_files
        )
        if cleanup_errors and events:
            events[-1]["detail"]["cleanup_errors"] = cleanup_errors
        _write_jsonl(directory / "events.jsonl", events)
        outcome = _evaluate_pair(
            case,
            role,
            events,
            fixture,
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
    evidence_paths = [
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    ]
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in evidence_paths
    )
    return "failed" if contains_credentials(text) else "passed"


def _reproduction_command(request: ChatGPTOnWeChatL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-chatgpt-on-wechat-l2"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    default = HISTORICAL_SOURCE_CAMPAIGN if request.historical else DEFAULT_SOURCE_CAMPAIGN
    if request.campaign.resolve() != default.resolve():
        command += f" --campaign {request.campaign}"
    if request.candidate_id is not None:
        command += f" --candidate-id {request.candidate_id}"
    if request.historical:
        command += " --historical"
    return command


def run_chatgpt_on_wechat_l2(
    request: ChatGPTOnWeChatL2RunRequest,
) -> dict[str, Any]:
    started = time.time()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError(
            "CowAgent targeted L2 timeouts and attempts must be positive"
        )
    campaign = (
        HISTORICAL_SOURCE_CAMPAIGN
        if request.historical and request.campaign == DEFAULT_SOURCE_CAMPAIGN
        else request.campaign
    )
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    cases = _select_cases(
        campaign.resolve(),
        candidate_id=request.candidate_id,
        historical=request.historical,
    )
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
    python = actual_build_dir / ".clawgap-venv/bin/python"
    if request.build_dir is not None:
        published_build_dir = request.out_dir.resolve() / "build"
        _remove_path(published_build_dir)
        published_build_dir.mkdir(parents=True)
        shutil.copyfile(
            actual_build_dir / "transformed-source-manifest.json",
            published_build_dir / "transformed-source-manifest.json",
        )

    results: list[dict[str, Any]] = []
    for case in cases:
        candidate_id = str(case["candidate_binding"]["candidate_id"])
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
                    python,
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
                "campaign_id": (
                    HISTORICAL_CAMPAIGN_ID
                    if request.historical
                    else CURRENT_CAMPAIGN_ID
                ),
                "candidate_id": candidate_id,
                "case_id": case["case_id"],
                "project": "chatgpt-on-wechat",
                "disposition": disposition,
                "evidence_tier": L2_EVIDENCE_TIER,
                "attempts": request.attempts,
                "reason": reason,
                "attempt_errors": [
                    outcome.errors for outcome in pair_outcomes if outcome.errors
                ],
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
        _remove_path(build_project)
    _write_jsonl(request.out_dir / "cases.jsonl", cases)
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "candidate_id": row["candidate_id"],
                "case_id": row["case_id"],
                "project": "chatgpt-on-wechat",
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
        if path.name in {"home", "state", "workspace", "runtime", "tmp"}
    ):
        try:
            _remove_path(path)
        except OSError:
            pass
    credential_scan = _artifact_credential_scan(request.out_dir)
    disposable_workspaces_removed = not any(
        path.is_dir()
        for path in (request.out_dir / "runs").rglob("*")
        if path.name in {"home", "state", "workspace", "runtime", "tmp"}
    )
    if credential_scan != "passed" or not disposable_workspaces_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
        counts = {"inconclusive": len(results)}
    manifest = {
        "schema_version": (
            "clawgap-dynamic-trigger-chatgpt-on-wechat-l2-manifest/v1"
        ),
        "campaign_id": (
            HISTORICAL_CAMPAIGN_ID if request.historical else CURRENT_CAMPAIGN_ID
        ),
        "source_campaign": str(campaign),
        "candidate_count": len(results),
        "attempt_pairs": request.attempts,
        "status_counts": counts,
        "evidence_tier": L2_EVIDENCE_TIER,
        "targeted_only": True,
        "historical_post_hoc": request.historical,
        "canonical_all_candidate_l2": False,
        "source_bindings": source_bindings,
        "source_drift": False,
        "dependency_requirements": sha256_file(SOURCE_ROOT / "requirements.txt"),
        "harness_bindings": {
            "src/runtime_validation/chatgpt_on_wechat_l2.py": sha256_file(
                REPO_ROOT / "src/runtime_validation/chatgpt_on_wechat_l2.py"
            )
        },
        "transformed_source_manifest": digest(build_manifest),
        "credential_scan": credential_scan,
        "disposable_workspaces_removed": disposable_workspaces_removed,
        "generation_command": _reproduction_command(request),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    atomic_write_json(request.out_dir / "manifest.json", manifest)
    scope = (
        "post-hoc historical"
        if request.historical
        else "current canonical-input"
    )
    atomic_write_text(
        request.out_dir / "summary.md",
        (
            "# ChatGPT-on-WeChat Targeted Dynamic-Trigger L2\n\n"
            f"> Complete reproduction command: `{manifest['generation_command']}`\n\n"
            f"Candidates accounted for: **{len(results)}/{len(cases)}**.\n\n"
            f"Paired attempts per candidate: **{request.attempts}**.\n\n"
            f"Runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**; "
            f"not-reproduced: **{counts.get('not-reproduced', 0)}**; "
            f"inconclusive: **{counts.get('inconclusive', 0)}**.\n\n"
            f"This is targeted {scope} L2 evidence. It does not by itself publish "
            "canonical all-candidate L2 evidence or change the 43-report truth gate.\n"
        ),
    )
    return manifest
