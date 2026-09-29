"""Targeted forced-provider L2 runtime for GT-linked nanobot candidates."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

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
PROJECT = get_project("nanobot")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v3"
)
TARGET_CANDIDATES = (
    "CAND-172340a317979d20",
    "CAND-41f28e9e17a06e89",
    "CAND-49ccfec7491078f6",
    "CAND-69c18202d18d7bcf",
    "CAND-f68ce42e92cbb622",
)
CAMPAIGN_ID = "runtime-dynamic-trigger-nanobot-l2-v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-nanobot-l2-result/v1"
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-nanobot-l2-event/v1"
MODEL_NAME = "custom/clawgap-nanobot-l2"
PROVIDER_CREDENTIAL = "clawgap-loopback-mock"
CANARY_CONTENT = "clawgap-nanobot-host-canary\n"
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

CITED_SOURCE_HASHES = {
    "pyproject.toml": (
        "b40fd1d30fbc623be8d0453d3b4e4ef9dcb3746e207a5df9246a0b389660638c"
    ),
    "nanobot/cli/commands.py": (
        "68f062e17076f26953678585f80becfac7ce604fd2a4ffef173a0ef10ef1d776"
    ),
    "nanobot/config/schema.py": (
        "2637ddcf65ca4fb4a1fd4df7fdbcc90644f1ac46f7c4039ab187e859dfa34b80"
    ),
    "nanobot/config/loader.py": (
        "9bbe5583c5b74cc1693a351e4001fd02a7ffd2b463b8c9197d54b8c1e5b24cb8"
    ),
    "nanobot/config/paths.py": (
        "94a16ffc950c6c21f512774d00c7f59f42a2098f651cd8d27ae38cd8739cbcf6"
    ),
    "nanobot/agent/loop.py": (
        "cfae98f20c7c1aa8d42ef2574311d832ed5684d7758638ed2b048c632b70aeec"
    ),
    "nanobot/agent/tools/registry.py": (
        "9ba76357d4b440ff051995a9b5143c01b471d2a72c0590e0b0742bce5f4cba36"
    ),
    "nanobot/agent/tools/shell.py": (
        "7e5e9a7afd6dbf4afb98e0a0e2f92ec2af9ed30e7d01e13298524a2a6b6ab292"
    ),
    "nanobot/providers/custom_provider.py": (
        "05a95af154ea43c14d37b729c60cdaa49f4139896143f7f9ddce2246ae136b04"
    ),
    "nanobot/providers/base.py": (
        "c7374de9eac325192a777f8e998b66fc981a9aa400b9fbdc865eb234e6fb8199"
    ),
    "nanobot/security/network.py": (
        "8e83c4a6c1296ca06d2b960cd8c9c0b9dcb52de646098de5b3d3d631e0941b89"
    ),
}

CANDIDATE_FAMILIES = {
    "CAND-172340a317979d20": "shell-chain",
    "CAND-41f28e9e17a06e89": "comment-tail",
    "CAND-49ccfec7491078f6": "missing-safe-read",
    "CAND-69c18202d18d7bcf": "workspace-boundary",
    "CAND-f68ce42e92cbb622": "wrapper-prefix",
}

PAYLOAD_REPAIRS = {
    "CAND-172340a317979d20": {
        "roles": {
            "exploit": {
                "command": "echo allowlisted; touch nanobot-chain-canary",
                "working_dir": "/tmp",
            },
            "control": {
                "command": "echo allowlisted",
                "working_dir": "/tmp",
            },
        },
        "reason": (
            "replace the compiled loopback URL carrier, which is independently "
            "rejected by contains_internal_url, with the reviewed chain form"
        ),
        "report_provenance": "GT-728de3b52b229b2d",
    },
    "CAND-41f28e9e17a06e89": {
        "roles": {
            "exploit": {
                "command": "touch nanobot-comment-canary # echo allowlisted",
                "working_dir": "/tmp",
            },
            "control": {
                "command": "echo allowlisted",
                "working_dir": "/tmp",
            },
        },
        "reason": (
            "use the report's POSIX comment-tail carrier instead of a plain chain"
        ),
        "report_provenance": "GT-624fbbb5b97a8bea",
    },
    "CAND-f68ce42e92cbb622": {
        "roles": {
            "exploit": {
                "command": (
                    "env bash -lc 'echo allowlisted && "
                    "touch nanobot-wrapper-canary'"
                ),
            },
            "control": {
                "command": "env bash -lc 'echo allowlisted'",
            },
        },
        "reason": (
            "use the report's nested wrapper-prefix carrier instead of a URL chain"
        ),
        "report_provenance": "GT-c57df0eae7d9f541",
    },
}

ALLOW_POLICIES = {
    "CAND-172340a317979d20": ["^echo\\b"],
    "CAND-41f28e9e17a06e89": ["\\becho\\s+allowlisted\\b"],
    "CAND-49ccfec7491078f6": [],
    "CAND-69c18202d18d7bcf": [],
    "CAND-f68ce42e92cbb622": [
        "^env\\s+bash\\s+-lc\\s+'echo\\s+allowlisted"
    ],
}

RESTRICT_TO_WORKSPACE = {
    "CAND-41f28e9e17a06e89": True,
    "CAND-69c18202d18d7bcf": True,
}


@dataclass(frozen=True)
class NanobotL2RunRequest:
    campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    out_dir: Path = ...
    attempts: int = 3
    timeout: int = 120
    build_timeout: int = 900
    candidate_id: str | None = None
    build_dir: Path | None = None


@dataclass
class PairOutcome:
    healthy: bool
    triggered: bool
    errors: list[str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
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


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists():
        shutil.rmtree(path)


def _candidate_id(case: Mapping[str, Any]) -> str:
    return str(case["candidate_binding"]["candidate_id"])


def _case_id(case: Mapping[str, Any]) -> str:
    return str(case["case_id"])


def _family(case: Mapping[str, Any]) -> str:
    return CANDIDATE_FAMILIES[_candidate_id(case)]


def _apply_payload_repair(case: dict[str, Any]) -> dict[str, Any] | None:
    repair = PAYLOAD_REPAIRS.get(_candidate_id(case))
    if repair is None:
        return None
    repaired_calls: list[dict[str, Any]] = []
    for row in case["forced_tool_calls"]:
        role = str(row.get("role"))
        arguments = dict(row.get("arguments") or {})
        arguments.update(repair["roles"][role])
        repaired_calls.append({"role": role, "arguments": arguments})
    case["forced_tool_calls"] = repaired_calls
    return {
        "candidate_id": _candidate_id(case),
        "case_id": _case_id(case),
        "original": [
            dict(row) for row in case.get("compiled_forced_tool_calls", [])
        ],
        "replacement": repaired_calls,
        "reason": repair["reason"],
        "report_provenance": repair["report_provenance"],
    }


def _select_cases(
    campaign: Path,
    candidate_id: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases = _read_jsonl(campaign / "cases.jsonl")
    selected = {
        str(row.get("candidate_binding", {}).get("candidate_id")): row
        for row in cases
        if row.get("project") == "nanobot"
    }
    expected = set(TARGET_CANDIDATES)
    if not expected.issubset(selected):
        missing = sorted(expected - set(selected))
        raise ValidationError(
            "nanobot targeted L2 source campaign is missing GT-linked "
            "candidates: " + ", ".join(missing)
        )
    identities = expected if candidate_id is None else {candidate_id}
    if candidate_id is not None and candidate_id not in expected:
        raise ValidationError(
            "requested nanobot candidate is not one of the five GT-linked IDs"
        )
    rows: list[dict[str, Any]] = []
    repairs: list[dict[str, Any]] = []
    for identity in TARGET_CANDIDATES:
        if identity not in identities:
            continue
        row = json.loads(json.dumps(selected[identity]))
        row["compiled_forced_tool_calls"] = list(row["forced_tool_calls"])
        repair = _apply_payload_repair(row)
        rows.append(row)
        if repair is not None:
            repairs.append(repair)
    return rows, repairs


def _role_arguments(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    row = next(row for row in case["forced_tool_calls"] if row["role"] == role)
    return dict(row["arguments"])


def _controlled_value(case: Mapping[str, Any], role: str) -> str:
    return str(_role_arguments(case, role).get("command", ""))


def _expected_gate_ids(case: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(str(row.get("id")) for row in case.get("gates", []))


def _source_bindings(cases: list[Mapping[str, Any]]) -> dict[str, str]:
    for case in cases:
        if case.get("revision") != PROJECT.analysis_revision:
            raise ValidationError("nanobot case revision does not match registry")
    bindings: dict[str, str] = {}
    for relative, expected in CITED_SOURCE_HASHES.items():
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"nanobot bound source is missing: {relative}")
        digest = sha256_file(source)
        if digest != expected:
            raise ValidationError(
                f"nanobot cited source hash drift: {relative}: {digest}"
            )
        bindings[relative] = digest
    return bindings


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(
            f"nanobot instrumentation marker mismatch ({label}): {count}"
        )
    return source.replace(old, new, 1)


def _instrumentation_helper() -> str:
    return r'''import asyncio
import os


_state = {
    "candidate_id": os.environ.get("CLAWGAP_L2_CANDIDATE_ID"),
    "case_id": os.environ.get("CLAWGAP_L2_CASE_ID"),
    "attempt": int(os.environ.get("CLAWGAP_L2_ATTEMPT", "0")),
    "role": os.environ.get("CLAWGAP_L2_ROLE"),
    "family": os.environ.get("CLAWGAP_L2_FAMILY"),
    "expected_command": os.environ.get("CLAWGAP_L2_COMMAND"),
    "expected_cwd": os.environ.get("CLAWGAP_L2_CWD"),
    "allow_patterns": [
        item for item in os.environ.get("CLAWGAP_L2_ALLOW_PATTERNS", "").split("\n")
        if item
    ],
    "restrict_to_workspace": os.environ.get(
        "CLAWGAP_L2_RESTRICT_TO_WORKSPACE", ""
    ) == "true",
    "gate_ids": [
        item for item in os.environ.get("CLAWGAP_L2_GATE_IDS", "").split("\n")
        if item
    ],
}


def _event(stage, detail):
    path = os.environ.get("CLAWGAP_L2_EVENT_PATH")
    if not path:
        raise RuntimeError("nanobot L2 instrumentation event path is unset")
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(__import__("json").dumps({"stage": stage, "detail": detail}) + "\n")


def clawgap_prompt(message, session_id):
    _event(
        "prompt_received",
        {"message": message, "session_id": session_id, "transport": "cli-message"},
    )


def clawgap_provider_request(kwargs):
    if _state.get("provider_request_emitted"):
        return
    _state["provider_request_emitted"] = True
    tools = kwargs.get("tools") or []
    _event(
        "provider_request",
        {
            "model": kwargs.get("model"),
            "tool_names": [
                item.get("function", {}).get("name") for item in tools if isinstance(item, dict)
            ],
            "stream": False,
        },
    )


def clawgap_provider_tool_call(tool_calls):
    if _state.get("provider_tool_call_emitted"):
        return
    _state["provider_tool_call_emitted"] = True
    rows = []
    for call in tool_calls or []:
        rows.append(
            {
                "id": getattr(call, "id", None),
                "name": getattr(call, "name", None),
                "arguments": getattr(call, "arguments", None),
            }
        )
    if len(rows) != 1 or rows[0]["name"] != "exec":
        raise RuntimeError("nanobot provider emitted an unreviewed tool-call shape")
    _event("provider_tool_call_or_decision", {"tool_calls": rows})


def clawgap_native_dispatch(tool_name, params):
    if tool_name != "exec":
        raise RuntimeError("nanobot native dispatch selected an unreviewed tool")
    _event("registry_or_native_dispatch", {"tool_name": tool_name, "params": dict(params)})


def clawgap_handler(arguments):
    _state["expected_command"] = arguments.get("command")
    _event("handler_entered", {"tool": "exec", "arguments": dict(arguments)})
    _event(
        "controlled_argument_recorded",
        {
            "command": arguments.get("command"),
            "working_dir": arguments.get("working_dir"),
            "argument_path": ["command"],
        },
    )


def clawgap_gate(command, cwd, result, allow_patterns, restrict_to_workspace):
    _state["expected_command"] = command
    _state["expected_cwd"] = cwd
    decision = "blocked" if result is not None else "allowed"
    detail = {
        "decision": decision,
        "result": result,
        "allow_patterns": list(allow_patterns),
        "restrict_to_workspace": bool(restrict_to_workspace),
        "cwd": cwd,
    }
    if _state["family"] == "missing-safe-read":
        _event(
            "missing_check_boundary_confirmed",
            {
                "missing_check": True,
                "policy": "safe-read auto-approval",
                **detail,
            },
        )
    else:
        detail["gate_ids"] = list(_state["gate_ids"])
        _event("gate_observed", detail)


class _FakeProcess:
    returncode = 0
    pid = 424242

    async def communicate(self, timeout=None, *_args, **_kwargs):
        return "clawgap intercepted nanobot process before execution\n", ""

    async def wait(self, timeout=None, *_args, **_kwargs):
        return 0

    def kill(self):
        return None

    def terminate(self):
        return None

    def poll(self):
        return 0


async def clawgap_create_subprocess_shell(factory, *args, **kwargs):
    command = args[0] if args else kwargs.get("args")
    if command != _state["expected_command"]:
        raise RuntimeError(
            "nanobot process sink received an unreviewed command: "
            + repr(command)
            + " != "
            + repr(_state["expected_command"])
        )
    cwd = kwargs.get("cwd")
    if cwd != _state["expected_cwd"]:
        raise RuntimeError("nanobot process sink received an unreviewed cwd")
    detail = {
        "command": command,
        "cwd": cwd,
        "environment_keys": sorted((kwargs.get("env") or {}).keys()),
        "allow_patterns": list(_state["allow_patterns"]),
        "restrict_to_workspace": _state["restrict_to_workspace"],
    }
    _event("sink_reached", detail)
    _event("pre_effect_interception", {**detail, "executed": False})
    _event("target_completed", {"executed": False})
    return _FakeProcess()
'''


def _instrument_project(project: Path) -> dict[str, str]:
    transformed: dict[str, str] = {}

    schema_path = project / "nanobot/config/schema.py"
    schema = schema_path.read_text(encoding="utf-8")
    schema = _replace_once(
        schema,
        '    timeout: int = 60\n    path_append: str = ""\n    login_shell_profile: bool = False\n',
        '    timeout: int = 60\n    path_append: str = ""\n'
        '    allow_patterns: list[str] = Field(default_factory=list)\n'
        '    login_shell_profile: bool = False\n',
        "ExecToolConfig allow-pattern field",
    )
    schema_path.write_text(schema, encoding="utf-8")
    transformed["nanobot/config/schema.py"] = sha256_file(schema_path)

    loop_path = project / "nanobot/agent/loop.py"
    loop = loop_path.read_text(encoding="utf-8")
    loop = _replace_once(
        loop,
        "            path_append=self.exec_config.path_append,\n            login_shell_profile=self.exec_config.login_shell_profile,\n        ))",
        "            path_append=self.exec_config.path_append,\n"
        "            allow_patterns=self.exec_config.allow_patterns,\n"
        "            login_shell_profile=self.exec_config.login_shell_profile,\n        ))",
        "AgentLoop allow-pattern plumbing",
    )
    loop_path.write_text(loop, encoding="utf-8")
    transformed["nanobot/agent/loop.py"] = sha256_file(loop_path)

    commands_path = project / "nanobot/cli/commands.py"
    commands = commands_path.read_text(encoding="utf-8")
    commands = _replace_once(
        commands,
        "response = await agent_loop.process_direct(message, session_id, on_progress=_cli_progress)",
        "clawgap_prompt(message, session_id)\n"
        "                response = await agent_loop.process_direct(message, session_id, on_progress=_cli_progress)",
        "CLI prompt boundary",
    )
    commands = commands.replace(
        "from nanobot.config.paths import get_workspace_path\n",
        "from nanobot.config.paths import get_workspace_path\n"
        "from clawgap_nanobot_l2_runtime import clawgap_prompt\n",
        1,
    )
    if commands.count("from clawgap_nanobot_l2_runtime import clawgap_prompt") != 1:
        raise ValidationError("nanobot CLI prompt helper import marker mismatch")
    commands_path.write_text(commands, encoding="utf-8")
    transformed["nanobot/cli/commands.py"] = sha256_file(commands_path)

    provider_path = project / "nanobot/providers/custom_provider.py"
    provider = provider_path.read_text(encoding="utf-8")
    provider = _replace_once(
        provider,
        "        try:\n            return self._parse(",
        "        from clawgap_nanobot_l2_runtime import clawgap_provider_request\n"
        "        clawgap_provider_request(kwargs)\n"
        "        try:\n            return self._parse(",
        "custom provider request boundary",
    )
    provider = _replace_once(
        provider,
        "        u = response.usage\n",
        "        from clawgap_nanobot_l2_runtime import clawgap_provider_tool_call\n"
        "        clawgap_provider_tool_call(tool_calls)\n"
        "        u = response.usage\n",
        "custom provider tool-call boundary",
    )
    provider_path.write_text(provider, encoding="utf-8")
    transformed["nanobot/providers/custom_provider.py"] = sha256_file(provider_path)

    registry_path = project / "nanobot/agent/tools/registry.py"
    registry = registry_path.read_text(encoding="utf-8")
    registry = _replace_once(
        registry,
        '        """Execute a tool by name with given parameters."""\n',
        '        """Execute a tool by name with given parameters."""\n'
        "        from clawgap_nanobot_l2_runtime import clawgap_native_dispatch\n"
        "        clawgap_native_dispatch(name, params)\n",
        "native tool dispatch boundary",
    )
    registry_path.write_text(registry, encoding="utf-8")
    transformed["nanobot/agent/tools/registry.py"] = sha256_file(registry_path)

    shell_path = project / "nanobot/agent/tools/shell.py"
    shell = shell_path.read_text(encoding="utf-8")
    shell = _replace_once(
        shell,
        "        cwd = working_dir or self.working_dir or os.getcwd()\n"
        "        guard_error = self._guard_command(command, cwd)\n",
        "        cwd = working_dir or self.working_dir or os.getcwd()\n"
        "        from clawgap_nanobot_l2_runtime import (\n"
        "            clawgap_gate,\n"
        "            clawgap_handler,\n"
        "        )\n"
        "        clawgap_handler({\n"
        "            \"command\": command,\n"
        "            \"working_dir\": working_dir,\n"
        "        })\n"
        "        guard_error = self._guard_command(command, cwd)\n"
        "        clawgap_gate(\n"
        "            command,\n"
        "            cwd,\n"
        "            guard_error,\n"
        "            self.allow_patterns,\n"
        "            self.restrict_to_workspace,\n"
        "        )\n",
        "exec handler and guard boundaries",
    )
    shell = _replace_once(
        shell,
        "process = await spawn_factory(",
        "process = await clawgap_create_subprocess_shell(\n                spawn_factory,",
        "pre-effect process sink",
    )
    shell = shell.replace(
        "from nanobot.agent.tools.base import Tool\n",
        "from nanobot.agent.tools.base import Tool\n"
        "from clawgap_nanobot_l2_runtime import clawgap_create_subprocess_shell\n",
        1,
    )
    if shell.count("from clawgap_nanobot_l2_runtime import clawgap_create_subprocess_shell") != 1:
        raise ValidationError("nanobot shell helper import marker mismatch")
    shell_path.write_text(shell, encoding="utf-8")
    transformed["nanobot/agent/tools/shell.py"] = sha256_file(shell_path)

    helper_path = project / "clawgap_nanobot_l2_runtime.py"
    helper_path.write_text(_instrumentation_helper(), encoding="utf-8")
    transformed["clawgap_nanobot_l2_runtime.py"] = sha256_file(helper_path)
    return transformed


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


def _render_build_copy(
    directory: Path,
    source_bindings: Mapping[str, str],
) -> dict[str, Any]:
    project = directory / "project"
    _remove_path(project)
    shutil.copytree(
        SOURCE_ROOT,
        project,
        ignore=shutil.ignore_patterns(
            ".git",
            ".clawgap-venv",
            "__pycache__",
            ".pytest_cache",
            "*.pyc",
        ),
    )
    transformed = _instrument_project(project)
    return {
        "schema_version": "clawgap-nanobot-transformed-source-manifest/v1",
        "revision": PROJECT.analysis_revision,
        "original": dict(source_bindings),
        "transformed": transformed,
        "config_backport": {
            "purpose": "expose ExecTool constructor allow_patterns through real config",
            "security_logic_changed": False,
            "files": [
                "nanobot/config/schema.py",
                "nanobot/agent/loop.py",
            ],
        },
    }


def _prepare_build(
    directory: Path,
    source_bindings: Mapping[str, str],
    timeout: int,
) -> dict[str, Any]:
    harness_path = REPO_ROOT / "src/runtime_validation/nanobot_l2.py"
    harness_sha256 = sha256_file(harness_path)
    manifest_path = directory / "transformed-source-manifest.json"
    venv_python = directory / ".clawgap-venv/bin/python"
    if manifest_path.is_file() and venv_python.is_file():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version")
            == "clawgap-nanobot-transformed-source-manifest/v1"
            and prior.get("revision") == PROJECT.analysis_revision
            and prior.get("original") == dict(source_bindings)
            and prior.get("harness_sha256") == harness_sha256
            and prior.get("interpreter_sha256") == sha256_file(venv_python)
        ):
            return prior

    directory.mkdir(parents=True, exist_ok=True)
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
        env={
            "HOME": str(directory / "build-home"),
            "NO_COLOR": "1",
        },
    )
    if bootstrap.returncode != 0 or not venv_python.is_file():
        raise ValidationError(
            f"nanobot disposable Python environment failed: {bootstrap.returncode}"
        )
    uv_path = shutil.which("uv")
    if uv_path is None:
        raise ValidationError("nanobot targeted L2 requires uv")
    install = _run(
        [
            uv_path,
            "pip",
            "install",
            "--python",
            str(venv_python),
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
            f"nanobot editable installation failed: {install.returncode}"
        )
    probe = _run(
        [
            str(venv_python),
            "-c",
            "from nanobot.config.schema import ExecToolConfig; "
            "from nanobot.cli import commands; "
            "assert ExecToolConfig().allow_patterns == []",
        ],
        cwd=directory / "project",
        log_path=directory / "import-probe.log",
        timeout=min(timeout, 120),
        env={
            "PYTHONPATH": str(directory / "project"),
            "HOME": str(directory / "build-home"),
            "PATH": f"{venv_dir / 'bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "NO_COLOR": "1",
        },
    )
    if probe.returncode != 0:
        raise ValidationError(
            f"nanobot transformed runtime import probe failed: {probe.returncode}"
        )
    manifest.update(
        {
            "harness_sha256": harness_sha256,
            "interpreter_sha256": sha256_file(venv_python),
        }
    )
    atomic_write_json(manifest_path, manifest)
    return manifest


class NanobotProviderServer:
    """Strict loopback OpenAI Chat Completions provider."""

    def __init__(
        self,
        *,
        role: str,
        arguments: Mapping[str, Any],
        transcript_path: Path,
        tool_name: str = "exec",
    ) -> None:
        self.role = role
        self.arguments = dict(arguments)
        self.tool_name = tool_name
        self.transcript_path = transcript_path
        self._lock = threading.Lock()
        self._chat_requests = 0
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="clawgap-nanobot-l2-provider",
            daemon=True,
        )
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

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

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _route(self) -> None:
                path = urlsplit(self.path).path
                if path != "/v1/chat/completions" or self.command != "POST":
                    server._record(
                        {
                            "path": path,
                            "method": self.command,
                            "valid": False,
                            "response_kind": "unsupported-endpoint",
                        }
                    )
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    body = json.loads(self.rfile.read(length))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body = {}
                with server._lock:
                    server._chat_requests += 1
                    ordinal = server._chat_requests
                request_kind = (
                    "forced-tool-call" if ordinal == 1 else "continuation"
                )
                tools = body.get("tools") or []
                tool_names = [
                    str(item.get("function", {}).get("name"))
                    for item in tools
                    if isinstance(item, dict)
                ]
                authorization = self.headers.get("Authorization", "")
                server._record(
                    {
                        "ordinal": ordinal,
                        "path": path,
                        "method": self.command,
                        "request_kind": request_kind,
                        "authorization_redacted": "Bearer [REDACTED_CREDENTIAL]",
                        "authorization_valid": authorization
                        == f"Bearer {PROVIDER_CREDENTIAL}",
                        "model": body.get("model"),
                        "stream": body.get("stream") is True,
                        "tool_names": tool_names,
                        "message_count": len(body.get("messages") or []),
                        "valid": True,
                    }
                )
                if ordinal == 1:
                    server._json(
                        self,
                        {
                            "id": f"chatcmpl-clawgap-{server.role}",
                            "object": "chat.completion",
                            "created": 1,
                            "model": MODEL_NAME,
                            "choices": [
                                {
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": None,
                                        "tool_calls": [
                                            {
                                                "id": f"call-clawgap-{server.role}",
                                                "type": "function",
                                                "function": {
                                                    "name": server.tool_name,
                                                    "arguments": json.dumps(
                                                        server.arguments,
                                                        sort_keys=True,
                                                        separators=(",", ":"),
                                                    ),
                                                },
                                            }
                                        ],
                                    },
                                    "finish_reason": "tool_calls",
                                }
                            ],
                        },
                    )
                    return
                if ordinal == 2:
                    server._json(
                        self,
                        {
                            "id": f"chatcmpl-clawgap-{server.role}-final",
                            "object": "chat.completion",
                            "created": 2,
                            "model": MODEL_NAME,
                            "choices": [
                                {
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": "clawgap-nanobot-l2-complete",
                                    },
                                    "finish_reason": "stop",
                                }
                            ],
                        },
                    )
                    return
                server._record({"path": path, "valid": False, "response_kind": "overflow"})
                self.send_error(429)

            def do_GET(self) -> None:
                self._route()

            def do_POST(self) -> None:
                self._route()

        return Handler


def _render_config(
    *,
    provider_port: int,
    workspace: Path,
    case: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = _candidate_id(case)
    return {
        "agents": {
            "defaults": {
                "model": MODEL_NAME,
                "provider": "custom",
                "workspace": str(workspace),
                "maxToolIterations": 2,
            }
        },
        "providers": {
            "custom": {
                "apiKey": PROVIDER_CREDENTIAL,
                "apiBase": f"http://127.0.0.1:{provider_port}/v1",
            }
        },
        "gateway": {"host": "127.0.0.1", "port": 0},
        "tools": {
            "exec": {
                "allowPatterns": ALLOW_POLICIES[candidate],
            },
            "restrictToWorkspace": RESTRICT_TO_WORKSPACE.get(candidate, False),
        },
    }


def _prepare_role(
    *,
    directory: Path,
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    provider_port: int,
) -> tuple[Path, dict[str, Any]]:
    directory = directory.resolve()
    role_root = directory / "runtime"
    home = role_root / "home"
    workspace = role_root / "workspace"
    home.mkdir(parents=True)
    workspace.mkdir()
    config = _render_config(
        provider_port=provider_port,
        workspace=workspace,
        case=case,
    )
    config_path = role_root / "config.json"
    atomic_write_json(config_path, config)
    canary = directory / "host-effect-canary.txt"
    atomic_write_text(canary, CANARY_CONTENT)
    fixture = {
        "role_root": str(role_root),
        "home": str(home),
        "workspace": str(workspace),
        "config": str(config_path),
        "config_sha256": sha256_file(config_path),
        "provider_base_url": f"http://127.0.0.1:{provider_port}/v1",
        "allow_patterns": ALLOW_POLICIES[_candidate_id(case)],
        "restrict_to_workspace": RESTRICT_TO_WORKSPACE.get(
            _candidate_id(case), False
        ),
        "host_canary": str(canary),
        "host_canary_sha256": sha256_file(canary),
    }
    return role_root, fixture


def _base_environment(
    *,
    build_project: Path,
    build_python: Path,
    role_root: Path,
    fixture: Mapping[str, Any],
    case: Mapping[str, Any],
    role: str,
    attempt: int,
) -> dict[str, str]:
    arguments = _role_arguments(case, role)
    expected_cwd = str(arguments.get("working_dir") or fixture["workspace"])
    return {
        "HOME": str(fixture["home"]),
        "TMPDIR": str(role_root / "tmp"),
        "PATH": f"{build_python.parent}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
        "PYTHONPATH": str(build_project),
        "NO_COLOR": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "LITELLM_TELEMETRY": "False",
        "CLAWGAP_L2_EVENT_PATH": str(Path(fixture["role_root"]).parent / "events.raw.jsonl"),
        "CLAWGAP_L2_CANDIDATE_ID": _candidate_id(case),
        "CLAWGAP_L2_CASE_ID": _case_id(case),
        "CLAWGAP_L2_ATTEMPT": str(attempt),
        "CLAWGAP_L2_ROLE": role,
        "CLAWGAP_L2_FAMILY": _family(case),
        "CLAWGAP_L2_COMMAND": str(arguments["command"]),
        "CLAWGAP_L2_CWD": expected_cwd,
        "CLAWGAP_L2_ALLOW_PATTERNS": "\n".join(ALLOW_POLICIES[_candidate_id(case)]),
        "CLAWGAP_L2_RESTRICT_TO_WORKSPACE": str(
            RESTRICT_TO_WORKSPACE.get(_candidate_id(case), False)
        ).lower(),
        "CLAWGAP_L2_GATE_IDS": "\n".join(_expected_gate_ids(case)),
    }


def _prompt(case: Mapping[str, Any], role: str) -> str:
    command = _controlled_value(case, role)
    return f"Use the reviewed exec command exactly once: {command}"


def _launch_and_prompt(
    *,
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    role_root: Path,
    fixture: Mapping[str, Any],
    build_project: Path,
    build_python: Path,
    provider: NanobotProviderServer,
    request: NanobotL2RunRequest,
) -> tuple[int, list[str]]:
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    transcript_path.write_text("", encoding="utf-8")
    event_path.write_text("", encoding="utf-8")
    errors: list[str] = []
    output = ""
    command = [
        str(build_python.parent / "nanobot"),
        "agent",
        "--config",
        str(fixture["config"]),
        "--workspace",
        str(fixture["workspace"]),
        "--session",
        f"nanobot:clawgap-{role}-{attempt}",
        "--message",
        _prompt(case, role),
        "--no-markdown",
    ]
    environment = _base_environment(
        build_project=build_project,
        build_python=build_python,
        role_root=role_root,
        fixture=fixture,
        case=case,
        role=role,
        attempt=attempt,
    )
    (role_root / "tmp").mkdir(exist_ok=True)
    process = subprocess.Popen(
        command,
        cwd=str(fixture["workspace"]),
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=request.timeout)
    except subprocess.TimeoutExpired:
        errors.append("nanobot one-shot role timed out")
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        output, _ = process.communicate()
    finally:
        provider.close()
    atomic_write_text(directory / "launch.log", redact_text(output or ""))
    if process.returncode != 0:
        errors.append(f"nanobot role exited {process.returncode}")
    return int(process.returncode or 0), errors


def _cleanup_role(directory: Path, fixture: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        _remove_path(Path(str(fixture["role_root"])))
    except OSError as exc:
        errors.append(f"remove disposable nanobot role root: {exc}")
    if Path(str(fixture["role_root"])).exists():
        errors.append("disposable nanobot role root remains")
    try:
        if (
            Path(str(fixture["host_canary"])).read_text(encoding="utf-8")
            != CANARY_CONTENT
        ):
            errors.append("host-effect canary changed")
    except OSError as exc:
        errors.append(f"host-effect canary verification: {exc}")
    return errors


def _source_anchor(stage: str, detail: Mapping[str, Any]) -> str:
    if stage == "prompt_received":
        return "nanobot/cli/commands.py:700"
    if stage == "provider_request":
        return "nanobot/providers/custom_provider.py:41"
    if stage == "provider_tool_call_or_decision":
        return "nanobot/providers/custom_provider.py:54"
    if stage == "registry_or_native_dispatch":
        return "nanobot/agent/tools/registry.py:38"
    if stage == "handler_entered":
        return "nanobot/agent/tools/shell.py:78"
    if stage in {"controlled_argument_recorded", "gate_observed", "missing_check_boundary_confirmed"}:
        return "nanobot/agent/tools/shell.py:83"
    if stage in {"sink_reached", "pre_effect_interception", "target_completed"}:
        return "nanobot/agent/tools/shell.py:94"
    return "src/runtime_validation/nanobot_l2.py"


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
        "case_id": _case_id(case),
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{_case_id(case)}:{attempt}:{role}",
        "fixture_id": f"nanobot-l2:{_case_id(case)}:{role}",
        "ordinal": 0,
        "source_anchor": "src/runtime_validation/nanobot_l2.py",
        "detail": dict(detail),
    }


def _expected_stages(case: Mapping[str, Any], role: str) -> tuple[str, ...]:
    stages = list(NORMALIZED_STAGES)
    if _family(case) == "missing-safe-read":
        stages.remove("gate_observed")
    elif role == "control":
        stages.remove("missing_check_boundary_confirmed")
    if role == "control":
        return tuple(stages)
    if _family(case) == "workspace-boundary":
        return tuple(
            stage
            for stage in stages
            if stage
            not in {
                "missing_check_boundary_confirmed",
                "sink_reached",
                "pre_effect_interception",
                "target_completed",
            }
        )
    return tuple(
        stage
        for stage in stages
        if stage != "missing_check_boundary_confirmed"
        or _family(case) == "missing-safe-read"
    )


def _normalize_events(
    *,
    raw_events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    source_bindings: Mapping[str, str],
    fixture: Mapping[str, Any],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    cleanup_errors: list[str],
) -> list[dict[str, Any]]:
    events = [
        _base_event(
            "case_bound",
            {"candidate_binding": dict(case["candidate_binding"])},
            case,
            attempt,
            role,
        ),
        _base_event(
            "source_verified",
            {
                "revision": PROJECT.analysis_revision,
                "source_hashes": dict(source_bindings),
            },
            case,
            attempt,
            role,
        ),
        _base_event(
            "fixture_prepared",
            {
                "allow_patterns": fixture["allow_patterns"],
                "restrict_to_workspace": fixture["restrict_to_workspace"],
                "provider_base_url": fixture["provider_base_url"],
                "config_sha256": fixture["config_sha256"],
            },
            case,
            attempt,
            role,
        ),
        _base_event(
            "launch_started",
            {"entrypoint": "nanobot agent", "transport": "cli-one-shot"},
            case,
            attempt,
            role,
        ),
    ]
    expected = _expected_stages(case, role)
    rank = {stage: index for index, stage in enumerate(expected)}
    allowed = set(expected)
    for raw in sorted(
        raw_events,
        key=lambda row: rank.get(str(row.get("stage")), 10**6),
    ):
        stage = str(raw.get("stage"))
        if stage not in allowed:
            raise ValidationError(f"unexpected nanobot event stage: {stage}")
        event = _base_event(
            stage, dict(raw.get("detail") or {}), case, attempt, role
        )
        events.append(event)
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
        event["ordinal"] = ordinal
        event["event_id"] = f"{event['correlation_id']}:{ordinal}"
        event["source_anchor"] = _source_anchor(
            str(event["stage"]), event["detail"]
        )
    return events


def _transcript_errors(
    rows: list[Mapping[str, Any]],
) -> list[str]:
    chat_rows = [
        row for row in rows if row.get("path") == "/v1/chat/completions"
    ]
    errors: list[str] = []
    unsupported = [row for row in rows if row.get("valid") is not True]
    if unsupported:
        errors.append("provider received an unsupported or invalid endpoint")
    if not 1 <= len(chat_rows) <= 2:
        errors.append(f"provider request count drifted: {len(chat_rows)}")
        return errors
    first = chat_rows[0]
    if first.get("request_kind") != "forced-tool-call":
        errors.append("first provider exchange was not the forced tool call")
    if first.get("model") != MODEL_NAME:
        errors.append("provider model drift")
    if first.get("stream") is not False:
        errors.append("nanobot custom provider protocol drift")
    if "exec" not in (first.get("tool_names") or []):
        errors.append("provider request did not advertise exec")
    if first.get("authorization_valid") is not True or first.get(
        "authorization_redacted"
    ) != "Bearer [REDACTED_CREDENTIAL]":
        errors.append("provider authorization/redaction drift")
    if len(chat_rows) > 1 and chat_rows[1].get("request_kind") != "continuation":
        errors.append("provider continuation accounting drift")
    return errors


def _sink_matches(
    case: Mapping[str, Any],
    role: str,
    detail: Mapping[str, Any],
) -> bool:
    if role != "exploit":
        return False
    command = str(detail.get("command", ""))
    family = _family(case)
    if command != _controlled_value(case, "exploit"):
        return False
    if family == "comment-tail":
        return (
            command.startswith("touch nanobot-comment-canary")
            and " # echo allowlisted" in command
        )
    if family == "shell-chain":
        return (
            command.startswith("echo allowlisted;")
            and "touch nanobot-chain-canary" in command
        )
    if family == "wrapper-prefix":
        return (
            command.startswith("env bash -lc 'echo allowlisted")
            and "&& touch nanobot-wrapper-canary" in command
        )
    if family == "missing-safe-read":
        return command == "cat /etc/passwd"
    return False


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    process_exit: int,
    errors: list[str],
) -> PairOutcome:
    all_errors = [*errors, *_transcript_errors(provider_rows)]
    if process_exit != 0:
        all_errors.append(f"process exit drift: {process_exit}")
    stages = [str(event.get("stage")) for event in events]
    expected = _expected_stages(case, role)
    if stages != list(expected):
        all_errors.append("event identity or order drift")
    controlled = [
        event
        for event in events
        if event.get("stage") == "controlled_argument_recorded"
    ]
    if len(controlled) != 1:
        all_errors.append("controlled argument witness count drift")
    elif (
        controlled[0].get("detail", {}).get("command")
        != _controlled_value(case, role)
    ):
        all_errors.append("controlled command drift")
    sink_events = [event for event in events if event.get("stage") == "sink_reached"]
    interception = [
        event
        for event in events
        if event.get("stage") == "pre_effect_interception"
    ]
    if role == "control":
        if len(sink_events) != 1 or len(interception) != 1:
            all_errors.append("safe control did not reach the intercepted sink")
        elif interception[0].get("detail", {}).get("executed") is not False:
            all_errors.append("control interception was not pre-effect")
    elif _family(case) == "workspace-boundary":
        gate = [event for event in events if event.get("stage") == "gate_observed"]
        if len(gate) != 1 or gate[0].get("detail", {}).get("decision") != "blocked":
            all_errors.append("workspace boundary did not produce a healthy block")
    else:
        if len(sink_events) != 1 or len(interception) != 1:
            all_errors.append("exploit did not reach the reviewed sink")
    healthy = not all_errors
    triggered = (
        healthy
        and role == "exploit"
        and len(sink_events) == 1
        and _sink_matches(case, "exploit", sink_events[0].get("detail", {}))
    )
    return PairOutcome(healthy, triggered, all_errors)


def _run_role_attempt(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    build_python: Path,
    source_bindings: Mapping[str, str],
    request: NanobotL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    directory.mkdir(parents=True, exist_ok=True)
    transcript_path = directory / "provider-transcript.jsonl"
    fixture: dict[str, Any] = {}
    launch_errors: list[str] = []
    process_exit = 1
    try:
        provider = NanobotProviderServer(
            role=role,
            arguments=_role_arguments(case, role),
            transcript_path=transcript_path,
        )
        role_root, prepared = _prepare_role(
            directory=directory,
            case=case,
            role=role,
            attempt=attempt,
            provider_port=provider.port,
        )
        fixture = prepared
        process_exit, launch_errors = _launch_and_prompt(
            case=case,
            role=role,
            attempt=attempt,
            directory=directory,
            role_root=role_root,
            fixture=fixture,
            build_project=build_project,
            build_python=build_python,
            provider=provider,
            request=request,
        )
    except Exception as exc:
        launch_errors.append(f"{type(exc).__name__}: {exc}")
        atomic_write_text(
            directory / "launch-error.log",
            redact_text(f"{type(exc).__name__}: {exc}\n"),
        )
    cleanup_errors = (
        _cleanup_role(directory, fixture) if fixture else ["role fixture was not prepared"]
    )
    try:
        raw_events = _read_jsonl(directory / "events.raw.jsonl")
        provider_rows = _read_jsonl(transcript_path)
        events = _normalize_events(
            raw_events=raw_events,
            provider_rows=provider_rows,
            source_bindings=source_bindings,
            fixture=fixture
            or {"role_root": str(directory / "missing-runtime")},
            case=case,
            attempt=attempt,
            role=role,
            cleanup_errors=cleanup_errors,
        )
        _write_jsonl(directory / "events.jsonl", events)
        outcome = _evaluate_pair(
            case,
            role,
            events,
            provider_rows,
            process_exit,
            [*launch_errors, *cleanup_errors],
        )
        return outcome, events
    except Exception as exc:
        return PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []


def _candidate_disposition(outcomes: list[PairOutcome]) -> tuple[str, str]:
    if any(not outcome.healthy for outcome in outcomes):
        return "inconclusive", "one or more paired attempts had infrastructure or trace failures"
    if all(outcome.triggered for outcome in outcomes):
        return "runtime-confirmed", "all paired forced-provider E2E attempts satisfied the oracle"
    if not any(outcome.triggered for outcome in outcomes):
        return "not-reproduced", "all paired attempts completed without the exploit witness"
    return "inconclusive", "paired exploit outcomes were inconsistent"


def _artifact_credential_scan(root: Path) -> str:
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    )
    return "failed" if contains_credentials(text) else "passed"


def _artifact_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }


def _reproduction_command(request: NanobotL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-nanobot-l2"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.campaign.resolve() != DEFAULT_SOURCE_CAMPAIGN.resolve():
        command += f" --campaign {request.campaign}"
    if request.candidate_id is not None:
        command += f" --candidate-id {request.candidate_id}"
    return command


def run_nanobot_l2(request: NanobotL2RunRequest) -> dict[str, Any]:
    started = datetime.now(timezone.utc).timestamp()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError("nanobot targeted L2 timeouts and attempts must be positive")
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    cases, payload_repairs = _select_cases(
        request.campaign.resolve(), request.candidate_id
    )
    source_bindings = _source_bindings(cases)
    build_dir = (
        request.build_dir.resolve()
        if request.build_dir
        else request.out_dir.resolve() / "build"
    )
    build_manifest = _prepare_build(
        build_dir, source_bindings, request.build_timeout
    )
    build_project = build_dir / "project"
    build_python = build_dir / ".clawgap-venv/bin/python"
    if request.build_dir is None:
        shutil.copyfile(
            build_dir / "transformed-source-manifest.json",
            request.out_dir.resolve() / "transformed-source-manifest.json",
        )
    else:
        published = request.out_dir.resolve() / "transformed-source-manifest.json"
        _remove_path(published)
        shutil.copyfile(build_dir / "transformed-source-manifest.json", published)

    repairs_by_candidate = {
        str(row["candidate_id"]): row for row in payload_repairs
    }
    results: list[dict[str, Any]] = []
    for case in cases:
        pair_outcomes: list[PairOutcome] = []
        for attempt in range(1, request.attempts + 1):
            role_outcomes: dict[str, PairOutcome] = {}
            for role in ("exploit", "control"):
                directory = (
                    request.out_dir
                    / "runs"
                    / _case_id(case)
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
                "case_id": _case_id(case),
                "project": "nanobot",
                "disposition": disposition,
                "evidence_tier": L2_EVIDENCE_TIER,
                "attempts": request.attempts,
                "reason": reason,
                "attempt_errors": [
                    outcome.errors for outcome in pair_outcomes if outcome.errors
                ],
                "payload_repair_applied": _candidate_id(case) in repairs_by_candidate,
                "payload_repair": repairs_by_candidate.get(_candidate_id(case)),
                "trace_accounting": {
                    "expected": request.attempts * 2,
                    "valid": sum(
                        outcome.healthy for outcome in pair_outcomes
                    )
                    * 2,
                    "blocked": sum(
                        not outcome.healthy for outcome in pair_outcomes
                    )
                    * 2,
                    "not_launched": 0
                    if all(outcome.healthy for outcome in pair_outcomes)
                    else sum(
                        2 for outcome in pair_outcomes if not outcome.healthy
                    ),
                },
            }
        )

    if request.build_dir is None:
        _remove_path(build_dir)
    _write_jsonl(request.out_dir / "cases.jsonl", cases)
    _write_jsonl(request.out_dir / "payload-repairs.jsonl", payload_repairs)
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "candidate_id": row["candidate_id"],
                "case_id": row["case_id"],
                "project": "nanobot",
                "status": row["disposition"],
                "evidence_tier": row["evidence_tier"],
            }
            for row in results
        ],
    )
    counts: dict[str, int] = {}
    for row in results:
        counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1
    disposable_roots_removed = not any(
        path.is_dir()
        for path in (request.out_dir / "runs").rglob("*")
        if path.name == "runtime"
    )
    credential_scan = _artifact_credential_scan(request.out_dir.resolve())
    if credential_scan != "passed" or not disposable_roots_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
        counts = {"inconclusive": len(results)}
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-nanobot-l2-manifest/v1",
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
        "transformed_source_manifest": build_manifest,
        "credential_scan": credential_scan,
        "disposable_roots_removed": disposable_roots_removed,
        "disposable_workspaces_removed": disposable_roots_removed,
        "artifact_sha256": _artifact_hashes(request.out_dir.resolve()),
        "reproduction_command": _reproduction_command(request),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "completed_at": _utc_now(),
    }
    atomic_write_json(request.out_dir.resolve() / "manifest.json", manifest)
    return manifest
