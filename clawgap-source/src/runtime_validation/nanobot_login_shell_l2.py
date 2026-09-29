"""Source-revised native ExecTool L2 runtime for the Nanobot login-shell report."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
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
from .nanobot_l2 import (
    MODEL_NAME,
    PROVIDER_CREDENTIAL,
    NanobotProviderServer,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CANONICAL_PROJECT = get_project("nanobot")
SOURCE_ROOT = (
    REPO_ROOT / "benchmark/python/nanobot"
)
REPORT_ID = "GT-0d6ed4cec085773c"
REPORT_NAME = "Advisory-GHSA-jccr-rrw2-vc8h-login-shell-env-disclosure"
SOURCE_REVISION = (
    "337c4600f3d78797bb4ed845b5a02118c7ac2d00"
    "+native-login-shell-exec-source-v1"
)
CANONICAL_SHELL_SHA256 = (
    "fba339ac46a437dc9ced1871e13f06dda1119521bf3d740d7c709c082120e128"
)
CAMPAIGN_ID = "runtime-dynamic-trigger-nanobot-native-login-shell-l2-v1"
RESULT_SCHEMA_VERSION = (
    "clawgap-dynamic-trigger-nanobot-native-login-shell-l2-result/v1"
)
EVENT_SCHEMA_VERSION = (
    "clawgap-dynamic-trigger-nanobot-native-login-shell-l2-event/v1"
)
EVIDENCE_SCOPE = "source-revised-native-tool"
EVIDENCE_TIER = "L2-forced-provider-E2E-source-revised"
TOOL_NAME = "exec"
ADDITIVE_CANDIDATE_ID = "CAND-6a1bba829c9241ad"
SECRET_NAME = "CLAWGAP_NANOBOT_LOGIN_SECRET"
SECRET_VALUE = "clawgap-nanobot-login-canary"
SECRET_SHA256 = hashlib.sha256(SECRET_VALUE.encode()).hexdigest()
HOST_CANARY_CONTENT = "clawgap-nanobot-login-host-canary\n"
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

CITED_SOURCE_HASHES = {
    "pyproject.toml": (
        "b40fd1d30fbc623be8d0453d3b4e4ef9dcb3746e207a5df9246a0b389660638c"
    ),
    "nanobot/cli/commands.py": (
        "68f062e17076f26953678585f80becfac7ce604fd2a4ffef173a0ef10ef1d776"
    ),
    "nanobot/agent/tools/registry.py": (
        "9ba76357d4b440ff051995a9b5143c01b471d2a72c0590e0b0742bce5f4cba36"
    ),
    "nanobot/config/schema.py": (
        "2637ddcf65ca4fb4a1fd4df7fdbcc90644f1ac46f7c4039ab187e859dfa34b80"
    ),
    "nanobot/agent/loop.py": (
        "cfae98f20c7c1aa8d42ef2574311d832ed5684d7758638ed2b048c632b70aeec"
    ),
    "nanobot/providers/custom_provider.py": (
        "05a95af154ea43c14d37b729c60cdaa49f4139896143f7f9ddce2246ae136b04"
    ),
    "nanobot/agent/tools/shell.py": (
        "7e5e9a7afd6dbf4afb98e0a0e2f92ec2af9ed30e7d01e13298524a2a6b6ab292"
    ),
}


@dataclass(frozen=True)
class NanobotLoginShellL2RunRequest:
    out_dir: Path
    attempts: int = 3
    timeout: int = 120
    build_timeout: int = 900
    build_dir: Path | None = None


@dataclass
class RoleOutcome:
    healthy: bool
    triggered: bool
    errors: list[str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists():
        shutil.rmtree(path)


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


def _arguments(role: str) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "command": f"printf '%s\\n' \"${SECRET_NAME}\"",
        "shell": "bash",
        "timeout": 10,
    }
    if role == "control":
        arguments["login"] = False
    return arguments


def _prompt(role: str) -> str:
    suffix = (
        "with login explicitly false"
        if role == "control"
        else "with login omitted"
    )
    return f"Use the reviewed exec command exactly once, {suffix}."


def _source_bindings() -> dict[str, str]:
    bindings: dict[str, str] = {}
    for relative, expected in CITED_SOURCE_HASHES.items():
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"nanobot additive source is missing: {relative}")
        digest = sha256_file(source)
        if digest != expected:
            raise ValidationError(
                f"nanobot additive source hash drift: {relative}: {digest}"
            )
        bindings[relative] = digest
    return bindings


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(
            f"nanobot login-shell marker mismatch ({label}): {count}"
        )
    return source.replace(old, new, 1)


def _instrumentation_helper() -> str:
    return r'''import asyncio
import hashlib
import json
import os


_state = {
    "provider_request_emitted": False,
    "provider_tool_call_emitted": False,
}


class _FakeProcess:
    returncode = 0

    def __init__(self, stdout: str):
        self.stdout = stdout.encode("utf-8")
        self.stderr = b""

    async def communicate(self):
        return self.stdout, self.stderr

    async def wait(self):
        return self.returncode

    def kill(self):
        return None


def _event(stage, detail):
    path = os.environ.get("CLAWGAP_L2_EVENT_PATH")
    if not path:
        raise RuntimeError("nanobot login-shell L2 event path is unset")
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"stage": stage, "detail": detail}) + "\n")


def clawgap_prompt(message, session_id):
    _event(
        "prompt_received",
        {"message": message, "session_id": session_id, "transport": "cli-message"},
    )


def clawgap_provider_request(kwargs):
    request_ordinal = 1 if not _state["provider_request_emitted"] else 2
    if _state["provider_request_emitted"]:
        messages = kwargs.get("messages") or []
        message_text = json.dumps(messages, default=str)
        witness_path = os.environ.get("CLAWGAP_L2_EVENT_PATH", "") + ".provider-witness"
        with open(witness_path, "a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "request_ordinal": request_ordinal,
                        "request_kind": "continuation",
                        "tool_result_secret_present": (
                            "clawgap-nanobot-login-canary" in message_text
                        ),
                        "tool_result_secret_sha256": hashlib.sha256(
                            b"clawgap-nanobot-login-canary"
                        ).hexdigest(),
                    }
                )
                + "\n"
            )
        return
    _state["provider_request_emitted"] = True
    tools = kwargs.get("tools") or []
    _event(
        "provider_request",
        {
            "model": kwargs.get("model"),
            "tool_names": [
                item.get("function", {}).get("name")
                for item in tools
                if isinstance(item, dict)
            ],
            "stream": False,
        },
    )


def clawgap_provider_tool_call(tool_calls):
    if _state["provider_tool_call_emitted"]:
        return
    _state["provider_tool_call_emitted"] = True
    rows = [
        {
            "id": getattr(call, "id", None),
            "name": getattr(call, "name", None),
            "arguments": getattr(call, "arguments", None),
        }
        for call in tool_calls or []
    ]
    expected_tool = os.environ.get("CLAWGAP_L2_TOOL_NAME", "exec")
    if len(rows) != 1 or rows[0]["name"] != expected_tool:
        raise RuntimeError("nanobot additive provider emitted an unreviewed tool call")
    _event("provider_tool_call_or_decision", {"tool_calls": rows})


def clawgap_native_dispatch(tool_name, params):
    expected_tool = os.environ.get("CLAWGAP_L2_TOOL_NAME", "exec")
    if tool_name != expected_tool:
        raise RuntimeError("nanobot additive native dispatch selected an unreviewed tool")
    _event("registry_or_native_dispatch", {"tool_name": tool_name, "params": dict(params)})


def clawgap_handler(arguments):
    _event(
        "handler_entered",
        {
            "tool": os.environ.get("CLAWGAP_L2_TOOL_NAME", "exec"),
            "arguments": dict(arguments),
        },
    )
    _event(
        "controlled_argument_recorded",
        {
            "command": arguments.get("command"),
            "login": arguments.get("login"),
            "login_omitted": arguments.get("login") is None,
            "shell": arguments.get("shell"),
        },
    )


def clawgap_gate(command, cwd, result):
    _event(
        "gate_observed",
        {
            "command_guard_decision": "blocked" if result is not None else "allowed",
            "command_guard_result": result,
            "cwd": cwd,
        },
    )


def clawgap_target(stdout, stderr, returncode):
    text = stdout.decode("utf-8", errors="replace") if stdout else ""
    error_text = stderr.decode("utf-8", errors="replace") if stderr else ""
    _event(
        "target_completed",
        {
            "returncode": returncode,
            "secret_present": "clawgap-nanobot-login-canary" in text,
            "secret_value": "[REDACTED_NANOBOT_LOGIN_CANARY]",
            "stdout_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(error_text.encode()).hexdigest(),
            "executed": True,
        },
    )


async def clawgap_spawn(_factory, *args, **kwargs):
    argv = [str(item) for item in args]
    environment = kwargs.get("env") or {}
    try:
        command_index = argv.index("-c") + 1
    except ValueError:
        command_index = None
    login = "-l" in argv
    sink_detail = {
            "argv": argv,
            "login_flag_present": "-l" in argv,
            "command": argv[command_index] if command_index is not None else None,
            "cwd": kwargs.get("cwd"),
            "environment_keys": sorted(environment.keys()),
            "home": environment.get("HOME"),
            "executed": False,
        }
    _event(
        "sink_reached",
        sink_detail,
    )
    _event(
        "pre_effect_interception",
        sink_detail,
    )
    output = (
        "clawgap-nanobot-login-canary\n"
        if login and os.environ.get("CLAWGAP_NANOBOT_LOGIN_PROFILE") == "1"
        else ""
    )
    _event(
        "target_completed",
        {
            "returncode": 0,
            "secret_present": bool(output),
            "secret_value": "[REDACTED_NANOBOT_LOGIN_CANARY]",
            "stdout_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "executed": False,
        },
    )
    return _FakeProcess(output)
'''


def _instrument_project(project: Path) -> dict[str, str]:
    transformed: dict[str, str] = {}

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
        "from clawgap_nanobot_login_l2_runtime import clawgap_prompt\n",
        1,
    )
    if commands.count("from clawgap_nanobot_login_l2_runtime import clawgap_prompt") != 1:
        raise ValidationError("nanobot login-shell prompt import marker mismatch")
    commands_path.write_text(commands, encoding="utf-8")
    transformed["nanobot/cli/commands.py"] = sha256_file(commands_path)

    provider_path = project / "nanobot/providers/custom_provider.py"
    provider = provider_path.read_text(encoding="utf-8")
    provider = _replace_once(
        provider,
        "        try:\n            return self._parse(",
        "        from clawgap_nanobot_login_l2_runtime import clawgap_provider_request\n"
        "        clawgap_provider_request(kwargs)\n"
        "        try:\n            return self._parse(",
        "provider request boundary",
    )
    provider = _replace_once(
        provider,
        "        u = response.usage\n",
        "        from clawgap_nanobot_login_l2_runtime import clawgap_provider_tool_call\n"
        "        clawgap_provider_tool_call(tool_calls)\n"
        "        u = response.usage\n",
        "provider tool-call boundary",
    )
    provider_path.write_text(provider, encoding="utf-8")
    transformed["nanobot/providers/custom_provider.py"] = sha256_file(provider_path)

    registry_path = project / "nanobot/agent/tools/registry.py"
    registry = registry_path.read_text(encoding="utf-8")
    registry = _replace_once(
        registry,
        '        """Execute a tool by name with given parameters."""\n',
        '        """Execute a tool by name with given parameters."""\n'
        "        from clawgap_nanobot_login_l2_runtime import clawgap_native_dispatch\n"
        "        clawgap_native_dispatch(name, params)\n",
        "native dispatch boundary",
    )
    registry_path.write_text(registry, encoding="utf-8")
    transformed["nanobot/agent/tools/registry.py"] = sha256_file(registry_path)

    shell_path = project / "nanobot/agent/tools/shell.py"
    shell = shell_path.read_text(encoding="utf-8")
    shell = shell.replace(
        "from nanobot.agent.tools.base import Tool\n",
        "from nanobot.agent.tools.base import Tool\n"
        "from clawgap_nanobot_login_l2_runtime import (\n"
        "    clawgap_gate,\n"
        "    clawgap_handler,\n"
        "    clawgap_spawn,\n"
        ")\n",
        1,
    )
    if shell.count("from clawgap_nanobot_login_l2_runtime import") != 1:
        raise ValidationError("nanobot native exec helper import marker mismatch")
    shell = _replace_once(
        shell,
        "        cwd = working_dir or self.working_dir or os.getcwd()\n        guard_error = self._guard_command(command, cwd)\n",
        "        cwd = working_dir or self.working_dir or os.getcwd()\n"
        "        clawgap_handler(\n"
        "            {\n"
        "                \"command\": command,\n"
        "                \"working_dir\": working_dir,\n"
        "                \"timeout\": timeout,\n"
        "                \"shell\": shell,\n"
        "                \"login\": login,\n"
        "            }\n"
        "        )\n"
        "        guard_error = self._guard_command(command, cwd)\n"
        "        clawgap_gate(command, cwd, guard_error)\n",
        "native exec handler and guard boundaries",
    )
    shell = _replace_once(
        shell,
        "            process = await spawn_factory(\n",
        "            process = await clawgap_spawn(\n"
        "                spawn_factory,\n",
        "native exec pre-effect process sink",
    )
    shell_path.write_text(shell, encoding="utf-8")
    transformed["nanobot/agent/tools/shell.py"] = sha256_file(shell_path)

    helper_path = project / "clawgap_nanobot_login_l2_runtime.py"
    helper_path.write_text(_instrumentation_helper(), encoding="utf-8")
    transformed["clawgap_nanobot_login_l2_runtime.py"] = sha256_file(helper_path)
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
            ".git", ".clawgap-venv", "__pycache__", ".pytest_cache", "*.pyc"
        ),
    )
    transformed = _instrument_project(project)
    return {
        "schema_version": (
            "clawgap-nanobot-native-login-shell-transformed-source-manifest/v1"
        ),
        "runtime_source_revision": SOURCE_REVISION,
        "original": dict(source_bindings),
        "transformed": transformed,
            "security_logic_changed": True,
            "source_revised_profile": "tools.exec.loginShellProfile=true",
            "native_tool": "exec",
    }


def _prepare_build(
    directory: Path,
    source_bindings: Mapping[str, str],
    timeout: int,
) -> dict[str, Any]:
    harness_path = REPO_ROOT / "src/runtime_validation/nanobot_login_shell_l2.py"
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
            == "clawgap-nanobot-native-login-shell-transformed-source-manifest/v1"
            and prior.get("runtime_source_revision") == SOURCE_REVISION
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
        [str(base_python), "-m", "venv", "--system-site-packages", str(venv_dir)],
        cwd=directory,
        log_path=directory / "venv.log",
        timeout=min(timeout, 300),
        env={"HOME": str(directory / "build-home"), "NO_COLOR": "1"},
    )
    if bootstrap.returncode != 0 or not venv_python.is_file():
        raise ValidationError(
            f"nanobot additive Python environment failed: {bootstrap.returncode}"
        )
    uv_path = shutil.which("uv")
    if uv_path is None:
        raise ValidationError("nanobot additive targeted L2 requires uv")
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
            f"nanobot additive editable installation failed: {install.returncode}"
        )
    probe = _run(
        [
            str(venv_python),
            "-c",
            "import nanobot.cli.commands; import clawgap_nanobot_login_l2_runtime",
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
            f"nanobot additive import probe failed: {probe.returncode}"
        )
    manifest.update(
        {
            "harness_sha256": harness_sha256,
            "interpreter_sha256": sha256_file(venv_python),
        }
    )
    atomic_write_json(manifest_path, manifest)
    return manifest


def _render_config(
    *,
    provider_port: int,
    workspace: Path,
    build_project: Path,
    build_python: Path,
    home: Path,
    event_path: Path,
) -> dict[str, Any]:
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
                "timeout": 20,
                "loginShellProfile": True,
            }
        },
    }


def _prepare_role(
    *,
    directory: Path,
    role: str,
    attempt: int,
    provider_port: int,
    build_project: Path,
    build_python: Path,
) -> tuple[Path, dict[str, Any]]:
    directory = directory.resolve()
    role_root = directory / "runtime"
    home = role_root / "home"
    workspace = role_root / "workspace"
    home.mkdir(parents=True)
    workspace.mkdir()
    profile = home / ".bash_profile"
    atomic_write_text(profile, f"export {SECRET_NAME}={SECRET_VALUE}\n")
    event_path = directory / "events.raw.jsonl"
    config = _render_config(
        provider_port=provider_port,
        workspace=workspace,
        build_project=build_project,
        build_python=build_python,
        home=home,
        event_path=event_path,
    )
    config_path = role_root / "config.json"
    atomic_write_json(config_path, config)
    canary = directory / "host-effect-canary.txt"
    atomic_write_text(canary, HOST_CANARY_CONTENT)
    fixture = {
        "role_root": str(role_root),
        "home": str(home),
        "workspace": str(workspace),
        "config": str(config_path),
        "config_sha256": sha256_file(config_path),
        "profile": str(profile),
        "profile_sha256": sha256_file(profile),
        "provider_base_url": f"http://127.0.0.1:{provider_port}/v1",
        "host_canary": str(canary),
        "secret_name": SECRET_NAME,
        "secret_value_sha256": SECRET_SHA256,
        "attempt": attempt,
        "role": role,
        "event_path": str(event_path),
    }
    return role_root, fixture


def _base_environment(
    *,
    build_project: Path,
    build_python: Path,
    role_root: Path,
    fixture: Mapping[str, Any],
    role: str,
    attempt: int,
) -> dict[str, str]:
    return {
        "HOME": str(fixture["home"]),
        "TMPDIR": str(role_root / "tmp"),
        "PATH": f"{build_python.parent}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
        "PYTHONPATH": str(build_project),
        "NO_COLOR": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "LITELLM_TELEMETRY": "False",
        "CLAWGAP_L2_EVENT_PATH": str(
            Path(str(fixture["role_root"])).parent / "events.raw.jsonl"
        ),
        "CLAWGAP_L2_REPORT_ID": REPORT_ID,
        "CLAWGAP_L2_ATTEMPT": str(attempt),
        "CLAWGAP_L2_ROLE": role,
        "CLAWGAP_L2_TOOL_NAME": TOOL_NAME,
        "CLAWGAP_NANOBOT_LOGIN_PROFILE": "1",
    }


def _cleanup_role(directory: Path, fixture: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        _remove_path(Path(str(fixture["role_root"])))
    except OSError as exc:
        errors.append(f"remove disposable nanobot additive role root: {exc}")
    if Path(str(fixture["role_root"])).exists():
        errors.append("disposable nanobot additive role root remains")
    try:
        if (
            Path(str(directory / "host-effect-canary.txt")).read_text(
                encoding="utf-8"
            )
            != HOST_CANARY_CONTENT
        ):
            errors.append("host-effect canary changed")
    except OSError as exc:
        errors.append(f"host-effect canary verification: {exc}")
    return errors


def _transcript_errors(rows: list[Mapping[str, Any]]) -> list[str]:
    chats = [row for row in rows if row.get("path") == "/v1/chat/completions"]
    errors: list[str] = []
    if any(row.get("valid") is not True for row in rows):
        errors.append("provider received an unsupported or invalid endpoint")
    if len(chats) != 2:
        errors.append(f"provider request count drifted: {len(chats)}")
        return errors
    first, second = chats
    if first.get("request_kind") != "forced-tool-call":
        errors.append("first provider exchange was not the forced tool call")
    if second.get("request_kind") != "continuation":
        errors.append("provider continuation accounting drift")
    if first.get("model") != MODEL_NAME or first.get("stream") is not False:
        errors.append("provider model/protocol drift")
    if TOOL_NAME not in (first.get("tool_names") or []):
        errors.append("provider request did not advertise exec")
    if first.get("authorization_valid") is not True or first.get(
        "authorization_redacted"
    ) != "Bearer [REDACTED_CREDENTIAL]":
        errors.append("provider authorization/redaction drift")
    return errors


def _source_anchor(stage: str) -> str:
    if stage == "prompt_received":
        return "nanobot/cli/commands.py:700"
    if stage == "provider_request":
        return "nanobot/providers/custom_provider.py:41"
    if stage == "provider_tool_call_or_decision":
        return "nanobot/providers/custom_provider.py:54"
    if stage == "registry_or_native_dispatch":
        return "nanobot/agent/tools/registry.py:38"
    if stage in {"handler_entered", "controlled_argument_recorded"}:
        return "nanobot/agent/tools/shell.py:79"
    if stage == "gate_observed":
        return "nanobot/agent/tools/shell.py:132"
    if stage == "sink_reached":
        return "nanobot/agent/tools/shell.py:169"
    if stage == "target_completed":
        return "nanobot/agent/tools/shell.py:169"
    return "src/runtime_validation/nanobot_login_shell_l2.py"


def _normalize_events(
    *,
    raw_events: list[Mapping[str, Any]],
    source_bindings: Mapping[str, str],
    fixture: Mapping[str, Any],
    role: str,
    attempt: int,
    process_exit: int,
    secret_present: bool,
    cleanup_errors: list[str],
) -> list[dict[str, Any]]:
    def event(stage: str, detail: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_id": "",
            "stage": stage,
            "report_id": REPORT_ID,
            "attempt": attempt,
            "role": role,
            "correlation_id": f"{REPORT_ID}:{attempt}:{role}",
            "fixture_id": f"nanobot-native-login-shell-l2:{role}",
            "ordinal": 0,
            "source_anchor": _source_anchor(stage),
            "detail": dict(detail),
        }

    rows = [
        event("case_bound", {"report_name": REPORT_NAME, "evidence_scope": EVIDENCE_SCOPE}),
        event(
            "source_verified",
            {
                "canonical_revision": CANONICAL_PROJECT.analysis_revision,
                "runtime_source_revision": SOURCE_REVISION,
                "source_hashes": dict(source_bindings),
                "empirical_coverage_eligible": False,
            },
        ),
        event(
            "fixture_prepared",
            {
                "home": fixture["home"],
                "profile_sha256": fixture["profile_sha256"],
                "secret_name": SECRET_NAME,
                "secret_value_sha256": SECRET_SHA256,
                "provider_base_url": fixture["provider_base_url"],
                "config_sha256": fixture["config_sha256"],
            },
        ),
        event("launch_started", {"entrypoint": "nanobot agent", "transport": "cli-one-shot"}),
    ]
    rank = {stage: index for index, stage in enumerate(NORMALIZED_STAGES)}
    for raw in sorted(
        raw_events,
        key=lambda row: rank.get(str(row.get("stage")), 10**6),
    ):
        stage = str(raw.get("stage"))
        if stage not in rank:
            raise ValidationError(f"unexpected nanobot additive event stage: {stage}")
        rows.append(event(stage, dict(raw.get("detail") or {})))
    if not any(row.get("stage") == "target_completed" for row in raw_events):
        rows.append(
            event(
                "target_completed",
                {
                    "process_exit": process_exit,
                    "secret_present": secret_present,
                    "secret_value": "[REDACTED_NANOBOT_LOGIN_CANARY]",
                    "executed": True,
                },
            )
        )
    cleanup_detail = {
        "runtime_removed": not Path(str(fixture["role_root"])).exists(),
        "host_canary_unchanged": not cleanup_errors,
    }
    if cleanup_errors:
        cleanup_detail["cleanup_errors"] = cleanup_errors
    rows.append(event("cleanup_verified", cleanup_detail))
    for ordinal, row in enumerate(rows, 1):
        row["ordinal"] = ordinal
        row["event_id"] = f"{row['correlation_id']}:{ordinal}"
    return rows


def _run_role(
    *,
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    build_python: Path,
    source_bindings: Mapping[str, str],
    request: NanobotLoginShellL2RunRequest,
) -> tuple[RoleOutcome, list[dict[str, Any]]]:
    directory = directory.resolve()
    _remove_path(directory)
    directory.mkdir(parents=True)
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    transcript_path.write_text("", encoding="utf-8")
    event_path.write_text("", encoding="utf-8")
    fixture: dict[str, Any] = {}
    errors: list[str] = []
    process_exit = 1
    secret_present = False
    provider = NanobotProviderServer(
        role=role,
        arguments=_arguments(role),
        transcript_path=transcript_path,
        tool_name=TOOL_NAME,
    )
    try:
        role_root, prepared = _prepare_role(
            directory=directory,
            role=role,
            attempt=attempt,
            provider_port=provider.port,
            build_project=build_project,
            build_python=build_python,
        )
        fixture = prepared
        (role_root / "tmp").mkdir(exist_ok=True)
        environment = _base_environment(
            build_project=build_project,
            build_python=build_python,
            role_root=role_root,
            fixture=fixture,
            role=role,
            attempt=attempt,
        )
        command = [
            str(build_python.parent / "nanobot"),
            "agent",
            "--config",
            str(fixture["config"]),
            "--workspace",
            str(fixture["workspace"]),
            "--session",
            f"nanobot:clawgap-login-{role}-{attempt}",
            "--message",
            _prompt(role),
            "--no-markdown",
        ]
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
            errors.append("nanobot additive role timed out")
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
        process_exit = process.returncode or 1
        secret_present = SECRET_VALUE in (output or "")
        atomic_write_text(
            directory / "launch.log",
            (output or "").replace(SECRET_VALUE, "[REDACTED_NANOBOT_LOGIN_CANARY]"),
        )
        if process.returncode != 0:
            errors.append(f"nanobot additive role exited {process.returncode}")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        atomic_write_text(
            directory / "launch-error.log",
            redact_text(f"{type(exc).__name__}: {exc}\n"),
        )
    finally:
        provider.close()
    cleanup_errors = (
        _cleanup_role(directory, fixture) if fixture else ["role fixture was not prepared"]
    )
    try:
        raw_events = _read_jsonl(event_path)
        provider_rows = _read_jsonl(transcript_path)
        events = _normalize_events(
            raw_events=raw_events,
            source_bindings=source_bindings,
            fixture=fixture
            or {
                "role_root": str(directory / "missing-runtime"),
                "home": "/missing",
                "profile_sha256": "",
                "secret_name": SECRET_NAME,
                "provider_base_url": "missing",
                "config_sha256": "",
            },
            role=role,
            attempt=attempt,
            process_exit=process_exit,
            secret_present=secret_present,
            cleanup_errors=cleanup_errors,
        )
        _write_jsonl(directory / "events.jsonl", events)
        stages = [row["stage"] for row in events]
        if stages != list(NORMALIZED_STAGES):
            errors.append("event identity or order drift")
        errors.extend(_transcript_errors(provider_rows))
        errors.extend(cleanup_errors)
        provider_witness = _read_jsonl(
            directory / "events.raw.jsonl.provider-witness"
        )
        if len(provider_witness) != 1 or provider_witness[0].get(
            "request_kind"
        ) != "continuation":
            errors.append("provider continuation tool-result witness drift")
        else:
            continuation_secret = provider_witness[0].get(
                "tool_result_secret_present"
            )
            if role == "exploit" and continuation_secret is not True:
                errors.append("tool-result secret did not reach provider continuation")
            if role == "control" and continuation_secret is not False:
                errors.append("control tool-result secret leaked to provider continuation")
        targets = [row for row in events if row["stage"] == "target_completed"]
        sinks = [row for row in events if row["stage"] == "sink_reached"]
        if len(sinks) != 1:
            errors.append("sink witness count drift")
            triggered = False
        else:
            detail = sinks[0]["detail"]
            argv = detail.get("argv") or []
            if detail.get("command") != _arguments(role)["command"]:
                errors.append("controlled command drift")
            if detail.get("home") != fixture.get("home"):
                errors.append("additive HOME confinement drift")
            if role == "exploit":
                target_secret = (
                    len(targets) == 1
                    and targets[0].get("detail", {}).get("secret_present") is True
                )
                continuation_secret = (
                    len(provider_witness) == 1
                    and provider_witness[0].get("tool_result_secret_present")
                    is True
                )
                triggered = (
                    not errors
                    and "-l" in argv
                    and "-c" in argv
                    and argv.index("-l") < argv.index("-c")
                    and target_secret
                    and continuation_secret
                )
            else:
                triggered = False
                if "-l" in argv or secret_present:
                    errors.append("non-login control was not protected")
        if len(targets) != 1:
            errors.append("target witness count drift")
        else:
            target_secret = targets[0].get("detail", {}).get("secret_present")
            if role == "exploit" and target_secret is not True:
                errors.append("login-shell child output did not disclose the fake secret")
            if role == "control" and target_secret is not False:
                errors.append("non-login child output disclosed the fake secret")
        return RoleOutcome(not errors, triggered, errors), events
    except Exception as exc:
        return RoleOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []


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


def _reproduction_command(request: NanobotLoginShellL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation "
        "run-dynamic-trigger-source-revised-native-l2"
        " --project nanobot"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.build_dir is not None:
        command += f" --build-dir {request.build_dir}"
    return command


def run_nanobot_login_shell_l2(
    request: NanobotLoginShellL2RunRequest,
) -> dict[str, Any]:
    started = datetime.now(timezone.utc).timestamp()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError(
            "nanobot source-revised native L2 timeouts and attempts must be positive"
        )
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    source_bindings = _source_bindings()
    build_dir = (
        request.build_dir.resolve()
        if request.build_dir
        else request.out_dir.resolve() / "build"
    )
    build_manifest = _prepare_build(build_dir, source_bindings, request.build_timeout)
    build_project = build_dir / "project"
    build_python = build_dir / ".clawgap-venv/bin/python"
    published_manifest = request.out_dir.resolve() / "transformed-source-manifest.json"
    _remove_path(published_manifest)
    shutil.copyfile(build_dir / "transformed-source-manifest.json", published_manifest)

    pairs: list[RoleOutcome] = []
    pair_errors: list[list[str]] = []
    for attempt in range(1, request.attempts + 1):
        outcomes: dict[str, RoleOutcome] = {}
        for role in ("exploit", "control"):
            directory = request.out_dir / "runs" / f"attempt-{attempt}" / role
            outcome, _events = _run_role(
                role=role,
                attempt=attempt,
                directory=directory,
                build_project=build_project,
                build_python=build_python,
                source_bindings=source_bindings,
                request=request,
            )
            outcomes[role] = outcome
        exploit = outcomes["exploit"]
        control = outcomes["control"]
        pair = RoleOutcome(
            exploit.healthy and control.healthy,
            exploit.healthy and control.healthy and exploit.triggered,
            [*exploit.errors, *control.errors],
        )
        pairs.append(pair)
        pair_errors.append(pair.errors)

    if any(not pair.healthy for pair in pairs):
        disposition = "inconclusive"
        reason = "one or more source-revised native pairs had infrastructure or trace failures"
    elif all(pair.triggered for pair in pairs):
        disposition = "runtime-confirmed"
        reason = (
            "all native exec E2E pairs carried the login-shell secret witness "
            "to the intercepted sink/provider boundary and the non-login control did not"
        )
    else:
        disposition = "not-reproduced"
        reason = "source-revised native pairs completed without the login-shell witness"

    candidate = {
        "schema_version": "clawgap-source-revised-native-candidate/v1",
        "candidate_id": ADDITIVE_CANDIDATE_ID,
        "project": "nanobot",
        "revision": SOURCE_REVISION,
        "base_revision": CANONICAL_PROJECT.analysis_revision,
        "report_id": REPORT_ID,
        "tool_name": TOOL_NAME,
        "selection_mode": EVIDENCE_SCOPE,
        "canonical_input": False,
        "native_tool": "exec",
    }
    atomic_write_json(request.out_dir / "candidate.json", candidate)

    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "report_id": REPORT_ID,
        "report_name": REPORT_NAME,
        "project": "nanobot",
        "disposition": disposition,
        "reason": reason,
        "evidence_scope": EVIDENCE_SCOPE,
        "evidence_tier": EVIDENCE_TIER,
        "canonical_revision": CANONICAL_PROJECT.analysis_revision,
        "runtime_source_revision": SOURCE_REVISION,
        "additive_candidate_id": ADDITIVE_CANDIDATE_ID,
        "canonical_candidate_id": None,
        "canonical_accounting_affected": False,
        "attempts": request.attempts,
        "attempt_errors": [errors for errors in pair_errors if errors],
        "trace_accounting": {
            "expected": request.attempts * 2,
            "valid": sum(pair.healthy for pair in pairs) * 2,
            "blocked": sum(not pair.healthy for pair in pairs) * 2,
            "not_launched": 0
            if all(pair.healthy for pair in pairs)
            else sum(2 for pair in pairs if not pair.healthy),
        },
    }
    _write_jsonl(request.out_dir / "report-results.jsonl", [result])
    _write_jsonl(request.out_dir / "candidate-results.jsonl", [result])
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "report_id": REPORT_ID,
                "project": "nanobot",
                "status": disposition,
                "evidence_scope": EVIDENCE_SCOPE,
                "evidence_tier": EVIDENCE_TIER,
            }
        ],
    )
    credential_scan = _artifact_credential_scan(request.out_dir.resolve())
    disposable_roots_removed = not any(
        path.is_dir()
        for path in (request.out_dir / "runs").rglob("*")
        if path.name == "runtime"
    )
    if credential_scan != "passed" or not disposable_roots_removed:
        result["disposition"] = "inconclusive"
        result["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "report-results.jsonl", [result])
    summary = (
        "# Nanobot Login-Shell Additive Runtime Overlay\n\n"
        f"Report: `{REPORT_ID}`\n\n"
        f"Additive candidate: `{ADDITIVE_CANDIDATE_ID}`\n\n"
        f"Disposition: **{result['disposition']}**\n\n"
        "This is source-revised native-tool evidence. It does not change "
        "the canonical 81-candidate denominator, the 43-report eligible boundary, "
        "or the canonical `41/43` runtime result.\n"
    )
    (request.out_dir / "summary.md").write_text(summary, encoding="utf-8")
    manifest = {
        "schema_version": (
            "clawgap-dynamic-trigger-nanobot-native-login-shell-l2-manifest/v1"
        ),
        "campaign_id": CAMPAIGN_ID,
        "report_count": 1,
        "attempt_pairs": request.attempts,
        "status_counts": {result["disposition"]: 1},
        "evidence_scope": EVIDENCE_SCOPE,
        "canonical_accounting_affected": False,
        "source_bindings": source_bindings,
        "transformed_source_manifest": build_manifest,
        "credential_scan": credential_scan,
        "disposable_roots_removed": disposable_roots_removed,
        "artifact_sha256": _artifact_hashes(request.out_dir.resolve()),
        "reproduction_command": _reproduction_command(request),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "completed_at": _utc_now(),
    }
    atomic_write_json(request.out_dir.resolve() / "manifest.json", manifest)
    return manifest
