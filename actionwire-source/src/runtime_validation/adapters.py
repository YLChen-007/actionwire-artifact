"""Native tool-dispatch adapter registry and capability-sandbox setup."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from src.projects import get_project

from .campaign_contracts import PROJECT_ADAPTERS
from .contracts import ValidationError, atomic_write_json, atomic_write_text, redact_text


class PairDriver(Protocol):
    def __call__(
        self,
        case: Mapping[str, Any],
        attempt: int,
        attempt_dir: Path,
        sandbox: "CapabilitySandbox",
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class AdapterSpec:
    project_id: str
    adapter_id: str
    language: str
    runtime: str
    driver: PairDriver | None = None
    supported_tools: tuple[str, ...] = ()

    def preflight(self, case: Mapping[str, Any]) -> tuple[bool, str]:
        spec = get_project(self.project_id)
        if case["project"] != self.project_id:
            return False, "adapter/project mismatch"
        if case["revision"] != spec.analysis_revision:
            return False, "case revision does not match project registry"
        if not spec.source_root.is_dir():
            return False, f"benchmark source root is unavailable: {spec.source_root}"
        if self.supported_tools and case["replay"]["tool_name"] not in self.supported_tools:
            return (
                False,
                f"native driver does not support tool {case['replay']['tool_name']!r}",
            )
        if self.runtime == "bun" and shutil.which("bun") is None:
            return False, "Bun runtime is not installed"
        if self.runtime == "node" and shutil.which("node") is None:
            return False, "Node.js runtime is not installed"
        if self.driver is None:
            return (
                False,
                "source-bound native dispatcher driver is not implemented for this project",
            )
        return True, "native dispatcher driver is available"


class CapabilitySandbox:
    """Per-attempt filesystem/network boundary for native replay drivers."""

    def __init__(self, root: Path, case: Mapping[str, Any]) -> None:
        self.root = root
        self.case = case
        self.home = root / "home"
        self.workspace = root / "workspace"
        self.tmp = root / "tmp"
        self.bin = root / "bin"

    def prepare(self) -> Mapping[str, Any]:
        for path in (self.home, self.workspace, self.tmp, self.bin):
            path.mkdir(parents=True, exist_ok=True)
        fixtures: dict[str, Any] = {
            "fixture": self.case["fixture"],
            "root": str(self.root),
            "home": str(self.home),
            "workspace": str(self.workspace),
            "network_policy": "loopback-only",
            "host_writes": False,
        }
        if self.case["fixture"] == "temporary-filesystem":
            allowed = self.workspace / "allowed"
            outside = self.workspace / "outside"
            allowed.mkdir()
            outside.mkdir()
            atomic_write_text(allowed / "safe.txt", "safe control\n")
            atomic_write_text(outside / "secret.txt", "sandbox canary\n")
            fixtures.update({"allowed": str(allowed), "outside": str(outside)})
            fixture_state = self.case.get("fixture_state", {})
            exploit_state = fixture_state.get("exploit", {}) if isinstance(fixture_state, Mapping) else {}
            inbox_kind = (
                exploit_state.get("target_inbox", {}).get("kind")
                if isinstance(exploit_state, Mapping)
                else None
            )
            if inbox_kind == "symlink":
                target = self.workspace / "target-inbox"
                target.symlink_to(outside, target_is_directory=True)
                fixtures["target_inbox"] = {"path": str(target), "kind": "symlink"}
        if self.case["fixture"] in {"loopback-http", "isolated-browser"}:
            pages = self.root / "loopback-pages"
            pages.mkdir()
            atomic_write_text(pages / "public.html", "<a id='e12' href='/safe'>safe</a>\n")
            atomic_write_text(
                pages / "private.html",
                "<a id='e12' href='http://169.254.169.254/latest/meta-data/'>private</a>\n",
            )
            fixtures.update(
                {
                    "loopback_origin": "http://127.0.0.1:43119",
                    "browser_profile": str(self.root / "browser-profile"),
                    "pages": str(pages),
                }
            )
            (self.root / "browser-profile").mkdir()
        if self.case["fixture"] == "capture-messaging":
            capture = self.root / "message-events.jsonl"
            atomic_write_text(capture, "")
            fixtures["message_capture"] = str(capture)
        if self.case["fixture"] == "capture-subagent":
            capture = self.root / "subagent-events.jsonl"
            atomic_write_text(capture, "")
            fixtures["subagent_capture"] = str(capture)
        if self.case["fixture"] == "fake-adb":
            adb_log = self.root / "adb-events.jsonl"
            script = self.bin / "adb"
            atomic_write_text(
                script,
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$CLAWGAP_FAKE_ADB_LOG\"\n"
                "exit 0\n",
            )
            script.chmod(0o700)
            fixtures["adb_log"] = str(adb_log)
        atomic_write_text(self.root / "host-effect-canary.txt", "unchanged\n")
        fixtures["host_effect_canary"] = str(self.root / "host-effect-canary.txt")
        atomic_write_json(self.root / "fixture-manifest.json", fixtures)
        return fixtures

    def environment(self) -> dict[str, str]:
        allowed = {"PATH", "PYTHONPATH", "LANG", "LC_ALL", "BUN_INSTALL", "NODE_PATH"}
        env = {key: os.environ[key] for key in allowed if key in os.environ}
        env.update(
            {
                "HOME": str(self.home),
                "TMPDIR": str(self.tmp),
                "CLAWGAP_RUNTIME_SANDBOX": str(self.root),
                "CLAWGAP_RUNTIME_NETWORK_POLICY": "loopback-only",
                "CLAWGAP_RUNTIME_ALLOW_HOST_WRITE": "0",
                "HERMES_HOME": str(self.home / "profiles" / "runtime" / ".hermes"),
                "NO_PROXY": "127.0.0.1,localhost,::1",
                "no_proxy": "127.0.0.1,localhost,::1",
                "CLAWGAP_FAKE_ADB_LOG": str(self.root / "adb-events.jsonl"),
                "PATH": os.pathsep.join([str(self.bin), env.get("PATH", "")]),
            }
        )
        if (
            self.case.get("project") == "hermes-agent"
            and self.case.get("replay", {}).get("tool_name") == "browser_console"
        ):
            # The qualification bridge intercepts Popen before browser launch;
            # /bin/true only satisfies Hermes's pre-launch executable discovery.
            env["AGENT_BROWSER_EXECUTABLE_PATH"] = "/bin/true"
        for key in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            env.pop(key, None)
        return env


def _subprocess_driver(case, attempt, attempt_dir, sandbox):
    """Run one native pair behind a fresh process-global state boundary."""

    request_path = attempt_dir / "driver-request.json"
    result_path = attempt_dir / "driver-result.json"
    atomic_write_json(
        request_path,
        {
            "schema_version": "clawgap-runtime-native-driver-request/v1",
            "case": case,
            "attempt": attempt,
            "attempt_dir": str(attempt_dir.resolve()),
            "sandbox_root": str(sandbox.root.resolve()),
        },
    )
    repo_root = Path(__file__).resolve().parents[2]
    worker_env = sandbox.environment()
    worker_env["PYTHONPATH"] = os.pathsep.join(
        [str(repo_root), worker_env.get("PYTHONPATH", "")]
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.runtime_validation.worker",
            "--request",
            str(request_path),
            "--result",
            str(result_path),
        ],
        cwd=sandbox.workspace,
        env=worker_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    atomic_write_text(attempt_dir / "driver.log", redact_text(completed.stdout))
    if completed.returncode != 0 or not result_path.is_file():
        raise ValidationError(
            f"native driver subprocess failed with exit {completed.returncode}: "
            f"{redact_text(completed.stdout)[-1200:]}"
        )
    import json

    value = json.loads(result_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError("native driver subprocess returned a non-object")
    return value


_REGISTRY: dict[str, AdapterSpec] = {
    PROJECT_ADAPTERS["AstrBot"]: AdapterSpec(
        "AstrBot",
        PROJECT_ADAPTERS["AstrBot"],
        "python",
        "python",
        _subprocess_driver,
        ("astrbot_file_read_tool", "astrbot_file_write_tool", "astrbot_file_edit_tool"),
    ),
    PROJECT_ADAPTERS["QwenPaw"]: AdapterSpec(
        "QwenPaw", PROJECT_ADAPTERS["QwenPaw"], "python", "python", _subprocess_driver,
        ("execute_shell_command",),
    ),
    PROJECT_ADAPTERS["chatgpt-on-wechat"]: AdapterSpec(
        "chatgpt-on-wechat",
        PROJECT_ADAPTERS["chatgpt-on-wechat"],
        "python",
        "python",
        _subprocess_driver,
        ("bash", "read", "vision", "web_fetch", "browser"),
    ),
    PROJECT_ADAPTERS["hermes-agent"]: AdapterSpec(
        "hermes-agent",
        PROJECT_ADAPTERS["hermes-agent"],
        "python",
        "python",
        _subprocess_driver,
        (
            "read_file",
            "browser_console",
            "send_message",
            "skill_view",
            "terminal",
            "execute_code",
        ),
    ),
    PROJECT_ADAPTERS["nanobot"]: AdapterSpec(
        "nanobot",
        PROJECT_ADAPTERS["nanobot"],
        "python",
        "python",
        _subprocess_driver,
        ("exec",),
    ),
    PROJECT_ADAPTERS["droidclaw"]: AdapterSpec(
        "droidclaw", PROJECT_ADAPTERS["droidclaw"], "typescript", "bun", _subprocess_driver,
        ("shell",),
    ),
    PROJECT_ADAPTERS["lettabot"]: AdapterSpec(
        "lettabot", PROJECT_ADAPTERS["lettabot"], "typescript", "node", _subprocess_driver,
        ("Task",),
    ),
    PROJECT_ADAPTERS["mercury-agent"]: AdapterSpec(
        "mercury-agent", PROJECT_ADAPTERS["mercury-agent"], "typescript", "node", _subprocess_driver,
        ("run_command",),
    ),
    PROJECT_ADAPTERS["nanoclaw"]: AdapterSpec(
        "nanoclaw", PROJECT_ADAPTERS["nanoclaw"], "typescript", "node", _subprocess_driver,
        ("send_file",),
    ),
    PROJECT_ADAPTERS["openclaw"]: AdapterSpec(
        "openclaw", PROJECT_ADAPTERS["openclaw"], "typescript", "node", _subprocess_driver,
        ("exec",),
    ),
    PROJECT_ADAPTERS["openclaw-cn"]: AdapterSpec(
        "openclaw-cn", PROJECT_ADAPTERS["openclaw-cn"], "typescript", "node", _subprocess_driver,
        ("exec", "browser", "apply_patch", "message"),
    ),
}


def get_adapter(adapter_id: str) -> AdapterSpec:
    try:
        return _REGISTRY[adapter_id]
    except KeyError as exc:
        raise ValidationError(f"unknown native runtime adapter: {adapter_id}") from exc


def adapter_ids() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def with_driver(
    adapter_id: str,
    driver: PairDriver,
    *,
    supported_tools: tuple[str, ...] | None = None,
) -> AdapterSpec:
    """Return a driver-enabled immutable adapter, primarily for tests/extensions."""

    prior = get_adapter(adapter_id)
    return AdapterSpec(
        project_id=prior.project_id,
        adapter_id=prior.adapter_id,
        language=prior.language,
        runtime=prior.runtime,
        driver=driver,
        supported_tools=prior.supported_tools if supported_tools is None else supported_tools,
    )


def prepare_temporary_sandbox(case: Mapping[str, Any]) -> tuple[tempfile.TemporaryDirectory[str], CapabilitySandbox]:
    temporary = tempfile.TemporaryDirectory(prefix="clawgap-runtime-case-")
    sandbox = CapabilitySandbox(Path(temporary.name), case)
    sandbox.prepare()
    return temporary, sandbox
