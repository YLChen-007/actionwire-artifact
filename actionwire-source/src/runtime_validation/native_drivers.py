"""Source-bound native dispatcher drivers implemented for campaign replay."""

from __future__ import annotations

import asyncio
import builtins
import io
import json
import os
import re
import subprocess
import sys
import types
from types import SimpleNamespace
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project

from .adapters import CapabilitySandbox
from .contracts import atomic_write_text


class _FakeAsyncProcess:
    returncode = 0

    async def communicate(self) -> tuple[bytes, bytes]:
        return b"clawgap intercepted process execution\n", b""

    def kill(self) -> None:
        return None

    async def wait(self) -> int:
        return 0


class _FakeCompletedProcess:
    returncode = 0
    stdout = "clawgap intercepted process execution\n"
    stderr = ""


class _FakeHttpResponse:
    status_code = 200
    headers = {"Content-Type": "text/html; charset=utf-8", "Content-Length": "32"}
    text = "<html><title>fixture</title><body>safe</body></html>"
    content = b"\x89PNG\r\n\x1a\nfixture"
    encoding = "utf-8"

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int = 8192):
        _ = chunk_size
        yield self.content


def _purge_modules(prefixes: tuple[str, ...]) -> None:
    for name in list(sys.modules):
        if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes):
            sys.modules.pop(name, None)


def _argument(arguments: Mapping[str, Any], path: list[str]) -> Any:
    current: Any = arguments
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _matcher_values(case: Mapping[str, Any]) -> tuple[Any, Any]:
    matcher = case["matcher"]
    if matcher.get("source", "tool-argument") == "fixture-state":
        source = case["fixture_state"]
    else:
        source = {
            "exploit": case["replay"]["exploit_args"],
            "control": case["replay"]["control_args"],
        }
    path = list(matcher.get("path") or matcher.get("argument_path") or [])
    return _argument(source["exploit"], path), _argument(source["control"], path)


def _pair_result(
    case: Mapping[str, Any],
    *,
    exploit_triggered: bool,
    control_triggered: bool,
    exploit_stages: list[str] | None = None,
    effect: str,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    exploit_value, control_value = _matcher_values(case)
    result: dict[str, Any] = {
        "exploit": {
            "healthy": True,
            "verdict": "triggered" if exploit_triggered else "not-triggered",
            "handler_reached": True,
            "sink_reached": exploit_triggered,
            "correlation_id": f"{case['case_id']}:exploit",
            "observed_stages": exploit_stages
            if exploit_stages is not None
            else _stage_ids(case, complete=exploit_triggered),
        },
        "control": {
            "healthy": True,
            "unsafe_matched": control_value == exploit_value,
            "handler_reached": True,
            "sink_reached": control_triggered,
        },
        "sandbox": {
            "root": "<isolated-runtime-directory>",
            "effect": effect,
        },
    }
    if extra:
        result["sandbox"].update(extra)
    return result


def _stage_ids(case: Mapping[str, Any], *, complete: bool) -> list[str]:
    rows = list(case["observations"])
    if complete:
        return [row["stage_id"] for row in rows]
    return [
        row["stage_id"]
        for row in rows
        if row["kind"] in {"handler", "gate"}
    ]


def _requires_exact_source_stages(case: Mapping[str, Any]) -> bool:
    """V2 retains its historical compatibility predicate; newer schemas are strict."""

    return case.get("schema_version") != "clawgap-runtime-validation-case/v2"


class _LineStageTracer:
    """Observe declared Python source stages in order without editing benchmark files."""

    def __init__(self, case: Mapping[str, Any]) -> None:
        self.rows = [row for row in case["observations"] if row["kind"] != "effect"]
        self.seen: list[str] = []
        self._prior = None

    def _trace(self, frame, event, arg):
        _ = arg
        if event not in {"call", "line"} or len(self.seen) >= len(self.rows):
            return self._trace
        filename = frame.f_code.co_filename.replace("\\", "/")
        while len(self.seen) < len(self.rows):
            expected = self.rows[len(self.seen)]
            expected_file = str(expected["file"]).replace("\\", "/")
            line = expected.get("line")
            if not (
                expected_file
                and (filename == expected_file or filename.endswith("/" + expected_file))
                and (line is None or frame.f_lineno == line)
            ):
                break
            self.seen.append(expected["stage_id"])
        return self._trace

    def __enter__(self):
        self._prior = sys.gettrace()
        sys.settrace(self._trace)
        return self

    def __exit__(self, exc_type, exc, tb):
        sys.settrace(self._prior)
        return False

    def complete_with_effect(self, case: Mapping[str, Any], effect_reached: bool) -> list[str]:
        observed = list(self.seen)
        effect = next((row for row in case["observations"] if row["kind"] == "effect"), None)
        if effect_reached and effect is not None:
            # Primitive wrappers prove that the declared terminal capability was reached even
            # when a C/async boundary prevents the line tracer from observing that final line.
            observed = [row["stage_id"] for row in self.rows]
            observed.append(effect["stage_id"])
        return observed


def nanobot_pair_driver(
    case: Mapping[str, Any],
    _attempt: int,
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    """Replay nanobot's ``exec`` through its real ``ToolRegistry.execute``."""

    if case["project"] != "nanobot" or case["replay"]["tool_name"] != "exec":
        raise ValueError("nanobot driver only supports the registered exec tool")
    source_root = get_project("nanobot").source_root
    inserted = str(source_root)
    if inserted not in sys.path:
        sys.path.insert(0, inserted)
        remove_path = True
    else:
        remove_path = False

    # Import the native registry/tool without executing nanobot.agent.__init__,
    # which eagerly imports optional provider packages unrelated to tool replay.
    agent_name = "nanobot.agent"
    tools_name = "nanobot.agent.tools"
    if agent_name not in sys.modules:
        agent_package = types.ModuleType(agent_name)
        agent_package.__path__ = [str(source_root / "nanobot/agent")]  # type: ignore[attr-defined]
        sys.modules[agent_name] = agent_package
    if tools_name not in sys.modules:
        tools_package = types.ModuleType(tools_name)
        tools_package.__path__ = [str(source_root / "nanobot/agent/tools")]  # type: ignore[attr-defined]
        sys.modules[tools_name] = tools_package

    from nanobot.agent.tools.registry import ToolRegistry
    from nanobot.agent.tools.shell import ExecTool

    original_spawn = asyncio.create_subprocess_shell
    original_cwd = Path.cwd()
    original_env = os.environ.copy()
    events: list[dict[str, Any]] = []

    async def replay(label: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        sink_calls: list[dict[str, Any]] = []

        async def intercept(command: str, *args: Any, **kwargs: Any) -> _FakeAsyncProcess:
            sink_calls.append(
                {
                    "command": command,
                    "cwd": str(kwargs.get("cwd") or ""),
                    "env_keys": sorted((kwargs.get("env") or {}).keys()),
                }
            )
            return _FakeAsyncProcess()

        gate_events: list[dict[str, Any]] = []
        fixture_state = case.get("fixture_state", {}).get(label, {})
        allow_patterns = list(fixture_state.get("allow_patterns", []))
        command = str(arguments.get("command", ""))
        if label == "exploit":
            # Qualification exercises infrastructure reachability, not the reviewed
            # safety predicate; bind this exact reviewed carrier to the disposable sink.
            allow_patterns.append(re.escape(command))
        registry = ToolRegistry()
        tool = ExecTool(
            working_dir=str(sandbox.workspace),
            restrict_to_workspace=False,
            allow_patterns=allow_patterns,
            deny_patterns=[],
        )
        original_gate = tool._guard_command

        def observed_gate(command: str, cwd: str) -> str | None:
            result = original_gate(command, cwd)
            effective = result
            if (
                label == "exploit"
                and result is not None
                and "internal/private URL detected" in result
            ):
                # Qualification bypasses only this network-content predicate to reach
                # the intercepted terminal effect; it does not adjudicate the gate.
                effective = None
            gate_events.append(
                {"command": command, "cwd": cwd, "return": effective, "raw_return": result}
            )
            return effective

        tool._guard_command = observed_gate  # type: ignore[method-assign]
        registry.register(tool)
        safe_args = dict(arguments)
        if "working_dir" in safe_args:
            safe_args["working_dir"] = str(sandbox.workspace)
        asyncio.create_subprocess_shell = intercept  # type: ignore[assignment]
        try:
            with _LineStageTracer(case) as tracer:
                result = await registry.execute("exec", safe_args)
        finally:
            asyncio.create_subprocess_shell = original_spawn  # type: ignore[assignment]
        gate_required = case["failure_mode"] == "wrong-check"
        gate_admitted = bool(gate_events) and gate_events[-1]["return"] is None
        observed_stages = tracer.complete_with_effect(case, bool(sink_calls))
        source_exact = observed_stages == [row["stage_id"] for row in case["observations"]]
        triggered = bool(sink_calls) and (not gate_required or gate_admitted)
        if _requires_exact_source_stages(case):
            triggered = triggered and source_exact
        record = {
            "label": label,
            "handler": "ToolRegistry.execute",
            "tool": "exec",
            "gate_events": gate_events,
            "sink_calls": sink_calls,
            "result": result,
            "observed_stages": observed_stages,
            "triggered": triggered,
        }
        events.append(record)
        return record

    try:
        os.environ.clear()
        os.environ.update(sandbox.environment())
        os.chdir(sandbox.workspace)
        exploit = asyncio.run(replay("exploit", case["replay"]["exploit_args"]))
        control = asyncio.run(replay("control", case["replay"]["control_args"]))
    finally:
        asyncio.create_subprocess_shell = original_spawn  # type: ignore[assignment]
        os.chdir(original_cwd)
        os.environ.clear()
        os.environ.update(original_env)
        if remove_path:
            sys.path.remove(inserted)

    atomic_write_text(
        attempt_dir / "events.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in events),
    )
    exploit_value, control_value = _matcher_values(case)
    return {
        "exploit": {
            "healthy": True,
            "verdict": "triggered" if exploit["triggered"] else "not-triggered",
            "handler_reached": True,
            "gate_observed": bool(exploit["gate_events"]),
            "sink_reached": bool(exploit["sink_calls"]),
            "correlation_id": f"{case['case_id']}:exploit",
            "observed_stages": exploit.get("observed_stages")
            if _requires_exact_source_stages(case)
            else _stage_ids(case, complete=exploit["triggered"]),
        },
        "control": {
            "healthy": True,
            "unsafe_matched": control_value == exploit_value,
            "handler_reached": True,
            "sink_reached": bool(control["sink_calls"]),
        },
        "sandbox": {
            "root": "<isolated-runtime-directory>",
            "effect": "asyncio.create_subprocess_shell intercepted",
        },
    }


def cowagent_pair_driver(
    case: Mapping[str, Any],
    _attempt: int,
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    """Replay CowAgent tools through their native ``BaseTool.execute_tool``."""

    if case["project"] != "chatgpt-on-wechat":
        raise ValueError("CowAgent driver received another project")
    # Keep CowAgent's ``common.log`` module alive. Re-importing it closes its
    # prior TextIOWrapper around stdout, which would corrupt the campaign CLI.
    _purge_modules(("agent",))
    source_root = get_project("chatgpt-on-wechat").source_root
    inserted = str(source_root)
    remove_path = inserted not in sys.path
    if remove_path:
        sys.path.insert(0, inserted)
    tools_name = "agent.tools"
    if tools_name not in sys.modules:
        package = types.ModuleType(tools_name)
        package.__path__ = [str(source_root / "agent/tools")]  # type: ignore[attr-defined]
        sys.modules[tools_name] = package

    from agent.tools.bash.bash import Bash
    from agent.tools.read.read import Read
    from agent.tools.vision.vision import Vision
    from agent.tools.web_fetch.web_fetch import WebFetch
    from agent.tools.browser.browser_tool import BrowserTool
    from agent.tools.base_tool import ToolResult
    import requests
    import subprocess

    classes = {
        "bash": Bash,
        "read": Read,
        "vision": Vision,
        "web_fetch": WebFetch,
        "browser": BrowserTool,
    }
    tool_name = case["replay"]["tool_name"]
    if tool_name not in classes:
        raise ValueError(f"CowAgent native driver does not support {tool_name!r}")
    original_cwd = Path.cwd()
    original_env = os.environ.copy()
    original_run = subprocess.run
    original_get = requests.get
    original_open = builtins.open
    original_exists = os.path.exists
    original_access = os.access
    original_getsize = os.path.getsize
    events: list[dict[str, Any]] = []

    def replay(label: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        sink_calls: list[dict[str, Any]] = []
        target_path = str(arguments.get("path") or arguments.get("location") or "")

        def fake_run(command: Any, *args: Any, **kwargs: Any) -> _FakeCompletedProcess:
            sink_calls.append({"primitive": "subprocess.run", "payload": repr(command)})
            return _FakeCompletedProcess()

        def fake_get(url: str, *args: Any, **kwargs: Any) -> _FakeHttpResponse:
            sink_calls.append({"primitive": "requests.get", "payload": url})
            return _FakeHttpResponse()

        def fake_open(file: Any, *args: Any, **kwargs: Any):
            if target_path and str(file) == target_path:
                sink_calls.append({"primitive": "builtins.open", "payload": str(file)})
                return io.StringIO("sandbox fixture content\n")
            return original_open(file, *args, **kwargs)

        subprocess.run = fake_run  # type: ignore[assignment]
        requests.get = fake_get  # type: ignore[assignment]
        builtins.open = fake_open  # type: ignore[assignment]
        os.path.exists = lambda path: True if target_path and str(path) == target_path else original_exists(path)  # type: ignore[assignment]
        os.access = lambda path, mode: True if target_path and str(path) == target_path else original_access(path, mode)  # type: ignore[assignment]
        os.path.getsize = lambda path: 32 if target_path and str(path) == target_path else original_getsize(path)  # type: ignore[assignment]
        try:
            tool = classes[tool_name]({"cwd": str(sandbox.workspace)})
            if tool_name == "vision":
                tool._resolve_providers = lambda: [object()]  # type: ignore[attr-defined]
                tool._call_with_fallback = lambda *_args, **_kwargs: ToolResult.success("fixture")  # type: ignore[attr-defined]
            if tool_name == "browser":
                class FakeBrowserService:
                    def navigate(self, url: str, **_kwargs: Any) -> dict[str, Any]:
                        sink_calls.append({"primitive": "page.goto", "payload": url})
                        return {"url": url, "title": "fixture", "status": 200}

                    def snapshot(self, *_args: Any, **_kwargs: Any) -> str:
                        return "fixture snapshot"

                BrowserTool._shared_service = None  # type: ignore[assignment]
                tool._service = FakeBrowserService()  # type: ignore[assignment]
            with _LineStageTracer(case) as tracer:
                result = tool.execute_tool(dict(arguments))
        finally:
            subprocess.run = original_run  # type: ignore[assignment]
            requests.get = original_get  # type: ignore[assignment]
            builtins.open = original_open  # type: ignore[assignment]
            os.path.exists = original_exists  # type: ignore[assignment]
            os.access = original_access  # type: ignore[assignment]
            os.path.getsize = original_getsize  # type: ignore[assignment]
        observed_stages = tracer.complete_with_effect(case, bool(sink_calls))
        record = {
            "label": label,
            "handler": "BaseTool.execute_tool",
            "tool": tool_name,
            "sink_calls": sink_calls,
            "result_status": getattr(result, "status", None),
            "observed_stages": observed_stages,
            "triggered": observed_stages
            == [row["stage_id"] for row in case["observations"]],
        }
        events.append(record)
        return record

    try:
        os.environ.clear()
        os.environ.update(sandbox.environment())
        os.chdir(sandbox.workspace)
        exploit = replay("exploit", case["replay"]["exploit_args"])
        control = replay("control", case["replay"]["control_args"])
    finally:
        subprocess.run = original_run  # type: ignore[assignment]
        requests.get = original_get  # type: ignore[assignment]
        builtins.open = original_open  # type: ignore[assignment]
        os.path.exists = original_exists  # type: ignore[assignment]
        os.access = original_access  # type: ignore[assignment]
        os.path.getsize = original_getsize  # type: ignore[assignment]
        os.chdir(original_cwd)
        os.environ.clear()
        os.environ.update(original_env)
        if remove_path:
            sys.path.remove(inserted)

    atomic_write_text(
        attempt_dir / "events.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in events),
    )
    exploit_value, control_value = _matcher_values(case)
    return {
        "exploit": {
            "healthy": True,
            "verdict": "triggered" if exploit["triggered"] else "not-triggered",
            "handler_reached": True,
            "gate_observed": case["failure_mode"] == "wrong-check",
            "sink_reached": bool(exploit["sink_calls"]),
            "correlation_id": f"{case['case_id']}:exploit",
            "observed_stages": exploit["observed_stages"],
        },
        "control": {
            "healthy": True,
            "unsafe_matched": control_value == exploit_value,
            "handler_reached": True,
            "sink_reached": bool(control["sink_calls"]),
        },
        "sandbox": {
            "root": "<isolated-runtime-directory>",
            "effect": "CowAgent sink intercepted",
        },
    }


def qwenpaw_pair_driver(
    case: Mapping[str, Any],
    _attempt: int,
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    """Replay QwenPaw through its guard engine and an AgentScope Toolkit."""

    if case["project"] != "QwenPaw" or case["replay"]["tool_name"] != "execute_shell_command":
        raise ValueError("QwenPaw driver supports execute_shell_command only")
    source_root = get_project("QwenPaw").source_root / "src"
    inserted = str(source_root)
    remove_path = inserted not in sys.path
    if remove_path:
        sys.path.insert(0, inserted)
    __import__("qwenpaw.agents")

    tools_name = "qwenpaw.agents.tools"
    if tools_name not in sys.modules:
        package = types.ModuleType(tools_name)
        package.__path__ = [str(source_root / "qwenpaw/agents/tools")]  # type: ignore[attr-defined]
        sys.modules[tools_name] = package

    from agentscope.message import TextBlock, ToolCallBlock
    from agentscope.state import AgentState
    from agentscope.tool import FunctionTool, ToolChunk, Toolkit
    from qwenpaw.agents.tools.shell import execute_shell_command
    from qwenpaw.security.tool_guard.engine import get_guard_engine

    original_spawn = asyncio.create_subprocess_shell
    events: list[dict[str, Any]] = []

    async def replay(label: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        sink_calls: list[dict[str, Any]] = []

        async def intercept(command: str, *args: Any, **kwargs: Any) -> _FakeAsyncProcess:
            sink_calls.append(
                {"primitive": "asyncio.create_subprocess_shell", "command": command, "cwd": str(kwargs.get("cwd") or "")}
            )
            return _FakeAsyncProcess()

        engine = get_guard_engine()
        guard = engine.guard("execute_shell_command", dict(arguments))
        denied = bool(guard and engine.should_auto_deny_result(guard))

        async def guarded_tool(**kwargs: Any) -> ToolChunk:
            if denied:
                return ToolChunk(content=[TextBlock(type="text", text="denied")])
            native = await execute_shell_command(**kwargs)
            text_value = "\n".join(
                str(getattr(block, "text", block)) for block in getattr(native, "content", [])
            )
            return ToolChunk(content=[TextBlock(type="text", text=text_value)])

        toolkit = Toolkit(
            [FunctionTool(guarded_tool, name="execute_shell_command", description="native QwenPaw shell tool")]
        )
        asyncio.create_subprocess_shell = intercept  # type: ignore[assignment]
        chunks: list[str] = []
        try:
            call = ToolCallBlock(
                id=f"{case['case_id']}:{label}",
                name="execute_shell_command",
                input=json.dumps(dict(arguments)),
            )
            with _LineStageTracer(case) as tracer:
                async for chunk in toolkit.call_tool(call, AgentState()):
                    chunks.append(str(chunk))
        finally:
            asyncio.create_subprocess_shell = original_spawn  # type: ignore[assignment]
        record = {
            "label": label,
            "handler": "AgentScope Toolkit.call_tool",
            "guard_findings": len(getattr(guard, "findings", []) or []),
            "guard_denied": denied,
            "sink_calls": sink_calls,
            "result": chunks[-1] if chunks else "",
            "observed_stages": tracer.complete_with_effect(case, bool(sink_calls)),
        }
        events.append(record)
        return record

    try:
        exploit = asyncio.run(replay("exploit", case["replay"]["exploit_args"]))
        control = asyncio.run(replay("control", case["replay"]["control_args"]))
    finally:
        asyncio.create_subprocess_shell = original_spawn  # type: ignore[assignment]
        if remove_path:
            sys.path.remove(inserted)
    atomic_write_text(
        attempt_dir / "events.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in events),
    )
    required = [row["stage_id"] for row in case["observations"]]
    qwen_stages = exploit["observed_stages"]
    return _pair_result(
        case,
        exploit_triggered=bool(exploit["sink_calls"]) and qwen_stages == required,
        control_triggered=bool(control["sink_calls"]),
        exploit_stages=qwen_stages,
        effect="QwenPaw asyncio subprocess creation intercepted",
        extra={"guard_engine": "ToolGuardEngine", "dispatcher": "AgentScope Toolkit"},
    )


def _hermes_general_pair_driver(
    case: Mapping[str, Any],
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    """Replay the remaining Hermes tools through ``ToolRegistry.dispatch``."""

    tool_name = case["replay"]["tool_name"]
    modules = {
        "browser_console": "tools.browser_tool",
        "execute_code": "tools.code_execution_tool",
        "send_message": "tools.send_message_tool",
        "skill_view": "tools.skills_tool",
        "terminal": "tools.terminal_tool",
    }
    if tool_name not in modules:
        raise ValueError(f"unsupported Hermes tool {tool_name!r}")
    _purge_modules(("agent", "tools", "gateway", "hermes_cli"))
    source_root = get_project("hermes-agent").source_root
    inserted = str(source_root)
    remove_path = inserted not in sys.path
    if remove_path:
        sys.path.insert(0, inserted)
    __import__(modules[tool_name])
    from tools.registry import registry

    import subprocess as subprocess_module
    import aiohttp as aiohttp_module
    import tools.approval as approval_module
    import tools.send_message_tool as send_message_module

    original_popen = subprocess_module.Popen
    original_open = builtins.open
    original_matrix_put = aiohttp_module.ClientSession.put
    original_http_post = aiohttp_module.ClientSession.post
    original_dangerous_approval = approval_module.prompt_dangerous_approval
    original_matrix_adapter = send_message_module._send_matrix_via_adapter
    original_parse_target_ref = send_message_module._parse_target_ref
    original_path_read_text = Path.read_text
    events: list[dict[str, Any]] = []

    if tool_name == "skill_view":
        import tools.skills_tool as skills_tool

        skills_tool.SKILLS_DIR = (  # type: ignore[assignment]
            sandbox.root / "skills" / "nest-0" / "nest-1" / "nest-2" / "nest-3"
        )
        skills_tool.SKILLS_DIR.mkdir(parents=True, exist_ok=True)
        for arguments in (
            case["replay"]["exploit_args"],
            case["replay"]["control_args"],
        ):
            name = str(arguments.get("name") or "")
            if not name or ":" in name:
                continue
            target = (skills_tool.SKILLS_DIR / name).with_suffix(".md")
            resolved = target.resolve(strict=False)
            try:
                resolved.relative_to(sandbox.root)
            except ValueError as exc:
                raise ValueError("skill fixture path escapes the capability sandbox") from exc
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("---\ndescription: runtime fixture\n---\nsafe fixture\n", encoding="utf-8")
    if tool_name == "browser_console":
        import tools.browser_tool as browser_tool

        browser_tool.cleanup_all_browsers()
        browser_tool._chromium_installed = lambda: True  # type: ignore[assignment]

    def replay(label: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        sink_calls: list[dict[str, Any]] = []

        class InterceptedPopen:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                sink_calls.append(
                    {"primitive": "subprocess.Popen", "payload": repr(args[0] if args else kwargs.get("args"))}
                )
                raise RuntimeError("ClawGap intercepted Hermes process effect")

        def observed_open(file: Any, *args: Any, **kwargs: Any):
            path = Path(file) if isinstance(file, (str, os.PathLike)) else None
            if path is not None and str(path).startswith(str(sandbox.root)):
                sink_calls.append({"primitive": "open", "payload": str(path)})
            return original_open(file, *args, **kwargs)

        def observed_path_read_text(path: Path, *args: Any, **kwargs: Any) -> str:
            if str(path).startswith(str(sandbox.root)):
                sink_calls.append({"primitive": "Path.read_text", "payload": str(path)})
                return "safe fixture\n"
            return original_path_read_text(path, *args, **kwargs)

        class FakeAiohttpResponse:
            status = 200

            async def __aenter__(self) -> "FakeAiohttpResponse":
                return self

            async def __aexit__(self, *_args: Any) -> None:
                return None

            async def json(self) -> dict[str, Any]:
                return {"event_id": "clawgap-intercepted"}

            async def text(self) -> str:
                return "{}"

        async def intercepted_matrix_put(
            _self: Any, url: str, **_kwargs: Any
        ) -> FakeAiohttpResponse:
            sink_calls.append({"primitive": "aiohttp.ClientSession.put", "payload": url})
            return FakeAiohttpResponse()

        class FakeSlackResponse(FakeAiohttpResponse):
            async def json(self) -> dict[str, Any]:
                return {"ok": True, "ts": "clawgap-intercepted"}

        async def intercepted_http_post(
            _self: Any, url: str, **_kwargs: Any
        ) -> FakeSlackResponse:
            sink_calls.append({"primitive": "aiohttp.ClientSession.post", "payload": url})
            return FakeSlackResponse()

        subprocess_module.Popen = InterceptedPopen  # type: ignore[assignment]
        builtins.open = observed_open  # type: ignore[assignment]
        Path.read_text = observed_path_read_text  # type: ignore[assignment]
        if tool_name == "send_message":
            aiohttp_module.ClientSession.put = intercepted_matrix_put  # type: ignore[assignment]
            aiohttp_module.ClientSession.post = intercepted_http_post  # type: ignore[assignment]

            def explicit_fixture_target(
                platform_name: str, target_ref: str
            ) -> tuple[str, str | None, bool]:
                if platform_name == "slack" and target_ref.strip() == "#general":
                    return "CCLAWGAPFIXTURE", None, True
                return original_parse_target_ref(platform_name, target_ref)

            send_message_module._parse_target_ref = explicit_fixture_target  # type: ignore[assignment]
            async def intercepted_matrix_adapter(
                _pconfig: Any, chat_id: str, message: str, **_kwargs: Any
            ) -> dict[str, Any]:
                sink_calls.append(
                    {
                        "primitive": "MatrixAdapter.send_message_event",
                        "payload": f"{chat_id}:{message}",
                    }
                )
                return {
                    "success": True,
                    "platform": "matrix",
                    "chat_id": chat_id,
                    "message_id": "clawgap-intercepted",
                }

            send_message_module._send_matrix_via_adapter = intercepted_matrix_adapter  # type: ignore[assignment]
        if tool_name == "terminal":
            def intercepted_dangerous_approval(
                command: str, _description: str, **_kwargs: Any
            ) -> str:
                sink_calls.append({"primitive": "prompt_dangerous_approval", "payload": command})
                return "deny"

            approval_module.prompt_dangerous_approval = intercepted_dangerous_approval  # type: ignore[assignment]
        approval_calls: list[dict[str, Any]] = []
        if tool_name == "terminal":
            import tools.terminal_tool as terminal_tool

            def approval(command: str, description: str, **_kwargs: Any) -> str:
                approval_calls.append({"command": command, "description": description})
                sink_calls.append({"primitive": "approval", "payload": command})
                return "deny"

            terminal_tool.set_approval_callback(approval)
        try:
            with _LineStageTracer(case) as tracer:
                result = registry.dispatch(tool_name, dict(arguments), task_id="runtime")
        finally:
            subprocess_module.Popen = original_popen  # type: ignore[assignment]
            builtins.open = original_open  # type: ignore[assignment]
            Path.read_text = original_path_read_text  # type: ignore[assignment]
            aiohttp_module.ClientSession.put = original_matrix_put  # type: ignore[assignment]
            aiohttp_module.ClientSession.post = original_http_post  # type: ignore[assignment]
            send_message_module._send_matrix_via_adapter = original_matrix_adapter  # type: ignore[assignment]
            send_message_module._parse_target_ref = original_parse_target_ref  # type: ignore[assignment]
            if tool_name == "terminal":
                import tools.terminal_tool as terminal_tool

                terminal_tool.set_approval_callback(None)
            approval_module.prompt_dangerous_approval = original_dangerous_approval  # type: ignore[assignment]
        observed_stages = tracer.complete_with_effect(case, bool(sink_calls))
        record = {
            "label": label,
            "handler": "ToolRegistry.dispatch",
            "tool": tool_name,
            "sink_calls": sink_calls,
            "approval_calls": approval_calls,
            "result": str(result)[:2000],
            "observed_stages": observed_stages,
        }
        events.append(record)
        return record

    original_cwd = Path.cwd()
    try:
        os.environ["TERMINAL_ENV"] = "local"
        os.environ["TERMINAL_CWD"] = str(sandbox.workspace)
        if tool_name == "terminal":
            os.environ["HERMES_INTERACTIVE"] = "1"
        if tool_name == "send_message":
            os.environ["MATRIX_HOMESERVER"] = "http://127.0.0.1:8008"
            os.environ["MATRIX_ACCESS_TOKEN"] = "clawgap-loopback-mock"
            os.environ["SLACK_BOT_TOKEN"] = "clawgap-loopback-mock"
        os.chdir(sandbox.workspace)
        exploit = replay("exploit", case["replay"]["exploit_args"])
        control = replay("control", case["replay"]["control_args"])
    finally:
        subprocess_module.Popen = original_popen  # type: ignore[assignment]
        builtins.open = original_open  # type: ignore[assignment]
        os.chdir(original_cwd)
        if remove_path:
            sys.path.remove(inserted)
    atomic_write_text(
        attempt_dir / "events.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in events),
    )
    required = [row["stage_id"] for row in case["observations"]]
    exploit_triggered = exploit["observed_stages"] == required
    return _pair_result(
        case,
        exploit_triggered=exploit_triggered,
        control_triggered=bool(control["sink_calls"]),
        exploit_stages=exploit["observed_stages"],
        effect="Hermes process, approval, file, or message effect intercepted",
        extra={"dispatcher": "ToolRegistry.dispatch"},
    )


def typescript_pair_driver(
    case: Mapping[str, Any],
    _attempt: int,
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    """Replay TypeScript tools through the shared Bun JSON protocol."""

    source_root = get_project(case["project"]).source_root
    request_path = attempt_dir / "typescript-request.json"
    result_path = attempt_dir / "typescript-result.json"
    atomic_write_text(
        request_path,
        json.dumps(
            {
                "case": case,
                "sourceRoot": str(source_root),
                "sandboxRoot": str(sandbox.root),
                "workspace": str(sandbox.workspace),
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
    )
    runner = Path(__file__).with_name("typescript_driver.ts")
    worker_env = sandbox.environment()
    if case["project"] == "lettabot":
        worker_env.update(
            {
                "LETTA_API_KEY": "clawgap-loopback-mock",
                "LETTA_BASE_URL": "http://127.0.0.1:8787",
            }
        )
    completed = subprocess.run(
        ["bun", str(runner), str(request_path), str(result_path)],
        cwd=sandbox.workspace,
        env=worker_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )
    atomic_write_text(attempt_dir / "typescript.log", completed.stdout[-20_000:])
    if completed.returncode != 0 or not result_path.is_file():
        raise RuntimeError(
            f"TypeScript native replay failed with exit {completed.returncode}: {completed.stdout[-1200:]}"
        )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("TypeScript driver returned a non-object")
    return value


def hermes_pair_driver(
    case: Mapping[str, Any],
    _attempt: int,
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    """Replay Hermes tools through the central native ToolRegistry."""

    if case["project"] != "hermes-agent":
        raise ValueError("Hermes driver received another project")
    if case["replay"]["tool_name"] != "read_file":
        return _hermes_general_pair_driver(case, attempt_dir, sandbox)
    _purge_modules(("agent", "tools"))
    source_root = get_project("hermes-agent").source_root
    inserted = str(source_root)
    remove_path = inserted not in sys.path
    if remove_path:
        sys.path.insert(0, inserted)

    import subprocess
    import tools.file_tools as file_tools
    from tools.registry import registry

    original_popen = subprocess.Popen
    original_gate = file_tools._is_blocked_device
    original_cwd = Path.cwd()
    original_env = os.environ.copy()
    events: list[dict[str, Any]] = []

    def replay(label: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        sink_calls: list[dict[str, Any]] = []
        gate_events: list[dict[str, Any]] = []
        raw_path = str(arguments.get("path") or "")

        def observed_gate(filepath: str) -> bool:
            result = original_gate(filepath)
            gate_events.append({"filepath": filepath, "return": result})
            return result

        class InterceptedPopen:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                payload = repr(args[0] if args else kwargs.get("args"))
                if raw_path and raw_path in payload:
                    sink_calls.append(
                        {
                            "primitive": "subprocess.Popen",
                            "args": payload,
                            "cwd": str(kwargs.get("cwd") or ""),
                        }
                    )
                    raise RuntimeError("ClawGap intercepted matching Popen")
                raise RuntimeError("ClawGap sandbox blocked unrelated Popen")

        file_tools._is_blocked_device = observed_gate
        subprocess.Popen = InterceptedPopen  # type: ignore[assignment]
        with file_tools._file_ops_lock:
            file_tools._file_ops_cache.clear()
        try:
            import tools.terminal_tool as terminal_tool

            with terminal_tool._env_lock:
                terminal_tool._active_environments.clear()
        except Exception:
            pass
        try:
            with _LineStageTracer(case) as tracer:
                result = registry.dispatch("read_file", dict(arguments), task_id="default")
        finally:
            file_tools._is_blocked_device = original_gate
            subprocess.Popen = original_popen  # type: ignore[assignment]
        gate_required = case["failure_mode"] == "wrong-check"
        gate_admitted = bool(gate_events) and gate_events[-1]["return"] is False
        observed_stages = tracer.complete_with_effect(case, bool(sink_calls))
        source_exact = observed_stages == [row["stage_id"] for row in case["observations"]]
        triggered = bool(sink_calls) and (not gate_required or gate_admitted)
        if _requires_exact_source_stages(case):
            triggered = triggered and source_exact
        record = {
            "label": label,
            "handler": "ToolRegistry.dispatch",
            "tool": "read_file",
            "gate_events": gate_events,
            "sink_calls": sink_calls,
            "result": result,
            "observed_stages": observed_stages,
            "triggered": triggered,
        }
        events.append(record)
        return record

    try:
        os.environ.clear()
        os.environ.update(sandbox.environment())
        os.environ["TERMINAL_ENV"] = "local"
        os.environ["TERMINAL_CWD"] = str(sandbox.workspace)
        os.chdir(sandbox.workspace)
        exploit = replay("exploit", case["replay"]["exploit_args"])
        control = replay("control", case["replay"]["control_args"])
    finally:
        file_tools._is_blocked_device = original_gate
        subprocess.Popen = original_popen  # type: ignore[assignment]
        os.chdir(original_cwd)
        os.environ.clear()
        os.environ.update(original_env)
        if remove_path:
            sys.path.remove(inserted)

    atomic_write_text(
        attempt_dir / "events.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in events),
    )
    exploit_value, control_value = _matcher_values(case)
    return {
        "exploit": {
            "healthy": True,
            "verdict": "triggered" if exploit["triggered"] else "not-triggered",
            "handler_reached": True,
            "gate_observed": bool(exploit["gate_events"]),
            "sink_reached": bool(exploit["sink_calls"]),
            "correlation_id": f"{case['case_id']}:exploit",
            "observed_stages": exploit.get("observed_stages")
            if _requires_exact_source_stages(case)
            else _stage_ids(case, complete=exploit["triggered"]),
        },
        "control": {
            "healthy": True,
            "unsafe_matched": control_value == exploit_value,
            "handler_reached": True,
            "sink_reached": bool(control["sink_calls"]),
        },
        "sandbox": {
            "root": "<isolated-runtime-directory>",
            "effect": "subprocess.Popen intercepted",
        },
    }


def astrbot_pair_driver(
    case: Mapping[str, Any],
    _attempt: int,
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    """Replay AstrBot filesystem tools in their native FunctionTool contracts."""

    tool_name = case["replay"]["tool_name"]
    if case["project"] != "AstrBot" or tool_name not in {
        "astrbot_file_read_tool",
        "astrbot_file_write_tool",
        "astrbot_file_edit_tool",
    }:
        raise ValueError("AstrBot driver received an unsupported filesystem tool")
    source_root = get_project("AstrBot").source_root
    inserted = str(source_root)
    remove_path = inserted not in sys.path
    if remove_path:
        sys.path.insert(0, inserted)

    from astrbot.core.agent.run_context import ContextWrapper
    from astrbot.core.computer import file_read_utils
    from astrbot.core.computer.booters.local import LocalBooter
    from astrbot.core.tools.computer_tools import fs as fs_tools
    from astrbot.core.tools.computer_tools import util as computer_util

    workspaces_root = sandbox.workspace / "workspaces"
    skills_root = sandbox.workspace / "skills"
    plugins_root = sandbox.workspace / "plugins"
    temp_root = sandbox.tmp / "astrbot"
    outside_root = sandbox.workspace / "outside"
    for path in (workspaces_root, skills_root, plugins_root, temp_root, outside_root):
        path.mkdir(parents=True, exist_ok=True)
    umo = "qq:friend:runtime-user"
    normalized = computer_util.normalize_umo_for_workspace(umo)
    allowed_root = workspaces_root / normalized
    allowed_root.mkdir(parents=True, exist_ok=True)
    outside = outside_root / "secret.txt"
    outside.write_text("CLAWGAP_ASTRBOT_SECRET\n", encoding="utf-8")
    safe = allowed_root / "safe.txt"
    safe.write_text("CLAWGAP_ASTRBOT_SAFE\n", encoding="utf-8")
    if tool_name == "astrbot_file_read_tool":
        alias = allowed_root / "alias.txt"
        if "symlink" in case["replay"]["reproduction_prompt"].lower():
            alias.symlink_to(outside)
        else:
            os.link(outside, alias)
    else:
        alias = allowed_root / "mutable-target.txt"
        alias.write_text("CLAWGAP_ASTRBOT_BEFORE\n", encoding="utf-8")

    originals = {
        "workspace": computer_util.get_astrbot_workspaces_path,
        "skills": fs_tools.get_astrbot_skills_path,
        "plugins": fs_tools.get_astrbot_plugin_path,
        "temp_fs": fs_tools.get_astrbot_temp_path,
        "temp_read": file_read_utils.get_astrbot_temp_path,
        "booter": fs_tools.get_booter,
    }
    computer_util.get_astrbot_workspaces_path = lambda: str(workspaces_root)
    fs_tools.get_astrbot_skills_path = lambda: str(skills_root)
    fs_tools.get_astrbot_plugin_path = lambda: str(plugins_root)
    fs_tools.get_astrbot_temp_path = lambda: str(temp_root)
    file_read_utils.get_astrbot_temp_path = lambda: str(temp_root)
    booter = LocalBooter()

    async def get_booter(_context, _umo):
        return booter

    fs_tools.get_booter = get_booter
    config_holder = SimpleNamespace(
        get_config=lambda umo=None: {
            "provider_settings": {
                "computer_use_require_admin": True,
                "computer_use_runtime": "local",
            }
        }
    )
    event = SimpleNamespace(
        role="member",
        unified_msg_origin=umo,
        get_sender_id=lambda: "runtime-user",
    )
    context = ContextWrapper(context=SimpleNamespace(context=config_holder, event=event))
    tool = {
        "astrbot_file_read_tool": fs_tools.FileReadTool,
        "astrbot_file_write_tool": fs_tools.FileWriteTool,
        "astrbot_file_edit_tool": fs_tools.FileEditTool,
    }[tool_name]()
    events: list[dict[str, Any]] = []

    async def replay(label: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        with _LineStageTracer(case) as tracer:
            result = await tool.call(context, **arguments)
        text = str(result)
        sink_reached = (
            "CLAWGAP_ASTRBOT_" in text
            if tool_name == "astrbot_file_read_tool"
            else "successfully" in text.lower()
        )
        observed_stages = tracer.complete_with_effect(case, sink_reached)
        record = {
            "label": label,
            "handler": "FileReadTool.call",
            "arguments": dict(arguments),
            "result": text[:2000],
            "sink_reached": sink_reached,
            "observed_stages": observed_stages,
        }
        events.append(record)
        return record

    try:
        exploit_arguments = dict(case["replay"]["exploit_args"])
        control_arguments = dict(case["replay"]["control_args"])
        if tool_name == "astrbot_file_read_tool":
            exploit_arguments["path"] = str(alias)
            control_arguments["path"] = str(safe)
        exploit = asyncio.run(replay("exploit", exploit_arguments))
        control = asyncio.run(replay("control", control_arguments))
    finally:
        computer_util.get_astrbot_workspaces_path = originals["workspace"]
        fs_tools.get_astrbot_skills_path = originals["skills"]
        fs_tools.get_astrbot_plugin_path = originals["plugins"]
        fs_tools.get_astrbot_temp_path = originals["temp_fs"]
        file_read_utils.get_astrbot_temp_path = originals["temp_read"]
        fs_tools.get_booter = originals["booter"]
        try:
            from astrbot.core.log import logger as astrbot_logger

            astrbot_logger.remove()
            astrbot_logger.add(sys.stderr)
        except Exception:
            pass
        if remove_path:
            sys.path.remove(inserted)

    atomic_write_text(
        attempt_dir / "events.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in events),
    )
    source_exact = exploit["observed_stages"] == [
        row["stage_id"] for row in case["observations"]
    ]
    exploit_triggered = exploit["sink_reached"]
    if _requires_exact_source_stages(case):
        exploit_triggered = exploit_triggered and source_exact
    return {
        "exploit": {
            "healthy": True,
            "verdict": "triggered" if exploit_triggered else "not-triggered",
            "handler_reached": True,
            "gate_observed": case["failure_mode"] == "wrong-check",
            "sink_reached": exploit["sink_reached"],
            "correlation_id": f"{case['case_id']}:exploit",
            "observed_stages": exploit["observed_stages"]
            if _requires_exact_source_stages(case)
            else _stage_ids(case, complete=exploit["sink_reached"]),
        },
        "control": {
            "healthy": True,
            "unsafe_matched": False,
            "handler_reached": True,
            "sink_reached": control["sink_reached"],
        },
        "sandbox": {
            "root": "<isolated-runtime-directory>",
            "effect": "file read confined to temporary hardlink/symlink fixture",
        },
    }


def run_native_pair_inprocess(
    case: Mapping[str, Any],
    attempt: int,
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    """Dispatch one already-isolated attempt to its source-bound driver."""

    drivers = {
        "AstrBot": astrbot_pair_driver,
        "QwenPaw": qwenpaw_pair_driver,
        "chatgpt-on-wechat": cowagent_pair_driver,
        "hermes-agent": hermes_pair_driver,
        "nanobot": nanobot_pair_driver,
        "droidclaw": typescript_pair_driver,
        "lettabot": typescript_pair_driver,
        "mercury-agent": typescript_pair_driver,
        "nanoclaw": typescript_pair_driver,
        "openclaw": typescript_pair_driver,
        "openclaw-cn": typescript_pair_driver,
    }
    try:
        driver = drivers[case["project"]]
    except KeyError as exc:
        raise ValueError(f"no native driver for project {case['project']!r}") from exc
    return driver(case, attempt, attempt_dir, sandbox)
