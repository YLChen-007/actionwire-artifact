"""Stateful Claude Agent SDK transport with read-only LSP-MCP research tools."""

from __future__ import annotations

import asyncio
import concurrent.futures
import dataclasses
import importlib.metadata
import json
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Coroutine
from urllib.parse import unquote, urlparse

from src.sink_capacity.agent import (
    CLAUDE_BIN,
    DEEPSEEK_ANTHROPIC_BASE,
    DEEPSEEK_API_KEY,
    DEFAULT_MODEL,
    AgentError,
)


BUILTIN_RESEARCH_TOOLS = ("Read", "Grep", "Glob")
LSP_SERVER_NAME = "lsp"
LSP_TOOL_NAMES = (
    "lsp_init",
    "lsp_definition",
    "lsp_references",
    "lsp_document_symbols",
    "lsp_workspace_symbols",
    "lsp_diagnostics",
    "lsp_type_definition",
    "lsp_implementation",
    "lsp_health",
)
LSP_RESEARCH_TOOLS = tuple(
    f"mcp__{LSP_SERVER_NAME}__{name}" for name in LSP_TOOL_NAMES
)
ALL_RESEARCH_TOOLS = BUILTIN_RESEARCH_TOOLS + LSP_RESEARCH_TOOLS
SDK_TRANSPORT_VERSION = "claude-agent-sdk-lsp/v1"
SOURCE_ROOT_POLICY_VERSION = "source-root-pretool/v1"
CLI_TRANSPORT_VERSION = "claude-cli-json/v1"

MODULE_DIR = Path(__file__).resolve().parent
LSP_BRIDGE = MODULE_DIR / "lsp" / "node_modules" / ".bin" / "lsp-mcp"
LSP_BIN_DIR = LSP_BRIDGE.parent

_TOOL_PATH_KEYS = {
    "Read": "file_path",
    "Grep": "path",
    "Glob": "path",
    "mcp__lsp__lsp_init": "root",
    "mcp__lsp__lsp_definition": "file",
    "mcp__lsp__lsp_references": "file",
    "mcp__lsp__lsp_document_symbols": "file",
    "mcp__lsp__lsp_diagnostics": "file",
    "mcp__lsp__lsp_type_definition": "file",
    "mcp__lsp__lsp_implementation": "file",
}


def _deepseek_env(model: str) -> dict[str, str]:
    return {
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_BASE_URL": DEEPSEEK_ANTHROPIC_BASE,
        "ANTHROPIC_AUTH_TOKEN": DEEPSEEK_API_KEY,
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "CLAUDE_CODE_ENTRYPOINT": "gate-semantics-sdk",
    }


def _jsonable(value: object) -> object:
    if dataclasses.is_dataclass(value):
        return {key: _jsonable(item) for key, item in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def normalize_token_usage(raw_usage: object) -> dict[str, int | bool]:
    """Normalize Anthropic-compatible usage while preserving cache categories."""

    usage = raw_usage if isinstance(raw_usage, dict) else {}

    known_keys = {
        "input_tokens",
        "inputTokens",
        "output_tokens",
        "outputTokens",
        "cache_creation_input_tokens",
        "cacheCreationInputTokens",
        "cache_read_input_tokens",
        "cacheReadInputTokens",
        "provider_reported",
    }
    if usage and not (set(usage) & known_keys):
        nested = [value for value in usage.values() if isinstance(value, dict)]
        if nested:
            return aggregate_token_usage(nested)

    def token_count(*keys: str) -> int:
        value = next((usage[key] for key in keys if key in usage), 0)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    input_tokens = token_count("input_tokens", "inputTokens")
    cache_creation = token_count(
        "cache_creation_input_tokens", "cacheCreationInputTokens"
    )
    cache_read = token_count("cache_read_input_tokens", "cacheReadInputTokens")
    output_tokens = token_count("output_tokens", "outputTokens")
    total_input = input_tokens + cache_creation + cache_read
    reported_value = usage.get("provider_reported")
    provider_reported = (
        reported_value if isinstance(reported_value, bool) else bool(usage)
    )
    return {
        "provider_reported": provider_reported,
        "input_tokens": input_tokens,
        "cache_creation_input_tokens": cache_creation,
        "cache_read_input_tokens": cache_read,
        "output_tokens": output_tokens,
        "total_input_tokens": total_input,
        "total_tokens": total_input + output_tokens,
    }


def aggregate_token_usage(usages: list[object]) -> dict[str, int | bool]:
    """Sum normalized or provider-native usage records."""

    total = normalize_token_usage(None)
    total["provider_reported"] = False
    for usage in usages:
        current = normalize_token_usage(usage)
        total["provider_reported"] = bool(total["provider_reported"]) or bool(
            current["provider_reported"]
        )
        for key in (
            "input_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
            "output_tokens",
            "total_input_tokens",
            "total_tokens",
        ):
            total[key] = int(total[key]) + int(current[key])
    return total


def _source_root_denial(
    source_root: Path,
    tool_name: str,
    tool_input: dict[str, Any],
) -> str | None:
    """Return a denial reason when a research tool addresses an external path."""

    key = _TOOL_PATH_KEYS.get(tool_name)
    if key is None or key not in tool_input:
        return None
    raw_value = tool_input.get(key)
    if not isinstance(raw_value, str):
        return f"{tool_name}.{key} must be a path string"

    parsed = urlparse(raw_value)
    if parsed.scheme:
        if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
            return f"{tool_name}.{key} uses an unsupported path URI"
        raw_value = unquote(parsed.path)

    candidate = Path(raw_value).expanduser()
    if not candidate.is_absolute():
        candidate = source_root / candidate
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(source_root)
    except (OSError, RuntimeError, ValueError):
        return (
            f"{tool_name}.{key} resolves outside the authorized source root "
            f"{source_root}"
        )
    return None


class ClaudeCLIRunner:
    """Claude CLI fallback that requests JSON so provider token usage is retained."""

    def __init__(
        self,
        *,
        source_root: Path,
        model: str | None = None,
        timeout: int = 900,
        max_turns: int = 20,
    ) -> None:
        self.source_root = source_root.resolve()
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout
        self.max_turns = max_turns
        self._turns: list[dict[str, Any]] = []

    def __call__(self, system: str, user: str) -> str:
        command = [
            CLAUDE_BIN,
            "-p",
            user.strip(),
            "--system-prompt",
            system.strip(),
            "--model",
            self.model,
            "--output-format",
            "json",
            "--permission-mode",
            "bypassPermissions",
            "--max-turns",
            str(self.max_turns),
            "--tools",
            ",".join(BUILTIN_RESEARCH_TOOLS),
            "--allowedTools",
            *BUILTIN_RESEARCH_TOOLS,
            "--setting-sources",
            "project",
            "--no-session-persistence",
            "--add-dir",
            str(self.source_root),
        ]
        turn: dict[str, Any] = {
            "turn": len(self._turns) + 1,
            "system_prompt": system,
            "user_prompt": user,
            "command_transport": CLI_TRANSPORT_VERSION,
        }
        try:
            completed = subprocess.run(
                command,
                cwd=self.source_root,
                env={**os.environ, **_deepseek_env(self.model)},
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if completed.returncode != 0:
                raise AgentError(
                    f"claude exit {completed.returncode}: "
                    f"{(completed.stderr or completed.stdout)[-1500:]}"
                )
            try:
                result = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise AgentError("claude CLI returned invalid JSON output") from exc
            if not isinstance(result, dict):
                raise AgentError("claude CLI JSON result must be an object")
            turn["result"] = _jsonable(result)
            output = str(result.get("result") or "").strip()
            if result.get("is_error"):
                raise AgentError(output or "claude CLI returned an error result")
            if not output:
                raise AgentError("claude CLI returned empty output")
            turn["assistant_response"] = output
            return output
        except subprocess.TimeoutExpired as exc:
            error = AgentError(f"claude timed out after {self.timeout}s")
            turn["error"] = f"{type(error).__name__}: {error}"
            raise error from exc
        except Exception as exc:
            turn["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            self._turns.append(turn)

    def audit_payload(self) -> dict[str, Any]:
        usage = aggregate_token_usage(
            [
                (
                    turn.get("result", {}).get("usage")
                    or turn.get("result", {}).get("modelUsage")
                )
                for turn in self._turns
                if isinstance(turn.get("result"), dict)
            ]
        )
        return {
            "transport": CLI_TRANSPORT_VERSION,
            "model": self.model,
            "source_root": str(self.source_root),
            "available_tools": list(BUILTIN_RESEARCH_TOOLS),
            "token_usage": usage,
            "turns": [
                {
                    key: value
                    for key, value in turn.items()
                    if key in {"turn", "result", "error"}
                }
                for turn in self._turns
            ],
        }

    def chat_payload(self) -> dict[str, Any]:
        return {
            "transport": CLI_TRANSPORT_VERSION,
            "model": self.model,
            "source_root": str(self.source_root),
            "token_usage": self.audit_payload()["token_usage"],
            "turns": list(self._turns),
        }

    def close(self) -> None:
        return None


class ClaudeAgentSDKRunner:
    """Keep one ClaudeSDKClient and one LSP-MCP process alive for one gate."""

    def __init__(
        self,
        *,
        source_root: Path,
        model: str | None = None,
        timeout: int = 900,
        max_turns: int = 20,
        enable_lsp: bool = True,
        allowed_source_files: tuple[str, ...] = (),
        max_tool_calls: int | None = None,
    ) -> None:
        self.source_root = source_root.resolve()
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout
        self.max_turns = max_turns
        self.enable_lsp = enable_lsp
        self.allowed_source_files = tuple(sorted(set(allowed_source_files)))
        self._allowed_source_paths = {
            (self.source_root / path).resolve(strict=False)
            for path in self.allowed_source_files
        }
        self.max_tool_calls = max_tool_calls
        self._runtime_config = Path(
            tempfile.mkdtemp(prefix="clawgap-gate-lsp-")
        ).resolve()
        self._loop = asyncio.new_event_loop()
        self._loop_ready = threading.Event()
        self._thread = threading.Thread(
            target=self._serve_loop,
            name="gate-semantics-agent-sdk",
            daemon=True,
        )
        self._thread.start()
        self._loop_ready.wait()
        self._client: Any = None
        self._base_system: str | None = None
        self._session_id: str | None = None
        self._mcp_status: dict[str, Any] | None = None
        self._turns: list[dict[str, Any]] = []
        self._stderr: list[str] = []
        self._policy_checks = 0
        self._policy_denials: list[dict[str, Any]] = []
        self._closed = False

    def _serve_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop_ready.set()
        self._loop.run_forever()

    def _submit(self, coroutine: Coroutine[Any, Any, Any], timeout: int) -> Any:
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()
            raise AgentError(f"Claude Agent SDK timed out after {timeout}s") from exc

    def _options(self, system: str) -> Any:
        try:
            from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
        except ImportError as exc:
            raise AgentError(
                "claude-agent-sdk is unavailable; install "
                "src/gate_semantics/requirements.txt or use --agent-transport cli"
            ) from exc

        tools = list(BUILTIN_RESEARCH_TOOLS)
        if self.allowed_source_files:
            tools.remove("Glob")
        mcp_servers: dict[str, dict[str, Any]] = {}
        if self.enable_lsp:
            if not LSP_BRIDGE.is_file():
                raise AgentError(
                    f"LSP MCP bridge is missing: {LSP_BRIDGE}; run npm install in "
                    f"{MODULE_DIR / 'lsp'}"
                )
            tools.extend(LSP_RESEARCH_TOOLS)
            if self.allowed_source_files:
                tools.remove("mcp__lsp__lsp_workspace_symbols")
            mcp_servers[LSP_SERVER_NAME] = {
                "type": "stdio",
                "command": str(LSP_BRIDGE),
                "args": [],
                "env": {
                    "LSP_MCP_LOG_LEVEL": "error",
                    "XDG_CONFIG_HOME": str(self._runtime_config),
                    "PATH": f"{LSP_BIN_DIR}{os.pathsep}{os.environ.get('PATH', '')}",
                    "NODE_PATH": str(MODULE_DIR / "lsp" / "node_modules"),
                },
            }

        return ClaudeAgentOptions(
            cwd=self.source_root,
            add_dirs=[self.source_root],
            cli_path=shutil.which(CLAUDE_BIN) or CLAUDE_BIN,
            system_prompt=system,
            model=self.model,
            max_turns=self.max_turns,
            tools=tools,
            allowed_tools=tools,
            disallowed_tools=[
                "Edit",
                "Write",
                "Bash",
                "WebFetch",
                "WebSearch",
                "mcp__lsp__lsp_rename",
                "mcp__lsp__lsp_code_action",
                "mcp__lsp__lsp_formatting",
                "mcp__lsp__lsp_range_formatting",
            ],
            mcp_servers=mcp_servers,
            strict_mcp_config=True,
            permission_mode="dontAsk",
            setting_sources=[],
            skills=[],
            hooks={
                "PreToolUse": [
                    HookMatcher(
                        matcher="|".join(ALL_RESEARCH_TOOLS),
                        hooks=[self._guard_source_root],
                    )
                ]
            },
            env=_deepseek_env(self.model),
            stderr=self._capture_stderr,
        )

    async def _guard_source_root(
        self,
        hook_input: dict[str, Any],
        _tool_use_id: str | None,
        _context: object,
    ) -> dict[str, Any]:
        tool_name = str(hook_input.get("tool_name", ""))
        tool_input = hook_input.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {}
        self._policy_checks += 1
        if self.max_tool_calls is not None and self._policy_checks > self.max_tool_calls:
            reason = f"source-validation tool-call limit exceeded ({self.max_tool_calls})"
            self._policy_denials.append(
                {
                    "tool_name": tool_name,
                    "tool_input": _jsonable(tool_input),
                    "reason": reason,
                }
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        reason = _source_root_denial(self.source_root, tool_name, tool_input)
        if reason is None and self._allowed_source_paths:
            key = _TOOL_PATH_KEYS.get(tool_name)
            raw_path = tool_input.get(key) if key is not None else None
            if tool_name == "mcp__lsp__lsp_init" and raw_path is not None:
                candidate = Path(str(raw_path))
                if not candidate.is_absolute():
                    candidate = self.source_root / candidate
                if candidate.resolve(strict=False) != self.source_root:
                    reason = "packet-constrained LSP root must equal the source root"
            elif key is not None and raw_path is not None:
                candidate = Path(str(raw_path))
                if not candidate.is_absolute():
                    candidate = self.source_root / candidate
                if candidate.resolve(strict=False) not in self._allowed_source_paths:
                    reason = (
                        f"{tool_name}.{key} is outside the packet source-file allowlist"
                    )
        if reason is None:
            return {}
        self._policy_denials.append(
            {
                "tool_name": tool_name,
                "tool_input": _jsonable(tool_input),
                "reason": reason,
            }
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

    def _capture_stderr(self, line: str) -> None:
        if len(self._stderr) < 200:
            self._stderr.append(line.rstrip())

    async def _connect(self, system: str) -> None:
        from claude_agent_sdk import ClaudeSDKClient

        self._base_system = system
        self._client = ClaudeSDKClient(self._options(system))
        await self._client.connect()
        if self.enable_lsp:
            status = await self._client.get_mcp_status()
            self._mcp_status = _jsonable(status)  # type: ignore[assignment]

    @staticmethod
    def _attach_tool_result(
        calls: list[dict[str, Any]], tool_use_id: str, content: object, is_error: object
    ) -> None:
        for call in reversed(calls):
            if call.get("tool_use_id") == tool_use_id:
                call["result"] = _jsonable(content)
                call["is_error"] = bool(is_error)
                return

    async def _run_turn(self, system: str, user: str) -> str:
        from claude_agent_sdk.types import (
            AssistantMessage,
            ResultMessage,
            TextBlock,
            ToolResultBlock,
            ToolUseBlock,
            UserMessage,
        )

        initial_turn = self._client is None
        prompt = user
        if not initial_turn and system != self._base_system:
            prompt = (
                "TURN-SPECIFIC ROLE INSTRUCTIONS:\n"
                + system.strip()
                + "\n\nTURN TASK:\n"
                + user.strip()
            )
        turn: dict[str, Any] = {
            "turn": len(self._turns) + 1,
            "role": "initial" if initial_turn else "follow-up",
            "system_prompt": system,
            "user_prompt": user,
            "effective_user_prompt": prompt,
            "events": [],
            "tool_calls": [],
        }
        try:
            if initial_turn:
                await self._connect(system)

            await self._client.query(prompt)
            assistant_text: list[str] = []
            final_result: str | None = None
            result_error: AgentError | None = None
            async for message in self._client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            assistant_text.append(block.text)
                            turn["events"].append(
                                {
                                    "role": "assistant",
                                    "type": "text",
                                    "text": block.text,
                                }
                            )
                        elif isinstance(block, ToolUseBlock):
                            tool_call = {
                                "tool_use_id": block.id,
                                "name": block.name,
                                "input": _jsonable(block.input),
                            }
                            turn["tool_calls"].append(tool_call)
                            turn["events"].append(
                                {
                                    "role": "assistant",
                                    "type": "tool_use",
                                    **tool_call,
                                }
                            )
                        elif isinstance(block, ToolResultBlock):
                            self._attach_tool_result(
                                turn["tool_calls"],
                                block.tool_use_id,
                                block.content,
                                block.is_error,
                            )
                            turn["events"].append(
                                {
                                    "role": "tool",
                                    "type": "tool_result",
                                    "tool_use_id": block.tool_use_id,
                                    "content": _jsonable(block.content),
                                    "is_error": bool(block.is_error),
                                }
                            )
                elif isinstance(message, UserMessage) and isinstance(
                    message.content, list
                ):
                    for block in message.content:
                        if isinstance(block, ToolResultBlock):
                            self._attach_tool_result(
                                turn["tool_calls"],
                                block.tool_use_id,
                                block.content,
                                block.is_error,
                            )
                            turn["events"].append(
                                {
                                    "role": "tool",
                                    "type": "tool_result",
                                    "tool_use_id": block.tool_use_id,
                                    "content": _jsonable(block.content),
                                    "is_error": bool(block.is_error),
                                }
                            )
                elif isinstance(message, ResultMessage):
                    self._session_id = message.session_id
                    turn["result"] = {
                        "subtype": message.subtype,
                        "is_error": message.is_error,
                        "num_turns": message.num_turns,
                        "duration_ms": message.duration_ms,
                        "duration_api_ms": message.duration_api_ms,
                        "stop_reason": message.stop_reason,
                        "total_cost_usd": message.total_cost_usd,
                        "usage": _jsonable(message.usage),
                        "model_usage": _jsonable(message.model_usage),
                        "errors": _jsonable(message.errors),
                    }
                    if message.is_error:
                        result_error = AgentError(
                            "Claude Agent SDK returned an error: "
                            + "; ".join(message.errors or [message.subtype])
                        )
                    else:
                        final_result = message.result
            if result_error is not None:
                raise result_error
            output = (final_result or "\n".join(assistant_text)).strip()
            if not output:
                raise AgentError("Claude Agent SDK returned empty output")
            turn["assistant_response"] = output
            return output
        except Exception as exc:
            turn["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            if self.enable_lsp and self._client is not None:
                try:
                    status = await self._client.get_mcp_status()
                    self._mcp_status = _jsonable(status)  # type: ignore[assignment]
                except Exception as exc:
                    turn["mcp_status_error"] = f"{type(exc).__name__}: {exc}"
            self._turns.append(turn)

    def __call__(self, system: str, user: str) -> str:
        if self._closed:
            raise AgentError("Claude Agent SDK gate session is already closed")
        return str(self._submit(self._run_turn(system, user), self.timeout))

    def audit_payload(self) -> dict[str, Any]:
        try:
            sdk_version = importlib.metadata.version("claude-agent-sdk")
        except importlib.metadata.PackageNotFoundError:
            sdk_version = "unavailable"
        token_usage = aggregate_token_usage(
            [
                (
                    turn.get("result", {}).get("usage")
                    or turn.get("result", {}).get("model_usage")
                )
                for turn in self._turns
                if isinstance(turn.get("result"), dict)
            ]
        )
        return {
            "transport": SDK_TRANSPORT_VERSION,
            "sdk_version": sdk_version,
            "model": self.model,
            "session_id": self._session_id,
            "token_usage": token_usage,
            "source_root": str(self.source_root),
            "lsp": {
                "enabled": self.enable_lsp,
                "bridge": "@theupsider/lsp-mcp@1.3.2" if self.enable_lsp else None,
                "mcp_status": self._mcp_status,
            },
            "available_tools": list(
                ALL_RESEARCH_TOOLS if self.enable_lsp else BUILTIN_RESEARCH_TOOLS
            ),
            "source_root_policy": {
                "version": SOURCE_ROOT_POLICY_VERSION,
                "checked_calls": self._policy_checks,
                "denials": list(self._policy_denials),
            },
            "packet_constraints": {
                "allowed_source_files": list(self.allowed_source_files),
                "max_tool_calls": self.max_tool_calls,
            },
            "turns": [
                {
                    key: value
                    for key, value in turn.items()
                    if key
                    in {
                        "turn",
                        "role",
                        "tool_calls",
                        "result",
                        "error",
                        "mcp_status_error",
                    }
                }
                for turn in self._turns
            ],
            "stderr_tail": self._stderr[-20:],
        }

    def chat_payload(self) -> dict[str, Any]:
        """Return the exact prompts, responses, and chronological tool events."""

        return {
            "transport": SDK_TRANSPORT_VERSION,
            "model": self.model,
            "session_id": self._session_id,
            "token_usage": self.audit_payload()["token_usage"],
            "source_root": str(self.source_root),
            "turns": list(self._turns),
        }

    async def _disconnect(self) -> None:
        if self._client is not None:
            await self._client.disconnect()
            self._client = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._submit(self._disconnect(), min(self.timeout, 30))
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
            if not self._thread.is_alive():
                self._loop.close()
            shutil.rmtree(self._runtime_config, ignore_errors=True)

    def __enter__(self) -> "ClaudeAgentSDKRunner":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def build_sdk_runner(
    *,
    source_root: Path,
    model: str | None,
    timeout: int,
    max_turns: int,
    enable_lsp: bool,
    allowed_source_files: tuple[str, ...] = (),
    max_tool_calls: int | None = None,
) -> ClaudeAgentSDKRunner:
    return ClaudeAgentSDKRunner(
        source_root=source_root,
        model=model,
        timeout=timeout,
        max_turns=max_turns,
        enable_lsp=enable_lsp,
        allowed_source_files=allowed_source_files,
        max_tool_calls=max_tool_calls,
    )
