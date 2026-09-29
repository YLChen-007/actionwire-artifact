"""Targeted forced-provider L2 runtime for linked OpenClaw candidates."""

from __future__ import annotations

import json
import os
import signal
import shutil
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
    redact_text,
    sha256_file,
)
from .campaign_contracts import canonical_json, digest


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("openclaw")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
TARGET_CANDIDATES = (
    "CAND-1257773235495a1c",
    "CAND-e2144f9497e0ba16",
    "CAND-97075fee3572a83e",
    "CAND-277f68cbebf546d0",
    "CAND-9c7a141a83043d0c",
)
CAMPAIGN_ID = "runtime-dynamic-trigger-openclaw-l2-v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-openclaw-l2-result/v1"
CANARY_CONTENT = "clawgap-openclaw-host-canary\n"

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
CONTROL_STAGES = tuple(
    stage
    for stage in NORMALIZED_STAGES
    if stage not in {"sink_reached", "pre_effect_interception"}
)


@dataclass(frozen=True)
class OpenClawL2RunRequest:
    campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    out_dir: Path = ...
    attempts: int = 3
    timeout: int = 90
    build_timeout: int = 1200
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
        raise ValidationError(f"cannot read OpenClaw L2 artifact {path}: {exc}") from exc
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


def _select_cases(
    campaign: Path, candidate_id: str | None = None
) -> list[dict[str, Any]]:
    cases = _read_jsonl(campaign / "cases.jsonl")
    selected = {
        str(row.get("candidate_binding", {}).get("candidate_id")): row
        for row in cases
        if row.get("project") == "openclaw"
    }
    expected = set(TARGET_CANDIDATES)
    if not expected.issubset(selected):
        missing = sorted(expected - set(selected))
        raise ValidationError(
            "OpenClaw targeted L2 source campaign is missing GT-linked candidates: "
            + ", ".join(missing)
        )
    if candidate_id is not None:
        if candidate_id not in expected:
            raise ValidationError(
                "requested OpenClaw candidate is not a GT-linked targeted L2 candidate"
            )
        return [selected[candidate_id]]
    return [selected[candidate_id] for candidate_id in TARGET_CANDIDATES]


def _source_bindings(cases: list[Mapping[str, Any]]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    required_files = {
        "package.json",
        "pnpm-lock.yaml",
        "tsconfig.json",
        "src/agents/bash-tools.exec.ts",
        "src/node-host/runner.ts",
        "src/process/spawn-utils.ts",
    }
    for case in cases:
        if case.get("revision") != PROJECT.analysis_revision:
            raise ValidationError("OpenClaw case revision does not match registry")
        for row in case["source_binding"]["files"]:
            relative = str(row["path"])
            source = SOURCE_ROOT / relative
            if not source.is_file():
                raise ValidationError(f"OpenClaw bound source is missing: {relative}")
            value = sha256_file(source)
            if value != row["sha256"]:
                raise ValidationError(f"OpenClaw source hash drift: {relative}")
            bindings[relative] = value
    for relative in sorted(required_files - set(bindings)):
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"OpenClaw build source is missing: {relative}")
        bindings[relative] = sha256_file(source)
    return bindings


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(f"OpenClaw instrumentation marker mismatch ({label}): {count}")
    return source.replace(old, new, 1)


def _replace_second_once(source: str, old: str, new: str, label: str) -> str:
    first = source.find(old)
    second = source.find(old, first + 1)
    third = source.find(old, second + 1)
    if first < 0 or second < 0 or third >= 0:
        count = source.count(old)
        raise ValidationError(
            f"OpenClaw instrumentation marker mismatch ({label}): {count}"
        )
    return source[:second] + new + source[second + len(old) :]


def _instrumentation_helper() -> str:
    return r'''
import { appendFileSync } from "node:fs";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import type { ChildProcess } from "node:child_process";

let clawgapHandlerObserved = false;

function clawgapEvent(stage: string, detail: Record<string, unknown>): void {
  const path = process.env.CLAWGAP_L2_EVENT_PATH;
  if (!path) return;
  appendFileSync(path, JSON.stringify({
    schema_version: "clawgap-dynamic-trigger-openclaw-l2-event/v1",
    stage,
    candidate_id: process.env.CLAWGAP_L2_CANDIDATE_ID,
    case_id: process.env.CLAWGAP_L2_CASE_ID,
    attempt: Number(process.env.CLAWGAP_L2_ATTEMPT ?? "0"),
    role: process.env.CLAWGAP_L2_ROLE,
    correlation_id: process.env.CLAWGAP_L2_CORRELATION_ID,
    fixture_id: process.env.CLAWGAP_L2_FIXTURE_ID,
    detail,
  }) + "\n");
}

class ClawgapInterceptedChild extends EventEmitter {
  readonly stdout = new PassThrough({ objectMode: false });
  readonly stderr = new PassThrough({ objectMode: false });
  readonly stdin = new PassThrough({ objectMode: false });
  readonly pid = -1;
  readonly exitCode = 0;
  readonly killed = false;
  kill(): boolean {
    this.emit("exit", 0, null);
    return true;
  }
}

export function __clawgapHandlerEntered(toolArguments: unknown): void {
  clawgapHandlerObserved = true;
  clawgapEvent("handler_entered", { tool_name: "exec", arguments: toolArguments });
}

export function __clawgapControlledArgument(value: unknown): void {
  clawgapEvent("controlled_argument_recorded", {
    argument_path: ["command"],
    value,
  });
}

export function __clawgapGateObserved(detail: Record<string, unknown>): void {
  clawgapEvent("gate_observed", detail);
}

export function __clawgapInterceptSpawn(
  sinkAnchor: string,
  command: string,
  args: readonly string[],
  fallback: () => ChildProcess,
): ChildProcess {
  if (!clawgapHandlerObserved) return fallback();
  clawgapEvent("sink_reached", {
    sink_anchor: sinkAnchor,
    command,
    args: [...args],
    argv: [command, ...args],
  });
  clawgapEvent("pre_effect_interception", {
    sink_anchor: sinkAnchor,
    command,
    args: [...args],
    argv: [command, ...args],
    executed: false,
  });
  const child = new ClawgapInterceptedChild() as unknown as ChildProcess;
  setTimeout(() => {
    child.emit("spawn");
    child.emit("exit", 0, null);
    setTimeout(() => {
      child.emit("close", 0, null);
    }, 20);
  }, 100);
  return child;
}
'''


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
        ignore=shutil.ignore_patterns(".git", "node_modules", "dist"),
    )
    (project / "node_modules").symlink_to(
        SOURCE_ROOT / "node_modules", target_is_directory=True
    )
    (project / "src" / "clawgap-l2.ts").write_text(
        _instrumentation_helper(), encoding="utf-8"
    )

    exec_path = project / "src" / "agents" / "bash-tools.exec.ts"
    exec_source = exec_path.read_text(encoding="utf-8")
    exec_source = (
        'import { __clawgapControlledArgument, __clawgapGateObserved, '
        '__clawgapHandlerEntered } from "../clawgap-l2.js";\n' + exec_source
    )
    handler_marker = "      if (!params.command) {\n        throw new Error(\"Provide a command to start.\");\n      }"
    handler_replacement = (
        "      __clawgapHandlerEntered(args);\n"
        "      __clawgapControlledArgument(params.command);\n"
        + handler_marker
    )
    exec_source = _replace_once(
        exec_source, handler_marker, handler_replacement, "exec handler entry"
    )
    gate_marker = (
        "        const requiresAsk = requiresExecApproval({\n"
        "          ask: hostAsk,\n"
        "          security: hostSecurity,\n"
        "          analysisOk,\n"
        "          allowlistSatisfied,\n"
        "        });"
    )
    gate_replacement = (
        gate_marker
        + "\n        __clawgapGateObserved({\n"
        "          gate_ids: (process.env.CLAWGAP_L2_GATE_IDS ?? \"\").split(\",\").filter(Boolean),\n"
        "          command: params.command,\n"
        "          admitted: allowlistSatisfied,\n"
        "          analysis_ok: analysisOk,\n"
        "          security: hostSecurity,\n"
        "          ask: hostAsk,\n"
        "        });"
    )
    exec_source = _replace_second_once(
        exec_source, gate_marker, gate_replacement, "gateway allowlist gate"
    )
    exec_path.write_text(exec_source, encoding="utf-8")

    runner_path = project / "src" / "node-host" / "runner.ts"
    runner_source = runner_path.read_text(encoding="utf-8")
    runner_source = (
        'import { __clawgapInterceptSpawn } from "../clawgap-l2.js";\n'
        + runner_source
    )
    runner_marker = (
        "    const child = spawn(argv[0], argv.slice(1), {\n"
        "      cwd,\n"
        "      env,\n"
        "      stdio: [\"ignore\", \"pipe\", \"pipe\"],\n"
        "      windowsHide: true,\n"
        "    });"
    )
    runner_replacement = (
        "    const child = __clawgapInterceptSpawn(\n"
        "      \"src/node-host/runner.ts:405\",\n"
        "      argv[0],\n"
        "      argv.slice(1),\n"
        "      () => spawn(argv[0], argv.slice(1), {\n"
        "        cwd,\n"
        "        env,\n"
        "        stdio: [\"ignore\", \"pipe\", \"pipe\"],\n"
        "        windowsHide: true,\n"
        "      }),\n"
        "    );"
    )
    runner_source = _replace_once(
        runner_source, runner_marker, runner_replacement, "node-host process sink"
    )
    runner_path.write_text(runner_source, encoding="utf-8")

    spawn_path = project / "src" / "process" / "spawn-utils.ts"
    spawn_source = spawn_path.read_text(encoding="utf-8")
    spawn_source = (
        'import { __clawgapInterceptSpawn } from "../clawgap-l2.js";\n'
        + spawn_source
    )
    spawn_marker = "  const child = spawnImpl(argv[0], argv.slice(1), options);"
    spawn_replacement = (
        "  const child = __clawgapInterceptSpawn(\n"
        "    \"src/process/spawn-utils.ts:67\",\n"
        "    argv[0],\n"
        "    argv.slice(1),\n"
        "    () => spawnImpl(argv[0], argv.slice(1), options),\n"
        "  );"
    )
    spawn_source = _replace_once(
        spawn_source, spawn_marker, spawn_replacement, "process spawn sink"
    )
    spawn_path.write_text(spawn_source, encoding="utf-8")

    transformed = {
        relative: sha256_file(project / relative)
        for relative in (
            "src/clawgap-l2.ts",
            "src/agents/bash-tools.exec.ts",
            "src/node-host/runner.ts",
            "src/process/spawn-utils.ts",
        )
    }
    return {
        "schema_version": "clawgap-openclaw-transformed-source-manifest/v1",
        "revision": PROJECT.analysis_revision,
        "original": dict(source_bindings),
        "transformed": transformed,
        "node_modules": "read-only dependency symlink to pinned benchmark installation",
        "build_required": True,
    }


def _prepare_build(
    directory: Path, source_bindings: Mapping[str, str], timeout: int
) -> dict[str, Any]:
    harness_sha256 = sha256_file(REPO_ROOT / "src/runtime_validation/openclaw_l2.py")
    manifest_path = directory / "transformed-source-manifest.json"
    entrypoint = directory / "project" / "dist" / "entry.js"
    if manifest_path.is_file() and entrypoint.is_file():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version") == "clawgap-openclaw-transformed-source-manifest/v1"
            and prior.get("revision") == PROJECT.analysis_revision
            and prior.get("original") == dict(source_bindings)
            and prior.get("dependency_lockfile") == sha256_file(SOURCE_ROOT / "pnpm-lock.yaml")
            and prior.get("harness_sha256") == harness_sha256
            and prior.get("entrypoint_sha256") == sha256_file(entrypoint)
        ):
            return prior
    manifest = _render_build_copy(directory, source_bindings)
    project = directory / "project"
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(directory / "home"),
        "CI": "true",
        "NO_COLOR": "1",
    }
    (directory / "home").mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            ["pnpm", "run", "build"],
            cwd=project,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if not isinstance(output, str):
            output = output.decode("utf-8", errors="replace")
        atomic_write_text(directory / "build.log", redact_text(output))
        raise ValidationError("OpenClaw instrumented build timed out") from exc
    atomic_write_text(
        directory / "build.log", redact_text(completed.stdout or "")
    )
    entrypoint = project / "dist" / "entry.js"
    if completed.returncode != 0 or not entrypoint.is_file():
        raise ValidationError(
            f"OpenClaw instrumented build failed with exit {completed.returncode}"
        )
    manifest["build_exit_code"] = completed.returncode
    manifest["entrypoint_sha256"] = sha256_file(entrypoint)
    manifest["dependency_lockfile"] = sha256_file(SOURCE_ROOT / "pnpm-lock.yaml")
    manifest["harness_sha256"] = harness_sha256
    atomic_write_json(directory / "transformed-source-manifest.json", manifest)
    _remove_path(directory / "home")
    return manifest


class OpenClawFixtureServer:
    """Loopback OpenAI fixture returning exactly one reviewed exec tool call."""

    def __init__(
        self,
        role: str,
        arguments: Mapping[str, Any],
        transcript_path: Path,
        tool_name: str = "exec",
    ):
        self.role = role
        self.arguments = dict(arguments)
        self.tool_name = tool_name
        self.transcript_path = transcript_path
        self.request_count = 0
        self.valid_request = False
        self.unsupported: list[str] = []
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:
                return

            def _record(self, body: str, valid: bool, reason: str = "") -> None:
                row = canonical_json(
                    {
                        "schema_version": "clawgap-openclaw-provider-transcript/v1",
                        "timestamp": _utc_now(),
                        "method": self.command,
                        "path": self.path,
                        "authorization": "Bearer [REDACTED_CREDENTIAL]",
                        "valid": valid,
                        "reason": reason,
                        "body": json.loads(body) if body else None,
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

            def _route(self) -> None:
                path = self.path.split("?", 1)[0]
                size = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(size).decode("utf-8", errors="replace") if size else ""
                if self.command != "POST" or path != "/v1/chat/completions":
                    server.unsupported.append(f"{self.command} {path}")
                    self._record(raw, False, "unsupported provider endpoint")
                    self._error("clawgap OpenClaw fixture endpoint is not implemented", 404)
                    return
                with server._lock:
                    server.request_count += 1
                    number = server.request_count
                if number > 2:
                    self._record(raw, False, "more than one provider request")
                    self._error("more than two provider requests for reviewed role", 409)
                    return
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    body = None
                tools = body.get("tools", []) if isinstance(body, dict) else []
                tool_names = {
                    str(row.get("function", {}).get("name"))
                    for row in tools
                    if isinstance(row, dict)
                }
                valid = (
                    isinstance(body, dict)
                    and isinstance(body.get("messages"), list)
                    and bool(body.get("messages"))
                    and server.tool_name in tool_names
                    and body.get("stream") is True
                )
                server.valid_request = valid
                self._record(raw, valid, "" if valid else "invalid provider request")
                if not valid:
                    self._error("request does not match the OpenClaw tool-call contract", 400)
                    return
                tool_chunks = [
                    {
                        "id": f"chatcmpl-clawgap-openclaw-{server.role}",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "clawgap-environment-probe",
                        "choices": [
                            {
                                "index": 0,
                                "finish_reason": None,
                                "delta": {"role": "assistant"},
                            }
                        ],
                    },
                    {
                        "id": f"chatcmpl-clawgap-openclaw-{server.role}",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "clawgap-environment-probe",
                        "choices": [
                            {
                                "index": 0,
                                "finish_reason": None,
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "call-clawgap-openclaw",
                                            "type": "function",
                                            "function": {
                                                "name": server.tool_name,
                                                "arguments": json.dumps(
                                                    server.arguments,
                                                    separators=(",", ":"),
                                                    sort_keys=True,
                                                ),
                                            },
                                        }
                                    ]
                                },
                            }
                        ],
                    },
                    {
                        "id": f"chatcmpl-clawgap-openclaw-{server.role}",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "clawgap-environment-probe",
                        "choices": [
                            {"index": 0, "finish_reason": "tool_calls", "delta": {}}
                        ],
                    },
                ]
                final_chunks = [
                    {
                        "id": f"chatcmpl-clawgap-openclaw-{server.role}-final",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "clawgap-environment-probe",
                        "choices": [
                            {
                                "index": 0,
                                "finish_reason": None,
                                "delta": {"role": "assistant", "content": "clawgap role complete"},
                            }
                        ],
                    },
                    {
                        "id": f"chatcmpl-clawgap-openclaw-{server.role}-final",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "clawgap-environment-probe",
                        "choices": [
                            {"index": 0, "finish_reason": "stop", "delta": {}}
                        ],
                    },
                ]
                chunks = tool_chunks if number == 1 else final_chunks
                response = (
                    "".join(
                        "data: " + json.dumps(chunk, separators=(",", ":")) + "\n\n"
                        for chunk in chunks
                    )
                    + "data: [DONE]\n\n"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("cache-control", "no-cache")
                self.send_header("content-length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
                self.close_connection = True

            do_GET = _route
            do_POST = _route
            do_PATCH = _route
            do_PUT = _route
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


def _forced_arguments(case: Mapping[str, Any], role: str, workspace: Path) -> dict[str, Any]:
    row = next(
        item for item in case["forced_tool_calls"] if item.get("role") == role
    )
    arguments = dict(row["arguments"])
    if arguments.get("workdir") == "/tmp":
        arguments["workdir"] = str(workspace)
    return arguments


def _openclaw_config(base_url: str) -> str:
    return json.dumps(
        {
            "gateway": {
                "mode": "local",
                "auth": {"mode": "token", "token": "clawgap-loopback-mock"},
            },
            "agents": {
                "defaults": {
                    "model": {"primary": "clawgap/clawgap-environment-probe"},
                    "skipBootstrap": True,
                }
            },
            "tools": {
                "exec": {
                    "host": "gateway",
                    "security": "allowlist",
                    "ask": "off",
                    "safeBins": ["pwsh", "cmd", "jq"],
                }
            },
            "models": {
                "providers": {
                    "clawgap": {
                        "baseUrl": base_url,
                        "apiKey": "clawgap-loopback-mock",
                        "api": "openai-completions",
                        "models": [
                            {
                                "id": "clawgap-environment-probe",
                                "name": "ClawGap Environment Probe",
                                "reasoning": False,
                                "input": ["text"],
                                "cost": {
                                    "input": 0,
                                    "output": 0,
                                    "cacheRead": 0,
                                    "cacheWrite": 0,
                                },
                                "contextWindow": 128000,
                                "maxTokens": 128,
                            }
                        ],
                    }
                }
            },
        },
        indent=2,
        sort_keys=True,
    )


def _fake_executables(directory: Path) -> dict[str, str]:
    directory.mkdir(parents=True, exist_ok=True)
    fixture_files: dict[str, str] = {}
    for name in ("pwsh", "cmd", "jq"):
        path = directory / name
        atomic_write_text(
            path,
            "#!/bin/sh\nexit 111\n",
        )
        path.chmod(0o500)
        fixture_files[str(path)] = sha256_file(path)
    return fixture_files


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _prepare_role(
    directory: Path,
    build_project: Path,
    base_url: str,
) -> tuple[dict[str, str], Path, Path, Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    home = directory / "home"
    state = directory / "state"
    workspace = directory / "workspace"
    bins = directory / "bin"
    for path in (home, state, workspace):
        path.mkdir(parents=True)
    fixture_files = _fake_executables(bins)
    config_path = state / "openclaw.json"
    atomic_write_text(config_path, _openclaw_config(base_url))
    fixture_files[str(config_path)] = sha256_file(config_path)
    project_link = directory / "project"
    project_link.symlink_to(build_project, target_is_directory=True)
    return fixture_files, home, state, workspace, project_link


def _cleanup_role(
    directory: Path,
    home: Path,
    state: Path,
    workspace: Path,
    project_link: Path,
) -> None:
    for disposable in (home, state, workspace, directory / "tmp", directory / "bin"):
        _remove_path(disposable)
    if project_link.is_symlink():
        project_link.unlink()


def _base_event(
    stage: str,
    detail: Mapping[str, Any],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
) -> dict[str, Any]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    return {
        "schema_version": "clawgap-dynamic-trigger-openclaw-l2-event/v1",
        "event_id": f"{case['case_id']}:{attempt}:{role}:{stage}",
        "stage": stage,
        "candidate_id": candidate_id,
        "case_id": case["case_id"],
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{case['case_id']}:{attempt}:{role}",
        "fixture_id": f"openclaw-l2:{case['case_id']}:{role}",
        "detail": dict(detail),
    }


def _normalize_events(
    raw_events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    fixture_files: Mapping[str, str],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    synthetic: dict[str, dict[str, Any]] = {
        "case_bound": {"candidate_id": case["candidate_binding"]["candidate_id"]},
        "source_verified": {"revision": case["revision"]},
        "fixture_prepared": {
            "files": {key: "sha256" for key in sorted(fixture_files)}
        },
        "launch_started": {"entrypoint": "node dist/entry.js agent"},
        "prompt_received": {"message": "environment probe"},
    }
    for stage in ("case_bound", "source_verified", "fixture_prepared", "launch_started", "prompt_received"):
        events.append(_base_event(stage, synthetic[stage], case, attempt, role))
    request = next(
        (row for row in provider_rows if row.get("valid") is True),
        None,
    )
    if request is None:
        raise RuntimeError("real OpenClaw provider client did not issue a valid request")
    arguments = _forced_arguments(
        case, role, Path(str(case.get("fixture", {}).get("workspace", ".")))
    )
    events.append(
        _base_event(
            "provider_request",
            {
                "method": request["method"],
                "path": request["path"],
                "protocol": "openai-chat-completions/v1",
                "body_model": request.get("body", {}).get("model"),
            },
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "provider_tool_call_or_decision",
            {"tool_name": "exec", "arguments": arguments},
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "registry_or_native_dispatch",
            {"tool_name": "exec", "runtime": "openclaw-agent"},
            case,
            attempt,
            role,
        )
    )
    events.extend(dict(row) for row in raw_events)
    events.append(_base_event("target_completed", {}, case, attempt, role))
    events.append(
        _base_event("cleanup_verified", {"canary_healthy": True}, case, attempt, role)
    )
    for ordinal, event in enumerate(events, 1):
        event["ordinal"] = ordinal
    return events


def _sink_matches(candidate_id: str, sink: Mapping[str, Any]) -> bool:
    argv = [str(item) for item in sink.get("detail", {}).get("argv", [])]
    rendered = " ".join(argv)
    if candidate_id == "CAND-1257773235495a1c":
        return "RwBpAHIAdAAgACcAaABpACcA" in rendered
    if candidate_id == "CAND-e2144f9497e0ba16":
        return "echo safe" in rendered and "echo pwned" in rendered
    if candidate_id == "CAND-97075fee3572a83e":
        return "include" in rendered and "secret" in rendered
    return candidate_id in {
        "CAND-277f68cbebf546d0",
        "CAND-9c7a141a83043d0c",
    } and "jq env" in rendered


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    fixture: OpenClawFixtureServer,
    process_exit: int,
    output: str,
) -> PairOutcome:
    errors: list[str] = []
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    first = events[0] if events else {}
    identity = {key: first.get(key) for key in IDENTITY_FIELDS}
    if fixture.unsupported:
        errors.append(f"unsupported provider endpoints: {fixture.unsupported}")
    if fixture.request_count != 2 or not fixture.valid_request:
        errors.append(
            "provider fixture did not observe exactly one forced tool call "
            "and one final tool-result turn"
        )
    if process_exit != 0:
        errors.append(f"target process exited with {process_exit}")
    if "error" in output.lower() and "clawgap" not in output.lower():
        errors.append("real OpenClaw entrypoint reported an error")
    for event in events:
        row = {key: event.get(key) for key in IDENTITY_FIELDS}
        if row != identity:
            errors.append("cross-attempt or cross-correlation event stitching")
            break
    stages = [str(event.get("stage")) for event in events]
    valid_shape = stages in [list(CONTROL_STAGES), list(NORMALIZED_STAGES)]
    if len(stages) != len(set(stages)) or not valid_shape:
        errors.append(f"event sequence mismatch: {stages}")

    forced = _forced_arguments(case, role, Path("."))
    handler = next(
        (row for row in events if row.get("stage") == "handler_entered"), None
    )
    if handler is None or handler.get("detail", {}).get("tool_name") != "exec":
        errors.append("native exec handler was not entered")
    controlled = next(
        (row for row in events if row.get("stage") == "controlled_argument_recorded"), None
    )
    if (
        controlled is None
        or controlled.get("detail", {}).get("value") != forced["command"]
    ):
        errors.append("controlled command value drift")
    gate = next((row for row in events if row.get("stage") == "gate_observed"), None)
    expected_gate_ids = {str(row["id"]) for row in case.get("gates", [])}
    if (
        gate is None
        or gate.get("detail", {}).get("command") != forced["command"]
        or set(gate.get("detail", {}).get("gate_ids", [])) != expected_gate_ids
    ):
        errors.append("cited OpenClaw gate identity or command drift")
    sink = next((row for row in events if row.get("stage") == "sink_reached"), None)
    intercepted = next(
        (row for row in events if row.get("stage") == "pre_effect_interception"), None
    )
    if role == "exploit":
        gate_admitted = gate is not None and gate.get("detail", {}).get("admitted") is True
        if stages == list(CONTROL_STAGES):
            if gate_admitted:
                errors.append("cited gate admitted the exploit without a process sink witness")
        else:
            if not gate_admitted:
                errors.append("reviewed exploit was not admitted by the cited gate")
            if sink is None or not _sink_matches(candidate_id, sink):
                errors.append("reviewed exploit did not reach the declared process sink")
            if (
                intercepted is None
                or intercepted.get("detail", {}).get("executed") is not False
                or not _sink_matches(candidate_id, intercepted)
            ):
                errors.append("process effect was not intercepted before execution")
    else:
        if sink is not None and _sink_matches(candidate_id, sink):
            errors.append("safe control command matched the reviewed exploit sink witness")
        if intercepted is not None and intercepted.get("detail", {}).get("executed") is not False:
            errors.append("safe control process effect was executed")
    triggered = (
        role == "exploit"
        and not errors
        and stages == list(NORMALIZED_STAGES)
        and sink is not None
        and _sink_matches(candidate_id, sink)
    )
    return PairOutcome(not errors, triggered, errors)


def _run_role_attempt(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    request: OpenClawL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    _remove_path(directory)
    directory.mkdir(parents=True)
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    launch_log = directory / "launch.log"
    atomic_write_text(transcript_path, "")
    atomic_write_text(event_path, "")
    fixture = OpenClawFixtureServer(
        role, _forced_arguments(case, role, directory / "workspace"), transcript_path
    )
    fixture.start()
    base_url = f"http://127.0.0.1:{fixture.port}/v1"
    fixture_files, home, state, workspace, project_link = _prepare_role(
        directory, build_project, base_url
    )
    canary = directory / "host-effect-canary.txt"
    atomic_write_text(canary, CANARY_CONTENT)
    node = shutil.which("node")
    if node is None:
        raise ValidationError("Node.js runtime is not installed")
    exit_code = 124
    output = ""
    try:
        environment = {
            "PATH": f"{directory / 'bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "HOME": str(home),
            "TMPDIR": str(directory / "tmp"),
            "OPENCLAW_STATE_DIR": str(state),
            "OPENCLAW_CONFIG_PATH": str(state / "openclaw.json"),
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "CLAWGAP_L2_EVENT_PATH": str(event_path),
            "CLAWGAP_L2_CANDIDATE_ID": str(case["candidate_binding"]["candidate_id"]),
            "CLAWGAP_L2_CASE_ID": str(case["case_id"]),
            "CLAWGAP_L2_ATTEMPT": str(attempt),
            "CLAWGAP_L2_ROLE": role,
            "CLAWGAP_L2_CORRELATION_ID": f"{case['case_id']}:{attempt}:{role}",
            "CLAWGAP_L2_FIXTURE_ID": f"openclaw-l2:{case['case_id']}:{role}",
            "CLAWGAP_L2_GATE_IDS": ",".join(
                str(row["id"]) for row in case.get("gates", [])
            ),
        }
        (directory / "tmp").mkdir(parents=True, exist_ok=True)
        process = subprocess.Popen(
            [
                node,
                "dist/entry.js",
                "agent",
                "--local",
                "--agent",
                "main",
                "--message",
                "environment probe",
                "--json",
                "--timeout",
                "30",
            ],
            cwd=project_link,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            output, _stderr = process.communicate(timeout=request.timeout)
            exit_code = process.returncode
        except subprocess.TimeoutExpired as exc:
            value = exc.stdout or ""
            if not isinstance(value, str):
                value = value.decode("utf-8", errors="replace")
            output = value
            exit_code = 124
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        atomic_write_text(launch_log, redact_text(output))
    finally:
        fixture.stop()

    raw_events = _read_jsonl(event_path)
    provider_rows = _read_jsonl(transcript_path)
    try:
        events = _normalize_events(
            raw_events,
            provider_rows,
            case,
            attempt,
            role,
            fixture_files,
        )
        _write_jsonl(directory / "events.jsonl", events)
        outcome = _evaluate_pair(case, role, events, fixture, exit_code, output)
    except Exception as exc:
        _cleanup_role(directory, home, state, workspace, project_link)
        outcome = PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"])
        events = []
    if canary.read_text(encoding="utf-8") != CANARY_CONTENT:
        outcome.errors.append("host-effect canary changed")
        outcome.healthy = False
        outcome.triggered = False
    events_text = (directory / "events.jsonl").read_text(encoding="utf-8") if events else ""
    if contains_credentials(events_text):
        outcome.errors.append("credential scan failed")
        outcome.healthy = False
        outcome.triggered = False
    _cleanup_role(directory, home, state, workspace, project_link)
    return outcome, events


def _run_role(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    request: OpenClawL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    outcome, events = _run_role_attempt(
        case, role, attempt, directory, build_project, request
    )
    retryable = not (directory / "events.jsonl").is_file() or any(
        "provider client did not issue a valid request" in error
        for error in outcome.errors
    )
    if not retryable:
        return outcome, events
    return _run_role_attempt(
        case, role, attempt, directory, build_project, request
    )


def _candidate_disposition(outcomes: list[PairOutcome]) -> tuple[str, str]:
    if any(not outcome.healthy for outcome in outcomes):
        return "inconclusive", "one or more paired attempts had infrastructure or trace failures"
    if all(outcome.triggered for outcome in outcomes):
        return "runtime-confirmed", "all paired forced-provider E2E attempts satisfied the oracle"
    if not any(outcome.triggered for outcome in outcomes):
        return "not-reproduced", "all paired forced-provider E2E attempts completed without the exploit sequence"
    return "inconclusive", "paired exploit outcomes were inconsistent"


def _artifact_credential_scan(root: Path) -> str:
    run_roots = [root / "runs", *(path / "runs" for path in (root / "candidates").glob("*"))]
    evidence_paths = [
        path
        for run_root in run_roots
        for path in run_root.rglob("*")
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    ]
    evidence_paths.extend(
        path
        for path in root.iterdir()
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    )
    build_log = root / "build" / "build.log"
    if build_log.is_file():
        evidence_paths.append(build_log)
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in evidence_paths
    )
    return "failed" if contains_credentials(text) else "passed"


def _reproduction_command(request: OpenClawL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-openclaw-l2"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.campaign != DEFAULT_SOURCE_CAMPAIGN:
        command += f" --campaign {request.campaign}"
    if request.candidate_id is not None:
        command += f" --candidate-id {request.candidate_id}"
    return command


def _run_candidate_subprocess(
    request: OpenClawL2RunRequest,
    candidate_id: str,
    build_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target_dir = request.out_dir.resolve() / "candidates" / candidate_id
    argv = [
        sys.executable,
        "-m",
        "src.runtime_validation",
        "run-dynamic-trigger-openclaw-l2",
        "--candidate-id",
        candidate_id,
        "--out-dir",
        str(target_dir),
        "--attempts",
        str(request.attempts),
        "--timeout",
        str(request.timeout),
        "--build-timeout",
        str(request.build_timeout),
        "--build-dir",
        str(build_dir),
    ]
    completed = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        atomic_write_text(
            request.out_dir / f"subprocess-{candidate_id}.log",
            redact_text(completed.stdout or ""),
        )
        raise ValidationError(
            f"OpenClaw candidate subprocess failed with exit {completed.returncode}: "
            f"{candidate_id}"
        )
    result_rows = _read_jsonl(target_dir / "candidate-results.jsonl")
    case_rows = _read_jsonl(target_dir / "cases.jsonl")
    if len(result_rows) != 1 or len(case_rows) != 1:
        raise ValidationError(
            f"OpenClaw candidate subprocess identity partition drift: {candidate_id}"
        )
    return case_rows[0], result_rows[0]


def run_openclaw_l2(request: OpenClawL2RunRequest) -> dict[str, Any]:
    started = time.time()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError("OpenClaw targeted L2 timeouts and attempts must be positive")
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    cases = _select_cases(request.campaign.resolve(), candidate_id=request.candidate_id)
    source_bindings = _source_bindings(cases)
    actual_build_dir = request.build_dir.resolve() if request.build_dir else request.out_dir.resolve() / "build"
    build_manifest = _prepare_build(
        actual_build_dir, source_bindings, request.build_timeout
    )
    build_project = actual_build_dir / "project"
    if request.build_dir is not None:
        published_build_dir = request.out_dir.resolve() / "build"
        _remove_path(published_build_dir)
        published_build_dir.mkdir(parents=True)
        shutil.copyfile(
            actual_build_dir / "transformed-source-manifest.json",
            published_build_dir / "transformed-source-manifest.json",
        )
        if (actual_build_dir / "build.log").is_file():
            shutil.copyfile(
                actual_build_dir / "build.log", published_build_dir / "build.log"
            )
    results: list[dict[str, Any]] = []
    if request.candidate_id is None:
        _remove_path(request.out_dir.resolve() / "runs")
        _remove_path(request.out_dir.resolve() / "candidates")
        cases = [
            _run_candidate_subprocess(request, candidate_id, actual_build_dir)
            for candidate_id in TARGET_CANDIDATES
        ]
        results = [result for _case, result in cases]
        cases = [case for case, _result in cases]
    else:
        for case in cases:
            candidate_id = str(case["candidate_binding"]["candidate_id"])
            pair_outcomes: list[PairOutcome] = []
            for attempt in range(1, request.attempts + 1):
                role_outcomes: dict[str, PairOutcome] = {}
                for role in ("exploit", "control"):
                    directory = (
                        request.out_dir.resolve()
                        / "runs"
                        / str(case["case_id"])
                        / f"attempt-{attempt:03d}"
                        / role
                    )
                    try:
                        outcome, _events = _run_role(
                            case,
                            role,
                            attempt,
                            directory,
                            build_project,
                            request,
                        )
                    except Exception as exc:
                        outcome = PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"])
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
                    "project": "openclaw",
                    "disposition": disposition,
                    "evidence_tier": L2_EVIDENCE_TIER,
                    "attempts": request.attempts,
                    "reason": reason,
                    "attempt_errors": [
                        outcome.errors for outcome in pair_outcomes if outcome.errors
                    ],
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
                "project": "openclaw",
                "status": row["disposition"],
                "evidence_tier": row["evidence_tier"],
            }
            for row in results
        ],
    )
    counts: dict[str, int] = {}
    for row in results:
        counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1
    credential_scan = _artifact_credential_scan(request.out_dir)
    disposable_roots = [request.out_dir / "runs", *(
        path / "runs" for path in (request.out_dir / "candidates").glob("*")
    )]
    disposable_workspaces_removed = not any(
        path.is_dir()
        for run_root in disposable_roots
        for path in run_root.rglob("*")
        if path.name in {"home", "state", "workspace", "temporary"}
    )
    if credential_scan != "passed" or not disposable_workspaces_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
        counts = {"inconclusive": len(results)}
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-openclaw-l2-manifest/v1",
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
        "dependency_lockfile": sha256_file(SOURCE_ROOT / "pnpm-lock.yaml"),
        "harness_bindings": {
            "src/runtime_validation/openclaw_l2.py": sha256_file(
                REPO_ROOT / "src/runtime_validation/openclaw_l2.py"
            )
        },
        "transformed_source_manifest": digest(build_manifest),
        "credential_scan": credential_scan,
        "disposable_workspaces_removed": disposable_workspaces_removed,
        "generation_command": _reproduction_command(request),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    atomic_write_json(request.out_dir / "manifest.json", manifest)
    atomic_write_text(
        request.out_dir / "summary.md",
        (
            "# OpenClaw Targeted Dynamic-Trigger L2\n\n"
            f"> Complete reproduction command: `{manifest['generation_command']}`\n\n"
            f"Candidates accounted for: **{len(results)}/{len(cases)}**.\n\n"
            f"Paired attempts per candidate: **{request.attempts}**.\n\n"
            f"Runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**; "
            f"not-reproduced: **{counts.get('not-reproduced', 0)}**; "
            f"inconclusive: **{counts.get('inconclusive', 0)}**.\n\n"
            "This is targeted OpenClaw L2 evidence. It does not by itself publish "
            "canonical all-candidate L2 evidence or change the 46-report truth gate.\n"
        ),
    )
    return manifest
