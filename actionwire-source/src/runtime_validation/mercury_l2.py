"""Targeted forced-provider L2 runtime for the six Mercury-Agent candidates."""

from __future__ import annotations

import json
import os
import pty
import select
import shutil
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from copy import deepcopy

from src.projects import get_project

from .campaign_contracts import canonical_json
from .contracts import ValidationError, atomic_write_json, atomic_write_text, contains_credentials, redact_text, sha256_file


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("mercury-agent")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
CAMPAIGN_ID = "runtime-dynamic-trigger-mercury-agent-l2-v2"
TARGET_CANDIDATES = (
    "CAND-068922557c7eb14a",
    "CAND-5c1154e984e2dff7",
    "CAND-60dd4810687a0688",
    "CAND-8037dbf8863d80ca",
    "CAND-dd18e4dc2cd4d18b",
    "CAND-dd18f351a1792471",
)
PROCESS_SINK_CANDIDATES = {
    "CAND-068922557c7eb14a",
    "CAND-5c1154e984e2dff7",
}
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-mercury-agent-l2-event/v1"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-mercury-agent-l2-result/v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
CANARY_CONTENT = "clawgap-mercury-agent-cleanup-canary\n"
BUILD_ENTRYPOINT = "dist/index.js"
PAYLOAD_REPAIRS = {
    "CAND-068922557c7eb14a": {
        "original_payload": "cat ${HOME}/secret.txt",
        "repaired_payload": "cat $HOME/secret.txt",
        "reason": (
            "Unbraced environment expansion preserves the reported shell-expansion bypass "
            "while avoiding unrelated brace-segment/path-scope blocking."
        ),
    },
    "CAND-8037dbf8863d80ca": {
        "original_payload": "echo value > /tmp/exploit.txt",
        "repaired_payload": "echo value > ./exploit.txt",
        "reason": (
            "Relative in-CWD redirection preserves the safe-read redirection bypass while "
            "avoiding the unrelated outside-CWD path-scope gate."
        ),
    },
}
GT_REPORTS = (
    {
        "report_id": "GT-064e5e8cd701c4f3",
        "report_name": "Advisory-GHSA-7977-c43c-xpwj-wc-files0-from",
        "candidate_ids": ["CAND-dd18e4dc2cd4d18b", "CAND-dd18f351a1792471"],
    },
    {
        "report_id": "GT-0933461dcb1d7159",
        "report_name": "CVE-2026-28463-safe-read-home-expansion",
        "candidate_ids": ["CAND-068922557c7eb14a", "CAND-5c1154e984e2dff7"],
    },
    {
        "report_id": "GT-a53f7c03db055552",
        "report_name": "CVE-2026-28391-safe-read-redirection",
        "candidate_ids": ["CAND-8037dbf8863d80ca"],
    },
    {
        "report_id": "GT-da46e23775a545e1",
        "report_name": "Advisory-GHSA-jccr-rrw2-vc8h-echo-env",
        "candidate_ids": ["CAND-60dd4810687a0688"],
    },
    {
        "report_id": "GT-e53a164b159182ee",
        "report_name": "CVE-2026-32010-find-exec-safe-read",
        "candidate_ids": ["CAND-dd18f351a1792471"],
    },
)


@dataclass(frozen=True)
class MercuryL2RunRequest:
    campaign: Path
    out_dir: Path
    attempts: int = 3
    timeout: int = 45
    candidate_id: str | None = None


@dataclass
class PairOutcome:
    healthy: bool
    triggered: bool
    errors: list[str]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValidationError(f"non-object row in {path}")
        rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    atomic_write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _select_cases(campaign: Path, candidate_id: str | None = None) -> list[dict[str, Any]]:
    cases = _read_jsonl(campaign / "cases.jsonl")
    selected = {
        row.get("candidate_binding", {}).get("candidate_id"): row
        for row in cases
        if row.get("project") == "mercury-agent"
    }
    if candidate_id is not None:
        if candidate_id not in selected:
            raise ValidationError("requested Mercury-Agent candidate is absent")
        return [selected[candidate_id]]
    if tuple(sorted(selected)) != tuple(sorted(TARGET_CANDIDATES)):
        raise ValidationError(
            "Mercury-Agent targeted L2 requires exactly the six canonical run_command candidates"
        )
    return [selected[candidate_id] for candidate_id in TARGET_CANDIDATES]


def _apply_payload_repairs(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach reviewed deterministic payload repairs without editing canonical input."""

    result: list[dict[str, Any]] = []
    for canonical in cases:
        candidate_id = canonical["candidate_binding"]["candidate_id"]
        repair = PAYLOAD_REPAIRS.get(candidate_id)
        row = deepcopy(canonical)
        if repair is not None:
            _forced_arguments(canonical, "exploit")
            row["payload_repair"] = {
                "schema_version": "clawgap-mercury-payload-repair/v1",
                **deepcopy(repair),
            }
        result.append(row)
    return result


def _repair_ledger(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": "clawgap-mercury-payload-repair/v1",
            "candidate_id": row["candidate_binding"]["candidate_id"],
            "case_id": row["case_id"],
            **deepcopy(row["payload_repair"]),
        }
        for row in cases
        if "payload_repair" in row
    ]


def _source_bindings() -> dict[str, str]:
    relatives = [
        "src/index.ts",
        "src/core/agent.ts",
        "src/capabilities/registry.ts",
        "src/capabilities/permissions.ts",
        "src/capabilities/shell/run-command.ts",
        "src/channels/base.ts",
        "src/channels/cli.ts",
        "src/channels/registry.ts",
        "src/providers/base.ts",
        "src/providers/openai-compat.ts",
        "src/providers/registry.ts",
        "src/ui/App.tsx",
        "src/ui/types.ts",
        "src/utils/config.ts",
        "src/utils/logger.ts",
        "package.json",
        "package-lock.json",
        "dist/index.js",
        "dist/index.js.map",
        "node_modules/ai/package.json",
        "node_modules/@ai-sdk/openai/package.json",
        "node_modules/ink/package.json",
        "node_modules/react/package.json",
        "node_modules/pino/package.json",
        "node_modules/zod/package.json",
    ]
    result: dict[str, str] = {}
    for relative in relatives:
        path = SOURCE_ROOT / relative
        if not path.is_file():
            raise ValidationError(f"Mercury-Agent L2 required file is missing: {relative}")
        result[relative] = sha256_file(path)
    return result


def _verify_case_source(case: Mapping[str, Any], bindings: Mapping[str, str]) -> None:
    if case.get("revision") != PROJECT.analysis_revision:
        raise ValidationError("Mercury-Agent L2 case revision drift")
    if Path(case["source_binding"]["source_root"]) != SOURCE_ROOT:
        raise ValidationError("Mercury-Agent L2 source root drift")
    for row in case["source_binding"]["files"]:
        relative = row["path"]
        if bindings.get(relative) != row["sha256"]:
            raise ValidationError(f"Mercury-Agent L2 source drift: {relative}")


def _forced_arguments(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    for call in case["forced_tool_calls"]:
        if call["role"] == role:
            arguments = dict(call["arguments"])
            repair = PAYLOAD_REPAIRS.get(case["candidate_binding"]["candidate_id"])
            if role == "exploit" and repair is not None:
                if arguments.get("command") != repair["original_payload"]:
                    raise ValidationError(
                        "Mercury-Agent payload repair source command drift"
                    )
                arguments["command"] = repair["repaired_payload"]
            return arguments
    raise ValidationError(f"case lacks forced {role} tool call")


def _expected_value(case: Mapping[str, Any], role: str) -> Any:
    current: Any = _forced_arguments(case, role)
    for part in case["handler"]["argument_path"]:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


class MercuryFixtureServer:
    """Loopback OpenAI-compatible fixture: one reviewed tool call, then final text."""

    def __init__(self, role: str, arguments: Mapping[str, Any], transcript_path: Path):
        self.role = role
        self.arguments = dict(arguments)
        self.transcript_path = transcript_path
        self.request_count = 0
        self.first_request_valid = False
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

            def _record(self, body: str, valid: bool) -> None:
                row = canonical_json(
                    {
                        "schema_version": "clawgap-mercury-provider-transcript/v1",
                        "timestamp": _utc_now(),
                        "method": self.command,
                        "path": self.path,
                        "authorization": "Bearer [REDACTED_CREDENTIAL]",
                        "valid": valid,
                        "body": body,
                    }
                )
                with server._lock:
                    with server.transcript_path.open("a", encoding="utf-8") as handle:
                        handle.write(row + "\n")

            def _json_error(self, message: str, status: int) -> None:
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
                    "data: " + json.dumps(chunk, separators=(",", ":")) + "\n\n"
                    for chunk in chunks
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("cache-control", "no-cache")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _chunk(self, delta: dict[str, Any], finish_reason: str | None = None) -> dict[str, Any]:
                return {
                    "id": f"chatcmpl-clawgap-{server.role}",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": "clawgap-loopback",
                    "choices": [
                        {"index": 0, "finish_reason": finish_reason, "delta": delta}
                    ],
                }

            def _route(self) -> None:
                path = self.path.split("?", 1)[0]
                size = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(size).decode("utf-8", errors="replace") if size else ""
                if self.command != "POST" or path != "/v1/chat/completions":
                    server.unsupported.append(f"{self.command} {path}")
                    self._record(raw, False)
                    self._json_error("clawgap Mercury fixture endpoint is not implemented", 404)
                    return
                with server._lock:
                    server.request_count += 1
                    number = server.request_count
                    if number > 2:
                        self._record(raw, False)
                        self._json_error("more than two provider requests for reviewed role", 409)
                        return
                try:
                    request = json.loads(raw)
                except json.JSONDecodeError:
                    request = None
                tools = request.get("tools", []) if isinstance(request, dict) else []
                valid = (
                    isinstance(request, dict)
                    and isinstance(request.get("messages"), list)
                    and bool(request.get("messages"))
                    and request.get("stream") is True
                    and any(
                        tool.get("function", {}).get("name") == "run_command"
                        for tool in tools
                        if isinstance(tool, dict)
                    )
                )
                if number == 1:
                    server.first_request_valid = valid
                self._record(raw, valid)
                if not valid:
                    self._json_error(
                        "request does not match Mercury streaming run_command contract", 400
                    )
                    return
                if number == 1:
                    call_id = f"call_clawgap_{server.role}"
                    self._sse(
                        [
                            self._chunk({"role": "assistant"}),
                            self._chunk(
                                {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": call_id,
                                            "type": "function",
                                            "function": {
                                                "name": "run_command",
                                                "arguments": canonical_json(server.arguments),
                                            },
                                        }
                                    ]
                                }
                            ),
                            self._chunk({}, "tool_calls"),
                        ]
                    )
                    return
                self._sse(
                    [
                        self._chunk({"role": "assistant"}),
                        self._chunk({"content": "ClawGap reviewed Mercury turn completed."}),
                        self._chunk({}, "stop"),
                    ]
                )

            do_GET = _route
            do_POST = _route
            do_PATCH = _route
            do_PUT = _route
            do_DELETE = _route

        return Handler

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(f"Mercury instrumentation marker mismatch ({label}): {count}")
    return source.replace(old, new, 1)


def _instrumentation_helper() -> str:
    return r'''
import { appendFileSync as __clawgapAppendFileSync } from "node:fs";
import { EventEmitter as __ClawgapEventEmitter } from "node:events";
import { PassThrough as __ClawgapPassThrough } from "node:stream";
function __clawgapL2Event(stage, detail = {}) {
  const path = process.env.CLAWGAP_L2_EVENT_PATH;
  if (!path) return;
  __clawgapAppendFileSync(path, JSON.stringify({
    schema_version: "clawgap-dynamic-trigger-mercury-agent-l2-event/v1",
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
const __clawgapRealFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input?.url ?? String(input);
  let hostname = "";
  let protocol = "";
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    protocol = parsed.protocol;
  } catch {}
  if ((protocol === "http:" || protocol === "https:") && !["127.0.0.1", "localhost", "::1"].includes(hostname)) {
    throw new Error(`ClawGap Mercury-Agent L2 rejected a non-loopback fetch: ${url}`);
  }
  if (url.endsWith("/v1/chat/completions")) {
    __clawgapL2Event("provider_request", {
      url,
      method: init?.method ?? input?.method ?? "POST",
    });
  }
  return __clawgapRealFetch(input, init);
};
class __ClawgapInterceptedChild extends __ClawgapEventEmitter {
  stdout = new __ClawgapPassThrough();
  stderr = new __ClawgapPassThrough();
  stdin = new __ClawgapPassThrough();
  pid = 424242;
  killed = false;
  kill(signal) {
    this.killed = true;
    queueMicrotask(() => {
      this.emit("exit", 0, signal ?? null);
      this.emit("close", 0, signal ?? null);
    });
    return true;
  }
}
function __clawgapInterceptSpawn(command, args, options) {
  __clawgapL2Event("impact_sink_reached", {
    primitive: "child_process.spawn",
    command,
    args,
    cwd: options?.cwd,
    shell: options?.shell === true,
    executed: false,
  });
  __clawgapL2Event("pre_effect_interception", {
    primitive: "child_process.spawn",
    command,
    args,
    cwd: options?.cwd,
    shell: options?.shell === true,
    executed: false,
  });
  setTimeout(() => process.exit(0), 2000);
  const child = new __ClawgapInterceptedChild();
  queueMicrotask(() => {
    child.emit("spawn");
    child.stdout.end("clawgap intercepted Mercury-Agent shell effect\n");
    child.stderr.end();
    child.emit("exit", 0, null);
    child.emit("close", 0, null);
  });
  return child;
}
'''


def _render_build_copy(destination: Path, canary: Path) -> tuple[dict[str, Any], dict[str, str]]:
    project = destination / "project"
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE_ROOT / "dist", project / "dist")
    shutil.copyfile(SOURCE_ROOT / "package.json", project / "package.json")
    (project / "node_modules").symlink_to(
        SOURCE_ROOT / "node_modules", target_is_directory=True
    )
    original_path = SOURCE_ROOT / BUILD_ENTRYPOINT
    original = original_path.read_text(encoding="utf-8")
    if original.startswith("#!/usr/bin/env node\n"):
        rendered = "#!/usr/bin/env node\n" + _instrumentation_helper() + original.removeprefix(
            "#!/usr/bin/env node\n"
        )
    else:
        rendered = _instrumentation_helper() + original

    prompt_marker = 'sendUserMessage(content) {\n    const userMsg'
    prompt_replacement = (
        'sendUserMessage(content) {\n'
        '    __clawgapL2Event("prompt_received", { prompt: content, channel: "cli" });\n'
        '    const userMsg'
    )
    rendered = _replace_once(
        rendered, prompt_marker, prompt_replacement, "CLI prompt ingress"
    )

    tool_marker = (
        'execute: async ({ command, timeout }) => {\n'
        '      const check = await permissions.checkShellCommand(command);\n'
        '      if (!check.allowed) {\n'
        '        return `Error: ${check.reason}`;\n'
        '      }'
    )
    tool_replacement = (
        'execute: async ({ command, timeout }) => {\n'
        '      __clawgapL2Event("registry_dispatch", {\n'
        '        tool_name: "run_command",\n'
        '        arguments: { command, timeout },\n'
        '      });\n'
        '      __clawgapL2Event("handler_entered", {\n'
        '        tool_name: "run_command",\n'
        '        handler: "createRunCommandTool.execute",\n'
        '      });\n'
        '      __clawgapL2Event("controlled_argument_recorded", {\n'
        '        argument_path: ["command"],\n'
        '        value: command,\n'
        '      });\n'
        '      const check = await permissions.checkShellCommand(command);\n'
        '      __clawgapL2Event("gate_observed", {\n'
        '        gate: "PermissionManager.checkShellCommand",\n'
        '        value: command,\n'
        '        decision: check,\n'
        '      });\n'
        '      if (!check.allowed) {\n'
        '        setTimeout(() => process.exit(0), 2000);\n'
        '        return `Error: ${check.reason}`;\n'
        '      }'
    )
    rendered = _replace_once(
        rendered, tool_marker, tool_replacement, "run_command dispatch and gate"
    )

    safe_read_marker = (
        'const allSegmentsSafeRead = segments.length > 0 && segments.every(\n'
        '      (segment) => _PermissionManager.SAFE_READ_PATTERNS.some((p) => this.matchPattern(segment, p))\n'
        '    );'
    )
    safe_read_replacement = (
        safe_read_marker
        + '\n    __clawgapL2Event("safe_read_classified", {\n'
        + '      value: trimmed,\n'
        + '      segments,\n'
        + '      all_segments_safe_read: allSegmentsSafeRead,\n'
        + '    });'
    )
    rendered = _replace_once(
        rendered, safe_read_marker, safe_read_replacement, "safe-read classification"
    )

    consent_marker = (
        'if (this.askHandler && this.currentChannelType !== "internal") {\n'
        '      const result = await this.askHandler(`Run command: ${trimmed}`);'
    )
    consent_replacement = (
        'if (this.askHandler && this.currentChannelType !== "internal") {\n'
        '      __clawgapL2Event("consent_sink_reached", {\n'
        '        value: trimmed,\n'
        '        prompt: `Run command: ${trimmed}`,\n'
        '      });\n'
        '      const result = await this.askHandler(`Run command: ${trimmed}`);'
    )
    rendered = _replace_once(
        rendered, consent_marker, consent_replacement, "askHandler consent boundary"
    )

    sink_marker = (
        'const child = spawn2(command, [], {\n'
        '      cwd,\n'
        '      shell: true,'
    )
    sink_replacement = (
        'const child = __clawgapInterceptSpawn(command, [], {\n'
        '      cwd,\n'
        '      shell: true,'
    )
    rendered = _replace_once(
        rendered, sink_marker, sink_replacement, "terminal shell spawn"
    )
    atomic_write_text(project / BUILD_ENTRYPOINT, rendered)

    manifest: dict[str, Any] = {
        "schema_version": "clawgap-mercury-transformed-build-manifest/v1",
        "mode": "disposable-build-copy",
        "source_root": str(SOURCE_ROOT),
        "rendered_root": str(project),
        "entrypoint": BUILD_ENTRYPOINT,
        "markers": [
            "CLI prompt ingress",
            "run_command dispatch and gate",
            "safe-read classification",
            "askHandler consent boundary",
            "terminal shell spawn",
        ],
        "original_sha256": sha256_file(original_path),
        "transformed_sha256": sha256_file(project / BUILD_ENTRYPOINT),
    }
    return manifest, {str(canary): sha256_file(canary)}


def _mercury_config(base_url: str) -> str:
    return (
        "identity:\n"
        "  name: Mercury\n"
        "  owner: ClawGap\n"
        "  creator: ClawGap\n"
        "providers:\n"
        "  default: openaiCompat\n"
        "  openaiCompat:\n"
        "    name: openaiCompat\n"
        "    apiKey: clawgap-loopback-mock\n"
        f"    baseUrl: {base_url}\n"
        "    model: clawgap-loopback\n"
        "    enabled: true\n"
        "channels:\n"
        "  telegram:\n"
        "    enabled: false\n"
        "memory:\n"
        "  secondBrain:\n"
        "    enabled: false\n"
        "subagents:\n"
        "  enabled: false\n"
        "spotify:\n"
        "  enabled: false\n"
        "web:\n"
        "  enabled: false\n"
    )


def _permissions_config() -> str:
    return (
        "capabilities:\n"
        "  filesystem:\n"
        "    enabled: true\n"
        "    scopes:\n"
        "      - {path: ., read: true, write: true}\n"
        "  shell:\n"
        "    enabled: true\n"
        "    cwdOnly: true\n"
        "  git:\n"
        "    enabled: false\n"
    )


def _prepare_fixture(
    directory: Path, base_url: str
) -> tuple[dict[str, Any], dict[str, str], Path, Path, Path]:
    home = directory / "home"
    workspace = directory / "workspace"
    data = directory / "data"
    for path in (home, workspace, data):
        path.mkdir(parents=True, exist_ok=True)
    mercury_home = home / ".mercury"
    mercury_home.mkdir(parents=True, exist_ok=True)
    canary = directory / "host-effect-canary.txt"
    atomic_write_text(canary, CANARY_CONTENT)
    config_path = mercury_home / "mercury.yaml"
    permissions_path = mercury_home / "permissions.yaml"
    atomic_write_text(config_path, _mercury_config(base_url))
    atomic_write_text(permissions_path, _permissions_config())
    build_manifest, fixture_files = _render_build_copy(workspace, canary)
    fixture_files.update(
        {
            str(config_path): sha256_file(config_path),
            str(permissions_path): sha256_file(permissions_path),
        }
    )
    return build_manifest, fixture_files, home, workspace, mercury_home


def _base_event(
    stage: str,
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    detail: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "stage": stage,
        "candidate_id": case["candidate_binding"]["candidate_id"],
        "case_id": case["case_id"],
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{case['case_id']}:{attempt}:{role}",
        "fixture_id": f"mercury-agent-l2:{case['case_id']}:{role}",
        "detail": dict(detail),
    }


def _normalize_events(
    raw_events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    source_bindings: Mapping[str, str],
    fixture_files: Mapping[str, str],
) -> list[dict[str, Any]]:
    def base(stage: str, detail: Mapping[str, Any] = {}) -> dict[str, Any]:
        return _base_event(stage, case, attempt, role, detail)

    events = [
        base("case_bound", {"source_campaign": str(DEFAULT_SOURCE_CAMPAIGN)}),
        base("source_verified", {"sha256": dict(source_bindings)}),
        base("fixture_prepared", {"files": dict(fixture_files)}),
        base("launch_started", {"entrypoint": "node dist/index.js start --foreground"}),
    ]
    node_stages = [row.get("stage") for row in raw_events]
    if "prompt_received" not in node_stages:
        raise RuntimeError("real Mercury-Agent CLI channel did not receive prompt")
    prompt_index = node_stages.index("prompt_received")
    events.extend(dict(row) for row in raw_events[: prompt_index + 1])
    provider_posts = [
        row
        for row in provider_rows
        if row.get("method") == "POST" and row.get("path") == "/v1/chat/completions"
    ]
    if not provider_posts:
        raise RuntimeError("real Mercury-Agent AI SDK client did not issue provider request")
    first_post = provider_posts[0]
    events.append(
        base(
            "provider_request",
            {
                "method": first_post["method"],
                "path": first_post["path"],
                "body_length": len(first_post.get("body", "")),
                "stream": True,
                "protocol": "openai-chat-completions/v1",
            },
        )
    )
    events.append(
        base("provider_tool_call", {"tool_name": "run_command", "arguments": _forced_arguments(case, role)})
    )
    events.extend(
        dict(row)
        for row in raw_events[prompt_index + 1 :]
        if row.get("stage") != "provider_request"
    )
    events.append(base("target_completed", {}))
    events.append(base("cleanup_verified", {"canary_healthy": True}))
    for ordinal, event in enumerate(events, 1):
        event["ordinal"] = ordinal
    return events


def _event(events: list[Mapping[str, Any]], stage: str) -> Mapping[str, Any] | None:
    return next((row for row in events if row.get("stage") == stage), None)


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    fixture: MercuryFixtureServer,
    process_exit: int,
    output: str,
) -> PairOutcome:
    errors: list[str] = []
    candidate_id = case["candidate_binding"]["candidate_id"]
    identity_keys = (
        "candidate_id",
        "case_id",
        "attempt",
        "role",
        "correlation_id",
        "fixture_id",
    )
    first = events[0] if events else {}
    identity = {key: first.get(key) for key in identity_keys}
    if fixture.unsupported:
        errors.append(f"unsupported provider endpoints: {fixture.unsupported}")
    if fixture.request_count != 2 or not fixture.first_request_valid:
        errors.append(
            f"provider fixture observed an invalid exchange count={fixture.request_count}"
        )
    if process_exit != 0:
        errors.append(f"target process exited with {process_exit}")
    if "Press Enter to open chat" not in output:
        errors.append("real Mercury-Agent PTY did not reach its CLI readiness boundary")
    for event in events:
        row = {key: event.get(key) for key in identity_keys}
        if row != identity:
            errors.append("cross-attempt or cross-correlation event stitching")
            break
    ordinals = [row.get("ordinal") for row in events]
    if ordinals != list(range(1, len(events) + 1)):
        errors.append("event ordinals are duplicate or unordered")
    stages = [row.get("stage") for row in events]
    if len(stages) != len(set(stages)):
        errors.append("duplicate event stage")
    required_prefix = [
        "case_bound",
        "source_verified",
        "fixture_prepared",
        "launch_started",
        "prompt_received",
        "provider_request",
        "provider_tool_call",
        "registry_dispatch",
        "handler_entered",
        "controlled_argument_recorded",
    ]
    if stages[: len(required_prefix)] != required_prefix:
        errors.append(f"event sequence mismatch: {stages}")
    elif "gate_observed" not in stages[len(required_prefix) :]:
        errors.append(f"permission gate event is absent or unordered: {stages}")

    controlled = _event(events, "controlled_argument_recorded")
    expected_value = _expected_value(case, role)
    if controlled is None or controlled.get("detail", {}).get("value") != expected_value:
        errors.append("controlled command value drift")
    gate = _event(events, "gate_observed")
    if gate is None or gate.get("detail", {}).get("value") != expected_value:
        errors.append("permission gate did not observe the reviewed command")
    safe_read = _event(events, "safe_read_classified")

    allowed = bool(gate.get("detail", {}).get("decision", {}).get("allowed")) if gate else False
    all_safe = bool(safe_read.get("detail", {}).get("all_segments_safe_read")) if safe_read else False
    consent_reached = _event(events, "consent_sink_reached") is not None
    if all_safe and allowed and consent_reached:
        errors.append("safe-read path unexpectedly reached askHandler consent")
    if not all_safe and not consent_reached and allowed:
        errors.append("allowed non-safe-read command missed askHandler consent")

    impact = _event(events, "impact_sink_reached")
    intercepted = _event(events, "pre_effect_interception")
    reaches_effect = impact is not None and intercepted is not None
    if reaches_effect:
        if impact.get("detail", {}).get("command") != expected_value:
            errors.append("controlled command drifted before terminal spawn")
        if intercepted.get("detail", {}).get("executed") is not False:
            errors.append("terminal shell effect was not intercepted before execution")

    if role == "exploit":
        triggered = (
            not errors
            and reaches_effect
            and impact.get("detail", {}).get("command") == expected_value
            and (all_safe or candidate_id not in PROCESS_SINK_CANDIDATES)
        )
    else:
        triggered = False
        if candidate_id in PROCESS_SINK_CANDIDATES and reaches_effect:
            errors.append("paired process-sink control reached terminal shell effect")
    return PairOutcome(not errors, triggered, errors)


def _run_pty(
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    prompt: str,
    timeout: int,
) -> tuple[int, str]:
    master_fd, slave_fd = pty.openpty()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        start_new_session=True,
        close_fds=True,
    )
    os.close(slave_fd)
    output = bytearray()
    deadline = time.monotonic() + timeout
    readiness_deadline = time.monotonic() + min(timeout, 25)
    mode_prompt_seen_at: float | None = None
    mode_prompt_handled = False
    mode_prompt_handled_at = 0.0
    prompt_sent = False
    chat_enter_sent = False
    last_input_at = time.monotonic()
    chat_ready_at: float | None = None
    denied_permission_prompts = 0
    try:
        while True:
            if process.poll() is not None:
                remaining = 0.1
            else:
                remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select([master_fd], [], [], min(0.2, remaining))
            if readable:
                try:
                    chunk = os.read(master_fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
                text = output.decode("utf-8", errors="replace")
                chunk_text = chunk.decode("utf-8", errors="replace")
                if mode_prompt_handled and (
                    "Allow access?" in chunk_text or "Run command:" in chunk_text
                ):
                    os.write(master_fd, b"n")
                    denied_permission_prompts += 1
                    last_input_at = time.monotonic()
                    continue
                if mode_prompt_seen_at is None and "Choose how Mercury handles risky actions" in text:
                    mode_prompt_seen_at = time.monotonic()
                if chat_ready_at is None and "Enter send" in text:
                    chat_ready_at = time.monotonic()
                elif (
                    not chat_enter_sent
                    and not mode_prompt_handled
                    and "Press Enter to open chat" in text
                ):
                    os.write(master_fd, b"\r")
                    chat_enter_sent = True
                    last_input_at = time.monotonic()
            if (
                mode_prompt_seen_at is not None
                and not mode_prompt_handled
                and time.monotonic() - mode_prompt_seen_at >= 0.5
            ):
                # Ink resolves the startup mode prompt to ask-me on Escape. Waiting avoids
                # sending the key before the real raw-mode input handler is mounted.
                os.write(master_fd, b"\x1b")
                mode_prompt_handled = True
                mode_prompt_handled_at = time.monotonic()
                last_input_at = mode_prompt_handled_at
            if (
                (chat_enter_sent or mode_prompt_handled)
                and not prompt_sent
                and chat_ready_at is not None
                and time.monotonic() - max(last_input_at, chat_ready_at) >= 0.5
            ):
                os.write(master_fd, prompt.encode("utf-8"))
                time.sleep(0.1)
                os.write(master_fd, b"\r")
                prompt_sent = True
                last_input_at = time.monotonic()
            if (
                not prompt_sent
                and not mode_prompt_handled
                and time.monotonic() > readiness_deadline
            ):
                break
            if time.monotonic() > deadline:
                break
            if process.poll() is not None and not readable:
                break
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        try:
            while True:
                chunk = os.read(master_fd, 65536)
                if not chunk:
                    break
                output.extend(chunk)
        except OSError:
            pass
        os.close(master_fd)
    return process.returncode, output.decode("utf-8", errors="replace")


def _run_role(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    request: MercuryL2RunRequest,
    source_bindings: Mapping[str, str],
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True, exist_ok=True)
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    launch_log = directory / "pty.log"
    atomic_write_text(transcript_path, "")
    atomic_write_text(event_path, "")
    fixture = MercuryFixtureServer(
        role, _forced_arguments(case, role), transcript_path
    )
    fixture.start()
    base_url = f"http://127.0.0.1:{fixture.port}/v1"
    build_manifest, fixture_files, home, workspace, mercury_home = _prepare_fixture(
        directory, base_url
    )
    project = workspace / "project"
    exit_code = 124
    output = ""
    try:
        environment = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(home),
            "MERCURY_HOME": str(mercury_home),
            "TERM": "xterm-256color",
            "NO_COLOR": "1",
            "NODE_NO_WARNINGS": "1",
            "SECRET": "clawgap-redacted-secret-marker",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "CLAWGAP_L2_EVENT_PATH": str(event_path),
            "CLAWGAP_L2_CANDIDATE_ID": case["candidate_binding"]["candidate_id"],
            "CLAWGAP_L2_CASE_ID": case["case_id"],
            "CLAWGAP_L2_ATTEMPT": str(attempt),
            "CLAWGAP_L2_ROLE": role,
            "CLAWGAP_L2_CORRELATION_ID": f"{case['case_id']}:{attempt}:{role}",
            "CLAWGAP_L2_FIXTURE_ID": f"mercury-agent-l2:{case['case_id']}:{role}",
        }
        exit_code, output = _run_pty(
            ["node", BUILD_ENTRYPOINT, "start", "--foreground"],
            project,
            environment,
            case["prompts"]["reproduction"],
            request.timeout,
        )
        atomic_write_text(launch_log, redact_text(output))
    finally:
        fixture.stop()

    raw_events = _read_jsonl(event_path)
    provider_rows = _read_jsonl(transcript_path)
    events = _normalize_events(
        raw_events,
        provider_rows,
        case,
        attempt,
        role,
        source_bindings,
        fixture_files,
    )
    _write_jsonl(directory / "events.jsonl", events)
    atomic_write_json(directory / "transformed-build-manifest.json", build_manifest)
    outcome = _evaluate_pair(case, role, events, fixture, exit_code, output)
    canary = directory / "host-effect-canary.txt"
    if not canary.is_file() or canary.read_text(encoding="utf-8") != CANARY_CONTENT:
        outcome.errors.append("cleanup canary failed")
        outcome.healthy = False
        outcome.triggered = False
    if contains_credentials((directory / "events.jsonl").read_text(encoding="utf-8")):
        outcome.errors.append("credential scan failed")
        outcome.healthy = False
        outcome.triggered = False
    for disposable in (home, workspace, directory / "data"):
        shutil.rmtree(disposable, ignore_errors=True)
    return outcome, events


def _candidate_disposition(outcomes: list[PairOutcome]) -> tuple[str, str]:
    if any(not outcome.healthy for outcome in outcomes):
        return "inconclusive", "one or more paired attempts had infrastructure or trace failures"
    if all(outcome.triggered for outcome in outcomes):
        return "runtime-confirmed", "all paired forced-provider E2E attempts satisfied the oracle"
    if not any(outcome.triggered for outcome in outcomes):
        return "not-reproduced", "all paired forced-provider E2E attempts completed without the exploit sequence"
    return "inconclusive", "paired exploit outcomes were inconsistent"


def _gt_projection(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_candidate = {row["candidate_id"]: row for row in results}
    projection: list[dict[str, Any]] = []
    for report in GT_REPORTS:
        if not set(report["candidate_ids"]) & set(by_candidate):
            continue
        linked = [
            by_candidate[candidate_id]
            for candidate_id in report["candidate_ids"]
            if candidate_id in by_candidate
        ]
        dispositions = {row["disposition"] for row in linked}
        if "inconclusive" in dispositions:
            disposition = "inconclusive"
        elif "runtime-confirmed" in dispositions:
            disposition = "runtime-confirmed"
        else:
            disposition = "not-reproduced"
        projection.append(
            {
                "schema_version": "clawgap-mercury-targeted-gt-projection/v1",
                "project": "mercury-agent",
                "report_id": report["report_id"],
                "report_name": report["report_name"],
                "matched_candidate_ids": list(report["candidate_ids"]),
                "dispositions_by_candidate": {
                    row["candidate_id"]: row["disposition"] for row in linked
                },
                "disposition": disposition,
                "reason": "targeted report aggregation from repaired candidate outcomes",
            }
        )
    return projection


def _reproduction_command(request: MercuryL2RunRequest) -> str:
    campaign = ""
    if request.campaign != DEFAULT_SOURCE_CAMPAIGN:
        campaign = f" --campaign {request.campaign}"
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-mercury-agent-l2"
        f"{campaign} --out-dir {request.out_dir} --attempts 3"
    )
    if getattr(request, "candidate_id", None):
        command += f" --candidate-id {request.candidate_id}"
    return command


def _artifact_credential_scan(root: Path) -> str:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".json", ".jsonl", ".log", ".md"}:
            continue
        if contains_credentials(path.read_text(errors="replace")):
            return "failed"
    return "passed"


def run_mercury_l2(request: MercuryL2RunRequest) -> dict[str, Any]:
    if request.attempts != 3:
        raise ValidationError("Mercury-Agent canonical L2 requires exactly three paired attempts")
    request = MercuryL2RunRequest(
        request.campaign.resolve(),
        request.out_dir.resolve(),
        request.attempts,
        request.timeout,
        request.candidate_id,
    )
    cases = _apply_payload_repairs(
        _select_cases(request.campaign, candidate_id=request.candidate_id)
    )
    source_bindings = _source_bindings()
    for case in cases:
        _verify_case_source(case, source_bindings)
    request.out_dir.mkdir(parents=True, exist_ok=True)
    runs = request.out_dir / "runs"
    results: list[dict[str, Any]] = []
    started = time.time()
    for case in cases:
        candidate_id = case["candidate_binding"]["candidate_id"]
        pair_outcomes: list[PairOutcome] = []
        for attempt in range(1, request.attempts + 1):
            role_outcomes: dict[str, PairOutcome] = {}
            for role in ("exploit", "control"):
                directory = runs / case["case_id"] / f"attempt-{attempt:03d}" / role
                try:
                    outcome, _ = _run_role(
                        case,
                        role,
                        attempt,
                        directory,
                        request,
                        source_bindings,
                    )
                except Exception as exc:
                    outcome = PairOutcome(False, False, [str(exc)])
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
                "project": "mercury-agent",
                "disposition": disposition,
                "evidence_tier": L2_EVIDENCE_TIER,
                "attempts": request.attempts,
                "reason": reason,
                "attempt_errors": [
                    outcome.errors for outcome in pair_outcomes if outcome.errors
                ],
            }
        )
    _write_jsonl(request.out_dir / "cases.jsonl", cases)
    _write_jsonl(request.out_dir / "payload-repairs.jsonl", _repair_ledger(cases))
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "candidate_id": row["candidate_id"],
                "case_id": row["case_id"],
                "project": "mercury-agent",
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
    for residual in list(request.out_dir.rglob("*")):
        if residual.is_dir() and residual.name in {"home", "workspace", "data"}:
            shutil.rmtree(residual, ignore_errors=True)
    disposable_workspaces_removed = not any(
        path.is_dir()
        for path in request.out_dir.rglob("*")
        if path.name in {"home", "workspace", "data"}
    )
    if credential_scan != "passed" or not disposable_workspaces_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
        _write_jsonl(
            request.out_dir / "qualification.jsonl",
            [
                {
                    "candidate_id": row["candidate_id"],
                    "case_id": row["case_id"],
                    "project": "mercury-agent",
                    "status": "inconclusive",
                    "evidence_tier": row["evidence_tier"],
                }
                for row in results
            ],
        )
        counts = {"inconclusive": len(results)}
    gt_projection = _gt_projection(results)
    _write_jsonl(request.out_dir / "gt-projection.jsonl", gt_projection)
    gt_counts: dict[str, int] = {}
    for row in gt_projection:
        gt_counts[row["disposition"]] = gt_counts.get(row["disposition"], 0) + 1
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-mercury-agent-l2-manifest/v1",
        "campaign_id": CAMPAIGN_ID,
        "source_campaign": str(request.campaign),
        "candidate_count": len(results),
        "attempt_pairs": request.attempts,
        "status_counts": counts,
        "evidence_tier": L2_EVIDENCE_TIER,
        "targeted_only": True,
        "canonical_all_candidate_l2": False,
        "default_permission_mode": "ask-me/cwd-only",
        "payload_repair_count": len(_repair_ledger(cases)),
        "payload_repairs": _repair_ledger(cases),
        "ground_truth_report_count": len(gt_projection),
        "ground_truth_status_counts": gt_counts,
        "source_bindings": source_bindings,
        "harness_bindings": {
            "src/runtime_validation/mercury_l2.py": sha256_file(
                REPO_ROOT / "src/runtime_validation/mercury_l2.py"
            )
        },
        "source_drift": False,
        "credential_scan": credential_scan,
        "disposable_workspaces_removed": disposable_workspaces_removed,
        "generation_command": _reproduction_command(request),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    atomic_write_json(request.out_dir / "manifest.json", manifest)
    atomic_write_text(
        request.out_dir / "summary.md",
        (
            "# Mercury-Agent Targeted Dynamic-Trigger L2\n\n"
            f"> Complete reproduction command: `{manifest['generation_command']}`\n\n"
            f"Candidates accounted for: **{len(results)}/6**.\n\n"
            f"Paired attempts per candidate: **{request.attempts}**.\n\n"
            f"Runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**; "
            f"not-reproduced: **{counts.get('not-reproduced', 0)}**; "
            f"inconclusive: **{counts.get('inconclusive', 0)}**.\n\n"
            f"Targeted GT reports runtime-confirmed: **{gt_counts.get('runtime-confirmed', 0)}/5**.\n\n"
            "Two reviewed deterministic payload repairs are recorded in `payload-repairs.jsonl`; "
            "the canonical input campaign is unchanged.\n\n"
            "This campaign preserves Mercury-Agent's default ask-me/cwd-only permission mode. "
            "It is targeted L2 evidence only; it does not publish canonical all-candidate L2 "
            "evidence or change the 46-report GT truth gate.\n"
        ),
    )
    return manifest
