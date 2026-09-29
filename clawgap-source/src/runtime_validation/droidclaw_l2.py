"""Targeted forced-provider L2 runtime for the canonical DroidClaw candidate."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project

from .campaign_contracts import canonical_json
from .contracts import ValidationError, atomic_write_json, atomic_write_text, contains_credentials, redact_text, sha256_file


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("droidclaw")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
CAMPAIGN_ID = "runtime-dynamic-trigger-droidclaw-l2-v1"
TARGET_CANDIDATES = ("CAND-02629879756e5c81",)
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-droidclaw-l2-event/v1"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-droidclaw-l2-result/v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
EXPLOIT_STAGES = (
    "case_bound",
    "source_verified",
    "fixture_prepared",
    "launch_started",
    "prompt_received",
    "provider_request",
    "provider_decision",
    "action_dispatch",
    "handler_entered",
    "controlled_argument_recorded",
    "gate_observed",
    "sink_reached",
    "pre_effect_interception",
    "target_completed",
    "cleanup_verified",
)
CONTROL_STAGES = tuple(stage for stage in EXPLOIT_STAGES if stage not in {"sink_reached", "pre_effect_interception"})
CONTROL_FORBIDDEN_STAGES = {"sink_reached", "pre_effect_interception"}
CANARY_CONTENT = "clawgap-droidclaw-cleanup-canary\n"


@dataclass(frozen=True)
class DroidClawL2RunRequest:
    campaign: Path
    out_dir: Path
    attempts: int = 3
    timeout: int = 45


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


def _select_cases(campaign: Path) -> list[dict[str, Any]]:
    cases = _read_jsonl(campaign / "cases.jsonl")
    selected = {
        row.get("candidate_binding", {}).get("candidate_id"): row
        for row in cases
        if row.get("project") == "droidclaw"
    }
    if tuple(sorted(selected)) != tuple(sorted(TARGET_CANDIDATES)):
        raise ValidationError(
            "DroidClaw targeted L2 requires exactly the canonical shell candidate"
        )
    return [selected[candidate_id] for candidate_id in TARGET_CANDIDATES]


def _source_bindings() -> dict[str, str]:
    relatives = [
        *(f"src/{path.name}" for path in sorted((SOURCE_ROOT / "src").glob("*.ts"))),
        "package.json",
        "tsconfig.json",
        "node_modules/@aws-sdk/client-bedrock-runtime/package.json",
        "node_modules/@openrouter/ai-sdk-provider/package.json",
        "node_modules/ai/package.json",
        "node_modules/fast-xml-parser/package.json",
        "node_modules/openai/package.json",
        "node_modules/zod/package.json",
    ]
    result: dict[str, str] = {}
    for relative in relatives:
        path = SOURCE_ROOT / relative
        if not path.is_file():
            raise ValidationError(f"DroidClaw L2 required file is missing: {relative}")
        result[relative] = sha256_file(path)
    return result


def _verify_case_source(case: Mapping[str, Any], bindings: Mapping[str, str]) -> None:
    if case.get("revision") != PROJECT.analysis_revision:
        raise ValidationError("DroidClaw L2 case revision drift")
    if case.get("source_binding", {}).get("source_root") != str(SOURCE_ROOT):
        raise ValidationError("DroidClaw L2 source root drift")
    for row in case["source_binding"]["files"]:
        relative = row["path"]
        if bindings.get(relative) != row["sha256"]:
            raise ValidationError(f"DroidClaw L2 source drift: {relative}")


def _forced_action(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    for call in case["forced_tool_calls"]:
        if call["role"] != role:
            continue
        arguments = call.get("arguments", {})
        action = arguments.get("action")
        if not isinstance(action, Mapping):
            raise ValidationError(f"case lacks nested DroidClaw action for {role}")
        result = dict(action)
        result.setdefault("reason", "ClawGap reviewed forced-provider decision")
        return result
    raise ValidationError(f"case lacks forced {role} action")


def _terminal_args(value: str) -> list[str]:
    return ["shell", *str(value).split(" ")]


class DroidClawFixtureServer:
    """Loopback OpenAI-compatible fixture serving one reviewed JSON decision."""

    def __init__(self, role: str, action: Mapping[str, Any], transcript_path: Path):
        self.role = role
        self.action = dict(action)
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

            def _record(self, body: str, valid: bool) -> None:
                row = canonical_json(
                    {
                        "schema_version": "clawgap-droidclaw-provider-transcript/v1",
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

            def _error(self, message: str, status: int) -> None:
                payload = json.dumps(
                    {"error": {"message": message, "type": "clawgap_invalid_request"}}
                ).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _sse(self) -> None:
                content = canonical_json(server.action)
                chunks = [
                    {
                        "id": f"chatcmpl-clawgap-{server.role}",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "clawgap-loopback",
                        "choices": [
                            {"index": 0, "finish_reason": None, "delta": {"role": "assistant"}}
                        ],
                    },
                    {
                        "id": f"chatcmpl-clawgap-{server.role}",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "clawgap-loopback",
                        "choices": [
                            {"index": 0, "finish_reason": None, "delta": {"content": content}}
                        ],
                    },
                    {
                        "id": f"chatcmpl-clawgap-{server.role}",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "clawgap-loopback",
                        "choices": [
                            {"index": 0, "finish_reason": "stop", "delta": {}}
                        ],
                    },
                ]
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

            def _route(self) -> None:
                path = self.path.split("?", 1)[0]
                size = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(size).decode("utf-8", errors="replace") if size else ""
                if self.command != "POST" or path != "/v1/chat/completions":
                    server.unsupported.append(f"{self.command} {path}")
                    self._record(raw, False)
                    self._error("clawgap DroidClaw fixture endpoint is not implemented", 404)
                    return
                with server._lock:
                    server.request_count += 1
                    if server.request_count != 1:
                        self._record(raw, False)
                        self._error("more than one provider request for reviewed role", 409)
                        return
                try:
                    body = json.loads(raw)
                    valid = (
                        isinstance(body, dict)
                        and isinstance(body.get("messages"), list)
                        and bool(body.get("messages"))
                        and body.get("stream") is True
                        and body.get("response_format") == {"type": "json_object"}
                    )
                except json.JSONDecodeError:
                    valid = False
                server.valid_request = valid
                self._record(raw, valid)
                if not valid:
                    self._error("request does not match the DroidClaw streaming JSON contract", 400)
                    return
                self._sse()

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
        raise ValidationError(f"DroidClaw instrumentation marker mismatch ({label}): {count}")
    return source.replace(old, new, 1)


def _instrumented_helper() -> str:
    return (
        "import { appendFileSync as __clawgapAppendFileSync } from \"node:fs\";\n"
        "export function __clawgapL2Event(stage: string, detail: Record<string, unknown>): void {\n"
        "  const path = process.env.CLAWGAP_L2_EVENT_PATH;\n"
        "  if (!path) return;\n"
        "  __clawgapAppendFileSync(path, JSON.stringify({\n"
        "    schema_version: \"clawgap-dynamic-trigger-droidclaw-l2-event/v1\",\n"
        "    stage,\n"
        "    candidate_id: process.env.CLAWGAP_L2_CANDIDATE_ID,\n"
        "    case_id: process.env.CLAWGAP_L2_CASE_ID,\n"
        "    attempt: Number(process.env.CLAWGAP_L2_ATTEMPT ?? \"0\"),\n"
        "    role: process.env.CLAWGAP_L2_ROLE,\n"
        "    correlation_id: process.env.CLAWGAP_L2_CORRELATION_ID,\n"
        "    fixture_id: process.env.CLAWGAP_L2_FIXTURE_ID,\n"
        "    detail,\n"
        "  }) + \"\\n\");\n"
        "}\n"
        "export function __clawgapInterceptAdb(args: string[]): string {\n"
        "  __clawgapL2Event(\"pre_effect_interception\", {\n"
        "    primitive: \"DroidClaw.runAdbCommand\",\n"
        "    command: \"adb\",\n"
        "    args,\n"
        "    executed: false,\n"
        "    approval_gate_present: false,\n"
        "    controlled_response: \"clawgap intercepted DroidClaw shell effect\\n\",\n"
        "  });\n"
        "  const log = process.env.CLAWGAP_L2_ADB_LOG;\n"
        "  if (log) {\n"
        "    __clawgapAppendFileSync(log, JSON.stringify({\n"
        "      schema_version: \"clawgap-droidclaw-adb-event/v1\",\n"
        "      command: \"adb\",\n"
        "      args,\n"
        "      intercepted: true,\n"
        "    }) + \"\\n\");\n"
        "  }\n"
        "  return \"clawgap intercepted DroidClaw shell effect\\n\";\n"
        "}\n"
    )


def _render_source_copy(destination: Path, canary: Path) -> tuple[dict[str, Any], dict[str, str]]:
    project = destination / "project"
    project.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE_ROOT / "src", project / "src")
    shutil.copyfile(SOURCE_ROOT / "package.json", project / "package.json")
    shutil.copyfile(SOURCE_ROOT / "tsconfig.json", project / "tsconfig.json")
    (project / "node_modules").symlink_to(SOURCE_ROOT / "node_modules", target_is_directory=True)
    atomic_write_text(project / "src" / "clawgap-l2.ts", _instrumented_helper())

    kernel_marker = (
        "reader.read().then(({ value }) => {\n"
        "      resolve(new TextDecoder().decode(value).trim());\n"
        "      reader.releaseLock();\n"
        "    });"
    )
    kernel_replacement = (
        "reader.read().then(({ value }) => {\n"
        "      const goal = new TextDecoder().decode(value).trim();\n"
        "      __clawgapL2Event(\"prompt_received\", { goal });\n"
        "      resolve(goal);\n"
        "      reader.releaseLock();\n"
        "    });"
    )
    dispatch_marker = "result = executeAction(decision);"
    dispatch_replacement = (
        "__clawgapL2Event(\"action_dispatch\", { decision });\n"
        "        result = executeAction(decision);"
    )
    kernel_original = (SOURCE_ROOT / "src/kernel.ts").read_text(encoding="utf-8")
    kernel_source = (
        "import { __clawgapL2Event } from \"./clawgap-l2.js\";\n" + kernel_original
    )
    kernel_source = _replace_once(
        kernel_source, kernel_marker, kernel_replacement, "stdin prompt boundary"
    )
    kernel_source = _replace_once(
        kernel_source, dispatch_marker, dispatch_replacement, "native action dispatch"
    )
    atomic_write_text(project / "src/kernel.ts", kernel_source)

    shell_prefix_marker = (
        "function executeShell(action: ActionDecision): ActionResult {\n"
        "  const cmd = action.command ?? \"\";\n"
        "  if (!cmd) return { success: false, message: \"No command provided\" };"
    )
    shell_prefix_replacement = (
        "function executeShell(action: ActionDecision): ActionResult {\n"
        "  __clawgapL2Event(\"handler_entered\", { tool_name: \"shell\", action });\n"
        "  const cmd = action.command ?? \"\";\n"
        "  __clawgapL2Event(\"controlled_argument_recorded\", {\n"
        "    argument_path: [\"action\", \"command\"],\n"
        "    value: cmd,\n"
        "  });\n"
        "  if (cmd) {\n"
        "    __clawgapL2Event(\"gate_observed\", {\n"
        "      gate: \"non-empty-command-only\",\n"
        "      value: cmd,\n"
        "      admitted: true,\n"
        "      approval_gate_present: false,\n"
        "    });\n"
        "  } else {\n"
        "    __clawgapL2Event(\"gate_observed\", {\n"
        "      gate: \"non-empty-command-only\",\n"
        "      value: cmd,\n"
        "      admitted: false,\n"
        "      approval_gate_present: false,\n"
        "    });\n"
        "    return { success: false, message: \"No command provided\" };\n"
        "  }"
    )
    sink_marker = "const result = runAdbCommand([\"shell\", ...cmd.split(\" \")]);"
    sink_replacement = (
        "__clawgapL2Event(\"sink_reached\", {\n"
        "    sink: \"DroidClaw.executeShell.runAdbCommand\",\n"
        "    args: [\"shell\", ...cmd.split(\" \")],\n"
        "    approval_gate_present: false,\n"
        "  });\n"
        "  const result = __clawgapInterceptAdb([\"shell\", ...cmd.split(\" \")]);"
    )
    actions_original = (SOURCE_ROOT / "src/actions.ts").read_text(encoding="utf-8")
    actions_source = (
        "import { __clawgapInterceptAdb, __clawgapL2Event } from \"./clawgap-l2.js\";\n"
        + actions_original
    )
    actions_source = _replace_once(
        actions_source, shell_prefix_marker, shell_prefix_replacement, "shell handler and gate"
    )
    actions_source = _replace_once(
        actions_source, sink_marker, sink_replacement, "ADB shell sink"
    )
    atomic_write_text(project / "src/actions.ts", actions_source)

    manifest: dict[str, Any] = {
        "schema_version": "clawgap-droidclaw-transformed-source-manifest/v1",
        "mode": "disposable-source-copy",
        "source_root": str(SOURCE_ROOT),
        "rendered_root": str(project),
        "stages": [],
    }
    for path, original_path, markers in (
        (
            project / "src/kernel.ts",
            SOURCE_ROOT / "src/kernel.ts",
            ("stdin prompt boundary", "native action dispatch"),
        ),
        (
            project / "src/actions.ts",
            SOURCE_ROOT / "src/actions.ts",
            ("shell handler and gate", "ADB shell sink"),
        ),
    ):
        manifest["stages"].append(
            {
                "path": str(path.relative_to(project)),
                "markers": list(markers),
                "original_sha256": sha256_file(original_path),
                "transformed_sha256": sha256_file(path),
            }
        )
    fixtures = {str(canary): sha256_file(canary)}
    return manifest, fixtures


def _fake_screen_xml() -> str:
    return (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
        "<hierarchy rotation=\"0\">\n"
        "  <node index=\"0\" text=\"\" resource-id=\"\" class=\"android.widget.FrameLayout\" "
        "package=\"com.clawgap.fixture\" content-desc=\"\" checkable=\"false\" checked=\"false\" "
        "clickable=\"false\" enabled=\"true\" focusable=\"false\" focused=\"false\" "
        "scrollable=\"false\" long-clickable=\"false\" password=\"false\" selected=\"false\" "
        "bounds=\"[0,0][1080,2400]\">\n"
        "    <node index=\"0\" text=\"ClawGap fixture target\" resource-id=\"com.clawgap:id/target\" "
        "class=\"android.widget.Button\" package=\"com.clawgap.fixture\" content-desc=\"\" "
        "checkable=\"false\" checked=\"false\" clickable=\"true\" enabled=\"true\" "
        "focusable=\"true\" focused=\"false\" scrollable=\"false\" long-clickable=\"false\" "
        "password=\"false\" selected=\"false\" bounds=\"[240,1080][840,1260]\" />\n"
        "  </node>\n"
        "</hierarchy>\n"
    )


def _fake_adb_script() -> str:
    return (
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  'shell wm size') printf '%s\\n' 'Physical size: 1080x2400' ;;\n"
        "  'shell dumpsys activity activities')\n"
        "    printf '%s\\n' 'mResumedActivity=ActivityRecord{clawgap com.clawgap.fixture/.MainActivity}' ;;\n"
        "  'shell uiautomator dump /sdcard/window_dump.xml') printf '%s\\n' 'UI hierarchy dumped to: /sdcard/window_dump.xml' ;;\n"
        "  'pull /sdcard/window_dump.xml'*)\n"
        "    last=''\n"
        "    for last in \"$@\"; do :; done\n"
        "    cp \"${CLAWGAP_FAKE_SCREEN_XML:?}\" \"$last\"\n"
        "    printf '%s\\n' \"$last: 1 file pulled\" ;;\n"
        "  *) printf '%s\\n' 'clawgap fake adb response' ;;\n"
        "esac\n"
    )


def _prepare_fixture(directory: Path) -> tuple[dict[str, Any], dict[str, str], Path, Path]:
    home = directory / "home"
    data = directory / "data"
    workspace = directory / "workspace"
    temporary = directory / "temporary"
    for path in (home, data, workspace, temporary):
        path.mkdir(parents=True, exist_ok=True)
    canary = directory / "host-effect-canary.txt"
    atomic_write_text(canary, CANARY_CONTENT)
    screen_xml = directory / "screen-dump.xml"
    atomic_write_text(screen_xml, _fake_screen_xml())
    bin_root = temporary / "bin"
    bin_root.mkdir(parents=True, exist_ok=True)
    adb = bin_root / "adb"
    atomic_write_text(adb, _fake_adb_script())
    adb.chmod(0o700)
    source_manifest, fixture_files = _render_source_copy(workspace, canary)
    fixture_files.update(
        {
            str(screen_xml): sha256_file(screen_xml),
            str(adb): sha256_file(adb),
        }
    )
    return source_manifest, fixture_files, screen_xml, adb


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
        "fixture_id": f"droidclaw-l2:{case['case_id']}:{role}",
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
        base("launch_started", {"entrypoint": "bun src/kernel.ts"}),
    ]
    node_stages = [row.get("stage") for row in raw_events]
    if "prompt_received" not in node_stages:
        raise RuntimeError("real DroidClaw entrypoint did not receive prompt")
    prompt_index = node_stages.index("prompt_received")
    events.extend(dict(row) for row in raw_events[: prompt_index + 1])
    provider_posts = [
        row
        for row in provider_rows
        if row.get("method") == "POST" and row.get("path") == "/v1/chat/completions"
    ]
    if not provider_posts:
        raise RuntimeError("real DroidClaw OpenAI-compatible client did not issue a request")
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
    events.append(base("provider_decision", {"decision": _forced_action(case, role)}))
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


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    fixture: DroidClawFixtureServer,
    process_exit: int,
    output: str,
) -> PairOutcome:
    errors: list[str] = []
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
    if fixture.request_count != 1 or not fixture.valid_request:
        errors.append("provider fixture did not observe exactly one valid request")
    if process_exit != 0:
        errors.append(f"target process exited with {process_exit}")
    if "Enter your goal" not in output:
        errors.append("real entrypoint did not reach its stdin readiness boundary")
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
    required = EXPLOIT_STAGES if role == "exploit" else CONTROL_STAGES
    if stages != list(required):
        errors.append(f"event sequence mismatch: {stages}")

    action = _forced_action(case, role)
    dispatch = next((row for row in events if row.get("stage") == "action_dispatch"), None)
    if dispatch is None or dispatch.get("detail", {}).get("decision") != action:
        errors.append("forced provider decision drifted before native dispatch")
    controlled = next(
        (row for row in events if row.get("stage") == "controlled_argument_recorded"), None
    )
    expected_value = case["unsafe_relation"][f"{role}_value"]
    if controlled is None or controlled.get("detail", {}).get("value") != expected_value:
        errors.append("controlled command value drift")
    gate = next((row for row in events if row.get("stage") == "gate_observed"), None)
    expected_admission = role == "exploit"
    if (
        gate is None
        or gate.get("detail", {}).get("admitted") is not expected_admission
        or gate.get("detail", {}).get("approval_gate_present") is not False
    ):
        errors.append("cited non-empty command gate did not produce the reviewed outcome")

    if role == "control":
        if CONTROL_FORBIDDEN_STAGES.intersection(stages):
            errors.append("safe empty-command control reached ADB shell effect")
    else:
        expected_args = _terminal_args(expected_value)
        sink = next((row for row in events if row.get("stage") == "sink_reached"), None)
        intercepted = next(
            (row for row in events if row.get("stage") == "pre_effect_interception"), None
        )
        if sink is None or sink.get("detail", {}).get("args") != expected_args:
            errors.append("controlled command did not reach the declared ADB shell sink")
        if (
            intercepted is None
            or intercepted.get("detail", {}).get("args") != expected_args
            or intercepted.get("detail", {}).get("executed") is not False
            or intercepted.get("detail", {}).get("approval_gate_present") is not False
        ):
            errors.append("ADB shell effect was not intercepted before execution")
    return PairOutcome(not errors, role == "exploit" and not errors, errors)


def _run_role(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    request: DroidClawL2RunRequest,
    source_bindings: Mapping[str, str],
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    directory.mkdir(parents=True, exist_ok=True)
    source_manifest, fixture_files, screen_xml, adb = _prepare_fixture(directory)
    home = directory / "home"
    data = directory / "data"
    workspace = directory / "workspace"
    project = workspace / "project"
    event_path = directory / "events.raw.jsonl"
    adb_log = directory / "adb-events.jsonl"
    transcript_path = directory / "provider-transcript.jsonl"
    launch_log = directory / "launch.log"
    atomic_write_text(event_path, "")
    atomic_write_text(adb_log, "")
    atomic_write_text(transcript_path, "")
    fixture = DroidClawFixtureServer(role, _forced_action(case, role), transcript_path)
    fixture.start()
    process: subprocess.Popen[bytes] | None = None
    output = ""
    exit_code = 124
    preload = (
        REPO_ROOT
        / "src/runtime_validation/l2_instrumentation/bun/droidclaw_l2_preload.ts"
    )
    try:
        environment = {
            "PATH": f"{adb.parent}{os.pathsep}{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "HOME": str(home),
            "TMPDIR": str(directory / "temporary"),
            "LOG_DIR": "logs",
            "MAX_STEPS": "1",
            "STEP_DELAY": "0",
            "MAX_RETRIES": "0",
            "VISION_MODE": "fallback",
            "STREAMING_ENABLED": "true",
            "LLM_PROVIDER": "ollama",
            "OLLAMA_BASE_URL": f"http://127.0.0.1:{fixture.port}/v1",
            "OLLAMA_MODEL": "clawgap-loopback",
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "CLAWGAP_FAKE_SCREEN_XML": str(screen_xml),
            "CLAWGAP_L2_EVENT_PATH": str(event_path),
            "CLAWGAP_L2_ADB_LOG": str(adb_log),
            "CLAWGAP_L2_CANDIDATE_ID": case["candidate_binding"]["candidate_id"],
            "CLAWGAP_L2_CASE_ID": case["case_id"],
            "CLAWGAP_L2_ATTEMPT": str(attempt),
            "CLAWGAP_L2_ROLE": role,
            "CLAWGAP_L2_CORRELATION_ID": f"{case['case_id']}:{attempt}:{role}",
            "CLAWGAP_L2_FIXTURE_ID": f"droidclaw-l2:{case['case_id']}:{role}",
            "CLAWGAP_L2_TERMINAL_COMMAND": str(case["unsafe_relation"]["exploit_value"]),
        }
        process = subprocess.Popen(
            ["bun", "--preload", str(preload), "src/kernel.ts"],
            cwd=project,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            raw_output, _ = process.communicate(
                input=(case["prompts"]["reproduction"] + "\n").encode("utf-8"),
                timeout=request.timeout,
            )
            exit_code = process.returncode
            output = raw_output.decode("utf-8", errors="replace")
            atomic_write_text(launch_log, redact_text(output))
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, subprocess.SIGTERM)
            try:
                raw_output, _ = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, subprocess.SIGKILL)
                raw_output, _ = process.communicate()
            output = raw_output.decode("utf-8", errors="replace")
            atomic_write_text(launch_log, redact_text(output))
            raise RuntimeError("DroidClaw L2 target timed out") from None
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, subprocess.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, subprocess.SIGKILL)
                process.wait()
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
    atomic_write_json(directory / "transformed-source-manifest.json", source_manifest)
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
    for disposable in (home, data, workspace, directory / "temporary"):
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


def _reproduction_command(request: DroidClawL2RunRequest) -> str:
    campaign = ""
    if request.campaign != DEFAULT_SOURCE_CAMPAIGN:
        campaign = f" --campaign {request.campaign}"
    return (
        "python -m src.runtime_validation run-dynamic-trigger-droidclaw-l2"
        f"{campaign} --out-dir {request.out_dir} --attempts 3"
    )


def _artifact_credential_scan(root: Path) -> str:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".json", ".jsonl", ".log", ".md"}:
            continue
        if contains_credentials(path.read_text(errors="replace")):
            return "failed"
    return "passed"


def run_droidclaw_l2(request: DroidClawL2RunRequest) -> dict[str, Any]:
    if request.attempts != 3:
        raise ValidationError("DroidClaw canonical L2 requires exactly three paired attempts")
    request = DroidClawL2RunRequest(
        request.campaign.resolve(),
        request.out_dir.resolve(),
        request.attempts,
        request.timeout,
    )
    cases = _select_cases(request.campaign)
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
                "project": "droidclaw",
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
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "candidate_id": row["candidate_id"],
                "case_id": row["case_id"],
                "project": "droidclaw",
                "status": row["disposition"],
                "evidence_tier": row["evidence_tier"],
            }
            for row in results
        ],
    )
    counts = {row["disposition"]: 0 for row in results}
    for row in results:
        counts[row["disposition"]] += 1
    credential_scan = _artifact_credential_scan(request.out_dir)
    disposable_workspaces_removed = not any(
        path.is_dir()
        for path in request.out_dir.rglob("*")
        if path.name in {"home", "data", "workspace", "temporary"}
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
                    "project": "droidclaw",
                    "status": "inconclusive",
                    "evidence_tier": row["evidence_tier"],
                }
                for row in results
            ],
        )
        counts = {"inconclusive": len(results)}
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-droidclaw-l2-manifest/v1",
        "campaign_id": CAMPAIGN_ID,
        "source_campaign": str(request.campaign),
        "candidate_count": len(results),
        "attempt_pairs": request.attempts,
        "status_counts": counts,
        "evidence_tier": L2_EVIDENCE_TIER,
        "targeted_only": True,
        "canonical_all_candidate_l2": False,
        "source_bindings": source_bindings,
        "dependency_lockfile": None,
        "dependency_identity": "installed package manifests are hashed; benchmark has no lockfile",
        "harness_bindings": {
            relative: sha256_file(REPO_ROOT / relative)
            for relative in (
                "src/runtime_validation/droidclaw_l2.py",
                "src/runtime_validation/l2_instrumentation/bun/droidclaw_l2_preload.ts",
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
            "# DroidClaw Targeted Dynamic-Trigger L2\n\n"
            f"> Complete reproduction command: `{manifest['generation_command']}`\n\n"
            f"Candidates accounted for: **{len(results)}/1**.\n\n"
            f"Paired attempts per candidate: **{request.attempts}**.\n\n"
            f"Runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**; "
            f"not-reproduced: **{counts.get('not-reproduced', 0)}**; "
            f"inconclusive: **{counts.get('inconclusive', 0)}**.\n\n"
            "This is targeted DroidClaw L2 evidence only. It does not publish canonical "
            "all-candidate L2 evidence or change the 46-report GT truth gate.\n"
        ),
    )
    return manifest
