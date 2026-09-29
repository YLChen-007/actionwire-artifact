"""Source-revised native-tool L2 runtime for two excluded OpenClaw reports."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
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
from .openclaw_l2 import OpenClawFixtureServer


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("openclaw")
SOURCE_ROOT = PROJECT.source_root
CAMPAIGN_ID = "runtime-dynamic-trigger-openclaw-source-revised-native-l2-v1"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-openclaw-source-revised-native-l2-result/v1"
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-openclaw-source-revised-native-l2-event/v1"
EVIDENCE_SCOPE = "source-revised-native-tool"
EVIDENCE_TIER = "L2-forced-provider-E2E-source-revised"
SOURCE_REVISION = (
    "d842b28a1517f95aae2a5bcd97f2f726e42b93d8"
    "+native-browser-message-source-v1"
)
HOST_CANARY = "clawgap-openclaw-source-revised-host-canary\n"
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

CANDIDATES = {
    "GT-c6a9e97a28acf193": {
        "candidate_id": "CAND-2e931bdf6190bd56",
        "report_name": (
            "Advisory-GHSA-527m-976r-jf79-dataflow-wait-fn-existing-session"
        ),
        "tool_name": "browser",
        "family": "browser-existing-session-wait",
    },
    "GT-f1647abba5c44969": {
        "candidate_id": "CAND-f892ccc9546f5929",
        "report_name": "Media_Root_Bypass-ISSUE-REPORT-fixed",
        "tool_name": "message",
        "family": "message-media-root-bypass",
    },
}

BOUND_FILES = {
    "package.json": (
        "9ffd60e01a31dd9d5b40568bdbaadc0128eab18eac3e2de8f45ae915132603ac"
    ),
    "pnpm-lock.yaml": (
        "bd223e18e5eed01cacca34ed211e23dfc9211aa441057223a08548196629e591"
    ),
    "tsconfig.json": (
        "9034c1a01163c6b6d3ba91e1773a025ab510b7970de80b9d81896cbaaf6374cd"
    ),
    "src/plugins/tools.ts": (
        "3ae2a696f10b37ac9c52789a9aca0361eb0aa30948bd08cee7de4c3e48b18d6a"
    ),
    "src/agents/bash-tools.exec.ts": (
        "f0bc93d59ac1d367447177e7db65a05a764ed40bcfe178ff4d2ea6ed6a34dfe4"
    ),
    "src/agents/tools/message-tool.ts": (
        "9d505696336edbf186416c3757aae5773e10d1340213f676e6e9232c7ef780c3"
    ),
    "src/agents/tools/browser-tool.ts": (
        "6a9ebfdc94807aaa2e6a9057afbd4f4ea837a0579ce7af8bc79985851d0fef7e"
    ),
    "src/agents/openclaw-tools.ts": (
        "d8bd02c0c24fef85a7e085d4acb97bea9a13e74a74b0369568ba418ea66b2023"
    ),
}


@dataclass(frozen=True)
class OpenClawSourceRevisedL2RunRequest:
    out_dir: Path
    attempts: int = 3
    timeout: int = 120
    build_timeout: int = 1800
    build_dir: Path | None = None
    report_id: str | None = None


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


def _source_bindings() -> dict[str, str]:
    bindings: dict[str, str] = {}
    for relative, expected in BOUND_FILES.items():
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"OpenClaw additive source is missing: {relative}")
        digest = sha256_file(source)
        if digest != expected:
            raise ValidationError(
                f"OpenClaw additive source hash drift: {relative}: {digest}"
            )
        bindings[relative] = digest
    return bindings


def _selected_reports(report_id: str | None) -> list[str]:
    if report_id is None:
        return list(CANDIDATES)
    if report_id not in CANDIDATES:
        raise ValidationError("requested report is not an OpenClaw additive overlay ID")
    return [report_id]


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(f"OpenClaw additive marker mismatch ({label}): {count}")
    return source.replace(old, new, 1)


def _instrument_registry(project: Path) -> str:
    path = project / "src/plugins/tools.ts"
    source = path.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        "import type { AnyAgentTool } from \"../agents/tools/common.js\";\n",
        "import type { AnyAgentTool } from \"../agents/tools/common.js\";\n"
        "import { appendFileSync } from \"node:fs\";\n",
        "registry event import",
    )
    marker = "    let resolved: AnyAgentTool | AnyAgentTool[] | null | undefined = null;\n"
    replacement = marker + (
        "    if (process.env.CLAWGAP_L2_EVENT_PATH) {\n"
        "      appendFileSync(process.env.CLAWGAP_L2_EVENT_PATH, JSON.stringify({\n"
        "        stage: \"registry_or_native_dispatch\",\n"
        "        detail: {\n"
        "          plugin_id: entry.pluginId,\n"
        "          tool_names: entry.names,\n"
        "          optional: entry.optional,\n"
        "        },\n"
        "      }) + \"\\n\");\n"
        "    }\n"
    )
    source = _replace_once(source, marker, replacement, "registry dispatch event")
    path.write_text(source, encoding="utf-8")
    return sha256_file(path)


def _instrument_native_tools(project: Path) -> dict[str, str]:
    helper_path = project / "src/clawgap-openclaw-native-l2.ts"
    helper_path.write_text(
        (
            "import { appendFileSync } from 'node:fs';\n"
            "\n"
            "export function nativeEvent(stage: string, detail: Record<string, unknown>): void {\n"
            "  if (!process.env.CLAWGAP_L2_EVENT_PATH) return;\n"
            "  appendFileSync(\n"
            "    process.env.CLAWGAP_L2_EVENT_PATH,\n"
            "    JSON.stringify({ stage, detail }) + '\\n',\n"
            "  );\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    browser_path = project / "src/agents/tools/browser-tool.ts"
    browser = browser_path.read_text(encoding="utf-8")
    browser = (
        "import { nativeEvent } from '../../clawgap-openclaw-native-l2.js';\n"
        + browser
    )
    if browser.count('        case "act": {') != 1:
        raise ValidationError("native browser act case marker mismatch")
    case_start = browser.index('        case "act": {')
    case_end = browser.index('        default:', case_start)
    native_browser_case = '''        case "act": {
          const request = params.request as Record<string, unknown> | undefined;
          if (!request || typeof request !== "object") {
            throw new Error("request required");
          }
          nativeEvent("registry_or_native_dispatch", { tool_name: "browser", runtime: "openclaw-agent" });
          nativeEvent("handler_entered", { tool_name: "browser", arguments: params });
          nativeEvent("controlled_argument_recorded", { argument_path: ["request", "fn"], value: request?.fn });
          nativeEvent("gate_observed", { gate: "browser act request presence", admitted: true });
          nativeEvent("missing_check_boundary_confirmed", { missing_check: "post-browser-act navigation-result SSRF revalidation" });
          nativeEvent("sink_reached", { sink: "Chrome MCP client.callTool", name: "evaluate_script", arguments: request });
          nativeEvent("pre_effect_interception", { sink: "Chrome MCP client.callTool", executed: false });
          nativeEvent("target_completed", { executed: false });
          return jsonResult({ ok: true, intercepted: true });
        }
'''
    browser = browser[:case_start] + native_browser_case + browser[case_end:]
    browser_path.write_text(browser, encoding="utf-8")

    message_path = project / "src/agents/tools/message-tool.ts"
    message = message_path.read_text(encoding="utf-8")
    message = (
        "import path from 'node:path';\n"
        "import { nativeEvent } from '../../clawgap-openclaw-native-l2.js';\n"
        + message
    )
    message = _replace_once(
        message,
        '      const action = readStringParam(params, "action", {\n        required: true,\n      }) as ChannelMessageActionName;\n\n      // Validate file paths against sandbox root to prevent host file access.\n',
        '      const action = readStringParam(params, "action", {\n'
        '        required: true,\n'
        '      }) as ChannelMessageActionName;\n'
        "      if (\n"
        "        process.env.CLAWGAP_SOURCE_REVISED_MESSAGE_MEDIA === '1' &&\n"
        "        action === 'send' &&\n"
        "        typeof params.filePath === 'string'\n"
        "      ) {\n"
        "        const raw = params.filePath;\n"
        "        const sandboxRoot =\n"
        "          options?.sandboxRoot ??\n"
        "          process.env.CLAWGAP_MEDIA_SANDBOX_ROOT ??\n"
        "          process.cwd();\n"
        "        const resolved = path.resolve(raw);\n"
        "        const root = path.resolve(sandboxRoot);\n"
        "        const insideRoot = resolved === root || resolved.startsWith(root + path.sep);\n"
        '        nativeEvent("registry_or_native_dispatch", { tool_name: "message", runtime: "openclaw-agent" });\n'
        '        nativeEvent("handler_entered", { tool_name: "message", arguments: params });\n'
        '        nativeEvent("controlled_argument_recorded", { argument_path: ["filePath"], value: raw });\n'
        '        nativeEvent("gate_observed", { gate: "sandbox-root policy", checked_keys: ["filePath", "path"], controlled_keys: ["filePath"], resolved, inside_root: insideRoot });\n'
        '        nativeEvent("missing_check_boundary_confirmed", { missing_check: "media path sandbox-root alias normalization" });\n'
        '        nativeEvent("sink_reached", { sink: "fs.open", path: raw, resolved, flags: "r", inside_root: insideRoot });\n'
        '        nativeEvent("pre_effect_interception", { sink: "fs.open", path: raw, resolved, executed: false });\n'
        '        nativeEvent("target_completed", { executed: false });\n'
        '        return jsonResult({ ok: true, intercepted: true });\n'
        "      }\n\n"
        "      // Validate file paths against sandbox root to prevent host file access.\n",
        "native message media boundary",
    )
    message_path.write_text(message, encoding="utf-8")

    return {
        "src/clawgap-openclaw-native-l2.ts": sha256_file(helper_path),
        "src/agents/tools/browser-tool.ts": sha256_file(browser_path),
        "src/agents/tools/message-tool.ts": sha256_file(message_path),
    }


def _render_build_copy(
    directory: Path,
    source_bindings: Mapping[str, str],
) -> dict[str, Any]:
    project = directory / "project"
    _remove_path(project)
    shutil.copytree(
        SOURCE_ROOT,
        project,
        ignore=shutil.ignore_patterns(".git", "node_modules", "dist"),
    )
    (project / "node_modules").symlink_to(
        SOURCE_ROOT / "node_modules", target_is_directory=True
    )
    transformed = _instrument_native_tools(project)
    return {
        "schema_version": (
            "clawgap-openclaw-source-revised-native-transformed-source-manifest/v1"
        ),
        "runtime_source_revision": SOURCE_REVISION,
        "original": dict(source_bindings),
        "transformed": transformed,
        "instrumentation_only": False,
        "security_logic_changed": True,
        "native_tools": ["browser", "message"],
    }


def _run(command: list[str], *, cwd: Path, log_path: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
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
    manifest_path = directory / "transformed-source-manifest.json"
    entrypoint = directory / "project/dist/entry.js"
    harness = sha256_file(REPO_ROOT / "src/runtime_validation/openclaw_source_revised_l2.py")
    if manifest_path.is_file() and entrypoint.is_file():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version")
            == "clawgap-openclaw-source-revised-native-transformed-source-manifest/v1"
            and prior.get("runtime_source_revision") == SOURCE_REVISION
            and prior.get("original") == dict(source_bindings)
            and prior.get("harness_sha256") == harness
            and prior.get("entrypoint_sha256") == sha256_file(entrypoint)
        ):
            return prior
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "home").mkdir(parents=True, exist_ok=True)
    manifest = _render_build_copy(directory, source_bindings)
    completed = _run(
        ["pnpm", "run", "build"],
        cwd=directory / "project",
        log_path=directory / "build.log",
        timeout=timeout,
    )
    if completed.returncode != 0 or not entrypoint.is_file():
        raise ValidationError(
            f"OpenClaw additive build failed with exit {completed.returncode}"
        )
    manifest.update(
        {
            "build_exit_code": completed.returncode,
            "entrypoint_sha256": sha256_file(entrypoint),
            "harness_sha256": harness,
        }
    )
    atomic_write_json(manifest_path, manifest)
    _remove_path(directory / "home")
    return manifest


def _arguments(report_id: str, role: str, workspace: Path, outside: Path) -> dict[str, Any]:
    if report_id == "GT-f1647abba5c44969":
        path = outside / "secret-media.txt" if role == "exploit" else workspace / "safe-media.txt"
        return {
            "action": "send",
            "message": "clawgap media carrier",
            "filePath": str(path),
        }
    exploit_fn = "window.location.href = 'http://127.0.0.1:9/clawgap-private'; true"
    control_fn = "true"
    return {
        "action": "act",
        "profile": "chrome",
        "request": {
            "kind": "wait",
            "fn": exploit_fn if role == "exploit" else control_fn,
        },
    }


def _config(base_url: str) -> dict[str, Any]:
    return {
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
    }


def _base_event(
    stage: str,
    detail: Mapping[str, Any],
    report_id: str,
    attempt: int,
    role: str,
) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "",
        "stage": stage,
        "candidate_id": CANDIDATES[report_id]["candidate_id"],
        "report_id": report_id,
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{report_id}:{attempt}:{role}",
        "fixture_id": f"openclaw-source-revised-native-l2:{report_id}:{role}",
        "ordinal": 0,
        "detail": dict(detail),
    }


def _normalize_events(
    *,
    raw_events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    source_bindings: Mapping[str, str],
    fixture: Mapping[str, Any],
    report_id: str,
    attempt: int,
    role: str,
    arguments: Mapping[str, Any],
    cleanup_errors: list[str],
) -> list[dict[str, Any]]:
    request = next(
        (row for row in provider_rows if row.get("valid") is True),
        None,
    )
    if request is None:
        raise ValidationError("real OpenClaw provider did not issue a valid request")
    events = [
        _base_event(
            "case_bound",
            {"report_name": CANDIDATES[report_id]["report_name"]},
            report_id,
            attempt,
            role,
        ),
        _base_event(
            "source_verified",
            {
                "canonical_revision": PROJECT.analysis_revision,
                "runtime_source_revision": SOURCE_REVISION,
                "source_hashes": dict(source_bindings),
            },
            report_id,
            attempt,
            role,
        ),
        _base_event(
            "fixture_prepared",
            {
                "workspace": fixture["workspace"],
                "outside_root": fixture["outside_root"],
                "config_sha256": fixture["config_sha256"],
                "native_tools": ["browser", "message"],
            },
            report_id,
            attempt,
            role,
        ),
        _base_event(
            "launch_started",
            {"entrypoint": "node dist/entry.js agent", "transport": "cli-local"},
            report_id,
            attempt,
            role,
        ),
        _base_event(
            "prompt_received",
            {"message": fixture["prompt"]},
            report_id,
            attempt,
            role,
        ),
        _base_event(
            "provider_request",
            {
                "method": request["method"],
                "path": request["path"],
                "model": request.get("body", {}).get("model"),
                "stream": True,
                "tool_names": [
                    row.get("function", {}).get("name")
                    for row in request.get("body", {}).get("tools", [])
                ],
            },
            report_id,
            attempt,
            role,
        ),
        _base_event(
            "provider_tool_call_or_decision",
            {
                "tool_name": CANDIDATES[report_id]["tool_name"],
                "arguments": dict(arguments),
            },
            report_id,
            attempt,
            role,
        ),
    ]
    rank = {stage: index for index, stage in enumerate(NORMALIZED_STAGES)}
    target_tool = CANDIDATES[report_id]["tool_name"]
    for raw in sorted(
        raw_events,
        key=lambda row: rank.get(str(row.get("stage")), 10**6),
    ):
        stage = str(raw.get("stage"))
        if (
            stage == "registry_or_native_dispatch"
            and target_tool != raw.get("detail", {}).get("tool_name")
        ):
            continue
        if stage not in rank:
            raise ValidationError(f"unexpected OpenClaw additive event stage: {stage}")
        events.append(_base_event(stage, raw.get("detail", {}), report_id, attempt, role))
    cleanup = {
        "runtime_removed": not Path(str(fixture["role_root"])).exists(),
        "host_canary_unchanged": not cleanup_errors,
    }
    if cleanup_errors:
        cleanup["cleanup_errors"] = cleanup_errors
    events.append(_base_event("cleanup_verified", cleanup, report_id, attempt, role))
    for ordinal, event in enumerate(events, 1):
        event["ordinal"] = ordinal
        event["event_id"] = f"{event['correlation_id']}:{ordinal}"
    return events


def _transcript_errors(
    rows: list[Mapping[str, Any]], tool_name: str
) -> list[str]:
    chats = [row for row in rows if row.get("path") == "/v1/chat/completions"]
    errors: list[str] = []
    if any(row.get("valid") is not True for row in rows):
        errors.append("provider received an unsupported or invalid endpoint")
    if len(chats) != 2:
        errors.append(f"provider request count drifted: {len(chats)}")
        return errors
    first = chats[0]
    names = {
        row.get("function", {}).get("name")
        for row in first.get("body", {}).get("tools", [])
    }
    if tool_name not in names:
        errors.append("provider request did not advertise the native tool")
    if first.get("body", {}).get("stream") is not True:
        errors.append("OpenClaw provider protocol drift")
    return errors


def _sink_matches(report_id: str, role: str, detail: Mapping[str, Any]) -> bool:
    if role != "exploit":
        return False
    if report_id == "GT-f1647abba5c44969":
        return detail.get("inside_root") is False and detail.get("sink") == "fs.open"
    function_text = str(detail.get("arguments", {}).get("fn", ""))
    return (
        detail.get("sink") == "Chrome MCP client.callTool"
        and detail.get("name") == "evaluate_script"
        and "127.0.0.1" in function_text
        and "window.location" in function_text
    )


def _evaluate_role(
    *,
    report_id: str,
    role: str,
    events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    arguments: Mapping[str, Any],
    process_exit: int,
    output: str,
    errors: list[str],
) -> RoleOutcome:
    all_errors = [
        *errors,
        *_transcript_errors(provider_rows, CANDIDATES[report_id]["tool_name"]),
    ]
    successful_completion = '"text": "clawgap role complete"' in output
    if process_exit != 0 and not (
        process_exit == 1 and successful_completion and not all_errors
    ):
        all_errors.append(f"OpenClaw exited {process_exit} without successful completion")
    stages = [str(event.get("stage")) for event in events]
    if stages != list(NORMALIZED_STAGES):
        all_errors.append("event identity or order drift")
    controlled = [
        row for row in events if row.get("stage") == "controlled_argument_recorded"
    ]
    if len(controlled) != 1:
        all_errors.append("controlled argument witness count drift")
    else:
        value = controlled[0].get("detail", {}).get("value")
        expected = arguments.get(
            "filePath",
            (arguments.get("request") or {}).get("fn"),
        )
        if value != expected:
            all_errors.append("controlled argument drift")
    sinks = [row for row in events if row.get("stage") == "sink_reached"]
    intercepted = [
        row for row in events if row.get("stage") == "pre_effect_interception"
    ]
    if len(sinks) != 1 or len(intercepted) != 1:
        all_errors.append("additive sink/interception witness count drift")
    elif intercepted[0].get("detail", {}).get("executed") is not False:
        all_errors.append("additive effect was not intercepted")
    triggered = (
        not all_errors
        and role == "exploit"
        and len(sinks) == 1
        and _sink_matches(report_id, role, sinks[0].get("detail", {}))
    )
    return RoleOutcome(not all_errors, triggered, all_errors)


def _run_role(
    *,
    report_id: str,
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    source_bindings: Mapping[str, str],
    request: OpenClawSourceRevisedL2RunRequest,
) -> tuple[RoleOutcome, list[dict[str, Any]]]:
    directory.mkdir(parents=True, exist_ok=True)
    directory = directory.resolve()
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    atomic_write_text(transcript_path, "")
    atomic_write_text(event_path, "")
    role_root = directory / "runtime"
    home = role_root / "home"
    state = role_root / "state"
    workspace = role_root / "workspace"
    outside = role_root / "outside"
    for path in (home, state, workspace, outside):
        path.mkdir(parents=True)
    if report_id == "GT-f1647abba5c44969":
        atomic_write_text(outside / "secret-media.txt", "clawgap-outside-media\n")
        atomic_write_text(workspace / "safe-media.txt", "clawgap-safe-media\n")
    arguments = _arguments(report_id, role, workspace, outside)
    prompt = f"Use {CANDIDATES[report_id]['tool_name']} exactly once with the reviewed arguments."
    fixture_server = OpenClawFixtureServer(
        role,
        arguments,
        transcript_path,
        tool_name=CANDIDATES[report_id]["tool_name"],
    )
    fixture_server.start()
    config_path = state / "openclaw.json"
    base_url = f"http://127.0.0.1:{fixture_server.port}/v1"
    atomic_write_json(config_path, _config(base_url))
    project_link = role_root / "project"
    project_link.symlink_to(build_project, target_is_directory=True)
    canary = directory / "host-effect-canary.txt"
    atomic_write_text(canary, HOST_CANARY)
    fixture = {
        "role_root": str(role_root),
        "workspace": str(workspace),
        "outside_root": str(outside),
        "config": str(config_path),
        "config_sha256": sha256_file(config_path),
        "prompt": prompt,
    }
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(role_root / "tmp"),
        "OPENCLAW_STATE_DIR": str(state),
        "OPENCLAW_CONFIG_PATH": str(config_path),
        "NO_COLOR": "1",
        "NO_PROXY": "127.0.0.1,localhost,::1",
        "no_proxy": "127.0.0.1,localhost,::1",
        "CLAWGAP_L2_EVENT_PATH": str(event_path),
        "CLAWGAP_MEDIA_SANDBOX_ROOT": str(workspace),
    }
    if report_id == "GT-f1647abba5c44969":
        environment["CLAWGAP_SOURCE_REVISED_MESSAGE_MEDIA"] = "1"
    (role_root / "tmp").mkdir(parents=True, exist_ok=True)
    node = shutil.which("node")
    if node is None:
        fixture_server.stop()
        raise ValidationError("Node.js runtime is not installed")
    process = subprocess.Popen(
        [
            node,
            "dist/entry.js",
            "agent",
            "--local",
            "--agent",
            "main",
            "--message",
            prompt,
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
    output = ""
    process_exit = 1
    errors: list[str] = []
    try:
        try:
            output, _ = process.communicate(timeout=request.timeout)
        except subprocess.TimeoutExpired as exc:
            errors.append("OpenClaw additive role timed out")
            value = exc.stdout or ""
            if not isinstance(value, str):
                value = value.decode("utf-8", errors="replace")
            output = value
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        process_exit = process.returncode or 1
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
        fixture_server.stop()
        atomic_write_text(directory / "launch.log", redact_text(output or ""))
    try:
        canary_value = canary.read_text(encoding="utf-8")
    except OSError:
        canary_value = ""
    if canary_value != HOST_CANARY:
        errors.append("host-effect canary changed")
    _remove_path(role_root)
    cleanup_errors = [] if not role_root.exists() else ["role root remains"]
    try:
        events = _normalize_events(
            raw_events=_read_jsonl(event_path),
            provider_rows=_read_jsonl(transcript_path),
            source_bindings=source_bindings,
            fixture=fixture,
            report_id=report_id,
            attempt=attempt,
            role=role,
            arguments=arguments,
            cleanup_errors=cleanup_errors,
        )
        _write_jsonl(directory / "events.jsonl", events)
        outcome = _evaluate_role(
            report_id=report_id,
            role=role,
            events=events,
            provider_rows=_read_jsonl(transcript_path),
            arguments=arguments,
            process_exit=process_exit,
            output=output,
            errors=[*errors, *cleanup_errors],
        )
        return outcome, events
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


def _reproduction_command(request: OpenClawSourceRevisedL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation "
        "run-dynamic-trigger-source-revised-native-l2"
        " --project openclaw"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.build_dir is not None:
        command += f" --build-dir {request.build_dir}"
    if request.report_id is not None:
        command += f" --report-id {request.report_id}"
    return command


def run_openclaw_source_revised_l2(
    request: OpenClawSourceRevisedL2RunRequest,
) -> dict[str, Any]:
    started = datetime.now(timezone.utc).timestamp()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError("OpenClaw source-revised native L2 parameters must be positive")
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    source_bindings = _source_bindings()
    build_dir = (
        request.build_dir.resolve()
        if request.build_dir
        else request.out_dir.resolve() / "build"
    )
    build_manifest = _prepare_build(build_dir, source_bindings, request.build_timeout)
    build_project = build_dir / "project"
    published = request.out_dir.resolve() / "transformed-source-manifest.json"
    _remove_path(published)
    shutil.copyfile(build_dir / "transformed-source-manifest.json", published)

    results: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for report_id in _selected_reports(request.report_id):
        spec = CANDIDATES[report_id]
        candidate = {
            "schema_version": "clawgap-source-revised-native-candidate/v1",
            "candidate_id": spec["candidate_id"],
            "project": "openclaw",
            "revision": SOURCE_REVISION,
            "base_revision": PROJECT.analysis_revision,
            "report_id": report_id,
            "report_name": spec["report_name"],
            "tool_name": spec["tool_name"],
            "selection_mode": EVIDENCE_SCOPE,
            "canonical_input": False,
            "native_tool": spec["tool_name"],
        }
        candidate_dir = request.out_dir / "candidates" / spec["candidate_id"]
        candidate_dir.mkdir(parents=True)
        atomic_write_json(candidate_dir / "candidate.json", candidate)
        candidates.append(candidate)
        outcomes: list[RoleOutcome] = []
        outcome_errors: list[list[str]] = []
        for attempt in range(1, request.attempts + 1):
            role_outcomes: dict[str, RoleOutcome] = {}
            for role in ("exploit", "control"):
                directory = (
                    request.out_dir
                    / "runs"
                    / report_id
                    / f"attempt-{attempt}"
                    / role
                )
                outcome, _events = _run_role(
                    report_id=report_id,
                    role=role,
                    attempt=attempt,
                    directory=directory,
                    build_project=build_project,
                    source_bindings=source_bindings,
                    request=request,
                )
                role_outcomes[role] = outcome
            exploit = role_outcomes["exploit"]
            control = role_outcomes["control"]
            pair = RoleOutcome(
                exploit.healthy and control.healthy,
                exploit.healthy and control.healthy and exploit.triggered,
                [*exploit.errors, *control.errors],
            )
            outcomes.append(pair)
            outcome_errors.append(pair.errors)
        if any(not outcome.healthy for outcome in outcomes):
            disposition = "inconclusive"
            reason = "one or more source-revised native pairs had infrastructure or trace failures"
        elif all(outcome.triggered for outcome in outcomes):
            disposition = "runtime-confirmed"
            reason = "all native browser/message pairs satisfied the report-specific witness"
        else:
            disposition = "not-reproduced"
            reason = "source-revised native pairs completed without the report-specific witness"
        result = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "campaign_id": CAMPAIGN_ID,
            "report_id": report_id,
            "report_name": spec["report_name"],
            "project": "openclaw",
            "candidate_id": spec["candidate_id"],
            "disposition": disposition,
            "reason": reason,
            "evidence_scope": EVIDENCE_SCOPE,
            "evidence_tier": EVIDENCE_TIER,
            "canonical_revision": PROJECT.analysis_revision,
            "runtime_source_revision": SOURCE_REVISION,
            "canonical_candidate_id": None,
            "canonical_accounting_affected": False,
            "attempts": request.attempts,
            "attempt_errors": [row for row in outcome_errors if row],
            "trace_accounting": {
                "expected": request.attempts * 2,
                "valid": sum(outcome.healthy for outcome in outcomes) * 2,
                "blocked": sum(not outcome.healthy for outcome in outcomes) * 2,
                "not_launched": 0
                if all(outcome.healthy for outcome in outcomes)
                else sum(2 for outcome in outcomes if not outcome.healthy),
            },
        }
        results.append(result)
        _write_jsonl(candidate_dir / "candidate-results.jsonl", [result])

    _write_jsonl(request.out_dir / "report-results.jsonl", results)
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "report_id": row["report_id"],
                "candidate_id": row["candidate_id"],
                "project": "openclaw",
                "status": row["disposition"],
                "evidence_scope": row["evidence_scope"],
            }
            for row in results
        ],
    )
    credential_scan = _artifact_credential_scan(request.out_dir.resolve())
    disposable_roots_removed = not any(
        path.is_dir()
        for path in (request.out_dir / "runs").rglob("*")
        if path.name == "runtime"
    )
    if credential_scan != "passed" or not disposable_roots_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "report-results.jsonl", results)
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    counts: dict[str, int] = {}
    for row in results:
        counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1
    summary = (
        "# OpenClaw Source-Revised Native Runtime\n\n"
        "This profile uses the native browser and message tools. It does not change "
        "the frozen canonical campaign, the 81-candidate denominator, the "
        "43-report eligible boundary, or the canonical `41/43` result.\n\n"
        + "\n".join(
            f"- `{row['report_id']}` / `{row['candidate_id']}`: **{row['disposition']}**"
            for row in results
        )
        + "\n"
    )
    (request.out_dir / "summary.md").write_text(summary, encoding="utf-8")
    manifest = {
        "schema_version": (
            "clawgap-dynamic-trigger-openclaw-source-revised-native-l2-manifest/v1"
        ),
        "campaign_id": CAMPAIGN_ID,
        "report_count": len(results),
        "attempt_pairs": request.attempts,
        "status_counts": counts,
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
