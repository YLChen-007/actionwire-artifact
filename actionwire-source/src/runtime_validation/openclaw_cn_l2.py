"""Targeted forced-provider L2 runtime for linked OpenClaw-CN candidates."""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import unquote
from urllib.request import urlopen

from src.projects import get_project

from .campaign_contracts import canonical_json, digest
from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    contains_credentials,
    redact_text,
    sha256_file,
)
from .openclaw_l2 import PairOutcome, _read_jsonl, _remove_path, _write_jsonl


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("openclaw-cn")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
TARGET_CANDIDATES = (
    "CAND-074808927f73b4ea",
    "CAND-229d4f6249170277",
    "CAND-71d8650705cc1fff",
    "CAND-aea54f2ae30ff6d8",
    "CAND-32a45d07e0ad9705",
    "CAND-5e591d48a7d860c9",
    "CAND-d5f97f93a48beedd",
    "CAND-f18a82fbd65a6fa9",
    "CAND-b795a91c6f4fb023",
)
CAMPAIGN_ID = "runtime-dynamic-trigger-openclaw-cn-l2-v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-openclaw-cn-l2-result/v1"
CANARY_CONTENT = "clawgap-openclaw-cn-host-canary\n"
IDENTITY_FIELDS = (
    "candidate_id",
    "case_id",
    "attempt",
    "role",
    "correlation_id",
    "fixture_id",
)
BASE_STAGES = (
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
)
TERMINAL_STAGES = ("target_completed", "cleanup_verified")
MISSING_CHECK_STAGE = "missing_check_boundary_confirmed"
GATE_STAGE = "gate_observed"
CLICK_CANDIDATES = {"CAND-074808927f73b4ea", "CAND-229d4f6249170277"}
OPEN_PAGE_CANDIDATES = {"CAND-71d8650705cc1fff"}
OPEN_CDP_CANDIDATES = {"CAND-aea54f2ae30ff6d8"}
EVALUATE_CANDIDATES = {"CAND-32a45d07e0ad9705"}
EXEC_CANDIDATES = {"CAND-5e591d48a7d860c9", "CAND-d5f97f93a48beedd"}
APPLY_PATCH_CANDIDATES = {"CAND-f18a82fbd65a6fa9"}
FEISHU_CANDIDATES = {"CAND-b795a91c6f4fb023"}
BROWSER_CANDIDATES = CLICK_CANDIDATES | OPEN_PAGE_CANDIDATES | OPEN_CDP_CANDIDATES | EVALUATE_CANDIDATES


@dataclass(frozen=True)
class OpenClawCNL2RunRequest:
    campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    out_dir: Path = ...
    attempts: int = 3
    timeout: int = 120
    build_timeout: int = 1800
    candidate_id: str | None = None
    build_dir: Path | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _select_cases(
    campaign: Path, candidate_id: str | None = None
) -> list[dict[str, Any]]:
    cases = _read_jsonl(campaign / "cases.jsonl")
    selected = {
        str(row.get("candidate_binding", {}).get("candidate_id")): row
        for row in cases
        if row.get("project") == "openclaw-cn"
    }
    expected = set(TARGET_CANDIDATES)
    if not expected.issubset(selected):
        missing = sorted(expected - set(selected))
        raise ValidationError(
            "OpenClaw-CN targeted L2 source campaign is missing GT-linked candidates: "
            + ", ".join(missing)
        )
    if candidate_id is not None:
        if candidate_id not in expected:
            raise ValidationError(
                "requested OpenClaw-CN candidate is not a GT-linked targeted L2 candidate"
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
        "src/agents/apply-patch.ts",
        "src/agents/sandbox-paths.ts",
        "src/agents/tools/browser-tool.ts",
        "src/agents/tools/message-tool.ts",
        "src/browser/cdp.helpers.ts",
        "src/browser/navigation-guard.ts",
        "src/browser/pw-session.ts",
        "src/browser/pw-tools-core.interactions.ts",
        "src/browser/server-context.ts",
        "src/cli/program/preaction.ts",
        "src/process/spawn-utils.ts",
        "extensions/feishu/src/media.ts",
    }
    for case in cases:
        if case.get("revision") != PROJECT.analysis_revision:
            raise ValidationError("OpenClaw-CN case revision does not match registry")
        for row in case["source_binding"]["files"]:
            relative = str(row["path"])
            source = SOURCE_ROOT / relative
            if not source.is_file():
                raise ValidationError(f"OpenClaw-CN bound source is missing: {relative}")
            value = sha256_file(source)
            if value != row["sha256"]:
                raise ValidationError(f"OpenClaw-CN source hash drift: {relative}")
            bindings[relative] = value
    for relative in sorted(required_files - set(bindings)):
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"OpenClaw-CN build source is missing: {relative}")
        bindings[relative] = sha256_file(source)
    return bindings


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(f"OpenClaw-CN instrumentation marker mismatch ({label}): {count}")
    return source.replace(old, new, 1)


def _instrumentation_helper() -> str:
    return r'''
import { appendFileSync } from "node:fs";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import type { ChildProcess } from "node:child_process";

let clawgapBoundaryEmitted = false;
let clawgapSinkEmitted = false;

function clawgapEvent(stage: string, detail: Record<string, unknown>): void {
  const path = process.env.CLAWGAP_L2_EVENT_PATH;
  if (!path) return;
  appendFileSync(path, JSON.stringify({
    schema_version: "clawgap-dynamic-trigger-openclaw-cn-l2-event/v1",
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

export function __clawgapHandlerEntered(
  toolName: string,
  toolArguments: unknown,
): void {
  clawgapEvent("handler_entered", { tool_name: toolName, arguments: toolArguments });
}

export function __clawgapControlledArgument(): void {
  const rawValue = process.env.CLAWGAP_L2_CONTROLLED_VALUE;
  let parsedValue: unknown = rawValue;
  if (typeof rawValue === "string") {
    try {
      parsedValue = JSON.parse(rawValue);
    } catch {
      parsedValue = rawValue;
    }
  }
  clawgapEvent("controlled_argument_recorded", {
    argument_path: String(process.env.CLAWGAP_L2_ARGUMENT_PATH ?? "").split(".").filter(Boolean),
    value: parsedValue,
  });
}

export function __clawgapGateOrMissing(detail: Record<string, unknown>): void {
  if (clawgapBoundaryEmitted) return;
  clawgapBoundaryEmitted = true;
  const ids = String(process.env.CLAWGAP_L2_GATE_IDS ?? "").split(",").filter(Boolean);
  if (ids.length === 0) {
    clawgapEvent("missing_check_boundary_confirmed", {
      ...detail,
      gate_required: false,
      reason: "reviewed missing-check case has no cited gate",
    });
    return;
  }
  clawgapEvent("gate_observed", { ...detail, gate_ids: ids, admitted: true });
}

export function __clawgapEffect(
  sinkAnchor: string,
  payload: Record<string, unknown>,
): void {
  if (clawgapSinkEmitted) return;
  clawgapSinkEmitted = true;
  clawgapEvent("sink_reached", { sink_anchor: sinkAnchor, ...payload });
  clawgapEvent("pre_effect_interception", {
    sink_anchor: sinkAnchor,
    ...payload,
    executed: false,
  });
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

export function __clawgapInterceptSpawn(
  sinkAnchor: string,
  command: string,
  args: readonly string[],
  fallback: () => ChildProcess,
): ChildProcess {
  if (!process.env.CLAWGAP_L2_EVENT_PATH) return fallback();
  __clawgapEffect(sinkAnchor, {
    command,
    args: [...args],
    argv: [command, ...args],
  });
  const child = new ClawgapInterceptedChild() as unknown as ChildProcess;
  setTimeout(() => {
    child.emit("spawn");
    (child.stdout as PassThrough | null)?.end("clawgap intercepted process execution\n");
    (child.stderr as PassThrough | null)?.end();
    child.emit("exit", 0, null);
    child.emit("close", 0, null);
  }, 50);
  return child;
}

class ClawgapInterceptedPty {
  readonly pid = -2;
  write(_data: string): void {}
  onData(callback: (data: Buffer) => void): void {
    callback(Buffer.from("clawgap intercepted pty execution\n", "utf8"));
  }
  onExit(callback: (event: { exitCode: number; signal?: number }) => void): void {
    callback({ exitCode: 0, signal: 0 });
  }
}

export function __clawgapInterceptPty<T>(
  sinkAnchor: string,
  command: string,
  fallback: () => T,
): T {
  if (!process.env.CLAWGAP_L2_EVENT_PATH) return fallback();
  __clawgapEffect(sinkAnchor, { pty: true, command, executed: false });
  return new ClawgapInterceptedPty() as unknown as T;
}

export async function __clawgapInterceptWrite(
  sinkAnchor: string,
  filePath: string,
  content: string,
): Promise<void> {
  __clawgapEffect(sinkAnchor, { file_path: filePath, content_length: content.length });
}

export async function __clawgapInterceptCdpFetch<T>(
  sinkAnchor: string,
  url: string,
): Promise<T> {
  __clawgapEffect(sinkAnchor, { url });
  return {
    id: "clawgap-cdp-tab",
    title: "ClawGap intercepted tab",
    url,
    webSocketDebuggerUrl: "ws://127.0.0.1/clawgap",
    type: "page",
  } as T;
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
    extension = project / "extensions" / "feishu"
    extension_node_modules = extension / "node_modules"
    extension_node_modules.mkdir()
    source_extension_node_modules = SOURCE_ROOT / "extensions/feishu/node_modules"
    for dependency in source_extension_node_modules.iterdir():
        if dependency.name == "openclaw":
            continue
        (extension_node_modules / dependency.name).symlink_to(
            dependency, target_is_directory=dependency.is_dir()
        )
    (extension_node_modules / "openclaw").symlink_to(
        Path("../../.."), target_is_directory=True
    )
    helper_path = project / "src" / "clawgap-l2.ts"
    helper_path.write_text(_instrumentation_helper(), encoding="utf-8")

    browser_path = project / "src" / "agents" / "tools" / "browser-tool.ts"
    source = browser_path.read_text(encoding="utf-8")
    source = (
        'import { __clawgapControlledArgument, __clawgapGateOrMissing, __clawgapHandlerEntered } '
        'from "../../clawgap-l2.js";\n' + source
    )
    marker = "    execute: async (_toolCallId, args) => {"
    source = _replace_once(
        source,
        marker,
        marker
        + '\n      __clawgapHandlerEntered("browser", args);\n'
        "      __clawgapControlledArgument();\n"
        "      if (!process.env.CLAWGAP_L2_GATE_IDS) {\n"
        '        __clawgapGateOrMissing({ tool_name: "browser" });\n'
        "      }",
        "browser handler",
    )
    browser_path.write_text(source, encoding="utf-8")

    exec_path = project / "src" / "agents" / "bash-tools.exec.ts"
    source = exec_path.read_text(encoding="utf-8")
    source = (
        'import { __clawgapControlledArgument, __clawgapGateOrMissing, '
        '__clawgapHandlerEntered, __clawgapInterceptPty } '
        'from "../clawgap-l2.js";\n' + source
    )
    marker = "    execute: async (_toolCallId, args, signal, onUpdate) => {"
    source = _replace_once(
        source,
        marker,
        marker
        + '\n      __clawgapHandlerEntered("exec", args);\n'
        "      __clawgapControlledArgument();",
        "exec handler",
    )
    extension_helper = extension / "src" / "clawgap-l2.ts"
    extension_helper.write_text(
        r'''
import { appendFileSync } from "node:fs";

let boundaryEmitted = false;
let sinkEmitted = false;

function event(stage: string, detail: Record<string, unknown>): void {
  const path = process.env.CLAWGAP_L2_EVENT_PATH;
  if (!path) return;
  appendFileSync(path, JSON.stringify({
    schema_version: "clawgap-dynamic-trigger-openclaw-cn-l2-event/v1",
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

export function gateOrMissing(detail: Record<string, unknown>): void {
  if (boundaryEmitted) return;
  boundaryEmitted = true;
  const ids = String(process.env.CLAWGAP_L2_GATE_IDS ?? "").split(",").filter(Boolean);
  if (ids.length === 0) {
    event("missing_check_boundary_confirmed", { ...detail, gate_required: false });
    return;
  }
  event("gate_observed", { ...detail, gate_ids: ids, admitted: true });
}

export function effect(anchor: string, payload: Record<string, unknown>): void {
  if (sinkEmitted) return;
  sinkEmitted = true;
  event("sink_reached", { sink_anchor: anchor, ...payload });
  event("pre_effect_interception", { sink_anchor: anchor, ...payload, executed: false });
}
''',
        encoding="utf-8",
    )

    gate_marker = "        const analysisOk = allowlistEval.analysisOk;"
    source = _replace_once(
        source,
        gate_marker,
        gate_marker
        + "\n        __clawgapGateOrMissing({\n"
        "          command: params.command,\n"
        "          allowlist_satisfied: allowlistEval.allowlistSatisfied,\n"
        "          analysis_ok: analysisOk,\n"
        "          second_approval_required: requiresExecApproval({\n"
        "            ask: hostAsk,\n"
        "            security: hostSecurity,\n"
        "            analysisOk,\n"
        "            allowlistSatisfied: allowlistEval.allowlistSatisfied,\n"
        "          }),\n"
        "        });",
        "exec approval boundary",
    )
    pty_marker = (
        "      pty = spawnPty(shell, [...shellArgs, opts.command], {\n"
        "        cwd: opts.workdir,\n"
        "        env: opts.env,\n"
        "        name: process.env.TERM ?? \"xterm-256color\",\n"
        "        cols: 120,\n"
        "        rows: 30,\n"
        "      });"
    )
    source = _replace_once(
        source,
        pty_marker,
        "      pty = __clawgapInterceptPty(\n"
        '        "src/agents/bash-tools.exec.ts:414",\n'
        "        opts.command,\n"
        "        () => spawnPty(shell, [...shellArgs, opts.command], {\n"
        "          cwd: opts.workdir,\n"
        "          env: opts.env,\n"
        '          name: process.env.TERM ?? "xterm-256color",\n'
        "          cols: 120,\n"
        "          rows: 30,\n"
        "        }),\n"
        "      );",
        "PTY sink opening",
    )
    exec_path.write_text(source, encoding="utf-8")
    exec_source = exec_path.read_text(encoding="utf-8")
    optional_safe_bins_marker = (
        '          allowlistEval.segmentSatisfiedBy.some((by) => by === "safeBins")'
    )
    exec_source = _replace_once(
        exec_source,
        optional_safe_bins_marker,
        '          (allowlistEval.segmentSatisfiedBy?.some((by) => by === "safeBins")'
        " ?? false)",
        "optional safe-bin metadata",
    )
    exec_path.write_text(exec_source, encoding="utf-8")

    spawn_path = project / "src" / "process" / "spawn-utils.ts"
    source = spawn_path.read_text(encoding="utf-8")
    source = 'import { __clawgapInterceptSpawn } from "../clawgap-l2.js";\n' + source
    marker = "  const child = spawnImpl(argv[0], argv.slice(1), options);"
    source = _replace_once(
        source,
        marker,
        "  const child = __clawgapInterceptSpawn(\n"
        '    "src/process/spawn-utils.ts:57",\n'
        "    argv[0],\n"
        "    argv.slice(1),\n"
        "    () => spawnImpl(argv[0], argv.slice(1), options),\n"
        "  );",
        "process spawn sink",
    )
    spawn_path.write_text(source, encoding="utf-8")

    patch_path = project / "src" / "agents" / "apply-patch.ts"
    source = patch_path.read_text(encoding="utf-8")
    source = (
        'import { __clawgapControlledArgument, __clawgapHandlerEntered, '
        '__clawgapInterceptWrite } from "../clawgap-l2.js";\n' + source
    )
    marker = "    execute: async (_toolCallId, args, signal) => {"
    source = _replace_once(
        source,
        marker,
        marker
        + '\n      __clawgapHandlerEntered("apply_patch", args);\n'
        "      __clawgapControlledArgument();",
        "apply-patch handler",
    )
    write_marker = (
        '    writeFile: (filePath, content) => fs.writeFile(filePath, content, "utf8"),'
    )
    source = _replace_once(
        source,
        write_marker,
        '    writeFile: (filePath, content) =>\n'
        '      __clawgapInterceptWrite("src/agents/apply-patch.ts:243", filePath, content),',
        "apply-patch write sink",
    )
    patch_path.write_text(source, encoding="utf-8")

    sandbox_path = project / "src" / "agents" / "sandbox-paths.ts"
    source = sandbox_path.read_text(encoding="utf-8")
    source = 'import { __clawgapGateOrMissing } from "../clawgap-l2.js";\n' + source
    marker = (
        "  const resolved = resolveSandboxPath(params);\n"
        "  await assertNoSymlinkEscape(resolved.relative, path.resolve(params.root), {\n"
        "    allowFinalSymlink: params.allowFinalSymlink,\n"
        "  });"
    )
    source = _replace_once(
        source,
        marker,
        marker
        + "\n  __clawgapGateOrMissing({\n"
        "    file_path: params.filePath,\n"
        "    resolved_path: resolved.resolved,\n"
        "    boundary: \"sandbox-path-and-dangling-symlink\",\n"
        "  });",
        "sandbox gates",
    )
    sandbox_path.write_text(source, encoding="utf-8")

    message_path = project / "src" / "agents" / "tools" / "message-tool.ts"
    source = message_path.read_text(encoding="utf-8")
    source = (
        'import { __clawgapControlledArgument, __clawgapHandlerEntered } '
        'from "../../clawgap-l2.js";\n' + source
    )
    marker = "    execute: async (_toolCallId, args, signal) => {"
    source = _replace_once(
        source,
        marker,
        marker
        + '\n      __clawgapHandlerEntered("message", args);\n'
        "      __clawgapControlledArgument();",
        "message handler",
    )
    message_path.write_text(source, encoding="utf-8")

    feishu_path = project / "extensions" / "feishu" / "src" / "media.ts"
    source = feishu_path.read_text(encoding="utf-8")
    source = 'import { effect, gateOrMissing } from "./clawgap-l2.js";\n' + source
    marker = (
        "      const response = await fetch(mediaUrl);\n"
        "      if (!response.ok) {\n"
        "        throw new Error(`Failed to fetch media from URL: ${response.status}`);\n"
        "      }\n"
        "      buffer = Buffer.from(await response.arrayBuffer());\n"
        "      name = fileName ?? (path.basename(new URL(mediaUrl).pathname) || \"file\");"
    )
    source = _replace_once(
        source,
        marker,
        '      gateOrMissing({ url: mediaUrl, boundary: "outbound-media-url" });\n'
        '      effect("extensions/feishu/src/media.ts:537", { url: mediaUrl });\n'
        '      return {\n'
        '        messageId: "clawgap-openclaw-cn-intercepted",\n'
        '        chatId: "oc_clawgapfixture",\n'
        "      };",
        "Feishu media fetch sink",
    )
    feishu_path.write_text(source, encoding="utf-8")

    navigation_path = project / "src" / "browser" / "navigation-guard.ts"
    source = navigation_path.read_text(encoding="utf-8")
    source = 'import { __clawgapGateOrMissing } from "../clawgap-l2.js";\n' + source
    marker = (
        "  if (!NETWORK_NAVIGATION_PROTOCOLS.has(parsed.protocol)) {\n"
        "    return;\n"
        "  }"
    )
    source = _replace_once(
        source,
        marker,
        "  if (!NETWORK_NAVIGATION_PROTOCOLS.has(parsed.protocol)) {\n"
        "    __clawgapGateOrMissing({ url: rawUrl, protocol: parsed.protocol });\n"
        "    return;\n"
        "  }",
        "navigation scheme gate",
    )
    navigation_path.write_text(source, encoding="utf-8")

    interactions_path = project / "src" / "browser" / "pw-tools-core.interactions.ts"
    source = interactions_path.read_text(encoding="utf-8")
    source = 'import { __clawgapEffect } from "../clawgap-l2.js";\n' + source
    click_marker = (
        "  const ref = requireRef(opts.ref);\n"
        "  const locator = refLocator(page, ref);\n"
        "  const timeout = Math.max(500, Math.min(60_000, Math.floor(opts.timeoutMs ?? 8000)));\n"
        "  try {"
    )
    source = _replace_once(
        source,
        click_marker,
        "  const ref = requireRef(opts.ref);\n"
        '  __clawgapEffect("src/browser/pw-tools-core.interactions.ts:46", {\n'
        "    ref,\n"
        "    double_click: Boolean(opts.doubleClick),\n"
        "  });\n"
        "  return;\n"
        "  const locator = refLocator(page, ref);\n"
        "  const timeout = Math.max(500, Math.min(60_000, Math.floor(opts.timeoutMs ?? 8000)));\n"
        "  try {",
        "browser click sink",
    )
    source = _replace_once(
        source,
        "  const fnText = String(opts.fn ?? \"\").trim();",
        '  const fnText = String(opts.fn ?? "").trim();\n'
        '  __clawgapEffect("src/browser/pw-tools-core.interactions.ts:257", {\n'
        "    fn: fnText,\n"
        "  });\n"
        "  return null;",
        "browser evaluate sink",
    )
    interactions_path.write_text(source, encoding="utf-8")

    pw_session_path = project / "src" / "browser" / "pw-session.ts"
    source = pw_session_path.read_text(encoding="utf-8")
    source = 'import { __clawgapEffect } from "../clawgap-l2.js";\n' + source
    marker = (
        "    await assertBrowserNavigationAllowed({\n"
        "      url: targetUrl,\n"
        "      ssrfPolicy: opts.ssrfPolicy,\n"
        "    });\n"
        "    await page.goto(targetUrl, { timeout: 30_000 }).catch(() => {"
    )
    source = _replace_once(
        source,
        marker,
        "    await assertBrowserNavigationAllowed({\n"
        "      url: targetUrl,\n"
        "      ssrfPolicy: opts.ssrfPolicy,\n"
        "    });\n"
        '    __clawgapEffect("src/browser/pw-session.ts:525", { url: targetUrl });\n'
        "    return {\n"
        '      targetId: "clawgap-fixture-tab",\n'
        '      title: "ClawGap fixture",\n'
        "      url: targetUrl,\n"
        '      type: "page",\n'
        "    };\n"
        "    await page.goto(targetUrl, { timeout: 30_000 }).catch(() => {",
        "browser create-page sink",
    )
    source = _replace_once(
        source,
        "  return {\n    targetId: tid,\n    title: await page.title().catch(() => \"\"),",
        "  return {\n"
        '    targetId: tid ?? "clawgap-fixture-tab",\n'
        '    title: await page.title().catch(() => ""),',
        "browser target narrowing",
    )
    pw_session_path.write_text(source, encoding="utf-8")
    source = _replace_once(
        interactions_path.read_text(encoding="utf-8"),
        "  if (opts.ref) {\n"
        "    const locator = refLocator(page, opts.ref);\n"
        "    // Use Function constructor at runtime to avoid esbuild adding __name helper",
        "  if (opts.ref) {\n"
        '    const locator = refLocator(page, opts.ref ?? "");\n'
        "    // Use Function constructor at runtime to avoid esbuild adding __name helper",
        "browser evaluate ref narrowing",
    )
    interactions_path.write_text(source, encoding="utf-8")
    source = pw_session_path.read_text(encoding="utf-8")
    connect_marker = (
        "async function connectBrowser(cdpUrl: string): Promise<ConnectedBrowser> {\n"
        "  const normalized = normalizeCdpUrl(cdpUrl);"
    )
    source = _replace_once(
        source,
        connect_marker,
        connect_marker
        + '\n  if (process.env.CLAWGAP_L2_BROWSER_FIXTURE === "1") {\n'
        "    const page = {\n"
        '      url: () => "http://fixture.invalid/",\n'
        '      title: async () => "ClawGap fixture",\n'
        "      context: () => context,\n"
        "      on: () => {},\n"
        "      evaluate: async () => null,\n"
        "      locator: () => ({ click: async () => {}, dblclick: async () => {} }),\n"
        "    } as unknown as Page;\n"
        "    const context = {\n"
        "      on: () => {},\n"
        "      pages: () => [page],\n"
        "      newPage: async () => page,\n"
        "      newCDPSession: async () => ({\n"
        '        send: async () => ({\n'
        "          targetInfo: {\n"
        '            targetId: process.env.CLAWGAP_L2_TARGET_ID ?? "clawgap-fixture-tab",\n'
        "          },\n"
        "        }),\n"
        "        detach: async () => {},\n"
        "      }),\n"
        "    } as unknown as BrowserContext;\n"
        "    const browser = {\n"
        "      contexts: () => [context],\n"
        "      newContext: async () => context,\n"
        "      close: async () => {},\n"
        "      on: () => {},\n"
        "    } as unknown as Browser;\n"
        "    cached = { browser, cdpUrl: normalized };\n"
        "    return cached;\n"
        "  }",
        "browser fixture connection",
    )
    pw_session_path.write_text(source, encoding="utf-8")

    server_context_path = project / "src" / "browser" / "server-context.ts"
    source = server_context_path.read_text(encoding="utf-8")
    source = 'import { __clawgapInterceptCdpFetch } from "../clawgap-l2.js";\n' + source
    marker = "  const ensureBrowserAvailable = async (): Promise<void> => {"
    source = _replace_once(
        source,
        marker,
        marker
        + '\n    if (process.env.CLAWGAP_L2_BROWSER_FIXTURE === "1") return;',
        "browser fixture availability",
    )
    cdp_marker = (
        "    const createdViaCdp = await createTargetViaCdp({\n"
        "      cdpUrl: profile.cdpUrl,\n"
        "      url,\n"
        "      ...(ssrfPolicy ? { ssrfPolicy } : {}),\n"
        "    })"
    )
    source = _replace_once(
        source,
        cdp_marker,
        '    if (process.env.CLAWGAP_L2_CANDIDATE_ID === "CAND-aea54f2ae30ff6d8") {\n'
        "      const encoded = encodeURIComponent(url);\n"
        "      const endpointUrl = new URL(appendCdpPath(profile.cdpUrl, \"/json/new\"));\n"
        "      const endpoint = endpointUrl.search\n"
        "        ? (() => {\n"
        "            endpointUrl.searchParams.set(\"url\", url);\n"
        "            return endpointUrl.toString();\n"
        "          })()\n"
        "        : `${endpointUrl.toString()}?${encoded}`;\n"
        "      const created = await __clawgapInterceptCdpFetch<{\n"
        "        id?: string;\n"
        "        title?: string;\n"
        "        url?: string;\n"
        "        webSocketDebuggerUrl?: string;\n"
        '        type?: string;\n'
        '      }>("src/browser/cdp.helpers.ts:106", endpoint);\n'
        "      const profileState = getProfileState();\n"
        "      profileState.lastTargetId = created.id ?? \"clawgap-cdp-tab\";\n"
        "      return {\n"
        "        targetId: created.id ?? \"clawgap-cdp-tab\",\n"
        '        title: created.title ?? "",\n'
        "        url: created.url ?? url,\n"
        '        type: created.type ?? "page",\n'
        "      };\n"
        "    }\n"
        + cdp_marker,
        "CDP tab sink",
    )
    server_context_path.write_text(source, encoding="utf-8")

    preaction_path = project / "src" / "cli" / "program" / "preaction.ts"
    source = preaction_path.read_text(encoding="utf-8")
    marker = (
        "    if (PLUGIN_REQUIRED_COMMANDS.has(commandPath[0])) {\n"
        "      ensurePluginRegistryLoaded();\n"
        "    }"
    )
    source = _replace_once(
        source,
        marker,
        marker
        + '\n    if (process.env.CLAWGAP_L2_LOAD_PLUGINS === "1") {\n'
        "      ensurePluginRegistryLoaded();\n"
        "    }",
        "agent plugin loading",
    )
    preaction_path.write_text(source, encoding="utf-8")

    transformed = {
        relative: sha256_file(project / relative)
        for relative in (
            "src/clawgap-l2.ts",
            "src/agents/bash-tools.exec.ts",
            "src/agents/apply-patch.ts",
            "src/agents/sandbox-paths.ts",
            "src/agents/tools/browser-tool.ts",
            "src/agents/tools/message-tool.ts",
            "src/browser/navigation-guard.ts",
            "src/browser/pw-session.ts",
            "src/browser/pw-tools-core.interactions.ts",
            "src/browser/server-context.ts",
            "src/cli/program/preaction.ts",
            "src/process/spawn-utils.ts",
            "extensions/feishu/src/clawgap-l2.ts",
            "extensions/feishu/src/media.ts",
        )
    }
    return {
        "schema_version": "clawgap-openclaw-cn-transformed-source-manifest/v1",
        "revision": PROJECT.analysis_revision,
        "original": dict(source_bindings),
        "transformed": transformed,
        "node_modules": "read-only dependency symlinks to pinned benchmark installations",
        "build_required": True,
    }


def _run_build(
    command: list[str], cwd: Path, environment: Mapping[str, str], timeout: int
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=dict(environment),
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
        raise ValidationError("OpenClaw-CN instrumented build timed out") from _TimeoutOutput(output)
    return completed


class _TimeoutOutput(Exception):
    def __init__(self, output: str):
        self.output = output


def _prepare_build(
    directory: Path, source_bindings: Mapping[str, str], timeout: int
) -> dict[str, Any]:
    harness_sha256 = sha256_file(REPO_ROOT / "src/runtime_validation/openclaw_cn_l2.py")
    manifest_path = directory / "transformed-source-manifest.json"
    entrypoint = directory / "project" / "dist" / "entry.js"
    if manifest_path.is_file() and entrypoint.is_file():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version") == "clawgap-openclaw-cn-transformed-source-manifest/v1"
            and prior.get("revision") == PROJECT.analysis_revision
            and prior.get("original") == dict(source_bindings)
            and prior.get("dependency_lockfile") == sha256_file(SOURCE_ROOT / "pnpm-lock.yaml")
            and prior.get("harness_sha256") == harness_sha256
            and prior.get("entrypoint_sha256") == sha256_file(entrypoint)
        ):
            return prior
    manifest = _render_build_copy(directory, source_bindings)
    project = directory / "project"
    home = directory / "home"
    home.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(home),
        "CI": "true",
        "NO_COLOR": "1",
    }
    try:
        root_build = _run_build(
            ["pnpm", "run", "build"], project, environment, timeout
        )
        logs = [root_build.stdout or ""]
        extension_build = _run_build(
            ["pnpm", "--dir", "extensions/feishu", "run", "build"],
            project,
            environment,
            timeout,
        )
        logs.append(extension_build.stdout or "")
    except _TimeoutOutput as exc:
        atomic_write_text(directory / "build.log", redact_text(exc.output))
        raise
    atomic_write_text(directory / "build.log", redact_text("\n".join(logs)))
    if root_build.returncode != 0 or extension_build.returncode != 0:
        raise ValidationError(
            "OpenClaw-CN instrumented build failed: "
            f"root={root_build.returncode}, feishu={extension_build.returncode}"
        )
    if not entrypoint.is_file():
        raise ValidationError("OpenClaw-CN instrumented entrypoint is missing")
    manifest["build_exit_code"] = root_build.returncode
    manifest["feishu_build_exit_code"] = extension_build.returncode
    manifest["entrypoint_sha256"] = sha256_file(entrypoint)
    manifest["dependency_lockfile"] = sha256_file(SOURCE_ROOT / "pnpm-lock.yaml")
    manifest["harness_sha256"] = harness_sha256
    atomic_write_json(manifest_path, manifest)
    _remove_path(home)
    return manifest


class OpenClawCNFixtureServer:
    """Loopback OpenAI fixture returning exactly one reviewed tool call."""

    def __init__(
        self,
        role: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        transcript_path: Path,
    ):
        self.role = role
        self.tool_name = tool_name
        self.arguments = dict(arguments)
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
                        "schema_version": "clawgap-openclaw-cn-provider-transcript/v1",
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
                    self._error("clawgap OpenClaw-CN fixture endpoint is not implemented", 404)
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
                    self._error("request does not match the OpenClaw-CN tool-call contract", 400)
                    return
                chunks_for = "tool" if number == 1 else "final"
                if chunks_for == "tool":
                    deltas = [
                        {"role": "assistant"},
                        {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call-clawgap-openclaw-cn",
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
                        {},
                    ]
                    finish = [None, None, "tool_calls"]
                else:
                    deltas = [
                        {"role": "assistant", "content": "clawgap role complete"},
                        {},
                    ]
                    finish = [None, "stop"]
                chunks = []
                for index, delta in enumerate(deltas):
                    chunks.append(
                        {
                            "id": f"chatcmpl-clawgap-openclaw-cn-{server.role}",
                            "object": "chat.completion.chunk",
                            "created": 0,
                            "model": "clawgap-environment-probe",
                            "choices": [
                                {
                                    "index": 0,
                                    "finish_reason": finish[index],
                                    "delta": delta,
                                }
                            ],
                        }
                    )
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
        self._server.server_close()
        self._thread.join(timeout=0.5)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])


def _role_arguments(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    return dict(
        next(row for row in case["forced_tool_calls"] if row.get("role") == role)[
            "arguments"
        ]
    )


def _controlled_value(case: Mapping[str, Any], role: str) -> Any:
    value: Any = _role_arguments(case, role)
    for part in case["unsafe_relation"]["argument_path"]:
        value = value[part]
    return value


def _native_arguments(
    case: Mapping[str, Any], role: str, workspace: Path, busybox: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    original = _role_arguments(case, role)
    native = dict(original)
    changes: dict[str, Any] = {}
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    if candidate_id in CLICK_CANDIDATES | EVALUATE_CANDIDATES:
        native["target"] = "host"
        changes["target"] = "host"
    elif candidate_id in OPEN_PAGE_CANDIDATES | OPEN_CDP_CANDIDATES:
        native["targetUrl"] = native.pop("url")
        native["target"] = "host"
        changes["url_to_targetUrl"] = native["targetUrl"]
        changes["target"] = "host"
    elif candidate_id in EXEC_CANDIDATES:
        native.pop("approvalDecision", None)
        native["workdir"] = str(workspace)
        native["env"] = {"PATH": str(busybox.parent)}
        changes.update(
            {
                "approvalDecision_removed": "disposable durable approval state",
                "workdir": str(workspace),
                "env_PATH": str(busybox.parent),
            }
        )
    elif candidate_id in APPLY_PATCH_CANDIDATES:
        pass
    elif candidate_id in FEISHU_CANDIDATES:
        native["action"] = "send"
        native["media"] = native.pop("mediaUrl")
        native["channel"] = "feishu"
        native["target"] = "oc_clawgapfixture"
        native.pop("to", None)
        changes.update(
            {
                "action": "send",
                "mediaUrl_to_media": native["media"],
                "channel": "feishu",
                "target": native["target"],
            }
        )
    else:
        raise ValidationError(f"unsupported OpenClaw-CN candidate family: {candidate_id}")
    return native, {"original": original, "native": native, "changes": changes}


def _openclaw_cn_config(
    base_url: str,
    browser_control_url: str,
    build_project: Path,
    workspace: Path,
    *,
    load_plugins: bool,
    enable_apply_patch: bool,
) -> str:
    provider_name = "openai" if enable_apply_patch else "clawgap"
    value = {
        "gateway": {
            "mode": "local",
            "auth": {"mode": "token", "token": "clawgap-loopback-mock"},
        },
        "agents": {
            "defaults": {
                "model": {"primary": f"{provider_name}/clawgap-environment-probe"},
                "workspace": str(workspace),
                "skipBootstrap": True,
            }
        },
        "tools": {
            "exec": {
                "host": "gateway",
                "security": "allowlist",
                "ask": "on-miss",
                "safeBins": [],
                "applyPatch": {"enabled": True},
            }
        },
        "browser": {
            "enabled": True,
            "controlUrl": browser_control_url,
            "headless": True,
            "noSandbox": True,
            "attachOnly": True,
            "defaultProfile": "clawd",
            "profiles": {
                "clawd": {
                    "cdpUrl": "http://example.com:9222",
                    "color": "#FF4500",
                },
                "clawdbot-cn": {
                    "cdpUrl": "http://127.0.0.1:9224",
                    "color": "#0066CC",
                },
            },
        },
        "models": {
            "providers": {
                provider_name: {
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
        "channels": {
            "feishu": {
                "appId": "clawgap-fixture",
                "appSecret": "clawgap-fixture",
            }
        },
    }
    if load_plugins:
        value["plugins"] = {
            "enabled": True,
            "load": {"paths": [str(build_project / "extensions" / "feishu")]},
        }
    return json.dumps(value, indent=2, sort_keys=True)


def _fake_busybox(directory: Path) -> tuple[Path, str]:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "busybox"
    atomic_write_text(path, "#!/bin/sh\nexit 111\n")
    path.chmod(0o500)
    return path, sha256_file(path)


def _approval_file(home: Path, busybox: Path) -> Path:
    root = home / ".openclaw"
    root.mkdir(parents=True, exist_ok=True)
    path = root / "exec-approvals.json"
    atomic_write_json(
        path,
        {
            "version": 1,
            "agents": {
                "main": {
                    "security": "allowlist",
                    "ask": "on-miss",
                    "askFallback": "deny",
                    "allowlist": [
                        {
                            "id": "clawgap-durable-busybox",
                            "pattern": str(busybox),
                        }
                    ],
                }
            },
        },
    )
    return path


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_http(url: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1) as response:
                if 200 <= response.status < 500:
                    return
        except (HTTPError, URLError, OSError) as exc:
            last_error = exc
        time.sleep(0.2)
    raise ValidationError(f"OpenClaw-CN browser server did not become ready: {last_error}")


def _base_event(
    stage: str,
    detail: Mapping[str, Any],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
) -> dict[str, Any]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    return {
        "schema_version": "clawgap-dynamic-trigger-openclaw-cn-l2-event/v1",
        "event_id": f"{case['case_id']}:{attempt}:{role}:{stage}",
        "stage": stage,
        "candidate_id": candidate_id,
        "case_id": case["case_id"],
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{case['case_id']}:{attempt}:{role}",
        "fixture_id": f"openclaw-cn-l2:{case['case_id']}:{role}",
        "detail": dict(detail),
    }


def _expected_stages(case: Mapping[str, Any], role: str) -> list[str]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    stages = list(BASE_STAGES)
    if candidate_id in BROWSER_CANDIDATES:
        stages.insert(3, "browser_server_ready")
    if case.get("gates"):
        if role == "exploit" or candidate_id not in BROWSER_CANDIDATES:
            stages.append(GATE_STAGE)
    else:
        stages.append(MISSING_CHECK_STAGE)
    stages.extend(("sink_reached", "pre_effect_interception"))
    stages.extend(TERMINAL_STAGES)
    return stages


def _normalize_events(
    raw_events: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    fixture_files: Mapping[str, str],
    argument_adaptation: Mapping[str, Any],
) -> list[dict[str, Any]]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    events: list[dict[str, Any]] = []
    synthetic = {
        "case_bound": {"candidate_id": candidate_id},
        "source_verified": {"revision": case["revision"]},
        "fixture_prepared": {"files": {key: "sha256" for key in sorted(fixture_files)}},
        "launch_started": {"entrypoint": "node dist/entry.js agent"},
        "prompt_received": {"message": "environment probe"},
    }
    for stage in ("case_bound", "source_verified", "fixture_prepared"):
        events.append(_base_event(stage, synthetic[stage], case, attempt, role))
    if candidate_id in BROWSER_CANDIDATES:
        events.append(
            _base_event(
                "browser_server_ready",
                {"entrypoint": "node dist/entry.js browser serve"},
                case,
                attempt,
                role,
            )
        )
    events.append(_base_event("launch_started", synthetic["launch_started"], case, attempt, role))
    events.append(_base_event("prompt_received", synthetic["prompt_received"], case, attempt, role))
    request = next((row for row in provider_rows if row.get("valid") is True), None)
    if request is None:
        raise RuntimeError("real OpenClaw-CN provider client did not issue a valid request")
    tool_name = str(case["handler"]["tool_name"])
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
            {
                "tool_name": tool_name,
                "arguments": argument_adaptation["native"],
                "argument_adaptation": argument_adaptation["changes"],
            },
            case,
            attempt,
            role,
        )
    )
    events.append(
        _base_event(
            "registry_or_native_dispatch",
            {"tool_name": tool_name, "runtime": "openclaw-cn-agent"},
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


def _sink_matches(candidate_id: str, sink: Mapping[str, Any], expected: Any) -> bool:
    detail = sink.get("detail", {})
    anchor = str(detail.get("sink_anchor", ""))
    if candidate_id in CLICK_CANDIDATES:
        return anchor.endswith("pw-tools-core.interactions.ts:46") and detail.get("ref") == expected
    if candidate_id in OPEN_PAGE_CANDIDATES:
        return anchor.endswith("pw-session.ts:525") and detail.get("url") == expected
    if candidate_id in OPEN_CDP_CANDIDATES:
        rendered = unquote(str(detail.get("url", "")))
        return anchor.endswith("cdp.helpers.ts:106") and str(expected) in rendered
    if candidate_id in EVALUATE_CANDIDATES:
        return anchor.endswith("pw-tools-core.interactions.ts:257") and detail.get("fn") == expected
    if candidate_id in EXEC_CANDIDATES:
        argv = detail.get("argv", [])
        command = detail.get("command")
        rendered = (
            " ".join(str(item) for item in argv)
            if argv
            else str(command)
        )
        return anchor in {
            "src/agents/bash-tools.exec.ts:414",
            "src/process/spawn-utils.ts:57",
        } and str(expected) in rendered
    if candidate_id in APPLY_PATCH_CANDIDATES:
        return anchor.endswith("apply-patch.ts:243") and "link/evil.txt" in str(
            detail.get("file_path", "")
        )
    if candidate_id in FEISHU_CANDIDATES:
        return anchor.endswith("extensions/feishu/src/media.ts:537") and detail.get("url") == expected
    return False


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    fixture: OpenClawCNFixtureServer,
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
        errors.append("provider did not observe exactly one tool call and one final turn")
    if process_exit != 0:
        errors.append(f"target process exited with {process_exit}")
    if "error" in output.lower() and "clawgap" not in output.lower():
        errors.append("real OpenClaw-CN entrypoint reported an error")
    for event in events:
        row = {key: event.get(key) for key in IDENTITY_FIELDS}
        if row != identity:
            errors.append("cross-attempt or cross-correlation event stitching")
            break
    stages = [str(event.get("stage")) for event in events]
    expected_stages = _expected_stages(case, role)
    if stages != expected_stages or len(stages) != len(set(stages)):
        errors.append(f"event sequence mismatch: {stages}")
    expected_value = _controlled_value(case, role)
    handler = next((row for row in events if row.get("stage") == "handler_entered"), None)
    if handler is None or handler.get("detail", {}).get("tool_name") != case["handler"]["tool_name"]:
        errors.append("native OpenClaw-CN handler was not entered")
    controlled = next(
        (row for row in events if row.get("stage") == "controlled_argument_recorded"), None
    )
    if controlled is None or controlled.get("detail", {}).get("value") != expected_value:
        errors.append("controlled OpenClaw-CN value drift")
    gate_ids = {str(row["id"]) for row in case.get("gates", [])}
    if role == "exploit":
        if gate_ids:
            gate = next((row for row in events if row.get("stage") == GATE_STAGE), None)
            if gate is None or set(gate.get("detail", {}).get("gate_ids", [])) != gate_ids:
                errors.append("cited OpenClaw-CN gate identity drift")
        else:
            boundary = next(
                (row for row in events if row.get("stage") == MISSING_CHECK_STAGE), None
            )
            if boundary is None or boundary.get("detail", {}).get("gate_required") is not False:
                errors.append("missing-check boundary was not confirmed")
    sink = next((row for row in events if row.get("stage") == "sink_reached"), None)
    intercepted = next(
        (row for row in events if row.get("stage") == "pre_effect_interception"), None
    )
    if sink is None:
        errors.append("reviewed value did not reach the declared OpenClaw-CN sink")
    elif role == "exploit" and not _sink_matches(candidate_id, sink, expected_value):
        errors.append("reviewed value did not reach the declared OpenClaw-CN sink")
    if (
        intercepted is None
        or intercepted.get("detail", {}).get("executed") is not False
        or (role == "exploit" and not _sink_matches(candidate_id, intercepted, expected_value))
    ):
        errors.append("OpenClaw-CN terminal effect was not intercepted before execution")
    if candidate_id in EXEC_CANDIDATES and role == "exploit":
        boundary = next(
            (row for row in events if row.get("stage") in {GATE_STAGE, MISSING_CHECK_STAGE}),
            None,
        )
        if boundary is None or boundary.get("detail", {}).get("second_approval_required") is not False:
            errors.append("durable BusyBox approval was not reused without a second approval")
    triggered = role == "exploit" and not errors and _sink_matches(
        candidate_id, sink or {}, expected_value
    )
    return PairOutcome(not errors, triggered, errors)


def _environment(
    *,
    directory: Path,
    home: Path,
    state: Path,
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    event_path: Path,
    expected_value: Any,
) -> dict[str, str]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    environment = {
        "PATH": f"{directory / 'bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
        "HOME": str(home),
        "TMPDIR": str(directory / "tmp"),
        "OPENCLAW_STATE_DIR": str(state),
        "OPENCLAW_CONFIG_PATH": str(state / "openclaw.json"),
        "NO_COLOR": "1",
        "OPENCLAW_HIDE_BANNER": "1",
        "NO_PROXY": "127.0.0.1,localhost,::1",
        "no_proxy": "127.0.0.1,localhost,::1",
        "CLAWGAP_L2_EVENT_PATH": str(event_path),
        "CLAWGAP_L2_CANDIDATE_ID": candidate_id,
        "CLAWGAP_L2_CASE_ID": str(case["case_id"]),
        "CLAWGAP_L2_ATTEMPT": str(attempt),
        "CLAWGAP_L2_ROLE": role,
        "CLAWGAP_L2_CORRELATION_ID": f"{case['case_id']}:{attempt}:{role}",
        "CLAWGAP_L2_FIXTURE_ID": f"openclaw-cn-l2:{case['case_id']}:{role}",
        "CLAWGAP_L2_GATE_IDS": ",".join(
            str(row["id"]) for row in case.get("gates", [])
        ),
        "CLAWGAP_L2_ARGUMENT_PATH": ".".join(
            str(part) for part in case["unsafe_relation"]["argument_path"]
        ),
        "CLAWGAP_L2_CONTROLLED_VALUE": json.dumps(expected_value),
    }
    if candidate_id in BROWSER_CANDIDATES:
        environment["CLAWGAP_L2_BROWSER_FIXTURE"] = "1"
        if candidate_id == "CAND-229d4f6249170277":
            environment["CLAWGAP_L2_TARGET_ID"] = "tab1"
    if candidate_id in FEISHU_CANDIDATES:
        environment["CLAWGAP_L2_LOAD_PLUGINS"] = "1"
    return environment


def _terminate(process: subprocess.Popen[str]) -> None:
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


def _run_role_attempt(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    request: OpenClawCNL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    _remove_path(directory)
    directory.mkdir(parents=True)
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    launch_log = directory / "launch.log"
    atomic_write_text(transcript_path, "")
    atomic_write_text(event_path, "")
    home = directory / "home"
    state = directory / "state"
    workspace = directory / "workspace"
    temporary = directory / "tmp"
    bins = directory / "bin"
    for path in (home, state, workspace, temporary):
        path.mkdir(parents=True, exist_ok=True)
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    busybox, busybox_hash = _fake_busybox(bins)
    fixture_files = {str(busybox): busybox_hash}
    if candidate_id in EXEC_CANDIDATES:
        approvals = _approval_file(home, busybox)
        fixture_files[str(approvals)] = sha256_file(approvals)
    if candidate_id in APPLY_PATCH_CANDIDATES:
        outside = directory / "outside"
        outside.mkdir()
        link_directory = workspace / "link"
        link_directory.mkdir()
        dangling = link_directory / "evil.txt"
        dangling.symlink_to(outside / "evil.txt", target_is_directory=False)
        fixture_files[str(dangling)] = "dangling-symlink"
    expected_value = _controlled_value(case, role)
    native_arguments, adaptation = _native_arguments(
        case, role, workspace, busybox
    )
    tool_name = str(case["handler"]["tool_name"])
    fixture = OpenClawCNFixtureServer(
        role, tool_name, native_arguments, transcript_path
    )
    fixture.start()
    base_url = f"http://127.0.0.1:{fixture.port}/v1"
    browser_port = _free_port()
    browser_control_url = f"http://127.0.0.1:{browser_port}"
    config = _openclaw_cn_config(
        base_url,
        browser_control_url,
        build_project,
        workspace,
        load_plugins=candidate_id in FEISHU_CANDIDATES,
        enable_apply_patch=candidate_id in APPLY_PATCH_CANDIDATES,
    )
    config_path = state / "openclaw.json"
    atomic_write_text(config_path, config)
    fixture_files[str(config_path)] = sha256_file(config_path)
    project_link = directory / "project"
    project_link.symlink_to(build_project, target_is_directory=True)
    environment = _environment(
        directory=directory,
        home=home,
        state=state,
        case=case,
        attempt=attempt,
        role=role,
        event_path=event_path,
        expected_value=expected_value,
    )
    canary = directory / "host-effect-canary.txt"
    atomic_write_text(canary, CANARY_CONTENT)
    node = shutil.which("node")
    if node is None:
        raise ValidationError("Node.js runtime is not installed")
    browser_process: subprocess.Popen[str] | None = None
    agent_process: subprocess.Popen[str] | None = None
    exit_code = 124
    output = ""
    browser_output = ""
    try:
        if candidate_id in BROWSER_CANDIDATES:
            browser_log = directory / "browser-server.log"
            browser_process = subprocess.Popen(
                [
                    node,
                    "dist/entry.js",
                    "browser",
                    "serve",
                    "--port",
                    str(browser_port),
                ],
                cwd=project_link,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            _wait_http(browser_control_url)
            browser_output = f"browser control listening on {browser_control_url}\n"
            atomic_write_text(browser_log, browser_output)
        agent_process = subprocess.Popen(
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
                "45",
            ],
            cwd=project_link,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            output, _stderr = agent_process.communicate(timeout=request.timeout)
            exit_code = agent_process.returncode
        except subprocess.TimeoutExpired as exc:
            value = exc.stdout or ""
            if not isinstance(value, str):
                value = value.decode("utf-8", errors="replace")
            output = value
            exit_code = 124
        atomic_write_text(launch_log, redact_text(browser_output + output))
    finally:
        if agent_process is not None:
            _terminate(agent_process)
        if browser_process is not None:
            _terminate(browser_process)
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
            adaptation,
        )
        _write_jsonl(directory / "events.jsonl", events)
        outcome = _evaluate_pair(case, role, events, fixture, exit_code, output)
    except Exception as exc:
        outcome = PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"])
        events = []
    if canary.read_text(encoding="utf-8") != CANARY_CONTENT:
        outcome.errors.append("host-effect canary changed")
        outcome.healthy = False
        outcome.triggered = False
    if candidate_id in APPLY_PATCH_CANDIDATES:
        outside = directory / "outside"
        if outside.exists() and any(outside.iterdir()):
            outcome.errors.append("pre-effect filesystem interception failed")
            outcome.healthy = False
            outcome.triggered = False
    events_text = (directory / "events.jsonl").read_text(encoding="utf-8") if events else ""
    if contains_credentials(events_text):
        outcome.errors.append("credential scan failed")
        outcome.healthy = False
        outcome.triggered = False
    for disposable in (home, state, workspace, temporary, bins, directory / "outside"):
        _remove_path(disposable)
    if project_link.is_symlink():
        project_link.unlink()
    return outcome, events


def _run_role(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    request: OpenClawCNL2RunRequest,
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
    paths = [
        path
        for run_root in run_roots
        for path in run_root.rglob("*")
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    ]
    paths.extend(
        path
        for path in root.iterdir()
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    )
    build_log = root / "build" / "build.log"
    if build_log.is_file():
        paths.append(build_log)
    text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in paths)
    return "failed" if contains_credentials(text) else "passed"


def _reproduction_command(request: OpenClawCNL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-openclaw-cn-l2"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.campaign != DEFAULT_SOURCE_CAMPAIGN:
        command += f" --campaign {request.campaign}"
    if request.candidate_id is not None:
        command += f" --candidate-id {request.candidate_id}"
    return command


def _run_candidate_subprocess(
    request: OpenClawCNL2RunRequest,
    candidate_id: str,
    build_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target_dir = request.out_dir.resolve() / "candidates" / candidate_id
    argv = [
        sys.executable,
        "-m",
        "src.runtime_validation",
        "run-dynamic-trigger-openclaw-cn-l2",
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
    result_rows = _read_jsonl(target_dir / "candidate-results.jsonl")
    case_rows = _read_jsonl(target_dir / "cases.jsonl")
    if completed.returncode != 0:
        atomic_write_text(
            request.out_dir / f"subprocess-{candidate_id}.log",
            redact_text(completed.stdout or ""),
        )
        valid_result = (
            len(result_rows) == 1
            and len(case_rows) == 1
            and result_rows[0].get("candidate_id") == candidate_id
            and result_rows[0].get("disposition") in {"not-reproduced", "inconclusive"}
        )
        if not valid_result:
            raise ValidationError(
                "OpenClaw-CN candidate subprocess failed without a valid candidate result: "
                f"exit={completed.returncode}, candidate={candidate_id}"
            )
        return case_rows[0], result_rows[0]
    if len(result_rows) != 1 or len(case_rows) != 1:
        raise ValidationError(
            f"OpenClaw-CN candidate subprocess identity partition drift: {candidate_id}"
        )
    return case_rows[0], result_rows[0]


def run_openclaw_cn_l2(request: OpenClawCNL2RunRequest) -> dict[str, Any]:
    started = time.time()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError("OpenClaw-CN targeted L2 timeouts and attempts must be positive")
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    cases = _select_cases(request.campaign.resolve(), candidate_id=request.candidate_id)
    source_bindings = _source_bindings(cases)
    actual_build_dir = request.build_dir.resolve() if request.build_dir else request.out_dir.resolve() / "build"
    build_manifest = _prepare_build(actual_build_dir, source_bindings, request.build_timeout)
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
            shutil.copyfile(actual_build_dir / "build.log", published_build_dir / "build.log")
    results: list[dict[str, Any]] = []
    if request.candidate_id is None:
        _remove_path(request.out_dir.resolve() / "runs")
        _remove_path(request.out_dir.resolve() / "candidates")
        selected = [
            _run_candidate_subprocess(request, candidate_id, actual_build_dir)
            for candidate_id in TARGET_CANDIDATES
        ]
        cases = [case for case, _result in selected]
        results = [result for _case, result in selected]
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
                    "project": "openclaw-cn",
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
                "project": "openclaw-cn",
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
    disposable_roots = [
        request.out_dir / "runs",
        *(path / "runs" for path in (request.out_dir / "candidates").glob("*")),
    ]
    disposable_workspaces_removed = not any(
        path.is_dir()
        for run_root in disposable_roots
        for path in run_root.rglob("*")
        if path.name in {"home", "state", "workspace", "temporary", "outside"}
    )
    if credential_scan != "passed" or not disposable_workspaces_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
        counts = {"inconclusive": len(results)}
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-openclaw-cn-l2-manifest/v1",
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
            "src/runtime_validation/openclaw_cn_l2.py": sha256_file(
                REPO_ROOT / "src/runtime_validation/openclaw_cn_l2.py"
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
            "# OpenClaw-CN Targeted Dynamic-Trigger L2\n\n"
            f"> Complete reproduction command: `{manifest['generation_command']}`\n\n"
            f"Candidates accounted for: **{len(results)}/{len(cases)}**.\n\n"
            f"Paired attempts per candidate: **{request.attempts}**.\n\n"
            f"Runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**; "
            f"not-reproduced: **{counts.get('not-reproduced', 0)}**; "
            f"inconclusive: **{counts.get('inconclusive', 0)}**.\n\n"
            "This is targeted OpenClaw-CN L2 evidence. It does not by itself publish "
            "canonical all-candidate L2 evidence or change the 46-report truth gate.\n"
        ),
    )
    return manifest
