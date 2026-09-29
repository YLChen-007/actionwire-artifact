"""Targeted forced-provider L2 runtime for linked NanoClaw candidates."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

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
from .openclaw_l2 import (
    PairOutcome,
    _read_jsonl,
    _remove_path,
    _replace_second_once,
    _write_jsonl,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("nanoclaw")
SOURCE_ROOT = PROJECT.source_root
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
TARGET_CANDIDATES = (
    "CAND-34e6b730eff7c9c7",
    "CAND-5a870a4d934a85cd",
    "CAND-79fbf2f6a976c935",
    "CAND-b1bde0d4c06ddc89",
)
ARBITRARY_SOURCE_CANDIDATES = {
    "CAND-34e6b730eff7c9c7",
    "CAND-5a870a4d934a85cd",
}
A2A_CANDIDATES = {"CAND-79fbf2f6a976c935", "CAND-b1bde0d4c06ddc89"}
CAMPAIGN_ID = "runtime-dynamic-trigger-nanoclaw-l2-v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-nanoclaw-l2-result/v1"
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-nanoclaw-l2-event/v1"
CANARY_CONTENT = "clawgap-nanoclaw-host-canary\n"
NATIVE_TOOL_NAME = "mcp__nanoclaw__send_file"
EXPECTED_GATE_ID = "GUbcdf63ad937d0566cd06"
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
    "image_verified",
    "fixture_prepared",
    "host_launch_started",
    "container_ready",
    "provider_request",
    "provider_tool_call",
    "native_dispatch",
    "handler_entered",
    "controlled_argument_recorded",
)
TERMINAL_STAGES = ("target_completed", "cleanup_verified")


@dataclass(frozen=True)
class NanoClawL2RunRequest:
    campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    out_dir: Path = ...
    attempts: int = 3
    timeout: int = 150
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
        if row.get("project") == "nanoclaw"
    }
    expected = set(TARGET_CANDIDATES)
    if not expected.issubset(selected):
        missing = sorted(expected - set(selected))
        raise ValidationError(
            "NanoClaw targeted L2 source campaign is missing GT-linked candidates: "
            + ", ".join(missing),
        )
    if candidate_id is not None:
        if candidate_id not in expected:
            raise ValidationError(
                "requested NanoClaw candidate is not a GT-linked targeted L2 candidate"
            )
        return [selected[candidate_id]]
    return [selected[candidate_id] for candidate_id in TARGET_CANDIDATES]


def _source_bindings(cases: list[Mapping[str, Any]]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    required_files = {
        "package.json",
        "pnpm-lock.yaml",
        "tsconfig.json",
        "src/index.ts",
        "src/container-runner.ts",
        "src/delivery.ts",
        "src/providers/index.ts",
        "src/providers/claude.ts",
        "src/session-manager.ts",
        "src/modules/agent-to-agent/agent-route.ts",
        "container/Dockerfile",
        "container/agent-runner/package.json",
        "container/agent-runner/bun.lock",
        "container/agent-runner/src/index.ts",
        "container/agent-runner/src/mcp-tools/server.ts",
        "container/agent-runner/src/mcp-tools/core.ts",
        "container/agent-runner/src/providers/claude.ts",
    }
    for case in cases:
        if case.get("revision") != PROJECT.analysis_revision:
            raise ValidationError("NanoClaw case revision does not match registry")
        for row in case["source_binding"]["files"]:
            relative = str(row["path"])
            source = SOURCE_ROOT / relative
            if not source.is_file():
                raise ValidationError(f"NanoClaw bound source is missing: {relative}")
            expected = str(row["sha256"])
            actual = sha256_file(source)
            if actual != expected:
                raise ValidationError(f"NanoClaw bound source hash drift: {relative}")
            required_files.add(relative)
    for relative in sorted(required_files):
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"NanoClaw infrastructure source is missing: {relative}")
        bindings[relative] = sha256_file(source)
    return bindings


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(f"NanoClaw instrumentation marker mismatch ({label}): {count}")
    return source.replace(old, new, 1)


def _container_helper() -> str:
    return r'''import { appendFileSync, copyFileSync, realpathSync } from "node:fs";

let handlerObserved = false;

function event(stage: string, detail: Record<string, unknown>): void {
  const target = process.env.CLAWGAP_L2_EVENT_PATH;
  if (!target) return;
  appendFileSync(target, JSON.stringify({
    schema_version: "clawgap-dynamic-trigger-nanoclaw-l2-event/v1",
    stage,
    candidate_id: process.env.CLAWGAP_L2_CANDIDATE_ID,
    case_id: process.env.CLAWGAP_L2_CASE_ID,
    attempt: Number(process.env.CLAWGAP_L2_ATTEMPT ?? "0"),
    role: process.env.CLAWGAP_L2_ROLE,
    correlation_id: process.env.CLAWGAP_L2_CORRELATION_ID,
    fixture_id: process.env.CLAWGAP_L2_FIXTURE_ID,
    process: "source-container",
    detail,
  }) + "\n");
}

export function __clawgapContainerReady(): void {
  event("container_ready", { provider: "claude", pid: process.pid });
}

export function __clawgapNativeDispatch(name: string, args: unknown): void {
  event("native_dispatch", { tool_name: name, arguments: args });
}

export function __clawgapHandlerEntered(args: unknown): void {
  handlerObserved = true;
  event("handler_entered", { tool_name: "send_file", arguments: args });
}

export function __clawgapControlledArgument(value: string): void {
  event("controlled_argument_recorded", { argument_path: ["path"], value });
}

export function __clawgapRoutingGate(
  requestedTo: string | undefined,
  routing: Record<string, unknown>,
): void {
  const gateId = process.env.CLAWGAP_L2_EXPECTED_GATE_ID;
  if (!gateId) return;
  event("gate_observed", {
    gate_ids: [gateId],
    admitted: !("error" in routing),
    requested_to: requestedTo ?? null,
    resolved_name: routing.resolvedName ?? null,
  });
}

export function __clawgapMissingCheckBoundary(resolvedPath: string): void {
  if (process.env.CLAWGAP_L2_EXPECTED_GATE_ID) return;
  let real: string | null = null;
  try { real = realpathSync(resolvedPath); } catch { real = null; }
  event("missing_check_boundary_confirmed", {
    gate_required: true,
    gate_present: false,
    resolved_path: resolvedPath,
    resolved_path_real: real,
    source_inside_permitted_root:
      real !== null && (real === "/workspace/agent" || real.startsWith("/workspace/agent/")),
  });
}

export function __clawgapCopyFile(source: string, destination: string, anchor: string): void {
  if (!handlerObserved) {
    copyFileSync(source, destination);
    return;
  }
  let real: string | null = null;
  try { real = realpathSync(source); } catch { real = null; }
  const detail = {
    sink_anchor: anchor,
    source,
    destination,
    source_real: real,
    source_inside_permitted_root:
      real !== null && (real === "/workspace/agent" || real.startsWith("/workspace/agent/")),
  };
  event("sink_reached", detail);
  if (process.env.CLAWGAP_L2_TERMINAL_COPY_SINK === "true") {
    event("pre_effect_interception", { ...detail, executed: false });
    return;
  }
  copyFileSync(source, destination);
}
'''


def _host_helper() -> str:
    return r'''import { appendFileSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import type { VolumeMount } from "./providers/provider-container-registry.js";

function event(stage: string, detail: Record<string, unknown>): void {
  const target = process.env.CLAWGAP_L2_EVENT_PATH;
  if (!target) return;
  appendFileSync(target, JSON.stringify({
    schema_version: "clawgap-dynamic-trigger-nanoclaw-l2-event/v1",
    stage,
    candidate_id: process.env.CLAWGAP_L2_CANDIDATE_ID,
    case_id: process.env.CLAWGAP_L2_CASE_ID,
    attempt: Number(process.env.CLAWGAP_L2_ATTEMPT ?? "0"),
    role: process.env.CLAWGAP_L2_ROLE,
    correlation_id: process.env.CLAWGAP_L2_CORRELATION_ID,
    fixture_id: process.env.CLAWGAP_L2_FIXTURE_ID,
    process: "host",
    detail,
  }) + "\n");
}

export function __clawgapOneCliBoundary(detail: Record<string, unknown>): void {
  event("onecli_gateway_boundary", {
    ...detail,
    replacement: "internal-loopback-anthropic-provider",
  });
}

export function __clawgapContainerEnvironment(args: string[]): void {
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith("CLAWGAP_L2_") || key === "CLAWGAP_L2_EVENT_PATH") continue;
    args.push("-e", `${key}=${value ?? ""}`);
  }
  args.push("-e", "CLAWGAP_L2_EVENT_PATH=/workspace/events.raw.jsonl");
}

export function __clawgapExtraMounts(): VolumeMount[] {
  const raw = process.env.CLAWGAP_L2_EXTRA_MOUNTS;
  if (!raw) return [];
  return JSON.parse(raw) as VolumeMount[];
}

export function __clawgapDeliveryObserved(msg: Record<string, unknown>): void {
  event("host_delivery_observed", {
    message_id: msg.id,
    channel_type: msg.channel_type,
    platform_id: msg.platform_id,
    content: msg.content,
  });
}

export function __clawgapA2aCopy(
  source: string,
  destination: string,
  targetInboxDir: string,
  filename: string,
  anchor: string,
): void {
  const targetInboxRoot = path.dirname(targetInboxDir);
  let targetSymlink = false;
  try { targetSymlink = lstatSync(targetInboxRoot).isSymbolicLink(); } catch {}
  let targetInboxRootReal: string | null = null;
  try { targetInboxRootReal = realpathSync(targetInboxRoot); } catch {}
  const targetInside = !targetSymlink && (
    targetInboxDir === targetInboxRoot ||
    targetInboxDir.startsWith(targetInboxRoot + path.sep)
  );
  let sourceReal: string | null = null;
  let destinationReal: string | null = null;
  try { sourceReal = realpathSync(source); } catch {}
  try { destinationReal = realpathSync(destination); } catch {}
  const detail = {
    sink_anchor: anchor,
    source,
    destination,
    source_real: sourceReal,
    destination_real: destinationReal,
    target_inbox_dir: targetInboxDir,
    target_inbox_root: targetInboxRoot,
    target_inbox_root_real: targetInboxRootReal,
    target_inbox_symlink: targetSymlink,
    target_inside_session_inbox: targetInside,
    filename,
  };
  event("sink_reached", detail);
  event("pre_effect_interception", { ...detail, executed: false });
}

export async function __clawgapWakeAfterSink<T extends { id: string }>(
  session: T,
  wake: (session: T) => Promise<boolean>,
): Promise<boolean> {
  if (process.env.CLAWGAP_L2_SUPPRESS_POST_SINK_WAKE === "true") {
    event("post_sink_target_wake_suppressed", { session_id: session.id });
    return false;
  }
  return wake(session);
}
'''


def _provider_server() -> str:
    return r'''import fs from "node:fs";
import http from "node:http";

const identity = {
  schema_version: "clawgap-dynamic-trigger-nanoclaw-l2-event/v1",
  candidate_id: process.env.CLAWGAP_L2_CANDIDATE_ID,
  case_id: process.env.CLAWGAP_L2_CASE_ID,
  attempt: Number(process.env.CLAWGAP_L2_ATTEMPT ?? 0),
  role: process.env.CLAWGAP_L2_ROLE,
  correlation_id: process.env.CLAWGAP_L2_CORRELATION_ID,
  fixture_id: process.env.CLAWGAP_L2_FIXTURE_ID,
  process: "provider",
};
const expectedArguments = JSON.parse(process.env.CLAWGAP_L2_ARGUMENTS);
const expectedTool = process.env.CLAWGAP_L2_NATIVE_TOOL_NAME;
const expectedModel = process.env.CLAWGAP_L2_MODEL;
let requestCount = 0;
let mainRequestCount = 0;

function write(file, row) {
  fs.appendFileSync(file, JSON.stringify(row) + "\n");
}
function event(stage, detail = {}) {
  if (process.env.CLAWGAP_L2_EVENT_PATH) {
    write(process.env.CLAWGAP_L2_EVENT_PATH, { ...identity, stage, detail });
  }
}
function record(body, valid, reason) {
  if (process.env.CLAWGAP_L2_PROVIDER_TRANSCRIPT) {
    write(process.env.CLAWGAP_L2_PROVIDER_TRANSCRIPT, {
      schema_version: "clawgap-runtime-provider-transcript/v1",
      valid,
      reason,
      protocol: "anthropic-messages/v1",
      method: "POST",
      path: "/v1/messages",
      body,
      authorization: "[REDACTED_CREDENTIAL]",
    });
  }
  event("provider_request", { valid, reason, request_number: requestCount });
}
function sse(res, rows) {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  for (const [name, data] of rows) {
    if (name) res.write(`event: ${name}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  }
  res.end();
}
function messageStart(model) {
  return ["message_start", {
    type: "message_start",
    message: {
      id: "msg_01T1x1fJ34qAmk2tNTrN7Up6",
      type: "message",
      role: "assistant",
      model,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 0, output_tokens: 0 },
    },
  }];
}
function toolResponse(model) {
  return [
    messageStart(model),
    ["ping", { type: "ping" }],
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_01T1x1fJ34qAmk2tNTrN7Up6", name: expectedTool, input: {} } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: "" } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(expectedArguments) } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 0 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}
function finalResponse(model) {
  const destination = expectedArguments.to ?? "default";
  return [
    messageStart(model),
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: `<message to="${destination}">ClawGap NanoClaw L2 turn complete.</message>` } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 4 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}
function titleResponse(model) {
  return [
    messageStart(model),
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "{\"title\":\"ClawGap NanoClaw Probe\"}" } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 7 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}
  const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", chunk => chunks.push(chunk));
  req.on("end", () => {
    const raw = Buffer.concat(chunks).toString("utf8");
    const path = (req.url || "").split("?")[0];
    if (req.method === "HEAD" && path === "/") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("clawgap-provider-ready");
      return;
    }
    requestCount += 1;
    if (req.method !== "POST" || path !== "/v1/messages") {
      record(null, false, `unsupported provider endpoint: ${req.method} ${path}`);
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { type: "not_found", message: "unsupported endpoint" } }));
      return;
    }
    let body = null;
    try { body = JSON.parse(raw || "{}"); } catch {}
    const tools = Array.isArray(body?.tools) ? body.tools : [];
    const toolNames = tools.map(tool => tool?.name).filter(Boolean);
    if (tools.length === 0) {
      record(body, true, "auxiliary Claude Code title-generation request");
      event("provider_auxiliary_request", { purpose: "title-generation" });
      return sse(res, titleResponse(body.model));
    }
    const valid = Boolean(
      body &&
      Array.isArray(body.messages) &&
      body.messages.length > 0 &&
      body.model === expectedModel &&
      toolNames.includes(expectedTool) &&
      req.headers.authorization === `Bearer ${process.env.CLAWGAP_L2_PROVIDER_CREDENTIAL}`
    );
    record(body, valid, valid ? "" : "invalid Anthropic provider request");
    if (!valid) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { type: "invalid_request_error", message: "request contract mismatch" } }));
      return;
    }
    mainRequestCount += 1;
    if (mainRequestCount === 1) {
      event("provider_tool_call", {
        tool_name: expectedTool,
        project_tool_name: "send_file",
        arguments: expectedArguments,
      });
    } else if (mainRequestCount > 2) {
      res.writeHead(409, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { type: "api_error", message: "too many provider requests" } }));
      return;
    }
    const model = body.model;
    if (body.stream === true) {
      return sse(res, mainRequestCount === 1 ? toolResponse(model) : finalResponse(model));
    }
    const payload = mainRequestCount === 1 ? {
      id: "msg_clawgap_nanoclaw_l2",
      type: "message",
      role: "assistant",
      model,
      content: [{ type: "tool_use", id: "toolu_clawgap_nanoclaw_l2", name: expectedTool, input: expectedArguments }],
      stop_reason: "tool_use",
      usage: { input_tokens: 0, output_tokens: 0 },
    } : {
      id: "msg_clawgap_nanoclaw_l2_final",
      type: "message",
      role: "assistant",
      model,
      content: [{ type: "text", text: `<message to="${expectedArguments.to ?? "default"}">ClawGap NanoClaw L2 turn complete.</message>` }],
      stop_reason: "end_turn",
      usage: { input_tokens: 0, output_tokens: 4 },
    };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  });
});
const listener = server.listen(Number(process.env.CLAWGAP_L2_PROVIDER_PORT), "0.0.0.0", () => {
  fs.writeFileSync(process.env.CLAWGAP_L2_PROVIDER_READY, `${JSON.stringify({ ready: true, port: listener.address().port })}\n`);
});
'''


def _seed_script() -> str:
    return r'''import fs from "node:fs";
import path from "node:path";
import { initDb, closeDb } from "./src/db/connection.js";
import { runMigrations } from "./src/db/migrations/index.js";
import { createAgentGroup } from "./src/db/agent-groups.js";
import { ensureContainerConfig, updateContainerConfigScalars, updateContainerConfigJson } from "./src/db/container-configs.js";
import { resolveSession, writeSessionMessage } from "./src/session-manager.js";
import { createDestination } from "./src/modules/agent-to-agent/db/agent-destinations.js";
import { initGroupFilesystem } from "./src/group-init.js";

const config = JSON.parse(fs.readFileSync(process.env.CLAWGAP_L2_SEED_CONFIG!, "utf8"));
const db = initDb(path.resolve("data/v2.db"));
runMigrations(db);
const now = new Date().toISOString();
for (const group of config.groups) {
  const entity = { id: group.id, name: group.name, folder: group.folder, agent_provider: null, created_at: now };
  createAgentGroup(entity);
  initGroupFilesystem(entity);
  ensureContainerConfig(group.id);
  updateContainerConfigScalars(group.id, {
    provider: "claude",
    model: config.model,
    image_tag: config.image_tag,
    assistant_name: group.name,
    max_messages_per_prompt: 1,
  });
  updateContainerConfigJson(group.id, "skills", []);
  updateContainerConfigJson(group.id, "mcp_servers", {});
  updateContainerConfigJson(group.id, "packages_apt", []);
  updateContainerConfigJson(group.id, "packages_npm", []);
  updateContainerConfigJson(group.id, "additional_mounts", []);
}
for (const destination of config.destinations) {
  createDestination({ ...destination, created_at: now });
}
const sessions: Record<string, string> = {};
for (const group of config.groups) {
  sessions[group.id] = resolveSession(group.id, null, null, "agent-shared").session.id;
}
const sourceGroup = config.groups[0];
if (config.target_inbox_symlink) {
  const targetGroup = config.groups[1];
  const inbox = path.resolve("data/v2-sessions", targetGroup.id, sessions[targetGroup.id], "inbox");
  fs.mkdirSync(config.outside_destination, { recursive: true });
  fs.rmSync(inbox, { force: true });
  fs.symlinkSync(config.outside_destination, inbox);
}
for (const file of config.files ?? []) {
  const target = path.resolve("groups", sourceGroup.folder, file.path);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  if (file.symlink_target) {
    fs.rmSync(target, { force: true });
    fs.symlinkSync(file.symlink_target, target);
  } else {
    fs.writeFileSync(target, file.content);
  }
}
writeSessionMessage(sourceGroup.id, sessions[sourceGroup.id], {
  id: config.message_id,
  kind: "chat",
  timestamp: now,
  platformId: null,
  channelType: null,
  threadId: null,
  content: JSON.stringify({ sender: "ClawGap", text: "environment probe" }),
});
fs.writeFileSync(config.result_path, `${JSON.stringify({ sessions }, null, 2)}\n`);
closeDb();
'''


def _render_build_copy(
    destination: Path, source_bindings: Mapping[str, str]
) -> dict[str, dict[str, str]]:
    project = destination / "project"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    shutil.copytree(
        SOURCE_ROOT,
        project,
        ignore=shutil.ignore_patterns(
            ".git", "node_modules", "dist", "data", "groups", "store"
        ),
    )
    shutil.copytree(
        SOURCE_ROOT / "node_modules",
        project / "node_modules",
        symlinks=True,
    )
    (project / "src" / "clawgap-l2.ts").write_text(_host_helper(), encoding="utf-8")
    (
        project / "container/agent-runner/src/clawgap-l2.ts"
    ).write_text(_container_helper(), encoding="utf-8")
    (project / "clawgap-provider.mjs").write_text(_provider_server(), encoding="utf-8")
    (project / "clawgap-seed.ts").write_text(_seed_script(), encoding="utf-8")
    transformed: dict[str, dict[str, str]] = {}

    def bind(path: Path) -> None:
        relative = str(path.relative_to(project))
        transformed[relative] = {
            "original_sha256": source_bindings[relative],
            "transformed_sha256": sha256_file(path),
        }

    dockerfile_path = project / "container/Dockerfile"
    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    dockerfile = _replace_once(
        dockerfile,
        "RUN curl -fsSL https://bun.sh/install | bash -s \"bun-v${BUN_VERSION}\" && \\\n"
        "    install -m 0755 /root/.bun/bin/bun /usr/local/bin/bun && \\\n"
        "    rm -rf /root/.bun",
        "COPY --from=oven/bun@sha256:c9aa897b6028d54e510c4babd41bcdd481ad4a4b5030ad31135a9cabfe2c24df "
        "/usr/local/bin/bun /usr/local/bin/bun",
        "pinned Bun binary source",
    )
    dockerfile_path.write_text(dockerfile, encoding="utf-8")
    bind(dockerfile_path)

    provider_index_path = project / "src/providers/index.ts"
    provider_index = provider_index_path.read_text(encoding="utf-8")
    if "import './claude.js';" not in provider_index:
        provider_index += "\nimport './claude.js';\n"
    provider_index_path.write_text(provider_index, encoding="utf-8")
    bind(provider_index_path)

    provider_path = project / "src/providers/claude.ts"
    provider = provider_path.read_text(encoding="utf-8")
    provider = _replace_once(
        provider,
        "const dotenv = readEnvFile(['ANTHROPIC_BASE_URL']);",
        "const dotenv = readEnvFile(['ANTHROPIC_BASE_URL']);\n"
        "const anthropicBaseUrl = process.env.ANTHROPIC_BASE_URL || dotenv.ANTHROPIC_BASE_URL;",
        "provider base URL precedence",
    )
    provider = _replace_once(
        provider,
        "if (dotenv.ANTHROPIC_BASE_URL) {\n"
        "    env.ANTHROPIC_BASE_URL = dotenv.ANTHROPIC_BASE_URL;\n"
        "    env.ANTHROPIC_AUTH_TOKEN = 'placeholder';",
        "if (anthropicBaseUrl) {\n"
        "    env.ANTHROPIC_BASE_URL = anthropicBaseUrl;\n"
        "    env.ANTHROPIC_AUTH_TOKEN = process.env.CLAWGAP_L2_PROVIDER_CREDENTIAL || 'placeholder';",
        "provider credential adapter",
    )
    provider_path.write_text(provider, encoding="utf-8")
    bind(provider_path)

    runner_path = project / "src/container-runner.ts"
    runner = runner_path.read_text(encoding="utf-8")
    runner = (
        "import { __clawgapContainerEnvironment, __clawgapExtraMounts, "
        "__clawgapOneCliBoundary } from './clawgap-l2.js';\n" + runner
    )
    runner = _replace_once(
        runner,
        "const args: string[] = ['run', '--rm', '--name', containerName, '--label', CONTAINER_INSTALL_LABEL];",
        "const args: string[] = ['run', '--rm', '--name', containerName, '--label', CONTAINER_INSTALL_LABEL, "
        "'--label', process.env.CLAWGAP_L2_ROLE_LABEL ?? ''];",
        "container role label",
    )
    runner = _replace_once(
        runner,
        "  if (providerContribution.env) {\n"
        "    for (const [key, value] of Object.entries(providerContribution.env)) {\n"
        "      args.push('-e', `${key}=${value}`);\n"
        "    }\n"
        "  }",
        "  if (providerContribution.env) {\n"
        "    for (const [key, value] of Object.entries(providerContribution.env)) {\n"
        "      args.push('-e', `${key}=${value}`);\n"
        "    }\n"
        "  }\n"
        "  __clawgapContainerEnvironment(args);",
        "container environment adapter",
    )
    runner = _replace_once(
        runner,
        "  if (agentIdentifier) {\n"
        "    await onecli.ensureAgent({ name: agentGroup.name, identifier: agentIdentifier });\n"
        "  }\n"
        "  const onecliApplied = await onecli.applyContainerConfig(args, { addHostMapping: false, agent: agentIdentifier });\n"
        "  if (!onecliApplied) {\n"
        "    throw new Error('OneCLI gateway not applied — refusing to spawn container without credentials');\n"
        "  }\n"
        "  log.info('OneCLI gateway applied', { containerName });",
        "  if (agentIdentifier) {\n"
        "    __clawgapOneCliBoundary({ agentIdentifier, containerName });\n"
        "  }",
        "OneCLI loopback boundary",
    )
    runner = _replace_once(
        runner,
        "  const mounts: VolumeMount[] = [];",
        "  const mounts: VolumeMount[] = [];",
        "role fixture mounts",
    )
    runner = _replace_once(
        runner,
        "  return mounts;",
        "  return [...mounts, ...__clawgapExtraMounts()];",
        "role fixture mount precedence",
    )
    runner_path.write_text(runner, encoding="utf-8")
    bind(runner_path)

    delivery_path = project / "src/delivery.ts"
    delivery = delivery_path.read_text(encoding="utf-8")
    delivery = (
        "import { __clawgapDeliveryObserved } from './clawgap-l2.js';\n" + delivery
    )
    delivery = _replace_once(
        delivery,
        "        const platformMsgId = await deliverMessage(msg, session, inDb);",
        "        __clawgapDeliveryObserved(msg as unknown as Record<string, unknown>);\n"
        "        const platformMsgId = await deliverMessage(msg, session, inDb);",
        "delivery observation",
    )
    delivery_path.write_text(delivery, encoding="utf-8")
    bind(delivery_path)

    route_path = project / "src/modules/agent-to-agent/agent-route.ts"
    route = route_path.read_text(encoding="utf-8")
    route = (
        "import { __clawgapA2aCopy, __clawgapWakeAfterSink } from '../../clawgap-l2.js';\n"
        + route
    )
    route = _replace_once(
        route,
        "    fs.copyFileSync(realSrc, dst);",
        "    __clawgapA2aCopy(realSrc, dst, targetInboxDir, filename, "
        "'src/modules/agent-to-agent/agent-route.ts:138');",
        "A2A terminal sink",
    )
    route = _replace_once(
        route,
        "  if (fresh) await wakeContainer(fresh);",
        "  if (fresh) await __clawgapWakeAfterSink(fresh, wakeContainer);",
        "post-sink wake boundary",
    )
    route_path.write_text(route, encoding="utf-8")
    bind(route_path)

    server_path = project / "container/agent-runner/src/mcp-tools/server.ts"
    server = server_path.read_text(encoding="utf-8")
    server = "import { __clawgapNativeDispatch } from '../clawgap-l2.js';\n" + server
    server = _replace_once(
        server,
        "    return tool.handler(args ?? {});",
        "    __clawgapNativeDispatch(name, args ?? {});\n    return tool.handler(args ?? {});",
        "native MCP dispatch",
    )
    server_path.write_text(server, encoding="utf-8")
    bind(server_path)

    core_path = project / "container/agent-runner/src/mcp-tools/core.ts"
    core = core_path.read_text(encoding="utf-8")
    core = (
        "import { __clawgapControlledArgument, __clawgapCopyFile, "
        "__clawgapHandlerEntered, __clawgapMissingCheckBoundary, __clawgapRoutingGate } "
        "from '../clawgap-l2.js';\n" + core
    )
    core = _replace_once(
        core,
        "  async handler(args) {\n    const filePath = args.path as string;",
        "  async handler(args) {\n    __clawgapHandlerEntered(args);\n"
        "    const filePath = args.path as string;",
        "handler entry",
    )
    core = _replace_once(
        core,
        "    const resolvedPath = path.isAbsolute(filePath) ? filePath : path.resolve('/workspace/agent', filePath);\n"
        "    if (!fs.existsSync(resolvedPath)) return err(`File not found: ${filePath}`);",
        "    const resolvedPath = path.isAbsolute(filePath) ? filePath : path.resolve('/workspace/agent', filePath);\n"
        "    __clawgapControlledArgument(filePath);\n"
        "    const pathExists = fs.existsSync(resolvedPath);\n"
        "    if (!pathExists) return err(`File not found: ${filePath}`);\n"
        "    __clawgapMissingCheckBoundary(resolvedPath);",
        "path guard and missing boundary",
    )
    core = _replace_second_once(
        core,
        "    const routing = resolveRouting(args.to as string | undefined);\n"
        "    if ('error' in routing) return err(routing.error);",
        "    const routing = resolveRouting(args.to as string | undefined);\n"
        "    __clawgapRoutingGate(args.to as string | undefined, routing as Record<string, unknown>);\n"
        "    if ('error' in routing) return err(routing.error);",
        "send_file routing gate",
    )
    core = _replace_once(
        core,
        "    fs.copyFileSync(resolvedPath, path.join(outboxDir, filename));",
        "    __clawgapCopyFile(resolvedPath, path.join(outboxDir, filename), "
        "'container/agent-runner/src/mcp-tools/core.ts:164');",
        "container copy sink",
    )
    core_path.write_text(core, encoding="utf-8")
    bind(core_path)

    container_index_path = project / "container/agent-runner/src/index.ts"
    container_index = container_index_path.read_text(encoding="utf-8")
    container_index = (
        "import { __clawgapContainerReady } from './clawgap-l2.js';\n"
        + container_index
    )
    container_index = _replace_once(
        container_index,
        "  log(`Starting v2 agent-runner (provider: ${providerName})`);",
        "  log(`Starting v2 agent-runner (provider: ${providerName})`);\n"
        "  __clawgapContainerReady();",
        "container readiness",
    )
    container_index_path.write_text(container_index, encoding="utf-8")
    bind(container_index_path)

    for relative in (
        "src/clawgap-l2.ts",
        "container/agent-runner/src/clawgap-l2.ts",
        "clawgap-provider.mjs",
        "clawgap-seed.ts",
    ):
        transformed[relative] = {
            "original_sha256": sha256_file(SOURCE_ROOT / relative)
            if (SOURCE_ROOT / relative).is_file()
            else "",
            "transformed_sha256": sha256_file(project / relative),
        }
    return transformed


def _run(command: list[str], *, cwd: Path, log_path: Path, timeout: int) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as stream:
        process = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    if process.returncode != 0:
        raise ValidationError(
            f"NanoClaw build command failed with exit {process.returncode}: "
            f"{' '.join(command)}"
        )


def _image_tag(source_bindings: Mapping[str, str]) -> str:
    identity = canonical_json(
        {"revision": PROJECT.analysis_revision, "files": dict(source_bindings)}
    ).encode("utf-8")
    return f"clawgap-nanoclaw-agent:{hashlib.sha256(identity).hexdigest()[:24]}"


def _prepare_build(
    directory: Path, source_bindings: Mapping[str, str], build_timeout: int
) -> dict[str, Any]:
    manifest_path = directory / "transformed-source-manifest.json"
    tag = _image_tag(source_bindings)
    project = directory / "project"
    if (
        manifest_path.is_file()
        and (directory / "image.json").is_file()
        and (directory / "build.log").is_file()
    ):
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (
                prior.get("revision") == PROJECT.analysis_revision
                and prior.get("image_tag") == tag
                and prior.get("source_bindings") == dict(source_bindings)
                and prior.get("harness_sha256")
                == sha256_file(REPO_ROOT / "src/runtime_validation/nanoclaw_l2.py")
                and Path(str(prior.get("project_root", ""))).resolve()
                == project.resolve()
            ):
                return prior
        except (OSError, json.JSONDecodeError):
            pass

    transformed = _render_build_copy(directory, source_bindings)
    _run(
        ["pnpm", "rebuild", "better-sqlite3"],
        cwd=project,
        log_path=directory / "native-build.log",
        timeout=build_timeout,
    )
    _run(
        ["pnpm", "run", "build"],
        cwd=project,
        log_path=directory / "build.log",
        timeout=build_timeout,
    )
    _run(
        [
            "docker",
            "build",
            "--build-arg",
            "AGENT_BROWSER_VERSION=0.34.0",
            "-t",
            tag,
            ".",
        ],
        cwd=project / "container",
        log_path=directory / "image-build.log",
        timeout=build_timeout,
    )
    inspect = subprocess.run(
        ["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if inspect.returncode != 0 or not inspect.stdout.strip():
        raise ValidationError("NanoClaw container image identity inspection failed")
    manifest = {
        "schema_version": "clawgap-nanoclaw-transformed-source-manifest/v1",
        "revision": PROJECT.analysis_revision,
        "source_bindings": dict(source_bindings),
        "transformed_files": transformed,
        "source_drift": False,
        "dependency_lockfile": sha256_file(SOURCE_ROOT / "pnpm-lock.yaml"),
        "agent_runner_lockfile": sha256_file(
            SOURCE_ROOT / "container/agent-runner/bun.lock"
        ),
        "image_tag": tag,
        "image_digest": inspect.stdout.strip(),
        "harness_sha256": sha256_file(
            REPO_ROOT / "src/runtime_validation/nanoclaw_l2.py"
        ),
        "project_root": str(project.resolve()),
        "generation_command": "run-dynamic-trigger-nanoclaw-l2",
    }
    atomic_write_json(manifest_path, manifest)
    atomic_write_json(
        directory / "image.json",
        {"tag": tag, "digest": inspect.stdout.strip()},
    )
    return manifest


def _role_arguments(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    return dict(
        next(row["arguments"] for row in case["forced_tool_calls"] if row["role"] == role)
    )


def _controlled_value(case: Mapping[str, Any], role: str) -> Any:
    value: Any = _role_arguments(case, role)
    for part in case["unsafe_relation"]["argument_path"]:
        value = value[part]
    return value


def _base_event(
    stage: str,
    detail: Mapping[str, Any],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    correlation_id: str,
    fixture_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "stage": stage,
        "candidate_id": str(case["candidate_binding"]["candidate_id"]),
        "case_id": str(case["case_id"]),
        "attempt": attempt,
        "role": role,
        "correlation_id": correlation_id,
        "fixture_id": fixture_id,
        "process": "harness",
        "detail": dict(detail),
    }


def _expected_stages(case: Mapping[str, Any], role: str) -> list[str]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    stages = [*BASE_STAGES[:-1]]
    if candidate_id == "CAND-79fbf2f6a976c935":
        stages.append("gate_observed")
    stages.append(BASE_STAGES[-1])
    if candidate_id != "CAND-79fbf2f6a976c935":
        stages.append("missing_check_boundary_confirmed")
    if candidate_id in A2A_CANDIDATES:
        stages.extend(
            ["host_delivery_observed", "sink_reached", "pre_effect_interception"]
        )
    else:
        stages.extend(["sink_reached", "pre_effect_interception"])
    stages.extend(TERMINAL_STAGES)
    return stages


def _normalize_events(path: Path) -> list[dict[str, Any]]:
    rows = _read_jsonl(path)
    candidate_ids = {
        str(row.get("candidate_id"))
        for row in rows
        if row.get("candidate_id") is not None
    }
    a2a_candidate = any(
        candidate_id in A2A_CANDIDATES for candidate_id in candidate_ids
    )
    normalized: list[dict[str, Any]] = []
    seen_provider_request = False
    seen_host_delivery = False
    for row_index, row in enumerate(rows):
        if any(row.get(field) is None for field in IDENTITY_FIELDS):
            continue
        stage = str(row.get("stage"))
        if stage in {
            "onecli_gateway_boundary",
            "provider_auxiliary_request",
            "post_sink_target_wake_suppressed",
        }:
            continue
        if (
            stage == "provider_request"
            and row_index + 1 < len(rows)
            and str(rows[row_index + 1].get("stage"))
            == "provider_auxiliary_request"
        ):
            continue
        if stage == "host_delivery_observed":
            if not a2a_candidate or seen_host_delivery:
                continue
            seen_host_delivery = True
        if (
            a2a_candidate
            and stage == "sink_reached"
            and str(row.get("detail", {}).get("sink_anchor"))
            == "container/agent-runner/src/mcp-tools/core.ts:164"
        ):
            continue
        if stage == "provider_request":
            if seen_provider_request:
                continue
            seen_provider_request = True
        normalized.append(row)
    return normalized


def _stage_errors(rows: list[Mapping[str, Any]], expected: list[str]) -> list[str]:
    actual = [str(row.get("stage")) for row in rows]
    if actual != expected:
        return [f"event stage order mismatch: expected={expected}, actual={actual}"]
    identities = [tuple(row.get(field) for field in IDENTITY_FIELDS) for row in rows]
    if len(set(identities)) != 1:
        return ["event identity drift within normalized role trace"]
    return []


def _sink_matches(
    case: Mapping[str, Any], role: str, sink: Mapping[str, Any]
) -> bool:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    expected = _controlled_value(case, role)
    if candidate_id in ARBITRARY_SOURCE_CANDIDATES:
        return bool(sink.get("source_inside_permitted_root")) is (role == "control")
    if candidate_id == "CAND-79fbf2f6a976c935":
        return sink.get("filename") == expected
    if candidate_id == "CAND-b1bde0d4c06ddc89":
        if role == "exploit":
            return (
                sink.get("target_inbox_symlink") is True
                and sink.get("target_inside_session_inbox") is False
            )
        return (
            sink.get("target_inbox_symlink") is False
            and sink.get("target_inside_session_inbox") is True
        )
    return False


def _transcript_errors(
    transcript: list[Mapping[str, Any]],
) -> list[str]:
    main_rows = [
        row
        for row in transcript
        if isinstance(row.get("body"), dict)
        and isinstance(row["body"].get("tools"), list)
        and bool(row["body"]["tools"])
    ]
    valid = [row for row in main_rows if row.get("valid") is True]
    invalid = [row for row in transcript if row.get("valid") is not True]
    if not 1 <= len(valid) <= 2:
        return ["provider did not observe one or two valid Messages requests"]
    if invalid:
        return ["provider observed unsupported or invalid requests"]
    for row in valid:
        body = row.get("body")
        if not isinstance(body, dict) or body.get("model") != "clawgap-nanoclaw-l2":
            return ["provider request model drift"]
    first = valid[0]
    body = first.get("body")
    tools = body.get("tools", []) if isinstance(body, dict) else []
    names = {str(row.get("name")) for row in tools if isinstance(row, dict)}
    if NATIVE_TOOL_NAME not in names:
        return ["provider request did not advertise the native NanoClaw MCP tool"]
    return []


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    transcript: list[Mapping[str, Any]],
    canary_unchanged: bool,
) -> PairOutcome:
    errors = _stage_errors(events, _expected_stages(case, role))
    errors.extend(_transcript_errors(transcript))
    if not canary_unchanged:
        errors.append("host or outside canary changed")
    tool_calls = [row for row in events if row.get("stage") == "provider_tool_call"]
    if len(tool_calls) != 1:
        errors.append("expected exactly one provider tool-call event")
    elif tool_calls[0].get("detail", {}).get("arguments") != _role_arguments(case, role):
        errors.append("provider tool arguments drifted from reviewed value")
    controlled = [
        row for row in events if row.get("stage") == "controlled_argument_recorded"
    ]
    if (
        len(controlled) != 1
        or controlled[0].get("detail", {}).get("value")
        != _role_arguments(case, role)["path"]
    ):
        errors.append("handler controlled path drifted from reviewed value")
    sinks = [row for row in events if row.get("stage") == "sink_reached"]
    if len(sinks) != 1:
        errors.append("expected exactly one terminal sink event")
    elif not _sink_matches(case, role, sinks[0].get("detail", {})):
        errors.append("terminal sink did not match role-specific witness")
    intercepts = [
        row for row in events if row.get("stage") == "pre_effect_interception"
    ]
    if len(intercepts) != 1 or intercepts[0].get("detail", {}).get("executed") is not False:
        errors.append("terminal effect was not intercepted exactly once")
    if (
        role == "exploit"
        and str(case["candidate_binding"]["candidate_id"])
        == "CAND-b1bde0d4c06ddc89"
    ):
        boundary = next(
            (
                row
                for row in events
                if row.get("stage") == "missing_check_boundary_confirmed"
            ),
            None,
        )
        if boundary is None or boundary.get("detail", {}).get(
            "source_inside_permitted_root"
        ) is not False:
            errors.append(
                "peer-state source symlink did not resolve outside the permitted root"
            )
    triggered = role == "exploit" and not errors
    return PairOutcome(not errors, triggered, errors)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _docker(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def _wait_for(path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for {path}")


def _append_event(row: Mapping[str, Any], path: Path) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")


def _runtime_project(build_project: Path, runtime_root: Path) -> Path:
    runtime_root.mkdir(parents=True, exist_ok=True)
    project = runtime_root / "project"
    project.mkdir()
    for name in (
        "src",
        "dist",
        "container",
        "node_modules",
        "scripts",
        "package.json",
        "pnpm-lock.yaml",
        "tsconfig.json",
        "clawgap-provider.mjs",
        "clawgap-seed.ts",
    ):
        source = (build_project / name).resolve()
        target = project / name
        target.symlink_to(source, target_is_directory=source.is_dir())
    return project


def _chown_runtime(path: Path) -> None:
    if not path.exists():
        return
    for root, directories, files in os.walk(path, followlinks=False):
        for name in directories + files:
            try:
                os.lchown(Path(root) / name, 1000, 1000)
            except OSError:
                return
    try:
        os.chown(path, 1000, 1000)
    except OSError:
        pass


def _terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and process.poll() is None:
        time.sleep(0.1)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _stop_role_containers(network: str, label: str, provider: str) -> list[str]:
    errors: list[str] = []
    listing = _docker(
        ["ps", "-aq", "--filter", f"label={label}", "--filter", f"network={network}"]
    )
    if listing.returncode == 0:
        for container_id in listing.stdout.split():
            stopped = _docker(["stop", container_id], timeout=30)
            if stopped.returncode != 0:
                errors.append(f"failed to stop container {container_id}")
            else:
                _docker(["rm", container_id], timeout=30)
    stopped = _docker(["stop", provider], timeout=30)
    provider_missing = (
        "No such container" in (stopped.stdout or "")
        or "No such object" in (stopped.stdout or "")
    )
    if stopped.returncode != 0 and not provider_missing:
        errors.append(f"failed to stop provider container: {provider}")
    else:
        if not provider_missing:
            _docker(["rm", provider], timeout=30)
    removed = _docker(["network", "rm", network], timeout=30)
    if removed.returncode != 0:
        errors.append(f"failed to remove Docker network {network}")
    return errors


def _capture_container_logs(network: str, label: str, directory: Path) -> None:
    listing = _docker(
        ["ps", "-aq", "--filter", f"label={label}", "--filter", f"network={network}"]
    )
    if listing.returncode != 0:
        return
    for index, container_id in enumerate(listing.stdout.split(), 1):
        logs = _docker(["logs", container_id], timeout=30)
        (directory / f"agent-container-{index}.log").write_text(
            logs.stdout, encoding="utf-8", errors="replace"
        )


def _prepare_role_files(
    case: Mapping[str, Any], role: str, directory: Path, image_tag: str
) -> dict[str, Any]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    arguments = _role_arguments(case, role)
    home = directory / "home"
    temporary = directory / "temporary"
    outside = directory / "outside"
    runtime = directory / "state"
    for path in (home, temporary, outside, runtime):
        path.mkdir(parents=True, exist_ok=True)
    (outside / "destination").mkdir(parents=True, exist_ok=True)
    (outside / "canary.txt").write_text(CANARY_CONTENT, encoding="utf-8")
    (directory / "host-effect-canary.txt").write_text(
        CANARY_CONTENT, encoding="utf-8"
    )
    source_secret = outside / "source-secret.txt"
    source_secret.write_text("CLAWGAP-NANOCLAW-SECRET\n", encoding="utf-8")
    extra_mounts: list[dict[str, Any]] = []
    extra_mounts.append(
        {
            "hostPath": str(directory / "events.raw.jsonl"),
            "containerPath": "/workspace/events.raw.jsonl",
            "readonly": False,
        }
    )
    files: list[dict[str, str]] = []
    if candidate_id in ARBITRARY_SOURCE_CANDIDATES:
        files.append({"path": "notes.txt", "content": "clawgap-safe-control-note\n"})
        extra_mounts.append(
            {
                "hostPath": str(source_secret),
                "containerPath": "/workspace/secret.txt",
                "readonly": True,
            }
        )
    elif candidate_id == "CAND-79fbf2f6a976c935":
        files.append({"path": "secret.txt", "content": "CLAWGAP-A2A-SOURCE\n"})
    elif candidate_id == "CAND-b1bde0d4c06ddc89":
        if role == "exploit":
            files.append(
                {
                    "path": "exploit.txt",
                    "content": "CLAWGAP-NANOCLAW-EXPLOIT\n",
                    "symlink_target": "/workspace/secret-source/exploit.txt",
                }
            )
            extra_mounts.append(
                {
                    "hostPath": str(source_secret),
                    "containerPath": "/workspace/secret-source/exploit.txt",
                    "readonly": True,
                }
            )
        else:
            files.append(
                {"path": "control.txt", "content": "clawgap-safe-control\n"}
            )
    target_local_name = (
        "target-agent" if candidate_id == "CAND-b1bde0d4c06ddc89" else "target"
    )
    seed_config = {
        "model": "clawgap-nanoclaw-l2",
        "image_tag": image_tag,
        "message_id": f"clawgap-{role}-{uuid.uuid4().hex[:8]}",
        "outside_destination": str(outside / "destination"),
        "target_inbox_symlink": candidate_id in A2A_CANDIDATES and role == "exploit",
        "groups": [
            {"id": "ag-source", "name": "ClawGap Source", "folder": "source"},
            {"id": "ag-target", "name": "ClawGap Target", "folder": "target"},
        ],
        "destinations": [
            {
                "agent_group_id": "ag-source",
                "local_name": "default"
                if candidate_id in ARBITRARY_SOURCE_CANDIDATES
                else target_local_name,
                "target_type": "agent",
                "target_id": "ag-target",
            }
        ],
        "files": files,
        "result_path": str(directory / "seed-result.json"),
    }
    atomic_write_json(directory / "seed-config.json", seed_config)
    fixture = {
        "arguments": arguments,
        "extra_mounts": extra_mounts,
        "outside_root": str(outside),
        "target_inbox_symlink": seed_config["target_inbox_symlink"],
        "source_files": files,
    }
    atomic_write_json(directory / "fixture-manifest.json", fixture)
    return fixture


def _run_role_attempt(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    build_manifest: Mapping[str, Any],
    request: NanoClawL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    directory.mkdir(parents=True, exist_ok=True)
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    correlation_id = f"nc-{case['case_id']}-{attempt}-{role}-{uuid.uuid4().hex[:8]}"
    fixture_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:16]
    fixture = _prepare_role_files(
        case, role, directory, str(build_manifest["image_tag"])
    )
    runtime_root = Path("/tmp") / f"clawgap-nc-{fixture_id}"
    project = _runtime_project(build_project, runtime_root)
    event_path = directory / "events.raw.jsonl"
    transcript_path = directory / "provider-transcript.jsonl"
    provider_ready = directory / "provider-ready.json"
    canary = directory / "host-effect-canary.txt"
    outside_canary = directory / "outside/canary.txt"
    network = f"clawgap-nc-{uuid.uuid4().hex[:12]}"
    label = f"clawgap-nanoclaw-l2={fixture_id}"
    provider_container = f"clawgap-nc-provider-{uuid.uuid4().hex[:12]}"
    provider_script = build_project / "clawgap-provider.mjs"
    port = _free_port()
    host_process: subprocess.Popen[str] | None = None
    errors: list[str] = []
    initial_details = {
        "case_bound": {"revision": PROJECT.analysis_revision},
        "source_verified": {
            "source_bindings": len(build_manifest["source_bindings"])
        },
        "image_verified": {
            "tag": build_manifest["image_tag"],
            "digest": build_manifest["image_digest"],
        },
        "fixture_prepared": fixture,
        "host_launch_started": {"entrypoint": "node dist/index.js"},
    }
    for stage, detail in initial_details.items():
        _append_event(
            _base_event(
                stage, detail, case, attempt, role, correlation_id, fixture_id
            ),
            event_path,
        )
    os.chmod(event_path, 0o666)
    transcript_path.touch()
    os.chmod(transcript_path, 0o666)
    try:
        created = _docker(["network", "create", "--internal", network])
        if created.returncode != 0:
            raise RuntimeError(f"Docker network creation failed: {created.stdout}")
        provider_command = [
            "run",
            "-d",
            "--name",
            provider_container,
            "--network",
            network,
            "--network-alias",
            "host.docker.internal",
            "--label",
            label,
            "--user",
            "0:0",
            "-e",
            f"CLAWGAP_L2_PROVIDER_PORT={port}",
            "-e",
            f"CLAWGAP_L2_CANDIDATE_ID={candidate_id}",
            "-e",
            f"CLAWGAP_L2_CASE_ID={case['case_id']}",
            "-e",
            f"CLAWGAP_L2_ATTEMPT={attempt}",
            "-e",
            f"CLAWGAP_L2_ROLE={role}",
            "-e",
            f"CLAWGAP_L2_CORRELATION_ID={correlation_id}",
            "-e",
            f"CLAWGAP_L2_FIXTURE_ID={fixture_id}",
            "-e",
            f"CLAWGAP_L2_ARGUMENTS={json.dumps(fixture['arguments'], sort_keys=True, separators=(',', ':'))}",
            "-e",
            f"CLAWGAP_L2_NATIVE_TOOL_NAME={NATIVE_TOOL_NAME}",
            "-e",
            "CLAWGAP_L2_MODEL=clawgap-nanoclaw-l2",
            "-e",
            "CLAWGAP_L2_PROVIDER_CREDENTIAL=clawgap-loopback-mock",
            "-e",
            "CLAWGAP_L2_PROVIDER_TRANSCRIPT=/evidence/provider-transcript.jsonl",
            "-e",
            "CLAWGAP_L2_EVENT_PATH=/evidence/events.raw.jsonl",
            "-e",
            "CLAWGAP_L2_PROVIDER_READY=/evidence/provider-ready.json",
            "-v",
            f"{directory.resolve()}:/evidence:rw",
            "-v",
            f"{provider_script.resolve()}:/provider.mjs:ro",
            "--entrypoint",
            "node",
            str(build_manifest["image_tag"]),
            "/provider.mjs",
        ]
        provider = _docker(provider_command)
        if provider.returncode != 0:
            raise RuntimeError(f"provider container failed: {provider.stdout}")
        try:
            _wait_for(provider_ready, 15)
        except Exception:
            logs = _docker(["logs", provider_container], timeout=15)
            (directory / "provider.log").write_text(
                logs.stdout, encoding="utf-8", errors="replace"
            )
            raise RuntimeError(f"provider readiness failed: {logs.stdout}") from None

        seed_environment = os.environ.copy()
        seed_environment.update(
            {
                "CLAWGAP_L2_SEED_CONFIG": str(directory / "seed-config.json"),
                "HOME": str(directory / "home"),
                "TMPDIR": str(directory / "temporary"),
            }
        )
        seed = subprocess.run(
            ["node", "--import", "tsx", str(build_project / "clawgap-seed.ts")],
            cwd=project,
            env=seed_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        (directory / "seed.log").write_text(
            redact_text(seed.stdout), encoding="utf-8"
        )
        if seed.returncode != 0:
            raise RuntimeError(f"NanoClaw DB/session seed failed: {seed.stdout}")
        upgrade = subprocess.run(
            [
                "node",
                "--import",
                "tsx",
                str(build_project / "scripts/upgrade-state.ts"),
                "set",
            ],
            cwd=project,
            env=seed_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        (directory / "upgrade-state.log").write_text(
            redact_text(upgrade.stdout), encoding="utf-8"
        )
        if upgrade.returncode != 0:
            raise RuntimeError(
                f"NanoClaw disposable upgrade-state initialization failed: {upgrade.stdout}"
            )
        _chown_runtime(runtime_root)
        os.chmod(event_path, 0o666)

        host_environment = os.environ.copy()
        host_environment.update(
            {
                "HOME": str(directory / "home"),
                "TMPDIR": str(directory / "temporary"),
                "CLAWGAP_L2_EVENT_PATH": str(event_path),
                "CLAWGAP_L2_CANDIDATE_ID": candidate_id,
                "CLAWGAP_L2_CASE_ID": str(case["case_id"]),
                "CLAWGAP_L2_ATTEMPT": str(attempt),
                "CLAWGAP_L2_ROLE": role,
                "CLAWGAP_L2_CORRELATION_ID": correlation_id,
                "CLAWGAP_L2_FIXTURE_ID": fixture_id,
                "CLAWGAP_L2_EXTRA_MOUNTS": json.dumps(fixture["extra_mounts"]),
                "CLAWGAP_L2_ROLE_LABEL": label,
                "CLAWGAP_L2_TERMINAL_COPY_SINK": str(
                    candidate_id in ARBITRARY_SOURCE_CANDIDATES
                ).lower(),
                "CLAWGAP_L2_SUPPRESS_POST_SINK_WAKE": str(
                    candidate_id in TARGET_CANDIDATES
                ).lower(),
                "CLAWGAP_L2_EXPECTED_GATE_ID": EXPECTED_GATE_ID
                if candidate_id == "CAND-79fbf2f6a976c935"
                else "",
                "ANTHROPIC_BASE_URL": f"http://host.docker.internal:{port}",
                "CLAWGAP_L2_PROVIDER_CREDENTIAL": "clawgap-loopback-mock",
                "NANOCLAW_EGRESS_LOCKDOWN": "true",
                "NANOCLAW_EGRESS_NETWORK": network,
                "ONECLI_GATEWAY_CONTAINER": provider_container,
            }
        )
        launch_log = (directory / "launch.log").open("w", encoding="utf-8")
        host_process = subprocess.Popen(
            ["node", "dist/index.js"],
            cwd=project,
            env=host_environment,
            stdout=launch_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        launch_log.close()
        deadline = time.monotonic() + request.timeout
        while time.monotonic() < deadline:
            rows = _read_jsonl(event_path) if event_path.is_file() else []
            if any(row.get("stage") == "pre_effect_interception" for row in rows):
                time.sleep(1.0)
                break
            if host_process.poll() is not None:
                raise RuntimeError(
                    "NanoClaw host exited early with code "
                    f"{host_process.returncode}"
                )
            time.sleep(0.5)
        else:
            raise TimeoutError("NanoClaw terminal sink witness timed out")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        if host_process is not None:
            _terminate(host_process)
        _capture_container_logs(network, label, directory)
        errors.extend(
            _stop_role_containers(network, label, provider_container)
        )
        canary_unchanged = (
            canary.read_text(encoding="utf-8") == CANARY_CONTENT
            and outside_canary.read_text(encoding="utf-8") == CANARY_CONTENT
        )
        for stage, detail in (
            ("target_completed", {"canary_unchanged": canary_unchanged}),
            (
                "cleanup_verified",
                {
                    "canary_unchanged": canary_unchanged,
                    "cleanup_errors": errors,
                },
            ),
        ):
            _append_event(
                _base_event(
                    stage,
                    detail,
                    case,
                    attempt,
                    role,
                    correlation_id,
                    fixture_id,
                ),
                event_path,
            )
        _remove_path(runtime_root)
        _remove_path(directory / "home")
        _remove_path(directory / "temporary")
        _remove_path(directory / "outside")
        _remove_path(directory / "state")

    events = _normalize_events(event_path)
    transcript = (
        _read_jsonl(transcript_path) if transcript_path.is_file() else []
    )
    if errors:
        outcome = PairOutcome(False, False, errors)
    else:
        outcome = _evaluate_pair(case, role, events, transcript, canary_unchanged)
    _write_jsonl(directory / "events.jsonl", events)
    atomic_write_json(
        directory / "trace-accounting.json",
        {
            "expected_trace_count": 1,
            "valid_trace_count": 1 if outcome.healthy else 0,
            "blocked_trace_count": 0 if outcome.healthy else 1,
            "status": "completed" if outcome.healthy else "inconclusive",
            "reason": "" if outcome.healthy else "; ".join(outcome.errors),
            "canary_unchanged": canary_unchanged,
        },
    )
    return outcome, events


def _run_role(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    build_manifest: Mapping[str, Any],
    request: NanoClawL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    try:
        return _run_role_attempt(
            case,
            role,
            attempt,
            directory,
            build_project,
            build_manifest,
            request,
        )
    except Exception as exc:
        return PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []


def _candidate_disposition(outcomes: list[PairOutcome]) -> tuple[str, str]:
    if all(outcome.healthy and outcome.triggered for outcome in outcomes):
        return (
            "runtime-confirmed",
            "all paired forced-provider E2E attempts satisfied the oracle",
        )
    if all(outcome.healthy for outcome in outcomes):
        return (
            "not-reproduced",
            "all paired forced-provider E2E attempts completed without the exploit sequence",
        )
    return (
        "inconclusive",
        "one or more paired attempts failed an infrastructure, trace, cleanup, or control gate",
    )


def _artifact_credential_scan(root: Path) -> str:
    paths = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    ]
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in paths
    )
    return "failed" if contains_credentials(text) else "passed"


def _reproduction_command(request: NanoClawL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-nanoclaw-l2"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.campaign != DEFAULT_SOURCE_CAMPAIGN:
        command += f" --campaign {request.campaign}"
    if request.candidate_id is not None:
        command += f" --candidate-id {request.candidate_id}"
    return command


def _run_candidate_subprocess(
    request: NanoClawL2RunRequest,
    candidate_id: str,
    build_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target_dir = request.out_dir.resolve() / "candidates" / candidate_id
    argv = [
        sys.executable,
        "-m",
        "src.runtime_validation",
        "run-dynamic-trigger-nanoclaw-l2",
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
            and result_rows[0].get("disposition")
            in {"not-reproduced", "inconclusive"}
        )
        if not valid_result:
            raise ValidationError(
                "NanoClaw candidate subprocess failed without a valid candidate result: "
                f"exit={completed.returncode}, candidate={candidate_id}"
            )
        return case_rows[0], result_rows[0]
    if len(result_rows) != 1 or len(case_rows) != 1:
        raise ValidationError(
            f"NanoClaw candidate subprocess identity partition drift: {candidate_id}"
        )
    return case_rows[0], result_rows[0]


def run_nanoclaw_l2(request: NanoClawL2RunRequest) -> dict[str, Any]:
    started = time.time()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError(
            "NanoClaw targeted L2 timeouts and attempts must be positive"
        )
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    cases = _select_cases(
        request.campaign.resolve(), candidate_id=request.candidate_id
    )
    source_bindings = _source_bindings(cases)
    actual_build_dir = (
        request.build_dir.resolve()
        if request.build_dir
        else request.out_dir.resolve() / "build"
    )
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
        for name in ("build.log", "image-build.log", "image.json"):
            if (actual_build_dir / name).is_file():
                shutil.copyfile(actual_build_dir / name, published_build_dir / name)

    results: list[dict[str, Any]] = []
    if request.candidate_id is None:
        _remove_path(request.out_dir.resolve() / "runs")
        _remove_path(request.out_dir.resolve() / "candidates")
        selected_cases = [
            _run_candidate_subprocess(request, candidate_id, actual_build_dir)
            for candidate_id in TARGET_CANDIDATES
        ]
        cases = [case for case, _result in selected_cases]
        results = [result for _case, result in selected_cases]
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
                    _remove_path(directory)
                    outcome, _events = _run_role(
                        case,
                        role,
                        attempt,
                        directory,
                        build_project,
                        build_manifest,
                        request,
                    )
                    role_outcomes[role] = outcome
                exploit = role_outcomes["exploit"]
                control = role_outcomes["control"]
                pair_outcomes.append(
                    PairOutcome(
                        exploit.healthy and control.healthy,
                        exploit.healthy
                        and control.healthy
                        and exploit.triggered,
                        [*exploit.errors, *control.errors],
                    )
                )
            disposition, reason = _candidate_disposition(pair_outcomes)
            results.append(
                {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "campaign_id": CAMPAIGN_ID,
                    "candidate_id": candidate_id,
                    "case_id": str(case["case_id"]),
                    "project": "nanoclaw",
                    "disposition": disposition,
                    "evidence_tier": L2_EVIDENCE_TIER,
                    "attempts": request.attempts,
                    "reason": reason,
                    "attempt_errors": [
                        outcome.errors
                        for outcome in pair_outcomes
                        if outcome.errors
                    ],
                }
            )

    if request.build_dir is None:
        _remove_path(build_project.parent)
    _write_jsonl(request.out_dir / "cases.jsonl", cases)
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "candidate_id": row["candidate_id"],
                "case_id": row["case_id"],
                "project": "nanoclaw",
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
        if path.name in {"home", "state", "temporary", "outside"}
    )
    if credential_scan != "passed" or not disposable_workspaces_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
        counts = {"inconclusive": len(results)}
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-nanoclaw-l2-manifest/v1",
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
            "src/runtime_validation/nanoclaw_l2.py": sha256_file(
                REPO_ROOT / "src/runtime_validation/nanoclaw_l2.py"
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
            "# NanoClaw Targeted Dynamic-Trigger L2\n\n"
            f"> Complete reproduction command: `{manifest['generation_command']}`\n\n"
            f"Candidates accounted for: **{len(results)}/{len(cases)}**.\n\n"
            f"Paired attempts per candidate: **{request.attempts}**.\n\n"
            f"Runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**; "
            f"not-reproduced: **{counts.get('not-reproduced', 0)}**; "
            f"inconclusive: **{counts.get('inconclusive', 0)}**.\n\n"
            "This is targeted NanoClaw L2 evidence. It does not by itself publish "
            "canonical all-candidate L2 evidence or change the 46-report truth gate.\n"
        ),
    )
    return manifest
