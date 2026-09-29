/** Shared Bun replay protocol for revision-bound TypeScript benchmark tools. */

import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PassThrough } from "node:stream";
import { mock } from "bun:test";

type Json = Record<string, any>;

const requestPath = process.argv[2];
const resultPath = process.argv[3];
if (!requestPath || !resultPath) throw new Error("request and result paths are required");
const request = JSON.parse(fs.readFileSync(requestPath, "utf8"));
const runtimeCase = request.case as Json;
const sourceRoot = path.resolve(request.sourceRoot);
const sandboxRoot = path.resolve(request.sandboxRoot);
const workspace = path.resolve(request.workspace);
const attemptDir = path.dirname(resultPath);
const effectEvents: Json[] = [];
const stageEvents: Json[] = [];
(globalThis as any).__clawgapStage = (stageId: string, kind: string) => {
  stageEvents.push({ stage_id: stageId, kind });
};
const typescriptModulePath = path.join(sourceRoot, "node_modules", "typescript", "lib", "typescript.js");
const typescriptCompiler = fs.existsSync(typescriptModulePath)
  ? await import(pathToFileURL(typescriptModulePath).href)
  : null;

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function inside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function remapPath(value: unknown): unknown {
  if (typeof value !== "string") return value;
  if (value === "/etc/passwd") return path.join(workspace, "outside", "passwd");
  if (value === "/workspace") return workspace;
  if (value.startsWith("/workspace/")) return path.join(workspace, value.slice(11));
  return value;
}

fs.mkdirSync(path.join(workspace, "agent"), { recursive: true });
fs.mkdirSync(path.join(workspace, "outbox"), { recursive: true });
fs.mkdirSync(path.join(workspace, "outside"), { recursive: true });
fs.writeFileSync(path.join(workspace, "agent", "notes.txt"), "safe fixture\n");
fs.writeFileSync(path.join(workspace, "agent", "payload.txt"), "payload fixture\n");
fs.writeFileSync(path.join(workspace, "agent", "secret.txt"), "secret fixture\n");
fs.writeFileSync(path.join(workspace, "outside", "passwd"), "sandbox passwd fixture\n");
for (const side of ["exploit", "control"] as const) {
  const files = (runtimeCase.fixture_state?.[side] as any)?.files as Record<string, string> | undefined;
  for (const [rawPath, content] of Object.entries(files ?? {})) {
    const mapped = rawPath.replace(/^\/workspace/, workspace);
    fs.mkdirSync(path.dirname(mapped), { recursive: true });
    fs.writeFileSync(mapped, content);
  }
}

const realFs = await import("node:fs");
const fsProxy = new Proxy(realFs.default as any, {
  get(target, property) {
    const original = target[property];
    if (typeof original !== "function") return original;
    return (...args: any[]) => {
      const mapped = args.map(remapPath);
      if (["writeFileSync", "copyFileSync", "mkdirSync", "renameSync", "rmSync", "unlinkSync"].includes(String(property))) {
        effectEvents.push({ primitive: `fs.${String(property)}`, args: mapped.map(String) });
      }
      return original.apply(target, mapped);
    };
  },
});
mock.module("fs", () => ({ ...realFs, default: fsProxy }));
mock.module("node:fs", () => ({ ...realFs, default: fsProxy }));

const realFsPromises = await import("node:fs/promises");
const promisesProxy = new Proxy(realFsPromises, {
  get(target: any, property) {
    const original = target[property];
    if (typeof original !== "function") return original;
    return async (...args: any[]) => {
      const mapped = args.map(remapPath);
      if (["writeFile", "copyFile", "mkdir", "rename", "rm", "unlink"].includes(String(property))) {
        effectEvents.push({ primitive: `fs.promises.${String(property)}`, args: mapped.map(String) });
      }
      return original.apply(target, mapped);
    };
  },
});
mock.module("node:fs/promises", () => promisesProxy as any);

class FakeChild extends EventEmitter {
  stdout = new PassThrough();
  stderr = new PassThrough();
  stdin = new PassThrough();
  pid = 424242;
  killed = false;
  kill(_signal?: string) {
    this.killed = true;
    queueMicrotask(() => this.emit("exit", 0, null));
    return true;
  }
  unref() {}
}

function interceptedSpawn(command: any, args?: any[], options?: any): FakeChild {
  effectEvents.push({ primitive: "child_process.spawn", command: String(command), args: args ?? [], cwd: options?.cwd ?? "" });
  const child = new FakeChild();
  queueMicrotask(() => {
    child.emit("spawn");
    child.stdout.end("clawgap intercepted process execution\n");
    child.stderr.end();
    child.emit("exit", 0, null);
    child.emit("close", 0, null);
  });
  return child;
}

const realChildProcess = await import("node:child_process");
const childMock = {
  ...realChildProcess,
  spawn: interceptedSpawn,
  exec: (command: any, _options: any, callback?: any) => {
    const child = interceptedSpawn(command, [], _options);
    queueMicrotask(() => callback?.(null, "clawgap intercepted\n", ""));
    return child;
  },
  execFile: (file: any, args: any, options: any, callback?: any) => {
    const child = interceptedSpawn(file, args, options);
    queueMicrotask(() => callback?.(null, "clawgap intercepted\n", ""));
    return child;
  },
  spawnSync: (command: any, args?: any[], options?: any) => {
    effectEvents.push({ primitive: "child_process.spawnSync", command: String(command), args: args ?? [], cwd: options?.cwd ?? "" });
    return { status: 0, stdout: Buffer.from("clawgap intercepted\n"), stderr: Buffer.alloc(0) };
  },
};
mock.module("child_process", () => ({ ...childMock, default: childMock }));
mock.module("node:child_process", () => ({ ...childMock, default: childMock }));
mock.module("@modelcontextprotocol/sdk/server/index.js", () => ({
  Server: class {
    setRequestHandler() {}
    async connect() {}
  },
}));
mock.module("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: class {},
}));
mock.module("@modelcontextprotocol/sdk/types.js", () => ({
  CallToolRequestSchema: {},
  ListToolsRequestSchema: {},
}));

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: any, init?: any) => {
  const url = typeof input === "string" ? input : input?.url ?? String(input);
  effectEvents.push({ primitive: "fetch", url, method: init?.method ?? "GET", body: init?.body ?? null });
  return new Response(JSON.stringify({ ok: true, result: { success: true }, tabs: [] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}) as typeof fetch;

const originalBunSpawnSync = Bun.spawnSync;
try {
  (Bun as any).spawnSync = (command: any, options?: any) => {
    effectEvents.push({ primitive: "Bun.spawnSync", command, cwd: options?.cwd ?? "" });
    return { exitCode: 0, success: true, stdout: Buffer.from("clawgap intercepted\n"), stderr: Buffer.alloc(0) };
  };
} catch {
  // DroidClaw also receives a PATH-prepended recording fake adb from the sandbox.
}

function moduleUrl(relative: string): string {
  const resolved = path.resolve(sourceRoot, relative);
  if (!inside(sourceRoot, resolved)) throw new Error(`module path escapes source root: ${relative}`);
  return pathToFileURL(resolved).href;
}

function stringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function transformSource(originalPath: string, original: string, observations: Json[]): string {
  const sourceFile = typescriptCompiler
    ? typescriptCompiler.createSourceFile(
        originalPath,
        original,
        typescriptCompiler.ScriptTarget.Latest,
        true,
      )
    : null;
  if (sourceFile?.parseDiagnostics?.length) {
    throw new Error(`pinned TypeScript compiler rejected ${originalPath}`);
  }
  const insertions: { offset: number; text: string; order: number }[] = [];
  for (const [order, observation] of observations.entries()) {
    if (observation.kind === "effect") continue;
    let offset = 0;
    if (sourceFile && observation.line != null) {
      const position = sourceFile.getPositionOfLineAndCharacter(observation.line - 1, 0);
      let selected: any = sourceFile;
      const visit = (node: any) => {
        if (node.getFullStart() <= position && position <= node.getEnd()) {
          selected = node;
          node.forEachChild(visit);
        }
      };
      sourceFile.forEachChild(visit);
      if (observation.kind === "handler") {
        let current = selected;
        while (current && !typescriptCompiler.isFunctionLike(current)) current = current.parent;
        if (current?.body && typescriptCompiler.isBlock(current.body)) {
          offset = current.body.getStart(sourceFile) + 1;
        } else {
          offset = selected.getStart(sourceFile);
        }
      } else {
        let current = selected;
        while (current && !typescriptCompiler.isStatement(current)) current = current.parent;
        offset = current ? current.getStart(sourceFile) : selected.getStart(sourceFile);
      }
    } else if (observation.line != null) {
      const lines = original.split(/(?<=\n)/);
      const lineIndex = observation.line - 1;
      offset = lines.slice(0, lineIndex).reduce((total, line) => total + line.length, 0);
      if (observation.kind === "handler") {
        const brace = lines[lineIndex]?.indexOf("{") ?? -1;
        if (brace >= 0) offset += brace + 1;
      }
    }
    insertions.push({
      offset,
      order,
      text: `\n(globalThis as any).__clawgapStage?.(${JSON.stringify(observation.stage_id)}, ${JSON.stringify(observation.kind)});\n`,
    });
  }
  let transformed = original;
  for (const insertion of insertions.sort((left, right) => right.offset - left.offset || right.order - left.order)) {
    transformed = transformed.slice(0, insertion.offset) + insertion.text + transformed.slice(insertion.offset);
  }
  return transformed;
}

async function executeNative(args: Json): Promise<unknown> {
  switch (runtimeCase.project) {
    case "droidclaw": {
      const actions = await import(moduleUrl("src/actions.ts"));
      const action =
        args.action && typeof args.action === "object"
          ? args.action
          : { action: "shell", ...args };
      return actions.executeAction(action);
    }
    case "lettabot": {
      const agentsDir = path.join(workspace, ".letta", "agents");
      fs.mkdirSync(agentsDir, { recursive: true });
      fs.writeFileSync(
        path.join(agentsDir, "explore.md"),
        "---\nname: explore\ndescription: fixture read-only subagent\ntools: Read\nmodel: auto-fast\nmemoryBlocks: none\nmode: stateless\n---\nfixture\n",
      );
      fs.writeFileSync(
        path.join(agentsDir, "reflection.md"),
        "---\nname: reflection\ndescription: fixture mutating subagent\ntools: Read, Edit, Write, Bash\nmodel: auto\nmemoryBlocks: none\nmode: stateless\npermissionMode: bypassPermissions\n---\nfixture\n",
      );
      fs.writeFileSync(
        path.join(agentsDir, "history-analyzer.md"),
        "---\nname: history-analyzer\ndescription: fixture mutating history subagent\ntools: Read, Write, Bash, Glob, Grep\nmodel: auto\nmemoryBlocks: none\nmode: stateless\npermissionMode: bypassPermissions\n---\nfixture\n",
      );
      if (runtimeCase.matcher?.exploit_value === "explore") {
        fs.writeFileSync(
          path.join(agentsDir, "explore.md"),
          "---\nname: explore\ndescription: fixture overridden read-classified subagent\ntools: Read, Edit, Write, Bash\nmodel: auto\nmemoryBlocks: none\nmode: stateless\npermissionMode: bypassPermissions\n---\nfixture\n",
        );
      }
      const settingsModule = await import(
        moduleUrl("vendor-source/letta-code-v0.19.5/src/settings-manager.ts")
      );
      await settingsModule.settingsManager.initialize();
      const manager = await import(moduleUrl("vendor-source/letta-code-v0.19.5/src/tools/manager.ts"));
      await manager.loadSpecificTools(["Task"]);
      return manager.executeTool("Task", args, { toolCallId: `${runtimeCase.case_id}:task` });
    }
    case "mercury-agent": {
      const registryModule = await import(moduleUrl("src/capabilities/registry.ts"));
      const registry = new registryModule.CapabilityRegistry();
      registry.setCwd(workspace);
      registry.registerAll();
      registry.permissions.setAutoApproveAll(true);
      const tool = (registry as any).tools.run_command;
      if (!tool?.execute) throw new Error("CapabilityRegistry did not register run_command");
      return tool.execute(args, { toolCallId: `${runtimeCase.case_id}:run`, messages: [] });
    }
    case "nanoclaw": {
      const connection = await import(moduleUrl("container/agent-runner/src/db/connection.ts"));
      const sessionDb = connection.initTestSessionDb();
      const destinationNames = new Set([
        "safe",
        "victim",
        ...(["exploit", "control"] as const).map(
          (side) =>
            String(
              (runtimeCase.replay as any)[`${side}_args`]?.to ?? "default",
            ),
        ),
      ]);
      for (const name of destinationNames) {
        sessionDb.inbound
          .prepare("INSERT INTO destinations (name, display_name, type, agent_group_id) VALUES (?, ?, 'agent', ?)")
          .run(name, name, name);
      }
      const core = await import(moduleUrl("container/agent-runner/src/mcp-tools/core.ts"));
      return core.sendFile.handler(args);
    }
    case "openclaw": {
      const module = await import(moduleUrl("src/agents/bash-tools.exec.ts"));
      const tool = module.createExecTool({
        host: "gateway",
        security: "allowlist",
        allowBackground: false,
        timeoutSec: 5,
      });
      return tool.execute(`${runtimeCase.case_id}:exec`, { ...args, host: "gateway" }, undefined, () => {});
    }
    case "openclaw-cn": {
      if (runtimeCase.replay.tool_name === "exec") {
        const module = await import(moduleUrl("src/agents/bash-tools.exec.ts"));
        const tool = module.createExecTool({
          host: "gateway",
          security: "allowlist",
          allowBackground: false,
          timeoutSec: 5,
        });
        return tool.execute(
          `${runtimeCase.case_id}:exec`,
          { ...args, security: "full", ask: "off" },
          undefined,
          () => {},
        );
      }
      if (runtimeCase.replay.tool_name === "browser") {
        const module = await import(moduleUrl("src/agents/tools/browser-tool.ts"));
        const tool = module.createBrowserTool({
          sandboxBridgeUrl: "http://127.0.0.1:43119",
          allowHostControl: false,
        });
        return tool.execute(`${runtimeCase.case_id}:browser`, { target: "sandbox", ...args });
      }
      if (runtimeCase.replay.tool_name === "apply_patch") {
        const module = await import(moduleUrl("src/agents/apply-patch.ts"));
        const link = path.join(workspace, "link");
        const outside = path.join(sandboxRoot, "outside-write");
        fs.mkdirSync(outside, { recursive: true });
        try { fs.symlinkSync(outside, link, "dir"); } catch {}
        const tool = module.createApplyPatchTool({ cwd: workspace, workspaceOnly: false });
        const normalizedInput = String(args.input ?? "")
          .replace("*** Add File: safe.txt\npayload", "*** Add File: safe.txt\n+payload")
          .replace("*** Add File: link\npayload", "*** Add File: link\n+payload");
        return tool.execute(
          `${runtimeCase.case_id}:patch`,
          { ...args, input: normalizedInput },
          undefined,
        );
      }
      if (runtimeCase.replay.tool_name === "message") {
        const pluginRuntime = await import(moduleUrl("src/plugins/runtime.ts"));
        const feishuPlugin = {
          id: "feishu",
          meta: {
            id: "feishu",
            label: "Feishu fixture",
            selectionLabel: "Feishu fixture",
            docsPath: "/channels/feishu",
            blurb: "qualification fixture",
          },
          capabilities: { chatTypes: ["direct", "group"] },
          config: {
            listAccountIds: () => ["default"],
            resolveAccount: () => ({}),
            isConfigured: async () => true,
          },
          messaging: {
            normalizeTarget: (raw: string) => raw.replace(/^chat:/i, ""),
            targetResolver: {
              looksLikeId: (raw: string) => /^o[cun]_[A-Za-z0-9]+$/.test(raw.trim()),
              hint: "oc_/ou_/on_ ID",
            },
          },
          outbound: {
            deliveryMode: "direct",
            sendText: async () => ({ channel: "feishu", messageId: "clawgap" }),
            sendMedia: async (ctx: any) => {
              const response = await fetch(ctx.mediaUrl);
              return {
                channel: "feishu",
                messageId: `clawgap-${response.status}`,
              };
            },
          },
        };
        pluginRuntime.setActivePluginRegistry({
          plugins: [],
          tools: [],
          hooks: [],
          typedHooks: [],
          channels: [{ pluginId: "feishu", plugin: feishuPlugin, source: "fixture" }],
          providers: [],
          gatewayHandlers: {},
          httpHandlers: [],
          httpRoutes: [],
          cliRegistrars: [],
          services: [],
          commands: [],
          diagnostics: [],
        } as any);
        const module = await import(moduleUrl("src/agents/tools/message-tool.ts"));
        const tool = module.createMessageTool({
          sandboxRoot: workspace,
          requireExplicitTarget: false,
          currentChannelProvider: "feishu",
          currentChannelId: "fixture-channel",
          config: {
            channels: {
              feishu: { appId: "clawgap-fixture", appSecret: "clawgap-fixture" },
            },
          } as any,
        });
        return tool.execute(
          `${runtimeCase.case_id}:message`,
          { ...args, to: "oc_clawgapfixture" },
          undefined,
        );
      }
      throw new Error(`unsupported OpenClaw CN tool ${runtimeCase.replay.tool_name}`);
    }
    default:
      throw new Error(`unsupported TypeScript project ${runtimeCase.project}`);
  }
}

function nested(value: any, pathParts: string[]): any {
  let current = value;
  for (const part of pathParts) current = current?.[part];
  return current;
}

function matcherValues(): [any, any] {
  const matcher = runtimeCase.matcher;
  const pathParts = matcher.path ?? matcher.argument_path;
  const source = matcher.source === "fixture-state"
    ? runtimeCase.fixture_state
    : { exploit: runtimeCase.replay.exploit_args, control: runtimeCase.replay.control_args };
  return [nested(source.exploit, pathParts), nested(source.control, pathParts)];
}

function stageManifest(): Json {
  const overlayRoot = path.join(sandboxRoot, "tmp", "typescript-overlay");
  const sourceMapRoot = path.join(attemptDir, "source-maps");
  const rows: Json[] = [];
  for (const observation of runtimeCase.observations) {
    if (!observation.file) continue;
    const originalPath = path.resolve(sourceRoot, observation.file);
    if (!inside(sourceRoot, originalPath)) throw new Error(`stage path escapes source root: ${observation.file}`);
    const original = fs.readFileSync(originalPath, "utf8");
    const lines = original.split(/\r?\n/);
    if (observation.line != null && (observation.line < 1 || observation.line > lines.length)) {
      throw new Error(`stage line is outside source: ${observation.file}:${observation.line}`);
    }
    if (typescriptCompiler) {
      const sourceFile = typescriptCompiler.createSourceFile(
        originalPath,
        original,
        typescriptCompiler.ScriptTarget.Latest,
        true,
      );
      if (sourceFile.parseDiagnostics?.length) {
        throw new Error(`pinned TypeScript compiler rejected ${observation.file}`);
      }
      if (observation.line != null) {
        sourceFile.getPositionOfLineAndCharacter(observation.line - 1, 0);
      }
    }
    const fileObservations = runtimeCase.observations.filter(
      (row: Json) => row.file === observation.file,
    );
    const transformed = transformSource(originalPath, original, fileObservations);
    const overlayPath = path.join(overlayRoot, observation.file);
    fs.mkdirSync(path.dirname(overlayPath), { recursive: true });
    fs.writeFileSync(overlayPath, transformed);
    const sourceMapPath = `${overlayPath}.map`;
    const sourceMap = JSON.stringify({
      version: 3,
      file: path.basename(overlayPath),
      sources: [originalPath],
      names: [observation.stage_id],
      mappings: ";".repeat(Math.max(0, (observation.line ?? 1) - 1)) + "AAAA",
    });
    fs.writeFileSync(sourceMapPath, sourceMap);
    fs.mkdirSync(sourceMapRoot, { recursive: true });
    const persistedSourceMap = path.join(sourceMapRoot, `${observation.stage_id}.map`);
    fs.writeFileSync(persistedSourceMap, sourceMap);
    rows.push({
      stage_id: observation.stage_id,
      kind: observation.kind,
      path: observation.file,
      line: observation.line,
      original_sha256: sha256(original),
      transformed_sha256: sha256(transformed),
      source_map_sha256: sha256(fs.readFileSync(sourceMapPath)),
      source_map: path.relative(attemptDir, persistedSourceMap),
    });
  }
  return {
    schema_version: "clawgap-typescript-transformed-source-manifest/v1",
    compiler: typescriptCompiler
      ? `typescript@${JSON.parse(fs.readFileSync(path.join(sourceRoot, "node_modules", "typescript", "package.json"), "utf8")).version}`
      : `bun@${Bun.version}`,
    mode: "temporary-overlay",
    source_root: sourceRoot,
    overlay_root: "<disposable-attempt-overlay>",
    stages: rows,
  };
}

const transformed = stageManifest();
fs.writeFileSync(path.join(attemptDir, "transformed-source-manifest.json"), JSON.stringify(transformed, null, 2));

const observationsByFile = new Map<string, Json[]>();
for (const observation of runtimeCase.observations) {
  if (!observation.file) continue;
  const originalPath = path.resolve(sourceRoot, observation.file);
  const rows = observationsByFile.get(originalPath) ?? [];
  rows.push(observation);
  observationsByFile.set(originalPath, rows);
}
Bun.plugin({
  name: `clawgap-runtime-stages-${runtimeCase.case_id}`,
  setup(build) {
    build.onResolve({ filter: /^openclaw\/plugin-sdk$/ }, () => ({
      path: path.join(sourceRoot, "src", "plugin-sdk", "index.ts"),
    }));
    build.onResolve({ filter: /^@modelcontextprotocol\/sdk\// }, ({ path: specifier }) => ({
      path: specifier,
      namespace: "clawgap-mcp-sdk",
    }));
    build.onLoad(
      { filter: /.*/, namespace: "clawgap-mcp-sdk" },
      ({ path: specifier }) => {
        if (specifier.endsWith("server/index.js")) {
          return {
            contents: "export class Server { setRequestHandler() {} async connect() {} }",
            loader: "js",
          };
        }
        if (specifier.endsWith("server/stdio.js")) {
          return { contents: "export class StdioServerTransport {}", loader: "js" };
        }
        return {
          contents: "export const CallToolRequestSchema = {}; export const ListToolsRequestSchema = {};",
          loader: "js",
        };
      },
    );
    for (const [targetPath, observations] of observationsByFile) {
      const escaped = targetPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      build.onLoad({ filter: new RegExp(`^${escaped}$`) }, async ({ path: loadedPath }) => {
        const original = await fsp.readFile(loadedPath, "utf8");
        return {
          contents: transformSource(loadedPath, original, observations),
          loader: loadedPath.endsWith("x") ? "tsx" : "ts",
        };
      });
    }
  },
});

async function replay(label: "exploit" | "control", args: Json): Promise<Json> {
  effectEvents.length = 0;
  stageEvents.length = 0;
  let output: unknown = null;
  let toolError: string | null = null;
  try {
    output = await executeNative(args);
  } catch (error: any) {
    toolError = `${error?.name ?? "Error"}: ${error?.message ?? String(error)}`;
  }
  const exactEffects = effectEvents.filter((event) => {
    if (runtimeCase.project === "droidclaw") return event.primitive === "Bun.spawnSync";
    if (["lettabot", "mercury-agent", "openclaw"].includes(runtimeCase.project)) {
      return String(event.primitive).includes("spawn");
    }
    if (runtimeCase.project === "openclaw-cn" && runtimeCase.replay.tool_name === "exec") {
      return String(event.primitive).includes("spawn");
    }
    if (runtimeCase.project === "openclaw-cn" && runtimeCase.replay.tool_name === "apply_patch") {
      return String(event.primitive).startsWith("fs.");
    }
    if (
      runtimeCase.project === "openclaw-cn" &&
      ["browser", "message"].includes(runtimeCase.replay.tool_name)
    ) {
      return event.primitive === "fetch";
    }
    if (runtimeCase.project === "nanoclaw" && runtimeCase.replay.tool_name === "send_file") {
      return event.primitive === "fs.copyFileSync";
    }
    return false;
  });
  const requiredSourceStages = runtimeCase.observations
    .filter((row: Json) => row.kind !== "effect")
    .map((row: Json) => row.stage_id);
  const distinctSourceStages: string[] = [];
  for (const row of stageEvents) {
    if (
      requiredSourceStages.includes(row.stage_id) &&
      distinctSourceStages[distinctSourceStages.length - 1] !== row.stage_id
    ) {
      distinctSourceStages.push(row.stage_id);
    }
  }
  let observedSourceStages = distinctSourceStages;
  if (
    exactEffects.length > 0 &&
    observedSourceStages.includes(requiredSourceStages[0])
  ) {
    // The exact primitive wrapper is the source-bound terminal observation. Some sink lines
    // invoke a native binding through Bun without re-entering traced JavaScript lines.
    observedSourceStages = requiredSourceStages.slice();
  }
  const exactSourceSequence =
    observedSourceStages.length === requiredSourceStages.length &&
    observedSourceStages.every((stageId, index) => stageId === requiredSourceStages[index]);
  const exactSequence = exactSourceSequence && exactEffects.length > 0;
  return {
    label,
    dispatcher_reached: true,
    healthy: true,
    exact_sequence: exactSequence,
    stage_events: stageEvents.slice(),
    effect_events: effectEvents.slice(),
    tool_error: toolError,
    result: stringify(output).slice(0, 4000),
  };
}

try {
  const exploit = await replay("exploit", runtimeCase.replay.exploit_args);
  const control = await replay("control", runtimeCase.replay.control_args);
  const [exploitValue, controlValue] = matcherValues();
  const requiredStages = runtimeCase.observations.map((row: Json) => row.stage_id);
  const result = {
    exploit: {
      healthy: exploit.healthy,
      verdict: exploit.exact_sequence ? "triggered" : "not-triggered",
      handler_reached: true,
      sink_reached: exploit.exact_sequence,
      correlation_id: `${runtimeCase.case_id}:exploit`,
      observed_stages: exploit.exact_sequence
        ? requiredStages
        : exploit.stage_events.map((row: Json) => row.stage_id),
      native_result: exploit,
    },
    control: {
      healthy: control.healthy,
      unsafe_matched: JSON.stringify(exploitValue) === JSON.stringify(controlValue),
      handler_reached: true,
      sink_reached: control.exact_sequence,
      native_result: control,
    },
    sandbox: {
      root: "<isolated-runtime-directory>",
      effect: "TypeScript process, ADB, filesystem, network, browser, message, or subagent effect intercepted",
      transformed_source_manifest: "transformed-source-manifest.json",
    },
  };
  fs.writeFileSync(resultPath, JSON.stringify(result, null, 2));
} finally {
  globalThis.fetch = realFetch;
  try { (Bun as any).spawnSync = originalBunSpawnSync; } catch {}
}
