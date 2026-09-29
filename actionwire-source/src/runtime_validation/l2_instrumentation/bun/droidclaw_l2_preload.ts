import { appendFileSync } from "node:fs";

type Json = Record<string, unknown>;

function eventPath(): string | null {
  return process.env.CLAWGAP_L2_EVENT_PATH ?? null;
}

function appendEvent(path: string | null, stage: string, detail: Json): void {
  if (!path) return;
  appendFileSync(
    path,
    JSON.stringify({
      schema_version: "clawgap-dynamic-trigger-droidclaw-l2-event/v1",
      stage,
      candidate_id: process.env.CLAWGAP_L2_CANDIDATE_ID,
      case_id: process.env.CLAWGAP_L2_CASE_ID,
      attempt: Number(process.env.CLAWGAP_L2_ATTEMPT ?? "0"),
      role: process.env.CLAWGAP_L2_ROLE,
      correlation_id: process.env.CLAWGAP_L2_CORRELATION_ID,
      fixture_id: process.env.CLAWGAP_L2_FIXTURE_ID,
      detail,
    }) + "\n",
  );
}

function requestUrl(input: unknown): string {
  if (typeof input === "string") return input;
  if (input && typeof input === "object" && "url" in input) {
    return String((input as { url?: unknown }).url);
  }
  return String(input);
}

const realFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
  const url = requestUrl(input);
  let hostname = "";
  let protocol = "";
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    protocol = parsed.protocol;
  } catch {
    hostname = "";
    protocol = "";
  }
  if (
    (protocol === "http:" || protocol === "https:") &&
    hostname !== "127.0.0.1" &&
    hostname !== "localhost" &&
    hostname !== "::1"
  ) {
    throw new Error(`ClawGap DroidClaw L2 rejected a non-loopback fetch: ${url}`);
  }
  if (url.endsWith("/v1/chat/completions")) {
    appendEvent(eventPath(), "provider_request", {
      url,
      method: init?.method ?? (input as Request | undefined)?.method ?? "POST",
    });
  }
  return realFetch(input as RequestInfo, init);
}) as typeof globalThis.fetch;

const realSpawnSync = Bun.spawnSync.bind(Bun);
const terminalCommand = process.env.CLAWGAP_L2_TERMINAL_COMMAND ?? "";

function spawnCall(
  command: string | Array<string>,
  args?: Array<string>,
  options?: Parameters<typeof Bun.spawnSync>[2],
): { command: string | Array<string>; args: Array<string>; options?: Parameters<typeof Bun.spawnSync>[2] } {
  if (Array.isArray(command)) return { command, args: command.slice(1), options: args };
  return { command, args: args ?? [], options };
}

function commandName(command: string | Array<string>): string {
  const value = Array.isArray(command) ? command[0] : command;
  return String(value ?? "").split("/").pop() ?? "";
}

function recordAdb(command: string | Array<string>, args: Array<string>): void {
  const path = process.env.CLAWGAP_L2_ADB_LOG;
  if (!path) return;
  appendFileSync(
    path,
    JSON.stringify({
      schema_version: "clawgap-droidclaw-adb-event/v1",
      command: Array.isArray(command) ? command[0] : command,
      args,
      intercepted: args[0] === "shell" && args.slice(1).join(" ") === terminalCommand,
    }) + "\n",
  );
}

(Bun as unknown as { spawnSync: typeof Bun.spawnSync }).spawnSync = ((
  command: string | Array<string>,
  args: Array<string> = [],
  options?: Parameters<typeof Bun.spawnSync>[2],
) => {
  const call = spawnCall(command, args, options);
  const name = commandName(call.command);
  if (name === "adb") recordAdb(call.command, call.args);
  if (
    name === "adb" &&
    call.args[0] === "shell" &&
    call.args.slice(1).join(" ") === terminalCommand &&
    terminalCommand !== ""
  ) {
    appendEvent(eventPath(), "pre_effect_interception", {
      primitive: "Bun.spawnSync",
      command: Array.isArray(call.command) ? call.command[0] : call.command,
      args: call.args,
      cwd: call.options?.cwd,
      executed: false,
      approval_gate_present: false,
      controlled_response: "clawgap intercepted DroidClaw shell effect\n",
    });
    return {
      exitCode: 0,
      success: true,
      stdout: Buffer.from("clawgap intercepted DroidClaw shell effect\n"),
      stderr: Buffer.from(""),
    } as ReturnType<typeof Bun.spawnSync>;
  }
  const fullCommand = Array.isArray(call.command)
    ? call.command
    : [call.command, ...call.args];
  return realSpawnSync(fullCommand as string, call.options);
}) as typeof Bun.spawnSync;
