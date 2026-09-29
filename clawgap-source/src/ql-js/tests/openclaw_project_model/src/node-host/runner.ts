import { spawn } from "node:child_process";
import {
  evaluateExecAllowlist,
  evaluateShellAllowlist,
} from "../infra/exec-approvals";

function decodeParams(value: string): {
  command: string[];
  rawCommand?: string;
  env?: Record<string, string>;
} {
  return JSON.parse(value);
}

const blockedEnvKeys = new Set(["NODE_OPTIONS"]);
const blockedEnvPrefixes = ["LD_"];

function sanitizeEnv(overrides?: Record<string, string> | null) {
  if (!overrides) return undefined;
  const merged: Record<string, string> = {};
  for (const [rawKey, value] of Object.entries(overrides)) {
    const key = rawKey.trim();
    const upper = key.toUpperCase();
    if (blockedEnvKeys.has(upper)) continue;
    if (blockedEnvPrefixes.some((prefix) => upper.startsWith(prefix))) continue;
    merged[key] = value;
  }
  return merged;
}

function runCommand(
  argv: string[],
  cwd: string | undefined,
  env: Record<string, string> | undefined,
  timeoutMs: number | undefined,
) {
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { cwd, env });
    resolve(child);
  });
}

export function handleInvoke(frame: { command: string; paramsJSON: string }) {
  if (frame.command !== "system.run") return;
  const params = decodeParams(frame.paramsJSON);
  const env = sanitizeEnv(params.env);
  let allowed = false;
  if (params.rawCommand) {
    allowed = evaluateShellAllowlist({ command: params.command });
  } else {
    allowed = evaluateExecAllowlist({ command: params.command });
  }
  if (!allowed) throw new Error("denied");
  return runCommand(params.command, undefined, env, undefined);
}
