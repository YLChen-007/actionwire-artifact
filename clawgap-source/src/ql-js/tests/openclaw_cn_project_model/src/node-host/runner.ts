import { spawn } from "node:child_process";

const blockedEnvKeys = new Set(["NODE_OPTIONS"]);
const blockedEnvPrefixes = ["LD_"];

function sanitizeEnv(overrides?: Record<string, string> | null) {
  if (!overrides) return undefined;
  const merged: Record<string, string> = {};
  for (const [rawKey, value] of Object.entries(overrides)) {
    const key = rawKey.trim();
    if (!key) continue;
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
    const child = spawn(argv[0], argv.slice(1), { cwd, env, timeoutMs });
    resolve(child);
  });
}

export function handleInvoke(frame: { command: string; params: { command: string[]; env?: Record<string, string> } }) {
  if (frame.command !== "system.run") return;
  const params = frame.params;
  const env = sanitizeEnv(params.env);
  return runCommand(params.command, undefined, env, undefined);
}
