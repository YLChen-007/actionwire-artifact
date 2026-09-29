import { spawn } from 'node:child_process';

export function invokeAgent() {}

export function runCommand(
  command: string,
  args: string[],
  cwd?: string,
  envOverrides?: Record<string, string>,
) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env: envOverrides });
    resolve(child);
  });
}

export function runCommandStreaming(
  command: string,
  args: string[],
  onLine: (line: string) => void,
  cwd?: string,
  envOverrides?: Record<string, string>,
  agentId?: string,
) {
  onLine(agentId || '');
  return runCommand(command, args, cwd, envOverrides);
}
