import { spawn } from 'node:child_process';
import type { PermissionManager } from '../permissions';

function executeCommand(command: string, cwd: string, timeoutMs: number) {
  return new Promise((resolve) => {
    const child = spawn(command, [], { cwd, timeout: timeoutMs });
    resolve(child);
  });
}

export function createRunCommandTool(permissions: PermissionManager) {
  return {
    execute: async ({ command, timeout }: { command: string; timeout: number }) => {
      const check = await permissions.checkShellCommand(command);
      if (!check.allowed) return 'denied';
      return executeCommand(command, '/tmp', timeout);
    },
  };
}
