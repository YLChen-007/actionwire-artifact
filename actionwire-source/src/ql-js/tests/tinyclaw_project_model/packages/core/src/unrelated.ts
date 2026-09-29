import { spawn } from 'node:child_process';

export const ordinary = { invoke(options: { message: string }) { return options.message; } };

export function ordinarySpawn(command: string, args: string[]) {
  return spawn(command, args);
}
