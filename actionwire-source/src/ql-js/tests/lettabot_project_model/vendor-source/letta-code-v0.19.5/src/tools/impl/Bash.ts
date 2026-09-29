import { spawn } from "node:child_process";
import { validateRequiredParams } from "./validation";

interface BashArgs {
  command: string;
  timeout?: number;
  run_in_background?: boolean;
}

async function spawnCommand(command: string, options: object) {
  return { command, options };
}

export async function bash(args: BashArgs) {
  validateRequiredParams(args, ["command"], "Bash");
  const { command, timeout = 120000, run_in_background = false } = args;
  if (run_in_background) {
    const executable = "bash";
    const launcherArgs = ["-c", command];
    return spawn(executable, launcherArgs, { shell: false });
  }
  return spawnCommand(command, { timeout });
}
