interface GrepArgs {
  pattern: string;
  path?: string;
  glob?: string;
}

async function execFileAsync(command: string, args: string[], options: object) {
  return { stdout: [command, ...args, JSON.stringify(options)].join("\n") };
}

const rgPath = "rg";

export async function grep(args: GrepArgs) {
  validateRequiredParams(args, ["pattern"], "Grep");
  const { pattern, path = ".", glob } = args;
  const rgArgs = glob ? ["--glob", glob, pattern, path] : [pattern, path];
  return execFileAsync(rgPath, rgArgs, { cwd: path });
}
import { validateRequiredParams } from "./validation";
