interface GlobArgs {
  pattern: string;
  path?: string;
}

async function execFileAsync(command: string, args: string[], options: object) {
  return { stdout: [command, ...args, JSON.stringify(options)].join("\n") };
}

const rgPath = "rg";

export async function glob(args: GlobArgs) {
  validateRequiredParams(args, ["pattern"], "Glob");
  const { pattern, path = "." } = args;
  if (!pattern) {
    throw new Error("pattern required");
  }
  const rgArgs = ["--files", "--glob", pattern, path];
  return execFileAsync(rgPath, rgArgs, { cwd: path });
}
import { validateRequiredParams } from "./validation";
