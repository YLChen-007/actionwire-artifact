import { promises as fs } from "node:fs";
import { validateRequiredParams } from "./validation";

interface WriteArgs {
  file_path: string;
  content: string;
}

export async function write(args: WriteArgs) {
  validateRequiredParams(args, ["file_path", "content"], "Write");
  const { file_path, content } = args;
  const resolvedPath = file_path;
  await fs.writeFile(resolvedPath, content, "utf-8");
  return content.length;
}
