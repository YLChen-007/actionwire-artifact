import { promises as fs } from "node:fs";
import { validateRequiredParams } from "./validation";

interface ReadArgs {
  file_path: string;
  offset?: number;
  limit?: number;
}

async function readImageFile(filePath: string) {
  return fs.readFile(filePath);
}

async function isBinaryFile(filePath: string) {
  return filePath.endsWith(".bin");
}

export async function read(args: ReadArgs) {
  validateRequiredParams(args, ["file_path"], "Read");
  const { file_path, offset, limit } = args;
  const resolvedPath = file_path;
  if (resolvedPath.endsWith(".png")) {
    return readImageFile(resolvedPath);
  }
  if (await isBinaryFile(resolvedPath)) {
    throw new Error("binary file");
  }
  const content = await fs.readFile(resolvedPath, "utf-8");
  return content.slice(offset, limit);
}
