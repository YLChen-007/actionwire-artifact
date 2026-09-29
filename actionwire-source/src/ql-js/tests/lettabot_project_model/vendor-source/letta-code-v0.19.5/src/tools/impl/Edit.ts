import { promises as fs } from "node:fs";
import { validateRequiredParams } from "./validation";

interface EditArgs {
  file_path: string;
  old_string: string;
  new_string: string;
  replace_all?: boolean;
}

export async function edit(args: EditArgs) {
  validateRequiredParams(args, ["file_path", "old_string", "new_string"], "Edit");
  const { file_path, replace_all = false } = args;
  const old_string = args.old_string.replace(/\r\n/g, "\n");
  const new_string = args.new_string.replace(/\r\n/g, "\n");
  if (old_string.length === 0) {
    throw new Error("old_string cannot be empty");
  }
  if (old_string === new_string) {
    throw new Error("no change");
  }
  const resolvedPath = file_path;
  const content = await fs.readFile(resolvedPath, "utf-8");
  const newContent = replace_all
    ? content.split(old_string).join(new_string)
    : content.replace(old_string, new_string);
  await fs.writeFile(resolvedPath, newContent, "utf-8");
  return newContent;
}
