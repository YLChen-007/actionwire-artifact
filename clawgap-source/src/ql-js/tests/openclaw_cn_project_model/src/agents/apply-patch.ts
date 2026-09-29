import fs from "node:fs/promises";

const ADD_FILE_MARKER = "*** Add File:";
const DELETE_FILE_MARKER = "*** Delete File:";
const UPDATE_FILE_MARKER = "*** Update File:";

export function createApplyPatchTool() {
  return {
    name: "apply_patch",
    execute: async (_id: string, args: { input: string }) => applyPatch(args.input),
  };
}

async function applyPatch(input: string) {
  const parsed = parsePatchText(input);
  const fileOps = resolvePatchFileOps({});
  for (const hunk of parsed.hunks) {
    await fileOps.writeFile(hunk.path, hunk.contents);
  }
}

export function resolvePatchFileOps(options: object) {
  return async (filePath: string, content: string) => {
    await fs.writeFile(filePath, content, "utf8");
    return options;
  };
}

function parsePatchText(input: string) {
  const hunks = [];
  const lines = input.split("\n");
  const { hunk } = parseOneHunk(lines, 1);
  hunks.push(hunk);
  return { hunks, patch: input };
}

function parseOneHunk(lines: string[], lineNumber: number) {
  const firstLine = lines[0].trim();
  if (firstLine.startsWith(ADD_FILE_MARKER)) {
    return { hunk: { kind: "add", path: lines[1], contents: lines[2] }, consumed: 3 };
  }
  if (firstLine.startsWith(DELETE_FILE_MARKER)) {
    return { hunk: { kind: "delete", path: lines[1], contents: "" }, consumed: 2 };
  }
  if (firstLine.startsWith(UPDATE_FILE_MARKER)) {
    return { hunk: { kind: "update", path: lines[1], contents: lines[2] }, consumed: 3 };
  }
  throw new Error(`Invalid patch hunk at ${lineNumber}`);
}
