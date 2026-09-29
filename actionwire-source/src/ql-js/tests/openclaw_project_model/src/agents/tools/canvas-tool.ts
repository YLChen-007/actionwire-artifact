import fs from "node:fs/promises";

export function createCanvasTool() {
  return {
    name: "canvas",
    execute: async (_id: string, args: { path: string }) => fs.readFile(args.path, "utf8"),
  };
}
