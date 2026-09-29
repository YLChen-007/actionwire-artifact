import { readFileSync } from 'node:fs';

export function createReadFileTool() {
  return { execute: async ({ path }: { path: string }) => readFileSync(path, 'utf8') };
}
