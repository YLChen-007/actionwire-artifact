import { writeFileSync } from 'node:fs';

export function createCreateFileTool() {
  return {
    execute: async ({ path, content }: { path: string; content: string }) =>
      writeFileSync(path, content),
  };
}
