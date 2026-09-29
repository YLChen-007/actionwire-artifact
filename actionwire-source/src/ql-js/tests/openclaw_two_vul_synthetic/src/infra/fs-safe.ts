import fs from "node:fs/promises";

export async function readLocalFileSafely(filePath: string) {
  return openLocalFileSafely(filePath);
}

async function openLocalFileSafely(filePath: string) {
  return fs.open(filePath, "r");
}
