declare const Bun: { spawnSync(argv: string[]): unknown };

export function ordinarySpawn(command: string[]) {
  return Bun.spawnSync(command);
}
