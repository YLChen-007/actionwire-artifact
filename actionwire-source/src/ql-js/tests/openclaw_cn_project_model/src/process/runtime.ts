export function spawnAndWaitForSpawn(spawnImpl: Function, argv: string[], options: object) {
  return spawnImpl(argv[0], argv.slice(1), options);
}

export function runExecProcess(opts: any) {
  const spawnPty: any = () => {};
  return spawnPty("sh", ["-c", opts.command], { cwd: opts.workdir });
}

export function runCommand(argv: string[], cwd: string, env: object, timeoutMs: number) {
  return new Promise((resolve) => {
    const spawn: any = () => {};
    resolve(spawn(argv[0], argv.slice(1), { cwd, env, timeoutMs }));
  });
}
