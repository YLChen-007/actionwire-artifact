export function wrapToolParamNormalization() {
  return { execute: async (_id: string, args: unknown) => args };
}

export function wrapSandboxPathGuard() {
  return { execute: async (_id: string, args: unknown) => args };
}

export function createClawdbotReadTool() {
  return { execute: async (_id: string, args: unknown) => args };
}
