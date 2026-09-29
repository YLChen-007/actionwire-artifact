type Tool = { execute(id: string, params: unknown): unknown };

export function wrapToolParamNormalization(tool: Tool) {
  return {
    name: "write",
    execute: async (toolCallId: string, params: unknown) => tool.execute(toolCallId, params),
  };
}

export function wrapSandboxPathGuard(tool: Tool) {
  return {
    name: "edit",
    execute: async (toolCallId: string, args: unknown) => tool.execute(toolCallId, args),
  };
}

export function createOpenClawReadTool(base: Tool) {
  return {
    name: "read",
    execute: async (toolCallId: string, params: unknown) => base.execute(toolCallId, params),
  };
}
