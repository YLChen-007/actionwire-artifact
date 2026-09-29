export function toToolDefinitions(tool: { execute(params: unknown): unknown }) {
  return {
    name: "dispatcher",
    execute: async (_id: string, args: unknown) => tool.execute(args),
  };
}
