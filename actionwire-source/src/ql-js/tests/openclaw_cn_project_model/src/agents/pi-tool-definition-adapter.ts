export function toToolDefinitions(tool: any) {
  return { name: "dispatcher", execute: async (_id: string, args: unknown) => tool.execute(args) };
}
