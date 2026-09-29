export function createPluginTool() {
  return { name: "plugin", execute: async (_id: string, args: unknown) => args };
}
