export function createBrowserTool() {
  return { name: "plugin_browser", execute: async (_id: string, args: unknown) => args };
}
