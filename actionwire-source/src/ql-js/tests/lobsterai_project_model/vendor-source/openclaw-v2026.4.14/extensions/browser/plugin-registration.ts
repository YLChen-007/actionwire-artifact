import { createBrowserTool } from "./src/browser-tool";

export function registerBrowserPlugin(api: { registerTool(factory: unknown): void }) {
  api.registerTool((ctx: unknown) => createBrowserTool(ctx));
}
