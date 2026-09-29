export function registerLegacyDynamicMcpTool(
  api: { registerTool(tool: unknown): void },
  configuredName: string,
) {
  api.registerTool({
    name: configuredName,
    async execute(_id: string, params: unknown) {
      return params;
    },
  });
}
