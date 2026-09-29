export function registerTools(_tools: unknown[]) {}
export function startMcpServer() {}

const dispatcher = {
  tool: { name: 'dispatcher' },
  async handler(args: unknown) { return args; },
};
