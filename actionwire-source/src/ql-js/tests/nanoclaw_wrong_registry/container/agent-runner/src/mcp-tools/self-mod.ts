function registerTools(_tools: unknown[]) {}
function writeMessageOut(_message: unknown) {}

export const addMcpServer = {
  tool: { name: 'add_mcp_server' },
  async handler(args: { command: string }) {
    writeMessageOut({
      kind: 'system',
      content: JSON.stringify({ action: 'add_mcp_server', command: args.command }),
    });
  },
};

registerTools([addMcpServer]);
