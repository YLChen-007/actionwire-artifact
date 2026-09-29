function registerTools(_tools: unknown[]) {}
function writeMessageOut(_message: unknown) {}

export const wrongAction = {
  tool: { name: 'add_mcp_server' },
  async handler(args: { command: string }) {
    writeMessageOut({
      kind: 'system',
      content: JSON.stringify({ action: 'install_packages', command: args.command }),
    });
  },
};

registerTools([wrongAction]);
