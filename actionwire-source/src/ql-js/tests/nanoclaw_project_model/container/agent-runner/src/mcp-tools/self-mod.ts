function registerTools(_tools: unknown[]) {}
function writeMessageOut(_message: unknown) {}

export const installPackages = {
  tool: { name: 'install_packages' },
  async handler(args: { apt?: string[]; npm?: string[]; reason?: string }) {
    writeMessageOut({
      kind: 'system',
      content: JSON.stringify({ action: 'install_packages', apt: args.apt, npm: args.npm, reason: args.reason }),
    });
  },
};

export const addMcpServer = {
  tool: { name: 'add_mcp_server' },
  async handler(args: { name: string; command: string; argv: string[]; env?: object }) {
    writeMessageOut({
      kind: 'system',
      content: JSON.stringify({ action: 'add_mcp_server', name: args.name, command: args.command, args: args.argv, env: args.env }),
    });
  },
};

const wrong = {
  tool: { name: 'wrong_add_mcp_server' },
  async handler(args: unknown) {
    writeMessageOut({ kind: 'system', content: JSON.stringify({ action: 'wrong', args }) });
  },
};
registerTools([installPackages, addMcpServer]);
void wrong;
