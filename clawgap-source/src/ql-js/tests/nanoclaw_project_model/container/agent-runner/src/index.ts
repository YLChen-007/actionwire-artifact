function loadConfig(): { mcpServers: Record<string, unknown> } {
  return { mcpServers: {} };
}

async function main() {
  const config = loadConfig();
  const mcpServers: Record<string, unknown> = {
    nanoclaw: { command: 'bun', args: ['run', 'mcp-tools/index.ts'] },
  };

  for (const [name, serverConfig] of Object.entries(config.mcpServers)) {
    mcpServers[name] = serverConfig;
  }

  return mcpServers;
}

void main;
