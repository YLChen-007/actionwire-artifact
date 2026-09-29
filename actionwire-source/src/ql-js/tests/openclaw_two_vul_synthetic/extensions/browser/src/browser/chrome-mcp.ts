const client = {
  async callTool(payload: { name: string; arguments: Record<string, unknown> }) {
    return payload;
  },
};

export function evaluateWithChromeMcp(fn: string) {
  return callTool("evaluate_script", { function: fn });
}

async function callTool(name: string, args: Record<string, unknown>) {
  return client.callTool({
    name,
    arguments: args,
  });
}
