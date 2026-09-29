async function callGatewayTool(method: string, options: unknown, payload: unknown) {
  return { method, options, payload };
}

export function createExecTool() {
  return {
    name: "exec",
    execute: async (_id: string, args: { command: string; env?: Record<string, string> }) => {
      const params = args;
      const buildInvokeParams = () => ({
        nodeId: "fixture-node",
        command: "system.run",
        params: { command: [params.command], env: params.env },
      });
      return callGatewayTool("node.invoke", {}, buildInvokeParams());
    },
  };
}
