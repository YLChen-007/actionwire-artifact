import { parseEnvPairs } from "../../cli/nodes-run";

async function callGatewayTool(method: string, options: unknown, payload: unknown) {
  return { method, options, payload };
}

export function createNodesTool() {
  return {
    name: "nodes",
    execute: async (_id: string, args: { command: string; env?: string[] }) => {
      const params = args;
      const env = parseEnvPairs(params.env);
      const runParams = { command: params.command, env };
      return callGatewayTool("node.invoke", {}, {
        nodeId: "fixture-node",
        command: "system.run",
        params: runParams,
      });
    },
  };
}
