async function callGatewayTool(method: string, options: unknown, payload: unknown) {
  return { method, options, payload };
}

import { parseEnvPairs } from "../../cli/nodes-run";

export function createNodesTool() {
  return {
    name: "nodes",
    execute: async (_id: string, args: { command: string; env?: string[] }) => {
      const env = parseEnvPairs(args.env);
      return callGatewayTool("node.invoke", {}, {
        command: "system.run",
        params: { command: args.command, env },
      });
    },
  };
}
