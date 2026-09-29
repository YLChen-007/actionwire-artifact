import { spawn } from "node:child_process";

function assertAllowed(value: string) {
  if (value === "blocked") throw new Error("blocked");
}

async function callGatewayTool(method: string, options: unknown, payload: unknown) {
  return { method, options, payload };
}

export function createExecTool() {
  return {
    name: "exec",
    execute: async (_id: string, args: { command: string; env?: Record<string, string> }) => {
      assertAllowed(args.command);
      const buildInvokeParams = () => ({
        command: "system.run",
        params: { command: [args.command], env: args.env },
      });
      await callGatewayTool("node.invoke", {}, buildInvokeParams());
      return spawn(args.command, [], {});
    },
  };
}
