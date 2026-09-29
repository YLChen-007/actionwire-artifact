import { evaluateWithChromeMcp } from "../chrome-mcp";

export function runActRoute(action: { kind: "evaluate" | "wait"; fn: string }) {
  const evaluateEnabled = true;
  const earlyFn = action.kind === "wait" || action.kind === "evaluate" ? action.fn : "";
  if ((action.kind === "evaluate" || (action.kind === "wait" && earlyFn)) && !evaluateEnabled) {
    throw new Error("browser evaluation disabled");
  }
  return evaluateWithChromeMcp(action.fn);
}
