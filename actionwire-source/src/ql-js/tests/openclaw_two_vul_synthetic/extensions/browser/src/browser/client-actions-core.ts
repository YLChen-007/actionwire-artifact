import { runActRoute } from "./routes/agent.act";

export function browserAct(req: { kind: "evaluate" | "wait"; fn: string }) {
  return runActRoute(req);
}
