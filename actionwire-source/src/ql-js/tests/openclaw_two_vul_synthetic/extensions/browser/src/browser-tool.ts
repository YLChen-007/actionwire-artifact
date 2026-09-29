import { browserAct } from "./browser/client-actions-core";

type BrowserArgs = {
  kind: "evaluate" | "wait";
  fn: string;
};

export function createBrowserTool() {
  return {
    name: "browser",
    execute: async (_toolCallId: string, args: BrowserArgs) => browserAct(args),
  };
}
