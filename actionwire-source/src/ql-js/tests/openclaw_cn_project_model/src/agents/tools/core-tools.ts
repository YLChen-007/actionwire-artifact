import { runMessageAction } from "../../infra/outbound/message-action-runner";

function tool(name: string) {
  return { name, execute: async (_id: string, args: unknown) => args };
}

export function createProcessTool() { return { name: "process", execute: async (_id: string, args: unknown) => args }; }
export function createAgentsListTool() { return { name: "agents_list", execute: async (_id: string, args: unknown) => args }; }
export function createBrowserTool() { return { name: "browser", execute: async (_id: string, args: unknown) => args }; }
export function createCanvasTool() { return { name: "canvas", execute: async (_id: string, args: unknown) => args }; }
export function createCronTool() { return { name: "cron", execute: async (_id: string, args: unknown) => args }; }
export function createGatewayTool() { return { name: "gateway", execute: async (_id: string, args: unknown) => args }; }
export function createImageTool() { return { name: "image", execute: async (_id: string, args: unknown) => args }; }
export function createMemorySearchTool() { return { name: "memory_search", execute: async (_id: string, args: unknown) => args }; }
export function createMemoryGetTool() { return { name: "memory_get", execute: async (_id: string, args: unknown) => args }; }
export function createMessageTool() {
  return {
    name: "message",
    execute: async (_id: string, args: { media?: string; text?: string }) => {
      const media = args.media;
      return runMessageAction({ params: args, media });
    },
  };
}
export function createSessionStatusTool() { return { name: "session_status", execute: async (_id: string, args: unknown) => args }; }
export function createSessionsHistoryTool() { return { name: "sessions_history", execute: async (_id: string, args: unknown) => args }; }
export function createSessionsListTool() { return { name: "sessions_list", execute: async (_id: string, args: unknown) => args }; }
export function createSessionsSendTool() { return { name: "sessions_send", execute: async (_id: string, args: unknown) => args }; }
export function createSessionsSpawnTool() { return { name: "sessions_spawn", execute: async (_id: string, args: unknown) => args }; }
export function createTtsTool() { return { name: "tts", execute: async (_id: string, args: unknown) => args }; }
export function createWebFetchTool() { return { name: "web_fetch", execute: async (_id: string, args: unknown) => args }; }
export function createWebSearchTool() { return { name: "web_search", execute: async (_id: string, args: unknown) => args }; }
export function createSubagentsTool() { return { name: "subagents", execute: async (_id: string, args: unknown) => args }; }

void tool;
