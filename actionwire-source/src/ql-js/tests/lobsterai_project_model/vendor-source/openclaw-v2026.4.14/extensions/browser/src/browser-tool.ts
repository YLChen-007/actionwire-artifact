function readTargetUrlParam(params: Record<string, unknown>) {
  return String(params.targetUrl ?? params.url);
}

const browserToolDeps = {
  browserOpenTab: async (_base: undefined, url: string) => ({ url }),
};

export function createBrowserTool(_opts?: unknown) {
  return {
    name: "browser",
    execute: async (_toolCallId: string, args: Record<string, unknown>) => {
      const params = args;
      const targetUrl = readTargetUrlParam(params);
      return await browserToolDeps.browserOpenTab(undefined, targetUrl);
    },
  };
}
