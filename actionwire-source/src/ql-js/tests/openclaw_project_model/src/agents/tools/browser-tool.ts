async function proxyRequest(payload: unknown) {
  return payload;
}

export function createBrowserTool() {
  return {
    name: "browser",
    execute: async (_id: string, args: { url: string }) =>
      proxyRequest({ path: "/tabs/open", body: { url: args.url } }),
  };
}
