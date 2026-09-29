async function runWebSearch(params: { url: string }) {
  return fetch(params.url, { method: "GET" });
}

export function createWebSearchTool() {
  return {
    name: "web_search",
    execute: async (_id: string, args: { url: string }) => runWebSearch(args),
  };
}
