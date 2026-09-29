export function createFetchUrlTool() {
  return { execute: async ({ url }: { url: string }) => fetch(url) };
}
