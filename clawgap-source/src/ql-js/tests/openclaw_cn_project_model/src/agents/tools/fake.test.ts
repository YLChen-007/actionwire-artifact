export function createFakeTool() {
  return { name: "fake", execute: async (_id: string, args: unknown) => args };
}
