async function runMessageAction(payload: unknown) {
  return payload;
}

export function createMessageTool() {
  return {
    name: "message",
    execute: async (_id: string, args: { text: string }) => runMessageAction(args),
  };
}
