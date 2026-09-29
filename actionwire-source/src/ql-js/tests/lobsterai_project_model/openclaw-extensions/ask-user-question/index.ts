export function registerAskUserQuestion(api: { registerTool(factory: unknown): void }) {
  api.registerTool((_ctx: unknown) => {
    return {
      name: "AskUserQuestion",
      async execute(_id: string, params: unknown) {
        return params;
      },
    };
  });
}
