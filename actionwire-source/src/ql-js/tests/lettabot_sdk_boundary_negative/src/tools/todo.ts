export function createManageTodoTool(agentKey: string) {
  return {
    name: 'manage_todo',
    async execute(_id: string, args: unknown) {
      return { agentKey, args };
    },
  };
}
