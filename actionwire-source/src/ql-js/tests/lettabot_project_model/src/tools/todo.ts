import { addTodo, completeTodo, removeTodo, reopenTodo, snoozeTodo } from '../todo/store';

function readStringParam(
  params: Record<string, string>,
  key: string,
  options: { required: boolean },
) {
  const value = params[key]?.trim();
  if (options.required && !value) throw new Error(`${key} required`);
  return value;
}

export function createManageTodoTool(agentKey: string) {
  return {
    name: 'manage_todo',
    async execute(_id: string, args: unknown) {
      const params = args as Record<string, string>;
      const action = readStringParam(params, 'action', { required: true });
      if (action === 'add') addTodo(agentKey, { text: params.text });
      if (action === 'complete') completeTodo(agentKey, params.id);
      if (action === 'reopen') reopenTodo(agentKey, params.id);
      if (action === 'remove') removeTodo(agentKey, params.id);
      if (action === 'snooze') snoozeTodo(agentKey, params.id, params.until);
    },
  };
}

export function reviewOnly(pathApi: { resolve(value: string): string }, input: string) {
  return pathApi.resolve(input.replace(/\r\n/g, '\n'));
}
