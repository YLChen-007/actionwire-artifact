import { createManageTodoTool } from '../tools/todo';

export class SessionManager {
  private config = {
    allowedTools: [
      'Bash', 'Read', 'Edit', 'Write', 'Glob', 'Grep', 'Task', 'web_search',
      'conversation_search', 'manage_todo',
    ],
  };

  baseSessionOptions() {
    return {
      allowedTools: this.config.allowedTools,
      tools: [createManageTodoTool('agent')],
    };
  }
}
