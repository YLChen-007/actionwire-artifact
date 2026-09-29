import { createManageTodoTool } from '../tools/todo';

export class SessionManager {
  private config = { allowedTools: ['Bash', 'Read', 'manage_todo'] };

  baseSessionOptions() {
    return {
      allowedTools: this.config.allowedTools,
      tools: [createManageTodoTool('agent')],
    };
  }
}
