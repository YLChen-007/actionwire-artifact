import type { Supervisor } from '../../core/supervisor';

export function createDelegateTaskTool(supervisor: Supervisor) {
  return {
    execute: async ({ task }: { task: string }) => supervisor.spawn({ task }),
  };
}
