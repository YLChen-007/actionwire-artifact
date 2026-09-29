import { updateContainerConfigJson } from '../../db/container-configs';

export function applyAddMcpServer({ payload }: { payload: unknown }) {
  return updateContainerConfigJson('agent', 'mcp_servers', payload);
}
