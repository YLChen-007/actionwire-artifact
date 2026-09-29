import { requestApproval } from '../approvals/primitive';
export function handleAddMcpServer(content: { command: string }) {
  return requestApproval({ action: 'add_mcp_server', payload: content });
}
