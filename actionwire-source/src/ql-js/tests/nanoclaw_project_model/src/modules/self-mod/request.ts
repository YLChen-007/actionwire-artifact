import { requestApproval } from '../approvals/primitive';
export function handleAddMcpServer(content: { name: string; command: string; args: string[] }) {
  return requestApproval({ action: 'add_mcp_server', payload: content });
}
