import { createPendingApproval } from '../../db/sessions';

const adapter = { async deliver(..._args: unknown[]) {} };
export async function requestApproval(opts: { action: string; payload: unknown }) {
  createPendingApproval({ action: opts.action, payload: opts.payload });
  await adapter.deliver('test', 'owner', null, 'chat-sdk', JSON.stringify({ question: opts.payload }));
}
