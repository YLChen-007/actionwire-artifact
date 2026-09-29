import { createPendingApproval } from '../../db/sessions';
export function requestApproval(opts: { action: string; payload: unknown }) {
  createPendingApproval({ action: opts.action, payload: opts.payload });
}
