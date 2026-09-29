const db = { prepare(_sql: string) { return { run(_value: unknown) {} }; } };
export function createPendingApproval(payload: unknown) {
  db.prepare(`INSERT INTO pending_approvals (payload) VALUES (?)`).run(payload);
}
