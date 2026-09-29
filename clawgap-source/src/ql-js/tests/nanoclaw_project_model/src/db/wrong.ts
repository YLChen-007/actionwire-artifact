const db = { prepare(_sql: string) { return { run(_value: unknown) {} }; } };
export function createPendingApproval(value: unknown) {
  db.prepare(`INSERT INTO unrelated (payload) VALUES (?)`).run(value);
}
