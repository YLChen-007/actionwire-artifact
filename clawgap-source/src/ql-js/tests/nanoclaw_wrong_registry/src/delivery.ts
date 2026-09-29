const actionHandlers = new Map<string, Function>();
function getDueOutboundMessages(_db: unknown): Array<Record<string, unknown>> { return []; }

export async function deliverSessionMessages(db: unknown) { await drainSession(db); }
async function drainSession(db: unknown) {
  for (const msg of getDueOutboundMessages(db)) await deliverMessage(msg, {}, {});
}
export async function deliverMessage(msg: Record<string, unknown>, session: unknown, db: unknown) {
  const content = JSON.parse(msg.content as string);
  if (msg.kind === 'system') await handleSystemAction(content, session, db);
}
export async function handleSystemAction(content: Record<string, unknown>, session: unknown, db: unknown) {
  const registered = actionHandlers.get(content.action as string);
  if (registered) await registered(content, session, db);
}
