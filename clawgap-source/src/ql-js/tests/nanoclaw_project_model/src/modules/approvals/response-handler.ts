function getApprovalHandler(_action: string): Function | undefined { return undefined; }

export async function handleRegisteredApproval(approval: { action: string; payload: string }) {
  const handler = getApprovalHandler(approval.action);
  if (!handler) return;
  const payload = JSON.parse(approval.payload);
  await handler({ payload });
}
