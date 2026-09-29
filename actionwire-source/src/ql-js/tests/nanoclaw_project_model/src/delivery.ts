import { routeAgentMessage } from './modules/agent-to-agent/agent-route';

const actionHandlers = new Map<string, Function>();

export function registerDeliveryAction(action: string, handler: Function) {
  actionHandlers.set(action, handler);
}

function getDueOutboundMessages(_db: unknown): Array<Record<string, unknown>> { return []; }

export async function deliverSessionMessages(outDb: unknown) {
  await drainSession(outDb);
}

async function drainSession(outDb: unknown) {
  const allDue = getDueOutboundMessages(outDb);
  for (const msg of allDue) {
    await deliverMessage(msg, {}, {});
  }
}

export async function deliverMessage(msg: Record<string, unknown>, session: unknown, inDb: unknown) {
  const content = JSON.parse(msg.content as string);
  if (msg.kind === 'system') {
    await handleSystemAction(content, session, inDb);
    return;
  }
  if (msg.channel_type === 'agent') {
    await routeAgentMessage(msg, session);
  }
}

export async function handleSystemAction(content: Record<string, unknown>, session: unknown, inDb: unknown) {
  const registered = actionHandlers.get(content.action as string);
  if (registered) await registered(content, session, inDb);
}
