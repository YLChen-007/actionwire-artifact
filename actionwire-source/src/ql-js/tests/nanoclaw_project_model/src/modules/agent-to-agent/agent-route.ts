import fs from 'node:fs';
export function forwardAttachedFiles(
  source: { path: string; filenames: string[] },
  target: { path: string },
) {
  fs.copyFileSync(source.path, target.path);
}

export function forwardFileAttachments(msg: Record<string, unknown>) {
  const parsed = JSON.parse(msg.content as string);
  const files = parsed.files as unknown;
  const filenames = Array.isArray(files) ? files.filter((f): f is string => typeof f === 'string') : [];
  return forwardAttachedFiles({ path: String(msg.content), filenames }, { path: '/target/inbox' });
}

export function routeAgentMessage(msg: Record<string, unknown>, _session: unknown) {
  return forwardFileAttachments(msg);
}
