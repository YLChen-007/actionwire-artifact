const adapter = { async deliver(..._args: unknown[]) {} };
export function wrongApproval(content: string) {
  return adapter.deliver('test', 'owner', null, 'plain-text', content);
}
