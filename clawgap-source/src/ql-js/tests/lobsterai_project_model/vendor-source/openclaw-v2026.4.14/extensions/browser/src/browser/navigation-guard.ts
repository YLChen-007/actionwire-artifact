declare function resolvePinnedHostnameWithPolicy(hostname: string, opts: unknown): Promise<void>;

export async function assertBrowserNavigationAllowed(opts: { url: string }) {
  const parsed = new URL(opts.url);
  await resolvePinnedHostnameWithPolicy(parsed.hostname, {});
}
