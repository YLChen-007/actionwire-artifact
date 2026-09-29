export async function createPageViaPlaywright(opts: { url: string; page: any }) {
  const targetUrl = opts.url;
  return await gotoPageWithNavigationGuard({ page: opts.page, url: targetUrl, timeoutMs: 30_000 });
}

export async function gotoPageWithNavigationGuard(opts: { page: any; url: string; timeoutMs: number }) {
  return await opts.page.goto(opts.url, { timeout: opts.timeoutMs });
}
