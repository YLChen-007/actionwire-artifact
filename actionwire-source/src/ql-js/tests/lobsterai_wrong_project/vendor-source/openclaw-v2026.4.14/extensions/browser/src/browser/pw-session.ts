export async function gotoPageWithNavigationGuard(opts: { page: any; url: string }) {
  return await opts.page.goto(opts.url);
}
