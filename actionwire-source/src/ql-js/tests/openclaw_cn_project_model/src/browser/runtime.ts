export async function evaluateViaPlaywright(opts: unknown) {
  const page: any = {};
  const locator: any = {};
  const fnText = String(opts);
  await locator.evaluate(() => {}, fnText);
  await page.evaluate(() => {}, fnText);
}

export async function clickViaPlaywright(opts: unknown) {
  const locator: any = {};
  await locator.click({ timeout: opts });
  await locator.dblclick({ timeout: opts });
}

export async function navigateViaPlaywright(opts: any) {
  const page: any = {};
  await page.goto(opts.url);
}

export async function createPageViaPlaywright(opts: any) {
  const page: any = {};
  await page.goto(opts.url);
}

export async function createTargetViaCdp(opts: any) {
  return await Promise.resolve(async (send: any) => {
    await send("Target.createTarget", { url: opts.url });
  });
}

export async function fetchJson(url: string, timeoutMs: number, init: object) {
  return fetch(url, { ...init, timeoutMs });
}
