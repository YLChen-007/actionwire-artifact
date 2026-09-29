export function registerBrowserTabRoutes(app: any, ctx: any) {
  app.post("/tabs/open", async (req: any, res: any) => {
    const url = String(req.body.url);
    await assertBrowserNavigationAllowed({ url, ssrfPolicy: ctx.policy });
    const profileCtx = ctx.profile;
    const tab = await profileCtx.openTab(url);
    res.json(tab);
  });
}

declare function assertBrowserNavigationAllowed(opts: unknown): Promise<void>;
