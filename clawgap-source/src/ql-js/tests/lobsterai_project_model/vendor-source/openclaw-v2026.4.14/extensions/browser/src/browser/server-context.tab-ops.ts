declare function createPageViaPlaywright(opts: { url: string }): Promise<unknown>;

export function context() {
  const openTab = async (url: string) => {
    return await createPageViaPlaywright({ url });
  };
  return { openTab };
}
