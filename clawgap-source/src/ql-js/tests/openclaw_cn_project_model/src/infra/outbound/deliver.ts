export function createPluginHandler(outbound: any) {
  return async function deliveryCallback(mediaUrl: string) {
    return outbound.sendMedia({ mediaUrl });
  };
}
