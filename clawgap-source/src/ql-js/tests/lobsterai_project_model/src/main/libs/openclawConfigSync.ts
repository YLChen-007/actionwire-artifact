export class OpenClawConfigSync {
  buildBrowserConfig(browserWebAccess: { networkMode: string }) {
    return browserWebAccess.networkMode === "strict"
      ? { ssrfPolicy: { dangerouslyAllowPrivateNetwork: false } }
      : { ssrfPolicy: { dangerouslyAllowPrivateNetwork: true } };
  }
}
