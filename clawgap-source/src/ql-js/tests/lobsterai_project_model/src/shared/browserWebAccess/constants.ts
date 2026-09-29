export const defaultBrowserWebAccessConfig = { networkMode: "proxy-compatible" };
export function normalizeBrowserWebAccessConfig(value: unknown) {
  return value ?? defaultBrowserWebAccessConfig;
}
