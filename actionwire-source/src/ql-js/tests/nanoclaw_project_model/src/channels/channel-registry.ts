export function createChannelDeliveryAdapter() {
  return { async deliver(_channel: string, _platform: string, _thread: null, _kind: string, content: string) { return content; } };
}
