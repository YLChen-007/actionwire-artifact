import { sendMediaFeishu } from "./media";

export const outbound = {
  deliveryMode: "direct",
  sendMedia: async (mediaUrl: string) => sendMediaFeishu({ mediaUrl }),
};
