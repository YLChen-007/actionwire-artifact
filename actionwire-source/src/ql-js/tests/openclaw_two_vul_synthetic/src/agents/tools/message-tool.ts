import { normalizeSandboxMediaParams } from "../../infra/outbound/message-action-params";
import { readLocalFileSafely } from "../../infra/fs-safe";

type MessageArgs = {
  media?: string;
  mediaUrl?: string;
  fileUrl?: string;
};

export function createMessageTool() {
  return {
    name: "message",
    execute: async (_toolCallId: string, args: MessageArgs) => {
      await normalizeSandboxMediaParams(args);
      const uncheckedAlias = args.mediaUrl ?? args.fileUrl;
      if (!uncheckedAlias) {
        return undefined;
      }
      return readLocalFileSafely(uncheckedAlias);
    },
  };
}
