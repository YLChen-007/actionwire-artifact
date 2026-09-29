import { loadWebMedia } from "../../web/media";

export function createImageTool() {
  return {
    name: "image",
    execute: async (_id: string, args: { image: string }) => loadWebMedia(args.image),
  };
}
