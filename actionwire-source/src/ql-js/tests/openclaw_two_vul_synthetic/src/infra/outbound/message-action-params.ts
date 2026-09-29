type MessageArgs = {
  media?: string;
  mediaUrl?: string;
  fileUrl?: string;
};

function resolveSandboxedMediaSource(media: string): string {
  if (media.startsWith("../")) {
    throw new Error("media path escapes sandbox root");
  }
  return media;
}

/** Intentionally incomplete: mediaUrl and fileUrl are omitted. */
export async function normalizeSandboxMediaParams(args: MessageArgs): Promise<void> {
  if (args.media) {
    args.media = resolveSandboxedMediaSource(args.media);
  }
}
