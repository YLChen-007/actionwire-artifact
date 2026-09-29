import { createPluginHandler } from "./deliver";
import { outbound } from "../../../extensions/feishu/src/outbound";

export async function runMessageAction(input: {
  params: { media?: string };
  media?: string;
}) {
  return handleSendAction(input.params, input.media);
}

function readStringParam(params: { media?: string }, field: "media") {
  return params[field];
}

async function handleSendAction(params: { media?: string }, fallback?: string) {
  const mediaUrl = readStringParam(params, "media") ?? fallback ?? "";
  const handler = createPluginHandler(outbound);
  return handler(mediaUrl);
}
