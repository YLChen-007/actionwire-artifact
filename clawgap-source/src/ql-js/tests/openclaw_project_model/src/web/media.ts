import { fetchRemoteMedia } from "../media/fetch";

async function loadWebMediaInternal(mediaUrl: string) {
  return fetchRemoteMedia({ url: mediaUrl, fetchImpl: fetch });
}

export async function loadWebMedia(mediaUrl: string) {
  return loadWebMediaInternal(mediaUrl);
}
