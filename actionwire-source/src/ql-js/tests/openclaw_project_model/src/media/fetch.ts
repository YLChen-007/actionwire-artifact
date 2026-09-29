async function readErrorBodySnippet(res: Response) {
  return res.text();
}

export async function fetchRemoteMedia(options: {
  url: string;
  fetchImpl: typeof fetch;
}) {
  const { url, fetchImpl: fetcher } = options;
  const res = await fetcher(url);
  if (!res.ok) return readErrorBodySnippet(res);
  return "ok";
}
