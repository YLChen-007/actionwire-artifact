export async function githubRequest(path: string, options: Record<string, unknown> = {}) {
  const url = path.startsWith('http') ? path : `https://api.github.com${path}`;
  return fetch(url, options);
}
