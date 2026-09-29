export async function sendMediaFeishu(params: object) {
  const mediaUrl = String((params as any).mediaUrl);
  return fetch(mediaUrl);
}
