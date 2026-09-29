type PromptInputBlock = { text: string }

declare function getTransport(): {
  call<T>(action: string, payload?: Record<string, unknown>): Promise<T>
}

export async function acpPrompt(
  connectionId: string,
  blocks: PromptInputBlock[],
  folderId: number | null = null,
  conversationId: number | null = null,
  clientMessageId: string | null = null
): Promise<void> {
  await getTransport().call("acp_prompt", {
    connectionId,
    blocks,
    folderId,
    conversationId,
    clientMessageId,
  })
}
