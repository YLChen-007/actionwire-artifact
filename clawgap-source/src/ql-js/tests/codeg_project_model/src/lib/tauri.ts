declare function invoke<T>(action: string, payload: Record<string, unknown>): Promise<T>

export async function acpPrompt(connectionId: string, blocks: unknown[]): Promise<void> {
  return invoke("acp_prompt", { connectionId, blocks })
}
