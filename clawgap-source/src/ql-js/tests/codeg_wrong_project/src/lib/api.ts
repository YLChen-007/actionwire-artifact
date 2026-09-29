declare function getTransport(): {
  call<T>(action: string, payload?: Record<string, unknown>): Promise<T>
}

export async function acpPrompt(connectionId: string, blocks: unknown[]): Promise<void> {
  await getTransport().call("acp_prompt", { connectionId, blocks })
}
