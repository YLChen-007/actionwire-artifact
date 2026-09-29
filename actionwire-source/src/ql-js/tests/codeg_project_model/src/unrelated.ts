declare function getTransport(): {
  call<T>(action: string, payload?: Record<string, unknown>): Promise<T>
}

export async function terminalSpawn(initialCommand: string): Promise<void> {
  await getTransport().call("terminal_spawn", { initialCommand })
}

export async function saveFile(rootPath: string, content: string): Promise<void> {
  await getTransport().call("save_file_content", { rootPath, content })
}

export async function commit(path: string, message: string): Promise<void> {
  await getTransport().call("git_commit", { path, message })
}

export async function upsertMcp(server: unknown): Promise<void> {
  await getTransport().call("mcp_upsert_local_server", { server })
}

export async function dynamicCall(
  action: string,
  payload: Record<string, unknown>
): Promise<void> {
  await getTransport().call(action, payload)
}

export async function wrongPrompt(blocks: unknown[]): Promise<void> {
  await getTransport().call("acp_prompt_wrong", { blocks })
}

export const wrongPayload = {
  async acpPrompt(
    connectionId: string,
    blocks: unknown[],
    folderId: number | null,
    conversationId: number | null,
    clientMessageId: string | null
  ): Promise<void> {
    await getTransport().call("acp_prompt", {
      connectionId,
      messages: blocks,
      folderId,
      conversationId,
      clientMessageId,
    })
  },
}

declare const customTransport: {
  call<T>(action: string, payload?: Record<string, unknown>): Promise<T>
}

export async function wrongReceiver(
  connectionId: string,
  blocks: unknown[],
  folderId: number | null,
  conversationId: number | null,
  clientMessageId: string | null
): Promise<void> {
  await customTransport.call("acp_prompt", {
    connectionId,
    blocks,
    folderId,
    conversationId,
    clientMessageId,
  })
}
