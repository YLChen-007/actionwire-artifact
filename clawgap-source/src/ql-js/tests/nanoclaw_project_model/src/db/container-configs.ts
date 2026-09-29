const db = { prepare(_sql: string) { return { run(..._values: unknown[]) {} }; } };
export function updateContainerConfigJson(group: string, _column: string, value: unknown) {
  db.prepare(`UPDATE container_configs SET ${'mcp_servers'} = ? WHERE agent_group_id = ?`).run(JSON.stringify(value), group);
}
