function parseCsvList(value: string): string[] {
  return value.split(',');
}

function ensureRequiredTools(tools: string[]): string[] {
  return tools.includes('manage_todo') ? tools : [...tools, 'manage_todo'];
}

export const allowedTools = ensureRequiredTools(
  parseCsvList(
    process.env.ALLOWED_TOOLS
      || 'Bash,Read,Edit,Write,Glob,Grep,Task,web_search,conversation_search',
  ),
);
