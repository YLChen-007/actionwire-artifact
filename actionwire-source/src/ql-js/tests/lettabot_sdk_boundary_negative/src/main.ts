function parseCsvList(value: string): string[] {
  return value.split(',');
}

function ensureRequiredTools(tools: string[]): string[] {
  return tools.includes('manage_todo') ? tools : [...tools, 'manage_todo'];
}

// A custom partial allowlist must not be reported as the repository's default SDK set.
export const allowedTools = ensureRequiredTools(
  parseCsvList(process.env.ALLOWED_TOOLS || 'Bash,Read,Edit'),
);
