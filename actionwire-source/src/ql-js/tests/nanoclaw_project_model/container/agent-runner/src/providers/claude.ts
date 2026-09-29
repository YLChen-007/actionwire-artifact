declare function sdkQuery(options: unknown): unknown;
declare function sdkQueryLike(options: unknown): unknown;

const TOOL_ALLOWLIST = [
  'Bash',
  'Read',
  'Write',
  'Edit',
  'Glob',
  'Grep',
  'WebSearch',
  'WebFetch',
  'Task',
  'TaskOutput',
  'TaskStop',
  'TeamCreate',
  'TeamDelete',
  'SendMessage',
  'TodoWrite',
  'ToolSearch',
  'Skill',
  'NotebookEdit',
];

const DECOY_ALLOWLIST = ['DecoyOnly'];

function mcpAllowPattern(serverName: string): string {
  return `mcp__${serverName.replace(/[^a-zA-Z0-9_-]/g, '_')}__*`;
}

export class ClaudeProvider {
  constructor(private mcpServers: Record<string, unknown>) {}

  query(prompt: string): unknown {
    return sdkQuery({
      prompt,
      options: {
        allowedTools: [
          ...TOOL_ALLOWLIST,
          ...Object.keys(this.mcpServers).map(mcpAllowPattern),
        ],
      },
    });
  }
}

// Same call name outside ClaudeProvider.query and an unforwarded list are decoys.
export function queryLikeSdk(prompt: string): unknown {
  const TOOL_ALLOWLIST = ['FakeSdkTool'];
  sdkQueryLike({ prompt, options: { allowedTools: [...TOOL_ALLOWLIST] } });
  return sdkQuery({ prompt });
}

void DECOY_ALLOWLIST;
