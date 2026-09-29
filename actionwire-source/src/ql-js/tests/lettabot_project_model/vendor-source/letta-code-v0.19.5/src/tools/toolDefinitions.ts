import { bash } from "./impl/Bash";
import { read } from "./impl/Read";
import { edit } from "./impl/Edit";
import { write } from "./impl/Write";
import { glob } from "./impl/Glob";
import { grep } from "./impl/Grep";
import { task } from "./impl/Task";

type ToolImplementation = (args: Record<string, unknown>) => Promise<unknown>;

const toolDefinitions = {
  Bash: { schema: {}, description: "bash", impl: bash as unknown as ToolImplementation },
  Read: { schema: {}, description: "read", impl: read as unknown as ToolImplementation },
  Edit: { schema: {}, description: "edit", impl: edit as unknown as ToolImplementation },
  Write: { schema: {}, description: "write", impl: write as unknown as ToolImplementation },
  Glob: { schema: {}, description: "glob", impl: glob as unknown as ToolImplementation },
  Grep: { schema: {}, description: "grep", impl: grep as unknown as ToolImplementation },
  Task: { schema: {}, description: "task", impl: task as unknown as ToolImplementation },
};

export const TOOL_DEFINITIONS = toolDefinitions;
