import { validateRequiredParams } from "./validation";

interface TaskArgs {
  description?: string;
  prompt?: string;
  subagent_type?: string;
  model?: string;
  run_in_background?: boolean;
  agent_id?: string;
  conversation_id?: string;
}

const VALID_DEPLOY_TYPES = new Set(["explore", "general-purpose"]);

function spawnBackgroundSubagentTask(args: object) {
  return args;
}

async function spawnSubagent(
  type: string,
  prompt: string,
  model: string | undefined,
  id: string,
  signal: undefined,
  agentId: string | undefined,
  conversationId: string | undefined,
  maxTurns: undefined,
) {
  return { type, prompt, model, id, signal, agentId, conversationId, maxTurns };
}

export async function task(args: TaskArgs) {
  const { prompt = "", model } = args;
  if (args.agent_id) {
    validateRequiredParams(args, ["prompt"], "Task");
  } else {
    validateRequiredParams(args, ["subagent_type", "prompt"], "Task");
  }
  const subagent_type = args.agent_id
    ? args.subagent_type || "general-purpose"
    : (args.subagent_type as string);
  const allConfigs = { explore: true, "general-purpose": true };
  if (!(subagent_type in allConfigs)) {
    return "invalid subagent";
  }
  if (args.agent_id && !VALID_DEPLOY_TYPES.has(subagent_type)) {
    return "invalid deployment type";
  }
  if (args.run_in_background) {
    return spawnBackgroundSubagentTask({
      subagentType: subagent_type,
      prompt,
      model,
      existingAgentId: args.agent_id,
    });
  }
  return spawnSubagent(
    subagent_type,
    prompt,
    model,
    "subagent-id",
    undefined,
    args.agent_id,
    args.conversation_id,
    undefined,
  );
}
