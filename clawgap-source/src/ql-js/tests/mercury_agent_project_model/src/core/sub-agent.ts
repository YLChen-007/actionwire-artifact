import { generateText } from 'ai';

export class SubAgent {
  capabilities = { getTools() { return {}; } };
  run(_task: string) {
    return generateText({ tools: this.capabilities.getTools() });
  }
}
