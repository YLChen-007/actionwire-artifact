import { SubAgent } from './sub-agent';

export class Supervisor {
  async spawn(config: { task: string }) { return this.startAgentInBackground(config); }
  async startAgentInBackground(config: { task: string }) {
    const subAgent = new SubAgent();
    return subAgent.run(config.task);
  }
}
