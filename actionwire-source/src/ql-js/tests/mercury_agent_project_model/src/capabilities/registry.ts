import { createRunCommandTool } from './shell/run-command';
import { createFetchUrlTool } from './web/fetch-url';
import { createGithubApiTool } from './github/github-api';
import { createReadFileTool } from './filesystem/read-file';
import { createCreateFileTool } from './filesystem/create-file';
import { createInstallSkillTool } from './skills/install-skill';
import { createDelegateTaskTool } from './subagents/delegate-task';
import { PermissionManager } from './permissions';

export class CapabilityRegistry {
  tools: Record<string, unknown> = {};

  registerAll() {
    this.tools.run_command = createRunCommandTool(new PermissionManager());
    this.tools.fetch_url = createFetchUrlTool();
    this.tools.github_api = createGithubApiTool();
    this.tools.read_file = createReadFileTool();
    this.tools.create_file = createCreateFileTool();
    this.tools.install_skill = createInstallSkillTool({ saveSkill() {} });
    this.tools.delegate_task = createDelegateTaskTool({ spawn() {} });
  }

  getTools() { return this.tools; }
}
