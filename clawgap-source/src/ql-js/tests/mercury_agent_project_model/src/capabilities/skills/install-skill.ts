import type { SkillLoader } from '../../skills/loader';

function parseYaml(content: string): { name: string } {
  return { name: content };
}

export function createInstallSkillTool(skillLoader: SkillLoader) {
  return {
    execute: async ({ content, url }: { content?: string; url?: string }) => {
      if (url) await fetch(url);
      const skillContent = content || url || '';
      const meta = parseYaml(skillContent);
      return skillLoader.saveSkill(meta.name, skillContent);
    },
  };
}
