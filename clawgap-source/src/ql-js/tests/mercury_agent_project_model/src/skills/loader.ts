import { writeFileSync } from 'node:fs';

export class SkillLoader {
  saveSkill(name: string, content: string) {
    writeFileSync(`/tmp/${name}`, content);
  }
}
