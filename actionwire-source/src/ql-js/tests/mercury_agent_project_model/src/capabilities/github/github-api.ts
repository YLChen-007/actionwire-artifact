import { githubRequest } from '../../utils/github';

export function createGithubApiTool() {
  return { execute: async ({ path }: { path: string }) => githubRequest(path, {}) };
}
