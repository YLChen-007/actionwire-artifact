import { runCommand } from '../invoke';

function register(_adapter: unknown) {}

const claudeAdapter = {
  invoke(opts: { message: string }) {
    const args: string[] = [];
    args.push(opts.message);
    return runCommand('claude', args);
  },
};

const codexAdapter = {
  invoke(options: { message: string }) {
    const args: string[] = [];
    args.push(options.message);
    return runCommand('codex', args);
  },
};

const opencodeAdapter = {
  invoke(opts: { message: string }) {
    const args: string[] = [];
    args.push(opts.message);
    return runCommand('opencode', args);
  },
};

register(claudeAdapter);
register(codexAdapter);
register(opencodeAdapter);
