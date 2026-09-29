function replaceOnce(source, marker, replacement, label) {
  const count = source.split(marker).length - 1;
  if (count !== 1) {
    throw new Error(`LettaBot L2 instrumentation marker mismatch (${label}): ${count}`);
  }
  return source.replace(marker, replacement);
}

function replaceFirst(source, marker, replacement, label) {
  if (!source.includes(marker)) {
    throw new Error(`LettaBot L2 instrumentation marker is missing: ${label}`);
  }
  return source.replace(marker, replacement);
}

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (!result.source) return result;

  if (url.endsWith('/dist/config/types.js')) {
    const source = replaceOnce(
      result.source.toString('utf8'),
      'export function normalizeAgents',
      'function originalNormalizeAgents',
      'config normalization',
    );
    return {
      ...result,
      format: 'module',
      source: `${source}
const clawgapRealFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = typeof input === 'string' ? input : input?.url ?? String(input);
  const hostname = new URL(url).hostname;
  const protocol = new URL(url).protocol;
  if ((protocol === 'http:' || protocol === 'https:') && hostname !== '127.0.0.1' && hostname !== 'localhost') {
    throw new Error('ClawGap LettaBot L2 rejected a non-loopback fetch');
  }
  return clawgapRealFetch(input, init);
};
export function normalizeAgents(config) {
  const agents = originalNormalizeAgents(config);
  if (config.channels?.mock?.enabled) {
    for (const agent of agents) agent.channels.mock = config.channels.mock;
  }
  return agents;
}
`,
    };
  }

  if (url.endsWith('/dist/channels/factory.js')) {
    const source = replaceOnce(
      result.source.toString('utf8'),
      'export function createChannelsForAgent',
      'function originalCreateChannelsForAgent',
      'factory export',
    );
    return {
      ...result,
      format: 'module',
      source: `import { appendFileSync as clawgapAppendFileSync } from 'node:fs';
import { MockChannelAdapter } from '../test/mock-channel.js';
function __clawgapL2Event(stage, detail = {}) {
  const eventPath = process.env.CLAWGAP_L2_EVENT_PATH;
  if (!eventPath) return;
  clawgapAppendFileSync(eventPath, JSON.stringify({
    schema_version: 'clawgap-dynamic-trigger-lettabot-l2-event/v1',
    stage,
    candidate_id: process.env.CLAWGAP_L2_CANDIDATE_ID,
    case_id: process.env.CLAWGAP_L2_CASE_ID,
    attempt: Number(process.env.CLAWGAP_L2_ATTEMPT || '0'),
    role: process.env.CLAWGAP_L2_ROLE,
    correlation_id: process.env.CLAWGAP_L2_CORRELATION_ID,
    fixture_id: process.env.CLAWGAP_L2_FIXTURE_ID,
    detail,
  }) + '\\n');
}
${source}
export function createChannelsForAgent(agentConfig, attachmentsDir, attachmentsMaxBytes) {
  const adapters = originalCreateChannelsForAgent(agentConfig, attachmentsDir, attachmentsMaxBytes);
  if (!agentConfig.channels?.mock?.enabled) return adapters;
  const adapter = new MockChannelAdapter();
  const delay = Number(process.env.CLAWGAP_L2_PROMPT_DELAY_MS || '1500');
  setTimeout(() => {
    __clawgapL2Event('prompt_received', {
      prompt: process.env.CLAWGAP_L2_PROMPT,
      channel: 'mock',
    });
    adapter
      .simulateMessage(process.env.CLAWGAP_L2_PROMPT || '', { timeoutMs: 30000 })
      .then((response) => {
        __clawgapL2Event('channel_response', { response });
        __clawgapL2Event('target_completed', {});
        setTimeout(() => process.exit(0), 50);
      })
      .catch((error) => {
        __clawgapL2Event('target_error', { message: String(error) });
        process.exitCode = 1;
      });
  }, delay);
  return [...adapters, adapter];
}
`,
    };
  }

  if (url.endsWith('/node_modules/@letta-ai/letta-code/letta.js')) {
    let source = result.source.toString('utf8');
    source = source.replace('#!/usr/bin/env node\n', '');
    const preamble = `import { appendFileSync as clawgapAppendFileSync } from 'node:fs';
import { EventEmitter as ClawgapEventEmitter } from 'node:events';
import { PassThrough as ClawgapPassThrough } from 'node:stream';
function __clawgapL2Event(stage, detail = {}) {
  const eventPath = process.env.CLAWGAP_L2_EVENT_PATH;
  if (!eventPath) return;
  const row = {
    schema_version: 'clawgap-dynamic-trigger-lettabot-l2-event/v1',
    stage,
    candidate_id: process.env.CLAWGAP_L2_CANDIDATE_ID,
    case_id: process.env.CLAWGAP_L2_CASE_ID,
    attempt: Number(process.env.CLAWGAP_L2_ATTEMPT || '0'),
    role: process.env.CLAWGAP_L2_ROLE,
    correlation_id: process.env.CLAWGAP_L2_CORRELATION_ID,
    fixture_id: process.env.CLAWGAP_L2_FIXTURE_ID,
    detail,
  };
  clawgapAppendFileSync(eventPath, JSON.stringify(row) + '\\n');
}
const clawgapBundleRealFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = typeof input === 'string' ? input : input?.url ?? String(input);
  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname;
  if ((parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') && hostname !== '127.0.0.1' && hostname !== 'localhost') {
    throw new Error('ClawGap Letta Code L2 rejected a non-loopback fetch: ' + url);
  }
  return clawgapBundleRealFetch(input, init);
};
class ClawgapInterceptedChild extends ClawgapEventEmitter {
  stdout = new ClawgapPassThrough();
  stderr = new ClawgapPassThrough();
  stdin = new ClawgapPassThrough();
  pid = 424242;
  killed = false;
  kill(signal) {
    this.killed = true;
    queueMicrotask(() => {
      this.emit('exit', 0, signal || null);
      this.emit('close', 0, signal || null);
    });
    return true;
  }
  unref() {}
}
function __clawgapInterceptSubagentSpawn(command, args, options) {
  __clawgapL2Event('pre_effect_interception', {
    command: String(command),
    args,
    cwd: options?.cwd,
    env: {
      LETTA_BASE_URL: options?.env?.LETTA_BASE_URL,
      LETTA_API_KEY: options?.env?.LETTA_API_KEY ? 'clawgap-loopback-mock' : undefined,
      LETTA_PARENT_AGENT_ID: options?.env?.LETTA_PARENT_AGENT_ID,
    },
  });
  const child = new ClawgapInterceptedChild();
  queueMicrotask(() => {
    child.emit('spawn');
    child.stdout.end(JSON.stringify({
      type: 'init',
      agent_id: 'clawgap-intercepted-subagent',
      conversation_id: 'clawgap-intercepted-conversation',
    }) + '\\n');
    child.stdout.end(JSON.stringify({
      type: 'result',
      result: 'clawgap intercepted subagent effect',
      is_error: false,
      duration_ms: 1,
      usage: { total_tokens: 0 },
    }) + '\\n');
    child.stderr.end();
    child.emit('exit', 0, null);
    child.emit('close', 0, null);
  });
  return child;
}
`;
    source = preamble + source;
    source = replaceFirst(
      source,
      'async function executeTool(name, args, options) {',
      `async function executeTool(name, args, options) {
  if (name === 'Task') {
    __clawgapL2Event('registry_dispatch', {
      tool_name: name,
      tool_call_id: options?.toolCallId,
      arguments: args,
    });
  }`,
      'native dispatch',
    );
    source = replaceOnce(
      source,
      'async function task(args) {',
      `async function task(args) {
  __clawgapL2Event('handler_entered', {
    tool_name: 'Task',
    arguments: args,
  });
  __clawgapL2Event('controlled_argument_recorded', {
    argument_path: ['subagent_type'],
    value: args?.subagent_type,
  });`,
      'Task handler',
    );
    source = replaceOnce(
      source,
      'const subagent_type = isDeployingExisting ? args.subagent_type || "general-purpose" : args.subagent_type;\n  const allConfigs = await getAllSubagentConfigs();',
      `const subagent_type = isDeployingExisting ? args.subagent_type || "general-purpose" : args.subagent_type;
  const allConfigs = await getAllSubagentConfigs();
  __clawgapL2Event('gate_observed', {
    gate: isDeployingExisting ? 'VALID_DEPLOY_TYPES' : 'subagent_type-in-allConfigs',
    value: subagent_type,
    admitted: subagent_type in allConfigs,
    resolved_config: allConfigs[subagent_type] || null,
  });`,
      'Task gate',
    );
    source = replaceOnce(
      source,
      'const { taskId, outputFile: outputFile2, subagentId: subagentId2 } = spawnBackgroundSubagentTask({',
      `__clawgapL2Event('sink_reached', {
    sink: 'background-subagent-delegation',
    value: subagent_type,
    resolved_config: allConfigs[subagent_type] || null,
  });
    const { taskId, outputFile: outputFile2, subagentId: subagentId2 } = spawnBackgroundSubagentTask({`,
      'background sink',
    );
    source = replaceOnce(
      source,
      'const result = await spawnSubagent(',
      `__clawgapL2Event('sink_reached', {
    sink: 'foreground-subagent-delegation',
    value: subagent_type,
    resolved_config: allConfigs[subagent_type] || null,
  });
    const result = await spawnSubagent(`,
      'foreground sink',
    );
    source = replaceOnce(
      source,
      'const proc2 = spawn4(launcher.command, launcher.args, {',
      'const proc2 = __clawgapInterceptSubagentSpawn(launcher.command, launcher.args, {',
      'subagent spawn',
    );
    return { ...result, format: 'module', source };
  }

  return result;
}
