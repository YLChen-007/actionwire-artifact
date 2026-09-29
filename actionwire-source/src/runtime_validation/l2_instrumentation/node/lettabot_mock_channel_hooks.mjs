function replaceOnce(source, marker, replacement) {
  if (!source.includes(marker)) {
    throw new Error(`LettaBot mock-channel bridge marker is missing: ${marker}`);
  }
  return source.replace(marker, replacement);
}

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (!result.source) {
    return result;
  }

  if (url.endsWith('/dist/config/types.js')) {
    const source = replaceOnce(
      result.source.toString('utf8'),
      'export function normalizeAgents',
      'function originalNormalizeAgents',
    );
    return {
      ...result,
      format: 'module',
      source: `${source}
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
    );
    return {
      ...result,
      format: 'module',
      source: `import { MockChannelAdapter } from '../test/mock-channel.js';
${source}
export function createChannelsForAgent(agentConfig, attachmentsDir, attachmentsMaxBytes) {
  const adapters = originalCreateChannelsForAgent(agentConfig, attachmentsDir, attachmentsMaxBytes);
  if (agentConfig.channels?.mock?.enabled) {
    const adapter = new MockChannelAdapter();
    adapters.push(adapter);
    if (typeof adapter.simulateMessage === 'function') {
      setTimeout(() => {
        adapter.simulateMessage(process.env.CLAWGAP_L2_PROMPT ?? 'environment probe').catch(error => {
          console.error('[MockChannel] Environment probe failed:', error);
        });
      }, 2000);
    }
  }
  return adapters;
}
`,
    };
  }

  return result;
}
