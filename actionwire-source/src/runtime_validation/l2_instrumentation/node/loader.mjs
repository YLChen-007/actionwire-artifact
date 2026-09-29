import fs from 'node:fs';
import path from 'node:path';
import childProcess from 'node:child_process';

const configPath = process.env.CLAWGAP_L2_INSTRUMENTATION;
if (!configPath) {
  throw new Error('CLAWGAP_L2_INSTRUMENTATION is required');
}
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const output = path.resolve(config.event_path);
fs.mkdirSync(path.dirname(output), { recursive: true });
let sequence = 0;

function append(kind, details = {}) {
  sequence += 1;
  const anchor = config.anchors.find((row) => row.kind === kind);
  fs.appendFileSync(
    output,
    `${JSON.stringify({
      schema_version: 'clawgap-l2-evidence-event/v1',
      event_id: `${config.case_id}:${config.attempt}:${sequence}`,
      case_id: config.case_id,
      correlation_id: config.correlation_id,
      attempt: config.attempt,
      role: config.role,
      kind,
      stage: kind,
      project: config.project,
      environment_id: config.environment_id,
      probe_id: config.probe_id,
      candidate_id: config.candidate_id,
      ordinal: sequence,
      source_anchor: anchor?.anchor ?? 'instrumentation-boundary:1',
      intercept_before_execution: kind === 'pre-effect',
      details,
    })}\n`,
  );
}

const realFetch = globalThis.fetch;
globalThis.fetch = async (...args) => {
  const url = String(args[0]);
  if (url.startsWith(config.provider_base_url)) {
    append('provider-request', { url });
  }
  return realFetch(...args);
};

if (config.intercept_effects) for (const name of ['spawn', 'spawnSync', 'exec', 'execFile', 'execFileSync']) {
  const original = childProcess[name];
  if (typeof original !== 'function') continue;
  childProcess[name] = function intercepted(...args) {
    append('pre-effect', { primitive: `child_process.${name}`, command: String(args[0]) });
    throw new Error(`ClawGap intercepted child_process.${name} before execution`);
  };
}
