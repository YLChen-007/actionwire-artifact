export function isSafeBinUsage(params: { argv: string[] }) {
  return params.argv.length > 0;
}

export function evaluateSegments(segments: string[][]) {
  return segments.every((argv) => isSafeBinUsage({ argv }));
}

export function evaluateExecAllowlist(params: { command: string[] }) {
  return evaluateSegments([params.command]);
}

export function evaluateShellAllowlist(params: { command: string[] }) {
  return evaluateExecAllowlist(params);
}
