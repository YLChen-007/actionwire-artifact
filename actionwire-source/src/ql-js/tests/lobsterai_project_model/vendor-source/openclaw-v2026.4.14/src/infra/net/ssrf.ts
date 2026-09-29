export function isPrivateNetworkAllowedByPolicy(policy?: { dangerouslyAllowPrivateNetwork?: boolean }) {
  return policy?.dangerouslyAllowPrivateNetwork === true;
}

function shouldSkipPrivateNetworkChecks(_hostname: string, policy?: object) {
  return isPrivateNetworkAllowedByPolicy(policy);
}

function resolveHostnamePolicyChecks(hostname: string, policy?: object) {
  return shouldSkipPrivateNetworkChecks(hostname, policy);
}

export async function resolvePinnedHostnameWithPolicy(hostname: string, params: { policy?: object }) {
  resolveHostnamePolicyChecks(hostname, params.policy);
}
