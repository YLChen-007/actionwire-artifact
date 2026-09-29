# Playwright Page.goto in LobsterAI bundled OpenClaw runtime

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-b361a9f6ca2bb402
api: Playwright Page.goto in LobsterAI bundled OpenClaw runtime
api_family: lobsterai.browser-navigation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: lobsterai
  version: legacy-source-bound
capability_class: browser-navigation
normative_authority: capability-facts-only
bound_sinks:
- page.goto
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-5230c9eb
  capability: Navigates the LobsterAI-managed host browser to a model-selected HTTP or HTTPS URL. Under a policy that allows private networks, the browser can reach loopback, RFC1918, link-local, VPN, and cloud-metadata addresses visible from the desktop host.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-385c6305
  role_id: null
  value: LobsterAI 2026.6.10 defaults browser network mode to ProxyCompatible and serializes dangerouslyAllowPrivateNetwork=true; its managed prompt also selects target="host". The bundled runtime follows redirects and performs navigation in Chromium's network stack.
  security_effect: LobsterAI 2026.6.10 defaults browser network mode to ProxyCompatible and serializes dangerouslyAllowPrivateNetwork=true; its managed prompt also selects target="host". The bundled runtime follows redirects and performs navigation in Chromium's network stack.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'page.goto("https://example.com", { timeout: 30000 })'
  capability_edge: 'page.goto(modelSelectedPrivateNetworkUrl, { timeout: 30000 })'
provenance:
- benchmark/typescript/LobsterAI/src/shared/browserWebAccess/constants.ts
- benchmark/typescript/LobsterAI/src/main/libs/openclawConfigSync.ts
- benchmark/typescript/LobsterAI/vendor-source/openclaw-v2026.4.14/extensions/browser/src/browser/pw-session.ts
```
