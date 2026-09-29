# browserOpenTab or node browser proxy /tabs/open

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-e2d5e1b2a1908fee
api: browserOpenTab or node browser proxy /tabs/open
api_family: openclaw.browser-navigation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw
  version: legacy-source-bound
capability_class: browser-navigation
normative_authority: capability-facts-only
bound_sinks:
- browserOpenTab
- proxyRequest:/tabs/open
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-b2092343
  capability: Navigate a host, sandbox, or paired-node browser to a caller-selected URL and create or focus a browsing tab.
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
- default_id: legacy-default-37483400
  role_id: null
  value: The selected browser profile may carry authenticated cookies, local session state, extensions, and ambient network access; the boundary delegates navigation policy to the selected browser target.
  security_effect: The selected browser profile may carry authenticated cookies, local session state, extensions, and ambient network access; the boundary delegates navigation policy to the selected browser target.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'browserOpenTab(browserUrl, { profile: "research", targetUrl: "https://example.com" })'
  capability_edge: 'browserOpenTab(browserUrl, { profile: selectedProfile, targetUrl: selectedUrl })'
provenance:
- benchmark/typescript/openclaw/src/agents/tools/browser-tool.ts
```
