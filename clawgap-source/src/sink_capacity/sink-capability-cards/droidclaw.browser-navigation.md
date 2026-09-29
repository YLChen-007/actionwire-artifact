# DroidClaw.executeOpenUrl

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-9c61cca15e7726c5
api: DroidClaw.executeOpenUrl
api_family: droidclaw.browser-navigation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: browser-navigation
normative_authority: capability-facts-only
bound_sinks:
- executeOpenUrl
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-6e76cc1d
  capability: Ask Android to open a model-selected URL or URI in the default handler on the attached device.
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
- default_id: legacy-default-8841433c
  role_id: null
  value: Android resolves the VIEW intent using installed applications and their ambient authentication and network access; accepted schemes are determined by the device runtime.
  security_effect: Android resolves the VIEW intent using installed applications and their ambient authentication and network access; accepted schemes are determined by the device runtime.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeOpenUrl({ action: "open_url", url: "https://example.com" })'
  capability_edge: 'executeOpenUrl({ action: "open_url", url: modelUrl })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
