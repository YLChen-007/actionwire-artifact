# DroidClaw.executeLaunch or DroidClaw.executeSwitchApp

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-21169261c2ec4ad3
api: DroidClaw.executeLaunch or DroidClaw.executeSwitchApp
api_family: droidclaw.app-launch
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: app-launch
normative_authority: capability-facts-only
bound_sinks:
- executeLaunch
- executeSwitchApp
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-7a170d8f
  capability: Launch or switch to an Android application, or start an Android intent using model-selected package, activity, URI, and extra values.
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-0b712baa
  role_id: null
  value: A package without an activity uses the default launcher activity; a URI selects the VIEW intent and the connected device resolves the receiving application.
  security_effect: A package without an activity uses the default launcher activity; a URI selects the VIEW intent and the connected device resolves the receiving application.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeSwitchApp({ action: "switch_app", package: "com.example.reviewed" })'
  capability_edge: 'executeLaunch({ action: "launch", uri: modelUri, extras: modelExtras })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
