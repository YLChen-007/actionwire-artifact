# DroidClaw.executeOpenSettings

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-95c806d7f51f0153
api: DroidClaw.executeOpenSettings
api_family: droidclaw.settings-navigation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: settings-navigation
normative_authority: capability-facts-only
bound_sinks:
- executeOpenSettings
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-8e3de741
  capability: Open the Android settings screen selected by the model from DroidClaw's supported settings map.
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
- default_id: legacy-default-31b23ec9
  role_id: null
  value: The selected symbolic setting is mapped to a fixed Android settings intent; the device resolves and displays that screen with the current user context.
  security_effect: The selected symbolic setting is mapped to a fixed Android settings intent; the device resolves and displays that screen with the current user context.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeOpenSettings({ action: "open_settings", setting: "wifi" })'
  capability_edge: 'executeOpenSettings({ action: "open_settings", setting: modelSetting })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
