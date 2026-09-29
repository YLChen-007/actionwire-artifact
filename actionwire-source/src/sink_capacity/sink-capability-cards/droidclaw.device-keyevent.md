# DroidClaw.executeKeyevent

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-bf6234836910b835
api: DroidClaw.executeKeyevent
api_family: droidclaw.device-keyevent
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: device-keyevent
normative_authority: capability-facts-only
bound_sinks:
- executeKeyevent
roles:
- role_id: code
  description: Legacy controlled role code.
  bindings:
  - expression: code
    caller_bindable: true
facets:
- facet_id: legacy-facet-f50c70e9
  capability: Send an arbitrary model-selected Android keycode to the attached device.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-a61cc104
  role_id: null
  value: Android delivers the key event to the current system or application focus; DroidClaw does not limit the code to its named convenience actions.
  security_effect: Android delivers the key event to the current system or application focus; DroidClaw does not limit the code to its named convenience actions.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeKeyevent({ action: "keyevent", code: 4 })'
  capability_edge: 'executeKeyevent({ action: "keyevent", code: modelKeycode })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
