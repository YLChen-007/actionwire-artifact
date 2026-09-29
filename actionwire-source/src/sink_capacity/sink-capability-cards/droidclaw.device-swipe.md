# DroidClaw.executeSwipe or DroidClaw.executeScroll

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-06e34cc40d36a739
api: DroidClaw.executeSwipe or DroidClaw.executeScroll
api_family: droidclaw.device-swipe
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: device-swipe
normative_authority: capability-facts-only
bound_sinks:
- executeSwipe
- executeScroll
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-7b23bbb8
  capability: Perform a directional swipe or scroll gesture on the attached Android device.
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
- default_id: legacy-default-29e9f7ed
  role_id: null
  value: Named directions are converted to coordinates derived from the current device dimensions; scroll reverses swipe direction to express the user's view of content movement.
  security_effect: Named directions are converted to coordinates derived from the current device dimensions; scroll reverses swipe direction to express the user's view of content movement.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeScroll({ action: "scroll", direction: "down" })'
  capability_edge: 'executeSwipe({ action: "swipe", direction: modelDirection })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
