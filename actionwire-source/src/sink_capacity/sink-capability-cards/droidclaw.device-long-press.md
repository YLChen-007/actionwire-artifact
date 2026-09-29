# DroidClaw.executeLongPress

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-7adbbaf39f78f260
api: DroidClaw.executeLongPress
api_family: droidclaw.device-long-press
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: device-long-press
normative_authority: capability-facts-only
bound_sinks:
- executeLongPress
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-c87e557b
  capability: Perform a long-press gesture at model-selected coordinates on the attached Android device.
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
- default_id: legacy-default-81f2f9d5
  role_id: null
  value: Validated coordinates are used as both endpoints of a timed swipe whose duration comes from DroidClaw's long-press constant.
  security_effect: Validated coordinates are used as both endpoints of a timed swipe whose duration comes from DroidClaw's long-press constant.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeLongPress({ action: "longpress", coordinates: [100, 200] })'
  capability_edge: 'executeLongPress({ action: "longpress", coordinates: modelCoordinates })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
