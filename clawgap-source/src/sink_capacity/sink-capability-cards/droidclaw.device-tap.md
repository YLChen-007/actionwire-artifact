# DroidClaw.executeTap or DroidClaw.findAndTap

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-2e7b99f289b99dad
api: DroidClaw.executeTap or DroidClaw.findAndTap
api_family: droidclaw.device-tap
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: device-tap
normative_authority: capability-facts-only
bound_sinks:
- executeTap
- findAndTap
roles:
- role_id: statement
  description: Legacy controlled role statement.
  bindings:
  - expression: query
    caller_bindable: true
facets:
- facet_id: legacy-facet-f34defb3
  capability: Select and perform one tap on the attached Android device, either at model-selected coordinates or at the UI element selected by a model-provided text query.
  role_ids:
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-d5238c58
  role_id: null
  value: Coordinate validation and UI lookup determine the final position; the action still causes an input event on the device selected by DroidClaw's ADB configuration.
  security_effect: Coordinate validation and UI lookup determine the final position; the action still causes an input event on the device selected by DroidClaw's ADB configuration.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeTap({ action: "tap", coordinates: [120, 300] })'
  capability_edge: 'findAndTap({ action: "find_and_tap", query: modelQuery }, elements)'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
- benchmark/typescript/droidclaw/src/skills.ts
```
