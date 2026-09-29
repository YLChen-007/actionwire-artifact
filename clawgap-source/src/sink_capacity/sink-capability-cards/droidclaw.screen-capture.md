# DroidClaw.executeScreenshot

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-c4b6856f8bc26851
api: DroidClaw.executeScreenshot
api_family: droidclaw.screen-capture
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: screen-capture
normative_authority: capability-facts-only
bound_sinks:
- executeScreenshot
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-ba89bbfc
  capability: Capture the attached Android device's screen and transfer the resulting image to a model-selected host path.
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
- default_id: legacy-default-e27b8b3f
  role_id: null
  value: The device-side screenshot path is fixed; when no filename is supplied DroidClaw uses its configured local screenshot path.
  security_effect: The device-side screenshot path is fixed; when no filename is supplied DroidClaw uses its configured local screenshot path.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeScreenshot({ action: "screenshot", filename: "./review/screen.png" })'
  capability_edge: 'executeScreenshot({ action: "screenshot", filename: modelPath })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
