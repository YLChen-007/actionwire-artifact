# DroidClaw.executePaste

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-78c7442572d4a078
api: DroidClaw.executePaste
api_family: droidclaw.clipboard-paste
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: clipboard-paste
normative_authority: capability-facts-only
bound_sinks:
- executePaste
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-3a36b937
  capability: Paste the Android clipboard into the focused field, optionally focusing a model-selected coordinate first.
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
- default_id: legacy-default-09223f85
  role_id: null
  value: When coordinates are absent, the current device focus is reused; the clipboard contents are whatever the Android session currently exposes.
  security_effect: When coordinates are absent, the current device focus is reused; the clipboard contents are whatever the Android session currently exposes.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executePaste({ action: "paste", coordinates: [100, 200] })'
  capability_edge: 'executePaste({ action: "paste", coordinates: modelCoordinates })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
