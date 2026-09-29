# DroidClaw.executeType

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-a553e2ca6ccc9841
api: DroidClaw.executeType
api_family: droidclaw.device-text-input
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: device-text-input
normative_authority: capability-facts-only
bound_sinks:
- executeType
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: text
    caller_bindable: true
facets:
- facet_id: legacy-facet-b656cd61
  capability: Type model-selected text into the currently focused input field on the attached Android device.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-1e969234
  role_id: null
  value: DroidClaw applies its text escaping and uses the currently focused field; focus and application state are inherited from the device session.
  security_effect: DroidClaw applies its text escaping and uses the currently focused field; focus and application state are inherited from the device session.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeType({ action: "type", text: "reviewed text" })'
  capability_edge: 'executeType({ action: "type", text: modelText })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
