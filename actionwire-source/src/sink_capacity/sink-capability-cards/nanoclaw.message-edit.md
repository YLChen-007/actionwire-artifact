# NanoClaw.edit_message

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-79b1babf0e7e0a40
api: NanoClaw.edit_message
api_family: nanoclaw.message-edit
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: message-edit
normative_authority: capability-facts-only
bound_sinks:
- edit_message
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: message
    caller_bindable: true
  - expression: text
    caller_bindable: true
facets:
- facet_id: legacy-facet-571bdf0d
  capability: Replace the content of a previously delivered message at its recorded destination.
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
- default_id: legacy-default-a33c2962
  role_id: null
  value: The original message routing and platform identifier are recovered from the session database.
  security_effect: The original message routing and platform identifier are recovered from the session database.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'edit_message({ messageId: 7, text: "Corrected status" })'
  capability_edge: 'edit_message({ messageId: selectedMessage, text: modelText })'
provenance:
- benchmark/typescript/nanoclaw/container/agent-runner/src/mcp-tools/core.ts
```
