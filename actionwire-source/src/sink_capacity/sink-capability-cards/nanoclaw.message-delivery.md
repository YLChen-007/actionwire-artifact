# NanoClaw.send_message

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-fd5738880b59be8c
api: NanoClaw.send_message
api_family: nanoclaw.message-delivery
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: message-delivery
normative_authority: capability-facts-only
bound_sinks:
- send_message
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: message
    caller_bindable: true
  - expression: text
    caller_bindable: true
facets:
- facet_id: legacy-facet-1e71429a
  capability: Deliver model-selected text to a named channel or agent destination.
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
- default_id: legacy-default-a9a59731
  role_id: null
  value: An omitted destination resolves through the current session routing when unambiguous.
  security_effect: An omitted destination resolves through the current session routing when unambiguous.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'send_message({ to: "family", text: "Done" })'
  capability_edge: 'send_message({ to: selectedDestination, text: modelText })'
provenance:
- benchmark/typescript/nanoclaw/container/agent-runner/src/mcp-tools/core.ts
```
