# NanoClaw.add_reaction

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-9fea7176ca0f7225
api: NanoClaw.add_reaction
api_family: nanoclaw.message-reaction
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: message-reaction
normative_authority: capability-facts-only
bound_sinks:
- add_reaction
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: message
    caller_bindable: true
facets:
- facet_id: legacy-facet-affcbe1d
  capability: Add a model-selected emoji reaction to a previously delivered message.
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
- default_id: legacy-default-b2cfaa79
  role_id: null
  value: The destination and platform message identifier are recovered from the session database.
  security_effect: The destination and platform message identifier are recovered from the session database.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'add_reaction({ messageId: 7, emoji: "check" })'
  capability_edge: 'add_reaction({ messageId: selectedMessage, emoji: modelEmoji })'
provenance:
- benchmark/typescript/nanoclaw/container/agent-runner/src/mcp-tools/core.ts
```
