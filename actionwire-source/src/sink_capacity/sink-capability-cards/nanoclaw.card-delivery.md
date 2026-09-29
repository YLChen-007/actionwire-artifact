# NanoClaw.send_card

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-f227654512df2f97
api: NanoClaw.send_card
api_family: nanoclaw.card-delivery
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: card-delivery
normative_authority: capability-facts-only
bound_sinks:
- send_card
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: text
    caller_bindable: true
facets:
- facet_id: legacy-facet-7a82bbfd
  capability: Deliver a model-defined structured card to the current conversation.
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
- default_id: legacy-default-2ecf86c9
  role_id: null
  value: The current session supplies routing and fallback text defaults to an empty string.
  security_effect: The current session supplies routing and fallback text defaults to an empty string.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'send_card({ card: { title: "Build complete" } })'
  capability_edge: 'send_card({ card: modelCard, fallbackText: modelText })'
provenance:
- benchmark/typescript/nanoclaw/container/agent-runner/src/mcp-tools/interactive.ts
```
