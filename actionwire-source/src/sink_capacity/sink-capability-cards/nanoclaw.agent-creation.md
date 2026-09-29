# NanoClaw.create_agent

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-67a6e7558fa96231
api: NanoClaw.create_agent
api_family: nanoclaw.agent-creation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: agent-creation
normative_authority: capability-facts-only
bound_sinks:
- create_agent
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-97ee9774
  capability: Create a persistent agent group, workspace, container configuration, and bidirectional destinations.
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
- default_id: legacy-default-475a68db
  role_id: null
  value: Confined callers require host-side approval; trusted global-scope callers apply the creation directly.
  security_effect: Confined callers require host-side approval; trusted global-scope callers apply the creation directly.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'create_agent({ name: "researcher", instructions: "Summarize papers" })'
  capability_edge: create_agent(modelSelectedAgentDefinition)
provenance:
- benchmark/typescript/nanoclaw/src/modules/agent-to-agent/create-agent.ts
```
