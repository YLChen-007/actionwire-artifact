# LettaCode.Task

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-333fc75ea095d058
api: LettaCode.Task
api_family: lettabot.subagent-delegation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: lettabot
  version: legacy-source-bound
capability_class: subagent-delegation
normative_authority: capability-facts-only
bound_sinks:
- Task
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-4e1b857e
  capability: Spawn or resume a model-selected subagent task with a model-selected prompt, execution model, and foreground or background lifecycle.
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
- default_id: legacy-default-591ed60b
  role_id: null
  value: New tasks require a configured subagent type; existing agent or conversation identifiers select resumption instead of creation.
  security_effect: New tasks require a configured subagent type; existing agent or conversation identifiers select resumption instead of creation.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'Task({ description: "inspect tests", prompt: "Find failing tests", subagent_type: "explore" })'
  capability_edge: 'Task({ description: modelDescription, prompt: modelPrompt, subagent_type: selectedType, agent_id: selectedAgent })'
provenance:
- benchmark/typescript/lettabot/vendor-source/letta-code-v0.19.5/src/tools/impl/Task.ts
```
