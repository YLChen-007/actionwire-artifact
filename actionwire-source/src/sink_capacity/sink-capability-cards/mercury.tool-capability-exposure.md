# ai.generateText tools option

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-1e71b1dca7822f83
api: ai.generateText tools option
api_family: mercury.tool-capability-exposure
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: mercury
  version: legacy-source-bound
capability_class: tool-capability-exposure
normative_authority: capability-facts-only
bound_sinks:
- generateText.tools
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-316510d5
  capability: Makes every supplied Mercury capability available for AI SDK tool dispatch during a delegated sub-agent run, including process, filesystem, network, and repository mutation capabilities.
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
- default_id: legacy-default-79c5c663
  role_id: null
  value: The boundary describes tool availability, not execution of every exposed tool. A caller-provided allowedTools list has no limiting effect unless the tool map is filtered before generateText receives it.
  security_effect: The boundary describes tool availability, not execution of every exposed tool. A caller-provided allowedTools list has no limiting effect unless the tool map is filtered before generateText receives it.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'generateText({ model, messages, tools: selectTools(reviewedAllowedTools) })'
  capability_edge: 'generateText({ model, messages, tools: capabilities.getTools() })'
provenance:
- benchmark/typescript/mercury-agent/src/core/sub-agent.ts
```
