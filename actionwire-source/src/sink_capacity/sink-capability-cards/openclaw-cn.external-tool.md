# wrapped AgentTool.execute

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-c25530c3929536bf
api: wrapped AgentTool.execute
api_family: openclaw-cn.external-tool
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw-cn
  version: legacy-source-bound
capability_class: external-tool-boundary
normative_authority: capability-facts-only
bound_sinks:
- read.execute
- write.execute
- edit.execute
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-9e85976b
  capability: Delegate normalized file-tool parameters to the external coding-tool implementation selected by the wrapper.
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
- default_id: legacy-default-2854b1a1
  role_id: null
  value: Workspace roots, sandbox mode, external package behavior, and wrapper checks determine the effective filesystem scope.
  security_effect: Workspace roots, sandbox mode, external package behavior, and wrapper checks determine the effective filesystem scope.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'base.execute(toolCallId, { path: "README.md" }, signal)'
  capability_edge: base.execute(toolCallId, selectedParams, signal)
provenance:
- benchmark/typescript/openclaw-cn/src/agents/pi-tools.read.ts
```
