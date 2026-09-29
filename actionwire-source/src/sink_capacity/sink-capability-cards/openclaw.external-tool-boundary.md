# AgentTool.execute from pi-coding-agent

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-a055f9e0f1c5b5ec
api: AgentTool.execute from pi-coding-agent
api_family: openclaw.external-tool-boundary
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw
  version: legacy-source-bound
capability_class: file-read-or-write
normative_authority: capability-facts-only
bound_sinks:
- tool.execute
- base.execute
roles:
- role_id: query-parameters
  description: Legacy controlled role query-parameters.
  bindings:
  - expression: params
    caller_bindable: true
facets:
- facet_id: legacy-facet-54cccfb1
  capability: Delegate file read, write, or edit parameters to the excluded pi-coding-agent implementation; the operation can disclose existing content or create, replace, and modify files according to the selected concrete tool.
  role_ids:
  - query-parameters
  activation:
    any_of:
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-7ccdddc0
  role_id: null
  value: The factory workspace root, external tool defaults, wrapper normalization, and sandbox path policy determine the effective paths and overwrite behavior.
  security_effect: The factory workspace root, external tool defaults, wrapper normalization, and sandbox path policy determine the effective paths and overwrite behavior.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'base.execute(toolCallId, { path: "README.md" }, signal)'
  capability_edge: base.execute(toolCallId, selectedNormalizedParams, signal)
provenance:
- benchmark/typescript/openclaw/src/agents/pi-tools.read.ts
```
