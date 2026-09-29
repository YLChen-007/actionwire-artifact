# NanoClaw.send_file

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-b4ff1e6486885f9d
api: NanoClaw.send_file
api_family: nanoclaw.file-delivery
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: file-delivery
normative_authority: capability-facts-only
bound_sinks:
- send_file
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: text
    caller_bindable: true
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-90e0265a
  capability: Stage and deliver a model-selected host-visible file to a named channel or agent destination.
  role_ids:
  - content
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-424c13c2
  role_id: null
  value: Relative paths resolve under the agent workspace and the display filename defaults to the source basename.
  security_effect: Relative paths resolve under the agent workspace and the display filename defaults to the source basename.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'send_file({ to: "owner", path: "report.pdf" })'
  capability_edge: 'send_file({ to: selectedDestination, path: selectedPath })'
provenance:
- benchmark/typescript/nanoclaw/container/agent-runner/src/mcp-tools/core.ts
```
