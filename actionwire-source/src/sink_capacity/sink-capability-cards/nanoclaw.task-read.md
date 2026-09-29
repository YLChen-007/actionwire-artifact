# NanoClaw.list_tasks

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-f6bbb2a83154e53d
api: NanoClaw.list_tasks
api_family: nanoclaw.task-read
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: task-read
normative_authority: capability-facts-only
bound_sinks:
- list_tasks
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-a776401d
  capability: Read persistent scheduled-task state and return task identifiers, timing, recurrence, status, and prompt excerpts to the model.
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
- default_id: legacy-default-43d484e6
  role_id: null
  value: An omitted status lists both pending and paused task series.
  security_effect: An omitted status lists both pending and paused task series.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'list_tasks({ status: "pending" })'
  capability_edge: 'list_tasks({ status: modelSelectedStatus })'
provenance:
- benchmark/typescript/nanoclaw/container/agent-runner/src/mcp-tools/scheduling.ts
```
