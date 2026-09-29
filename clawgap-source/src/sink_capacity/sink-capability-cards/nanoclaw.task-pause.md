# NanoClaw.pause_task

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-947afd8e45b53587
api: NanoClaw.pause_task
api_family: nanoclaw.task-pause
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: task-pause
normative_authority: capability-facts-only
bound_sinks:
- pause_task
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-dca89a8e
  capability: Change the selected pending scheduled-task series to paused state.
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
- default_id: legacy-default-6677e34e
  role_id: null
  value: Matching uses either the occurrence id or the stable series id.
  security_effect: Matching uses either the occurrence id or the stable series id.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'pause_task({ taskId: "task-123" })'
  capability_edge: 'pause_task({ taskId: modelSelectedTask })'
provenance:
- benchmark/typescript/nanoclaw/src/modules/scheduling/db.ts
```
