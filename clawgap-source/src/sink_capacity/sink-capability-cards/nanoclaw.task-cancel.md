# NanoClaw.cancel_task

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-7f1e17d426e44952
api: NanoClaw.cancel_task
api_family: nanoclaw.task-cancel
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: task-cancel
normative_authority: capability-facts-only
bound_sinks:
- cancel_task
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-109e75a7
  capability: Mark the selected live scheduled-task series completed and clear its recurrence.
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
- default_id: legacy-default-bef90a69
  role_id: null
  value: Both pending and paused occurrences matching the id or series id are affected.
  security_effect: Both pending and paused occurrences matching the id or series id are affected.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'cancel_task({ taskId: "task-123" })'
  capability_edge: 'cancel_task({ taskId: modelSelectedTask })'
provenance:
- benchmark/typescript/nanoclaw/src/modules/scheduling/db.ts
```
