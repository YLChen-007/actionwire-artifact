# NanoClaw.update_task

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-d1da02e80ac0e395
api: NanoClaw.update_task
api_family: nanoclaw.task-update
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: task-update
normative_authority: capability-facts-only
bound_sinks:
- update_task
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-be4374f7
  capability: Modify model-selected content and execution metadata on a live scheduled-task series.
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
- default_id: legacy-default-c286038c
  role_id: null
  value: Omitted fields remain unchanged and empty recurrence or script values clear those fields.
  security_effect: Omitted fields remain unchanged and empty recurrence or script values clear those fields.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'update_task({ taskId: "task-123", recurrence: "0 9 * * 1-5" })'
  capability_edge: 'update_task({ taskId: selectedTask, prompt: modelPrompt, script: modelScript })'
provenance:
- benchmark/typescript/nanoclaw/src/modules/scheduling/db.ts
```
