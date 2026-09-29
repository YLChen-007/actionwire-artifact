# NanoClaw.schedule_task

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-28052f2884e0ad8b
api: NanoClaw.schedule_task
api_family: nanoclaw.task-scheduling
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: task-scheduling
normative_authority: capability-facts-only
bound_sinks:
- schedule_task
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-d121bbd2
  capability: Persist a model-defined one-shot or recurring task for later agent execution.
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
- default_id: legacy-default-3d38ac08
  role_id: null
  value: Times are normalized to UTC and an omitted recurrence creates a one-shot task.
  security_effect: Times are normalized to UTC and an omitted recurrence creates a one-shot task.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'schedule_task({ prompt: "Daily summary", processAfter: "2026-08-10T09:00:00" })'
  capability_edge: 'schedule_task({ prompt: modelPrompt, processAfter: selectedTime, script: modelScript })'
provenance:
- benchmark/typescript/nanoclaw/src/modules/scheduling/actions.ts
```
