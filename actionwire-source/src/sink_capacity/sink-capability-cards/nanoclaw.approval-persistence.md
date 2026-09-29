# better-sqlite3.Statement.run:pending_approvals

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-24ae33b94e161769
api: better-sqlite3.Statement.run:pending_approvals
api_family: nanoclaw.approval-persistence
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: approval-persistence
normative_authority: capability-facts-only
bound_sinks:
- Statement.run:pending_approvals
roles:
- role_id: payload
  description: Legacy controlled role payload.
  bindings:
  - expression: payload
    caller_bindable: true
facets:
- facet_id: legacy-facet-6ee6400d
  capability: Persist the complete action payload that will be recovered and applied after an administrator accepts the corresponding NanoClaw approval request.
  role_ids:
  - payload
  activation:
    any_of:
    - predicate: role-bound
      subject: payload
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-5ba9d1bc
  role_id: null
  value: JSON serialization preserves execution-relevant fields that need not be present in the human-visible approval question; the action registry selects the later apply handler.
  security_effect: JSON serialization preserves execution-relevant fields that need not be present in the human-visible approval question; the action registry selects the later apply handler.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'createPendingApproval({ action: "add_mcp_server", payload: JSON.stringify(reviewedPayload) })'
  capability_edge: 'statement.run({ ...approval, payload: JSON.stringify(modelControlledPayload) })'
provenance:
- benchmark/typescript/nanoclaw/src/db/sessions.ts
```
