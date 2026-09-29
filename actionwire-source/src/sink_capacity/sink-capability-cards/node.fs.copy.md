# node:fs.copyFileSync

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-ba8b28d389692e2d
api: node:fs.copyFileSync
api_family: node.fs.copy
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: node
  version: legacy-source-bound
capability_class: file-copy
normative_authority: capability-facts-only
bound_sinks:
- copyFileSync
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-5b102304
  capability: Copy bytes from a caller-selected source path to a caller-selected destination path under the Node process filesystem privileges.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-574eca18
  role_id: null
  value: The destination is overwritten when it exists unless an exclusive copy flag is supplied; operating-system path and symbolic-link resolution determine the effective source and target.
  security_effect: The destination is overwritten when it exists unless an exclusive copy flag is supplied; operating-system path and symbolic-link resolution determine the effective source and target.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: fs.copyFileSync("/workspace/outbox/report.txt", "/workspace/inbox/report.txt")
  capability_edge: fs.copyFileSync(selectedSource, selectedDestination)
provenance:
- https://nodejs.org/api/fs.html#fscopyfilesyncsrc-dest-mode
```
