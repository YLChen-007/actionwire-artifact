# node:fs deletion primitives

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-0333a2729932127b
api: node:fs deletion primitives
api_family: node.fs.delete
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: node
  version: legacy-source-bound
capability_class: file-delete
normative_authority: capability-facts-only
bound_sinks:
- rm
- rmSync
- unlink
- unlinkSync
- rmdir
- rmdirSync
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-63943c7f
  capability: Delete a caller-selected file or directory, including a directory tree when recursive options permit it.
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
- default_id: legacy-default-09036e89
  role_id: null
  value: Deletion uses the agent process privileges and host path resolution and is generally irreversible; rm options can change missing-target and recursive behavior.
  security_effect: Deletion uses the agent process privileges and host path resolution and is generally irreversible; rm options can change missing-target and recursive behavior.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await fs.rm(path.join(workspace, "build.tmp"))
  capability_edge: 'await fs.rm(selectedPath, { recursive: selectedRecursive, force: selectedForce })'
provenance:
- https://nodejs.org/api/fs.html
```
